//! Async TLS streams backed by AWS-LC.
//!
#![warn(missing_docs)]

use std::fmt;
use std::future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use aws_lc_sys as ffi;
mod bio;
use core::ffi::c_int;

mod ssl {
    use aws_lc_sys as ffi;
    use std::io::{self, Read, Write};
    use std::marker::PhantomData;
    use std::mem::ManuallyDrop;
    use std::mem::MaybeUninit;

    use crate::bio;
    use crate::ErrorCode;
    use crate::ShutdownResult;

    /// A TLS session over a stream.
    #[derive(Debug)]
    pub struct SslStream<S> {
        ssl: *mut ffi::SSL,
        method: ManuallyDrop<bio::BioMethod>,
        _p: PhantomData<S>,
    }

    impl<S: Read + Write> SslStream<S> {
        pub fn new(ssl: *mut ffi::SSL, stream: S) -> Result<Self, ()> {
            let (bio, method) = bio::new(stream)?;
            unsafe {
                ffi::SSL_set_bio(ssl, bio, bio);
            }

            Ok(SslStream {
                ssl,
                method: ManuallyDrop::new(method),
                _p: PhantomData,
            })
        }

        /// Initiates a client-side TLS handshake.
        ///
        /// # Warning
        ///
        /// OpenSSL's default configuration is insecure. It is highly recommended to use
        /// `SslConnector` rather than `Ssl` directly, as it manages that configuration.
        pub fn connect(&mut self) -> Result<(), Error> {
            let ret = unsafe { ffi::SSL_connect(self.ssl) };
            if ret > 0 {
                Ok(())
            } else {
                let ssl_error = unsafe { ffi::SSL_get_error(self.ssl, ret) };
                Err(Error::Ssl(ssl_error as u32))
            }
        }

        /// Initiates a server-side TLS handshake.
        ///
        /// # Warning
        ///
        /// OpenSSL's default configuration is insecure. It is highly recommended to use
        /// `SslAcceptor` rather than `Ssl` directly, as it manages that configuration.
        pub fn accept(&mut self) -> Result<(), Error> {
            let ret = unsafe { ffi::SSL_accept(self.ssl) };
            if ret > 0 {
                Ok(())
            } else {
                let ssl_error = unsafe { ffi::SSL_get_error(self.ssl, ret) };
                Err(Error::Ssl(ssl_error as u32))
            }
        }

        /// Initiates the handshake.
        ///
        /// This will fail if `set_accept_state` or `set_connect_state` was not called first.
        pub fn do_handshake(&mut self) -> Result<(), Error> {
            let ret = unsafe { ffi::SSL_do_handshake(self.ssl) };
            if ret > 0 {
                Ok(())
            } else {
                let ssl_error = unsafe { ffi::SSL_get_error(self.ssl, ret) };
                Err(Error::Ssl(ssl_error as u32))
            }
        }

        /// Reads data from the stream, without removing it from the queue.
        pub fn ssl_peek(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            let mut readbytes = 0;
            let ret = unsafe {
                ffi::SSL_peek_ex(self.ssl, buf.as_mut_ptr().cast(), buf.len(), &mut readbytes)
            };

            if ret > 0 {
                Ok(readbytes)
            } else {
                Err(Error::Ssl(unsafe { ffi::ERR_get_error() }))
            }
        }

        /// Like `read_ssl`, but takes a possibly-uninitialized slice.
        ///
        /// # Safety
        ///
        /// No portion of `buf` will be de-initialized by this method. If the method returns `Ok(n)`,
        /// then the first `n` bytes of `buf` are guaranteed to be initialized.
        pub fn ssl_read_uninit(&mut self, buf: &mut [MaybeUninit<u8>]) -> Result<usize, Error> {
            let mut readbytes = 0;
            let ret = unsafe {
                ffi::SSL_read_ex(self.ssl, buf.as_mut_ptr().cast(), buf.len(), &mut readbytes)
            };

            if ret > 0 {
                Ok(readbytes)
            } else {
                Err(Error::Ssl(unsafe { ffi::ERR_get_error() }))
            }
        }

        /// Like `read`, but takes a possibly-uninitialized slice.
        ///
        /// # Safety
        ///
        /// No portion of `buf` will be de-initialized by this method. If the method returns `Ok(n)`,
        /// then the first `n` bytes of `buf` are guaranteed to be initialized.
        pub fn read_uninit(&mut self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
            loop {
                match self.ssl_read_uninit(buf) {
                    Ok(n) => return Ok(n),
                    _ => todo!("Lol"),
                }
            }
        }

        /// Like `write`, but returns an `ssl::Error` rather than an `io::Error`.
        ///
        /// It is particularly useful with a non-blocking socket, where the error value will identify if
        /// OpenSSL is waiting on read or write readiness.
        pub fn ssl_write(&mut self, buf: &[u8]) -> Result<usize, Error> {
            let mut written = 0;
            let ret = unsafe {
                ffi::SSL_write_ex(self.ssl, buf.as_ptr().cast(), buf.len(), &mut written)
            };

            if ret > 0 {
                Ok(written)
            } else {
                Err(Error::Ssl(unsafe { ffi::ERR_get_error() }))
            }
        }

        /// Shuts down the session.
        ///
        /// The shutdown process consists of two steps. The first step sends a close notify message to
        /// the peer, after which `ShutdownResult::Sent` is returned. The second step awaits the receipt
        /// of a close notify message from the peer, after which `ShutdownResult::Received` is returned.
        ///
        /// While the connection may be closed after the first step, it is recommended to fully shut the
        /// session down. In particular, it must be fully shut down if the connection is to be used for
        /// further communication in the future.
        pub fn shutdown(&mut self) -> Result<ShutdownResult, Error> {
            match unsafe { ffi::SSL_shutdown(self.ssl) } {
                0 => Ok(ShutdownResult::Sent),
                1 => Ok(ShutdownResult::Received),
                n => Err(Error::Ssl(unsafe { ffi::ERR_get_error() })),
            }
        }
    }

    impl<S> SslStream<S> {
        /// Returns a shared reference to the underlying stream.
        pub fn get_ref(&self) -> &S {
            unsafe {
                let bio = ffi::SSL_get_rbio(self.ssl);
                bio::get_ref(bio)
            }
        }

        /// Returns a mutable reference to the underlying stream.
        ///
        /// # Warning
        ///
        /// It is inadvisable to read from or write to the underlying stream as it
        /// will most likely corrupt the SSL session.
        pub fn get_mut(&mut self) -> &mut S {
            unsafe {
                let bio = ffi::SSL_get_rbio(self.ssl);
                bio::get_mut(bio)
            }
        }
    }

    impl<S: Read + Write> Read for SslStream<S> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // SAFETY: `read_uninit` does not de-initialize the buffer
            unsafe {
                self.read_uninit(std::slice::from_raw_parts_mut(
                    buf.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                    buf.len(),
                ))
            }
        }
    }

    impl<S: Read + Write> Write for SslStream<S> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            loop {
                match self.ssl_write(buf) {
                    Ok(n) => return Ok(n),
                    Err(e) => {
                        todo!("Lol");
                    }
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.get_mut().flush()
        }
    }

    #[derive(Debug)]
    pub enum Error {
        Ssl(u32),
    }

    impl Error {
        pub fn code(&self) -> crate::ErrorCode {
            crate::ErrorCode(match self {
                Error::Ssl(code) => *code as _,
            })
        }
    }
}

/// An error code returned from SSL functions.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ErrorCode(c_int);

impl ErrorCode {
    /// The SSL session has been closed.
    pub const ZERO_RETURN: ErrorCode = ErrorCode(6);

    /// An attempt to read data from the underlying socket returned `WouldBlock`.
    ///
    /// Wait for read readiness and retry the operation.
    pub const WANT_READ: ErrorCode = ErrorCode(2);

    /// An attempt to write data to the underlying socket returned `WouldBlock`.
    ///
    /// Wait for write readiness and retry the operation.
    pub const WANT_WRITE: ErrorCode = ErrorCode(3);

    /// A non-recoverable IO error occurred.
    pub const SYSCALL: ErrorCode = ErrorCode(5);

    /// An error occurred in the SSL library.
    pub const SSL: ErrorCode = ErrorCode(1);

    pub fn from_raw(raw: c_int) -> ErrorCode {
        ErrorCode(raw)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

/// The result of a shutdown request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShutdownResult {
    /// A close notify message has been sent to the peer.
    Sent,

    /// A close notify response message has been received from the peer.
    Received,
}

bitflags::bitflags! {
    /// The shutdown state of a session.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct ShutdownState: c_int {
        /// A close notify message has been sent to the peer.
        const SENT = 1;
        /// A close notify message has been received from the peer.
        const RECEIVED = 2;
    }
}

#[cfg(test)]
mod test;

struct StreamWrapper<S> {
    stream: S,
    context: usize,
}

impl<S> fmt::Debug for StreamWrapper<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.stream, fmt)
    }
}

impl<S> StreamWrapper<S> {
    /// # Safety
    ///
    /// Must be called with `context` set to a valid pointer to a live `Context` object, and the
    /// wrapper must be pinned in memory.
    unsafe fn parts(&mut self) -> (Pin<&mut S>, &mut Context<'_>) {
        debug_assert_ne!(self.context, 0);
        let stream = Pin::new_unchecked(&mut self.stream);
        let context = &mut *(self.context as *mut _);
        (stream, context)
    }
}

impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (stream, cx) = unsafe { self.parts() };
        let mut buf = ReadBuf::new(buf);
        match stream.poll_read(cx, &mut buf)? {
            Poll::Ready(()) => Ok(buf.filled().len()),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (stream, cx) = unsafe { self.parts() };
        match stream.poll_write(cx, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let (stream, cx) = unsafe { self.parts() };
        match stream.poll_flush(cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

fn cvt_ossl<T>(r: Result<T, ssl::Error>) -> Poll<Result<T, ssl::Error>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(e) => match e.code() {
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => Poll::Pending,
            _ => Poll::Ready(Err(e)),
        },
    }
}

/// An asynchronous version of [`openssl::ssl::SslStream`].
#[derive(Debug)]
pub struct SslStream<S>(ssl::SslStream<StreamWrapper<S>>);

impl<S> SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    /// Like [`SslStream::new`](ssl::SslStream::new).
    pub fn new(ssl: *mut ffi::SSL, stream: S) -> Result<Self, ()> {
        ssl::SslStream::new(ssl, StreamWrapper { stream, context: 0 }).map(SslStream)
    }

    /// Like [`SslStream::connect`](ssl::SslStream::connect).
    pub fn poll_connect(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.connect()))
    }

    /// A convenience method wrapping [`poll_connect`](Self::poll_connect).
    pub async fn connect(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_connect(cx)).await
    }

    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    pub fn poll_accept(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.accept()))
    }

    /// A convenience method wrapping [`poll_accept`](Self::poll_accept).
    pub async fn accept(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_accept(cx)).await
    }

    /// Like [`SslStream::do_handshake`](ssl::SslStream::do_handshake).
    pub fn poll_do_handshake(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.do_handshake()))
    }

    /// A convenience method wrapping [`poll_do_handshake`](Self::poll_do_handshake).
    pub async fn do_handshake(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_do_handshake(cx)).await
    }

    /// Like [`SslStream::ssl_peek`](ssl::SslStream::ssl_peek).
    pub fn poll_peek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.ssl_peek(buf)))
    }

    /// A convenience method wrapping [`poll_peek`](Self::poll_peek).
    pub async fn peek(mut self: Pin<&mut Self>, buf: &mut [u8]) -> Result<usize, ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_peek(cx, buf)).await
    }

    /// Like [`SslStream::read_early_data`](ssl::SslStream::read_early_data).
    #[cfg(ossl111)]
    pub fn poll_read_early_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.read_early_data(buf)))
    }

    /// A convenience method wrapping [`poll_read_early_data`](Self::poll_read_early_data).
    #[cfg(ossl111)]
    pub async fn read_early_data(
        mut self: Pin<&mut Self>,
        buf: &mut [u8],
    ) -> Result<usize, ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_read_early_data(cx, buf)).await
    }

    /// Like [`SslStream::write_early_data`](ssl::SslStream::write_early_data).
    #[cfg(ossl111)]
    pub fn poll_write_early_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.write_early_data(buf)))
    }

    /// A convenience method wrapping [`poll_write_early_data`](Self::poll_write_early_data).
    #[cfg(ossl111)]
    pub async fn write_early_data(
        mut self: Pin<&mut Self>,
        buf: &[u8],
    ) -> Result<usize, ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_write_early_data(cx, buf)).await
    }
}

impl<S> SslStream<S> {
    /// Returns a shared reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.0.get_ref().stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0.get_mut().stream
    }

    /// Returns a pinned mutable reference to the underlying stream.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().0.get_mut().stream) }
    }

    fn with_context<F, R>(self: Pin<&mut Self>, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut ssl::SslStream<StreamWrapper<S>>) -> R,
    {
        let this = unsafe { self.get_unchecked_mut() };
        this.0.get_mut().context = ctx as *mut _ as usize;
        let r = f(&mut this.0);
        this.0.get_mut().context = 0;
        r
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| {
            // SAFETY: read_uninit does not de-initialize the buffer.
            match cvt(s.read_uninit(unsafe { buf.unfilled_mut() }))? {
                Poll::Ready(nread) => {
                    // SAFETY: read_uninit guarantees that nread bytes have been initialized.
                    unsafe { buf.assume_init(nread) };
                    buf.advance(nread);
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        })
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(s.write(buf)))
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        match self.as_mut().with_context(ctx, |s| s.shutdown()) {
            Ok(ShutdownResult::Sent) | Ok(ShutdownResult::Received) => {}
            Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {}
            Err(ref e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                return Poll::Pending;
            }
            Err(e) => {
                todo!("Lol")
            }
        }

        self.get_pin_mut().poll_shutdown(ctx)
    }
}
