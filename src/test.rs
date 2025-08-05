use crate::SslStream;
use aws_lc_sys as ffi;
use futures_util::future;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn google() {
    let addr = "httpbin.org:443".to_socket_addrs().unwrap().next().unwrap();
    println!("Connecting to: {}", addr);
    let stream = TcpStream::connect(&addr).await.unwrap();
    println!("TCP connection established");

    /*let ssl = SslConnector::builder(SslMethod::tls())
    .unwrap()
    .build()
    .configure()
    .unwrap()
    .into_ssl("google.com")
    .unwrap();*/
    let ssl = unsafe {
        let ctx = ffi::SSL_CTX_new(ffi::TLS_method());
        if ctx.is_null() {
            panic!("Failed to create SSL context");
        }

        // Disable verification for testing
        ffi::SSL_CTX_set_verify(ctx, ffi::SSL_VERIFY_NONE, None);

        // Set up cipher suites
        ffi::SSL_CTX_set_cipher_list(ctx, b"HIGH:!aNULL:!MD5\0".as_ptr() as *const _);

        let ssl = ffi::SSL_new(ctx);
        if ssl.is_null() {
            panic!("Failed to create SSL object");
        }

        // Set hostname for SNI
        ffi::SSL_set_tlsext_host_name(ssl, b"httpbin.org\0".as_ptr() as *const _);
        ffi::SSL_set_connect_state(ssl);

        // Free the context as it's not needed after SSL object creation
        ffi::SSL_CTX_free(ctx);
        ssl
    };
    let mut stream = SslStream::new(ssl, stream).unwrap();

    match Pin::new(&mut stream).connect().await {
        Ok(()) => println!("SSL handshake successful"),
        Err(e) => {
            println!("SSL handshake failed: {:?}", e);
            // Print the actual SSL error and get BIO errors
            unsafe {
                let err = aws_lc_sys::ERR_get_error();
                println!("SSL error code: {}", err);
                if err != 0 {
                    let mut buf = [0u8; 256];
                    aws_lc_sys::ERR_error_string_n(err, buf.as_mut_ptr() as *mut i8, buf.len());
                    let error_str =
                        std::ffi::CStr::from_ptr(buf.as_ptr() as *const i8).to_string_lossy();
                    println!("SSL error string: {}", error_str);
                }

                // Print all errors in the error queue
                let mut all_errors = Vec::new();
                loop {
                    let err = aws_lc_sys::ERR_get_error();
                    if err == 0 {
                        break;
                    }
                    all_errors.push(err);
                }
                println!("All SSL errors: {:?}", all_errors);
            }
            panic!("SSL handshake failed");
        }
    }

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    // any response code is fine
    assert!(response.starts_with("HTTP/1.0 "));
    assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
}
