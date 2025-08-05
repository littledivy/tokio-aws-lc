# tokio-aws-lc

An implementation of SSL streams for Tokio built on top of the [`aws-lc-sys` crate]

Based on `tokio-openssl`

```rust
let ctx = aws_lc_sys::SSL_CTX_new(aws_lc_sys::TLS_method());
let ssl = aws_lc_sys::SSL_new(ctx);

let stream = tokio::net::TcpStream::connect("example.com:443").await?;
let stream = tokio_aws_lc::SslStream::new(ssl, stream);

stream.connect().await?;

stream.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
```
