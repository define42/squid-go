//! TLS + plain-HTTP listener wiring with graceful shutdown. Routes CONNECT
//! at the connection layer (since hyper 1.x doesn't expose a connection
//! upgrade for unencrypted CONNECT in a server-friendly way) and dispatches
//! everything else through the hyper service.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use http::{Method, Request};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::proxy::{handle_connect_tunnel, handle_request, ProxyState};

/// Run the proxy. Blocks until a shutdown signal or fatal listener error.
pub async fn run(
    listen_addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    http_listen_addr: Option<SocketAddr>,
    state: ProxyState,
) -> Result<()> {
    let shutdown = Arc::new(Notify::new());
    let shutdown_signal = shutdown.clone();

    tokio::spawn(async move {
        wait_for_shutdown().await;
        shutdown_signal.notify_waiters();
    });

    let tls_ln = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind TLS listener {listen_addr}"))?;
    info!(addr = %listen_addr, "TLS listener bound");

    let plain_ln = if let Some(addr) = http_listen_addr {
        let ln = TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind plain-HTTP listener {addr}"))?;
        info!(addr = %addr, "plain-HTTP listener bound (UNENCRYPTED)");
        Some(ln)
    } else {
        None
    };

    let s1 = shutdown.clone();
    let state_tls = state.clone();
    let tls_task = tokio::spawn(async move {
        accept_loop_tls(tls_ln, tls_acceptor, state_tls, s1).await;
    });

    let plain_task = if let Some(ln) = plain_ln {
        let s2 = shutdown.clone();
        let state_plain = state.clone();
        Some(tokio::spawn(async move {
            accept_loop_plain(ln, state_plain, s2).await;
        }))
    } else {
        None
    };

    let _ = tls_task.await;
    if let Some(t) = plain_task {
        let _ = t.await;
    }
    Ok(())
}

async fn wait_for_shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        let mut sig = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            Ok(s) => s,
            Err(_) => return,
        };
        sig.recv().await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} };
    info!("shutdown signal received");
}

async fn accept_loop_tls(
    ln: TcpListener,
    acceptor: TlsAcceptor,
    state: ProxyState,
    shutdown: Arc<Notify>,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => return,
            res = ln.accept() => match res {
                Ok((sock, peer)) => {
                    let acceptor = acceptor.clone();
                    let mut state = state.clone();
                    state.remote_addr = Some(peer);
                    tokio::spawn(async move {
                        let _ = sock.set_nodelay(true);
                        match acceptor.accept(sock).await {
                            Ok(tls) => {
                                serve_connection(tls, state).await;
                            }
                            Err(e) => warn!(peer = %peer, err = %e, "TLS handshake failed"),
                        }
                    });
                }
                Err(e) => {
                    error!(err = %e, "TLS accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

async fn accept_loop_plain(ln: TcpListener, state: ProxyState, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => return,
            res = ln.accept() => match res {
                Ok((sock, peer)) => {
                    let mut state = state.clone();
                    state.remote_addr = Some(peer);
                    tokio::spawn(async move {
                        let _ = sock.set_nodelay(true);
                        serve_connection(sock, state).await;
                    });
                }
                Err(e) => {
                    error!(err = %e, "plain-HTTP accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

/// Drive a single connection. Peek the request line; if it's CONNECT, take
/// the connection over for raw tunneling. Otherwise hand it to hyper.
async fn serve_connection<S>(stream: S, state: ProxyState)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    // Buffer enough to peek the request line and headers.
    let mut peek_buf: Vec<u8> = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    let mut stream = stream;
    let mut header_end: Option<usize> = None;

    // Read until we see the end of headers or fill 8 KiB. CONNECT requests
    // are short and arrive in one packet in practice.
    loop {
        let n = match stream.read(&mut tmp).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        peek_buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_double_crlf(&peek_buf) {
            header_end = Some(end);
            break;
        }
        if peek_buf.len() >= 8192 {
            break;
        }
    }

    let is_connect = peek_buf
        .split(|&b| b == b' ' || b == b'\r' || b == b'\n')
        .next()
        .map(|w| w == b"CONNECT")
        .unwrap_or(false);

    if is_connect {
        // Parse Host of the CONNECT request line: first token after method.
        let req_line_end = peek_buf
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .unwrap_or(peek_buf.len());
        let line = &peek_buf[..req_line_end];
        let parts: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
        let target = if parts.len() >= 2 {
            std::str::from_utf8(parts[1]).unwrap_or("").to_string()
        } else {
            String::new()
        };

        // Auth + exemption check.
        if !is_authorized_for_connect(&peek_buf, &state) {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"go-https-proxy\"\r\n\
                      Content-Type: text/plain; charset=utf-8\r\n\
                      Content-Length: 31\r\n\
                      Connection: close\r\n\r\n\
                      proxy authentication required\n",
                )
                .await;
            return;
        }

        // Anything after the end of headers was pipelined by the client
        // (e.g. an early TLS ClientHello).
        let pipelined: Vec<u8> = if let Some(end) = header_end {
            peek_buf[end..].to_vec()
        } else {
            Vec::new()
        };

        handle_connect_tunnel(&target, &state.allowed_ports, stream, &pipelined).await;
        return;
    }

    // Not CONNECT: replay the peeked bytes into hyper via a chained reader.
    let prefixed = PrefixedReader::new(peek_buf, stream);
    let io = TokioIo::new(prefixed);
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { handle_request(state, req).await }
    });

    if let Err(e) = http1::Builder::new()
        .keep_alive(true)
        .header_read_timeout(Duration::from_secs(10))
        .serve_connection(io, svc)
        .await
    {
        // Common when a client closes mid-request.
        tracing::debug!(err = %e, "connection serve ended");
    }
    let _: Result<(), Infallible> = Ok(());
}

fn is_authorized_for_connect(req_bytes: &[u8], state: &ProxyState) -> bool {
    use crate::auth::{authorized, client_ip_exempt};
    let exempt = client_ip_exempt(state.remote_addr.map(|s| s.ip()), &state.no_auth_nets);
    if exempt {
        return true;
    }
    // Extract "Proxy-Authorization: ..." header line.
    let mut header_val: Option<String> = None;
    for line in split_lines(req_bytes) {
        if let Some(rest) = strip_prefix_ci(line, b"proxy-authorization:") {
            let v = std::str::from_utf8(rest).unwrap_or("").trim();
            header_val = Some(v.to_string());
            break;
        }
    }
    authorized(header_val.as_deref(), &state.allowed_hashes)
}

fn strip_prefix_ci<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if s.len() < prefix.len() {
        return None;
    }
    if s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn split_lines(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    buf.split(|&b| b == b'\n').map(|l| {
        if let Some(stripped) = l.strip_suffix(b"\r") {
            stripped
        } else {
            l
        }
    })
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    let needle = b"\r\n\r\n";
    buf.windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + needle.len())
}

/// AsyncRead/Write that prepends a buffered prefix before delegating to an
/// inner stream. Used to replay the bytes we peeked before deciding whether
/// the connection was a CONNECT or a regular request.
struct PrefixedReader<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedReader<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedReader<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.offset += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedReader<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Re-export for tests/integration that need to spin up an HTTP-only listener.
#[allow(dead_code)]
pub(crate) async fn _accept_one_plain(ln: TcpListener, state: ProxyState) {
    if let Ok((sock, peer)) = ln.accept().await {
        let mut state = state.clone();
        state.remote_addr = Some(peer);
        serve_connection(sock, state).await;
    }
}

// Suppress unused-import warnings for items only consumed conditionally.
#[allow(dead_code)]
fn _unused(_t: TcpStream) {}
#[allow(dead_code)]
fn _unused2(_m: Method) {}
