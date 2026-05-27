//! Tiny HTTP/1.1 forward-proxy client used by `handle_plain_http`. Performs
//! SSRF-safe DNS resolution via `crate::blocklist::safe_dial` and emits a
//! distinct "blocked" error so the caller can map it to 403.

use std::time::Duration;

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use thiserror::Error;
use tokio::net::TcpStream;

use crate::blocklist::{safe_dial, SafeDialError};

#[derive(Debug)]
pub struct Client {
    connect_timeout: Duration,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("target resolves to a blocked address")]
    Blocked,
    #[error("upstream request failed: {0}")]
    Upstream(String),
}

impl ClientError {
    pub fn is_blocked(&self) -> bool {
        matches!(self, ClientError::Blocked)
    }
}

impl Default for Client {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
        }
    }
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    /// Send the request and return the response.
    pub async fn request<B>(&self, req: Request<B>) -> Result<Response<Incoming>, ClientError>
    where
        B: hyper::body::Body<Data = Bytes> + Send + Sync + 'static + Unpin,
        B::Error: std::fmt::Display + Send + Sync + 'static,
    {
        let uri = req.uri().clone();
        let host = uri
            .host()
            .ok_or_else(|| ClientError::Upstream("missing host".into()))?
            .to_string();
        let port = uri.port_u16().unwrap_or(80);
        let stream = match safe_dial(&host, port, self.connect_timeout).await {
            Ok(s) => s,
            Err(SafeDialError::Blocked) => return Err(ClientError::Blocked),
            Err(e) => return Err(ClientError::Upstream(e.to_string())),
        };
        send_one(stream, req, &host, port).await
    }
}

async fn send_one<B>(
    stream: TcpStream,
    req: Request<B>,
    host: &str,
    port: u16,
) -> Result<Response<Incoming>, ClientError>
where
    B: hyper::body::Body<Data = Bytes> + Send + Sync + 'static + Unpin,
    B::Error: std::fmt::Display + Send + Sync + 'static,
{
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| ClientError::Upstream(format!("handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Convert URI to origin-form for the upstream request.
    let (mut parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    parts.uri = Uri::try_from(path_and_query)
        .map_err(|e| ClientError::Upstream(format!("invalid path: {e}")))?;
    // Ensure Host header is set to the original authority.
    if !parts.headers.contains_key(HOST) {
        let host_hdr = if port == 80 {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        if let Ok(v) = HeaderValue::from_str(&host_hdr) {
            parts.headers.insert(HOST, v);
        }
    }
    // Wrap incoming body so type matches what http1::send_request expects.
    let body = body
        .map_err(|e| std::io::Error::other(e.to_string()))
        .boxed();
    let req = Request::from_parts(parts, body);

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| ClientError::Upstream(format!("send: {e}")))?;
    let _ = resp.status();
    Ok(resp)
}

/// Helper for tests: a noop Empty body.
#[allow(dead_code)]
pub fn empty() -> Empty<Bytes> {
    Empty::<Bytes>::new()
}

/// Suppress dead_code warning on StatusCode while keeping it in scope as
/// documentation of intended response mapping.
#[allow(dead_code)]
fn _doc(_: StatusCode) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_returns_blocked_for_loopback_literal() {
        let c = Client::new();
        let req = Request::builder()
            .uri("http://127.0.0.1:1/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let err = c.request(req).await.unwrap_err();
        assert!(err.is_blocked());
    }
}
