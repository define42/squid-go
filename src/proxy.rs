//! HTTPS proxy request handler: PAC, CONNECT tunneling, plain-HTTP forward,
//! hop-by-hop header stripping. Ported from the Go original.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use ipnet::IpNet;
use tokio::io::AsyncWriteExt;

use crate::auth::{authorized, client_ip_exempt};
use crate::blocklist::{safe_dial, SafeDialError};
use crate::config::{AllowedPorts, PROXY_PAC_PATH};

/// Captured per-connection state shared with every request handler invocation.
#[derive(Clone)]
pub struct ProxyState {
    pub allowed_ports: Arc<AllowedPorts>,
    pub allowed_hashes: Arc<Vec<String>>,
    pub no_auth_nets: Arc<Vec<IpNet>>,
    pub pac_endpoint: Arc<String>,
    pub remote_addr: Option<SocketAddr>,
    pub http_client: Arc<crate::http_client::Client>,
}

type ResponseBody = BoxBody<Bytes, std::io::Error>;

fn full_body(b: impl Into<Bytes>) -> ResponseBody {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

fn text_response(status: StatusCode, msg: &str) -> Response<ResponseBody> {
    let body = format!("{msg}\n");
    let mut r = Response::new(full_body(body));
    *r.status_mut() = status;
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

fn pac_response(host_port: &str) -> Response<ResponseBody> {
    let body =
        format!("function FindProxyForURL(url, host) {{\n    return \"HTTPS {host_port}\";\n}}\n");
    let mut r = Response::new(full_body(body));
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ns-proxy-autoconfig"),
    );
    r.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    r.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// Build a PAC response, mirroring `servePAC` in Go.
pub fn serve_pac(endpoint: &str, req_host: Option<&str>) -> Response<ResponseBody> {
    let host_port: String = if !endpoint.is_empty() {
        endpoint.to_string()
    } else {
        req_host.unwrap_or("").trim().to_string()
    };
    if host_port.is_empty() {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "proxy endpoint not configured",
        );
    }
    if host_port
        .chars()
        .any(|c| matches!(c, '"' | '\\' | '\r' | '\n'))
    {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "proxy endpoint not configured",
        );
    }
    pac_response(&host_port)
}

/// Top-level request handler. Note: CONNECT is handled at the connection
/// layer by `crate::server`, so this handler only sees non-CONNECT requests.
pub async fn handle_request(
    state: ProxyState,
    req: Request<Incoming>,
) -> Result<Response<ResponseBody>, Infallible> {
    Ok(handle(state, req).await)
}

async fn handle(state: ProxyState, req: Request<Incoming>) -> Response<ResponseBody> {
    // Decode origin-form vs absolute-form. In hyper 1.x server mode, the URI
    // preserves the form the client sent.
    let uri = req.uri().clone();
    let method = req.method().clone();

    // Origin-form PAC fetch: method=GET, scheme=None, authority=None, path=/proxy.pac.
    if method == Method::GET
        && uri.scheme().is_none()
        && uri.authority().is_none()
        && uri.path() == PROXY_PAC_PATH
    {
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok());
        return serve_pac(&state.pac_endpoint, host);
    }

    let exempt = client_ip_exempt(state.remote_addr.map(|s| s.ip()), &state.no_auth_nets);
    if !exempt {
        let header = req
            .headers()
            .get("proxy-authorization")
            .and_then(|h| h.to_str().ok());
        if !authorized(header, &state.allowed_hashes) {
            let mut r = text_response(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "proxy authentication required",
            );
            r.headers_mut().insert(
                http::header::PROXY_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"go-https-proxy\""),
            );
            return r;
        }
    }

    handle_plain_http(state, req).await
}

/// Forward a plain HTTP request (absolute-form). HTTPS targets must use
/// CONNECT instead.
pub async fn handle_plain_http(
    state: ProxyState,
    req: Request<Incoming>,
) -> Response<ResponseBody> {
    let uri = req.uri().clone();
    if uri.scheme().is_none() || uri.authority().is_none() {
        return text_response(
            StatusCode::BAD_REQUEST,
            "expected absolute URL for HTTP proxy request",
        );
    }
    if uri.scheme_str() != Some("http") {
        return text_response(StatusCode::BAD_REQUEST, "use CONNECT for HTTPS targets");
    }

    // Strip hop-by-hop + Proxy-* headers.
    let (mut parts, body) = req.into_parts();
    remove_hop_by_hop_headers(&mut parts.headers);
    parts.headers.remove("proxy-authorization");
    parts.headers.remove("proxy-authenticate");

    let out_req = Request::from_parts(parts, body);

    match state.http_client.request(out_req).await {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            remove_hop_by_hop_headers(&mut parts.headers);
            // Re-attach body unchanged.
            let body = body.map_err(std::io::Error::other).boxed();
            Response::from_parts(parts, body)
        }
        Err(e) => {
            if e.is_blocked() {
                text_response(StatusCode::FORBIDDEN, "target address is not allowed")
            } else {
                text_response(StatusCode::BAD_GATEWAY, "upstream request failed")
            }
        }
    }
}

/// Validate a CONNECT target ("host:port"). Returns (host, port) or an
/// error string for the 400/403 response.
pub fn validate_connect_target(target: &str) -> Result<(String, u16), (StatusCode, &'static str)> {
    let (host, port) =
        split_host_port(target).ok_or((StatusCode::BAD_REQUEST, "bad CONNECT target"))?;
    if host.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "bad CONNECT target"));
    }
    if host.chars().any(|c| matches!(c, '%' | '\0')) {
        return Err((StatusCode::BAD_REQUEST, "bad CONNECT target"));
    }
    let port_n: u16 = port
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad CONNECT target"))?;
    if port_n == 0 {
        return Err((StatusCode::BAD_REQUEST, "bad CONNECT target"));
    }
    Ok((host, port_n))
}

/// Split a "host:port" string, supporting bracketed IPv6 literals.
pub fn split_host_port(s: &str) -> Option<(String, String)> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = tail.strip_prefix(':')?;
        if port.is_empty() {
            return None;
        }
        return Some((host.to_string(), port.to_string()));
    }
    let last = s.rfind(':')?;
    let host = &s[..last];
    let port = &s[last + 1..];
    if host.contains(':') {
        // Unbracketed IPv6 with port is ambiguous; reject.
        return None;
    }
    if port.is_empty() {
        return None;
    }
    Some((host.to_string(), port.to_string()))
}

/// Tunnel data between `client` and `dst` until both directions complete.
pub async fn tunnel<C, D>(mut client: C, mut dst: D)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    D: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Use copy_bidirectional which already waits for both halves and
    // handles half-close via TCP shutdown semantics.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut dst).await;
    let _ = client.shutdown().await;
    let _ = dst.shutdown().await;
}

pub fn remove_hop_by_hop_headers(h: &mut HeaderMap) {
    // First, remove anything named by the Connection header itself.
    let mut to_remove: Vec<HeaderName> = Vec::new();
    for v in h.get_all(CONNECTION).iter() {
        if let Ok(s) = v.to_str() {
            for field in s.split(',') {
                let f = field.trim();
                if f.is_empty() {
                    continue;
                }
                if let Ok(n) = HeaderName::try_from(f) {
                    to_remove.push(n);
                }
            }
        }
    }
    for n in to_remove {
        h.remove(&n);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        h.remove(name);
    }
}

/// Helper used by the CONNECT path in `crate::server`. Dials the target with
/// SSRF protection and runs the bidirectional tunnel. Writes the 200 line
/// directly to `client` on success, or an HTTP error line on failure.
pub async fn handle_connect_tunnel<C>(
    target: &str,
    allowed_ports: &AllowedPorts,
    mut client: C,
    pipelined: &[u8],
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (host, port) = match validate_connect_target(target) {
        Ok(v) => v,
        Err((status, msg)) => {
            write_status(&mut client, status, msg).await;
            return;
        }
    };
    if !allowed_ports.allows(port) {
        write_status(
            &mut client,
            StatusCode::FORBIDDEN,
            "CONNECT to this port is not allowed",
        )
        .await;
        return;
    }
    let dst = match safe_dial(&host, port, Duration::from_secs(10)).await {
        Ok(c) => c,
        Err(SafeDialError::Blocked) => {
            tracing::warn!(target = %target, "CONNECT blocked: address not allowed");
            write_status(
                &mut client,
                StatusCode::FORBIDDEN,
                "target address is not allowed",
            )
            .await;
            return;
        }
        Err(e) => {
            tracing::warn!(target = %target, err = %e, "CONNECT dial failed");
            write_status(
                &mut client,
                StatusCode::BAD_GATEWAY,
                "failed to connect to target",
            )
            .await;
            return;
        }
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let mut dst = dst;
    if !pipelined.is_empty() && dst.write_all(pipelined).await.is_err() {
        return;
    }
    tracing::info!(target = %target, "CONNECT");
    tunnel(client, dst).await;
}

async fn write_status<C: tokio::io::AsyncWrite + Unpin>(c: &mut C, status: StatusCode, msg: &str) {
    let line = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        msg.len() + 1,
        msg,
    );
    let _ = c.write_all(line.as_bytes()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn pac_simple() {
        let r = serve_pac("proxy.example.com:443", None);
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/x-ns-proxy-autoconfig"
        );
    }

    #[test]
    fn pac_no_endpoint_no_host_503() {
        let r = serve_pac("", None);
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn pac_rejects_injection() {
        let r = serve_pac("", Some("evil\"; alert(1); //"));
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn pac_falls_back_to_host_header() {
        let r = serve_pac("", Some("proxy.local:8443"));
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn connect_target_validation() {
        assert!(validate_connect_target("not-a-host-port").is_err());
        assert!(validate_connect_target("example.com:443").is_ok());
        assert!(validate_connect_target("fe80::1%eth0:443").is_err());
        let (host, port) = validate_connect_target("[2001:db8::1]:443").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn hop_by_hop_strip() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, "Keep-Alive, X-Custom-Hop".parse().unwrap());
        h.insert("keep-alive", "timeout=5".parse().unwrap());
        h.insert("proxy-authorization", "Basic xxx".parse().unwrap());
        h.insert("x-custom-hop", "drop-me".parse().unwrap());
        h.insert("x-keep", "keep-me".parse().unwrap());
        remove_hop_by_hop_headers(&mut h);
        for k in [
            "connection",
            "keep-alive",
            "proxy-authorization",
            "x-custom-hop",
        ] {
            assert!(h.get(k).is_none(), "header {k} should be removed");
        }
        assert_eq!(h.get("x-keep").unwrap(), "keep-me");
    }
}
