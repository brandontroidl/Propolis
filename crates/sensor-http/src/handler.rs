use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{ConnectionBounds, EventEmitter, Uuid, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SensorEvent, WIRE_VERSION,
};

const PROTOCOL_LABEL: &str = "http";

const MAX_REQUEST_LINE_LEN: usize = 8192;
const MAX_HEADER_BLOCK: usize = 16384;
const MAX_BODY_CAPTURE: usize = 65536;
const READ_CHUNK_SIZE: usize = 4096;

/// The impersonated server. Coherent with the shared persona (an Ubuntu host): this is the exact
/// `Server` token an Ubuntu-packaged nginx emits. A missing or mismatched Server (and, worse, the
/// previously-absent Date header) is what a service scanner keys on.
const SERVER_BANNER: &str = "nginx/1.18.0 (Ubuntu)";

/// A fixed, plausible mtime for the served static pages, so `Last-Modified` is stable across
/// requests (a real file's mtime does not move) and the `ETag` mtime component agrees with it.
const PAGE_LAST_MODIFIED: &str = "Tue, 16 Jan 2024 10:24:30 GMT";
const PAGE_MTIME_EPOCH: u64 = 1_705_400_670; // == PAGE_LAST_MODIFIED, for the ETag mtime field

/// The verbatim Ubuntu-packaged nginx default index (`index.nginx-debian.html`). The old page said
/// "It works!" - Apache's phrase, not nginx's - which contradicted any nginx Server header.
const RESPONSE_200_HTML: &str = "<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href=\"http://nginx.org/\">nginx.org</a>.<br/>
Commercial support is available at
<a href=\"http://nginx.com/\">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
";

const RESPONSE_ROBOTS: &str = "User-agent: *\nDisallow: /\n";

/// nginx's generated 404 page (its exact markup, ending with the Server token).
const NGINX_404_HTML: &str = "<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
";

/// nginx's generated 405 page (returned for any method other than GET/HEAD on a static resource).
const NGINX_405_HTML: &str = "<html>
<head><title>405 Not Allowed</title></head>
<body>
<center><h1>405 Not Allowed</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
";

pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) {
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = stream
        .local_addr()
        .ok()
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    let conn_event = connection_event(source_ip, wan_ip, session_id);
    if emitter.append(&conn_event).await.is_err() {
        tracing::error!(%peer_addr, "http: failed to append connection event");
    }

    let mut reader = BoundedReader::new(bounds);

    let Some(request) = reader.read_request(&mut stream).await else {
        return;
    };

    {
        let method = sanitize_value(&request.method, 16);
        let path = sanitize_value(&request.path, 2048);
        let user_agent = request
            .header("user-agent")
            .map(|v| sanitize_value(v, 512))
            .unwrap_or_default();
        let host = request
            .header("host")
            .map(|v| sanitize_value(v, 255))
            .unwrap_or_default();

        let mut metadata = serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "method": method,
            "path": path,
        });
        if !user_agent.is_empty() {
            metadata["user_agent"] = serde_json::Value::String(user_agent);
        }
        if !host.is_empty() {
            metadata["host"] = serde_json::Value::String(host);
        }
        if let Some(query) = &request.query {
            metadata["query"] = serde_json::Value::String(sanitize_value(query, 2048));
        }
        if !request.body.is_empty() {
            let body_preview = sanitize_value(
                &String::from_utf8_lossy(&request.body),
                MAX_BODY_CAPTURE.min(4096),
            );
            metadata["body_preview"] = serde_json::Value::String(body_preview);
            metadata["body_size"] = serde_json::Value::Number(request.body.len().into());
        }

        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip,
            wan_ip,
            sensor: PROTOCOL_LABEL.to_string(),
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.to_string(),
            protocol: PROTO_TCP.to_string(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata,
            sample: None,
            session_id: Some(session_id),
        };
        let _ = emitter.append(&event).await;

        let response = build_response(&request.method, &request.path);
        let _ = stream.write_all(&response).await;
    }
}

/// The IMF-fixdate `Date` header value for now (e.g. `Tue, 16 Jan 2024 10:24:30 GMT`), regenerated
/// per response as every real HTTP server does. Its previous absence was a one-request tell.
fn http_date_now() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// Build the full response an Ubuntu nginx sends for `(method, path)`: GET/HEAD are served (a static
/// 200 carries Last-Modified/ETag/Accept-Ranges; HEAD omits the body), an unknown path is nginx's
/// 404, and any other method is nginx's 405. Deferred as documented low-interaction limits, not
/// folded in here: keep-alive, echoing/validating the request's HTTP version, conditional (If-*) and
/// Range requests, and chunked request bodies.
fn build_response(method: &str, path: &str) -> Vec<u8> {
    let date = http_date_now();
    let is_head = method == "HEAD";

    // Only GET/HEAD are valid on nginx-served static content; every other method is 405.
    if method != "GET" && !is_head {
        return error_response("405 Not Allowed", NGINX_405_HTML, &date, false);
    }

    let (content_type, body): (&str, &[u8]) = match path {
        "/" => ("text/html", RESPONSE_200_HTML.as_bytes()),
        "/robots.txt" => ("text/plain", RESPONSE_ROBOTS.as_bytes()),
        _ => return error_response("404 Not Found", NGINX_404_HTML, &date, is_head),
    };

    // A static 200 in nginx's header order, with the file-serving headers a real nginx adds.
    let etag = format!("\"{:x}-{:x}\"", PAGE_MTIME_EPOCH, body.len());
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Server: {SERVER_BANNER}\r\n\
         Date: {date}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Last-Modified: {PAGE_LAST_MODIFIED}\r\n\
         Connection: close\r\n\
         ETag: {etag}\r\n\
         Accept-Ranges: bytes\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    if !is_head {
        out.extend_from_slice(body);
    }
    out
}

/// An nginx error response (404/405): the generated HTML page with Server/Date and no static-file
/// headers. `is_head` omits the body while keeping the Content-Length, as nginx does.
fn error_response(status: &str, body: &str, date: &str, is_head: bool) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         Server: {SERVER_BANNER}\r\n\
         Date: {date}\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    if !is_head {
        out.extend_from_slice(body.as_bytes());
    }
    out
}

fn connection_event(source_ip: IpAddr, wan_ip: Option<IpAddr>, session_id: Uuid) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({ "protocol_label": PROTOCOL_LABEL }),
        sample: None,
        session_id: Some(session_id),
    }
}

struct HttpRequest {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct BoundedReader {
    buf: Vec<u8>,
    bounds: ConnectionBounds,
    first_read: bool,
    total_captured: u64,
}

impl BoundedReader {
    fn new(bounds: ConnectionBounds) -> Self {
        Self {
            buf: Vec::new(),
            bounds,
            first_read: true,
            total_captured: 0,
        }
    }

    async fn fill(&mut self, stream: &mut TcpStream) -> Option<usize> {
        if self.total_captured >= self.bounds.max_captured_bytes {
            return None;
        }
        let timeout = if self.first_read {
            self.bounds.read_timeout
        } else {
            self.bounds.idle_timeout
        };
        self.first_read = false;

        let mut tmp = [0u8; READ_CHUNK_SIZE];
        match tokio::time::timeout(timeout, stream.read(&mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => None,
            Ok(Ok(n)) => {
                self.total_captured += n as u64;
                self.buf.extend_from_slice(&tmp[..n]);
                Some(n)
            }
        }
    }

    async fn read_request(&mut self, stream: &mut TcpStream) -> Option<HttpRequest> {
        // Accumulate until we see the header terminator \r\n\r\n
        loop {
            if let Some(end) = find_header_end(&self.buf) {
                return self.parse_request(end, stream).await;
            }
            if self.buf.len() > MAX_HEADER_BLOCK {
                return None;
            }
            self.fill(stream).await?;
        }
    }

    async fn parse_request(
        &mut self,
        header_end: usize,
        stream: &mut TcpStream,
    ) -> Option<HttpRequest> {
        let header_bytes = self.buf[..header_end].to_vec();
        // Drain the headers plus the \r\n\r\n separator
        self.buf.drain(..header_end + 4);

        let header_str = String::from_utf8_lossy(&header_bytes);
        let mut lines = header_str.split("\r\n");

        let request_line = lines.next()?;
        if request_line.len() > MAX_REQUEST_LINE_LEN {
            return None;
        }

        let mut parts = request_line.splitn(3, ' ');
        let method = parts.next()?.to_string();
        let raw_path = parts.next()?.to_string();
        // HTTP version is optional for robustness

        let (path, query) = if let Some(idx) = raw_path.find('?') {
            (
                raw_path[..idx].to_string(),
                Some(raw_path[idx + 1..].to_string()),
            )
        } else {
            (raw_path, None)
        };

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }

        let content_length: usize = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);

        let body_to_read = content_length.min(MAX_BODY_CAPTURE);
        let mut body = Vec::new();
        if body_to_read > 0 {
            // Drain what we already have in the buffer from a pipelined read
            let from_buf = body_to_read.min(self.buf.len());
            body.extend_from_slice(&self.buf[..from_buf]);
            self.buf.drain(..from_buf);

            while body.len() < body_to_read {
                if self.fill(stream).await.is_none() {
                    break;
                }
                let need = body_to_read - body.len();
                let take = need.min(self.buf.len());
                body.extend_from_slice(&self.buf[..take]);
                self.buf.drain(..take);
            }
        }

        Some(HttpRequest {
            method,
            path,
            query,
            headers,
            body,
        })
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_event_is_unauthenticated_with_http_label() {
        let event = connection_event("203.0.113.7".parse().unwrap(), None, Uuid::now_v7());
        assert!(!event.authenticated);
        assert_eq!(event.sensor, "http");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert_eq!(event.protocol, PROTO_TCP);
        assert_eq!(
            event
                .metadata
                .get("protocol_label")
                .and_then(|v| v.as_str()),
            Some("http")
        );
    }

    #[test]
    fn find_header_end_finds_double_crlf() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\n"), Some(14));
        assert_eq!(find_header_end(b"no terminator"), None);
        assert_eq!(find_header_end(b"\r\n\r\n"), Some(0));
    }
}
