use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{ConnectionBounds, EventEmitter, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SensorEvent, WIRE_VERSION,
};

const PROTOCOL_LABEL: &str = "http";

const MAX_REQUEST_LINE_LEN: usize = 8192;
const MAX_HEADER_BLOCK: usize = 16384;
const MAX_BODY_CAPTURE: usize = 65536;
const READ_CHUNK_SIZE: usize = 4096;

const RESPONSE_200_HTML: &str = "\
<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1><p>Server is running.</p></body></html>";

const RESPONSE_ROBOTS: &str = "User-agent: *\nDisallow: /\n";

pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
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

    let conn_event = connection_event(source_ip, wan_ip);
    if emitter.append(&conn_event).await.is_err() {
        tracing::error!(%peer_addr, "http: failed to append connection event");
    }

    let mut reader = BoundedReader::new(bounds);

    loop {
        let Some(request) = reader.read_request(&mut stream).await else {
            return;
        };

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
        };
        let _ = emitter.append(&event).await;

        let (status, content_type, body) = match request.path.as_str() {
            "/" => ("200 OK", "text/html", RESPONSE_200_HTML.as_bytes()),
            "/robots.txt" => ("200 OK", "text/plain", RESPONSE_ROBOTS.as_bytes()),
            _ => ("404 Not Found", "text/plain", b"Not Found" as &[u8]),
        };

        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        if stream.write_all(body).await.is_err() {
            return;
        }

        // HTTP/1.1 keep-alive is common; Connection: close tells the client we are done
        // after one request-response. Real scanners typically send one request per connection
        // anyway, and serving more than one would only add complexity with no intel gain.
        return;
    }
}

fn connection_event(source_ip: IpAddr, wan_ip: Option<IpAddr>) -> SensorEvent {
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
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
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

    async fn parse_request(&mut self, header_end: usize, stream: &mut TcpStream) -> Option<HttpRequest> {
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
            (raw_path[..idx].to_string(), Some(raw_path[idx + 1..].to_string()))
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
            .find(|(k, _)| k.to_ascii_lowercase() == "content-length")
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
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_event_is_unauthenticated_with_http_label() {
        let event = connection_event("203.0.113.7".parse().unwrap(), None);
        assert!(!event.authenticated);
        assert_eq!(event.sensor, "http");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert_eq!(event.protocol, PROTO_TCP);
        assert_eq!(
            event.metadata.get("protocol_label").and_then(|v| v.as_str()),
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
