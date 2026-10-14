use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::session_memory::{self, AccountRef};
use sensor_framework::{ConnectionBounds, EventEmitter, Uuid, WanResolver};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SensorEvent, WIRE_VERSION,
};

use crate::redact;

const PROTOCOL_LABEL: &str = "http";

const MAX_REQUEST_LINE_LEN: usize = 8192;
/// The request line and header lines together, their ending blank line included. A block that has
/// not ended by then is answered as nginx answers a header past its buffers.
const MAX_HEADER_BLOCK: usize = 16384;
const MAX_BODY_CAPTURE: usize = 65536;
const READ_CHUNK_SIZE: usize = 4096;
/// nginx's default `client_max_body_size` (1m): a larger declared body is refused with 413 before
/// any of it is read, as nginx does.
const NGINX_MAX_BODY: usize = 1_048_576;

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

/// nginx's generated 413 page (a request body over `client_max_body_size`).
const NGINX_413_HTML: &str = "<html>
<head><title>413 Request Entity Too Large</title></head>
<body>
<center><h1>413 Request Entity Too Large</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
";

/// nginx's page for a header block larger than its header buffers (its internal status 494,
/// sent as `400 Bad Request`).
const NGINX_494_HTML: &str = "<html>
<head><title>400 Request Header Or Cookie Too Large</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<center>Request Header Or Cookie Too Large</center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
";

// Eight parameters: the stream plus the per-connection context every sensor handler takes;
// bundling them would diverge from the uniform handler shape the sibling sensors share.
#[allow(clippy::too_many_arguments)]
pub async fn handle_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    tls: bool,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // A session the sensor could not account would hold whatever it liked: refuse it instead.
    if session_memory::unaccounted_session() {
        return;
    }
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = local_addr
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    let conn_event = connection_event(source_ip, wan_ip, session_id, tls);
    if emitter.append(&conn_event).await.is_err() {
        tracing::error!(%peer_addr, "http: failed to append connection event");
    }

    let mut reader = BoundedReader::new(bounds);
    let request = match reader.read_request(&mut stream).await {
        ReadOutcome::Request(request) => request,
        ReadOutcome::HeaderTooLarge => {
            let response =
                error_response("400 Bad Request", NGINX_494_HTML, &http_date_now(), false);
            let _ = stream.write_all(&response).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return;
        }
        ReadOutcome::Closed => return,
    };
    drop(reader);

    {
        // Credentials are cut out before the sanitizer and the caps: every value under a
        // password-like name, the Authorization/Proxy-Authorization credentials, every cookie
        // value, a userinfo password in the target (docs/security/sample-and-credential-privacy.md
        // states what the textual scanners do and do not promise). The flag is absent, not false,
        // when nothing was replaced, so credential-free events stay byte-identical.
        let mut credentials_redacted = false;
        let method = sanitize_value(&request.method(), 16);
        let raw_path = request.path();
        let kept = redact::redact_target(&raw_path).inspect(|_| credentials_redacted = true);
        let path = sanitize_value(kept.as_deref().unwrap_or(&raw_path), 2048);
        let user_agent = request
            .header("user-agent")
            .map(|v| sanitize_value(&v, 512))
            .unwrap_or_default();
        let host = request
            .header("host")
            .map(|v| sanitize_value(&v, 255))
            .unwrap_or_default();

        let mut metadata = serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "method": method,
            "path": path,
        });
        if !user_agent.is_empty() {
            // Display annotation only: the header is attacker-controlled, so this label never
            // feeds scoring or exclusion (see `crawler`).
            if let Some(label) = crate::crawler::claimed_crawler(&user_agent) {
                metadata["claimed_crawler"] = serde_json::Value::String(label.to_string());
            }
            metadata["user_agent"] = serde_json::Value::String(user_agent);
        }
        if !host.is_empty() {
            metadata["host"] = serde_json::Value::String(host);
        }
        if let Some(query) = request.query() {
            let kept = redact::redact_form(&query).inspect(|_| credentials_redacted = true);
            metadata["query"] =
                serde_json::Value::String(sanitize_value(kept.as_deref().unwrap_or(&query), 2048));
        }
        for (header, scheme_key, username_key) in [
            ("authorization", "auth_scheme", "auth_username"),
            (
                "proxy-authorization",
                "proxy_auth_scheme",
                "proxy_auth_username",
            ),
        ] {
            let Some(value) = request.header(header) else {
                continue;
            };
            let Some(auth) = redact::redact_authorization(&value) else {
                continue;
            };
            credentials_redacted |= auth.credential_dropped;
            metadata[scheme_key] = serde_json::Value::String(sanitize_value(&auth.scheme, 32));
            if let Some(username) = auth.username {
                metadata[username_key] = serde_json::Value::String(sanitize_value(&username, 255));
            }
        }
        if let Some(cookie) = request.header("cookie") {
            let kept = redact::redact_cookie(&cookie).inspect(|_| credentials_redacted = true);
            metadata["cookie"] =
                serde_json::Value::String(sanitize_value(kept.as_deref().unwrap_or(&cookie), 2048));
        }
        if request.body_declared > 0 {
            metadata["body_size"] = serde_json::Value::Number(request.body_received.into());
            metadata["body_declared"] = serde_json::Value::Number(request.body_declared.into());
            metadata["body_complete"] =
                serde_json::Value::Bool(request.body_received == request.body_declared);
            metadata["truncated"] =
                serde_json::Value::Bool(request.body_received > request.body.len());
        }
        if !request.body.is_empty() {
            let body = String::from_utf8_lossy(&request.body);
            let kept = redact::redact_body(&body, request.header("content-type").as_deref())
                .inspect(|_| credentials_redacted = true);
            let body_preview =
                sanitize_value(kept.as_deref().unwrap_or(&body), MAX_BODY_CAPTURE.min(4096));
            metadata["body_preview"] = serde_json::Value::String(body_preview);
        }
        if credentials_redacted {
            metadata["credentials_redacted"] = serde_json::Value::Bool(true);
        }
        if tls {
            metadata["tls"] = serde_json::Value::Bool(true);
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
            occurrence_id: None,
            reply: None,
        };

        // A body the client never finished sending is not a request nginx answers: it logs the
        // premature close and drops the connection. Answering it (and the old handler did, with
        // whatever had arrived counted as the whole body) treated a partial read as a request.
        let response = if request.body_declared > NGINX_MAX_BODY {
            Some(error_response(
                "413 Request Entity Too Large",
                NGINX_413_HTML,
                &http_date_now(),
                false,
            ))
        } else if request.body_received < request.body_declared {
            None
        } else {
            Some(build_response(&request.method(), &request.path()))
        };
        // The header block and the body are in the event now; they are not held while it is
        // written or the reply is sent.
        drop(request);

        if emitter.append(&event).await.is_err() {
            tracing::error!(%peer_addr, "http: failed to append request event");
        }
        let Some(response) = response else {
            return;
        };
        let _ = stream.write_all(&response).await;
        let _ = stream.flush().await;
        // Over TLS this sends close_notify as nginx does; without it a real client logs an
        // unexpected EOF, a tell. On plain TCP it is a FIN just before the drop.
        let _ = stream.shutdown().await;
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

/// An nginx error response (400/404/405/413): the generated HTML page with Server/Date and no static-file
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

fn connection_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    tls: bool,
) -> SensorEvent {
    // The key is absent (not false) on the plain path so plain events stay byte-identical.
    let mut metadata = serde_json::json!({ "protocol_label": PROTOCOL_LABEL });
    if tls {
        metadata["tls"] = serde_json::Value::Bool(true);
    }
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata,
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
        reply: None,
    }
}

/// What [`BoundedReader::read_request`] ends with.
enum ReadOutcome {
    Request(HttpRequest),
    /// The header block had not ended within `MAX_HEADER_BLOCK` bytes.
    HeaderTooLarge,
    /// Nothing to answer: the client left, went quiet, sent no usable request line, or its
    /// session was ended.
    Closed,
}

struct HttpRequest {
    /// The request line and the header lines as received, without the blank line that ends
    /// them. Every field is read out of it when it is asked for, so a request holds its header
    /// block once and nothing per line: a block of thousands of empty `:` lines costs its bytes,
    /// not a table entry each.
    head: Vec<u8>,
    /// `head[..method_end]` is the method.
    method_end: usize,
    /// The request target (path and query) within `head`.
    target: Range<usize>,
    /// The body up to `MAX_BODY_CAPTURE` bytes.
    body: Vec<u8>,
    /// The Content-Length the client declared (zero when absent).
    body_declared: usize,
    /// Body bytes that actually arrived, kept or not. Less than `body_declared` when the
    /// client stopped early; then the request is incomplete. Zero when the declared size
    /// exceeds what the server accepts, since nothing is read.
    body_received: usize,
}

impl HttpRequest {
    /// Read the request line out of `head`: a method, a space, a target, then optionally a space
    /// and the version. `None` for a line over `MAX_REQUEST_LINE_LEN` or without a target.
    fn parse(head: Vec<u8>) -> Option<HttpRequest> {
        let line_end = find_crlf(&head).unwrap_or(head.len());
        if line_end > MAX_REQUEST_LINE_LEN {
            return None;
        }
        let line = &head[..line_end];
        let method_end = line.iter().position(|&b| b == b' ')?;
        let target_start = method_end + 1;
        let target_end = line[target_start..]
            .iter()
            .position(|&b| b == b' ')
            .map_or(line_end, |at| target_start + at);
        Some(HttpRequest {
            method_end,
            target: target_start..target_end,
            head,
            body: Vec::new(),
            body_declared: 0,
            body_received: 0,
        })
    }

    fn method(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.head[..self.method_end])
    }

    fn target(&self) -> &[u8] {
        &self.head[self.target.clone()]
    }

    /// The target up to its first `?`.
    fn path(&self) -> Cow<'_, str> {
        let target = self.target();
        let end = target
            .iter()
            .position(|&b| b == b'?')
            .unwrap_or(target.len());
        String::from_utf8_lossy(&target[..end])
    }

    /// The target after its first `?`, when it has one.
    fn query(&self) -> Option<Cow<'_, str>> {
        let target = self.target();
        let at = target.iter().position(|&b| b == b'?')?;
        Some(String::from_utf8_lossy(&target[at + 1..]))
    }

    /// The first header named `name` (ASCII case-insensitive), its value trimmed. A line without
    /// a `:` is skipped, as before.
    fn header(&self, name: &str) -> Option<Cow<'_, str>> {
        let line_end = find_crlf(&self.head)?;
        crlf_lines(&self.head[line_end + 2..])
            .take_while(|line| !line.is_empty())
            .find_map(|line| {
                let colon = line.iter().position(|&b| b == b':')?;
                String::from_utf8_lossy(&line[..colon])
                    .trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| match String::from_utf8_lossy(&line[colon + 1..]) {
                        Cow::Borrowed(value) => Cow::Borrowed(value.trim()),
                        Cow::Owned(value) => Cow::Owned(value.trim().to_string()),
                    })
            })
    }
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|w| w == b"\r\n")
}

/// `bytes` split at each CRLF, the last piece included.
fn crlf_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(bytes);
    std::iter::from_fn(move || {
        let current = rest?;
        match find_crlf(current) {
            Some(at) => {
                rest = Some(&current[at + 2..]);
                Some(&current[..at])
            }
            None => {
                rest = None;
                Some(current)
            }
        }
    })
}

/// Make room for `additional` more bytes without letting the capacity pass `cap`: doubling as
/// `Vec` does, so many small reads do not each copy the buffer, but never past the cap, so the
/// header buffer holds at most `MAX_HEADER_BLOCK` bytes however its reads arrive.
fn reserve_within(buf: &mut Vec<u8>, additional: usize, cap: usize) {
    let needed = buf.len() + additional;
    if needed > buf.capacity() {
        let target = buf
            .capacity()
            .saturating_mul(2)
            .clamp(needed, cap.max(needed));
        buf.reserve_exact(target - buf.len());
    }
}

struct BoundedReader {
    buf: Vec<u8>,
    bounds: ConnectionBounds,
    first_read: bool,
    total_captured: u64,
    /// This session's memory account, while the sensor accounts sessions.
    account: Option<AccountRef>,
}

impl BoundedReader {
    fn new(bounds: ConnectionBounds) -> Self {
        Self {
            buf: Vec::new(),
            bounds,
            first_read: true,
            total_captured: 0,
            account: session_memory::current_account(),
        }
    }

    /// One read of at most `into.len()` bytes into `into`. `None` once the session's byte budget
    /// is spent, the session memory pool asks it to let go, or the read fails, times out or finds
    /// the stream closed.
    async fn read_some<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
        into: &mut [u8],
    ) -> Option<usize> {
        if self.total_captured >= self.bounds.max_captured_bytes {
            return None;
        }
        // Between reads: over what a session may keep, or asked to let go.
        if self.account.is_some_and(|a| a.check_retained()) {
            return None;
        }
        let timeout = if self.first_read {
            self.bounds.read_timeout
        } else {
            self.bounds.idle_timeout
        };
        self.first_read = false;

        // A session asked to let go while it waits for its peer's next bytes ends now, not at
        // its read timeout.
        let read = tokio::select! {
            read = tokio::time::timeout(timeout, stream.read(into)) => read,
            () = session_memory::evicted(self.account) => return None,
        };
        match read {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => None,
            Ok(Ok(n)) => {
                self.total_captured += n as u64;
                Some(n)
            }
        }
    }

    async fn read_request<S: AsyncRead + Unpin>(&mut self, stream: &mut S) -> ReadOutcome {
        let header_end = match self.read_header_block(stream).await {
            Ok(end) => end,
            Err(outcome) => return outcome,
        };
        let Some(request) = HttpRequest::parse(self.buf[..header_end].to_vec()) else {
            return ReadOutcome::Closed;
        };
        ReadOutcome::Request(self.read_body(request, header_end + 4, stream).await)
    }

    /// Read until the blank line that ends the header block, never holding more than
    /// `MAX_HEADER_BLOCK` bytes: the offset of that blank line's CRLF CRLF, or how the read
    /// ended without one.
    async fn read_header_block<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
    ) -> Result<usize, ReadOutcome> {
        let mut chunk = [0u8; READ_CHUNK_SIZE];
        let mut scanned = 0;
        loop {
            if let Some(end) = find_header_end(&self.buf, scanned) {
                return Ok(end);
            }
            // The terminator may straddle the next read; everything before this was searched.
            scanned = self.buf.len().saturating_sub(3);
            let room = MAX_HEADER_BLOCK - self.buf.len();
            if room == 0 {
                return Err(ReadOutcome::HeaderTooLarge);
            }
            let want = room.min(READ_CHUNK_SIZE);
            let Some(n) = self.read_some(stream, &mut chunk[..want]).await else {
                return Err(ReadOutcome::Closed);
            };
            reserve_within(&mut self.buf, n, MAX_HEADER_BLOCK);
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read the whole declared body, keeping the first MAX_BODY_CAPTURE bytes and draining the
    /// rest, so the reply follows the body the way a server's does; the old reader stopped at
    /// the capture cap and answered with the remainder still in flight. A body over what nginx
    /// accepts is not read at all: the 413 goes out first. The session's byte budget still
    /// bounds the drain; a body it cuts off counts as incomplete. `body_start` is where the body
    /// begins in the header buffer, which may already hold its first bytes.
    async fn read_body<S: AsyncRead + Unpin>(
        &mut self,
        mut request: HttpRequest,
        body_start: usize,
        stream: &mut S,
    ) -> HttpRequest {
        let content_length: usize = request
            .header("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        request.body_declared = content_length;
        if content_length > NGINX_MAX_BODY {
            self.buf = Vec::new();
            return request;
        }

        // Sized once for what is kept, so the capture never grows past it.
        let keep_cap = content_length.min(MAX_BODY_CAPTURE);
        let mut body = Vec::with_capacity(keep_cap);
        let arrived = &self.buf[body_start..];
        let mut received = content_length.min(arrived.len());
        body.extend_from_slice(&arrived[..received.min(keep_cap)]);
        // The header buffer is done with; the rest of the body is read a chunk at a time.
        self.buf = Vec::new();

        let mut chunk = [0u8; READ_CHUNK_SIZE];
        while received < content_length {
            let want = (content_length - received).min(READ_CHUNK_SIZE);
            let Some(n) = self.read_some(stream, &mut chunk[..want]).await else {
                break;
            };
            let keep = (keep_cap - body.len()).min(n);
            body.extend_from_slice(&chunk[..keep]);
            received += n;
        }
        request.body = body;
        request.body_received = received;
        request
    }
}

/// The offset of the first CRLF CRLF in `buf` at or after `from`.
fn find_header_end(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| from + at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_event_is_unauthenticated_with_http_label() {
        let event = connection_event("203.0.113.7".parse().unwrap(), None, Uuid::now_v7(), false);
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
    fn connection_event_marks_tls_only_when_tls() {
        let plain = connection_event("203.0.113.7".parse().unwrap(), None, Uuid::now_v7(), false);
        assert!(plain.metadata.get("tls").is_none());
        let tls = connection_event("203.0.113.7".parse().unwrap(), None, Uuid::now_v7(), true);
        assert_eq!(
            tls.metadata.get("tls").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            tls.metadata.get("protocol_label").and_then(|v| v.as_str()),
            Some("http")
        );
    }

    #[test]
    fn find_header_end_finds_double_crlf() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\n", 0), Some(14));
        assert_eq!(find_header_end(b"no terminator", 0), None);
        assert_eq!(find_header_end(b"\r\n\r\n", 0), Some(0));
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\n\r\n", 11),
            Some(14),
            "a terminator that straddles the previous read is still found"
        );
        assert_eq!(find_header_end(b"\r\n\r\n", 5), None);
    }

    #[test]
    fn the_header_buffer_doubles_but_never_past_its_cap() {
        let mut buf = Vec::new();
        for _ in 0..MAX_HEADER_BLOCK {
            reserve_within(&mut buf, 1, MAX_HEADER_BLOCK);
            buf.push(b':');
            assert!(buf.capacity() <= MAX_HEADER_BLOCK, "{}", buf.capacity());
        }
        assert_eq!(buf.capacity(), MAX_HEADER_BLOCK);
    }

    fn parsed(head: &str) -> HttpRequest {
        HttpRequest::parse(head.as_bytes().to_vec()).expect("a request line")
    }

    #[test]
    fn request_line_fields_read_as_before() {
        let r = parsed("GET /a/b?x=1?y HTTP/1.1\r\nHost: h");
        assert_eq!(r.method(), "GET");
        assert_eq!(r.path(), "/a/b");
        assert_eq!(r.query().as_deref(), Some("x=1?y"));
        let r = parsed("GET /");
        assert_eq!((r.path(), r.query()), ("/".into(), None));
        assert!(HttpRequest::parse(b"GET".to_vec()).is_none(), "no target");
        let long = format!("GET /{} HTTP/1.1", "a".repeat(MAX_REQUEST_LINE_LEN));
        assert!(HttpRequest::parse(long.into_bytes()).is_none());
    }

    #[test]
    fn headers_are_found_by_name_first_match_trimmed_and_lines_without_a_colon_skipped() {
        let r = parsed(
            "GET / HTTP/1.1\r\n:\r\nnot a header\r\n  User-Agent :  curl/8 \r\nuser-agent: second",
        );
        assert_eq!(r.header("user-agent").as_deref(), Some("curl/8"));
        assert_eq!(r.header("host"), None);
        assert_eq!(parsed("GET / HTTP/1.1").header("host"), None);
        let invalid = HttpRequest::parse(b"GET / HTTP/1.1\r\nX: a\xffb ".to_vec()).unwrap();
        assert_eq!(invalid.header("x").as_deref(), Some("a\u{fffd}b"));
    }
}
