//! The ntfy alert dispatcher for operational alerts. Mirrors the Guardian alert dispatcher's
//! discipline: fail-safe delivery (a send that exhausts retries returns `Err`, never silently
//! dropped), header-injection immunity (attacker-influenced content goes in the BODY; every header
//! value is sanitized), dedup with a per-key cooldown that permits re-post after it elapses (the
//! re-page mechanism), and a bounded dedup map so an unbounded set of keys cannot grow memory.
//!
//! The HTTP send is behind the `Poster` trait so the retry/dedup/sanitize logic is unit-testable
//! without a mock HTTP server (and without adding a dev-dependency): tests inject a recording poster.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::config::OpsAlertConfig;

const MAX_ATTEMPTS: u32 = 4;
const BASE_BACKOFF: Duration = Duration::from_millis(200);
const MAX_HEADER_LEN: usize = 200;
/// Bounds the dedup map against an unbounded set of condition keys over the daemon's runtime.
const MAX_DEDUP_ENTRIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Critical,
}

/// One operational alert to deliver. `title` is built from safe fields; `body` may carry
/// attacker-influenced telemetry (subsystem names, paths, vendor bodies) and is delivered as the
/// POST body only, never a header.
#[derive(Debug, Clone)]
pub struct OpsAlert {
    pub key: String,
    pub severity: Severity,
    pub title: String,
    pub body: String,
    pub recovered: bool,
}

/// A single outbound HTTP request, as the dispatcher composes it.
#[derive(Debug, Clone)]
pub struct PostReq {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug)]
pub enum PostErr {
    /// A transport-level failure (connection refused, timeout, TLS) - transient, retryable.
    Transport(String),
}

#[derive(Debug)]
pub enum DispatchError {
    /// Delivery failed after exhausting retries, or hit a permanent error. The caller MUST log this
    /// loudly - an ops alert that cannot be delivered is never silently dropped.
    Undelivered(String),
}

/// The HTTP transport. The real impl posts via reqwest; tests inject a recorder.
pub trait Poster: Send + Sync {
    fn post(&self, req: PostReq) -> impl std::future::Future<Output = Result<u16, PostErr>> + Send;
}

/// The production poster: reqwest over the already-vetted rustls stack.
pub struct ReqwestPoster {
    client: reqwest::Client,
}

impl ReqwestPoster {
    pub fn new() -> Result<Self, DispatchError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| DispatchError::Undelivered(format!("http client build failed: {e}")))?;
        Ok(Self { client })
    }
}

impl Poster for ReqwestPoster {
    async fn post(&self, req: PostReq) -> Result<u16, PostErr> {
        let mut rb = self.client.post(&req.url).body(req.body);
        for (k, v) in &req.headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        match rb.send().await {
            Ok(resp) => Ok(resp.status().as_u16()),
            Err(e) => Err(PostErr::Transport(e.to_string())),
        }
    }
}

/// Strip every ASCII control character (this removes CR and LF, the header-line terminators, and
/// NUL/DEL) and cap the length, so no attacker-influenced value placed in a header can inject a new
/// header or split the request.
fn sanitize_header(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_ascii_control())
        .take(MAX_HEADER_LEN)
        .collect()
}

fn priority(severity: Severity, recovered: bool) -> u8 {
    if recovered {
        2
    } else {
        match severity {
            Severity::Critical => 5,
            Severity::Warning => 3,
        }
    }
}

pub struct Dispatcher<P: Poster> {
    poster: P,
    topic_url: String,
    token: Option<String>,
    cooldown: Duration,
    last_sent: Mutex<HashMap<String, Instant>>,
}

impl Dispatcher<ReqwestPoster> {
    /// Build the production dispatcher from config. The topic URL is `{ntfy_url}/{topic}`.
    pub fn new(cfg: &OpsAlertConfig) -> Result<Self, DispatchError> {
        Ok(Self::with_poster(
            ReqwestPoster::new()?,
            &cfg.ntfy_url,
            &cfg.ntfy_topic,
            cfg.ntfy_token.clone(),
            cfg.repage_cooldown,
        ))
    }
}

impl<P: Poster> Dispatcher<P> {
    pub fn with_poster(
        poster: P,
        ntfy_url: &str,
        topic: &str,
        token: Option<String>,
        cooldown: Duration,
    ) -> Self {
        let topic_url = format!("{}/{}", ntfy_url.trim_end_matches('/'), topic);
        Self {
            poster,
            topic_url,
            token,
            cooldown,
            last_sent: Mutex::new(HashMap::new()),
        }
    }

    fn build_request(&self, alert: &OpsAlert) -> PostReq {
        let title = if alert.recovered {
            format!("[recovered] {}", alert.title)
        } else {
            alert.title.clone()
        };
        let mut headers = vec![
            ("X-Title".to_string(), sanitize_header(&title)),
            (
                "X-Priority".to_string(),
                priority(alert.severity, alert.recovered).to_string(),
            ),
            (
                "X-Tags".to_string(),
                sanitize_header(if alert.recovered {
                    "white_check_mark"
                } else {
                    "rotating_light"
                }),
            ),
        ];
        if let Some(token) = &self.token {
            headers.push(("Authorization".to_string(), format!("Bearer {token}")));
        }
        PostReq {
            url: self.topic_url.clone(),
            headers,
            // Untrusted content, body only, never sanitized-away (the body is not header-parsed).
            body: alert.body.clone(),
        }
    }

    async fn send_with_retry(&self, req: PostReq) -> Result<(), DispatchError> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self.poster.post(req.clone()).await {
                Ok(code) if (200..300).contains(&code) => return Ok(()),
                // 429 / 5xx / transport error: transient, retry within the attempt budget.
                Ok(code) if code == 429 || (500..600).contains(&code) => {
                    if attempt >= MAX_ATTEMPTS {
                        return Err(DispatchError::Undelivered(format!(
                            "ntfy returned {code} after {MAX_ATTEMPTS} attempts"
                        )));
                    }
                }
                Err(PostErr::Transport(e)) => {
                    if attempt >= MAX_ATTEMPTS {
                        return Err(DispatchError::Undelivered(format!(
                            "ntfy transport error after {MAX_ATTEMPTS} attempts: {e}"
                        )));
                    }
                }
                // Any other non-2xx (400/401/404 ...) is a permanent config error: do not retry.
                Ok(code) => {
                    return Err(DispatchError::Undelivered(format!(
                        "ntfy returned a permanent {code}"
                    )));
                }
            }
            // Exponential backoff. No jitter: there is a single ops-monitor sender, so there is no
            // thundering herd to spread.
            let backoff = BASE_BACKOFF * 2u32.pow(attempt - 1);
            tokio::time::sleep(backoff).await;
        }
    }

    fn evict_if_full(map: &mut HashMap<String, Instant>, now: Instant) {
        if map.len() < MAX_DEDUP_ENTRIES {
            return;
        }
        // Evict the oldest-by-Instant entry; it is the one most likely already past its cooldown.
        if let Some(oldest) = map
            .iter()
            .min_by_key(|entry| *entry.1)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
        let _ = now;
    }

    /// Deliver `alert`. A non-recovered alert whose key was successfully delivered within the
    /// cooldown is suppressed (returns Ok). A recovered notice is always delivered. On a delivery
    /// failure returns `Err` so the caller escalates - never silently dropped.
    pub async fn dispatch(&self, alert: OpsAlert, now: Instant) -> Result<(), DispatchError> {
        if !alert.recovered {
            let suppressed = {
                let map = self.last_sent.lock().unwrap_or_else(|p| p.into_inner());
                matches!(map.get(&alert.key), Some(t) if now.duration_since(*t) < self.cooldown)
            };
            if suppressed {
                return Ok(());
            }
        }

        let req = self.build_request(&alert);
        self.send_with_retry(req).await?;

        // Only a SUCCESSFUL send of a non-recovered alert arms the cooldown.
        if !alert.recovered {
            let mut map = self.last_sent.lock().unwrap_or_else(|p| p.into_inner());
            Self::evict_if_full(&mut map, now);
            map.insert(alert.key, now);
        }
        Ok(())
    }

    /// Drop dedup entries whose cooldown has fully elapsed. The monitor's ticker calls this.
    pub fn prune_expired(&self, now: Instant) {
        let mut map = self.last_sent.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, t| now.duration_since(*t) < self.cooldown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    /// Records every request and returns queued status codes (default 200), for asserting the
    /// dispatcher's logic without a real server.
    struct Recorder {
        sent: StdMutex<Vec<PostReq>>,
        responses: StdMutex<VecDeque<Result<u16, ()>>>,
    }
    impl Recorder {
        fn new() -> Self {
            Self {
                sent: StdMutex::new(Vec::new()),
                responses: StdMutex::new(VecDeque::new()),
            }
        }
        fn with_responses(codes: &[u16]) -> Self {
            let r = Self::new();
            *r.responses.lock().unwrap() = codes.iter().map(|c| Ok(*c)).collect();
            r
        }
        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }
    impl Poster for &Recorder {
        async fn post(&self, req: PostReq) -> Result<u16, PostErr> {
            self.sent.lock().unwrap().push(req);
            match self.responses.lock().unwrap().pop_front() {
                Some(Ok(code)) => Ok(code),
                Some(Err(())) => Err(PostErr::Transport("stub".into())),
                None => Ok(200),
            }
        }
    }

    fn alert(key: &str) -> OpsAlert {
        OpsAlert {
            key: key.into(),
            severity: Severity::Critical,
            title: "db near full".into(),
            body: "free 4%".into(),
            recovered: false,
        }
    }

    fn dispatcher(rec: &Recorder, cooldown_secs: u64) -> Dispatcher<&Recorder> {
        Dispatcher::with_poster(
            rec,
            "https://ntfy.example",
            "propolis-ops",
            None,
            Duration::from_secs(cooldown_secs),
        )
    }

    #[tokio::test]
    async fn a_firing_alert_posts_once_at_the_mapped_priority() {
        let rec = Recorder::new();
        let d = dispatcher(&rec, 300);
        d.dispatch(alert("capacity"), Instant::now()).await.unwrap();
        assert_eq!(rec.count(), 1);
        let req = &rec.sent.lock().unwrap()[0];
        assert_eq!(req.url, "https://ntfy.example/propolis-ops");
        let pri = req.headers.iter().find(|(k, _)| k == "X-Priority").unwrap();
        assert_eq!(pri.1, "5"); // Critical
    }

    #[tokio::test]
    async fn a_duplicate_within_cooldown_is_suppressed_then_reposts_after() {
        let rec = Recorder::new();
        let d = dispatcher(&rec, 300);
        let base = Instant::now();
        d.dispatch(alert("capacity"), base).await.unwrap();
        d.dispatch(alert("capacity"), base + Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(rec.count(), 1, "suppressed within cooldown");
        d.dispatch(alert("capacity"), base + Duration::from_secs(301))
            .await
            .unwrap();
        assert_eq!(rec.count(), 2, "reposts after the cooldown");
    }

    #[tokio::test]
    async fn a_recovered_notice_always_posts_and_does_not_arm_the_cooldown() {
        let rec = Recorder::new();
        let d = dispatcher(&rec, 300);
        let mut a = alert("capacity");
        a.recovered = true;
        let base = Instant::now();
        d.dispatch(a.clone(), base).await.unwrap();
        d.dispatch(a, base + Duration::from_secs(1)).await.unwrap();
        assert_eq!(rec.count(), 2, "recovered notices are never deduped");
    }

    #[tokio::test]
    async fn a_persistent_500_is_retried_then_surfaced_as_err() {
        let rec = Recorder::with_responses(&[500, 500, 500, 500]);
        let d = dispatcher(&rec, 300);
        let err = d.dispatch(alert("capacity"), Instant::now()).await;
        assert!(matches!(err, Err(DispatchError::Undelivered(_))));
        assert_eq!(rec.count(), MAX_ATTEMPTS as usize);
    }

    #[tokio::test]
    async fn attacker_content_never_injects_a_header() {
        let rec = Recorder::new();
        let d = dispatcher(&rec, 300);
        let mut a = alert("capacity");
        a.title = "ok\r\nX-Priority: 1\r\n\0evil".into();
        a.body = "path=/tmp/x\r\nX-Tags: spoof".into();
        d.dispatch(a, Instant::now()).await.unwrap();
        let req = &rec.sent.lock().unwrap()[0];
        for (_, v) in &req.headers {
            assert!(!v.contains('\r') && !v.contains('\n') && !v.contains('\0'));
        }
        // The attacker's fake "X-Priority: 1" is inert text inside X-Title (no CRLF to make it a
        // separate header line): there is exactly one real X-Priority header and it is the true 5.
        let priorities: Vec<&String> = req
            .headers
            .iter()
            .filter(|(k, _)| k == "X-Priority")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(priorities, vec![&"5".to_string()]);
        assert!(req.body.contains("X-Tags: spoof")); // untrusted content survives in the body
    }

    #[tokio::test]
    async fn the_dedup_map_stays_bounded() {
        let rec = Recorder::new();
        let d = dispatcher(&rec, 3600);
        let base = Instant::now();
        for i in 0..(MAX_DEDUP_ENTRIES + 50) {
            d.dispatch(
                alert(&format!("k{i}")),
                base + Duration::from_millis(i as u64),
            )
            .await
            .unwrap();
        }
        assert!(d.last_sent.lock().unwrap().len() <= MAX_DEDUP_ENTRIES);
    }
}
