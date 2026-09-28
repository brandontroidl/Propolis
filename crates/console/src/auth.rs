//! Password hashing, session management, CSRF tokens, login rate limiting, and the session-gate
//! middleware for the operator console (`internal/design/06-console-observability.md`,
//! "Authentication"). Everything here is in-process state: this is a single-operator console, so
//! there is no session table and no multi-instance coordination, and a restart clears every
//! session by design. The one asynchronous piece is [`PasswordStore::verify_bounded`], which moves
//! Argon2 off the async workers.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Name of the session cookie set on login and read on every subsequent request.
pub const SESSION_COOKIE: &str = "propolis_session";

/// The operator password, held only as an Argon2id hash
/// (`internal/design/06-console-observability.md`, "Password storage"). The plaintext passed to
/// [`PasswordStore::new`] is hashed and dropped immediately; only the PHC hash string is kept, and
/// only in memory - never written to disk or the database.
///
/// Verification is deliberately expensive (Argon2id), so login attempts are a CPU lever for
/// whoever can reach `/login`. [`Self::verify_bounded`] runs it on the blocking pool behind
/// [`MAX_CONCURRENT_VERIFICATIONS`] slots, so a spray from many addresses can occupy at most that
/// many threads and never an async worker the rest of the console (and, in the unified daemon,
/// every other subsystem) runs on.
pub struct PasswordStore {
    hash: String,
    verify_slots: tokio::sync::Semaphore,
    busy: AtomicU64,
}

/// Argon2 verifications allowed to run at once. One operator logs in rarely; two lets a login go
/// through while one other attempt is being checked, and bounds the CPU a spray can take.
pub const MAX_CONCURRENT_VERIFICATIONS: usize = 2;

/// How long an attempt waits for a verification slot before being answered "busy". Long enough
/// that a real login behind one or two in-flight checks succeeds; short enough that queued
/// attempts cannot pile up connections for minutes.
const VERIFY_SLOT_WAIT: Duration = Duration::from_secs(5);

/// The result of a bounded password check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordCheck {
    Match,
    Mismatch,
    /// No verification slot freed up in time; the attempt was not checked at all.
    Busy,
}

impl PasswordStore {
    /// Hashes `plaintext` with Argon2id (default params) and discards it.
    ///
    /// Panics if hashing fails. `argon2`'s own docs attribute failure here only to invalid
    /// parameters (never to the input being hashed), so this is a startup-time fail-fast on a
    /// misconfigured build, not a panic reachable from a request path.
    pub fn new(plaintext: &str) -> Self {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(plaintext.as_bytes(), &salt)
            .expect("argon2 hashing with default params should not fail")
            .to_string();
        Self {
            hash,
            verify_slots: tokio::sync::Semaphore::new(MAX_CONCURRENT_VERIFICATIONS),
            busy: AtomicU64::new(0),
        }
    }

    /// Verifies `attempt` off the async workers, at most [`MAX_CONCURRENT_VERIFICATIONS`] at a
    /// time. An attempt that cannot get a slot within the wait is answered [`PasswordCheck::Busy`]
    /// without being checked, and counted (see [`Self::busy_count`]).
    pub async fn verify_bounded(self: &Arc<Self>, attempt: String) -> PasswordCheck {
        let permit = match tokio::time::timeout(VERIFY_SLOT_WAIT, self.verify_slots.acquire()).await
        {
            Ok(Ok(permit)) => permit,
            _ => {
                self.busy.fetch_add(1, Ordering::Relaxed);
                return PasswordCheck::Busy;
            }
        };
        let store = Arc::clone(self);
        let matched = tokio::task::spawn_blocking(move || store.verify(&attempt))
            .await
            .unwrap_or(false);
        drop(permit);
        if matched {
            PasswordCheck::Match
        } else {
            PasswordCheck::Mismatch
        }
    }

    /// Attempts answered busy since startup, for `/metrics`.
    pub fn busy_count(&self) -> u64 {
        self.busy.load(Ordering::Relaxed)
    }

    /// Verifies `attempt` against the stored hash. Fails closed: a stored hash that fails to parse
    /// (never produced by [`Self::new`], but the input is still handled without panicking) counts
    /// as a non-match rather than propagating.
    pub fn verify(&self, attempt: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(&self.hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(attempt.as_bytes(), &parsed)
            .is_ok()
    }
}

/// A validated session, returned by value from [`SessionStore::validate`] so callers never hold
/// the store's internal lock past the lookup that produced it.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    csrf_token: Option<String>,
    expires_at: Instant,
}

const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// In-memory session store. A session cookie's value is `"{session_id}.{hmac_tag}"`, where the tag
/// is an HMAC-SHA256 of the session ID under a server-side secret
/// (`internal/design/06-console-observability.md`, "Sessions"). Verifying the tag before ever
/// touching `sessions` means a guessed or forged session ID is rejected without a map lookup, and
/// keeping the ID itself unencrypted (rather than, say, AEAD-sealing it) lets it double as the map
/// key with no separate decode step.
///
/// No session table: entries live only in `sessions` and vanish on restart - the accepted
/// trade-off for a single-operator console with no need to survive a restart mid-session.
pub struct SessionStore {
    sessions: RwLock<HashMap<String, Session>>,
    secret: [u8; 32],
    ttl: Duration,
}

impl SessionStore {
    /// Builds a store using the spec's default 24h session TTL.
    pub fn new(secret: [u8; 32]) -> Self {
        Self::with_ttl(secret, DEFAULT_SESSION_TTL)
    }

    /// Builds a store with an explicit TTL - the configurable half of the spec's `session_ttl`
    /// (`ConsoleConfig`), and how tests obtain a deterministically-expired session
    /// (`Duration::ZERO`) without sleeping: `expires_at` is then equal to `created_at`, and any
    /// later call to [`Self::validate`] observes a strictly later `Instant::now()`.
    pub fn with_ttl(secret: [u8; 32], ttl: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            secret,
            ttl,
        }
    }

    /// This store's configured session TTL. The login route uses it to set the session cookie's
    /// `Max-Age` so the client-side cookie lifetime matches the server-side one - otherwise the
    /// cookie would default to a browser-session-lifetime cookie, outliving or (more likely)
    /// disappearing well before the server actually expires the session.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Creates a new session and returns `(session_id, cookie_value)`. Cookie attributes
    /// (`HttpOnly`/`Secure`/`SameSite`/`Max-Age`) are the login route's concern, not this store's -
    /// this only produces the value that goes inside the cookie.
    pub fn create(&self) -> (String, String) {
        let id = hex::encode(rand::rng().random::<[u8; 32]>());
        let cookie_value = self.sign(&id);
        let session = Session {
            id: id.clone(),
            csrf_token: None,
            expires_at: Instant::now() + self.ttl,
        };
        self.sessions.write().unwrap().insert(id.clone(), session);
        (id, cookie_value)
    }

    /// Validates a cookie value produced by [`Self::create`]: checks the HMAC tag, then looks up
    /// the session and confirms it has not expired. An expired entry is evicted here - lazy
    /// cleanup, since a single operator's session count is never large enough to need a background
    /// sweep.
    pub fn validate(&self, cookie_value: &str) -> Option<Session> {
        let (id, tag_hex) = cookie_value.split_once('.')?;
        let tag = hex::decode(tag_hex).ok()?;
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
        mac.update(id.as_bytes());
        mac.verify_slice(&tag).ok()?;

        let mut sessions = self.sessions.write().unwrap();
        match sessions.get(id).cloned() {
            Some(session) if Instant::now() < session.expires_at => Some(session),
            Some(_) => {
                sessions.remove(id);
                None
            }
            None => None,
        }
    }

    /// Returns the session's CSRF token, generating one on first use and reusing it afterward so
    /// multiple concurrently-open forms stay valid against the same session. `None` if
    /// `session_id` names no active session.
    pub fn generate_csrf(&self, session_id: &str) -> Option<String> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions.get_mut(session_id)?;
        if session.csrf_token.is_none() {
            session.csrf_token = Some(hex::encode(rand::rng().random::<[u8; 32]>()));
        }
        session.csrf_token.clone()
    }

    /// Validates `token` against the session's stored CSRF token in constant time. `false` if the
    /// session does not exist or has no token generated yet.
    pub fn validate_csrf(&self, session_id: &str, token: &str) -> bool {
        let sessions = self.sessions.read().unwrap();
        let Some(stored) = sessions
            .get(session_id)
            .and_then(|s| s.csrf_token.as_deref())
        else {
            return false;
        };
        bool::from(stored.as_bytes().ct_eq(token.as_bytes()))
    }

    /// Removes `session_id` from the store, invalidating it immediately. Called on logout: clearing
    /// only the client-side cookie would leave a captured or previously-issued cookie value valid
    /// server-side until the session's TTL elapses on its own, which defeats the point of a
    /// "sign out" action. A no-op if `session_id` names no active session (already expired,
    /// already logged out, or never existed) - logout is idempotent by design.
    pub fn destroy(&self, session_id: &str) {
        self.sessions.write().unwrap().remove(session_id);
    }

    fn sign(&self, id: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
        mac.update(id.as_bytes());
        let tag = mac.finalize().into_bytes();
        format!("{id}.{}", hex::encode(tag))
    }
}

/// Sliding-window rate limiter for login attempts, keyed by source IP
/// (`internal/design/06-console-observability.md`, "Rate limiting": 5/min, reset on success),
/// plus a budget across all sources.
///
/// The per-IP window alone does not bound guessing: an attacker with many addresses gets five
/// guesses per minute from each. The global budget caps the total guesses per window whatever
/// their spread. The price is that a sustained spray can keep the operator from logging in until
/// it stops; that trade is deliberate for a single-password console, where the alternative is an
/// unbounded guessing rate. Both kinds of refusal are counted for `/metrics`, so a spray is
/// visible rather than looking like a quiet login page.
pub struct RateLimiter {
    attempts: RwLock<HashMap<IpAddr, VecDeque<Instant>>>,
    global: Mutex<VecDeque<Instant>>,
    max_attempts: usize,
    max_global_attempts: usize,
    window: Duration,
    refused_per_ip: AtomicU64,
    refused_global: AtomicU64,
}

/// Login attempts allowed across all sources per window by [`RateLimiter::default`]. Six times
/// the per-IP allowance: room for a few mistyped passwords from several places at once, far
/// below a useful guessing rate.
pub const DEFAULT_GLOBAL_LOGIN_ATTEMPTS: usize = 30;

impl RateLimiter {
    /// A limiter of `max_attempts` per IP per `window` and no effective global budget; see
    /// [`Self::with_global_limit`].
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            attempts: RwLock::new(HashMap::new()),
            global: Mutex::new(VecDeque::new()),
            max_attempts,
            max_global_attempts: usize::MAX,
            window,
            refused_per_ip: AtomicU64::new(0),
            refused_global: AtomicU64::new(0),
        }
    }

    /// Caps attempts across all sources to `max` per window.
    pub fn with_global_limit(mut self, max: usize) -> Self {
        self.max_global_attempts = max;
        self
    }

    /// Records an attempt from `ip` and reports whether it is allowed. A refused attempt is not
    /// recorded anywhere, so a burst of refused retries cannot extend either window, and an
    /// address that is refused never gains an entry in the per-IP map (which is therefore bounded
    /// by the global budget per window rather than by the number of addresses that try).
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut attempts = self.attempts.write().unwrap();

        if attempts.len() > 10_000 {
            attempts.retain(|_, v| {
                v.retain(|&t| now.duration_since(t) < self.window);
                !v.is_empty()
            });
        }

        if attempts.len() > 50_000 {
            self.refused_global.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let recent_from_ip = attempts.get_mut(&ip).map_or(0, |entry| {
            entry.retain(|&t| now.duration_since(t) < self.window);
            entry.len()
        });
        if recent_from_ip >= self.max_attempts {
            self.refused_per_ip.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let mut global = self.global.lock().unwrap();
        while global
            .front()
            .is_some_and(|&t| now.duration_since(t) >= self.window)
        {
            global.pop_front();
        }
        if global.len() >= self.max_global_attempts {
            self.refused_global.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        global.push_back(now);
        attempts.entry(ip).or_default().push_back(now);
        true
    }

    /// Clears `ip`'s attempt history. Called on successful login. The global window is not
    /// cleared: a success from one address says nothing about the attempts from others.
    pub fn reset(&self, ip: IpAddr) {
        self.attempts.write().unwrap().remove(&ip);
    }

    /// Attempts refused by the per-IP window since startup, for `/metrics`.
    pub fn refused_per_ip(&self) -> u64 {
        self.refused_per_ip.load(Ordering::Relaxed)
    }

    /// Attempts refused by the global budget (or the address-map backstop) since startup.
    pub fn refused_global(&self) -> u64 {
        self.refused_global.load(Ordering::Relaxed)
    }
}

impl Default for RateLimiter {
    /// The spec's default: 5 attempts per minute per source IP, plus
    /// [`DEFAULT_GLOBAL_LOGIN_ATTEMPTS`] per minute across all sources.
    fn default() -> Self {
        Self::new(5, Duration::from_secs(60)).with_global_limit(DEFAULT_GLOBAL_LOGIN_ATTEMPTS)
    }
}

/// Rejects any request without a valid session cookie, sending the operator to `/login`. Applied
/// only to the router's protected route group via `Router::route_layer` (see `routes` module)
/// rather than exempting `/health`, `/ready`, and `/login` by path-matching inside this function -
/// those three are simply mounted outside the layer this wraps.
///
/// An HTMX request gets `HX-Redirect` rather than a 303, and the difference is not cosmetic. A
/// browser XHR follows a 303 transparently, `/login` answers 200 with a WHOLE HTML document, and
/// HTMX swaps that document into whatever container issued the request - producing a page with
/// `<html>`, `<head>` and a second copy of every vendored script nested inside a `<div>`, showing
/// a login form wearing the previous page's chrome. Nothing about that response looks like an
/// error to HTMX, so a polling panel neither warns nor recovers; it just quietly stops being the
/// panel. This is the ordinary path after any restart, because sessions live in memory and a
/// restart clears them (see this module's own doc comment) while a polled page keeps polling.
///
/// `HX-Redirect` makes HTMX perform a real navigation instead. The vendored HTMX honours it
/// regardless of status (its response handler acts on the header before it decides whether to
/// swap), so the status stays a truthful 401 for anything that is not a browser.
pub async fn require_session(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Response {
    let session = jar
        .get(SESSION_COOKIE)
        .and_then(|cookie| state.sessions.validate(cookie.value()));

    match session {
        Some(session) => {
            request.extensions_mut().insert(session);
            next.run(request).await
        }
        // Set by HTMX on every request it issues; absent on an ordinary browser navigation.
        None if request.headers().contains_key("hx-request") => (
            StatusCode::UNAUTHORIZED,
            [("HX-Redirect", "/login")],
            // No body: a swappable one is the bug this arm exists to avoid.
            "",
        )
            .into_response(),
        None => Redirect::to("/login").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_verification_answers_match_and_mismatch() {
        let store = Arc::new(PasswordStore::new("right"));
        assert_eq!(
            store.verify_bounded("right".into()).await,
            PasswordCheck::Match
        );
        assert_eq!(
            store.verify_bounded("wrong".into()).await,
            PasswordCheck::Mismatch
        );
        assert_eq!(store.busy_count(), 0);
    }

    /// On a single-threaded runtime another task can run during a verification only if Argon2
    /// is off the runtime's worker. Run inline, the ticker would not advance at all while it ran.
    #[tokio::test(flavor = "current_thread")]
    async fn verification_does_not_occupy_the_async_worker() {
        let store = Arc::new(PasswordStore::new("right"));
        let ticks = Arc::new(AtomicU64::new(0));
        let ticker = {
            let ticks = Arc::clone(&ticks);
            tokio::spawn(async move {
                loop {
                    ticks.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            })
        };
        tokio::task::yield_now().await;

        let before = ticks.load(Ordering::Relaxed);
        assert_eq!(
            store.verify_bounded("wrong".into()).await,
            PasswordCheck::Mismatch
        );
        let during = ticks.load(Ordering::Relaxed) - before;
        ticker.abort();
        assert!(
            during > 0,
            "the runtime made no progress while a password was being verified"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_with_no_free_slot_is_answered_busy_and_counted() {
        let store = Arc::new(PasswordStore::new("right"));
        let _held = store
            .verify_slots
            .acquire_many(MAX_CONCURRENT_VERIFICATIONS as u32)
            .await
            .unwrap();
        // Paused time auto-advances past the slot wait once every task is idle.
        assert_eq!(
            store.verify_bounded("right".into()).await,
            PasswordCheck::Busy,
            "even the correct password is not checked when no slot frees up"
        );
        assert_eq!(store.busy_count(), 1);
    }

    #[test]
    fn the_global_budget_caps_attempts_spread_over_many_addresses() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60)).with_global_limit(3);
        for last in 1..=3u8 {
            assert!(limiter.check(IpAddr::from([192, 0, 2, last])));
        }
        assert!(
            !limiter.check(IpAddr::from([192, 0, 2, 4])),
            "a fourth address must be refused once the shared budget is spent"
        );
        assert_eq!(limiter.refused_global(), 1);
        assert_eq!(limiter.refused_per_ip(), 0);
        assert_eq!(
            limiter.attempts.read().unwrap().len(),
            3,
            "a refused address must not gain an entry in the per-address map"
        );
    }

    #[test]
    fn per_address_refusals_are_counted_separately_and_spend_no_global_budget() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60)).with_global_limit(3);
        let ip = IpAddr::from([198, 51, 100, 7]);
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip));
        assert_eq!(limiter.refused_per_ip(), 1);
        assert!(
            limiter.check(IpAddr::from([198, 51, 100, 8])),
            "the refused attempt must not have used the last global slot"
        );
    }

    #[test]
    fn the_default_limiter_has_a_global_budget() {
        let limiter = RateLimiter::default();
        let allowed = (0..=u8::MAX)
            .filter(|&n| limiter.check(IpAddr::from([203, 0, 113, n])))
            .count();
        assert_eq!(allowed, DEFAULT_GLOBAL_LOGIN_ATTEMPTS);
    }
}
