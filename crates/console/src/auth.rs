//! Password hashing, session management, CSRF tokens, login rate limiting, and the session-gate
//! middleware for the operator console (`internal/design/06-console-observability.md`,
//! "Authentication"). Everything here is deliberately synchronous, in-process state: this is a
//! single-operator console, so there is no session table and no multi-instance coordination, and a
//! restart clears every session by design.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::extract::{Request, State};
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
pub struct PasswordStore {
    hash: String,
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
        Self { hash }
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

    fn sign(&self, id: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts a key of any length");
        mac.update(id.as_bytes());
        let tag = mac.finalize().into_bytes();
        format!("{id}.{}", hex::encode(tag))
    }
}

/// Sliding-window rate limiter for login attempts, keyed by source IP
/// (`internal/design/06-console-observability.md`, "Rate limiting": 5/min, reset on success).
pub struct RateLimiter {
    attempts: RwLock<HashMap<IpAddr, VecDeque<Instant>>>,
    max_attempts: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            attempts: RwLock::new(HashMap::new()),
            max_attempts,
            window,
        }
    }

    /// Records an attempt from `ip` and reports whether it is allowed. A blocked attempt is not
    /// itself recorded, so a burst of rejected retries cannot extend the window past the original
    /// `max_attempts` attempts within it.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut attempts = self.attempts.write().unwrap();
        let entry = attempts.entry(ip).or_default();
        entry.retain(|&t| now.duration_since(t) < self.window);
        if entry.len() >= self.max_attempts {
            false
        } else {
            entry.push_back(now);
            true
        }
    }

    /// Clears `ip`'s attempt history. Called on successful login.
    pub fn reset(&self, ip: IpAddr) {
        self.attempts.write().unwrap().remove(&ip);
    }
}

impl Default for RateLimiter {
    /// The spec's default: 5 attempts per minute per source IP.
    fn default() -> Self {
        Self::new(5, Duration::from_secs(60))
    }
}

/// Rejects any request without a valid session cookie, redirecting to `/login`. Applied only to
/// the router's protected route group via `Router::route_layer` (see `routes` module) rather than
/// exempting `/health`, `/ready`, and `/login` by path-matching inside this function - those three
/// are simply mounted outside the layer this wraps.
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
        None => Redirect::to("/login").into_response(),
    }
}
