//! `GET /login` (render the password form) and `POST /login` (verify + create session + redirect),
//! per `internal/design/06-console-observability.md`'s "Pages" > "Login" and "Authentication" >
//! "Rate limiting". Mounted OUTSIDE the `protected` group in `routes::mod` - a login page cannot
//! itself require a session.
//!
//! # Why this route has no CSRF check
//!
//! Every other mutating form in this crate (`routes::queue`'s approve/reject/snooze) checks a CSRF
//! token bound to the operator's existing, authenticated session - the exact defense a
//! session-riding cross-site forgery needs. This route has no session to bind a token to before
//! login succeeds, and creating one just to hold a pre-auth CSRF token would hand `require_session`
//! a valid session cookie before the password is ever checked, which would let any visitor bypass
//! auth entirely by loading this page - unacceptable. The threat CSRF protects against does not
//! apply here anyway: a forged cross-site POST to this endpoint still has to supply the correct
//! operator password to do anything (verified by Argon2id below), so an attacker who could forge a
//! successful login already knows the password and gains nothing from the forgery. The per-source
//! rate limiter below is this route's actual defense (brute force), independent of CSRF.
//!
//! # `ConnectInfo` requirement on the real binary
//!
//! The rate limiter and the cookie's `Secure` decision both key on the TCP peer address via
//! `axum::extract::ConnectInfo<SocketAddr>`. That extractor is populated by a real accept loop only
//! when the router is served via `Router::into_make_service_with_connect_info::<SocketAddr>()`
//! (falling back to a test-only `MockConnectInfo` layer otherwise - see `connect_info.rs` in
//! vendored axum). Task 4's `main.rs` MUST serve this way, or `ConnectInfo` extraction fails
//! closed on every login attempt in production.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use minijinja::context;
use serde::Deserialize;

use crate::AppState;
use crate::auth::SESSION_COOKIE;
use crate::routes::error::AppError;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", get(login_form).post(login_submit))
        .route("/logout", get(logout))
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    password: String,
}

async fn login_form(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    Ok(Html(render(&state, None)?))
}

async fn login_submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let peer_ip = addr.ip();

    if !state.login_rate_limiter.check(peer_ip) {
        tracing::warn!(ip = %peer_ip, "login rate limit exceeded");
        let html = render(&state, Some("Too many attempts. Try again in a minute."))?;
        return Ok((StatusCode::TOO_MANY_REQUESTS, Html(html)).into_response());
    }

    if !state.passwords.verify(&form.password) {
        tracing::warn!(ip = %peer_ip, "login failed: wrong password");
        let html = render(&state, Some("Invalid password."))?;
        return Ok((StatusCode::UNAUTHORIZED, Html(html)).into_response());
    }

    state.login_rate_limiter.reset(peer_ip);
    let (_, cookie_value) = state.sessions.create();
    let cookie = session_cookie(
        cookie_value,
        peer_ip,
        state.sessions.ttl(),
        state.trusted_proxy,
    );

    tracing::info!(ip = %peer_ip, "login succeeded");
    Ok((CookieJar::new().add(cookie), Redirect::to("/")).into_response())
}

/// `GET /logout`: ends the operator's session and sends them back to the login form. Destroys the
/// session server-side via [`crate::auth::SessionStore::destroy`], not just the client-side cookie,
/// so a leaked or previously-synced cookie value cannot go on authenticating after the operator
/// believes they have signed out. Mounted alongside `/login` outside the `protected` group (see
/// `routes::mod`), so it works the same way whether or not the caller currently holds a valid
/// session: no cookie, an expired session, or a tampered cookie all fall through to the same
/// "clear and redirect" response rather than erroring - matching the plain `<a href="/logout">`
/// link in `base_tail.html`, which carries no state of its own to validate against.
async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get(SESSION_COOKIE)
        && let Some(session) = state.sessions.validate(cookie.value())
    {
        state.sessions.destroy(&session.id);
    }
    // Matches `session_cookie`'s `Path=/` below so the browser recognizes this as the same cookie
    // to overwrite; `CookieJar::remove` only emits a `Set-Cookie` removal header at all when `jar`
    // (built from the incoming request's own `Cookie:` header) actually contained this cookie,
    // so hitting `/logout` with none present is a clean no-op rather than sending a pointless header.
    let jar = jar.remove(Cookie::build(SESSION_COOKIE).path("/").build());
    (jar, Redirect::to("/login")).into_response()
}

/// Builds the session cookie: `HttpOnly` always, `SameSite=Strict` always, and `Max-Age` tracking
/// the store's own TTL. `Secure` is set when `force_secure` (the console is behind a trusted TLS
/// reverse proxy, `PROPOLIS_CONSOLE_TRUSTED_PROXY`) OR the peer is not loopback. The `force_secure`
/// path matters because a same-host reverse proxy terminates TLS and connects to the console over
/// loopback, so `peer_ip.is_loopback()` alone would wrongly drop `Secure` on a real HTTPS session.
fn session_cookie(
    value: String,
    peer_ip: IpAddr,
    ttl: std::time::Duration,
    force_secure: bool,
) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, value))
        .http_only(true)
        .secure(force_secure || !peer_ip.is_loopback())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(ttl.as_secs() as i64))
        .build()
}

fn render(state: &AppState, error: Option<&str>) -> Result<String, AppError> {
    let tmpl = state.templates.get_template("login.html")?;
    Ok(tmpl.render(context! { error, version => state.version })?)
}
