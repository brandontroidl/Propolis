use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use minijinja::context;
use serde::Deserialize;
use tokio::sync::Semaphore;

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::base_context;
use crate::routes::degraded::Degraded;
use crate::routes::error::AppError;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/integrity", get(integrity_page))
        .route("/integrity/verify", post(run_verify))
}

/// One chain verification at a time per process. Verification reads the whole ledger, so its cost
/// grows with it; a second request while one runs would only repeat the same read, and repeated
/// POSTs would otherwise stack full-ledger scans against the database. Public only so the route
/// tests can hold it to exercise the busy path.
#[doc(hidden)]
pub static VERIFY_IN_FLIGHT: Semaphore = Semaphore::const_new(1);

#[derive(Debug, Deserialize)]
struct VerifyForm {
    csrf_token: String,
}

/// The ledger's row count, or `None` when it could not be read - the template says so rather
/// than rendering the placeholder as "0 events", which on this page reads as an empty ledger.
async fn event_count(db: &sqlx::PgPool, degraded: &mut Degraded) -> Option<i64> {
    degraded.soft_or(
        "event count",
        sqlx::query_scalar("SELECT COUNT(*) FROM event")
            .fetch_one(db)
            .await
            .map(Some),
        None,
    )
}

async fn integrity_page(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Html<String>, AppError> {
    render(&state, &session, Outcome::NotRun).await.map(Html)
}

/// Runs the full chain verification. It changes no state, but it is an operator action with a
/// real cost, so it carries the session's CSRF token like every other POST in the console: without
/// one, any page the operator's browser visits could trigger it.
async fn run_verify(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Form(form): Form<VerifyForm>,
) -> Result<Response, AppError> {
    if !state.sessions.validate_csrf(&session.id, &form.csrf_token) {
        tracing::warn!("integrity verify rejected: missing or invalid csrf token");
        return Ok((StatusCode::FORBIDDEN, "invalid or missing csrf token").into_response());
    }

    let Ok(_running) = VERIFY_IN_FLIGHT.try_acquire() else {
        let html = render(&state, &session, Outcome::AlreadyRunning).await?;
        return Ok((StatusCode::CONFLICT, Html(html)).into_response());
    };

    let result = core_scoring::verify_chain(&state.db).await;
    Ok(Html(render(&state, &session, Outcome::Ran(result)).await?).into_response())
}

enum Outcome {
    NotRun,
    AlreadyRunning,
    Ran(Result<core_scoring::ChainStatus, core_scoring::RepoError>),
}

async fn render(state: &AppState, session: &Session, outcome: Outcome) -> Result<String, AppError> {
    let base = base_context(&state.db, state.startup_time, state.version).await;
    let mut degraded = base.degraded;
    let event_count = event_count(&state.db, &mut degraded).await;
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();

    let (status, verified, intact, busy) = match outcome {
        Outcome::NotRun => (String::new(), false, false, false),
        Outcome::AlreadyRunning => (String::new(), false, false, true),
        Outcome::Ran(Ok(core_scoring::ChainStatus::Intact)) => (
            match event_count {
                Some(n) => format!("Chain intact - all {n} events verified"),
                None => "Chain intact - every event verified (count unavailable)".to_string(),
            },
            true,
            true,
            false,
        ),
        Outcome::Ran(Ok(core_scoring::ChainStatus::Broken { first_bad_id })) => (
            format!("Chain BROKEN at event id {first_bad_id}"),
            true,
            false,
            false,
        ),
        Outcome::Ran(Err(e)) => (format!("Verification error: {e}"), true, false, false),
    };

    let tmpl = state.templates.get_template("integrity.html")?;
    Ok(tmpl.render(context! {
        active_nav => "integrity",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        degraded => degraded.names(),
        csrf_token,
        event_count,
        status,
        verified,
        intact,
        busy,
    })?)
}
