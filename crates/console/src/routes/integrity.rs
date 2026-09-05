use axum::Router;
use axum::extract::State;
use axum::response::Html;
use axum::routing::{get, post};
use minijinja::context;

use crate::AppState;
use crate::routes::context::base_context;
use crate::routes::degraded::Degraded;
use crate::routes::error::AppError;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/integrity", get(integrity_page))
        .route("/integrity/verify", post(run_verify))
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

async fn integrity_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let base = base_context(&state.db, state.startup_time, state.version).await;
    let mut degraded = base.degraded;
    let event_count = event_count(&state.db, &mut degraded).await;

    let tmpl = state.templates.get_template("integrity.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "integrity",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        degraded => degraded.names(),
        event_count,
        status => "",
        verified => false,
    })?))
}

async fn run_verify(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let base = base_context(&state.db, state.startup_time, state.version).await;
    let mut degraded = base.degraded;
    let event_count = event_count(&state.db, &mut degraded).await;

    let result = core_scoring::verify_chain(&state.db).await;
    let (status, intact) = match result {
        Ok(core_scoring::ChainStatus::Intact) => (
            match event_count {
                Some(n) => format!("Chain intact - all {n} events verified"),
                None => "Chain intact - every event verified (count unavailable)".to_string(),
            },
            true,
        ),
        Ok(core_scoring::ChainStatus::Broken { first_bad_id }) => {
            (format!("Chain BROKEN at event id {first_bad_id}"), false)
        }
        Err(e) => (format!("Verification error: {e}"), false),
    };

    let tmpl = state.templates.get_template("integrity.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "integrity",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        degraded => degraded.names(),
        event_count,
        status,
        verified => true,
        intact,
    })?))
}
