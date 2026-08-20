use axum::Router;
use axum::extract::State;
use axum::response::Html;
use axum::routing::{get, post};
use minijinja::context;

use crate::AppState;
use crate::routes::context::base_context;
use crate::routes::error::AppError;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/integrity", get(integrity_page))
        .route("/integrity/verify", post(run_verify))
}

async fn integrity_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let base = base_context(&state.db, state.startup_time, state.version).await;
    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let tmpl = state.templates.get_template("integrity.html")?;
    Ok(Html(tmpl.render(context! {
        active_nav => "integrity",
        pending_count => base.pending_count,
        uptime => base.uptime,
        version => base.version,
        event_count,
        status => "",
        verified => false,
    })?))
}

async fn run_verify(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let base = base_context(&state.db, state.startup_time, state.version).await;
    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let result = core_scoring::verify_chain(&state.db).await;
    let (status, intact) = match result {
        Ok(core_scoring::ChainStatus::Intact) => (
            format!("Chain intact - all {event_count} events verified"),
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
        event_count,
        status,
        verified => true,
        intact,
    })?))
}
