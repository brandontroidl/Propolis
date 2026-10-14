//! Test driver for `tests/process.rs`: installs the shared logging setup at TRACE and emits one
//! event per level plus one whose field value tries to forge a second, emergency-priority line.
//! An example rather than a binary so `cargo build --workspace` ships nothing extra.

use tracing::level_filters::LevelFilter;

fn main() {
    log_format::init(LevelFilter::TRACE);
    tracing::error!("e-line");
    tracing::warn!("w-line");
    tracing::info!("i-line");
    tracing::debug!("d-line");
    tracing::trace!("t-line");
    let hostile = "x\n<0>forged\x1b[31m";
    tracing::info!(value = %hostile, "hostile-field");
    // The stock formatter leaves a newline in the message text itself untouched.
    tracing::info!("hostile-message {hostile}");
}
