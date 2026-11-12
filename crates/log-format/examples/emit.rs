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
    // What a scanner's malformed hello makes rustls log through the `log` facade.
    if std::env::var_os("EMIT_RUSTLS").is_some() {
        log::warn!(target: "rustls::server::hs", "Illegal SNI extension: ignoring IP address presented as hostname (c0000201)");
        log::error!(target: "rustls::server::hs", "rustls-error-line");
        // And what an SSH client's channel request makes russh log, with text the client chose.
        log::warn!(target: "russh::server::encrypted", "unknown channel request client-chosen-name");
    }
    // A field past journald's LineMax with a priority prefix straddling the old 48K boundary.
    if std::env::var_os("EMIT_LONG").is_some() {
        let long = format!("{}<0>tail", "A".repeat(49_149));
        tracing::info!(value = %long, "long-field");
    }
}
