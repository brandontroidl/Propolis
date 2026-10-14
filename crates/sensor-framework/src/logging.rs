//! The one logging setup every sensor binary uses.

use tracing::level_filters::LevelFilter;

/// Install the process-wide subscriber: INFO by default, `RUST_LOG` overrides it.
///
/// `tracing_subscriber::fmt::init()` is not used because its default depends on Cargo feature
/// unification: with `env-filter` on (which `cargo build --workspace` turns on for every binary,
/// because the console, propolis and this crate enable it) an unset `RUST_LOG` means ERROR, so a
/// deployed sensor would log no listening lines and no warnings. `log_format::init` enables
/// `env-filter` itself, so the result is the same however the binary is built. Invalid `RUST_LOG`
/// directives are skipped (lossy), never a startup failure.
///
/// Output format (no colour off a terminal, journald priority prefixes under systemd) is owned
/// by the `log-format` crate, shared with the daemon and every other binary.
pub fn init_logging() {
    log_format::init(LevelFilter::INFO);
}
