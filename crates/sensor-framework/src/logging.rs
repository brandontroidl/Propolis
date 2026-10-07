//! The one logging setup every sensor binary uses.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

/// Install the process-wide fmt subscriber: INFO by default, `RUST_LOG` overrides it.
///
/// `tracing_subscriber::fmt::init()` is not used because its default depends on Cargo feature
/// unification: with `env-filter` on (which `cargo build --workspace` turns on for every binary,
/// because the console, propolis and this crate enable it) an unset `RUST_LOG` means ERROR, so a
/// deployed sensor would log no listening lines and no warnings. This crate enables `env-filter`
/// itself, so the result is the same however the binary is built. Invalid `RUST_LOG` directives
/// are skipped (lossy), never a startup failure.
pub fn init_logging() {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
