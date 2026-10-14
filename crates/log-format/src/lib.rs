//! The one `tracing` output format every Propolis binary uses.
//!
//! The stock `fmt` layer writes ANSI colour escapes whether or not stdout is a terminal and gives
//! journald no level, so under systemd every line landed in the journal at priority 6 with escape
//! bytes in the message, and `journalctl -p warning` saw nothing. This crate fixes both without a
//! new dependency:
//!
//! - colour is on only when stdout is a terminal and `NO_COLOR` is unset or empty;
//! - when stdout is the journal stream, each event is written as one line with the `<N>` prefix
//!   of sd-daemon(3) (`<3>` error, `<4>` warning, `<6>` info, `<7>` debug), which journald strips
//!   and turns into the entry's `PRIORITY` (`SyslogLevelPrefix=` in systemd.exec(5), default on).
//!
//! "stdout is the journal" is decided the way systemd.exec(5) prescribes for `$JOURNAL_STREAM`:
//! the variable holds the device and inode of the stream, and the process compares them with its
//! own stdout, because the variable alone survives into children whose stdout was redirected.
//! A redirect to a file or pipe therefore never gets a prefix.
//!
//! Off a terminal the formatted event is flattened to a single line (control characters other
//! than tab are written as `\n`, `\u{1b}`, and so on). The stock formatter escapes ESC in the
//! message text but not in field values, and leaves newlines alone everywhere. journald parses a
//! priority prefix at the start of every line, so an attacker-controlled value containing a
//! newline followed by `<0>` would otherwise forge an emergency-priority entry, and a raw ESC in
//! a log file reaches the terminal of whoever reads it.

use std::fmt;
use std::io::IsTerminal as _;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::{Format, Full, Writer};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer};

/// How the output stream is rendered, decided once at startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// stdout is a terminal: the stock coloured format.
    Terminal,
    /// stdout is a file or pipe: the stock format without colour.
    Plain,
    /// stdout is the journal stream: one `<N>`-prefixed line per event, no colour.
    Journal,
}

impl Mode {
    /// Inspects this process's stdout and environment.
    pub fn detect() -> Mode {
        let journal = is_journal_stream(
            std::env::var("JOURNAL_STREAM").ok().as_deref(),
            stdout_identity(),
        );
        Mode::from_facts(
            journal,
            std::io::stdout().is_terminal(),
            std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty()),
        )
    }

    /// The pure decision, separate from the probes so it can be tested with every combination.
    pub fn from_facts(journal: bool, terminal: bool, no_color: bool) -> Mode {
        if journal {
            Mode::Journal
        } else if terminal && !no_color {
            Mode::Terminal
        } else {
            Mode::Plain
        }
    }
}

/// Parses `$JOURNAL_STREAM` (`<dev>:<ino>`, decimal) and compares it with `stdout`'s device and
/// inode. A missing, malformed or non-matching value is not the journal.
pub fn is_journal_stream(var: Option<&str>, stdout: Option<(u64, u64)>) -> bool {
    let (Some(var), Some(stdout)) = (var, stdout) else {
        return false;
    };
    let Some((dev, ino)) = var.split_once(':') else {
        return false;
    };
    match (dev.parse::<u64>(), ino.parse::<u64>()) {
        (Ok(dev), Ok(ino)) => (dev, ino) == stdout,
        _ => false,
    }
}

/// Device and inode of this process's stdout. `/proc/self/fd/1` is a magic link, so `stat`
/// follows it to the open file itself (a socket, for the journal stream). `None` off Linux or
/// when stdout is closed, which reads as "not the journal".
fn stdout_identity() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self/fd/1")
            .ok()
            .map(|m| (m.dev(), m.ino()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// sd-daemon(3) priority for a tracing level. TRACE shares DEBUG's priority: syslog has nothing
/// finer.
pub fn priority(level: Level) -> u8 {
    match level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        Level::DEBUG | Level::TRACE => 7,
    }
}

/// The stock `Full` event format. Off a terminal each event is also flattened to one line, and
/// in [`Mode::Journal`] it gets the `<N>` prefix. [`Mode::Terminal`] passes straight through to
/// the stock formatter.
pub struct LogFormat {
    inner: Format<Full, SystemTime>,
    flatten: bool,
    prefix: bool,
}

impl LogFormat {
    pub fn new(mode: Mode) -> Self {
        LogFormat {
            inner: Format::default(),
            flatten: mode != Mode::Terminal,
            prefix: mode == Mode::Journal,
        }
    }
}

impl<S, N> FormatEvent<S, N> for LogFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'w> FormatFields<'w> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        if !self.flatten {
            return self.inner.format_event(ctx, writer, event);
        }
        let mut line = String::new();
        self.inner
            .format_event(ctx, Writer::new(&mut line), event)?;
        if self.prefix {
            write!(writer, "<{}>", priority(*event.metadata().level()))?;
        }
        for c in line.trim_end_matches('\n').chars() {
            if c.is_control() && c != '\t' {
                write!(writer, "{}", c.escape_default())?;
            } else {
                writer.write_char(c)?;
            }
        }
        writer.write_char('\n')
    }
}

/// The output layer for `mode`, writing to `writer`. [`layer`] is this with stdout; tests pass a
/// buffer.
pub fn layer_for<S, W>(mode: Mode, writer: W) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + 'static,
{
    tracing_subscriber::fmt::layer()
        .with_ansi(mode == Mode::Terminal)
        .event_format(LogFormat::new(mode))
        .with_writer(writer)
}

/// The output layer for this process's stdout, mode detected from the environment. For binaries
/// that build their own registry (the daemon and the console add a log-buffer layer).
pub fn layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    layer_for(Mode::detect(), std::io::stdout)
}

/// Installs the process-wide subscriber: this crate's layer under an `EnvFilter` that reads
/// `RUST_LOG` and falls back to `default_level` when it is unset. Invalid `RUST_LOG` directives
/// are skipped (lossy), never a startup failure.
pub fn init(default_level: LevelFilter) {
    let filter = EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(filter)
        .with(layer())
        .init();
}
