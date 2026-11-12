//! Rendering of each mode through a real subscriber into a buffer, plus the pure decisions.

use std::io;
use std::sync::{Arc, Mutex};

use log_format::{Mode, is_journal_stream, layer_for, priority};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Buf {
        self.clone()
    }
}

fn render(mode: Mode, emit: impl FnOnce()) -> String {
    let buf = Buf::default();
    let subscriber = tracing_subscriber::registry().with(layer_for(mode, buf.clone()));
    tracing::subscriber::with_default(subscriber, emit);
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

fn emit_all() {
    tracing::error!("e-line");
    tracing::warn!("w-line");
    tracing::info!("i-line");
    tracing::debug!("d-line");
    tracing::trace!("t-line");
}

#[test]
fn journal_mode_prefixes_each_level_per_sd_daemon() {
    let out = render(Mode::Journal, emit_all);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 5, "{out:?}");
    for (line, (prefix, word)) in lines.iter().zip([
        ("<3>", "e-line"),
        ("<4>", "w-line"),
        ("<6>", "i-line"),
        ("<7>", "d-line"),
        ("<7>", "t-line"),
    ]) {
        assert!(
            line.starts_with(prefix),
            "{line:?} should start with {prefix}"
        );
        assert!(line.ends_with(word), "{line:?} should end with {word}");
    }
    assert!(
        !out.contains('\x1b'),
        "no escape byte in journal mode: {out:?}"
    );
}

#[test]
fn journal_mode_cannot_be_made_to_forge_a_priority_line() {
    let out = render(Mode::Journal, || {
        // Message text is not escaped by the stock formatter, nor are span field values.
        let hostile = "x\n<0>forged\ry";
        let span = tracing::info_span!("sp", f = %hostile);
        let _guard = span.enter();
        tracing::info!("hostile {hostile}");
    });
    assert_eq!(
        out.lines().count(),
        1,
        "one event must be one line: {out:?}"
    );
    assert!(out.starts_with("<6>"), "{out:?}");
    assert_eq!(out.matches("x\\n<0>forged\\ry").count(), 2, "{out:?}");
}

#[test]
fn plain_mode_has_no_prefix_and_no_escape() {
    let out = render(Mode::Plain, || {
        emit_all();
        tracing::info!(value = %"a\x1b[31mb\nc", "hostile");
    });
    assert_eq!(out.lines().count(), 6, "{out:?}");
    assert!(!out.contains('\x1b'), "{out:?}");
    assert!(!out.starts_with('<'), "{out:?}");
}

#[test]
fn terminal_mode_keeps_the_stock_coloured_format() {
    let out = render(Mode::Terminal, || tracing::warn!("w-line"));
    assert!(
        out.contains("\x1b[33m"),
        "WARN is yellow on a terminal: {out:?}"
    );
    assert!(!out.starts_with('<'), "{out:?}");
}

#[test]
fn mode_decision_covers_every_combination() {
    // (journal, terminal, no_color) -> mode
    for (journal, terminal, no_color, want) in [
        (true, true, false, Mode::Journal),
        (true, false, false, Mode::Journal),
        (false, true, false, Mode::Terminal),
        (false, true, true, Mode::Plain),
        (false, false, false, Mode::Plain),
        (false, false, true, Mode::Plain),
    ] {
        assert_eq!(
            Mode::from_facts(journal, terminal, no_color),
            want,
            "{journal} {terminal} {no_color}"
        );
    }
}

#[test]
fn journal_stream_must_match_stdout_exactly() {
    assert!(is_journal_stream(Some("12:345"), Some((12, 345))));
    // The variable alone is not enough: it survives into children whose stdout was redirected.
    assert!(!is_journal_stream(Some("12:345"), Some((12, 346))));
    assert!(!is_journal_stream(Some("13:345"), Some((12, 345))));
    assert!(!is_journal_stream(None, Some((12, 345))));
    assert!(!is_journal_stream(Some("12:345"), None));
    for bad in ["", "12", "12:", ":345", "a:b", "12:345:6", "-1:5"] {
        assert!(!is_journal_stream(Some(bad), Some((12, 345))), "{bad:?}");
    }
}

#[test]
fn priorities_follow_sd_daemon() {
    assert_eq!(priority(Level::ERROR), 3);
    assert_eq!(priority(Level::WARN), 4);
    assert_eq!(priority(Level::INFO), 6);
    assert_eq!(priority(Level::DEBUG), 7);
    assert_eq!(priority(Level::TRACE), 7);
}
