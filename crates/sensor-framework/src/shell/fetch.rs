//! `honeypot_file_download` events: what a line fetched, read from what it executed.
//!
//! The authoritative source is the evaluator. When a simple command's expanded argument vector is
//! a fetch (`wget`, `curl`, `tftp`, `ftpget`, their busybox forms), [`FakeShell::note_fetch`]
//! records it, so a fetch inside a loop, a script run by `sh FILE`, `sh -c`, a command
//! substitution or after a variable assignment is reported with the URL it really named, and text
//! that merely contains a fetch command (an `echo` writing a script, a here-document body, a quoted
//! assignment) reports nothing.
//!
//! A purely lexical pass over the text the line carried stays as a fallback, so evidence the
//! evaluator never reached is not lost: a branch the fake's answers skipped (`test -f x && wget
//! URL`), a construct outside the grammar subset, a line the budget cut short. It reads the text
//! with the shell's own tokenizer, so quoting and here-documents are honoured, and it looks only at
//! command position (after reserved words, assignments and wrappers such as `nohup`), looking
//! inside `sh -c 'script'`. A lexical candidate whose URL still holds an unexpanded `$name` or
//! backtick is not a URL: it is recorded as a command with no `url`, and not at all when the line
//! already executed a fetch (the executed one carries the expanded URL). Text the tokenizer cannot
//! read is scanned by the older whole-line heuristic, which cannot tell data from a command.
//!
//! One fetch is one event per input line however it was found, so an executed fetch and the same
//! fetch seen lexically are a single event. The per-line cap and the connection's allowance bound
//! the events; the whole input line, every script it runs included, is the line.

use sensor_wire::{PROTO_TCP, SIGNAL_HONEYPOT_FILE_DOWNLOAD, SensorEvent, WIRE_VERSION};

use super::ast::{Word, WordPart};
use super::eval::LineBudget;
use super::lex::{Op, Tok, lex};
use super::{
    BudgetHit, FakeShell, Fetch, MAX_COMMAND_LEN, MAX_URL_LEN, TraceEventKind, command_basename,
    download_targets,
};
use crate::sanitize_value;

/// Texts of the units one input line ran that are kept for the lexical fallback, in bytes.
const MAX_UNIT_BYTES: usize = 262_144;

/// Nesting of `sh -c 'sh -c ...'` the lexical fallback looks through.
const MAX_SCRIPT_NESTING: u32 = 3;

/// What the running input line fetched.
#[derive(Clone, Debug, Default)]
pub(super) struct LineFetches {
    /// Events are wanted for this line: a normal command, not a flood marker or a rerun of a
    /// line whose events already went out.
    pub(super) enabled: bool,
    /// Distinct fetches the evaluator executed, in order, at most one past the per-line cap.
    executed: Vec<Fetch>,
    /// The complete units of text the line ran (one per physical line, or the whole exec string).
    units: Vec<String>,
    unit_bytes: usize,
}

/// Words that open a command without being it.
const RESERVED: [&str; 10] = [
    "if", "then", "elif", "else", "do", "while", "until", "!", "{", "}",
];

/// Commands that run the command after their options.
const WRAPPERS: [&str; 12] = [
    "nohup", "exec", "command", "env", "sudo", "setsid", "nice", "time", "timeout", "stdbuf",
    "toybox", "toolbox",
];

/// Whether `url` still holds a `$name`, `${..}`, `$(..)` or backtick: the text of a command nothing
/// expanded, not an address.
fn has_unexpanded(url: &str) -> bool {
    url.contains('`')
        || url.as_bytes().windows(2).any(|pair| match pair {
            [b'$', next] => {
                next.is_ascii_alphanumeric()
                    || matches!(
                        next,
                        b'_' | b'{' | b'(' | b'?' | b'@' | b'*' | b'#' | b'!' | b'$'
                    )
            }
            _ => false,
        })
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with(|c: char| c.is_ascii_digit())
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_assignment(token: &str) -> bool {
    token.split_once('=').is_some_and(|(name, _)| is_name(name))
}

fn static_parts(parts: &[WordPart], out: &mut String) -> bool {
    parts.iter().all(|part| match part {
        WordPart::Literal(text) | WordPart::Quoted(text) => {
            out.push_str(text);
            true
        }
        WordPart::DoubleQuoted(inner) => static_parts(inner, out),
        WordPart::Tilde => {
            out.push('~');
            true
        }
        _ => false,
    })
}

/// A word as the text the command would see if nothing in it expanded: quotes removed, an
/// expansion left as written.
fn static_word(word: &Word) -> String {
    let mut text = String::new();
    if static_parts(&word.parts, &mut text) {
        text
    } else {
        word.raw.trim_matches(['"', '\'']).to_string()
    }
}

/// The fetches a text would make if every command in it ran, from its tokens: each is the fetch and
/// whether its URL was left unexpanded.
fn lexical_fetches(
    shell: &FakeShell,
    text: &str,
    max_depth: u32,
    budget: &mut LineBudget,
    nesting: u32,
    out: &mut Vec<(Fetch, bool)>,
) {
    let Ok(lexed) = lex(text, true, 1, 0, max_depth, budget) else {
        for fetch in download_targets(shell, text) {
            out.push(unexpanded_to_command(fetch, text));
        }
        return;
    };
    let mut command: Vec<String> = Vec::new();
    let mut skip_target = false;
    let mut commands: Vec<Vec<String>> = Vec::new();
    for token in &lexed.tokens {
        match &token.tok {
            Tok::Word(word) => {
                if skip_target {
                    skip_target = false;
                } else {
                    command.push(static_word(word));
                }
            }
            Tok::IoNumber(_) => {}
            Tok::Op(
                Op::Less
                | Op::Great
                | Op::DGreat
                | Op::LessAnd
                | Op::GreatAnd
                | Op::LessGreat
                | Op::Clobber
                | Op::DLess { .. }
                | Op::TLess,
            ) => skip_target = true,
            Tok::Op(_) | Tok::Newline => {
                skip_target = false;
                commands.push(std::mem::take(&mut command));
            }
        }
    }
    commands.push(command);
    for words in commands {
        command_fetches(shell, &words, max_depth, budget, nesting, out);
    }
}

fn command_fetches(
    shell: &FakeShell,
    words: &[String],
    max_depth: u32,
    budget: &mut LineBudget,
    nesting: u32,
    out: &mut Vec<(Fetch, bool)>,
) {
    let mut at = 0;
    loop {
        let Some(word) = words.get(at) else {
            return;
        };
        if RESERVED.contains(&word.as_str()) || is_assignment(word) {
            at += 1;
        } else if WRAPPERS.contains(&command_basename(word)) {
            at += 1;
            while words
                .get(at)
                .is_some_and(|w| w.starts_with('-') || is_assignment(w) || w.parse::<u64>().is_ok())
            {
                at += 1;
            }
        } else {
            break;
        }
    }
    let Some(rest) = words.get(at..) else {
        return;
    };
    let refs: Vec<&str> = rest.iter().map(String::as_str).collect();
    let shell_at = match refs.first().map(|w| command_basename(w)) {
        Some("sh" | "bash" | "dash" | "ash") => Some(0),
        Some("busybox") if matches!(refs.get(1), Some(&("sh" | "ash"))) => Some(1),
        _ => None,
    };
    if let Some(shell_at) = shell_at {
        let options = refs.get(shell_at + 1..).unwrap_or(&[]);
        let script = options
            .iter()
            .take_while(|o| o.starts_with('-'))
            .position(|o| !o.starts_with("--") && o.contains('c'))
            .and_then(|i| options.get(i + 1));
        if let Some(script) = script
            && nesting < MAX_SCRIPT_NESTING
        {
            lexical_fetches(shell, script, max_depth, budget, nesting + 1, out);
        }
        return;
    }
    if let Some(fetch) = shell.fetch_attempt(&refs) {
        out.push(unexpanded_to_command(fetch, &refs.join(" ")));
    }
}

/// A fetch whose URL holds unexpanded text becomes the command alone, flagged so the caller can
/// drop it when the line executed a fetch.
fn unexpanded_to_command(fetch: Fetch, source: &str) -> (Fetch, bool) {
    match fetch {
        Fetch::Url(url) if has_unexpanded(&url) => (Fetch::Unparsed(source.to_string()), true),
        Fetch::Unparsed(raw) if has_unexpanded(&raw) => (Fetch::Unparsed(raw), true),
        other => (other, false),
    }
}

impl FakeShell {
    /// Start collecting the line's fetches, for a normal command event.
    pub(super) fn enable_fetches(&mut self) {
        self.fetches.enabled = true;
    }

    /// A complete unit of text is about to run: keep it for the lexical fallback.
    pub(super) fn note_unit(&mut self, text: &str) {
        let fetches = &mut self.fetches;
        if fetches.enabled && fetches.unit_bytes.saturating_add(text.len()) <= MAX_UNIT_BYTES {
            fetches.unit_bytes = fetches.unit_bytes.saturating_add(text.len());
            fetches.units.push(text.to_string());
        }
    }

    /// The running simple command's expanded argument vector `argv`. `unset[i]` says the word
    /// `argv[i]` came from held a variable that was not set, and `source` is the command as
    /// written, in `words`.
    pub(super) fn note_fetch(&mut self, argv: &[&str], unset: &[bool], words: &[Word]) {
        if !self.fetches.enabled {
            return;
        }
        let Some(fetch) = self.fetch_attempt(argv) else {
            return;
        };
        let fetch = match fetch {
            Fetch::Url(url) => {
                let from_unset = match argv.iter().position(|a| *a == url) {
                    Some(i) => unset.get(i).copied().unwrap_or(false),
                    None => unset.iter().any(|u| *u),
                };
                if from_unset || has_unexpanded(&url) {
                    let source: Vec<&str> = words.iter().map(|w| w.raw.as_str()).collect();
                    Fetch::Unparsed(source.join(" "))
                } else {
                    Fetch::Url(url)
                }
            }
            other => other,
        };
        let cap = usize::try_from(self.budget().limits().download_per_line).unwrap_or(usize::MAX);
        let executed = &mut self.fetches.executed;
        if executed.len() <= cap && !executed.contains(&fetch) {
            executed.push(fetch);
        }
    }

    /// Append the download events of the line that just ran to `events`, then stop collecting.
    pub(super) fn append_downloads(&mut self, events: &mut Vec<SensorEvent>) {
        let fetches = std::mem::take(&mut self.fetches);
        if !fetches.enabled {
            return;
        }
        let executed_any = !fetches.executed.is_empty();
        let mut all = fetches.executed;
        let max_depth = self.budget().limits().max_depth;
        let mut budget = LineBudget::new(self.budget().limits().work_per_line);
        for unit in &fetches.units {
            let mut found = Vec::new();
            lexical_fetches(self, unit, max_depth, &mut budget, 0, &mut found);
            for (fetch, unexpanded) in found {
                let superseded = unexpanded && executed_any;
                if !superseded && !all.contains(&fetch) {
                    all.push(fetch);
                }
            }
        }
        let per_line_cap = self.budget().limits().download_per_line;
        let mut recorded: u64 = 0;
        let mut capped = false;
        for fetch in all {
            // The per-line cap is tested first so a URL refused by it spends none of the
            // connection's allowance.
            if recorded >= per_line_cap {
                self.record_hit(BudgetHit::DownloadPerLine);
                capped = true;
                break;
            }
            if !self.budget().download_allowed() {
                capped = true;
                break;
            }
            recorded = recorded.saturating_add(1);
            self.trace.events.push(TraceEventKind::FileDownload);
            events.push(self.download_event(&fetch));
        }
        if capped && self.budget().claim_download_cap_marker() {
            self.trace.events.push(TraceEventKind::FloodDownloadCap);
            events.push(self.command_event(serde_json::json!({
                "protocol_label": self.ctx.protocol_label,
                "command": "<download cap reached; further download events suppressed>",
                "flood": "download_cap",
            })));
        }
    }

    fn download_event(&self, fetch: &Fetch) -> SensorEvent {
        let metadata = match fetch {
            Fetch::Url(url) => serde_json::json!({
                "protocol_label": self.ctx.protocol_label,
                "url": sanitize_value(url, MAX_URL_LEN),
            }),
            Fetch::Unparsed(raw) => serde_json::json!({
                "protocol_label": self.ctx.protocol_label,
                "command": sanitize_value(raw, MAX_COMMAND_LEN),
            }),
        };
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: self.ctx.source_ip,
            wan_ip: self.ctx.wan_ip,
            sensor: self.ctx.protocol_label.clone(),
            signal_type: SIGNAL_HONEYPOT_FILE_DOWNLOAD.into(),
            protocol: PROTO_TCP.into(),
            authenticated: self.ctx.authenticated,
            observed_at: (self.clock)(),
            metadata,
            sample: None,
            session_id: self.ctx.session_id,
            occurrence_id: None,
            reply: None,
        }
    }
}
