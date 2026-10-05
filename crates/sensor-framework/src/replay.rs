//! The `.session` replay fixture: one recorded attacker session, parsed once for both the replay
//! test (`tests/shell_replay.rs`) and the operator's offline `propolis shell explain`.
//!
//! ```text
//! # source: where the lines were observed        (required)
//! # date: YYYY-MM-DD                              (required)
//! # protocol: ssh | telnet | adb                  (required)
//! # persona: ubuntu | android                     (required)
//! $ an input line, exactly as sent
//! > an output line, compared with a trailing LF
//! >~ output text with no trailing LF
//! >e a\tb                                         an output line with escapes (\t \r \n \\
//!                                                 \0 \xHH), compared with a trailing LF
//! >x 7f 45 4c 46                                  raw output bytes, in hex
//! >prefix-x 7f 45 4c 46                           the output starts with these bytes
//! >prefix-e PING localhost (                      the same, as escaped text
//! >len 2193272                                    the output is exactly this long
//! @cwd /tmp                                       the working directory after the line
//! @downloads http://example.invalid/a             the line's download events, in order
//! @events 1                                       every event the line emitted
//! @class supported                                the line's coverage class: supported, partial,
//!                                                 unknown or parse_limit (optional; unchecked
//!                                                 when absent)
//! ```
//!
//! Parsing reads text only. Nothing here opens a file, a socket or a database.

use std::fmt;
use std::io::{self, Write};
use std::net::IpAddr;

use crate::fakefs::FakeFs;
use crate::shell::{CommandClass, EmitContext, FakeShell};

/// The persona a fixture's shell answers as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persona {
    Ubuntu,
    Android,
}

/// The required `# key: value` headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub source: String,
    pub date: String,
    pub protocol: String,
    pub persona: Persona,
}

/// What one input line must produce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expect {
    pub output: Vec<u8>,
    pub prefix: Option<Vec<u8>>,
    pub len: Option<usize>,
    pub cwd: Option<String>,
    pub downloads: Option<Vec<String>>,
    pub events: Option<usize>,
    pub class: Option<CommandClass>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// 1-based line of the `$` input in the fixture text.
    pub line_no: usize,
    pub input: String,
    pub expect: Expect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    pub header: Header,
    pub steps: Vec<Step>,
}

/// A fixture the parser rejected. `line` is 1-based, or 0 when the fault is a missing header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            f.write_str(&self.message)
        } else {
            write!(f, "line {}: {}", self.line, self.message)
        }
    }
}

impl std::error::Error for ParseError {}

fn fail<T>(line: usize, message: String) -> Result<T, ParseError> {
    Err(ParseError { line, message })
}

fn parse_hex(field: &str, line: usize) -> Result<Vec<u8>, ParseError> {
    field
        .split_whitespace()
        .map(|h| u8::from_str_radix(h, 16).or_else(|_| fail(line, format!("bad hex byte {h:?}"))))
        .collect()
}

fn unescape(text: &str, line: usize) -> Result<Vec<u8>, ParseError> {
    let mut out = Vec::new();
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match bytes.next() {
            Some(b't') => out.push(b'\t'),
            Some(b'r') => out.push(b'\r'),
            Some(b'n') => out.push(b'\n'),
            Some(b'0') => out.push(0),
            Some(b'\\') => out.push(b'\\'),
            Some(b'x') => {
                let hex: Vec<u8> = bytes.by_ref().take(2).collect();
                let hex = std::str::from_utf8(&hex).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => out.push(b),
                    Err(_) => return fail(line, format!("bad \\x escape {hex:?}")),
                }
            }
            other => {
                return fail(
                    line,
                    format!("unknown escape \\{:?}", other.map(char::from)),
                );
            }
        }
    }
    Ok(out)
}

fn parse_count<T: std::str::FromStr>(text: &str, what: &str, line: usize) -> Result<T, ParseError> {
    text.trim()
        .parse()
        .or_else(|_| fail(line, format!("bad {what}")))
}

/// Parses one `.session` text into its headers and steps.
pub fn parse(text: &str) -> Result<Fixture, ParseError> {
    let mut meta = std::collections::BTreeMap::new();
    let mut steps: Vec<Step> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let at = i + 1;
        if let Some(rest) = raw.strip_prefix("# ") {
            if let Some((key, value)) = rest.split_once(':') {
                meta.insert(key.trim().to_string(), value.trim().to_string());
            }
            continue;
        }
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        if let Some(input) = raw.strip_prefix("$ ") {
            steps.push(Step {
                line_no: at,
                input: input.to_string(),
                expect: Expect::default(),
            });
            continue;
        }
        let Some(step) = steps.last_mut() else {
            return fail(at, "a directive before any `$` line".to_string());
        };
        let e = &mut step.expect;
        if let Some(hex) = raw.strip_prefix(">prefix-x ") {
            e.prefix = Some(parse_hex(hex, at)?);
        } else if let Some(text) = raw.strip_prefix(">prefix-e ") {
            e.prefix = Some(unescape(text, at)?);
        } else if let Some(text) = raw.strip_prefix(">e ") {
            e.output.extend(unescape(text, at)?);
            e.output.push(b'\n');
        } else if let Some(hex) = raw.strip_prefix(">x ") {
            e.output.extend(parse_hex(hex, at)?);
        } else if let Some(n) = raw.strip_prefix(">len ") {
            e.len = Some(parse_count(n, "length", at)?);
        } else if let Some(text) = raw.strip_prefix(">~ ") {
            e.output.extend_from_slice(text.as_bytes());
        } else if raw == ">" {
            e.output.push(b'\n');
        } else if let Some(text) = raw.strip_prefix("> ") {
            e.output.extend_from_slice(text.as_bytes());
            e.output.push(b'\n');
        } else if let Some(cwd) = raw.strip_prefix("@cwd ") {
            e.cwd = Some(cwd.to_string());
        } else if let Some(urls) = raw.strip_prefix("@downloads") {
            e.downloads = Some(urls.split_whitespace().map(str::to_string).collect());
        } else if let Some(n) = raw.strip_prefix("@events ") {
            e.events = Some(parse_count(n, "count", at)?);
        } else if let Some(word) = raw.strip_prefix("@class ") {
            e.class = Some(match word.trim() {
                "supported" => CommandClass::Supported,
                "partial" => CommandClass::Partial,
                "unknown" => CommandClass::Unknown,
                "parse_limit" => CommandClass::ParseLimit,
                other => return fail(at, format!("unknown class {other:?}")),
            });
        } else {
            return fail(at, format!("unrecognised line {raw:?}"));
        }
    }
    let mut required = |key: &str| {
        meta.remove(key)
            .map_or_else(|| fail(0, format!("missing `# {key}:` header")), Ok)
    };
    let source = required("source")?;
    let date = required("date")?;
    let protocol = required("protocol")?;
    let persona = match required("persona")?.as_str() {
        "ubuntu" => Persona::Ubuntu,
        "android" => Persona::Android,
        other => return fail(0, format!("unknown persona {other:?}")),
    };
    Ok(Fixture {
        header: Header {
            source,
            date,
            protocol,
            persona,
        },
        steps,
    })
}

/// The time every replayed session reads, so replies that print the time replay exactly.
pub fn replay_clock() -> chrono::DateTime<chrono::Utc> {
    "2026-09-29T12:00:00Z"
        .parse()
        .expect("the replay time is a valid RFC 3339 literal")
}

impl Fixture {
    /// The shell that answers this fixture: its persona's filesystem, its protocol label, an
    /// authenticated documentation-range source, and the fixed replay clock.
    pub fn shell(&self) -> FakeShell {
        let ctx = EmitContext {
            source_ip: IpAddr::from([192, 0, 2, 10]),
            wan_ip: None,
            authenticated: true,
            protocol_label: self.header.protocol.clone(),
            session_id: None,
        };
        let shell = match self.header.persona {
            Persona::Ubuntu => FakeShell::new(FakeFs::new(), ctx),
            Persona::Android => FakeShell::android(FakeFs::android(), ctx),
        };
        shell.with_clock(replay_clock)
    }
}

/// Longest slice of attacker-influenced text or JSON printed per step.
const SHOW_INPUT_MAX: usize = 512;
const SHOW_REPLY_MAX: usize = 256;
const SHOW_TRACE_MAX: usize = 16 * 1024;

/// Bytes shown escaped and cut to `max`, with the true length when cut.
fn show_bytes(bytes: &[u8], max: usize) -> String {
    let head = &bytes[..bytes.len().min(max)];
    let mut s = head.escape_ascii().to_string();
    if bytes.len() > head.len() {
        s.push_str(&format!("... ({} bytes)", bytes.len()));
    }
    s
}

/// Replays `fixture` through its shell and writes the engine's decision trace for each input
/// line: the line, the reply size and a bounded escaped preview, the coverage class, the program
/// basename and exit status, and the whole `LineTrace` as JSON. Operator output only; the shell
/// is the same in-memory one a sensor builds and nothing is opened.
pub fn explain(fixture: &Fixture, out: &mut impl Write) -> io::Result<()> {
    let h = &fixture.header;
    writeln!(
        out,
        "fixture: source={} date={} protocol={} persona={:?} steps={}",
        show_bytes(h.source.as_bytes(), SHOW_INPUT_MAX),
        h.date,
        h.protocol,
        h.persona,
        fixture.steps.len()
    )?;
    let mut shell = fixture.shell();
    for (n, step) in fixture.steps.iter().enumerate() {
        let (reply, events) = shell.handle_input(&step.input);
        let reply = reply.into_bytes();
        let trace = shell.last_trace();
        writeln!(out)?;
        writeln!(
            out,
            "[{}] line {}: $ {}",
            n + 1,
            step.line_no,
            show_bytes(step.input.as_bytes(), SHOW_INPUT_MAX)
        )?;
        writeln!(
            out,
            "  reply: {} bytes {}",
            reply.len(),
            show_bytes(&reply, SHOW_REPLY_MAX)
        )?;
        writeln!(out, "  class: {}", trace.classify().as_str())?;
        writeln!(
            out,
            "  command_basename: {}",
            trace.primary_basename().unwrap_or("-")
        )?;
        match trace.final_status() {
            Some(s) => writeln!(out, "  status: {s}")?,
            None => writeln!(out, "  status: -")?,
        }
        writeln!(out, "  events: {}", events.len())?;
        let json = serde_json::to_string_pretty(trace)
            .unwrap_or_else(|e| format!("trace not serializable: {e}"));
        let mut end = json.len().min(SHOW_TRACE_MAX);
        while !json.is_char_boundary(end) {
            end -= 1;
        }
        writeln!(out, "  trace:")?;
        for line in json[..end].lines() {
            writeln!(out, "    {line}")?;
        }
        if end < json.len() {
            writeln!(out, "    ... (trace cut, {} bytes)", json.len())?;
        }
    }
    Ok(())
}

impl Expect {
    /// Whether `out` satisfies the step's reply directives: the whole reply when no `>prefix-*` or
    /// `>len` is given, else only what those state. The replay checker applies the same rule.
    pub fn reply_matches(&self, out: &[u8]) -> bool {
        if self.prefix.is_none() && self.len.is_none() {
            return out == self.output;
        }
        self.prefix.as_ref().is_none_or(|p| out.starts_with(p))
            && self.len.is_none_or(|n| out.len() == n)
    }

    /// The reply expectation as bounded escaped text, for review output.
    fn describe_reply(&self) -> String {
        if self.prefix.is_none() && self.len.is_none() {
            return show_bytes(&self.output, SHOW_REPLY_MAX);
        }
        let mut parts = Vec::new();
        if let Some(p) = &self.prefix {
            parts.push(format!("starts with {}", show_bytes(p, SHOW_REPLY_MAX)));
        }
        if let Some(n) = self.len {
            parts.push(format!("{n} bytes"));
        }
        parts.join(", ")
    }
}

/// One step's committed expectation against what the current emulator produces.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StepDiff {
    pub line_no: usize,
    pub input: String,
    /// Expected reply, escaped and bounded; a `>prefix-*` or `>len` step shows what it states.
    pub reply_expected: String,
    /// Actual reply, escaped and bounded.
    pub reply_actual: String,
    /// The fixture's `@class`, when it has one.
    pub class_expected: Option<String>,
    pub class_actual: String,
    /// False when the reply differs or, for a step with `@class`, the class does.
    pub matched: bool,
}

/// Replays `fixture` through a fresh shell and compares each step's reply and classification with
/// the fixture's expectations, without asserting: the result is for review before a behavior
/// change is accepted. A step without `@class` is compared on its reply alone. Working directory,
/// downloads and event counts are the replay checker's concern and are not compared here.
pub fn diff(fixture: &Fixture) -> Vec<StepDiff> {
    let mut shell = fixture.shell();
    fixture
        .steps
        .iter()
        .map(|step| {
            let (reply, _events) = shell.handle_input(&step.input);
            let reply = reply.into_bytes();
            let class_actual = shell.last_trace().classify();
            let e = &step.expect;
            StepDiff {
                line_no: step.line_no,
                input: step.input.clone(),
                reply_expected: e.describe_reply(),
                reply_actual: show_bytes(&reply, SHOW_REPLY_MAX),
                class_expected: e.class.map(|c| c.as_str().to_string()),
                class_actual: class_actual.as_str().to_string(),
                matched: e.reply_matches(&reply) && e.class.is_none_or(|c| c == class_actual),
            }
        })
        .collect()
}

/// Per-file diffs as one JSON array of `{"file", "steps"}` objects, for
/// `propolis shell shadow-diff --json`. Every step is included, matched or not.
pub fn files_to_json(files: &[(String, Vec<StepDiff>)]) -> String {
    let value: Vec<serde_json::Value> = files
        .iter()
        .map(|(file, steps)| serde_json::json!({ "file": file, "steps": steps }))
        .collect();
    serde_json::to_string_pretty(&value).expect("a StepDiff list always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "# source: unit test\n# date: 2026-10-03\n# protocol: ssh\n\
        # persona: android\n$ pwd\n> /\n@cwd /\n$ printf a\n>~ a\n>e b\\t\\x41\n>x 00 ff\n\
        >prefix-x 61\n>len 5\n@events 1\n@downloads http://example.invalid/a http://example.invalid/b\n";

    #[test]
    fn parses_headers_and_every_directive() {
        let f = parse(GOOD).unwrap();
        assert_eq!(
            f.header,
            Header {
                source: "unit test".into(),
                date: "2026-10-03".into(),
                protocol: "ssh".into(),
                persona: Persona::Android,
            }
        );
        assert_eq!(f.steps.len(), 2);
        assert_eq!(f.steps[0].line_no, 5);
        assert_eq!(f.steps[0].input, "pwd");
        assert_eq!(f.steps[0].expect.output, b"/\n");
        assert_eq!(f.steps[0].expect.cwd.as_deref(), Some("/"));
        let e = &f.steps[1].expect;
        assert_eq!(e.output, b"ab\tA\n\x00\xff");
        assert_eq!(e.prefix.as_deref(), Some(&b"a"[..]));
        assert_eq!(e.len, Some(5));
        assert_eq!(e.events, Some(1));
        assert_eq!(
            e.downloads.as_deref(),
            Some(
                &[
                    "http://example.invalid/a".to_string(),
                    "http://example.invalid/b".to_string()
                ][..]
            )
        );
    }

    #[test]
    fn rejects_malformed_fixtures() {
        let head = "# source: s\n# date: d\n# protocol: ssh\n# persona: ubuntu\n";
        for (text, needle) in [
            (
                "# date: d\n# protocol: ssh\n# persona: ubuntu\n$ id\n",
                "missing `# source:`",
            ),
            (
                "# source: s\n# date: d\n# protocol: ssh\n# persona: beos\n",
                "unknown persona",
            ),
            (&format!("{head}> orphan\n"), "before any `$`"),
            (&format!("{head}$ id\nnonsense\n"), "unrecognised line"),
            (&format!("{head}$ id\n>x zz\n"), "bad hex"),
            (&format!("{head}$ id\n>e \\q\n"), "unknown escape"),
            (&format!("{head}$ id\n>len many\n"), "bad length"),
        ] {
            let err = parse(text).unwrap_err();
            assert!(err.to_string().contains(needle), "{err} for {text:?}");
        }
    }

    const HEAD: &str = "# source: s\n# date: d\n# protocol: ssh\n# persona: ubuntu\n";

    #[test]
    fn parses_class_and_rejects_an_unknown_class_word() {
        let f = parse(&format!(
            "{HEAD}$ id\n@class supported\n$ a\n@class partial\n$ b\n@class unknown\n$ c\n@class parse_limit\n$ d\n"
        ))
        .unwrap();
        let classes: Vec<_> = f.steps.iter().map(|s| s.expect.class).collect();
        assert_eq!(
            classes,
            [
                Some(CommandClass::Supported),
                Some(CommandClass::Partial),
                Some(CommandClass::Unknown),
                Some(CommandClass::ParseLimit),
                None
            ]
        );
        let err = parse(&format!("{HEAD}$ id\n@class mostly\n")).unwrap_err();
        assert!(err.to_string().contains("unknown class"), "{err}");
    }

    #[test]
    fn diff_matches_a_correct_class_and_flags_a_wrong_one() {
        // `id` is supported and `nosuchcmd-xyz` unknown (see the explain test below).
        let good = parse(&format!(
            "{HEAD}$ id\n> uid=0(root) gid=0(root) groups=0(root)\n@class supported\n\
             $ nosuchcmd-xyz\n> nosuchcmd-xyz: command not found\n@class unknown\n"
        ))
        .unwrap();
        let d = diff(&good);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|s| s.matched), "{d:#?}");
        assert_eq!(d[1].class_expected.as_deref(), Some("unknown"));
        assert_eq!(d[1].class_actual, "unknown");

        // Same replies, deliberately wrong classes: only the class differs.
        let wrong = parse(&format!(
            "{HEAD}$ id\n> uid=0(root) gid=0(root) groups=0(root)\n@class unknown\n\
             $ nosuchcmd-xyz\n> nosuchcmd-xyz: command not found\n@class supported\n"
        ))
        .unwrap();
        let d = diff(&wrong);
        assert!(d.iter().all(|s| !s.matched), "{d:#?}");
        assert_eq!(d[0].reply_expected, d[0].reply_actual);
        assert_eq!(d[0].class_actual, "supported");
    }

    #[test]
    fn diff_without_class_compares_the_reply_only() {
        let f = parse(&format!(
            "{HEAD}$ id\n> uid=0(root) gid=0(root) groups=0(root)\n$ whoami\n> nobody\n\
             $ id\n>prefix-e uid=\n$ id\n>len 3\n"
        ))
        .unwrap();
        let d = diff(&f);
        let matched: Vec<bool> = d.iter().map(|s| s.matched).collect();
        assert_eq!(matched, [true, false, true, false], "{d:#?}");
        assert_eq!(d[1].reply_expected, "nobody\\n");
        assert_eq!(d[1].reply_actual, "root\\n");
        assert_eq!(d[1].class_expected, None);
        assert_eq!(d[2].reply_expected, "starts with uid=");
        let json: serde_json::Value =
            serde_json::from_str(&files_to_json(&[("f.session".to_string(), d)])).unwrap();
        assert_eq!(json[0]["file"], "f.session");
        assert_eq!(json[0]["steps"][1]["matched"], false);
        assert_eq!(json[0]["steps"][0]["matched"], true);
    }

    #[test]
    fn explain_traces_each_line_and_ends_cleanly() {
        let f = parse(&format!(
            "{}$ id\n$ nosuchcmd-xyz\n",
            "# source: s\n# date: d\n# protocol: telnet\n# persona: ubuntu\n"
        ))
        .unwrap();
        let mut out = Vec::new();
        explain(&f, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("class: supported"), "{text}");
        assert!(text.contains("class: unknown"), "{text}");
        assert!(text.contains("command_basename: id"), "{text}");
        assert!(text.contains("status: 127"), "{text}");
        assert!(text.contains("\"segments\""), "{text}");
    }
}
