//! `grep`: GNU grep 3.7 over the modeled bytes, with basic (the default), extended (`-E`), fixed
//! (`-F`) and an approximated Perl (`-P`) syntax.
//!
//! A survey script greps everything it reads (`free | grep -i '^Mem:'`, `top -bn1 | grep
//! '^%Cpu\|^Cpu'`, `ip addr | grep -E '^[0-9]+:'`), so an engine that answered only `-F` printed
//! nothing for every one of them, the empty answer a real host never gives. Patterns compile
//! through [`super::regex`], whose scan is linear and charged to the line.
//!
//! Layouts and messages were recorded from Ubuntu 22.04's grep 3.7 (2026-10-07 reference
//! session): the `name:` and `n:` prefixes, `-` for context lines and `--` between groups, the
//! regex compile errors, `binary file matches` on standard error, status 0/1/2 with `-q` winning
//! over a later error. `-r` walks the modeled tree under a bounded visit count.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::cell::Cell;

use memchr::memmem::Finder;

use super::read::errno_text;
use super::regex::{Regex, Syntax};
use super::registry::Registry;
use super::texttools::stopped;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};

pub(super) fn register(r: &mut Registry) {
    // The phone's toolbox has no recorded answer for grep, and it answers "not found" today.
    r.register_if("grep", ubuntu, HandlerId::Grep, FakeShell::cmd_grep);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

const USAGE: &str =
    "Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n";
/// The most files `-r` visits.
const RECURSE_MAX: usize = 2_048;
const RECURSE_DEPTH: u32 = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Fixed,
    Re(Syntax),
}

#[derive(Default)]
struct Plan {
    fixed: bool,
    extended: bool,
    perl: bool,
    fold: bool,
    invert: bool,
    count: bool,
    quiet: bool,
    no_messages: bool,
    word: bool,
    whole_line: bool,
    only: bool,
    number: bool,
    names: Option<bool>,
    list_matching: bool,
    list_missing: bool,
    max: Option<u64>,
    after: usize,
    before: usize,
    null: bool,
    text: bool,
    recursive: bool,
    patterns: Vec<String>,
    pattern_files: Vec<String>,
    explicit: bool,
    files: Vec<String>,
}

fn usage_error(text: String) -> CommandResult {
    CommandResult::stderr(2, text)
}

fn number_arg(value: &str, what: &str) -> Result<u64, CommandResult> {
    value
        .parse::<u64>()
        .map_err(|_| usage_error(format!("grep: invalid {what} argument\n")))
}

fn parse(args: &[&str]) -> Result<Plan, CommandResult> {
    let owned: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    let mut plan = Plan::default();
    let mut operands: Vec<String> = Vec::new();
    let mut options = true;
    let mut i = 0usize;
    let mut files_from: Vec<String> = Vec::new();
    while let Some(arg) = owned.get(i) {
        i = i.saturating_add(1);
        if !options || arg == "-" || !arg.starts_with('-') {
            operands.push(arg.clone());
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let take = |i: &mut usize| -> Result<String, CommandResult> {
                if let Some(v) = value.clone() {
                    return Ok(v);
                }
                let v = owned.get(*i).cloned().ok_or_else(|| {
                    usage_error(format!(
                        "grep: option '--{name}' requires an argument\n{USAGE}"
                    ))
                })?;
                *i = i.saturating_add(1);
                Ok(v)
            };
            match name {
                "extended-regexp" => plan.extended = true,
                "fixed-strings" => plan.fixed = true,
                "basic-regexp" => {
                    plan.extended = false;
                    plan.fixed = false;
                }
                "perl-regexp" => plan.perl = true,
                "ignore-case" => plan.fold = true,
                "no-ignore-case" => plan.fold = false,
                "invert-match" => plan.invert = true,
                "count" => plan.count = true,
                "quiet" | "silent" => plan.quiet = true,
                "no-messages" => plan.no_messages = true,
                "word-regexp" => plan.word = true,
                "line-regexp" => plan.whole_line = true,
                "only-matching" => plan.only = true,
                "line-number" => plan.number = true,
                "with-filename" => plan.names = Some(true),
                "no-filename" => plan.names = Some(false),
                "files-with-matches" => plan.list_matching = true,
                "files-without-match" => plan.list_missing = true,
                "null" => plan.null = true,
                "text" => plan.text = true,
                "recursive" | "dereference-recursive" => plan.recursive = true,
                "color" | "colour" | "line-buffered" | "binary-files" | "label" | "exclude"
                | "include" | "exclude-dir" | "devices" | "directories" => {
                    if matches!(
                        name,
                        "binary-files" | "label" | "exclude" | "include" | "exclude-dir"
                    ) {
                        take(&mut i)?;
                    }
                }
                "regexp" => {
                    plan.patterns.push(take(&mut i)?);
                    plan.explicit = true;
                }
                "file" => {
                    files_from.push(take(&mut i)?);
                    plan.explicit = true;
                }
                "max-count" => plan.max = Some(number_arg(&take(&mut i)?, "max count")?),
                "after-context" => {
                    plan.after = context(&take(&mut i)?)?;
                }
                "before-context" => {
                    plan.before = context(&take(&mut i)?)?;
                }
                "context" => {
                    let n = context(&take(&mut i)?)?;
                    plan.after = n;
                    plan.before = n;
                }
                _ => {
                    return Err(usage_error(format!(
                        "grep: unrecognized option '{arg}'\n{USAGE}"
                    )));
                }
            }
            continue;
        }
        let cluster: Vec<char> = arg.chars().skip(1).collect();
        let mut at = 0usize;
        while let Some(&flag) = cluster.get(at) {
            at = at.saturating_add(1);
            // An option that takes a value takes the rest of the word, or the next word.
            let mut value = |i: &mut usize| -> Result<String, CommandResult> {
                let rest: String = cluster.get(at..).unwrap_or(&[]).iter().collect();
                at = cluster.len();
                if !rest.is_empty() {
                    return Ok(rest);
                }
                let v = owned.get(*i).cloned().ok_or_else(|| {
                    usage_error(format!(
                        "grep: option requires an argument -- '{flag}'\n{USAGE}"
                    ))
                })?;
                *i = i.saturating_add(1);
                Ok(v)
            };
            match flag {
                'E' => plan.extended = true,
                'F' => plan.fixed = true,
                'G' => {
                    plan.extended = false;
                    plan.fixed = false;
                }
                'P' => plan.perl = true,
                'i' | 'y' => plan.fold = true,
                'v' => plan.invert = true,
                'c' => plan.count = true,
                'q' => plan.quiet = true,
                's' => plan.no_messages = true,
                'w' => plan.word = true,
                'x' => plan.whole_line = true,
                'o' => plan.only = true,
                'n' => plan.number = true,
                'H' => plan.names = Some(true),
                'h' => plan.names = Some(false),
                'l' => plan.list_matching = true,
                'L' => plan.list_missing = true,
                'Z' => plan.null = true,
                'a' => plan.text = true,
                'r' | 'R' => plan.recursive = true,
                'I' | 'U' | 'b' | 'u' | 'T' => {}
                'e' => {
                    plan.patterns.push(value(&mut i)?);
                    plan.explicit = true;
                }
                'f' => {
                    files_from.push(value(&mut i)?);
                    plan.explicit = true;
                }
                'm' => plan.max = Some(number_arg(&value(&mut i)?, "max count")?),
                'A' => plan.after = context(&value(&mut i)?)?,
                'B' => plan.before = context(&value(&mut i)?)?,
                'C' => {
                    let n = context(&value(&mut i)?)?;
                    plan.after = n;
                    plan.before = n;
                }
                'd' | 'D' => {
                    value(&mut i)?;
                }
                'X' => {
                    let matcher = value(&mut i)?;
                    match matcher.as_str() {
                        "grep" => {}
                        "egrep" => plan.extended = true,
                        "fgrep" => plan.fixed = true,
                        "perl" => plan.perl = true,
                        other => {
                            return Err(usage_error(format!("grep: invalid matcher {other}\n")));
                        }
                    }
                }
                digit if digit.is_ascii_digit() => {
                    // `-5` is `-C 5`.
                    let mut digits = String::from(digit);
                    while let Some(&d) = cluster.get(at).filter(|c| c.is_ascii_digit()) {
                        digits.push(d);
                        at = at.saturating_add(1);
                    }
                    let n = context(&digits)?;
                    plan.after = n;
                    plan.before = n;
                }
                other => {
                    return Err(usage_error(format!(
                        "grep: invalid option -- '{other}'\n{USAGE}"
                    )));
                }
            }
        }
    }
    let mut operands = operands.into_iter();
    if !plan.explicit {
        match operands.next() {
            Some(pattern) => plan.patterns.push(pattern),
            None => return Err(usage_error(USAGE.to_string())),
        }
    }
    plan.files = operands.collect();
    plan.pattern_files = files_from;
    Ok(plan)
}

fn context(value: &str) -> Result<usize, CommandResult> {
    value
        .parse::<usize>()
        .map(|n| n.min(1_000))
        .map_err(|_| usage_error(format!("grep: {value}: invalid context length argument\n")))
}

/// One compiled pattern. A fixed string is searched with a two-way searcher built once, linear
/// in the bytes it reads; under `-i` its needle is ASCII-lowercased, and so is the line it reads.
enum Matcher {
    Fixed(Box<Finder<'static>>),
    Re(Regex),
}

/// The work a scan has done and may do. `-o` and `-w` search one line again from later offsets, so a scan's work is not the input's length: each search adds what it read, and once
/// past the allowance every search finds nothing and the caller stops the line.
#[derive(Clone, Copy, Default)]
struct Meter {
    allowance: u64,
    spent: u64,
}

struct Search {
    matchers: Vec<Matcher>,
    fold: bool,
    word: bool,
    whole_line: bool,
    meter: Cell<Meter>,
}

/// One input line, and under `-i` with a fixed string the same bytes ASCII-lowercased, made
/// once per line however many times the line is searched.
struct Line<'a> {
    bytes: &'a [u8],
    folded: Option<Vec<u8>>,
}

impl Line<'_> {
    fn fixed_hay(&self) -> &[u8] {
        self.folded.as_deref().unwrap_or(self.bytes)
    }
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

impl Search {
    fn cost(&self, len: usize) -> u64 {
        self.matchers
            .iter()
            .map(|m| match m {
                Matcher::Fixed(_) => len_u64(len),
                Matcher::Re(re) => re.cost(len),
            })
            .fold(0u64, u64::saturating_add)
    }

    /// Start a scan that may do `allowance` work.
    fn allow(&self, allowance: u64) {
        self.meter.set(Meter {
            allowance,
            spent: 0,
        });
    }

    fn spent(&self) -> u64 {
        self.meter.get().spent
    }

    fn over(&self) -> bool {
        let meter = self.meter.get();
        meter.spent > meter.allowance
    }

    fn spend(&self, work: u64) {
        let mut meter = self.meter.get();
        meter.spent = meter.spent.saturating_add(work);
        self.meter.set(meter);
    }

    fn line<'a>(&self, bytes: &'a [u8]) -> Line<'a> {
        let folded = (self.fold && self.matchers.iter().any(|m| matches!(m, Matcher::Fixed(_))))
            .then(|| bytes.to_ascii_lowercase());
        Line { bytes, folded }
    }

    /// The first match of one matcher at or after `from`, its work spent; none once the scan is
    /// past its allowance.
    fn raw_find(&self, matcher: &Matcher, line: &Line<'_>, from: usize) -> Option<(usize, usize)> {
        if self.over() {
            return None;
        }
        match matcher {
            Matcher::Fixed(finder) => {
                let hay = line.fixed_hay().get(from..)?;
                let needle = finder.needle().len();
                if needle == 0 {
                    self.spend(1);
                    return Some((from, from));
                }
                let found = finder.find(hay);
                let read = found.map_or(hay.len(), |at| at.saturating_add(needle));
                self.spend(len_u64(read));
                found.map(|at| {
                    let start = from.saturating_add(at);
                    (start, start.saturating_add(needle))
                })
            }
            Matcher::Re(re) => {
                let (found, stopped) = re.find_scanned(line.bytes, from);
                self.spend(re.cost(stopped.saturating_sub(from)));
                found
            }
        }
    }

    /// The first acceptable match of one matcher at or after `from`: whole-line under `-x`,
    /// bounded by non-word characters under `-w`.
    fn find_one(
        &self,
        matcher: &Matcher,
        line: &Line<'_>,
        mut from: usize,
    ) -> Option<(usize, usize)> {
        let bytes = line.bytes;
        loop {
            let (start, end) = self.raw_find(matcher, line, from)?;
            let accepted = if self.whole_line {
                start == 0 && end == bytes.len()
            } else if self.word {
                let before_ok = start
                    .checked_sub(1)
                    .and_then(|i| bytes.get(i))
                    .is_none_or(|&b| !is_word(b));
                let after_ok = bytes.get(end).is_none_or(|&b| !is_word(b));
                before_ok && after_ok
            } else {
                true
            };
            if accepted {
                return Some((start, end));
            }
            if self.whole_line || start >= bytes.len() {
                return None;
            }
            from = start.saturating_add(1);
        }
    }

    /// The leftmost match of any pattern at or after `from`, the longest among those at it.
    fn find(&self, line: &Line<'_>, from: usize) -> Option<(usize, usize)> {
        self.matchers
            .iter()
            .filter_map(|m| self.find_one(m, line, from))
            .min_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))
    }

    fn matches(&self, line: &Line<'_>) -> bool {
        self.find(line, 0).is_some()
    }
}

/// What one input yields.
struct Outcome {
    selected: u64,
    text: Vec<u8>,
    binary_hit: bool,
}

fn scan(data: &[u8], search: &Search, plan: &Plan, prefix: &str) -> Outcome {
    let mut outcome = Outcome {
        selected: 0,
        text: Vec::new(),
        binary_hit: false,
    };
    if data.is_empty() {
        return outcome;
    }
    let binary = !plan.text && data.contains(&0);
    let body = data.strip_suffix(b"\n").unwrap_or(data);
    let lines: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    let mut last_printed: Option<usize> = None;
    let mut after_left = 0usize;
    let quiet_output = plan.count || plan.quiet || plan.list_matching || plan.list_missing;
    for (index, line) in lines.iter().enumerate() {
        if plan.max.is_some_and(|max| outcome.selected >= max) || search.over() {
            break;
        }
        let searched = search.line(line);
        let selected = search.matches(&searched) != plan.invert;
        if !selected {
            if after_left > 0 && !quiet_output && !binary {
                after_left = after_left.saturating_sub(1);
                emit_line(&mut outcome.text, prefix, index, line, '-', plan);
                last_printed = Some(index);
            }
            continue;
        }
        outcome.selected = outcome.selected.saturating_add(1);
        if quiet_output {
            if plan.quiet {
                break;
            }
            continue;
        }
        if binary {
            outcome.binary_hit = true;
            break;
        }
        let first_context = index.saturating_sub(plan.before);
        let from = match last_printed {
            Some(last) => first_context.max(last.saturating_add(1)),
            None => first_context,
        };
        let context_on = plan.before > 0 || plan.after > 0;
        if context_on
            && let Some(last) = last_printed
            && from > last.saturating_add(1)
        {
            outcome.text.extend_from_slice(b"--\n");
        }
        for ctx in from..index {
            if let Some(text) = lines.get(ctx) {
                emit_line(&mut outcome.text, prefix, ctx, text, '-', plan);
            }
        }
        if plan.only && !plan.invert {
            let mut at = 0usize;
            while let Some((start, end)) = search.find(&searched, at) {
                if end > start {
                    emit_line(
                        &mut outcome.text,
                        prefix,
                        index,
                        line.get(start..end).unwrap_or(&[]),
                        ':',
                        plan,
                    );
                    at = end;
                } else {
                    at = start.saturating_add(1);
                }
                if at > line.len() {
                    break;
                }
            }
        } else if !plan.only {
            emit_line(&mut outcome.text, prefix, index, line, ':', plan);
        }
        last_printed = Some(index);
        after_left = plan.after;
    }
    outcome
}

fn emit_line(out: &mut Vec<u8>, prefix: &str, index: usize, line: &[u8], sep: char, plan: &Plan) {
    if !prefix.is_empty() {
        out.extend_from_slice(prefix.as_bytes());
        if plan.null {
            out.push(0);
        } else {
            out.extend_from_slice(sep.to_string().as_bytes());
        }
    }
    if plan.number {
        out.extend_from_slice(format!("{}{sep}", index.saturating_add(1)).as_bytes());
    }
    out.extend_from_slice(line);
    out.push(b'\n');
}

impl FakeShell {
    /// `grep`: see the module documentation.
    pub(super) fn cmd_grep(&mut self, parts: &[&str]) -> CommandResult {
        let mut plan = match parse(parts.get(1..).unwrap_or(&[])) {
            Ok(plan) => plan,
            Err(refusal) => return refusal,
        };
        let mut acc = CommandResult::silent(0);
        let mut errored = false;
        let cap = self.read_cap();
        for file in plan.pattern_files.clone() {
            match self.read_source(parts, Some(file.as_str()), cap) {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    let body = text.strip_suffix('\n').unwrap_or(&text);
                    if !body.is_empty() || !text.is_empty() {
                        plan.patterns.extend(body.split('\n').map(str::to_string));
                    }
                }
                Err(error) => {
                    return CommandResult::stderr(
                        2,
                        format!("grep: {file}: {}\n", errno_text(&error)),
                    );
                }
            }
        }
        let kind = if plan.fixed {
            Kind::Fixed
        } else if plan.perl {
            Kind::Re(Syntax::Perl)
        } else if plan.extended {
            Kind::Re(Syntax::Extended)
        } else {
            Kind::Re(Syntax::Basic)
        };
        let mut matchers = Vec::new();
        for pattern in plan.patterns.iter().flat_map(|p| p.split('\n')) {
            match kind {
                Kind::Fixed => {
                    let needle = if plan.fold {
                        pattern.as_bytes().to_ascii_lowercase()
                    } else {
                        pattern.as_bytes().to_vec()
                    };
                    matchers.push(Matcher::Fixed(Box::new(Finder::new(&needle).into_owned())));
                }
                Kind::Re(syntax) => match Regex::new(pattern.as_bytes(), syntax, plan.fold) {
                    Ok(re) => matchers.push(Matcher::Re(re)),
                    Err(error) => {
                        return CommandResult::stderr(2, format!("grep: {}\n", error.message()));
                    }
                },
            }
        }
        let search = Search {
            matchers,
            fold: plan.fold,
            word: plan.word,
            whole_line: plan.whole_line,
            meter: Cell::default(),
        };
        let busybox = self.busybox_depth > 0;
        let mut names: Vec<Option<String>> = if plan.files.is_empty() {
            if plan.recursive {
                vec![Some(".".to_string())]
            } else {
                vec![None]
            }
        } else {
            plan.files.iter().map(|f| Some(f.clone())).collect()
        };
        if plan.recursive {
            names = self.grep_expand(names);
        }
        let labelled = plan
            .names
            .unwrap_or(names.len() > 1 || (plan.recursive && !plan.files.is_empty()));
        let mut any = false;
        let mut listed = false;
        for name in names {
            let label = match name.as_deref() {
                None | Some("-") => "(standard input)".to_string(),
                Some(path) => path.to_string(),
            };
            let bytes = match self.read_source(parts, name.as_deref(), cap) {
                Ok(bytes) => bytes,
                Err(error) => {
                    errored = true;
                    if !plan.no_messages {
                        acc.append(CommandResult::stderr(
                            2,
                            format!("grep: {label}: {}\n", errno_text(&error)),
                        ));
                    }
                    continue;
                }
            };
            // The read already charged one pass over the bytes (stdin was charged by whatever
            // produced it), so only the matchers' work beyond that pass is charged before the
            // scan. The scan may then spend one pass and whatever the line has left, and what it
            // spent past the one pass is charged after it: each byte read pays once.
            let one_pass = search.cost(bytes.len());
            let extra = one_pass.saturating_sub(len_u64(bytes.len()));
            if !self.charge_work(extra) || self.line.exhausted() {
                return stopped();
            }
            search.allow(one_pass.saturating_add(self.line.remaining()));
            let prefix = if labelled {
                label.clone()
            } else {
                String::new()
            };
            let found = scan(&bytes, &search, &plan, &prefix);
            let beyond = if search.over() {
                self.line.remaining().saturating_add(1)
            } else {
                search.spent().saturating_sub(one_pass)
            };
            if !self.charge_work(beyond) {
                return stopped();
            }
            any |= found.selected > 0;
            if plan.quiet {
                if any {
                    break;
                }
                continue;
            }
            if plan.list_matching {
                if found.selected > 0 {
                    acc.append(CommandResult::stdout(list_name(&label, plan.null)));
                }
                continue;
            }
            if plan.list_missing {
                if found.selected == 0 {
                    listed = true;
                    acc.append(CommandResult::stdout(list_name(&label, plan.null)));
                }
                continue;
            }
            if plan.count {
                let head = if labelled {
                    if plan.null {
                        format!("{label}\0")
                    } else {
                        format!("{label}:")
                    }
                } else {
                    String::new()
                };
                acc.append(CommandResult::stdout(format!("{head}{}\n", found.selected)));
            } else if found.binary_hit {
                // The BusyBox applet's wording [unverified]; GNU's was recorded.
                if busybox {
                    acc.append(CommandResult::stdout(format!(
                        "Binary file {label} matches\n"
                    )));
                } else {
                    acc.append(CommandResult::stderr(
                        0,
                        format!("grep: {label}: binary file matches\n"),
                    ));
                }
            } else {
                acc.append(CommandResult::stdout(found.text));
            }
        }
        acc.status = if plan.quiet && any {
            0
        } else if errored {
            2
        } else if plan.list_missing {
            // grep 3.7: success means a file was listed (recorded: `-L` listing one file is 0).
            u8::from(!listed)
        } else {
            u8::from(!any)
        };
        acc
    }

    /// The files a recursive grep reads under each operand, in listing order, bounded.
    fn grep_expand(&mut self, operands: Vec<Option<String>>) -> Vec<Option<String>> {
        let mut out = Vec::new();
        for operand in operands {
            match operand {
                Some(path) if path != "-" => {
                    let logical = self.normalize_logical(&path);
                    self.grep_walk(&path, &logical, 0, &mut out);
                }
                other => out.push(other),
            }
        }
        out
    }

    fn grep_walk(&mut self, shown: &str, logical: &str, depth: u32, out: &mut Vec<Option<String>>) {
        if out.len() >= RECURSE_MAX || !self.charge_work(1) {
            return;
        }
        if !self.fs.is_dir(logical) {
            out.push(Some(shown.to_string()));
            return;
        }
        if depth >= RECURSE_DEPTH {
            return;
        }
        let Some(mut entries) = self.fs.list_dir(logical) else {
            return;
        };
        entries.sort();
        for entry in entries {
            let child_shown = if shown.ends_with('/') {
                format!("{shown}{entry}")
            } else {
                format!("{shown}/{entry}")
            };
            let child_logical = format!("{}/{entry}", logical.trim_end_matches('/'));
            // Links are not followed by `-r`, as GNU does not.
            if self.fs.link_target(&child_logical).is_some() {
                continue;
            }
            self.grep_walk(&child_shown, &child_logical, depth.saturating_add(1), out);
        }
    }
}

fn list_name(label: &str, null: bool) -> String {
    if null {
        format!("{label}\0")
    } else {
        format!("{label}\n")
    }
}
