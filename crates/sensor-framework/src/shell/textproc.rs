//! `cut` and `tee`, GNU coreutils 8.32: the field splitter every survey pipes through
//! (`grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2`) and the writer a dropper saves a
//! streamed script with (`... | tee /etc/systemd/system/x.service`).
//!
//! Both read and write the modeled bytes only. `tee` writes its files through the same traced
//! filesystem calls as a redirection, so a body it saves from the session input is noted as the
//! line's input sink and captured like `cat > FILE`. Messages were recorded from Ubuntu 22.04
//! (2026-10-07 reference session): `cut`'s missing-list and numbering errors, `tee`'s per-file
//! open error with status 1.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::read::errno_text;
use super::registry::Registry;
use super::texttools::stopped;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};
use crate::fakefs::{FsError, READ_CAP};

pub(super) fn register(r: &mut Registry) {
    r.register_if(
        "cut",
        super::multicall::bare_applet,
        HandlerId::Cut,
        FakeShell::cmd_cut,
    );
    r.register_if("tee", ubuntu, HandlerId::Tee, FakeShell::cmd_tee);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

fn try_help(cmd: &str) -> String {
    format!("Try '{cmd} --help' for more information.\n")
}

fn usage(cmd: &str, text: &str) -> CommandResult {
    CommandResult::stderr(1, format!("{cmd}: {text}\n{}", try_help(cmd)))
}

// ----------------------------------------------------------------------------------------- cut

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Bytes,
    Fields,
}

/// One `N`, `N-`, `-M` or `N-M` of a list, 1-based and inclusive; `None` is open.
#[derive(Clone, Copy)]
struct Span {
    from: usize,
    to: Option<usize>,
}

struct CutPlan {
    mode: Mode,
    spans: Vec<Span>,
    delimiter: u8,
    only_delimited: bool,
    complement: bool,
    output_delimiter: Option<Vec<u8>>,
    zero: bool,
    files: Vec<String>,
}

fn parse_list(list: &str, mode: Mode) -> Result<Vec<Span>, CommandResult> {
    let numbered = match mode {
        Mode::Fields => "fields are numbered from 1",
        Mode::Bytes => "byte/character positions are numbered from 1",
    };
    let invalid = match mode {
        Mode::Fields => "invalid field range",
        Mode::Bytes => "invalid byte or character range",
    };
    let number = |text: &str| -> Result<usize, CommandResult> {
        let value = text.parse::<usize>().map_err(|_| usage("cut", invalid))?;
        if value == 0 {
            return Err(usage("cut", numbered));
        }
        Ok(value)
    };
    let mut spans = Vec::new();
    for item in list.split([',', ' ']) {
        if item.is_empty() {
            return Err(usage("cut", invalid));
        }
        let span = match item.split_once('-') {
            None => {
                let n = number(item)?;
                Span {
                    from: n,
                    to: Some(n),
                }
            }
            Some(("", "")) => return Err(usage("cut", "invalid range with no endpoint: -")),
            Some(("", to)) => Span {
                from: 1,
                to: Some(number(to)?),
            },
            Some((from, "")) => Span {
                from: number(from)?,
                to: None,
            },
            Some((from, to)) => {
                let (from, to) = (number(from)?, number(to)?);
                if to < from {
                    return Err(usage("cut", "invalid decreasing range"));
                }
                Span { from, to: Some(to) }
            }
        };
        spans.push(span);
    }
    Ok(spans)
}

fn parse_cut(args: &[&str]) -> Result<CutPlan, CommandResult> {
    let mut mode: Option<Mode> = None;
    let mut list: Option<String> = None;
    let mut delimiter: Option<String> = None;
    let mut plan = CutPlan {
        mode: Mode::Bytes,
        spans: Vec::new(),
        delimiter: b'\t',
        only_delimited: false,
        complement: false,
        output_delimiter: None,
        zero: false,
        files: Vec::new(),
    };
    let set_mode = |mode: &mut Option<Mode>, new: Mode| -> Result<(), CommandResult> {
        if mode.is_some_and(|m| m != new) {
            return Err(usage("cut", "only one type of list may be specified"));
        }
        *mode = Some(new);
        Ok(())
    };
    let mut options = true;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if !options || arg == "-" || !arg.starts_with('-') {
            plan.files.push(arg.to_string());
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let value = |i: &mut usize| -> Result<String, CommandResult> {
                if let Some(v) = inline.clone() {
                    return Ok(v);
                }
                let v = args.get(*i).ok_or_else(|| {
                    usage("cut", &format!("option '--{name}' requires an argument"))
                })?;
                *i = i.saturating_add(1);
                Ok((*v).to_string())
            };
            match name {
                "bytes" | "characters" => {
                    set_mode(&mut mode, Mode::Bytes)?;
                    list = Some(value(&mut i)?);
                }
                "fields" => {
                    set_mode(&mut mode, Mode::Fields)?;
                    list = Some(value(&mut i)?);
                }
                "delimiter" => delimiter = Some(value(&mut i)?),
                "only-delimited" => plan.only_delimited = true,
                "complement" => plan.complement = true,
                "output-delimiter" => plan.output_delimiter = Some(value(&mut i)?.into_bytes()),
                "zero-terminated" => plan.zero = true,
                _ => return Err(usage("cut", &format!("unrecognized option '{arg}'"))),
            }
            continue;
        }
        let cluster: Vec<char> = arg.chars().skip(1).collect();
        let mut at = 0usize;
        while let Some(&flag) = cluster.get(at) {
            at = at.saturating_add(1);
            let mut value = |i: &mut usize| -> Result<String, CommandResult> {
                let rest: String = cluster.get(at..).unwrap_or(&[]).iter().collect();
                at = cluster.len();
                if !rest.is_empty() {
                    return Ok(rest);
                }
                let v = args.get(*i).ok_or_else(|| {
                    usage("cut", &format!("option requires an argument -- '{flag}'"))
                })?;
                *i = i.saturating_add(1);
                Ok((*v).to_string())
            };
            match flag {
                'b' | 'c' => {
                    set_mode(&mut mode, Mode::Bytes)?;
                    list = Some(value(&mut i)?);
                }
                'f' => {
                    set_mode(&mut mode, Mode::Fields)?;
                    list = Some(value(&mut i)?);
                }
                'd' => delimiter = Some(value(&mut i)?),
                's' => plan.only_delimited = true,
                'z' => plan.zero = true,
                'n' => {}
                other => return Err(usage("cut", &format!("invalid option -- '{other}'"))),
            }
        }
    }
    let (Some(mode), Some(list)) = (mode, list) else {
        return Err(usage(
            "cut",
            "you must specify a list of bytes, characters, or fields",
        ));
    };
    plan.mode = mode;
    if let Some(delim) = delimiter {
        if mode != Mode::Fields {
            return Err(usage(
                "cut",
                "an input delimiter may be specified only when operating on fields",
            ));
        }
        match delim.as_bytes() {
            [one] => plan.delimiter = *one,
            [] => plan.delimiter = b'\0',
            _ => {
                return Err(usage("cut", "the delimiter must be a single character"));
            }
        }
    }
    if plan.only_delimited && mode != Mode::Fields {
        return Err(usage(
            "cut",
            "suppressing non-delimited lines makes sense\n\tonly when operating on fields",
        ));
    }
    plan.spans = merged(parse_list(&list, mode)?);
    Ok(plan)
}

/// The spans of a list in ascending order with every overlapping or adjacent pair joined (a
/// position is selected or not, so output is the same; GNU keeps adjacent ranges apart only for
/// the output delimiter, which this model does not place between them), so a position is found by binary search: a list of thousands
/// of spans is searched for each byte of the input.
fn merged(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by_key(|span| span.from);
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        match out.last_mut() {
            Some(last) if last.to.is_none_or(|to| span.from <= to.saturating_add(1)) => {
                last.to = match (last.to, span.to) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    _ => None,
                };
            }
            _ => out.push(span),
        }
    }
    out
}

/// Whether 1-based `index` is selected by `spans`, which [`merged`] sorted and joined.
fn selected(spans: &[Span], index: usize, complement: bool) -> bool {
    let after = spans.partition_point(|span| span.from <= index);
    let inside = after
        .checked_sub(1)
        .and_then(|at| spans.get(at))
        .is_some_and(|span| span.to.is_none_or(|to| index <= to));
    inside != complement
}

/// `out` with `piece` added, unless that takes it past `room` bytes: the output delimiter is the
/// attacker's length and goes in before every field, so what one line of input makes is bounded
/// by what the line may still spend, not by the input.
fn put(out: &mut Vec<u8>, piece: &[u8], room: usize) -> bool {
    if out.len().saturating_add(piece.len()) > room {
        return false;
    }
    out.extend_from_slice(piece);
    true
}

/// One line of input cut into `out`. False, with `out` left short, once the output would pass
/// `room` bytes.
fn cut_line(line: &[u8], plan: &CutPlan, out: &mut Vec<u8>, terminator: u8, room: usize) -> bool {
    match plan.mode {
        Mode::Bytes => {
            let mut first_run = true;
            let mut previous_kept = false;
            for (offset, &byte) in line.iter().enumerate() {
                let keep = selected(&plan.spans, offset.saturating_add(1), plan.complement);
                if keep {
                    if let Some(sep) = &plan.output_delimiter
                        && !previous_kept
                        && !first_run
                        && !put(out, sep, room)
                    {
                        return false;
                    }
                    if !put(out, &[byte], room) {
                        return false;
                    }
                    first_run = false;
                }
                previous_kept = keep;
            }
            put(out, &[terminator], room)
        }
        Mode::Fields => {
            if !line.contains(&plan.delimiter) {
                if plan.only_delimited {
                    return true;
                }
                return put(out, line, room) && put(out, &[terminator], room);
            }
            let own = [plan.delimiter];
            let sep = plan.output_delimiter.as_deref().unwrap_or(&own);
            let mut first = true;
            for (index, field) in line.split(|b| *b == plan.delimiter).enumerate() {
                if selected(&plan.spans, index.saturating_add(1), plan.complement) {
                    if !first && !put(out, sep, room) {
                        return false;
                    }
                    if !put(out, field, room) {
                        return false;
                    }
                    first = false;
                }
            }
            put(out, &[terminator], room)
        }
    }
}

impl FakeShell {
    /// `cut -b|-c|-f LIST [-d D] [-s] [--complement] [--output-delimiter=S] [FILE...]`.
    pub(super) fn cmd_cut(&mut self, parts: &[&str]) -> CommandResult {
        let plan = match parse_cut(parts.get(1..).unwrap_or(&[])) {
            Ok(plan) => plan,
            Err(refusal) => return refusal,
        };
        let names: Vec<Option<String>> = if plan.files.is_empty() {
            vec![None]
        } else {
            plan.files.iter().map(|f| Some(f.clone())).collect()
        };
        let terminator = if plan.zero { b'\0' } else { b'\n' };
        let cap = self.read_cap();
        let mut acc = CommandResult::silent(0);
        let mut failed = false;
        let mut produced = 0usize;
        for name in names {
            let bytes = match self.read_source(parts, name.as_deref(), cap) {
                Ok(bytes) => bytes,
                Err(error) => {
                    failed = true;
                    acc.append(CommandResult::stderr(
                        1,
                        format!(
                            "cut: {}: {}\n",
                            name.as_deref().unwrap_or("-"),
                            errno_text(&error)
                        ),
                    ));
                    continue;
                }
            };
            if !self.charge_work(len_u64(bytes.len())) {
                return stopped();
            }
            // What the line can still pay for, less what earlier operands produced: the output
            // is charged once the command returns, so it is bounded here, as it is built.
            let room = usize::try_from(self.line.remaining())
                .unwrap_or(usize::MAX)
                .saturating_sub(produced);
            let mut out = Vec::new();
            if !bytes.is_empty() {
                let body = bytes.strip_suffix(&[terminator]).unwrap_or(&bytes);
                for line in body.split(|b| *b == terminator) {
                    if !cut_line(line, &plan, &mut out, terminator, room) {
                        return stopped();
                    }
                }
            }
            produced = produced.saturating_add(out.len());
            acc.append(CommandResult::stdout(out));
        }
        acc.status = u8::from(failed);
        acc
    }
}

// ----------------------------------------------------------------------------------------- tee

impl FakeShell {
    /// `tee [-a] [-i] [-p] [FILE...]`: standard input to standard output and to every file.
    pub(super) fn cmd_tee(&mut self, parts: &[&str]) -> CommandResult {
        let mut append = false;
        let mut files: Vec<&str> = Vec::new();
        let mut options = true;
        for &arg in parts.get(1..).unwrap_or(&[]) {
            if !options || arg == "-" || !arg.starts_with('-') {
                files.push(arg);
                continue;
            }
            if arg == "--" {
                options = false;
                continue;
            }
            if let Some(long) = arg.strip_prefix("--") {
                match long {
                    "append" => append = true,
                    "ignore-interrupts" => {}
                    _ if long == "output-error" || long.starts_with("output-error=") => {}
                    _ => return usage("tee", &format!("unrecognized option '{arg}'")),
                }
                continue;
            }
            for flag in arg.chars().skip(1) {
                match flag {
                    'a' => append = true,
                    'i' | 'p' => {}
                    other => return usage("tee", &format!("invalid option -- '{other}'")),
                }
            }
        }
        let cap = self.read_cap();
        let data = self.stdin.take(cap);
        if !self.charge_work(len_u64(data.len())) {
            return stopped();
        }
        let mut acc = CommandResult::stdout(data.clone());
        let mut failed = false;
        // `-` is a file like any other: coreutils' tee does not treat it specially, as POSIX
        // requires: `echo hi | tee - - | wc -c` is 3 and leaves a file named `-` under coreutils
        // 9.10 [unverified for 8.32, not captured from the reference container].
        for file in files {
            let path = self.resolve_logical(file);
            if self.fs.is_dir(&path) {
                failed = true;
                acc.append(CommandResult::stderr(
                    1,
                    format!("tee: {file}: Is a directory\n"),
                ));
                continue;
            }
            // Each file costs the line what is copied into it, before the copy is made, so a
            // thousand operands cost a thousand copies of the input and the line stops.
            let mut content = if append {
                match self.read_charged(&path, READ_CAP) {
                    Some(read) => read.unwrap_or_default(),
                    None => return stopped(),
                }
            } else {
                Vec::new()
            };
            if !self.charge_work(len_u64(data.len())) {
                return stopped();
            }
            content.extend_from_slice(&data);
            if let Err(error) = self.traced_write_file(&path, &content) {
                failed = true;
                let reason = match &error {
                    FsError::ReadOnly => "Read-only file system",
                    other => {
                        super::budget_refusal_text(other).unwrap_or("No such file or directory")
                    }
                };
                acc.append(CommandResult::stderr(1, format!("tee: {file}: {reason}\n")));
            }
        }
        acc.status = u8::from(failed);
        acc
    }
}
