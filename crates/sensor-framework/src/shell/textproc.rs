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
    r.register_if("cut", ubuntu, HandlerId::Cut, FakeShell::cmd_cut);
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
    plan.spans = parse_list(&list, mode)?;
    Ok(plan)
}

fn selected(spans: &[Span], index: usize, complement: bool) -> bool {
    let inside = spans
        .iter()
        .any(|s| index >= s.from && s.to.is_none_or(|to| index <= to));
    inside != complement
}

fn cut_line(line: &[u8], plan: &CutPlan, out: &mut Vec<u8>, terminator: u8) {
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
                    {
                        out.extend_from_slice(sep);
                    }
                    out.push(byte);
                    first_run = false;
                }
                previous_kept = keep;
            }
            out.push(terminator);
        }
        Mode::Fields => {
            if !line.contains(&plan.delimiter) {
                if !plan.only_delimited {
                    out.extend_from_slice(line);
                    out.push(terminator);
                }
                return;
            }
            let sep = plan
                .output_delimiter
                .clone()
                .unwrap_or_else(|| vec![plan.delimiter]);
            let mut first = true;
            for (index, field) in line.split(|b| *b == plan.delimiter).enumerate() {
                if selected(&plan.spans, index.saturating_add(1), plan.complement) {
                    if !first {
                        out.extend_from_slice(&sep);
                    }
                    out.extend_from_slice(field);
                    first = false;
                }
            }
            out.push(terminator);
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
            let mut out = Vec::new();
            if !bytes.is_empty() {
                let body = bytes.strip_suffix(&[terminator]).unwrap_or(&bytes);
                for line in body.split(|b| *b == terminator) {
                    cut_line(line, &plan, &mut out, terminator);
                }
            }
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
        for file in files {
            if file == "-" {
                // coreutils 8.32 treats `-` as a file name for tee [unverified]; it is rare.
                acc.append(CommandResult::stdout(data.clone()));
                continue;
            }
            let path = self.resolve_logical(file);
            if self.fs.is_dir(&path) {
                failed = true;
                acc.append(CommandResult::stderr(
                    1,
                    format!("tee: {file}: Is a directory\n"),
                ));
                continue;
            }
            let mut content = if append {
                self.fs.read_all(&path, READ_CAP).unwrap_or_default()
            } else {
                Vec::new()
            };
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
