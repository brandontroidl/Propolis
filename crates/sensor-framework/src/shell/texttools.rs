//! `wc`, `grep -F` and `od`: the tools a recorded chain inspects a file it just wrote with
//! (`wc -c .fxcat` is `1 .fxcat`, `od -An -tx1 .fxcat` is ` 0a`, pty README finding 7).
//!
//! Each reads the modeled bytes of its operands (or standard input) through the same bounded
//! reader as `cat`, so the figures come from the file the session holds and cannot drift from it.
//! What a tool is not asked to model it does not invent: an option or format outside the recorded
//! ones prints nothing and succeeds, never a count, match or dump this shell made up.
//!
//! Standard input at the terminal reads as empty, as it does for `cat`.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::read::errno_text;
use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};
use crate::fakefs::{FileKind, FsError};

pub(super) fn register(r: &mut Registry) {
    // The phone's toolbox has no recorded answer for these, and it answers "not found" today.
    r.register_if("wc", ubuntu, HandlerId::Wc, FakeShell::cmd_wc);
    r.register_if("grep", ubuntu, HandlerId::Grep, FakeShell::cmd_grep);
    r.register_if("od", ubuntu, HandlerId::Od, FakeShell::cmd_od);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// The result of a line whose allowance ran out while a tool was reading.
fn stopped() -> CommandResult {
    let mut result = CommandResult::silent(1);
    result.stop_line = true;
    result
}

/// GNU's column width when a count comes from standard input or a file that is not a regular one.
const WIDE: usize = 7;

impl FakeShell {
    /// Up to `limit` bytes of one operand: standard input for no operand or `-`.
    fn read_source(
        &mut self,
        argv: &[&str],
        path: Option<&str>,
        limit: u64,
    ) -> Result<Vec<u8>, FsError> {
        match path {
            None | Some("-") => Ok(self.stdin.take(limit)),
            Some(path) => self.read_operand(argv, path, 0, limit),
        }
    }

    /// Whether `path` is a file GNU `wc` sizes by content only (a device, a directory) rather than
    /// by its length.
    fn is_special(&mut self, path: &str) -> bool {
        let logical = self.normalize_logical(path);
        self.fs
            .stat(&logical, true)
            .is_some_and(|stat| stat.kind != FileKind::Regular)
    }
}

// ---------------------------------------------------------------------------------------- wc

const WC_TRY: &str = "Try 'wc --help' for more information.\n";

struct WcPlan<'a> {
    lines: bool,
    words: bool,
    chars: bool,
    bytes: bool,
    files: Vec<&'a str>,
}

impl WcPlan<'_> {
    fn selected(&self) -> usize {
        [self.lines, self.words, self.chars, self.bytes]
            .into_iter()
            .filter(|on| *on)
            .count()
    }
}

/// What `wc`'s command line asks for: a plan, the tool's own error text (status 1), or `None`
/// for an option the tool has that this shell does not model.
fn parse_wc<'a>(args: &[&'a str]) -> Option<Result<WcPlan<'a>, String>> {
    let mut plan = WcPlan {
        lines: false,
        words: false,
        chars: false,
        bytes: false,
        files: Vec::new(),
    };
    let mut options = true;
    for &arg in args {
        if !options || arg == "-" || !arg.starts_with('-') {
            plan.files.push(arg);
        } else if arg == "--" {
            options = false;
        } else if let Some(long) = arg.strip_prefix("--") {
            match long {
                "bytes" => plan.bytes = true,
                "lines" => plan.lines = true,
                "words" => plan.words = true,
                "chars" => plan.chars = true,
                "max-line-length" | "files0-from" | "total" => return None,
                _ if long.starts_with("files0-from=") || long.starts_with("total=") => {
                    return None;
                }
                _ => {
                    return Some(Err(format!("wc: unrecognized option '{arg}'\n{WC_TRY}")));
                }
            }
        } else {
            for flag in arg.get(1..).unwrap_or("").chars() {
                match flag {
                    'c' => plan.bytes = true,
                    'l' => plan.lines = true,
                    'w' => plan.words = true,
                    'm' => plan.chars = true,
                    'L' => return None,
                    other => {
                        return Some(Err(format!("wc: invalid option -- '{other}'\n{WC_TRY}")));
                    }
                }
            }
        }
    }
    if plan.selected() == 0 {
        plan.lines = true;
        plan.words = true;
        plan.bytes = true;
    }
    Some(Ok(plan))
}

#[derive(Clone, Copy, Default)]
struct Counts {
    lines: u64,
    words: u64,
    bytes: u64,
}

impl Counts {
    fn of(data: &[u8]) -> Self {
        let mut counts = Self {
            bytes: len_u64(data.len()),
            ..Self::default()
        };
        let mut in_word = false;
        for &byte in data {
            if byte == b'\n' {
                counts.lines = counts.lines.saturating_add(1);
            }
            // `isspace` in the C locale.
            if matches!(byte, b' ' | 0x09..=0x0d) {
                in_word = false;
            } else if !in_word {
                in_word = true;
                counts.words = counts.words.saturating_add(1);
            }
        }
        counts
    }

    fn add(&mut self, other: Self) {
        self.lines = self.lines.saturating_add(other.lines);
        self.words = self.words.saturating_add(other.words);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }
}

/// One operand of a `wc` run once read.
struct WcSlot<'a> {
    /// `None` for the implicit standard input, which prints no name.
    name: Option<&'a str>,
    /// What to print for it: `None` when the file could not be opened.
    counts: Option<Counts>,
    /// The tool's complaint about it, printed before its counts.
    error: Option<String>,
    /// Standard input or a file that is not a regular one: GNU pads to [`WIDE`] columns.
    special: bool,
}

/// GNU `wc` right-aligns each count to one width for the whole run. A lone count of a lone operand
/// is unpadded. Otherwise the width is the digits of the regular files' summed length, and at
/// least [`WIDE`] once standard input or a special file is among them.
fn wc_width(selected: usize, slots: &[WcSlot<'_>]) -> usize {
    if selected == 1 && slots.len() <= 1 {
        return 1;
    }
    let mut floor = 1;
    let mut total = 0u64;
    for slot in slots {
        if slot.special {
            floor = WIDE;
        } else if let Some(counts) = slot.counts {
            total = total.saturating_add(counts.bytes);
        }
    }
    total.to_string().len().max(floor)
}

fn wc_row(plan: &WcPlan<'_>, counts: Counts, width: usize, name: Option<&str>) -> String {
    let mut columns = Vec::new();
    if plan.lines {
        columns.push(counts.lines);
    }
    if plan.words {
        columns.push(counts.words);
    }
    // No multibyte locale is modeled, so a character is a byte.
    if plan.chars {
        columns.push(counts.bytes);
    }
    if plan.bytes {
        columns.push(counts.bytes);
    }
    let cells: Vec<String> = columns.iter().map(|n| format!("{n:>width$}")).collect();
    let mut row = cells.join(" ");
    if let Some(name) = name {
        row.push(' ');
        row.push_str(name);
    }
    row.push('\n');
    row
}

impl FakeShell {
    /// `wc` for `-c -l -w -m` over standard input or files, with GNU's layout and the `total` row
    /// for several operands. `-L` and the long options with arguments are not modeled.
    pub(super) fn cmd_wc(&mut self, parts: &[&str]) -> CommandResult {
        let plan = match parse_wc(parts.get(1..).unwrap_or(&[])) {
            Some(Ok(plan)) => plan,
            Some(Err(text)) => return CommandResult::stderr(1, text),
            None => return CommandResult::silent(0),
        };
        let names: Vec<Option<&str>> = if plan.files.is_empty() {
            vec![None]
        } else {
            plan.files.iter().copied().map(Some).collect()
        };
        let cap = self.read_cap();
        let mut slots = Vec::new();
        for name in names {
            let mut slot = WcSlot {
                name,
                counts: None,
                error: None,
                special: matches!(name, None | Some("-")),
            };
            match self.read_source(parts, name, cap) {
                Ok(bytes) => {
                    // Scanning is work the line pays for, output or not.
                    if !self.charge_work(len_u64(bytes.len())) {
                        return stopped();
                    }
                    slot.counts = Some(Counts::of(&bytes));
                    if let Some(path) = name.filter(|path| *path != "-") {
                        slot.special = self.is_special(path);
                    }
                }
                Err(error) => {
                    let text = format!("wc: {}: {}\n", name.unwrap_or("-"), errno_text(&error));
                    slot.error = Some(text);
                    if matches!(error, FsError::IsADirectory) {
                        // Reading a directory fails, and the row of zeros is still printed.
                        slot.counts = Some(Counts::default());
                        slot.special = true;
                    }
                }
            }
            slots.push(slot);
        }
        let width = wc_width(plan.selected(), &slots);
        let mut acc = CommandResult::silent(0);
        let mut failed = false;
        let mut total = Counts::default();
        for slot in &slots {
            if let Some(text) = &slot.error {
                failed = true;
                acc.append(CommandResult::stderr(1, text.as_str()));
            }
            if let Some(counts) = slot.counts {
                total.add(counts);
                acc.append(CommandResult::stdout(wc_row(
                    &plan, counts, width, slot.name,
                )));
            }
        }
        if slots.len() > 1 {
            acc.append(CommandResult::stdout(wc_row(
                &plan,
                total,
                width,
                Some("total"),
            )));
        }
        acc.status = u8::from(failed);
        acc
    }
}

// -------------------------------------------------------------------------------------- grep

const GREP_USAGE: &str =
    "Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n";

struct GrepPlan<'a> {
    fixed: bool,
    count: bool,
    invert: bool,
    fold: bool,
    pattern: Option<&'a str>,
    files: Vec<&'a str>,
}

/// The command line of a `grep`, or `None` for any option outside `-F -c -v -i`.
fn parse_grep<'a>(args: &[&'a str]) -> Option<GrepPlan<'a>> {
    let mut plan = GrepPlan {
        fixed: false,
        count: false,
        invert: false,
        fold: false,
        pattern: None,
        files: Vec::new(),
    };
    let mut options = true;
    for &arg in args {
        if !options || arg == "-" || !arg.starts_with('-') {
            if plan.pattern.is_none() {
                plan.pattern = Some(arg);
            } else {
                plan.files.push(arg);
            }
        } else if arg == "--" {
            options = false;
        } else if let Some(long) = arg.strip_prefix("--") {
            match long {
                "fixed-strings" => plan.fixed = true,
                "count" => plan.count = true,
                "invert-match" => plan.invert = true,
                "ignore-case" => plan.fold = true,
                _ => return None,
            }
        } else {
            for flag in arg.get(1..).unwrap_or("").chars() {
                match flag {
                    'F' => plan.fixed = true,
                    'c' => plan.count = true,
                    'v' => plan.invert = true,
                    'i' => plan.fold = true,
                    _ => return None,
                }
            }
        }
    }
    Some(plan)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// What one input yielded: how many lines were selected and the text to print for them.
struct Selection {
    selected: u64,
    text: Vec<u8>,
    /// The input holds a NUL and a line was selected, so it is reported instead of printed.
    binary_hit: bool,
}

/// The lines of `data` that match any of `patterns` (or, inverted, none of them).
fn select_lines(data: &[u8], patterns: &[Vec<u8>], plan: &GrepPlan<'_>, prefix: &str) -> Selection {
    let mut selection = Selection {
        selected: 0,
        text: Vec::new(),
        binary_hit: false,
    };
    if data.is_empty() {
        return selection;
    }
    let binary = data.contains(&0);
    let body = data.strip_suffix(b"\n").unwrap_or(data);
    for line in body.split(|byte| *byte == b'\n') {
        let hit = if plan.fold {
            let folded = line.to_ascii_lowercase();
            patterns.iter().any(|pattern| contains(&folded, pattern))
        } else {
            patterns.iter().any(|pattern| contains(line, pattern))
        };
        if hit == plan.invert {
            continue;
        }
        selection.selected = selection.selected.saturating_add(1);
        if plan.count {
            continue;
        }
        if binary {
            selection.binary_hit = true;
            break;
        }
        selection.text.extend_from_slice(prefix.as_bytes());
        selection.text.extend_from_slice(line);
        selection.text.push(b'\n');
    }
    selection
}

impl FakeShell {
    /// `grep -F` (with `-c`, `-v`, `-i`) over standard input or files: the lines containing the
    /// literal pattern, status 0 if one was selected, 1 if none, 2 on an error. No regular
    /// expression engine exists here, so a pattern searched without `-F`, or any other option, is
    /// not modeled: it prints nothing and succeeds.
    pub(super) fn cmd_grep(&mut self, parts: &[&str]) -> CommandResult {
        let Some(plan) = parse_grep(parts.get(1..).unwrap_or(&[])) else {
            return CommandResult::silent(0);
        };
        let Some(pattern) = plan.pattern else {
            return CommandResult::stderr(2, GREP_USAGE);
        };
        if !plan.fixed {
            return CommandResult::silent(0);
        }
        let folded;
        let pattern = if plan.fold {
            folded = pattern.to_ascii_lowercase();
            folded.as_str()
        } else {
            pattern
        };
        // Each line of the pattern text is one pattern.
        let patterns: Vec<Vec<u8>> = pattern
            .split('\n')
            .map(|line| line.as_bytes().to_vec())
            .collect();
        let busybox = self.busybox_depth > 0;
        let names: Vec<Option<&str>> = if plan.files.is_empty() {
            vec![None]
        } else {
            plan.files.iter().copied().map(Some).collect()
        };
        let labelled = names.len() > 1;
        let cap = self.read_cap();
        let mut acc = CommandResult::silent(0);
        let mut errored = false;
        let mut any = false;
        for name in names {
            let label = match name {
                None | Some("-") => "(standard input)",
                Some(path) => path,
            };
            let bytes = match self.read_source(parts, name, cap) {
                Ok(bytes) => bytes,
                Err(error) => {
                    errored = true;
                    acc.append(CommandResult::stderr(
                        2,
                        format!("grep: {label}: {}\n", errno_text(&error)),
                    ));
                    continue;
                }
            };
            if !self.charge_work(len_u64(bytes.len())) {
                return stopped();
            }
            let prefix = if labelled && !plan.count {
                format!("{label}:")
            } else {
                String::new()
            };
            let picked = select_lines(&bytes, &patterns, &plan, &prefix);
            any |= picked.selected > 0;
            if plan.count {
                let head = if labelled {
                    format!("{label}:")
                } else {
                    String::new()
                };
                acc.append(CommandResult::stdout(format!(
                    "{head}{}\n",
                    picked.selected
                )));
            } else if picked.binary_hit {
                // [unverified] both wordings: GNU 3.7 reports on standard error, the BusyBox
                // applet on standard output; neither was captured.
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
                acc.append(CommandResult::stdout(picked.text));
            }
        }
        acc.status = if errored { 2 } else { u8::from(!any) };
        acc
    }
}

// ---------------------------------------------------------------------------------------- od

#[derive(Clone, Copy, PartialEq, Eq)]
enum Radix {
    None,
    Octal,
    Decimal,
    Hex,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    /// `-t x1`: each byte as two hex digits.
    Hex1,
    /// The default and `-o`: each two-byte little-endian word as six octal digits.
    Octal2,
}

struct OdPlan<'a> {
    radix: Radix,
    format: Format,
    verbose: bool,
    files: Vec<&'a str>,
}

/// The value of an option that is attached (`-tx1`) or is the next word (`-t x1`).
fn od_value<'a>(
    cluster: &'a str,
    at: usize,
    args: &[&'a str],
    next: &mut usize,
) -> Option<&'a str> {
    let attached = cluster.get(at.saturating_add(1)..).unwrap_or("");
    if attached.is_empty() {
        let value = args.get(*next).copied()?;
        *next = next.saturating_add(1);
        Some(value)
    } else {
        Some(attached)
    }
}

/// The plan for an `od` command line, or `None` for anything but the address radix, the `x1`
/// and default word formats, `-v` and file operands.
fn parse_od<'a>(args: &[&'a str]) -> Option<OdPlan<'a>> {
    let mut plan = OdPlan {
        radix: Radix::Octal,
        format: Format::Octal2,
        verbose: false,
        files: Vec::new(),
    };
    let mut formats = 0u32;
    let mut options = true;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if !options || arg == "-" || !arg.starts_with('-') {
            plan.files.push(arg);
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        if arg.starts_with("--") {
            return None;
        }
        let cluster = arg.get(1..).unwrap_or("");
        for (at, flag) in cluster.char_indices() {
            match flag {
                'A' => {
                    plan.radix = match od_value(cluster, at, args, &mut i)? {
                        "n" => Radix::None,
                        "o" => Radix::Octal,
                        "d" => Radix::Decimal,
                        "x" => Radix::Hex,
                        _ => return None,
                    };
                    break;
                }
                't' => {
                    plan.format = match od_value(cluster, at, args, &mut i)? {
                        "x1" => Format::Hex1,
                        "o2" => Format::Octal2,
                        _ => return None,
                    };
                    formats = formats.saturating_add(1);
                    break;
                }
                'o' => {
                    plan.format = Format::Octal2;
                    formats = formats.saturating_add(1);
                }
                'v' => plan.verbose = true,
                _ => return None,
            }
        }
    }
    (formats <= 1).then_some(plan)
}

fn od_address(radix: Radix, offset: usize) -> String {
    match radix {
        Radix::None => String::new(),
        Radix::Octal => format!("{offset:07o}"),
        Radix::Decimal => format!("{offset:07}"),
        Radix::Hex => format!("{offset:06x}"),
    }
}

/// `data` as `od` lays it out: sixteen bytes a line, each item led by a space, a line identical to
/// the one before it collapsed into one `*` (unless `-v`), and, with an address column, a last line
/// giving the length.
fn od_render(data: &[u8], plan: &OdPlan<'_>) -> String {
    let mut out = String::new();
    let mut previous: Option<&[u8]> = None;
    let mut starred = false;
    let mut offset = 0usize;
    for chunk in data.chunks(16) {
        let full = chunk.len() == 16;
        if !plan.verbose && full && previous == Some(chunk) {
            if !starred {
                out.push_str("*\n");
                starred = true;
            }
            offset = offset.saturating_add(chunk.len());
            continue;
        }
        starred = false;
        previous = full.then_some(chunk);
        out.push_str(&od_address(plan.radix, offset));
        match plan.format {
            Format::Hex1 => {
                for byte in chunk {
                    out.push_str(&format!(" {byte:02x}"));
                }
            }
            Format::Octal2 => {
                for pair in chunk.chunks(2) {
                    let low = pair.first().copied().unwrap_or(0);
                    let high = pair.get(1).copied().unwrap_or(0);
                    let word = u16::from_le_bytes([low, high]);
                    out.push_str(&format!(" {word:06o}"));
                }
            }
        }
        out.push('\n');
        offset = offset.saturating_add(chunk.len());
    }
    if plan.radix != Radix::None {
        out.push_str(&od_address(plan.radix, data.len()));
        out.push('\n');
    }
    out
}

impl FakeShell {
    /// `od` for `-An -tx1` (the form the recorded chain inspects a file with) and the default
    /// octal words, over standard input or the concatenated files. Any other format, option or
    /// address radix is not modeled: it prints nothing and succeeds, never a dump this shell made
    /// up.
    ///
    /// The input is bounded so the dump fits what the line has left (a byte takes at most four
    /// characters of it); a file longer than that is dumped up to that point.
    pub(super) fn cmd_od(&mut self, parts: &[&str]) -> CommandResult {
        let Some(plan) = parse_od(parts.get(1..).unwrap_or(&[])) else {
            return CommandResult::silent(0);
        };
        let names: Vec<Option<&str>> = if plan.files.is_empty() {
            vec![None]
        } else {
            plan.files.iter().copied().map(Some).collect()
        };
        let allowance = self.read_cap().min(self.line.remaining()) / 4;
        let mut data: Vec<u8> = Vec::new();
        let mut acc = CommandResult::silent(0);
        let mut failed = false;
        for name in names {
            let room = allowance.saturating_sub(len_u64(data.len()));
            match self.read_source(parts, name, room) {
                Ok(bytes) => data.extend(bytes),
                Err(error) => {
                    failed = true;
                    acc.append(CommandResult::stderr(
                        1,
                        format!("od: {}: {}\n", name.unwrap_or("-"), errno_text(&error)),
                    ));
                }
            }
        }
        acc.append(CommandResult::stdout(od_render(&data, &plan)));
        acc.status = u8::from(failed);
        acc
    }
}
