//! `wc` and `od`: the tools a recorded chain inspects a file it just wrote with (`wc -c .fxcat` is
//! `1 .fxcat`, `od -An -tx1 .fxcat` is ` 0a`, pty README finding 7). `grep` lives in `grep.rs`.
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
    r.register_if(
        "wc",
        super::multicall::bare_applet,
        HandlerId::Wc,
        FakeShell::cmd_wc,
    );
    r.register_if(
        "od",
        super::multicall::bare_applet,
        HandlerId::Od,
        FakeShell::cmd_od,
    );
}

/// The result of a line whose allowance ran out while a tool was reading.
pub(super) fn stopped() -> CommandResult {
    let mut result = CommandResult::silent(1);
    result.stop_line = true;
    result
}

/// GNU's column width when a count comes from standard input or a file that is not a regular one.
const WIDE: usize = 7;

impl FakeShell {
    /// Up to `limit` bytes of one operand: standard input for no operand or `-`.
    pub(super) fn read_source(
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
        let mut plan = match parse_wc(parts.get(1..).unwrap_or(&[])) {
            Some(Ok(plan)) => plan,
            Some(Err(text)) => return CommandResult::stderr(1, text),
            None => return CommandResult::silent(0),
        };
        let android = self.flavor == ShellFlavor::AndroidSh;
        if android {
            plan.bytes |= plan.chars;
            plan.chars = false;
        }
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
        // Toybox's `show_lengths` joins the counts with single spaces, no padding, and `-m` and
        // `-c` share one column (`lib/args.c` flags `m` as `c` too).
        let width = if android {
            1
        } else {
            wc_width(plan.selected(), &slots)
        };
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
    /// `-c` and `-t c`: each byte as a character, a C escape or three octal digits.
    Char,
}

/// One byte as `od -c` shows it, right-aligned in four columns (recorded: `od -c /bin/true` on
/// Ubuntu 22.04 opens ` 177   E   L   F 002 001 001  \0`).
fn od_char(byte: u8) -> String {
    let cell = match byte {
        0 => "\\0".to_string(),
        0x07 => "\\a".to_string(),
        0x08 => "\\b".to_string(),
        0x0c => "\\f".to_string(),
        b'\n' => "\\n".to_string(),
        b'\r' => "\\r".to_string(),
        b'\t' => "\\t".to_string(),
        0x0b => "\\v".to_string(),
        0x20..=0x7e => char::from(byte).to_string(),
        other => format!("{other:03o}"),
    };
    format!("{cell:>4}")
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
                        "c" => Format::Char,
                        _ => return None,
                    };
                    formats = formats.saturating_add(1);
                    break;
                }
                'c' => {
                    plan.format = Format::Char;
                    formats = formats.saturating_add(1);
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
            Format::Char => {
                for &byte in chunk {
                    out.push_str(&od_char(byte));
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
