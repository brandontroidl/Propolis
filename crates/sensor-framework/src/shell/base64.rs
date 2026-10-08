//! `base64`: a dropper stages a script as text and rebuilds it with
//! `printf '%s' <b64> | base64 -d > file`.
//!
//! This is bounded encode and decode over the modeled bytes of one operand (or standard input),
//! never an interpreter: the decoded bytes are only written where the line redirects them. The
//! input is read through the same bounded reader as `cat`, and the line's remaining allowance caps
//! how much it may be asked to produce.
//!
//! What the tool is not asked to model it does not invent: `--help` and `--version` print nothing
//! and succeed. Standard input at the terminal reads as empty, as it does for `cat`.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::read::errno_text;
use super::registry::Registry;
use super::texttools::stopped;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};

pub(super) fn register(r: &mut Registry) {
    // Not an applet of the captured BusyBox, so `busybox base64` answers "applet not found" on
    // its own; the Ubuntu coreutils binary and the phone's toybox applet are the two that exist.
    r.register_if(
        "base64",
        super::multicall::bare_applet,
        HandlerId::Base64,
        FakeShell::cmd_base64,
    );
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// GNU's default line width for encoded output.
const DEFAULT_WRAP: usize = 76;

const TRY: &str = "Try 'base64 --help' for more information.\n";

struct Plan<'a> {
    decode: bool,
    ignore_garbage: bool,
    wrap: usize,
    file: Option<&'a str>,
}

enum Parsed<'a> {
    Run(Plan<'a>),
    /// The tool's own complaint (status 1).
    Fail(String),
    /// `--help` and `--version`, which this shell does not print.
    Unmodeled,
}

fn parse_wrap(text: &str) -> Result<usize, String> {
    text.parse::<usize>()
        .map_err(|_| format!("base64: invalid wrap size: '{text}'\n"))
}

fn parse_base64<'a>(args: &[&'a str]) -> Parsed<'a> {
    let mut plan = Plan {
        decode: false,
        ignore_garbage: false,
        wrap: DEFAULT_WRAP,
        file: None,
    };
    let mut options = true;
    let mut extra: Option<&str> = None;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if !options || arg == "-" || !arg.starts_with('-') {
            if plan.file.is_none() {
                plan.file = Some(arg);
            } else if extra.is_none() {
                extra = Some(arg);
            }
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match name {
                "decode" if value.is_none() => plan.decode = true,
                "ignore-garbage" if value.is_none() => plan.ignore_garbage = true,
                "wrap" => {
                    let text = match value {
                        Some(text) => text,
                        None => {
                            let Some(&next) = args.get(i) else {
                                return Parsed::Fail(format!(
                                    "base64: option '--wrap' requires an argument\n{TRY}"
                                ));
                            };
                            i = i.saturating_add(1);
                            next
                        }
                    };
                    match parse_wrap(text) {
                        Ok(wrap) => plan.wrap = wrap,
                        Err(text) => return Parsed::Fail(text),
                    }
                }
                "help" | "version" if value.is_none() => return Parsed::Unmodeled,
                _ => {
                    return Parsed::Fail(format!("base64: unrecognized option '{arg}'\n{TRY}"));
                }
            }
            continue;
        }
        let cluster = arg.get(1..).unwrap_or("");
        for (at, flag) in cluster.char_indices() {
            match flag {
                'd' => plan.decode = true,
                'i' => plan.ignore_garbage = true,
                'w' => {
                    let attached = cluster.get(at.saturating_add(1)..).unwrap_or("");
                    let text = if attached.is_empty() {
                        let Some(&next) = args.get(i) else {
                            return Parsed::Fail(format!(
                                "base64: option requires an argument -- 'w'\n{TRY}"
                            ));
                        };
                        i = i.saturating_add(1);
                        next
                    } else {
                        attached
                    };
                    match parse_wrap(text) {
                        Ok(wrap) => plan.wrap = wrap,
                        Err(text) => return Parsed::Fail(text),
                    }
                    break;
                }
                other => {
                    return Parsed::Fail(format!("base64: invalid option -- '{other}'\n{TRY}"));
                }
            }
        }
    }
    if let Some(extra) = extra {
        return Parsed::Fail(format!("base64: extra operand '{extra}'\n{TRY}"));
    }
    Parsed::Run(plan)
}

fn sextet(group: u32, shift: u32) -> char {
    let index = usize::try_from((group >> shift) & 0x3f).unwrap_or(0);
    ALPHABET.get(index).map_or('A', |&byte| char::from(byte))
}

/// `data` as base64 broken into lines of `wrap` characters (no breaks for 0). Output ends with a
/// newline unless it is empty, and a full last line is not followed by an empty one.
fn encode(data: &[u8], wrap: usize) -> String {
    let mut out = String::new();
    let mut column = 0usize;
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let group = (b0 << 16) | (b1 << 8) | b2;
        let quad = [
            sextet(group, 18),
            sextet(group, 12),
            if chunk.len() > 1 {
                sextet(group, 6)
            } else {
                '='
            },
            if chunk.len() > 2 {
                sextet(group, 0)
            } else {
                '='
            },
        ];
        for ch in quad {
            if wrap > 0 && column == wrap {
                out.push('\n');
                column = 0;
            }
            out.push(ch);
            column = column.saturating_add(1);
        }
    }
    if column > 0 {
        out.push('\n');
    }
    out
}

fn sextet_value(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte.wrapping_sub(b'A'))),
        b'a'..=b'z' => Some(u32::from(byte.wrapping_sub(b'a')).saturating_add(26)),
        b'0'..=b'9' => Some(u32::from(byte.wrapping_sub(b'0')).saturating_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The bytes one group of four symbols stands for, or `None` for a group GNU rejects: padding
/// anywhere but the last one or two places, or fewer than four symbols.
fn decode_group(group: &[u8]) -> Option<Vec<u8>> {
    let [c0, c1, c2, c3] = <[u8; 4]>::try_from(group).ok()?;
    let v0 = sextet_value(c0)?;
    let v1 = sextet_value(c1)?;
    let (v2, keep) = match (c2, c3) {
        (b'=', b'=') => (0, 1usize),
        (b'=', _) => return None,
        (_, b'=') => (sextet_value(c2)?, 2),
        _ => (sextet_value(c2)?, 3),
    };
    let v3 = if keep == 3 { sextet_value(c3)? } else { 0 };
    let joined = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
    let all = [
        u8::try_from((joined >> 16) & 0xff).ok()?,
        u8::try_from((joined >> 8) & 0xff).ok()?,
        u8::try_from(joined & 0xff).ok()?,
    ];
    Some(all.get(..keep)?.to_vec())
}

/// What decoding yielded: the bytes of every group before a bad one, and whether one was bad.
struct Decoded {
    bytes: Vec<u8>,
    invalid: bool,
}

/// Newlines are always skipped. Any other byte outside the alphabet and `=` is a fault unless
/// `ignore_garbage`, which drops it. [unverified] GNU writes the groups it decoded before the
/// fault, and accepts a padded group followed by more input; neither was captured.
fn decode(data: &[u8], ignore_garbage: bool) -> Decoded {
    let mut symbols: Vec<u8> = Vec::new();
    let mut garbage = false;
    for &byte in data {
        if byte == b'\n' {
            continue;
        }
        if byte == b'=' || sextet_value(byte).is_some() {
            symbols.push(byte);
        } else if !ignore_garbage {
            garbage = true;
            break;
        }
    }
    let mut decoded = Decoded {
        bytes: Vec::new(),
        invalid: false,
    };
    for group in symbols.chunks(4) {
        match decode_group(group) {
            Some(bytes) => decoded.bytes.extend(bytes),
            None => {
                decoded.invalid = true;
                return decoded;
            }
        }
    }
    decoded.invalid = garbage;
    decoded
}

// ---------------------------------------------------------------------------- toybox (Android)

/// Bytes toybox's `do_base64` takes per `read`: its 4096-byte `toybuf` less the 128 it keeps for
/// the alphabet. [unverified] against a device: the size of `toybuf` is read from `toys.h`.
const TOYBOX_READ: usize = 3968;

/// The `-d`, `-i` and `-w` of `base64 [-di] [-w COLUMNS] [FILE...]` in toybox 6.0.1
/// (`toys/other/base64.c`). `toyopt` has already refused anything else.
struct ToyboxPlan<'a> {
    decode: bool,
    ignore: bool,
    columns: usize,
    files: Vec<&'a str>,
}

fn parse_toybox<'a>(args: &[&'a str]) -> ToyboxPlan<'a> {
    let mut plan = ToyboxPlan {
        decode: false,
        ignore: false,
        columns: DEFAULT_WRAP,
        files: Vec::new(),
    };
    let mut options = true;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if !options || arg == "-" || !arg.starts_with('-') {
            plan.files.push(arg);
        } else if arg == "--" {
            options = false;
        } else {
            let cluster = arg.get(1..).unwrap_or("");
            for (at, flag) in cluster.char_indices() {
                match flag {
                    'd' => plan.decode = true,
                    'i' => plan.ignore = true,
                    'w' => {
                        let attached = cluster.get(at.saturating_add(1)..).unwrap_or("");
                        let text = if attached.is_empty() {
                            let next = args.get(i).copied().unwrap_or("");
                            i = i.saturating_add(1);
                            next
                        } else {
                            attached
                        };
                        plan.columns = text.parse().unwrap_or(DEFAULT_WRAP).max(1);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    plan
}

/// `do_base64` encoding, including the release's own line and padding bookkeeping: `x` counts the
/// characters on the current line, the padding loop runs on it, and the final newline is written
/// unless nothing was printed since the last line break.
fn toybox_encode(data: &[u8], columns: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits, mut x) = (0u32, 0u32, 0usize);
    let push = |out: &mut Vec<u8>, index: u32| {
        let at = usize::try_from(index & 0x3f).unwrap_or(0);
        out.push(ALPHABET.get(at).copied().unwrap_or(b'A'));
    };
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits = bits.saturating_add(8);
        while bits >= 6 {
            bits = bits.saturating_sub(6);
            push(&mut out, acc >> bits);
            acc &= (1u32 << bits).saturating_sub(1);
            x = x.saturating_add(1);
            if columns == x {
                out.push(b'\n');
                x = 0;
            }
        }
    }
    if bits > 0 {
        push(&mut out, acc << 6u32.saturating_sub(bits));
        x = x.saturating_add(1);
    }
    loop {
        let pad = x & 3 != 0;
        x = x.saturating_add(1);
        if !pad {
            break;
        }
        out.push(b'=');
    }
    if x != 1 {
        out.push(b'\n');
    }
    out
}

/// `do_base64` decoding: lenient. A `=` ends the decode at once; a byte outside the alphabet that
/// is not a newline (or any byte, under `-i`) drops the rest of the `read` it arrived in and the
/// decode carries on with the next one. Nothing is reported, and the status stays 0.
fn toybox_decode(data: &[u8], ignore: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for read in data.chunks(TOYBOX_READ) {
        for &byte in read {
            if byte == b'=' {
                return out;
            }
            if let Some(value) = sextet_value(byte) {
                acc = (acc << 6) | value;
                bits = bits.saturating_add(6);
                if bits >= 8 {
                    bits = bits.saturating_sub(8);
                    out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
                    acc &= (1u32 << bits).saturating_sub(1);
                }
                continue;
            }
            if byte == b'\n' || ignore {
                continue;
            }
            break;
        }
    }
    out
}

impl FakeShell {
    /// toybox's `base64`: each operand (standard input for none or `-`) encoded or decoded on its
    /// own, a file it cannot open reported as `base64: NAME: No such file or directory` with the
    /// rest still done and status 1. Bounded like the GNU path.
    fn toybox_base64(&mut self, parts: &[&str]) -> CommandResult {
        let plan = parse_toybox(parts.get(1..).unwrap_or(&[]));
        let allowance = self.read_cap().min(self.line.remaining());
        let room = if plan.decode {
            allowance
        } else {
            allowance / 3
        };
        let names: Vec<Option<&str>> = if plan.files.is_empty() {
            vec![None]
        } else {
            plan.files.iter().copied().map(Some).collect()
        };
        let mut acc = CommandResult::silent(0);
        let mut failed = false;
        for name in names {
            let data = match self.read_source(parts, name, room) {
                Ok(data) => data,
                Err(error) => {
                    failed = true;
                    acc.append(CommandResult::stderr(
                        1,
                        format!("base64: {}: {}\n", name.unwrap_or("-"), errno_text(&error)),
                    ));
                    continue;
                }
            };
            if !self.charge_work(len_u64(data.len())) {
                return stopped();
            }
            if plan.decode {
                let decoded = toybox_decode(&data, plan.ignore);
                self.note_decoded(&data, matches!(name, None | Some("-")), &decoded);
                acc.append(CommandResult::stdout(decoded));
            } else {
                acc.append(CommandResult::stdout(toybox_encode(&data, plan.columns)));
            }
        }
        acc.status = u8::from(failed);
        acc
    }

    /// `base64` and `base64 -d` (with `-i`, `-w`) over standard input or one file, as GNU
    /// coreutils prints them. `--help` and `--version` are not modeled.
    ///
    /// Encoding is bounded so the output fits what the line has left (a byte of input takes at
    /// most three of output with a wrap width of one); an input longer than that is encoded up to
    /// that point.
    pub(super) fn cmd_base64(&mut self, parts: &[&str]) -> CommandResult {
        if self.flavor == ShellFlavor::AndroidSh {
            return self.toybox_base64(parts);
        }
        let plan = match parse_base64(parts.get(1..).unwrap_or(&[])) {
            Parsed::Run(plan) => plan,
            Parsed::Fail(text) => return CommandResult::stderr(1, text),
            Parsed::Unmodeled => return CommandResult::silent(0),
        };
        let allowance = self.read_cap().min(self.line.remaining());
        let room = if plan.decode {
            allowance
        } else {
            allowance / 3
        };
        let data = match self.read_source(parts, plan.file, room) {
            Ok(data) => data,
            Err(error) => {
                return CommandResult::stderr(
                    1,
                    format!(
                        "base64: {}: {}\n",
                        plan.file.unwrap_or("-"),
                        errno_text(&error)
                    ),
                );
            }
        };
        if !self.charge_work(len_u64(data.len())) {
            return stopped();
        }
        if !plan.decode {
            return CommandResult::stdout(encode(&data, plan.wrap));
        }
        let decoded = decode(&data, plan.ignore_garbage);
        self.note_decoded(&data, matches!(plan.file, None | Some("-")), &decoded.bytes);
        let mut result = CommandResult::stdout(decoded.bytes);
        if decoded.invalid {
            result.append(CommandResult::stderr(1, "base64: invalid input\n"));
            result.status = 1;
        }
        result
    }
}
