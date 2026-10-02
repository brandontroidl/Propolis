//! `printf`: format text and bytes the way a loader expects.
//!
//! Droppers use `printf '%s' ...` or `printf '%s\n' ...` to emit a payload exactly and
//! `printf '\xNN\xNN...'` to assemble bytes one escape at a time. The format is interpreted here,
//! never handed to a host `printf`, and the only thing done with it is turning text into text, so
//! the shell's never-exec and no-network guarantees hold by construction. Escapes above 0x7f leave
//! as the char with that code point, the convention `echo` follows until output carries bytes.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::iter::Peekable;
use std::str::Chars;

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId};

/// Cap on the reply: a recycled format or a huge width must not grow an unbounded response.
const PRINTF_MAX_OUTPUT: usize = 65536;

const USAGE: &str = "printf: usage: printf [-v var] format [arguments]\n";

pub(super) fn register(r: &mut Registry) {
    r.register_builtin("printf", HandlerId::Printf, FakeShell::builtin_printf);
}

/// Up to `max` digits in `base` read from `chars`, folded onto `init`. Returns the value and how
/// many digits were taken.
fn take_digits(chars: &mut Peekable<Chars<'_>>, base: u32, max: usize, init: u32) -> (u32, usize) {
    let mut val = init;
    let mut taken = 0usize;
    while taken < max {
        match chars.peek().and_then(|d| d.to_digit(base)) {
            Some(d) => {
                val = val.wrapping_mul(base).wrapping_add(d);
                chars.next();
                taken = taken.saturating_add(1);
            }
            None => break,
        }
    }
    (val, taken)
}

/// Decode one escape (the backslash already consumed) into `out`. Returns `true` for `\c`, which
/// stops all further output. Octal is `\NNN` or `\0NNN`.
fn decode_escape(chars: &mut Peekable<Chars<'_>>, out: &mut String) -> bool {
    match chars.next() {
        Some('n') => out.push('\n'),
        Some('t') => out.push('\t'),
        Some('r') => out.push('\r'),
        Some('a') => out.push('\x07'),
        Some('b') => out.push('\x08'),
        Some('f') => out.push('\x0c'),
        Some('v') => out.push('\x0b'),
        Some('\\') => out.push('\\'),
        Some('"') => out.push('"'),
        Some('\'') => out.push('\''),
        Some('c') => return true,
        Some('x') => {
            let (val, taken) = take_digits(chars, 16, 2, 0);
            if taken == 0 {
                out.push_str("\\x");
            } else if let Some(ch) = char::from_u32(val & 0xff) {
                out.push(ch);
            }
        }
        Some(first @ '0'..='7') => {
            let (init, more) = if first == '0' {
                (0, 3)
            } else {
                (first.to_digit(8).unwrap_or(0), 2)
            };
            let (val, _) = take_digits(chars, 8, more, init);
            if let Some(ch) = char::from_u32(val & 0xff) {
                out.push(ch);
            }
        }
        Some(other) => {
            out.push('\\');
            out.push(other);
        }
        None => out.push('\\'),
    }
    false
}

#[derive(Default)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    zero: bool,
    alt: bool,
    width: usize,
    precision: Option<usize>,
}

/// Digits of a run of ASCII digits at the front of `chars`, saturating at the output cap.
fn take_number(chars: &mut Peekable<Chars<'_>>) -> Option<usize> {
    let mut val: Option<usize> = None;
    while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
        let cur = val.unwrap_or(0);
        let next = cur
            .saturating_mul(10)
            .saturating_add(usize::try_from(d).unwrap_or(0));
        val = Some(next.min(PRINTF_MAX_OUTPUT));
        chars.next();
    }
    val
}

/// An operand as a number. `'A` and `"A` are the code of the next character; otherwise an
/// optionally signed decimal, `0x` hex or leading-`0` octal integer that fits an `i64`.
fn parse_number(op: &str) -> Option<i64> {
    let mut chars = op.chars();
    if let Some('\'' | '"') = chars.clone().next() {
        chars.next();
        return Some(chars.next().map_or(0, |c| i64::from(u32::from(c))));
    }
    let trimmed = op.trim_start();
    let (neg, rest) = match trimmed.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let (radix, digits) =
        if let Some(h) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            (16, h)
        } else if rest.len() > 1 && rest.starts_with('0') {
            (8, rest.get(1..).unwrap_or(""))
        } else {
            (10, rest)
        };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let mag = i128::from(u64::from_str_radix(digits, radix).ok()?);
    let signed = if neg { 0i128.checked_sub(mag)? } else { mag };
    i64::try_from(signed).ok()
}

/// Pad `body` to the spec's width. `zero_ok` lets the `0` flag fill between `lead` (sign or base
/// prefix) and the digits.
fn pad(spec: &Spec, lead: &str, body: &str, zero_ok: bool) -> String {
    let used = lead.chars().count().saturating_add(body.chars().count());
    let fill = spec.width.saturating_sub(used);
    let mut out = String::new();
    if spec.left {
        out.push_str(lead);
        out.push_str(body);
        out.extend(std::iter::repeat_n(' ', fill));
    } else if spec.zero && zero_ok {
        out.push_str(lead);
        out.extend(std::iter::repeat_n('0', fill));
        out.push_str(body);
    } else {
        out.extend(std::iter::repeat_n(' ', fill));
        out.push_str(lead);
        out.push_str(body);
    }
    out
}

fn format_int(spec: &Spec, conv: char, value: i64) -> String {
    let (lead, mut digits) = match conv {
        'd' | 'i' => {
            let sign = if value < 0 {
                "-"
            } else if spec.plus {
                "+"
            } else if spec.space {
                " "
            } else {
                ""
            };
            (sign.to_string(), value.unsigned_abs().to_string())
        }
        _ => {
            let bits = value as u64;
            let digits = match conv {
                'o' => format!("{bits:o}"),
                'x' => format!("{bits:x}"),
                'X' => format!("{bits:X}"),
                _ => bits.to_string(),
            };
            let prefix = match (spec.alt, conv, bits) {
                (true, 'x', 1..) => "0x",
                (true, 'X', 1..) => "0X",
                _ => "",
            };
            (prefix.to_string(), digits)
        }
    };
    if let Some(min) = spec.precision {
        let short = min.saturating_sub(digits.len());
        digits.insert_str(0, &"0".repeat(short));
        if min == 0 && value == 0 {
            digits.clear();
        }
    }
    let mut lead = lead;
    if spec.alt && conv == 'o' && !digits.starts_with('0') {
        lead.push('0');
    }
    pad(spec, &lead, &digits, spec.precision.is_none())
}

struct Printer<'a> {
    operands: &'a [&'a str],
    next: usize,
    text: String,
    err: String,
    status: u8,
    stopped: bool,
}

impl<'a> Printer<'a> {
    fn emit(&mut self, s: &str) {
        let room = PRINTF_MAX_OUTPUT.saturating_sub(self.text.len());
        if s.len() <= room {
            self.text.push_str(s);
            return;
        }
        for c in s.chars() {
            if c.len_utf8() > PRINTF_MAX_OUTPUT.saturating_sub(self.text.len()) {
                break;
            }
            self.text.push(c);
        }
        self.stopped = true;
    }

    fn operand(&mut self) -> Option<&'a str> {
        let op = self.operands.get(self.next).copied();
        if op.is_some() {
            self.next = self.next.saturating_add(1);
        }
        op
    }

    /// One walk over the format. Returns whether it held a conversion spec.
    fn pass(&mut self, format: &str) -> bool {
        let mut had_spec = false;
        let mut chars = format.chars().peekable();
        while let Some(c) = chars.next() {
            if self.stopped {
                break;
            }
            match c {
                '\\' => {
                    let mut piece = String::new();
                    let stop = decode_escape(&mut chars, &mut piece);
                    self.emit(&piece);
                    if stop {
                        self.stopped = true;
                    }
                }
                '%' => {
                    if chars.peek() == Some(&'%') {
                        chars.next();
                        self.emit("%");
                    } else {
                        had_spec = true;
                        self.convert(&mut chars);
                    }
                }
                other => {
                    let mut buf = [0u8; 4];
                    self.emit(other.encode_utf8(&mut buf));
                }
            }
        }
        had_spec
    }

    /// One `%` conversion, the `%` already consumed.
    fn convert(&mut self, chars: &mut Peekable<Chars<'_>>) {
        let mut spec = Spec::default();
        while let Some(&flag) = chars.peek() {
            match flag {
                '-' => spec.left = true,
                '+' => spec.plus = true,
                ' ' => spec.space = true,
                '0' => spec.zero = true,
                '#' => spec.alt = true,
                _ => break,
            }
            chars.next();
        }
        spec.width = take_number(chars).unwrap_or(0);
        if chars.peek() == Some(&'.') {
            chars.next();
            spec.precision = Some(take_number(chars).unwrap_or(0));
        }
        let Some(conv) = chars.next() else {
            self.invalid();
            return;
        };
        match conv {
            's' => {
                let op = self.operand().unwrap_or("");
                let body: String = match spec.precision {
                    Some(p) => op.chars().take(p).collect(),
                    None => op.to_string(),
                };
                self.emit(&pad(&spec, "", &body, false));
            }
            'b' => {
                let op = self.operand().unwrap_or("");
                let mut decoded = String::new();
                let mut it = op.chars().peekable();
                while let Some(c) = it.next() {
                    if c == '\\' {
                        if decode_escape(&mut it, &mut decoded) {
                            self.stopped = true;
                            break;
                        }
                    } else {
                        decoded.push(c);
                    }
                }
                self.emit(&decoded);
            }
            'c' => {
                let first: String = self.operand().unwrap_or("").chars().take(1).collect();
                self.emit(&pad(&spec, "", &first, false));
            }
            'd' | 'i' | 'o' | 'u' | 'x' | 'X' => {
                let value = match self.operand() {
                    None => 0,
                    Some(op) => parse_number(op).unwrap_or_else(|| {
                        // [unverified] wording: not captured from a real shell.
                        self.err
                            .push_str(&format!("printf: {op}: expected a numeric value\n"));
                        self.status = self.status.max(1);
                        0
                    }),
                };
                self.emit(&format_int(&spec, conv, value));
            }
            _ => self.invalid(),
        }
    }

    fn invalid(&mut self) {
        // [unverified] wording: not captured from a real shell.
        self.err
            .push_str("printf: invalid conversion specification\n");
        self.status = 2;
        self.stopped = true;
    }
}

impl FakeShell {
    /// `printf FORMAT [ARGUMENT]...`. The format's escapes are always decoded and it is reused
    /// while operands remain, so `printf '%s\n' a b c` prints three lines.
    pub(super) fn builtin_printf(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let args = match args.split_first() {
            Some((&"--", rest)) => rest,
            _ => args,
        };
        let Some((format, operands)) = args.split_first() else {
            return CommandResult::stderr(2, USAGE);
        };
        let mut printer = Printer {
            operands,
            next: 0,
            text: String::new(),
            err: String::new(),
            status: 0,
            stopped: false,
        };
        loop {
            let before = printer.next;
            let had_spec = printer.pass(format);
            let consumed = printer.next > before;
            if printer.stopped || !had_spec || !consumed || printer.next >= operands.len() {
                break;
            }
        }
        let status = printer.status;
        let mut result = CommandResult::stdout(printer.text);
        result.append(CommandResult::stderr(status, printer.err));
        result.status = status;
        result
    }
}
