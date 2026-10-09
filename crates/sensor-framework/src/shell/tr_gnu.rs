//! `tr`, the Ubuntu shell's: GNU coreutils 8.32 (`src/tr.c` at tag `v8.32`, the release Ubuntu
//! 22.04 ships as `8.32-4.1ubuntu1`), over standard input.
//!
//! Every wording and rule here was read from that source and checked against `/usr/bin/tr` in an
//! Ubuntu 22.04 container with `LANG=C.UTF-8`, the locale the persona's login sets. Where the
//! Android persona's toybox `tr` (`tr.rs`) and this one differ, this one follows GNU:
//!
//! - Options: `-c`/`-C`/`--complement`, `-d`/`--delete`, `-s`/`--squeeze-repeats`,
//!   `-t`/`--truncate-set1`, the undocumented `-A`, `--help` and `--version`, with `getopt_long`
//!   abbreviations. Option parsing stops at the first operand. Toybox accepts `-C` and ignores it,
//!   and has no long options or `-t`.
//! - Escapes: `\NNN` (one to three octal digits, a value above `\377` stops after two digits with
//!   a warning), `\\`, `\a`, `\b`, `\f`, `\n`, `\r`, `\t`, `\v`; any other backslash pair is the
//!   second byte alone. Toybox adds `\xHH` and `\e` and keeps an unknown escape's backslash.
//! - Sets: `a-z` ranges, the twelve classes (`graph` and `print` too), `[=c=]`, and `[c*n]` /
//!   `[c*]` repeats in SET2. Toybox has ten classes, no repeats, and its `[=c=]` leaves the
//!   character in twice. Classes expand in ascending byte order, so `[:alnum:]` starts at `0`
//!   here and at `A` in toybox.
//! - A short SET2 is padded with its last character; `-t` truncates SET1 instead. `[:upper:]`
//!   and `[:lower:]` in SET2 translate by case when SET1 has the matching class in the same place.
//! - `-s` squeezes runs of one output byte that SET2 (the last SET given) names, after translation
//!   or deletion; toybox compares whole table entries.
//! - Errors are `tr: ...` lines followed, for a usage mistake, by `Try 'tr --help' ...`, status 1.
//!   The tool names itself as it was invoked, so `/usr/bin/tr` prints `/usr/bin/tr: ...`.
//!   Quoted operands use the typographic quotes gnulib picks for a UTF-8 locale.
//!
//! Characters are bytes, as in 8.32. Classes use the C locale's tables, which is what the byte
//! values below 128 give under `C.UTF-8` and what glibc gives bytes above 127 there (no member).
//! A different `LANG` on the command line changes the quote glyphs in a real tr; this shell does
//! not read it.
//!
//! Output is never longer than the input, so reading through the shared bounded reader bounds it.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::texttools::stopped;
use super::{CommandResult, FakeShell, len_u64};

/// The largest repeat count: `UINTMAX_MAX - 1`, as `tr.c` reserves the top value for a state.
const REPEAT_MAX: u64 = u64::MAX - 1;

const VERSION: &str = "tr (GNU coreutils) 8.32
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Jim Meyering.
";

/// `--help`, after its `Usage:` line.
const HELP: &str = r#"Translate, squeeze, and/or delete characters from standard input,
writing to standard output.

  -c, -C, --complement    use the complement of SET1
  -d, --delete            delete characters in SET1, do not translate
  -s, --squeeze-repeats   replace each sequence of a repeated character
                            that is listed in the last specified SET,
                            with a single occurrence of that character
  -t, --truncate-set1     first truncate SET1 to length of SET2
      --help     display this help and exit
      --version  output version information and exit

SETs are specified as strings of characters.  Most represent themselves.
Interpreted sequences are:

  \NNN            character with octal value NNN (1 to 3 octal digits)
  \\              backslash
  \a              audible BEL
  \b              backspace
  \f              form feed
  \n              new line
  \r              return
  \t              horizontal tab
  \v              vertical tab
  CHAR1-CHAR2     all characters from CHAR1 to CHAR2 in ascending order
  [CHAR*]         in SET2, copies of CHAR until length of SET1
  [CHAR*REPEAT]   REPEAT copies of CHAR, REPEAT octal if starting with 0
  [:alnum:]       all letters and digits
  [:alpha:]       all letters
  [:blank:]       all horizontal whitespace
  [:cntrl:]       all control characters
  [:digit:]       all digits
  [:graph:]       all printable characters, not including space
  [:lower:]       all lower case letters
  [:print:]       all printable characters, including space
  [:punct:]       all punctuation characters
  [:space:]       all horizontal or vertical whitespace
  [:upper:]       all upper case letters
  [:xdigit:]      all hexadecimal digits
  [=CHAR=]        all characters which are equivalent to CHAR

Translation occurs if -d is not given and both SET1 and SET2 appear.
-t may be used only when translating.  SET2 is extended to length of
SET1 by repeating its last character as necessary.  Excess characters
of SET2 are ignored.  Only [:lower:] and [:upper:] are guaranteed to
expand in ascending order; used in SET2 while translating, they may
only be used in pairs to specify case conversion.  -s uses the last
specified SET, and occurs after translation or deletion.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Report any translation bugs to <https://translationproject.org/team/>
Full documentation <https://www.gnu.org/software/coreutils/tr>
or available locally via: info '(coreutils) tr invocation'
"#;

/// The long options, in `long_options` order (the order `getopt_long` lists an ambiguity in).
const LONG_OPTIONS: [&str; 6] = [
    "complement",
    "delete",
    "squeeze-repeats",
    "truncate-set1",
    "help",
    "version",
];

/// The messages a run writes to standard error, each prefixed with the name the tool was run as.
struct Diag<'a> {
    name: &'a str,
    text: Vec<u8>,
    /// `-A` switches the locale to `C`, where `quote` uses plain apostrophes.
    c_locale: bool,
}

impl<'a> Diag<'a> {
    fn new(name: &'a str) -> Self {
        Self {
            name,
            text: Vec::new(),
            c_locale: false,
        }
    }

    /// gnulib's `quote`, the locale style: curly quotes under the persona's `C.UTF-8`, apostrophes
    /// under `-A`'s `C`. Backslashes are doubled and unprintable characters escaped as the C style
    /// does, which in the `C` locale includes every byte of a non-ASCII character.
    fn quote(&self, text: &str) -> String {
        let (open, close) = if self.c_locale {
            ('\'', '\'')
        } else {
            ('\u{2018}', '\u{2019}')
        };
        let mut out = String::from(open);
        for c in text.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '\u{7}' => out.push_str("\\a"),
                '\u{8}' => out.push_str("\\b"),
                '\t' => out.push_str("\\t"),
                '\n' => out.push_str("\\n"),
                '\u{b}' => out.push_str("\\v"),
                '\u{c}' => out.push_str("\\f"),
                '\r' => out.push_str("\\r"),
                c if c.is_ascii_control() => out.push_str(&format!("\\{:03o}", u32::from(c))),
                c if self.c_locale && !c.is_ascii() => {
                    let mut buf = [0u8; 4];
                    for byte in c.encode_utf8(&mut buf).bytes() {
                        out.push_str(&format!("\\{byte:03o}"));
                    }
                }
                c => out.push(c),
            }
        }
        out.push(close);
        out
    }

    /// `error (0, 0, ...)`: `NAME: MESSAGE`.
    fn say(&mut self, message: &str) {
        self.text.extend_from_slice(self.name.as_bytes());
        self.text.extend_from_slice(b": ");
        self.text.extend_from_slice(message.as_bytes());
        self.text.push(b'\n');
    }

    /// `usage (EXIT_FAILURE)`: the pointer to `--help`.
    fn try_help(&mut self) {
        let line = format!("Try '{} --help' for more information.\n", self.name);
        self.text.extend_from_slice(line.as_bytes());
    }

    /// A line of the message that carries no prefix.
    fn plain(&mut self, line: &str) {
        self.text.extend_from_slice(line.as_bytes());
        self.text.push(b'\n');
    }

    fn fail(self, status: u8) -> CommandResult {
        CommandResult::stderr(status, self.text)
    }
}

fn is_print(b: u8) -> bool {
    b.is_ascii_graphic() || b == b' '
}

/// `make_printable_char`: the character itself, or its three-digit octal escape.
fn printable_char(b: u8) -> String {
    if is_print(b) {
        char::from(b).to_string()
    } else {
        format!("\\{b:03o}")
    }
}

/// `make_printable_str`: backslash and the C escapes by letter, other unprintable bytes in octal.
fn printable_str(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'\\' => out.push('\\'),
            7 => out.push_str("\\a"),
            8 => out.push_str("\\b"),
            12 => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            11 => out.push_str("\\v"),
            b => out.push_str(&printable_char(b)),
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Alnum,
    Alpha,
    Blank,
    Cntrl,
    Digit,
    Graph,
    Lower,
    Print,
    Punct,
    Space,
    Upper,
    Xdigit,
}

const CLASSES: [(&str, Class); 12] = [
    ("alnum", Class::Alnum),
    ("alpha", Class::Alpha),
    ("blank", Class::Blank),
    ("cntrl", Class::Cntrl),
    ("digit", Class::Digit),
    ("graph", Class::Graph),
    ("lower", Class::Lower),
    ("print", Class::Print),
    ("punct", Class::Punct),
    ("space", Class::Space),
    ("upper", Class::Upper),
    ("xdigit", Class::Xdigit),
];

impl Class {
    fn has(self, b: u8) -> bool {
        match self {
            Self::Alnum => b.is_ascii_alphanumeric(),
            Self::Alpha => b.is_ascii_alphabetic(),
            Self::Blank => b == b' ' || b == b'\t',
            Self::Cntrl => b.is_ascii_control(),
            Self::Digit => b.is_ascii_digit(),
            Self::Graph => b.is_ascii_graphic(),
            Self::Lower => b.is_ascii_lowercase(),
            Self::Print => is_print(b),
            Self::Punct => b.is_ascii_punctuation(),
            Self::Space => b == b' ' || (9..=13).contains(&b),
            Self::Upper => b.is_ascii_uppercase(),
            Self::Xdigit => b.is_ascii_hexdigit(),
        }
    }

    fn count(self) -> u64 {
        (0..=255u8)
            .filter(|b| self.has(*b))
            .count()
            .try_into()
            .unwrap_or(0)
    }
}

/// One construct of a SET (`struct List_element`).
#[derive(Clone, Copy)]
enum Elem {
    Char(u8),
    Range(u8, u8),
    Class(Class),
    Equiv(u8),
    /// `[c*n]`; a count of zero is the open-ended `[c*]` until it is resolved against SET1.
    Repeat(u8, u64),
}

#[derive(Default)]
struct Spec {
    elems: Vec<Elem>,
    length: u64,
    indefinite: usize,
    indefinite_at: Option<usize>,
    has_equiv: bool,
    has_class: bool,
    has_restricted_class: bool,
}

/// Which case class a character came from, for the pairing of `[:lower:]` with `[:upper:]`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ul {
    Lower,
    Upper,
    Neither,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Begin,
    New,
    At(u64),
}

/// `get_next` and the `tail`/`state` it keeps: the characters of a SET one at a time.
struct Cursor<'a> {
    elems: &'a [Elem],
    tail: usize,
    state: State,
}

impl<'a> Cursor<'a> {
    fn new(elems: &'a [Elem]) -> Self {
        Self {
            elems,
            tail: 0,
            state: State::Begin,
        }
    }

    /// `skip_construct`: past the current construct, whatever is left of it.
    fn skip_construct(&mut self) {
        self.tail = self.tail.saturating_add(1);
        self.state = State::New;
    }

    fn next_char(&mut self) -> Option<(u8, Ul)> {
        loop {
            if self.state == State::Begin {
                self.tail = 0;
                self.state = State::New;
            }
            let elem = *self.elems.get(self.tail)?;
            match elem {
                Elem::Char(c) | Elem::Equiv(c) => {
                    self.skip_construct();
                    return Some((c, Ul::Neither));
                }
                Elem::Range(first, last) => {
                    let current = match self.state {
                        State::At(v) => v.saturating_add(1),
                        _ => u64::from(first),
                    };
                    if current >= u64::from(last) {
                        self.skip_construct();
                    } else {
                        self.state = State::At(current);
                    }
                    return Some((u8::try_from(current).unwrap_or(last), Ul::Neither));
                }
                Elem::Class(class) => {
                    let ul = match class {
                        Class::Lower => Ul::Lower,
                        Class::Upper => Ul::Upper,
                        _ => Ul::Neither,
                    };
                    let current = match self.state {
                        State::At(v) => u8::try_from(v).unwrap_or(0),
                        _ => (0..=255u8).find(|b| class.has(*b)).unwrap_or(0),
                    };
                    let following = (u16::from(current).saturating_add(1)..=255u16)
                        .filter_map(|v| u8::try_from(v).ok())
                        .find(|b| class.has(*b));
                    match following {
                        Some(next) => self.state = State::At(u64::from(next)),
                        None => self.skip_construct(),
                    }
                    return Some((current, ul));
                }
                Elem::Repeat(c, count) => {
                    if count == 0 {
                        self.skip_construct();
                        continue;
                    }
                    let done = match self.state {
                        State::At(v) => v.saturating_add(1),
                        _ => 1,
                    };
                    if done == count {
                        self.skip_construct();
                    } else {
                        self.state = State::At(done);
                    }
                    return Some((c, Ul::Neither));
                }
            }
        }
    }
}

/// A SET after its escapes are read: the bytes, and which of them came from a backslash.
struct Esc {
    bytes: Vec<u8>,
    escaped: Vec<bool>,
}

impl Esc {
    fn at(&self, i: usize) -> u8 {
        self.bytes.get(i).copied().unwrap_or(0)
    }

    /// `es_match`: byte `i` is `c` and was not escaped.
    fn is(&self, i: usize, c: u8) -> bool {
        self.bytes.get(i) == Some(&c) && self.escaped.get(i) == Some(&false)
    }

    fn escaped_at(&self, i: usize) -> bool {
        self.escaped.get(i).copied().unwrap_or(false)
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }
}

/// `unquote`: the first pass, reading `\c` and `\NNN`, with its two warnings.
fn unquote(s: &[u8], diag: &mut Diag<'_>) -> Esc {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut esc = Esc {
        bytes: Vec::new(),
        escaped: Vec::new(),
    };
    let mut i = 0usize;
    while i < s.len() {
        let here = at(i);
        if here != b'\\' {
            esc.bytes.push(here);
            esc.escaped.push(false);
            i = i.saturating_add(1);
            continue;
        }
        let next = at(i.saturating_add(1));
        let value: u8 = match next {
            b'\\' => b'\\',
            b'a' => 7,
            b'b' => 8,
            b'f' => 12,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'v' => 11,
            b'0'..=b'7' => {
                let mut c = char::from(next).to_digit(8).unwrap_or(0);
                if let Some(d) = char::from(at(i.saturating_add(2))).to_digit(8) {
                    c = c.saturating_mul(8).saturating_add(d);
                    i = i.saturating_add(1);
                    if let Some(d) = char::from(at(i.saturating_add(2))).to_digit(8) {
                        let wide = c.saturating_mul(8).saturating_add(d);
                        if wide < 256 {
                            c = wide;
                            i = i.saturating_add(1);
                        } else {
                            let a = char::from(at(i));
                            let b = char::from(at(i.saturating_add(1)));
                            let third = char::from(at(i.saturating_add(2)));
                            diag.say(&format!(
                                "warning: the ambiguous octal escape \\{a}{b}{third} is being\n\tinterpreted as the 2-byte sequence \\0{a}{b}, {third}"
                            ));
                        }
                    }
                }
                u8::try_from(c & 0xff).unwrap_or(0)
            }
            0 => {
                diag.say("warning: an unescaped backslash at end of string is not portable");
                // Only the backslash is consumed, and it stays a plain one.
                esc.bytes.push(b'\\');
                esc.escaped.push(false);
                i = i.saturating_add(1);
                continue;
            }
            other => other,
        };
        esc.bytes.push(value);
        esc.escaped.push(true);
        i = i.saturating_add(2);
    }
    esc
}

/// `find_closing_delim`: the index of the first unescaped `delim` followed by an unescaped `]`.
fn find_closing_delim(es: &Esc, start: usize, delim: u8) -> Option<usize> {
    (start..es.len().saturating_sub(1)).find(|&i| {
        es.at(i) == delim
            && es.at(i.saturating_add(1)) == b']'
            && !es.escaped_at(i)
            && !es.escaped_at(i.saturating_add(1))
    })
}

/// `star_digits_closebracket`: the text at `idx` is `\*[0-9]*\]` with nothing escaped.
fn star_digits_closebracket(es: &Esc, idx: usize) -> bool {
    if !es.is(idx, b'*') {
        return false;
    }
    for i in idx.saturating_add(1)..es.len() {
        if !es.at(i).is_ascii_digit() || es.escaped_at(i) {
            return es.is(i, b']');
        }
    }
    false
}

/// `xstrtoumax (digits, &end, base, ...)` over the whole of `digits`: a leading `0` makes it
/// octal, leading white space and one `+` are skipped, and anything else left over, a `-`, an
/// empty number or a value past `UINTMAX_MAX - 1` is a refusal.
fn parse_count(digits: &[u8]) -> Option<u64> {
    let base: u32 = if digits.first() == Some(&b'0') { 8 } else { 10 };
    let mut rest = digits;
    while let Some((first, tail)) = rest.split_first() {
        if matches!(first, b' ' | 9..=13) {
            rest = tail;
        } else {
            break;
        }
    }
    if rest.first() == Some(&b'-') {
        return None;
    }
    if rest.first() == Some(&b'+') {
        rest = rest.get(1..).unwrap_or(&[]);
    }
    if rest.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for &b in rest {
        let d = char::from(b).to_digit(base)?;
        value = value
            .checked_mul(u64::from(base))?
            .checked_add(u64::from(d))?;
    }
    (value <= REPEAT_MAX).then_some(value)
}

/// `find_bracketed_repeat`: `Ok(Some((c, count, closing index)))` for a `[c*n]` whose `[` is
/// just before `start`, `Ok(None)` when it is not one, `Err` after reporting a bad count.
fn find_bracketed_repeat(
    es: &Esc,
    start: usize,
    diag: &mut Diag<'_>,
) -> Result<Option<(u8, u64, usize)>, ()> {
    if !es.is(start.saturating_add(1), b'*') {
        return Ok(None);
    }
    let first = start.saturating_add(2);
    let mut i = first;
    while i < es.len() && !es.escaped_at(i) {
        if es.at(i) == b']' {
            let digits = es.bytes.get(first..i).unwrap_or(&[]);
            let count = if digits.is_empty() {
                0
            } else if let Some(count) = parse_count(digits) {
                count
            } else {
                diag.say(&format!(
                    "invalid repeat count {} in [c*n] construct",
                    diag.quote(&printable_str(digits))
                ));
                return Err(());
            };
            return Ok(Some((es.at(start), count, i)));
        }
        i = i.saturating_add(1);
    }
    Ok(None)
}

/// `build_spec_list`: the constructs of one SET.
fn build_spec_list(es: &Esc, diag: &mut Diag<'_>) -> Option<Vec<Elem>> {
    let mut elems = Vec::new();
    let mut i = 0usize;
    while i.saturating_add(2) < es.len() {
        if es.is(i, b'[') {
            let delim = es.at(i.saturating_add(1));
            let mut done = false;
            if es.is(i.saturating_add(1), b':') || es.is(i.saturating_add(1), b'=') {
                let from = i.saturating_add(2);
                if let Some(close) = find_closing_delim(es, from, delim) {
                    let name = es.bytes.get(from..close).unwrap_or(&[]);
                    if name.is_empty() {
                        diag.say(if delim == b':' {
                            "missing character class name '[::]'"
                        } else {
                            "missing equivalence class character '[==]'"
                        });
                        return None;
                    }
                    let parsed = if delim == b':' {
                        CLASSES
                            .iter()
                            .find(|(n, _)| n.as_bytes() == name)
                            .map(|(_, class)| Elem::Class(*class))
                    } else {
                        match name {
                            [only] => Some(Elem::Equiv(*only)),
                            _ => None,
                        }
                    };
                    match parsed {
                        Some(elem) => {
                            elems.push(elem);
                            i = close.saturating_add(2);
                            done = true;
                        }
                        None if star_digits_closebracket(es, from) => {}
                        None if delim == b':' => {
                            diag.say(&format!(
                                "invalid character class {}",
                                diag.quote(&printable_str(name))
                            ));
                            return None;
                        }
                        None => {
                            diag.say(&format!(
                                "{}: equivalence class operand must be a single character",
                                printable_str(name)
                            ));
                            return None;
                        }
                    }
                }
            }
            if done {
                continue;
            }
            match find_bracketed_repeat(es, i.saturating_add(1), diag) {
                Ok(Some((c, count, close))) => {
                    elems.push(Elem::Repeat(c, count));
                    i = close.saturating_add(1);
                    continue;
                }
                Ok(None) => {}
                Err(()) => return None,
            }
        }
        if es.is(i.saturating_add(1), b'-') {
            let (first, last) = (es.at(i), es.at(i.saturating_add(2)));
            if last < first {
                diag.say(&format!(
                    "range-endpoints of '{}-{}' are in reverse collating sequence order",
                    printable_char(first),
                    printable_char(last)
                ));
                return None;
            }
            elems.push(Elem::Range(first, last));
            i = i.saturating_add(3);
        } else {
            elems.push(Elem::Char(es.at(i)));
            i = i.saturating_add(1);
        }
    }
    while i < es.len() {
        elems.push(Elem::Char(es.at(i)));
        i = i.saturating_add(1);
    }
    Some(elems)
}

fn parse_set(arg: &str, diag: &mut Diag<'_>) -> Option<Spec> {
    let es = unquote(arg.as_bytes(), diag);
    let elems = build_spec_list(&es, diag)?;
    Some(Spec {
        elems,
        ..Spec::default()
    })
}

/// `get_spec_stats`: length and kind flags, with `tr.c`'s overflow refusal.
fn spec_stats(spec: &mut Spec, diag: &mut Diag<'_>) -> Result<(), ()> {
    let mut length: u64 = 0;
    spec.indefinite = 0;
    spec.indefinite_at = None;
    spec.has_equiv = false;
    spec.has_class = false;
    spec.has_restricted_class = false;
    for (index, elem) in spec.elems.iter().enumerate() {
        let len: u64 = match *elem {
            Elem::Char(_) => 1,
            Elem::Range(first, last) => u64::from(last)
                .saturating_sub(u64::from(first))
                .saturating_add(1),
            Elem::Class(class) => {
                spec.has_class = true;
                if !matches!(class, Class::Upper | Class::Lower) {
                    spec.has_restricted_class = true;
                }
                class.count()
            }
            Elem::Equiv(_) => {
                spec.has_equiv = true;
                1
            }
            Elem::Repeat(_, count) => {
                if count > 0 {
                    count
                } else {
                    spec.indefinite_at = Some(index);
                    spec.indefinite = spec.indefinite.saturating_add(1);
                    0
                }
            }
        };
        match length.checked_add(len) {
            Some(total) if total <= REPEAT_MAX => length = total,
            _ => {
                diag.say("too many characters in set");
                return Err(());
            }
        }
    }
    spec.length = length;
    Ok(())
}

/// `card_of_complement`: how many bytes are not in the SET.
fn card_of_complement(spec: &Spec) -> u64 {
    let members = membership(spec, false);
    len_u64(members.iter().filter(|m| !**m).count())
}

/// `set_initialize`: which bytes the SET names, or does not name when `complement`.
fn membership(spec: &Spec, complement: bool) -> Vec<bool> {
    let mut set = vec![false; 256];
    let mut cursor = Cursor::new(&spec.elems);
    while let Some((c, _)) = cursor.next_char() {
        if let Some(slot) = set.get_mut(usize::from(c)) {
            *slot = true;
        }
    }
    if complement {
        for slot in &mut set {
            *slot = !*slot;
        }
    }
    set
}

/// `validate_case_classes`: `[:upper:]` / `[:lower:]` in SET2 must line up with SET1's. `tr.c`
/// also takes 25 off both lengths for every aligned pair; both sets lose the same amount, so no
/// comparison or difference of the two lengths changes and it is not repeated here.
fn validate_case_classes(s1: &Spec, s2: &Spec, diag: &mut Diag<'_>) -> Result<(), ()> {
    if !s2.has_class {
        return Ok(());
    }
    let mut c1 = Cursor::new(&s1.elems);
    let mut c2 = Cursor::new(&s2.elems);
    let (mut s1_new, mut s2_new) = (true, true);
    let (mut more1, mut more2) = (true, true);
    while more1 && more2 {
        let a = c1.next_char();
        let b = c2.next_char();
        more1 = a.is_some();
        more2 = b.is_some();
        let class1 = a.map_or(Ul::Neither, |x| x.1);
        let class2 = b.map_or(Ul::Neither, |x| x.1);
        if s2_new && class2 != Ul::Neither && !(s1_new && class1 != Ul::Neither) {
            diag.say("misaligned [:upper:] and/or [:lower:] construct");
            return Err(());
        }
        if class2 != Ul::Neither {
            c1.skip_construct();
            c2.skip_construct();
        }
        s1_new = c1.state == State::New;
        s2_new = c2.state == State::New;
    }
    Ok(())
}

/// `homogeneous_spec_list`: a non-empty SET naming one byte only.
fn homogeneous(spec: &Spec) -> bool {
    let mut cursor = Cursor::new(&spec.elems);
    let Some((first, _)) = cursor.next_char() else {
        return false;
    };
    while let Some((c, _)) = cursor.next_char() {
        if c != first {
            return false;
        }
    }
    true
}

/// `string2_extend`: pad SET2 with its last character to the length of SET1.
fn string2_extend(s1: &Spec, s2: &mut Spec, diag: &mut Diag<'_>) -> Result<(), ()> {
    let repeat = match s2.elems.last() {
        // An equivalence class never gets here: `validate` refuses it in SET2 first.
        Some(Elem::Char(c) | Elem::Repeat(c, _) | Elem::Equiv(c)) => *c,
        Some(Elem::Range(_, last)) => *last,
        Some(Elem::Class(_)) => {
            diag.say(
                "when translating with string1 longer than string2,\nthe latter string must not end with a character class",
            );
            return Err(());
        }
        None => return Ok(()),
    };
    s2.elems
        .push(Elem::Repeat(repeat, s1.length.saturating_sub(s2.length)));
    s2.length = s1.length;
    Ok(())
}

struct Flags {
    complement: bool,
    delete: bool,
    squeeze: bool,
    truncate: bool,
}

/// `validate`.
fn validate(
    s1: &mut Spec,
    s2: Option<&mut Spec>,
    flags: &Flags,
    translating: bool,
    diag: &mut Diag<'_>,
) -> Result<(), ()> {
    spec_stats(s1, diag)?;
    if flags.complement {
        s1.length = card_of_complement(s1);
    }
    if s1.indefinite > 0 {
        diag.say("the [c*] repeat construct may not appear in string1");
        return Err(());
    }
    let Some(s2) = s2 else {
        return Ok(());
    };
    spec_stats(s2, diag)?;
    if s1.length >= s2.length
        && s2.indefinite == 1
        && let Some(at) = s2.indefinite_at
    {
        let fill = s1.length.saturating_sub(s2.length);
        if let Some(Elem::Repeat(_, count)) = s2.elems.get_mut(at) {
            *count = fill;
        }
        s2.length = s1.length;
    }
    if s2.indefinite > 1 {
        diag.say("only one [c*] repeat construct may appear in string2");
        return Err(());
    }
    if translating {
        if s2.has_equiv {
            diag.say("[=c=] expressions may not appear in string2 when translating");
            return Err(());
        }
        if s2.has_restricted_class {
            diag.say(
                "when translating, the only character classes that may appear in\nstring2 are 'upper' and 'lower'",
            );
            return Err(());
        }
        validate_case_classes(s1, s2, diag)?;
        if s1.length > s2.length && !flags.truncate {
            if s2.length == 0 {
                diag.say("when not truncating set1, string2 must be non-empty");
                return Err(());
            }
            string2_extend(s1, s2, diag)?;
        }
        if flags.complement && s1.has_class && !(s2.length == s1.length && homogeneous(s2)) {
            diag.say(
                "when translating with complemented character classes,\nstring2 must map all characters in the domain to one",
            );
            return Err(());
        }
    } else if s2.indefinite > 0 {
        diag.say("the [c*] construct may appear in string2 only when translating");
        return Err(());
    }
    Ok(())
}

/// The byte translation table of a translating run.
fn translation(s1: &Spec, s2: &Spec, flags: &Flags) -> Vec<u8> {
    let mut map: Vec<u8> = (0..=255u8).collect();
    let mut second = Cursor::new(&s2.elems);
    if flags.complement {
        let named = membership(s1, false);
        for (i, in_s1) in named.iter().enumerate() {
            if *in_s1 {
                continue;
            }
            let Some((c, _)) = second.next_char() else {
                break;
            };
            if let Some(slot) = map.get_mut(i) {
                *slot = c;
            }
        }
        return map;
    }
    let mut first = Cursor::new(&s1.elems);
    loop {
        let a = first.next_char();
        let b = second.next_char();
        let class1 = a.map_or(Ul::Neither, |x| x.1);
        let class2 = b.map_or(Ul::Neither, |x| x.1);
        if class1 == Ul::Lower && class2 == Ul::Upper {
            for byte in b'a'..=b'z' {
                if let Some(slot) = map.get_mut(usize::from(byte)) {
                    *slot = byte.to_ascii_uppercase();
                }
            }
        } else if class1 == Ul::Upper && class2 == Ul::Lower {
            for byte in b'A'..=b'Z' {
                if let Some(slot) = map.get_mut(usize::from(byte)) {
                    *slot = byte.to_ascii_lowercase();
                }
            }
        } else {
            let (Some((from, _)), Some((to, _))) = (a, b) else {
                break;
            };
            if let Some(slot) = map.get_mut(usize::from(from)) {
                *slot = to;
            }
        }
        if class2 != Ul::Neither {
            first.skip_construct();
            second.skip_construct();
        }
    }
    map
}

/// What `getopt_long` makes of one `--name[=value]`.
enum Long {
    Complement,
    Delete,
    Squeeze,
    Truncate,
    Help,
    Version,
    /// The tool's refusal, status 1, with the pointer to `--help` still to add.
    Refused(String),
}

fn long_option(arg: &str) -> Long {
    let rest = arg.strip_prefix("--").unwrap_or(arg);
    let (name, has_value) = match rest.split_once('=') {
        Some((name, _)) => (name, true),
        None => (rest, false),
    };
    let exact = LONG_OPTIONS.iter().find(|candidate| **candidate == name);
    let matches: Vec<&&str> = LONG_OPTIONS
        .iter()
        .filter(|candidate| candidate.starts_with(name))
        .collect();
    let chosen = match (exact, matches.as_slice()) {
        (Some(found), _) => *found,
        (None, [only]) => **only,
        (None, []) => {
            return Long::Refused(format!("unrecognized option '{arg}'"));
        }
        (None, _) => {
            let possible: String = matches.iter().map(|m| format!(" '--{m}'")).collect();
            return Long::Refused(format!(
                "option '{arg}' is ambiguous; possibilities:{possible}"
            ));
        }
    };
    if has_value {
        return Long::Refused(format!("option '--{chosen}' doesn't allow an argument"));
    }
    match chosen {
        "complement" => Long::Complement,
        "delete" => Long::Delete,
        "squeeze-repeats" => Long::Squeeze,
        "truncate-set1" => Long::Truncate,
        "help" => Long::Help,
        _ => Long::Version,
    }
}

impl FakeShell {
    /// `tr [OPTION]... SET1 [SET2]` over standard input.
    pub(super) fn cmd_tr_gnu(&mut self, parts: &[&str]) -> CommandResult {
        let name = parts.first().copied().unwrap_or("tr");
        let mut diag = Diag::new(name);
        let args = parts.get(1..).unwrap_or(&[]);
        let mut flags = Flags {
            complement: false,
            delete: false,
            squeeze: false,
            truncate: false,
        };
        let mut index = 0usize;
        while let Some(&arg) = args.get(index) {
            if arg == "--" {
                index = index.saturating_add(1);
                break;
            }
            if arg.starts_with("--") {
                match long_option(arg) {
                    Long::Complement => flags.complement = true,
                    Long::Delete => flags.delete = true,
                    Long::Squeeze => flags.squeeze = true,
                    Long::Truncate => flags.truncate = true,
                    Long::Help => {
                        return CommandResult::stdout(format!(
                            "Usage: {name} [OPTION]... SET1 [SET2]\n{HELP}"
                        ));
                    }
                    Long::Version => return CommandResult::stdout(VERSION),
                    Long::Refused(message) => {
                        diag.say(&message);
                        diag.try_help();
                        return diag.fail(1);
                    }
                }
            } else if arg.starts_with('-') && arg.len() > 1 {
                for flag in arg.bytes().skip(1) {
                    match flag {
                        b'A' => diag.c_locale = true,
                        b'c' | b'C' => flags.complement = true,
                        b'd' => flags.delete = true,
                        b's' => flags.squeeze = true,
                        b't' => flags.truncate = true,
                        other => {
                            // getopt reports the one offending byte, even half of a UTF-8 letter.
                            diag.text.extend_from_slice(name.as_bytes());
                            diag.text.extend_from_slice(b": invalid option -- '");
                            diag.text.push(other);
                            diag.text.extend_from_slice(b"'\n");
                            diag.try_help();
                            return diag.fail(1);
                        }
                    }
                }
            } else {
                break;
            }
            index = index.saturating_add(1);
        }
        let operands = args.get(index..).unwrap_or(&[]);
        let given = operands.len();
        let translating = given == 2 && !flags.delete;
        let min_operands: usize = if flags.delete == flags.squeeze { 2 } else { 1 };
        let max_operands: usize = if flags.delete <= flags.squeeze { 2 } else { 1 };

        if given < min_operands {
            match operands.last() {
                None => diag.say("missing operand"),
                Some(last) => {
                    diag.say(&format!("missing operand after {}", diag.quote(last)));
                    diag.plain(if flags.squeeze {
                        "Two strings must be given when both deleting and squeezing repeats."
                    } else {
                        "Two strings must be given when translating."
                    });
                }
            }
            diag.try_help();
            return diag.fail(1);
        }
        if max_operands < given {
            if let Some(extra) = operands.get(max_operands) {
                diag.say(&format!("extra operand {}", diag.quote(extra)));
            }
            if given == 2 {
                diag.plain("Only one string may be given when deleting without squeezing repeats.");
            }
            diag.try_help();
            return diag.fail(1);
        }

        let Some(mut s1) = operands.first().and_then(|a| parse_set(a, &mut diag)) else {
            return diag.fail(1);
        };
        let mut s2 = match operands.get(1) {
            Some(arg) => match parse_set(arg, &mut diag) {
                Some(spec) => Some(spec),
                None => return diag.fail(1),
            },
            None => None,
        };
        if validate(&mut s1, s2.as_mut(), &flags, translating, &mut diag).is_err() {
            return diag.fail(1);
        }

        let mut delete_set: Option<Vec<bool>> = None;
        let mut map: Option<Vec<u8>> = None;
        let mut squeeze_set: Option<Vec<bool>> = None;
        if let Some(s2) = s2.as_ref() {
            if translating {
                map = Some(translation(&s1, s2, &flags));
                if flags.squeeze {
                    squeeze_set = Some(membership(s2, false));
                }
            } else {
                // Deleting and squeezing: SET1 is deleted, SET2 squeezed.
                delete_set = Some(membership(&s1, flags.complement));
                squeeze_set = Some(membership(s2, false));
            }
        } else if flags.squeeze {
            squeeze_set = Some(membership(&s1, flags.complement));
        } else {
            delete_set = Some(membership(&s1, flags.complement));
        }

        let input = self.stdin.take(self.read_cap());
        if !self.charge_work(len_u64(input.len())) {
            return stopped();
        }
        let flagged = |set: &Option<Vec<bool>>, byte: u8| {
            set.as_ref()
                .is_some_and(|set| set.get(usize::from(byte)).copied().unwrap_or(false))
        };
        let mut out = Vec::with_capacity(input.len());
        let mut previous: Option<u8> = None;
        for byte in input {
            if flagged(&delete_set, byte) {
                continue;
            }
            let byte = map
                .as_ref()
                .and_then(|map| map.get(usize::from(byte)).copied())
                .unwrap_or(byte);
            if previous == Some(byte) && flagged(&squeeze_set, byte) {
                continue;
            }
            out.push(byte);
            previous = Some(byte);
        }

        if diag.text.is_empty() {
            return CommandResult::stdout(out);
        }
        let mut result = CommandResult::stderr(0, diag.text);
        result.append(CommandResult::stdout(out));
        result
    }
}
