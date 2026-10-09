//! `tr`, the Android shell's: a loader strips the line breaks a chunked upload picked up
//! (`tr -d '\n' < part > joined`) before it decodes it.
//!
//! Ported from toybox 6.0.1's `toys/pending/tr.c` (tag `android-6.0.1_r81`), quirks included: it
//! reads only standard input, `-C` is `-c` (the `[+cC]` group of its option string makes the two
//! set each other's flag, and only `FLAG_c` is read), a `-s`
//! squeeze compares the previous output byte's whole map entry, a SET2 shorter than SET1 repeats
//! its last byte, and a `[=c=]` class leaves `c` in the set twice. The option and operand
//! refusals (`Needs 1 argument`, `Unknown option`) are `toyopt`'s. The Ubuntu shell's `tr` is
//! GNU coreutils 8.32 and lives in `tr_gnu.rs`; the two share only the registry name and the
//! bounded read of standard input. `reverse colating order` is printed by `perror_exit`, whose
//! errno text is not known; `Success` is [unverified].
//!
//! Output is never longer than the input, so reading through the shared bounded reader bounds it.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::texttools::stopped;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};

pub(super) fn register(r: &mut Registry) {
    r.register_if("tr", android, HandlerId::Tr, FakeShell::cmd_tr);
    r.register_if("tr", ubuntu, HandlerId::Tr, FakeShell::cmd_tr_gnu);
}

fn android(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::AndroidSh
}

/// Bash has the coreutils file; `busybox tr` is BusyBox's applet, whose usage and refusals are
/// not captured, so under `busybox` the name stays a silent success as every uncaptured applet.
fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash && shell.busybox_depth == 0
}

const DELETE: u16 = 0x100;
const SQUEEZE: u16 = 0x200;

/// `handle_escape_char`: the byte made of the text at `at`, the index just after a backslash, and
/// the index of the first byte after the escape.
fn escape(arg: &[u8], at: usize) -> (u8, usize) {
    let byte = |i: usize| arg.get(i).copied().unwrap_or(0);
    let first = byte(at);
    if first == b'x' || first.is_ascii_digit() {
        let hex = first == b'x';
        let base: u32 = if hex { 16 } else { 8 };
        let mut here = if hex { at.saturating_add(1) } else { at };
        let mut used: u32 = u32::from(hex);
        let mut result: u32 = 0;
        while used < 3 {
            let c = byte(here).to_ascii_lowercase();
            let mut num = u32::from(c).wrapping_sub(u32::from(b'0'));
            if num > 10 {
                num = num
                    .wrapping_add(u32::from(b'0'))
                    .wrapping_sub(u32::from(b'a'))
                    .wrapping_add(10);
            }
            if num >= base {
                if hex {
                    used = used.saturating_sub(1);
                    if used == 0 {
                        // `\x` with no hex digit after it stays as written.
                        return (b'\\', at);
                    }
                }
                break;
            }
            used = used.saturating_add(1);
            result = result.saturating_mul(base).saturating_add(num);
            here = here.saturating_add(1);
        }
        return (u8::try_from(result & 0xff).unwrap_or(0), here);
    }
    let value = match first {
        b'n' => b'\n',
        b't' => b'\t',
        b'e' => 27,
        b'b' => 8,
        b'a' => 7,
        b'f' => 12,
        b'v' => 11,
        b'r' => b'\r',
        b'\\' => b'\\',
        // An unknown escape is the backslash itself; the byte after it is read as plain text.
        _ => return (b'\\', at),
    };
    (value, at.saturating_add(1))
}

const CLASSES: [&str; 10] = [
    "[:alpha:]",
    "[:alnum:]",
    "[:digit:]",
    "[:lower:]",
    "[:upper:]",
    "[:space:]",
    "[:blank:]",
    "[:punct:]",
    "[:cntrl:]",
    "[:xdigit:]",
];

/// The bytes of the `[:class:]` that starts `rest`, and the length of its name in the argument.
fn class_of(rest: &[u8]) -> Option<(Vec<u8>, usize)> {
    let (index, name) = CLASSES
        .iter()
        .enumerate()
        .find(|(_, name)| rest.starts_with(name.as_bytes()))?;
    let upper = b'A'..=b'Z';
    let lower = b'a'..=b'z';
    let digits = b'0'..=b'9';
    let set: Vec<u8> = match index {
        0 => upper.chain(lower).collect(),
        1 => upper.chain(lower).chain(digits).collect(),
        2 => digits.collect(),
        3 => lower.collect(),
        4 => upper.collect(),
        5 => vec![b'\t', b'\n', 12, b'\r', 11, b' '],
        6 => vec![b'\t', b' '],
        7 => (0..=255u8).filter(u8::is_ascii_punctuation).collect(),
        8 => (0..=255u8).filter(u8::is_ascii_control).collect(),
        _ => digits.chain(b'A'..=b'F').chain(b'a'..=b'f').collect(),
    };
    Some((set, name.len()))
}

/// `expand_set`: escapes, `a-z` ranges, `[:class:]` and `[=c=]`, as the release does.
fn expand_set(arg: &[u8]) -> Result<Vec<u8>, String> {
    let mut set = Vec::new();
    let mut at = 0usize;
    while let Some(&c) = arg.get(at) {
        let next = arg.get(at.saturating_add(1)).copied().unwrap_or(0);
        if c == b'\\' {
            let (value, resume) = escape(arg, at.saturating_add(1));
            set.push(value);
            at = resume;
            continue;
        }
        if next == b'-' {
            let end = arg.get(at.saturating_add(2)).copied().unwrap_or(0);
            if end != 0 {
                if c > end {
                    return Err("reverse colating order: Success".to_string());
                }
                set.extend(c..=end);
                at = at.saturating_add(3);
                continue;
            }
        } else if c == b'[' && next == b':' {
            if let Some((class, len)) = arg.get(at..).and_then(class_of) {
                set.extend(class);
                at = at.saturating_add(len);
                continue;
            }
        } else if c == b'[' && next == b'=' {
            let at_c = at.saturating_add(2);
            if let Some(&ch) = arg.get(at_c).filter(|ch| **ch != 0) {
                set.push(ch);
            }
            let closes = arg.get(at_c.saturating_add(1)) == Some(&b'=')
                && arg.get(at_c.saturating_add(2)) == Some(&b']');
            if !closes {
                return Err("bad equiv class".to_string());
            }
            // The release does not step past the class: its character is read again as text.
            at = at_c;
            continue;
        }
        set.push(c);
        at = at.saturating_add(1);
    }
    Ok(set)
}

impl FakeShell {
    /// `tr [-cds] SET1 [SET2]` over standard input.
    pub(super) fn cmd_tr(&mut self, parts: &[&str]) -> CommandResult {
        let mut complement = false;
        let (mut delete, mut squeeze) = (false, false);
        let mut sets: Vec<&str> = Vec::new();
        let mut options = true;
        for &arg in parts.get(1..).unwrap_or(&[]) {
            if options && arg == "--" {
                options = false;
            } else if options && arg.starts_with('-') && arg.len() > 1 {
                for flag in arg.chars().skip(1) {
                    match flag {
                        'c' | 'C' => complement = true,
                        'd' => delete = true,
                        's' => squeeze = true,
                        _ => {}
                    }
                }
            } else {
                // `^` in the option string: the first operand ends the options.
                options = false;
                sets.push(arg);
            }
        }
        let fail = |text: &str| CommandResult::stderr(1, format!("tr: {text}\n"));
        let Some(first) = sets.first() else {
            return fail("Needs 1 argument");
        };
        let mut set1 = match expand_set(first.as_bytes()) {
            Ok(set) => set,
            Err(text) => return fail(&text),
        };
        if complement {
            set1 = (0..=255u8).filter(|b| !set1.contains(b)).collect();
        }
        let set2 = match sets.get(1) {
            Some(&"") => return fail("set2 can't be empty string"),
            Some(text) => match expand_set(text.as_bytes()) {
                Ok(set) => Some(set),
                Err(text) => return fail(&text),
            },
            None => None,
        };

        let mut map: Vec<u16> = (0..=255u16).collect();
        if delete {
            for &byte in &set1 {
                if let Some(entry) = map.get_mut(usize::from(byte)) {
                    *entry = u16::from(byte) | DELETE;
                }
            }
        }
        if squeeze {
            for &byte in set1.iter().chain(set2.iter().flatten()) {
                if let Some(entry) = map.get_mut(usize::from(byte)) {
                    *entry |= SQUEEZE;
                }
            }
        }
        if let (false, Some(set2)) = (delete, &set2) {
            let mut k = 0usize;
            for &byte in &set1 {
                let to = set2.get(k).copied().unwrap_or(0);
                if let Some(entry) = map.get_mut(usize::from(byte)) {
                    *entry = (*entry & 0xff00) | u16::from(to);
                }
                // The last byte of SET2 serves every byte of SET1 past its end.
                if set2.get(k.saturating_add(1)).is_some_and(|next| *next != 0) {
                    k = k.saturating_add(1);
                }
            }
        }

        let input = self.stdin.take(self.read_cap());
        if !self.charge_work(len_u64(input.len())) {
            return stopped();
        }
        let mut out = Vec::with_capacity(input.len());
        let mut previous: Option<u16> = None;
        for byte in input {
            let entry = map
                .get(usize::from(byte))
                .copied()
                .unwrap_or(u16::from(byte));
            if delete && entry & DELETE != 0 {
                continue;
            }
            if squeeze && entry & SQUEEZE != 0 && previous == Some(entry) {
                continue;
            }
            out.push(u8::try_from(entry & 0xff).unwrap_or(0));
            previous = Some(entry);
        }
        CommandResult::stdout(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn phone() -> FakeShell {
        let ctx = crate::shell::EmitContext {
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            authenticated: true,
            protocol_label: "adb".to_string(),
            session_id: None,
        };
        FakeShell::android(crate::fakefs::FakeFs::android(), ctx)
    }

    /// What `line` printed (both streams) and its status.
    fn run(sh: &mut FakeShell, line: &str) -> (String, u8) {
        let out = sh.handle_input(line).0;
        (
            String::from_utf8_lossy(out.bytes()).into_owned(),
            out.status,
        )
    }

    #[test]
    fn it_deletes_translates_squeezes_and_complements_standard_input() {
        let mut sh = phone();
        sh.fs.write_file("/data/local/tmp/f", b"ab\ncd\n").unwrap();
        let f = "< /data/local/tmp/f";
        assert_eq!(
            run(&mut sh, &format!("tr -d '\\n' {f}")),
            ("abcd".into(), 0)
        );
        assert_eq!(
            run(&mut sh, &format!("tr a-d A-D {f}")),
            ("AB\nCD\n".into(), 0)
        );
        // SET2 shorter than SET1 repeats its last byte.
        assert_eq!(
            run(&mut sh, &format!("tr abcd xy {f}")),
            ("xy\nyy\n".into(), 0)
        );
        // `-s` squeezes runs of what SET1 names.
        sh.fs.write_file("/data/local/tmp/s", b"a   b  c").unwrap();
        assert_eq!(
            run(&mut sh, "tr -s ' ' < /data/local/tmp/s"),
            ("a b c".into(), 0)
        );
        // `-cd` keeps only what SET1 names.
        assert_eq!(
            run(&mut sh, &format!("tr -cd 'a-c' {f}")),
            ("abc".into(), 0)
        );
        // `-C` sets `-c`'s flag too (`[+cC]` in the option string), so it complements as well.
        assert_eq!(
            run(&mut sh, &format!("tr -Cd 'a-c' {f}")),
            ("abc".into(), 0)
        );
    }

    #[test]
    fn it_refuses_in_toyboxs_words() {
        let mut sh = phone();
        for (line, want) in [
            ("tr", "tr: Needs 1 argument\n"),
            ("tr a b c", "tr: Max 2 arguments\n"),
            ("tr -z a", "tr: Unknown option z\n"),
            ("tr a ''", "tr: set2 can't be empty string\n"),
            ("tr z-a b", "tr: reverse colating order: Success\n"),
        ] {
            assert_eq!(run(&mut sh, line), (want.into(), 1), "{line}");
        }
    }

    #[test]
    fn ranges_classes_and_escapes_expand_in_order() {
        assert_eq!(expand_set(b"a-c").unwrap(), b"abc");
        assert_eq!(expand_set(b"\\n\\x41\\101").unwrap(), b"\nAA");
        assert_eq!(expand_set(b"[:digit:]x").unwrap(), b"0123456789x");
        assert_eq!(expand_set(b"[:space:]").unwrap(), b"\t\n\x0c\r\x0b ");
        // A dash at the end, and a class name that is not one, stay as written.
        assert_eq!(expand_set(b"a-").unwrap(), b"a-");
        assert_eq!(expand_set(b"[:nope:]").unwrap(), b"[:nope:]");
    }

    #[test]
    fn an_unknown_or_hexless_escape_stays_as_written() {
        assert_eq!(expand_set(b"\\q").unwrap(), b"\\q");
        assert_eq!(expand_set(b"\\xvd").unwrap(), b"\\xvd");
        // Two hex digits at most, so the third is plain text.
        assert_eq!(expand_set(b"\\x414").unwrap(), b"A4");
    }

    #[test]
    fn a_backwards_range_and_a_broken_equivalence_class_are_refused() {
        assert!(expand_set(b"z-a").is_err());
        assert_eq!(expand_set(b"[=a").unwrap_err(), "bad equiv class");
    }

    #[test]
    fn the_equivalence_class_leaves_its_character_in_twice() {
        assert_eq!(expand_set(b"[=a=]").unwrap(), b"aa=]");
    }
}
