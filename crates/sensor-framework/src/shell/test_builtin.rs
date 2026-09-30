//! `test` and `[`: file, string and integer predicates over the filesystem model, with no output
//! and a status only (0 true, 1 false, 2 usage error).
//!
//! The argument-count rules are bash's `test.c`: zero to four operands take the POSIX forms
//! (`test X`, `test ! X`, `test A op B`, `test ( X )`), and more take the `-o`, `-a`, `!`, `( )`
//! grammar. Files are answered from [`FakeFs::stat`] through the same logical-to-physical
//! resolution every other path goes through, so a predicate and the command that would open the
//! path cannot disagree: a `-w` on a directory is true exactly when a write there would succeed.
//!
//! Root is the only user, so `-r` is true of any node that exists and `-w` of any node whose
//! mount is not read-only, whatever its mode bits. `[[ ]]` is not this: the parser skips it.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, command_basename, len_u64};
use crate::fakefs::{FileKind, Stat};

/// Parenthesis nesting the expression grammar follows before giving up, the depth cap the rest of
/// the engine holds.
const MAX_NESTING: u8 = 16;
const STICKY: u32 = 0o1000;
const SETUID: u32 = 0o4000;
const SETGID: u32 = 0o2000;
const EXEC_BITS: u32 = 0o111;

pub(super) fn register(r: &mut Registry) {
    for name in ["test", "["] {
        r.register(name, HandlerId::Test, FakeShell::builtin_test);
    }
}

/// Why an expression is not a valid `test`, worded per shell family.
#[derive(Debug, PartialEq, Eq)]
enum Fault {
    /// An operand where an operator was expected (`test a b`).
    Unary(String),
    /// An operator that is not one (`test a b c`).
    Binary(String),
    Integer(String),
    ArgExpected,
    TooMany,
    /// A `(` never closed: nothing left, or the token found instead.
    CloseParen(Option<String>),
}

impl Fault {
    /// The message after `test: `. The dash and mksh wordings are [unverified]: only bash's were
    /// compared with a real shell.
    fn text(&self, bash: bool) -> String {
        match (self, bash) {
            (Self::Unary(arg), true) => format!("{arg}: unary operator expected"),
            (Self::Binary(arg), true) => format!("{arg}: binary operator expected"),
            (Self::Unary(arg) | Self::Binary(arg), false) => format!("{arg}: unexpected operator"),
            (Self::Integer(arg), true) => format!("{arg}: integer expression expected"),
            (Self::Integer(arg), false) => format!("Illegal number: {arg}"),
            (Self::ArgExpected, _) => "argument expected".to_string(),
            (Self::TooMany, _) => "too many arguments".to_string(),
            (Self::CloseParen(None), true) => "`)' expected".to_string(),
            (Self::CloseParen(Some(found)), true) => format!("`)' expected, found {found}"),
            (Self::CloseParen(_), false) => "closing paren expected".to_string(),
        }
    }
}

type Outcome = Result<bool, Fault>;

/// Every unary operator's flag letter. `-t`, `-o`, `-R` and `-N` are named so `test -t 1` is a
/// test, and answer false: the box tracks no terminal, shell options, namerefs or read times.
const UNARY_FLAGS: &str = "abcdefghknoprstuvwxzGLNORS";

fn is_switch(token: &str) -> bool {
    token.len() == 2 && token.starts_with('-')
}

fn is_unary(token: &str) -> bool {
    is_switch(token)
        && token
            .chars()
            .nth(1)
            .is_some_and(|flag| UNARY_FLAGS.contains(flag))
}

fn is_binary(token: &str) -> bool {
    matches!(
        token,
        "=" | "=="
            | "!="
            | "<"
            | ">"
            | "-eq"
            | "-ne"
            | "-lt"
            | "-le"
            | "-gt"
            | "-ge"
            | "-nt"
            | "-ot"
            | "-ef"
    )
}

/// An integer operand the way bash reads one: optional surrounding blanks, an optional sign and
/// decimal digits, within `i64`.
fn integer(token: &str) -> Result<i64, Fault> {
    let blank = |c: char| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r');
    let trimmed = token.trim_matches(blank);
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Fault::Integer(token.to_string()));
    }
    trimmed
        .parse::<i64>()
        .map_err(|_| Fault::Integer(token.to_string()))
}

struct Found {
    stat: Stat,
    /// The path was a `/proc/<pid>/exe` link, which the filesystem does not store.
    proc_exe: bool,
}

struct Eval<'a> {
    shell: &'a mut FakeShell,
    args: &'a [&'a str],
    pos: usize,
    nesting: u8,
}

impl<'a> Eval<'a> {
    fn at(&self, offset: usize) -> &'a str {
        self.args
            .get(self.pos.saturating_add(offset))
            .copied()
            .unwrap_or("")
    }

    fn left(&self) -> usize {
        self.args.len().saturating_sub(self.pos)
    }

    fn advance(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }

    fn finish(&mut self) {
        self.pos = self.args.len();
    }

    fn run(&mut self) -> Outcome {
        if self.args.is_empty() {
            return Ok(false);
        }
        self.shell.charge_work(len_u64(self.args.len()));
        let value = self.posix()?;
        if self.left() != 0 {
            return Err(Fault::TooMany);
        }
        Ok(value)
    }

    /// The argument-count forms; five or more operands are the general grammar.
    fn posix(&mut self) -> Outcome {
        match self.left() {
            0 => Err(Fault::ArgExpected),
            1 => {
                let value = !self.at(0).is_empty();
                self.finish();
                Ok(value)
            }
            2 => {
                let value = self.two()?;
                self.finish();
                Ok(value)
            }
            3 => self.three(),
            4 => self.four(),
            _ => self.expr(),
        }
    }

    /// `! X` or `-op X`, over the next two operands.
    fn two(&mut self) -> Outcome {
        let (first, second) = (self.at(0), self.at(1));
        if first == "!" {
            return Ok(second.is_empty());
        }
        if is_unary(first) {
            return Ok(self.unary(first, second));
        }
        Err(Fault::Unary(first.to_string()))
    }

    /// `A op B`, `! two`, `A -a B`, `A -o B`, `( X )`, over the next three operands.
    fn three(&mut self) -> Outcome {
        let (first, second, third) = (self.at(0), self.at(1), self.at(2));
        let value = if is_binary(second) {
            self.binary(first, second, third)?
        } else if first == "!" {
            self.advance(1);
            !self.two()?
        } else if second == "-a" {
            !first.is_empty() && !third.is_empty()
        } else if second == "-o" {
            !first.is_empty() || !third.is_empty()
        } else if first == "(" && third == ")" {
            !second.is_empty()
        } else {
            return Err(Fault::Binary(second.to_string()));
        };
        self.finish();
        Ok(value)
    }

    /// `! three`, `( two )`, else the general grammar, over the next four operands.
    fn four(&mut self) -> Outcome {
        if self.at(0) == "!" {
            self.advance(1);
            return Ok(!self.three()?);
        }
        if self.at(0) == "(" && self.at(3) == ")" {
            self.advance(1);
            let value = self.two()?;
            self.finish();
            return Ok(value);
        }
        self.expr()
    }

    fn expr(&mut self) -> Outcome {
        if self.left() == 0 {
            return Err(Fault::ArgExpected);
        }
        self.or()
    }

    /// Every side is parsed, so a syntax error later in the expression is reported even when an
    /// earlier term already decided the answer.
    fn or(&mut self) -> Outcome {
        let mut value = self.and()?;
        while self.left() > 0 && self.at(0) == "-o" {
            self.advance(1);
            let next = self.and()?;
            value = value || next;
        }
        Ok(value)
    }

    fn and(&mut self) -> Outcome {
        let mut value = self.term()?;
        while self.left() > 0 && self.at(0) == "-a" {
            self.advance(1);
            let next = self.term()?;
            value = value && next;
        }
        Ok(value)
    }

    fn term(&mut self) -> Outcome {
        if self.left() == 0 {
            return Err(Fault::ArgExpected);
        }
        if self.at(0) == "!" {
            let mut negate = false;
            while self.left() > 0 && self.at(0) == "!" {
                self.advance(1);
                negate = !negate;
            }
            return Ok(self.term()? != negate);
        }
        if self.at(0) == "(" {
            if self.nesting >= MAX_NESTING {
                return Err(Fault::TooMany);
            }
            self.advance(1);
            self.nesting = self.nesting.saturating_add(1);
            let inner = self.expr();
            self.nesting = self.nesting.saturating_sub(1);
            let value = inner?;
            if self.left() == 0 {
                return Err(Fault::CloseParen(None));
            }
            if self.at(0) != ")" {
                return Err(Fault::CloseParen(Some(self.at(0).to_string())));
            }
            self.advance(1);
            return Ok(value);
        }
        if self.left() >= 3 && is_binary(self.at(1)) {
            let (left, op, right) = (self.at(0), self.at(1), self.at(2));
            self.advance(3);
            return self.binary(left, op, right);
        }
        let token = self.at(0);
        if is_switch(token) {
            if !is_unary(token) {
                return Err(Fault::Unary(token.to_string()));
            }
            // A flag with nothing after it is the string `-f`, not a test of no file.
            if self.left() < 2 {
                self.advance(1);
                return Ok(true);
            }
            let value = self.unary(token, self.at(1));
            self.advance(2);
            return Ok(value);
        }
        self.advance(1);
        Ok(!token.is_empty())
    }

    fn binary(&mut self, left: &str, op: &str, right: &str) -> Outcome {
        Ok(match op {
            "=" | "==" => left == right,
            "!=" => left != right,
            "<" => left.as_bytes() < right.as_bytes(),
            ">" => left.as_bytes() > right.as_bytes(),
            "-nt" | "-ot" | "-ef" => self.compare_files(left, op, right),
            _ => {
                let (a, b) = (integer(left)?, integer(right)?);
                match op {
                    "-eq" => a == b,
                    "-ne" => a != b,
                    "-lt" => a < b,
                    "-le" => a <= b,
                    "-gt" => a > b,
                    _ => a >= b,
                }
            }
        })
    }

    fn unary(&mut self, op: &str, arg: &str) -> bool {
        match op.chars().nth(1) {
            Some('z') => arg.is_empty(),
            Some('n') => !arg.is_empty(),
            Some('v') => self.shell.state().get(arg).is_some(),
            Some('t' | 'o' | 'R' | 'N') | None => false,
            Some(flag) => self.file_test(flag, arg),
        }
    }

    /// The node `arg` names, resolved as any path is. `/proc/self/exe` is the one link the
    /// filesystem cannot store: it names the executable of the process reading it, here the shell.
    fn find(&mut self, arg: &str, follow: bool) -> Option<Found> {
        if arg.is_empty() {
            return None;
        }
        self.shell.charge_work(len_u64(arg.len()));
        let reader = self.shell.shell_reader();
        let typed = self.shell.resolve_logical(arg);
        let read = self.shell.resolve_reading(arg, reader);
        if read != typed {
            let stat = self.shell.fs.stat(&read, true)?;
            return Some(Found {
                stat,
                proc_exe: true,
            });
        }
        let stat = self.shell.fs.stat(&typed, follow)?;
        Some(Found {
            stat,
            proc_exe: false,
        })
    }

    fn file_test(&mut self, flag: char, arg: &str) -> bool {
        // A trailing slash makes the kernel follow a link, so `-L /bin/` names the directory.
        let names_link = matches!(flag, 'L' | 'h') && !(arg.len() > 1 && arg.ends_with('/'));
        let Some(found) = self.find(arg, !names_link) else {
            return false;
        };
        if names_link {
            return found.proc_exe || found.stat.kind == FileKind::Symlink;
        }
        let stat = &found.stat;
        match flag {
            'e' | 'a' | 'r' => true,
            'f' => stat.kind == FileKind::Regular,
            'd' => stat.kind == FileKind::Directory,
            'c' => stat.kind == FileKind::CharDevice,
            'w' => !stat.read_only,
            'x' => match stat.kind {
                FileKind::Directory => true,
                FileKind::Regular => stat.mode & EXEC_BITS != 0 && !stat.no_exec,
                FileKind::Symlink | FileKind::CharDevice => false,
            },
            's' => match stat.kind {
                FileKind::Regular => stat.size > 0,
                // A directory holds at least a block. The box does not model the empty-looking
                // directories of proc and sys.
                FileKind::Directory => true,
                FileKind::Symlink | FileKind::CharDevice => false,
            },
            'k' => stat.mode & STICKY != 0,
            'u' => stat.mode & SETUID != 0,
            'g' => stat.mode & SETGID != 0,
            'O' => stat.uid == 0,
            'G' => stat.gid == 0,
            // No block device, FIFO or socket is modeled.
            _ => false,
        }
    }

    fn compare_files(&mut self, left: &str, op: &str, right: &str) -> bool {
        let a = self.find(left, true).map(|found| found.stat);
        let b = self.find(right, true).map(|found| found.stat);
        match (op, a, b) {
            ("-nt", Some(a), Some(b)) => a.mtime > b.mtime,
            ("-nt", Some(_), None) => true,
            ("-ot", Some(a), Some(b)) => a.mtime < b.mtime,
            ("-ot", None, Some(_)) => true,
            ("-ef", Some(a), Some(b)) => a.physical == b.physical,
            _ => false,
        }
    }
}

impl FakeShell {
    /// `test EXPR` and `[ EXPR ]`.
    pub(super) fn builtin_test(&mut self, parts: &[&str]) -> CommandResult {
        let bracket = parts
            .first()
            .is_some_and(|first| command_basename(first) == "[");
        let name = if bracket { "[" } else { "test" };
        let bash = self.is_bash();
        let mut args = parts.get(1..).unwrap_or(&[]);
        if bracket {
            match args.split_last() {
                Some((&"]", rest)) => args = rest,
                _ => {
                    let text = if bash { "missing `]'" } else { "missing ]" };
                    return CommandResult::stderr(2, self.shell_error(format_args!("[: {text}")));
                }
            }
        }
        let outcome = Eval {
            shell: self,
            args,
            pos: 0,
            nesting: 0,
        }
        .run();
        match outcome {
            Ok(value) => CommandResult::silent(u8::from(!value)),
            Err(fault) => CommandResult::stderr(
                2,
                self.shell_error(format_args!("{name}: {}", fault.text(bash))),
            ),
        }
    }
}
