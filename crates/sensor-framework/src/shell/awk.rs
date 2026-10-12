//! `awk`, as Ubuntu 22.04's `mawk` 1.3.4 20200120 answers it (`/usr/bin/awk` is the alternatives
//! link to `/usr/bin/mawk`).
//!
//! A survey computes with it (`free | grep -i '^Mem:' | awk '{printf "%.1f", ($3/$2)*100}'`), and
//! a missing `awk` is the one answer no Ubuntu box gives. This is an interpreter for the language
//! over the session's modeled bytes: patterns and actions, `BEGIN`/`END`, fields and `NF`/`NR`,
//! the operators and control statements, arrays and `for (k in a)`, user functions, the string
//! and math built-ins, `printf`/`sprintf` through [`super::cfmt`], `getline` from the input, a file
//! or a command, and output to files or a command.
//!
//! Never-exec holds: `system()`, `"cmd" | getline` and `print | "cmd"` hand their text to this fake
//! shell's own evaluator, the same place `sh -c` goes, so nothing reaches a host process. Every
//! statement, loop trip and output byte is charged to the line's work allowance, so `BEGIN { while
//! (1) ; }` ends where any other runaway line ends.
//!
//! Recorded from mawk on Ubuntu 22.04 (2026-10-07 reference session): number output (integral
//! values within the 32-bit range print as integers, others through `%.6g`), string-number
//! comparison, `substr`/`index`/`split`/`sub`/`match` results, the usage text, the `-W version`
//! banner, and the error wordings below. `for (k in a)` walks keys in insertion order, which
//! mawk's hash order does not promise [unverified].

use std::collections::HashMap;

use super::cfmt;
use super::eval::Stdin;
use super::read::errno_text;
use super::regex::Regex;
use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};

pub(super) fn register(r: &mut Registry) {
    for name in ["awk", "mawk"] {
        r.register_if(name, ubuntu, HandlerId::Awk, FakeShell::cmd_awk);
    }
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

const USAGE: &str = "Usage: mawk [Options] [Program] [file ...]\n\nProgram:\n    The -f option value is the name of a file containing program text.\n    If no -f option is given, a \"--\" ends option processing; the following\n    parameters are the program text.\n\nOptions:\n    -f program-file  Program  text is read from file instead of from the\n                     command-line.  Multiple -f options are accepted.\n    -F value         sets the field separator, FS, to value.\n    -v var=value     assigns value to program variable var.\n    --               unambiguous end of options.\n\n    Implementation-specific options are prefixed with \"-W\".  They can be\n    abbreviated:\n\n    -W version       show version information and exit.\n    -W dump          show assembler-like listing of program and exit.\n    -W help          show this message and exit.\n    -W interactive   set unbuffered output, line-buffered input.\n    -W exec file     use file as program as well as last option.\n    -W random=number set initial random seed.\n    -W sprintf=number adjust size of sprintf buffer.\n    -W posix_space   do not consider \"\\n\" a space.\n    -W usage         show this message and exit.\n";

/// The first two lines were recorded; the rest of the banner follows mawk's source [unverified].
const VERSION: &str = "mawk 1.3.4 20200120\nCopyright 2008-2019,2020, Thomas E. Dickey\nCopyright 1991-1996,2014, Michael D. Brennan\n\nrandom-funcs:       srandom/random\nregex-funcs:        internal\ncompiled limits:\nsprintf buffer      8192\nmaximum-integer     2147483647\n";

/// mawk prints an integral value as an integer only inside this bound.
const MAX_INT: f64 = 2_147_483_647.0;
/// Deepest user-function recursion.
const CALL_DEPTH_MAX: usize = 64;
/// The most bytes one run may write anywhere.
const OUTPUT_MAX: usize = 1 << 20;
/// The longest string a single value may grow to.
const STRING_MAX: usize = 1 << 20;

// ======================================================================================== lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Str(String),
    Re(String),
    Name(String),
    /// A name directly followed by `(`: a call.
    Func(String),
    Builtin(String),
    Kw(&'static str),
    Op(&'static str),
    Newline,
    Eof,
}

const KEYWORDS: &[&str] = &[
    "BEGIN", "END", "function", "func", "if", "else", "while", "for", "do", "break", "continue",
    "next", "nextfile", "exit", "return", "delete", "getline", "print", "printf", "in",
];

const BUILTINS: &[&str] = &[
    "length", "substr", "index", "split", "sub", "gsub", "match", "sprintf", "sin", "cos", "atan2",
    "exp", "log", "sqrt", "int", "rand", "srand", "tolower", "toupper", "system", "close",
    "fflush",
];

const OPS: &[&str] = &[
    "+=", "-=", "*=", "/=", "%=", "^=", "**=", "==", "<=", ">=", "!=", "!~", "&&", "||", "++",
    "--", ">>", "**", "{", "}", "(", ")", "[", "]", ";", ",", "+", "-", "*", "/", "%", "^", "!",
    ">", "<", "|", "?", ":", "~", "$", "=",
];

struct Lexed {
    toks: Vec<(Tok, u32)>,
}

#[derive(Debug)]
enum SyntaxErr {
    At(u32, String),
    Runaway(u32, String),
    MissingBrace(u32),
    Regex(u32, String, String),
}

fn regex_allowed(prev: Option<&Tok>) -> bool {
    !matches!(
        prev,
        Some(Tok::Num(_) | Tok::Str(_) | Tok::Name(_) | Tok::Builtin(_) | Tok::Re(_))
            | Some(Tok::Op(")" | "]" | "$" | "++" | "--"))
    )
}

fn lex(src: &str) -> Result<Lexed, SyntaxErr> {
    let bytes = src.as_bytes();
    let mut toks: Vec<(Tok, u32)> = Vec::new();
    let mut line = 1u32;
    let mut i = 0usize;
    while let Some(&c) = bytes.get(i) {
        match c {
            b' ' | b'\t' | b'\r' => i = i.saturating_add(1),
            b'\\' if bytes.get(i.saturating_add(1)) == Some(&b'\n') => {
                i = i.saturating_add(2);
                line = line.saturating_add(1);
            }
            b'\n' => {
                toks.push((Tok::Newline, line));
                line = line.saturating_add(1);
                i = i.saturating_add(1);
            }
            b'#' => {
                while bytes.get(i).is_some_and(|&b| b != b'\n') {
                    i = i.saturating_add(1);
                }
            }
            b'"' => {
                i = i.saturating_add(1);
                let mut out = Vec::new();
                loop {
                    match bytes.get(i) {
                        None | Some(b'\n') => {
                            return Err(SyntaxErr::Runaway(
                                line,
                                format!(
                                    "runaway string constant \"{} ...",
                                    String::from_utf8_lossy(&out)
                                ),
                            ));
                        }
                        Some(b'"') => {
                            i = i.saturating_add(1);
                            break;
                        }
                        Some(b'\\') => {
                            i = i.saturating_add(1);
                            i = unescape(bytes, i, &mut out);
                        }
                        Some(&b) => {
                            out.push(b);
                            i = i.saturating_add(1);
                        }
                    }
                }
                toks.push((Tok::Str(String::from_utf8_lossy(&out).into_owned()), line));
            }
            b'/' if regex_allowed(toks.last().map(|(t, _)| t)) => {
                let start = i.saturating_add(1);
                let mut j = start;
                let mut out = Vec::new();
                let mut in_bracket = false;
                loop {
                    match bytes.get(j) {
                        None | Some(b'\n') => {
                            let text = String::from_utf8_lossy(bytes.get(i..j).unwrap_or(&[]));
                            return Err(SyntaxErr::Runaway(
                                line,
                                format!("runaway regular expression {text} ..."),
                            ));
                        }
                        Some(b'\\') if bytes.get(j.saturating_add(1)) == Some(&b'/') => {
                            out.push(b'/');
                            j = j.saturating_add(2);
                        }
                        Some(b'\\') => {
                            out.push(b'\\');
                            if let Some(&n) = bytes.get(j.saturating_add(1)) {
                                out.push(n);
                            }
                            j = j.saturating_add(2);
                        }
                        Some(b'[') => {
                            in_bracket = true;
                            out.push(b'[');
                            j = j.saturating_add(1);
                        }
                        Some(b']') => {
                            in_bracket = false;
                            out.push(b']');
                            j = j.saturating_add(1);
                        }
                        Some(b'/') if !in_bracket => {
                            j = j.saturating_add(1);
                            break;
                        }
                        Some(&b) => {
                            out.push(b);
                            j = j.saturating_add(1);
                        }
                    }
                }
                i = j;
                toks.push((Tok::Re(String::from_utf8_lossy(&out).into_owned()), line));
            }
            b'0'..=b'9' | b'.'
                if c != b'.'
                    || bytes
                        .get(i.saturating_add(1))
                        .is_some_and(u8::is_ascii_digit) =>
            {
                let start = i;
                while bytes
                    .get(i)
                    .is_some_and(|b| b.is_ascii_digit() || *b == b'.')
                {
                    i = i.saturating_add(1);
                }
                if matches!(bytes.get(i), Some(b'e' | b'E')) {
                    let mut j = i.saturating_add(1);
                    if matches!(bytes.get(j), Some(b'+' | b'-')) {
                        j = j.saturating_add(1);
                    }
                    if bytes.get(j).is_some_and(u8::is_ascii_digit) {
                        i = j;
                        while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                            i = i.saturating_add(1);
                        }
                    }
                }
                let text = std::str::from_utf8(bytes.get(start..i).unwrap_or(&[])).unwrap_or("0");
                toks.push((Tok::Num(str_to_num(text)), line));
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while bytes
                    .get(i)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                {
                    i = i.saturating_add(1);
                }
                let word = std::str::from_utf8(bytes.get(start..i).unwrap_or(&[]))
                    .unwrap_or("")
                    .to_string();
                let tok = if let Some(kw) = KEYWORDS.iter().find(|k| **k == word) {
                    Tok::Kw(kw)
                } else if BUILTINS.contains(&word.as_str()) {
                    Tok::Builtin(word)
                } else if bytes.get(i) == Some(&b'(') {
                    Tok::Func(word)
                } else {
                    Tok::Name(word)
                };
                toks.push((tok, line));
            }
            _ => {
                let rest = bytes.get(i..).unwrap_or(&[]);
                let Some(op) = OPS.iter().find(|op| rest.starts_with(op.as_bytes())) else {
                    return Err(SyntaxErr::At(line, char::from(c).to_string()));
                };
                i = i.saturating_add(op.len());
                toks.push((Tok::Op(op), line));
            }
        }
    }
    toks.push((Tok::Eof, line.saturating_add(1)));
    Ok(Lexed { toks })
}

/// Decode one string escape starting at `i` (just past the backslash) into `out`.
fn unescape(bytes: &[u8], i: usize, out: &mut Vec<u8>) -> usize {
    let Some(&c) = bytes.get(i) else {
        out.push(b'\\');
        return i;
    };
    let next = i.saturating_add(1);
    match c {
        b'n' => out.push(b'\n'),
        b't' => out.push(b'\t'),
        b'r' => out.push(b'\r'),
        b'\\' => out.push(b'\\'),
        b'"' => out.push(b'"'),
        b'/' => out.push(b'/'),
        b'a' => out.push(0x07),
        b'b' => out.push(0x08),
        b'f' => out.push(0x0c),
        b'v' => out.push(0x0b),
        b'0'..=b'7' => {
            let mut value = 0u32;
            let mut j = i;
            while j < i.saturating_add(3) && bytes.get(j).is_some_and(|b| (b'0'..=b'7').contains(b))
            {
                value = value.saturating_mul(8).saturating_add(u32::from(
                    bytes.get(j).copied().unwrap_or(b'0').saturating_sub(b'0'),
                ));
                j = j.saturating_add(1);
            }
            out.push(u8::try_from(value & 0xff).unwrap_or(0));
            return j;
        }
        other => {
            out.push(b'\\');
            out.push(other);
        }
    }
    next
}

/// The escapes of a `-v` value or `-F` argument.
fn unescape_all(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'\\' {
            i = unescape(bytes, i.saturating_add(1), &mut out);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ========================================================================================== ast

#[derive(Debug, Clone)]
enum Expr {
    Num(f64),
    Str(String),
    Re(usize),
    Field(Box<Expr>),
    Var(String),
    Index(String, Vec<Expr>),
    Assign(Option<&'static str>, Box<Expr>, Box<Expr>),
    Cond(Box<Expr>, Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Plus(Box<Expr>),
    Bin(&'static str, Box<Expr>, Box<Expr>),
    Cmp(&'static str, Box<Expr>, Box<Expr>),
    Concat(Box<Expr>, Box<Expr>),
    Match(bool, Box<Expr>, Box<Expr>),
    In(Vec<Expr>, String),
    Incr(bool, i8, Box<Expr>),
    Call(String, Vec<Expr>),
    Builtin(String, Vec<Expr>),
    Getline(GetSrc, Option<Box<Expr>>),
    Group(Vec<Expr>),
}

#[derive(Debug, Clone)]
enum GetSrc {
    Input,
    File(Box<Expr>),
    Cmd(Box<Expr>),
}

#[derive(Debug, Clone)]
enum Redirect {
    File(Expr),
    Append(Expr),
    Pipe(Expr),
}

#[derive(Debug, Clone)]
enum Stmt {
    Print(Vec<Expr>, Option<Redirect>),
    Printf(Vec<Expr>, Option<Redirect>),
    Expr(Expr),
    If(Expr, Box<Stmt>, Option<Box<Stmt>>),
    While(Expr, Box<Stmt>),
    Do(Box<Stmt>, Expr),
    For(
        Option<Box<Stmt>>,
        Option<Expr>,
        Option<Box<Stmt>>,
        Box<Stmt>,
    ),
    ForIn(String, String, Box<Stmt>),
    Block(Vec<Stmt>),
    Next,
    Exit(Option<Expr>),
    Return(Option<Expr>),
    Break,
    Continue,
    Delete(String, Option<Vec<Expr>>),
    Nop,
}

#[derive(Debug, Clone)]
enum Pattern {
    All,
    Expr(Expr),
    Range(Expr, Expr),
}

#[derive(Debug, Clone)]
struct Rule {
    pattern: Pattern,
    action: Option<Vec<Stmt>>,
}

#[derive(Debug, Clone)]
struct Func {
    params: Vec<String>,
    body: Vec<Stmt>,
}

#[derive(Debug, Default)]
struct Program {
    begin: Vec<Vec<Stmt>>,
    end: Vec<Vec<Stmt>>,
    rules: Vec<Rule>,
    funcs: HashMap<String, Func>,
    regexes: Vec<Regex>,
}

// ======================================================================================= parser

struct Parser {
    toks: Vec<(Tok, u32)>,
    pos: usize,
    regexes: Vec<Regex>,
    /// Inside an unparenthesized `print` list, where `>` is a redirection.
    no_gt: bool,
    /// Inside `for (... in` detection or a getline target, where `in` must not be consumed.
    no_in: bool,
    depth: u32,
}

type PResult<T> = Result<T, SyntaxErr>;

impl Parser {
    fn peek(&self) -> &Tok {
        self.toks.get(self.pos).map_or(&Tok::Eof, |(t, _)| t)
    }

    fn peek_at(&self, n: usize) -> &Tok {
        self.toks
            .get(self.pos.saturating_add(n))
            .map_or(&Tok::Eof, |(t, _)| t)
    }

    fn line(&self) -> u32 {
        self.toks.get(self.pos).map_or(1, |(_, l)| *l)
    }

    fn bump(&mut self) -> Tok {
        let tok = self.peek().clone();
        self.pos = self.pos.saturating_add(1);
        tok
    }

    fn is_op(&self, op: &str) -> bool {
        matches!(self.peek(), Tok::Op(o) if *o == op)
    }

    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Tok::Kw(k) if *k == kw)
    }

    fn error(&self) -> SyntaxErr {
        let near = match self.peek() {
            Tok::Eof => return SyntaxErr::MissingBrace(self.line()),
            Tok::Num(n) => num_to_str(*n, "%.6g"),
            Tok::Str(s) => format!("\"{s}\""),
            Tok::Re(r) => format!("/{r}/"),
            Tok::Name(n) | Tok::Func(n) | Tok::Builtin(n) => n.clone(),
            Tok::Kw(k) => (*k).to_string(),
            Tok::Op(o) => (*o).to_string(),
            Tok::Newline => "end of line".to_string(),
        };
        SyntaxErr::At(self.line(), near)
    }

    fn expect_op(&mut self, op: &str) -> PResult<()> {
        if self.is_op(op) {
            self.bump();
            Ok(())
        } else {
            Err(self.error())
        }
    }

    fn newlines(&mut self) {
        while matches!(self.peek(), Tok::Newline) {
            self.bump();
        }
    }

    fn terminators(&mut self) {
        while matches!(self.peek(), Tok::Newline) || self.is_op(";") {
            self.bump();
        }
    }

    fn enter(&mut self) -> PResult<()> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > 200 {
            return Err(self.error());
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn program(&mut self) -> PResult<Program> {
        let mut program = Program::default();
        self.terminators();
        while !matches!(self.peek(), Tok::Eof) {
            if self.is_kw("BEGIN") {
                self.bump();
                self.newlines();
                program.begin.push(self.block()?);
            } else if self.is_kw("END") {
                self.bump();
                self.newlines();
                program.end.push(self.block()?);
            } else if self.is_kw("function") || self.is_kw("func") {
                self.bump();
                let name = match self.bump() {
                    Tok::Func(n) | Tok::Name(n) => n,
                    _ => return Err(self.error()),
                };
                self.expect_op("(")?;
                let mut params = Vec::new();
                while !self.is_op(")") {
                    match self.bump() {
                        Tok::Name(p) => params.push(p),
                        _ => return Err(self.error()),
                    }
                    if self.is_op(",") {
                        self.bump();
                        self.newlines();
                    }
                }
                self.bump();
                self.newlines();
                let body = self.block()?;
                program.funcs.insert(name, Func { params, body });
            } else {
                let pattern = if self.is_op("{") {
                    Pattern::All
                } else {
                    let first = self.expr()?;
                    if self.is_op(",") {
                        self.bump();
                        self.newlines();
                        Pattern::Range(first, self.expr()?)
                    } else {
                        Pattern::Expr(first)
                    }
                };
                let action = if self.is_op("{") {
                    Some(self.block()?)
                } else {
                    None
                };
                program.rules.push(Rule { pattern, action });
            }
            self.terminators();
        }
        program.regexes = std::mem::take(&mut self.regexes);
        Ok(program)
    }

    fn block(&mut self) -> PResult<Vec<Stmt>> {
        self.expect_op("{")?;
        let mut stmts = Vec::new();
        self.terminators();
        while !self.is_op("}") {
            if matches!(self.peek(), Tok::Eof) {
                return Err(SyntaxErr::MissingBrace(self.line()));
            }
            stmts.push(self.stmt()?);
            self.terminators();
        }
        self.bump();
        Ok(stmts)
    }

    /// The end of a simple statement: `;`, a newline, or a `}` left for the block.
    fn end_simple(&mut self) -> PResult<()> {
        if self.is_op(";") || matches!(self.peek(), Tok::Newline) {
            self.bump();
            Ok(())
        } else if self.is_op("}") || matches!(self.peek(), Tok::Eof) {
            Ok(())
        } else {
            Err(self.error())
        }
    }

    fn body(&mut self) -> PResult<Stmt> {
        self.newlines();
        if self.is_op(";") {
            self.bump();
            return Ok(Stmt::Nop);
        }
        self.stmt()
    }

    fn stmt(&mut self) -> PResult<Stmt> {
        self.enter()?;
        let result = self.stmt_inner();
        self.leave();
        result
    }

    fn stmt_inner(&mut self) -> PResult<Stmt> {
        if self.is_op("{") {
            return Ok(Stmt::Block(self.block()?));
        }
        if self.is_kw("if") {
            self.bump();
            self.expect_op("(")?;
            let cond = self.expr()?;
            self.expect_op(")")?;
            let then = self.body()?;
            let save = self.pos;
            self.terminators();
            if self.is_kw("else") {
                self.bump();
                let els = self.body()?;
                return Ok(Stmt::If(cond, Box::new(then), Some(Box::new(els))));
            }
            self.pos = save;
            return Ok(Stmt::If(cond, Box::new(then), None));
        }
        if self.is_kw("while") {
            self.bump();
            self.expect_op("(")?;
            let cond = self.expr()?;
            self.expect_op(")")?;
            if self.is_op(";") {
                self.bump();
                return Ok(Stmt::While(cond, Box::new(Stmt::Nop)));
            }
            let body = self.body()?;
            return Ok(Stmt::While(cond, Box::new(body)));
        }
        if self.is_kw("do") {
            self.bump();
            let body = self.body()?;
            self.terminators();
            if !self.is_kw("while") {
                return Err(self.error());
            }
            self.bump();
            self.expect_op("(")?;
            let cond = self.expr()?;
            self.expect_op(")")?;
            self.end_simple()?;
            return Ok(Stmt::Do(Box::new(body), cond));
        }
        if self.is_kw("for") {
            self.bump();
            self.expect_op("(")?;
            if let (Tok::Name(var), Tok::Kw("in"), Tok::Name(array), Tok::Op(")")) = (
                self.peek().clone(),
                self.peek_at(1).clone(),
                self.peek_at(2).clone(),
                self.peek_at(3).clone(),
            ) {
                self.pos = self.pos.saturating_add(4);
                let body = self.body()?;
                return Ok(Stmt::ForIn(var, array, Box::new(body)));
            }
            let init = if self.is_op(";") {
                None
            } else {
                Some(Box::new(self.simple_stmt()?))
            };
            self.expect_op(";")?;
            self.newlines();
            let cond = if self.is_op(";") {
                None
            } else {
                Some(self.expr()?)
            };
            self.expect_op(";")?;
            self.newlines();
            let step = if self.is_op(")") {
                None
            } else {
                Some(Box::new(self.simple_stmt()?))
            };
            self.expect_op(")")?;
            if self.is_op(";") {
                self.bump();
                return Ok(Stmt::For(init, cond, step, Box::new(Stmt::Nop)));
            }
            let body = self.body()?;
            return Ok(Stmt::For(init, cond, step, Box::new(body)));
        }
        if self.is_op(";") {
            self.bump();
            return Ok(Stmt::Nop);
        }
        let stmt = match self.peek().clone() {
            Tok::Kw("next") | Tok::Kw("nextfile") => {
                self.bump();
                Stmt::Next
            }
            Tok::Kw("break") => {
                self.bump();
                Stmt::Break
            }
            Tok::Kw("continue") => {
                self.bump();
                Stmt::Continue
            }
            Tok::Kw("exit") => {
                self.bump();
                if self.at_simple_end() {
                    Stmt::Exit(None)
                } else {
                    Stmt::Exit(Some(self.expr()?))
                }
            }
            Tok::Kw("return") => {
                self.bump();
                if self.at_simple_end() {
                    Stmt::Return(None)
                } else {
                    Stmt::Return(Some(self.expr()?))
                }
            }
            Tok::Kw("delete") => {
                self.bump();
                let Tok::Name(name) = self.bump() else {
                    return Err(self.error());
                };
                if self.is_op("[") {
                    self.bump();
                    let keys = self.expr_list()?;
                    self.expect_op("]")?;
                    Stmt::Delete(name, Some(keys))
                } else {
                    Stmt::Delete(name, None)
                }
            }
            _ => self.simple_stmt()?,
        };
        self.end_simple()?;
        Ok(stmt)
    }

    fn at_simple_end(&self) -> bool {
        self.is_op(";") || self.is_op("}") || matches!(self.peek(), Tok::Newline | Tok::Eof)
    }

    fn simple_stmt(&mut self) -> PResult<Stmt> {
        if self.is_kw("print") || self.is_kw("printf") {
            let printf = self.is_kw("printf");
            self.bump();
            let saved = self.no_gt;
            self.no_gt = true;
            let mut args =
                if self.at_simple_end() || self.is_op(">") || self.is_op(">>") || self.is_op("|") {
                    Vec::new()
                } else {
                    self.expr_list()?
                };
            self.no_gt = saved;
            if let [Expr::Group(inner)] = args.as_slice() {
                args = inner.clone();
            }
            let redirect = if self.is_op(">") {
                self.bump();
                Some(Redirect::File(self.concat_expr()?))
            } else if self.is_op(">>") {
                self.bump();
                Some(Redirect::Append(self.concat_expr()?))
            } else if self.is_op("|") {
                self.bump();
                Some(Redirect::Pipe(self.concat_expr()?))
            } else {
                None
            };
            return Ok(if printf {
                if args.is_empty() {
                    return Err(self.error());
                }
                Stmt::Printf(args, redirect)
            } else {
                Stmt::Print(args, redirect)
            });
        }
        Ok(Stmt::Expr(self.expr()?))
    }

    fn expr_list(&mut self) -> PResult<Vec<Expr>> {
        let mut list = vec![self.expr()?];
        while self.is_op(",") {
            self.bump();
            self.newlines();
            list.push(self.expr()?);
        }
        Ok(list)
    }

    fn expr(&mut self) -> PResult<Expr> {
        self.enter()?;
        let result = self.assignment();
        self.leave();
        result
    }

    fn assignment(&mut self) -> PResult<Expr> {
        let lhs = self.ternary()?;
        let op = match self.peek() {
            Tok::Op("=") => None,
            Tok::Op("+=") => Some("+"),
            Tok::Op("-=") => Some("-"),
            Tok::Op("*=") => Some("*"),
            Tok::Op("/=") => Some("/"),
            Tok::Op("%=") => Some("%"),
            Tok::Op("^=" | "**=") => Some("^"),
            _ => return Ok(lhs),
        };
        if !matches!(lhs, Expr::Var(_) | Expr::Index(..) | Expr::Field(_)) {
            return Err(self.error());
        }
        self.bump();
        self.newlines();
        let rhs = self.assignment()?;
        Ok(Expr::Assign(op, Box::new(lhs), Box::new(rhs)))
    }

    fn ternary(&mut self) -> PResult<Expr> {
        let cond = self.or()?;
        if !self.is_op("?") {
            return Ok(cond);
        }
        self.bump();
        self.newlines();
        let a = self.ternary()?;
        self.newlines();
        self.expect_op(":")?;
        self.newlines();
        let b = self.ternary()?;
        Ok(Expr::Cond(Box::new(cond), Box::new(a), Box::new(b)))
    }

    fn or(&mut self) -> PResult<Expr> {
        let mut left = self.and()?;
        while self.is_op("||") {
            self.bump();
            self.newlines();
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> PResult<Expr> {
        let mut left = self.in_expr()?;
        while self.is_op("&&") {
            self.bump();
            self.newlines();
            let right = self.in_expr()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn in_expr(&mut self) -> PResult<Expr> {
        let mut left = self.match_expr()?;
        while self.is_kw("in") && !self.no_in {
            self.bump();
            let Tok::Name(array) = self.bump() else {
                return Err(self.error());
            };
            let keys = match left {
                Expr::Group(keys) => keys,
                other => vec![other],
            };
            left = Expr::In(keys, array);
        }
        Ok(left)
    }

    fn match_expr(&mut self) -> PResult<Expr> {
        let mut left = self.relational()?;
        loop {
            let negate = if self.is_op("~") {
                false
            } else if self.is_op("!~") {
                true
            } else {
                return Ok(left);
            };
            self.bump();
            let right = self.relational()?;
            left = Expr::Match(negate, Box::new(left), Box::new(right));
        }
    }

    fn relational(&mut self) -> PResult<Expr> {
        let left = self.concat_expr()?;
        let op = match self.peek() {
            Tok::Op("<") => "<",
            Tok::Op("<=") => "<=",
            Tok::Op("!=") => "!=",
            Tok::Op("==") => "==",
            Tok::Op(">") if !self.no_gt => ">",
            Tok::Op(">=") => ">=",
            _ => return Ok(left),
        };
        self.bump();
        let right = self.concat_expr()?;
        Ok(Expr::Cmp(op, Box::new(left), Box::new(right)))
    }

    /// Whether the next token can start an operand of a concatenation.
    fn starts_operand(&self) -> bool {
        match self.peek() {
            Tok::Num(_)
            | Tok::Str(_)
            | Tok::Re(_)
            | Tok::Name(_)
            | Tok::Func(_)
            | Tok::Builtin(_) => true,
            Tok::Op("$" | "!" | "(" | "-" | "+" | "++" | "--") => true,
            Tok::Kw("getline") => false,
            _ => false,
        }
    }

    fn concat_expr(&mut self) -> PResult<Expr> {
        let mut left = self.additive()?;
        loop {
            // `cmd | getline [var]`.
            if self.is_op("|") && matches!(self.peek_at(1), Tok::Kw("getline")) {
                self.bump();
                self.bump();
                let target = self.getline_target()?;
                left = Expr::Getline(GetSrc::Cmd(Box::new(left)), target);
                continue;
            }
            if !self.starts_operand() || self.is_op("-") || self.is_op("+") {
                return Ok(left);
            }
            let right = self.additive()?;
            left = Expr::Concat(Box::new(left), Box::new(right));
        }
    }

    fn additive(&mut self) -> PResult<Expr> {
        let mut left = self.multiplicative()?;
        loop {
            let op = if self.is_op("+") {
                "+"
            } else if self.is_op("-") {
                "-"
            } else {
                return Ok(left);
            };
            self.bump();
            let right = self.multiplicative()?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
        }
    }

    fn multiplicative(&mut self) -> PResult<Expr> {
        let mut left = self.unary()?;
        loop {
            let op = match self.peek() {
                Tok::Op("*") => "*",
                Tok::Op("/") => "/",
                Tok::Op("%") => "%",
                _ => return Ok(left),
            };
            self.bump();
            let right = self.unary()?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
        }
    }

    fn unary(&mut self) -> PResult<Expr> {
        self.enter()?;
        let result = match self.peek() {
            Tok::Op("!") => {
                self.bump();
                self.unary().map(|e| Expr::Not(Box::new(e)))
            }
            Tok::Op("-") => {
                self.bump();
                self.unary().map(|e| Expr::Neg(Box::new(e)))
            }
            Tok::Op("+") => {
                self.bump();
                self.unary().map(|e| Expr::Plus(Box::new(e)))
            }
            _ => self.power(),
        };
        self.leave();
        result
    }

    fn power(&mut self) -> PResult<Expr> {
        let base = self.postfix()?;
        if self.is_op("^") || self.is_op("**") {
            self.bump();
            let exponent = self.unary()?;
            return Ok(Expr::Bin("^", Box::new(base), Box::new(exponent)));
        }
        Ok(base)
    }

    fn postfix(&mut self) -> PResult<Expr> {
        let primary = self.primary()?;
        if matches!(primary, Expr::Var(_) | Expr::Index(..) | Expr::Field(_)) {
            if self.is_op("++") {
                self.bump();
                return Ok(Expr::Incr(false, 1, Box::new(primary)));
            }
            if self.is_op("--") {
                self.bump();
                return Ok(Expr::Incr(false, -1, Box::new(primary)));
            }
        }
        Ok(primary)
    }

    fn lvalue(&mut self) -> PResult<Expr> {
        match self.bump() {
            Tok::Op("$") => {
                let inner = self.field_operand()?;
                Ok(Expr::Field(Box::new(inner)))
            }
            Tok::Name(name) => {
                if self.is_op("[") {
                    self.bump();
                    let keys = self.expr_list()?;
                    self.expect_op("]")?;
                    Ok(Expr::Index(name, keys))
                } else {
                    Ok(Expr::Var(name))
                }
            }
            _ => {
                self.pos = self.pos.saturating_sub(1);
                Err(self.error())
            }
        }
    }

    /// What follows `$`: a primary, with `++`/`--` and `-` allowed (`$i++` is `($i)++`).
    fn field_operand(&mut self) -> PResult<Expr> {
        match self.peek() {
            Tok::Op("-") => {
                self.bump();
                self.field_operand().map(|e| Expr::Neg(Box::new(e)))
            }
            Tok::Op("++") | Tok::Op("--") => {
                let delta = if self.is_op("++") { 1 } else { -1 };
                self.bump();
                let target = self.lvalue()?;
                Ok(Expr::Incr(true, delta, Box::new(target)))
            }
            _ => self.primary(),
        }
    }

    fn getline_target(&mut self) -> PResult<Option<Box<Expr>>> {
        if matches!(self.peek(), Tok::Name(_)) || self.is_op("$") {
            let saved = self.no_in;
            self.no_in = true;
            let target = self.lvalue();
            self.no_in = saved;
            return Ok(Some(Box::new(target?)));
        }
        Ok(None)
    }

    fn primary(&mut self) -> PResult<Expr> {
        self.enter()?;
        let result = self.primary_inner();
        self.leave();
        result
    }

    fn primary_inner(&mut self) -> PResult<Expr> {
        match self.peek().clone() {
            Tok::Num(n) => {
                self.bump();
                Ok(Expr::Num(n))
            }
            Tok::Str(s) => {
                self.bump();
                Ok(Expr::Str(s))
            }
            Tok::Re(r) => {
                let line = self.line();
                self.bump();
                let re = Regex::awk(r.as_bytes()).map_err(|e| {
                    SyntaxErr::Regex(line, mawk_regex_reason(&e).to_string(), r.clone())
                })?;
                self.regexes.push(re);
                Ok(Expr::Re(self.regexes.len().saturating_sub(1)))
            }
            Tok::Op("$") => self.lvalue(),
            Tok::Op("++") | Tok::Op("--") => {
                let delta = if self.is_op("++") { 1 } else { -1 };
                self.bump();
                let target = self.lvalue()?;
                Ok(Expr::Incr(true, delta, Box::new(target)))
            }
            Tok::Op("-") => {
                self.bump();
                self.unary().map(|e| Expr::Neg(Box::new(e)))
            }
            Tok::Op("!") => {
                self.bump();
                self.unary().map(|e| Expr::Not(Box::new(e)))
            }
            Tok::Op("(") => {
                self.bump();
                let saved = (self.no_gt, self.no_in);
                self.no_gt = false;
                self.no_in = false;
                self.newlines();
                let first = self.expr();
                let result = match first {
                    Ok(first) if self.is_op(",") => {
                        let mut items = vec![first];
                        while self.is_op(",") {
                            self.bump();
                            self.newlines();
                            items.push(self.expr()?);
                        }
                        self.newlines();
                        self.expect_op(")").map(|()| Expr::Group(items))
                    }
                    Ok(first) => {
                        self.newlines();
                        self.expect_op(")").map(|()| first)
                    }
                    Err(e) => Err(e),
                };
                (self.no_gt, self.no_in) = saved;
                result
            }
            Tok::Name(_) => self.lvalue(),
            Tok::Func(name) => {
                self.bump();
                self.expect_op("(")?;
                let args = self.call_args()?;
                Ok(Expr::Call(name, args))
            }
            Tok::Builtin(name) => {
                self.bump();
                let args = if self.is_op("(") {
                    self.bump();
                    self.call_args()?
                } else if name == "length" {
                    Vec::new()
                } else {
                    return Err(self.error());
                };
                Ok(Expr::Builtin(name, args))
            }
            Tok::Kw("getline") => {
                self.bump();
                let target = self.getline_target()?;
                if self.is_op("<") {
                    self.bump();
                    let file = self.primary()?;
                    return Ok(Expr::Getline(GetSrc::File(Box::new(file)), target));
                }
                Ok(Expr::Getline(GetSrc::Input, target))
            }
            _ => Err(self.error()),
        }
    }

    fn call_args(&mut self) -> PResult<Vec<Expr>> {
        let saved = (self.no_gt, self.no_in);
        self.no_gt = false;
        self.no_in = false;
        self.newlines();
        let args = if self.is_op(")") {
            Vec::new()
        } else {
            self.expr_list()?
        };
        self.newlines();
        (self.no_gt, self.no_in) = saved;
        self.expect_op(")")?;
        Ok(args)
    }
}

/// mawk's parenthesized reason for a pattern that does not compile.
fn mawk_regex_reason(error: &super::regex::RegexError) -> &'static str {
    use super::regex::RegexError as E;
    match error {
        E::UnmatchedParen | E::UnmatchedCloseParen => "missing ')'",
        E::UnmatchedBracket | E::Invalid => "bad class -- [], [^] or [",
        E::TrailingBackslash => "trailing \\",
        _ => "bad regular expression",
    }
}

// ======================================================================================= values

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Uninit,
    Num(f64),
    Str(String),
    /// Input text that looks like a number: compares as a number, prints as written.
    StrNum(String, f64),
}

/// The leading number of `text`, as `strtod` reads it; 0 when there is none.
fn str_to_num(text: &str) -> f64 {
    let t = text.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let bytes = t.as_bytes();
    let mut end = 0usize;
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        end = 1;
    }
    let digits_start = end;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end = end.saturating_add(1);
    }
    if bytes.get(end) == Some(&b'.') {
        end = end.saturating_add(1);
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end = end.saturating_add(1);
        }
    }
    let mantissa_digits = t
        .get(digits_start..end)
        .is_some_and(|m| m.bytes().any(|b| b.is_ascii_digit()));
    if !mantissa_digits {
        return 0.0;
    }
    if matches!(bytes.get(end), Some(b'e' | b'E')) {
        let mut j = end.saturating_add(1);
        if matches!(bytes.get(j), Some(b'+' | b'-')) {
            j = j.saturating_add(1);
        }
        if bytes.get(j).is_some_and(u8::is_ascii_digit) {
            end = j;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end = end.saturating_add(1);
            }
        }
    }
    t.get(..end)
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0)
}

/// Whether input text is a number in full (blanks around it allowed), so it compares as one.
fn looks_numeric(text: &str) -> Option<f64> {
    let t = text.trim_matches([' ', '\t', '\n']);
    if t.is_empty() {
        return None;
    }
    let body = t.strip_prefix(['+', '-']).unwrap_or(t);
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(at) => (body.get(..at)?, Some(body.get(at.saturating_add(1)..)?)),
        None => (body, None),
    };
    let mantissa_ok = !mantissa.is_empty()
        && mantissa.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && mantissa.bytes().filter(|b| *b == b'.').count() <= 1
        && mantissa.bytes().any(|b| b.is_ascii_digit());
    let exponent_ok = exponent.is_none_or(|e| {
        let digits = e.strip_prefix(['+', '-']).unwrap_or(e);
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    });
    (mantissa_ok && exponent_ok).then(|| str_to_num(t))
}

/// A number as mawk prints it: an integer inside the 32-bit range, otherwise `fmt`.
fn num_to_str(n: f64, fmt: &str) -> String {
    if n.is_finite() && n.fract() == 0.0 && n.abs() <= MAX_INT {
        if n == 0.0 {
            return "0".to_string();
        }
        return format!("{n:.0}");
    }
    let mut out = Vec::new();
    sprintf_into(fmt.as_bytes(), &[Val::Num(n)], "%.6g", &mut out);
    String::from_utf8_lossy(&out).into_owned()
}

impl Val {
    fn num(&self) -> f64 {
        match self {
            Self::Uninit => 0.0,
            Self::Num(n) | Self::StrNum(_, n) => *n,
            Self::Str(s) => str_to_num(s),
        }
    }

    fn string(&self, convfmt: &str) -> String {
        match self {
            Self::Uninit => String::new(),
            Self::Num(n) => num_to_str(*n, convfmt),
            Self::Str(s) | Self::StrNum(s, _) => s.clone(),
        }
    }

    fn truthy(&self) -> bool {
        match self {
            Self::Uninit => false,
            Self::Num(n) => *n != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::StrNum(_, n) => *n != 0.0,
        }
    }

    fn input(text: String) -> Self {
        match looks_numeric(&text) {
            Some(n) => Self::StrNum(text, n),
            None => Self::Str(text),
        }
    }

    fn is_numeric(&self) -> bool {
        matches!(self, Self::Num(_) | Self::StrNum(..) | Self::Uninit)
    }
}

/// `sprintf(fmt, args...)` into `out`. A conversion with no argument left is reported by the caller.
fn sprintf_into(fmt: &[u8], args: &[Val], convfmt: &str, out: &mut Vec<u8>) -> bool {
    let mut next = 0usize;
    let mut i = 0usize;
    let mut short = false;
    while let Some(&b) = fmt.get(i) {
        if b != b'%' {
            out.push(b);
            i = i.saturating_add(1);
            continue;
        }
        let rest = fmt.get(i.saturating_add(1)..).unwrap_or(&[]);
        if rest.first() == Some(&b'%') {
            out.push(b'%');
            i = i.saturating_add(2);
            continue;
        }
        let mut take = || -> Option<Val> {
            let v = args.get(next).cloned();
            next = next.saturating_add(1);
            v
        };
        let mut star_missing = false;
        let parsed = cfmt::parse_spec(rest, || match take() {
            Some(v) => v.num() as i64,
            None => {
                star_missing = true;
                0
            }
        });
        let Some((spec, conv, used)) = parsed else {
            out.push(b'%');
            out.extend_from_slice(rest);
            break;
        };
        i = i.saturating_add(1).saturating_add(used);
        if !b"diouxXcseEfFgG".contains(&conv) {
            // Not a conversion: copied through as written.
            out.push(b'%');
            out.extend_from_slice(rest.get(..used).unwrap_or(&[]));
            continue;
        }
        let Some(value) = take() else {
            short = true;
            break;
        };
        if star_missing {
            short = true;
            break;
        }
        match conv {
            b'd' | b'i' => {
                let n = value.num().trunc().clamp(-MAX_INT, MAX_INT);
                out.extend_from_slice(cfmt::signed(&spec, n as i64).as_bytes());
            }
            b'o' | b'u' | b'x' | b'X' => {
                let n = value.num().trunc().clamp(0.0, 4_294_967_295.0);
                out.extend_from_slice(cfmt::unsigned(&spec, char::from(conv), n as u64).as_bytes());
            }
            b'c' => {
                let bytes = match &value {
                    Val::Num(n) => vec![(n.trunc().rem_euclid(256.0)) as u8],
                    other => other.string(convfmt).bytes().take(1).collect(),
                };
                out.extend_from_slice(&cfmt::string(
                    &cfmt::Spec {
                        precision: None,
                        ..spec
                    },
                    &bytes,
                ));
            }
            b's' => {
                out.extend_from_slice(&cfmt::string(&spec, value.string(convfmt).as_bytes()));
            }
            _ => {
                out.extend_from_slice(cfmt::float(&spec, char::from(conv), value.num()).as_bytes());
            }
        }
        if out.len() > STRING_MAX {
            out.truncate(STRING_MAX);
            break;
        }
    }
    !short
}

// ================================================================================= interpreter

enum Flow {
    Normal,
    Next,
    Exit,
    Return(Val),
    Break,
    Continue,
    /// The line's allowance ran out, or output hit its cap.
    Stop,
}

#[derive(Default)]
struct Array {
    map: HashMap<String, Val>,
    order: Vec<String>,
}

impl Array {
    fn get(&self, key: &str) -> Val {
        self.map.get(key).cloned().unwrap_or(Val::Uninit)
    }

    fn set(&mut self, key: String, value: Val) {
        if !self.map.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.map.insert(key, value);
    }

    fn remove(&mut self, key: &str) {
        if self.map.remove(key).is_some() {
            self.order.retain(|k| k != key);
        }
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

/// A function call's locals: scalars by name, array parameters as indexes into `arrays`.
#[derive(Default)]
struct Frame {
    scalars: HashMap<String, Val>,
    arrays: HashMap<String, usize>,
}

struct Reader {
    data: Vec<u8>,
    pos: usize,
}

struct Awk<'s, 'p> {
    sh: &'s mut FakeShell,
    parts: &'p [&'p str],
    program: Program,
    globals: HashMap<String, Val>,
    global_arrays: HashMap<String, usize>,
    arrays: Vec<Array>,
    frames: Vec<Frame>,
    record: String,
    fields: Vec<String>,
    nf: usize,
    /// The operands still to read as input, and the one being read.
    inputs: Vec<String>,
    current: Option<Reader>,
    /// Some operand names a file, so standard input is not read by default.
    file_named: bool,
    stdin_used: bool,
    files_out: Vec<(String, Vec<u8>, bool)>,
    pipes_out: Vec<(String, Vec<u8>)>,
    readers: HashMap<String, Reader>,
    out: CommandResult,
    pending_stdout: Vec<u8>,
    written: usize,
    exit_status: u8,
    range_active: Vec<bool>,
    rand_state: u64,
    error: Option<String>,
}

impl Awk<'_, '_> {
    fn charge(&mut self, n: u64) -> bool {
        self.sh.charge_work(n)
    }

    fn convfmt(&self) -> String {
        self.globals
            .get("CONVFMT")
            .map_or_else(|| "%.6g".to_string(), |v| v.string("%.6g"))
    }

    fn global_str(&self, name: &str) -> String {
        let fmt = self.convfmt();
        self.globals
            .get(name)
            .map_or_else(String::new, |v| v.string(&fmt))
    }

    fn set_global(&mut self, name: &str, value: Val) {
        self.globals.insert(name.to_string(), value);
    }

    fn runtime_error(&mut self, message: &str) {
        if self.error.is_none() {
            let filename = self.global_str("FILENAME");
            let fnr = self.global_str("FNR");
            let nr = self.global_str("NR");
            self.error = Some(format!(
                "awk: run time error: {message}\n\tFILENAME=\"{filename}\" FNR={fnr} NR={nr}\n"
            ));
        }
    }

    // ---- fields ------------------------------------------------------------------------------

    fn set_record(&mut self, text: String) {
        self.record = text;
        let fs = self.global_str("FS");
        self.fields = split_text(&self.record, &fs);
        self.nf = self.fields.len();
        self.set_global("NF", Val::Num(self.nf as f64));
    }

    fn get_field(&mut self, index: f64) -> Val {
        if index < 0.0 {
            self.runtime_error(&format!("negative field index ${}", index as i64));
            return Val::Uninit;
        }
        let i = index as usize;
        if i == 0 {
            return Val::input(self.record.clone());
        }
        match self.fields.get(i.saturating_sub(1)) {
            Some(f) => Val::input(f.clone()),
            None => Val::Uninit,
        }
    }

    fn rebuild_record(&mut self) {
        let ofs = self.global_str("OFS");
        self.record = self.fields.join(&ofs);
    }

    fn set_field(&mut self, index: f64, value: String) {
        let i = index.max(0.0) as usize;
        if i == 0 {
            self.set_record(value);
            return;
        }
        if i > 10_000 {
            self.runtime_error("field index too large");
            return;
        }
        if self.fields.len() < i {
            self.fields.resize(i, String::new());
        }
        if let Some(slot) = self.fields.get_mut(i.saturating_sub(1)) {
            *slot = value;
        }
        self.nf = self.fields.len();
        self.set_global("NF", Val::Num(self.nf as f64));
        self.rebuild_record();
    }

    fn set_nf(&mut self, n: f64) {
        let n = n.max(0.0) as usize;
        if n > 10_000 {
            self.runtime_error("NF too large");
            return;
        }
        self.fields.resize(n, String::new());
        self.nf = n;
        self.rebuild_record();
    }

    // ---- variables ---------------------------------------------------------------------------

    fn get_var(&mut self, name: &str) -> Val {
        if let Some(frame) = self.frames.last()
            && let Some(v) = frame.scalars.get(name)
        {
            return v.clone();
        }
        if name == "NF" {
            return Val::Num(self.nf as f64);
        }
        self.globals.get(name).cloned().unwrap_or(Val::Uninit)
    }

    fn set_var(&mut self, name: &str, value: Val) {
        if let Some(frame) = self.frames.last_mut()
            && frame.scalars.contains_key(name)
        {
            frame.scalars.insert(name.to_string(), value);
            return;
        }
        if name == "NF" {
            self.set_nf(value.num());
            return;
        }
        if name == "FS" {
            // A new FS applies from the next record.
            self.set_global(name, value);
            return;
        }
        self.set_global(name, value);
    }

    fn array_id(&mut self, name: &str) -> usize {
        if let Some(frame) = self.frames.last()
            && let Some(&id) = frame.arrays.get(name)
        {
            return id;
        }
        if let Some(&id) = self.global_arrays.get(name) {
            return id;
        }
        self.arrays.push(Array::default());
        let id = self.arrays.len().saturating_sub(1);
        if let Some(frame) = self.frames.last_mut()
            && frame.scalars.contains_key(name)
        {
            frame.scalars.remove(name);
            frame.arrays.insert(name.to_string(), id);
        } else {
            self.global_arrays.insert(name.to_string(), id);
        }
        id
    }

    fn key(&mut self, keys: &[Expr]) -> Result<String, Flow> {
        let subsep = self
            .globals
            .get("SUBSEP")
            .map_or_else(|| "\u{1c}".to_string(), |v| v.string("%.6g"));
        let fmt = self.convfmt();
        let mut parts = Vec::new();
        for k in keys {
            parts.push(self.eval(k)?.string(&fmt));
        }
        Ok(parts.join(&subsep))
    }

    fn assign(&mut self, target: &Expr, value: Val) -> Result<Val, Flow> {
        match target {
            Expr::Var(name) => {
                self.set_var(name, value.clone());
            }
            Expr::Index(name, keys) => {
                let key = self.key(keys)?;
                let id = self.array_id(name);
                if let Some(array) = self.arrays.get_mut(id) {
                    array.set(key, value.clone());
                }
            }
            Expr::Field(index) => {
                let i = self.eval(index)?.num();
                let fmt = self.convfmt();
                self.set_field(i, value.string(&fmt));
            }
            _ => {}
        }
        Ok(value)
    }

    // ---- evaluation --------------------------------------------------------------------------

    fn eval(&mut self, expr: &Expr) -> Result<Val, Flow> {
        if !self.charge(1) {
            return Err(Flow::Stop);
        }
        if self.error.is_some() {
            return Err(Flow::Exit);
        }
        let fmt = self.convfmt();
        Ok(match expr {
            Expr::Num(n) => Val::Num(*n),
            Expr::Str(s) => Val::Str(s.clone()),
            Expr::Re(index) => {
                let record = self.record.clone();
                let hit = self
                    .program
                    .regexes
                    .get(*index)
                    .is_some_and(|re| re.is_match(record.as_bytes()));
                Val::Num(f64::from(u8::from(hit)))
            }
            Expr::Field(index) => {
                let i = self.eval(index)?.num();
                self.get_field(i)
            }
            Expr::Var(name) => self.get_var(name),
            Expr::Index(name, keys) => {
                let key = self.key(keys)?;
                let id = self.array_id(name);
                match self.arrays.get_mut(id) {
                    Some(array) => {
                        let v = array.get(&key);
                        if v == Val::Uninit {
                            // A reference creates the element, as in every awk.
                            array.set(key, Val::Uninit);
                        }
                        v
                    }
                    None => Val::Uninit,
                }
            }
            Expr::Assign(op, target, value) => {
                let rhs = self.eval(value)?;
                let new = match op {
                    None => match rhs {
                        Val::Uninit => Val::Uninit,
                        other => other,
                    },
                    Some(op) => {
                        let lhs = self.eval(target)?.num();
                        Val::Num(self.arith(op, lhs, rhs.num())?)
                    }
                };
                self.assign(target, new)?
            }
            Expr::Cond(c, a, b) => {
                if self.eval(c)?.truthy() {
                    self.eval(a)?
                } else {
                    self.eval(b)?
                }
            }
            Expr::And(a, b) => {
                let v = self.eval(a)?.truthy() && self.eval(b)?.truthy();
                Val::Num(f64::from(u8::from(v)))
            }
            Expr::Or(a, b) => {
                let v = self.eval(a)?.truthy() || self.eval(b)?.truthy();
                Val::Num(f64::from(u8::from(v)))
            }
            Expr::Not(a) => Val::Num(f64::from(u8::from(!self.eval(a)?.truthy()))),
            Expr::Neg(a) => Val::Num(-self.eval(a)?.num()),
            Expr::Plus(a) => Val::Num(self.eval(a)?.num()),
            Expr::Bin(op, a, b) => {
                let x = self.eval(a)?.num();
                let y = self.eval(b)?.num();
                Val::Num(self.arith(op, x, y)?)
            }
            Expr::Cmp(op, a, b) => {
                let x = self.eval(a)?;
                let y = self.eval(b)?;
                let ordering = if x.is_numeric() && y.is_numeric() {
                    x.num().partial_cmp(&y.num())
                } else {
                    Some(x.string(&fmt).cmp(&y.string(&fmt)))
                };
                let truth = match (ordering, *op) {
                    (None, "!=") => true,
                    (None, _) => false,
                    (Some(o), "<") => o.is_lt(),
                    (Some(o), "<=") => o.is_le(),
                    (Some(o), ">") => o.is_gt(),
                    (Some(o), ">=") => o.is_ge(),
                    (Some(o), "==") => o.is_eq(),
                    (Some(o), _) => o.is_ne(),
                };
                Val::Num(f64::from(u8::from(truth)))
            }
            Expr::Concat(a, b) => {
                let mut s = self.eval(a)?.string(&fmt);
                s.push_str(&self.eval(b)?.string(&fmt));
                if s.len() > STRING_MAX {
                    self.runtime_error("string too long");
                    return Err(Flow::Exit);
                }
                Val::Str(s)
            }
            Expr::Match(negate, subject, pattern) => {
                let text = self.eval(subject)?.string(&fmt);
                let hit = self.regex_matches(pattern, &text)?;
                Val::Num(f64::from(u8::from(hit != *negate)))
            }
            Expr::In(keys, array) => {
                let key = self.key(keys)?;
                let id = self.array_id(array);
                let present = self
                    .arrays
                    .get(id)
                    .is_some_and(|a| a.map.contains_key(&key));
                Val::Num(f64::from(u8::from(present)))
            }
            Expr::Incr(prefix, delta, target) => {
                let old = self.eval(target)?.num();
                let new = old + f64::from(*delta);
                self.assign(target, Val::Num(new))?;
                Val::Num(if *prefix { new } else { old })
            }
            Expr::Group(items) => {
                // A parenthesized list outside `in` or print: mawk reports it as a syntax error;
                // evaluated here as its last item.
                let mut last = Val::Uninit;
                for item in items {
                    last = self.eval(item)?;
                }
                last
            }
            Expr::Call(name, args) => self.call(name, args)?,
            Expr::Builtin(name, args) => self.builtin(name, args)?,
            Expr::Getline(src, target) => self.getline(src, target.as_deref())?,
        })
    }

    fn arith(&mut self, op: &str, x: f64, y: f64) -> Result<f64, Flow> {
        Ok(match op {
            "+" => x + y,
            "-" => x - y,
            "*" => x * y,
            "/" => {
                if y == 0.0 {
                    self.runtime_error("division by zero");
                    return Err(Flow::Exit);
                }
                x / y
            }
            "%" => {
                if y == 0.0 {
                    self.runtime_error("division by zero in %");
                    return Err(Flow::Exit);
                }
                x % y
            }
            _ => x.powf(y),
        })
    }

    fn regex_of(&mut self, pattern: &Expr) -> Result<Option<Regex>, Flow> {
        if let Expr::Re(index) = pattern {
            return Ok(self.program.regexes.get(*index).cloned());
        }
        let fmt = self.convfmt();
        let text = self.eval(pattern)?.string(&fmt);
        match Regex::awk(text.as_bytes()) {
            Ok(re) => Ok(Some(re)),
            Err(e) => {
                self.runtime_error(&format!(
                    "regular expression compile failed ({})\n{text}",
                    mawk_regex_reason(&e)
                ));
                Err(Flow::Exit)
            }
        }
    }

    fn regex_matches(&mut self, pattern: &Expr, text: &str) -> Result<bool, Flow> {
        let Some(re) = self.regex_of(pattern)? else {
            return Ok(false);
        };
        if !self.charge(re.cost(text.len())) {
            return Err(Flow::Stop);
        }
        Ok(re.is_match(text.as_bytes()))
    }

    fn call(&mut self, name: &str, args: &[Expr]) -> Result<Val, Flow> {
        let Some(func) = self.program.funcs.get(name).cloned() else {
            self.runtime_error(&format!("function {name} never defined"));
            return Err(Flow::Exit);
        };
        if self.frames.len() >= CALL_DEPTH_MAX {
            self.runtime_error("function call nesting too deep");
            return Err(Flow::Exit);
        }
        let mut frame = Frame::default();
        for (index, param) in func.params.iter().enumerate() {
            match args.get(index) {
                // A bare name that is (or will be) an array is passed by reference.
                Some(Expr::Var(arg)) if self.is_array_name(arg) || !self.is_scalar_name(arg) => {
                    if self.is_array_name(arg) {
                        let id = self.array_id(arg);
                        frame.arrays.insert(param.clone(), id);
                    } else {
                        frame.scalars.insert(param.clone(), Val::Uninit);
                    }
                }
                Some(expr) => {
                    let value = self.eval(expr)?;
                    frame.scalars.insert(param.clone(), value);
                }
                None => {
                    frame.scalars.insert(param.clone(), Val::Uninit);
                }
            }
        }
        self.frames.push(frame);
        let flow = self.run_block(&func.body);
        self.frames.pop();
        match flow {
            Flow::Return(v) => Ok(v),
            Flow::Normal | Flow::Break | Flow::Continue => Ok(Val::Uninit),
            other => Err(other),
        }
    }

    fn is_array_name(&self, name: &str) -> bool {
        self.frames
            .last()
            .is_some_and(|f| f.arrays.contains_key(name))
            || (!self
                .frames
                .last()
                .is_some_and(|f| f.scalars.contains_key(name))
                && self.global_arrays.contains_key(name))
    }

    fn is_scalar_name(&self, name: &str) -> bool {
        self.frames
            .last()
            .is_some_and(|f| f.scalars.get(name).is_some_and(|v| *v != Val::Uninit))
            || self.globals.contains_key(name)
    }

    fn builtin(&mut self, name: &str, args: &[Expr]) -> Result<Val, Flow> {
        let fmt = self.convfmt();
        let arg = |me: &mut Self, i: usize| -> Result<Val, Flow> {
            match args.get(i) {
                Some(e) => me.eval(e),
                None => Ok(Val::Uninit),
            }
        };
        Ok(match name {
            "length" => match args.first() {
                None => Val::Num(self.record.len() as f64),
                Some(Expr::Var(n)) if self.is_array_name(n) => {
                    let id = self.array_id(n);
                    Val::Num(self.arrays.get(id).map_or(0, |a| a.map.len()) as f64)
                }
                Some(e) => Val::Num(self.eval(e)?.string(&fmt).len() as f64),
            },
            "substr" => {
                let s = arg(self, 0)?.string(&fmt);
                let len = s.len() as f64;
                let start = arg(self, 1)?.num();
                let (from, to) = if args.len() > 2 {
                    let count = arg(self, 2)?.num();
                    substr_range(start, Some(count), len)
                } else {
                    substr_range(start, None, len)
                };
                Val::Str(s.get(from..to).unwrap_or("").to_string())
            }
            "index" => {
                let s = arg(self, 0)?.string(&fmt);
                let t = arg(self, 1)?.string(&fmt);
                Val::Num(s.find(&t).map_or(0, |i| i.saturating_add(1)) as f64)
            }
            "split" => {
                let s = arg(self, 0)?.string(&fmt);
                let Some(Expr::Var(array)) = args.get(1) else {
                    self.runtime_error("split: second argument is not an array");
                    return Err(Flow::Exit);
                };
                let pieces = match args.get(2) {
                    Some(Expr::Re(index)) => match self.program.regexes.get(*index).cloned() {
                        Some(re) => split_regex(&s, &re),
                        None => Vec::new(),
                    },
                    Some(e) => {
                        let sep = self.eval(e)?.string(&fmt);
                        split_text(&s, &sep)
                    }
                    None => {
                        let fs = self.global_str("FS");
                        split_text(&s, &fs)
                    }
                };
                let id = self.array_id(array);
                let count = pieces.len();
                if let Some(a) = self.arrays.get_mut(id) {
                    a.clear();
                    for (i, piece) in pieces.into_iter().enumerate() {
                        a.set(i.saturating_add(1).to_string(), Val::input(piece));
                    }
                }
                Val::Num(count as f64)
            }
            "sub" | "gsub" => {
                let Some(pattern) = args.first() else {
                    return Ok(Val::Num(0.0));
                };
                let Some(re) = self.regex_of(pattern)? else {
                    return Ok(Val::Num(0.0));
                };
                let replacement = arg(self, 1)?.string(&fmt);
                let target = args
                    .get(2)
                    .cloned()
                    .unwrap_or(Expr::Field(Box::new(Expr::Num(0.0))));
                let text = self.eval(&target)?.string(&fmt);
                if !self.charge(re.cost(text.len()).saturating_mul(2)) {
                    return Err(Flow::Stop);
                }
                let (result, count) = substitute(&re, &text, &replacement, name == "gsub");
                if count > 0 {
                    self.assign(&target, Val::Str(result))?;
                }
                Val::Num(count as f64)
            }
            "match" => {
                let text = arg(self, 0)?.string(&fmt);
                let Some(pattern) = args.get(1) else {
                    return Ok(Val::Num(0.0));
                };
                let Some(re) = self.regex_of(pattern)? else {
                    return Ok(Val::Num(0.0));
                };
                let (start, length) = match re.find_at(text.as_bytes(), 0) {
                    Some((s, e)) => (s.saturating_add(1) as f64, e.saturating_sub(s) as f64),
                    None => (0.0, -1.0),
                };
                self.set_global("RSTART", Val::Num(start));
                self.set_global("RLENGTH", Val::Num(length));
                Val::Num(start)
            }
            "sprintf" => {
                let mut values = Vec::new();
                for a in args {
                    values.push(self.eval(a)?);
                }
                let Some((format, rest)) = values.split_first() else {
                    return Ok(Val::Str(String::new()));
                };
                let format = format.string(&fmt);
                let mut out = Vec::new();
                if !sprintf_into(format.as_bytes(), rest, &fmt, &mut out) {
                    self.runtime_error(&format!(
                        "not enough arguments passed to sprintf(\"{format}\")"
                    ));
                    return Err(Flow::Exit);
                }
                Val::Str(String::from_utf8_lossy(&out).into_owned())
            }
            "sin" => Val::Num(arg(self, 0)?.num().sin()),
            "cos" => Val::Num(arg(self, 0)?.num().cos()),
            "atan2" => {
                let y = arg(self, 0)?.num();
                let x = arg(self, 1)?.num();
                Val::Num(y.atan2(x))
            }
            "exp" => Val::Num(arg(self, 0)?.num().exp()),
            "log" => {
                let x = arg(self, 0)?.num();
                // glibc prints the NaN of a negative logarithm as `-nan` (recorded).
                Val::Num(if x < 0.0 { -f64::NAN } else { x.ln() })
            }
            "sqrt" => Val::Num(arg(self, 0)?.num().sqrt()),
            "int" => Val::Num(arg(self, 0)?.num().trunc()),
            "rand" => {
                self.rand_state = self
                    .rand_state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                Val::Num((self.rand_state >> 11) as f64 / (1u64 << 53) as f64)
            }
            "srand" => {
                let previous = self.rand_state;
                let seed = if args.is_empty() {
                    self.sh.now().timestamp() as f64
                } else {
                    arg(self, 0)?.num()
                };
                self.rand_state = seed as u64;
                Val::Num(previous as f64)
            }
            "tolower" => Val::Str(arg(self, 0)?.string(&fmt).to_ascii_lowercase()),
            "toupper" => Val::Str(arg(self, 0)?.string(&fmt).to_ascii_uppercase()),
            "system" => {
                let command = arg(self, 0)?.string(&fmt);
                self.flush_stdout();
                let status = self.run_command_with(&command, None, None);
                Val::Num(f64::from(status))
            }
            "close" => {
                let target = arg(self, 0)?.string(&fmt);
                Val::Num(f64::from(self.close(&target)))
            }
            "fflush" => {
                self.flush_stdout();
                Val::Num(0.0)
            }
            _ => Val::Uninit,
        })
    }

    // ---- input -------------------------------------------------------------------------------

    /// The next record of the main input, or `None` at its end.
    fn next_record(&mut self) -> Option<String> {
        loop {
            if self.current.is_none() && !self.open_next_input() {
                return None;
            }
            let rs = self.global_str("RS");
            let reader = self.current.as_mut()?;
            if let Some(record) = read_record(reader, &rs) {
                return Some(record);
            }
            self.current = None;
        }
    }

    /// Open the next input operand, applying `NAME=value` operands on the way. Standard input is
    /// read once when no operand names a file.
    fn open_next_input(&mut self) -> bool {
        loop {
            let operand = if !self.inputs.is_empty() {
                self.inputs.remove(0)
            } else if !self.file_named && !self.stdin_used {
                self.stdin_used = true;
                "-".to_string()
            } else {
                return false;
            };
            if let Some((name, value)) = assignment_operand(&operand) {
                self.set_var(&name, Val::input(unescape_all(&value)));
                continue;
            }
            let cap = self.sh.read_cap();
            let name = if operand == "-" {
                None
            } else {
                Some(operand.as_str())
            };
            match self.sh.read_source(self.parts, name, cap) {
                Ok(data) => {
                    if !self.charge(len_u64(data.len())) {
                        return false;
                    }
                    self.set_global(
                        "FILENAME",
                        Val::Str(if operand == "-" {
                            String::new()
                        } else {
                            operand.clone()
                        }),
                    );
                    self.set_global("FNR", Val::Num(0.0));
                    self.current = Some(Reader { data, pos: 0 });
                    return true;
                }
                Err(error) => {
                    let text = format!("awk: cannot open {operand} ({})\n", errno_text(&error));
                    self.out.append(CommandResult::stderr(2, text));
                    self.exit_status = 2;
                }
            }
        }
    }

    fn getline(&mut self, src: &GetSrc, target: Option<&Expr>) -> Result<Val, Flow> {
        let fmt = self.convfmt();
        let line = match src {
            GetSrc::Input => match self.next_record() {
                Some(line) => {
                    let nr = self.get_var("NR").num() + 1.0;
                    self.set_global("NR", Val::Num(nr));
                    let fnr = self.get_var("FNR").num() + 1.0;
                    self.set_global("FNR", Val::Num(fnr));
                    Some(line)
                }
                None => None,
            },
            GetSrc::File(file) => {
                let name = self.eval(file)?.string(&fmt);
                if !self.readers.contains_key(&name) {
                    let cap = self.sh.read_cap();
                    let source = if name == "-" || name == "/dev/stdin" {
                        None
                    } else {
                        Some(name.as_str())
                    };
                    match self.sh.read_source(self.parts, source, cap) {
                        Ok(data) => {
                            self.readers.insert(name.clone(), Reader { data, pos: 0 });
                        }
                        Err(_) => return Ok(Val::Num(-1.0)),
                    }
                }
                let rs = self.global_str("RS");
                self.readers
                    .get_mut(&name)
                    .and_then(|r| read_record(r, &rs))
            }
            GetSrc::Cmd(command) => {
                let command = self.eval(command)?.string(&fmt);
                let key = format!("\u{0}cmd:{command}");
                if !self.readers.contains_key(&key) {
                    self.flush_stdout();
                    let mut captured = Vec::new();
                    self.run_command_with(&command, Some(&mut captured), None);
                    self.readers.insert(
                        key.clone(),
                        Reader {
                            data: captured,
                            pos: 0,
                        },
                    );
                }
                let rs = self.global_str("RS");
                let line = self.readers.get_mut(&key).and_then(|r| read_record(r, &rs));
                if line.is_some() {
                    let nr = self.get_var("NR").num() + 1.0;
                    self.set_global("NR", Val::Num(nr));
                }
                line
            }
        };
        let Some(line) = line else {
            return Ok(Val::Num(0.0));
        };
        match target {
            Some(target) => {
                self.assign(target, Val::input(line))?;
            }
            None => {
                self.set_record(line);
                if matches!(src, GetSrc::File(_) | GetSrc::Cmd(_)) {
                    // `getline < file` sets $0 and NF only.
                }
            }
        }
        Ok(Val::Num(1.0))
    }

    /// Run `command` through the fake shell: its standard output goes to `capture` when given,
    /// else into this command's output, and `input` is what it reads.
    fn run_command_with(
        &mut self,
        command: &str,
        capture: Option<&mut Vec<u8>>,
        input: Option<Vec<u8>>,
    ) -> u8 {
        let saved = input.map(|data| std::mem::replace(&mut self.sh.stdin, Stdin::data(data)));
        let mut result =
            self.sh
                .run_shell_text("sh", command, None, &[], super::ScriptKind::Command);
        if let Some(previous) = saved {
            self.sh.stdin = previous;
        }
        let status = result.status;
        match capture {
            Some(buffer) => {
                buffer.extend(result.take_stdout());
                result.status = 0;
                self.out.append(strip_status(result));
            }
            None => {
                self.written = self.written.saturating_add(result.bytes().len());
                self.out.append(strip_status(result));
            }
        }
        status
    }

    // ---- output ------------------------------------------------------------------------------

    fn emit(&mut self, bytes: Vec<u8>, redirect: Option<&Redirect>) -> Result<(), Flow> {
        if !self.charge(len_u64(bytes.len())) {
            return Err(Flow::Stop);
        }
        self.written = self.written.saturating_add(bytes.len());
        if self.written > OUTPUT_MAX {
            return Err(Flow::Stop);
        }
        let fmt = self.convfmt();
        match redirect {
            None => self.pending_stdout.extend(bytes),
            Some(Redirect::File(target) | Redirect::Append(target)) => {
                let name = self.eval(target)?.string(&fmt);
                let append = matches!(redirect, Some(Redirect::Append(_)));
                match name.as_str() {
                    "/dev/stdout" | "-" => self.pending_stdout.extend(bytes),
                    "/dev/stderr" => {
                        self.flush_stdout();
                        self.out.append(CommandResult::stderr(0, bytes));
                    }
                    _ => match self.files_out.iter_mut().find(|(n, _, _)| *n == name) {
                        Some((_, buffer, _)) => buffer.extend(bytes),
                        None => self.files_out.push((name, bytes, append)),
                    },
                }
            }
            Some(Redirect::Pipe(target)) => {
                let name = self.eval(target)?.string(&fmt);
                match self.pipes_out.iter_mut().find(|(n, _)| *n == name) {
                    Some((_, buffer)) => buffer.extend(bytes),
                    None => self.pipes_out.push((name, bytes)),
                }
            }
        }
        Ok(())
    }

    fn flush_stdout(&mut self) {
        let pending = std::mem::take(&mut self.pending_stdout);
        if !pending.is_empty() {
            self.out.append(CommandResult::stdout(pending));
        }
    }

    fn close(&mut self, name: &str) -> u8 {
        if let Some(at) = self.files_out.iter().position(|(n, _, _)| n == name) {
            let (path, bytes, append) = self.files_out.remove(at);
            self.write_file(&path, &bytes, append);
            return 0;
        }
        if let Some(at) = self.pipes_out.iter().position(|(n, _)| n == name) {
            let (command, bytes) = self.pipes_out.remove(at);
            return self.run_command_with(&command, None, Some(bytes));
        }
        let key = format!("\u{0}cmd:{name}");
        if self.readers.remove(&key).is_some() || self.readers.remove(name).is_some() {
            return 0;
        }
        // mawk returns -1 for a name it has open nothing under.
        255
    }

    fn write_file(&mut self, name: &str, bytes: &[u8], append: bool) {
        let path = self.sh.resolve_logical(name);
        let mut content = if append {
            self.sh
                .fs
                .read_all(&path, crate::fakefs::READ_CAP)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        content.extend_from_slice(bytes);
        if self.sh.traced_write_file(&path, &content).is_err() {
            self.out.append(CommandResult::stderr(
                2,
                format!("awk: cannot open \"{name}\" for output\n"),
            ));
            self.exit_status = 2;
        }
    }

    fn close_all(&mut self) {
        for (path, bytes, append) in std::mem::take(&mut self.files_out) {
            self.write_file(&path, &bytes, append);
        }
        for (command, bytes) in std::mem::take(&mut self.pipes_out) {
            self.run_command_with(&command, None, Some(bytes));
        }
    }

    // ---- statements --------------------------------------------------------------------------

    fn run_block(&mut self, stmts: &[Stmt]) -> Flow {
        for stmt in stmts {
            match self.exec(stmt) {
                Flow::Normal => {}
                other => return other,
            }
        }
        Flow::Normal
    }

    fn exec(&mut self, stmt: &Stmt) -> Flow {
        match self.exec_inner(stmt) {
            Ok(flow) => flow,
            Err(flow) => flow,
        }
    }

    fn exec_inner(&mut self, stmt: &Stmt) -> Result<Flow, Flow> {
        if !self.charge(1) {
            return Err(Flow::Stop);
        }
        let fmt = self.convfmt();
        Ok(match stmt {
            Stmt::Nop => Flow::Normal,
            Stmt::Print(args, redirect) => {
                let ofmt = self
                    .globals
                    .get("OFMT")
                    .map_or_else(|| "%.6g".to_string(), |v| v.string("%.6g"));
                let ofs = self.global_str("OFS");
                let ors = self.global_str("ORS");
                let mut line = String::new();
                if args.is_empty() {
                    line.push_str(&self.record.clone());
                } else {
                    for (i, a) in args.iter().enumerate() {
                        if i > 0 {
                            line.push_str(&ofs);
                        }
                        let v = self.eval(a)?;
                        line.push_str(&match v {
                            Val::Num(n) => num_to_str(n, &ofmt),
                            other => other.string(&fmt),
                        });
                    }
                }
                line.push_str(&ors);
                self.emit(line.into_bytes(), redirect.as_ref())?;
                Flow::Normal
            }
            Stmt::Printf(args, redirect) => {
                let mut values = Vec::new();
                for a in args {
                    values.push(self.eval(a)?);
                }
                let Some((format, rest)) = values.split_first() else {
                    return Ok(Flow::Normal);
                };
                let format = format.string(&fmt);
                let mut out = Vec::new();
                let complete = sprintf_into(format.as_bytes(), rest, &fmt, &mut out);
                self.emit(out, redirect.as_ref())?;
                if !complete {
                    self.runtime_error(&format!(
                        "not enough arguments passed to printf(\"{format}\")"
                    ));
                    return Err(Flow::Exit);
                }
                Flow::Normal
            }
            Stmt::Expr(e) => {
                self.eval(e)?;
                Flow::Normal
            }
            Stmt::If(cond, then, els) => {
                if self.eval(cond)?.truthy() {
                    self.exec(then)
                } else if let Some(els) = els {
                    self.exec(els)
                } else {
                    Flow::Normal
                }
            }
            Stmt::While(cond, body) => {
                while self.eval(cond)?.truthy() {
                    match self.exec(body) {
                        Flow::Break => break,
                        Flow::Normal | Flow::Continue => {}
                        other => return Ok(other),
                    }
                }
                Flow::Normal
            }
            Stmt::Do(body, cond) => {
                loop {
                    match self.exec(body) {
                        Flow::Break => break,
                        Flow::Normal | Flow::Continue => {}
                        other => return Ok(other),
                    }
                    if !self.eval(cond)?.truthy() {
                        break;
                    }
                }
                Flow::Normal
            }
            Stmt::For(init, cond, step, body) => {
                if let Some(init) = init {
                    match self.exec(init) {
                        Flow::Normal => {}
                        other => return Ok(other),
                    }
                }
                loop {
                    if let Some(cond) = cond
                        && !self.eval(cond)?.truthy()
                    {
                        break;
                    }
                    match self.exec(body) {
                        Flow::Break => break,
                        Flow::Normal | Flow::Continue => {}
                        other => return Ok(other),
                    }
                    if let Some(step) = step {
                        match self.exec(step) {
                            Flow::Normal => {}
                            other => return Ok(other),
                        }
                    }
                }
                Flow::Normal
            }
            Stmt::ForIn(var, array, body) => {
                let id = self.array_id(array);
                let keys = self
                    .arrays
                    .get(id)
                    .map(|a| a.order.clone())
                    .unwrap_or_default();
                for key in keys {
                    let present = self
                        .arrays
                        .get(id)
                        .is_some_and(|a| a.map.contains_key(&key));
                    if !present {
                        continue;
                    }
                    self.set_var(var, Val::input(key));
                    match self.exec(body) {
                        Flow::Break => break,
                        Flow::Normal | Flow::Continue => {}
                        other => return Ok(other),
                    }
                }
                Flow::Normal
            }
            Stmt::Block(stmts) => self.run_block(stmts),
            Stmt::Next => Flow::Next,
            Stmt::Exit(code) => {
                if let Some(code) = code {
                    let n = self.eval(code)?.num();
                    self.exit_status = (n as i64).rem_euclid(256) as u8;
                }
                Flow::Exit
            }
            Stmt::Return(value) => {
                let v = match value {
                    Some(e) => self.eval(e)?,
                    None => Val::Uninit,
                };
                Flow::Return(v)
            }
            Stmt::Break => Flow::Break,
            Stmt::Continue => Flow::Continue,
            Stmt::Delete(name, keys) => {
                let id = self.array_id(name);
                match keys {
                    Some(keys) => {
                        let key = self.key(keys)?;
                        if let Some(a) = self.arrays.get_mut(id) {
                            a.remove(&key);
                        }
                    }
                    None => {
                        if let Some(a) = self.arrays.get_mut(id) {
                            a.clear();
                        }
                    }
                }
                Flow::Normal
            }
        })
    }

    /// Run the whole program; the result is the command's output and status.
    fn run(mut self) -> CommandResult {
        let begins = std::mem::take(&mut self.program.begin);
        let ends = std::mem::take(&mut self.program.end);
        let rules = std::mem::take(&mut self.program.rules);
        self.range_active = vec![false; rules.len()];
        let mut exiting = false;
        let mut stopped = false;
        for block in &begins {
            match self.run_block(block) {
                Flow::Exit => {
                    exiting = true;
                    break;
                }
                Flow::Stop => {
                    stopped = true;
                    break;
                }
                _ => {}
            }
        }
        if !exiting && !stopped && (!rules.is_empty() || !ends.is_empty()) {
            'records: while let Some(record) = self.next_record() {
                let nr = self.get_var("NR").num() + 1.0;
                self.set_global("NR", Val::Num(nr));
                let fnr = self.get_var("FNR").num() + 1.0;
                self.set_global("FNR", Val::Num(fnr));
                self.set_record(record);
                for (index, rule) in rules.iter().enumerate() {
                    let selected = match self.selected(index, &rule.pattern) {
                        Ok(s) => s,
                        Err(Flow::Stop) => {
                            stopped = true;
                            break 'records;
                        }
                        Err(_) => break 'records,
                    };
                    if !selected {
                        continue;
                    }
                    let flow = match &rule.action {
                        Some(action) => self.run_block(action),
                        None => {
                            let line = format!("{}{}", self.record, self.global_str("ORS"));
                            match self.emit(line.into_bytes(), None) {
                                Ok(()) => Flow::Normal,
                                Err(flow) => flow,
                            }
                        }
                    };
                    match flow {
                        Flow::Next => continue 'records,
                        // `exit` skips the rest of the input; the END actions still run.
                        Flow::Exit => break 'records,
                        Flow::Stop => {
                            stopped = true;
                            break 'records;
                        }
                        _ => {}
                    }
                }
            }
        }
        if !stopped && self.error.is_none() {
            for block in &ends {
                match self.run_block(block) {
                    Flow::Exit | Flow::Stop => break,
                    _ => {}
                }
            }
        }
        let error = self.error.take();
        if error.is_some() {
            self.exit_status = 2;
        }
        self.close_all();
        self.flush_stdout();
        if let Some(text) = error {
            self.out.append(CommandResult::stderr(2, text));
        }
        let mut out = self.out;
        out.status = self.exit_status;
        if stopped {
            // The same bounded silent failure as every other tool the allowance stops.
            out.append(super::texttools::stopped());
        }
        out
    }

    fn selected(&mut self, index: usize, pattern: &Pattern) -> Result<bool, Flow> {
        match pattern {
            Pattern::All => Ok(true),
            Pattern::Expr(e) => Ok(self.eval(e)?.truthy()),
            Pattern::Range(a, b) => {
                let active = self.range_active.get(index).copied().unwrap_or(false);
                if active {
                    if self.eval(b)?.truthy()
                        && let Some(slot) = self.range_active.get_mut(index)
                    {
                        *slot = false;
                    }
                    Ok(true)
                } else if self.eval(a)?.truthy() {
                    if !self.eval(b)?.truthy()
                        && let Some(slot) = self.range_active.get_mut(index)
                    {
                        *slot = true;
                    }
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }
}

fn strip_status(mut result: CommandResult) -> CommandResult {
    result.status = 0;
    result
}

/// `NAME=value` operands assign instead of naming a file.
fn assignment_operand(operand: &str) -> Option<(String, String)> {
    let (name, value) = operand.split_once('=')?;
    let valid = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then(|| (name.to_string(), value.to_string()))
}

/// 0-based byte bounds of `substr(s, start[, count])` on a string of `len` bytes, as mawk
/// 1.3.4 20200120 computes them (recorded on Ubuntu 22.04): both arguments truncate toward zero,
/// and a start below 1 moves to 1 while the count grows by the distance moved
/// (`substr("hello", -1, 3)` is `hell`, `substr("hello", 0, 2)` is `he`).
fn substr_range(start: f64, count: Option<f64>, len: f64) -> (usize, usize) {
    let trunc = |x: f64| if x.is_nan() { 0.0 } else { x.trunc() };
    let mut first = trunc(start);
    let mut length = count.map_or(f64::INFINITY, trunc);
    if first < 1.0 {
        length -= first;
        first = 1.0;
    }
    let last = (first + length).min(len + 1.0);
    if last <= first {
        return (0, 0);
    }
    ((first - 1.0) as usize, (last - 1.0) as usize)
}

fn read_record(reader: &mut Reader, rs: &str) -> Option<String> {
    let rest = reader.data.get(reader.pos..)?;
    if rest.is_empty() {
        return None;
    }
    if rs.is_empty() {
        // Paragraph mode: blank lines separate records.
        let mut start = 0usize;
        while rest.get(start) == Some(&b'\n') {
            start = start.saturating_add(1);
        }
        let body = rest.get(start..)?;
        if body.is_empty() {
            reader.pos = reader.data.len();
            return None;
        }
        let end = body
            .windows(2)
            .position(|w| w == b"\n\n")
            .unwrap_or(body.len());
        let record = String::from_utf8_lossy(body.get(..end).unwrap_or(&[]))
            .trim_end_matches('\n')
            .to_string();
        let mut consumed = start.saturating_add(end);
        while rest.get(consumed) == Some(&b'\n') {
            consumed = consumed.saturating_add(1);
        }
        reader.pos = reader.pos.saturating_add(consumed);
        return Some(record);
    }
    let sep = rs.as_bytes().first().copied().unwrap_or(b'\n');
    let (record, consumed) = match rest.iter().position(|&b| b == sep) {
        Some(at) => (rest.get(..at).unwrap_or(&[]), at.saturating_add(1)),
        None => (rest, rest.len()),
    };
    reader.pos = reader.pos.saturating_add(consumed);
    Some(String::from_utf8_lossy(record).into_owned())
}

/// Split `text` by a field separator as awk does: `" "` splits on runs of blanks and trims, a
/// single other character literally, the empty string into characters, anything longer as a
/// regular expression.
fn split_text(text: &str, fs: &str) -> Vec<String> {
    if fs == " " {
        return text
            .split([' ', '\t', '\n'])
            .filter(|f| !f.is_empty())
            .map(str::to_string)
            .collect();
    }
    if text.is_empty() {
        return Vec::new();
    }
    if fs.is_empty() {
        return text.chars().map(|c| c.to_string()).collect();
    }
    let mut chars = fs.chars();
    if let (Some(only), None) = (chars.next(), chars.next())
        && only != '\\'
    {
        return text.split(only).map(str::to_string).collect();
    }
    match Regex::awk(fs.as_bytes()) {
        Ok(re) => split_regex(text, &re),
        Err(_) => vec![text.to_string()],
    }
}

fn split_regex(text: &str, re: &Regex) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut at = 0usize;
    while let Some((s, e)) = re.find_at(bytes, at) {
        if e == s {
            at = s.saturating_add(1);
            if at > bytes.len() {
                break;
            }
            continue;
        }
        out.push(String::from_utf8_lossy(bytes.get(start..s).unwrap_or(&[])).into_owned());
        start = e;
        at = e;
    }
    out.push(String::from_utf8_lossy(bytes.get(start..).unwrap_or(&[])).into_owned());
    out
}

/// `sub`/`gsub`: `&` in the replacement is the matched text, `\&` a literal ampersand.
fn substitute(re: &Regex, text: &str, replacement: &str, global: bool) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut count = 0usize;
    let mut at = 0usize;
    let mut copied = 0usize;
    while at <= bytes.len() {
        let Some((s, e)) = re.find_at(bytes, at) else {
            break;
        };
        out.extend_from_slice(bytes.get(copied..s).unwrap_or(&[]));
        let matched = bytes.get(s..e).unwrap_or(&[]);
        let rep = replacement.as_bytes();
        let mut i = 0usize;
        while let Some(&b) = rep.get(i) {
            if b == b'\\' && rep.get(i.saturating_add(1)) == Some(&b'&') {
                out.push(b'&');
                i = i.saturating_add(2);
            } else if b == b'&' {
                out.extend_from_slice(matched);
                i = i.saturating_add(1);
            } else {
                out.push(b);
                i = i.saturating_add(1);
            }
        }
        count = count.saturating_add(1);
        if e == s {
            if let Some(&next) = bytes.get(s) {
                out.push(next);
            }
            copied = s.saturating_add(1);
            at = s.saturating_add(1);
        } else {
            copied = e;
            at = e;
        }
        if !global || out.len() > STRING_MAX {
            break;
        }
    }
    out.extend_from_slice(bytes.get(copied.min(bytes.len())..).unwrap_or(&[]));
    (String::from_utf8_lossy(&out).into_owned(), count)
}

fn syntax_message(error: &SyntaxErr) -> String {
    match error {
        SyntaxErr::At(line, near) => format!("awk: line {line}: syntax error at or near {near}\n"),
        SyntaxErr::Runaway(line, text) => format!("awk: line {line}: {text}\n"),
        SyntaxErr::MissingBrace(line) => {
            format!("awk: line {line}: missing }} near end of file\n")
        }
        SyntaxErr::Regex(line, reason, text) => {
            format!("awk: line {line}: regular expression compile failed ({reason})\n{text}\n")
        }
    }
}

impl FakeShell {
    /// `awk` / `mawk`: see the module documentation.
    pub(super) fn cmd_awk(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let mut fs: Option<String> = None;
        let mut assigns: Vec<(String, String)> = Vec::new();
        let mut program_files: Vec<String> = Vec::new();
        let mut i = 0usize;
        while let Some(&arg) = args.get(i) {
            if arg == "--" {
                i = i.saturating_add(1);
                break;
            }
            if !arg.starts_with('-') || arg == "-" {
                break;
            }
            i = i.saturating_add(1);
            let (flag, attached) = arg.split_at(2.min(arg.len()));
            let value = |i: &mut usize| -> Option<String> {
                if !attached.is_empty() {
                    return Some(attached.to_string());
                }
                let v = args.get(*i).map(|s| (*s).to_string());
                *i = i.saturating_add(1);
                v
            };
            match flag {
                "-F" => fs = value(&mut i),
                "-v" => {
                    let Some(text) = value(&mut i) else {
                        return CommandResult::stderr(2, "awk: option requires an argument -- v\n");
                    };
                    match assignment_operand(&text) {
                        Some(pair) => assigns.push(pair),
                        None => {
                            return CommandResult::stderr(
                                2,
                                format!("awk: improper assignment: -v {text}\n"),
                            );
                        }
                    }
                }
                "-f" => match value(&mut i) {
                    Some(file) => program_files.push(file),
                    None => {
                        return CommandResult::stderr(2, "awk: option requires an argument -- f\n");
                    }
                },
                "-W" => {
                    let what = value(&mut i).unwrap_or_default();
                    if what.starts_with('v') {
                        return CommandResult::stdout(VERSION);
                    }
                    if what.starts_with('h') || what.starts_with('u') {
                        return CommandResult::stdout(USAGE);
                    }
                }
                "--" => {
                    // `--version` and friends: mawk 20200120 takes them as `-W` options
                    // [unverified].
                    if arg.starts_with("--v") {
                        return CommandResult::stdout(VERSION);
                    }
                    if arg.starts_with("--h") || arg.starts_with("--u") {
                        return CommandResult::stdout(USAGE);
                    }
                    return CommandResult::stderr(2, format!("awk: not an option: {arg}\n"));
                }
                _ => {
                    return CommandResult::stderr(2, format!("awk: not an option: {arg}\n"));
                }
            }
        }
        let mut source = String::new();
        if program_files.is_empty() {
            match args.get(i) {
                Some(text) => {
                    source = (*text).to_string();
                    i = i.saturating_add(1);
                }
                None => return CommandResult::stdout(USAGE),
            }
        } else {
            let cap = self.read_cap();
            for file in &program_files {
                match self.read_source(parts, Some(file.as_str()), cap) {
                    Ok(bytes) => {
                        source.push_str(&String::from_utf8_lossy(&bytes));
                        source.push('\n');
                    }
                    Err(error) => {
                        return CommandResult::stderr(
                            2,
                            format!("awk: cannot open {file} ({})\n", errno_text(&error)),
                        );
                    }
                }
            }
        }
        if !self.charge_work(len_u64(source.len())) {
            return super::texttools::stopped();
        }
        let lexed = match lex(&source) {
            Ok(lexed) => lexed,
            Err(error) => return CommandResult::stderr(2, syntax_message(&error)),
        };
        let mut parser = Parser {
            toks: lexed.toks,
            pos: 0,
            regexes: Vec::new(),
            no_gt: false,
            no_in: false,
            depth: 0,
        };
        let program = match parser.program() {
            Ok(program) => program,
            Err(error) => return CommandResult::stderr(2, syntax_message(&error)),
        };
        let mut globals: HashMap<String, Val> = HashMap::new();
        for (name, value) in [
            ("FS", " "),
            ("OFS", " "),
            ("ORS", "\n"),
            ("RS", "\n"),
            ("SUBSEP", "\u{1c}"),
            ("CONVFMT", "%.6g"),
            ("OFMT", "%.6g"),
            ("FILENAME", ""),
        ] {
            globals.insert(name.to_string(), Val::Str(value.to_string()));
        }
        for name in ["NR", "FNR", "NF", "RSTART"] {
            globals.insert(name.to_string(), Val::Num(0.0));
        }
        globals.insert("RLENGTH".to_string(), Val::Num(-1.0));
        if let Some(fs) = fs {
            let fs = unescape_all(&fs);
            let fs = if fs == "t" { "\t".to_string() } else { fs };
            globals.insert("FS".to_string(), Val::Str(fs));
        }
        let operands: Vec<String> = args
            .get(i..)
            .unwrap_or(&[])
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut awk = Awk {
            sh: self,
            parts,
            program,
            globals,
            global_arrays: HashMap::new(),
            arrays: Vec::new(),
            frames: Vec::new(),
            record: String::new(),
            fields: Vec::new(),
            nf: 0,
            inputs: operands.clone(),
            current: None,
            file_named: operands.iter().any(|op| assignment_operand(op).is_none()),
            stdin_used: false,
            files_out: Vec::new(),
            pipes_out: Vec::new(),
            readers: HashMap::new(),
            out: CommandResult::silent(0),
            pending_stdout: Vec::new(),
            written: 0,
            exit_status: 0,
            range_active: Vec::new(),
            rand_state: 0,
            error: None,
        };
        // ENVIRON and ARGV.
        let environ: Vec<(String, String)> = awk
            .sh
            .state()
            .vars
            .iter()
            .filter(|(_, v)| v.exported)
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect();
        let env_id = awk.array_id("ENVIRON");
        if let Some(env) = awk.arrays.get_mut(env_id) {
            for (k, v) in environ {
                env.set(k, Val::input(v));
            }
        }
        let argv_id = awk.array_id("ARGV");
        if let Some(argv) = awk.arrays.get_mut(argv_id) {
            argv.set("0".to_string(), Val::Str("awk".to_string()));
            for (n, op) in operands.iter().enumerate() {
                argv.set(n.saturating_add(1).to_string(), Val::input(op.clone()));
            }
        }
        awk.set_global("ARGC", Val::Num(operands.len().saturating_add(1) as f64));
        for (name, value) in assigns {
            awk.set_global(&name, Val::input(unescape_all(&value)));
        }
        awk.run()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_print_as_mawk_prints_them() {
        assert_eq!(num_to_str(2_147_483_647.0, "%.6g"), "2147483647");
        assert_eq!(num_to_str(2_147_483_648.0, "%.6g"), "2.14748e+09");
        assert_eq!(num_to_str(-2_147_483_649.0, "%.6g"), "-2.14748e+09");
        assert_eq!(num_to_str(1e20, "%.6g"), "1e+20");
        assert_eq!(num_to_str(1e6, "%.6g"), "1000000");
        assert_eq!(num_to_str(0.1 + 0.2, "%.6g"), "0.3");
        assert_eq!(num_to_str(-0.0, "%.6g"), "0");
        // CONVFMT applies to a non-integral value (recorded: `CONVFMT="%.2f"` gave `3.14`).
        assert_eq!(num_to_str(1.23456, "%.2f"), "1.23");
    }

    #[test]
    fn input_text_is_a_number_only_when_it_all_is_one() {
        assert_eq!(looks_numeric(" 10 "), Some(10.0));
        assert_eq!(looks_numeric("1e3"), Some(1000.0));
        assert_eq!(looks_numeric("3abc"), None);
        assert_eq!(looks_numeric(""), None);
        assert_eq!(str_to_num("3abc"), 3.0);
        assert_eq!(str_to_num("abc"), 0.0);
    }

    /// Each case is what mawk printed for `substr("hello", ...)` on Ubuntu 22.04.
    #[test]
    fn substr_matches_the_recorded_mawk() {
        let cut = |start: f64, count: Option<f64>| {
            let (from, to) = substr_range(start, count, 5.0);
            "hello".get(from..to).unwrap_or("").to_string()
        };
        assert_eq!(cut(2.0, None), "ello");
        assert_eq!(cut(-1.0, Some(3.0)), "hell");
        assert_eq!(cut(0.0, Some(2.0)), "he");
        assert_eq!(cut(0.0, Some(1.0)), "h");
        assert_eq!(cut(1.5, Some(1.0)), "h");
        assert_eq!(cut(2.5, Some(1.0)), "e");
        assert_eq!(cut(-1.0, None), "hello");
        assert_eq!(cut(2.0, Some(1.5)), "e");
        assert_eq!(cut(2.0, Some(0.5)), "");
        assert_eq!(cut(3.0, Some(-1.0)), "");
        assert_eq!(cut(4.0, Some(100.0)), "lo");
    }

    #[test]
    fn fields_split_as_awk_splits_them() {
        assert_eq!(split_text("  a   b  ", " "), vec!["a", "b"]);
        assert_eq!(split_text("a:b::c", ":"), vec!["a", "b", "", "c"]);
        assert_eq!(split_text("a1b22c", "[0-9]+"), vec!["a", "b", "c"]);
        assert!(split_text("", ":").is_empty());
    }
}
