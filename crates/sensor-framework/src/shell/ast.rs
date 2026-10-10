//! The syntax tree the parser builds and the evaluator walks. It holds no behaviour: the grammar
//! subset the fake shell understands is written down here as data, and everything outside it has
//! a home in [`UnsupportedKind`] so it can parse, degrade silently and never raise an error a real
//! shell would not.
//!
//! Words are `String`s. File content already reaches handlers as bytes through `FakeFs`
//! `read_range` and `OutputSegment`, and no recorded session passes a binary argument; migrating
//! every handler to byte-string arguments is deferred to when a command family (F1/F2) needs it.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;

/// A 1-based physical line within one parse unit.
pub(super) type Line = u32;

/// One shell word: the parts as written, plus the source text for the few diagnostics that quote it
/// (`$x: ambiguous redirect`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Word {
    pub parts: Vec<WordPart>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WordPart {
    /// Unquoted text: subject to globbing, never split.
    Literal(String),
    /// Single-quoted text or one backslash-escaped character: no glob, no split.
    Quoted(String),
    /// `"..."`: parts expand but do not split or glob.
    DoubleQuoted(Vec<WordPart>),
    Param(Param),
    /// `$(( expr ))`, the raw expression text.
    Arith(String),
    /// `$( list )` or a backtick pair.
    CmdSub(List),
    /// A leading `~`.
    Tilde,
    /// A construct outside the subset (`$'..'`, `${x##*/}`, brace expansion, `<(..)`, an array
    /// assignment). The command holding it degrades to [`Command::Unsupported`].
    Unsupported(UnsupportedKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Param {
    pub name: ParamName,
    /// `${name:-word}` and `${name-word}`.
    pub default: Option<ParamDefault>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ParamName {
    Var(String),
    /// `$?`
    Status,
    /// `$$`
    Pid,
    /// `$0`
    Zero,
    /// `$!`
    Bang,
    /// `$#`
    Count,
    /// `$1` and up.
    Positional(usize),
    /// `$@`
    At,
    /// `$*`
    Star,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParamDefault {
    /// `:-` treats an empty value like an unset one; `-` only an unset one.
    pub colon: bool,
    pub word: Word,
}

/// Why a construct is outside the subset. Only the trace reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum UnsupportedKind {
    DoubleBracket,
    AnsiCQuote,
    ArithCommand,
    ParamOp,
    BraceExpansion,
    HereString,
    Array,
    Coproc,
    ProcessSubstitution,
}

/// A sequence separated by `;`, `&` and newlines.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct List {
    pub items: Vec<ListItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ListItem {
    pub and_or: AndOr,
    /// Ended by `&`: runs in a copy of the shell state.
    pub background: bool,
    /// The physical line the item ends on.
    pub end_line: Line,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AndOr {
    pub first: Pipeline,
    pub rest: Vec<(AndOrOp, Pipeline)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AndOrOp {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pipeline {
    pub bang: bool,
    /// bash's `time` keyword before the pipeline: `Some(true)` for `time -p`. The stages may be
    /// empty under it (`time` alone times nothing).
    pub timed: Option<bool>,
    pub stages: Vec<Command>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Command {
    Simple(SimpleCommand),
    Subshell {
        body: List,
        redirs: Vec<Redir>,
    },
    Brace {
        body: List,
        redirs: Vec<Redir>,
    },
    If {
        cond: List,
        then: List,
        elifs: Vec<(List, List)>,
        els: Option<List>,
        redirs: Vec<Redir>,
    },
    For {
        var: String,
        /// `None` is `for x; do`, which iterates over the positional parameters.
        words: Option<Vec<Word>>,
        body: List,
        redirs: Vec<Redir>,
    },
    While {
        cond: List,
        body: List,
        until: bool,
        redirs: Vec<Redir>,
    },
    Case {
        word: Word,
        arms: Vec<CaseArm>,
        redirs: Vec<Redir>,
    },
    /// `name() command` and bash's `function name { ... }`: running it stores the body.
    Function(Arc<FunctionDef>),
    /// Parsed and skipped: status 0, no output, no diagnostic.
    Unsupported(UnsupportedKind),
}

/// A function definition as written. The body is any command (dash) or a compound command
/// (bash); redirections written after it belong to the body command, so they apply at each call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FunctionDef {
    pub name: String,
    /// Bash accepts any literal word as a name and fails at run time on one holding a quote or an
    /// expansion (`"f"() {..}`); dash refuses those at parse time, so there it is always true.
    pub valid: bool,
    /// Written `function name`: the Korn spelling, which mksh scopes `local` variables to.
    pub keyword: bool,
    pub body: Command,
    /// The definition as written, from the name to the end of the body: what it costs against the
    /// connection's allowance, and what bash's listing falls back on for a body this shell
    /// skips.
    pub source: String,
}

/// dash's special builtins: it refuses them as function names (`Bad function name`) and words them
/// `special shell builtin` in `type`. Verified on Ubuntu 22.04's dash, where each of these is
/// refused and `cd`, `echo`, `true`, `alias`, `read`, `test`, `umask`, `type`, `command` and
/// `getopts` are not.
pub(super) const POSIX_SPECIAL: [&str; 16] = [
    ".", ":", "break", "continue", "eval", "exec", "exit", "export", "local", "readonly", "return",
    "set", "shift", "times", "trap", "unset",
];

/// Which shell's grammar a text is read in, for the few places the grammars differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Dialect {
    /// dash: no `function` keyword, a function body may be any command, a function name must be a
    /// plain identifier that is not a special builtin.
    Posix,
    /// bash, and mksh, which reads `function name { }` the same way.
    Bash,
}

/// One `pattern|pattern) list ;;` arm of a `case`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CaseArm {
    pub patterns: Vec<Word>,
    /// Empty for an arm with no commands (`x) ;;`).
    pub body: List,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SimpleCommand {
    pub assigns: Vec<Assign>,
    pub words: Vec<Word>,
    pub redirs: Vec<Redir>,
    pub line: Line,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Assign {
    pub name: String,
    pub value: Word,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Redir {
    /// The explicit file descriptor (`2>`), when written.
    pub fd: Option<u16>,
    pub op: RedirOp,
    pub target: RedirTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RedirOp {
    /// `<`
    In,
    /// `>`
    Out,
    /// `>>`
    Append,
    /// `>|`
    Clobber,
    /// `>&`
    DupOut,
    /// `<&`
    DupIn,
    /// `<>`
    ReadWrite,
    /// `<<` and `<<-`
    HereDoc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RedirTarget {
    Word(Word),
    /// The literal body of a here-document. `expand` is true when its delimiter was unquoted.
    HereBody {
        text: String,
        expand: bool,
        /// The delimiter as written (`'EOF'`), and whether it was `<<-`: bash's listing of a
        /// function prints them back.
        delim: String,
        strip: bool,
    },
}

/// What the parser found wrong, for the diagnostic the active shell level words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SyntaxError {
    pub near: Near,
    pub line: Line,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Near {
    /// An unexpected token, written as it appears (`)`, `fi`, `;;`).
    Token(String),
    Newline,
    EndOfFile,
    /// dash's `Bad function name`: not a complaint about a token, so it has its own wording.
    BadFunctionName,
}

/// Whether a word, or anything nested in it, is a construct outside the subset.
pub(super) fn word_unsupported(word: &Word) -> Option<UnsupportedKind> {
    parts_unsupported(&word.parts)
}

fn parts_unsupported(parts: &[WordPart]) -> Option<UnsupportedKind> {
    parts.iter().find_map(|part| match part {
        WordPart::Unsupported(kind) => Some(*kind),
        WordPart::DoubleQuoted(inner) => parts_unsupported(inner),
        WordPart::Param(Param {
            default: Some(default),
            ..
        }) => word_unsupported(&default.word),
        _ => None,
    })
}
