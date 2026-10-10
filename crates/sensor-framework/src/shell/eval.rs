//! The evaluator: walks the syntax tree and produces a [`CommandResult`]. A simple command is
//! expanded to an argument vector and dispatched through the registry to the same handlers as
//! ever; everything else here is the shell around them.
//!
//! - Redirections are a real [`Redir`] list, opened once before the command runs and applied to
//!   what it wrote afterwards, so `> f`, `2>&1`, `< f`, here-documents and `/dev/null` behave the
//!   same on a simple command and on a whole loop.
//! - Pipelines run their stages in order, each in a copy of the shell state, feeding one stage's
//!   standard output to the next as its standard input. The status is the last stage's.
//! - `( )`, a pipeline stage, `$( )` and a background `&` run in a copy of the state; `{ }` does
//!   not. The filesystem is shared by all of them.
//! - `&&` and `||` decide on the previous status, never on output words.
//!
//! No arm of this file spawns anything: a simple command still ends in a handler that returns a
//! string, and `sh -c`, `sh FILE` and a piped `sh` re-enter this evaluator on text, under the same
//! per-line allowance and depth cap as every other re-entry.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;
use std::sync::Arc;

use super::alias::Alias;
use super::ast::{
    AndOr, AndOrOp, CaseArm, Command, Dialect, FunctionDef, List, ListItem, Near, Pipeline, Redir,
    RedirOp, RedirTarget, SimpleCommand, Word,
};
use super::expand::ExpandError;
use super::parse::{Parsed, Tail};
use super::trace::BudgetHit;
use super::trap::Traps;
use super::{
    CommandResult, ControlOp, FakeShell, Flow, Frame, FrameKind, HandlerId, OutputFd,
    OutputSegment, ParseNode, RunDecision, SegmentTrace, ShellFlavor, ShellLevel, command_basename,
    len_u64,
};
use crate::fakefs::{FsError, READ_CAP};

/// The per-line work allowance: steps taken plus bytes scanned or produced, shared by parsing,
/// expansion, evaluation and every re-entry of the line. Reset once per input line, never on
/// re-entry.
#[derive(Debug, Clone)]
pub(super) struct LineBudget {
    left: u64,
    exhausted: bool,
    charged: u64,
    unreported: bool,
}

impl LineBudget {
    pub(super) fn new(limit: u64) -> Self {
        Self {
            left: limit,
            exhausted: false,
            charged: 0,
            unreported: false,
        }
    }

    /// Spend `n`. False once the allowance is spent, and from then on.
    pub(super) fn charge(&mut self, n: u64) -> bool {
        self.charged = self.charged.saturating_add(n);
        if self.exhausted {
            return false;
        }
        if n > self.left {
            self.left = 0;
            self.exhausted = true;
            self.unreported = true;
            return false;
        }
        self.left = self.left.saturating_sub(n);
        true
    }

    /// True once, the first time after the allowance ran out, so the trace notes the hit once.
    pub(super) fn take_refusal(&mut self) -> bool {
        std::mem::take(&mut self.unreported)
    }

    pub(super) fn charged(&self) -> u64 {
        self.charged
    }

    /// What the line may still spend: the most bytes a reader may hand back without the line's
    /// own charge for them running it out.
    pub(super) fn remaining(&self) -> u64 {
        self.left
    }

    pub(super) fn exhausted(&self) -> bool {
        self.exhausted
    }
}

/// Recursive entries right now: compound commands, substitutions, `sh -c`, `sh FILE`, applets.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct DepthGuard {
    depth: u32,
}

impl DepthGuard {
    #[cfg(test)]
    pub(super) fn at(depth: u32) -> Self {
        Self { depth }
    }

    pub(super) fn current(self) -> u32 {
        self.depth
    }

    /// Enter one level deeper unless `max` levels are already open.
    pub(super) fn try_enter(&mut self, max: u32) -> bool {
        if self.depth >= max {
            return false;
        }
        self.depth = self.depth.saturating_add(1);
        true
    }

    pub(super) fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

/// Open `bytes` for reading on `fd` in `plan`; on descriptor 0 the command reads it as its input.
fn install_input(plan: &mut RedirPlan, fd: u16, bytes: Vec<u8>) {
    if fd == 0 {
        plan.stdin = Some(Stdin::data(bytes.clone()));
        plan.reads_from = None;
    }
    plan.ins.insert(fd, OpenInput::new(bytes));
}

/// Whether a failing pipeline is something bash's `ERR` handler follows: more than one stage, a
/// simple command or a subshell.
fn err_unit(pipeline: &Pipeline) -> bool {
    pipeline.stages.len() > 1
        || matches!(
            pipeline.stages.first(),
            Some(Command::Simple(_) | Command::Subshell { .. })
        )
}

/// Whether a script's text holds the word `alias`: the only way it can define one.
fn mentions_alias(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word| word == "alias")
}

/// Work charged for one trip round a loop, on top of what the body costs, so a body that costs
/// nothing (`while :; do :; done`) still runs out of allowance quickly.
const LOOP_STEP_COST: u64 = 256;

/// Work charged for one call of a shell function, on top of what its body costs, so a function
/// that calls itself twice (a fork bomb's `:|:`) runs out of allowance, not time.
const FUNCTION_CALL_COST: u64 = 256;

/// Most functions running at once in one shell. A real shell has no such limit (dash stops at
/// 1000 and says so, bash segfaults); this is the stack and work guard of a shell that must never
/// follow an attacker's recursion to its end.
const FUNCTION_DEPTH_MAX: usize = 10;

/// Most functions one shell holds.
const FUNCTIONS_MAX: usize = 128;

/// One shell variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Var {
    pub value: String,
    pub exported: bool,
}

/// A function the shell holds.
#[derive(Debug, Clone)]
pub(super) struct ShellFunction {
    pub def: Arc<FunctionDef>,
    /// bash's `export -f`: a bash started from this shell has it too.
    pub exported: bool,
}

/// A function that is running.
#[derive(Debug, Clone)]
pub(super) struct Call {
    pub name: String,
    /// Defined with `function name`: mksh scopes `local` to those alone.
    pub keyword: bool,
    /// What `local` shadowed in this call, restored when it returns: each name with the variable
    /// it replaced, `None` if it was not set.
    pub locals: Vec<(String, Option<Var>)>,
}

/// What a `( )`, a pipeline stage, a `$( )` and a background job each get a copy of. The
/// filesystem is not in here: it is shared.
#[derive(Debug, Clone)]
pub(super) struct ShellState {
    pub cwd: String,
    pub oldpwd: Option<String>,
    pub vars: BTreeMap<String, Var>,
    pub umask: u16,
    pub positional: Vec<String>,
    /// `$0` when the level's own name is not it (`sh FILE`, `sh -c CMD NAME`).
    pub argv0: Option<String>,
    pub last_status: u8,
    pub last_bg_pid: Option<u32>,
    /// `$$`.
    pub pid: u32,
    /// Functions defined here. A subshell's copy of the state carries them and loses what it
    /// defines, as a forked shell does.
    pub functions: BTreeMap<String, ShellFunction>,
    /// The functions running, outermost first. A subshell started inside one is still inside it
    /// (`return` ends the subshell, `local` still scopes to the function).
    pub calls: Vec<Call>,
    /// The line of the script text the running command sits on, which a non-interactive bash
    /// names in its diagnostics (`bash: line 3: f: command not found`).
    pub line: u32,
    /// Where a script level's text came from, which a non-interactive bash words its syntax
    /// errors by.
    pub script: ScriptKind,
    /// The aliases defined here, in the order they were first defined. A shell started from this
    /// one has none; a subshell has a copy.
    pub aliases: Vec<Alias>,
    /// bash's `shopt` options changed from their defaults, and its `set -o` ones.
    pub shopt: BTreeMap<String, bool>,
    pub set_o: BTreeMap<String, bool>,
    /// The `trap` handlers this shell runs.
    pub traps: Traps,
    /// What a subshell lists as its handlers until it changes one: those of the shell it was made
    /// from. `None` in every other shell.
    pub trap_view: Option<Traps>,
    /// The `EXIT` handler is running: an `exit` in it ends it, not the shell a second time.
    pub exiting: bool,
    /// A `DEBUG` or `ERR` handler is running, and does not trigger itself.
    pub in_trap: bool,
    /// Commands being run whose status something tests (an `if` condition, all but the last of a
    /// `&&` list): `ERR` does not fire for a failure inside them.
    pub err_ignore: u32,
    /// The descriptors `exec` has opened, moved or closed.
    pub fds: Fds,
}

/// Where the text a non-interactive shell runs comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum ScriptKind {
    /// `-c TEXT`, and an SSH exec request.
    #[default]
    Command,
    /// A file named on the command line.
    File,
    /// Standard input.
    Stdin,
}

const DEFAULT_IFS: &str = " \t\n";

impl ShellState {
    /// The state a login shell starts with.
    pub(super) fn login(flavor: ShellFlavor, pid: u32, hostname: &str) -> Self {
        let mut state = Self {
            cwd: String::new(),
            oldpwd: None,
            vars: BTreeMap::new(),
            umask: 0o022,
            positional: Vec::new(),
            argv0: None,
            last_status: 0,
            last_bg_pid: None,
            pid,
            functions: BTreeMap::new(),
            calls: Vec::new(),
            line: 1,
            script: ScriptKind::Command,
            aliases: Vec::new(),
            shopt: BTreeMap::new(),
            set_o: BTreeMap::new(),
            traps: Traps::new(),
            trap_view: None,
            exiting: false,
            in_trap: false,
            err_ignore: 0,
            fds: Fds::default(),
        };
        state.set_var("IFS", DEFAULT_IFS.to_string(), false);
        match flavor {
            ShellFlavor::Bash => {
                state.set_cwd("/root".to_string());
                state.set_var("HOME", "/root".to_string(), true);
                state.set_var("USER", "root".to_string(), true);
                state.set_var("LOGNAME", "root".to_string(), true);
                state.set_var("SHELL", "/bin/bash".to_string(), true);
                // [unverified] the stock Ubuntu value, not captured from the reference host.
                state.set_var(
                    "PATH",
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
                        .to_string(),
                    true,
                );
                state.set_var("HOSTNAME", hostname.to_string(), false);
                state.set_var("UID", "0".to_string(), false);
                state.set_var("EUID", "0".to_string(), false);
            }
            ShellFlavor::AndroidSh => {
                state.set_cwd("/".to_string());
                state.set_var("SHELL", "/system/bin/sh".to_string(), true);
                // [unverified] Android 6's stock value, not captured from a device.
                state.set_var(
                    "PATH",
                    "/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin".to_string(),
                    true,
                );
            }
        }
        state
    }

    /// What a spawned shell inherits: exported variables and the working directory, and nothing
    /// else, as the environment of a child process.
    pub(super) fn child(&self, pid: u32) -> Self {
        let mut vars: BTreeMap<String, Var> = self
            .vars
            .iter()
            .filter(|(_, var)| var.exported)
            .map(|(name, var)| (name.clone(), var.clone()))
            .collect();
        vars.insert(
            "IFS".to_string(),
            Var {
                value: DEFAULT_IFS.to_string(),
                exported: false,
            },
        );
        Self {
            cwd: self.cwd.clone(),
            oldpwd: self.oldpwd.clone(),
            vars,
            umask: self.umask,
            positional: Vec::new(),
            argv0: None,
            last_status: 0,
            last_bg_pid: None,
            pid,
            functions: BTreeMap::new(),
            calls: Vec::new(),
            line: 1,
            script: ScriptKind::Command,
            aliases: Vec::new(),
            shopt: BTreeMap::new(),
            set_o: BTreeMap::new(),
            traps: Traps::new(),
            trap_view: None,
            exiting: false,
            in_trap: false,
            err_ignore: 0,
            // Open descriptors pass to a process started from this one.
            fds: self.fds.clone(),
        }
    }

    /// The state of a subshell made from this one: a copy, except that the handlers it would run
    /// are reset (the ignored signals stay ignored) while it still lists the parent's, as bash does
    /// until it sets one itself; dash lists none.
    pub(super) fn subshell_copy(&self, dash: bool) -> Self {
        let mut copy = self.clone();
        copy.trap_view = Some(if dash {
            Traps::new()
        } else {
            self.trap_view.clone().unwrap_or_else(|| self.traps.clone())
        });
        copy.traps.retain(|_, action| action.is_empty());
        copy
    }

    /// What the variables and functions hold, against the connection's content allowance.
    pub(super) fn owned_bytes(&self) -> usize {
        let vars = self
            .vars
            .iter()
            .map(|(name, var)| name.len().saturating_add(var.value.len()));
        let functions = self
            .functions
            .iter()
            .map(|(name, held)| name.len().saturating_add(held.def.source.len()));
        let aliases = self
            .aliases
            .iter()
            .map(|alias| alias.name.len().saturating_add(alias.value.len()));
        let traps = self.traps.values().map(String::len);
        vars.chain(functions)
            .chain(aliases)
            .chain(traps)
            .fold(0, usize::saturating_add)
    }

    pub(super) fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(|var| var.value.as_str())
    }

    /// Set a variable, keeping its export flag if it has one.
    pub(super) fn assign(&mut self, name: &str, value: String) {
        match self.vars.get_mut(name) {
            Some(var) => var.value = value,
            None => self.set_var(name, value, false),
        }
    }

    pub(super) fn set_var(&mut self, name: &str, value: String, exported: bool) {
        self.vars.insert(name.to_string(), Var { value, exported });
    }

    /// Move to `cwd`, keeping `PWD` and `OLDPWD` in step, as `cd` does.
    pub(super) fn set_cwd(&mut self, cwd: String) {
        let previous = std::mem::replace(&mut self.cwd, cwd.clone());
        if !previous.is_empty() {
            self.set_var("OLDPWD", previous.clone(), true);
            self.oldpwd = Some(previous);
        }
        self.set_var("PWD", cwd, true);
    }
}

/// Where a command's standard input comes from.
#[derive(Debug, Clone)]
pub(super) enum Stdin {
    /// The terminal as [`FakeShell::handle_input`] models it: nothing more to read without
    /// another input line, so a reader sees end of input at once.
    Terminal,
    /// A pipe, a here-document or a file: all of it is here.
    Data { bytes: Vec<u8>, pos: usize },
    /// The session's own input to a line that reads it (an SSH exec channel, or the terminal of
    /// a shell run through [`FakeShell::start_line`]), as much of it as has arrived.
    Session(SessionInput),
}

/// The session input a line reads: what has arrived, whether more can, and whether a reader asked
/// for more than had arrived. That last fact is the whole of the shell's decision that a line
/// waits for its input: a command that never reads standard input never sets it, whatever its
/// name, and one that does sets it by reading, through the same calls every reader makes.
#[derive(Debug, Clone)]
pub(super) struct SessionInput {
    bytes: Vec<u8>,
    pos: usize,
    /// Nothing more will arrive: a read past the end sees end of input, as it does on a pipe.
    eof: bool,
    /// The input is a terminal: a bare `sh` opens an interactive level on it rather than reading
    /// a script from it.
    tty: bool,
    /// A read wanted more than had arrived while more still could.
    blocked: bool,
}

impl Stdin {
    pub(super) fn data(bytes: Vec<u8>) -> Self {
        Self::Data { bytes, pos: 0 }
    }

    pub(super) fn session(bytes: Vec<u8>, eof: bool, tty: bool) -> Self {
        Self::Session(SessionInput {
            bytes,
            pos: 0,
            eof,
            tty,
            blocked: false,
        })
    }

    /// The unread bytes and the read position, or `None` for the terminal.
    fn unread(&mut self) -> Option<(&[u8], &mut usize)> {
        match self {
            Self::Terminal => None,
            Self::Data { bytes, pos } => Some((bytes.get(*pos..).unwrap_or(&[]), pos)),
            Self::Session(input) => {
                Some((input.bytes.get(input.pos..).unwrap_or(&[]), &mut input.pos))
            }
        }
    }

    /// Note that a reader asked for more than has arrived, when more still can.
    fn want_more(&mut self) {
        if let Self::Session(input) = self
            && !input.eof
        {
            input.blocked = true;
        }
    }

    /// Whether a reader of this session input has asked for more than had arrived.
    pub(super) fn is_blocked(&self) -> bool {
        matches!(self, Self::Session(input) if input.blocked)
    }

    /// How far into the session input the readers have got, `None` for any other input.
    pub(super) fn session_pos(&self) -> Option<usize> {
        match self {
            Self::Session(input) => Some(input.pos),
            _ => None,
        }
    }

    /// The next line without its newline, and whether a newline ended it. `None` at end of input.
    pub(super) fn read_line(&mut self) -> Option<(Vec<u8>, bool)> {
        let (rest, pos) = self.unread()?;
        let (line, ended) = match rest.iter().position(|&b| b == b'\n') {
            Some(end) => (rest.get(..end).unwrap_or(&[]).to_vec(), true),
            None => (rest.to_vec(), false),
        };
        *pos = pos
            .saturating_add(line.len())
            .saturating_add(usize::from(ended));
        if !ended {
            self.want_more();
        }
        (ended || !line.is_empty()).then_some((line, ended))
    }

    /// Up to `n` bytes not yet read, so a reader that stops early leaves the rest for the next.
    pub(super) fn take(&mut self, n: u64) -> Vec<u8> {
        let Some((rest, pos)) = self.unread() else {
            return Vec::new();
        };
        let asked = usize::try_from(n).unwrap_or(usize::MAX);
        let want = asked.min(rest.len());
        let taken = rest.get(..want).unwrap_or(&[]).to_vec();
        *pos = pos.saturating_add(want);
        if want < asked {
            self.want_more();
        }
        taken
    }

    /// Everything not yet read.
    pub(super) fn take_rest(&mut self) -> Vec<u8> {
        let Some((rest, pos)) = self.unread() else {
            return Vec::new();
        };
        let taken = rest.to_vec();
        *pos = pos.saturating_add(taken.len());
        self.want_more();
        taken
    }

    /// A script piped to a bare `sh`: everything not yet read, or `None` when the input is a
    /// terminal, which a bare `sh` reads as an interactive shell instead.
    pub(super) fn take_script(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Terminal => None,
            Self::Session(input) if input.tty => None,
            Self::Data { .. } | Self::Session(_) => Some(self.take_rest()),
        }
    }
}

/// The per-session process id allocator: `$$` is the shell's own, and each background job or
/// spawned shell takes the next. Seeded from the session, so a replay with the same session gets
/// the same numbers.
#[derive(Debug, Clone)]
pub(super) struct PidAlloc {
    next: u32,
}

impl PidAlloc {
    pub(super) fn new(shell_pid: u32) -> Self {
        Self {
            next: shell_pid.saturating_add(1),
        }
    }

    pub(super) fn next(&mut self) -> u32 {
        let pid = self.next;
        self.next = self.next.saturating_add(1);
        pid
    }

    /// The id the next process would take: every id below it, past the shell's own, was handed
    /// out to something this session started.
    pub(super) fn peek(&self) -> u32 {
        self.next
    }
}

/// Where one of a command's descriptors goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Sink {
    /// The terminal, as its standard output or its standard error: a descriptor duplicated from
    /// standard error keeps writing to the error stream.
    Terminal(OutputFd),
    Discard,
    File {
        path: String,
        append: bool,
    },
    /// Not open: a write to it fails (`Bad file descriptor`).
    Closed,
}

/// Descriptors a shell can hold open: 0 to 63, which is room for every one a script opens.
pub(super) const FD_MAX: usize = 64;

/// A file open for reading on a descriptor, read from where the last read stopped.
#[derive(Debug, Clone)]
pub(super) struct OpenInput {
    bytes: Arc<Vec<u8>>,
    pos: usize,
}

impl OpenInput {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(bytes),
            pos: 0,
        }
    }

    /// What has not been read.
    pub(super) fn remaining(&self) -> Vec<u8> {
        self.bytes.get(self.pos..).unwrap_or(&[]).to_vec()
    }

    pub(super) fn advance(&mut self, by: usize) {
        self.pos = self.pos.saturating_add(by).min(self.bytes.len());
    }
}

/// The descriptors a shell holds beyond the terminal's, which `exec` opens, moves and closes and
/// which every command and every shell it starts inherits.
#[derive(Debug, Clone)]
pub(super) struct Fds {
    /// Where each descriptor writes. Index 0 is unused (standard input has no sink), 1 is standard
    /// output and 2 standard error; the rest are closed until something opens them.
    pub out: Vec<Sink>,
    /// The descriptors open for reading, standard input included once `exec` redirects it.
    pub ins: BTreeMap<u16, OpenInput>,
}

impl Default for Fds {
    fn default() -> Self {
        Self {
            out: (0..FD_MAX)
                .map(|fd| match fd {
                    0 | 1 => Sink::Terminal(OutputFd::Stdout),
                    2 => Sink::Terminal(OutputFd::Stderr),
                    _ => Sink::Closed,
                })
                .collect(),
            ins: BTreeMap::new(),
        }
    }
}

impl Fds {
    /// Whether anything differs from a fresh shell's descriptors.
    pub(super) fn is_default(&self) -> bool {
        self.ins.is_empty() && self.out == Self::default().out
    }

    /// Whether error output still reaches the terminal, which is where an interactive bash writes
    /// its prompt.
    pub(super) fn stderr_is_terminal(&self) -> bool {
        matches!(self.out.get(2), Some(Sink::Terminal(_)))
    }
}

/// The descriptors a command's redirections describe, opened before it runs.
struct RedirPlan {
    /// Where each descriptor writes now: the shell's own, changed by the redirections.
    sinks: Vec<Sink>,
    /// The descriptors open for reading, standard input included.
    ins: BTreeMap<u16, OpenInput>,
    /// Standard input as a redirection of this command set it; `None` leaves the shell's.
    stdin: Option<Stdin>,
    /// The descriptor standard input is read from, so what the command read moves its position.
    reads_from: Option<u16>,
    active: bool,
}

impl RedirPlan {
    /// Where descriptor `fd` goes now.
    fn sink(&self, fd: usize) -> Sink {
        self.sinks.get(fd).cloned().unwrap_or(Sink::Closed)
    }

    /// The plan of a command that has no redirection of its own: the shell's descriptors.
    fn from_fds(fds: &Fds) -> Self {
        let stdin = fds.ins.get(&0).map(|input| Stdin::data(input.remaining()));
        Self {
            sinks: fds.out.clone(),
            ins: fds.ins.clone(),
            reads_from: stdin.as_ref().map(|_| 0),
            stdin,
            active: !fds.is_default(),
        }
    }
}

impl FakeShell {
    // ---- input ---------------------------------------------------------------------------------

    /// Feed one physical input line. It joins any lines still pending from an incomplete
    /// construct; when the text is then complete it is parsed and run, and when it is not, the
    /// shell waits for the next line (the PS2 prompt) and prints nothing.
    pub(super) fn feed_line(&mut self, line: &str) -> CommandResult {
        let max_pending_lines = 64;
        let max_pending_bytes = 65_536;
        self.pending.push(line.to_string());
        self.pending_bytes = self
            .pending_bytes
            .saturating_add(line.len())
            .saturating_add(1);
        let text = self.pending.join("\n");
        let lines = u64::try_from(self.pending.len()).unwrap_or(u64::MAX);
        let base = self.dash_counter().map_or(1, |(_, counter)| {
            counter.saturating_sub(lines.saturating_sub(1)).max(1)
        });
        let base_line = u32::try_from(base).unwrap_or(u32::MAX);
        let max_depth = self.budget().limits().max_depth;
        let dialect = self.grammar();
        let none: &[Alias] = &[];
        let aliases = if self.aliases_expand() {
            self.frames
                .last()
                .map_or(none, |f| f.state.aliases.as_slice())
        } else {
            none
        };
        let parsed = super::parse::parse_unit(
            &text,
            false,
            max_depth,
            dialect,
            &mut self.line,
            base_line,
            aliases,
        );
        self.sync_budget_trace();
        if parsed.tail == Tail::NeedMore {
            if self.pending.len() > max_pending_lines || self.pending_bytes > max_pending_bytes {
                // [unverified] what bash does past its own limits; a bounded discard is all
                // this shell needs.
                self.pending.clear();
                self.pending_bytes = 0;
                return CommandResult::silent(1);
            }
            return CommandResult::silent(self.state().last_status);
        }
        self.pending.clear();
        self.pending_bytes = 0;
        self.note_unit(&text);
        self.execute_unit(parsed, base_line, None)
    }

    /// Run the items that parsed, then say what was wrong with the rest. Only items that ended on
    /// a line before the error run, as a shell that reads and runs one command at a time would.
    /// `text` is the script the items came from, when it is one: a non-interactive bash quotes the
    /// line a syntax error is on.
    pub(super) fn execute_unit(
        &mut self,
        parsed: Parsed,
        base_line: u32,
        text: Option<&str>,
    ) -> CommandResult {
        let Parsed { mut items, tail } = parsed;
        if let Tail::Error(error) = &tail {
            items.retain(|item| item.end_line < error.line);
        }
        let counter = self.dash_counter();
        let mut result = self.eval_list(&List { items });
        match tail {
            Tail::Done | Tail::NeedMore => {}
            Tail::Error(error) => {
                if !result.stop_line {
                    let line = base_line.saturating_add(error.line).saturating_sub(1);
                    self.set_dash_line(line);
                    let error = super::ast::SyntaxError { line, ..error };
                    let message = self.syntax_error_text(&error, text);
                    result.append(CommandResult::stderr(2, message));
                    self.state_mut().last_status = 2;
                }
            }
            Tail::TooDeep => {
                self.record_hit(BudgetHit::Depth);
                self.note_depth();
                result.append(CommandResult::silent(1));
            }
            Tail::Budget => {
                result.stop_line = true;
                result.append(CommandResult::silent(1));
                result.stop_line = true;
            }
        }
        if let Some((frames, line)) = counter
            && self.frames.len() == frames
        {
            self.restore_dash_counter(line);
        }
        result
    }

    /// What the active level says about text it cannot parse.
    fn syntax_error_text(&self, error: &super::ast::SyntaxError, text: Option<&str>) -> String {
        let near = &error.near;
        match self.active_level() {
            ShellLevel::Bash { .. } if self.bash_is_scripted() && text.is_some() => {
                self.scripted_bash_syntax_error(error, text.unwrap_or(""))
            }
            ShellLevel::Bash { .. } => match near {
                Near::Token(token) | Near::Word(token) => {
                    self.shell_error(format_args!("syntax error near unexpected token `{token}'"))
                }
                Near::Newline => self.shell_error("syntax error near unexpected token `newline'"),
                Near::EndOfFile | Near::Message(_) | Near::Unmatched(_) => {
                    self.shell_error("syntax error: unexpected end of file")
                }
                // Only dash refuses a name at parse time.
                Near::BadFunctionName => self.shell_error("syntax error: bad function name"),
            },
            ShellLevel::Dash { .. } => {
                // dash's `synexpect`: what was unexpected, and, where the grammar was waiting for
                // one particular token, what that was.
                let hint = error
                    .expecting
                    .map_or_else(String::new, |token| format!(" (expecting {token})"));
                match near {
                    // Dash names every redirection operator alike.
                    Near::Token(token)
                        if matches!(
                            token.as_str(),
                            "<" | ">" | ">>" | "<<" | "<<<" | "<&" | ">&" | "<>" | ">|"
                        ) =>
                    {
                        self.shell_error(format_args!("Syntax error: redirection unexpected{hint}"))
                    }
                    Near::Token(token) => {
                        self.shell_error(format_args!("Syntax error: \"{token}\" unexpected{hint}"))
                    }
                    Near::Word(_) => {
                        self.shell_error(format_args!("Syntax error: word unexpected{hint}"))
                    }
                    Near::Newline => {
                        self.shell_error(format_args!("Syntax error: newline unexpected{hint}"))
                    }
                    Near::EndOfFile | Near::Unmatched(_) => {
                        self.shell_error(format_args!("Syntax error: end of file unexpected{hint}"))
                    }
                    Near::Message(message) => {
                        self.shell_error(format_args!("Syntax error: {message}"))
                    }
                    Near::BadFunctionName => self.shell_error("Syntax error: Bad function name"),
                }
            }
            // [unverified] mksh's wording; no Android capture exists.
            ShellLevel::AndroidMksh => match near {
                Near::Token(token) | Near::Word(token) => {
                    self.shell_error(format_args!("syntax error: '{token}' unexpected"))
                }
                Near::Newline => self.shell_error("syntax error: newline unexpected"),
                Near::EndOfFile | Near::Message(_) | Near::Unmatched(_) => {
                    self.shell_error("syntax error: unexpected EOF")
                }
                Near::BadFunctionName => self.shell_error("syntax error: bad function name"),
            },
        }
    }

    /// bash's syntax error in a script, as Ubuntu 22.04's bash 5.1.16 words it: where the text came
    /// from (`bash: -c: line 2:` for `-c` text, `FILE: line 2:` for a file, `bash: line 2:` for
    /// standard input), and for a bad token the line it is on, quoted. An unfinished construct is
    /// reported on the line after the last one.
    fn scripted_bash_syntax_error(&self, error: &super::ast::SyntaxError, text: &str) -> String {
        let state = self.state();
        let name = state.argv0.as_deref().unwrap_or("bash");
        let at = |line: usize| match state.script {
            ScriptKind::Command => format!("{name}: -c: line {line}"),
            ScriptKind::File => format!("{name}: line {line}"),
            ScriptKind::Stdin => format!("{name}: line {line}"),
        };
        let token = match &error.near {
            Near::Token(token) | Near::Word(token) => token.as_str(),
            Near::Newline => "newline",
            Near::EndOfFile | Near::Message(_) | Near::Unmatched(_) => {
                let newlines = text.matches('\n').count();
                let lines = if text.ends_with('\n') {
                    newlines
                } else {
                    newlines.saturating_add(1)
                };
                // Running out inside a quote or a substitution is first said where, on the
                // last line, and then as the end of the file one line further.
                let matching = match error.near {
                    Near::Unmatched(closer) => format!(
                        "{}: unexpected EOF while looking for matching `{closer}'\n",
                        at(lines)
                    ),
                    _ => String::new(),
                };
                return format!(
                    "{matching}{}: syntax error: unexpected end of file\n",
                    at(lines.saturating_add(1))
                );
            }
            Near::BadFunctionName => {
                return self.shell_error("syntax error: bad function name");
            }
        };
        let line = usize::try_from(error.line).unwrap_or(usize::MAX);
        let source = text.split('\n').nth(line.saturating_sub(1)).unwrap_or("");
        format!(
            "{at}: syntax error near unexpected token `{token}'\n{at}: `{source}'\n",
            at = at(line)
        )
    }

    /// Run `text` as a script in the shell level just pushed by the caller: a nested `sh -c`, a
    /// script file, or a script piped to `sh`. The text is complete, so an unterminated construct
    /// is a syntax error and the first error stops the script, as it does a non-interactive
    /// shell.
    pub(super) fn run_script(&mut self, text: &str) -> CommandResult {
        self.script_depth = self.script_depth.saturating_add(1);
        let mut result = self.run_script_text(text);
        self.script_depth = self.script_depth.saturating_sub(1);
        result.flow = Flow::None;
        result
    }

    /// Parse and run complete text in the current shell level.
    pub(super) fn run_script_text(&mut self, text: &str) -> CommandResult {
        // A script that defines an alias is read a command at a time, since the alias is in force
        // from the next line; any other is parsed whole.
        if (self.aliases_expand() || (self.is_bash() && text.contains("expand_aliases")))
            && mentions_alias(text)
        {
            return self.run_script_lines(text);
        }
        let max_depth = self.budget().limits().max_depth;
        let dialect = self.grammar();
        let parsed =
            super::parse::parse_unit(text, true, max_depth, dialect, &mut self.line, 1, &[]);
        self.sync_budget_trace();
        self.execute_unit(parsed, 1, Some(text))
    }

    /// Run `text` as a shell reads a script that may define aliases: each physical line joins the
    /// lines of an unfinished construct and runs as soon as the text is complete, with the aliases
    /// defined so far in force. The end of the text finishes whatever is left.
    fn run_script_lines(&mut self, text: &str) -> CommandResult {
        let max_depth = self.budget().limits().max_depth;
        let dialect = self.grammar();
        let mut acc = CommandResult::silent(0);
        let mut pending: Vec<&str> = Vec::new();
        let mut first_line: u32 = 1;
        let body = text.strip_suffix('\n').unwrap_or(text);
        let total = body.split('\n').count();
        for (index, line) in body.split('\n').enumerate() {
            pending.push(line);
            let unit = pending.join("\n");
            let last = index.saturating_add(1) == total;
            let none: &[Alias] = &[];
            let aliases = if self.aliases_expand() {
                self.frames
                    .last()
                    .map_or(none, |f| f.state.aliases.as_slice())
            } else {
                none
            };
            let parsed = super::parse::parse_unit(
                &unit,
                last,
                max_depth,
                dialect,
                &mut self.line,
                first_line,
                aliases,
            );
            self.sync_budget_trace();
            if parsed.tail == Tail::NeedMore {
                continue;
            }
            // The first text the shell cannot read ends the script.
            let refused = !matches!(parsed.tail, Tail::Done);
            let ran = self.execute_unit(parsed, first_line, Some(text));
            pending.clear();
            first_line = u32::try_from(index.saturating_add(2)).unwrap_or(u32::MAX);
            acc.append(ran);
            if refused || acc.stop_line || acc.flow != Flow::None {
                break;
            }
        }
        acc
    }

    // ---- lists ---------------------------------------------------------------------------------

    pub(super) fn eval_list(&mut self, list: &List) -> CommandResult {
        let mut acc = CommandResult::silent(0);
        for item in &list.items {
            if !self.charge_work(1) {
                acc.stop_line = true;
                acc.status = 1;
                break;
            }
            let result = if item.background {
                self.eval_background(item)
            } else {
                self.eval_and_or(&item.and_or)
            };
            acc.append(result);
            if acc.stop_line || acc.flow != Flow::None {
                break;
            }
        }
        acc
    }

    fn eval_and_or(&mut self, chain: &AndOr) -> CommandResult {
        let record = self.trace_stack.is_empty();
        let mut acc =
            self.eval_element(&chain.first, ControlOp::Seq, record, chain.rest.is_empty());
        for (index, (op, pipeline)) in chain.rest.iter().enumerate() {
            if acc.stop_line || acc.flow != Flow::None {
                break;
            }
            let (control, run) = match op {
                AndOrOp::And => (ControlOp::And, acc.status == 0),
                AndOrOp::Or => (ControlOp::Or, acc.status != 0),
            };
            if run {
                let last = index.saturating_add(1) == chain.rest.len();
                let next = self.eval_element(pipeline, control, record, last);
                acc.append(next);
            } else if record {
                self.trace.segments.push(SegmentTrace {
                    op: control,
                    decision: if control == ControlOp::And {
                        RunDecision::SkippedByAnd
                    } else {
                        RunDecision::SkippedByOr
                    },
                    command: None,
                });
            }
        }
        acc
    }

    /// One pipeline of an and-or chain. bash's `ERR` handler runs after the last one of the chain
    /// fails when it is a simple command, a pipeline or a subshell (a brace group, an `if` or a
    /// loop leaves it to the commands inside), and not for one that is negated or whose status
    /// something tests, which is every earlier one of the chain.
    fn eval_element(
        &mut self,
        pipeline: &Pipeline,
        op: ControlOp,
        record: bool,
        last: bool,
    ) -> CommandResult {
        if !last {
            self.state_mut().err_ignore = self.state().err_ignore.saturating_add(1);
        }
        let mut result = self.eval_segment(pipeline, op, record);
        if !last {
            self.state_mut().err_ignore = self.state().err_ignore.saturating_sub(1);
        } else if result.status != 0
            && !result.stop_line
            && result.flow == Flow::None
            && !pipeline.bang
            && err_unit(pipeline)
            && let Some(handler) = self.err_after(result.status)
        {
            result.append(handler);
        }
        result
    }

    fn eval_segment(&mut self, pipeline: &Pipeline, op: ControlOp, record: bool) -> CommandResult {
        if record {
            self.trace.segments.push(SegmentTrace {
                op,
                decision: RunDecision::Ran,
                command: None,
            });
        }
        let result = self.eval_pipeline(pipeline);
        self.state_mut().last_status = result.status;
        result
    }

    /// `cmd &`: runs at once in a copy of the shell, since no task is ever created. It reports
    /// the job to an interactive login shell and sets `$!`.
    fn eval_background(&mut self, item: &ListItem) -> CommandResult {
        let pid = self.pids.next();
        self.state_mut().last_bg_pid = Some(pid);
        let mut acc = CommandResult::silent(0);
        if self.reports_jobs() {
            self.next_job = self.next_job.saturating_add(1);
            acc.append(CommandResult::stderr(
                0,
                format!("[{}] {pid}\n", self.next_job),
            ));
        }
        let copy = self.subshell_state();
        self.frames.push(Frame {
            kind: FrameKind::Subshell,
            state: copy,
        });
        let saved = std::mem::replace(&mut self.stdin, Stdin::data(Vec::new()));
        self.script_depth = self.script_depth.saturating_add(1);
        let mut ran = self.eval_and_or(&item.and_or);
        self.script_depth = self.script_depth.saturating_sub(1);
        self.stdin = saved;
        self.append_exit_trap(&mut ran);
        self.frames.pop();
        let stopped = ran.stop_line;
        acc.append(ran);
        acc.status = 0;
        acc.flow = Flow::None;
        acc.stop_line = stopped;
        self.state_mut().last_status = 0;
        acc
    }

    /// Job control notices belong to an interactive shell reading the terminal.
    fn reports_jobs(&self) -> bool {
        self.context == super::ShellContext::LoginInteractive
            && self.script_depth == 0
            && !self.frames.iter().any(|f| f.kind == FrameKind::Subshell)
    }

    fn eval_pipeline(&mut self, pipeline: &Pipeline) -> CommandResult {
        let Some(posix) = pipeline.timed else {
            return self.eval_untimed(pipeline);
        };
        match self.active_level() {
            // dash has no `time` keyword and Ubuntu ships no /usr/bin/time, so the word is a
            // command it cannot find.
            ShellLevel::Dash { .. } => CommandResult::stderr(127, self.not_found("time")),
            level => {
                let before = self.timing;
                let mut result = self.eval_untimed(pipeline);
                let spent = self.timing.since(&before);
                let report = if level == ShellLevel::AndroidMksh {
                    super::timing::mksh_report(&spent)
                } else {
                    super::timing::bash_report(&spent, posix)
                };
                let (status, flow) = (result.status, result.flow);
                result.append(CommandResult::stderr(status, report));
                result.flow = flow;
                result
            }
        }
    }

    fn eval_untimed(&mut self, pipeline: &Pipeline) -> CommandResult {
        if pipeline.stages.is_empty() {
            return CommandResult::silent(0);
        }
        if let ([stage], false) = (pipeline.stages.as_slice(), pipeline.bang) {
            return self.eval_command(stage);
        }
        self.trace_open(&[], ParseNode::Pipeline, HandlerId::Compound);
        let mut acc = CommandResult::silent(0);
        let mut carried: Option<Vec<u8>> = None;
        let mut carried_typed = false;
        let count = pipeline.stages.len();
        for (index, stage) in pipeline.stages.iter().enumerate() {
            let last = index.saturating_add(1) == count;
            // bash runs a simple command's `DEBUG` handler before it forks the stage, so what it
            // prints goes to the terminal and not into the pipe.
            if matches!(stage, Command::Simple(_))
                && let Some(handler) = self.debug_before()
            {
                acc.append(handler);
            }
            let copy = self.subshell_state();
            self.frames.push(Frame {
                kind: FrameKind::Subshell,
                state: copy,
            });
            let stdin = carried.take().map(Stdin::data);
            let saved = stdin.map(|s| std::mem::replace(&mut self.stdin, s));
            self.script_depth = self.script_depth.saturating_add(1);
            // Whether this stage's input is typed output of the one before it, and whether its own
            // output is, are what let `echo B64 | base64 -d > f` be seen as an assembly.
            let outer_typed = std::mem::take(&mut self.typed_output);
            self.piped_typed = std::mem::take(&mut carried_typed);
            let mut ran = self.eval_command(stage);
            self.piped_typed = false;
            carried_typed = std::mem::replace(&mut self.typed_output, outer_typed);
            self.typed_output |= carried_typed;
            self.script_depth = self.script_depth.saturating_sub(1);
            if let Some(previous) = saved {
                self.stdin = previous;
            }
            self.append_exit_trap(&mut ran);
            self.frames.pop();
            ran.flow = Flow::None;
            let stopped = ran.stop_line;
            if last {
                acc.append(ran);
            } else {
                let out = ran.take_stdout();
                carried = Some(out);
                acc.append(ran);
            }
            if stopped {
                break;
            }
        }
        if pipeline.bang {
            acc.status = u8::from(acc.status == 0);
        }
        self.trace_close(acc.status);
        acc
    }

    fn eval_command(&mut self, command: &Command) -> CommandResult {
        match command {
            Command::Simple(simple) => self.eval_simple(simple),
            Command::Function(def) => self.eval_function_def(def),
            Command::Unsupported(kind) => {
                self.trace_open(&[], ParseNode::Unsupported, HandlerId::Compound);
                self.trace_unsupported(*kind);
                // dash's expansion error ends the shell (or the script, subshell or stage).
                let refused = *kind == super::UnsupportedKind::BadSubstitution && self.is_dash();
                let result = if refused {
                    self.dash_bad_substitution()
                } else {
                    CommandResult::silent(0)
                };
                self.trace_close(result.status);
                result
            }
            compound => self.eval_compound(compound),
        }
    }

    // ---- compound commands ---------------------------------------------------------------------

    fn eval_compound(&mut self, command: &Command) -> CommandResult {
        let (node, redirs): (ParseNode, &[Redir]) = match command {
            Command::Subshell { redirs, .. } => (ParseNode::Subshell, redirs),
            Command::Brace { redirs, .. } => (ParseNode::Brace, redirs),
            Command::If { redirs, .. } => (ParseNode::If, redirs),
            Command::For { redirs, .. } => (ParseNode::For, redirs),
            Command::While { redirs, .. } => (ParseNode::While, redirs),
            Command::Case { redirs, .. } => (ParseNode::Case, redirs),
            Command::Simple(_) | Command::Function(_) | Command::Unsupported(_) => {
                return CommandResult::silent(0);
            }
        };
        let max_depth = self.budget().limits().max_depth;
        if !self.depth.try_enter(max_depth) {
            self.record_hit(BudgetHit::Depth);
            self.note_depth();
            return CommandResult::silent(1);
        }
        self.note_depth();
        self.trace_open(&[], node, HandlerId::Compound);
        let result = self.compound_inner(command, redirs);
        self.trace_close(result.status);
        self.depth.leave();
        result
    }

    fn compound_inner(&mut self, command: &Command, redirs: &[Redir]) -> CommandResult {
        let mut plan = match self.open_redirs(redirs) {
            Ok(plan) => plan,
            Err(refused) => return refused,
        };
        let saved = plan
            .stdin
            .take()
            .map(|stdin| std::mem::replace(&mut self.stdin, stdin));
        let outer_mark = std::mem::replace(&mut self.input_mark, self.stdin.session_pos());
        let outer_typed = std::mem::take(&mut self.typed_output);
        let result = match command {
            Command::Subshell { body, .. } => self.eval_subshell(body),
            Command::Brace { body, .. } => self.eval_list(body),
            Command::If {
                cond,
                then,
                elifs,
                els,
                ..
            } => self.eval_if(cond, then, elifs, els.as_ref()),
            Command::For {
                var, words, body, ..
            } => self.eval_for(var, words.as_deref(), body),
            Command::While {
                cond, body, until, ..
            } => self.eval_while(cond, body, *until),
            Command::Case { word, arms, .. } => self.eval_case(word, arms),
            Command::Simple(_) | Command::Function(_) | Command::Unsupported(_) => {
                CommandResult::silent(0)
            }
        };
        self.settle_input(plan.reads_from);
        if let Some(previous) = saved {
            self.stdin = previous;
        }
        let typed = std::mem::replace(&mut self.typed_output, outer_typed);
        let routed = self.route(result, &plan, "sh", typed);
        self.input_mark = outer_mark;
        self.pass_typed_output(typed, &plan);
        routed
    }

    /// The state a `( )`, a pipeline stage, a `$( )` and a background job start from.
    pub(super) fn subshell_state(&self) -> ShellState {
        self.state().subshell_copy(self.is_dash())
    }

    fn eval_subshell(&mut self, body: &List) -> CommandResult {
        let copy = self.subshell_state();
        self.frames.push(Frame {
            kind: FrameKind::Subshell,
            state: copy,
        });
        self.script_depth = self.script_depth.saturating_add(1);
        let mut result = self.eval_list(body);
        self.script_depth = self.script_depth.saturating_sub(1);
        self.append_exit_trap(&mut result);
        self.frames.pop();
        // `exit`, `break` and `continue` end at the subshell's edge.
        result.flow = Flow::None;
        result
    }

    /// A condition: the status of what it runs is tested, so `ERR` does not follow a failure in it.
    fn eval_tested(&mut self, list: &List) -> CommandResult {
        self.state_mut().err_ignore = self.state().err_ignore.saturating_add(1);
        let result = self.eval_list(list);
        self.state_mut().err_ignore = self.state().err_ignore.saturating_sub(1);
        result
    }

    fn eval_if(
        &mut self,
        cond: &List,
        then: &List,
        elifs: &[(List, List)],
        els: Option<&List>,
    ) -> CommandResult {
        let mut acc = self.eval_tested(cond);
        if acc.stop_line || acc.flow != Flow::None {
            return acc;
        }
        if acc.status == 0 {
            let body = self.eval_list(then);
            acc.append(body);
            return acc;
        }
        for (test, body) in elifs {
            let tested = self.eval_tested(test);
            acc.append(tested);
            if acc.stop_line || acc.flow != Flow::None {
                return acc;
            }
            if acc.status == 0 {
                let ran = self.eval_list(body);
                acc.append(ran);
                return acc;
            }
        }
        match els {
            Some(body) => {
                let ran = self.eval_list(body);
                acc.append(ran);
            }
            None => acc.status = 0,
        }
        acc
    }

    /// `case WORD in ... esac`: the first arm with a matching pattern runs; no match is status 0.
    fn eval_case(&mut self, word: &Word, arms: &[CaseArm]) -> CommandResult {
        let Some(mut handler) = self.debug_before() else {
            return self.eval_case_arms(word, arms);
        };
        let ran = self.eval_case_arms(word, arms);
        handler.append(ran);
        handler
    }

    fn eval_case_arms(&mut self, word: &Word, arms: &[CaseArm]) -> CommandResult {
        let subject = match self.expand_scalar(word) {
            Ok(subject) => subject,
            Err(error) => return self.expand_failure(error),
        };
        for arm in arms {
            for pattern in &arm.patterns {
                match self.case_pattern_matches(pattern, &subject) {
                    Ok(true) => return self.eval_list(&arm.body),
                    Ok(false) => {}
                    Err(error) => return self.expand_failure(error),
                }
            }
        }
        CommandResult::silent(0)
    }

    fn eval_for(&mut self, var: &str, words: Option<&[Word]>, body: &List) -> CommandResult {
        let items = match words {
            Some(words) => match self.expand_argv(words) {
                Ok(items) => items,
                Err(error) => return self.expand_failure(error),
            },
            None => self.state().positional.clone(),
        };
        let mut acc = CommandResult::silent(0);
        self.loop_depth = self.loop_depth.saturating_add(1);
        for item in items {
            if !self.charge_work(LOOP_STEP_COST) {
                acc.stop_line = true;
                acc.status = 1;
                break;
            }
            if let Some(handler) = self.debug_before() {
                acc.append(handler);
            }
            self.assign_var(var, item);
            let ran = self.eval_list(body);
            acc.append(ran);
            if !loop_continues(&mut acc) {
                break;
            }
        }
        self.loop_depth = self.loop_depth.saturating_sub(1);
        acc
    }

    fn eval_while(&mut self, cond: &List, body: &List, until: bool) -> CommandResult {
        let mut acc = CommandResult::silent(0);
        let mut body_status = 0;
        self.loop_depth = self.loop_depth.saturating_add(1);
        loop {
            if !self.charge_work(LOOP_STEP_COST) {
                acc.stop_line = true;
                body_status = 1;
                break;
            }
            let tested = self.eval_tested(cond);
            acc.append(tested);
            if !loop_continues(&mut acc) {
                body_status = acc.status;
                break;
            }
            let holds = (acc.status == 0) != until;
            if !holds {
                break;
            }
            let ran = self.eval_list(body);
            acc.append(ran);
            body_status = acc.status;
            if !loop_continues(&mut acc) {
                break;
            }
        }
        self.loop_depth = self.loop_depth.saturating_sub(1);
        acc.status = body_status;
        acc
    }

    // ---- simple commands -----------------------------------------------------------------------

    fn eval_simple(&mut self, simple: &SimpleCommand) -> CommandResult {
        self.trace_open(&[], ParseNode::Simple, HandlerId::Empty);
        let outer_stderr = std::mem::take(&mut self.deferred_stderr);
        let outer_subst = self.last_subst_status.take();
        self.set_dash_line(simple.line);
        self.state_mut().line = simple.line;
        // bash's `DEBUG` handler runs first, and what it prints comes first.
        let debug = self.debug_before();
        let ran = self.simple_inner(simple);
        let produced = std::mem::replace(&mut self.deferred_stderr, outer_stderr);
        self.last_subst_status = outer_subst;
        // What the expansions wrote to standard error came before the command itself.
        let mut result = CommandResult::silent(ran.status);
        if let Some(handler) = debug {
            result.append(handler);
        }
        for segment in produced {
            result.append(CommandResult::one(segment.fd, 0, segment.bytes));
        }
        result.append(ran);
        self.trace_close(result.status);
        result
    }

    fn simple_inner(&mut self, simple: &SimpleCommand) -> CommandResult {
        let (argv, unset) = match self.expand_argv_flagged(&simple.words) {
            Ok(expanded) => expanded,
            Err(error) => return self.expand_failure(error),
        };
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        // A function answers a bare command name before any builtin or file does. Only the
        // shell's own lookup sees them: `command f`, `env f` and the other commands that start
        // one are handed to `dispatch`, which does not.
        let function = refs
            .first()
            .filter(|name| !name.contains('/'))
            .and_then(|name| self.state().functions.get(*name))
            .map(|held| Arc::clone(&held.def));
        if refs.is_empty() {
            self.trace_set(
                &argv,
                ParseNode::RedirectionOnly,
                HandlerId::RedirectionOnly,
            );
        } else if function.is_some() {
            self.trace_set(&argv, ParseNode::Simple, HandlerId::ShellFunction);
        } else {
            let resolved = self.resolve_handler(&refs);
            self.trace_set(&argv, ParseNode::Simple, resolved);
        }
        // `exec` with no command changes the shell's own descriptors.
        let exec_only = function.is_none()
            && refs.first() == Some(&"exec")
            && !self.state().functions.contains_key("exec")
            && !self.exec_has_command(&refs);
        let mut plan = match self.open_redirs(&simple.redirs) {
            Ok(plan) => plan,
            Err(mut refused) => {
                // dash ends the shell when a redirection of its special builtin fails.
                if exec_only && self.is_dash() {
                    self.end_process(&mut refused);
                }
                return refused;
            }
        };
        if exec_only {
            if let Err(usage) = self.exec_args_check(&refs) {
                return usage;
            }
            return self.exec_redirections(plan);
        }
        let mut assigns: Vec<(String, String)> = Vec::new();
        for assign in &simple.assigns {
            match self.expand_scalar(&assign.value) {
                Ok(value) => assigns.push((assign.name.clone(), value)),
                Err(error) => return self.expand_failure(error),
            }
        }
        if refs.is_empty() {
            // Assignments with no command set the shell's own variables.
            let mut refused = false;
            for (name, value) in assigns {
                refused |= !self.assign_var(&name, value);
            }
            if refused {
                return CommandResult::silent(1);
            }
            return CommandResult::silent(self.last_subst_status.unwrap_or(0));
        }
        // With a command, they are that command's environment alone.
        let saved: Vec<(String, Option<Var>)> = assigns
            .iter()
            .map(|(name, _)| (name.clone(), self.state().vars.get(name).cloned()))
            .collect();
        for (name, value) in &assigns {
            self.state_mut().set_var(name, value.clone(), true);
        }
        let stdin = plan
            .stdin
            .take()
            .map(|stdin| std::mem::replace(&mut self.stdin, stdin));
        let outer_mark = std::mem::replace(&mut self.input_mark, self.stdin.session_pos());
        let was_blocked = self.stdin.is_blocked();
        let outer_typed = std::mem::take(&mut self.typed_output);
        // A function's own commands are noted as they run; the call is not a fetch.
        let mut result = match &function {
            Some(def) => self.call_function(def, &refs),
            None => {
                self.note_fetch(&refs, &unset, &simple.words);
                self.dispatch(&refs)
            }
        };
        let typed = std::mem::replace(&mut self.typed_output, outer_typed);
        // A command whose input was cut off (Ctrl-C, a closed channel) dies at the read it was
        // waiting in, and the signal ends the rest of the line with it.
        if !was_blocked
            && self.stdin.is_blocked()
            && let Some(status) = self.input_interrupt
        {
            result.status = status;
            result.stop_line = true;
        }
        // Charged here, once per command and before output is routed, so bytes a redirection
        // sends to a file cost the line as much as bytes sent to the terminal, and a re-entrant
        // command's output is not counted twice.
        if !self.charge_work(len_u64(result.bytes().len())) {
            result.stop_line = true;
        }
        self.settle_input(plan.reads_from);
        if let Some(previous) = stdin {
            self.stdin = previous;
        }
        for (name, before) in saved {
            match before {
                Some(var) => {
                    self.state_mut().vars.insert(name, var);
                }
                None => {
                    self.state_mut().vars.remove(&name);
                }
            }
        }
        // A program started by path names itself by it in its own errors.
        let writer = refs.first().map_or("sh", |arg| {
            if arg.contains('/') {
                arg
            } else {
                command_basename(arg)
            }
        });
        // Routed before the mark goes back, so a file this command's output lands in is known to
        // hold what it read from the session input.
        let routed = self.route(result, &plan, writer, typed);
        self.input_mark = outer_mark;
        self.pass_typed_output(typed, &plan);
        routed
    }

    /// Typed bytes a command wrote to a standard output that stays the enclosing command's (a
    /// group `{ echo ...; } > f`) are that command's typed output too.
    fn pass_typed_output(&mut self, typed: bool, plan: &RedirPlan) {
        if typed && matches!(plan.sink(1), Sink::Terminal(OutputFd::Stdout)) {
            self.typed_output = true;
        }
    }

    /// `exec` with redirections only: they become the shell's own descriptors.
    fn exec_redirections(&mut self, mut plan: RedirPlan) -> CommandResult {
        // `exec <FILE` at the terminal: the shell goes on reading commands, from the file.
        if plan.stdin.is_some() && plan.reads_from.is_none() && self.exec_reads_commands() {
            let bytes = plan
                .ins
                .remove(&0)
                .map(|input| input.remaining())
                .unwrap_or_default();
            self.commit_descriptors(plan.sinks, plan.ins);
            return self.exec_input_script(&bytes);
        }
        self.commit_descriptors(plan.sinks, plan.ins);
        CommandResult::silent(0)
    }

    /// A command that read standard input from descriptor `fd` moves that descriptor's position by
    /// what it read.
    pub(super) fn settle_input(&mut self, fd: Option<u16>) {
        let Some(fd) = fd else { return };
        let used = match &self.stdin {
            Stdin::Data { pos, .. } => *pos,
            _ => return,
        };
        if let Some(open) = self.state_mut().fds.ins.get_mut(&fd) {
            open.advance(used);
        }
    }

    /// What an expansion that failed leaves: its own message and status 1, or, for a refusal by
    /// the depth cap or the allowance, a bounded silent failure.
    pub(super) fn expand_failure(&mut self, error: ExpandError) -> CommandResult {
        let mut result = match error {
            ExpandError::Message(message) => CommandResult::stderr(1, message),
            ExpandError::Fatal(message) => {
                let mut fatal = CommandResult::stderr(2, message);
                self.end_process(&mut fatal);
                fatal
            }
            ExpandError::Refused => CommandResult::silent(1),
        };
        if self.line.exhausted() {
            result.stop_line = true;
        }
        result
    }

    // ---- redirections --------------------------------------------------------------------------

    /// Open every redirection in order. The first that fails prints the shell's own error and the
    /// command does not run.
    fn open_redirs(&mut self, redirs: &[Redir]) -> Result<RedirPlan, CommandResult> {
        let mut plan = RedirPlan::from_fds(&self.state().fds);
        plan.active |= !redirs.is_empty();
        for redir in redirs {
            if !self.charge_work(1) {
                let mut stopped = CommandResult::silent(1);
                stopped.stop_line = true;
                return Err(stopped);
            }
            let default_fd = match redir.op {
                RedirOp::In | RedirOp::DupIn | RedirOp::ReadWrite | RedirOp::HereDoc => 0,
                _ => 1,
            };
            let fd = redir.fd.unwrap_or(default_fd);
            let index = usize::from(fd);
            if index >= FD_MAX {
                continue;
            }
            match (&redir.op, &redir.target) {
                (RedirOp::HereDoc, RedirTarget::HereBody { text, expand, .. }) => {
                    let body = if *expand {
                        match self.expand_text(text) {
                            Ok(body) => body,
                            Err(error) => return Err(self.expand_failure(error)),
                        }
                    } else {
                        text.clone()
                    };
                    install_input(&mut plan, fd, body.into_bytes());
                }
                (RedirOp::Out | RedirOp::Append | RedirOp::Clobber, RedirTarget::Word(word)) => {
                    let text = self.redirect_target(word)?;
                    let append = redir.op == RedirOp::Append;
                    let natural = if index == 2 {
                        OutputFd::Stderr
                    } else {
                        OutputFd::Stdout
                    };
                    let sink = self.open_output(&text, append, &plan, natural)?;
                    if let Some(slot) = plan.sinks.get_mut(index) {
                        *slot = sink;
                    }
                    plan.ins.remove(&fd);
                }
                (RedirOp::DupOut | RedirOp::DupIn, RedirTarget::Word(word)) => {
                    let text = match self.expand_scalar(word) {
                        Ok(text) => text,
                        Err(error) => return Err(self.expand_failure(error)),
                    };
                    self.dup_descriptor(&mut plan, index, &text, redir.op == RedirOp::DupOut)?;
                }
                (RedirOp::In, RedirTarget::Word(word)) => {
                    let text = self.redirect_target(word)?;
                    let (bytes, _) = self.open_input(&text, false)?;
                    install_input(&mut plan, fd, bytes);
                    if index != 0
                        && let Some(slot) = plan.sinks.get_mut(index)
                    {
                        *slot = Sink::Closed;
                    }
                }
                (RedirOp::ReadWrite, RedirTarget::Word(word)) => {
                    let text = self.redirect_target(word)?;
                    let (bytes, path) = self.open_input(&text, true)?;
                    install_input(&mut plan, fd, bytes);
                    if index != 0
                        && let Some(slot) = plan.sinks.get_mut(index)
                    {
                        // Written at the end: the file is not rewound.
                        *slot = Sink::File { path, append: true };
                    }
                }
                _ => {}
            }
        }
        Ok(plan)
    }

    /// A redirection target. Bash refuses one that expands to anything but a single word; dash
    /// and mksh take it whole.
    fn redirect_target(&mut self, word: &Word) -> Result<String, CommandResult> {
        if self.is_bash() {
            return match self.expand_fields(word) {
                Ok(mut fields) if fields.len() == 1 => Ok(fields.remove(0)),
                Ok(_) => Err(CommandResult::stderr(
                    1,
                    self.shell_error(format_args!("{}: ambiguous redirect", word.raw)),
                )),
                Err(error) => Err(self.expand_failure(error)),
            };
        }
        match self.expand_scalar(word) {
            Ok(text) => Ok(text),
            Err(error) => Err(self.expand_failure(error)),
        }
    }

    /// Create or truncate (or, for `>>`, keep) the file a `>` names and return where writes go.
    fn open_output(
        &mut self,
        text: &str,
        append: bool,
        plan: &RedirPlan,
        natural: OutputFd,
    ) -> Result<Sink, CommandResult> {
        let resolved = self.resolve_logical(text);
        match resolved.as_str() {
            "/dev/null" => return Ok(Sink::Discard),
            "/dev/stdout" | "/dev/fd/1" => return Ok(plan.sink(1)),
            "/dev/stderr" | "/dev/fd/2" => return Ok(plan.sink(2)),
            // The session's terminal, when it has one.
            "/dev/tty" if self.tty_input => return Ok(Sink::Terminal(natural)),
            _ => {}
        }
        let opened = if append && self.fs.file_exists(&resolved) {
            Ok(())
        } else {
            self.traced_create(&resolved)
        };
        match opened {
            Ok(()) => Ok(Sink::File {
                path: resolved,
                append,
            }),
            Err(error) => Err(self.redirect_open_error(text, &error)),
        }
    }

    /// `< file` and `<> file`: the whole file, read now.
    fn open_input(&mut self, text: &str, create: bool) -> Result<(Vec<u8>, String), CommandResult> {
        // Opened by the shell, before any command it starts has replaced it: `cat < /proc/self/exe`
        // reads the shell's own binary, where `cat /proc/self/exe` reads cat's.
        let reader = self.shell_reader();
        let resolved = self.resolve_reading(text, reader);
        if create
            && !self.fs.file_exists(&resolved)
            && let Err(error) = self.traced_create(&resolved)
        {
            return Err(self.redirect_open_error(text, &error));
        }
        match self.fs.read_all(&resolved, READ_CAP) {
            Ok(bytes) => {
                if !self.charge_work(len_u64(bytes.len())) {
                    let mut stopped = CommandResult::silent(1);
                    stopped.stop_line = true;
                    return Err(stopped);
                }
                Ok((bytes, resolved))
            }
            Err(FsError::IsADirectory) => {
                // Opening a directory succeeds; reading it fails, which the reader reports.
                Ok((Vec::new(), resolved))
            }
            Err(_) => Err(self.input_open_error(text)),
        }
    }

    /// `N>&M`, `N>&-`, and `>&word` (both streams to a file).
    fn dup_descriptor(
        &mut self,
        plan: &mut RedirPlan,
        index: usize,
        text: &str,
        output: bool,
    ) -> Result<(), CommandResult> {
        // dash takes a descriptor number of one digit, or `-`, after `>&` and `<&`, and refuses
        // anything else (bash opens a name as a file).
        if self.is_dash()
            && text != "-"
            && !(text.len() == 1 && text.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(self.dash_fatal(2, "Syntax error: Bad fd number"));
        }
        let fd = u16::try_from(index).unwrap_or(u16::MAX);
        if text == "-" {
            // `N>&-` and `N<&-` both close the descriptor.
            if let Some(slot) = plan.sinks.get_mut(index) {
                *slot = Sink::Closed;
            }
            plan.ins.remove(&fd);
            if index == 0 {
                plan.stdin = Some(Stdin::data(Vec::new()));
                plan.reads_from = None;
            }
            return Ok(());
        }
        if let Ok(from) = text.parse::<usize>() {
            let from_fd = u16::try_from(from).unwrap_or(u16::MAX);
            if output {
                // The descriptor copied must be open.
                if from >= FD_MAX
                    || (plan.sink(from) == Sink::Closed && !plan.ins.contains_key(&from_fd))
                {
                    return Err(self.bad_descriptor(text));
                }
                let dest = plan.sink(from);
                if let Some(slot) = plan.sinks.get_mut(index) {
                    *slot = dest;
                }
                if let Some(input) = plan.ins.get(&from_fd).cloned() {
                    plan.ins.insert(fd, input);
                } else {
                    plan.ins.remove(&fd);
                }
            } else if from != 0 {
                let Some(input) = plan.ins.get(&from_fd).cloned() else {
                    return Err(self.bad_descriptor(text));
                };
                if index == 0 {
                    plan.stdin = Some(Stdin::data(input.remaining()));
                    plan.reads_from = Some(from_fd);
                } else {
                    plan.ins.insert(fd, input);
                }
            }
            return Ok(());
        }
        if output && index == 1 {
            // `>&file` is `&>file`.
            let sink = self.open_output(text, false, plan, OutputFd::Stdout)?;
            for stream in [1, 2] {
                if let Some(slot) = plan.sinks.get_mut(stream) {
                    *slot = sink.clone();
                }
            }
        } else if self.is_bash() {
            // Only `>&word` on standard output is a file; anywhere else the word must be a
            // descriptor.
            return Err(CommandResult::stderr(
                1,
                self.shell_error(format_args!("{text}: ambiguous redirect")),
            ));
        }
        Ok(())
    }

    /// What the shell says of a descriptor a redirection copies that is not open.
    fn bad_descriptor(&self, text: &str) -> CommandResult {
        CommandResult::stderr(
            if self.is_dash() { 2 } else { 1 },
            self.shell_error(format_args!("{text}: Bad file descriptor")),
        )
    }

    /// What the shell itself says when it cannot open a redirection target for writing.
    fn redirect_open_error(&self, text: &str, error: &FsError) -> CommandResult {
        if self.is_dash() {
            // dash's own words, and its status for a redirection it could not make.
            let reason = match error {
                FsError::ReadOnly => "Read-only file system",
                FsError::IsADirectory => "Is a directory",
                other => super::budget_refusal_text(other).unwrap_or("Directory nonexistent"),
            };
            return CommandResult::stderr(
                2,
                self.shell_error(format_args!("cannot create {text}: {reason}")),
            );
        }
        let reason = match error {
            FsError::ReadOnly => "Read-only file system",
            FsError::IsADirectory => "Is a directory",
            other => super::budget_refusal_text(other).unwrap_or("No such file or directory"),
        };
        CommandResult::stderr(1, self.shell_error(format_args!("{text}: {reason}")))
    }

    /// What the shell says when it cannot open a file for `<`. Dash words it its own way and
    /// exits 2.
    fn input_open_error(&self, text: &str) -> CommandResult {
        match self.active_level() {
            ShellLevel::Dash { .. } => CommandResult::stderr(
                2,
                self.shell_error(format_args!("cannot open {text}: No such file")),
            ),
            _ => CommandResult::stderr(
                1,
                self.shell_error(format_args!("{text}: No such file or directory")),
            ),
        }
    }

    /// Send what a command wrote where its redirections point. Streams the redirections did not
    /// move stay on the terminal. `typed` says the command's output carries bytes the attacker
    /// typed (`echo`, `printf`), so a file it lands in is noted as assembled from them.
    fn route(
        &mut self,
        result: CommandResult,
        plan: &RedirPlan,
        writer: &str,
        typed: bool,
    ) -> CommandResult {
        let carried = self.cat_origin.take();
        if !plan.active {
            return result;
        }
        let mut kept: Vec<OutputSegment> = Vec::new();
        let mut writes: Vec<(String, bool, Vec<u8>)> = Vec::new();
        // A command that writes to a descriptor that is not open finds out when it writes.
        let mut unwritable = false;
        for segment in &result.output {
            let index = match segment.fd {
                OutputFd::Stdout => 1,
                OutputFd::Stderr => 2,
            };
            match plan.sink(index) {
                Sink::Discard => {}
                Sink::Closed => unwritable = true,
                Sink::File { path, append } => {
                    match writes.iter_mut().find(|(p, _, _)| *p == path) {
                        Some((_, _, buf)) => buf.extend_from_slice(&segment.bytes),
                        None => writes.push((path, append, segment.bytes.clone())),
                    }
                }
                Sink::Terminal(stream) => kept.push(OutputSegment {
                    fd: stream,
                    bytes: segment.bytes.clone(),
                }),
            }
        }

        // The target was truncated or preserved at open, so `>` and `>>` both continue from the
        // file's current content. Only a budget refusal is reported: the target opened, so any
        // other refusal cannot happen here.
        let mut write_refusal = None;
        for (path, append, bytes) in writes {
            let mut content = if append {
                self.fs.read_all(&path, READ_CAP).unwrap_or_default()
            } else {
                Vec::new()
            };
            let prior = content.len();
            content.extend_from_slice(&bytes);
            match self.traced_write_file(&path, &content) {
                Ok(()) if !append && carried.is_some() => {
                    if let Some(origin) = carried.clone() {
                        self.set_origin(&path, origin);
                    }
                }
                Ok(()) if typed => {
                    let (before, _) = content.split_at(prior.min(content.len()));
                    self.note_typed_write(&path, before, &content);
                }
                Ok(()) => {}
                Err(error) => {
                    write_refusal = write_refusal.or_else(|| super::budget_refusal_text(&error));
                }
            }
        }

        let mut terminal = CommandResult::silent(result.status);
        for segment in kept {
            terminal.append(CommandResult::one(segment.fd, result.status, segment.bytes));
        }
        if let Some(reason) = write_refusal {
            // [unverified] wording: the `write error` form is what a command prints when a write
            // to its redirected stdout fails; no capture of the sensor's exact commands exists.
            terminal.append(CommandResult::stderr(
                1,
                format!("{writer}: write error: {reason}\n"),
            ));
        }
        if unwritable && matches!(plan.sink(2), Sink::Terminal(_)) {
            terminal.append(CommandResult::stderr(1, self.closed_write_error(writer)));
        }
        terminal.close_session = result.close_session;
        terminal.stop_line = result.stop_line;
        terminal.flow = result.flow;
        terminal
    }

    /// What a command says when the descriptor it writes to is closed: a builtin in the words of
    /// its shell, a program in its own (`coreutils`' `write error`).
    fn closed_write_error(&self, writer: &str) -> String {
        let builtin = !writer.contains('/')
            && super::registry::Registry::builtin().kind(writer, self)
                == Some(super::registry::CommandKind::Builtin);
        match (builtin, self.is_dash()) {
            (true, true) => self.shell_error(format_args!("{writer}: {writer}: I/O error")),
            (true, false) => {
                self.shell_error(format_args!("{writer}: write error: Bad file descriptor"))
            }
            // cat names the stream it could not write; most coreutils say `write error`.
            (false, _) if writer == "cat" || writer.ends_with("/cat") => {
                format!("{writer}: standard output: Bad file descriptor\n")
            }
            (false, _) => format!("{writer}: write error: Bad file descriptor\n"),
        }
    }

    // ---- shell level bookkeeping ---------------------------------------------------------------

    /// Set a shell variable unless the shell's variables would then hold more than the connection's
    /// content allowance. A refused assignment leaves the variable as it was and is noted in the
    /// trace; it prints nothing, since no real shell has such a limit to word an error for.
    pub(super) fn assign_var(&mut self, name: &str, value: String) -> bool {
        let cap = usize::try_from(self.budget().limits().owned_bytes).unwrap_or(usize::MAX);
        let state = self.state();
        let held = state.owned_bytes();
        let before = state
            .vars
            .get(name)
            .map_or(0, |var| name.len().saturating_add(var.value.len()));
        let after = held
            .saturating_sub(before)
            .saturating_add(name.len())
            .saturating_add(value.len());
        if after > cap {
            self.record_hit(BudgetHit::OwnedBytes);
            return false;
        }
        self.state_mut().assign(name, value);
        true
    }

    /// The active dash level's line counter and the number of frames, so a caller can put the
    /// counter back after commands moved it.
    fn dash_counter(&self) -> Option<(usize, u64)> {
        match self.active_level() {
            ShellLevel::Dash { line } => Some((self.frames.len(), line)),
            _ => None,
        }
    }

    fn restore_dash_counter(&mut self, line: u64) {
        self.set_dash_line(u32::try_from(line).unwrap_or(u32::MAX));
    }

    /// Point the active dash level at `line`, the line a command being run sits on.
    pub(super) fn set_dash_line(&mut self, line: u32) {
        for frame in self.frames.iter_mut().rev() {
            match &mut frame.kind {
                FrameKind::Level(ShellLevel::Dash { line: at })
                | FrameKind::Script(ShellLevel::Dash { line: at }) => {
                    *at = u64::from(line);
                    return;
                }
                FrameKind::Level(_) | FrameKind::Script(_) => return,
                FrameKind::Subshell => {}
            }
        }
    }
}

// ---- shell functions ---------------------------------------------------------------------------

impl FakeShell {
    /// Which grammar the active shell reads.
    pub(super) fn grammar(&self) -> Dialect {
        match self.active_level() {
            ShellLevel::Dash { .. } => Dialect::Posix,
            ShellLevel::Bash { .. } | ShellLevel::AndroidMksh => Dialect::Bash,
        }
    }

    /// Running a definition stores the function; the body runs when it is called.
    fn eval_function_def(&mut self, def: &Arc<FunctionDef>) -> CommandResult {
        self.trace_open(&[], ParseNode::FunctionDef, HandlerId::Compound);
        let result = self.store_function(def);
        self.trace_close(result.status);
        result
    }

    fn store_function(&mut self, def: &Arc<FunctionDef>) -> CommandResult {
        if !def.valid {
            return CommandResult::stderr(
                1,
                self.shell_error(format_args!("`{}': not a valid identifier", def.name)),
            );
        }
        let cap = usize::try_from(self.budget().limits().owned_bytes).unwrap_or(usize::MAX);
        let state = self.state();
        let before = state.functions.get(&def.name).map_or(0, |held| {
            def.name.len().saturating_add(held.def.source.len())
        });
        let after = state
            .owned_bytes()
            .saturating_sub(before)
            .saturating_add(def.name.len())
            .saturating_add(def.source.len());
        let is_new = !state.functions.contains_key(&def.name);
        let full = is_new && state.functions.len() >= FUNCTIONS_MAX;
        let exported = state
            .functions
            .get(&def.name)
            .is_some_and(|held| held.exported);
        if after > cap || full {
            // Like a refused assignment: nothing is printed, since no real shell has the limit.
            self.record_hit(BudgetHit::OwnedBytes);
            return CommandResult::silent(1);
        }
        self.state_mut().functions.insert(
            def.name.clone(),
            ShellFunction {
                def: Arc::clone(def),
                exported,
            },
        );
        CommandResult::silent(0)
    }

    /// bash's `FUNCNEST`: the nesting its functions may reach, when the session set a positive
    /// number. Anything else leaves bash unlimited.
    fn funcnest(&self) -> Option<usize> {
        if !self.is_bash() {
            return None;
        }
        self.state()
            .get("FUNCNEST")
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|limit| *limit > 0)
    }

    /// Run a function with `argv` (`argv[0]` is its name): its own positional parameters, its own
    /// `local` scope and no enclosing loop, all put back when it returns. `return` ends it with
    /// its status; otherwise the status is the last command's.
    fn call_function(&mut self, def: &Arc<FunctionDef>, argv: &[&str]) -> CommandResult {
        if !self.charge_work(FUNCTION_CALL_COST) {
            let mut stopped = CommandResult::silent(1);
            stopped.stop_line = true;
            return stopped;
        }
        let running = self.state().calls.len();
        if let Some(limit) = self.funcnest()
            && running >= limit
        {
            let mut refused = CommandResult::stderr(
                1,
                self.shell_error(format_args!(
                    "{}: maximum function nesting level exceeded ({limit})",
                    def.name
                )),
            );
            // bash drops the whole command list, not just this call.
            refused.stop_line = true;
            return refused;
        }
        if running >= FUNCTION_DEPTH_MAX {
            return self.function_overflow();
        }
        let frames = self.frames.len();
        let saved_args = std::mem::replace(
            &mut self.state_mut().positional,
            argv.iter().skip(1).map(|arg| (*arg).to_string()).collect(),
        );
        self.state_mut().calls.push(Call {
            name: def.name.clone(),
            keyword: def.keyword,
            locals: Vec::new(),
        });
        let saved_loops = std::mem::take(&mut self.loop_depth);
        let mut result = self.eval_command(&def.body);
        self.loop_depth = saved_loops;
        // An `exit` that left a shell level took this call's state with it.
        if self.frames.len() == frames {
            let state = self.state_mut();
            if let Some(call) = state.calls.pop() {
                for (name, previous) in call.locals.into_iter().rev() {
                    match previous {
                        Some(var) => {
                            state.vars.insert(name, var);
                        }
                        None => {
                            state.vars.remove(&name);
                        }
                    }
                }
            }
            state.positional = saved_args;
        }
        if result.flow == Flow::Return {
            result.flow = Flow::None;
        }
        result
    }

    /// The function stack reached its cap. dash words it and ends the shell with status 2; bash
    /// without `FUNCNEST` has no limit and dies of a stack overflow, silently, with status 139,
    /// which is what ending this shell here stands in for. Whichever shell it is, only the
    /// process that overflowed ends: a subshell, a pipeline stage or a script ends alone, and the
    /// login shell abandons the rest of the line but keeps the session.
    fn function_overflow(&mut self) -> CommandResult {
        self.record_hit(BudgetHit::Depth);
        self.note_depth();
        match self.active_level() {
            ShellLevel::Dash { .. } => self.dash_fatal(
                2,
                format_args!("Maximum function recursion depth (1000) reached"),
            ),
            ShellLevel::Bash { .. } | ShellLevel::AndroidMksh => {
                let mut crashed = CommandResult::silent(139);
                self.end_process(&mut crashed);
                crashed
            }
        }
    }

    /// dash's refusal of a `${...}` it cannot read: no `Syntax error:` prefix, status 2, and the
    /// shell process ends.
    fn dash_bad_substitution(&mut self) -> CommandResult {
        let mut result = CommandResult::stderr(2, self.shell_error("Bad substitution"));
        self.end_process(&mut result);
        result
    }

    /// An error dash makes fatal (its `sh_error`, which every special builtin's complaint is):
    /// the shell process exits with `status`.
    pub(super) fn dash_fatal(
        &mut self,
        status: u8,
        message: impl std::fmt::Display,
    ) -> CommandResult {
        let mut result = CommandResult::stderr(status, self.shell_error(message));
        self.end_process(&mut result);
        result
    }

    /// End the process running now, as `exit` does: a subshell, a pipeline stage or a script
    /// alone, or else the rest of the line.
    pub(super) fn end_process(&self, result: &mut CommandResult) {
        if self.top_frame_is_scoped() {
            result.flow = Flow::ExitSubshell;
        } else {
            result.stop_line = true;
        }
    }
}

/// After a loop body or condition: whether the loop goes on. Consumes the `break` or `continue`
/// aimed at this loop and passes one aimed further out up to the enclosing loop.
fn loop_continues(acc: &mut CommandResult) -> bool {
    if acc.stop_line {
        return false;
    }
    match acc.flow {
        Flow::None => true,
        // Both leave the loop and keep going up: to the subshell's edge, to the function's call.
        Flow::ExitSubshell | Flow::Return => false,
        Flow::Break(n) => {
            acc.flow = if n > 1 {
                Flow::Break(n.saturating_sub(1))
            } else {
                Flow::None
            };
            false
        }
        Flow::Continue(n) => {
            if n > 1 {
                acc.flow = Flow::Continue(n.saturating_sub(1));
                false
            } else {
                acc.flow = Flow::None;
                true
            }
        }
    }
}
