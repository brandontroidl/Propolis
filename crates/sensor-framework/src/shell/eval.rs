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

use super::ast::{
    AndOr, AndOrOp, Command, List, ListItem, Near, Pipeline, Redir, RedirOp, RedirTarget,
    SimpleCommand, Word,
};
use super::expand::ExpandError;
use super::parse::{Parsed, Tail};
use super::trace::BudgetHit;
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

/// Work charged for one trip round a loop, on top of what the body costs, so a body that costs
/// nothing (`while :; do :; done`) still runs out of allowance quickly.
const LOOP_STEP_COST: u64 = 256;

/// One shell variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Var {
    pub value: String,
    pub exported: bool,
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
        }
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
#[derive(Debug, Clone)]
enum Sink {
    /// The terminal, as its standard output or its standard error: a descriptor duplicated from
    /// standard error keeps writing to the error stream.
    Terminal(OutputFd),
    Discard,
    File {
        path: String,
        append: bool,
    },
}

/// The descriptors a command's redirections describe, opened before it runs.
struct RedirPlan {
    /// Index 0 is unused (standard input has no output sink); 1 is standard output, 2 standard
    /// error, 3 to 9 only matter through a `N>&M` duplicate.
    sinks: Vec<Sink>,
    stdin: Option<Stdin>,
    active: bool,
}

impl RedirPlan {
    /// Where descriptor `fd` goes now.
    fn sink(&self, fd: usize) -> Sink {
        self.sinks
            .get(fd)
            .cloned()
            .unwrap_or(Sink::Terminal(OutputFd::Stdout))
    }

    fn new() -> Self {
        Self {
            sinks: (0..10)
                .map(|fd| {
                    Sink::Terminal(if fd == 2 {
                        OutputFd::Stderr
                    } else {
                        OutputFd::Stdout
                    })
                })
                .collect(),
            stdin: None,
            active: false,
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
        let parsed = super::parse::parse_unit(&text, false, max_depth, &mut self.line, base_line);
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
        self.execute_unit(parsed, base_line)
    }

    /// Run the items that parsed, then say what was wrong with the rest. Only items that ended on
    /// a line before the error run, as a shell that reads and runs one command at a time would.
    pub(super) fn execute_unit(&mut self, parsed: Parsed, base_line: u32) -> CommandResult {
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
                    let message = self.syntax_error_text(&error.near);
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
    fn syntax_error_text(&self, near: &Near) -> String {
        match self.active_level() {
            ShellLevel::Bash { .. } => match near {
                Near::Token(token) => {
                    self.shell_error(format_args!("syntax error near unexpected token `{token}'"))
                }
                Near::Newline => self.shell_error("syntax error near unexpected token `newline'"),
                Near::EndOfFile => self.shell_error("syntax error: unexpected end of file"),
            },
            ShellLevel::Dash { .. } => match near {
                // Dash names every redirection operator alike.
                Near::Token(token)
                    if matches!(
                        token.as_str(),
                        "<" | ">" | ">>" | "<<" | "<<<" | "<&" | ">&" | "<>" | ">|"
                    ) =>
                {
                    self.shell_error("Syntax error: redirection unexpected")
                }
                Near::Token(token) => {
                    self.shell_error(format_args!("Syntax error: \"{token}\" unexpected"))
                }
                Near::Newline => self.shell_error("Syntax error: newline unexpected"),
                Near::EndOfFile => self.shell_error("Syntax error: end of file unexpected"),
            },
            // [unverified] mksh's wording; no Android capture exists.
            ShellLevel::AndroidMksh => match near {
                Near::Token(token) => {
                    self.shell_error(format_args!("syntax error: '{token}' unexpected"))
                }
                Near::Newline => self.shell_error("syntax error: newline unexpected"),
                Near::EndOfFile => self.shell_error("syntax error: unexpected EOF"),
            },
        }
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
        let max_depth = self.budget().limits().max_depth;
        let parsed = super::parse::parse_unit(text, true, max_depth, &mut self.line, 1);
        self.sync_budget_trace();
        self.execute_unit(parsed, 1)
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
        let mut acc = self.eval_segment(&chain.first, ControlOp::Seq, record);
        for (op, pipeline) in &chain.rest {
            if acc.stop_line || acc.flow != Flow::None {
                break;
            }
            let (control, run) = match op {
                AndOrOp::And => (ControlOp::And, acc.status == 0),
                AndOrOp::Or => (ControlOp::Or, acc.status != 0),
            };
            if run {
                let next = self.eval_segment(pipeline, control, record);
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
        let copy = self.state().clone();
        self.frames.push(Frame {
            kind: FrameKind::Subshell,
            state: copy,
        });
        let saved = std::mem::replace(&mut self.stdin, Stdin::data(Vec::new()));
        self.script_depth = self.script_depth.saturating_add(1);
        let ran = self.eval_and_or(&item.and_or);
        self.script_depth = self.script_depth.saturating_sub(1);
        self.stdin = saved;
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
        if let ([stage], false) = (pipeline.stages.as_slice(), pipeline.bang) {
            return self.eval_command(stage);
        }
        self.trace_open(&[], ParseNode::Pipeline, HandlerId::Compound);
        let mut acc = CommandResult::silent(0);
        let mut carried: Option<Vec<u8>> = None;
        let count = pipeline.stages.len();
        for (index, stage) in pipeline.stages.iter().enumerate() {
            let last = index.saturating_add(1) == count;
            let copy = self.state().clone();
            self.frames.push(Frame {
                kind: FrameKind::Subshell,
                state: copy,
            });
            let stdin = carried.take().map(Stdin::data);
            let saved = stdin.map(|s| std::mem::replace(&mut self.stdin, s));
            self.script_depth = self.script_depth.saturating_add(1);
            let mut ran = self.eval_command(stage);
            self.script_depth = self.script_depth.saturating_sub(1);
            if let Some(previous) = saved {
                self.stdin = previous;
            }
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
            Command::Unsupported(kind) => {
                self.trace_open(&[], ParseNode::Unsupported, HandlerId::Compound);
                self.trace_unsupported(*kind);
                self.trace_close(0);
                CommandResult::silent(0)
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
            Command::Simple(_) | Command::Unsupported(_) => return CommandResult::silent(0),
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
            Command::Simple(_) | Command::Unsupported(_) => CommandResult::silent(0),
        };
        if let Some(previous) = saved {
            self.stdin = previous;
        }
        let routed = self.route(result, &plan, "sh");
        self.input_mark = outer_mark;
        routed
    }

    fn eval_subshell(&mut self, body: &List) -> CommandResult {
        let copy = self.state().clone();
        self.frames.push(Frame {
            kind: FrameKind::Subshell,
            state: copy,
        });
        self.script_depth = self.script_depth.saturating_add(1);
        let mut result = self.eval_list(body);
        self.script_depth = self.script_depth.saturating_sub(1);
        self.frames.pop();
        // `exit`, `break` and `continue` end at the subshell's edge.
        result.flow = Flow::None;
        result
    }

    fn eval_if(
        &mut self,
        cond: &List,
        then: &List,
        elifs: &[(List, List)],
        els: Option<&List>,
    ) -> CommandResult {
        let mut acc = self.eval_list(cond);
        if acc.stop_line || acc.flow != Flow::None {
            return acc;
        }
        if acc.status == 0 {
            let body = self.eval_list(then);
            acc.append(body);
            return acc;
        }
        for (test, body) in elifs {
            let tested = self.eval_list(test);
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
            let tested = self.eval_list(cond);
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
        let ran = self.simple_inner(simple);
        let produced = std::mem::replace(&mut self.deferred_stderr, outer_stderr);
        self.last_subst_status = outer_subst;
        // What the expansions wrote to standard error came before the command itself.
        let mut result = CommandResult::silent(ran.status);
        for segment in produced {
            result.append(CommandResult::one(segment.fd, 0, segment.bytes));
        }
        result.append(ran);
        self.trace_close(result.status);
        result
    }

    fn simple_inner(&mut self, simple: &SimpleCommand) -> CommandResult {
        let argv = match self.expand_argv(&simple.words) {
            Ok(argv) => argv,
            Err(error) => return self.expand_failure(error),
        };
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        if refs.is_empty() {
            self.trace_set(
                &argv,
                ParseNode::RedirectionOnly,
                HandlerId::RedirectionOnly,
            );
        } else {
            let resolved = self.resolve_handler(&refs);
            self.trace_set(&argv, ParseNode::Simple, resolved);
        }
        let mut plan = match self.open_redirs(&simple.redirs) {
            Ok(plan) => plan,
            Err(refused) => return refused,
        };
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
        let mut result = self.dispatch(&refs);
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
        let writer = refs.first().map_or("sh", |arg| command_basename(arg));
        // Routed before the mark goes back, so a file this command's output lands in is known to
        // hold what it read from the session input.
        let routed = self.route(result, &plan, writer);
        self.input_mark = outer_mark;
        routed
    }

    /// What an expansion that failed leaves: its own message and status 1, or, for a refusal by
    /// the depth cap or the allowance, a bounded silent failure.
    pub(super) fn expand_failure(&mut self, error: ExpandError) -> CommandResult {
        let mut result = match error {
            ExpandError::Message(message) => CommandResult::stderr(1, message),
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
        let mut plan = RedirPlan::new();
        plan.active = !redirs.is_empty();
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
            if index > 9 {
                continue;
            }
            match (&redir.op, &redir.target) {
                (RedirOp::HereDoc, RedirTarget::HereBody { text, expand }) => {
                    let body = if *expand {
                        match self.expand_text(text) {
                            Ok(body) => body,
                            Err(error) => return Err(self.expand_failure(error)),
                        }
                    } else {
                        text.clone()
                    };
                    plan.stdin = Some(Stdin::data(body.into_bytes()));
                }
                (RedirOp::Out | RedirOp::Append | RedirOp::Clobber, RedirTarget::Word(word)) => {
                    let text = self.redirect_target(word)?;
                    let append = redir.op == RedirOp::Append;
                    let sink = self.open_output(&text, append, &plan)?;
                    if let Some(slot) = plan.sinks.get_mut(index) {
                        *slot = sink;
                    }
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
                    plan.stdin = Some(self.open_input(&text, false)?);
                }
                (RedirOp::ReadWrite, RedirTarget::Word(word)) => {
                    let text = self.redirect_target(word)?;
                    plan.stdin = Some(self.open_input(&text, true)?);
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
    ) -> Result<Sink, CommandResult> {
        let resolved = self.resolve_logical(text);
        match resolved.as_str() {
            "/dev/null" => return Ok(Sink::Discard),
            "/dev/stdout" | "/dev/fd/1" => return Ok(plan.sink(1)),
            "/dev/stderr" | "/dev/fd/2" => return Ok(plan.sink(2)),
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
    fn open_input(&mut self, text: &str, create: bool) -> Result<Stdin, CommandResult> {
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
                Ok(Stdin::data(bytes))
            }
            Err(FsError::IsADirectory) => {
                // Opening a directory succeeds; reading it fails, which the reader reports.
                Ok(Stdin::data(Vec::new()))
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
        if text == "-" {
            if let Some(slot) = plan.sinks.get_mut(index) {
                *slot = Sink::Discard;
            }
            return Ok(());
        }
        if let Ok(from) = text.parse::<usize>() {
            if output {
                let dest = plan.sink(from);
                if let Some(slot) = plan.sinks.get_mut(index) {
                    *slot = dest;
                }
            }
            return Ok(());
        }
        if output && index == 1 {
            // `>&file` is `&>file`.
            let sink = self.open_output(text, false, plan)?;
            for stream in [1, 2] {
                if let Some(slot) = plan.sinks.get_mut(stream) {
                    *slot = sink.clone();
                }
            }
        }
        Ok(())
    }

    /// What the shell itself says when it cannot open a redirection target for writing.
    fn redirect_open_error(&self, text: &str, error: &FsError) -> CommandResult {
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
    /// move stay on the terminal.
    fn route(&mut self, result: CommandResult, plan: &RedirPlan, writer: &str) -> CommandResult {
        if !plan.active {
            return result;
        }
        let mut kept: Vec<OutputSegment> = Vec::new();
        let mut writes: Vec<(String, bool, Vec<u8>)> = Vec::new();
        for segment in &result.output {
            let index = match segment.fd {
                OutputFd::Stdout => 1,
                OutputFd::Stderr => 2,
            };
            match plan.sink(index) {
                Sink::Discard => {}
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
            content.extend_from_slice(&bytes);
            if let Err(error) = self.traced_write_file(&path, &content) {
                write_refusal = write_refusal.or_else(|| super::budget_refusal_text(&error));
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
        terminal.close_session = result.close_session;
        terminal.stop_line = result.stop_line;
        terminal.flow = result.flow;
        terminal
    }

    // ---- shell level bookkeeping ---------------------------------------------------------------

    /// Set a shell variable unless the shell's variables would then hold more than the connection's
    /// content allowance. A refused assignment leaves the variable as it was and is noted in the
    /// trace; it prints nothing, since no real shell has such a limit to word an error for.
    pub(super) fn assign_var(&mut self, name: &str, value: String) -> bool {
        let cap = usize::try_from(self.budget().limits().owned_bytes).unwrap_or(usize::MAX);
        let state = self.state();
        let held: usize = state
            .vars
            .iter()
            .map(|(name, var)| name.len().saturating_add(var.value.len()))
            .fold(0, usize::saturating_add);
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

/// After a loop body or condition: whether the loop goes on. Consumes the `break` or `continue`
/// aimed at this loop and passes one aimed further out up to the enclosing loop.
fn loop_continues(acc: &mut CommandResult) -> bool {
    if acc.stop_line {
        return false;
    }
    match acc.flow {
        Flow::None => true,
        Flow::ExitSubshell => false,
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
