//! The fake interactive shell (Task 13) presented to an attacker after SSH authentication
//! succeeds. Originally part of `sensor-ssh`; moved here (Task 1 of the remaining-sensors plan)
//! so `sensor-telnet`/`sensor-adb` can reuse it without depending on sensor-ssh. See "Fake
//! shell", "Never-exec", and "No attacker-directed fetch" in
//! `internal/design/02-sensor-framework.md`: this module sits on the two highest-priority
//! security surfaces in the platform, and both governing invariants are enforced by
//! construction, not by care.
//!
//! **Never-exec.** No file in this crate's `src/`, nor in `sensor-ssh`'s, imports a
//! process-spawning facility: no `Command` type pulled in from `std`'s `process` module, no
//! `exec`-family call, no dynamic evaluation of any kind. Every command below returns a
//! hand-written, static or lightly-interpolated string; there is no code path from an
//! attacker-typed byte to a real shell, syscall, or interpreter. `never_exec_static_check` in
//! `sensor-ssh`'s `tests/shell_test.rs` asserts this at the source level (as plain substring
//! matches, so this doc comment is deliberately phrased to describe those APIs without spelling
//! out their exact paths) across every file in both crates' `src/`, not just this one.
//!
//! **No attacker-directed fetch.** `wget`/`curl` return a canned transcript and perform zero
//! network I/O. This is guaranteed the same way never-exec is: this crate (and the whole
//! workspace) depends on no HTTP or generic network-fetch client, so there is nothing present
//! capable of making the request even if a future change tried to. `tests/shell_test.rs`'s
//! `workspace_lockfile_has_no_http_client_crate` asserts the fully-resolved workspace lockfile
//! names none; Task 14's `no_outbound_connection` integration test verifies the same thing at
//! runtime, across a live session.
//!
//! Every attacker-controlled byte this module embeds in a `SensorEvent` clears
//! `sensor_framework::sanitize_value` first - the same chokepoint `auth.rs` and `channel.rs`
//! route through - so a command line can never forge a second wire record via an embedded CR/LF
//! or ANSI escape.
//!
//! **The grammar.** An input line is tokenized (`lex`), parsed into a tree (`parse`, `ast`),
//! expanded (`expand`, `arith`) and evaluated (`eval`) with real quoting, redirections,
//! pipelines, lists, subshells and `if`/`for`/`while`/`until`; each simple command then
//! dispatches through the `registry` to the handlers in this file and in `builtins`. Constructs
//! outside that subset (`case`, `[[ ]]`, functions, `$'..'`, brace expansion, here-strings,
//! arrays) parse and are skipped with status 0, so they never raise an error a real shell would
//! not. Words are `String`s; migrating every handler to byte-string arguments is deferred until a
//! command family needs it (F1 and F2 did not: file contents and pipe data are already bytes).
#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::sync::Arc;

use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_FILE_DOWNLOAD, SensorEvent,
    WIRE_VERSION,
};

use crate::binaries;
use crate::budget::{ConnectionBudget, Resource};
use crate::command_codec::CommandCodec;
use crate::fakefs::{Blob, FakeFs, FsError, READ_CAP};
use crate::persona;
use crate::sanitize_value;

mod android;
mod androidsys;
mod arith;
mod ast;
mod base64;
mod builtins;
mod busybox;
mod dd;
mod eval;
mod expand;
mod fsops;
mod hashing;
mod lex;
mod lookup;
mod multicall;
mod parse;
mod pathtools;
mod printf;
mod read;
mod readlink;
mod registry;
mod test_builtin;
mod texttools;
mod trace;

use eval::{DepthGuard, LineBudget, PidAlloc, ShellState, Stdin};
use registry::{HandlerFn, Registry, resolve_proc_self};

pub use ast::UnsupportedKind;
pub use trace::{
    BudgetHit, BudgetTrace, CommandTrace, FsDenied, FsEffect, HandlerId, LineTrace, ParseNode,
    RunDecision, SegmentTrace, TraceEventKind,
};

/// Cap applied to the sanitized command line captured in `metadata.command`. Matches
/// `auth::MAX_METADATA_STRING_LEN`'s convention of a generous, fixed bound on an
/// attacker-controlled string entering an event.
const MAX_COMMAND_LEN: usize = 1024;

/// Cap applied to the `wget`/`curl` target URL echoed back in canned output. Smaller than
/// `MAX_COMMAND_LEN` since it is one token of the line, not the whole line.
const MAX_URL_LEN: usize = 512;

/// The per-session facts every `honeypot_command_exec` event carries, handed in once at shell
/// construction. Mirrors `auth::AuthState`'s "real parameters, no placeholder" convention:
/// `source_ip`/`wan_ip` are this connection's real attributes. `authenticated` is read from here
/// rather than hardcoded `true` - the shell is only ever reached post-authentication in practice,
/// but a future caller (a pre-auth probe, a non-interactive path) must not have its events
/// silently mis-tagged by a hardcoded value.
///
/// `protocol_label` exists because this shell is shared across protocols (SSH, Telnet, and per
/// the design spec eventually ADB): it names both the emitted event's top-level `sensor` field
/// and its `metadata.protocol_label` entry, so `handle_input` never hardcodes which sensor is
/// driving it. Every current and planned caller uses the same string for both - there is no
/// observed case where a `FakeShell` consumer's `sensor` name differs from its `protocol_label` -
/// so one field covers both rather than two that would only ever be set identically.
pub struct EmitContext {
    pub source_ip: IpAddr,
    pub wan_ip: Option<IpAddr>,
    pub authenticated: bool,
    pub protocol_label: String,
    pub session_id: Option<uuid::Uuid>,
}

/// Where a shell reads the time: the timestamps in its replies and the `observed_at` of its
/// events. Sessions use the system clock; a replay fixes it, so a transcript that prints the time
/// can be compared byte for byte.
pub type Clock = fn() -> chrono::DateTime<chrono::Utc>;

/// The two output streams a modeled command may write. Keeping the stream identity alongside
/// bytes lets a non-PTY SSH exec send stderr as extended data while a terminal can merge both in
/// their original order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFd {
    Stdout,
    Stderr,
}

/// One ordered write made by a modeled command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSegment {
    pub fd: OutputFd,
    pub bytes: Vec<u8>,
}

/// A non-local transfer of control a builtin asked for, carried up the tree until something
/// consumes it: a loop takes `break` and `continue`, a subshell takes `exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Flow {
    #[default]
    None,
    /// `break N`: leave N loops.
    Break(u32),
    /// `continue N`: go on to the next trip of the Nth loop out.
    Continue(u32),
    /// `exit` inside a subshell, a pipeline stage or a script run by `sh -c`.
    ExitSubshell,
}

/// The observable result of one command or command list. Status is authoritative for shell
/// control flow; output wording is never inspected to decide whether `&&` or `||` continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub status: u8,
    pub output: Vec<OutputSegment>,
    pub close_session: bool,
    combined: Vec<u8>,
    stop_line: bool,
    flow: Flow,
}

impl CommandResult {
    fn silent(status: u8) -> Self {
        Self {
            status,
            output: Vec::new(),
            close_session: false,
            combined: Vec::new(),
            stop_line: false,
            flow: Flow::None,
        }
    }

    /// Remove what was written to standard output and return it; standard error stays.
    fn take_stdout(&mut self) -> Vec<u8> {
        let mut taken = Vec::new();
        let mut kept = Vec::new();
        let mut combined = Vec::new();
        for segment in std::mem::take(&mut self.output) {
            if segment.fd == OutputFd::Stdout {
                taken.extend_from_slice(&segment.bytes);
            } else {
                combined.extend_from_slice(&segment.bytes);
                kept.push(segment);
            }
        }
        self.output = kept;
        self.combined = combined;
        taken
    }

    fn stdout(bytes: impl Into<Vec<u8>>) -> Self {
        Self::one(OutputFd::Stdout, 0, bytes.into())
    }

    fn stderr(status: u8, bytes: impl Into<Vec<u8>>) -> Self {
        Self::one(OutputFd::Stderr, status, bytes.into())
    }

    fn one(fd: OutputFd, status: u8, bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::silent(status);
        }
        Self {
            status,
            combined: bytes.clone(),
            output: vec![OutputSegment { fd, bytes }],
            close_session: false,
            stop_line: false,
            flow: Flow::None,
        }
    }

    fn shell_exit(status: u8, bytes: impl Into<Vec<u8>>, close_session: bool) -> Self {
        let mut result = Self::one(OutputFd::Stdout, status, bytes.into());
        result.close_session = close_session;
        result.stop_line = true;
        result
    }

    /// Add what `other` produced after this. The status and any pending flow are `other`'s, the
    /// most recent command's.
    fn append(&mut self, mut other: Self) {
        self.status = other.status;
        self.close_session |= other.close_session;
        self.stop_line |= other.stop_line;
        self.flow = other.flow;
        self.combined.append(&mut other.combined);
        self.output.append(&mut other.output);
    }

    pub fn bytes(&self) -> &[u8] {
        &self.combined
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.combined
    }

    pub fn is_empty(&self) -> bool {
        self.combined.is_empty()
    }

    pub fn contains(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        self.combined
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    pub fn starts_with(&self, prefix: &str) -> bool {
        self.combined.starts_with(prefix.as_bytes())
    }

    pub fn ends_with(&self, suffix: &str) -> bool {
        self.combined.ends_with(suffix.as_bytes())
    }

    pub fn lines(&self) -> std::str::Lines<'_> {
        std::str::from_utf8(&self.combined).unwrap_or("").lines()
    }
}

impl std::fmt::Display for CommandResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.combined))
    }
}

impl PartialEq<&str> for CommandResult {
    fn eq(&self, other: &&str) -> bool {
        self.combined == other.as_bytes()
    }
}

impl PartialEq<String> for CommandResult {
    fn eq(&self, other: &String) -> bool {
        self.combined == other.as_bytes()
    }
}

/// Apply the terminal ONLCR output transformation without assuming UTF-8. Every LF becomes CR-LF;
/// all other bytes, including NUL and arbitrary executable bytes, pass through unchanged.
pub fn onlcr(bytes: &[u8]) -> Vec<u8> {
    let extra = bytes.iter().filter(|&&byte| byte == b'\n').count();
    let mut out = Vec::with_capacity(bytes.len().saturating_add(extra));
    for &byte in bytes {
        if byte == b'\n' {
            out.push(b'\r');
        }
        out.push(byte);
    }
    out
}

/// Default ceiling on `honeypot_command_exec` events, the value of `BudgetLimits::command_events`.
/// A real interactive attacker runs a bounded kill chain (tens of commands); an unbounded stream is
/// a flood - one IP produced >20k command events by streaming binary over the channel. Past this,
/// the shell keeps responding but stops appending per-line events (one marker is emitted at the
/// boundary), so a single session cannot pollute the append-only ledger without bound. The count is
/// per connection, shared by every shell on it, through the connection budget.
pub(crate) const MAX_COMMANDS_PER_SESSION: u64 = 256;

/// The fake shell. One instance per interactive session or exec request; filesystem, working
/// directory, codec and nested shell levels persist across input lines.
pub struct FakeShell {
    fs: FakeFs,
    ctx: EmitContext,
    /// Per-session de-obfuscation for XOR-encoded command probes (see `command_codec`).
    codec: CommandCodec,
    /// Whether the one-per-session binary-flood marker has been emitted.
    binary_flagged: bool,
    /// Which host persona this session presents. Active shell levels decide diagnostics and
    /// prompts; the flavor keeps `uname` aligned with the filesystem snapshot.
    flavor: ShellFlavor,
    context: ShellContext,
    /// The shells and subshells open right now, outermost first, each with its own state. The
    /// first is the login shell. A subshell, pipeline stage or substitution pushes a copy of the
    /// state and pops it, discarding what it changed.
    frames: Vec<Frame>,
    hostname: String,
    clock: Clock,
    /// What the engine decided for the current input line; reset at the top of `handle_input`.
    trace: LineTrace,
    /// Commands open at this moment, outermost first. A re-entrant dispatch pushes; closing pops
    /// and attaches to the parent's `reentry` or, for the outermost, to the current segment.
    trace_stack: Vec<CommandTrace>,
    /// Trace nodes recorded for the current line, so a loop cannot grow the trace without bound.
    trace_nodes: usize,
    /// Commands opened past the trace cap: their closes are matched and dropped.
    trace_dropped: u32,
    /// Steps and bytes the current line may still spend. Reset once per line, never on re-entry,
    /// so a chain of nested dispatches and every loop trip share one allowance.
    line: LineBudget,
    /// Recursive entries right now: compound commands, substitutions, applets, scripts.
    depth: DepthGuard,
    /// Lines held for an incomplete construct, waiting for the rest (the PS2 continuation).
    pending: Vec<String>,
    pending_bytes: usize,
    /// Where the running command reads standard input.
    stdin: Stdin,
    /// Process ids for `$$` and `$!`, deterministic for a session.
    pids: PidAlloc,
    /// The last job number a background command was given.
    next_job: u32,
    /// What `$( )` expansions wrote to standard error while a command's words were expanded; it
    /// goes ahead of that command's own output.
    deferred_stderr: Vec<OutputSegment>,
    /// The status of the last `$( )` run while expanding the current command.
    last_subst_status: Option<u8>,
    /// Scripts, subshells, pipeline stages and substitutions open right now: the shell is not
    /// reading the terminal.
    script_depth: u32,
    /// Loops open right now, for `break` and `continue`.
    loop_depth: u32,
    /// BusyBox applets running right now. An applet runs inside the busybox process, so what it
    /// opens as `/proc/self/exe` is busybox, whatever applet name it was started under.
    busybox_depth: u32,
    /// What `setprop` set this session, read before the modeled table. Android's property
    /// service is system-wide, so it sits here rather than in a frame's state, which a subshell
    /// discards.
    props: std::collections::BTreeMap<String, String>,
}

/// One entry of the shell stack.
struct Frame {
    kind: FrameKind,
    state: ShellState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    /// A shell that reads the terminal: the login shell, or one opened by `sh` or `su`.
    Level(ShellLevel),
    /// A shell running a script (`sh -c`, `sh FILE`, a piped script): it ends when the script does.
    Script(ShellLevel),
    /// A subshell, pipeline stage, substitution or background job.
    Subshell,
}

/// How the outermost shell was entered. Login shells read Ubuntu's interactive startup files;
/// one-shot exec commands do not; Android uses mksh rather than either GNU shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellContext {
    LoginInteractive,
    ExecC,
    AndroidMksh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellLevel {
    Bash { login: bool },
    Dash { line: u64 },
    AndroidMksh,
}

/// The command name of the executable a shell level runs as: Ubuntu's bash, or the dash `sh` is.
/// The phone's mksh has no modeled file.
fn level_command(level: ShellLevel) -> Option<&'static str> {
    match level {
        ShellLevel::Bash { .. } => Some("bash"),
        ShellLevel::Dash { .. } => Some("dash"),
        ShellLevel::AndroidMksh => None,
    }
}

/// The host persona a session presents. The command grammar is shared, but Linux and Android
/// report different kernels and use different outer shell identities. A session that mixed them
/// was the ADB tell: a Nexus 5 banner followed by an Ubuntu bash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShellFlavor {
    /// Ubuntu's bash, on SSH and telnet.
    #[default]
    Bash,
    /// Android's mksh (`/system/bin/sh`), on ADB.
    AndroidSh,
}

impl FakeShell {
    pub fn new(fs: FakeFs, ctx: EmitContext) -> Self {
        Self::with_context(fs, ctx, ShellFlavor::Bash, ShellContext::LoginInteractive)
    }

    /// A non-interactive `bash -c`-style shell used by SSH exec requests.
    pub fn exec(fs: FakeFs, ctx: EmitContext) -> Self {
        Self::with_context(fs, ctx, ShellFlavor::Bash, ShellContext::ExecC)
    }

    /// The Android shell ADB serves: `FakeFs::android()` plus [`ShellFlavor::AndroidSh`], landing
    /// in `/` as an `adb shell` session does rather than a Linux server's `/root`.
    pub fn android(fs: FakeFs, ctx: EmitContext) -> Self {
        Self::with_context(fs, ctx, ShellFlavor::AndroidSh, ShellContext::AndroidMksh)
    }

    pub fn with_flavor(fs: FakeFs, ctx: EmitContext, flavor: ShellFlavor) -> Self {
        let context = match flavor {
            ShellFlavor::Bash => ShellContext::LoginInteractive,
            ShellFlavor::AndroidSh => ShellContext::AndroidMksh,
        };
        Self::with_context(fs, ctx, flavor, context)
    }

    fn with_context(
        fs: FakeFs,
        ctx: EmitContext,
        flavor: ShellFlavor,
        context: ShellContext,
    ) -> Self {
        let level = match context {
            ShellContext::LoginInteractive => ShellLevel::Bash { login: true },
            ShellContext::ExecC => ShellLevel::Bash { login: false },
            ShellContext::AndroidMksh => ShellLevel::AndroidMksh,
        };
        let line = LineBudget::new(fs.budget().limits().work_per_line);
        let hostname = persona::hostname();
        let pid = persona::session_pid(ctx.session_id.map(|id| id.as_u128()));
        let state = ShellState::login(flavor, pid, &hostname);
        Self {
            fs,
            ctx,
            codec: CommandCodec::new(),
            binary_flagged: false,
            flavor,
            context,
            frames: vec![Frame {
                kind: FrameKind::Level(level),
                state,
            }],
            hostname,
            clock: chrono::Utc::now,
            trace: LineTrace::default(),
            trace_stack: Vec::new(),
            trace_nodes: 0,
            trace_dropped: 0,
            line,
            depth: DepthGuard::default(),
            pending: Vec::new(),
            pending_bytes: 0,
            stdin: Stdin::Terminal,
            pids: PidAlloc::new(pid),
            next_job: 0,
            deferred_stderr: Vec::new(),
            last_subst_status: None,
            script_depth: 0,
            loop_depth: 0,
            busybox_depth: 0,
            props: std::collections::BTreeMap::new(),
        }
    }

    /// What the engine decided while running the most recent non-blank input line. For tests and
    /// in-process readers; it is never part of a reply.
    pub fn last_trace(&self) -> &LineTrace {
        &self.trace
    }

    /// The same shell reading its time from `clock` instead of the system clock.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The same shell and its filesystem charging `budget`, the one budget of their connection,
    /// instead of the standard-limits budget a shell starts with. Every shell of a connection takes
    /// a clone of the same `Arc`.
    pub fn with_budget(mut self, budget: Arc<ConnectionBudget>) -> Self {
        self.line = LineBudget::new(budget.limits().work_per_line);
        self.fs = self.fs.with_budget(budget);
        self
    }

    /// The budget this shell charges: its filesystem's, so the two can never disagree.
    fn budget(&self) -> &ConnectionBudget {
        self.fs.budget()
    }

    /// The state the running command sees: the innermost frame's.
    fn state(&self) -> &ShellState {
        &self
            .frames
            .last()
            .expect("a FakeShell always has an outermost level")
            .state
    }

    fn state_mut(&mut self) -> &mut ShellState {
        &mut self
            .frames
            .last_mut()
            .expect("a FakeShell always has an outermost level")
            .state
    }

    /// The working directory, for the prompt a sensor prints between commands.
    pub fn cwd(&self) -> &str {
        &self.state().cwd
    }

    /// The prompt for the active shell level. Exec requests have no prompt. While a construct is
    /// incomplete the continuation prompt (PS2) stands in for it.
    pub fn prompt(&self) -> String {
        if !self.pending.is_empty() && self.context != ShellContext::ExecC {
            return "> ".to_string();
        }
        let cwd = self.cwd();
        match (self.context, self.active_level()) {
            (ShellContext::ExecC, _) => String::new(),
            (_, ShellLevel::Bash { .. }) => {
                let display = match cwd.strip_prefix("/root") {
                    Some("") => "~".to_string(),
                    Some(rest) if rest.starts_with('/') => format!("~{rest}"),
                    _ => cwd.to_string(),
                };
                format!("root@{}:{display}# ", self.hostname)
            }
            (_, ShellLevel::Dash { .. }) => "# ".to_string(),
            (_, ShellLevel::AndroidMksh) => persona::android_root_prompt(cwd),
        }
    }

    /// The innermost shell, subshells looked through.
    fn active_level(&self) -> ShellLevel {
        self.frames
            .iter()
            .rev()
            .find_map(|frame| match frame.kind {
                FrameKind::Level(level) | FrameKind::Script(level) => Some(level),
                FrameKind::Subshell => None,
            })
            .expect("a FakeShell always has an outermost level")
    }

    /// Shell levels open that read the terminal (the login shell counts).
    fn open_levels(&self) -> usize {
        self.frames
            .iter()
            .filter(|frame| matches!(frame.kind, FrameKind::Level(_)))
            .count()
    }

    fn advance_shell_line(&mut self) {
        for frame in self.frames.iter_mut().rev() {
            match &mut frame.kind {
                FrameKind::Level(ShellLevel::Dash { line })
                | FrameKind::Script(ShellLevel::Dash { line }) => {
                    *line = line.saturating_add(1);
                    return;
                }
                FrameKind::Level(_) | FrameKind::Script(_) => return,
                FrameKind::Subshell => {}
            }
        }
    }

    fn error_prefix(&self) -> String {
        match (self.context, self.active_level()) {
            (ShellContext::ExecC, ShellLevel::Bash { .. }) => "bash: line 1".to_string(),
            (_, ShellLevel::Bash { login: true }) => "-bash".to_string(),
            (_, ShellLevel::Bash { login: false }) => "bash".to_string(),
            (_, ShellLevel::Dash { line }) => format!("sh: {line}"),
            (_, ShellLevel::AndroidMksh) => "sh".to_string(),
        }
    }

    fn shell_error(&self, detail: impl std::fmt::Display) -> String {
        format!("{}: {detail}\n", self.error_prefix())
    }

    fn argv_zero(&self) -> &'static str {
        match self.active_level() {
            ShellLevel::Bash { login: true } => "-bash",
            ShellLevel::Bash { login: false } => "bash",
            ShellLevel::Dash { .. } | ShellLevel::AndroidMksh => "sh",
        }
    }

    fn is_bash(&self) -> bool {
        matches!(self.active_level(), ShellLevel::Bash { .. })
    }

    /// What the active shell says for a command it cannot find.
    fn not_found(&self, what: &str) -> String {
        match (self.context, self.active_level()) {
            (ShellContext::ExecC, ShellLevel::Bash { .. }) => {
                format!("bash: line 1: {what}: command not found\n")
            }
            (_, ShellLevel::Bash { .. }) => login_command_not_found(what)
                .map(str::to_string)
                .unwrap_or_else(|| format!("{what}: command not found\n")),
            (_, ShellLevel::Dash { line }) => format!("sh: {line}: {what}: not found\n"),
            (_, ShellLevel::AndroidMksh) => format!("sh: {what}: not found\n"),
        }
    }

    /// Encode outbound bytes with the session's locked obfuscation key (identity when the session is
    /// plaintext). The sensor calls this on its assembled response so a symmetric-codec bot reads
    /// plaintext after de-obfuscating.
    pub fn encode_output(&self, bytes: &[u8]) -> Vec<u8> {
        self.codec.encode(bytes)
    }

    /// Handle one line of shell input: capture it as a `honeypot_command_exec` event (unless the
    /// line is blank - see below), then return the canned terminal output for a recognized
    /// command, or a `command not found` message for anything else.
    ///
    /// A blank line (empty or whitespace-only) produces neither output nor an event. A bare
    /// keystroke or a terminal keepalive is not "a command" by any real shell's definition, and
    /// counting one would pad `honeypot_command_exec` telemetry with empty-command noise on
    /// every idle newline a client sends. This is the one place this function departs from
    /// "every call captures exactly one event" - called out here since it is the one behavior in
    /// this module not dictated directly by the interface.
    pub fn handle_input(&mut self, line: impl AsRef<[u8]>) -> (CommandResult, Vec<SensorEvent>) {
        let raw = String::from_utf8_lossy(line.as_ref());
        self.begin_line();
        if raw.trim().is_empty() {
            if self.pending.is_empty() {
                return (CommandResult::silent(0), Vec::new());
            }
            // A blank line inside an open construct (a here-document body, a continued command)
            // belongs to it, and is still not a command of its own.
            self.advance_shell_line();
            return (self.feed_line(""), Vec::new());
        }
        self.trace = LineTrace::default();
        self.advance_shell_line();

        // Decode a single-byte-XOR-obfuscated probe (identity for plaintext). The event records a
        // sanitized, lossily decoded representation of the pre-codec bytes; the transport capture,
        // when one is retained, is where exact wire bytes live. The decoded form and key are
        // annotated alongside so the grammar can respond and an analyst can read it. Dispatch and
        // URL capture run on the decoded line.
        let (decoded, key) = self.codec.decode(&raw);
        // Every non-blank line counts, whether or not it produces an event, so a binary flood
        // spends the same allowance a command flood does.
        let command_allowed = self.budget().command_event_allowed();
        self.trace.decoded = decoded.to_string();
        self.trace.xor_key = key;

        // Two floods must never pollute the append-only ledger with one event per line: a
        // binary/non-text line (an SSH/telnet channel tunneling binary, or a fuzzer - not a
        // command), and an unbounded stream of commands from one session (a single IP produced
        // >20k `command_exec` events this way). In both cases we STILL dispatch below so the fake
        // shell keeps responding - a silently dead session is itself a tell - but emit at most ONE
        // marker event per session per flood kind rather than one event per garbage line.
        let events = if is_binary_line(&decoded) {
            self.trace.binary_line = true;
            if std::mem::replace(&mut self.binary_flagged, true) {
                Vec::new()
            } else {
                self.trace.events.push(TraceEventKind::FloodBinary);
                vec![self.command_event(serde_json::json!({
                    "protocol_label": self.ctx.protocol_label,
                    "command": "<binary channel data; per-line command events suppressed>",
                    "flood": "binary",
                }))]
            }
        } else if !command_allowed {
            if !self.budget().claim_command_cap_marker() {
                Vec::new()
            } else {
                self.trace.events.push(TraceEventKind::FloodCommandCap);
                let cap = self.budget().limits().command_events;
                vec![self.command_event(serde_json::json!({
                    "protocol_label": self.ctx.protocol_label,
                    "command": format!(
                        "<per-session command cap of {cap} reached; further commands suppressed>"
                    ),
                    "flood": "command_cap",
                }))]
            }
        } else {
            // Normal command: the event records the sanitized pre-codec text; the decoded form and
            // XOR key are annotated alongside.
            let mut metadata = serde_json::json!({
                "protocol_label": self.ctx.protocol_label,
                "command": sanitize_value(&raw, MAX_COMMAND_LEN),
            });
            if let Some(k) = key
                && let Some(obj) = metadata.as_object_mut()
            {
                obj.insert(
                    "command_decoded".to_string(),
                    serde_json::json!(sanitize_value(&decoded, MAX_COMMAND_LEN)),
                );
                obj.insert("xor_key".to_string(), serde_json::json!(k));
            }
            let mut evs = vec![self.command_event(metadata)];
            self.trace.events.push(TraceEventKind::CommandExec);
            // Scanning the line for fetch targets is linear in its length.
            self.charge_work(len_u64(decoded.len()));
            let per_line_cap = self.budget().limits().download_per_line;
            let mut recorded_this_line: u64 = 0;
            let mut download_capped = false;
            for url in download_targets(&decoded) {
                // The per-line cap is tested first so a URL refused by it spends none of the
                // connection's allowance.
                if recorded_this_line >= per_line_cap {
                    self.record_hit(BudgetHit::DownloadPerLine);
                    download_capped = true;
                    break;
                }
                if !self.budget().download_allowed() {
                    download_capped = true;
                    break;
                }
                recorded_this_line = recorded_this_line.saturating_add(1);
                self.trace.events.push(TraceEventKind::FileDownload);
                let sanitized_url = sanitize_value(&url, MAX_URL_LEN);
                evs.push(SensorEvent {
                    v: WIRE_VERSION,
                    source_ip: self.ctx.source_ip,
                    wan_ip: self.ctx.wan_ip,
                    sensor: self.ctx.protocol_label.clone(),
                    signal_type: SIGNAL_HONEYPOT_FILE_DOWNLOAD.into(),
                    protocol: PROTO_TCP.into(),
                    authenticated: self.ctx.authenticated,
                    observed_at: (self.clock)(),
                    metadata: serde_json::json!({
                        "protocol_label": self.ctx.protocol_label,
                        "url": sanitized_url,
                    }),
                    sample: None,
                    session_id: self.ctx.session_id,
                    occurrence_id: None,
                });
            }
            if download_capped && self.budget().claim_download_cap_marker() {
                self.trace.events.push(TraceEventKind::FloodDownloadCap);
                evs.push(self.command_event(serde_json::json!({
                    "protocol_label": self.ctx.protocol_label,
                    "command": "<download cap reached; further download events suppressed>",
                    "flood": "download_cap",
                })));
            }
            evs
        };

        let output = self.run_input(&decoded);
        tracing::debug!(target: "propolis::shell::trace", trace = ?self.trace, "shell line");
        (output, events)
    }

    /// Reset what is scoped to one input line: the work allowance, the trace, the stack of
    /// subshells and the state a previous line's early stop could have left behind. Depth is
    /// balanced by every entry, so it is not reset.
    fn begin_line(&mut self) {
        self.line = LineBudget::new(self.budget().limits().work_per_line);
        self.trace_stack.clear();
        self.trace_nodes = 0;
        self.trace_dropped = 0;
        self.frames
            .retain(|frame| matches!(frame.kind, FrameKind::Level(_)));
        self.stdin = Stdin::Terminal;
        self.deferred_stderr.clear();
        self.last_subst_status = None;
        self.script_depth = 0;
        self.loop_depth = 0;
        self.busybox_depth = 0;
    }

    /// Run one decoded input as a shell reads it, one physical line at a time: each line joins
    /// any lines still open, and once the text is a complete command it is parsed and evaluated
    /// (see `eval`). A line that leaves a construct open prints nothing and the prompt becomes the
    /// continuation prompt until the construct is closed.
    ///
    /// Dispatching a whole line as one command answered a loader's gate line
    /// `ls /home; /bin/busybox BOTNET` with "ls: cannot access '/home;'" and never ran the busybox
    /// probe, so the bot never got the "applet not found" reply it waits for and left before its
    /// download stage (observed live 2026-09-06).
    fn run_input(&mut self, decoded: &str) -> CommandResult {
        if self.context == ShellContext::ExecC {
            // An exec request is one complete command string, as `bash -c` gets it: there is no
            // next line to finish an open construct, so it is parsed whole.
            return self.run_script_text(decoded);
        }
        let mut result = CommandResult::silent(0);
        let mut first = true;
        let text = decoded.strip_suffix('\n').unwrap_or(decoded);
        for physical in text.split('\n') {
            if !first {
                self.advance_shell_line();
            }
            first = false;
            let ran = self.feed_line(physical);
            result.append(ran);
            if result.stop_line {
                break;
            }
        }
        result
    }

    /// Build a `honeypot_command_exec` event carrying `metadata`, stamped from the session context.
    /// Shared by the normal-command path and the two flood-marker paths.
    fn command_event(&self, metadata: serde_json::Value) -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: self.ctx.source_ip,
            wan_ip: self.ctx.wan_ip,
            sensor: self.ctx.protocol_label.clone(),
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
            protocol: PROTO_TCP.into(),
            authenticated: self.ctx.authenticated,
            observed_at: (self.clock)(),
            metadata,
            sample: None,
            session_id: self.ctx.session_id,
            occurrence_id: None,
        }
    }

    /// The registry entry, or fallback decision, for a tokenized command: the decision the trace
    /// reports and, for a registered command, the handler that runs. `dispatch` runs exactly what
    /// this returns, so the two cannot disagree.
    ///
    /// Looks up the command's basename, so a full path (`/bin/busybox`, `/userfs/bin/wget`,
    /// `/bin/sh`) - which IoT loaders routinely use - resolves to the same applet a bare invocation
    /// would, the way a real shell finds it on PATH. Only the command token is normalised;
    /// arguments are untouched. A name the registry lacks is a path invocation when the token has
    /// a slash and not-found otherwise; those two have no handler in the registry.
    fn resolve(&self, parts: &[&str]) -> (HandlerId, Option<HandlerFn>) {
        let Some(first) = parts.first() else {
            return (HandlerId::Empty, None);
        };
        if let Some((id, handler)) =
            Registry::builtin().lookup(command_basename(first), self, parts)
        {
            return (id, Some(handler));
        }
        if first.contains('/') {
            (HandlerId::PathInvoke, None)
        } else {
            (HandlerId::NotFound, None)
        }
    }

    fn resolve_handler(&self, parts: &[&str]) -> HandlerId {
        self.resolve(parts).0
    }

    /// Produce the canned terminal output for one already-tokenized command line.
    /// Every handler returns a static or lightly-interpolated string; none evaluates, spawns, or
    /// otherwise interprets `parts` as code - see the module doc.
    fn dispatch(&mut self, parts: &[&str]) -> CommandResult {
        // One step per entry, so a chain of nested dispatches spends the line's allowance.
        if !self.charge_work(1) {
            let mut stopped = CommandResult::silent(1);
            stopped.stop_line = true;
            return stopped;
        }
        let (id, handler) = self.resolve(parts);
        if let Some(handler) = handler {
            return handler(self, parts);
        }
        match id {
            HandlerId::PathInvoke => self.invoke_path(parts),
            // An interactive bash on Ubuntu prefixes the message with its own name; the bare form
            // matched no real shell.
            HandlerId::NotFound => {
                CommandResult::stderr(127, self.not_found(command_basename(parts[0])))
            }
            // A command made only of redirections has nothing to run; `RedirectionOnly` is the
            // trace's name for it and never comes back from `resolve`.
            _ => CommandResult::silent(0),
        }
    }

    fn builtin_uname(&mut self, parts: &[&str]) -> CommandResult {
        CommandResult::stdout(cmd_uname(parts, self.flavor))
    }

    fn builtin_id(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::stdout(
            "uid=0(root) gid=0(root) groups=0(root)\n"
                .as_bytes()
                .to_vec(),
        )
    }

    fn builtin_whoami(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::stdout(b"root\n".to_vec())
    }

    fn builtin_pwd(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::stdout(format!("{}\n", self.cwd()))
    }

    fn builtin_echo(&mut self, parts: &[&str]) -> CommandResult {
        CommandResult::stdout(cmd_echo(self.echo_dialect(), &parts[1..]))
    }

    /// Which `echo` is running: the busybox applet while one runs, otherwise the active shell
    /// level's builtin.
    fn echo_dialect(&self) -> EchoDialect {
        if self.busybox_depth > 0 {
            return EchoDialect::Busybox;
        }
        match self.active_level() {
            ShellLevel::Bash { .. } => EchoDialect::Bash,
            ShellLevel::Dash { .. } => EchoDialect::Dash,
            ShellLevel::AndroidMksh => EchoDialect::Mksh,
        }
    }

    /// `mount` with no arguments lists the same table `/proc/mounts` exposes; mounting
    /// something as root is a silent success like the other no-output applets.
    fn builtin_mount(&mut self, parts: &[&str]) -> CommandResult {
        CommandResult::stdout(cmd_mount(parts))
    }

    /// Mirai's telnet preamble is `enable`, `system`, `shell`, `sh`: CLI-escape words for
    /// routers. On the bash this box claims, `enable` is a builtin that lists the enabled
    /// builtins; answering "command not found" for it (observed live 2026-09-06) was the
    /// one reply a bash never gives. `system` and `shell` really are unknown to bash.
    fn builtin_enable(&mut self, parts: &[&str]) -> CommandResult {
        CommandResult::stdout(cmd_enable(parts))
    }

    fn builtin_enable_not_found(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::stderr(127, self.not_found("enable"))
    }

    fn builtin_wget(&mut self, parts: &[&str]) -> CommandResult {
        let writes_stdout = matches!(wget_output(parts), WgetOutput::Stdout);
        let out = cmd_wget(parts, (self.clock)());
        let refused = self.save_fetched_file("wget", parts);
        let mut result = if writes_stdout {
            CommandResult::stdout(out)
        } else {
            CommandResult::one(OutputFd::Stderr, 0, out.into_bytes())
        };
        if let Some((name, reason)) = refused {
            // [unverified] wording, from GNU wget's write-failure line.
            result.append(CommandResult::stderr(
                1,
                format!("Cannot write to '{name}' ({reason}).\n"),
            ));
        }
        result
    }

    fn builtin_curl(&mut self, parts: &[&str]) -> CommandResult {
        let out = cmd_curl(parts);
        let refused = self.save_fetched_file("curl", parts);
        let mut result = CommandResult::stdout(out);
        if refused.is_some() {
            // curl's exit code 23 and message for a failed write to the output file.
            result.append(CommandResult::stderr(
                23,
                "curl: (23) Failure writing output to destination\n",
            ));
        }
        result
    }

    fn builtin_ping(&mut self, parts: &[&str]) -> CommandResult {
        CommandResult::stdout(cmd_ping(parts))
    }

    /// tftp/ftpget are BusyBox download applets these loaders use; stay quiet (a real
    /// non-interactive fetch prints nothing on success) rather than "command not found". The
    /// target URL is captured by `download_target` above.
    fn builtin_fetcher(&mut self, parts: &[&str]) -> CommandResult {
        let command = command_basename(parts[0]);
        match self.save_fetched_file(command, parts) {
            // [unverified] wording, in BusyBox's `can't open` style.
            Some((name, reason)) => {
                CommandResult::stderr(1, format!("{command}: can't open '{name}': {reason}\n"))
            }
            None => CommandResult::silent(0),
        }
    }

    /// Filesystem/no-output applets in a loader's drop chain (`chmod +x x`, then `cp`/`rm`/
    /// `mkdir`/`sleep`). A real shell prints nothing on success, and "command not found" for
    /// `chmod` is impossible on any real Linux - it outs the honeypot before the loader ever
    /// executes its payload, costing the capture - so model them as silent successes.
    fn builtin_chmod(&mut self, parts: &[&str]) -> CommandResult {
        // Silent like the real thing, but an executable mode on a file the attacker
        // created is remembered so that running it afterwards succeeds.
        let mut args = parts[1..].iter().filter(|a| !a.starts_with('-'));
        if let Some(mode) = args.next()
            && mode_grants_execute(mode)
        {
            for target in args {
                let path = self.resolve_logical(target);
                self.traced_mark_executable(&path);
            }
        }
        CommandResult::silent(0)
    }

    fn builtin_sleep(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::silent(0)
    }

    /// Already root on this box, so `su` (and `su -`, `su root`) opens another bash
    /// silently. It is still a real nested level: one `exit` returns to the caller.
    fn builtin_su(&mut self, _parts: &[&str]) -> CommandResult {
        let level = match self.active_level() {
            ShellLevel::AndroidMksh => ShellLevel::AndroidMksh,
            _ => ShellLevel::Bash { login: false },
        };
        self.push_level(level);
        CommandResult::silent(0)
    }

    /// A token with a slash names a path, and bash answers for the path, not for PATH:
    /// a file the attacker created and chmod'ed runs (an empty file exits 0 with no
    /// output, which is what the writable-directory probe `>/tmp/d && chmod 777 /tmp/d
    /// && /tmp/d && cd /tmp/` keys its `cd` on), one it did not chmod is refused, and a
    /// path that does not exist is "No such file", never "command not found".
    fn invoke_path(&mut self, parts: &[&str]) -> CommandResult {
        let path = self.resolve_logical(parts[0]);
        if self.fs.is_executable(&path) {
            self.run_saved_executable(parts, &path)
        } else if self.fs.file_exists(&path) {
            CommandResult::stderr(
                126,
                self.shell_error(format_args!("{}: Permission denied", parts[0])),
            )
        } else if self.fs.is_dir(&path) {
            CommandResult::stderr(
                126,
                self.shell_error(format_args!("{}: Is a directory", parts[0])),
            )
        } else {
            // mksh says only "not found" for a path it cannot execute.
            CommandResult::stderr(
                127,
                match self.active_level() {
                    ShellLevel::AndroidMksh => self.not_found(parts[0]),
                    _ => self.shell_error(format_args!("{}: No such file or directory", parts[0])),
                },
            )
        }
    }

    /// Running the executable file at `path`, which nothing here ever does for real. A file the
    /// session made runs as an empty program does. A saved copy of the modeled busybox answers as
    /// busybox does when started under another name: a name beginning `busybox` is the multi-call
    /// binary and takes its applet from the first argument, anything else has no such applet
    /// (`cp /usr/bin/busybox /tmp/.bb && /tmp/.bb PROBE` prints `.bb: applet not found`, status
    /// 127, on the reference system).
    fn run_saved_executable(&mut self, parts: &[&str], path: &str) -> CommandResult {
        let is_busybox = self
            .fs
            .content_and_mode(path)
            .ok()
            .and_then(|(blob, _)| blob.as_elf())
            .is_some_and(|image| binaries::is_busybox(&image));
        if !is_busybox {
            return CommandResult::silent(0);
        }
        let name = command_basename(parts[0]);
        if name.starts_with("busybox") {
            let mut multicall = vec!["busybox"];
            multicall.extend_from_slice(&parts[1..]);
            return self.cmd_busybox(&multicall);
        }
        CommandResult::stderr(127, format!("{name}: applet not found\n"))
    }

    /// Dispatch a command re-entrantly (a busybox applet, `sh -c`) and record it under the
    /// command that caused it.
    ///
    /// Every re-entrant path goes through here, so this is where the depth cap holds. A refusal
    /// is a bounded silent failure (status 1): no real loader nests this deep, the cap is a stack
    /// and DoS guard, and a novel error string would itself be a fingerprint. The trace shows it
    /// fired.
    fn dispatch_nested(&mut self, parts: &[&str]) -> CommandResult {
        let max_depth = self.budget().limits().max_depth;
        if !self.depth.try_enter(max_depth) {
            self.record_hit(BudgetHit::Depth);
            self.note_depth();
            return CommandResult::silent(1);
        }
        self.note_depth();
        let resolved = self.resolve_handler(parts);
        self.trace_open(parts, ParseNode::Simple, resolved);
        let result = self.dispatch(parts);
        self.trace_close(result.status);
        self.depth.leave();
        result
    }

    fn note_depth(&mut self) {
        let reached = self
            .trace
            .budget
            .max_depth_reached
            .max(self.depth.current());
        self.trace.budget.max_depth_reached = reached;
    }

    /// Spend `n` steps or bytes of the line's allowance. False once it is spent, and from then on:
    /// the caller stops the line. The allowance is shared by parsing, expansion, every loop trip
    /// and every nested dispatch of the line.
    fn charge_work(&mut self, n: u64) -> bool {
        let allowed = self.line.charge(n);
        self.sync_budget_trace();
        allowed
    }

    /// Bring the trace's work count and first-hit note up to date with the line budget, after
    /// anything that charged it directly (the parser).
    fn sync_budget_trace(&mut self) {
        self.trace.budget.work_charged = self.line.charged();
        if self.line.take_refusal() {
            self.record_hit(BudgetHit::Work);
        }
    }

    /// Note the first cap this line ran into.
    fn record_hit(&mut self, hit: BudgetHit) {
        self.trace.budget.hit.get_or_insert(hit);
    }

    /// The most nodes one line's trace records; a loop that runs many trips keeps the first.
    const MAX_TRACE_NODES: usize = 512;

    fn trace_open(&mut self, tokens: &[&str], node: ParseNode, resolved: HandlerId) {
        if self.trace_dropped > 0 || self.trace_nodes >= Self::MAX_TRACE_NODES {
            self.trace_dropped = self.trace_dropped.saturating_add(1);
            return;
        }
        self.trace_nodes = self.trace_nodes.saturating_add(1);
        self.trace_stack
            .push(CommandTrace::open(tokens, node, resolved));
    }

    /// Fill in the command opened as a placeholder, once its words are known.
    fn trace_set(&mut self, tokens: &[String], node: ParseNode, resolved: HandlerId) {
        if self.trace_dropped > 0 {
            return;
        }
        if let Some(open) = self.trace_stack.last_mut() {
            open.tokens = tokens.to_vec();
            open.node = node;
            open.resolved = resolved;
        }
    }

    /// Note why the open command was skipped.
    fn trace_unsupported(&mut self, kind: UnsupportedKind) {
        if self.trace_dropped > 0 {
            return;
        }
        if let Some(open) = self.trace_stack.last_mut() {
            open.unsupported = Some(kind);
        }
    }

    /// Close the innermost open command with its `status`, attaching it to its caller or, for the
    /// outermost, to the segment being run.
    fn trace_close(&mut self, status: u8) {
        if self.trace_dropped > 0 {
            self.trace_dropped = self.trace_dropped.saturating_sub(1);
            return;
        }
        let Some(mut command) = self.trace_stack.pop() else {
            return;
        };
        command.status = status;
        match self.trace_stack.last_mut() {
            Some(parent) => parent.reentry.push(command),
            None => {
                if let Some(segment) = self.trace.segments.last_mut() {
                    segment.command = Some(command);
                }
            }
        }
    }

    fn trace_fs(&mut self, effect: FsEffect) {
        if self.trace_dropped > 0 {
            return;
        }
        if let Some(open) = self.trace_stack.last_mut() {
            open.fs_effects.push(effect);
        }
    }

    fn trace_denied(&mut self, path: &str, error: &FsError) {
        match self.budget().take_refusal() {
            Some(Resource::OwnedBytes) => self.record_hit(BudgetHit::OwnedBytes),
            Some(Resource::Nodes) => self.record_hit(BudgetHit::Nodes),
            None => {}
        }
        self.trace_fs(FsEffect::Denied {
            path: path.to_string(),
            why: FsDenied::from(error),
        });
    }

    fn traced_create(&mut self, path: &str) -> Result<(), FsError> {
        let result = self.fs.create_file(path);
        match &result {
            Ok(()) => self.trace_fs(FsEffect::Created {
                path: path.to_string(),
                bytes: 0,
            }),
            Err(error) => self.trace_denied(path, error),
        }
        result
    }

    fn traced_write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        let result = self.fs.write_file(path, bytes);
        match &result {
            Ok(()) => self.trace_fs(FsEffect::Wrote {
                path: path.to_string(),
                bytes: bytes.len(),
            }),
            Err(error) => self.trace_denied(path, error),
        }
        result
    }

    fn traced_write_blob(&mut self, path: &str, blob: Blob, mode: u32) -> Result<(), FsError> {
        let len = usize::try_from(blob.len()).unwrap_or(usize::MAX);
        let result = self.fs.write_blob(path, blob, mode);
        match &result {
            Ok(()) => self.trace_fs(FsEffect::Wrote {
                path: path.to_string(),
                bytes: len,
            }),
            Err(error) => self.trace_denied(path, error),
        }
        result
    }

    fn traced_remove(&mut self, path: &str) -> Result<bool, FsError> {
        let result = self.fs.remove_path(path);
        match &result {
            Ok(existed) => self.trace_fs(FsEffect::Removed {
                path: path.to_string(),
                existed: *existed,
            }),
            Err(error) => self.trace_denied(path, error),
        }
        result
    }

    fn traced_make_dir(&mut self, path: &str) -> Result<(), FsError> {
        let result = self.fs.make_dir(path);
        match &result {
            Ok(()) => self.trace_fs(FsEffect::MadeDir {
                path: path.to_string(),
            }),
            Err(error) => self.trace_denied(path, error),
        }
        result
    }

    /// `FakeFs::mark_executable` refuses silently (a baked-in file keeps its mode), so only an
    /// applied change is recorded.
    fn traced_mark_executable(&mut self, path: &str) {
        if self.fs.mark_executable(path) {
            self.trace_fs(FsEffect::MarkedExecutable {
                path: path.to_string(),
            });
        }
    }

    /// Resolve `arg` to an absolute logical path: joined onto `cwd` unless it starts with `/`, then
    /// normalised lexically. Symlinks stay unresolved here, so `cd /var/run` leaves `pwd` at
    /// `/var/run` as bash's logical mode does; [`FakeFs`] resolves them physically per operation.
    fn resolve_logical(&mut self, arg: &str) -> String {
        let normalized = self.normalize_logical(arg);
        self.alias_own_pid(normalized)
    }

    /// The shell's own `/proc/<pid>` is `/proc/self` to the shell.
    fn alias_own_pid(&self, normalized: String) -> String {
        let own = format!("/proc/{}", self.state().pid);
        match normalized.strip_prefix(&own) {
            Some(rest) if rest.is_empty() || rest.starts_with('/') => format!("/proc/self{rest}"),
            _ => normalized,
        }
    }

    /// [`Self::resolve_logical`] for a path a process is about to open. `/proc/self/exe` is the
    /// executable of the process that opens it, so it resolves against `reader`, the command name
    /// of that process (`None` when it has no file behind it), and `/proc/<pid>/exe` of an open
    /// shell resolves against that shell. Everything else resolves as any other path. Nothing
    /// here reads a file of the host: the result is a path into the fake filesystem.
    fn resolve_reading(&mut self, arg: &str, reader: Option<&str>) -> String {
        let normalized = self.normalize_logical(arg);
        // Only the Ubuntu persona has binaries behind these names; the phone's would be ARM.
        if self.flavor == ShellFlavor::Bash {
            if normalized == "/proc/self/exe" {
                if let Some(path) = reader.and_then(resolve_proc_self) {
                    return path.to_string();
                }
            } else if let Some(pid) = normalized
                .strip_prefix("/proc/")
                .and_then(|rest| rest.strip_suffix("/exe"))
                .and_then(|pid| pid.parse::<u32>().ok())
                && let Some(path) = self.shell_exe_of_pid(pid).and_then(resolve_proc_self)
            {
                return path.to_string();
            }
        }
        self.alias_own_pid(normalized)
    }

    /// The command name of the process reading a file named by `argv0`: busybox while an applet
    /// runs, else the command's own name.
    fn reader_of<'a>(&self, argv0: &'a str) -> &'a str {
        if self.busybox_depth > 0 {
            "busybox"
        } else {
            command_basename(argv0)
        }
    }

    /// The command name of the shell the innermost level is running: what a redirection opened by
    /// the shell itself sees as `/proc/self/exe`.
    fn shell_reader(&self) -> Option<&'static str> {
        level_command(self.active_level())
    }

    /// The command name of the open shell whose process id is `pid`.
    fn shell_exe_of_pid(&self, pid: u32) -> Option<&'static str> {
        self.frames
            .iter()
            .find(|frame| frame.state.pid == pid)
            .and_then(|frame| match frame.kind {
                FrameKind::Level(level) | FrameKind::Script(level) => level_command(level),
                FrameKind::Subshell => None,
            })
    }

    /// [`Self::resolve_logical`] without the `/proc/<pid>` alias.
    fn normalize_logical(&mut self, arg: &str) -> String {
        let joined = if arg.starts_with('/') {
            arg.to_string()
        } else {
            format!("{}/{arg}", self.cwd().trim_end_matches('/'))
        };
        // Normalise the way a kernel resolves a path: `.` and an empty segment (a trailing or
        // doubled slash) drop out, `..` climbs. Without this `./payload` - the form every
        // loader runs its dropped file with - resolved to a path the model never held.
        let mut segments: Vec<&str> = Vec::new();
        for segment in joined.split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                name => segments.push(name),
            }
        }
        let resolved = if segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segments.join("/"))
        };
        // The result is already built and its size is bounded by the line; an exhausted allowance
        // is noted here and stops the line at the next checkpoint.
        self.charge_work(len_u64(segments.len()));
        resolved
    }

    /// Record the file a fetch command saved, with the body this shell claims to have fetched,
    /// so the `chmod +x` and `./payload` a loader runs next find something there. A fetch that
    /// printed to stdout saves nothing, as the real command does not.
    ///
    /// A save the budget refuses returns the sanitized name and the kernel's reason so the command
    /// can say so. Any other refusal stays silent, as it always has.
    fn save_fetched_file(&mut self, cmd: &str, parts: &[&str]) -> Option<(String, &'static str)> {
        let name = download_save_name(cmd, parts)?;
        let path = self.resolve_logical(&name);
        match self.traced_write_file(&path, FETCHED_BODY.as_bytes()) {
            Ok(()) => None,
            Err(error) => budget_refusal_text(&error)
                .map(|reason| (sanitize_value(&name, MAX_URL_LEN), reason)),
        }
    }

    /// Open a shell level that reads the terminal, the way `sh` and `su` do: it inherits the
    /// exported variables and the working directory, and has a process id of its own.
    fn push_level(&mut self, level: ShellLevel) {
        let pid = self.pids.next();
        let state = self.state().child(pid);
        self.frames.push(Frame {
            kind: FrameKind::Level(level),
            state,
        });
    }

    /// Open a shell level that runs one script and ends with it.
    fn push_script_level(&mut self, level: ShellLevel) {
        let pid = self.pids.next();
        let state = self.state().child(pid);
        self.frames.push(Frame {
            kind: FrameKind::Script(level),
            state,
        });
    }

    /// Leave the innermost shell level that reads the terminal, or end the session from the login
    /// shell. `status` is what `exit` was given.
    fn exit_shell(&mut self, status: u8) -> CommandResult {
        if self.open_levels() > 1 {
            let popped = self.frames.pop().map(|frame| frame.kind);
            let output = if matches!(popped, Some(FrameKind::Level(ShellLevel::Bash { .. }))) {
                b"exit\n".to_vec()
            } else {
                Vec::new()
            };
            return CommandResult::shell_exit(status, output, false);
        }

        let output = if matches!(self.active_level(), ShellLevel::Bash { login: true }) {
            b"logout\n".to_vec()
        } else {
            Vec::new()
        };
        CommandResult::shell_exit(status, output, true)
    }

    fn logout_shell(&mut self) -> CommandResult {
        match self.active_level() {
            ShellLevel::Bash { login: true } if self.open_levels() == 1 => {
                CommandResult::shell_exit(0, b"logout\n".to_vec(), true)
            }
            ShellLevel::Bash { .. } => {
                CommandResult::stderr(1, self.shell_error("logout: not login shell: use `exit'"))
            }
            ShellLevel::Dash { .. } | ShellLevel::AndroidMksh => {
                CommandResult::stderr(127, self.not_found("logout"))
            }
        }
    }

    /// `cp [-flags] SRC DST`. The destination is a real copy for the rest of the session, and
    /// keeps the source's executable bit as a real `cp` does.
    fn cmd_cp(&mut self, parts: &[&str]) -> CommandResult {
        let operands: Vec<&str> = parts[1..]
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-'))
            .collect();
        let (Some(&src), Some(&dst)) = (operands.first(), operands.get(1)) else {
            return CommandResult::stderr(1, "cp: missing destination file operand\n");
        };
        let reader = self.reader_of(parts[0]);
        let src_path = self.resolve_reading(src, Some(reader));
        let Ok((blob, mode)) = self.fs.content_and_mode(&src_path) else {
            return CommandResult::stderr(
                1,
                format!("cp: cannot stat '{src}': No such file or directory\n"),
            );
        };
        let mut dst_path = self.resolve_logical(dst);
        if self.fs.is_dir(&dst_path) {
            dst_path = format!(
                "{}/{}",
                dst_path.trim_end_matches('/'),
                command_basename(src)
            );
        }
        match self.traced_write_blob(&dst_path, blob, mode) {
            Ok(()) => {}
            Err(FsError::ReadOnly) => {
                return CommandResult::stderr(
                    1,
                    format!("cp: cannot create regular file '{dst}': Read-only file system\n"),
                );
            }
            Err(error) => {
                let reason = budget_refusal_text(&error).unwrap_or("No such file or directory");
                return CommandResult::stderr(
                    1,
                    format!("cp: cannot create regular file '{dst}': {reason}\n"),
                );
            }
        }
        CommandResult::silent(0)
    }

    /// `rm [-rf] PATH...`. A removed file stops being readable and listed; `-f` stays silent on
    /// a path that was not there, as the real one does.
    fn cmd_rm(&mut self, parts: &[&str]) -> CommandResult {
        let flags: Vec<&str> = parts[1..]
            .iter()
            .copied()
            .filter(|a| a.starts_with('-'))
            .collect();
        let force = flags.iter().any(|f| f.contains('f'));
        let recursive = flags.iter().any(|f| f.contains('r') || f.contains('R'));
        let targets: Vec<&str> = parts[1..]
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-'))
            .collect();
        if targets.is_empty() {
            return if force {
                CommandResult::silent(0)
            } else {
                CommandResult::stderr(1, "rm: missing operand\n")
            };
        }
        let mut out = String::new();
        for target in targets {
            let path = self.resolve_logical(target);
            if self.fs.is_dir(&path) && !recursive {
                out.push_str(&format!("rm: cannot remove '{target}': Is a directory\n"));
                continue;
            }
            match self.traced_remove(&path) {
                Ok(true) => {}
                Ok(false) if force => {}
                Ok(false) => out.push_str(&format!(
                    "rm: cannot remove '{target}': No such file or directory\n"
                )),
                Err(_) => out.push_str(&format!(
                    "rm: cannot remove '{target}': Read-only file system\n"
                )),
            }
        }
        if out.is_empty() {
            CommandResult::silent(0)
        } else {
            CommandResult::stderr(1, out)
        }
    }

    /// `mkdir [-p] DIR...`. The new directory is one `cd` and `ls` accept afterwards.
    fn cmd_mkdir(&mut self, parts: &[&str]) -> CommandResult {
        let parents = parts[1..]
            .iter()
            .any(|a| a.starts_with('-') && a.contains('p'));
        let targets: Vec<&str> = parts[1..]
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-'))
            .collect();
        if targets.is_empty() {
            return CommandResult::stderr(1, "mkdir: missing operand\n");
        }
        let mut out = String::new();
        for target in targets {
            let path = self.resolve_logical(target);
            match self.traced_make_dir(&path) {
                Ok(()) => {}
                // `-p` is silent about an existing directory and creates missing parents.
                Err(FsError::ReadOnly) => out.push_str(&format!(
                    "mkdir: cannot create directory '{target}': Read-only file system\n"
                )),
                Err(error) if budget_refusal_text(&error).is_some() => {
                    let reason = budget_refusal_text(&error).unwrap_or_default();
                    out.push_str(&format!(
                        "mkdir: cannot create directory '{target}': {reason}\n"
                    ));
                }
                Err(_) if parents => {
                    let mut built = String::new();
                    for segment in path.trim_start_matches('/').split('/') {
                        built.push('/');
                        built.push_str(segment);
                        // An existing parent is expected; a refusal of room or name is not.
                        if let Err(error) = self.traced_make_dir(&built)
                            && let Some(reason) = budget_refusal_text(&error)
                        {
                            out.push_str(&format!(
                                "mkdir: cannot create directory '{target}': {reason}\n"
                            ));
                            break;
                        }
                    }
                }
                Err(FsError::Exists) => out.push_str(&format!(
                    "mkdir: cannot create directory '{target}': File exists\n"
                )),
                Err(_) => out.push_str(&format!(
                    "mkdir: cannot create directory '{target}': No such file or directory\n"
                )),
            }
        }
        if out.is_empty() {
            CommandResult::silent(0)
        } else {
            CommandResult::stderr(1, out)
        }
    }

    fn cmd_ls(&mut self, parts: &[&str]) -> CommandResult {
        let cwd = self.cwd().to_string();
        let target = first_non_flag_arg(&parts[1..]).unwrap_or(cwd.as_str());
        let show_hidden = parts[1..]
            .iter()
            .any(|a| a.starts_with('-') && (a.contains('a') || a.contains('A')));
        let listed = self.resolve_logical(target);
        match self.fs.list_dir(&listed) {
            Some(mut entries) => {
                // A real `ls` hides dotfiles without `-a` and sorts what it prints. Listing the
                // `.x` probe files a loader had just dropped was a tell on both counts.
                if !show_hidden {
                    entries.retain(|name| !name.starts_with('.'));
                }
                entries.sort();
                if entries.is_empty() {
                    CommandResult::silent(0)
                } else {
                    CommandResult::stdout(entries.join("  ") + "\n")
                }
            }
            None => CommandResult::stderr(
                2,
                format!("ls: cannot access '{target}': No such file or directory\n"),
            ),
        }
    }

    /// `sh` / `bash`. A bare invocation pushes a nested interactive shell level, or, when a
    /// script is piped in, runs it; `sh -c "CMD"` and `sh FILE` run their text in a shell level of
    /// their own that ends with it, since loaders stage their payload that way.
    fn cmd_shell_spawn(&mut self, parts: &[&str]) -> CommandResult {
        let shell = command_basename(parts[0]);
        let script_at = parts.iter().position(|&p| p == "-c");
        let script = script_at.and_then(|pos| parts.get(pos + 1));
        if let (Some(script), Some(at)) = (script, script_at) {
            if script.trim().is_empty() {
                return CommandResult::silent(0);
            }
            // The operands after the script are `$0` and then the positional parameters.
            let operands = parts.get(at + 2..).unwrap_or(&[]);
            return self.run_shell_text(
                shell,
                script,
                operands.first().copied(),
                operands.get(1..).unwrap_or(&[]),
            );
        }
        if script.is_none()
            && let Some(file) = first_non_flag_arg(&parts[1..])
        {
            let after = parts
                .iter()
                .position(|p| p == &file)
                .map_or(parts.len(), |i| i + 1);
            let args = parts.get(after..).unwrap_or(&[]);
            return self.run_sh_file(shell, file, args);
        }
        if parts.len() == 1 {
            if let Some(text) = self.take_piped_script() {
                return self.run_shell_text(shell, &text, None, &[]);
            }
            let level = self.spawned_level(shell, 0);
            self.push_level(level);
        }
        CommandResult::silent(0)
    }

    /// Run `text` as a script in a shell level of its own, one recursive entry under the depth cap.
    /// The level inherits the exported variables and working directory; `argv0` and `args` are
    /// its `$0` and positional parameters.
    fn run_shell_text(
        &mut self,
        shell: &str,
        text: &str,
        argv0: Option<&str>,
        args: &[&str],
    ) -> CommandResult {
        let max_depth = self.budget().limits().max_depth;
        if !self.depth.try_enter(max_depth) {
            self.record_hit(BudgetHit::Depth);
            self.note_depth();
            return CommandResult::silent(1);
        }
        self.note_depth();
        let level = self.spawned_level(shell, 1);
        let caller_frames = self.frames.len();
        self.push_script_level(level);
        let state = self.state_mut();
        state.argv0 = argv0.map(str::to_string);
        state.positional = args.iter().map(|a| (*a).to_string()).collect();
        // A script is a shell process of its own: the commands in it start as separate processes,
        // not as applets of the busybox that started the script.
        let applets = std::mem::take(&mut self.busybox_depth);
        let result = self.run_script(text);
        self.busybox_depth = applets;
        self.frames.truncate(caller_frames);
        self.depth.leave();
        result
    }

    /// `sh|bash|dash|ash FILE`. `shell_name` is the invoked command's basename: bash reports its own
    /// open error with 127, the dash family dash's with 2. The spawned shell reports at its own
    /// line 0 whatever the caller's line counter says, and pushes no persistent level, like
    /// `sh -c`.
    fn run_sh_file(&mut self, shell_name: &str, file: &str, args: &[&str]) -> CommandResult {
        let path = self.resolve_logical(file);
        match self.fs.read_all(&path, READ_CAP) {
            Ok(bytes) => {
                if !self.charge_work(len_u64(bytes.len())) {
                    let mut stopped = CommandResult::silent(1);
                    stopped.stop_line = true;
                    return stopped;
                }
                let content = String::from_utf8_lossy(&bytes);
                self.run_shell_text(shell_name, &content, Some(file), args)
            }
            Err(_) if shell_name == "bash" => {
                // [unverified] wording and status: no `bash FILE` capture exists yet.
                CommandResult::stderr(127, format!("bash: {file}: No such file or directory\n"))
            }
            Err(_) => {
                CommandResult::stderr(2, format!("sh: 0: cannot open {file}: No such file\n"))
            }
        }
    }

    fn spawned_level(&self, command: &str, dash_line: u64) -> ShellLevel {
        match (self.active_level(), command) {
            (ShellLevel::AndroidMksh, _) => ShellLevel::AndroidMksh,
            (_, "bash") => ShellLevel::Bash { login: false },
            _ => ShellLevel::Dash { line: dash_line },
        }
    }

    /// `busybox`. Bare invocation prints the multi-call banner. `busybox <applet> ...` runs an
    /// applet the banner lists: through its modeled handler when there is one, else as a silent
    /// success (the applet exists, and its usage text and behavior are not captured, so nothing
    /// is invented). A name the banner does not list returns BusyBox's exact "<applet>: applet not
    /// found" - the reply Mirai/Gafgyt check for to confirm a real busybox before delivering.
    fn cmd_busybox(&mut self, parts: &[&str]) -> CommandResult {
        match parts.get(1).copied() {
            None => CommandResult::stdout(busybox::banner()),
            Some(applet) if busybox::is_applet(applet) => {
                if self.resolve(&parts[1..]).1.is_none() {
                    return CommandResult::silent(0);
                }
                self.busybox_depth = self.busybox_depth.saturating_add(1);
                let result = self.dispatch_nested(&parts[1..]);
                self.busybox_depth = self.busybox_depth.saturating_sub(1);
                result
            }
            Some(applet) => CommandResult::stderr(127, format!("{applet}: applet not found\n")),
        }
    }
}

/// The kernel's wording for the refusals a budget or name limit produces, or `None` for any other
/// error.
fn budget_refusal_text(error: &FsError) -> Option<&'static str> {
    match error {
        FsError::NoSpace => Some("No space left on device"),
        FsError::FileTooLarge => Some("File too large"),
        FsError::NameTooLong => Some("File name too long"),
        _ => None,
    }
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Ubuntu 22.04's interactive command-not-found handler for the names most often used to escape
/// router CLIs. Package ordering is a captured persona detail, not a claim that every Ubuntu host
/// prints suggestions in the same order.
fn login_command_not_found(name: &str) -> Option<&'static str> {
    match name {
        "start" => Some(
            "Command 'start' not found, did you mean:\n  command 'tart' from deb tart (3.10-1build1)\n  command 'stat' from deb coreutils (8.32-4.1ubuntu1.3)\n  command 'rstart' from deb x11-session-utils (7.7+4build2)\n  command 'kstart' from deb kde-cli-tools (4:5.24.4-0ubuntu1)\n  command 'startx' from deb xinit (1.4.1-0ubuntu4)\nTry: apt install <deb name>\n",
        ),
        "config" => Some(
            "Command 'config' not found, did you mean:\n  command 'cconfig' from deb xrootd-server (5.4.1-1)\n  command 'mconfig' from deb mono-devel (6.8.0.105+dfsg-3.2)\n  command 'vconfig' from deb vlan (2.0.5ubuntu5)\n  command 'iconfig' from deb ipmiutil (3.1.8-1)\n  command 'kconfig' from deb kconfig-frontends (4.11.0.1+dfsg-6)\n  command 'kconfig' from deb kconfig-frontends-nox (4.11.0.1+dfsg-6)\n  command 'fconfig' from deb redboot-tools (0.7build4)\nTry: apt install <deb name>\n",
        ),
        "system" => Some(
            "Command 'system' not found, did you mean:\n  command 'system3' from deb simh (3.8.1-6.1)\n  command 'systemd' from deb systemd (249.11-0ubuntu3.21)\nTry: apt install <deb name>\n",
        ),
        "shell" => Some(
            "Command 'shell' not found, did you mean:\n  command 'bshell' from deb avahi-ui-utils (0.8-5ubuntu5.5)\n  command 'rshell' from deb pyboard-rshell (0.0.31-0ubuntu1)\n  command 'spell' from deb spell (1.0-24.2)\n  command 'shelr' from deb shelr (0.16.3-2.1)\n  command 'jshell' from deb openjdk-11-jdk-headless (11.0.31+11-1ubuntu1~22.04.2)\n  command 'jshell' from deb openjdk-17-jdk-headless (17.0.19+10-1~22.04.2)\n  command 'jshell' from deb openjdk-18-jdk-headless (18.0.2+9-2~22.04)\n  command 'jshell' from deb openjdk-21-jdk-headless (21.0.11+10-1~22.04.2)\n  command 'jshell' from deb openjdk-25-jdk-headless (25.0.3+9-2~22.04.2)\nTry: apt install <deb name>\n",
        ),
        "ifconfig" => Some(
            "Command 'ifconfig' not found, but can be installed with:\napt install net-tools\n",
        ),
        "tftp" => Some(
            "Command 'tftp' not found, but can be installed with:\napt install tftp-hpa  # version 5.2+20150808-1.2build2, or\napt install tftp      # version 0.17-23ubuntu1\n",
        ),
        "ftpget" => Some(
            "Command 'ftpget' not found, did you mean:\n  command 'lftpget' from deb lftp (4.9.2-1build1)\nTry: apt install <deb name>\n",
        ),
        _ => None,
    }
}

/// The command token with any leading path stripped (`/bin/busybox` -> `busybox`), so a full-path
/// invocation resolves the way a real shell finds a command on PATH. Shared by [`FakeShell::dispatch`]
/// and [`download_target`] so they agree on what a command is; without this the two drift and a
/// full-path fetch answers in-persona while its download evidence is silently dropped.
/// A line dominated by non-printable-ASCII characters is a binary flood (an SSH/telnet channel
/// tunneling binary, or a fuzzer), not a shell command. `String::from_utf8_lossy` turns invalid
/// bytes into U+FFFD, and high bytes that do not form valid UTF-8 land there too, so a genuine
/// binary stream is mostly non-printable while a real command is ~all printable ASCII. A `> 30%`
/// non-printable ratio flags the former without catching an ordinary command carrying a stray byte.
/// Whether a raw capture buffer looks like a binary payload rather than typed input.
///
/// Same 30%-non-printable rule [`is_binary_line`] applies to one decoded line, but over raw bytes
/// and tolerating the line terminators a session buffer carries. A sensor needs this because the
/// per-line flag is only raised once a COMPLETE line has been assembled and dispatched to the
/// shell: a dropper streaming a payload with no newline yet, cut off when the listener cancels
/// the session, would otherwise hold a buffer full of binary that no flag had claimed, and the
/// capture would be discarded as ordinary typing.
pub fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let nonprintable = bytes
        .iter()
        .filter(|&&b| !matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
        .count();
    nonprintable * 100 / bytes.len() > 30
}

fn is_binary_line(s: &str) -> bool {
    let total = s.chars().count();
    if total == 0 {
        return false;
    }
    let nonprintable = s
        .chars()
        .filter(|&c| c != '\t' && !(' '..='~').contains(&c))
        .count();
    nonprintable * 100 / total > 30
}

fn command_basename(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

/// The download target of a fetch command, or `None` if the line is not one. Covers the direct
/// fetchers and the BusyBox forms (`busybox wget URL`, `busybox tftp ...`) IoT loaders favour, so
/// the `honeypot_file_download` event fires for those too - not only a bare `wget`/`curl`.
///
/// `wget`/`curl` take a URL token, returned as-is. `tftp` and `ftpget` take a HOST and a FILE as
/// separate arguments with no scheme, so the URL is synthesized (`tftp://host/file`,
/// `ftp://host/file`): recording just the first non-flag token - which was the host for one flag
/// order and the filename for another - produced a scheme-less fragment the fetcher could not
/// parse, so a Mirai loader's `tftp -g HOST -r FILE` was logged and then silently never fetched.
///
/// The top-level command token is basename-resolved like `dispatch`, so `/bin/busybox tftp ...` is
/// captured. The busybox *applet* token is matched raw, exactly like `cmd_busybox`/`busybox::is_applet`
/// do: real busybox resolves an applet by bare name only, so `busybox /bin/tftp` is "applet not
/// found" and must not be recorded as a fetch the persona did not answer in character.
fn download_target(parts: &[&str]) -> Option<String> {
    const FETCHERS: [&str; 4] = ["wget", "curl", "tftp", "ftpget"];
    // BusyBox ships wget/tftp/ftpget applets but NOT curl, so `busybox curl` is "applet not found"
    // (see `busybox::applets`) and must not be recorded as a fetch the persona did not answer in
    // character - the same principle the full-path `busybox /bin/tftp` case relies on.
    const BUSYBOX_FETCHERS: [&str; 3] = ["wget", "tftp", "ftpget"];
    let (cmd, args) = match parts.first().map(|c| command_basename(c)) {
        Some(cmd) if FETCHERS.contains(&cmd) => (cmd, &parts[1..]),
        Some("busybox") if parts.get(1).is_some_and(|a| BUSYBOX_FETCHERS.contains(a)) => {
            (parts[1], &parts[2..])
        }
        _ => return None,
    };
    match cmd {
        "tftp" => tftp_url(args),
        "ftpget" => ftpget_url(args),
        _ => fetch_url_arg(cmd, args).map(str::to_string),
    }
}

/// The URL argument of a `wget`/`curl` invocation. A token carrying a scheme wins outright,
/// whatever its position. Failing that, the first positional that is not the VALUE of an option:
/// `wget -q -O 1.sh http://h/1.sh` names its output file before the URL, and a parser that only
/// skips dash-prefixed tokens returned `1.sh` as the download - a bare filename the fetcher could
/// never retrieve (observed live 2026-09-03 on a Mirai loader line). Only the options that take a
/// separate value are consumed; a value attached to its flag (`-O-`, `-qO-`, `-o1.sh`) is not.
fn fetch_url_arg<'a>(cmd: &str, args: &[&'a str]) -> Option<&'a str> {
    if let Some(url) = args.iter().find(|a| a.contains("://")) {
        return Some(url);
    }
    // Short options that take the next token as their value. Everything else is a bare switch.
    let short_with_value: &[char] = match cmd {
        "wget" => &['O', 'o', 'P', 'T', 't', 'U', 'w', 'a', 'i', 'B', 'e'],
        _ => &[
            'o', 'H', 'd', 'A', 'X', 'u', 'm', 'e', 'x', 'T', 'b', 'c', 'K', 'w',
        ],
    };
    let mut it = args.iter();
    while let Some(&a) = it.next() {
        if let Some(long) = a.strip_prefix("--") {
            // `--output=x` carries its value; `--output x` does not.
            if !long.contains('=') && LONG_OPTIONS_WITH_VALUE.contains(&long) {
                it.next();
            }
        } else if let Some(cluster) = a.strip_prefix('-')
            && !cluster.is_empty()
        {
            // In a cluster like `-qO`, a value-taking letter with nothing after it consumes the
            // next token; with characters after it (`-qO-`, `-so1.sh`) the value is attached.
            let mut chars = cluster.chars();
            while let Some(c) = chars.next() {
                if short_with_value.contains(&c) {
                    if chars.as_str().is_empty() {
                        it.next();
                    }
                    break;
                }
            }
        } else {
            return Some(a);
        }
    }
    None
}

const LONG_OPTIONS_WITH_VALUE: [&str; 18] = [
    "output-document",
    "output-file",
    "directory-prefix",
    "timeout",
    "tries",
    "user-agent",
    "wait",
    "header",
    "post-data",
    "output",
    "data",
    "request",
    "user",
    "max-time",
    "referer",
    "proxy",
    "upload-file",
    "cookie",
];

/// The distinct URLs a line retrieves, in order of first appearance. A loader line is rarely one
/// simple command: Mirai wraps every fetcher in a `( a || busybox a ) > f; chmod ...` fallback
/// chain, so the fetch verb is never the line's first token, and a whole-line `download_target`
/// saw `(tftp` and dropped the retrieval (observed live 2026-09-02: the wget line of that chain
/// was captured only because the raw-line scan found its `http://`). Each simple command is
/// examined on its own; the fallback pair `wget X || busybox wget X` names one URL and yields
/// one event. The raw-line scheme scan stays as the last resort for a URL inside quotes
/// (`sh -c "wget http://h/x; ..."`), where the separators belong to a quoted script.
fn download_targets(decoded: &str) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for tokens in simple_commands(decoded) {
        if let Some(url) = download_target(&tokens)
            && !urls.contains(&url)
        {
            urls.push(url);
        }
    }
    if urls.is_empty()
        && let Some(url) = url_if_fetch_line(decoded)
    {
        urls.push(url.to_string());
    }
    urls
}

/// Split a line into its simple commands' token lists at `;`, `|`, `||`, `&&`, a background `&`,
/// `(`, `)`, backticks and newlines, cutting each command at its first redirection (`> t`,
/// `2>&1`, `< x`) since a redirection target is not an argument. A `&` inside a URL query
/// (`?a=1&b=2`) is not a separator. Quotes are not honoured: the split serves URL capture, not
/// execution, and a URL never contains a bare separator.
fn simple_commands(line: &str) -> Vec<Vec<&str>> {
    let bytes = line.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let is_sep = match b {
            b';' | b'|' | b'(' | b')' | b'`' | b'\n' => true,
            b'&' => bytes
                .get(i + 1)
                .is_none_or(|&n| n == b'&' || n.is_ascii_whitespace()),
            _ => false,
        };
        if is_sep {
            segments.push(&line[start..i]);
            start = i + 1;
        }
    }
    segments.push(&line[start..]);
    segments
        .into_iter()
        .map(|seg| {
            seg.split_whitespace()
                .take_while(|t| !is_redirection(t))
                .collect::<Vec<_>>()
        })
        .filter(|tokens| !tokens.is_empty())
        .collect()
}

fn is_redirection(token: &str) -> bool {
    let t = token.trim_start_matches(|c: char| c.is_ascii_digit());
    t.starts_with('>') || t.starts_with('<')
}

/// The control operator that precedes a segment of an input line, deciding whether it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ControlOp {
    /// `;`, a background `&`, a newline, or the start of the line: run unconditionally.
    Seq,
    /// `&&`: run only if the previous command succeeded.
    And,
    /// `||`: run only if the previous command failed.
    Or,
}

/// `tftp [-g|-p] [-l LOCAL] [-r REMOTE] HOST [PORT]` (BusyBox) -> `tftp://HOST[:PORT]/REMOTE`.
/// `-r`/`-l` consume the next token; other flags do not. Flag order varies between loaders
/// (`-g -r FILE HOST` and `-g HOST -r FILE` are both common), so positionals are collected rather
/// than indexed. With only `-l` given, BusyBox uses it as the remote name too. No host -> `None`;
/// a host with no file still yields `tftp://HOST`, since the retrieval host is evidence on its own.
fn tftp_url(args: &[&str]) -> Option<String> {
    let mut remote = None;
    let mut local = None;
    let mut positional = Vec::new();
    let mut it = args.iter();
    while let Some(&a) = it.next() {
        match a {
            "-r" => remote = it.next().copied(),
            "-l" => local = it.next().copied(),
            _ if a.starts_with('-') => {}
            _ => positional.push(a),
        }
    }
    let host = *positional.first()?;
    let port = positional.get(1);
    let file = remote.or(local);
    Some(join_fetch_url("tftp", host, port.copied(), file))
}

/// `ftpget [-c] [-v] [-u USER] [-p PASS] [-P PORT] HOST [LOCAL] REMOTE` (BusyBox) ->
/// `ftp://HOST[:PORT]/REMOTE`. `-u`/`-p`/`-P` consume the next token. The remote name is the LAST
/// positional whenever at least two are present (`HOST REMOTE` or `HOST LOCAL REMOTE`). The
/// fetcher does not retrieve `ftp://` (unsupported scheme, by design), but the retrieval attempt is
/// still recorded accurately rather than as a bare host.
fn ftpget_url(args: &[&str]) -> Option<String> {
    let mut port = None;
    let mut positional = Vec::new();
    let mut it = args.iter();
    while let Some(&a) = it.next() {
        match a {
            "-u" | "-p" => {
                it.next();
            }
            "-P" => port = it.next().copied(),
            _ if a.starts_with('-') => {}
            _ => positional.push(a),
        }
    }
    let host = *positional.first()?;
    let file = if positional.len() >= 2 {
        positional.last().copied()
    } else {
        None
    };
    Some(join_fetch_url("ftp", host, port, file))
}

fn join_fetch_url(scheme: &str, host: &str, port: Option<&str>, file: Option<&str>) -> String {
    let mut url = format!("{scheme}://{host}");
    if let Some(p) = port {
        url.push(':');
        url.push_str(p);
    }
    if let Some(f) = file {
        url.push('/');
        url.push_str(f.trim_start_matches('/'));
    }
    url
}

/// Recover a download URL from a command line that a fetch command hides from token-level parsing -
/// most importantly `sh -c "wget http://h/x; chmod +x x; ./x"`, where the whitespace tokenizer
/// splits the quoted script apart. Only fires when a fetch verb is present, then returns the first
/// `http(s)://`/`tftp://`/`ftp://` token, so an ordinary `echo http://...` is not miscounted as a
/// download.
fn url_if_fetch_line(line: &str) -> Option<&str> {
    if !["wget", "curl", "tftp", "ftpget"]
        .iter()
        .any(|v| line.contains(v))
    {
        return None;
    }
    for scheme in ["http://", "https://", "tftp://", "ftp://"] {
        if let Some(start) = line.find(scheme) {
            let rest = &line[start..];
            let end = rest
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '|' | '`' | '&')
                })
                .unwrap_or(rest.len());
            return Some(&rest[..end]);
        }
    }
    None
}

/// Whether a `chmod` mode adds execute permission: a symbolic mode naming `x` (`+x`, `a+x`,
/// `u+rwx`) or an octal mode with an execute bit set in any of its last three digits (`777`,
/// `755`, `0755`).
fn mode_grants_execute(mode: &str) -> bool {
    if mode.chars().all(|c| c.is_ascii_digit()) {
        let digits: Vec<u32> = mode.chars().filter_map(|c| c.to_digit(8)).collect();
        let perms = &digits[digits.len().saturating_sub(3)..];
        return perms.iter().any(|d| d & 1 == 1);
    }
    mode.contains('x') && !mode.contains('-')
}

/// bash 5.1's enabled builtins, in the order `enable` prints them.
const BASH_BUILTINS: [&str; 61] = [
    ".",
    ":",
    "[",
    "alias",
    "bg",
    "bind",
    "break",
    "builtin",
    "caller",
    "cd",
    "command",
    "compgen",
    "complete",
    "compopt",
    "continue",
    "declare",
    "dirs",
    "disown",
    "echo",
    "enable",
    "eval",
    "exec",
    "exit",
    "export",
    "false",
    "fc",
    "fg",
    "getopts",
    "hash",
    "help",
    "history",
    "jobs",
    "kill",
    "let",
    "local",
    "logout",
    "mapfile",
    "popd",
    "printf",
    "pushd",
    "pwd",
    "read",
    "readarray",
    "readonly",
    "return",
    "set",
    "shift",
    "shopt",
    "source",
    "suspend",
    "test",
    "times",
    "trap",
    "true",
    "type",
    "typeset",
    "ulimit",
    "umask",
    "unalias",
    "unset",
    "wait",
];

/// bash's `enable` builtin: with no name it lists the enabled builtins as `enable NAME` lines;
/// enabling or disabling a named builtin prints nothing.
fn cmd_enable(parts: &[&str]) -> String {
    if parts[1..].iter().any(|a| !a.starts_with('-')) {
        return String::new();
    }
    let mut out = String::new();
    for name in BASH_BUILTINS {
        out.push_str("enable ");
        out.push_str(name);
        out.push('\n');
    }
    out
}

/// `mount` with no arguments (or `-l`): util-linux's `source on point type fstype (opts)` lines
/// from the fake filesystem's one mount table. Any other form is a root mounting something,
/// which prints nothing on success.
fn cmd_mount(parts: &[&str]) -> String {
    let listing = parts[1..].iter().all(|a| *a == "-l" || *a == "-v");
    if !listing {
        return String::new();
    }
    let mut out = String::new();
    for m in crate::fakefs::MOUNT_TABLE {
        out.push_str(&format!(
            "{} on {} type {} ({})\n",
            m.source, m.point, m.fstype, m.opts
        ));
    }
    out
}

/// `uname` with real per-flag field selection. Each flag adds its field and the selected fields
/// print in coreutils' fixed order (kernel-name, nodename, kernel-release, kernel-version, machine,
/// processor, hardware-platform, operating-system); a bare `uname` prints the kernel name only, and
/// `-a` the full canonical line. The previous shortcut - ANY flag returned the whole `uname -a`
/// line - was a one-probe fingerprint (real `uname -m` prints only `x86_64`) that also fed IoT
/// loaders a garbage machine string and broke their architecture-based payload selection. Fields
/// come from persona so `uname` cannot disagree with /etc/os-release or the prompt.
fn cmd_uname(parts: &[&str], flavor: ShellFlavor) -> String {
    let android = flavor == ShellFlavor::AndroidSh;
    let host = if android {
        persona::ANDROID_HOSTNAME.to_string()
    } else {
        persona::hostname()
    };
    let (kernel_release, kernel_build, arch) = if android {
        (
            persona::ANDROID_KERNEL_RELEASE,
            persona::ANDROID_KERNEL_BUILD,
            persona::ANDROID_ARCH,
        )
    } else {
        (
            persona::KERNEL_RELEASE,
            persona::KERNEL_BUILD,
            persona::ARCH,
        )
    };
    let (
        mut want_s,
        mut want_n,
        mut want_r,
        mut want_v,
        mut want_m,
        mut want_p,
        mut want_i,
        mut want_o,
    ) = (false, false, false, false, false, false, false, false);
    let mut all = false;
    let mut any_flag = false;
    for arg in &parts[1..] {
        if let Some(long) = arg.strip_prefix("--") {
            any_flag = true;
            match long {
                "all" => all = true,
                "kernel-name" => want_s = true,
                "nodename" => want_n = true,
                "kernel-release" => want_r = true,
                "kernel-version" => want_v = true,
                "machine" => want_m = true,
                "processor" => want_p = true,
                "hardware-platform" => want_i = true,
                "operating-system" => want_o = true,
                _ => {}
            }
        } else if let Some(shorts) = arg.strip_prefix('-') {
            any_flag = true;
            for c in shorts.chars() {
                match c {
                    'a' => all = true,
                    's' => want_s = true,
                    'n' => want_n = true,
                    'r' => want_r = true,
                    'v' => want_v = true,
                    'm' => want_m = true,
                    'p' => want_p = true,
                    'i' => want_i = true,
                    'o' => want_o = true,
                    _ => {}
                }
            }
        }
    }
    // `-a` reuses the canonical line (same persona source), keeping its exact historical bytes; a
    // bare `uname` is the kernel name, like real coreutils.
    if all {
        return if android {
            format!("{}\n", crate::persona::android_uname_all())
        } else {
            format!("{}\n", persona::uname_all(&host))
        };
    }
    if !any_flag {
        return "Linux\n".to_string();
    }
    let mut fields = Vec::new();
    if want_s {
        fields.push("Linux".to_string());
    }
    if want_n {
        fields.push(host.clone());
    }
    if want_r {
        fields.push(kernel_release.to_string());
    }
    if want_v {
        fields.push(kernel_build.to_string());
    }
    if want_m {
        fields.push(arch.to_string());
    }
    if want_p {
        fields.push(arch.to_string());
    }
    if want_i {
        fields.push(arch.to_string());
    }
    if want_o {
        // Android's userspace is not GNU; `uname -o` there says Android.
        fields.push(if android { "Android" } else { "GNU/Linux" }.to_string());
    }
    if fields.is_empty() {
        // Only unrecognized flags: degrade to the kernel name rather than erroring, since a wrong
        // error format would itself be a tell.
        return "Linux\n".to_string();
    }
    format!("{}\n", fields.join(" "))
}

/// A plausible fetched body, printed by `curl URL` and `wget -O- URL` (the `... | sh` pattern).
/// Canned by necessity - the module performs zero network I/O - but real servers do answer a bare
/// path with exactly this Apache-default page, so it is not itself a tell; the previous tell was
/// only that `-O`/`-o` (save to a file) also printed it, which a real client never does.
const FETCHED_BODY: &str =
    "<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>\n";

/// `wget URL`: the classic wget banner (connection line, HTTP status, progress bar, final "saved"
/// summary) - zero network I/O, see the module doc. The timestamp is `now`, the session clock's
/// time (a frozen date is a tell an attacker catches by running twice). The saved filename is derived from `-O` or
/// the URL's own basename rather than a constant "index.html" (every download claiming the same
/// name was a tell); `-q`/`-nv` suppress the banner as real wget does; `-O-`/`-qO-` write the body
/// to stdout (the `wget -qO- | sh` loader pattern) instead of the transcript.
fn cmd_wget(parts: &[&str], now: chrono::DateTime<chrono::Utc>) -> String {
    let url = fetch_url_arg("wget", &parts[1..]).unwrap_or("");
    let sanitized_url = sanitize_value(url, MAX_URL_LEN);

    let out = wget_output(parts);
    if out == WgetOutput::Stdout {
        return FETCHED_BODY.to_string();
    }
    if parts
        .iter()
        .any(|&p| p == "-q" || p == "-nv" || p == "--quiet")
    {
        return String::new();
    }
    let name = match out {
        WgetOutput::File(n) => n,
        _ => wget_basename(url),
    };
    let name = sanitize_value(&name, MAX_URL_LEN);
    let now = now.format("%Y-%m-%d %H:%M:%S");
    format!(
        "--{now}--  {sanitized_url}\n\
         Connecting to {sanitized_url}... connected.\n\
         HTTP request sent, awaiting response... 200 OK\n\
         Length: 1234 (1.2K) [application/octet-stream]\n\
         Saving to: '{name}'\n\
         \n\
         {name}          100%[==================>]   1.2K  --.-KB/s    in 0s\n\
         \n\
         {now} (1.2 MB/s) - '{name}' saved [1234/1234]\n"
    )
}

#[derive(PartialEq)]
enum WgetOutput {
    Stdout,
    File(String),
    Default,
}

/// Resolve wget's output target from its flags: `-O-`/`-qO-` -> stdout, `-O <name>` -> that file,
/// otherwise the default (URL basename).
fn wget_output(parts: &[&str]) -> WgetOutput {
    for (i, &p) in parts.iter().enumerate() {
        if p == "-O-" || p == "-qO-" || p == "-nvO-" {
            return WgetOutput::Stdout;
        }
        if p == "-O" {
            match parts.get(i + 1) {
                Some(&"-") => return WgetOutput::Stdout,
                Some(name) => return WgetOutput::File((*name).to_string()),
                None => return WgetOutput::Default,
            }
        }
        if let Some(name) = p.strip_prefix("-O") {
            // `-Ofile` (no space).
            if name == "-" {
                return WgetOutput::Stdout;
            }
            return WgetOutput::File(name.to_string());
        }
    }
    WgetOutput::Default
}

/// The basename a real wget would save a URL to: the last path segment (query string stripped), or
/// `index.html` when the URL ends in `/` or has no path.
/// The local file a fetch command writes its body to, or `None` when it writes to stdout (and so
/// leaves nothing behind). `parts[0]` is the command token; `cmd` is its basename, already
/// resolved by the caller so a full-path or BusyBox form lands here the same way.
fn download_save_name(cmd: &str, parts: &[&str]) -> Option<String> {
    let args = &parts[1..];
    match cmd {
        "wget" => match wget_output(parts) {
            WgetOutput::Stdout => None,
            WgetOutput::File(name) => Some(name),
            WgetOutput::Default => Some(wget_basename(fetch_url_arg("wget", args)?)),
        },
        "curl" => {
            let mut it = args.iter();
            while let Some(&a) = it.next() {
                if a == "-O" || a == "--remote-name" {
                    return Some(wget_basename(fetch_url_arg("curl", args)?));
                }
                if a == "-o" || a == "--output" {
                    return it.next().map(|n| (*n).to_string());
                }
                if let Some(name) = a.strip_prefix("-o")
                    && !name.is_empty()
                {
                    return Some(name.to_string());
                }
            }
            None
        }
        // BusyBox `tftp -g -r REMOTE [-l LOCAL] HOST`: the local name wins when given.
        "tftp" => {
            let (mut remote, mut local) = (None, None);
            let mut it = args.iter();
            while let Some(&a) = it.next() {
                match a {
                    "-r" => remote = it.next().copied(),
                    "-l" => local = it.next().copied(),
                    _ => {}
                }
            }
            local.or(remote).map(str::to_string)
        }
        // BusyBox `ftpget [opts] HOST [LOCAL] REMOTE`: the local name is the second positional
        // when three are given, else the remote name doubles as it.
        "ftpget" => {
            let mut positional = Vec::new();
            let mut it = args.iter();
            while let Some(&a) = it.next() {
                match a {
                    "-u" | "-p" | "-P" => {
                        it.next();
                    }
                    _ if a.starts_with('-') => {}
                    _ => positional.push(a),
                }
            }
            match positional.len() {
                0 | 1 => None,
                2 => Some(positional[1].to_string()),
                _ => Some(positional[1].to_string()),
            }
        }
        _ => None,
    }
}

fn wget_basename(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    match path.trim_end_matches('/').rsplit('/').next() {
        Some(seg) if !seg.is_empty() && !seg.contains(':') => seg.to_string(),
        _ => "index.html".to_string(),
    }
}

/// `curl URL`. With `-O`/`-o` (save to a file) a real curl writes nothing to stdout - only a
/// progress meter to stderr, which this shell does not emit - so the output is empty; the previous
/// implementation printed the fetched body even under `-O`, which no real curl does and which was a
/// clean one-probe tell. Without `-o`/`-O`, the body goes to stdout as curl does.
fn cmd_curl(parts: &[&str]) -> String {
    let saves_to_file = parts.iter().enumerate().any(|(i, &p)| {
        p == "-O"
            || p == "--remote-name"
            || p == "-o"
            || p == "--output"
            || (p.starts_with("-o") && p.len() > 2)
            // a combined short-flag cluster containing O or o, e.g. -sO, -fsSLO
            || (p.starts_with('-') && !p.starts_with("--") && p[1..].chars().any(|c| c == 'O')
                && parts.get(i).is_some())
    });
    if saves_to_file {
        String::new()
    } else {
        FETCHED_BODY.to_string()
    }
}

/// `ping HOST`. Real ping exists on virtually every host, so "command not found" is a tell. A
/// line-based fake shell cannot stream a continuous ping, so this answers as though `-c` bounded it:
/// a couple of replies and a summary against the requested target, printed at once.
fn cmd_ping(parts: &[&str]) -> String {
    let target = first_non_flag_arg(&parts[1..]).unwrap_or("localhost");
    let target = sanitize_value(target, MAX_URL_LEN);
    // A stable pseudo-address for the target so two pings of the same host agree (a real resolve
    // would); derived from the name, not random.
    let last = 1 + (target.bytes().fold(0u32, |a, b| a.wrapping_add(b as u32)) % 253);
    format!(
        "PING {target} ({}): 56 data bytes\n\
         64 bytes from {}: icmp_seq=0 ttl=54 time=11.4 ms\n\
         64 bytes from {}: icmp_seq=1 ttl=54 time=11.9 ms\n\
         \n\
         --- {target} ping statistics ---\n\
         2 packets transmitted, 2 packets received, 0.0% packet loss\n\
         round-trip min/avg/max/stddev = 11.4/11.7/11.9/0.3 ms\n",
        format_args!("93.184.216.{last}"),
        format_args!("93.184.216.{last}"),
        format_args!("93.184.216.{last}"),
    )
}

/// The first token that does not look like a flag (does not start with `-`), or `None` if every
/// token is a flag or the slice is empty. `ls -la`, `ls -la /tmp`, and `cat -A file` all name
/// their real target after zero or more flags this fake shell has no reason to parse
/// individually; treating the first `-`-prefixed token as the path (what a bare
/// `parts.get(1)` lookup would do) misreads the single most common attacker recon command
/// (`ls -la`) as a lookup for a nonexistent path named `-la`.
fn first_non_flag_arg<'a>(args: &[&'a str]) -> Option<&'a str> {
    args.iter().find(|arg| !arg.starts_with('-')).copied()
}

/// A honeypot `echo` faithful enough to survive the shell-detection handshakes IoT botnets run
/// before they drop a payload. The important one is Gafgyt/BASHLITE, which sends
/// `echo -e "\x47\x41\x59\x46\x47\x54"` and hangs up unless it reads back exactly `GAYFGT`. The
/// previous implementation joined the raw tokens (flags, surrounding quotes, and undecoded escapes
/// included), so that probe returned `-e "\x47\x41\x59\x46\x47\x54"` and fingerprinted the honeypot
/// on the spot. This interprets a leading run of `-e`/`-n`/`-E` flags and, under `-e`, decodes the
/// backslash escapes a real `echo -e` would. Quoting was already removed by the shell before the
/// arguments got here. It only transforms text - nothing here is evaluated or executed, per the
/// module's never-exec guarantee.
///
/// The dialect is the `echo` actually running. Ubuntu's dash is captured in the 2026-09-29 ground
/// truth ("dash echo", "dash echo -e"): it decodes escapes always, `-e` is an ordinary operand and
/// `\xHH` is not an escape. The Android mksh has no capture, so it keeps the bash rules
/// ([unverified]). Escapes above 0x7f leave as the char with that code point rather than the raw
/// byte until words and output carry bytes.
fn cmd_echo(dialect: EchoDialect, args: &[&str]) -> String {
    if dialect == EchoDialect::Dash {
        return dash_echo(args);
    }
    let mut interpret = false; // -e
    let mut trailing_newline = true; // -n suppresses
    let mut first_operand = 0;
    for (idx, tok) in args.iter().enumerate() {
        // A flag token is '-' followed only by e/n/E (e.g. -e, -n, -E, -en). Anything else, or a
        // bare '-', ends the option run and begins the operands.
        let is_flag = tok.len() >= 2
            && tok.starts_with('-')
            && tok[1..].chars().all(|c| matches!(c, 'e' | 'n' | 'E'));
        if !is_flag {
            first_operand = idx;
            break;
        }
        for c in tok[1..].chars() {
            match c {
                'e' => interpret = true,
                'E' => interpret = false,
                'n' => trailing_newline = false,
                _ => {}
            }
        }
        first_operand = idx + 1;
    }

    let mut out = String::new();
    for (idx, tok) in args[first_operand..].iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        if interpret {
            if decode_echo_escapes_into(tok, &mut out, false) {
                // A `\c` escape stops all further output, including the trailing newline.
                return out;
            }
        } else {
            out.push_str(tok);
        }
    }
    if trailing_newline {
        out.push('\n');
    }
    out
}

/// Which implementation of `echo` answers: the escape and flag rules differ between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EchoDialect {
    Bash,
    Dash,
    Busybox,
    Mksh,
}

/// dash's `echo`: only a first operand that is exactly `-n` is an option, and every operand is
/// decoded as escapes with no `-e`.
fn dash_echo(args: &[&str]) -> String {
    let (trailing_newline, operands) = match args.split_first() {
        Some((&"-n", rest)) => (false, rest),
        _ => (true, args),
    };
    let mut out = String::new();
    for (idx, tok) in operands.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        if decode_echo_escapes_into(tok, &mut out, true) {
            return out;
        }
    }
    if trailing_newline {
        out.push('\n');
    }
    out
}

/// Decode the backslash escapes `echo -e` understands, appending to `out`. Returns `true` if a
/// `\c` escape was hit, which tells the caller to stop producing output entirely. Supports the
/// escapes real-world loaders actually use: `\xHH` hex, `\0NNN`/`\NNN` octal, and the single-letter
/// set (`\n \t \r \\ \a \b \f \v \0`). `dash` selects dash's set: bare `\NNN` octal is decoded and
/// `\xHH` is not.
fn decode_echo_escapes_into(s: &str, out: &mut String, dash: bool) -> bool {
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('a') => out.push('\x07'),
            Some('b') => out.push('\x08'),
            Some('f') => out.push('\x0c'),
            Some('v') => out.push('\x0b'),
            Some('\\') => out.push('\\'),
            Some('c') => return true, // stop all further output
            Some(first @ '1'..='7') if dash => {
                // dash reads `\NNN` as octal (bash needs the leading 0): up to three digits,
                // truncated to a byte.
                let mut val = first.to_digit(8).unwrap_or(0);
                let mut n = 1;
                while n < 3 {
                    match chars.peek().and_then(|d| d.to_digit(8)) {
                        Some(d) => {
                            val = val * 8 + d;
                            chars.next();
                            n += 1;
                        }
                        None => break,
                    }
                }
                if let Some(ch) = char::from_u32(val & 0xff) {
                    out.push(ch);
                }
            }
            Some('x') if !dash => {
                // Up to two hex digits.
                let mut val: u32 = 0;
                let mut n = 0;
                while n < 2 {
                    match chars.peek().and_then(|d| d.to_digit(16)) {
                        Some(d) => {
                            val = val * 16 + d;
                            chars.next();
                            n += 1;
                        }
                        None => break,
                    }
                }
                if n == 0 {
                    out.push_str("\\x"); // not a valid escape: emit literally
                } else if let Some(ch) = char::from_u32(val) {
                    out.push(ch);
                }
            }
            Some('0') => {
                // \0NNN: up to three octal digits after the 0.
                let mut val: u32 = 0;
                let mut n = 0;
                while n < 3 {
                    match chars.peek().and_then(|d| d.to_digit(8)) {
                        Some(d) => {
                            val = val * 8 + d;
                            chars.next();
                            n += 1;
                        }
                        None => break,
                    }
                }
                if let Some(ch) = char::from_u32(val) {
                    out.push(ch);
                }
            }
            Some(other) => {
                // Unknown escape: bash echo -e emits it verbatim (backslash included).
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'), // trailing backslash
        }
    }
    false
}

// Declared with the test modules, after all production code: `trace_type_never_feeds_wire_output`
// reads each file of this module up to its first `#[cfg(test)]` as the production source, and skips
// the files that hold only tests.
#[cfg(test)]
mod android_tests;
#[cfg(test)]
mod androidsys_tests;
#[cfg(test)]
mod base64_tests;
#[cfg(test)]
mod budget_tests;

#[cfg(test)]
mod busybox_tests;
#[cfg(test)]
mod dd_tests;
#[cfg(test)]
mod fsops_tests;
#[cfg(test)]
mod grammar_tests;
#[cfg(test)]
mod hashing_tests;
#[cfg(test)]
mod lookup_tests;
#[cfg(test)]
mod multicall_tests;
#[cfg(test)]
mod pathtools_tests;
#[cfg(test)]
mod printf_tests;
#[cfg(test)]
mod proc_self_tests;
#[cfg(test)]
mod read_tests;
#[cfg(test)]
mod readlink_tests;
#[cfg(test)]
mod test_builtin_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod texttools_tests;
