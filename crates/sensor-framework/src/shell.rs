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

use crate::fakefs::FakeFs;
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

/// The fake interactive shell. One instance per SSH session; `cwd` is the only mutable state,
/// tracking a `cd` across calls the way a real shell would.
pub struct FakeShell {
    fs: FakeFs,
    ctx: EmitContext,
    cwd: String,
}

impl FakeShell {
    pub fn new(fs: FakeFs, ctx: EmitContext) -> Self {
        Self {
            fs,
            ctx,
            cwd: "/root".to_string(),
        }
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

        let sanitized_cmd = sanitize_value(line, MAX_COMMAND_LEN);
        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: self.ctx.source_ip,
            wan_ip: self.ctx.wan_ip,
            sensor: self.ctx.protocol_label.clone(),
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
            protocol: PROTO_TCP.into(),
            authenticated: self.ctx.authenticated,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({
                "protocol_label": self.ctx.protocol_label,
                "command": sanitized_cmd,
            }),
            sample: None,
            session_id: self.ctx.session_id,
        };

        let parts: Vec<&str> = line.split_whitespace().collect();
        let output = self.dispatch(&parts);

        let mut events = vec![event];

        if matches!(parts.first().copied(), Some("wget") | Some("curl")) {
            let url = first_non_flag_arg(&parts[1..]).unwrap_or("");
            if !url.is_empty() {
                let sanitized_url = sanitize_value(url, MAX_URL_LEN);
                events.push(SensorEvent {
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
                });
            }
        }

        (output, events)
    }

    /// Produce the canned terminal output for one already-tokenized, non-empty command line.
    /// Every arm returns a static or lightly-interpolated string; none evaluates, spawns, or
    /// otherwise interprets `parts` as code - see the module doc.
    fn dispatch(&mut self, parts: &[&str]) -> String {
        match parts.first().copied() {
            Some("uname") => cmd_uname(parts),
            Some("id") => "uid=0(root) gid=0(root) groups=0(root)\n".to_string(),
            Some("whoami") => "root\n".to_string(),
            Some("pwd") => format!("{}\n", self.cwd),
            Some("echo") => format!("{}\n", parts[1..].join(" ")),
            Some("cat") => self.cmd_cat(parts),
            Some("ls") => self.cmd_ls(parts),
            Some("wget") => cmd_wget(parts),
            Some("curl") => cmd_curl(),
            Some("cd") => {
                self.cwd = first_non_flag_arg(&parts[1..])
                    .unwrap_or("/root")
                    .to_string();
                String::new()
            }
            Some("exit") | Some("logout") => String::new(),
            Some(other) => format!("{other}: command not found\n"),
            None => String::new(),
        }
    }

    fn cmd_cat(&self, parts: &[&str]) -> String {
        match first_non_flag_arg(&parts[1..]) {
            Some(path) => self
                .fs
                .read_file(path)
                .unwrap_or_else(|| format!("cat: {path}: No such file or directory\n")),
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
}

fn cmd_uname(parts: &[&str]) -> String {
    if parts.len() > 1 {
        // Any flag at all gets the full banner; this is a canned-response shell, not a faithful
        // per-flag `uname` reimplementation, so `-a`/`-r`/`-s`/... are treated alike.
        "Linux server01 5.15.0-91-generic #101-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux\n"
            .to_string()
    } else {
        "Linux\n".to_string()
    }
}

/// `wget URL`: the classic wget banner (connection line, HTTP status, progress bar, final
/// "saved" summary), on stdout/stderr - zero network I/O, see the module doc. The timestamp is
/// real wall-clock time: a frozen or wildly-wrong date is itself a tell an attacker can catch by
/// running the same command twice, which is exactly the kind of self-contradiction the design
/// doc's detectability section warns against.
fn cmd_wget(parts: &[&str]) -> String {
    let url = parts.get(1).copied().unwrap_or("");
    let sanitized_url = sanitize_value(url, MAX_URL_LEN);
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
    format!(
        "--{now}--  {sanitized_url}\n\
         Connecting to {sanitized_url}... connected.\n\
         HTTP request sent, awaiting response... 200 OK\n\
         Length: 1234 (1.2K) [application/octet-stream]\n\
         Saving to: 'index.html'\n\
         \n\
         index.html          100%[==================>]   1.2K  --.-KB/s    in 0s\n\
         \n\
         {now} (1.2 MB/s) - 'index.html' saved [1234/1234]\n"
    )
}

/// `curl URL`: real curl with no `-o`/`-O` writes the fetched body straight to stdout with no
/// banner at all (unlike wget's verbose-by-default transcript) - so, unlike `cmd_wget`, this
/// prints only a plausible fetched body. Zero network I/O either way; the URL itself is still
/// captured (sanitized) as the event's `command` field by the caller.
fn cmd_curl() -> String {
    "<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>\n".to_string()
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
