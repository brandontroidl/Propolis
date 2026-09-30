<!--
title: Sensor behavior reference
audience: all
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-01
-->

# Sensor behavior reference

Per-protocol capture behavior for the Propolis sensor layer: what each sensor
impersonates, what it captures, which events it emits, and the shared framework
knobs that bound every capture.

There are **9 sensor crates covering 12 protocols** (the `cred` sensor serves
VNC, MySQL, MSSQL, PostgreSQL, and MongoDB from one binary).

**Canonical owners referenced here.** This page owns *capture behavior*. It does
not restate values owned elsewhere:

- Env-var names, exact defaults, bounds, and fail behavior:
  [`environment-variables.md`](environment-variables.md).
- Ports and binds: [`ports-and-protocols.md`](ports-and-protocols.md).
- Filesystem paths (log/spool/host-key locations):
  [`filesystem-paths.md`](filesystem-paths.md).
- Signal types, event fields, and weights:
  [`events-and-signals.md`](events-and-signals.md).

> **No compiled-in listen port.** No sensor hardcodes a port. Each takes its bind
> address from a required env var and refuses to start if absent. The
> "conventional" ports named below (SSH 22, Telnet 23, and so on) appear only in
> persona strings and comments; the actual bind is whatever the deploy units
> supply. Any mapping of a sensor to its conventional port is `[inferred]`.

## Shared wire contract

Every sensor emits the frozen NDJSON `SensorEvent` record defined in `sensor-wire`
(`crates/sensor-wire/src/lib.rs#SensorEvent`): `v`, `source_ip`, `wan_ip` (nullable),
`sensor`, `signal_type`, `protocol`, `authenticated`, `observed_at` (RFC 3339),
`metadata` (JSON), `sample` (optional `SampleRef`), `session_id` (optional),
`occurrence_id` (optional). Wire
version is `1` (`crates/sensor-wire/src/lib.rs#WIRE_VERSION`). A captured sample is referenced by
`SampleRef { sha256, size, orig_name, capture_id }` (`crates/sensor-wire/src/lib.rs#SampleRef`); `orig_name` is a sanitized
indicator string, never a path component. Signal-type and protocol constants are
owned by [`events-and-signals.md`](events-and-signals.md).

## Shared framework knobs

All sensors are built on `sensor-framework`. The knobs below are properties of the
capture machinery, not of any one protocol.

### Connection bounds

`ConnectionBounds` (`crates/sensor-framework/src/bounds.rs#ConnectionBounds`) carries
`read_timeout`, `idle_timeout`, `max_duration`, `max_captured_bytes`, and
`max_concurrent`. The struct is **shape only**; concrete values are set per-sensor
in each `main.rs` and are overridable by env var (owned by
[`environment-variables.md`](environment-variables.md)). `max_duration` and
`max_concurrent` are enforced by the listener; the read/idle timeouts and
`max_captured_bytes` are enforced by each handler's read loop.

A connection accepted past `max_concurrent` is refused immediately (socket closed,
not queued) (`crates/sensor-framework/src/bounds.rs#ConnectionBounds`). Every bound is validated at startup: for most
sensors a present-but-zero or unparseable value is rejected and the process refuses
to start ("zero never means unlimited"). **Exceptions:** `sensor-smtp`
(`crates/sensor-smtp/src/main.rs#parse_positive_u64`, `crates/sensor-smtp/src/main.rs#parse_positive_u32`) and `sensor-cred`
(`crates/sensor-cred/src/main.rs#parse_positive_u64`, `crates/sensor-cred/src/main.rs#parse_positive_u32`) fall back to the default on an
invalid or zero value instead of refusing to start. This is an evidenced
behavioral inconsistency across the sensor set, not a bug claim.

Common defaults across the internet-facing TCP sensors are `read_timeout`
30000&nbsp;ms, `idle_timeout` 60000&nbsp;ms, `max_duration` 600&nbsp;s,
`max_captured_bytes` 1_000_000, `max_concurrent` 256 (verified
`crates/sensor-ssh/src/main.rs#DEFAULT_READ_TIMEOUT_MS`, `crates/sensor-ssh/src/main.rs#DEFAULT_IDLE_TIMEOUT_MS`, `crates/sensor-ssh/src/main.rs#DEFAULT_MAX_DURATION_SECS`, `crates/sensor-ssh/src/main.rs#DEFAULT_MAX_CAPTURED_BYTES`, `crates/sensor-ssh/src/main.rs#DEFAULT_MAX_CONCURRENT`). Per-sensor deviations are noted in the
protocol table below; the canonical values live in
[`environment-variables.md`](environment-variables.md).

### Listener model

`run_tcp_listener` (`crates/sensor-framework/src/listener.rs#run_tcp_listener`) binds one TCP
address, spawns an accept loop, enforces `max_concurrent` with a
`tokio::sync::Semaphore` (`crates/sensor-framework/src/listener.rs#run_tcp_listener`), and wraps each handler future in
`tokio::time::timeout(max_duration, fut)` (`crates/sensor-framework/src/listener.rs#run_tcp_listener`). Each connection gets a fresh
`uuid::Uuid::now_v7()` session id (`crates/sensor-framework/src/listener.rs#run_tcp_listener`).

- **Panic isolation:** each connection handler runs in its own `tokio::spawn`; a
  panicking handler is caught, logged, and never crashes the accept loop
  (`crates/sensor-framework/src/listener.rs#run_tcp_listener`).
- **Accept-error backoff:** `ACCEPT_ERROR_BACKOFF = 20ms` between transient accept
  errors (`crates/sensor-framework/src/listener.rs#ACCEPT_ERROR_BACKOFF`).
- **UDP** (`run_udp_listener`, `crates/sensor-framework/src/listener.rs#run_udp_listener`): `UDP_MAX_DATAGRAM = 65536` buffer;
  **the socket is never handed to the handler**, so a UDP sensor cannot answer a
  probe by construction (`crates/sensor-framework/src/listener.rs#run_udp_listener`). Each datagram runs in its own bounded task.
- **Dual-stack normalization** (`normalize_dual_stack`, `crates/sensor-framework/src/listener.rs#normalize_dual_stack`): maps
  `::ffff:a.b.c.d` down to plain IPv4 (port preserved) before WAN resolution, so a
  plain-IPv4 WAN map matches a dual-stack peer.
- `shutdown_signal()` resolves on SIGINT or (Unix) SIGTERM (`crates/sensor-framework/src/listener.rs#shutdown_signal`).

### WAN attribution

`WanResolver` (`crates/sensor-framework/src/wan.rs#WanResolver::new`, `crates/sensor-framework/src/wan.rs#WanResolver::resolve`) maps the local bound
address a connection landed on to the operator's WAN IP. An unmapped local address
resolves to `None`, and the event's `wan_ip` is null (a documented case, not an
error). No-NAT deployments carry an identity entry (local == WAN) (`crates/sensor-framework/src/wan.rs#WanResolver::new`).

### Persona (single fictional host)

One coherent host identity is resolved from `persona.rs` so no two sensors
contradict each other (`crates/sensor-framework/src/persona.rs`): **Ubuntu
22.04.4 LTS "Jammy Jellyfish"**, kernel `5.15.0-91-generic`, `#101-Ubuntu SMP`,
`x86_64` (`crates/sensor-framework/src/persona.rs#OS_PRETTY`, `crates/sensor-framework/src/persona.rs#OS_VERSION`, `crates/sensor-framework/src/persona.rs#KERNEL_RELEASE`, `crates/sensor-framework/src/persona.rs#KERNEL_BUILD`, `crates/sensor-framework/src/persona.rs#ARCH`). Default hostname is `server01`, overridable with
`PROPOLIS_HOSTNAME` (`crates/sensor-framework/src/persona.rs#DEFAULT_HOSTNAME`, `crates/sensor-framework/src/persona.rs#ENV_HOSTNAME`, `crates/sensor-framework/src/persona.rs#hostname`). The SSH banner default is
`OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` (`crates/sensor-framework/src/persona.rs#OPENSSH_VERSION`). Helpers produce a consistent
`uname -a` string and `/proc/version`; the shell builds its
`root@<host>:<cwd>#` prompt from that identity and its current state
(`crates/sensor-framework/src/persona.rs#uname_all`, `crates/sensor-framework/src/persona.rs#proc_version`, `crates/sensor-framework/src/shell.rs#FakeShell::prompt`).

`sensor-adb` resolves a **second** identity from the same file: a rooted Nexus 5 on
Android 6.0.1 (build M4B30Z, kernel 3.4.0, armv7l). ADB is Android's own debug
protocol, so the device the CNXN banner announces, the `adb shell` prompt, `uname`,
`/system/build.prop` and the filesystem all come from that half, and the banner cannot
drift from the shell the way it had. The device is rooted, which is why it grants a root
shell over ADB and carries busybox and `su`.

### Fake filesystem

`fakefs.rs` is an in-memory static snapshot, fresh per session, with no real
filesystem underneath, so path traversal is structurally impossible
(`crates/sensor-framework/src/fakefs.rs`). It serves canned `/etc/hostname`,
`/etc/passwd` (9 accounts incl. root, `ubuntu` uid 1000, `www-data`, `sshd`),
`/etc/hosts` (loopback and IPv6 multicast only - no routable IPs), `/etc/os-release`,
`/proc/version`, `/proc/cpuinfo` (Intel Xeon E5-2686 v4, 1 core), and one mount table
behind `/proc/mounts`, `/proc/self/mounts`, `/etc/mtab`, `/proc/self/mountinfo` and the
shell's `mount` (a stock Ubuntu cloud image on `/dev/sda1`; every mount point it names is
a directory the shell will enter). Directories include `/`, `/tmp`, `/root`, `/etc`,
`/home/ubuntu`, the loader-probed `/var/run`, `/mnt`, `/usr`, `/dev`, `/dev/shm`, and the
`/sys`, `/run` and `/boot` subtrees the mount table names. `/bin/busybox`, `/bin/sh`,
`/bin/bash` and `/usr/bin/wget` are present and executable, so the `cp /bin/busybox x`
staging step has something to copy.

`FakeFs::android()` is the same machinery over the phone's filesystem: `/system` (mounted
read-only, so a write there is refused as on a real device), `/system/bin`,
`/system/xbin/busybox`, `/data/local/tmp` and `/sdcard` (the two directories an ADB
dropper writes to), `/default.prop`, `/system/build.prop` and an Android mount table.

The snapshot is **writable for the length of one session**: a bare redirection, a fetch
that saves to a file, `cp`, `mkdir` and `rm` all change what the rest of that session
sees, and `chmod` marks a file executable so running it succeeds. That is what lets a
loader chain behave: `>/tmp/d && chmod 777 /tmp/d && /tmp/d && cd /tmp/` completes, and
`wget URL -O x; chmod 777 x; ./x; rm -rf x` finds its payload at every step and leaves
nothing behind. Nothing persists between sessions.

### Fake shell (SSH, Telnet, ADB)

`shell.rs` presents interactive and one-shot shells shared by SSH, Telnet, and ADB
(`crates/sensor-framework/src/shell.rs`). It is **never-exec and no-fetch by
construction**: there is no process-spawn API and no HTTP/network-fetch client
anywhere in the crate; `wget`/`curl` return canned transcripts with zero network
I/O (`crates/sensor-framework/src/shell.rs`). This is asserted by `never_exec_static_check` and
`workspace_lockfile_has_no_http_client_crate` in
`crates/sensor-ssh/tests/shell_test.rs`.

- One `honeypot_command_exec` is emitted per non-blank input line, except that a
  binary line or a line past the per-session cap of 256 commands
  (`MAX_COMMANDS_PER_SESSION`, `crates/sensor-framework/src/shell.rs#MAX_COMMANDS_PER_SESSION`) yields at most one marker event per session
  per flood kind; a blank line produces no event or output (`crates/sensor-framework/src/shell.rs#FakeShell::handle_input`). The raw
  line is recorded verbatim in
  `metadata.command`, sanitized and capped at `MAX_COMMAND_LEN = 1024` (`crates/sensor-framework/src/shell.rs#MAX_COMMAND_LEN`, `crates/sensor-framework/src/shell.rs#FakeShell::handle_input`).
- If the line is single-byte-XOR obfuscated, `command_decoded` and `xor_key` are
  added to metadata (`crates/sensor-framework/src/shell.rs#FakeShell::handle_input`).
- A recognized fetch verb additionally emits `honeypot_file_download` with
  `metadata.url`, capped at `MAX_URL_LEN = 512` (`crates/sensor-framework/src/shell.rs#MAX_URL_LEN`, `crates/sensor-framework/src/shell.rs#FakeShell::handle_input`).
- Shell identity is state, not fixed response text (`crates/sensor-framework/src/shell.rs#ShellContext`, `crates/sensor-framework/src/shell.rs#FakeShell::prompt`). An Ubuntu login starts as
  `-bash`, uses the interactive command-not-found handler and a prompt that follows
  the working directory. SSH exec uses `bash: line 1:` diagnostics and no prompt.
  Bare `su`, `sh`, `bash` and `ash` push nested levels; dash levels have their own
  `sh: N:` line counters. `exit` pops one level, and only exiting the outer level
  sets `close_session`. Android starts and nests as mksh with `sh:` diagnostics.
- Implemented commands (`dispatch`, `crates/sensor-framework/src/shell.rs#FakeShell::dispatch`): `uname` (real per-flag field
  selection), `id`/`whoami`/`pwd`, `echo` (Gafgyt/BASHLITE `\xHH`-decoding
  handshake returning `GAYFGT`, `crates/sensor-framework/src/shell.rs#cmd_echo`, `crates/sensor-framework/src/shell.rs#decode_echo_escapes_into`), `cat` (fakefs plus a special
  `/proc/self/cmdline` returning argv), `ls` (sorted, dotfiles hidden without `-a`),
  `cp`/`rm`/`mkdir` (they change the session's filesystem and report the real errors),
  `wget`/`curl` (canned transcripts, `-O-`/`-qO-` writes body to stdout, a saved
  download becomes a file), `ping` (canned replies), `sh`/`bash`/`ash`
  (nested shell; `sh -c "CMD"` dispatches CMD), `enable` (bash's builtin list, since
  Mirai's telnet preamble sends it and only a non-bash says "command not found"), `mount`
  (the fake filesystem's mount table), `busybox` (multi-call banner
  v1.31.1 plus applet dispatch; unknown applet gives `applet not found`),
  `tftp`/`ftpget` (silent; the download url is synthesized from the separate host and file
  arguments as `tftp://host[:port]/file` / `ftp://host[:port]/file`, since neither command
  takes a url token),
  `chmod`/`cp`/`rm`/`mkdir`/`sleep` (silent success), `cd`, `exit`/`logout`; an
  unknown command uses the active shell level's diagnostic form.
- BusyBox applet set is a single source of truth (`BUSYBOX_APPLETS`, `crates/sensor-framework/src/shell.rs#BUSYBOX_APPLETS`)
  and deliberately excludes `curl` (real busybox ships none), so `busybox curl`
  gives `applet not found` - matching the real-busybox check Mirai/Gafgyt perform.
- Download capture handles direct, busybox, full-path, and
  `sh -c "wget ...; ..."` chained forms. A line is split into its simple commands
  at `;`, `|`, `||`, `&&`, `&`, parentheses, backticks and newlines, each command
  cut at its first redirection, and every fetcher in the line is examined; one
  `honeypot_file_download` is emitted per distinct url, so a Mirai
  `(tftp ... || busybox tftp ...) > t` fallback chain yields one event
  (`download_targets`, `simple_commands`).

### Command de-obfuscation

`command_codec.rs` decodes single-byte-XOR obfuscated telnet/shell probes
(LZRD-Mirai style) (`crates/sensor-framework/src/command_codec.rs`).
`detect_key` brute-forces keys `1..=255` and locks the key that yields printable
ASCII containing an anchor token (`/bin/busybox`, `busybox`, `enable`, `system`,
`/bin/sh`); plaintext returns `None` (`crates/sensor-framework/src/command_codec.rs#ANCHORS`, `crates/sensor-framework/src/command_codec.rs#detect_key`). `MAX_DETECT_ATTEMPTS = 8`
(`crates/sensor-framework/src/command_codec.rs#MAX_DETECT_ATTEMPTS`) caps key-less detection attempts per session to bound the brute-force CPU
cost; after 8 misses the session is treated as plaintext for good (`crates/sensor-framework/src/command_codec.rs#CommandCodec::decode`).

### Capture sanitization

`sanitize_value(input, max_len)` is the shared chokepoint every attacker string
clears before entering an event, closing CR/LF/ANSI log injection
(`crates/sensor-framework/src/sanitize.rs#sanitize_value`). Fixed order: collapse CR/LF/tab
runs to one space; strip ANSI CSI escapes, C0/C1 controls, DEL, bidi and
zero-width characters; NFC normalize; UTF-8-boundary-safe truncate to `max_len`
bytes (`crates/sensor-framework/src/sanitize.rs#sanitize_value`, `crates/sensor-framework/src/sanitize.rs#is_dangerous`, `crates/sensor-framework/src/sanitize.rs#truncate_to_len`). `to_hex_bounded` hex-encodes byte-derived fields, safe by
alphabet (`crates/sensor-framework/src/sanitize.rs#to_hex_bounded`).

### Quarantine spool

`QuarantineSpool::new(dir, max_file_size, global_budget)` stores captured bodies
named by their SHA-256 (never the attacker filename, so traversal is impossible),
with 0640 permissions and re-hash-on-read fail-closed integrity
(`crates/sensor-framework/src/spool.rs#QuarantineSpool`).

- `store(body)` rejects `FileSizeExceeded` when `size > max_file_size`, dedups on
  an existing hash (no extra budget), reserves budget atomically via
  `compare_exchange`, and rejects `BudgetExhausted` past `global_budget`
  (`sensor-framework/src/spool.rs#store`, `sensor-framework/src/spool.rs#reserve_budget`). A body is written to a staging file at 0640,
  synced, then hard-linked to its digest name (`sensor-framework/src/spool.rs#publish`, `sensor-framework/src/spool.rs#write_and_seal`).
- `new()` recovers used bytes by scanning the directory at startup so a restart
  does not reset the ceiling (`sensor-framework/src/spool.rs#QuarantineSpool`, `sensor-framework/src/spool.rs#scan_existing_usage`).
- **Only SSH, FTP, and ADB spool bodies.** All three use `max_file_size` =
  10_000_000 (10&nbsp;MB) and `global_budget` = 100_000_000 (100&nbsp;MB). Redis,
  Telnet, HTTP, SMTP, cred, and catchall never write a body to a spool (confirmed
  by absence of `QuarantineSpool`/`CaptureHandoff` in those crates).

### Capture hand-off

`CaptureHandoff` moves capture off the connection's response path so a capture
never delays the reply - response latency must not leak whether a capture happened
(`crates/sensor-framework/src/handoff.rs`). `submit(job)` is backed by
`mpsc::try_send` and never blocks: a full queue drops the job, returns
`CaptureDropped`, increments `dropped_count`, and logs at power-of-two totals
(`crates/sensor-framework/src/handoff.rs#CaptureHandoff::submit`). Every spooling sensor sets `capture_queue_size` = **64**
(`crates/sensor-ssh/src/server.rs#serve`, `crates/sensor-ftp/src/lib.rs#CAPTURE_QUEUE_SIZE`,
`crates/sensor-adb/src/lib.rs#CAPTURE_QUEUE_SIZE`). Exactly one worker drains the queue strictly sequentially
(`start_worker` panics on a second call), so `spool.store` is never called
concurrently (`crates/sensor-framework/src/handoff.rs#CaptureHandoff::start_worker`). `orig_name` is sanitized and capped at
`MAX_ORIG_NAME_LEN = 255` (`crates/sensor-framework/src/handoff.rs#MAX_ORIG_NAME_LEN`, `crates/sensor-framework/src/handoff.rs#process_job`); a spool refusal is counted in
`spool_refused_count` with no event emitted (`crates/sensor-framework/src/handoff.rs#CaptureHandoff::spool_refused_count`, `crates/sensor-framework/src/handoff.rs#process_job`); a panicking event builder
is isolated with `catch_unwind` and the worker continues (`crates/sensor-framework/src/handoff.rs#process_job`).

### Event emission

`EventEmitter::append(event)` serializes to one NDJSON line, opens the log with
`O_APPEND` (atomic concurrent appends on local storage), then `write_all` +
`flush`; a serialize/append failure never partially writes a line
(`crates/sensor-framework/src/emit.rs#EventEmitter::append`). The log directory must be local
storage - NFS `O_APPEND` can race (`crates/sensor-framework/src/emit.rs#EventEmitter::append`).

## Per-protocol capture behavior

Every sensor normalizes the peer via `normalize_dual_stack`, resolves `wan_ip` from
the local address, emits `honeypot_connection` (authenticated=false) at accept, and
sanitizes all attacker strings. Signal-type semantics are owned by
[`events-and-signals.md`](events-and-signals.md).

### sensor-ssh

Impersonates OpenSSH on Ubuntu (conventional port 22). Performs a full real SSH
handshake using the crate's own crypto primitives, then presents the fake shell and
captures SCP/SFTP transfers.

- **Handshake / crypto** (fixed offer): KEX `curve25519-sha256`, host key
  `ssh-ed25519` (ed25519, loaded-or-generated and persisted so it is stable across
  restarts), cipher `chacha20-poly1305@openssh.com` both directions (AEAD),
  compression `none` (`crates/sensor-ssh/src/transport/mod.rs#KEX_ALGORITHMS`, `crates/sensor-ssh/src/transport/mod.rs#SERVER_HOST_KEY_ALGORITHMS`, `crates/sensor-ssh/src/transport/mod.rs#ENCRYPTION_ALGORITHMS`, `crates/sensor-ssh/src/transport/mod.rs#build_kexinit`,
  `crates/sensor-ssh/src/main.rs#main`). Banner default is the persona OpenSSH version
  (`crates/sensor-ssh/src/main.rs#DEFAULT_BANNER`). A residual HASSHServer distinguishability from the minimal
  KEXINIT offer is a tracked follow-up (`crates/sensor-ssh/src/main.rs#DEFAULT_BANNER`).
- **Auth** (`auth.rs`): **accepts every credential and method** - reaching userauth
  is itself crypto proof the peer is real - except `none`, which is rejected with
  `USERAUTH_FAILURE` listing `publickey,password` to defeat the
  `PreferredAuthentications=none` probe (`crates/sensor-ssh/src/auth.rs#AuthState::handle_userauth`, `crates/sensor-ssh/src/auth.rs#build_userauth_failure`). Captures sanitized `username`
  and `method` in `honeypot_login_attempt`; the **password is read only to advance
  the parser and is never stored, logged, or emitted** (`crates/sensor-ssh/src/auth.rs`, `crates/sensor-ssh/src/auth.rs#AuthState::handle_userauth`). String
  cap `MAX_METADATA_STRING_LEN = 255` (`crates/sensor-ssh/src/auth.rs#MAX_METADATA_STRING_LEN`).
- **Channels** (`channel.rs`): only `session` channels are confirmed;
  `direct-tcpip` and all other types are refused at open - this closes off
  attacker-directed proxying by construction (`crates/sensor-ssh/src/channel.rs#handle_channel_open`). Actions: `pty-req`
  (ack), `shell` (interactive FakeShell with state-derived prompts), `exec <cmd>`
  (one-shot with noninteractive bash diagnostics; `scp -t ` starts
  the SCP receiver), `subsystem sftp` (SFTP handler). `MAX_LINE_LEN = 8192`.
- **Capture** (`transfer.rs`): captures **inbound writes only, never serves reads**
  (`crates/sensor-ssh/src/transfer.rs`). SCP receive mode parses the `C<mode> <size> <name>` header and streams
  the body to `honeypot_malware_upload`. SFTP v3 subset supports INIT/VERSION,
  OPEN (write-mode only), WRITE, CLOSE→capture; every other verb returns
  `SSH_FX_OP_UNSUPPORTED` (`crates/sensor-ssh/src/transfer.rs#SftpHandler::feed`, `crates/sensor-ssh/src/transfer.rs#SftpHandler::handle_open`). Caps: `MAX_CAPTURE_BODY` 10_000_000,
  `SFTP_MAX_FILE_BODY` 10_000_000, `SFTP_MAX_OPEN_HANDLES` 64,
  `SFTP_MAX_SESSION_BYTES` 20_000_000, `SFTP_MAX_PACKET_SIZE` 262_144
  (`crates/sensor-ssh/src/transfer.rs#MAX_CAPTURE_BODY`, `crates/sensor-ssh/src/transfer.rs#SFTP_MAX_FILE_BODY`, `crates/sensor-ssh/src/transfer.rs#SFTP_MAX_OPEN_HANDLES`, `crates/sensor-ssh/src/transfer.rs#SFTP_MAX_SESSION_BYTES`, `crates/sensor-ssh/src/transfer.rs#SFTP_MAX_PACKET_SIZE`). A body past its cap is kept as a prefix and emitted with
  `truncated: true` plus the real `wire_size`. A transfer still open when the session
  ends (SCP before its trailer, SFTP handles never CLOSEd) is kept as a capture with
  `complete: false` rather than dropped.
- **Spool:** 10&nbsp;MB / 100&nbsp;MB, hand-off queue 64 (`crates/sensor-ssh/src/server.rs#serve`).
- **Bounds:** common defaults (deliberately identical to Telnet), `max_concurrent`
  256 (`crates/sensor-ssh/src/main.rs#DEFAULT_MAX_CONCURRENT`).
- **Emits:** `honeypot_connection`, `honeypot_login_attempt`,
  `honeypot_command_exec`, `honeypot_file_download` (via shell),
  `honeypot_malware_upload` (SCP/SFTP).

### sensor-telnet

Impersonates a Telnet login (conventional port 23). Negotiates IAC, accepts any
credential, then presents the fake shell.

- **IAC** (`telnet.rs`): sends `IAC WILL ECHO` and `IAC WILL SGA` at connect;
  answers client `WILL <opt>`→`DONT` and `DO <opt>`→`WONT` (except its own offered
  ECHO/SGA), never replies to `WONT`/`DONT` (RFC 854 loop avoidance) (`crates/sensor-telnet/src/telnet.rs#negotiation_preamble`,
  `crates/sensor-telnet/src/telnet.rs#IacFilter::process`). The IAC/subnegotiation stripper survives being split across
  reads (`crates/sensor-telnet/src/telnet.rs#IacFilter::process`).
- **Flow** (`crates/sensor-telnet/src/handler.rs#handle_connection`): writes the persona issue banner and
  `<host> login:` prompt; reads the username (cap `MAX_USERNAME_LEN = 255`);
  prompts `Password:` and reads the password **read-only, then drops it, never
  stored or logged** (`crates/sensor-telnet/src/handler.rs#handle_connection`); accepts unconditionally and emits
  `honeypot_login_attempt` (authenticated=true); enters the FakeShell. Echoes typed
  characters, hides password characters, translates shell LF to CR-LF for NVT,
  prints the active level's prompt, and closes only when the outer shell exits.
  `MAX_LINE_LEN` 8192.
- **Bounds:** common defaults, `max_concurrent` 256. **Does not spool bodies.**
- **Emits:** `honeypot_connection`, `honeypot_login_attempt`,
  `honeypot_command_exec`, `honeypot_file_download` (via shell).

### sensor-http

Impersonates **Ubuntu-packaged nginx 1.18.0** (conventional port 80).

- **Behavior** (`handler.rs`): `SERVER_BANNER = "nginx/1.18.0 (Ubuntu)"`. Serves
  `/` (nginx default welcome page) and `/robots.txt`; GET/HEAD only, other methods
  give an nginx 405 and unknown paths an nginx 404 (`crates/sensor-http/src/handler.rs#build_response`). Static 200s carry
  Last-Modified/ETag/Accept-Ranges and a regenerated `Date` header. Captures
  method, path, query, user-agent, host, and a body preview into one
  `honeypot_command_exec` (authenticated=false, `crates/sensor-http/src/handler.rs#handle_connection`). Caps: request line
  8192, header block 16384, body capture 65536 (`crates/sensor-http/src/handler.rs#MAX_REQUEST_LINE_LEN`, `crates/sensor-http/src/handler.rs#MAX_HEADER_BLOCK`, `crates/sensor-http/src/handler.rs#MAX_BODY_CAPTURE`). A declared body is read to
  its end before the reply (the first 65536 bytes kept, the rest drained); the event
  records `body_size` (bytes received), `body_declared`, `body_complete` and
  `truncated`. A body over nginx's 1 MB `client_max_body_size` gets nginx's 413 before
  any of it is read; a client that hangs up before its declared body has arrived gets
  no reply, as nginx gives none, and the event says `body_complete: false`.
- **Bounds:** common defaults except **`max_concurrent` 512** (higher than the
  others, `crates/sensor-http/src/main.rs#DEFAULT_MAX_CONCURRENT`).
- **Capture:** no login, no spool. **The POST body is captured only as a truncated
  preview in metadata**, never stored as a file.
- **Emits:** `honeypot_connection`, `honeypot_command_exec`.

### sensor-ftp

Impersonates **vsFTPd 3.0.5** (conventional port 21).

- **Behavior** (`handler.rs`): banner `220 (vsFTPd 3.0.5)`. Verbs
  (case-insensitive, `crates/sensor-ftp/src/handler.rs#handle_connection`): USER→331, PASS→login event + 230 (password
  dropped), SYST→`215 UNIX Type: L8`, FEAT, PWD/CWD, TYPE (validated), SIZE/MDTM
  (canned `readme.txt`, 4096 bytes), REST, PASV/EPSV (opens a passive data listener
  on the control interface), LIST/NLST (canned listing), STOR (captures upload →
  `honeypot_malware_upload`), RETR→550, PORT/EPRT→502 (**active mode unimplemented - never dials out**), QUIT, NOOP, unknown→500.
  A data transfer is reported the way it ended: no data connection within the idle
  timeout → `425 Failed to establish connection.` (LIST and STOR alike); the client
  closing the data connection → `226`; a STOR whose data connection goes quiet or
  fails part way → `426 Failure reading network stream.` with the fragment still
  captured and `complete: false` in the event; a STOR the sensor stops reading at the
  drain cap → `451 Failure writing to local file.`.
- **Passive-data hijack defense** (`data_peer_matches`, `crates/sensor-ftp/src/handler.rs#data_peer_matches`, `crates/sensor-ftp/src/handler.rs#handle_connection`): a
  passive data connection whose source IP differs from the control connection's is
  refused with `425 Security: bad IP connecting.`, preventing off-path attribution
  poisoning (historical fix, commits `94a62ae1`, `016721e1`).
- **Caps:** `MAX_STOR_BODY = 10_000_000` (a larger STOR keeps the prefix, drains up
  to `MAX_STOR_DRAIN` more to measure it, and emits `truncated`/`wire_size` - see
  [events-and-signals](events-and-signals.md#sampleref)), login
  sanitized cap 255.
- **Spool:** 10&nbsp;MB / 100&nbsp;MB, hand-off queue 64 (`crates/sensor-ftp/src/lib.rs#SPOOL_MAX_FILE_SIZE`, `crates/sensor-ftp/src/lib.rs#SPOOL_GLOBAL_BUDGET`, `crates/sensor-ftp/src/lib.rs#CAPTURE_QUEUE_SIZE`, `crates/sensor-ftp/src/lib.rs#start_test_server`).
- **Bounds:** common defaults, `max_concurrent` 256.
- **Emits:** `honeypot_connection`, `honeypot_login_attempt`,
  `honeypot_malware_upload`.

### sensor-redis

Impersonates a **Redis 7.2.4 standalone master** (conventional port 6379).

- **Behavior** (`handler.rs`): parses RESP (inline and multi-bulk); arguments are kept
  as raw bytes, so a binary key or value round-trips byte for byte and only the ledger copy
  is decoded as text. **Never authenticates or persists across connections.** Commands
  (`crates/sensor-redis/src/handler.rs#Session::dispatch`): PING (echoes arg), AUTH
  (always OK → `honeypot_login_attempt`, password never in metadata), INFO
  (live-ish 7.2.4 dump with per-process random `run_id`/`master_replid`, real pid,
  advancing uptime, persona OS line, `crates/sensor-redis/src/handler.rs#canned_info`), CONFIG GET (canned), CONFIG SET
  (always OK; only `dir`/`dbfilename` - the RDB-RCE staging primitive - emit a
  `honeypot_command_exec` indicator, `crates/sensor-redis/src/handler.rs#Session::handle_config_set`), SET (OK; key and value captured,
  and kept whole in a per-session store of at most 256 keys and 1 MB; a write past either
  limit is refused with Redis's OOM error rather than acknowledged and dropped), GET (the
  value SET earlier this session, else nil; no event), SLAVEOF/REPLICAOF (OK +
  captured args), EVAL/SCRIPT (canned compile error + captured args, **never runs
  Lua**), unknown → Redis-exact error. Caps: metadata string 255, value 1024.
- **Bounds:** common defaults, `max_concurrent` 256. No spool.
- **Emits:** `honeypot_connection`, `honeypot_login_attempt` (AUTH),
  `honeypot_command_exec` (CONFIG SET dir/dbfilename, SET, SLAVEOF/REPLICAOF,
  EVAL/SCRIPT).

### sensor-smtp

Impersonates **Ubuntu Postfix ESMTP** (conventional port 25).

- **Behavior** (`handler.rs`): banner `220 <host> ESMTP Postfix (Ubuntu)` (persona
  host). EHLO advertises PIPELINING, SIZE 10240000, ETRN, STARTTLS, AUTH PLAIN
  LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING (`crates/sensor-smtp/src/handler.rs#handle_connection`). Verbs
  (`crates/sensor-smtp/src/handler.rs#handle_connection`): HELO/EHLO, STARTTLS (`454 TLS not available` - no in-process TLS),
  AUTH PLAIN (decodes username, drops password → `honeypot_login_attempt`), AUTH
  LOGIN (username captured, password dropped), MAIL FROM / RCPT TO, DATA (captures
  mail_from/rcpt_to/subject/body_size → `honeypot_command_exec`, replies with a
  Postfix queue id; without the terminating `.` line nothing is acknowledged or recorded),
  BDAT `<size> [LAST]` (CHUNKING: raw chunks accumulate as bytes until LAST, then the same
  message event with `chunking: true`; `BDAT 0 LAST` is a valid empty final chunk; a chunk
  the client does not finish sending, or that exceeds the session byte budget, is neither
  acknowledged nor recorded), RSET, NOOP, QUIT, VRFY (252), EXPN (502),
  unknown→502. Caps: line 8192, username 255; a message body is kept up to 65536 bytes and
  the event records the full `body_size` received plus `truncated` when it was cut.
- **Bounds:** common defaults, `max_concurrent` 256. **Bound parsing falls back to
  the default on invalid/zero input rather than refusing to start**
  (`crates/sensor-smtp/src/main.rs#parse_positive_u64`, `crates/sensor-smtp/src/main.rs#parse_positive_u32`) - differs from the reject-on-zero sensors. No spool (message
  body captured as size and subject only, never stored as a file).
- **Emits:** `honeypot_connection`, `honeypot_login_attempt`,
  `honeypot_command_exec` (DATA).

### sensor-adb

Impersonates **Android Debug Bridge / adbd** on a fake Nexus 5 (conventional port
5555).

- **Protocol** (`adb_proto.rs`): 24-byte header messages
  (CNXN/OPEN/OKAY/WRTE/CLSE). **No A_AUTH** - the emulated surface is the
  auth-disabled adbd on port 5555 (the ADB.Miner target) (`crates/sensor-adb/src/adb_proto.rs`).
  `device_banner()` presents a fake Nexus 5 / hammerhead / Android 6.0.1 / sdk 23
  and deliberately omits `shell_v2` so real clients fall back to plain v1 shell
  framing (`crates/sensor-adb/src/adb_proto.rs#device_banner`). `MAX_MESSAGE_DATA_LEN` 1_000_000, `OUR_MAXDATA` 4096.
- **Behavior** (`handler.rs`): CNXN handshake → device banner, then multiplexed
  streams (`MAX_STREAMS_PER_CONN = 32`). OPEN destinations (`crates/sensor-adb/src/handler.rs#handle_open`): `shell:` →
  interactive FakeShell **in its Android flavor** (the device's filesystem, a
  `root@hammerhead:<cwd> #` prompt that follows `cd`, Android's `uname`, nested mksh
  levels that close the stream only when the outer shell exits, and mksh's
  `sh: x: not found` rather than bash's `command not found`; authenticated **always
  false** - ADB has no auth step),
  `shell:<cmd>` → one-shot exec, `sync:` → file-transfer sub-protocol, anything
  else refused. Sync sub-protocol: SEND/DATA/DONE → captures the pushed file →
  `honeypot_malware_upload`; RECV → refused (`FAIL Permission denied`, **never
  serves outbound**); STAT → not-found. Sync body cap `MAX_SYNC_BODY` 10_000_000
  (a larger push keeps the prefix and is emitted with `truncated`/`wire_size`). A SEND
  whose DONE never arrives (stream closed or session dropped) is kept with
  `complete: false`.
- **Spool:** 10&nbsp;MB / 100&nbsp;MB, hand-off queue 64 (`lib.rs`).
- **Bounds:** common defaults, `max_concurrent` 256.
- **Emits:** `honeypot_connection`, `honeypot_command_exec` (shell),
  `honeypot_malware_upload` (sync push). **All ADB events are authenticated=false.**

### sensor-catchall

A passive, protocol-agnostic listener that emulates no protocol and **never writes
a byte back** (`crates/sensor-catchall/src/handler.rs#handle_tcp`).

- **Binds** every listed address on **both TCP and UDP** (`PROPOLIS_CATCHALL_BIND_ADDRS`, a
  comma-separated `ip:port` list, ≥1 required); per-port bind failure is non-fatal
  (`crates/sensor-catchall/src/main.rs#main`).
- **Distinct bound defaults** (`crates/sensor-catchall/src/main.rs#DEFAULT_READ_TIMEOUT_MS`, `crates/sensor-catchall/src/main.rs#DEFAULT_IDLE_TIMEOUT_MS`, `crates/sensor-catchall/src/main.rs#DEFAULT_MAX_DURATION_SECS`, `crates/sensor-catchall/src/main.rs#DEFAULT_MAX_CAPTURED_BYTES`, `crates/sensor-catchall/src/main.rs#DEFAULT_MAX_CONCURRENT`): `read_timeout` **5000&nbsp;ms**,
  `idle_timeout` **5000&nbsp;ms**, `max_duration` **30&nbsp;s**,
  `max_captured_bytes` **4096**, `max_concurrent` 256.
- **Behavior** (`handler.rs`): reads up to `max_captured_bytes` and emits one
  `catchall_probe` with `metadata.payload_hex` (capped `MAX_HEX_SAMPLE_BYTES = 256`)
  and `observed_len`, authenticated=false, no `protocol_label` (`crates/sensor-catchall/src/handler.rs#MAX_HEX_SAMPLE_BYTES`, `crates/sensor-catchall/src/handler.rs#build_event`). TCP
  uses protocol `tcp`; UDP uses `udp` with a session id minted per datagram. No
  spool.
- **UDP WAN caveat:** `wan_ip` attribution under a wildcard UDP bind is a documented
  limitation (no `local_addr()` on UDP receive; `local_ip` is caller-supplied,
  `crates/sensor-catchall/src/handler.rs#handle_udp`).
- **Emits:** `catchall_probe` only.

### sensor-cred (VNC / MySQL / MSSQL / PostgreSQL / MongoDB)

One binary running one listener per configured DB/remote protocol. Every configured
protocol logs to its own `<log_dir>/<protocol>.jsonl` (`crates/sensor-cred/src/main.rs#main`). At least one
per-protocol bind var is required.

- **Distinct bound defaults** (`crates/sensor-cred/src/main.rs#main`): `read_timeout` 30000&nbsp;ms,
  `idle_timeout` 60000&nbsp;ms, `max_duration` **60&nbsp;s**, `max_captured_bytes`
  **100_000**, `max_concurrent` 256. Bound parsing falls back to the default on
  invalid input (`crates/sensor-cred/src/main.rs#parse_positive_u64`, `crates/sensor-cred/src/main.rs#parse_positive_u32`).

| Protocol | Impersonates (conventional port) | Capture behavior |
|---|---|---|
| **vnc** (`vnc.rs`) | RFB 3.8, VNC Auth type 2 (5900) | Sends a 16-byte random challenge, reads the DES response; the attempt is the signal (plaintext unrecoverable) → `honeypot_login_attempt` with no username (`crates/sensor-cred/src/vnc.rs#handle_connection`). |
| **mysql** (`mysql.rs`) | MySQL 5.7.42 (3306) | Sends a greeting with per-connection random thread id + 20-byte scramble, parses the username from HandshakeResponse41, drops the password → login event (`crates/sensor-cred/src/mysql.rs#handle_connection`, `crates/sensor-cred/src/mysql.rs#build_greeting`). |
| **mssql** (`mssql.rs`) | SQL Server 2019 (15.0.16.57) TDS (1433) | PreLogin/Login7; parses the UTF-16LE username from Login7, sends LOGINACK (`crates/sensor-cred/src/mssql.rs#handle_connection`, `crates/sensor-cred/src/mssql.rs#parse_login7_username`, `crates/sensor-cred/src/mssql.rs#build_loginack`). |
| **postgresql** (`postgresql.rs`) | PostgreSQL (5432) | StartupMessage (declines SSL with `N`), parses the `user` param, sends AuthenticationMD5Password with a per-connection random salt, reads and discards the PasswordMessage → login event; then AuthenticationOk, a PostgreSQL 14 ParameterStatus set, BackendKeyData and ReadyForQuery, and a query loop: each simple query → `honeypot_command_exec` with the statement text, answered `ERROR 42501 permission denied` and ReadyForQuery, until Terminate, 200 statements, or the byte budget. Extended protocol: Parse records the SQL and answers ParseComplete; Bind, Describe (ParameterDescription then NoData for a statement, NoData for a portal) and Close get their completions; Execute is refused with 42501 and everything after it, a simple Query included, is discarded until Sync. |
| **mongodb** (`mongodb.rs`) | MongoDB OP_MSG (27017) | Answers isMaster/hello; on saslStart/authenticate extracts the SCRAM `n=<user>` or BSON `user` → login event (`crates/sensor-cred/src/mongodb.rs#handle_connection`, `crates/sensor-cred/src/mongodb.rs#extract_scram_username`, `crates/sensor-cred/src/mongodb.rs#extract_bson_string`). |

- Every cred protocol emits `honeypot_connection` + `honeypot_login_attempt`
  (authenticated=true). Username sanitized cap 255. **No spool**; passwords, DES
  responses, and MD5 responses are never stored.

## Cross-cutting invariants

- **Session id:** `Uuid::now_v7()` minted per accepted TCP connection by the
  listener, per datagram for catchall UDP; carried on every event.
- **Password discipline:** every login-capturing sensor reads the password only to
  advance the protocol and drops it - never stored, logged, or placed in any event
  field (SSH `crates/sensor-ssh/src/auth.rs`, telnet `crates/sensor-telnet/src/handler.rs#handle_connection`, FTP `crates/sensor-ftp/src/handler.rs#handle_connection`, redis
  `crates/sensor-redis/src/handler.rs#Session::handle_auth`, SMTP `crates/sensor-smtp/src/handler.rs#handle_connection`, cred handlers). Tests assert absence at
  the serialized-JSON level.
- **`authenticated` flag:** `honeypot_connection` and `catchall_probe` are always
  false; ADB events are always false (no auth step); `honeypot_login_attempt` is
  true; `honeypot_command_exec` reflects session auth state (redis/http false,
  ssh/telnet true post-login).
- **Never-serve-outbound:** FTP RETR→550, FTP PORT/EPRT→502, ADB sync RECV→FAIL,
  SSH `direct-tcpip` refused, catchall/UDP never responds, shell `wget`/`curl`
  canned - no sensor fetches or serves attacker-directed content.

## Notes

- `SensorConfig` in `sensor-framework/src/config.rs` is the framework's aggregate
  config type but is **not** used by the individual sensor binaries; each sensor
  defines its own `Config` struct. It appears to be dead or reference-only surface
  `[inferred]`.
- The SSH version-exchange wire string (`SSH-2.0-<banner>`) is `[inferred]` from
  the banner default and handshake usage; the exact formatting function body was
  not read line-by-line.
