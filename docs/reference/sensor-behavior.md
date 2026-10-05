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

There are **10 sensor crates covering 13 protocols** (the `cred` sensor serves
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
  The one deliberate exception is `sensor-tftp`, which does not use this listener: it
  owns a request socket that only receives and a per-transfer socket whose every send
  passes a byte budget (see [sensor-tftp](#sensor-tftp)).
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
(`crates/sensor-framework/src/persona.rs#uname_all`, `crates/sensor-framework/src/persona.rs#proc_version`, `crates/sensor-framework/src/shell/mod.rs#FakeShell::prompt`).

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
`/sys`, `/run` and `/boot` subtrees the mount table names. The Ubuntu persona has the 73
executables recorded from a real Ubuntu 22.04 (`/bin/busybox`, `/bin/ls`, `/bin/echo`,
`/bin/cat`, `/bin/bash`, `/usr/bin/wget` and the rest of `BINARIES`,
`crates/sensor-framework/src/binaries.rs#BINARIES`; `/bin/sh` is a link to dash), each a
synthetic ELF image: the first 64 bytes a real one starts with, then generated filler out to
its real size, so a probe that reads the header or the length sees what Ubuntu shows and
`cp /bin/busybox x` has something to copy. The images are generated data, never a file of the
host, and nothing runs them. Only `/bin/ls` holds a newline before offset 410 (at 409, as
the recorded `head -n 1` shows). `/proc/self/exe` is the executable of the process that
opens it: an applet of `busybox` reads busybox, a direct `cat` reads cat, a redirection the
shell opens (`cat < /proc/self/exe`) and `/proc/$$/exe` read bash (dash in a shell opened
with `sh`). The phone's binaries stay stubs and it has no `/proc/self/exe`. A copy of the
busybox image runs as a renamed busybox does: `.bb: applet not found` (127), or the
multi-call binary when the copy's name begins `busybox`.

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

`shell/mod.rs` presents interactive and one-shot shells shared by SSH, Telnet, and ADB
(`crates/sensor-framework/src/shell/mod.rs`). It is **never-exec and no-fetch by
construction**: there is no process-spawn API and no HTTP/network-fetch client
anywhere in the crate; `wget`/`curl` return canned transcripts with zero network
I/O (`crates/sensor-framework/src/shell/mod.rs`). This is asserted by `never_exec_static_check` and
`workspace_lockfile_has_no_http_client_crate` in
`crates/sensor-ssh/tests/shell_test.rs`.

- One `honeypot_command_exec` is emitted per non-blank input line, except that a
  binary line or a line past the per-connection cap of 256 commands
  (`MAX_COMMANDS_PER_SESSION`, `crates/sensor-framework/src/shell/mod.rs#MAX_COMMANDS_PER_SESSION`, shared by every shell on the connection through
  `crates/sensor-framework/src/budget.rs#ConnectionBudget`) yields at most one marker event per session
  per flood kind; a blank line produces no event or output (`crates/sensor-framework/src/shell/mod.rs#FakeShell::handle_input`). The raw
  line is recorded verbatim in
  `metadata.command`, sanitized and capped at `MAX_COMMAND_LEN = 1024` (`crates/sensor-framework/src/shell/mod.rs#MAX_COMMAND_LEN`, `crates/sensor-framework/src/shell/mod.rs#FakeShell::handle_input`).
- If the line is single-byte-XOR obfuscated, `command_decoded` and `xor_key` are
  added to metadata (`crates/sensor-framework/src/shell/mod.rs#FakeShell::handle_input`).
- One `ConnectionBudget` per connection (`crates/sensor-framework/src/budget.rs#ConnectionBudget`, limits in `crates/sensor-framework/src/budget.rs#BudgetLimits::standard`)
  bounds what a session can make the sensor hold or send: 256 KiB of created file content and 4096
  created nodes (a removed file's slot is not freed), 64 recorded downloads per connection and 8 per
  line, 16 MiB written to the peer, and per input line a work allowance and a re-entry depth of 16.
  A refused write prints the kernel's own `No space left on device`, `File too large` or
  `File name too long` (names over 255 per component or 4096 per path). Past the download cap the
  connection's one `download_cap` marker is emitted and no further `honeypot_file_download` events;
  a refused re-entry, loop or nesting is a silent failure with status 1, never an error string. A connection that has written its 16 MiB is dropped after
  the reply that spent it.
- A recognized fetch verb additionally emits `honeypot_file_download` with
  `metadata.url`, capped at `MAX_URL_LEN = 512` (`crates/sensor-framework/src/shell/mod.rs#MAX_URL_LEN`, `crates/sensor-framework/src/shell/mod.rs#FakeShell::handle_input`).
- Shell identity is state, not fixed response text (`crates/sensor-framework/src/shell/mod.rs#ShellContext`, `crates/sensor-framework/src/shell/mod.rs#FakeShell::prompt`). An Ubuntu login starts as
  `-bash`, uses the interactive command-not-found handler and a prompt that follows
  the working directory. SSH exec uses `bash: line 1:` diagnostics and no prompt.
  Bare `su`, `sh`, `bash` and `ash` push nested levels; dash levels have their own
  `sh: N:` line counters. `exit` pops one level, and only exiting the outer level
  sets `close_session`. Android starts and nests as mksh with `sh:` diagnostics.
- Input is read as a shell reads it, by a lexer, parser and evaluator
  (`crates/sensor-framework/src/shell/lex.rs`, `crates/sensor-framework/src/shell/parse.rs`,
  `crates/sensor-framework/src/shell/eval.rs`), not split on whitespace. Quotes and backslashes,
  `$VAR`, `${VAR:-w}`, `$?`, `$$`, `$0`, `$!`, `$#`, `$1..`, `$(( ))` (64-bit wrapping;
  division by zero prints bash's `division by 0 (error token is "0")`), `$( )` and backticks, `~`,
  field splitting at `$IFS` and globbing over the fake filesystem (1,024-name cap) expand in
  POSIX order (`crates/sensor-framework/src/shell/expand.rs`, `crates/sensor-framework/src/shell/arith.rs`).
  Redirections (`>`, `>>`, `<`, here-documents, `N>&M`, `>&-`, `/dev/null`) are opened before the
  command runs and apply to a whole loop or group as well as a simple command; a bash target
  that expands to other than one word is `-bash: WORD: ambiguous redirect`. Pipelines run every
  stage, feeding each the one before, and take the last stage's status; `&&` and `||` decide on
  status alone; `!`, `( )`, `{ }`, `if`, `for`, `while` and `until` run with the state-copy rules
  (`( )`, a pipeline stage, `$( )` and `&` get a copy of the working directory and variables;
  `{ }` does not). A trailing `&` runs the command at once and, in an interactive login shell,
  prints `[N] PID`. An unfinished construct waits for more input under the PS2 prompt `> ` (64
  lines or 64 KiB at most). Constructs outside this subset (`case`, `[[ ]]`, functions, `$'..'`,
  `${x##*/}`, brace expansion, `<<<`, arrays) parse and are skipped with status 0 and no output;
  what bash and dash also reject prints their syntax error and status 2. `read`, `export`,
  `unset`, `set`, `shift`, `umask`, `break`, `continue`, `cd`, `exit` act on the shell itself
  (`crates/sensor-framework/src/shell/builtins.rs`); `source`, `.` and `eval` only record intent.
  `$$` and `$!` come from a per-session process id seeded from the session id
  (`crates/sensor-framework/src/persona.rs#session_pid`), and the shell's own `/proc/PID` reads as
  `/proc/self`. Words are strings: byte-string arguments are deferred to the command families that
  need binary operands.
- Implemented commands (`dispatch`, `crates/sensor-framework/src/shell/mod.rs#FakeShell::dispatch`): `uname` (real per-flag field
  selection), `id`/`whoami`/`pwd`, `echo` (Gafgyt/BASHLITE `\xHH`-decoding
  handshake returning `GAYFGT`, `crates/sensor-framework/src/shell/mod.rs#cmd_echo`, `crates/sensor-framework/src/shell/mod.rs#decode_echo_escapes_into`), `cat` (fakefs plus a special
  `/proc/self/cmdline` returning argv, `crates/sensor-framework/src/shell/read.rs#FakeShell::cmd_cat`), `head` (`-n`/`-c` over a file or a pipe,
  `crates/sensor-framework/src/shell/read.rs#FakeShell::cmd_head`), `more` (copies its input through: the pty pager needs a
  terminal-rows model the shell does not have, `crates/sensor-framework/src/shell/read.rs#FakeShell::cmd_more`) and `hexdump` (only `-e '16/1 "%c"'` with `-n`;
  any other format prints nothing, `crates/sensor-framework/src/shell/read.rs#FakeShell::cmd_hexdump`), `dd` (`if`, `of`, `bs`, `ibs`, `obs`, `count`, `skip`, `seek`,
  `conv=notrunc`, `status`; the bytes are read once at offset `skip*bs` for `bs*count`, bounded by what the line has left, then the record
  lines on stderr, plus GNU's summary whose elapsed time is synthesized, `crates/sensor-framework/src/shell/dd.rs#FakeShell::cmd_dd`),
  `wc` (`-c -l -w -m` over a file or a pipe, GNU column widths and `total` row,
  `crates/sensor-framework/src/shell/texttools.rs#FakeShell::cmd_wc`), `od` (`-An -tx1`, the default octal words and `-A`
  radixes; other formats print nothing, `crates/sensor-framework/src/shell/texttools.rs#FakeShell::cmd_od`) and `grep` (only `-F` with `-c`, `-v`, `-i`;
  a search without `-F` prints nothing, `crates/sensor-framework/src/shell/texttools.rs#FakeShell::cmd_grep`),
  `ls` (sorted, dotfiles hidden without `-a`),
  `cp`/`rm`/`mkdir` (they change the session's filesystem and report the real errors),
  `wget`/`curl` (canned transcripts, `-O-`/`-qO-` writes body to stdout, a saved
  download becomes a file), `ping` (canned replies), `sh`/`bash`/`ash`
  (nested shell; `sh -c "CMD"`, `sh FILE` and a script piped to `sh` run their text in a shell level of their own), `enable` (bash's builtin list, since
  Mirai's telnet preamble sends it and only a non-bash says "command not found"), `mount`
  (the fake filesystem's mount table), `busybox` (the real v1.30.1 multi-call banner
  plus applet dispatch; an unlisted name gives `applet not found`),
  `tftp`/`ftpget` (silent; the download url is synthesized from the separate host and file
  arguments as `tftp://host[:port]/file` / `ftp://host[:port]/file`, since neither command
  takes a url token),
  `chmod`/`cp`/`rm`/`mkdir`/`sleep` (silent success), `cd`, `exit`/`logout`; an
  unknown command uses the active shell level's diagnostic form.
- BusyBox applet set is a single source of truth (`APPLET_ROWS`, `crates/sensor-framework/src/shell/busybox.rs#APPLET_ROWS`):
  the banner prints those rows and `busybox <applet>` recognizes exactly the names they list, so the
  two cannot contradict. Both are the reference build's own (BusyBox v1.30.1, 263 applets, captured
  from a bare `/bin/busybox`). A listed applet runs its modeled handler when there is one
  (`crates/sensor-framework/src/shell/mod.rs#FakeShell::cmd_busybox`) and otherwise succeeds silently:
  its usage text is not captured, so none is invented. A name the banner does not list, `curl`
  included (real busybox ships none), gives `applet not found` - matching the real-busybox check
  Mirai/Gafgyt perform.
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
- **SSH, FTP, ADB, Telnet (binary payloads only), and TFTP spool bodies.** SSH, FTP, ADB and TFTP use `max_file_size` =
  10_000_000 (10&nbsp;MB) and `global_budget` = 100_000_000 (100&nbsp;MB). Redis,
  HTTP, SMTP, cred, and catchall never write a body to a spool (confirmed
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
- **Channel table:** one connection may hold several channels, each with its own
  handler and its own flow-control state, keyed by the client's sender-channel number
  (mirrored as the server id). The table is capped at `MAX_CHANNELS_PER_CONNECTION`
  = 10; a valid `session` open past the cap, or reusing an id already in the table, is
  refused with `SSH_OPEN_RESOURCE_SHORTAGE` ("channel limit reached") so an OPEN flood
  cannot pin unbounded shells. Only `session` channels are confirmed; `direct-tcpip`,
  every other type, and a zero peer max-packet are refused at open with
  `SSH_OPEN_UNKNOWN_CHANNEL_TYPE` - this closes off attacker-directed proxying by
  construction (`crates/sensor-ssh/src/server.rs#MAX_CHANNELS_PER_CONNECTION`, `crates/sensor-ssh/src/channel.rs#handle_channel_open`, `crates/sensor-ssh/src/channel.rs#build_channel_open_resource_shortage`).
  A channel the server has already closed stays in the table until the peer's CLOSE
  arrives, and meanwhile refuses new requests and drops further data.
- **Flow control** (RFC 4254 section 5.2, per channel): the server advertises
  `INITIAL_WINDOW_SIZE` 2 MiB and `CHANNEL_MAX_PACKET_SIZE` 32 KiB on every
  confirmation. Server-to-client output honors the **peer's** window and max packet:
  output is queued per channel and emitted in chunks of at most `min(peer max packet,
  32 KiB, remaining peer window)`, stopping at a zero peer window and resuming only on
  that channel's `WINDOW_ADJUST`, so a 2 MiB reply is never one oversized packet.
  Client-to-server data is counted as it is consumed, and the server sends
  `WINDOW_ADJUST` once the consumed bytes reach half the initial window (1 MiB)
  (`crates/sensor-ssh/src/server.rs#next_frame`, `crates/sensor-ssh/src/server.rs#flush_channel_output`, `crates/sensor-ssh/src/server.rs#build_channel_window_adjust`, `crates/sensor-ssh/src/channel.rs#INITIAL_WINDOW_SIZE`, `crates/sensor-ssh/src/channel.rs#CHANNEL_MAX_PACKET_SIZE`).
- **Channel requests** (`channel.rs`, dispatched in `handle_session`): `pty-req` (sets
  a flag on the channel), `shell`, `exec <cmd>` and `subsystem sftp` are accepted only
  on a channel still awaiting its handler; any other subsystem or request type (`env`,
  `window-change`, `signal`) is not acted on. A reply is sent **only when `want_reply`
  is set**: `CHANNEL_SUCCESS` if accepted, `CHANNEL_FAILURE` for an unknown or refused
  request (`crates/sensor-ssh/src/channel.rs#handle_channel_request`, `crates/sensor-ssh/src/channel.rs#ChannelAction`, `crates/sensor-ssh/src/server.rs#build_channel_failure`).
- **Interactive shell vs exec:** the `pty-req` flag selects terminal behavior. With a
  pty the shell prints its state-derived prompt, echoes typed bytes, converts bare LF
  to CR-LF with `onlcr`, and sends both streams merged on `CHANNEL_DATA`. Without a pty
  (an `exec`, or `shell` with no `pty-req`) there is no echo or prompt, LF is left
  untouched, and stderr is sent as `CHANNEL_EXTENDED_DATA` type 1
  (`SSH_EXTENDED_DATA_STDERR`) while stdout stays on `CHANNEL_DATA`. `exec <cmd>` runs
  once in the exec-mode shell (noninteractive bash diagnostics); `scp -t ` starts the
  SCP receiver, `subsystem sftp` the SFTP handler. `MAX_LINE_LEN = 8192`
  (`crates/sensor-ssh/src/server.rs#handle_session`, `crates/sensor-ssh/src/server.rs#build_channel_extended_data`, `crates/sensor-ssh/src/server.rs#MAX_LINE_LEN`, `crates/sensor-framework/src/shell/mod.rs#onlcr`).
- **Exec lifecycle:** a one-shot exec sends its queued output, then `exit-status`
  (`want_reply` false), then `CHANNEL_EOF`, then `CHANNEL_CLOSE`, each only once all
  queued output has drained, so a window-stalled reply still ends cleanly. An
  interactive shell that exits takes the same path. A peer `CHANNEL_EOF` is a
  half-close and does not cut queued output (`crates/sensor-ssh/src/server.rs#build_exit_status`, `crates/sensor-ssh/src/server.rs#build_channel_eof`, `crates/sensor-ssh/src/server.rs#build_channel_close`).
- **Write deadline:** the session stream is wrapped once in `TimeoutStream`, so a write
  or flush pending past `idle_timeout` fails rather than letting a peer that stops
  reading (a zero window with a full socket buffer) stall the handler; the egress budget
  is charged per data chunk and ends the session once spent (`crates/sensor-ssh/src/timeout_stream.rs#TimeoutStream`, `crates/sensor-ssh/src/server.rs#classify_read_failure`).
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
  characters, hides password characters, prints the active level's prompt, and closes
  only when the shell reports `close_session` (see below). `MAX_LINE_LEN` 8192
  (`crates/sensor-telnet/src/handler.rs#LineReader`).
- **Data encoder** (`crates/sensor-telnet/src/handler.rs#encode_telnet_data`): every
  application byte the client reads (issue banner, login and password prompts,
  typed-character echo, shell output, shell prompt) goes through one encoder and the
  one writer built on it (`crates/sensor-telnet/src/handler.rs#write_telnet_data`). Order is fixed: ONLCR (every LF
  becomes CR-LF, all other bytes untouched, no UTF-8 assumption, `crates/sensor-framework/src/shell/mod.rs#onlcr`), then
  the optional per-session XOR codec (applied only where a shell exists: the shell
  reply, its prompt, and the first prompt after login pass the `FakeShell`; the
  pre-login banner, prompts and typed-character echo pass `None` and get ONLCR and IAC
  doubling only), then RFC 854 doubling of every literal `0xFF` data byte. Negotiation
  bytes (the connect preamble and the filter's `DONT`/`WONT` replies) bypass the
  encoder through the raw writer because their `0xFF` bytes are protocol markers, not
  data (`crates/sensor-telnet/src/handler.rs#write_raw`, `crates/sensor-framework/src/shell/mod.rs#FakeShell`). Egress is charged on the encoded length.
- **Session end** (`crates/sensor-telnet/src/handler.rs#handle_connection`): when the shell's result has
  `close_session` set (the outer shell exited, not a nested `exit`,
  `crates/sensor-framework/src/shell/mod.rs#CommandResult`), the sensor writes that output once through the encoder
  with no prompt appended, records `CaptureEnd::ClientLogout`, and drops the
  connection. Every other exit (peer close, idle timeout, failed write, spent egress)
  records its own ending (`crates/sensor-framework/src/handoff.rs#CaptureEnd`).
- **Write deadline** (`crates/sensor-telnet/src/handler.rs#write_raw`): every write, negotiation replies and
  in-reader echo included, is wrapped in a timeout of the connection's `idle_timeout`
  (`crates/sensor-framework/src/bounds.rs#ConnectionBounds`). A timed-out or failed write ends the session (recorded as
  `TransportError` where a capture is armed), so a client that stops reading cannot
  hold the handler on a blocked `write_all`.
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

### sensor-tftp

A TFTP (RFC 1350) honeypot on UDP, conventional port 69. It is the only sensor that
answers over UDP, so its reply surface is bounded in code and **it is off until an
operator sets `PROPOLIS_TFTP_BIND`**: with no bind it logs the error, exits 1 and binds
nothing (`crates/sensor-tftp/src/main.rs#load_config_from`).

- **Sockets.** A request socket on the configured bind only receives. Each valid RRQ or
  WRQ moves to a fresh ephemeral socket bound on the same local IP, as the RFC specifies
  (`crates/sensor-tftp/src/guarded.rs#Transfer`). Malformed datagrams and stray
  DATA/ACK/ERROR packets on the request socket are dropped with no reply and no event
  (`crates/sensor-tftp/src/handler.rs#classify`).
- **Reads are never served.** An RRQ in a valid mode gets one ERROR 1 "File not found"
  (at most 19 bytes), then silence. An unsupported mode, and any WRQ in `mail` or an
  unknown mode, gets ERROR 4. No DATA packet can be built: the protocol module has no
  DATA builder (`crates/sensor-tftp/src/protocol.rs#error`).
- **Writes are acknowledged and captured.** A WRQ in `netascii` or `octet` mode gets
  ACK 0, then lock-step ACKs for each in-order DATA block (fixed 512-byte blocks, no
  option negotiation). A duplicate of the previous block is re-ACKed and not stored
  again. Out-of-order blocks, block 0 and stray packets get no reply. The transfer ends
  on the first short block (complete), a peer ERROR, the body cap (ERROR 3), the idle
  timeout, the packet cap, or `max_duration`; whatever arrived is captured either way,
  with `complete: false` unless the final short block was received
  (`crates/sensor-tftp/src/handler.rs#UploadCapture`).
- **Anti-amplification.** Every send goes through one `send_to`, behind a byte budget
  that refuses any packet which would take bytes sent past bytes received from the
  peer, the request datagram included (`crates/sensor-tftp/src/guarded.rs#ByteBudget`).
  There is no retransmission, because that would be a send with nothing new received.
  A spoofed request therefore reflects strictly fewer bytes than the spoofer sent: the
  reply to an 8-byte request is at most 8 bytes, to a 4-byte request none.
- **Source pinning.** The transfer socket sends only to the exact (ip, port) the
  request came from and drops any packet from another source without counting it or
  resetting the idle clock.
- **Bounds.** `max_concurrent` permits (a request past the limit is dropped
  unanswered), per-transfer read/idle timeout, `max_duration` (dropping the transfer
  keeps what arrived), a packet cap derived from the body cap, and a retained-body cap of
  `PROPOLIS_TFTP_MAX_CAPTURED_BYTES` (default 1_000_000, at most
  `MAX_BODY_HARD_CAP` = 10_000_000, `crates/sensor-tftp/src/handler.rs#MAX_BODY_HARD_CAP`).
  A WRQ that never delivers a byte is recorded only as a probe, not as an empty upload.
- **Spool:** 10&nbsp;MB / 100&nbsp;MB, hand-off queue 64
  (`crates/sensor-tftp/src/lib.rs#SPOOL_GLOBAL_BUDGET`, `crates/sensor-tftp/src/lib.rs#CAPTURE_QUEUE_SIZE`,
  `crates/sensor-tftp/src/lib.rs#start_test_server`). The body is never executed,
  served or interpreted; `netascii` uploads are stored as the raw bytes received.
- **Emits:** `honeypot_connection` per RRQ/WRQ (protocol `udp`, metadata `protocol_label`,
  `filename`, `mode`, `direction` of `rrq` or `wrq`, all sanitized) and
  `honeypot_malware_upload` (protocol `udp`, standard upload metadata). Both are
  `authenticated=false` (TFTP has no authentication) and share one session id per
  transfer. `wan_ip` resolves against the bind address, so a wildcard bind has the same
  attribution limit as the catch-all's UDP path.

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
  framing (`crates/sensor-adb/src/adb_proto.rs#device_banner`). `MAX_MESSAGE_DATA_LEN` 1_000_000 bounds any
  inbound message before a buffer is allocated for it (a larger declared length ends
  the session as malformed input), and `OUR_MAXDATA` 4096 is the maxdata the sensor
  advertises in its own CNXN (`crates/sensor-adb/src/adb_proto.rs#MAX_MESSAGE_DATA_LEN`, `crates/sensor-adb/src/adb_proto.rs#OUR_MAXDATA`, `crates/sensor-adb/src/adb_proto.rs#build_cnxn`).
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
- **Write chunking** (`crates/sensor-adb/src/handler.rs#handle_connection`): the maxdata the client advertises
  in its CNXN (`arg1`, clamped to 1 through `MAX_MESSAGE_DATA_LEN`) is the ceiling for
  every WRTE the sensor sends. A reply larger than that is split into WRTEs of at most
  that many payload bytes, so a client with a small maxdata never receives a message it
  must reject (`crates/sensor-adb/src/handler.rs#drive_stream`).
- **Per-stream send state** (`crates/sensor-adb/src/handler.rs#Stream`, `crates/sensor-adb/src/handler.rs#PendingWrite`): each stream
  owns an outbound queue, an offset into the response being sent, and an `awaiting_okay`
  flag. ADB flow control is stop-and-wait per stream: the sensor sends one WRTE, sets
  the flag, and sends the next chunk only when the client's OKAY for that stream clears
  it. Sending is never awaited inline and never blocks on the OKAY: the OPEN, WRTE and
  OKAY arms of the read loop each call `drive_stream` once, which writes at most one
  chunk and returns, so one slow stream cannot stall reading or the other streams
  (`crates/sensor-adb/src/handler.rs#handle_wrte`). An OKAY with the wrong ids, or for a stream not awaiting one,
  is ignored.
- **Drain then close** (`crates/sensor-adb/src/handler.rs#drive_stream`): a one-shot `shell:<cmd>` queues its
  whole output and sends CLSE only after the queue is empty and the last chunk has been
  acknowledged; a command with no output closes at once. An interactive shell's `exit`
  from the outer level drains its final output and prompt before the CLSE. A stream
  whose response is fully sent is removed from the table.
- **Android line endings** (`crates/sensor-framework/src/shell/mod.rs#onlcr`): the shell's output is passed
  through ONLCR before it is queued, as a pty-backed adbd does; every LF becomes CR-LF
  and all other bytes, NUL and binary included, pass through unchanged. Interactive
  input is handled as a terminal would: CR, LF or CR-LF each end one line, the line is
  echoed as CR-LF, backspace and DEL erase one buffered character, and the prompt is
  re-read after every line because `cd` or a nested shell changes it (`crates/sensor-adb/src/handler.rs#handle_wrte`).
- **Memory and egress bound** (`crates/sensor-framework/src/budget.rs#ConnectionBudget`): the connection creates
  one `ConnectionBudget` and every shell on it, one-shot or interactive, holds a clone
  of that same `Arc`. The 32 streams therefore share one ceiling on created file
  content, nodes, recorded commands, downloads and egress bytes rather than each holding
  a full set (the memory bound, `crates/sensor-adb/src/handler.rs#handle_open`). Every WRTE payload sent is
  charged with `charge_egress`; once the cap is spent the sensor finishes the response
  in progress and drops the connection (`crates/sensor-framework/src/budget.rs#ConnectionBudget::charge_egress`).
- **Write deadline** (`crates/sensor-adb/src/handler.rs#write_or_err`): every write (the CNXN reply, OKAY, WRTE
  and CLSE) is wrapped in a timeout of the connection's `idle_timeout`; a peer that
  stops reading cannot hold the handler on a blocked write, and reads carry the same
  idle bound so a client that never sends OKAY ends the session too.
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
  listener, per datagram for catchall UDP, per transfer for TFTP; carried on every event.
- **Password discipline:** every login-capturing sensor reads the password only to
  advance the protocol and drops it - never stored, logged, or placed in any event
  field (SSH `crates/sensor-ssh/src/auth.rs`, telnet `crates/sensor-telnet/src/handler.rs#handle_connection`, FTP `crates/sensor-ftp/src/handler.rs#handle_connection`, redis
  `crates/sensor-redis/src/handler.rs#Session::handle_auth`, SMTP `crates/sensor-smtp/src/handler.rs#handle_connection`, cred handlers). Tests assert absence at
  the serialized-JSON level.
- **`authenticated` flag:** `honeypot_connection` and `catchall_probe` are always
  false; ADB and TFTP events are always false (no auth step); `honeypot_login_attempt` is
  true; `honeypot_command_exec` reflects session auth state (redis/http false,
  ssh/telnet true post-login).
- **Never-serve-outbound:** FTP RETR→550, FTP PORT/EPRT→502, ADB sync RECV→FAIL,
  SSH `direct-tcpip` refused, catchall/UDP never responds, TFTP RRQ gets one tiny
  error and never any file content, shell `wget`/`curl`
  canned - no sensor fetches or serves attacker-directed content.

## Notes

- `SensorConfig` in `sensor-framework/src/config.rs` is the framework's aggregate
  config type but is **not** used by the individual sensor binaries; each sensor
  defines its own `Config` struct. It appears to be dead or reference-only surface
  `[inferred]`.
- The SSH version-exchange wire string (`SSH-2.0-<banner>`) is `[inferred]` from
  the banner default and handshake usage; the exact formatting function body was
  not read line-by-line.
