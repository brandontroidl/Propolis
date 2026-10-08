<!--
title: Sensor behavior reference
audience: all
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Sensor behavior reference

Per-protocol capture behavior for the Propolis sensor layer: what each sensor
impersonates, what it captures, which events it emits, and the shared framework
knobs that bound every capture.

There are **12 sensor crates covering 15 protocols** (the `cred` sensor serves
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
  The two deliberate exceptions are `sensor-tftp` and `sensor-dns`, which do not use this
  listener: `sensor-tftp` owns a request socket that only receives and a per-transfer socket
  whose every send passes a byte budget (see [sensor-tftp](#sensor-tftp)), and `sensor-dns`
  answers each query with a reply no larger than the query, through one guarded send (see
  [sensor-dns](#sensor-dns)).
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
  per flood kind; a blank line produces no event or output (`crates/sensor-framework/src/shell/mod.rs#FakeShell::handle_input`).
  A repeated command past its source network's command-event budget is folded into a summary
  instead ([below](#command-event-budget-ssh-telnet-adb)). The raw
  line is recorded verbatim in
  `metadata.command`, sanitized and capped at `MAX_COMMAND_LEN = 1024` (`crates/sensor-framework/src/shell/mod.rs#MAX_COMMAND_LEN`, `crates/sensor-framework/src/shell/mod.rs#FakeShell::handle_input`).
- If the line is single-byte-XOR obfuscated, `command_decoded` and `xor_key` are
  added to metadata (`crates/sensor-framework/src/shell/mod.rs#FakeShell::handle_input`).
- One `ConnectionBudget` per connection (`crates/sensor-framework/src/budget.rs#ConnectionBudget`, limits in `crates/sensor-framework/src/budget.rs#BudgetLimits::standard`)
  bounds what a session can make the sensor hold or send: 192 KiB of created file content and 4096
  created nodes (a removed file's slot is not freed), 64 recorded downloads per connection and 8 per
  line, 16 MiB written to the peer, and per input line a work allowance and a re-entry depth of 16.
  A refused write prints the kernel's own `No space left on device`, `File too large` or
  `File name too long` (names over 255 per component or 4096 per path). Past the download cap the
  connection's one `download_cap` marker is emitted and no further `honeypot_file_download` events;
  a refused re-entry, loop or nesting is a silent failure with status 1, never an error string. A connection that has written its 16 MiB is dropped after
  the reply that spent it.
- A recognized fetch verb additionally emits `honeypot_file_download` with
  `metadata.url`, capped at `MAX_URL_LEN = 512` (`crates/sensor-framework/src/shell/mod.rs#MAX_URL_LEN`, `crates/sensor-framework/src/shell/mod.rs#FakeShell::handle_input`).
- **Standard input.** The sensors run each line through `start_line`
  (`crates/sensor-framework/src/shell/mod.rs#FakeShell::start_line`), which decides by the
  shell's own model of the commands whether the line reads the session's input: it runs the line
  with that input open and empty, and a command that reads past what has arrived (`cat` with no
  file or `-`, `cat > f`, `cat >> f`, `dd` without `if=`, `base64 -d`, `head`, `read`, a bare `sh`
  given a script on a pipe, any of these inside `sh -c '...'`, a `{ }` group or a pipeline's first
  stage) makes the line wait. Everything that run did is rolled back (the shell's state, the
  connection's filesystem and the budget counters its writes moved), so the line runs exactly
  once, by `finish_line`, on the input that arrived. A command that reads no input never waits,
  whatever its name; a here-document, `< file` or a pipe gives a reader its input without the
  session's. The waiting line's `honeypot_command_exec` is emitted at once, without `status`. How
  the input arrives is the sensor's (`crates/sensor-framework/src/held_input.rs#HeldInput`): the
  rest of an SSH exec channel up to its EOF, or what is typed at a terminal, in canonical mode:
  a line reaches the command at Enter, Backspace and Ctrl-U edit the line being typed, Ctrl-D at
  the start of a line is end of input (elsewhere it hands over the line so far), Ctrl-C kills the
  command (status 130, the rest of the line skipped, `^C` echoed), control characters echo as
  `^X`. Input cut off (a closed channel, the session's end) kills the command as a hangup (status
  129) at the read it waited in, keeping what it wrote. The input is bounded by
  `max_captured_bytes` and the capture memory budget; reaching either ends it there and the
  command sees end of file. What the command consumed is captured as `exec_stdin` or
  `shell_stdin` ([events-and-signals.md](events-and-signals.md#capture_reason-and-the-standard-input-keys)).
  Output is sent when the command ends, not as it reads: a typed `cat` with no redirection prints
  its lines after Ctrl-D, not one by one, and `read` or `head -n 1` at a terminal waits for Ctrl-D
  where a real one returns after its line.
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
  handshake returning `GAYFGT`; every `\xHH` and octal escape, `echo` and `printf` alike, writes
  the one byte it names, 0x80 to 0xff included, so a chunk redirected with `>` or `>>` puts the
  attacker's exact bytes in the file, `crates/sensor-framework/src/shell/mod.rs#cmd_echo`, `crates/sensor-framework/src/shell/mod.rs#decode_echo_escapes_into`), `cat` (fakefs plus a special
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
  `ls` (sorted, dotfiles hidden without `-a`, which does not add `.` and `..`; a file operand lists
  itself, files before directories, a `DIR:` heading once there are several operands, a missing
  one is `cannot access` with status 2; `-l` is GNU's long listing from the node facts `stat` prints,
  so a size or mode cannot disagree with `stat`, `wc -c` or `md5sum`, `crates/sensor-framework/src/shell/fileinfo.rs#FakeShell::cmd_ls`),
  `cp`/`rm`/`mkdir` (they change the session's filesystem and report the real errors),
  `wget`/`curl` (canned transcripts, `-O-`/`-qO-` writes body to stdout, a saved
  download becomes a file; `busybox wget` with no URL prints BusyBox 1.30.1's wget usage on
  stderr and exits 1, `crates/sensor-framework/src/shell/busybox.rs#wget_usage`), `ping` (canned replies), `sh`/`bash`/`ash`
  (nested shell; `sh -c "CMD"` (also with `-c` clustered, `sh -lc`, `bash -ec`), `sh FILE` and a script piped to `sh` run their text in a shell level of their own), `enable` (bash's builtin list, since
  Mirai's telnet preamble sends it and only a non-bash says "command not found"), `mount`
  (the fake filesystem's mount table), `busybox` (the real v1.30.1 multi-call banner
  plus applet dispatch; an unlisted name gives `applet not found`),
  `tftp`/`ftpget` (silent; the download url is synthesized from the separate host and file
  arguments as `tftp://host[:port]/file` / `ftp://host[:port]/file`, since neither command
  takes a url token),
  `chmod`/`cp`/`rm`/`mkdir`/`sleep` (silent success), `cd`, `exit`/`logout`; an
  unknown command uses the active shell level's diagnostic form, and so does a path that does
  not exist: bash's `No such file or directory`, dash's and mksh's `not found`
  (`crates/sensor-framework/src/shell/mod.rs#FakeShell::invoke_path`).
- BusyBox applet set is a single source of truth (`APPLET_ROWS`, `crates/sensor-framework/src/shell/busybox.rs#APPLET_ROWS`):
  the banner prints those rows and `busybox <applet>` recognizes exactly the names they list, so the
  two cannot contradict. Both are the reference build's own (BusyBox v1.30.1, 263 applets, captured
  from a bare `/bin/busybox`). A listed applet runs its modeled handler when there is one
  (`crates/sensor-framework/src/shell/mod.rs#FakeShell::cmd_busybox`) and otherwise succeeds silently:
  an applet's usage text is printed only where a handler models it (`kill`, `wget` without a
  URL), so none is invented. A name the banner does not list, `curl`
  included (real busybox ships none), gives `applet not found` - matching the real-busybox check
  Mirai/Gafgyt perform.
- Download capture handles direct, busybox, full-path, and
  `sh -c "wget ...; ..."` chained forms. A line is split into its simple commands
  at `;`, `|`, `||`, `&&`, `&`, parentheses, backticks and newlines, each command
  cut at its first redirection, and every fetcher in the line is examined; one
  `honeypot_file_download` is emitted per distinct url, so a Mirai
  `(tftp ... || busybox tftp ...) > t` fallback chain yields one event
  (`download_targets`, `simple_commands`).
- Echo-loader reassembly (`crates/sensor-framework/src/shell/loader.rs`). A Mirai or Mozi loader
  with no usable `wget` uploads a small downloader as `busybox echo -ne '\xNN...' > .i`, then
  `>> .i` per chunk, makes it executable (`chmod 777 .i`, or `cp /bin/ls .j && cat .i>.j && rm .i
  && cp .j .i` where that fails) and runs `./.i a b c d port`. Every step answers as on the
  reference box: the escapes write exact bytes, the writable-directory probe
  (`>/var/run/.x&&cd /var/run;...;>/var/.x&&cd /var`) succeeds for every directory and ends in
  `/var`, `busybox wget` prints its usage, `busybox cat /bin/ls|head -n 1` and `busybox hexdump -e
  '16/1 "%c"' -n 52 /bin/ls` print the recorded x86-64 header bytes, and a missing `./Runn` gets
  the active shell's not-found reply. The file the chunks built is captured as one
  `echo_loader` sample when it is made executable or run, or when the session ends if never run,
  and each chunk's command event names it; see
  [events-and-signals.md](events-and-signals.md#echo-loader-captures-and-their-keys). Running the
  assembled file executes nothing. When it is an ELF that holds an HTTP request line and its
  arguments are four octets and a port, the shell answers as that downloader does when its server
  cannot be reached: no output and status 1 [inferred: the exact status of the observed sample],
  since this box connects nowhere and so never gets the stage 2 the loader looks for next; any
  other session-made file runs as an empty program (status 0). The stage-2 URL it would have
  requested is emitted as a `honeypot_file_download` marked `derived_from: echo_loader_args`, for
  the vetted fetcher only ([attack-surfaces.md](../security/attack-surfaces.md#malware-fetcher-attacker-directed-outbound)).

### Command-event budget (ssh, telnet, adb)

A Mirai-family echo loader runs the same fifty-odd commands per session, several sessions at once
from one address, without pause. One command was one event, so a handful of such bots made telnet
97% of all events and put intake eleven days behind its log
([queue and spool troubleshooting](../troubleshooting/queue-and-spool.md#a-telnet-or-ssh-bot-loop-floods-the-event-log)).
The per-connection cap of 256 cannot see it, since every session stays far under it. Each of the
three sensors therefore holds one budget per source network for the whole process
(`crates/sensor-framework/src/command_flood.rs#CommandEventGate`, carried to every shell of a
connection by `crates/sensor-framework/src/budget.rs#ConnectionBudget::with_command_gate` and
applied as the last step of each line, `crates/sensor-framework/src/shell/mod.rs#FakeShell::gate_events`).

- **Only logging changes.** The command has already run when the gate sees its event: every
  reply, file and capture is the same whether its event is written or summarized.
- **The budget.** A token bucket per source network (IPv4 /24, IPv6 /56, the same key as the
  UDP reply limit), charged one token per `honeypot_command_exec`: a burst of 200, then 12 a
  minute (`PROPOLIS_<SENSOR>_COMMAND_EVENT_RATE_PER_MIN` / `_BURST`, see
  [environment variables](environment-variables.md#standard-sensors-strict-parse---ssh-telnet-http-ftp-redis-adb-catchall-tftp-mqtt-dns)).
  Within it, events are exactly as before.
- **First sightings.** The first time a command *shape* is seen from the network in a 60 s
  window, the command is written in full even with the bucket empty (and takes a token if one is
  left), so a new kind of command always appears. The shape
  (`crates/sensor-framework/src/command_flood.rs#command_shape`) is the line with its payload taken
  out: each run of `\xNN` or `\NNN` escapes, each run of 16 or more hex digits and each
  base64-looking run of 24 or more characters becomes a placeholder, and whitespace runs collapse
  to one space. So a loader's echo chunks, which differ only in their bytes, and its markers,
  whether fixed or random per session, are one shape each; the observed 53-line session is 16
  shapes. A window remembers 128 shapes
  (`crates/sensor-framework/src/command_flood.rs#MAX_TRACKED_COMMANDS`); past that, a new one goes
  by the bucket. Each address's first command event in the window is written too, for up to 64
  addresses of the network (`crates/sensor-framework/src/command_flood.rs#MAX_TRACKED_ADDRESSES`):
  scoring is per address and the budget per network, so a host whose commands all repeat a
  neighbour's would otherwise have no command event at all.
- **Echo-loader chunks are never firsts.** A command event carrying `assembled_file` (one chunk
  of an echo-loader upload) goes by the bucket alone: its bytes are in the `echo_loader` capture,
  and the summary keeps `assembled_file` and the highest suppressed `chunk_index`.
- **Never summarized** (`crates/sensor-framework/src/command_flood.rs#summarizable`): anything that
  is not a plain command event. Logins and connections never pass through the shell;
  `honeypot_file_download` (a fetch verb's URL or an echo-loader's derived stage-2 URL), every
  `honeypot_malware_upload` (`exec_stdin`, `shell_stdin`, `echo_loader` captures), the
  per-session `binary`, `command_cap` and `download_cap` markers and the summaries themselves are
  passed through untouched and spend nothing.
- **The summary.** A command event over the budget is counted into its network's summary for the
  window: one `honeypot_command_exec` with `command_summary: true`, written when the window ends
  (checked each second) and at shutdown (within 2 s,
  `crates/sensor-telnet/src/main.rs#SHUTDOWN_FLUSH_TIMEOUT`,
  `crates/sensor-ssh/src/main.rs#SHUTDOWN_FLUSH_TIMEOUT`,
  `crates/sensor-adb/src/main.rs#SHUTDOWN_FLUSH_TIMEOUT`). Its keys are in
  [events-and-signals](events-and-signals.md#command-summary-keys). A window that suppressed
  nothing writes nothing. A session's end does not write the summary early: its window outlives
  it, so the bot's next session is still measured against the same first sightings.
- **Bounded.** The bucket table holds 4096 networks with eviction; the window table 1024
  networks, each with at most 128 shape digests, 64 addresses, 8 samples of at most 256 bytes and 32 session
  ids; a network arriving while it is full is counted in one `overflow` summary without first
  sightings (`crates/sensor-framework/src/command_flood.rs#CommandEventGate::admit_at`). The
  worst case is a few MiB per sensor.
- **What it leaves.** With the defaults a source that keeps sending writes at most 200 + 12 a
  minute of individual command events, plus per minute one first sighting per shape, one first
  event per address and one summary. The observed loop (the 53-line session, four at once from
  one address, a new round every 30 s) is 4,240 command events in ten minutes ungated and 407
  individual events plus 10 summaries with the gate
  (`crates/sensor-framework/src/command_flood.rs#the_observed_loader_loop_is_bounded_by_burst_rate_shapes_and_addresses`).

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
  SCP receiver, `subsystem sftp` the SFTP handler. An exec command that reads its standard
  input (see [Fake shell](#fake-shell-ssh-telnet-adb)) is held with the channel open: the
  channel's data is its input, collected while the window is replenished as usual, until the
  client's `CHANNEL_EOF`, a `CHANNEL_CLOSE` (the command is killed and nothing is sent), the
  capture ceiling, or the session's end. With a pty the input is a terminal (echo, Ctrl-D,
  Ctrl-C), without one a pipe. At the shell, a typed line that reads its input takes the bytes
  after it (to Ctrl-D with a pty, to the channel's EOF without one) and the prompt returns when it
  ends; those bytes are its input and are not also offered to the binary-payload capture
  (`crates/sensor-ssh/src/server.rs#ChannelHandler`). `MAX_LINE_LEN = 8192`
  (`crates/sensor-ssh/src/server.rs#handle_session`, `crates/sensor-ssh/src/server.rs#build_channel_extended_data`, `crates/sensor-ssh/src/server.rs#MAX_LINE_LEN`, `crates/sensor-framework/src/shell/mod.rs#onlcr`).
- **Exec lifecycle:** a one-shot exec sends its queued output, then `exit-status`
  (`want_reply` false), then `CHANNEL_EOF`, then `CHANNEL_CLOSE`, each only once all
  queued output has drained, so a window-stalled reply still ends cleanly. A command that
  reads no input does this at the request, whether or not the client ever sends EOF; one held
  for its input does it when the input ends. An interactive shell that exits takes the same
  path. A peer `CHANNEL_EOF` is a half-close and does not cut queued output; it ends a held
  command's input (`crates/sensor-ssh/src/server.rs#build_exit_status`, `crates/sensor-ssh/src/server.rs#build_channel_eof`, `crates/sensor-ssh/src/server.rs#build_channel_close`, `crates/sensor-ssh/src/server.rs#finish_exec`).
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
  `honeypot_malware_upload` (SCP/SFTP, a binary shell payload, a command's standard input).
  Shell and exec channels share the connection's handle on the sensor's
  [command-event budget](#command-event-budget-ssh-telnet-adb): repeats past it become one
  `command_summary` event per source network per minute.

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
  (`crates/sensor-telnet/src/handler.rs#LineReader`). The reader keeps what it read off the
  socket and cuts lines from it only as they are wanted, so a typed line that reads its input
  (`cat > f`) takes the raw bytes after it, as a terminal, until Ctrl-D, the same input model as
  the SSH shell (`crates/sensor-telnet/src/handler.rs#LineReader::read_held`). The rest of a
  CR-LF or CR-NUL Enter already read stays with its line. The binary-payload capture keeps the
  bytes the line reader consumed, so input a command consumed is captured once, as that.
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
- **Bounds:** common defaults, `max_concurrent` 256. Spools only shell-phase evidence: a binary
  shell payload and the standard input a command read; there is no file-transfer protocol.
- **Emits:** `honeypot_connection`, `honeypot_login_attempt`,
  `honeypot_command_exec`, `honeypot_file_download` (via shell), `honeypot_malware_upload` (a
  binary shell payload, a command's standard input). A looping loader's repeated commands past
  the [command-event budget](#command-event-budget-ssh-telnet-adb) become one `command_summary`
  event per source network per minute; its logins, connections, captures and derived URLs keep
  their own events.

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
- **HTTPS (optional):** when `PROPOLIS_HTTP_TLS_BIND` is set, a second implicit-TLS listener in the
  same process serves the same nginx persona and writes the same `events.jsonl`
  (`crates/sensor-http/src/lib.rs#start_test_server_tls`). No client certificate is requested.
  The handshake is cut at the read timeout; a failed or stalled handshake, including plaintext sent
  to the TLS port, is dropped with a debug log and emits no event. Every event from a TLS session,
  the connection event and each request event, carries `"tls": true`; the key is absent, not false,
  on the plain listener (`crates/sensor-http/src/handler.rs#connection_event`). After each response the
  handler flushes and shuts the stream down, which sends `close_notify` over TLS as nginx does.
  Fail-closed: the sensor refuses to start (exit 1, before any bind) on a half-configured or
  unusable cert and key pair, and the key must be mode `0600`; an OS bind failure of the TLS
  listener stops the plain listener and exits 1. Cert and key without `PROPOLIS_HTTP_TLS_BIND` load
  and validate, start no TLS listener, and log one warning. Rules and variables are in
  [environment-variables.md](environment-variables.md); the operator view is
  [../operations/networking-tls.md](../operations/networking-tls.md#sensor-tls-attacker-facing-listeners).
- **Capture:** no login, no spool. **The POST body is captured only as a truncated
  preview in metadata**, never stored as a file.
- **Emits:** `honeypot_connection`, `honeypot_command_exec`.

### sensor-ftp

Impersonates **vsFTPd 3.0.5** (conventional port 21).

- **Behavior** (`handler.rs`): banner `220 (vsFTPd 3.0.5)`. Verbs
  (case-insensitive, including the PASV/EPSV and LIST/NLST distinctions: lowercase `pasv`
  gets the 227 reply and lowercase `nlst` the bare-names listing,
  `crates/sensor-ftp/src/handler.rs#handle_connection`): USER→331, PASS→login event + 230 (password
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
- **FTPS and AUTH TLS (optional):** `PROPOLIS_FTP_TLS_CERT` and `PROPOLIS_FTP_TLS_KEY` together
  enable AUTH TLS on the plain listener (21); `PROPOLIS_FTP_TLS_BIND` adds an implicit-TLS (FTPS,
  990) listener that needs the pair, where the handshake comes before the banner. Both run in one
  process, write one `events.jsonl` and share one capture hand-off and capture memory budget
  (`crates/sensor-ftp/src/lib.rs#start_listeners`); 990 exists only when its bind is set. No
  client certificate is requested. Rules, in the order the handler checks them
  (`crates/sensor-ftp/src/handler.rs#handle_connection`):
  - With no pair configured, AUTH, PBSZ and PROT get the unchanged `500 Unknown command.`, and
    FEAT omits `AUTH SSL`, `AUTH TLS`, `PBSZ` and `PROT`. With the pair, FEAT lists them.
  - AUTH inside TLS (implicit, or after an upgrade) gets `503 Bad sequence of commands.`. On a
    plain session `AUTH TLS`, `AUTH TLS-C`, `AUTH SSL` and `AUTH TLS-P` are accepted (the mechanism
    is case-insensitive); any other mechanism gets `504 Unknown AUTH type.`.
  - Bytes the client sent behind the AUTH line (already buffered when it is read) are refused
    before any `234`: one `honeypot_command_exec` event with `command` `AUTH`, `starttls_refused`
    `pipelined_plaintext` and `pipelined_bytes` (the count; the injected bytes are never captured
    or interpreted), then `504 Pipelined commands after AUTH TLS refused.`, a stream shutdown and
    the end of the session. The event is plaintext-phase and carries no `"tls"` key.
  - Otherwise `234 Proceed with negotiation.`, then the handshake bounded by the read timeout
    (`crates/sensor-framework/src/tls.rs#upgrade_buffered`). A failed handshake ends the session
    with no plaintext fallback. The upgrade then resets the session as REIN would: the username,
    the login state, PBSZ, PROT and any open passive listener are discarded, so a USER sent in
    cleartext does not carry into the protected session and the client must log in again; the
    per-connection captured-byte count is kept.
  - PBSZ is accepted only inside TLS and answers `200 PBSZ set to 0.` whatever the argument;
    on a plain control channel it gets `503 Bad sequence of commands.`. PROT needs TLS and a
    prior PBSZ, otherwise `503 Bad sequence of commands.`; then `PROT C` gets `200 PROT now Clear.`,
    `PROT P` gets `200 PROT now Private.`, `PROT S` and `PROT E` get `536 PROT not supported.`
    and anything else `504 Bad PROT command.`.
  - After `PROT P` the passive data connection is wrapped in TLS, but only after the data peer
    passed the same source-IP check as a plaintext transfer (`data_peer_matches`), so an off-path
    connector never reaches the handshake. The data handshake is bounded by the read timeout and a
    failed or stalled one gets `425 Failed to establish connection.`. LIST and NLST send the
    listing and then close the data stream (`close_notify` on TLS). STOR over `PROT P` is captured
    and spooled exactly like plaintext (same caps, same `honeypot_malware_upload` event), and a
    data connection closed without a `close_notify` counts as the end of the file, as vsftpd
    tolerates it (`crates/sensor-ftp/src/handler.rs#protect_data`).
  - Connection, login and upload events from a session whose **control channel** is TLS carry
    `"tls": true`; the key is absent, not false, on plain sessions
    (`crates/sensor-ftp/src/handler.rs#tag_tls`). Data-channel protection (`PROT`) does not
    change the tag, and the connection event of a plain session that later upgrades stays
    untagged. Passwords are never captured, TLS or not. QUIT sends `221` then a stream shutdown
    (`close_notify` on TLS).
  - An implicit handshake that fails or stalls is dropped with a debug log and emits no event.
  - Fail-closed: the sensor refuses to start (exit 1, before any bind) on a half-configured or
    unusable pair, a TLS bind without a pair, or an unparseable TLS bind, and the key must be
    mode `0600`; an OS bind failure on any listener stops the others and exits 1. A pair with no
    TLS bind is not an error: it enables AUTH TLS and opens no 990 listener. Variables and the
    full rules are in [environment-variables.md](environment-variables.md); the operator view is
    [../operations/networking-tls.md](../operations/networking-tls.md#sensor-tls-attacker-facing-listeners).
- **Emits:** `honeypot_connection`, `honeypot_login_attempt`,
  `honeypot_malware_upload`, and `honeypot_command_exec` (only the pipelined-AUTH-TLS refusal).

### sensor-tftp

A TFTP (RFC 1350) honeypot on UDP, conventional port 69. It is one of two sensors that
answer over UDP, so its reply surface is bounded in code and **it is off until an
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
- **Source check.** A request from an unspecified, broadcast or multicast address (IPv4-mapped
  IPv6 judged as the IPv4 it maps) or from a source port in
  `crates/sensor-framework/src/reply_source.rs#REFLECTIVE_SOURCE_PORTS` (0, echo 7, daytime 13,
  qotd 17, chargen 19, time 37) gets no transfer socket and no packet at all, not even the first
  ERROR or ACK 0. It is still recorded, with a `suppress_reason` of `unroutable_source` or
  `reflective_source_port` (`crates/sensor-tftp/src/handler.rs#Sensor::handle_request`). The
  check is the one `sensor-dns` uses
  (`crates/sensor-framework/src/reply_source.rs#check_reply_source`), and the transfer's send
  re-runs it before the byte budget (`crates/sensor-tftp/src/guarded.rs#Transfer::send`).
- **Rate limit** (`crates/sensor-framework/src/rate_limit.rs#ReplyRateLimiter`, wired in
  `crates/sensor-tftp/src/lib.rs#serve`). The byte budget stops amplification, not reflection
  itself: without a rate limit one spoofer can make the sensor send a victim one ERROR per
  request at line rate. Every datagram on the request socket, before it is parsed, takes a token
  from its source network's bucket (the IPv4 /24, IPv4-mapped IPv6 included, or the IPv6 /56) and
  from a global bucket, with the same defaults as `sensor-dns`: 5 per second with a burst of 10
  per network and 1000 per second with a burst of 2000 in total (`PROPOLIS_TFTP_REPLY_*`, see
  [environment-variables.md](environment-variables.md)). A datagram over either budget gets no
  reply and no event of its own; it is counted in its network's summary and one `rate_limited`
  event per network is written when its 10-second window ends (see Emits), with the same tables,
  eviction, overflow summary and 2-second shutdown flush as `sensor-dns`. Malformed datagrams are
  charged too, so a junk flood is summarized rather than invisible. The DATA, ACK and ERROR
  packets of a running transfer arrive on its own ephemeral socket and are not charged: the
  transfer is already pinned to one peer and answers only within that peer's byte budget.
- **Bounds.** The rate limit above; `max_concurrent` permits and the per-source admission cap (a
  request past either is dropped unanswered), per-transfer read/idle timeout, `max_duration`
  (dropping the transfer keeps what arrived), a packet cap derived from the body cap, and a
  retained-body cap of `PROPOLIS_TFTP_MAX_CAPTURED_BYTES` (default 1_000_000, at most
  `MAX_BODY_HARD_CAP` = 10_000_000, `crates/sensor-tftp/src/handler.rs#MAX_BODY_HARD_CAP`).
  A WRQ that never delivers a byte is recorded only as a probe, not as an empty upload. A zero or
  unparseable bound or rate aborts startup.
- **Spool:** 10&nbsp;MB / 100&nbsp;MB, hand-off queue 64
  (`crates/sensor-tftp/src/lib.rs#SPOOL_GLOBAL_BUDGET`, `crates/sensor-tftp/src/lib.rs#CAPTURE_QUEUE_SIZE`,
  `crates/sensor-tftp/src/lib.rs#start_test_server`). The body is never executed,
  served or interpreted; `netascii` uploads are stored as the raw bytes received.
- **Emits:** `honeypot_connection` per RRQ/WRQ the sensor handles (protocol `udp`, metadata
  `protocol_label`, `filename`, `mode`, `direction` of `rrq` or `wrq`, all sanitized, and
  `suppress_reason` when the source check refused it) and `honeypot_malware_upload` (protocol
  `udp`, standard upload metadata). Both share one session id per transfer. A request dropped by
  the per-source cap or the `max_concurrent` pool gets no event, only a `warn` log line at
  power-of-two totals. Rate-limited datagrams produce one `honeypot_connection` (protocol `udp`,
  `query_status` `rate_limited`) per source network per window, the same event `sensor-dns`
  writes (`crates/sensor-framework/src/rate_limit.rs#rate_limited_event`): `source_ip` is the
  first address seen from the network in the window, and the metadata carries `protocol_label`
  `tftp`, `transport` `udp`, `source_prefix` (CIDR, or `overflow`), `suppressed_count`,
  `suppressed_bytes` (each datagram counted up to the 1024-byte receive buffer,
  `crates/sensor-tftp/src/handler.rs#RECV_BUFFER`), `per_source_limited`, `global_limited`,
  `first_seen`, `last_seen`, `window_secs`, up to 8 sanitized `samples` of `"<rrq|wrq>
  <filename>"` (or `malformed`), and `distinct_sources` (counted up to 32, with
  `distinct_sources_capped` set beyond that). All TFTP events are `authenticated=false` (TFTP has
  no authentication). `wan_ip` resolves against the bind address, so a wildcard bind has the same
  attribution limit as the catch-all's UDP path.

### sensor-mqtt

An MQTT honeypot on TCP, conventional port 1883. It records metadata for every PUBLISH and
additionally spools a PUBLISH payload that passes the shared `looks_binary` gate
(`crates/sensor-mqtt/src/handler.rs#on_publish`). It is **off until an
operator sets `PROPOLIS_MQTT_BIND`**: with no bind it logs the error, exits 1 and binds
nothing (`crates/sensor-mqtt/src/main.rs#load_config_from_env`). It speaks MQTT 3.1
(`MQIsdp` level 3), 3.1.1 (`MQTT` level 4) and 5.0 (`MQTT` level 5), accepts any credential
on every connection (the deliberate low-interaction choice: it is what lets the
post-CONNECT SUBSCRIBE and PUBLISH recon through, and every CONNECT is logged, so a
brute-force run across connections is captured), and serves nothing: no message is ever
delivered to a subscriber, retained, or forwarded, no outbound socket is opened, and nothing
is executed. A binary PUBLISH payload is quarantined through the framework capture hand-off,
under the process-wide capture-memory budget, and never run.

- **Packets answered.** CONNECT (CONNACK accept `20 02 00 00`; for level 5
  `20 03 00 00 00`: ack flags 0, reason `0x00`, empty properties), SUBSCRIBE (SUBACK granting
  `min(requested, 1)` per filter, `0x80` for an invalid filter, `0x8F` in 5.0; the 5.0 SUBACK
  is the packet id, an empty properties byte, then one reason per filter), UNSUBSCRIBE
  (UNSUBACK; in 5.0 the packet id, an empty properties byte and a `0x00` reason per filter),
  PUBLISH (QoS 0 silent, QoS 1 PUBACK, QoS 2 PUBREC then PUBCOMP on PUBREL; the 5.0 acks use
  the short form with an implied success reason, which the spec allows), PINGREQ (PINGRESP),
  and in 5.0 only AUTH (answered with AUTH reason `0x00`, no properties, and logged as a
  `command` `AUTH` with its `reason_code` and `auth_method`). A 5.0 PUBACK, PUBREC or PUBCOMP
  is parsed and ignored, since the sensor never sends a PUBLISH. DISCONNECT closes. Every
  other type, a reserved fixed-header flag violation (SUBSCRIBE/UNSUBSCRIBE/PUBREL need
  `0b0010`, the rest `0`), a second CONNECT, any packet before CONNECT, and (before 5.0)
  AUTH, PUBACK, PUBREC or PUBCOMP close the connection without a reply
  (`crates/sensor-mqtt/src/handler.rs#Session`).
- **CONNECT.** The protocol name and level must pair as `MQIsdp`/3 or `MQTT`/4 or `MQTT`/5;
  any other pair, the reserved connect-flag bit, a will-QoS or will-retain without a will,
  will-QoS 3, or (before 5.0) a password flag without a username flag is malformed and closes
  the connection, recorded as a malformed connection event (see below). The password is read
  only to reach the end of the payload and is dropped; it never reaches an event or the log
  (`crates/sensor-mqtt/src/handler.rs#parse_connect`).
- **MQTT 5.0 properties.** A properties block is a varint byte length and then that many
  bytes of identifier and typed value. It is parsed strictly inside its declared length with
  checked indexing, reads at most `MAX_PROPERTIES` = 64 properties, and keeps at most
  `MAX_LOGGED_USER_PROPERTIES` = 16 user properties (`user_property_count` counts them all)
  (`crates/sensor-mqtt/src/handler.rs#parse_properties`). A malformed, unknown or
  over-count property stops the block and sets `properties_parse_error` on the event; the
  packet is not failed and the payload boundary stays exact, because the cursor lands on the
  declared block end. Only a declared length that does not fit in the packet is malformed.
  Session-Expiry-Interval, Receive-Maximum, Maximum-Packet-Size, Topic-Alias-Maximum,
  Request-Response-Information, user properties and the Authentication-Method name are
  decoded; Authentication-Data is a credential and, like the password, is read to advance
  the parser and dropped, never stored or logged. A 5.0 PUBLISH payload is the remainder
  after its properties block, and a Topic Alias is recorded as `topic_alias` and never
  resolved. Levels 3 and 4 have no properties blocks.
- **Keepalive.** After CONNECT the per-read idle wait is `min(idle_timeout, 1.5 x
  keepalive)`; a keepalive of 0 leaves `idle_timeout` in charge, as a real broker's
  keepalive-off does (`crates/sensor-mqtt/src/handler.rs#keepalive_idle`).
- **Parser bounds.** The remaining-length varint is at most four bytes (a fifth continuation
  byte closes the connection). A packet declaring more than `MAX_PACKET_BYTES` = 262144 bytes
  is refused on the declaration alone, before any body is read
  (`crates/sensor-mqtt/src/handler.rs#MAX_PACKET_BYTES`). The body is read through a limit of
  the declared length, so memory grows with bytes actually received, never with what is
  merely declared. A connection ends after `MAX_PACKETS` = 1024 packets
  (`crates/sensor-mqtt/src/handler.rs#MAX_PACKETS`), at `max_captured_bytes` total bytes read,
  on the first-byte `read_timeout` and per-read `idle_timeout`, or at `max_duration`.
- **Emits:** `honeypot_connection` at accept; `honeypot_login_attempt`
  (`authenticated=true`; `client_id`, `username` (empty when anonymous), `protocol_level`,
  `keepalive`, `clean_session`, and `will_topic` and `will_payload_len` when a will is set;
  for level 5 also `auth_method`, `session_expiry`, `receive_max`, `max_packet_size`,
  `topic_alias_max`, `request_response_info` and `user_properties` (name and value pairs,
  first 16) when present; never the password or the authentication data);
  `honeypot_command_exec` with `command` `SUBSCRIBE` (`topics` and `qos`
  for the first 32 filters, `topic_count` for all) or `PUBLISH` (`topic`, `qos`, `retain`,
  `dup`, `payload_len`, a `payload_preview` of at most 256 bytes as sanitized text or as hex
  when the prefix has non-UTF-8 or control bytes (`payload_preview_encoding` says which), and
  `payload_sha256` over the whole payload), or `AUTH` (5.0 only). Every attacker string is
  lossy-decoded, passed through `sanitize_value` and capped at 255 characters; no event
  carries a sample except the one below.
- **Binary PUBLISH capture.** When a PUBLISH payload passes `looks_binary`, the metadata
  event above is still emitted and the payload is also spooled, emitting a
  `honeypot_malware_upload` event (`crates/sensor-mqtt/src/handler.rs#capture_job`) whose
  metadata carries `topic`, `qos`, `retain`, `dup`, `capture_reason` =
  `binary_publish_payload` and, in 5.0, `topic_alias`. The sample is named after the
  sanitized, bounded topic (or `mqtt-publish-<session id>` when the topic is empty). A text
  or control payload stays metadata-only.
- **Malformed first packet.** A connection that sent bytes but whose first packet was
  malformed or not a CONNECT (a bad remaining length, an oversize declaration, a truncated or
  invalid CONNECT, a wrong fixed-header flag, a non-CONNECT first packet) emits a second
  `honeypot_connection` event with `malformed=true`, a `reason`, `bytes_seen`, and
  `first_bytes_hex`, at most 32 wire bytes as hex, never raw text
  (`crates/sensor-mqtt/src/handler.rs#malformed_observation`). A connection that sent
  nothing, and a malformed packet after a successful CONNECT, add no such event.
- **Session end.** Every connection ends with one `honeypot_session_end` event
  (`authenticated=false`; `packets`, `publishes`, `subscribes`, `bytes_in`, `duration_ms`
  and the `client_id` when a CONNECT was seen)
  (`crates/sensor-mqtt/src/handler.rs#Session::end_observation`). It is not emitted when
  `max_duration` cancels the handler, because the listener drops the handler future.
- **Bounds:** common defaults, `max_concurrent` 256, per-source admission cap. Strict
  parsing: a zero or unparseable bound aborts startup. Only a binary PUBLISH payload is spooled
  (see above); a text payload is never spooled.
- **MQTT over TLS (optional):** when `PROPOLIS_MQTT_TLS_BIND` is set, a second implicit-TLS
  (MQTTS) listener in the same process serves the same persona and writes the same
  `events.jsonl` (`crates/sensor-mqtt/src/lib.rs#start_tls_listener`). MQTT 3.1, 3.1.1 and 5.0
  all work over it. No STARTTLS exists and no client certificate is requested. The handshake is
  cut at the read timeout; a failed or stalled handshake, including plaintext sent to the TLS
  port, is dropped with a debug log and emits no event. Every event from a TLS session, the
  connection event, the login attempt, each command event, the malformed-first-packet event, the
  `honeypot_malware_upload` event and the session-end event, carries `"tls": true`; the key is
  absent, not false, on the plain listener (`crates/sensor-mqtt/src/handler.rs#stamp_tls`).
  Binary-PUBLISH spooling, the capture-memory budget and the shutdown drain apply identically
  over TLS: the plain and TLS listeners share one capture hand-off, one budget and one drain
  (`crates/sensor-mqtt/src/lib.rs#new_capture_handoff`). Replies are flushed, and every session
  ends with a stream shutdown, which sends `close_notify` on TLS and a FIN on a plain
  connection (the plain listener now closes its side cleanly too; no new event or reply
  results). No refusal replies are added. Fail-closed: the sensor refuses to start (exit 1,
  before any bind) on a half-configured or unusable cert and key pair, and the key must be mode
  `0600`; an OS bind failure of the TLS listener stops the plain listener and exits 1. Cert and
  key without `PROPOLIS_MQTT_TLS_BIND` load and validate, start no TLS listener, and log one
  warning. Rules and variables are in [environment-variables.md](environment-variables.md); the
  operator view is
  [../operations/networking-tls.md](../operations/networking-tls.md#sensor-tls-attacker-facing-listeners).

### sensor-dns

A DNS honeypot with three surfaces: UDP and TCP on the one `PROPOLIS_DNS_BIND` address
(conventional port 53) and, optionally, DNS over TLS (RFC 7858, conventional port 853). It is
**off until an operator sets `PROPOLIS_DNS_BIND`**: with no bind it logs the error, exits 1 and
binds nothing (`crates/sensor-dns/src/main.rs#load_config_from`). UDP and TCP are bound together
or not at all: UDP is bound first but not served until TCP binds on the same port, and if either
bind fails the sensor exits 1 with nothing left listening
(`crates/sensor-dns/src/lib.rs#start_test_server`). It serves no records: every query that parses
gets the same REFUSED reply, and it never resolves, forwards, or looks anything up.

- **Parsing** (`crates/sensor-dns/src/protocol.rs#parse_query`). Checks run in a fixed order and
  the first failure rejects the message: shorter than the 12-byte header (`short_header`), QR set
  (`response_inbound`: a response arriving inbound is never answered, so two DNS honeypots cannot
  loop), a non-zero opcode such as NOTIFY or UPDATE (`opcode`), QDCOUNT other than 1
  (`qdcount`), then the question: a compression pointer (`compression_pointer`; no pointer is
  ever followed), an extended or reserved label type (`bad_label`), a name over 255 wire bytes
  (`name_too_long`), or a name, type or class running past the end (`truncated_question`).
  Last, any answer record, or any authority record (`answer_or_authority_present`), except that
  an IXFR over TCP may carry the one SOA authority record RFC 1995 requires: exactly one
  authority record, of type SOA. Any other authority type is `answer_or_authority_present`, and
  an authority record that does not parse is `malformed_authority`. The EDNS scan never
  rejects: it walks at most 8 additional records for an OPT, skipping owner-name pointers
  without following them and holding each owner name to 255 wire bytes, root byte included, and
  records two OPT records, a non-root OPT owner, an unparseable additional record or an option
  running past its data as `edns_malformed`. At most 16 option codes are kept; option data is
  never stored (an ECS option carries a third party's subnet). The qname is rendered in RFC 1035
  master-file form, so every byte survives as printable ASCII (`\.`, `\\`, `\DDD`).
- **The one reply** (`crates/sensor-dns/src/protocol.rs#refused_reply`): the query's own header
  rewritten in place (ID kept, QR set, opcode 0, AA/TC/RA/Z/AD clear, RD and CD copied, RCODE 5
  REFUSED, QDCOUNT 1, other counts 0) followed by the first question copied verbatim, nothing
  appended. Its length is the end of the question, never more than the query, so on UDP **bytes
  sent never exceed bytes received**. AXFR and IXFR get the same REFUSED. No OPT record is
  returned even when the query had one; that is a known fingerprint, since a real EDNS responder
  returns an OPT [inferred].
- **UDP send guard.** Before the crate's single `send_to`
  (`crates/sensor-dns/src/guarded.rs#ReplySocket`), `crates/sensor-dns/src/guarded.rs#reply_gate`
  refuses to answer an unspecified, broadcast or multicast source, a source port in
  `crates/sensor-framework/src/reply_source.rs#REFLECTIVE_SOURCE_PORTS` (0, echo 7, daytime 13,
  qotd 17, chargen 19, time 37), both through
  `crates/sensor-framework/src/reply_source.rs#check_reply_source`, which `sensor-tftp` shares,
  and any reply a byte budget
  seeded with the query length would refuse.
  Such a query is still recorded, with `query_status` `suppressed` and a `suppress_reason`
  (`reflective_source_port`, `unroutable_source`, `byte_budget`). A rejected datagram gets no
  reply; a datagram shorter than a header gets neither a reply nor an event.
  `crates/sensor-dns/tests/integration.rs#never_amplifies_static_check` keeps the send site and
  the TCP write site to one each.
- **UDP rate limit** (`crates/sensor-framework/src/rate_limit.rs#ReplyRateLimiter`). Bounding
  each reply's size stops amplification, not reflection itself: without a rate limit one
  spoofer can make the sensor send a victim one reply per query at line rate. Every UDP datagram
  of at least a header first takes a token from its source network's bucket (the IPv4 /24,
  IPv4-mapped IPv6 included, or the IPv6 /56) and from a global bucket. The defaults are 5 per
  second with a burst of 10 per network and 1000 per second with a burst of 2000 in total
  (`PROPOLIS_DNS_REPLY_*`, see
  [environment-variables.md](environment-variables.md)). The first datagrams of a burst are
  handled, answered and logged as usual. A datagram over either budget gets no reply (there is
  no truncated "slip" reply: a honeypot has no legitimate client to steer to TCP) and no event of
  its own. It is counted instead in its network's summary in
  `crates/sensor-framework/src/rate_limit.rs#FloodLedger`, and one `rate_limited` event per
  network is written when its 10-second window ends (see Emits), so a flood costs the log at most
  one event per network per window. The network table holds 4096 networks and the summary table
  1024, both allocated once: a full network table evicts the least recently seen of four sampled
  entries, and a network arriving at a full summary table is counted in one `overflow` summary.
  At shutdown the summaries still accumulating are written, bounded by those tables and a
  2-second timeout. TCP and DoT are not rate limited: the handshake proves the source, so they
  cannot be aimed at a third party.
- **TCP and DNS over TLS** (`crates/sensor-dns/src/stream.rs#handle_connection`). RFC 1035
  length-prefixed framing; pipelined queries are answered in order. A length prefix under 12
  is rejected as `short_header` and one over
  `crates/sensor-dns/src/stream.rs#MAX_TCP_MESSAGE_BYTES` (4096) as `oversize`, in both cases
  without reading the body; either, or any rejected message, ends the connection without a
  reply. A connection carries at most
  `crates/sensor-dns/src/stream.rs#MAX_QUERIES_PER_CONNECTION` (64) queries and at most
  `max_captured_bytes` bytes, each message charged its 2-byte prefix as well as its body (the
  default 262_272 is exactly 64 maximum-size messages). A message that would pass that cap is
  not read and is rejected as `byte_cap`; a body the peer cuts short is `truncated_body`, and one
  that does not arrive within `read_timeout` is `body_timeout`. Each of those carries the
  `declared_len` and ends the connection. The first message must arrive within `read_timeout`
  and each later one within `idle_timeout`; a silent connection ends with no further event. A
  reply must be written within `read_timeout`, so a peer that stops reading cannot hold the
  handler. Every exit path of the handler shuts the stream down, so a DoT session it ends
  finishes with `close_notify`. The exception is `max_duration`: the listener drops the handler
  wherever it is waiting, which closes the connection with no `close_notify` and no event. DoT
  (`crates/sensor-dns/src/lib.rs#start_test_server_tls`) runs the same handler behind an
  implicit-TLS handshake cut at the read timeout; a failed or stalled handshake, plaintext
  included, is dropped with no event. No ALPN is advertised.
- **Emits:** UDP: one `honeypot_connection` (protocol `udp`) per datagram the sensor handles,
  with its own session id. Not every datagram is handled one by one: one over the rate limit is
  counted in a summary instead, and one dropped by the per-source admission cap or the
  `max_concurrent` pool, or whose handling `read_timeout` cuts off before the event is written,
  gets no event, only a `warn` log line at power-of-two totals. Rate-limited datagrams produce one
  `honeypot_connection` (protocol `udp`, `query_status` `rate_limited`) per source network per
  window (`crates/sensor-framework/src/rate_limit.rs#rate_limited_event`): `source_ip` is the first
  address
  seen from the network in the window, and the metadata carries `source_prefix` (CIDR, or
  `overflow`), `suppressed_count`, `suppressed_bytes`, `per_source_limited` and
  `global_limited` (which budget refused them), `first_seen` and `last_seen` (RFC 3339),
  `window_secs`, up to 8 sanitized `samples` of `"<QTYPE> <qname>"` (or `malformed`), and
  `distinct_sources` (counted up to 32, with `distinct_sources_capped` set beyond that). TCP and
  DoT: one `honeypot_connection` (protocol `tcp`) per connection, then one
  `honeypot_command_exec` (protocol `tcp`) per message, with `command` `"<QTYPE> <qname>"` or
  `malformed`. Events are appended before the reply is sent. Metadata: `protocol_label` `dns`,
  `transport`, `query_status` (`answered`, `rejected`, `suppressed` or `rate_limited`),
  `reject_reason`, `query_len`, `declared_len` (TCP framing rejects), `msg_index` (TCP/DoT), the
  header
  (`dns_id`, `flags_raw`, the four counts, `opcode`, `opcode_name`, `rd`, `ad`, `cd`), the
  question (`qname` sanitized and capped at 1024 characters, `qname_mixed_case`,
  `qname_labels`, `qname_wire_len`, `qtype`, `qtype_name`, `qclass`, `qclass_name`), `edns`
  (`version`, `udp_payload_size`, `do`, `extended_rcode`, `option_codes`) or `edns_malformed`,
  `probe_signals`, and for an answered query `rcode` `REFUSED` and `reply_len`. DoT events carry
  `"tls": true`; the key is absent on the plain surfaces
  (`crates/sensor-dns/src/events.rs#stamp_tls`). All DNS events are `authenticated=false`.
- **Probe signals** (`crates/sensor-dns/src/events.rs#probe_signals`), metadata only, never a
  `signal_type`: `amplification_probe` (UDP ANY, or UDP TXT/DNSKEY/RRSIG with an EDNS buffer
  over 512), `open_resolver_probe` (RD set, class IN or ANY, not a transfer),
  `zone_transfer_probe` (AXFR or IXFR), `chaos_fingerprint_probe` (class CH, for example
  `version.bind`).
- **Bounds:** the UDP rate limit above; `max_concurrent` applies separately to the UDP handler
  pool, the TCP listener and the DoT listener, each with the per-source admission cap; a UDP
  datagram's handling is cut at `read_timeout`. Strict parsing: a zero or unparseable bound or
  rate aborts startup. Nothing is spooled.
- **Port 53 already in use.** A bind failure names the transport and the address, for example
  `sensor-dns: udp: cannot start listener on 0.0.0.0:53: Address already in use (os error 98);
  refusing to start` (`tcp` and `dot` likewise). Find the holder with
  `sudo ss -lunpt 'sport = :53'`. Linux refuses a wildcard bind over any specific bind of the
  same port and a specific bind under a wildcard one, for UDP and TCP alike. So against the
  systemd-resolved stub, which holds only `127.0.0.53:53` (and `127.0.0.54:53`), binding the
  public address works and `0.0.0.0:53` does not; against a resolver holding the wildcard
  (dnsmasq without `bind-interfaces`, named with its default `listen-on`, unbound with
  `interface: 0.0.0.0` [inferred]) no bind of port 53 works until that resolver is narrowed. The
  fixes: for systemd-resolved, set `DNSStubListener=no` in `resolved.conf`, or bind the public
  address; for dnsmasq, `bind-interfaces` with `listen-address=127.0.0.1`; for unbound,
  `interface: 127.0.0.1`; for named, `listen-on { 127.0.0.1; };`. A host behind NAT binds its
  private address and maps it with `PROPOLIS_DNS_WAN_MAP`.
- **WAN attribution.** TCP and DoT events resolve `wan_ip` from the accepted socket's local
  address. UDP has no per-datagram local address, so UDP events (and `rate_limited` summaries)
  resolve it against the bind address, as `sensor-tftp` does: under a wildcard bind with a WAN
  map keyed on the public address, UDP events carry a null `wan_ip` while TCP events on the
  same port carry the mapped one. Bind the specific address when WAN attribution matters.
- **Verify from outside.** `dig @<host> example.com` (UDP), `dig +tcp @<host> example.com` and,
  with DoT on, `dig +tls @<host> -p 853 example.com` (BIND 9.18 or later; `kdig +tls @<host> -p
  853 example.com` from Knot is the equivalent [inferred]). The deploy certificate is
  self-signed, and neither tool checks it by default. Each answer shows `status: REFUSED`, flags
  `qr rd` (plus `WARNING: recursion requested but not available`, since RA is never set),
  `QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0`, the question echoed, and no `OPT
  PSEUDOSECTION` even though `dig` sends EDNS. The UDP query lands as `honeypot_connection` with
  `protocol` `udp`; the TCP and DoT queries as `honeypot_command_exec` with `protocol` `tcp` and
  `command` `A example.com.`, each after a `honeypot_connection` for the connection, the DoT
  ones with `"tls": true`. On the host, `ss -lunp 'sport = :53'` shows the UDP socket and
  `ss -ltnp 'sport = :53 or sport = :853'` the TCP and DoT listeners, all held by
  `sensor-dns`.

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
- **Redis over TLS (optional):** when `PROPOLIS_REDIS_TLS_BIND` is set, a second implicit-TLS
  (`rediss://`) listener in the same process serves the same persona and writes the same
  `events.jsonl` (`crates/sensor-redis/src/lib.rs#start_test_server_tls`). No STARTTLS exists and
  no client certificate is requested. The handshake is cut at the read timeout; a failed or stalled
  handshake, including plaintext sent to the TLS port, is dropped with a debug log and emits no
  event. Every event from a TLS session, the connection event, the login attempt and each command
  event, carries `"tls": true`; the key is absent, not false, on the plain listener
  (`crates/sensor-redis/src/handler.rs#connection_event`). The AUTH password is never captured over
  TLS either. Replies are flushed, and after a protocol error the handler sends its error reply and
  then shuts the stream down, which sends `close_notify`. Fail-closed: the sensor refuses to start
  (exit 1, before any bind) on a half-configured or unusable cert and key pair, and the key must be
  mode `0600`; an OS bind failure of the TLS listener stops the plain listener and exits 1. Cert and
  key without `PROPOLIS_REDIS_TLS_BIND` load and validate, start no TLS listener, and log one
  warning. Rules and variables are in [environment-variables.md](environment-variables.md); the
  operator view is
  [../operations/networking-tls.md](../operations/networking-tls.md#sensor-tls-attacker-facing-listeners).
- **Emits:** `honeypot_connection`, `honeypot_login_attempt` (AUTH),
  `honeypot_command_exec` (CONFIG SET dir/dbfilename, SET, SLAVEOF/REPLICAOF,
  EVAL/SCRIPT).

### sensor-smtp

Impersonates **Ubuntu Postfix ESMTP** (conventional port 25).

- **Behavior** (`handler.rs`): banner `220 <host> ESMTP Postfix (Ubuntu)` (persona
  host). EHLO advertises PIPELINING, SIZE 10240000, ETRN, STARTTLS, AUTH PLAIN
  LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING (`crates/sensor-smtp/src/handler.rs#handle_connection`). Verbs
  (`crates/sensor-smtp/src/handler.rs#handle_connection`): HELO/EHLO, STARTTLS (`454 TLS not available` unless TLS is
  configured, see "SMTP over TLS" below),
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
- **SMTP over TLS (optional):** `PROPOLIS_SMTP_TLS_CERT` and `PROPOLIS_SMTP_TLS_KEY` together
  enable STARTTLS on the plain listeners (25 and the optional 587,
  `PROPOLIS_SMTP_SUBMISSION_BIND`); `PROPOLIS_SMTP_TLS_BIND` adds an implicit-TLS (SMTPS, 465)
  listener that needs the pair. All listeners run in one process and write one `events.jsonl`
  (`crates/sensor-smtp/src/lib.rs#start_listeners`); 465 and 587 exist only when their bind is
  set. No client certificate is requested. Rules, in the order the handler checks them
  (`crates/sensor-smtp/src/handler.rs#handle_connection`):
  - Inside TLS (implicit, or after an upgrade) STARTTLS gets `503 5.5.1 Error: TLS already
    active`, and EHLO omits the STARTTLS extension; on a plain session it is offered.
  - STARTTLS with parameters, when TLS is configured, gets `501 5.5.4 Syntax error (no
    parameters allowed)`.
  - Plaintext the client sent behind STARTTLS (already buffered when the line is read) is
    refused before any `220`: one `honeypot_command_exec` event with `command` `STARTTLS`,
    `starttls_refused` `pipelined_plaintext` and `pipelined_bytes` (the count; the injected bytes
    are never captured or interpreted), then `554 5.5.1 Error: command pipelining after
    STARTTLS`, a flush, a stream shutdown and the end of the session. The event is
    plaintext-phase and carries no `"tls"` key.
  - Otherwise `220 2.0.0 Ready to start TLS`, then the handshake bounded by the read timeout
    (`crates/sensor-framework/src/tls.rs#upgrade_buffered`). A failed handshake ends the session
    with no plaintext fallback. After the upgrade MAIL FROM, RCPT TO and BDAT state is reset and
    the client must EHLO again; the per-connection captured-byte count is kept.
  - With no pair configured every STARTTLS line, with or without parameters, gets the unchanged
    `454 4.7.0 TLS not available due to local problem`, and EHLO still advertises STARTTLS.
  - Connection, login (`AUTH PLAIN` and `AUTH LOGIN`) and data events from a TLS session carry
    `"tls": true`; the key is absent, not false, on plain sessions
    (`crates/sensor-smtp/src/handler.rs#tag_tls`). Passwords are never captured, TLS or not.
    QUIT sends `221` then a stream shutdown (`close_notify` on TLS).
  - An implicit handshake that fails or stalls is dropped with a debug log and emits no event.
  - Fail-closed: the sensor refuses to start (exit 1, before any bind) on a half-configured or
    unusable pair, a TLS bind without a pair, or an unparseable extra bind, and the key must be
    mode `0600`; an OS bind failure on any listener stops the others and exits 1. A pair with
    no TLS bind is not an error: it enables STARTTLS and opens no 465 listener. Variables and
    the full rules are in [environment-variables.md](environment-variables.md); the operator
    view is
    [../operations/networking-tls.md](../operations/networking-tls.md#sensor-tls-attacker-facing-listeners).
- **Emits:** `honeypot_connection`, `honeypot_login_attempt`,
  `honeypot_command_exec` (DATA, and the pipelined-STARTTLS refusal).

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
  else refused. A `shell:<cmd>` that reads its standard input (see
  [Fake shell](#fake-shell-ssh-telnet-adb)) holds the stream open and takes its WRTE data as
  input; legacy ADB has no end-of-input message on a shell stream, so the client's CLSE (the
  command is killed, nothing is sent, the capture's end is `peer_closed`), the capture ceiling
  (the command runs on what was kept and the stream closes after its output) or the session's
  end ends it. At the interactive `shell:` a typed line that reads its input takes what is typed
  after it until Ctrl-D, as on the SSH and telnet shells
  (`crates/sensor-adb/src/handler.rs#HeldStdin`). Sync sub-protocol: SEND/DATA/DONE → captures the pushed file →
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
  `honeypot_malware_upload` (sync push, a binary shell payload, a command's standard input).
  Every shell stream shares the connection's handle on the sensor's
  [command-event budget](#command-event-budget-ssh-telnet-adb): repeats past it become one
  `command_summary` event per source network per minute.
  **All ADB events are authenticated=false.**

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
| **postgresql** (`postgresql.rs`) | PostgreSQL (5432) | StartupMessage (a GSSENCRequest is declined with `N`; an SSLRequest is declined with `N`, or accepted with `S` when TLS is configured, see below), parses the `user` param, sends AuthenticationMD5Password with a per-connection random salt, reads and discards the PasswordMessage → login event; then AuthenticationOk, a PostgreSQL 14 ParameterStatus set, BackendKeyData and ReadyForQuery, and a query loop: each simple query → `honeypot_command_exec` with the statement text, answered `ERROR 42501 permission denied` and ReadyForQuery, until Terminate, 200 statements, or the byte budget. Extended protocol: Parse records the SQL and answers ParseComplete; Bind, Describe (ParameterDescription then NoData for a statement, NoData for a portal) and Close get their completions; Execute is refused with 42501 and everything after it, a simple Query included, is discarded until Sync. |
| **mongodb** (`mongodb.rs`) | MongoDB OP_MSG (27017) | Answers isMaster/hello; on saslStart/authenticate extracts the SCRAM `n=<user>` or BSON `user` → login event (`crates/sensor-cred/src/mongodb.rs#handle_connection`, `crates/sensor-cred/src/mongodb.rs#extract_scram_username`, `crates/sensor-cred/src/mongodb.rs#extract_bson_string`). |

- Every cred protocol emits `honeypot_connection` + `honeypot_login_attempt`
  (authenticated=true). Username sanitized cap 255. **No spool**; passwords, DES
  responses, and MD5 responses are never stored.
- **Bind failures:** a protocol whose bind the OS refuses is logged and skipped; the others keep
  running, and the sensor exits 1 only when every configured protocol failed to bind
  (`crates/sensor-cred/src/main.rs#main`). The five are independent traps, and TLS adds no
  listener of its own whose loss this could hide.
- **TLS (optional):** `PROPOLIS_CRED_TLS_CERT` and `PROPOLIS_CRED_TLS_KEY` together enable TLS
  on the existing postgresql, mysql, mssql and mongodb ports. There is no TLS bind and no new
  port; vnc is unchanged. One certificate serves all four (`crates/sensor-cred/src/lib.rs#CredTls`).
  No client certificate is requested. Every handshake is bounded by the read timeout, and one that
  fails or stalls ends the session with no further event and no plaintext fallback (mssql and
  mongodb also log it at debug level). The `honeypot_connection` event is always written before
  the handshake, so a failed or abandoned handshake is still recorded.
  Plaintext clients keep working on every port. At startup the sensor logs which of the
  configured protocols TLS applies to, or a warning when none of the bound protocols can use it
  (vnc only, for example) (`crates/sensor-cred/src/main.rs#TLS_CAPABLE`).
  - **postgresql:** an SSLRequest is answered `S` and the handshake runs on the same socket; the
    StartupMessage and everything after it then travel over TLS. The reads before the upgrade are
    exact-length reads with no user-space buffer, so plaintext the client sent after the
    SSLRequest is never replayed into the TLS session: it reaches the handshake as garbage and the
    connection is dropped. This guards against an on-path party injecting plaintext behind the
    SSLRequest that a server would otherwise read as if it had arrived inside TLS. A plaintext
    StartupMessage and PasswordMessage sent after `S` get at most a TLS alert, never a PostgreSQL
    reply, and no login event
    (`crates/sensor-cred/tests/tls_integration.rs#pg_plaintext_after_s_is_dropped`). A second
    SSLRequest inside TLS closes the connection. Without the pair the answer is the unchanged `N`.
    A GSSENCRequest (code 80877104, sent first by libpq with its default `gssencmode=prefer`) is
    answered with a single `N`, with or without the pair, and the sensor keeps reading: the client
    then sends an SSLRequest (answered as above) or a plain StartupMessage
    (`crates/sensor-cred/src/postgresql.rs#handle_connection`). As in PostgreSQL's own startup
    handling, each request kind is honoured at most once per connection and none inside TLS, so
    at most two negotiation packets precede the StartupMessage; a repeated request closes the
    connection without a reply
    (`crates/sensor-cred/tests/tls_integration.rs#pg_repeated_negotiation_requests_close_the_connection`).
  - **mysql:** the greeting advertises `CLIENT_SSL` (0x0800) only when the pair is set. A 32-byte
    SSLRequest packet carrying that flag switches the session to TLS before the
    HandshakeResponse41, which then arrives over TLS and is answered OK with sequence id 3 (greeting
    0, SSLRequest 1, response 2). A client that ignores the flag is served exactly as before (OK at
    sequence id 2) (`crates/sensor-cred/src/mysql.rs#is_ssl_request`).
  - **mssql:** TLS inside TDS, per MS-TDS for TDS 7.x: the PRELOGIN response carries an ENCRYPTION
    option, the handshake records travel inside TDS PRELOGIN (0x12) packets, and once it completes
    Login7 and LOGINACK flow as raw TLS records (`crates/sensor-cred/src/tds_tls.rs`). TLS 1.3
    session tickets are switched off for mssql only, because a ticket written after the handshake
    would reach a client that has already stopped de-framing. The reply to the client's ENCRYPTION
    option (`crates/sensor-cred/src/mssql.rs#negotiate_encryption`):

    | Client offers | Reply | Session |
    |---|---|---|
    | `ENCRYPT_ON` (0x01) or `ENCRYPT_REQ` (0x03) | `ENCRYPT_ON` | TLS |
    | `ENCRYPT_OFF` (0x00) | the pre-TLS PRELOGIN response, byte for byte (VERSION only, no ENCRYPTION option) | plaintext |
    | `ENCRYPT_NOT_SUP` (0x02), or no ENCRYPTION option | `ENCRYPT_NOT_SUP` | plaintext |

    Only the low two bits of the client's value are read (`v & 0x03`); every other bit, the
    client-certificate bit 0x80 included, is ignored. This is deliberately not the MS-TDS
    server table: a real server with encryption on answers an `ENCRYPT_OFF` client with
    `ENCRYPT_REQ` and forces TLS, which would lose the Login7, and so the username, of every
    scanner that cannot do TLS. The honeypot chooses capture over fidelity, so a client offering
    `ENCRYPT_OFF` sees exactly what it saw before TLS existed. Login-only encryption (a reply of
    `ENCRYPT_OFF`) is never offered, since it would need a TLS-to-plaintext switch after Login7.
    The same capture-first rule covers a client that asked for encryption, was answered
    `ENCRYPT_ON`, and then sends a plaintext Login7 (packet type 0x10) where the first TLS
    handshake packet belongs: the first byte after PRELOGIN is read before the TDS-TLS adapter is
    built, and a 0x10 takes the plaintext Login7 path, so the username is captured in an untagged
    login event. Any other first byte goes to the adapter, which makes the same framed-or-raw
    decision it makes for a first read (`crates/sensor-cred/src/tds_tls.rs#TdsTlsAdapter`).
    Without the pair, the PRELOGIN response carries no ENCRYPTION option, as before
    (`crates/sensor-cred/src/mssql.rs#prelogin_response_without_tls_is_byte_identical_to_before`).
  - **mongodb:** on its plaintext port the sensor peeks (never consumes) the first two bytes,
    bounded by the read timeout. When they are `0x16 0x03` (a TLS handshake record and the record
    version's major byte) and the pair is set, the connection is served over TLS, the way a mongod
    in `allowTLS` mode takes both on one port. Anything else, fewer than two bytes before the
    timeout or end of stream, or no pair, takes the plaintext path. The connection event is
    written as soon as the sniff decides and before any handshake, tagged `"tls": true` when TLS
    was chosen, so a client that sends a ClientHello and then aborts, rejects the certificate, or
    stalls is recorded exactly once, as it would be on a node without TLS
    (`crates/sensor-cred/src/mongodb.rs#handle_sniffed`). A MongoDB message starts with
    its little-endian length, so a one-byte check would misroute every plaintext first message
    whose length is 22, 278, 534 and so on; with two bytes only a 790-byte first message still
    matches, and longer matching lengths exceed the 64 KiB message cap
    (`crates/sensor-cred/src/mongodb.rs#TLS_RECORD_PREFIX`). When only `0x16` has arrived the peek
    is retried every 10 ms (`crates/sensor-cred/src/mongodb.rs#SNIFF_REPEEK`). After a sniff that
    times out, the plaintext path waits up to another read timeout for the message header, so a
    silent connection can hold a slot for up to twice the read timeout, still capped by the
    maximum session duration.
  - **Event tagging:** events from a TLS session carry `"tls": true`; the key is absent, not
    false, on plaintext sessions (`crates/sensor-cred/src/lib.rs#with_tls`). For postgresql, mysql
    and mssql the `honeypot_connection` event is written before negotiation and stays untagged,
    while the login and postgresql query events of a TLS session are tagged. For mongodb the sniff
    decides TLS before the connection event is written, so every event of a TLS session is tagged,
    the connection event included, even when the handshake then fails. An mssql Login7 captured
    by the plaintext fallback above is untagged.
  - **Fail-closed:** when either variable is set (a blank value counts as unset) the pair must
    load, or the sensor exits 1 before binding any protocol; exactly one set, a non-UTF-8 value,
    an unusable pair and a key that is not mode `0600` all count. Variables are in
    [environment-variables.md](environment-variables.md); the operator view is
    [../operations/networking-tls.md](../operations/networking-tls.md#sensor-cred-in-band-tls).
  - **Validation scope:** the MSSQL TDS-TLS adapter is validated against a rustls client (TLS 1.2
    and 1.3) framed by hand in the tests and against the MS-TDS text, not against real SQL Server
    drivers. The owner smoke tests listed in
    [../operations/networking-tls.md](../operations/networking-tls.md#sensor-cred-in-band-tls)
    are still to be run.

## Cross-cutting invariants

- **Session id:** `Uuid::now_v7()` minted per accepted TCP connection by the
  listener, per datagram for catchall UDP and DNS UDP, per transfer for TFTP, and per summary
  for a DNS or TFTP `rate_limited` event; carried on every event.
- **Password discipline:** every login-capturing sensor reads the password only to
  advance the protocol and drops it - never stored, logged, or placed in any event
  field (SSH `crates/sensor-ssh/src/auth.rs`, telnet `crates/sensor-telnet/src/handler.rs#handle_connection`, FTP `crates/sensor-ftp/src/handler.rs#handle_connection`, redis
  `crates/sensor-redis/src/handler.rs#Session::handle_auth`, SMTP `crates/sensor-smtp/src/handler.rs#handle_connection`, MQTT `crates/sensor-mqtt/src/handler.rs#parse_connect`, cred handlers). Tests assert absence at
  the serialized-JSON level.
- **`authenticated` flag:** `honeypot_connection` and `catchall_probe` are always
  false; ADB, TFTP and DNS events are always false (no auth step); `honeypot_login_attempt` is
  true; `honeypot_command_exec` reflects session auth state (redis/http false,
  ssh/telnet true post-login).
- **Never-serve-outbound:** FTP RETR→550, FTP PORT/EPRT→502, ADB sync RECV→FAIL,
  SSH `direct-tcpip` refused, catchall/UDP never responds, TFTP RRQ gets one tiny
  error and never any file content, an MQTT PUBLISH is recorded but never delivered,
  retained or forwarded, a DNS query gets REFUSED and no record, shell `wget`/`curl`
  canned - no sensor fetches or serves attacker-directed content.

## Notes

- `SensorConfig` in `sensor-framework/src/config.rs` is the framework's aggregate
  config type but is **not** used by the individual sensor binaries; each sensor
  defines its own `Config` struct. It appears to be dead or reference-only surface
  `[inferred]`.
- The SSH version-exchange wire string (`SSH-2.0-<banner>`) is `[inferred]` from
  the banner default and handshake usage; the exact formatting function body was
  not read line-by-line.
