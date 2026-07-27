# Sub-project 2: native sensor framework + catch-all + first TCP-auth sensor

Detailed design spec for the Propolis-new native sensor layer (Rust). This layer sits directly on
the core scoring layer (sub-project 1): it produces the events that layer scores. It is built
complete and tested in isolation before the intake layer (sub-project 3) that consumes its output.

## Purpose and scope

This layer owns three things and nothing else:

1. The sensor framework: a safe-by-construction harness that every self-authored passive sensor is
   built on. It fixes the shared isolation contract (unprivileged, no database handle, no secrets,
   passive-only) and provides the reusable machinery (listener lifecycle, bounded capture, WAN
   attribution, sanitized event emission, quarantine spool) so an individual sensor is small.
2. The catch-all listener: a raw TCP and UDP listener across a wide operator-configured port set. It
   supplies breadth signal (`catchall_probe`) and nothing else. It emulates no protocol.
3. The first TCP-authenticated honeypot: a self-authored SSH server that produces the confirmed-real
   event the eligibility floor requires (`protocol = tcp AND authenticated = true AND category =
   honeypot`), plus the attacker's command sequence and any uploaded samples.

This layer has no database handle, no vendor client, no web surface, no scoring logic, and no
outbound path to any attacker or third party. A sensor observes, captures a bounded sanitized record,
and appends it to a local log. Deriving weight, confidence, and category from the signal type, and
writing the ledger, belong to intake (sub-project 3) and the core scoring layer; a sensor never
computes them.

The single cross-cutting interface this layer must settle is the sensor to intake wire contract,
flagged in `architecture/frozen-contracts.md` as the highest-risk deferred interface. It is settled
here (see The sensor to intake wire contract) before sub-projects 2 and 3 fork.

## Inherited invariants (from the roadmap and security posture)

These are established at the foundation and are not relitigated here; this layer realizes them.

- **Passive-only.** A sensor never responds to an attacker, never probes back, never originates
  outbound traffic to a source. UDP sensors never answer, so a sensor can never be a reflection or
  amplification vector. The only outbound actions the whole platform ever takes are operator-approved
  vendor reports and the published feed, both in later layers.
- **Least authority.** Each sensor runs unprivileged under its own dedicated OS user, holds no
  database handle, holds no secrets (no vendor API keys, no DB credentials, no push tokens), and
  carries only `CAP_NET_BIND_SERVICE` when it must bind a privileged port - granted by the service
  manager, never by root.
- **PII dropped at capture.** Passwords and raw payload bodies are dropped at the sensor, at capture
  time, and never enter an emitted event. Where a credential must be read to parse a record, it is
  read and discarded in the same step.
- **One-directional log flow.** A sensor has write access only to its own log and spool; intake has
  read-only access. Enforced by filesystem permissions and service-manager mounts, not convention.

## Architecture

Four crates, added to the workspace:

- `crates/sensor-wire` - the on-disk event record and sample-reference types (serde). One
  definition, imported by both the sensors (producer) and sub-project 3 intake (consumer), so the
  wire shape has a single source of truth and cannot drift into two clones.
- `crates/sensor-framework` - the shared harness (library). Depends on `sensor-wire`. Has no
  database dependency and no secret-bearing dependency, so a sensor built on it cannot hold either by
  construction.
- `crates/sensor-catchall` - the catch-all listener (binary).
- `crates/sensor-ssh` - the SSH honeypot (binary).

Each sensor binary is a thin composition: it configures the framework with its port set and its
per-connection handler, and the handler emits events. The framework owns everything that must be
uniform across sensors; a sensor owns only its protocol-specific capture logic.

### Vendored cryptographic primitives

The SSH honeypot needs real, correct SSH crypto (a client verifies the key exchange and MAC, so it
cannot be faked). The SSH *server* - the binary packet protocol, the handshake orchestration, the
authentication state machine, the fake shell, and all capture - is self-authored Propolis code. The
raw cryptographic *primitives* underneath it (curve25519 key exchange, an ed25519 host key,
ChaCha20-Poly1305, the hashes) are the small, foundational RustCrypto primitive crates - the same
family as the `sha2` the core scoring layer already ships for its hash chain - and their pinned
source is vendored into the tree (`cargo vendor` + `.cargo/config.toml`), so the build never fetches
them and no upstream project can be abandoned out from under Propolis. Rationale and the rejected
alternatives (a third-party SSH server library; reimplementing the primitives) are recorded in
ADR-0011.

## The sensor to intake wire contract

This is the frozen interface. It has three parts: the event record, the sample side channel, and the
integrity model.

### Event record

Each event is one line of newline-delimited JSON, appended to the sensor's local log. One line is
one event; a single SSH session produces several lines (a connection, a login attempt, each command,
an upload). The record carries exactly the facts the core scoring layer's `EventInput::from_signal`
needs, and nothing derived:

```json
{
  "v": 1,
  "source_ip": "203.0.113.7",
  "wan_ip": "198.51.100.4",
  "sensor": "ssh",
  "signal_type": "honeypot_command_exec",
  "protocol": "tcp",
  "authenticated": true,
  "observed_at": "2026-07-20T14:03:11.482913Z",
  "metadata": { "protocol_label": "ssh", "command": "uname -a" },
  "sample": null
}
```

- `v` is the schema version. New optional fields may be added under the same version; a bump is
  reserved for a change that intake must actively transform (mirrors the additive-only schema policy).
- `signal_type` is the snake_case `signal_type_enum` value. The sensor never emits `weight`,
  `confidence`, or `category`: intake derives all three from `signal_type` via `from_signal`, the
  single source of truth, and `validate()` rejects any record whose signal type is unknown.
- `observed_at` is UTC at microsecond precision, matching the ledger's hash normalization.
- `metadata` is sanitized and PII-free: an indicator such as the offered username, the command
  string, or a probe banner - never a password, never a full payload body. Every attacker-controlled
  value in it has passed the capture sanitization contract below; that is a hard precondition of the
  wire format, not a quality-of-implementation matter.
- `metadata.protocol_label` is the **exact lowercase L7 protocol label**, and it is mandatory on
  every event a protocol-speaking sensor emits. It is distinct from `protocol`, which is the L4
  `protocol_enum` (`tcp`/`udp`/`icmp`) and cannot express the application protocol. Sub-project 4
  derives a protocol-specific vendor report category from this string on top of the generic
  brute-force category, so the literal matters: `ssh`, `telnet`, `ftp`. A daemon-style label
  (`ftpd`, `mysqld`, `smbd`) or a near miss (`mysql`, `http`) silently collapses to the generic
  category with no error and no test failure, which is exactly how the old system lost the FTP
  category until it was pinned. The lexicon is pinned by test (see Testing strategy). The catch-all
  emulates no protocol and therefore emits no `protocol_label`.
- `sample` is present (non-null) only on an upload or download event: `{ "sha256": "...", "size":
  12345, "orig_name": "x" }`, referencing a file on the quarantine side channel. Intake folds it into
  the event `metadata` and uses the SHA-256 to locate the spooled body. `orig_name` is an
  attacker-controlled string carried as an indicator only; it is sanitized like any other metadata
  value and is never used as a path component (see Sample side channel).

`wan_ip` is the local WAN IP the connection arrived on - the per-hit WAN attribution the breadth
model depends on. The framework resolves it from the accepted connection's local socket address,
mapped through an operator-supplied local-address to WAN-IP table where NAT or DNAT is in play (the
operator's WAN IPs are NAT'd to the host). Where no mapping applies - a corroborating sensor with no
bindable WAN IP - `wan_ip` is null, exactly as the ledger column allows. Aggregating these across
collector nodes is sub-project 3's job; this layer's job is to stamp each event with the WAN IP it
landed on.

### Capture sanitization contract

The transport is newline-delimited, so the neutralization of attacker-controlled text is part of the
wire contract rather than a hygiene nicety. An attacker types the command; the attacker names the
uploaded file; the attacker chooses the probe bytes. If any of those reaches the log carrying a
newline, the sensor emits **two** lines and the second one is an event the attacker authored.
Intake would ingest it faithfully and the ledger would hash-chain it as genuine evidence. Note what
the integrity model below does and does not cover: the OS channel and the hash chain defend against
a *compromised* sensor and against later alteration of stored evidence, and neither one stops an
uncompromised sensor from being talked into emitting a forged event. Log injection is therefore the
live integrity threat against this wire format, and the capture-time chokepoint is what closes it.

Every attacker-controlled value is passed through one shared sanitizer in `sensor-framework` before
it can enter a record. There is exactly one such function; a sensor never hand-rolls a second path.
Its order of operations is load-bearing:

1. Convert CR, LF, tab, vertical tab, and form feed to a single space **first**, before any other
   stripping. Doing this after control-character removal is the classic mistake: a stripped control
   character can leave a bare newline behind, and the record is forged anyway.
2. Strip ANSI CSI escape sequences, the C0 and C1 control ranges, U+2028 and U+2029, and the
   invisible, bidirectional-override, and zero-width sets. These are operator-console attacks
   (terminal escapes and text-direction spoofing) staged through captured evidence.
3. Normalize to NFC and cap the value at a fixed maximum length.

Paired with it is a structural invariant that holds even if the sanitizer were bypassed:
**byte-derived metadata fields carry only hexadecimal or a SHA-256 digest, never decoded bytes.**
A hex string cannot express a newline, a control character, or a markup delimiter, so a truncated
payload sample or a digest is safe by its alphabet rather than by a function call. Genuinely textual
fields (command, username, filename-as-text) get the sanitizer; raw captured bytes get hex. Where a
protocol banner must be reproduced byte-exactly it is handled as bytes, never as UTF-8 text, so
high-range protocol bytes are neither corrupted nor smuggled into a record as text.

### Sample side channel

Captured file bodies never travel inline in the event line (they are binary and unbounded). The
framework writes each captured body to an isolated quarantine spool directory, one file named by its
SHA-256, size-bounded, with no-execute permissions, and never opened or executed by any Propolis
process. The event references it by SHA-256. Intake reads event and spool together. The SHA-256 is
both the spool dedup key and, downstream, the VirusTotal lookup key (SP4/SP8). The quarantine store,
retention, and the operator-approved forward to VirusTotal are downstream layers - this layer only
captures the body sterile and references it.

Four properties of the spool are load-bearing rather than incidental:

- **The spool is a `noexec,nosuid,nodev` mount, not merely a directory of non-executable files.**
  Permission bits are one `chmod` away from being wrong; the mount option holds regardless of what
  any process does to a file inside it. Files are mode 0600 or 0640, owned by the sensor's dedicated
  user.
- **The attacker's filename is never a path component.** The on-disk name is the honeypot-computed
  SHA-256, an index this layer controls, which makes path traversal structurally impossible rather
  than a validation problem. The attacker-supplied name survives only as sanitized text in
  `sample.orig_name`.
- **Re-hash on read, fail closed on mismatch.** A body whose content no longer matches the digest it
  is filed under is treated as corrupt and refused, never passed downstream.
- **The spool carries a global byte budget, not only a per-transfer cap.** A per-connection or
  per-transfer limit bounds one attacker's upload and does nothing about many of them; without a
  store-wide ceiling the spool can be filled long before any downstream retention policy runs. When
  the budget is reached, further captures are refused and logged as a refusal with the observed size,
  which is still a recorded sighting. The budget's value is an operator-set, range-validated config
  bound, and zero does not mean unlimited.

### Integrity model

The scope's original wording ("signed events") is amended here, because the no-secrets posture makes
sensor-side cryptographic signing both impossible and pointless: a signature needs a key, a key is a
secret forbidden on a sensor, and a compromised sensor holding its own signing key would hand that
key to the attacker - defending against nothing. The real, stronger model has two parts:

1. **Trust boundary: the OS-enforced one-directional channel.** The sensor's OS user has write-only
   access to its log and spool; intake has read-only access. A sensor compromise can spoil *that
   sensor's own* lines and reach nothing else - precisely the blast radius the posture already
   accepts. This boundary is filesystem permissions plus service-manager mounts, kernel-enforced.
2. **Tamper-evidence: the ledger hash chain (sub-project 1),** applied by intake as it appends each
   event. Altering ingested evidence breaks the chain and is detectable. Integrity of the durable
   evidence lives in the ledger, not in a sensor-held signature.

This amendment closes the deferred frozen-contract item; it is recorded in ADR-0010 and reflected in
`architecture/frozen-contracts.md`.

### Transport

The sensor appends to a local newline-delimited JSON log file; intake tails it from a durable offset
cursor (inode, offset, and a content fingerprint, rotation- and truncation-aware) for at-least-once
delivery. This is chosen over a local socket or a message broker because events survive on disk when
intake is down, so the sensor's hot path never blocks on intake liveness (a hard rule: a protective
or emit path must never await a downstream that can hang), it is crash-safe, and it keeps the sensor
trivial - append a line, no network client, no connection state, no database handle. The multi-node
aggregation transport (a direct PostgreSQL write per collector versus a broker in front of intake) is
sub-project 3's decision; this layer fixes only the sensor to local-log contract.

**The producer bounds the log; the consumer only tolerates the bounding.** Requiring intake's cursor
to be rotation- and truncation-aware describes how the reader copes, and specifies nothing that
actually causes rotation. An unbounded append driven by internet-facing traffic is a disk-fill denial
of service against the host, and it is trivially reachable: a flood of probes costs the attacker
nothing and each one writes a line. This layer therefore ships the rotation policy with the sensor,
as a required deliverable rather than a deployment detail: a size cap with a retained-generation
count, using a rotation mode the appending sensor survives (either `copytruncate`, which preserves
the sensor's open descriptor, or a reopen-on-signal path in the sensor). The pairing is verified
end to end, because a rotation mode the tailer mishandles silently loses events rather than failing
loudly (see Testing strategy).

## The sensor framework

The framework provides, once, for every sensor:

- **Listener lifecycle.** Bind the configured TCP and UDP ports, run the accept loop, and shut down
  gracefully on signal. A per-port bind failure is non-fatal and logged: the sensor binds what it can
  and keeps serving, so one unavailable port never takes the sensor down.
- **Privileged-port binding.** Ports below 1024 are bound with `CAP_NET_BIND_SERVICE` granted by the
  service manager. The process never runs as root and holds no other capability.
- **WAN attribution.** For each accepted connection, resolve the local landing address to a WAN IP
  (through the operator's local-address to WAN-IP table where NAT applies) and stamp it on every
  event from that connection.
- **Bounded per-connection resources.** A read timeout, an idle timeout, a maximum session duration,
  a maximum captured-bytes budget, and a concurrent-connection cap. A sensor is internet-facing and
  must not be turnable into a resource-exhaustion victim; these bounds are enforced by the framework,
  not left to each handler.
- **Capture sanitization.** The single shared sanitizer of the capture sanitization contract, plus
  helpers that capture a bounded, truncated sample as hex. Passwords and full payload bodies are
  dropped here, at capture; the emit path has no way to carry them. A sensor has no route to a record
  that bypasses this.
- **Event emission.** Serialize a `sensor-wire` record and append it atomically as one line to the
  local log.
- **Off-response-path capture hand-off.** Hashing a body, writing it to the spool, and appending the
  event are done by a worker task, never on the connection's reply path. Once the handler has read
  enough to commit its protocol reply it enqueues the capture job on a bounded in-process queue and
  answers immediately. The reason is covertness, not throughput: an attacker who measures response
  latency is measuring exactly the work that only happens when something is worth capturing, so
  doing it inline announces the capture, and announces it hardest under load when the delay is
  largest. **A full queue drops the job and increments a counter; it never blocks the producer.**
  Blocking to avoid losing a sample would reintroduce the precise latency tell the hand-off exists
  to remove, and would do so under exactly the saturation an attacker can induce on purpose. Under
  overload this layer loses a sample rather than its covertness, and the drop is a metric the
  operator can see.
- **Quarantine spool.** Write a captured body to the isolated spool by SHA-256, size-bounded,
  no-execute, and return the reference for the event.

A per-connection handler that panics or errors never crashes the accept loop: the framework isolates
each connection, drops the offending one, and keeps serving - the never-raise contract, at the
connection boundary.

## Catch-all listener

Signal `catchall_probe` (category `network`, `authenticated = false`). A from-scratch raw TCP and UDP
listener across an operator-configured port set (a validated, bounded config; a wide default on the
order of the old ~50 ports). For each hit it captures a bounded record - a truncated payload sample, a
banner, and the full observed length - and emits one event. It emulates no protocol and presents no
service beyond accepting the connection or datagram. UDP is log-only: the listener records the
datagram and sends nothing back, by construction, so it can never be a reflection or amplification
vector. A bind failure on any single port is non-fatal.

## SSH honeypot

Binary `sensor-ssh`. A self-authored SSH server over the vendored primitives, deep enough to capture
the full attack but incapable of executing anything.

### Protocol and authentication

The server performs the real SSH transport: version exchange, key exchange (curve25519), an ed25519
host key, and an encrypted channel (ChaCha20-Poly1305). On transport establishment it emits
`honeypot_connection` with `authenticated = false`. When the client sends a user-authentication
request, `authenticated` latches true for that session and every subsequent event: a completed SSH
key exchange is a multi-round-trip cryptographic proof that the source address is real, and reaching
user-authentication is the point at which the confirmed-real semantics apply. The server captures the
offered **username** (an indicator) and drops the password at capture. It accepts the authentication
(so the attacker reaches the shell and reveals intent) and emits `honeypot_login_attempt` with
`authenticated = true` - the event that sets `has_confirmed_real` in the ledger.

### Fake shell

On an accepted session the server presents a fake interactive shell backed by an in-memory fake
filesystem with canned responses. Every command the attacker types is captured as
`honeypot_command_exec` - the primary telemetry of this sensor, the attacker's actual command
sequence and tooling. An SCP or SFTP transfer is captured as `honeypot_malware_upload` (or
`honeypot_file_download`): the file body is written sterile to the quarantine spool and the event
references it by SHA-256; the password and no unbounded content ever enter an event.

### Never-exec (load-bearing, architectural)

The fake shell never passes a single attacker byte to a real shell, an `exec`-family syscall, a
subprocess, or any interpreter. This is guaranteed by construction, not by care: the crate depends on
no process-spawning facility, uses no dynamic evaluation, and serves only canned responses over the
in-memory fake filesystem. It is locked by a test that asserts the process spawns no child across a
full captured attack session (see Testing strategy). This is the single highest-risk property in the
platform and the review gates on it.

### No attacker-directed fetch (load-bearing, architectural)

Never-exec's companion, and the second guarantee the review gates on. The rule is that **direction
decides danger**:

- **Inbound push is safe to capture.** The attacker's socket already carries the bytes, and the
  sensor makes no request of its own, so there is no request-forgery surface. `scp -t`, an SFTP
  write, an FTP `STOR`, a TFTP `WRQ`: capture under the read-time byte caps.
- **An attacker-directed outbound fetch is never performed, by any sensor, ever.** The fake shell
  will be typed at with `wget` and `curl` constantly, because that is what the attacker came to do.
  The shell returns a plausible canned transcript, records the requested URL as an indicator, and
  performs **zero** network I/O. The same holds for every verb whose semantics are "the server goes
  and gets something": FTP `RETR`, TFTP `RRQ`, and FTP's `PORT` bounce, which is a server-initiated
  connection to an attacker-named host and port and is the request-forgery primitive of that
  protocol. None is ever honored.

This is the exact defect that produced CVE-2025-34469 in Cowrie, whose emulated `wget` and `curl`
issued real outbound requests to attacker-named hosts: a single session driving concatenated fetches
generated on the order of a thousand outbound requests in a few seconds, all sourced from the
honeypot's own address. That inverts the platform's whole purpose at once. It masks the attacker
behind the sensor's IP, so the attribution the entire scoring model rests on now points at the
operator; it makes the honeypot a denial-of-service amplifier aimed at a third party, which is the
`passive-only, no hack-back` invariant broken from the inside; and it exposes any reachable internal
or cloud-metadata address to an attacker who only has to type a URL.

Rate-limiting a fetcher is not a fix and must not be mistaken for one. The upstream remediation was
volume-limiting, which leaves the forgery surface entirely intact: it adds no egress filtering, no
blocking of loopback, private, link-local, or metadata addresses, no DNS pinning, no redirect
suppression, and no scheme restriction. The only safe fetcher is one that is never built here.
Should an operator ever want the artifact behind a captured URL, that is a separate, disposable,
egress-filtered process in a later layer and off by default (see the deferred list); it is never
the sensor, and never inline.

Like never-exec, this is guaranteed by construction: `sensor-ssh` and `sensor-framework` depend on
no HTTP or outbound network client, so there is nothing present to make the request with, and a
test asserts the sensor opens no outbound connection across a full captured session.

### Host key

The honeypot generates and persists its own SSH host key locally, because an SSH server must have one
and because persisting it stops the honeypot from fingerprinting itself as freshly minted on every
restart. This host key is not a platform secret: no vendor, database, session, or push credential
reaches the sensor (the posture is unchanged), and compromise of a honeypot's host key is immaterial -
impersonating a honeypot has no value. The interaction with the no-secrets posture is recorded in
ADR-0011.

## Isolation and deployment

Each sensor ships a hardened service-manager unit running as its own dedicated OS user. The unit
grants write access only to that sensor's own log and spool directory. Intake mounts those
read-only. The log flow is one-directional and kernel-enforced. A sensor unit that lacks this
hardening is a defect, not a deployment convenience deferred to later.

Three layers, each answering a different failure:

- **Least authority.** `NoNewPrivileges`, `ProtectSystem=strict`, a read-only system view,
  `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies=AF_INET AF_INET6`, and a single
  `CAP_NET_BIND_SERVICE` (both ambient and in the bounding set) only where a privileged port is
  bound. This bounds what a working sensor can reach.
- **Resource caps.** `MemoryMax`, `TasksMax`, `CPUQuota`, and `LimitNOFILE`. The per-connection
  bounds in the framework govern one attacker; these govern the aggregate, which is what a flood
  actually produces. An internet-facing listener with no ceiling is a resource-exhaustion victim
  waiting for a cheap attack.
- **Containment.** A `SystemCallFilter` allowlist plus `MemoryDenyWriteExecution`. This is the layer
  that pays off when a memory-safety defect exists despite Rust, which is the honest assumption for
  a self-authored SSH implementation parsing hostile binary packets: unsafe code, a dependency, or a
  logic error reachable pre-authentication. The empirical argument is OpenSSH's, whose sandbox
  contained a pre-authentication double-free because exploitation required a syscall the filter
  denied. A tight filter downgrades memory corruption from remote code execution to a crash, and a
  crashed sensor is a monitored, recoverable event. The sensor's actual needs are small (socket I/O,
  file append, event loop, futex, memory management), but the exact set is **derived empirically
  against the running binary and re-derived when its syscall surface changes**. A syscall list
  copied from a document is either too narrow, breaking the sensor in production, or too wide,
  meaning nothing.

**The unit hardening is asserted by test, not by documentation.** A directive that exists only in
prose is one careless edit away from silently disappearing, and nothing about a passing test suite
or a running sensor would reveal it. The directives above are checked mechanically the same way the
never-exec guarantee is (see Testing strategy).

## Detectability and anti-fingerprinting

A honeypot that is trivially identified as one stops collecting the signal it exists to collect, so
detectability is a design property of this layer and is stated here with its limits rather than left
implicit.

**The achievable goal, stated honestly.** Concealment from a determined analyst is not achievable
and is not an objective. Low- and medium-interaction honeypots have been fingerprinted at internet
scale from a single crafted packet, across thousands of deployments and nine different
implementations, with the authors' explicit finding that correcting identity strings and error
messages is not sufficient, because the distinguishing behaviour lives in thousands of protocol
interactions no reimplementation reproduces exactly. The realistic goal is to defeat the bulk of
threat volume: mass scanners, commodity fingerprint-and-skip tooling, and known-signature scoring
services. Clearing that bar means not being a default-configuration signature match and not
contradicting oneself. Framed as raising the cost of identification above one canned packet, not as
invisibility. No claim of undetectability is made anywhere in this layer.

**The tradeoff this layer's catch-all makes, named.** The catch-all emulates no protocol and emits
no banner, which removes an entire class of tells the old system carried: version anachronisms,
malformed handshakes, protocol-impossible responses, and byte-identical replies across unrelated
ports. What it does not remove is the uniform profile that replaces them. A host that accepts on
many unrelated ports, says nothing on any of them, and closes is not what any real host looks like
either, and always-accept-never-fail is itself a documented tell. The judgement here is that the
uniform-silence profile is the better trade, because the alternative is exactly the multi-turn
emulation surface this layer is built to avoid, and adding parser surface to a breadth sensor to
look more real is the wrong direction. It is a deliberate ceiling, not an oversight, and it is
recorded so a later maintainer does not reach for banner emulation without re-opening the trade.

**One coherent role per WAN IP, and the tension with the breadth model.** The strongest structural
tell is not any banner but the topology: one address answering on fifty unrelated ports is a host
that could not exist, since no real machine is simultaneously a file server, a database cluster
member, an industrial controller, and a blockchain node. The scoring model's breadth signal pulls
the other way, because it wants many WAN IPs and rewards a source sweeping across them. The two
reconcile at different levels, and the resolution is inherited from the deployment model: **breadth
is a deployment-level property (many WAN IPs, the sweep still visible because every event carries
its `wan_ip`), while each individual WAN IP presents one coherent role**, a disjoint and plausible
port set rather than a share of one kitchen sink. Breadth is therefore unaffected. The port-set
assignment is operator configuration validated at startup, not sensor logic.

**Host stack coherence is out of this layer's reach, and is conceded.** Passive and active OS
fingerprinting reads kernel-level TCP/IP characteristics that a userspace listener neither inspects
nor influences. Tuning them is host configuration, and it is only meaningful once one address
presents one role, since no single kernel profile can be coherent with several mutually exclusive
service personas at once. For any address that still presents more than one role, full coherence is
unreachable and is accepted rather than papered over. Nothing in this layer claims to address it.

## Error handling

- A malformed or unparseable input is dropped and never crashes the accept loop; the connection is
  closed and serving continues.
- A per-port bind failure is non-fatal: the sensor serves the ports it did bind.
- A captured body that exceeds the size bound is truncated to the bound (or refused, per config), never
  allowed to exhaust disk; the event still records the sighting and the observed length.
- The emit path fails closed: if an event cannot be serialized or appended, the sighting is logged as
  an emit error and the connection is dropped; a sensor never blocks its accept loop on a stuck write,
  and never fabricates or partially writes an event line.
- Overload sheds work rather than stalling, and says so: a full capture queue drops the job and
  counts it, a spool at its global byte budget refuses the capture and logs the refusal with the
  observed size. Both are recorded sightings and visible metrics, never silent.
- Instrumentation cannot crash the sensor: a fault in a metrics or logging path degrades gracefully
  and never takes down the listener it observes.

## Testing strategy

Verified against the real capture and emit path, not mocks. Load-bearing invariants:

- **Never-exec.** Across a full captured attack session (login, a sequence of commands, an upload),
  the SSH honeypot process spawns no child process. This is a required test and the highest-priority
  gate.
- **No outbound connection.** Across a full captured session including typed `wget` and `curl`
  commands against attacker-named hosts, an FTP-style `RETR`, and a `PORT`-bounce attempt, the sensor
  opens no outbound connection. Required, and gated at the same priority as never-exec.
- **Log forging is impossible.** A command, a username, and an uploaded filename each containing CR,
  LF, ANSI escapes, and bidirectional-override characters produce exactly one event line apiece, with
  the injected content neutralized and no second parseable record anywhere in the log. Driven through
  the real capture path, and asserted on the log bytes rather than on the sanitizer in isolation,
  since the defect being guarded is a bypass of it.
- **`protocol_label` lexicon.** Each protocol-speaking sensor emits the exact expected literal, and
  the assertion is on the literal string. This test exists because a wrong-but-plausible label
  degrades vendor reporting silently, with no error at any layer.
- **SSH handshake completes against a real client.** An integration test drives a real SSH client at
  the honeypot, completes the transport handshake and user-authentication, and asserts the emitted
  events (`honeypot_connection` then `honeypot_login_attempt` with `authenticated = true`) and that
  the offered username is captured.
- **`authenticated` semantics.** A session that completes the transport but never sends a
  user-authentication request produces only `authenticated = false` events (no confirmed-real latch);
  a session that reaches authentication produces `authenticated = true`.
- **PII discipline.** No emitted event, for any sensor, ever contains a password or a full payload
  body. A test drives an authentication attempt and an upload with a known password and known bytes
  and asserts neither appears in any emitted line or in metadata.
- **UDP never answers.** The catch-all UDP path emits zero response bytes to a probing datagram.
- **WAN attribution.** An event carries the WAN IP of the local address the connection arrived on,
  resolved through the configured map; a sensor with no WAN binding emits `wan_ip = null`.
- **Wire record round-trips.** A `sensor-wire` record serializes and deserializes to an equal value,
  and deserializes into a valid `EventInput` via `from_signal` for every emittable signal type.
- **Accept loop survives adversarial input.** Malformed, truncated, and oversized inputs drop the
  offending connection and never crash the listener (property-style over adversarial inputs).
- **Sample spool.** An uploaded body is written to the spool named by its SHA-256, is size-bounded,
  carries no-execute permissions, and the event references it correctly; the body never appears inline.
- **Bind-failure non-fatal.** With one configured port already occupied, the sensor still binds and
  serves the rest.
- **Capture is off the response path.** The protocol reply is observed to return before hashing and
  spool writing complete, and a saturated capture queue drops jobs (incrementing the counter) instead
  of delaying the reply. Asserted as a bound on reply latency with capture saturated versus idle,
  because the property being protected is a timing difference an attacker can measure.
- **Overload refusals.** At the global spool byte budget, a further upload is refused and logged with
  its observed size rather than written; the sensor keeps serving.
- **Rotation is survivable end to end.** With the shipped rotation policy driven against a live
  appending sensor, no event is lost and none is double-counted across the rotation, read back
  through the same durable-cursor logic intake uses. This is verified as a pair because the failure
  mode is silent loss, not an error.
- **Unit hardening is present.** The shipped service-manager units are asserted to carry the
  least-authority directives, the resource caps, and the syscall filter, and to run as a non-root
  dedicated user. A missing directive fails the build rather than being noticed in production.

## Decisions closed by this spec

Ratified with the operator on 2026-07-20:

1. First TCP-auth honeypot protocol: **SSH**.
2. Emulation depth: **fake shell (Cowrie-class)** - full command logging plus sterile upload capture,
   chosen over the lower-surface login-capture depth for its richer attacker telemetry, under the
   architectural never-exec guarantee.
3. Malware handling: **sterile capture in this layer** (quarantine spool by SHA-256); the
   operator-approved forward to **VirusTotal** (hash-first, public-disclosure-on-upload accepted) and
   the vendor abuse reports are downstream, human-gated (SP4/SP8). Recorded in memory and honored here.
4. Sensor to intake wire contract: **NDJSON log line + tail**, sample side channel by SHA-256,
   integrity via the OS one-directional channel plus the ledger hash chain at intake (ADR-0010).
5. SSH implementation: **self-authored SSH server + vendored, pinned crypto primitives in-tree**; no
   third-party SSH server or honeypot library; primitives not reimplemented (ADR-0011).

## Open questions - deferred to their owning layer (not open for this spec)

These are named so they are not lost, and are explicitly out of scope here:

- Multi-node aggregation transport, backpressure when a collector outruns intake, cross-node dedup of
  the same hit, and scorer leader election - all sub-project 3.
- The quarantine store, retention, and the operator-approved VirusTotal and vendor forward paths -
  sub-projects 4 and 8.
- The remaining native sensors (Redis, ADB, malware-capture, credential) - sub-project 8.
- **An out-of-band fetcher for captured URLs**, if an operator ever wants the artifact behind one.
  Never the sensor and never inline (see No attacker-directed fetch): a separate disposable process
  in its own network namespace with a default-deny egress allowlist, scheme restriction, resolution
  of both address families validated before connecting to the pinned result, no connection reuse, no
  redirects, and hard size and time caps. Off by default. Named here so the requirement set is not
  reinvented casually; whether it is ever built is a later layer's decision.
- **Sample sharing mechanics**: hash lookup before any upload, per-vendor submission windows and
  acceptance rules, the sensitivity ceiling of each channel (the public ones cannot carry anything
  restricted, and a share is irreversible), and submission timing decorrelated from capture timing so
  the appearance of a sample does not date the sensor. A hash lookup is low exposure, not zero: it
  still discloses the digest and the fact of interest. Sub-projects 4 and 8, consistent with the
  operator intent already recorded for this layer.
- **Feed self-deanonymization**: sub-project 5, and concrete enough to state now so it is not
  rediscovered late. Coarsening one exporter is not sufficient when another republishes the same
  facts by a different name: a per-entry confidence field that is the raw score rounded re-exposes
  the score, and a validity or expiry timestamp re-exposes a coarsened last-seen exactly, because
  subtracting the publicly known tier window recovers it. Coarsening must be applied across every
  exporter and to every derived timestamp (validity start and end, expiry, and the manifest build
  time) together, or the mitigation is only apparent.

## Provenance of this spec

The scope, the ratified decisions, and the wire contract were settled on 2026-07-20 with the
operator. On 2026-07-27 the spec was checked against the prior-art sensor specification and
implementation held outside this repository (the unified in-house sensor build spec written for the
predecessor Python system, and the abandoned Go rewrite's realization of parts of it). That pass
added the capture sanitization contract, the `protocol_label` requirement, the off-response-path
capture hand-off, the spool byte budget and log rotation policy, the containment layer of the unit
hardening, the explicit no-attacker-directed-fetch rule, and this layer's detectability section,
along with the deferred items above. Those additions are engineering carried forward from prior
findings, not separately operator-ratified decisions; the five ratified decisions above are
unchanged by them.
