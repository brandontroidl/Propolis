<!--
title: Input handling
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Input handling

All sensor input is adversary-controlled ([threat-model.md](threat-model.md)). Three
structural controls contain it before it can forge an event, inject SQL, or exhaust
memory: a single shared sanitization chokepoint, exclusively parameterized SQL, and bounds
on every attacker-influenced read. This page owns those controls' behavior; event fields
and the hash chain that seals them are owned by
[../reference/events-and-signals.md](../reference/events-and-signals.md) and
[../architecture/storage.md](../architecture/storage.md).

## `sanitize_value`: the event-boundary chokepoint

`crates/sensor-framework/src/sanitize.rs` is the single shared function every sensor routes
attacker-controlled text through before it can enter an event record. It closes a
log-injection class: an uncompromised sensor talked into emitting a **forged second event
line** via an unescaped CR/LF, terminal escape, or bidirectional override in captured
evidence.

`sanitize_value(input, max_len)` runs a **load-bearing fixed order** (`sanitize.rs:22-27`):

1. **Collapse** each run of CR / LF / tab / VT / FF to a single space - runs **first**,
   against the raw input. Order matters: stripping controls first could remove a character
   adjacent to a bare CR or LF and leave it standing, forging the record anyway
   (module doc, `sanitize.rs:7-10,38-45`).
2. **Strip** ANSI CSI escapes; C0 (`0x00-0x1F`, `0x7F`) and C1 (`0x80-0x9F`) controls;
   line/paragraph separators (`0x2028`/`0x2029`); bidirectional overrides and isolates;
   zero-width / BOM / word-joiner / invisible-math characters; and the Unicode tag block
   (`0xE0000-0xE007F`, the ASCII-smuggling vector) (`is_dangerous`).
3. **NFC-normalize** (combining marks preserved).
4. **Truncate** to `max_len` bytes on a UTF-8 char boundary - never panics on a split code
   point (`truncate_to_len`).

Supporting properties:

- The **CSI parser is bounded** (`consume_csi_tail`): a truncated escape drains to the
  first out-of-range byte and cannot hang (test `malformed_csi_does_not_panic_or_hang`).
- **Byte-derived fields use hex, not decoded text** (`to_hex_bounded`): hex cannot express a
  newline, control character, or delimiter, so such fields are "safe by their alphabet"
  rather than by a sanitizer call.

### Applied structurally, not per-sensor-discretion

`sanitize_value` is called across 18 source files - every sensor handler plus framework
`shell.rs`, `handoff.rs`, and `emit.rs`. Two facts make it structural rather than a habit
each sensor must remember:

- The framework enforces it for captured filenames: `orig_name` is sanitized in the capture
  worker (`handoff.rs:202`), which is the **only** caller of `spool.store`; `spool.store`
  itself always returns an empty `orig_name` (`spool.rs`), so a sensor cannot route an
  unsanitized filename around the chokepoint (test
  `orig_name_is_sanitized_before_reaching_the_event`).
- The event wire type carries no free-text field a sensor could populate unsanitized off
  this path; see [../reference/events-and-signals.md](../reference/events-and-signals.md).

## Parameterized SQL (no SQL injection)

Every database write binds its values; **no SQL string is built with `format!`** in
non-test source (a grep for `format!(...)` containing `SELECT|INSERT|UPDATE|DELETE|WHERE`
across `crates/*/src` returns zero - the `format!` hits in tests are all inside `.bind(...)`
argument values, not query text).

- The **event insert** is fully parameterized: `INSERT INTO event ... VALUES ($1::inet,
  $2::inet, $3, ... $14) RETURNING id` via `sqlx::query_scalar` with bound params
  (`crates/core-scoring/src/repository/events.rs:167-171`). The advisory lock guarding the
  hash chain is parameterized too (`pg_advisory_xact_lock($1)`).
- Feed builder, review CLI, and VirusTotal writes all use `$`-placeholders or static SQL.
- The repository module deliberately uses the runtime `sqlx::query*` API with bound values,
  never interpolation.

Console query surfaces reinforce this at the route layer: search filters combine as prepared
`($n::type IS NULL OR ...)` clauses with at least one filter required before a query runs,
LIKE-metacharacters in free-text are escaped, and sort columns are chosen from a fixed match
(literal order strings - no injection surface). See
[../reference/console-routes.md](../reference/console-routes.md).

Tables, enums, and migrations: [../reference/database.md](../reference/database.md).

## Bounded reads

Attacker input cannot drive unbounded resource use:

- **Every sanitized field is length-capped** at its call site via `sanitize_value`'s
  `max_len` (for example the SSH auth username, `auth.rs:34`), and byte-derived fields are
  hex-bounded.
- **Captured samples are size-bounded twice:** a per-file cap (`FileSizeExceeded`) and a
  **global byte budget** with an atomic check-and-reserve, recovered from disk on restart. A
  dedup hit costs no budget. See [malware-custody.md](malware-custody.md).
- **The spool never trusts an attacker filename or hash into a path:** files are named by
  their own SHA-256, and `verify()`'s hash argument is validated as 64-hex before any path
  join ("safe by alphabet"), rejecting traversal like `../../../../etc/passwd`. See
  [malware-custody.md](malware-custody.md) and
  [filesystem-and-db-protections.md](filesystem-and-db-protections.md).
- **Capture hand-off never blocks the reply path:** the sensor submits a `CaptureJob` on a
  bounded mpsc channel with `try_send`; a full queue **drops** the job and increments a
  counter rather than blocking or growing unbounded. See
  [../architecture/concurrency-and-failure.md](../architecture/concurrency-and-failure.md).
- **Console read pages are bounded:** event/IP listings paginate (search page size 50; the
  attacker IP list caps at 500 rows). See [../reference/console-routes.md](../reference/console-routes.md).

## Why sanitized input still cannot forge history

Sanitization keeps a single malicious value from spanning lines or smuggling control
sequences; the **hash chain** keeps the *record* tamper-evident even against a value that
passes sanitization. Each event is bound into a SHA-256 chain over a frozen, length-prefixed
canonical encoding, so any later mutation of a stored field changes the chain. That control
is owned by [../architecture/storage.md](../architecture/storage.md); the console exposes an
integrity-verification route to check it ([../reference/console-routes.md](../reference/console-routes.md)).
