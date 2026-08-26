<!--
title: Sample and credential privacy
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Sample and credential privacy

Three privacy invariants hold across the platform: submitted passwords are read
only far enough to advance the protocol and then dropped, captured samples are
handled under the custody controls documented elsewhere, and the honeypot's own
WAN vantage address is internal-only and never leaves the host in the public
feed or a vendor report.

## Credential handling

**Passwords are read-to-advance-then-dropped, never stored, never logged.** The
SSH auth handler accepts any credential unconditionally - the goal is to let the
attacker reach the shell and reveal intent, not to gatekeep. It captures the
`username` and `method`; it does **not** capture the password.

`crates/sensor-ssh/src/auth.rs` module doc (lines 1-16) states the invariant: a
submitted password is "read only far enough to advance the parser past it, then
dropped; it is never placed in any field of any `SensorEvent`." In
`handle_userauth` the password appears only as a local `_password` binding that
"is never read again and is dropped when this call returns" (lines 138-146) - it
is never stored on the auth state, never logged, and never reaches `metadata`.

Enforcement:

- **Serialized-JSON test.** `password_never_in_event`
  (`crates/sensor-ssh/tests/auth_test.rs:49`) asserts the password is absent from
  the serialized event JSON, not merely from the typed struct - so a future field
  addition cannot reintroduce it silently.
- **No password is logged.** A grep for `tracing::*` lines containing `password`
  (or `metadata.*password`) across `sensor-cred/src` and `sensor-ssh/src` returns
  zero.
- **No password field on the wire type.** `SensorEvent`
  (`crates/sensor-wire/src/lib.rs`, ~line 30) has fields `source_ip`, `wan_ip`,
  `sensor`, `signal_type`, `protocol`, `authenticated`, `observed_at`,
  `metadata`, `sample`, `session_id` - and no password field. There is nowhere in
  the event schema for a password to land. Event fields are owned by
  [../reference/events-and-signals.md](../reference/events-and-signals.md).
- **Captured identifiers are sanitized.** The `username` and `method` that *are*
  captured are length-capped and run through `sanitize_value` before entering the
  event (`auth.rs:34` and four `sanitize_value` calls in `auth.rs`). The shared
  sanitizer chokepoint is covered by
  [input-handling.md](input-handling.md).

## Sample privacy

Captured sample bodies are stored under the sterile-spool custody model - named
by SHA-256 (never the attacker's filename), size-bounded, re-hashed on read, and
forwarded to a vendor only after operator approval. That model, including the
never-execute and disk-fill controls, is owned by
[malware-custody.md](malware-custody.md). A sample leaves the host only through
the human-gated vendor-submission path in
[outbound-controls.md](outbound-controls.md#2-vendor-abuse-submitters-review);
there is no automatic sample egress.

## WAN vantage is internal-only

`wan_ip` is the honeypot's **own** public ingress address (its vantage point,
derived from `PROPOLIS_SSH_WAN_MAP` and related config via
`sensor-framework/src/wan.rs`). It is carried on events and stored so that
internal analysis can attribute which ingress an attacker hit, but it is **never
published** in the public blocklist feed and never sent to a vendor.

- **Referenced in 37 source files** - sensors, `core-scoring`
  (domain/repository/hashing), `intake`, and the `console` detail/search views.
  Every one of these is internal or session-gated.
- **The public feed contains zero `wan_ip` references.** A grep across all of
  `crates/feed/src/**` (builder, publisher, exclusion, and every `export/*`
  target - cidr/json/plaintext/csv/firewall) returns 0. The feed selects only
  `host(source_ip)` (attacker IPs) plus tier, first_seen, last_seen, and
  categories (`crates/feed/src/builder.rs:169-172,226`). Feed contents are owned
  by [../reference/scoring-and-feed.md](../reference/scoring-and-feed.md).
- **In the console, `wan_ip` appears only** in `routes/detail.rs`,
  `routes/search.rs`, and their templates - all behind the `require_session`
  session gate (see [authn-authz.md](authn-authz.md)).

The invariant is that the honeypot's own vantage address stays inside the trust
boundary: it informs internal scoring and the operator's own views, but a vendor
report or a downstream feed consumer never learns which ingress address the
honeypot presents. Trust boundaries and data flows are covered in
[../architecture/trust-boundaries-and-data-flows.md](../architecture/trust-boundaries-and-data-flows.md).
