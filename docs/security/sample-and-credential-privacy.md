<!--
title: Sample and credential privacy
audience: security
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-12
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
  (`crates/sensor-ssh/tests/auth_test.rs#password_never_in_event`) asserts the password is absent from
  the serialized event JSON, not merely from the typed struct - so a future field
  addition cannot reintroduce it silently.
- **No password is logged.** A grep for `tracing::*` lines containing `password`
  (or `metadata.*password`) across `sensor-cred/src`, `sensor-ssh/src` and
  `sensor-http/src` returns zero.
- **No password field on the wire type.** `SensorEvent`
  (`crates/sensor-wire/src/lib.rs`, ~line 30) has fields `source_ip`, `wan_ip`,
  `sensor`, `signal_type`, `protocol`, `authenticated`, `observed_at`,
  `metadata`, `sample`, `session_id` - and no password field. There is nowhere in
  the event schema for a password to land. Event fields are owned by
  [../reference/events-and-signals.md](../reference/events-and-signals.md).
- **Captured identifiers are sanitized.** The `username` and `method` that *are*
  captured are length-capped and run through `sanitize_value` before entering the
  event (`crates/sensor-ssh/src/auth.rs#handle_userauth` for both `username` and `method` - two
  `sanitize_value` calls in `auth.rs`). The shared
  sanitizer chokepoint is covered by
  [input-handling.md](input-handling.md).

**HTTP keeps the evidence with the credential cut out.** The HTTP sensor cannot
drop a password the way SSH does, because it arrives inside the bytes that are the
evidence: the request target, the query string, a form, JSON, XML or multipart
body, an `Authorization` header, a cookie. So `crates/sensor-http/src/redact.rs`
removes the credential at the point the event fields are built, before the
sanitizer and the size caps (`crates/sensor-http/src/handler.rs#handle_connection`).
What it promises is scoped by how it works: the scanners are textual and match the
names and shapes real clients send, under password-like names, in
`Authorization` / `Proxy-Authorization` and in `Cookie`.

- **Kept:** parameter and cookie names, the values of username-like fields, the
  `Authorization` / `Proxy-Authorization` scheme (`auth_scheme`,
  `proxy_auth_scheme`) and for `Basic` the username from the decoded pair, for
  `Digest` the `username` field (`auth_username`, `proxy_auth_username`). Which
  fields a scanner targets, and with what account, is the intelligence. A name
  ending in `type`, `method` or `kind` (`auth_type=basic`, `token_type=bearer`)
  names a credential's kind, not a credential, and its value stays.
- **Dropped:** every value under a password-like name (`password`, `passwd`,
  `pwd`, `pw`, `psw`, `pswd`, `pass`, `passcode`, `passphrase`, `senha`, `secret`,
  `token`, `apikey`, `accesskey`, `auth`, `credential`, `credentials`, `pin`,
  `otp`; a name matches as a whole with its punctuation removed (`api-key`), by
  any segment (`user[pin]`, `client_secret`), or by containing `pass`
  (`userpass`, `pass1`, `mot_de_passe`): `crates/sensor-http/src/redact.rs#is_secret_name`),
  in the query string (pairs split on `&` and `;`), in the request target (a
  `%3F`-encoded query, a `;` matrix parameter, the password of an absolute-form
  `user:password@host`: `crates/sensor-http/src/redact.rs#redact_target`), and in
  url-encoded, JSON (at any depth, a container value replaced whole, a truncated
  body included), XML (an element, an attribute, an XML-RPC struct member under a
  secret name, and every parameter after the first of a login-shaped XML-RPC call,
  `wp.*` / `metaWeblog.*` / `blogger.*` / `mt.*` / `system.multicall`, whose
  parameters are positional and anonymous:
  `crates/sensor-http/src/redact.rs#redact_xml`) and multipart bodies (CRLF or
  bare LF line endings, a quoted or token `name`, in any parameter order); a
  `Basic` password, a bearer token, a digest response, an `Authorization` value
  with no scheme word (a raw token or Basic blob is the credential, so
  `auth_scheme` is `<redacted>`); and every cookie value, a bare token without a
  name included. Each is replaced by the marker `<redacted>`
  (`crates/sensor-http/src/redact.rs#REDACTED`, the same token the review crate's
  `redact_secrets` writes) and the event carries `credentials_redacted: true`,
  meaning a value was replaced, not that a credential was proven: every cookie
  value counts, a scheme word alone (`Authorization: Basic`) does not. The key is
  absent on an event where nothing was replaced, so a credential-free request
  serializes exactly as it did before.
- **Out of scope (bypass classes).** A textual scanner is an accident-prevention
  layer for what real clients send; a sender that disguises its own request can
  get a secret past it, and the ledger's access controls remain the containment.
  Known classes: a JSON key spelled with an escape (`"password"`), a
  non-ASCII space (U+00A0) between a key and its colon, a non-UTF-8 byte inside a
  name, JSON or XML carried inside a url-encoded value (`data=%7B...`), a GraphQL
  login mutation inside a `query` string, a multipart body whose declared boundary
  does not match, a credential under a name outside the list, an unknown
  `Authorization` scheme word followed by its credential (the word is kept as the
  scheme, capped at 32 bytes), and a secret in a field the scanners do not read (a
  header other than the three above). The JSON scanner does not run on the query
  string.
- **Serialized-JSON tests.** `form_login_password_never_in_event`,
  `json_login_password_never_in_event_at_any_depth`,
  `basic_auth_keeps_the_username_and_never_the_password`,
  `bearer_token_never_in_event`, `cookie_values_never_in_event`,
  `multipart_login_password_never_in_event` and
  `query_string_password_never_in_event`
  (`crates/sensor-http/tests/integration.rs#form_login_password_never_in_event`
  and siblings) assert each secret is absent from the line the sensor wrote, with
  the usernames and names present;
  `request_without_credentials_serializes_exactly_as_before` pins the common case,
  and `redacted_body_preview_still_respects_the_cap` the preview cap. The bypasses
  a review found in the first cut each have a test with the request that leaked:
  `authorization_without_a_scheme_word_never_in_event`,
  `xmlrpc_and_xml_login_password_never_in_event`,
  `password_like_names_outside_the_first_list_never_in_event`,
  `json_secret_inside_a_container_never_in_event`,
  `multipart_as_real_senders_write_it_never_in_event`,
  `cookie_token_without_a_name_never_in_event` and
  `semicolon_query_and_target_secrets_never_in_event`
  (`crates/sensor-http/tests/integration.rs#authorization_without_a_scheme_word_never_in_event`
  and siblings).

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
  `host(source_ip)` (attacker IPs) plus tier, first_seen, last_seen,
  event_count, distinct_categories, and categories
  (`crates/feed/src/builder.rs#build`). Feed contents are owned
  by [../reference/scoring-and-feed.md](../reference/scoring-and-feed.md).
- **In the console, `wan_ip` appears only** in `routes/detail.rs`,
  `routes/search.rs`, and their templates - all behind the `require_session`
  session gate (see [authn-authz.md](authn-authz.md)).

The invariant is that the honeypot's own vantage address stays inside the trust
boundary: it informs internal scoring and the operator's own views, but a vendor
report or a downstream feed consumer never learns which ingress address the
honeypot presents. Trust boundaries and data flows are covered in
[../architecture/trust-boundaries-and-data-flows.md](../architecture/trust-boundaries-and-data-flows.md).
