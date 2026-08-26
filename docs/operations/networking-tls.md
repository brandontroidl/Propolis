<!--
title: Networking and TLS
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Networking and TLS

This page covers the network exposure of each component and the platform's TLS
posture. Exact ports and binds are owned by
[../reference/ports-and-protocols.md](../reference/ports-and-protocols.md); this
page explains exposure and operator responsibilities.

## Three exposure classes

| Class | Components | Default binding |
|---|---|---|
| Attacker-facing | the nine sensors (ssh, telnet, http, ftp, smtp, redis, adb, catchall, cred) | operator-chosen `ip:port` per sensor — **no code default** |
| Operator-facing | console web UI (and `/health`, `/ready`, `/metrics` on the same port) | `127.0.0.1:8080` (loopback) |
| No listener | `intake`, `review`, `feed`, and the unified daemon's fetcher | none (DB clients / outbound-only) |

### Sensors (attacker-facing)

Sensors are the internet-exposed honeypot listeners. Each requires its bind
address explicitly and fails closed if it is absent or unparseable — there is no
compiled-in default port anywhere (`crates/sensor-ssh/src/main.rs:130-134` and
the equivalent in each sensor). The IP portion is whatever the operator writes
(`0.0.0.0`, a specific address, etc.). `sensor-ftp` additionally opens
passive-mode data connections on dynamic ephemeral ports negotiated per session
(`94a62ae1`, `016721e1`); the exact range is OS-ephemeral [inferred — not
verified to a fixed/configurable range in this pass].

> **Warning — sensors are live attacker listeners.** Expose them only on a host
> positioned as intended: an isolated VLAN, firewalled, with out-of-band host
> administration (the honeypot's port 22 is the *fake* SSH sensor, not a real
> admin channel — real host admin is out-of-band, e.g. the hypervisor console).
> See [../getting-started/production-readiness-checklist.md](../getting-started/production-readiness-checklist.md).

### Console (operator-facing)

The console binds **loopback-only by default** (`127.0.0.1:8080`,
`crates/propolis/src/config.rs:30,509-513`), on an unprivileged port with no
capability grant. It binds a non-localhost address only if the operator
overrides `PROPOLIS_CONSOLE_BIND` — the design intent is to keep it loopback and
put any remote access behind the operator's own reverse proxy
(`crates/console/src/main.rs:36-37`).

`/health`, `/ready`, and `/metrics` share the console's bind (no separate port)
and are mounted outside the session-auth middleware
(`crates/console/src/routes/mod.rs`). This is acceptable *because* the console is
loopback-only; if you rebind it off-loopback, those endpoints become reachable
too — front them with authentication at the proxy. Route ownership is in
[../reference/console-routes.md](../reference/console-routes.md).

## TLS posture — no in-process TLS

> **There is no built-in TLS.** The console is plain HTTP served by
> `axum::serve` on a plain `tokio::net::TcpListener`
> (`crates/propolis/src/main.rs:413-424`) — there is no rustls or other TLS
> setup in the code. Do not assume any component terminates TLS itself.

Any TLS for the console is the **operator's responsibility, via a reverse
proxy** in front of the loopback listener (`[inferred]` — this is the design
intent implied by the loopback-by-default bind and the "put it behind your own
reverse proxy" comment, not a shipped feature). A typical arrangement:

- Keep `PROPOLIS_CONSOLE_BIND=127.0.0.1:8080` (do not expose the console
  directly).
- Terminate TLS at a reverse proxy on the same host and proxy to
  `127.0.0.1:8080`.
- Enforce authentication at the proxy for the unauthenticated
  `/health`/`/ready`/`/metrics` endpoints if the proxy is remotely reachable.

The application sets `X-Frame-Options: DENY` and `X-Content-Type-Options:
nosniff` on console routes (`crates/console/src/routes/mod.rs:59-70`) but sets no
global HSTS or CSP — HSTS, if wanted, is another reason to terminate at a proxy.

Outbound connections (vendor APIs, VirusTotal, the fetcher) use HTTPS provided
by their own HTTP clients; that is unrelated to the console's inbound posture and
those paths default off. See
[../security/outbound-controls.md](../security/outbound-controls.md).

## Firewall and exposure guidance

Based on `INSTALL.md:378-385` (operator guidance, not code):

- **Inbound:** allow the configured sensor ports from the internet (that is the
  point). Allow nothing inbound to the console port from off-host — keep it
  loopback, or reachable only through your proxy.
- **Outbound:** the unified daemon needs outbound HTTPS to the vendor APIs *only
  if* review/VirusTotal are enabled, and outbound `5432` only if PostgreSQL is
  remote. **Sensors make no outbound connections by design**
  (`INSTALL.md:385`); their unit files restrict address families to
  `AF_INET AF_INET6` with no outbound path.
- **Recovery path:** before applying any firewall rule that could sever access,
  confirm you have out-of-band administration (hypervisor console / serial), not
  just the honeypot's fake SSH.

## Related

- [../reference/ports-and-protocols.md](../reference/ports-and-protocols.md) —
  exact ports/binds (canonical)
- [../security/attack-surfaces.md](../security/attack-surfaces.md) — exposure as
  a threat surface
- [configuration.md](configuration.md) — bind configuration
- [secret-management.md](secret-management.md) — console auth secrets
