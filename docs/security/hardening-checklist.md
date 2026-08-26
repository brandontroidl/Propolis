<!--
title: Hardening checklist
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Hardening checklist

Actionable steps an operator performs *before and after* exposing Propolis to
hostile traffic. Exact env-var defaults/bounds are owned by
[../reference/environment-variables.md](../reference/environment-variables.md);
ports/paths by [../reference/ports-and-protocols.md](../reference/ports-and-protocols.md)
and [../reference/filesystem-paths.md](../reference/filesystem-paths.md). This
page is the sequence, not a re-listing of values.

Propolis is source-available and actively developed, with one tagged release
(`v0.1.0`); the current tree is `0.3.0`, untagged. It is not certified or
production-blessed — see [../overview/maturity-and-status.md](../overview/maturity-and-status.md).

## 1. Derive the real syscall filter

Every shipped unit carries a **placeholder** `SystemCallFilter`
(`@system-service` minus `@privileged @resources`) — a broad development
allowlist, not a hardened filter. Before production, derive the tight per-binary
allowlist and replace the placeholder in each `deploy/*.service` unit.

- Run each binary under representative load with `strace -c -f` (or
  `systemd-analyze syscall-filter` plus audit logs) to enumerate the syscalls it
  actually issues.
- Narrow `SystemCallFilter` to that set; keep `SystemCallArchitectures=native`.
- Confirm the service still starts and captures after tightening.

Until this is done, treat the syscall sandbox as absent (see
[residual-risks.md](./residual-risks.md)).

## 2. Enforce the noexec spool mounts

`install.sh` *prints* but does not create the quarantine mounts. Add the
`noexec,nosuid,nodev` mounts it lists for every spool path (and
`/var/spool/propolis/fetched` if the malware fetcher is enabled), then verify:

```
findmnt -no OPTIONS /var/spool/propolis/ssh   # expect noexec,nosuid,nodev
```

Captured sample files are written `0640`; the mount options are what keep a
captured binary from being executed. See [malware custody](./malware-custody.md).

## 3. Lock down network exposure

- Bind sensors only on the interfaces/ports you intend to expose; the `*_BIND`
  vars are required (no code default). Attacker-facing ports are the *only*
  inbound surface the sensors need.
- **Keep the console loopback-only.** It defaults to `127.0.0.1:8080`. Do not set
  `PROPOLIS_CONSOLE_BIND` to a routable address without a fronting reverse proxy
  (next item) — the console serves plain HTTP and the `/metrics` endpoint is
  unauthenticated by design (acceptable only because it is loopback).
- Restrict outbound egress at the host firewall to exactly the paths you enable
  (see step 5). Sensors make no outbound connections.
- For a containerized PostgreSQL, do **not** use `host all all all trust` in
  `pg_hba.conf`.

## 4. Terminate TLS in a reverse proxy

Propolis has **no in-process TLS**. The console is plain HTTP on a `TcpListener`
(`axum::serve`, no rustls). If the console must be reachable beyond loopback,
front it with an operator-provided TLS-terminating reverse proxy bound to
loopback upstream. This is an operator responsibility, not a built-in feature.
See [../operations/networking-tls.md](../operations/networking-tls.md).

## 5. Treat every egress path as opt-in

All five outbound paths default OFF and several fail closed without a
credential/topic. Enable only what you need, and confirm each is intended:

- VirusTotal (`PROPOLIS_VT_ENABLED`, honored only with a non-empty key)
- Vendor abuse submitters AbuseIPDB / DShield / OTX (`PROPOLIS_VENDOR_*_ENABLED`)
- Malware fetcher (`PROPOLIS_FETCH_ENABLED`) — fetches attacker-supplied URLs
  through the SSRF vetter; leave off unless you accept that risk
- Console reverse DNS (`PROPOLIS_CONSOLE_RDNS_ENABLED`)
- Ops-alert ntfy (`PROPOLIS_OPS_ENABLED`)

> **Warning — enabling these produces outbound network traffic and, for the
> fetcher, dials attacker-controlled destinations.** Understand each path before
> turning it on. Full behavior and guards: [outbound-controls.md](./outbound-controls.md).

## 6. Provision secrets correctly

- Create `/etc/propolis/*.env` by hand, mode `0600`, owned by the service user.
  `install.sh` never creates them.
- Set a strong `PROPOLIS_CONSOLE_PASSWORD` (the console refuses to start without
  one; hashed with Argon2id at startup).
- Set `PROPOLIS_CONSOLE_SESSION_SECRET` (64 hex chars) if you want sessions to
  survive a restart; otherwise a fresh key is generated each start and all
  sessions are invalidated on restart.
- Keep API keys and the DB URL only in these env files, never in units or code.

See [../operations/secret-management.md](../operations/secret-management.md) and
[authn/authz](./authn-authz.md).

## 7. Keep the feed publication repository private-by-default

The public blocklist feed carries only attacker source IPs plus tier/first-seen/
last-seen/categories; it contains **zero** `wan_ip` (your ingress attribution)
references by construction. The feed *contents* are safe to publish. Still:

- Decide deliberately whether the blocklist Git repository is public.
- The publish-to-repo step (`deploy/blocklist-sync.sh`) is an operator cron job;
  it is **not** wired into any shipped systemd timer. If you run it, secure the
  deploy key it pushes with and verify the cron/SSH-agent setup.

## 8. Verify database privileges and backups

- Confirm the production `event` table has had `UPDATE/DELETE/TRUNCATE` revoked
  from the `propolis` role (migration `0004` does this only when the database is
  named `propolis`). The hash-chain trigger (`0005`) must be present.
- Establish and **test** an off-host backup and restore path — a single-node
  deployment has no built-in redundancy (see [residual-risks.md](./residual-risks.md)).
  A backup is unverified until you have restored from it. See
  [../operations/backup-and-restore.md](../operations/backup-and-restore.md).

## Related

- [Filesystem and DB protections](./filesystem-and-db-protections.md)
- [Outbound controls](./outbound-controls.md)
- [Residual risks](./residual-risks.md)
- [Threat model](./threat-model.md)
