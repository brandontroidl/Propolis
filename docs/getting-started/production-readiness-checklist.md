<!--
title: Production-Readiness Checklist
audience: deployer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Production-readiness checklist

Work through this before exposing any Propolis listener to untrusted traffic. The
[evaluation deployment](evaluation-deployment.md) is deliberately not production-safe;
this page lists what must be true first, linking each item to its owner.

> [!IMPORTANT]
> Propolis is source-available and actively developed, with one tagged release
> (`v0.1.0`) and a current tree at `0.3.0` (untagged). It carries **no** production,
> security, legal, or regulatory certification. This checklist reduces risk; it does not
> confer any assurance. Residual risks remain even when every item is done - see
> [residual risks](../security/residual-risks.md).

## Secrets

- [ ] Every secret lives in a per-service `/etc/propolis/*.env` file, mode `0600`, owned
      by the service user, created by hand - `install.sh` never writes them
      (`deploy/install.sh:25-28`, `deploy/propolis.service:55-57`).
- [ ] `DATABASE_URL` set (carries the DB password inline); the daemon fails fast if it is
      missing (`crates/propolis/src/config.rs:168-173,430`).
- [ ] `PROPOLIS_CONSOLE_PASSWORD` set to a strong value (e.g. `openssl rand -base64 24`);
      empty/absent refuses to start (`config.rs:517`).
- [ ] `PROPOLIS_CONSOLE_SESSION_SECRET` set to 64 hex chars (`openssl rand -hex 32`) -
      otherwise a fresh key is generated each start and every session drops on restart
      (`config.rs:371-389`).
- [ ] Vendor / VirusTotal / ntfy keys set only for the egress paths you deliberately
      enable (all default off). Owner: [secret management](../operations/secret-management.md),
      exact vars in [reference/environment-variables.md](../reference/environment-variables.md).

## TLS / network exposure

- [ ] Understand that the console has **no in-process TLS** - it is plain HTTP on a
      loopback `TcpListener` (`crates/propolis/src/main.rs:413-424`). Any TLS is
      operator-provided.
- [ ] If the console must be reachable off-host, front it with an operator-provided TLS
      reverse proxy and keep `PROPOLIS_CONSOLE_BIND` on loopback behind it
      [inferred - not in code]. Owner: [networking and TLS](../operations/networking-tls.md).
- [ ] `/metrics`, `/health`, `/ready` are unauthenticated; they are only acceptable
      because the console is loopback-only. Do not expose them directly
      (`crates/console/src/routes/metrics.rs:8-11`).
- [ ] Firewall: allow inbound only on the sensor ports you expose; the console needs no
      inbound from the network (`INSTALL.md:378-385`). Ports owned by
      [reference/ports-and-protocols.md](../reference/ports-and-protocols.md).

## Host and process hardening

- [ ] **Derive a real `SystemCallFilter`.** Every shipped unit ships a **placeholder**
      (`@system-service` minus `@privileged @resources`) - a broad dev allowlist the unit
      header explicitly says to tighten via `strace -c -f` before production
      (`deploy/propolis.service:176-187`). This is a residual risk, not a delivered
      control. Owner: [hardening checklist](../security/hardening-checklist.md).
- [ ] Create the `noexec,nosuid,nodev` spool mounts - `install.sh` prints fstab guidance
      but does not create them (`deploy/install.sh:171-193`).
- [ ] Confirm the systemd sandboxing directives the units set are in effect
      (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateUsers`, `MemoryDenyWriteExecute`,
      per-sensor capability sets). Owner: [service lifecycle](../operations/service-lifecycle.md).
- [ ] Do not run the containerized Postgres with `host all all all trust`
      (`INSTALL.md:99-104`).

## Backups and evidence continuity

- [ ] A backup exists **and has been restored end-to-end at least once** - possessing a
      backup is not being able to recover. Owner:
      [backup and restore](../operations/backup-and-restore.md) and
      [upgrade, rollback and DR](../operations/upgrade-rollback-and-dr.md).
- [ ] Retention configured for the ledger, samples, and logs. Owner:
      [retention](../operations/retention.md).

## Public feed / blocklist repo privacy

- [ ] The blocklist-sync cron is an **operator setup step**: `deploy/blocklist-sync.sh`
      is referenced by comment but is **not** wired into any shipped systemd timer or cron
      in `deploy/` - you must install the crontab yourself
      (`deploy/blocklist-sync.sh:9`, [evidence 09 §12]).
- [ ] The published feed output (`/var/lib/propolis/feed/current`) is deliberately
      world-traversable so a distribution user can serve it - confirm that is intended
      before publishing (`deploy/install.sh:139-142`).
- [ ] Confirm the blocklist target repo's visibility (public vs private) matches your
      intent before the first push. The feed content is IP indicators; treat repo
      exposure as a decision, not a default.

## Enrichment / reporting egress (opt-in, default off)

Enable only what you intend to, and only after reading its controls:

- [ ] VirusTotal (`PROPOLIS_VT_ENABLED`), vendor abuse submitters
      (`PROPOLIS_VENDOR_*_ENABLED`), console rDNS (`PROPOLIS_CONSOLE_RDNS_ENABLED`),
      ops-alert ntfy (`PROPOLIS_OPS_ENABLED`), and the malware fetcher
      (`PROPOLIS_FETCH_ENABLED`) all default **off**. Owner:
      [outbound controls](../security/outbound-controls.md) and
      [reference/integrations.md](../reference/integrations.md).

## Operations readiness

- [ ] Ops self-alerting configured (or a conscious decision not to): with
      `PROPOLIS_OPS_ENABLED=true`, the ntfy URL and topic become required and the monitor
      fails closed if it cannot page (`crates/propolis/src/ops_alert/config.rs:119-134`).
      Owner: [health and observability](../operations/health-and-observability.md).
- [ ] Routine procedures and service lifecycle understood:
      [routine procedures](../operations/routine-procedures.md),
      [service lifecycle](../operations/service-lifecycle.md).

When you decommission, follow [safe teardown](safe-teardown.md).
