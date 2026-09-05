<!--
title: Production-readiness checklist
audience: deployer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-09-05
-->

# Production-readiness checklist

Work through this before any listener accepts untrusted traffic. Propolis has one
tagged release, `v0.1.0`, and the tree is at `0.3.0` with unreleased work; it carries no
certification of any kind. This list reduces risk, it does not remove it; the
[residual risks](../security/residual-risks.md) page says what remains when every box
is ticked.

## Secrets

- [ ] Every secret is in a per-service `/etc/propolis/*.env` file, mode 0600, owned by
      that service's user. You write these by hand; `install.sh` never does.
- [ ] `DATABASE_URL` is set. It carries the database password, and the daemon refuses
      to start without it.
- [ ] `PROPOLIS_CONSOLE_PASSWORD` is a strong value, for example from
      `openssl rand -base64 24`. Empty refuses to start.
- [ ] `PROPOLIS_CONSOLE_SESSION_SECRET` is 64 hex characters, for example from
      `openssl rand -hex 32`. Without it a fresh key is generated at each start and
      every session ends on restart.
- [ ] Vendor, VirusTotal and ntfy credentials are set only for the paths you mean to
      enable. See [secret management](../operations/secret-management.md).

## Network exposure

- [ ] You know the console has no TLS of its own. Keep `PROPOLIS_CONSOLE_BIND` on
      loopback; if it must be reachable off-host, put a TLS reverse proxy in front and
      set `PROPOLIS_CONSOLE_TRUSTED_PROXY`. See [networking and TLS](../operations/networking-tls.md).
- [ ] `/health`, `/ready` and `/metrics` are unauthenticated. They are only safe on
      loopback; set `PROPOLIS_CONSOLE_METRICS_TOKEN` if `/metrics` must be scraped from
      elsewhere.
- [ ] The firewall allows inbound only on the sensor ports you expose. The console
      needs nothing inbound from the network. Ports are listed in
      [ports and protocols](../reference/ports-and-protocols.md).

## Host and process hardening

- [ ] You have replaced the placeholder `SystemCallFilter` in the units. The shipped
      value is a broad allowlist the unit header tells you to narrow with `strace` under
      real load. Until you do, this is an open item, not a control. See the
      [hardening checklist](../security/hardening-checklist.md).
- [ ] The spool directories under `/var/spool/propolis` are mounted
      `noexec,nosuid,nodev`. `install.sh` prints the fstab lines and creates the
      directories; it does not mount anything.
- [ ] The sandboxing in the unit files is in effect on your systemd version:
      `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateUsers`,
      `MemoryDenyWriteExecute`, and the per-sensor capability sets. See
      [service lifecycle](../operations/service-lifecycle.md).
- [ ] PostgreSQL does not trust all hosts. The evaluation's `trust` auth is for a
      loopback container only.

## Backups and evidence

- [ ] A backup exists and you have restored it end to end at least once. Having a
      backup is not the same as being able to recover. See
      [backup and restore](../operations/backup-and-restore.md) and
      [upgrade, rollback and DR](../operations/upgrade-rollback-and-dr.md).
- [ ] You have decided how long to keep the ledger, the samples and the logs. See
      [retention](../operations/retention.md).

## Publishing the feed

- [ ] If you publish the feed, the cron entry for `deploy/blocklist-sync.sh` is yours to
      install; nothing shipped schedules it. Set `PROPOLIS_OPS_FEED_PUSH_EXPECTED` once it
      is in place so a push that never works is reported.
- [ ] The feed output directory is world-readable on purpose, so a web server or sync
      user can serve it. Confirm that is what you want before anything else can read the
      host.
- [ ] The target repository's visibility matches your intent. The content is a list of
      attacker addresses, and the repository reveals that you run a honeypot.

## Outbound integrations

- [ ] Each one you enable is a deliberate decision: VirusTotal (`PROPOLIS_VT_ENABLED`),
      the dropper fetcher (`PROPOLIS_FETCH_ENABLED`), reverse DNS
      (`PROPOLIS_CONSOLE_RDNS_ENABLED`), push alerts (`PROPOLIS_OPS_ENABLED`), and any
      vendor whose key you set. All are off until then. What each one sends is in
      [outbound controls](../security/outbound-controls.md).

## Operations

- [ ] Alerting is configured, or you have decided to do without it. With
      `PROPOLIS_OPS_ENABLED=true` the ntfy URL and topic are required and the daemon
      refuses to start without them. See
      [health and observability](../operations/health-and-observability.md).
- [ ] You have read [routine procedures](../operations/routine-procedures.md) and know
      how to [tear the node down](safe-teardown.md).
