<!--
title: Quickstart manual
audience: evaluator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Quickstart manual

The shortest safe path to a running local Propolis and a first captured event.

> [!WARNING]
> **Non-production.** This is a loopback-only evaluation. It skips systemd
> sandboxing, per-service secret files, syscall hardening, a TLS proxy, and
> backups that a real deployment requires. Do **not** expose these listeners to
> untrusted networks. In this configuration Propolis makes no outbound requests
> beyond PostgreSQL (every enrichment/reporting egress path defaults off). For a
> real deployment, use the [deployment manual](deployment.md) and the
> [production-readiness checklist](../getting-started/production-readiness-checklist.md).

## Path

Follow these canonical pages in order - each owns its exact commands and values;
this manual is the sequence, not a copy.

1. **Prerequisites** - Linux + systemd, the pinned Rust toolchain (`1.96.1`),
   PostgreSQL 15+, and building needs no root:
   [`../getting-started/prerequisites.md`](../getting-started/prerequisites.md).
2. **Bring it up** - `cargo build --release`, a throwaway loopback PostgreSQL,
   the minimal required env (`DATABASE_URL`, `PROPOLIS_CONSOLE_PASSWORD`,
   `PROPOLIS_SENSOR_LOGS`, `PROPOLIS_CURSOR_DIR`), run the daemon, run one SSH
   sensor on a high unprivileged port, and open the console at
   `http://127.0.0.1:8080/`:
   [`../getting-started/evaluation-deployment.md`](../getting-started/evaluation-deployment.md).
3. **First capture** - connect to the local sensor, then watch the event flow
   sensor log -> hash-chained ledger -> score -> console (Live logs, Attackers,
   IP detail, Review queue):
   [`../getting-started/first-capture.md`](../getting-started/first-capture.md).

## Then

- Explore the UI: [console tour](../getting-started/console-tour.md).
- Tear down cleanly (stop sensors first, then the daemon; remove the eval DB):
  [safe teardown](../getting-started/safe-teardown.md).

> [!WARNING]
> Any file a sensor captures from an upload is a live payload and may be malware.
> Never execute captured content; handle only in an isolated environment. See
> [malware custody](../security/malware-custody.md).

## Next step

Ready for real infrastructure? Do not treat this eval as a template - start from
the [deployment manual](deployment.md) and work the
[production-readiness checklist](../getting-started/production-readiness-checklist.md)
first.
