<!--
title: Filesystem and database protections
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Filesystem and database protections

How Propolis constrains what its processes can touch on disk and what any
database client (including a compromised collector) can do to the event store.
This page owns the *security rationale*; exhaustive values live in the reference
pages linked below.

## Process isolation (systemd)

Every shipped unit under `deploy/` runs as a dedicated, unprivileged OS user and
applies a least-authority sandbox. These directives are asserted by
`crates/sensor-framework/tests/deploy_test.rs` (a dropped directive fails the
test), not merely documented.

Security-relevant directives common to the unified daemon (`deploy/propolis.service`)
and every sensor unit:

| Directive | Value | Effect |
|---|---|---|
| `User=` / `Group=` | dedicated `propolis-*` user, never root | asserted `User != root` (`deploy_test.rs:84`) |
| `NoNewPrivileges=yes` | - | no setuid/capability escalation after exec |
| `ProtectSystem=strict` | - | entire filesystem read-only except explicit `ReadWritePaths` |
| `ProtectHome=yes` | - | home trees invisible |
| `MemoryDenyWriteExecute=yes` | correct spelling (the `-ion` form silently installs no rule) | no W^X pages: captured code cannot become executable memory |
| `RestrictAddressFamilies=` | sensors `AF_INET AF_INET6`; daemon adds `AF_UNIX` (local PostgreSQL socket) | no raw/packet/netlink sockets |
| `PrivateTmp`, `PrivateDevices`, `ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`, `RestrictNamespaces`, `RestrictSUIDSGID`, `LockPersonality`, `RemoveIPC`, `ProtectProc=invisible`, `ProcSubset=pid` | - | broad supplementary containment |
| `UMask=` | sensors `0027` (logs group-readable so the daemon's group membership can read them); console `0077` | default file mode |
| Resource caps | `MemoryMax`, `TasksMax`, `CPUQuota`, `LimitNOFILE` per unit | bound resource-exhaustion blast radius |

`ReadWritePaths` is scoped to each service's own log/spool/state directories.
Only `sensor-ssh` gets a third writable path (`/var/lib/propolis/ssh`) for its
persistent host key. Sensors binding a privileged port (22/23/80/21/25) carry
`AmbientCapabilities=CAP_NET_BIND_SERVICE` with a matching bounding set; the
daemon and non-privileged-port sensors carry an empty `CapabilityBoundingSet=`.

The unified daemon additionally sets `ReadOnlyPaths=/var/log/propolis`,
`NoExecPaths=/var/spool/propolis/fetched` (systemd ≥244, defense-in-depth over
the fstab `noexec` mount for live malware binaries), and `PrivateUsers=yes`.

> **Caveat - `SystemCallFilter` is a placeholder, not a delivered control.**
> Every unit ships `SystemCallFilter=@system-service` minus `@privileged
> @resources` (`deploy/propolis.service:176-187`, `deploy/sensor-ssh.service:80-99`).
> The unit header explicitly labels this a **broad development allowlist** and
> instructs the operator to derive the real per-binary allowlist (e.g. via
> `strace -c -f`) before production. A tightened syscall filter is **not** shipped
> in the repo. See [residual-risks.md](./residual-risks.md) and the
> [hardening checklist](./hardening-checklist.md).

## Filesystem permission model (install.sh)

`deploy/install.sh` (idempotent; `install -d` reasserts mode/owner/group) lays
out the directory tree. The exhaustive path/mode table is owned by
[../reference/filesystem-paths.md](../reference/filesystem-paths.md); the
security-load-bearing choices:

- **`/var/lib/propolis` is root-owned `0755`** on purpose
  (`install.sh:132-137`): a parent writable by the `propolis` daemon would let a
  compromised daemon unlink or swap the sibling `ssh/` host-key directory for a
  symlink that `ProtectSystem=strict`'s bind-mount would then follow. The host-key
  dir `/var/lib/propolis/ssh` is `0750` owned `propolis-ssh`.
- **Captured sample files are written `0640`**
  (`crates/sensor-framework/src/spool.rs:277`) into spool directories that
  `install.sh` prints (does **not** auto-create) `noexec,nosuid,nodev` fstab lines
  for (`install.sh:172-182`). Whether those mount options are actually applied on
  a given host is an operator step, not enforceable from the repo - see
  [malware custody](./malware-custody.md) and
  [residual risks](./residual-risks.md).
- **Secrets live only in `/etc/propolis/*.env`, mode `0600`, owned by the service
  user** - created by hand by the operator, never by `install.sh`. No secret is
  read from argv or baked into a unit file. See
  [../operations/secret-management.md](../operations/secret-management.md).
- Dedicated users are created `--system --no-create-home --shell /usr/sbin/nologin`
  (`install.sh:86-101`); no sensor user can log in.

## Database-layer protections

The event store is defended at the PostgreSQL layer, independently of the
application, so a compromised collector or direct SQL access cannot forge or
rewrite history. Table/enum/migration details are owned by
[../reference/database.md](../reference/database.md).

**Append-only immutability** (`crates/core-scoring/migrations/0004_harden_event_table.sql`):
in the production database the `propolis` role retains `INSERT` but is stripped of
`UPDATE`, `DELETE`, and `TRUNCATE` on the `event` table (the `REVOKE` is skipped
for test databases so fixtures can clean up). `CHECK` constraints enforce
non-empty `sensor`, a 32-byte `hash`, `confidence` in `[0,1]`, and non-negative
`weight`, so a direct INSERT bypassing the application cannot inject invalid rows.

**Hash-chain linkage enforced by trigger**
(`crates/core-scoring/migrations/0005_chain_enforcement_trigger.sql`): a
`BEFORE INSERT` trigger (`enforce_chain_linkage`) rejects any row whose
`prev_hash` does not equal the current chain head - the first event must carry a
NULL `prev_hash`; every later event must match. The SHA-256 hash *value* is still
computed application-side over a frozen canonical byte encoding
(`crates/core-scoring/src/hashing.rs`; see
[../architecture/storage.md](../architecture/storage.md) for the chain design),
but the database now enforces the *linkage* a rogue INSERT would try to skip.

**Serialized inserts.** The chain-head read, INSERT, and projection run inside one
transaction under a `pg_advisory_xact_lock` at READ COMMITTED
(`crates/core-scoring/src/repository/events.rs:142-171`) so two concurrent inserts
cannot fork the chain on the same `prev_hash`.

**Parameterized queries only.** No SQL string is built with `format!` in non-test
source (workspace grep for `format!(...)` containing `SELECT|INSERT|UPDATE|DELETE|WHERE`
returns zero). The event insert, feed builder, review CLI, and VirusTotal writer
all use `sqlx` bound placeholders (`$1`, `$2`, …), never string interpolation.

## Related

- [Attack surfaces](./attack-surfaces.md)
- [Never-execute invariant](./never-execute.md)
- [Malware custody](./malware-custody.md)
- [Supply chain](./supply-chain.md)
- [Hardening checklist](./hardening-checklist.md)
- [Residual risks](./residual-risks.md)
