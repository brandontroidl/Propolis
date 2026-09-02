<!--
title: Residual risks
audience: security
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Residual risks

What Propolis does **not** protect against, stated plainly. These are limits of
the shipped code and deployment model, not defects to be discovered later. None
of them is a hidden guarantee. For the positive controls, see the rest of this
section; for what to do about several of these, see the
[hardening checklist](./hardening-checklist.md).

## `SystemCallFilter` is a placeholder

Every shipped systemd unit sets `SystemCallFilter=@system-service` minus
`@privileged @resources` - explicitly a broad development allowlist, labelled as
such in the unit header, which instructs the operator to derive the real
per-binary allowlist before production. **A tightened seccomp filter is not
shipped in the repo, and whether one was derived on any given host is not
verifiable from source.** Until an operator narrows it, the syscall sandbox
should be treated as effectively absent; the other sandbox layers
(`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, capability
bounding, address-family restriction) still apply. See
[hardening checklist step 1](./hardening-checklist.md).

## No in-process TLS

The console serves plain HTTP on a `TcpListener` (`axum::serve`, no rustls). There
is no built-in TLS anywhere in the platform. Confidentiality and integrity for
console traffic beyond loopback depend entirely on an operator-provided reverse
proxy. Do not assume transport encryption exists unless you configured it.

## Quarantine mount options are operator-applied

Captured samples are written `0640` under spool directories that the deployment
*expects* to be mounted `noexec,nosuid,nodev`. `install.sh` only prints the fstab
guidance; it cannot enforce the mount. If those options are missing on the host,
the `0640` mode and the daemon's `NoExecPaths` are the remaining defenses, but the
intended filesystem-level no-execute guarantee is not in force. Sample bodies are
never executed by Propolis itself regardless (see
[never-execute](./never-execute.md) and [malware custody](./malware-custody.md)).

## Single-node blast radius

The default and reference deployment is a single host running the sensors and the
unified daemon against one PostgreSQL database. There is no built-in redundancy,
failover, or off-host replication. A full host loss loses everything not already
backed up off-host, and a host compromise reaches every subsystem on it. Real
resilience requires operator-provided off-host backups (tested by restoring) and,
where warranted, independent infrastructure. See
[../operations/backup-and-restore.md](../operations/backup-and-restore.md).

## Egress paths, once enabled, are real egress

Five outbound paths exist, all opt-in and defaulting OFF. When an operator enables
one, it makes genuine outbound requests:

- The **malware fetcher** dials attacker-supplied URLs. It is guarded by a
  fail-closed SSRF vetter (scheme allowlist, userinfo rejection, DNS-rebinding
  defense, pinned-address connect, forbidden-target/reserved-IP checks, tftp
  port-69 pinning) run on the initial URL and every redirect hop - but enabling it
  is still a deliberate acceptance of dialing hostile hosts.
- **VirusTotal**, **vendor abuse submitters**, **console rDNS**, and **ops-alert
  ntfy** each reach a third-party or operator-configured endpoint when enabled.

The accurate framing is: *sensors are egress-free by construction; the platform's
few enrichment/reporting egress paths are operator-gated and default off.* The
workspace is **not** egress-free - `Cargo.lock` contains `reqwest` and `hyper`,
used by these paths. Full behavior and guards live in
[outbound-controls.md](./outbound-controls.md).

## Honeypot-detection tells

Propolis emulates services to attract and observe attackers. No emulation is
indistinguishable from a real system to a determined, well-resourced adversary:
protocol-level and behavioral fingerprinting can identify a honeypot. Persona and
banner work reduces obvious tells, but detection remains possible and IP rotation
is the practical lever for recovering interaction after a source has fingerprinted
the node. This is an inherent limit of the approach, not a solved problem, and no
specifics are enumerated here.

## Public feed repository exposure

The published blocklist feed contains only attacker source IPs and
tier/first-seen/last-seen/category fields - **zero** `wan_ip` (honeypot ingress
attribution) references, verified by construction across the feed crate. Publishing
the feed contents does not leak your vantage. However, the publish-to-repo step
(`deploy/blocklist-sync.sh`) is an operator cron job, not a shipped timer; its
deploy key, repository visibility, and cron/SSH-agent setup are operator
responsibilities and out of the code's control.

## Unauthenticated console metrics

`/health`, `/ready`, and `/metrics` are unauthenticated. This is safe *only*
because the console defaults to loopback-only. Binding the console to a routable
address without a fronting proxy exposes operational metrics to the network. See
[authn/authz](./authn-authz.md) and [attack surfaces](./attack-surfaces.md).

## Related

- [Hardening checklist](./hardening-checklist.md)
- [Threat model](./threat-model.md)
- [Outbound controls](./outbound-controls.md)
- [Limitations](../overview/limitations.md)
