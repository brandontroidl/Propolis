<!--
title: Residual risks
audience: security
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
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

## No in-process TLS on the console

The console serves plain HTTP on a `TcpListener` (`console::server::serve`, HTTP/1.1, no rustls). It
has no built-in TLS; the only in-process TLS in the platform is on seven sensors' attacker-facing
ports, which protects nothing of the operator's. Confidentiality and integrity for
console traffic beyond loopback depend entirely on an operator-provided reverse
proxy. Do not assume transport encryption exists unless you configured it.

## Quarantine mount options are operator-applied

Captured samples are written `0640` under spool directories that the deployment
*expects* to be mounted `noexec,nosuid,nodev`. `install.sh` only prints the fstab
guidance; it cannot enforce the mount. If those options are missing on the host,
the `0640` mode and every unit's `NoExecPaths=/` are the remaining defenses, but the
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

## A compromised sensor can forge its own kind of evidence

Intake believes a sensor log line only as far as the file it came from proves it
([origin policy](../reference/events-and-signals.md#what-a-log-line-may-claim-the-origin-policy)):
a log speaks for its own sensor, within the signal types, protocols and authentication that
sensor can produce, and a line dated more than an hour ahead is refused. What remains:

- **A sensor's own kind of event, under its own name, for any address.** A compromised
  `sensor-ssh` can write authenticated ssh uploads, and a compromised sensor-cred protocol can
  write login summaries worth up to a million events each, for an address that never connected.
  The policy narrows what a low-interaction sensor (catchall, tftp, dns, http, adb) can claim;
  it does not make a sensor's testimony about its own protocol verifiable. One forged summary,
  or a thousand forged TCP lines, still takes an address that never connected past the volume
  threshold.
- **A log that is not bound.** Only a `PROPOLIS_SENSOR_LOGS` name that is a sensor's name or one
  of the five shipped `cred-*` labels binds a log. Under any other name the log may carry any
  known sensor's lines, each held to its own row only, so the writer of that log can speak for
  every sensor.
- **A compromised collector, as a whole.** In a split deployment the per-log check runs in the
  shipper on the collector. Root on the collector, or its shipper or certificate key, can send
  the control plane any line that fits some known sensor's row
  ([split deployment](../operations/split-deployment.md#known-limitations)).
- **Timestamps within the bounds.** A line may be dated up to an hour ahead, and as far back as
  its writer likes: a back-dated line cannot move `last_seen` or the decay anchor, but it is
  stored with the time it claims and sorts there in the ledger and the console.
- **What was stored before these checks.** Ledger rows and `ip_score` rows written by an earlier
  version keep the sensor names and timestamps they had. Nothing re-validates the ledger and
  nothing rebuilds a projection, so a row whose `last_seen` or `decay_anchor` was moved back by
  an out-of-order event stays as it is until that address's next event, and one that is dated
  in the future stays so until the clock passes it (the next event no longer pulls it back).
  `SELECT source_ip, last_seen FROM ip_score WHERE last_seen > now() + interval '1 hour'` finds
  the latter; delisting the address in the console takes it out of the feed.

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

The script reads a directory the daemon writes, so a compromised daemon chooses
what it finds there. It copies only single-link regular files with the publisher's
names, opens each name once, without following a link or blocking (`O_NOFOLLOW|O_NONBLOCK`), compares
the device and inode of the open descriptor with the stat it took before opening
(reading only from that descriptor), and writes
nothing in that directory, so a planted link, FIFO or stray file is refused, including
one present only for the instant of the open. Planting a hard link to a file the
daemon cannot itself read is also refused by the kernel when `fs.protected_hardlinks=1`
(the Debian default); the script's checks do not depend on it, but a host that sets it
to 0 loses that first layer and should be treated as relying on the checks alone. What
it cannot stop is
the daemon publishing false content under the right names: the feed is the
daemon's output, and a compromised daemon can list any address it likes. The
account it runs as is the operator's choice; the documented one,
`propolis-blocklist`, cannot read root's files, but a crontab left under root still
runs (with a warning), and then the checks are the only boundary.

## Unauthenticated console metrics

`/health`, `/ready`, and `/metrics` are unauthenticated. This is safe *only*
because the console defaults to loopback-only. Binding the console to a routable
address without a fronting proxy exposes operational metrics to the network. See
[authn/authz](./authn-authz.md) and [attack surfaces](./attack-surfaces.md).

## Deploying from the repository

`deploy/upgrade.sh` fetches the repository, builds it as the checkout's owner and installs the
result as root. Its checks (a clean tree, the origin the last deploy recorded, fast-forward
only unless the operator names the commit, and an SSH signature when
`/etc/propolis/upgrade-signers` exists) hold against the
remote and against operator mistakes; the checkout's owner account builds what root installs
and is trusted by construction. What remains:

- **Without a signers file, the remote is trusted.** A hostile or hijacked remote (a
  compromised hosting account or push credential, a `core.sshCommand` in the owner's config,
  an https interception the owner's CA store accepts) that serves any commit descending from
  `HEAD` is fetched, built and installed as root. Origin pinning and fast-forward-only stop a
  mispointed remote and a rollback, not the remote itself. Signing is the control, and it is
  off by default.
- **With signing on, the signature proves the author, not the intent to release.** The remote
  may present any commit a listed key signed that descends from `HEAD`, including a signed
  branch never meant for `main`, and the box deploys it.
- **Adopting a history trusts the commit the operator names.**
  `--adopt-history=<commit>` deploys an `origin/main` that does not descend from what the box
  runs, provided it is exactly the commit named: an unrelated history, a rewritten `main`, or
  an earlier commit of the box's own history, which makes the argument the one way a remote's
  rollback is accepted. Nothing in such a commit can prove it continues the same code, so the
  proof is the id, and it is worth what the channel it came through is worth. An id read off
  the remote being checked (this box's own fetch, or the hosting site's page for a repository
  that may be hijacked) checks nothing. Until a run has accepted `origin/main` the script
  prints neither the fetched id nor what the remote sent during the fetch, which keeps it
  from inviting that mistake and does not prevent it: the id is one `git rev-parse` away in
  the box's clone, and a remote has other ways to reach an operator than the terminal. An
  adopted tree that lacks migrations the database has run builds a daemon that will not
  start; the run warns and goes on. The run prints how many files differ so the operator
  sees what they accept; it cannot judge whether the difference is benign. With signing on,
  the named commit must also carry a listed key's signature, and that is the control that
  does not depend on where the id came from. See
  [a restarted history](../operations/upgrade-rollback-and-dr.md#a-restarted-history-or-a-successor-repository).
- **A freeze is not detected.** The remote may withhold new commits indefinitely; nothing on
  the box knows that `main` has moved elsewhere. The fleet pane's "behind" reading is from
  the last fetch, not a live query.
- **The hand-run collector upgrade** in
  [split deployment](../operations/split-deployment.md#upgrading) runs the fetch, signature
  check and fast-forward by hand; the dirty check and the origin pin are done by eye, and
  nothing records the origin. The by-hand steps onto a restarted history, on a collector and
  on a box whose `upgrade.sh` predates `--adopt-history`, make the same checks as the script
  in one chained command, but they are typed by an operator, not enforced by a program: a
  step left out is not noticed.

The setup and the full list of what signing does and does not cover are in
[upgrade, rollback and DR](../operations/upgrade-rollback-and-dr.md#signed-upgrades-recommended).

## Related

- [Hardening checklist](./hardening-checklist.md)
- [Threat model](./threat-model.md)
- [Outbound controls](./outbound-controls.md)
- [Limitations](../overview/limitations.md)
