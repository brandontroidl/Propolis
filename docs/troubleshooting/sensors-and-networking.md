<!--
title: Troubleshooting - sensors and networking
audience: operator
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Sensors and networking

There are 9 sensor crates covering 12 protocols (the `cred` sensor serves VNC,
MySQL, MSSQL, PostgreSQL, and MongoDB). Each sensor is a separate process with
its own `/etc/propolis/<name>.env`. Sensors make **no outbound connections by
design** and have no HTTP client in their dependency tree - if a sensor appears
to be reaching out, that is not expected behavior. Per-protocol capture details
are owned by [Sensor behavior](../reference/sensor-behavior.md); binds and ports
by [Ports and protocols](../reference/ports-and-protocols.md).

## Nothing is being captured

Work outward from the process:

1. **Is the sensor running?** `systemctl status sensor-ssh` (etc.). A crash-loop
   is almost always a config abort - see
   [Startup and config](startup-and-config.md). Standard sensors carry
   `Restart=always`, so a misconfigured sensor restarts endlessly; read
   `journalctl -u sensor-ssh`.
2. **Is it listening?** Confirm the socket:
   ```
   ss -ltnp | grep -E ':22|:23|:80'   # example ports
   ```
   No listener means the bind failed or the sensor is not started.
3. **Is the daemon reading the sensor's log?** Capture only reaches scoring if
   the unified daemon (or standalone `intake`) is consuming that sensor's
   `events.jsonl` via `PROPOLIS_SENSOR_LOGS` (a `name:path` list). A sensor can
   be capturing to its log while the daemon ignores it because the path is not in
   `PROPOLIS_SENSOR_LOGS`. Verify the mapping matches each sensor's `LOG_PATH`.
4. **Can traffic reach the port?** From another host, test the port is open
   through the firewall. Sensors need inbound on their configured ports.

## Port not listening

- **Bind var unset or wrong** - every sensor's `*_BIND` (catchall:
  `CATCHALL_BIND_ADDRS`) is required with no default. Unset → the sensor refuses
  to start. A typo'd `ip:port` → abort (strict sensors) or, for `cred`/`smtp`
  only, exit 1 on an invalid bind.
- **Bound to the wrong interface** - `127.0.0.1:22` only accepts loopback.
  Exposure needs `0.0.0.0:22` (or the specific public interface). This is an
  operator choice in the `.env`, not a code default.
- **Privileged port without capability** - catchall/ssh/telnet/http/ftp/smtp
  units carry `CAP_NET_BIND_SERVICE` for ports below 1024; redis/adb/cred do
  not. Rebinding a no-capability sensor to a low port fails to bind.
- **Port already owned** - a real service (e.g. the host's own `sshd`) holds the
  port. See bind conflicts in [Startup and config](startup-and-config.md).

## Bind address vs. exposure

The honeypot is meant to be reached from the internet, but the surrounding
network controls what actually arrives. If sensors listen on `0.0.0.0` yet see
nothing, check upstream: VLAN default-deny rules, cloud security groups, NAT/DNAT
forwarding, and any host firewall. The sensor only sees what the network delivers
to its socket.

## WAN attribution empty ("Distinct WAN vantages" reads 0, `wan_ip` null)

Each sensor takes an optional `*_WAN_MAP` (catchall: `CATCHALL_WAN_MAP`) mapping a
local bind address to its public WAN IP, used for multi-vantage breadth scoring.
Two accepted forms:

- NAT/DNAT: `private=public` (the bind is a private address, mapped to the public
  IP that fronts it).
- Direct-bind identity: `public=public` (the sensor binds the public address
  itself).

An **unmapped** local bind address yields a null `wan_ip`: no WAN attribution,
and the console detail page shows "Distinct WAN vantages" as 0. Fixes:

1. Confirm the sensor's actual bind address matches a left-hand key in its
   `*_WAN_MAP` exactly. A map that references a different address than the sensor
   binds attributes nothing.
2. On a NAT'd node, set the `private=public` mapping; on a directly-bound public
   node, set `public=public`.
3. After changing the map, restart the sensor. Historical events captured before
   the fix stay null - attribution is stamped at capture time and is not
   backfilled.

Breadth scoring only counts a WAN vantage that completed an authenticated TCP
handshake, and dedups vantages by /24 (IPv4) or /64 (IPv6) prefix
(`crates/core-scoring/src/scoring/breadth.rs:29-57`). So a single operator block
or spoofed UDP source will not inflate the vantage count even when mapped
correctly - that is intended. Scoring constants:
[Scoring and feed](../reference/scoring-and-feed.md).

## SSH sensor fingerprint / host key

`sensor-ssh` persists its host key at `/var/lib/propolis/ssh/host_key`
(`PROPOLIS_SSH_HOST_KEY_PATH`) and reuses it across restarts so the honeypot does
not present as freshly minted each boot. If that path is not writable by
`propolis-ssh`, the sensor cannot persist the key; check ownership
(`0750 propolis-ssh`). The banner defaults to the persona OpenSSH version and can
be overridden with `PROPOLIS_SSH_BANNER`.

## No in-process TLS

The console and sensors do not terminate TLS in-process. Any TLS is provided by
an operator-run reverse proxy `[inferred]`; there is no built-in HTTPS to
misconfigure at the application layer. See
[Networking and TLS](../operations/networking-tls.md).
