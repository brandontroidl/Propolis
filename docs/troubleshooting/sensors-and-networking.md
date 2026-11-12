<!--
title: Troubleshooting - sensors and networking
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Sensors and networking

There are 12 sensor crates covering 15 protocols (the `cred` sensor serves VNC,
MySQL, MSSQL, PostgreSQL, and MongoDB). Each sensor is a separate process with
its own `/etc/propolis/<name>.env`. Sensors make **no outbound connections by
design** and have no HTTP client in their dependency tree - if a sensor appears
to be reaching out, that is not expected behavior. Per-protocol capture details
are owned by [Sensor behavior](../reference/sensor-behavior.md); binds and ports
by [Ports and protocols](../reference/ports-and-protocols.md).

## Nothing is being captured

Run `sudo ./deploy/config-check.sh` first. It checks every step below for every listener at
once (unit, port and its holder, firewall, log, the `PROPOLIS_SENSOR_LOGS` entry, newest
ledger event) and prints an exact fix line per failure; see
[service lifecycle](../operations/service-lifecycle.md#configuration-check). The manual steps
follow for when you want to see one yourself.

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
  `PROPOLIS_CATCHALL_BIND_ADDRS`) is required with no default. Unset → the sensor refuses
  to start. A typo'd `ip:port` → abort (strict sensors) or, for `cred`/`smtp`
  only, exit 1 on an invalid bind.
- **Bound to the wrong interface** - `127.0.0.1:22` only accepts loopback.
  Exposure needs `0.0.0.0:22` (or the specific public interface). This is an
  operator choice in the `.env`, not a code default.
- **Privileged port without capability** - catchall/ssh/telnet/http/ftp/smtp/tftp/dns
  units carry `CAP_NET_BIND_SERVICE` for ports below 1024; redis/adb/mqtt/cred do
  not. Rebinding a no-capability sensor to a low port fails to bind.
- **Port already owned** - a real service (e.g. the host's own `sshd`) holds the
  port. See bind conflicts in [Startup and config](startup-and-config.md).
- **DNS on port 53 next to a local resolver** - the sensor exits 1 with
  `sensor-dns: udp: cannot start listener on 0.0.0.0:53: Address already in use (os error 98);
  refusing to start` (UDP binds first; `tcp` or `dot` names the other listeners). Find the
  holder with `sudo ss -lunpt 'sport = :53'`. Linux refuses a wildcard bind over a specific one
  and a specific bind under a wildcard one, so the fix depends on what the holder binds:
  - systemd-resolved holds only `127.0.0.53:53` and `127.0.0.54:53`: bind the public address
    (it coexists), or set `DNSStubListener=no` in `/etc/systemd/resolved.conf` and restart
    `systemd-resolved` to free the port for a wildcard bind.
  - A resolver on the wildcard (dnsmasq without `bind-interfaces`, named with its default
    `listen-on`) blocks every bind of port 53, the public address included. Narrow it to
    loopback: dnsmasq `bind-interfaces` with `listen-address=127.0.0.1`; unbound
    `interface: 127.0.0.1`; named `listen-on { 127.0.0.1; };`.
  - Behind NAT the public address is not on the host: bind the private address and map it with
    `PROPOLIS_DNS_WAN_MAP`.

  Details are in [sensor-behavior](../reference/sensor-behavior.md#sensor-dns).

Every sensor logs a listener that fails to start, after its configuration
validated, in one form
(`crates/sensor-framework/src/listener.rs#listener_start_error`):

```
<sensor>: cannot start listener on <ip:port>: <OS error>; refusing to start
```

for example `Address already in use (os error 98)` (another process holds the
port) or `Permission denied (os error 13)` (a port below 1024 without
`CAP_NET_BIND_SERVICE`). The sensor stops any listener it already started and
exits 1. Two sensors skip one failed address instead of exiting: catchall logs
`catchall: tcp cannot start listener on ...; skipping this port` (or `udp`),
and cred logs `...; skipping protocol <name>`. Each exits 1 with
`no listener started on any configured address; refusing to start` only when
every address failed. `sensor-dns`, whose one bind starts two listeners, names
the transport first: `sensor-dns: udp: cannot start listener on ...` (or `tcp`,
or `dot` for the DNS over TLS listener).

## Bind address vs. exposure

The honeypot is meant to be reached from the internet, but the surrounding
network controls what actually arrives. If sensors listen on `0.0.0.0` yet see
nothing, check upstream: VLAN default-deny rules, cloud security groups, NAT/DNAT
forwarding, and any host firewall. The sensor only sees what the network delivers
to its socket.

## WAN attribution empty ("Distinct WAN vantages" reads 0, `wan_ip` null)

Each sensor takes an optional `*_WAN_MAP` (catchall: `PROPOLIS_CATCHALL_WAN_MAP`) mapping a
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
(`crates/core-scoring/src/scoring/breadth.rs#distinct_wan_count`). So a single operator block
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

## Sensor TLS

Seven sensors (http, redis, mqtt, smtp, ftp, cred, dns) terminate TLS in-process; the variables, ports
and rules are in [Networking and TLS](../operations/networking-tls.md#sensor-tls-attacker-facing-listeners).
The console has no in-process TLS: put it behind your own reverse proxy.

**The sensor exits 1 at start and the journal says `refusing to start`.** TLS is fail-closed:
any doubt about the TLS configuration or the pair stops the whole sensor, plain listener included,
before it binds anything; a bind the OS refuses (last item) stops it after its earlier listeners
bound. With `Restart=always` that shows as a restart loop; read the one error line with
`journalctl -u sensor-<name> -n 20`. The usual causes:

- **Key mode.** The error names the key, its mode, and says `chmod 0600`. The key must have no
  group or other permission bit; the certificate is not checked. A pair minted by
  `deploy/provision-tls.sh` is already `0600`; a real certificate copied in by hand often is not.
- **Missing or unreadable pair.** `cannot read /etc/propolis/tls/<sensor>.crt` (or `.key`)
  followed by an OS error. `No such file or directory`: the env file names a file that is not
  there. `Permission denied`: the file exists but the sensor's user cannot open it, usually
  because it is owned by root or another account (a pair copied in with `cp` as root). Check
  with `ls -l /etc/propolis/tls`; each file must be owned by `propolis-<sensor>` (the key
  `0600`, the certificate `0644`) and the directory must be traversable (`0711`). Run
  `sudo deploy/provision-tls.sh` to repair ownership and mode on a minted or installed pair
  (it mints only a missing pair, and needs a build tree), or fix it by hand as in
  [Install a real certificate](../operations/networking-tls.md#install-a-real-certificate),
  or fix the path. If `/etc/propolis/tls` itself is missing, run `deploy/provision.sh` first.
- **Half-set variables.** Only one of `*_TLS_CERT` and `*_TLS_KEY` is set, or a `*_TLS_BIND` is
  set without both. The error names the variables involved. On every TLS sensor a value is
  trimmed and a blank one counts as unset, so `PROPOLIS_<X>_TLS_BIND=` means no TLS listener.
- **Non-UTF-8 value.** `environment variable <VARIABLE> is not valid UTF-8`: a sensor variable
  (a TLS variable or bind here, but any `PROPOLIS_*` variable of any sensor behaves the same)
  holds bytes that are not UTF-8, usually an env file saved in a legacy encoding. It is never
  read as unset and never replaced by a default; rewrite the line as plain ASCII.
- **Unparseable bind.** `invalid <VARIABLE>`: the TLS bind is not an `ip:port`.
- **Unusable file.** Not PEM, no certificate or key in it, larger than 1 MiB, not a regular
  file, or a certificate and key that do not match. A malformed PEM is reported as
  `malformed PEM in <path>: <fault>`, where the fault is a fixed phrase such as
  `missing section end marker` (often a key pasted onto one line); the file's content is never
  logged.
- **TLS port in use or not permitted.** The TLS listener is bound last, after the plain one,
  so this is not caught by the configuration checks. The journal shows
  `<sensor>: cannot start listener on <ip:port>: Address already in use (os error 98); refusing
  to start` (another process holds the port) or `...: Permission denied (os error 13); refusing
  to start` (a port below 1024 on a unit without `CAP_NET_BIND_SERVICE`; only redis, mqtt and
  cred lack it, and their TLS ports are unprivileged). The sensor tears the plain listener down
  and exits 1, so neither port is served. Free the port or change the bind; see
  [Port not listening](#port-not-listening).

A missing `/etc/propolis/tls` directory does not stop a unit that uses no TLS: the units grant it
as `ReadOnlyPaths=-/etc/propolis/tls`, where the `-` makes it optional.

**The cert and key are set but the TLS port is not listening.** A TLS listener exists only when
its `*_TLS_BIND` (or `PROPOLIS_SMTP_SUBMISSION_BIND`) is set; a pair alone opens no port and logs
one warning. sensor-smtp and sensor-ftp use a pair alone for STARTTLS and AUTH TLS on the plain
port, and sensor-cred never opens a TLS port: its TLS runs on the plain binds.

**Clients connect but the TLS handshake fails, and nothing is logged.** Failed and timed-out
handshakes are dropped with no event and logged at debug level only, because plaintext sent to a
TLS port is the common scanner case. The certificate is self-signed for `localhost`, so a client
that verifies certificates rejects it unless told not to.

**Raising the log level.** Sensors log at `info` when `RUST_LOG` is unset
([`RUST_LOG`](../reference/environment-variables.md#rust_log)), so the startup, listening and
"no TLS listener started" warning lines are in the journal by default. `RUST_LOG` overrides the
default; to also log each failed handshake, add a line to the sensor's env file and restart it:

```
# /etc/propolis/<sensor>.env
RUST_LOG=debug
```

`debug` is noisy on an internet-facing port, so set it only while diagnosing and remove it
afterwards.

```
sudo systemctl restart sensor-<sensor>
journalctl -u sensor-<sensor> -f
```
