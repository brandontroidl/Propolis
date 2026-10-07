<!--
title: Networking and TLS
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-06
-->

# Networking and TLS

This page covers the network exposure of each component and the platform's TLS
posture. Exact ports and binds are owned by
[../reference/ports-and-protocols.md](../reference/ports-and-protocols.md); this
page explains exposure and operator responsibilities.

## Three exposure classes

| Class | Components | Default binding |
|---|---|---|
| Attacker-facing | the eleven sensors (ssh, telnet, http, ftp, smtp, tftp, mqtt, redis, adb, catchall, cred) | operator-chosen `ip:port` per sensor - **no code default** |
| Operator-facing | console web UI (and `/health`, `/ready`, `/metrics` on the same port) | `127.0.0.1:8080` (loopback) |
| No listener | `intake`, `review`, `feed`, and the unified daemon's fetcher | none (DB clients / outbound-only) |

### Sensors (attacker-facing)

Sensors are the internet-exposed honeypot listeners. Each requires its bind
address explicitly and fails closed if it is absent or unparseable - there is no
compiled-in default port anywhere
(`crates/sensor-ssh/src/main.rs#load_config_from_env` and
the equivalent in each sensor). The IP portion is whatever the operator writes
(`0.0.0.0`, a specific address, etc.). `sensor-ftp` additionally opens
passive-mode data connections on dynamic ephemeral ports negotiated per session
(`94a62ae1`, `016721e1`); the exact range is OS-ephemeral [inferred - not
verified to a fixed/configurable range in this pass].

> **Warning - sensors are live attacker listeners.** Expose them only on a host
> positioned as intended: an isolated VLAN, firewalled, with out-of-band host
> administration (the honeypot's port 22 is the *fake* SSH sensor, not a real
> admin channel - real host admin is out-of-band, e.g. the hypervisor console).
> See [../getting-started/production-readiness-checklist.md](../getting-started/production-readiness-checklist.md).

### Console (operator-facing)

The console binds **loopback-only by default** (`127.0.0.1:8080`,
`crates/propolis/src/config.rs#DEFAULT_CONSOLE_BIND`), on an unprivileged port with no
capability grant. It binds a non-localhost address only if the operator
overrides `PROPOLIS_CONSOLE_BIND` - the design intent is to keep it loopback and
put any remote access behind the operator's own reverse proxy
(`crates/console/src/main.rs#DEFAULT_BIND`).

`/health`, `/ready`, and `/metrics` share the console's bind (no separate port)
and are mounted outside the session-auth middleware
(`crates/console/src/routes/mod.rs#router`). This is acceptable *because* the console is
loopback-only; if you rebind it off-loopback, those endpoints become reachable
too - front them with authentication at the proxy. Route ownership is in
[../reference/console-routes.md](../reference/console-routes.md).

## TLS posture - no in-process TLS

> **The console has no built-in TLS.** It is plain HTTP/1.1 served by
> `console::server::serve` on a plain `tokio::net::TcpListener`
> (`crates/console/src/server.rs`) - there is no rustls or other TLS
> setup in the console code. Do not assume the console terminates TLS itself.
> The sensor framework now carries a TLS capability for the attacker-facing
> listeners, but no sensor binds TLS yet; see
> [Sensor TLS](#sensor-tls-attacker-facing-listeners).
>
> The console does bound its own connections whether or not a proxy is in
> front: at most 64 open, 10 seconds for request headers (idle keep-alive
> connections included) and for the body, 2 MiB bodies. See
> [rate limits and budgets](../reference/rate-limits-and-budgets.md#console-connection-bounds).
> A proxy in front should still apply its own per-client limits, since behind
> it every connection arrives from the proxy's address.

Any TLS for the console is the **operator's responsibility, via a reverse
proxy** in front of the loopback listener (`[inferred]` - this is the design
intent implied by the loopback-by-default bind and the "put it behind your own
reverse proxy" comment, not a shipped feature). A typical arrangement:

- Keep `PROPOLIS_CONSOLE_BIND=127.0.0.1:8080` (do not expose the console
  directly).
- Terminate TLS at a reverse proxy on the same host and proxy to
  `127.0.0.1:8080`.
- Enforce authentication at the proxy for the unauthenticated
  `/health`/`/ready`/`/metrics` endpoints if the proxy is remotely reachable.

The application sets `X-Frame-Options: DENY`, `X-Content-Type-Options:
nosniff` and a Content-Security-Policy (unless a route set a stricter one) on console routes (`crates/console/src/routes/mod.rs#security_headers`) but sets no
HSTS - HSTS, if wanted, is another reason to terminate at a proxy.

Outbound connections (vendor APIs, VirusTotal, the fetcher) use HTTPS provided
by their own HTTP clients; that is unrelated to the console's inbound posture and
those paths default off. See
[../security/outbound-controls.md](../security/outbound-controls.md).

## Sensor TLS (attacker-facing listeners)

This is separate from the console and the gateway and shipper mTLS material: it is
server-side TLS on the honeypot's own attacker-facing ports, so the sensors can answer
HTTPS, MQTTS and the other encrypted variants of the protocols they imitate.

> **Status: shared capability only.** The shared capability, the certificate minting and the
> deploy wiring below are in place, but **no sensor binds a TLS listener yet** `[planned]`.
> Nothing in a current install listens with TLS, and no sensor reads a TLS variable. Per-sensor
> binds land next. Planned surfaces, all pending:
>
> - HTTPS on 443 (`sensor-http`)
> - MQTTS on 8883 (`sensor-mqtt`)
> - Redis TLS on 6380 (`sensor-redis`)
> - SMTPS on 465, plus SMTP STARTTLS (`sensor-smtp`)
> - FTPS on 990, plus FTP AUTH TLS (`sensor-ftp`)
> - in-band TLS for the `sensor-cred` PostgreSQL, MySQL, MSSQL and MongoDB protocols

What the framework provides (`crates/sensor-framework/src/tls.rs`): a fail-closed config
loader (`crates/sensor-framework/src/tls.rs#load_server_config`), an implicit-TLS listener
(`crates/sensor-framework/src/tls.rs#run_tls_listener`) that reuses the plain TCP listener's
connection bounds, and a stream type for in-protocol upgrades such as STARTTLS
(`crates/sensor-framework/src/tls.rs#MaybeTlsStream`).

### Certificate model

Each TLS-capable sensor gets its own self-signed certificate and key, minted at deploy time
by `provision-certs --sensor-tls` (`crates/provision-certs/src/lib.rs#provision_sensor_tls`,
driven by `deploy/provision-tls.sh#TLS_SENSORS`: http, mqtt, redis, smtp, ftp, cred). The
common name and only subject alternative name of every certificate is `localhost`
(`crates/provision-certs/src/lib.rs#SENSOR_TLS_COMMON_NAME`), fixed so that a deploy host's
name never appears in a certificate anyone can fetch by connecting to the port. The private
key is never shared between sensors. No client certificates are requested: the server config
is built with no client authentication (`crates/sensor-framework/src/tls.rs#build`).

### Where the files live

| Path | Mode | Owner |
|---|---|---|
| `/etc/propolis/tls` (directory) | `0711` | `root:root` |
| `/etc/propolis/tls/<sensor>.key` | `0600` | `propolis-<sensor>` |
| `/etc/propolis/tls/<sensor>.crt` | `0644` | `propolis-<sensor>` |

The directory is created by `deploy/provision.sh#ensure_dir /etc/propolis/tls`; the files are
minted and re-owned by `deploy/provision-tls.sh`. The exact path table is in
[../reference/filesystem-paths.md](../reference/filesystem-paths.md#tls-material-per-sensor).

The directory is `0711` rather than `0750` because it is **traverse-only**: a sensor's user
is neither the owner nor in the directory's group, so it needs the execute bit to open its own
key by exact name, while without the read bit nobody can list which sensors have TLS. A
`0750` directory would lock every sensor out of its own key.

### Replacing the self-signed pair with a real certificate

Put both files at the paths above (`<sensor>.crt` and `<sensor>.key`). `provision-tls.sh`
skips a sensor whose certificate **and** key already exist as non-empty regular files, so a real
pair survives every re-run of `install.sh`, `upgrade.sh` or `provision-tls.sh`
(`crates/provision-certs/src/lib.rs#provision_sensor_tls`). Two consequences:

- A path that is a **symlink** counts as present and is never replaced, and
  `provision-tls.sh` neither follows it to change ownership or mode nor changes the link
  itself (`deploy/provision-tls.sh#operator-managed`). The operator owns the permissions of
  whatever it points at, and the key must still satisfy the `0600` rule below.
- If only one file of a pair is present, the stray is removed and a fresh self-signed pair is
  minted, so a new pair is never mixed with an old half. To supply a real pair, install both
  files.

### Loading is fail-closed

The loader returns an error, and a sensor with a TLS bind configured refuses to start (no
fallback to plaintext or to a default certificate), when any of these hold. This is the
contract the per-sensor binds will follow
(`crates/sensor-framework/src/tls.rs#load_server_config`,
`crates/sensor-framework/src/tls.rs#TlsConfigError`):

- the certificate or key file is missing or unreadable;
- the path is not a regular file;
- the file is larger than 1 MiB (`MAX_PEM_FILE_BYTES`);
- the PEM is malformed, or holds no certificate or no private key;
- rustls rejects the pair, including a certificate and key that do not match;
- the **key file has any group or other permission bit set**. It is checked before the file is
  read, and the error names the mode and says to `chmod 0600`.

The certificate file is not mode-checked.

### Handshake bound

The handshake is cut at the sensor's read timeout (`ConnectionBounds::read_timeout`), so a
client that stalls after connecting cannot hold a connection slot for the full session
lifetime. The per-source cap, the global connection limit and the maximum session duration
apply to TLS connections unchanged (`crates/sensor-framework/src/tls.rs#run_tls_listener`).
A failed or timed-out handshake is logged at debug level only, because plaintext sent to a TLS
port is the common scanner case.

### Running provisioning by hand

`install.sh` and `upgrade.sh` run it for you (see [installation](installation.md) and
[upgrade, rollback and DR](upgrade-rollback-and-dr.md)). To run it manually, after
`deploy/provision.sh` has created the directory and with a release build present:

```
sudo deploy/provision-tls.sh
DRY_RUN=1 deploy/provision-tls.sh   # prints every action; needs no privilege or binary
```

It is idempotent. It reasserts ownership and mode on every run, so a pair minted by an
interrupted earlier run is repaired.

## Firewall and exposure guidance

Based on `docs/archive/2026-08-26/root/INSTALL.md#Firewall considerations` (operator guidance, not code; the
live `INSTALL.md` is now a redirect stub):

- **Inbound:** allow the configured sensor ports from the internet (that is the
  point). Allow nothing inbound to the console port from off-host - keep it
  loopback, or reachable only through your proxy.
- **Outbound:** the unified daemon needs outbound HTTPS to the vendor APIs *only
  if* review/VirusTotal are enabled, and outbound `5432` only if PostgreSQL is
  remote. The vendor and VirusTotal clients honor `HTTPS_PROXY` and the other
  standard proxy variables, so they can leave through an egress proxy. The
  malware fetcher, if enabled, ignores those variables and always connects
  directly, so a policy that allows egress only through a proxy blocks it. **Sensors make no outbound connections by design**
  (`docs/archive/2026-08-26/root/INSTALL.md#Firewall considerations`); their unit files restrict address families to
  `AF_INET AF_INET6` with no outbound path.
- **Recovery path:** before applying any firewall rule that could sever access,
  confirm you have out-of-band administration (hypervisor console / serial), not
  just the honeypot's fake SSH.

## Related

- [../reference/ports-and-protocols.md](../reference/ports-and-protocols.md) - exact ports/binds (canonical)
- [../security/attack-surfaces.md](../security/attack-surfaces.md) - exposure as
  a threat surface
- [configuration.md](configuration.md) - bind configuration
- [secret-management.md](secret-management.md) - console auth secrets
