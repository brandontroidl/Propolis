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

## Console TLS posture - no in-process TLS

> **The console has no built-in TLS.** It is plain HTTP/1.1 served by
> `console::server::serve` on a plain `tokio::net::TcpListener`
> (`crates/console/src/server.rs`) - there is no rustls or other TLS
> setup in the console code. Do not assume the console terminates TLS itself.
> The attacker-facing sensors are different: six of them terminate TLS in-process, see
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

### Overview

Six sensors speak TLS: `sensor-http`, `sensor-redis`, `sensor-mqtt`, `sensor-smtp`,
`sensor-ftp` and `sensor-cred`. The others (ssh, telnet, adb, tftp, catchall) read no TLS
variable. Every TLS surface is off until the operator sets its variables, and none has a
compiled-in default. The shared pieces live in the sensor framework
(`crates/sensor-framework/src/tls.rs`): a fail-closed loader
(`crates/sensor-framework/src/tls.rs#load_server_config`), an implicit-TLS listener that reuses
the plain TCP listener's connection bounds
(`crates/sensor-framework/src/tls.rs#run_tls_listener`), the in-protocol upgrade path
(`crates/sensor-framework/src/tls.rs#upgrade_buffered`, over
`crates/sensor-framework/src/tls.rs#MaybeTlsStream`), and the fail-closed reader for the TLS
variables (`crates/sensor-framework/src/tls.rs#tls_env_var`).

Three modes exist. **Implicit** TLS puts the handshake first on a dedicated port. **STARTTLS**
(SMTP `STARTTLS`, FTP `AUTH TLS`) upgrades a plaintext session in place after a command. **In-band**
TLS is negotiated inside the protocol's own startup on the existing port (sensor-cred), and for
MongoDB the sensor **sniffs** the first bytes to tell a TLS client from a plaintext one.

### TLS surfaces

Ports are the deploy conventions from `deploy/sensor.env.example`; the code has no default.

| Sensor | Port | Mode | Bind variable | Certificate and key variables |
|---|---|---|---|---|
| `sensor-http` | 443 | implicit (HTTPS) | `PROPOLIS_HTTP_TLS_BIND` | `PROPOLIS_HTTP_TLS_CERT`, `PROPOLIS_HTTP_TLS_KEY` |
| `sensor-redis` | 6380 | implicit (`rediss://`) | `PROPOLIS_REDIS_TLS_BIND` | `PROPOLIS_REDIS_TLS_CERT`, `PROPOLIS_REDIS_TLS_KEY` |
| `sensor-mqtt` | 8883 | implicit (MQTTS; MQTT 3.1, 3.1.1 and 5.0) | `PROPOLIS_MQTT_TLS_BIND` | `PROPOLIS_MQTT_TLS_CERT`, `PROPOLIS_MQTT_TLS_KEY` |
| `sensor-smtp` | 465 | implicit (SMTPS) | `PROPOLIS_SMTP_TLS_BIND` | `PROPOLIS_SMTP_TLS_CERT`, `PROPOLIS_SMTP_TLS_KEY` |
| `sensor-smtp` | 25, 587 | STARTTLS | `PROPOLIS_SMTP_BIND`, `PROPOLIS_SMTP_SUBMISSION_BIND` (plain listeners) | the smtp pair |
| `sensor-ftp` | 990 | implicit (FTPS) | `PROPOLIS_FTP_TLS_BIND` | `PROPOLIS_FTP_TLS_CERT`, `PROPOLIS_FTP_TLS_KEY` |
| `sensor-ftp` | 21 | STARTTLS (`AUTH TLS`; `PROT P` data channels) | `PROPOLIS_FTP_BIND` (plain listener) | the ftp pair |
| `sensor-cred` | 5432 | in-band (PostgreSQL SSLRequest) | `PROPOLIS_CRED_PG_BIND` (plain listener) | `PROPOLIS_CRED_TLS_CERT`, `PROPOLIS_CRED_TLS_KEY` |
| `sensor-cred` | 3306 | in-band (MySQL `CLIENT_SSL`) | `PROPOLIS_CRED_MYSQL_BIND` (plain listener) | the cred pair |
| `sensor-cred` | 1433 | in-band (MSSQL TLS inside TDS PRELOGIN) | `PROPOLIS_CRED_MSSQL_BIND` (plain listener) | the cred pair |
| `sensor-cred` | 27017 | sniff (MongoDB, first two bytes) | `PROPOLIS_CRED_MONGO_BIND` (plain listener) | the cred pair |

Common to every row:

- **Certificate and key paths.** The deploy values are `/etc/propolis/tls/<sensor>.crt` and
  `/etc/propolis/tls/<sensor>.key` (key mode `0600`), minted by `deploy/provision-tls.sh` (see
  [Certificate model](#certificate-model)). sensor-cred uses one pair for all four protocols;
  VNC (5900) has no TLS.
- **No client certificate** is requested on any surface.
- **One process, one log.** A sensor's TLS listener runs in the same process as its plain one and
  writes the same `events.jsonl`. For sensor-mqtt the two listeners also share one capture
  hand-off, one capture-memory budget and one shutdown drain, so binary-PUBLISH spooling works
  identically over TLS.
- **Event tagging.** Events from a TLS session carry `"tls": true`; plaintext events have no such
  key. For sensor-smtp and sensor-ftp that covers sessions upgraded by STARTTLS or AUTH TLS too,
  and the ftp tag refers to the control channel only. For sensor-cred's PostgreSQL, MySQL and
  MSSQL the connection event is written before negotiation and stays untagged; for MongoDB every
  event of a TLS session is tagged.
- **Plaintext clients** keep working on every plain listener with the pair set.
- **Capabilities.** http (80, 443), ftp (21, 990) and smtp (25, 465, 587) keep
  `CAP_NET_BIND_SERVICE`; redis, mqtt and cred grant none, since all their ports are unprivileged.

Variables are owned by [environment-variables.md](../reference/environment-variables.md); replies
and per-protocol behavior by [sensor-behavior.md](../reference/sensor-behavior.md).

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

Restart the sensor after replacing its pair: the pair is loaded once, at start.

### Running `provision-tls.sh`

`install.sh` and `upgrade.sh` run it for you (see [installation](installation.md) and
[upgrade, rollback and DR](upgrade-rollback-and-dr.md)). To run it manually, after
`deploy/provision.sh` has created the directory and with a release build present:

```
sudo deploy/provision-tls.sh
DRY_RUN=1 deploy/provision-tls.sh   # prints every action; needs no privilege or binary
```

It is idempotent. It reasserts ownership and mode on every run, so a pair minted by an
interrupted earlier run is repaired. Minting a pair turns nothing on: a sensor uses it only once
its env file names it.

### Fail-closed rules

A sensor never falls back to plaintext or to a default certificate where TLS was configured.
Every refusal below happens before the sensor binds any listener, the plain one included: the
process logs an error and exits 1. The error ends in `refusing to start`.

**How the variables are read.** All six sensors read every TLS variable (each `*_TLS_BIND`,
`*_TLS_CERT` and `*_TLS_KEY`, and `PROPOLIS_SMTP_SUBMISSION_BIND`) through one reader,
`crates/sensor-framework/src/tls.rs#tls_env_var`, so one rule holds everywhere:

- unset is unset;
- the value is trimmed of leading and trailing ASCII whitespace;
- a value blank after the trim counts as unset, as `deploy/fleet-listeners.sh` skips a blank
  bind, so `PROPOLIS_HTTP_TLS_BIND=` means no TLS listener, never an invalid address;
- a value that is not valid UTF-8 is invalid, never read as unset (see below).

**Configuration.** Per sensor (`crates/sensor-http/src/main.rs#parse_tls`,
`crates/sensor-redis/src/main.rs#parse_tls`, `crates/sensor-mqtt/src/main.rs#parse_tls`,
`crates/sensor-smtp/src/lib.rs#tls_from_env`, `crates/sensor-ftp/src/main.rs#tls_paths`,
`crates/sensor-cred/src/main.rs#main`), after that reading step:

- exactly one of the cert and key variables is set;
- a TLS bind is set without both paths;
- a TLS bind, or smtp's submission bind, does not parse (a bad bind never falls back to a default);
- any TLS variable holds a value that is not valid UTF-8. It is invalid, never read as unset,
  which would silently turn TLS off or skip a listener
  (`crates/sensor-framework/src/tls.rs#tls_env_var`).

**The pair itself.** The loader returns an error when any of these hold
(`crates/sensor-framework/src/tls.rs#load_server_config`,
`crates/sensor-framework/src/tls.rs#TlsConfigError`):

- the certificate or key file is missing or unreadable;
- the path is not a regular file;
- the file is larger than 1 MiB (`MAX_PEM_FILE_BYTES`);
- the PEM is malformed, or holds no certificate or no private key. The error names the file and
  a fixed description of the fault (for example `missing section end marker`), never the
  parser's own message, which can quote the file's bytes: a key written on one line would
  otherwise land in the log (`crates/sensor-framework/src/tls.rs#pem_error_kind`);
- rustls rejects the pair, including a certificate and key that do not match;
- the **key file has any group or other permission bit set**. It is checked before the file is
  read, and the error names the mode and says to `chmod 0600`.

The certificate file is not mode-checked.

**No implicit TLS bind.** A TLS listener exists only when its `*_TLS_BIND` variable (for
sensor-smtp also `PROPOLIS_SMTP_SUBMISSION_BIND`) is explicitly set.
`deploy/fleet-listeners.sh` derives the fleet inventory from the `*_BIND` variables, so a
compiled-in default bind would open a port the inventory never lists. A certificate and key
with no TLS bind are still loaded and validated (fail-closed), start no TLS listener, and log
one warning. The exceptions:

- sensor-smtp and sensor-ftp: the pair also enables STARTTLS or AUTH TLS on the plain listener,
  so it is in use and logs no warning;
- sensor-cred has no TLS bind at all: its TLS runs on the existing plain binds, so the pair
  opens no port and the inventory is unchanged.

**A bind the OS refuses.** For http, redis, mqtt, smtp and ftp, if the OS refuses any one bind,
the listeners already started are stopped and the sensor exits 1, logging
`<sensor>: cannot start listener on <address>: <OS error>; refusing to start`
(`crates/sensor-framework/src/listener.rs#listener_start_error`). sensor-cred instead logs the
same text ending `; skipping protocol <name>` and exits 1 only when every configured protocol
failed to bind, because its TLS adds no listener whose loss could hide behind the others.

On success sensor-cred logs `TLS enabled for <protocols>`, naming only the TLS-capable
protocols (postgresql, mysql, mssql, mongodb) that have a bind configured; when none has (vnc
only, for example) it logs the warning `TLS is configured but no TLS-capable protocol is bound`
instead (`crates/sensor-cred/src/main.rs#TLS_CAPABLE`). Sensors log
at `info` unless `RUST_LOG` says otherwise, so the warnings and info lines are visible by default
(see [troubleshooting](../troubleshooting/sensors-and-networking.md#sensor-tls)).

### The unit's TLS directory grant

Each of the six units carries `ReadOnlyPaths=-/etc/propolis/tls` (for example
`deploy/sensor-http.service#ReadOnlyPaths=-/etc/propolis/tls`). Read-only because the sensor reads
its pair and never writes it. The leading `-` makes a missing directory non-fatal: without it
systemd refuses to start the unit (`226/NAMESPACE`) on a host where `/etc/propolis/tls` was
never provisioned, even for a sensor that uses no TLS. Dropping the hard requirement costs no
safety, because a configured pair that cannot be read still refuses to start in-process. A test
holds the set of units carrying this line equal to the sensors `provision-tls.sh` mints for
(`crates/sensor-framework/tests/deploy_test.rs#tls_dir_grant_units_match_provision_tls_sensors_exactly`).

### Handshake bound

The handshake is cut at the sensor's read timeout (`ConnectionBounds::read_timeout`), so a
client that stalls after connecting cannot hold a connection slot for the full session
lifetime. The per-source cap, the global connection limit and the maximum session duration
apply to TLS connections unchanged (`crates/sensor-framework/src/tls.rs#run_tls_listener`).
A failed or timed-out handshake is dropped with no event and logged at debug level only,
because plaintext sent to a TLS port is the common scanner case.

### STARTTLS upgrades and pipelining refusal

Protocols that switch to TLS in-band (SMTP `STARTTLS`, FTP `AUTH TLS`) go through one shared
path, `crates/sensor-framework/src/tls.rs#upgrade_buffered`. The upgrade handshake is bounded by
the same read timeout, and a failed or stalled handshake ends the session: there is no plaintext
fallback after the go-ahead reply. If the client has already sent more plaintext after the
upgrade command (command pipelining across the upgrade, the CVE-2011-0411 injection shape), the
upgrade is refused and the connection dropped rather than letting those pre-handshake bytes be
read inside the encrypted session. The sensor records one `honeypot_command_exec` event with
`starttls_refused` set to `pipelined_plaintext` and the byte count (the bytes themselves are
never captured). The per-connection capture cap is kept across an upgrade.

`sensor-cred`'s PostgreSQL and MySQL upgrades read without a user-space buffer, so they call
`crates/sensor-framework/src/tls.rs#MaybeTlsStream` `upgrade` directly: plaintext sent after the
request stays in the socket and fails the handshake. Its MSSQL handshake runs inside TDS packets
instead (`crates/sensor-cred/src/tds_tls.rs`).

#### `sensor-smtp` STARTTLS

Rules (`crates/sensor-smtp/src/handler.rs#handle_connection`; replies in
[sensor-behavior.md](../reference/sensor-behavior.md#sensor-smtp)):

- With the pair set, STARTTLS answers `220 2.0.0 Ready to start TLS` and upgrades in place. A
  pipelined STARTTLS gets `554` and the connection is closed without the `220`.
- After the upgrade the client must send EHLO again: MAIL, RCPT and BDAT state is discarded.
- A second STARTTLS inside TLS gets `503`, and EHLO inside TLS omits the STARTTLS extension.
  STARTTLS with parameters gets `501` (only when TLS is configured).
- With no pair set nothing changes: EHLO still advertises STARTTLS and every STARTTLS line gets
  the unchanged `454` reply.
- A cert and key with no `PROPOLIS_SMTP_TLS_BIND` and no submission bind still enable STARTTLS on
  port 25 and open nothing else (pinned by the spawned-binary test
  `crates/sensor-smtp/tests/tls.rs#a_valid_pair_without_a_tls_bind_enables_starttls_on_the_plain_listener_only`).

#### `sensor-ftp` AUTH TLS

Rules (`crates/sensor-ftp/src/handler.rs#handle_connection`; replies in
[sensor-behavior.md](../reference/sensor-behavior.md#sensor-ftp)):

- With the pair set, `AUTH TLS`, `AUTH TLS-C`, `AUTH SSL` and `AUTH TLS-P` answer
  `234 Proceed with negotiation.` and upgrade in place. Any other AUTH type gets `504`, and AUTH
  inside TLS gets `503`. A pipelined AUTH TLS gets
  `504 Pipelined commands after AUTH TLS refused.` and the connection is closed without the `234`.
- After the upgrade the session is reset as REIN would: the username, login state, PBSZ, PROT and
  any open passive listener are discarded.
- PBSZ (inside TLS only, always `0`) and then PROT (`C` or `P`; `S` and `E` get `536`) set the
  data-channel protection. After `PROT P` the passive data socket is wrapped in TLS once the data
  peer passed the source-IP check; the handshake is bounded by the read timeout and a failed one
  gets `425`. STOR over `PROT P` is captured and spooled exactly like plaintext, and a data close
  without `close_notify` counts as end of file.
- FEAT lists `AUTH`, `PBSZ` and `PROT` only when TLS is configured. With no pair set nothing
  changes: AUTH, PBSZ and PROT answer `500` like any unknown command.
- A cert and key with no `PROPOLIS_FTP_TLS_BIND` still enable AUTH TLS on port 21 and open nothing
  else (pinned by the spawned-binary test
  `crates/sensor-ftp/tests/tls_config.rs#a_valid_pair_without_a_tls_bind_enables_auth_tls_on_the_plain_listener_only`).

### `sensor-cred` in-band TLS

Per-protocol rules (replies and tables in
[sensor-behavior.md](../reference/sensor-behavior.md#sensor-cred-vnc--mysql--mssql--postgresql--mongodb)):

- **PostgreSQL:** an SSLRequest is answered `S` and the session continues over TLS; without the
  pair it is answered `N` as before. Plaintext sent where the ClientHello belongs is never read
  as a startup message: the handshake fails and the connection is dropped. A second SSLRequest
  inside TLS closes the connection.
- **MySQL:** the greeting advertises `CLIENT_SSL` only with the pair; a client's SSLRequest
  switches to TLS before the HandshakeResponse, which is then answered OK at sequence id 3.
- **MSSQL:** a client that asks for encryption (`ENCRYPT_ON` or `ENCRYPT_REQ`) is answered
  `ENCRYPT_ON` and gets TLS inside TDS; TLS 1.3 session tickets are off for MSSQL only. A client
  that offers `ENCRYPT_OFF` gets the pre-TLS PRELOGIN response byte for byte and a plaintext
  session, and an `ENCRYPT_NOT_SUP` or silent client gets `ENCRYPT_NOT_SUP` and plaintext. A real
  server with encryption on would answer `ENCRYPT_OFF` with `ENCRYPT_REQ` and force TLS; the
  sensor deliberately does not, so the credentials of scanners that cannot do TLS are still
  captured. For the same reason a client that asked for encryption but then sends a plaintext
  Login7 (first byte 0x10) instead of a handshake is served in plaintext and its username
  captured, untagged. Only the low two bits of the client's ENCRYPTION value are read
  (`v & 0x03`); all other bits, the client-certificate bit included, are ignored.
- **MongoDB (two-byte sniff):** the first two bytes on the port are peeked, bounded by the read
  timeout; `0x16 0x03` (a TLS record header) with the pair set selects TLS, anything else the
  plaintext path. The connection event is written once the sniff decides, before the handshake,
  tagged `"tls": true` when TLS was chosen, so a failed or abandoned handshake is still recorded.
  After a sniff that times out the plaintext path waits up to another read
  timeout, so a silent connection can hold a slot for up to twice the read timeout, capped by the
  maximum session duration.

**MSSQL validation status and owner smoke tests.** The MSSQL TDS-TLS adapter is validated
against a rustls client (TLS 1.2 and 1.3) framed by hand in
`crates/sensor-cred/tests/tls_integration.rs` and against the MS-TDS text, not against real SQL
Server drivers. Before relying on it, run against a TLS-enabled node:

- `sqlcmd -N -C`, and .NET SqlClient with `Encrypt=True;TrustServerCertificate=True`;
- FreeTDS `tsql` with `encryption = require` and with `encryption = off`;
- go-mssqldb with `encrypt=true` and with `encrypt=disable`;
- impacket `mssqlclient.py`;
- any driver that attempts TLS 1.3 inside TDS 7.x. If one fails, the fallback is restricting
  MSSQL to TLS 1.2, which is an owner decision;
- plaintext PostgreSQL, MySQL and MongoDB clients, to confirm they are still served.

Known follow-up: PostgreSQL does not yet answer a GSSENCRequest with `N`, as a real server
without GSSAPI encryption does.

## Firewall and exposure guidance

Based on `docs/archive/2026-08-26/root/INSTALL.md#Firewall considerations` (operator guidance, not code; the
live `INSTALL.md` is now a redirect stub):

- **Inbound:** allow the configured sensor ports from the internet (that is the
  point), including any TLS ports you set a bind for (see [TLS surfaces](#tls-surfaces)).
  Allow nothing inbound to the console port from off-host - keep it
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
- [../troubleshooting/sensors-and-networking.md](../troubleshooting/sensors-and-networking.md#sensor-tls) - sensor TLS failure modes
- [configuration.md](configuration.md) - bind configuration
- [secret-management.md](secret-management.md) - console auth secrets
