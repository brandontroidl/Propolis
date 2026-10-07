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
> The sensor framework carries a TLS capability for the attacker-facing
> listeners, and `sensor-http` is the first sensor to use it; see
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

> **Status: five sensors live.** The shared capability, the certificate minting and the deploy
> wiring below are in place, and `sensor-http` serves HTTPS, `sensor-redis` serves Redis over TLS,
> `sensor-mqtt` serves MQTTS, `sensor-smtp` serves SMTPS and SMTP STARTTLS and `sensor-ftp` serves
> FTPS and FTP AUTH TLS (all below). The other surfaces are still pending `[planned]`: no other
> sensor reads a TLS variable or listens with TLS.
>
> **No implicit TLS bind.** A TLS listener exists only when its `*_TLS_BIND` variable (for
> `sensor-smtp` also `PROPOLIS_SMTP_SUBMISSION_BIND`) is explicitly set.
> `deploy/fleet-listeners.sh` derives the fleet inventory from the `*_BIND` variables, so a
> compiled-in default bind would open a port the inventory never lists. A certificate and key
> with no TLS bind are still loaded and validated (fail-closed), start no TLS listener, and log
> one warning. The exception is `sensor-smtp` and `sensor-ftp`, where the pair also enables an
> in-protocol upgrade (STARTTLS, AUTH TLS) on the plain listener, so it is in use and logs no
> warning. `sensor-cred` has no TLS bind at all: its TLS runs on the existing plain binds, so the
> pair opens no port and the inventory is unchanged.
>
> Pending surfaces: none.

What the framework provides (`crates/sensor-framework/src/tls.rs`): a fail-closed config
loader (`crates/sensor-framework/src/tls.rs#load_server_config`), an implicit-TLS listener
(`crates/sensor-framework/src/tls.rs#run_tls_listener`) that reuses the plain TCP listener's
connection bounds, and a stream type for in-protocol upgrades such as STARTTLS
(`crates/sensor-framework/src/tls.rs#MaybeTlsStream`).

### Live: HTTPS on `sensor-http`

| Item | Value |
|---|---|
| Mode | implicit TLS (the handshake is the first thing on the connection), no client certificate |
| Bind | `PROPOLIS_HTTP_TLS_BIND`, no compiled default; the deploy convention is `0.0.0.0:443` |
| Certificate and key | `PROPOLIS_HTTP_TLS_CERT` (`/etc/propolis/tls/http.crt`), `PROPOLIS_HTTP_TLS_KEY` (`/etc/propolis/tls/http.key`, mode `0600`) |
| Plain listener | unchanged, `PROPOLIS_HTTP_BIND`; both listeners run in one process and write one `events.jsonl` |
| Unit | `deploy/sensor-http.service` adds `ReadOnlyPaths=/etc/propolis/tls`; `CAP_NET_BIND_SERVICE` stays for ports 80 and 443 |
| Event tagging | events from a TLS session carry `"tls": true`; plain events have no such key |

The sensor exits 1 with `refusing to start`, before binding anything, when exactly one of cert
and key is set (a blank value counts as unset), when the TLS bind is set without both paths or
does not parse, or when the pair is unusable (see [Loading is fail-closed](#loading-is-fail-closed)).
If the OS refuses the TLS bind itself, the plain listener is stopped and the sensor exits 1.
Variables are owned by [environment-variables.md](../reference/environment-variables.md);
behavior by [sensor-behavior.md](../reference/sensor-behavior.md).

### Live: Redis TLS on `sensor-redis`

| Item | Value |
|---|---|
| Mode | implicit TLS (`rediss://`; the handshake is the first thing on the connection), no client certificate, no STARTTLS |
| Bind | `PROPOLIS_REDIS_TLS_BIND`, no compiled default; the deploy convention is `0.0.0.0:6380` |
| Certificate and key | `PROPOLIS_REDIS_TLS_CERT` (`/etc/propolis/tls/redis.crt`), `PROPOLIS_REDIS_TLS_KEY` (`/etc/propolis/tls/redis.key`, mode `0600`) |
| Plain listener | unchanged, `PROPOLIS_REDIS_BIND`; both listeners run in one process and write one `events.jsonl` |
| Unit | `deploy/sensor-redis.service` adds `ReadOnlyPaths=/etc/propolis/tls`; no capability, since 6379 and 6380 are unprivileged |
| Event tagging | events from a TLS session carry `"tls": true`; plain events have no such key |

The sensor exits 1 with `refusing to start`, before binding anything, when exactly one of cert
and key is set (a blank value counts as unset), when the TLS bind is set without both paths or
does not parse, or when the pair is unusable (see [Loading is fail-closed](#loading-is-fail-closed)).
If the OS refuses the TLS bind itself, the plain listener is stopped and the sensor exits 1.
Variables are owned by [environment-variables.md](../reference/environment-variables.md);
behavior by [sensor-behavior.md](../reference/sensor-behavior.md).

### Live: MQTTS on `sensor-mqtt`

| Item | Value |
|---|---|
| Mode | implicit TLS (the handshake is the first thing on the connection), no client certificate, no STARTTLS; MQTT 3.1, 3.1.1 and 5.0 all work over it |
| Bind | `PROPOLIS_MQTT_TLS_BIND`, no compiled default; the deploy convention is `0.0.0.0:8883` |
| Certificate and key | `PROPOLIS_MQTT_TLS_CERT` (`/etc/propolis/tls/mqtt.crt`), `PROPOLIS_MQTT_TLS_KEY` (`/etc/propolis/tls/mqtt.key`, mode `0600`) |
| Plain listener | unchanged, `PROPOLIS_MQTT_BIND`; both listeners run in one process and write one `events.jsonl` |
| Capture | the plain and TLS listeners share one capture hand-off, one capture-memory budget and one shutdown drain, so binary-PUBLISH spooling works identically over TLS |
| Unit | `deploy/sensor-mqtt.service` adds `ReadOnlyPaths=/etc/propolis/tls`; no capability, since 1883 and 8883 are unprivileged |
| Event tagging | events from a TLS session carry `"tls": true`; plain events have no such key |

The sensor exits 1 with `refusing to start`, before binding anything, when exactly one of cert
and key is set (a blank value counts as unset), when the TLS bind is set without both paths or
does not parse, or when the pair is unusable (see [Loading is fail-closed](#loading-is-fail-closed)).
If the OS refuses the TLS bind itself, the plain listener is stopped and the sensor exits 1.
Variables are owned by [environment-variables.md](../reference/environment-variables.md);
behavior by [sensor-behavior.md](../reference/sensor-behavior.md).

### Live: SMTPS and STARTTLS on `sensor-smtp`

| Item | Value |
|---|---|
| Modes | implicit TLS on the SMTPS port (the handshake comes before the banner), and STARTTLS on the plain listeners; no client certificate |
| Plain bind | `PROPOLIS_SMTP_BIND` (25), required as before; offers STARTTLS and upgrades iff the cert and key are set |
| Submission bind | `PROPOLIS_SMTP_SUBMISSION_BIND` (587), optional, no compiled default; the same plain session as 25, with STARTTLS iff the pair is set |
| SMTPS bind | `PROPOLIS_SMTP_TLS_BIND` (465), optional, no compiled default; implicit TLS, requires the pair |
| Certificate and key | `PROPOLIS_SMTP_TLS_CERT` (`/etc/propolis/tls/smtp.crt`), `PROPOLIS_SMTP_TLS_KEY` (`/etc/propolis/tls/smtp.key`, mode `0600`) |
| Listeners | up to three in one process, writing one `events.jsonl`; 465 and 587 exist only when their bind is set |
| Unit | `deploy/sensor-smtp.service` adds `ReadOnlyPaths=/etc/propolis/tls`; `CAP_NET_BIND_SERVICE` stays for ports 25, 465 and 587 |
| Event tagging | connection, login and data events from a TLS session (implicit, or after STARTTLS) carry `"tls": true`; plain events have no such key |

STARTTLS rules (`crates/sensor-smtp/src/handler.rs#handle_connection`; replies in
[sensor-behavior.md](../reference/sensor-behavior.md#sensor-smtp)):

- With the pair set, STARTTLS answers `220 2.0.0 Ready to start TLS` and upgrades in place. A
  failed or stalled handshake ends the session; there is no plaintext fallback after the `220`.
- Plaintext the client pipelined behind STARTTLS is never read as a command inside the TLS
  session (the CVE-2011-0411 class). The sensor records one `honeypot_command_exec` event with
  `starttls_refused` set to `pipelined_plaintext` and the byte count (the bytes themselves are
  never captured), replies `554`, and closes the connection without sending the `220`.
- After the upgrade the client must send EHLO again: MAIL, RCPT and BDAT state is discarded. The
  per-connection capture cap (`total_read`) is kept across the upgrade.
- A second STARTTLS inside TLS gets `503`, and EHLO inside TLS omits the STARTTLS extension.
  STARTTLS with parameters gets `501` (only when TLS is configured).
- With no pair set nothing changes: EHLO still advertises STARTTLS and every STARTTLS line gets
  the unchanged `454` reply.
- A cert and key with no `PROPOLIS_SMTP_TLS_BIND` and no submission bind still enable STARTTLS on
  port 25 and open nothing else (pinned by the spawned-binary test
  `crates/sensor-smtp/tests/tls.rs#a_valid_pair_without_a_tls_bind_enables_starttls_on_the_plain_listener_only`).

Fail-closed: the sensor exits 1 with `refusing to start`, before binding anything, when exactly
one of cert and key is set (a blank value counts as unset), when the SMTPS bind is set without
both paths, when either extra bind does not parse, or when the pair is unusable (see
[Loading is fail-closed](#loading-is-fail-closed)). If the OS refuses any one bind, the
listeners already started are stopped and the sensor exits 1. An implicit handshake that fails
is dropped with a debug log and no event. Variables are owned by
[environment-variables.md](../reference/environment-variables.md); behavior by
[sensor-behavior.md](../reference/sensor-behavior.md).

### Live: FTPS and AUTH TLS on `sensor-ftp`

| Item | Value |
|---|---|
| Modes | implicit TLS on the FTPS port (the handshake comes before the banner), and AUTH TLS on the plain listener; no client certificate |
| Plain bind | `PROPOLIS_FTP_BIND` (21), required as before; answers AUTH TLS, PBSZ and PROT iff the cert and key are set |
| FTPS bind | `PROPOLIS_FTP_TLS_BIND` (990), optional, no compiled default; implicit TLS, requires the pair |
| Certificate and key | `PROPOLIS_FTP_TLS_CERT` (`/etc/propolis/tls/ftp.crt`), `PROPOLIS_FTP_TLS_KEY` (`/etc/propolis/tls/ftp.key`, mode `0600`) |
| Listeners | up to two in one process, writing one `events.jsonl`; 990 exists only when its bind is set |
| Passive data ports | unchanged (ephemeral, negotiated per session); with `PROT P` they carry TLS |
| Unit | `deploy/sensor-ftp.service` adds `ReadOnlyPaths=/etc/propolis/tls`; `CAP_NET_BIND_SERVICE` stays for ports 21 and 990 |
| Event tagging | connection, login and upload events from a session whose control channel is TLS (implicit, or after AUTH TLS) carry `"tls": true`; plain events have no such key |

AUTH TLS rules (`crates/sensor-ftp/src/handler.rs#handle_connection`; replies in
[sensor-behavior.md](../reference/sensor-behavior.md#sensor-ftp)):

- With the pair set, `AUTH TLS`, `AUTH TLS-C`, `AUTH SSL` and `AUTH TLS-P` answer
  `234 Proceed with negotiation.` and upgrade in place. Any other AUTH type gets `504`, and AUTH
  inside TLS gets `503`. A failed or stalled handshake ends the session; there is no plaintext
  fallback after the `234`.
- Plaintext the client pipelined behind AUTH TLS is never read as a command inside the TLS
  session (the CVE-2011-0411 class). The sensor records one `honeypot_command_exec` event with
  `starttls_refused` set to `pipelined_plaintext` and the byte count (the bytes themselves are
  never captured), replies `504 Pipelined commands after AUTH TLS refused.`, and closes the
  connection without sending the `234`.
- After the upgrade the session is reset as REIN would: the username, login state, PBSZ, PROT and
  any open passive listener are discarded. The per-connection capture cap is kept across the
  upgrade.
- PBSZ (inside TLS only, always `0`) and then PROT (`C` or `P`; `S` and `E` get `536`) set the
  data-channel protection. After `PROT P` the passive data socket is wrapped in TLS once the data
  peer passed the source-IP check; the handshake is bounded by the read timeout and a failed one
  gets `425`. STOR over `PROT P` is captured and spooled exactly like plaintext, and a data close
  without `close_notify` counts as end of file. The `"tls"` tag refers to the control channel
  only.
- FEAT lists `AUTH`, `PBSZ` and `PROT` only when TLS is configured. With no pair set nothing
  changes: AUTH, PBSZ and PROT answer `500` like any unknown command.
- A cert and key with no `PROPOLIS_FTP_TLS_BIND` still enable AUTH TLS on port 21 and open nothing
  else (pinned by the spawned-binary test
  `crates/sensor-ftp/tests/tls_config.rs#a_valid_pair_without_a_tls_bind_enables_auth_tls_on_the_plain_listener_only`).

Fail-closed: the sensor exits 1 with `refusing to start`, before binding anything, when exactly
one of cert and key is set (a blank value counts as unset), when the FTPS bind is set without
both paths, when the FTPS bind does not parse, or when the pair is unusable (see
[Loading is fail-closed](#loading-is-fail-closed)). If the OS refuses any one bind, the
listeners already started are stopped and the sensor exits 1. An implicit handshake that fails
is dropped with a debug log and no event. Variables are owned by
[environment-variables.md](../reference/environment-variables.md); behavior by
[sensor-behavior.md](../reference/sensor-behavior.md).

### Live: in-band TLS on `sensor-cred`

| Item | Value |
|---|---|
| Modes | in-band on the existing plaintext ports: PostgreSQL SSLRequest (5432), MySQL `CLIENT_SSL` (3306), MSSQL TLS inside TDS PRELOGIN (1433), and a MongoDB ClientHello sniff (27017); VNC (5900) unchanged; no client certificate |
| Binds | unchanged (`PROPOLIS_CRED_PG_BIND`, `PROPOLIS_CRED_MYSQL_BIND`, `PROPOLIS_CRED_MSSQL_BIND`, `PROPOLIS_CRED_MONGO_BIND`); there is no TLS bind and no new port, so `deploy/fleet-listeners.sh` derives nothing new |
| Certificate and key | `PROPOLIS_CRED_TLS_CERT` (`/etc/propolis/tls/cred.crt`), `PROPOLIS_CRED_TLS_KEY` (`/etc/propolis/tls/cred.key`, mode `0600`); one pair for all four protocols |
| Plaintext clients | keep working on every port with the pair set |
| Unit | `deploy/sensor-cred.service` adds `ReadOnlyPaths=/etc/propolis/tls`; no capability, since every cred port is unprivileged |
| Event tagging | events from a TLS session carry `"tls": true`; for PostgreSQL, MySQL and MSSQL the connection event is written before negotiation and stays untagged, for MongoDB every event of a TLS session is tagged |

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
  captured.
- **MongoDB:** the first two bytes on the port are peeked, bounded by the read timeout; `0x16 0x03`
  (a TLS record header) with the pair set selects TLS, anything else the plaintext path. After a
  sniff that times out the plaintext path waits up to another read timeout, so a silent
  connection can hold a slot for up to twice the read timeout, capped by the maximum session
  duration.

Fail-closed (`crates/sensor-cred/src/main.rs#main`): when either variable is present, the pair
must load or the sensor exits 1 with `refusing to start` before binding any protocol: exactly one
set, a blank or non-UTF-8 value, or an unusable pair (see
[Loading is fail-closed](#loading-is-fail-closed)). On success it logs
`TLS enabled for postgresql, mysql, mssql and mongodb`. Unlike the other TLS sensors, an OS bind
failure does not stop the sensor: that one protocol is logged and skipped and the sensor exits 1
only when every configured protocol failed to bind, because TLS adds no listener whose loss could
hide behind the others. Variables are owned by
[environment-variables.md](../reference/environment-variables.md); behavior by
[sensor-behavior.md](../reference/sensor-behavior.md).

**Validation scope and owner smoke tests.** The MSSQL TDS-TLS adapter is validated against a
rustls client (TLS 1.2 and 1.3) framed by hand in
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
contract every per-sensor TLS bind follows
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

### STARTTLS upgrades

Protocols that switch to TLS in-band (SMTP `STARTTLS`, FTP `AUTH TLS`) go through one shared
path, `crates/sensor-framework/src/tls.rs#upgrade_buffered`. The upgrade handshake is bounded by
the same read timeout. If the client has already sent more plaintext after the STARTTLS command
(command pipelining across the upgrade, the CVE-2011-0411 injection shape), the upgrade is
refused and the connection dropped rather than letting those pre-handshake bytes be read inside
the encrypted session. `sensor-cred`'s PostgreSQL and MySQL upgrades read without a user-space
buffer, so they call `crates/sensor-framework/src/tls.rs#MaybeTlsStream` `upgrade` directly:
plaintext sent after the request stays in the socket and fails the handshake. Its MSSQL handshake
runs inside TDS packets instead (`crates/sensor-cred/src/tds_tls.rs`).

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
