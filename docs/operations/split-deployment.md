<!--
title: Split deployment
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-08
-->

# Split deployment

A split deployment runs the attacker-facing sensors on a disposable **collector** host and
everything else on a **control plane** host. The collector holds no database credential, no vendor
key and no console password, so if it is fingerprinted or taken over it is rebuilt rather than
cleaned. This page is the procedure for standing one up, checking that it works, and operating it,
including the parts the shipped tooling does not do for you.

For the single-host deployment see [deployment models](deployment-models.md). Everything there
still applies to the control plane except where this page says otherwise.

## How it fits together

```text
collector host                                  control plane host
--------------                                  ------------------
sensor-*  ->  /var/log/propolis/<sensor>/...
                    |
                 shipper  ---- TCP, mutual TLS ---->  gateway
                                                         |
                               /var/spool/propolis/gateway/<collector-id>/events.jsonl
                                                         |
                               propolis (intake, review, feed, console)  ->  PostgreSQL
```

- The **shipper** tails the sensor logs it is given, batches up to 15 lines, and sends each batch
  with a sequence number and the hash of the batch before it
  (`crates/shipper/src/batcher.rs#Batcher::next_batch`, `crates/shipper/src/batcher.rs#MAX_RECORDS_FRAME_SAFE`).
  It is the last place that knows which sensor's log a line came from, so it applies the
  [origin policy](../reference/events-and-signals.md#what-a-log-line-may-claim-the-origin-policy)
  there: a line that parses as an event and claims another sensor's name, or a signal type,
  protocol, authentication or summary its sensor cannot produce, is dropped with a WARN and not
  shipped (`crates/shipper/src/batcher.rs#admit`). A sensor's own `sensor_stats` line is held to
  its log the same way: it is dropped unless it is well formed, names a known sensor and, in a log
  bound to a sensor, names that sensor, because past the shipper nothing can tell the telnet log's
  stats line from the ssh log's. A line that does not parse is shipped unchanged.
- The **gateway** accepts a connection only with a client certificate signed by its CA, takes the
  collector id from that certificate's CommonName rather than from anything the collector sends,
  checks each batch's hash and its place in the chain, and appends the lines byte for byte to one
  spool file per collector, synced to disk before it acknowledges the batch
  (`crates/collector-wire/src/tls.rs#server_config`, `crates/gateway/src/server.rs#handle_connection`,
  `crates/gateway/src/verify.rs#GatewaySink::accept`, `crates/gateway/src/spool.rs#SpoolWriter::write_records`).
- **Intake** on the control plane tails that spool file the way it tails a sensor log on a single
  host. Every line keeps its own `sensor` field, so one entry per collector is enough. The entry's
  name must not be a sensor's name or one of the shipped `cred-*` labels: such a name binds the
  log to that one sensor, every other sensor's lines in the stream would be refused, and that
  sensor's `sensor_stats` line would be stored under the bare sensor name, the control plane's
  own row (`config-check` fails such an entry as `spool-label-sensor`). Under any
  other name (the collector id is the convention) the stream may carry every known sensor, and
  intake still holds each line to its own sensor's row of the policy and refuses a line dated more
  than an hour ahead of the control plane's clock. The `sensor_stats` line each capturing sensor
  writes every minute is stored for that collector and sensor together, under the entry's name
  (`crates/intake/src/runner.rs#stats_key`), so the control plane's `/metrics` publishes each
  collector's capture counters with two labels, for example
  `propolis_sensor_capture_queue_dropped_total{collector="collector-01",sensor="ssh"}`, beside
  the control plane's own sensors, which keep the one label `sensor`. A collector that stops
  reporting shows `propolis_sensor_stats_stale` 1 for its own series only
  ([sensor stats](health-and-observability.md#sensor-stats)).
- Each end keeps its position in the chain on disk, as `last_seq` and `last_batch_hash` in a file
  named after the collector id (`crates/gateway/src/state.rs#CollectorState`,
  `crates/shipper/src/state.rs#ConfirmedState`). Equal `last_seq` values mean the two ends agree
  on the chain, not that the shipper has sent everything; see [step 5](#5-check-that-it-works).

The collector dials the gateway; the gateway never dials a collector. Captured sample bodies do not
cross: the shipper sends log lines only (`crates/shipper/src/main.rs#main`), so files a sensor
stores on the collector stay there and never reach the control plane's review or VirusTotal scanning.
The collector's own sensors age them out after 30 days (the sensor's pass, [retention](retention.md)),
which deletes the only copy of each body. The owner accepted that age-only pruning on 2026-10-20
until the planned `CustodyComplete` receipt lands; copy bodies off within 30 days if you need them
longer ([retention](retention.md#why-the-sensors-prune-their-own-spools)).

## What is and is not supported

Several parts of the split are not finished. Read this before building anything.

- **One collector per CA.** `provision-certs` creates a new CA on every run, issues one gateway
  certificate and one collector certificate from it, and never writes the CA's private key
  (`crates/provision-certs/src/lib.rs#provision`). No shipped tool can issue a second collector
  certificate under an existing CA, so this page sets up one collector.
- **No revocation and no expiry.** `provision` sets no validity period, so the certificates carry
  the library's default of 1975 to 4096, and the gateway checks no revocation list
  (`crates/provision-certs/src/lib.rs#provision`, `crates/collector-wire/src/tls.rs#server_config`).
  Cutting off a collector means creating a new CA and installing its files on both hosts.
- **The installer does not know about roles.** `deploy/install.sh` and `deploy/provision.sh` create
  no user, directory or unit for the gateway or the shipper; the steps below create them by hand.
  `deploy/upgrade.sh` must not be run on a collector (see [Upgrading](#upgrading)).
- **Quiet by default.** The gateway and the shipper log only errors unless `RUST_LOG` is set, so a
  healthy gateway prints nothing at all. The env files below set `RUST_LOG=info,rustls=error`: a set `RUST_LOG` replaces the built-in default that holds `rustls` and `russh` at `error`, so the example restates it for `rustls`.
- **The malware fetcher runs on the control plane.** If you enable it, it fetches attacker URLs
  from the control plane's own address, which the split otherwise keeps out of attackers' sight,
  and its guard against fetching from its own hosts does not know about the collector. Add the
  collector's public addresses to `PROPOLIS_FETCH_OWN_IPS` so a captured URL pointing at the
  collector is refused ([environment variables](../reference/environment-variables.md)).

Further limits that matter day to day are under [Known limitations](#known-limitations).

## 1. Build and install the binaries

Build and install on both hosts as for a single host ([installation](installation.md)).
`deploy/install.sh` installs the sensors, `propolis` and their unit files, but not the gateway, the
shipper or `provision-certs`; after the build all three are in `target/release/`. From the top of
the repository checkout:

```sh
# control plane
sudo install -m 0755 target/release/gateway /usr/local/bin/gateway
# collector
sudo install -m 0755 target/release/shipper /usr/local/bin/shipper
```

`install.sh` enables nothing, and neither host should enable what belongs to the other role: no
sensor units on the control plane, and on the collector neither `propolis.service` nor an
`/etc/propolis/propolis.env`, which is where the database credential would live.

## 2. Create the certificates

Choose two names:

- A **collector id**, made of letters, digits and hyphens, for example `collector-01`. The tool
  accepts more (`crates/provision-certs/src/lib.rs#is_safe_path_component`), but the control
  plane's `PROPOLIS_SENSOR_LOGS` splits its entries on `,`, so an id containing one cannot be
  listed there (`crates/propolis/src/config.rs#parse_sensor_logs`), and the ids `ca` and
  `gateway` overwrite files the same run writes.
- A **gateway name** for the gateway's certificate, for example `gateway.example.internal`. The
  shipper checks the certificate against this name but dials an address, so the name does not have
  to resolve in DNS (`crates/shipper/src/client.rs#ShipperClient::connect`).

Run the tool on the control plane, as root, into a directory only root can read. From the top of
the checkout:

```sh
sudo install -d -m 0700 /root/propolis-certs
sudo ./target/release/provision-certs /root/propolis-certs gateway.example.internal collector-01
```

It prints a `wrote` line for each of five files (`crates/provision-certs/src/main.rs#main`,
`crates/provision-certs/src/lib.rs#provision`):

| File | Mode | Installed on |
|---|---|---|
| `ca.crt` | 0644 | both hosts |
| `gateway.crt` | 0644 | control plane |
| `gateway.key` | 0600 | control plane |
| `collector-01.crt` | 0644 | collector |
| `collector-01.key` | 0600 | collector |

Running it again into the same directory replaces all five files with ones from a new CA (the
collector's too, when the id is the same). Once the gateway runs with the new files, a collector
still holding the previous run's files can no longer connect.

## 3. Set up the control plane

1. Create the gateway's user and the directories its unit expects (`deploy/gateway.service`).
   All three must exist before the unit starts: it names them in `ReadOnlyPaths=` and
   `ReadWritePaths=` without the `-` prefix that would let systemd skip a missing path.

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin --user-group propolis-gateway
   sudo install -d -m 0755 -o root -g root /etc/propolis/certs
   sudo install -d -m 0750 -o propolis-gateway -g propolis-gateway /var/spool/propolis/gateway
   sudo install -d -m 0700 -o propolis-gateway -g propolis-gateway /var/lib/propolis/gateway
   ```

2. Install the gateway's certificates:

   ```sh
   sudo install -m 0644 -o root -g root /root/propolis-certs/ca.crt /root/propolis-certs/gateway.crt /etc/propolis/certs/
   sudo install -m 0600 -o propolis-gateway -g propolis-gateway /root/propolis-certs/gateway.key /etc/propolis/certs/
   ```

3. Write `/etc/propolis/gateway.env`, mode 0600, `root:root` (systemd reads it as root; nothing creates it on this host):

   ```sh
   PROPOLIS_GATEWAY_BIND=0.0.0.0:9443
   PROPOLIS_GATEWAY_CA_CERT_PATH=/etc/propolis/certs/ca.crt
   PROPOLIS_GATEWAY_SERVER_CERT_PATH=/etc/propolis/certs/gateway.crt
   PROPOLIS_GATEWAY_SERVER_KEY_PATH=/etc/propolis/certs/gateway.key
   RUST_LOG=info,rustls=error
   ```

   The bind is a literal `ip:port` on port 1024 or above. The unit runs with `PrivateUsers=yes`,
   so adding `CAP_NET_BIND_SERVICE` does not let it bind a lower port. Leave
   `PROPOLIS_GATEWAY_SPOOL_DIR` and `PROPOLIS_GATEWAY_STATE_DIR` unset: the unit can write only to
   their default paths. Every gateway variable is in the
   [environment variable reference](../reference/environment-variables.md#gateway).

4. Let intake read the spool. The gateway creates each collector's directory and file readable by
   its own group (the unit's `UMask=0027`), so the `propolis` user needs that group. Without it,
   intake finds nothing to read and says nothing about it
   (`crates/log-tailer/src/tailer.rs#LogTailer::read_batch`).

   ```sh
   sudo usermod -aG propolis-gateway propolis
   ```

5. In `/etc/propolis/propolis.env`, point intake at the collector's spool file, one `name:path`
   entry per collector. Use the collector id as the name, never a sensor's name (`ssh`, `vnc`,
   `cred-pg` and so on): a sensor's name binds the stream to that one sensor and intake would
   refuse every other sensor's lines in it:

   ```sh
   PROPOLIS_SENSOR_LOGS=collector-01:/var/spool/propolis/gateway/collector-01/events.jsonl
   ```

   The path is `<spool dir>/<collector id>/events.jsonl`. The name labels the tailer in logs and
   in the `sensor-down` and `intake-stalled` alerts; do not reuse a name the daemon gives one of
   its own subsystems (`crates/propolis/src/ops_alert/condition.rs#DAEMON_SUBSYSTEMS`). The file
   does not exist until the first batch arrives, and intake waits for it.

   Every collector needs its own entry, including one added later or given a new id when it is
   rebuilt: the gateway accepts and acknowledges a collector's batches whether or not intake reads
   its spool, so without the entry its evidence piles up unread and nothing else reports it.
   `sudo ./deploy/config-check.sh` reports a collector spool that no entry lists
   (`spool-unlisted`) and an entry whose name is not the collector id. On a control plane that
   also runs sensors, an entry that points into the gateway spool directory is judged by that
   `gateway-spool` row alone: it is not reported as an entry that matches no configured sensor
   (`intake-orphan`), which any other entry no local sensor writes still is. An entry whose
   collector directory does not exist yet raises no finding and leaves the row's state as it is;
   the row names its id after `listed but nothing delivered yet:` (the first three, then how many
   more), since a collector listed ahead of its first batch and a misspelled id look the same
   there. Compare those ids with the collectors' certificate names. Intake reads a newly listed
   spool from its start, so an entry added late still ingests what the file holds. The old id's
   spool, once intake has read it to its end, is moved out of the spool directory, as
   [Rebuilding a collector](#rebuilding-a-collector) describes.

6. Install and start the gateway, then restart `propolis` so it picks up the new group and log
   list. From the top of the checkout:

   ```sh
   sudo install -m 0644 deploy/gateway.service /etc/systemd/system/gateway.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now gateway.service
   sudo systemctl restart propolis.service
   ```

7. Open the gateway port (TCP 9443 above) in the host firewall to the collector's address only.
   The unit does not restrict source addresses itself
   (`deploy/gateway.service#IPAddressDeny=/IPAddressAllow=`).

## 4. Set up the collector

Install and enable the sensors this collector runs, as on a single host
([installation](installation.md)). `sensor-catchall` has no absolute default log path, so set
`PROPOLIS_CATCHALL_LOG_PATH=/var/log/propolis/catchall/events.jsonl` in its env file
([filesystem paths](../reference/filesystem-paths.md)). In the env file of each sensor that
captures files (`ssh`, `telnet`, `ftp`, `adb`), set `PROPOLIS_COLLECTOR_ID` to the collector id as
well: today it only labels the capture records those sensors keep on the collector, but the deploy
files expect it to match the shipper's. Then:

1. Create the shipper's user, give it read access to every sensor's log through the sensors'
   groups, and create its state directory. A log the shipper cannot read ships nothing, with no
   error.

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin --user-group propolis-shipper
   sudo usermod -aG propolis-catchall,propolis-ssh,propolis-telnet,propolis-redis,propolis-adb,propolis-http,propolis-ftp,propolis-smtp,propolis-tftp,propolis-mqtt,propolis-dns,propolis-cred propolis-shipper
   sudo install -d -m 0755 -o root -g root /etc/propolis/certs
   sudo install -d -m 0700 -o propolis-shipper -g propolis-shipper /var/lib/propolis/shipper
   ```

2. Copy the collector's three files from the control plane, where only root can read them, then
   delete the collector's key there; the `&&` deletes it only if the copy succeeded, since it cannot
   be issued again under the same CA. The collector never needs `gateway.key`. On the control
   plane, with `collector` standing for the collector's SSH address:

   ```sh
   sudo tar -C /root/propolis-certs -cf - ca.crt collector-01.crt collector-01.key | ssh collector 'umask 077 && mkdir certs-in && tar -C certs-in -xf -' && sudo rm /root/propolis-certs/collector-01.key
   ```

   On the collector, install them and remove the copies:

   ```sh
   sudo install -m 0644 -o root -g root ~/certs-in/ca.crt ~/certs-in/collector-01.crt /etc/propolis/certs/
   sudo install -m 0600 -o propolis-shipper -g propolis-shipper ~/certs-in/collector-01.key /etc/propolis/certs/
   rm -r ~/certs-in
   ```

3. Write `/etc/propolis/shipper.env`, mode 0600, `root:root` (systemd reads it as root; nothing creates it on this host):

   ```sh
   PROPOLIS_SHIPPER_GATEWAY_ADDR=203.0.113.10:9443
   PROPOLIS_SHIPPER_GATEWAY_DNS=gateway.example.internal
   PROPOLIS_SHIPPER_CA_CERT_PATH=/etc/propolis/certs/ca.crt
   PROPOLIS_SHIPPER_CLIENT_CERT_PATH=/etc/propolis/certs/collector-01.crt
   PROPOLIS_SHIPPER_CLIENT_KEY_PATH=/etc/propolis/certs/collector-01.key
   PROPOLIS_COLLECTOR_ID=collector-01
   PROPOLIS_SHIPPER_SENSOR_LOGS=ssh:/var/log/propolis/ssh/events.jsonl,catchall:/var/log/propolis/catchall/events.jsonl
   RUST_LOG=info,rustls=error
   ```

   - `PROPOLIS_SHIPPER_GATEWAY_ADDR` is a literal IP address and port; a host name is refused at
     startup (`crates/shipper/src/config.rs#load_config_from_env`).
   - `PROPOLIS_SHIPPER_GATEWAY_DNS` is the gateway name from step 2.
   - `PROPOLIS_COLLECTOR_ID` must equal the certificate's CommonName, or the shipper refuses to
     start (`crates/shipper/src/config.rs#validate_collector_id`).
   - `PROPOLIS_SHIPPER_SENSOR_LOGS` lists every log to ship as `name:path`, with the path each
     sensor actually writes. The name labels log lines and binds the log to a sensor: name each
     log after the sensor that writes it (`ssh`, `telnet`, `catchall`, and so on), and the shipper
     ships only that sensor's lines from it. A name that is not a sensor's leaves the log
     unbound (any known sensor's lines are shipped from it), and the name of a different sensor
     gets every line dropped, so a swapped name and path shows as
     `shipper: dropping a line the origin policy refuses for this log` in the journal. By default
     the path is `/var/log/propolis/<sensor>/events.jsonl`, except for `sensor-catchall` (set
     above) and `sensor-cred`, which writes one file per protocol it binds: `vnc.jsonl`,
     `mysql.jsonl`, `mssql.jsonl`, `postgresql.jsonl` (from `PROPOLIS_CRED_PG_BIND`) and
     `mongodb.jsonl` (from `PROPOLIS_CRED_MONGO_BIND`) under `/var/log/propolis/cred/`, each
     needing its own entry under its own name: `cred-vnc`, `cred-mysql`, `cred-mssql`, `cred-pg`,
     `cred-mongo`, for example `cred-pg:/var/log/propolis/cred/postgresql.jsonl`
     (`crates/sensor-cred/src/main.rs#main`, `crates/sensor-wire/src/origin.rs#bound_sensor`). A
     path the shipper cannot open, including a misspelled one, ships nothing and reports nothing,
     and the unit can read only under `/var/log/propolis`.

   Every shipper variable is in the
   [environment variable reference](../reference/environment-variables.md#shipper).

4. Install and start the shipper. From the top of the checkout:

   ```sh
   sudo install -m 0644 deploy/shipper.service /etc/systemd/system/shipper.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now shipper.service
   ```

The two hosts can come up in either order, and intake waits for the spool file to appear. The
shipper keeps trying for as long as the gateway is unreachable: each pass tries one connection per
entry in `PROPOLIS_SHIPPER_SENSOR_LOGS`, then waits one poll interval (1 s by default). A refused
connection fails at once, but when a firewall drops the packets each attempt waits for the
kernel's TCP connect timeout, because the shipper sets none.

## 5. Check that it works

1. The gateway is listening: `journalctl -u gateway.service` shows `gateway: listening` with the
   bind address.
2. The shipper is running: `journalctl -u shipper.service` shows
   `shipper: starting single multiplexed ship loop` with the collector id, and no repeated
   `shipper: failed to connect to gateway; will retry next pass` or
   `shipper: ship cycle IO error; will retry next pass`.
3. Make a sensor log something, for example by connecting to one of its ports from another
   machine. Then on the control plane:
   - the spool file exists and grows: `sudo ls -l /var/spool/propolis/gateway/collector-01/events.jsonl`;
   - intake is allowed to read it: `sudo -u propolis test -r /var/spool/propolis/gateway/collector-01/events.jsonl && echo readable`
     checks the file's modes, and
     `ps -o supgrp= -p "$(systemctl show -p MainPID --value propolis.service)"` must list
     `propolis-gateway`, which shows the running daemon has the group (if it does not, restart
     `propolis.service`);
   - the events reach the ledger: `propolis_events_ingested_total` on the console's `/metrics`
     goes up ([health and observability](health-and-observability.md)).
4. The two ends agree on the chain: `sudo cat /var/lib/propolis/gateway/collector-01.json` on the
   control plane and `sudo cat /var/lib/propolis/shipper/state/collector-01.json` on the collector
   show the same `last_seq`. While a batch is in flight, `collector-01.pending` sits beside the
   shipper's file and the gateway's `last_seq` may already be one higher; the file is deleted once
   the shipper has recorded the gateway's answer.
5. The shipper has sent everything from a log when the `offset` in that log's cursor file equals
   the log's size. The cursor file is named after the SHA-256 of the log's path
   (`crates/log-tailer/src/cursor.rs#DurableCursor::cursor_file_path`):

   ```sh
   log=/var/log/propolis/ssh/events.jsonl
   sudo stat -c %s "$log"
   sudo cat "/var/lib/propolis/shipper/cursors/$(printf '%s' "$log" | sha256sum | cut -d' ' -f1).json"
   ```

The console's fleet pane can prove the whole path on its own schedule. With the listener probe on,
the control plane connects to each collector listener, and a row reads ok only when that connect
succeeded and the line it produced has come back through the shipper, the gateway and intake
within two sweep intervals (`crates/fleet/src/health.rs#reach_level`,
`crates/intake/src/runner.rs#run_batch`). In a split, set all four of its values by hand in the
control plane's `/etc/propolis/propolis.env`:

```sh
PROPOLIS_FLEET_LISTENERS=collector-01/ssh/tcp/22
PROPOLIS_FLEET_COLLECTOR_ENDPOINTS=collector-01=198.51.100.7
PROPOLIS_FLEET_PROBE_ENABLED=true
PROPOLIS_FLEET_PROBE_SOURCE_IPS=192.0.2.20
```

- Each `PROPOLIS_FLEET_LISTENERS` entry is `collector/sensor/protocol/port`, and its collector
  field must be the collector id that `PROPOLIS_FLEET_COLLECTOR_ENDPOINTS` maps to the address the
  control plane dials; a listener with no endpoint is recorded as not probeable.
- `PROPOLIS_FLEET_PROBE_SOURCE_IPS` is the control plane's address as the collector's sensors see
  it, after any NAT. With the probe on and this unset, `propolis` refuses to start
  (`crates/propolis/src/config.rs#ConfigError::ProbeEnabledWithoutSources`). Set to the wrong
  address, intake does not recognise the probe's lines and the control plane scores its own address.
- `deploy/fleet-listeners.sh` cannot generate the inventory here: it reads the sensor env files,
  which live on the collector, and every install or upgrade on the control plane rewrites the file
  it generates with an empty inventory. A value in `propolis.env` wins because the unit loads that
  file last (`deploy/propolis.service#EnvironmentFile=/etc/propolis/propolis.env`). The variables
  are described in the
  [fleet health reference](../reference/environment-variables.md#fleet-health-the-consoles-fleet-pane).

## Operating it

### Upgrading

- **Order: control plane first, collectors after.** A sensor that records a shell reply puts it in
  a new field of its log line. An intake that predates the field ignores it, so a reply recorded
  while the collector runs the new build and the control plane the old one is dropped: the event
  is ingested without it and the console shows no reply for that command. The same order covers
  the cred sensor's connection and login summaries: an intake that predates them scores one as a
  single event, so a flooder's volume count is low, and a summary ingested that way stays counted
  once (nothing re-projects it). The hash chain stays intact. Upgrading the control plane first
  avoids both gaps.
- **Control plane.** `deploy/upgrade.sh` works as on a single host: it reinstalls and restarts
  `gateway.service` because the unit is enabled, then restarts `propolis`.
- **Collector.** Do not run `deploy/upgrade.sh`. It restarts `propolis.service` on every host
  (`deploy/upgrade.sh#systemctl restart propolis.service`), which on a collector either fails,
  stopping the script before it restarts the shipper, or starts the daemon if a `propolis.env`
  exists. Instead, as the owner of the checkout, fetch and fast-forward by hand with the same
  checks `upgrade.sh` makes, then build:

  ```sh
  git status --porcelain --untracked-files=normal   # must print nothing
  git remote get-url origin                         # must be the remote you expect
  git fetch --quiet --no-tags origin '+refs/heads/main:refs/remotes/origin/main'
  # only with /etc/propolis/upgrade-signers on this box (see "Signed upgrades")
  git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=/etc/propolis/upgrade-signers \
      -c gpg.ssh.program=ssh-keygen -c gpg.program=/bin/false -c gpg.x509.program=/bin/false \
      verify-commit refs/remotes/origin/main
  git merge --ff-only refs/remotes/origin/main
  cargo build --release --workspace --locked
  ```

  The fetch is the script's: `main` and nothing else, so no tag or branch name the remote
  chooses reaches the clone or the terminal. The first two lines are the dirty check and the origin pin done by eye: this path writes no
  deploy stamp, so the origin a collector's stamp records is the one `install.sh` saw and is
  never refreshed (see [what the pull trusts](upgrade-rollback-and-dr.md#what-the-pull-trusts)).
  Then, as root
  from the top of the same checkout (`sudo -i` would start you in `/root`, where these relative
  paths do not exist):

  ```sh
  for bin in sensor-catchall sensor-ssh sensor-telnet sensor-redis sensor-adb sensor-http sensor-ftp sensor-smtp sensor-tftp sensor-mqtt sensor-dns sensor-cred shipper; do
      install -m 0755 "target/release/$bin" "/usr/local/bin/$bin"
  done
  ./deploy/provision.sh
  install -m 0644 deploy/sensor-*.service deploy/shipper.service /etc/systemd/system/
  install -m 0644 deploy/logrotate-sensors.conf /etc/logrotate.d/propolis-sensors
  install -m 0755 deploy/logrotate-guard.sh /usr/local/sbin/propolis-logrotate-guard
  install -m 0644 deploy/propolis-logrotate.service deploy/propolis-logrotate.timer /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now propolis-logrotate.timer
  ```

  The guard goes in with the policy: the policy calls it before every rotation, so a missing
  guard stops every sensor log from rotating.

  Then restart each enabled sensor unit, and `shipper.service` last.

  Until a collector's shipper is upgraded, its sensors' `sensor_stats` counters on the control
  plane are only as trustworthy as its least trusted sensor. The control plane reads the whole
  spool under one label and stores a stats line under whatever known sensor it names; only the
  shipper can see which log a line came from, and a shipper from before this release ships every
  stats line from every log, so a compromised telnet sensor on that collector could keep
  `propolis_sensor_stats_stale{collector="<id>",sensor="ssh"}` at 0 after ssh died
  ([which log may report which sensor](health-and-observability.md#sensor-stats)). Such a
  shipper holds no line to the log it came from, evidence lines included; the control plane
  still holds each evidence line to its own sensor's row of the policy.

The shipper's frames carry a wire version with no negotiation
(`crates/collector-wire/src/frame.rs#VERSION`). A release that changes it has to reach both hosts
together, since a shipper on the other version stops at its first batch.

#### Following a restarted history

When the repository's history was restarted, the project moved to a successor repository, or
`main` was rewritten or moved back, the control plane follows with
`upgrade.sh --adopt-history=<commit>`
([a restarted history](upgrade-rollback-and-dr.md#a-restarted-history-or-a-successor-repository)).
The collectors follow by hand after it, with the same commit id. How the ordinary collector
procedure above behaves depends on the shape, and neither behaviour moves the collector:

- A `main` that does not descend from what the collector runs makes `git merge --ff-only`
  fail, as it should.
- A `main` that was moved back makes it print `Already up to date.` and change nothing. The
  collector then stays ahead of the control plane, which is the skew the order rule above
  exists to avoid.

In both cases use this instead, as the owner of the checkout, from the top of it. Every
command after the fetch names the id and none names the ref:

```sh
# Example - ID is the full commit id the control plane adopted, from a channel the remote does not control.
ID=<full commit id of the new main>
git remote get-url origin    # read it: the remote you mean (set-url first when moving)
# One command: each step runs only if the one before it succeeded.
[ "$(git symbolic-ref --quiet HEAD)" = refs/heads/main ] &&
[ -z "$(git status --porcelain --untracked-files=normal)" ] &&
OLD="$(git rev-parse --verify HEAD)" &&
git fetch --quiet --no-tags origin '+refs/heads/main:refs/remotes/origin/main' &&
[ "$(git rev-parse --verify 'FETCH_HEAD^{commit}')" = "$ID" ] &&
[ "$(git rev-parse --verify 'refs/remotes/origin/main^{commit}')" = "$ID" ] &&
{ [ ! -e /etc/propolis/upgrade-signers ] ||
  git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=/etc/propolis/upgrade-signers \
      -c gpg.ssh.program=ssh-keygen -c gpg.program=/bin/false -c gpg.x509.program=/bin/false \
      verify-commit "$ID^{commit}"; } &&
git diff --shortstat "$OLD" "$ID^{commit}" &&
git update-ref "refs/propolis/before-adoption/$(date -u +%Y%m%dT%H%M%SZ)" "$OLD" &&
git checkout --quiet --no-overwrite-ignore -B main "$ID^{commit}" &&
[ -z "$(git status --porcelain --untracked-files=no)" ] &&
[ "$(git rev-parse HEAD)" = "$ID" ] &&
git diff --no-renames --name-only --diff-filter=D -z "$OLD" "$ID^{commit}" |
    xargs -0 -r sh -c 'for p; do d="$p"; while [ "$d" != "${d%/*}" ]; do d="${d%/*}"; [ -L "$d" ] && continue 2; done; if [ -f "$p" ] || [ -L "$p" ]; then echo "still on disk: $p"; exit 1; fi; done' sh &&
echo "OK: the checkout is on the commit named" ||
echo "STOPPED: a step failed and nothing after it ran"
```

In order: the checkout is on `main`; the tree is clean; `main` and nothing else is fetched,
and this fetch delivered it; `origin/main` is the commit named; with a signers file on the
box, that commit carries a listed key's SSH signature; the number of files that differ is
printed, which is what you are accepting; the commit being left is recorded, because it is on
no branch afterwards and cannot be fetched again from a restarted history; the branch moves,
without replacing ignored files; and the result is the named commit, with no tracked file
differing from it and no file the new commit removed still on disk (a file reached through
a link the new commit put where a directory was is the link target's, not a leftover). A step
that fails prints `STOPPED` and leaves the rest undone.

Three things the block does on purpose. `"$ID^{commit}"` rather than the bare id: handed a
bare id as the start point, `git checkout -B` looks it up as a ref name first, and a tag of
that name would decide where the branch lands. `ID` is set before anything is fetched:
whatever a remote prints during a fetch is the thing being checked, never a source for the
id. And it moves `main` only: on a checkout that is on another branch, put that branch's name
in the first line and in the `-B` line; on a detached one, drop the first line and use
`git checkout --quiet --no-overwrite-ignore --detach "$ID^{commit}"`.

After `OK`, build as the same account with `cargo build --release --workspace --locked`, then
install and restart as root exactly as above.

### Rotating certificates

The certificates never expire, so rotation is a response to a leaked key. Create a new set as in
step 2 with the **same** collector id, install the new files on both hosts as in steps 3.2 and 4.2
(including deleting the new `collector-01.key` from `/root/propolis-certs` once it is on the
collector), and restart `gateway.service` and `shipper.service`: each reads its certificates only
at startup. Both ends key the chain by collector id, not by certificate, so it carries over as long
as both hosts keep their state directories. Until both hosts hold the new files the shipper keeps
retrying, and nothing is lost unless the sensor logs rotate past lines it has not sent. If a host
was lost and rebuilt, also follow [Rebuilding a collector](#rebuilding-a-collector) or
[Backups and restores](#backups-and-restores).

### Rebuilding a collector

A collector rebuilt with the same id but an empty `/var/lib/propolis/shipper` starts its chain again
at 1 while the gateway still holds the old position. The shipper sees this at its first batch,
logs `shipper: this collector's chain has diverged from the gateway's` and exits non-zero
(`crates/shipper/src/client.rs#ship_cycle`, `crates/shipper/src/main.rs#run_ship_loop`). There are
two ways out:

- Give the rebuilt collector a new id: run step 2 with the new id, install the new `ca.crt`,
  `gateway.crt` and `gateway.key` on the control plane (step 3.2) and restart `gateway.service`,
  replace the old `PROPOLIS_SENSOR_LOGS` entry with the new id's spool path and restart
  `propolis.service`, then set `PROPOLIS_COLLECTOR_ID` to the new id in the capturing sensors'
  env files (step 4) and set up the collector from step 4.2 with the new id. The old id's
  `sensor_stats` rows stay behind: `/metrics` goes on publishing them beside the new id's, for
  example `propolis_sensor_stats_stale{collector="collector-01",sensor="ssh"} 1`, with an age
  that only grows, and an alert on `stale == 1` keeps firing. Delete them by hand once the old
  spool is retired (below), not before: while intake is still reading the old spool it stores
  that collector's last stats lines again.

  The old id's spool directory stays under the gateway spool as well. Once intake has read it in
  full (its cursor, found as under [Disk space](#disk-space), shows an `offset` equal to the file's
  size, and `sudo ./deploy/config-check.sh` counts it in the `gateway-spool` row as read to the end
  and no longer listed, which it does once the file has not been written for ten minutes), move it
  out of the spool directory. Keep it under `/var/spool/propolis`,
  which the [documented archive](backup-and-restore.md) holds:

  ```sh
  sudo install -d -m 0750 -o propolis-gateway -g propolis-gateway /var/spool/propolis/gateway-retired
  sudo mv /var/spool/propolis/gateway/collector-01 /var/spool/propolis/gateway-retired/
  ```

  If `config-check` instead fails the old id with `spool-unlisted` and says bytes were written
  after intake stopped reading it, put its entry back beside the new one and restart
  `propolis.service`; intake resumes from its saved position. Remove the entry again once the
  cursor reaches the end. Then delete the old id's `sensor_stats` rows, by its `collector` label
  as `/metrics` prints it, with the statement under
  [sensor stats](health-and-observability.md#sensor-stats); it deletes no other collector's rows.
  A collector retired for good is handled the same way.
- Or reset the chain on both sides, so both restart at 1 together:
  1. stop `shipper.service` on the collector, then `gateway.service` on the control plane;
  2. delete `/var/lib/propolis/gateway/<collector id>.json` on the control plane and, on the
     collector, `/var/lib/propolis/shipper/state/<collector id>.json` together with
     `<collector id>.pending` and `<collector id>.pending.damaged` beside it if they are there;
  3. start `gateway.service`, then `shipper.service`.

  The gateway holds chain state in memory, so deleting its file while it runs changes nothing. The
  shipper's read positions are separate files and stay as they were, so nothing already sent is
  sent again, apart from a batch that was in flight (`<collector id>.pending`), whose lines are
  sent again because its log's read position had not moved past them. New lines go on appending
  to the same spool file. A `<collector id>.pending` left behind does not block the new chain: a
  batch that was in flight as the old chain's first batch is simply sent as the new chain's first,
  and any other is dropped with `shipper: dropping a record of a batch in flight that does not
  follow the confirmed state`.

Resetting only one side always ends in a stop: a gateway with no state rejects the shipper's next
batch as a sequence gap, and a shipper with no state diverges as above. One case stops a batch
late. If the gateway had accepted exactly one batch from the collector (`last_seq` 1) when the
shipper's state was lost, the shipper's first batch is taken as a resend of that one and dropped,
and its lines are lost. The shipper logs nothing for it; the gateway logs
`gateway: batch reuses the last accepted seq with different content` (see
[Troubleshooting](#troubleshooting)). The next batch then fails the gateway's hash check and
the shipper stops with `shipper: gateway rejected a batch` (`reason=HashMismatch`). Resetting both
sides whenever a collector's state is lost avoids it.

### Backups and restores

The [documented archive](backup-and-restore.md) already holds the gateway spool, which is under
`/var/spool/propolis`. The chain state is not worth backing up: after either host is restored or
rebuilt, the two sides' positions no longer agree, and the only way forward is to reset both
(above). A restore also costs events, in two ways:

- Batches the gateway accepted after the backup was taken are not sent again after the reset,
  because the shipper's read positions are past them.
- A restored spool file is a new file to intake, which reads it from the start whether or not its
  cursors were restored (`crates/log-tailer/src/cursor.rs#DurableCursor::detect_rotation`), and
  records every event in it that the database already holds a second time.

On a rebuilt control plane, before unpacking any part of the archive (the restore procedure
unpacks `/etc/propolis` first), run `deploy/provision.sh`, which creates the `propolis` user, and
then step 3.1's `useradd` and step 3.4's `usermod`. `provision.sh` does neither of those two, and
`tar` maps each file's owner by name, so `propolis-gateway` has to exist when the gateway's files
are unpacked. The archive's `/etc/propolis` already holds what steps 3.2, 3.3 and 3.5 write, and
`/root/propolis-certs` is not in it. After unpacking, run step 3.1's `install -d` commands (the
gateway's state directory is not in the archive), steps 3.6 and 3.7, and reset the chain.

### Disk space

- **Control plane.** Each collector's spool file grows without limit; the shipped rotation policy
  covers the sensor logs only (`deploy/logrotate-sensors.conf`). With `PROPOLIS_OPS_ENABLED=true`
  (it is off by default), ops-alert's disk check watches the filesystem holding
  `/var/spool/propolis`, which includes the gateway spool unless it is mounted separately
  (`crates/propolis/src/main.rs#ops_spool_root`,
  `crates/propolis/src/ops_alert/conditions/capacity.rs#Capacity::evaluate`). To reclaim the space,
  stop `shipper.service`, wait until intake has read the file to its end (its cursor, found under
  `/var/lib/propolis/cursors` the way step 5.5 finds the shipper's, shows an `offset` equal to the
  file's size), empty the file with
  `sudo truncate -s 0 /var/spool/propolis/gateway/collector-01/events.jsonl`, and start the shipper
  again. Intake treats the emptied file as rotated and reads new lines from its start. Do not
  rotate it with `copytruncate`: lines appended between the copy and the truncate are lost after
  the collector was told they were stored.
- **Collector.** Each sensor trims its own capture spool (`/var/spool/propolis/ssh`, `telnet`,
  `ftp`, `adb`, `tftp`, `mqtt`): files older than 30 days are removed at start and hourly, in the
  sensor, so the collector needs no daemon for it ([retention](retention.md)). A sensor that
  reaches its 100 MB budget inside that window refuses later bodies but still records the upload
  event, marked not stored ([queue and spool](queue-and-spool.md)). The sensor logs rotate by
  `copytruncate` at 100 MB. The shipper uses the same tailer as intake, so lines it had not sent
  when a log was rotated, for example during a gateway outage, are read from `events.jsonl.1`
  before the new file, and the rotation guard skips a log whose `.1` it has not finished (it reads
  the shipper's cursor under `PROPOLIS_SHIPPER_CURSOR_DIR`). Only a `.1` that is missing,
  compressed or another generation's loses them, with a journal WARN from the shipper and no
  alert on a collector, which does not run the ops monitor.

## Troubleshooting

With `RUST_LOG=info`. Each message is quoted from its start, as the binaries print it.

| What you see | Likely cause | What to do |
|---|---|---|
| Nothing at all in the gateway or shipper journal | `RUST_LOG` unset, so only errors are logged | Add `RUST_LOG=info` to the env file and restart |
| `refusing to start` or `gateway: failed to start server`, repeating every 5 s (gateway) or 10 s (shipper) | a missing or malformed variable; an unreadable certificate or key; a certificate and key that do not parse or do not belong together (`failed to build TLS ... config`); a bind address in use or not on this host; or `shipper: COLLECTOR_ID does not match the client certificate` | Read the first error line; check file ownership from steps 3.2 and 4.2 |
| `shipper: failed to connect to gateway; will retry next pass`, repeating | wrong `PROPOLIS_SHIPPER_GATEWAY_ADDR`, the firewall, the gateway is down, or `PROPOLIS_SHIPPER_GATEWAY_DNS` or `ca.crt` does not match the gateway's certificate. With `BadSignature` in the error, the collector's `ca.crt` comes from a different `provision-certs` run than the gateway's certificate, for example after it was run again and only the control plane got the new files | `sudo ss -ltn` on the control plane; check the firewall; compare the name with step 2; for `BadSignature`, install one run's files on both hosts and restart both units |
| Gateway logs `tls handshake failed; dropping connection` with `BadSignature`; once it has events the shipper logs `shipper: ship cycle IO error; will retry next pass` with `DecryptError` on every pass | the collector's certificate and key come from a different `provision-certs` run than the gateway's `ca.crt`, while the collector's own `ca.crt` matches the gateway (it got the new `ca.crt` but kept its old certificate and key) | Install one run's files on both hosts and restart both units |
| `shipper: ship cycle IO error; will retry next pass` about every two minutes, only while a backlog drains | the gateway closes every connection after `PROPOLIS_GATEWAY_MAX_DURATION_SECS` (120 s) | Expected; nothing is lost |
| `shipper: this collector's chain has diverged from the gateway's` | a rebuilt collector, or lost shipper state | [Rebuild or reset](#rebuilding-a-collector) |
| Gateway logs `gateway: batch reuses the last accepted seq with different content; acknowledged as Duplicate without storing it` (ERROR) | the shipper sent a different batch under a number the gateway had already stored a batch under. A shipper from this release resends a batch whose answer it never saw byte for byte (see [Known limitations](#known-limitations)), so from it this means one of three things. Its chain state was lost, restored or reset without the gateway's: `<collector id>.json` under `/var/lib/propolis/shipper/state` deleted or replaced while the gateway kept its own. Or the record of the batch in flight was unreadable; then the shipper stops with `shipper: the gateway already holds a batch under this sequence number` instead of moving past anything, and a chain reset on both sides is all it needs. Or it is the first start of this release after an upgrade from an earlier one that stopped with an answer outstanding: the earlier release left no record, so the new one built that number again from the read positions. A shipper from an earlier release also does it after a lost answer (a reset connection, the 60 s batch timeout, a restart), by building the next batch under the same number: more lines from the same log, or the next log in the pass. Nothing from this batch of `records` lines was stored, and the shipper has moved past all of them. When it read the same log again, the batch begins with the lines of the earlier batch under that seq, which are stored, so only the lines after those are missing; from another log, or after a lost or restored state file, all of them are. The gateway cannot tell which. `suppressed_batches` and `suppressed_records` count the further such batches since the previous line, which is logged at most once a minute per `collector_id` | On that collector, read the shipper journal first. If it shows `shipper: the gateway already holds a batch under this sequence number`, the shipper stopped before moving any read position and nothing is missing: reset the chain on both sides ([Rebuilding a collector](#rebuilding-a-collector)) and it sends those lines again. Otherwise, check the shipper's version, whether its state under `/var/lib/propolis/shipper` was deleted or restored, and whether the line came at the first start after an upgrade from an earlier release (the shipper journal shows the start just before it); for an earlier release still running, also look just before the line for a connection error, timeout or restart, and upgrade it. In these cases (lost or restored shipper state, the first start after an upgrade, or an earlier release) the shipper's next batch is rejected with `reason=HashMismatch`: reset the chain on both sides, see [Known limitations](#known-limitations). The shipper keeps its read positions, so it then sends the lines after the missing ones but never the missing ones. Once it has caught up, copy `/var/spool/propolis/gateway/<collector id>/events.jsonl` to the collector and list each sensor log's lines the spool does not hold, for example `grep -Fxv -f events.jsonl /var/log/propolis/ssh/events.jsonl`, and the same for its `.1`. Those are the missing lines, apart from any the shipper dropped with a warning (`shipper: dropping a line the origin policy refuses for this log`) and any older than a spool file emptied to reclaim space. They stay in the sensor log until it rotates past them |
| `shipper: gateway rejected a batch` with `reason=SeqGap` or `reason=HashMismatch` | the gateway's state was lost, could not be read (a gateway that cannot read `/var/lib/propolis/gateway/<collector id>.json` answers as if it had never seen the collector, and logs nothing for it) or was restored from an older backup; or the shipper's state was lost when the gateway had accepted exactly one batch; or, with `HashMismatch`, the batch after one the gateway logged as `batch reuses the last accepted seq` | The shipper keeps the record of the batch it was sending (`<collector id>.pending`), since the gateway may hold that batch, and stops for good. If the gateway's file is there but could not be read (its owner or mode, a failing disk), fix that and restart `gateway.service`: the shipper, restarted by systemd, sends that same batch again and it is confirmed, with nothing lost. Otherwise reset the chain on both sides ([Rebuilding a collector](#rebuilding-a-collector)), which deletes the record; after a `batch reuses the last accepted seq` line, also follow that row |
| `shipper: gateway rejected a batch` with `reason=Oversize` | a blank line in a sensor log: the gateway refuses an empty record | Not cleared by a reset or restart; see [Known limitations](#known-limitations) |
| Spool file grows, nothing is ingested | the running `propolis` does not have the `propolis-gateway` group, or `PROPOLIS_SENSOR_LOGS` names another path | Step 5.3's checks; steps 3.4 to 3.6 |
| One sensor's events never arrive | the shipper cannot read that log, or its path in `PROPOLIS_SHIPPER_SENSOR_LOGS` is not the file the sensor writes | Step 4.1; the paths in step 4.3 |
| `systemctl status shipper` shows `activating (auto-restart)` and a climbing restart count | a stop the shipper cannot recover from: it exits, and `Restart=always` starts it into the same stop again | Treat it as stopped and fix the cause in the journal |

## Known limitations

Each of these is a defect or an unbuilt part of the split, not a setup mistake.

- A blank line in a sensor log stops the shipper for good. The gateway refuses the batch holding
  it as oversize and the shipper stops. The refused batch is kept in `<collector id>.pending` and
  sent again as stored after every restart, and a batch built again from the log after a reset
  would hold the blank line too, so neither a restart nor a reset clears the stop, and the lines
  before and after it are not shipped either (`crates/collector-wire/src/frame.rs#decode_frame`,
  `crates/shipper/src/batcher.rs#Batcher::next_batch`). The sensors do not write blank lines
  themselves; one appears only if something else writes to the log.
- `PROPOLIS_GATEWAY_READ_TIMEOUT_MS` and `PROPOLIS_GATEWAY_IDLE_TIMEOUT_MS` are validated but not
  applied, so a connection that stops sending holds one of the gateway's connection slots until
  `PROPOLIS_GATEWAY_MAX_DURATION_SECS` runs out (`crates/gateway/src/server.rs#handle_connection`).
- The shipper bounds the dial (TCP connect plus handshake, 20 s) and each batch (write plus ack,
  60 s). A gateway that accepts a connection but never completes the handshake or never answers a
  batch costs one such wait and then a logged error (`shipper: failed to connect to gateway` or
  `shipper: ship cycle IO error`); the same batch is resent on the next pass
  (`crates/shipper/src/client.rs#ShipperClient::connect`, `crates/shipper/src/client.rs#ShipperClient::send_batch`).
- If the shipper cannot write to its state directory (a full or read-only disk), it ships nothing
  until it can: a batch is not sent before its record is written, which logs `shipper: cannot
  record the batch about to be sent in the state directory` on every pass, and a batch the
  gateway confirmed is sent again on each pass until the shipper has recorded that, which logs
  `shipper: ship cycle IO error`. The same holds while a batch is in flight and
  `<collector id>.json` exists but cannot be read: the pass stops with `shipper: ship cycle IO
  error` and the record is kept. The cursor directory (`PROPOLIS_SHIPPER_CURSOR_DIR`,
  `/var/lib/propolis/shipper/cursors` by default, a separate path) is needed the same way: a
  confirmed batch keeps its record until its log's read position is saved past it, so if that
  save fails, every pass logs `shipper: ship cycle IO error` and every log on the collector stops
  shipping, not only the one whose cursor cannot be written. In every case the lines stay in the
  sensor logs, so nothing is lost unless the logs rotate past lines it has not sent; once the disk
  is fixed, shipping resumes on the next pass with no restart (`crates/shipper/src/client.rs#ship_cycle`).
- Delivery is at least once, and a line delivered twice becomes a second event row; the dedup
  window only keeps it from adding score (`crates/core-scoring/src/scoring/constants.rs#DEDUP_WINDOW_SECONDS`).
- A lost acknowledgement (a reset connection, the 60 s batch timeout, a restart between the send
  and the answer) does not cost lines. The gateway answers `Duplicate` on the sequence number
  alone, and the number is shared by every log on the collector, so the shipper never sends two
  different batches under one number: before a batch is first sent it writes it, as sent, with
  the log it was read from, how many lines it took and the read positions it was read from and
  ended at, to
  `<collector id>.pending` in its state directory (`crates/shipper/src/pending.rs#PendingBatch`).
  Until the gateway's answer is recorded, every pass resends that batch first and no other log
  sends anything, across reconnects and restarts. Once it is confirmed, that log's read position
  moves past exactly the lines the batch took, even though the log has grown since, and the file
  is deleted (`crates/shipper/src/client.rs#ship_cycle`, `crates/shipper/src/main.rs#run_ship_loop`).
  It costs one more synced write per batch, and the file holds one batch (a few KiB for ordinary
  lines, under 16 MiB at most). What can still happen:
  - A batch's lines are sent twice, never skipped, if its log's read position cannot be placed
    after them. When the log was rotated away, truncated or replaced while the batch was in
    flight, or the batch was read from a renamed log that a restarted shipper no longer reads,
    the shipper logs `shipper: the gateway holds the batch that was in flight, but this
    log no longer has its lines where they were read` and leaves the read position where it was.
    When power is lost just after a batch was confirmed, the saved read position can be undone
    while the record's deletion is not, and the batch is then read again as a new one.
  - An unreadable record (damaged, or written by a newer release before a rollback) is moved to
    `<collector id>.pending.damaged` with an ERROR, and shipping goes on. Until a batch is
    accepted, a `Duplicate` answer for the next number cannot show which batch the gateway holds,
    so the shipper stops with `shipper: the gateway already holds a batch under this sequence
    number` and exits non-zero rather than move past lines the gateway may not have. Reset the
    chain on both sides ([Rebuilding a collector](#rebuilding-a-collector)). An accepted batch
    deletes the `.damaged` file instead.
  - A record for a log no longer in `PROPOLIS_SHIPPER_SENSOR_LOGS` (removed or renamed) is resent
    to settle its number, with `shipper: the batch in flight was read from a log that is no longer
    configured`; that log's read position is not moved, so its lines are sent again if it comes
    back. A record that does not follow the shipper's chain state (left behind by a reset that did
    not delete it, or by a rollback to an earlier release and back) is dropped with `shipper:
    dropping a record of a batch in flight that does not follow the confirmed state`, and records
    of another collector id are reported at start and never read.
  - A rejected batch keeps its record, and the shipper stops for good with `shipper: gateway
    rejected a batch`. A gateway that lost or could not read its state for the collector rejects
    a batch it may hold, and a batch rebuilt under that number once its state is back would be
    confirmed in its place. Fixing the gateway's state file and restarting `gateway.service` lets
    the same batch be confirmed; otherwise the reset on both sides deletes the record
    ([Rebuilding a collector](#rebuilding-a-collector)).
  - A lost or restored `<collector id>.json` is not covered: see the case of `last_seq` 1 under
    [Rebuilding a collector](#rebuilding-a-collector). The gateway logs an ERROR whenever a batch
    under its last accepted number differs from the one it stored, and counts it
    (`crates/gateway/src/verify.rs#GatewaySink::reused_seq_counts`; see
    [Troubleshooting](#troubleshooting)). It keeps only the last accepted batch's hash, so a reused
    older number cannot be told from a resend and stays silent.

  A shipper from an earlier release does none of this: after a lost acknowledgement it builds the
  next batch under the same number from whatever its logs hold, the gateway's `Duplicate` is taken
  as confirmation, up to a whole batch (15 lines) never reaches the gateway, and the batch after
  that is rejected with `reason=HashMismatch`. The wire format is unchanged, so a shipper and a
  gateway from either release work together. The protection starts with the first batch the new
  release sends: an earlier shipper stopped for the upgrade with an answer outstanding left no
  record, so the new one builds that number again from the read positions and can lose lines once,
  as before. Upgrade a collector while its gateway is reachable, and afterwards check the gateway
  journal for `batch reuses the last accepted seq`. From this release on, that line has three
  causes, the same ones [Troubleshooting](#troubleshooting) lists with what to do for each: a
  shipper chain state lost, restored or reset without the gateway's (lines are missing: reset both
  sides, then recover them with `grep`); an unreadable record of the batch in flight (the shipper
  stops with `shipper: the gateway already holds a batch under this sequence number` and nothing
  is missing: reset both sides); and this first start after an upgrade with an answer outstanding
  (lines are missing: reset both sides, then recover them with `grep`).
- A line the control plane's database refuses is quarantined on the control plane, in
  `/var/lib/propolis/quarantine` (`PROPOLIS_QUARANTINE_DIR`), under the collector's label: the
  collector's own log is not touched, and the gateway has already acknowledged the line
  ([quarantined intake lines](health-and-observability.md#quarantined-intake-lines)).
- Nothing alerts when a collector goes quiet, the shipper stops or the gateway is down:
  `intake-stalled` fires only when intake falls behind a file it can read
  (`crates/propolis/src/ops_alert/monitor.rs#default_conditions`,
  `crates/propolis/src/ops_alert/conditions/intake.rs#IntakeStalled`).
- The ledger does not record which collector an event came from, and the fleet pane matches probe
  lines and event age by sensor name, so two collectors running the same sensor cannot be told
  apart there (`crates/fleet/src/store.rs#confirm_sensor`, `crates/console/src/routes/fleet.rs`).
- The origin policy separates the sensors of a collector from each other, `sensor_stats` lines
  included, only once the collector runs a shipper from this release (see
  [Upgrading](#upgrading)), and never the collector from the control plane. The shipper runs on the collector and the batch it sends carries no record
  of which log a line came from, so a collector that is compromised as a whole (its shipper, its
  certificate key, or root on the host) is still trusted for every sensor it could run: it can
  send any line that fits some known sensor's row. The control plane refuses only what no sensor
  could write, a line under an unknown sensor name, and a line dated more than an hour ahead.
- A line the shipper drops is logged and counted in the shipper's journal
  (`shipper: this cycle dropped lines the origin policy refuses for this log`) and nowhere else:
  it never reaches the control plane, so `propolis_events_rejected_total` does not see it.
- `gateway` and `shipper` have no `--version`, and the deploy stamp records only `propolis` and
  `console` (`deploy/deploy-stamp.sh`), so their installed build is not visible.
- `propolis`, `console` and the sensors default to `info` when `RUST_LOG` is unset; every other
  binary logs only errors ([environment variables](../reference/environment-variables.md#rust_log)).

## Related

- [Deployment models](deployment-models.md) - the single-host deployment this extends.
- [Environment variables](../reference/environment-variables.md) - every `PROPOLIS_GATEWAY_*` and
  `PROPOLIS_SHIPPER_*` variable.
- [Outbound controls](../security/outbound-controls.md) - the collector's one outbound connection.
- [Backup and restore](backup-and-restore.md) and [upgrade, rollback and DR](upgrade-rollback-and-dr.md).
