<!--
title: Adding or modifying a sensor
audience: developer
status: current
owner: maintainer
applies-to: 0.3.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Adding or modifying a sensor

A sensor is a standalone binary crate that composes the shared
`sensor-framework` harness, emits the frozen `sensor-wire` NDJSON format, and runs
as its own OS process. This page covers the framework contract, the tests a sensor
must pass, and wiring a systemd unit. For sensor architecture, see
[`architecture/sensors`](../architecture/sensors.md); for per-protocol capture
behavior, [`reference/sensor-behavior`](../reference/sensor-behavior.md).

## The framework contract

Add a crate under `crates/` with exactly these dependencies (the sensor construction
invariant - no HTTP client, nothing beyond the harness and tokio):

```toml
[dependencies]
sensor-wire = { path = "../sensor-wire" }
sensor-framework = { path = "../sensor-framework" }
tokio = { version = "1.53.1", features = ["rt-multi-thread", "macros", "net", "io-util", "signal", "time"] }
```

`tokio`'s `process` feature is deliberately **off** (see
[tests](#the-tests-a-sensor-must-pass)). Add the crate to `Cargo.toml` `members`.

The harness (`crates/sensor-framework/src/lib.rs`) provides the pieces a sensor
composes rather than reimplements:

| Item | Role |
|---|---|
| `run_tcp_listener` / `run_udp_listener` | Bind an address and run a per-connection async handler with `ConnectionBounds` applied. A per-port bind failure is non-fatal; one unavailable port does not take the sensor down. |
| `ConnectionBounds` | Read/idle timeouts, max duration, max captured bytes, max concurrent. |
| `EventEmitter` | Writes `SensorEvent` NDJSON records to the sensor's log path. |
| `WanResolver` | Maps local bind IP → WAN IP for attribution; empty map = null `wan_ip`. |
| `QuarantineSpool` / `CaptureHandoff` | Off-response-path capture of uploaded file bodies to the quarantine spool, named by SHA-256. |
| `sanitize_value`, `to_hex_bounded` | Sanitize attacker-controlled data before it reaches metadata. |
| `shutdown_signal` | Await SIGINT/SIGTERM for graceful shutdown. |
| Fake shell / fs, persona | Shared interactive-service emulation. |

A minimal sensor `main.rs` (pattern, from `crates/sensor-catchall/src/main.rs`):

1. `tracing_subscriber::fmt::init()`.
2. Load and **validate** config from environment variables; on any malformed or
   zero-valued bound, log and `std::process::exit(1)` - fail closed, never
   substitute a default that disables the bound it names (`main.rs` `load_config_from_env`).
3. Build `EventEmitter` and `WanResolver`.
4. For each configured bind address, start the TCP and/or UDP listener with the
   protocol handler closure.
5. If nothing bound, `exit(1)`.
6. `shutdown_signal().await`, then abort the listener handles.

Config is env vars only - no TOML or CLI parsing dependency. Env-var names,
defaults, and bounds are owned by
[`reference/environment-variables`](../reference/environment-variables.md); a new
sensor's vars must be added there and to `INSTALL.md` (the doc/code gate below
enforces the latter).

## Emit the frozen wire format

Sensors emit `sensor_wire::SensorEvent` only - raw facts (`source_ip`, `wan_ip`,
`sensor`, `signal_type` and `protocol` as plain strings, `authenticated`,
`observed_at`, `metadata`, optional `sample`, optional `session_id`). Weight,
confidence, and category are **not** on the wire; they are derived downstream by
intake. The encoding is frozen and hash-chain-critical - see
[schema-and-migrations](schema-and-migrations.md#the-frozen-wire-contract) and
[`reference/events-and-signals`](../reference/events-and-signals.md). A sensor may
emit only the SP2 signal subset (`catchall_probe`, `honeypot_connection`,
`honeypot_login_attempt`, `honeypot_command_exec`, `honeypot_malware_upload`,
`honeypot_file_download`; `crates/sensor-wire/src/lib.rs:17-22`).

## The tests a sensor must pass

Sensors test with **real TCP** against an ephemeral `:0` listener per connection
(`CONTRIBUTING.md:25-27`). Two static-check tests enforce the "never execute, never
fetch" guarantee and should be present in a new sensor's `tests/`:

- **`never_exec_static_check`** - greps the crate's own `src/` for process-spawning
  patterns (`std::process::Command`, `process::Command`, `Command::new`,
  `libc::exec`, `nix::unistd::exec`) and fails if any appear (e.g.
  `crates/sensor-http/tests/integration.rs:198`). Present across the protocol
  sensors (ftp, telnet, redis, adb, http, smtp, cred, ssh).
- **No HTTP-client dependency** - `crates/sensor-ssh/tests/shell_test.rs:364`
  (`sensor_ssh_has_no_http_client_dependency`) asserts the crate manifest declares
  none of `reqwest`, `hyper`, `ureq`, `curl`, `isahc`, `surf`, `attohttpc`. This
  explicit test currently lives in `sensor-ssh` only; the dependency structure
  above gives the same guarantee by construction for every sensor. **Add an
  equivalent test to a new sensor.**
- **`tokio_dependency_lacks_process_feature`** (`shell_test.rs:344`) - asserts
  `tokio`'s `process` feature stays off, so adding process-spawning capability
  requires a visible `Cargo.toml` diff.

The doc/code agreement gate (`crates/propolis/tests/docs_agreement.rs`) additionally
fails CI if a new `PROPOLIS_*` / `CATCHALL_*` env-var name in source is absent from
`INSTALL.md`.

## Wiring a systemd unit

Sensors run one OS process each. Add `deploy/sensor-<name>.service` modeled on the
existing units. Observable required directives (`deploy/sensor-ssh.service`):

- `Type=simple`, dedicated unprivileged `User=`/`Group=` (never root),
  `EnvironmentFile=/etc/propolis/<name>.env`, `ExecStart=/usr/local/bin/sensor-<name>`,
  `Restart=always`.
- Hardening: `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`,
  `RestrictAddressFamilies=AF_INET AF_INET6`, `ReadWritePaths=` scoped to only this
  sensor's log/spool/state dirs, `AmbientCapabilities`/`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.
- Resource caps: `MemoryMax=512M`, `TasksMax=`, `LimitNOFILE=`, `CPUQuota=`.

> **`SystemCallFilter` is a placeholder, not a shipped hardened filter.** The units
> ship `SystemCallFilter=@system-service` + `SystemCallFilter=~@privileged @resources`
> - a broad dev allowlist the unit header explicitly says to replace with a tightened
> per-sensor allowlist (`deploy/sensor-ssh.service:90-99`). This is residual risk, not
> a delivered control.

`crates/sensor-framework/tests/deploy_test.rs` asserts these directives are present - but the assertions target the **catchall and ssh units specifically**
(`catchall_unit_has_hardening_directives`, `ssh_unit_has_hardening_directives`). A new
sensor's unit is not automatically covered; extend `deploy_test.rs` to assert your
new unit too.

Then register the binary and unit in `deploy/install.sh` (the binary list at
`install.sh:198` and the unit-enable list at `install.sh:215`). `install.sh` installs
units but does **not** start them; `systemctl enable --now <unit>` is an operator
action after populating `/etc/propolis/<name>.env`. Deploy details:
[`operations/service-lifecycle`](../operations/service-lifecycle.md); real bind ports:
[`reference/ports-and-protocols`](../reference/ports-and-protocols.md).
