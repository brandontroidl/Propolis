<!--
title: Commands reference
audience: developer
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Commands

Runnable commands verified against the repository. Exact env-var defaults and
bounds live in [`environment-variables.md`](environment-variables.md); ports in
[`ports-and-protocols.md`](ports-and-protocols.md); paths in
[`filesystem-paths.md`](filesystem-paths.md). This page owns only the command
invocations.

The toolchain is pinned to Rust `1.96.1` with `clippy` + `rustfmt`
(`rust-toolchain.toml#channel`, `rust-toolchain.toml#components`); cargo selects it automatically inside the repo.
Every workspace crate is edition 2024.

## Build

```
cargo build            # debug build, all 29 workspace members
cargo build --release  # release binaries into target/release/
```

`cargo build --release` is the documented build step (`README.md#Building and trying it`,
`docs/operations/installation.md#1. Build`); the install script expects those release
binaries in `target/release/` (`deploy/install.sh#BUILD_DIR`).

## The gate

CI is authoritative. It runs three **independent** jobs (not one chained
sequence, deliberately, so a cheap failure cannot mask an expensive one) on
every push and pull request (`.github/workflows/ci.yml`):

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
set -o pipefail
cargo test --workspace --locked -- --test-threads=1 2>&1 | tee /tmp/test-output.txt
```

- `--all-targets` in clippy compiles test targets, so a non-compiling test file
  fails there rather than silently vanishing from the suite.
- `--test-threads=1` runs the suite serially; `set -o pipefail` is mandatory so
  the `tee` pipe cannot report green over a red suite.
- `--locked` enforces the committed `Cargo.lock` frozen.

`docs/governance/contribution.md#The merge gate` gives a shorter chained form
(`cargo fmt --check && cargo clippy -- -D warnings && cargo test`); it omits the
scope flags above and bails on first failure, so treat CI as authoritative. See
[`../development/build-and-test.md`](../development/build-and-test.md) for the
full test taxonomy.

### Single crate / single test

```
cargo test -p console                       # one crate
cargo test -p console -- --ignored rdns     # the one #[ignore]d live rDNS test (egress, see below)
```

> **Egress warning.** `cargo test -p console -- --ignored rdns` performs a live
> reverse-DNS lookup (`live_forward_confirmed_reverse_lookup_of_a_stable_public_ip`,
> `crates/console/src/rdns.rs#live_forward_confirmed_reverse_lookup_of_a_stable_public_ip`). It is `#[ignore]`d
> precisely so the default suite stays offline-deterministic. Run it only when a
> real DNS query is acceptable.

## Test database

DB-backed tests use `sqlx::test`, which provisions a fresh database per test.
Provide `DATABASE_URL` and a reachable PostgreSQL 18 server. Local dev uses a
disposable, localhost-only, trust-auth container
(`.env`, gitignored via `.gitignore:7`):

```
podman run -d --name propolis-pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:5432:5432 \
  docker.io/library/postgres:18
# then, on later sessions:
podman start propolis-pg
```

`DATABASE_URL` differs across sources (CI `postgres@localhost/postgres`, `.env`
`postgres@127.0.0.1/postgres`, `docs/archive/2026-08-26/root/CONTRIBUTING.md#Development setup`
`propolis:...@localhost/propolis_test`). Match your local `.env`; see
[`environment-variables.md`](environment-variables.md).

## Running a component locally

Each crate that produces a binary is runnable with `cargo run -p <crate>`.
Every binary reads its configuration from environment variables **only** and
refuses to start on a malformed value rather than substituting a default
(`crates/sensor-catchall/src/main.rs`,
`crates/review/src/main.rs` module doc). Set the required vars first; see
[`environment-variables.md`](environment-variables.md).

### A single sensor

```
cargo run -p sensor-ssh        # binds its configured TCP/UDP address, writes NDJSON event logs
```

The twelve sensor binaries are `sensor-{catchall,ssh,telnet,redis,adb,http,ftp,smtp,tftp,mqtt,dns,cred}`.
A sensor has no compiled-in default port; the bind address comes from its env
config (`/etc/propolis/<x>.env` in production).

### The unified daemon

```
cargo run -p propolis          # intake + review + feed + console + VT + fetcher + ops-monitor
```

`propolis` connects the `PgPool`, applies migrations (see below), then spawns
each subsystem as a supervised tokio task. The console listens on
`config.console_bind` (default `127.0.0.1:8080`, `DEFAULT_CONSOLE_BIND`,
`crates/propolis/src/main.rs#main`, `crates/propolis/src/config.rs#DEFAULT_CONSOLE_BIND`). Review, feed, VirusTotal,
fetcher, and the ops-monitor are each **opt-in** and default OFF; when enabled,
several are outbound paths (see warning under Operations). See
[`../architecture/process-topology.md`](../architecture/process-topology.md).

## Live watch

```
sudo -u propolis-watch /usr/local/bin/propolis-watch
sudo ./deploy/watch-env.sh            # refresh /etc/propolis/watch.env after changing PROPOLIS_SENSOR_LOGS
ssh -p <admin-port> -i ~/.ssh/propolis_watch propolis-watch@honeypot -- --sensor ssh   # from the reading machine; the real sshd's port, never the sensor-ssh listener
```

`propolis-watch` streams every sensor event log as JSON Lines on stdout, read-only; it takes
`--sensor <label>` (repeatable), `--signal <type>`, `--source-ip <ip>`, `--journal` and
`--since-start`, and exits 2 on anything else. It reads its log list from
`/etc/propolis/watch.env`, a one-line copy `deploy/watch-env.sh` derives from `propolis.env`, so
it never sees the daemon's secrets. Setup, envelope and filters:
[`../operations/live-watch.md`](../operations/live-watch.md).

## Configuration check

```
sudo ./deploy/config-check.sh [--json | --tsv] [--report-only] [--no-events] [--env-dir DIR]
sudo /usr/local/lib/propolis/config-check.sh [the same options]
```

Read-only comparison of the configured listeners with what is running: unit, port and its
holder, firewall, log, `PROPOLIS_SENSOR_LOGS` entry, newest ledger event, plus the rotation
timer, installed binaries, deploy stamp, env file modes, env lines systemd and the shell scripts
read differently, watcher env, the alert channel (invalid push settings, and a topic the stored
anonymous-read check found readable; it makes no request of its own) and, on a control plane, the
collector spools `PROPOLIS_SENSOR_LOGS` does not list and intake has not read to their end. The
second form is the copy `install.sh` and `upgrade.sh` install, which runs from any directory and
names the checkout's scripts in its fix lines. `--json` prints one JSON document and `--tsv`
tab-separated records (`deploy/config-check.sh#emit_tsv`); the two together are bad usage. Exit
`0` ok, `1` warnings or checks it could not answer, `2` failures, `64` bad usage, `70` the alert
library (`/usr/local/sbin/propolis-alert-lib`, or `alert-lib.sh` beside the script) is missing or
too old; with `--report-only` the findings never make it exit non-zero, though bad usage and a
missing library still do (`upgrade.sh` uses it and tolerates both). What each
column means and what runs without root:
[`../operations/service-lifecycle.md`](../operations/service-lifecycle.md#configuration-check).

## Status walk

```
sudo propolis-status                 # every stage in order, the first stopped one marked >
sudo propolis-status STAGE           # one stage or rail with everything behind its row
sudo propolis-status --setup         # what reaches you and why; runs the anonymous-read check now
sudo propolis-status --test-page     # one test page through the failure-alert unit
sudo propolis-status --ack-test CODE # type back the code the test page carried
sudo propolis-status --banner        # the login banner's text
sudo propolis-status --maint MINUTES # hold unit, collector and database kinds for planned work
propolis-status -h                   # usage, for any user
```

`STAGE` is one of `listen source ship gateway intake ledger review reports feed publish` or a
rail, `alert backup chain host monitor witness peers`. Root only: anyone else gets
`propolis-status needs root: run sudo propolis-status` and exit `3`. The walk and a stage view
are read-only: they write nothing except a temporary header file for the metrics token, removed
on exit, and take no lock. Their network use is the database `DATABASE_URL` names (local or
remote), through `propolis pg-exec`, and the console on loopback, asked only while
`propolis.service` runs (`deploy/propolis-status.sh#status_walk`). Exit `0` nothing stopped and
nothing to look at; `1` a WARN or `?` anywhere (a row, an unreadable state file, a config-check
finding or a config-check run that did not finish) or an open ACT incident; `2` a stage is
marked stopped, a rail is FAIL or a PAGE incident is open; `3` not root; `64` bad usage (an
unknown word, a verb with a bad value, or more than one form); `70` the alert library is
missing (the message says to reinstall it), fails its trust check (the message names the
directory and the `chmod` that fixes it) or is older than the script needs. Once a witness pass
has run on the host, the incidents it judged are listed under `OPEN`; until then the failures
the failure hook recorded, and the firings it spooled because it could not take the lock, are
listed as recent failures and never change the exit status. A stage view exits as the walk
would. What each row and NEXT key means:
[health and observability](../operations/health-and-observability.md#where-to-look-first).

`--banner` prints what the witness writes to `/run/motd.d/propolis` at the end of each light
pass, from the state files alone, and exits `0` (`deploy/propolis-status.sh#status_banner`).
`--maint MINUTES` announces planned work (a manual `systemctl stop`, a PostgreSQL window, a
collector powered off on purpose): it writes `/run/propolis-witness/maintenance` with reason
`manual` until now plus `MINUTES` (1 to 120), then rewrites the banner, and nothing else; while
it holds, unit, collector and database kinds open nothing on this host, and unit kinds stay
held for ten minutes after the witness last saw it. An upgrade or rollback run inside the window replaces the marker with its own for its
restarts and puts this one back afterwards while its end is still ahead. `--maint 0` ends any
marker, whoever wrote it. It takes no lock, so it works while a hung writer holds the state
lock. Exit `0` written or removed, `1` the marker could not be written, `64` a value outside 0
to 120 (`deploy/propolis-status.sh#status_maint`).

`--setup` says what reaches the operator and why, one item a line: the alias test pages (and the
shell messages of a later release) name this host by (record it; off a single box it warns that
a fallback alias cannot be told from other hosts') and that today's failure alerts name it by its
host name, with no channel line where neither has a target; the push target from
`/etc/propolis/propolis.env` (of the URL only its scheme and host, of the topic only its length,
of the token only whether it is set), the anonymous-read check made now (three GETs, four with a
token) with each status code and content type and the class it gives, what the token can read,
the gate, what the daemon and today's failure hook still reveal on a topic that does not refuse
anonymous reads, the heartbeat URL and VERIFIED. The gate governs only the test page and the
shell messages a later release adds, and the test page carries only the alias and the code in
every mode, so at `full` only those later messages may carry detail; today's failure hook and the
daemon are not gated. Wherever
the hook posts (its own reader finds a URL and a topic) over plain http, or to a topic not proven
to refuse anonymous reads, a `failures` line says that the gate does not apply to its alerts and
that each carries the host name, the failed unit and its last journal lines (over plain http in
clear, the token too). The check is made before the state lock is taken; the answer is then stored under the
lock as the witness stores it, and the id salt the fallback alias comes from is made if there is
none. Exit `0` only when the gate is `full`, `1` otherwise, `75` when the state lock was not free
within 10 s (`deploy/propolis-status.sh#status_setup`).

When the shell senders have no target but today's failure hook, which reads `propolis.env` with
a rule of its own (the last line that starts with `KEY=`), still finds a URL and a topic (a value
the shell senders ignore as invalid, or a later indented line the hook never sees), the target
line says that the hook still posts there (of the URL only its scheme and host, or that curl uses
plain http when it has no scheme) and names each setting with its fix, the gate line says the
shell senders push nothing, the walk's alert row warns that the hook still posts, and
`--test-page` says it sent nothing while the hook still posts. A push setting that the hook reads
otherwise than the shell senders do (an indented line, `KEY = value`, a trailing comment) is
named under the target line (`deploy/alert-lib.sh#pa_hook_differs`). The verified line ends with
the next step: type the code back after a page that went out while its code is under a day old,
what to fix after one that did not, the settings to set without a target (none is expected on a
collector unless the hook still posts), the setting to write plainly when the hook reads one
otherwise (an invalid URL or topic is given with its rule instead, and so is an invalid token
when nothing else is read otherwise), and
`Run: sudo propolis-status --test-page` for `never`, `expired`, a code over a day old and a
`changed` the hook reads the same way.

`--test-page` sends one test page, `<alias>: test page <CODE>` with the body `Type back on
<alias>: status --ack-test <CODE>`, at priority 3. Under the state lock it counts the page in the
send ledger (at most 3 in 24 hours, counting every page that was or may have been sent:
`sending`, `ok`, `perm:*` and `transient:*`, and `pending` only for the hook's 120 s, since the
hook claims a page as `sending` before it sends and an attempt still `pending` after that never
went out, `deploy/alert-lib.sh#pa_budget_admit`) and records a
fresh 6-hex code from `/dev/urandom` in `/var/lib/propolis/witness/testpage`, replacing any
earlier one; then it starts `propolis-alert@propolis-test-page-<CODE>.service`, so the page goes
out through the failure-alert unit. A page that arrives proves that unit, the network and the
target as the shell senders read it; VERIFIED also requires today's failure hook to read the same
target and token from `propolis.env`. The hook sends it only for the recorded code, while it waits
and for 10 minutes after it was asked for, and claims its ledger line and then the record
(`sending`) before the send, so a second start for the same code sends nothing and a page that
went out always counts toward the three; a page that cannot go out whatever the server would
answer (no target, no alias, no curl) is marked with that word and never claimed. When the hook sent the page it prints `sent test
page <CODE>: ok` with the next step, or `sent test page <CODE>; the result could not be recorded`
when the hook could not write its result (it was sent, or was being sent when the hook stopped).
When nothing was sent it prints one line that says so
and why: `test page not sent: curl is not installed here`, `... found no push target`, `... it
could not be put together` (no alias yet, or a value that cannot be sent safely), `... ran over 10
minutes after the page was asked for`, `... could not write its claim on the send ledger`, `not
sent: the failure-alert unit did not run, or could not write the page's record` (the unit's
journal says which) or `... found the state lock busy`; before the unit is started, `test page
not sent:` with the reason when the id salt or the state could not be written, the send ledger
could not be read or no code could be made; `test page budget spent (3 in 24 h): nothing sent; the next is
allowed at <HH:MM> UTC`, and without a target `no push target: nothing sent` (or, while today's
failure hook still posts, `no target the shell senders accept: nothing sent`). When the server
did not accept it, it prints `test page <CODE> not accepted by the server (<result>)` with a next
step (for a permanent refusal with status 401 or 403 the token and the topic's access, for
another `perm:*` the URL and the topic, for `transient:*` to try later) and that the page counted toward the three a
day. Exit `0` when the page went out (`ok`), `1` when it did not, when its result could not be
recorded, or when the budget is spent, `75` when the lock was busy
(`deploy/propolis-status.sh#status_test_page`). Apart from today's failure alerts, which the hook
sends as before, it is the only message the shell code of this release can send.

`--ack-test CODE` (6 characters, `0-9` and `a-f`, checked before anything is read) acknowledges
the waiting test page when `CODE` is its code, it went out (`ok`, or `sending` when its result
could not be recorded), and it is at most a day old; it prints `VERIFIED: the test page reached
you` when every rule of VERIFIED then holds, and otherwise `acknowledged; NOT VERIFIED (<word>)`
(for a setting today's failure hook reads otherwise, followed by its name, or by `the shell
senders ignore <KEY> as invalid; set <KEY> to <rule>` for one they ignore, and `see sudo
propolis-status --setup`), and exits `0`. The same code typed again prints `already acknowledged at <HH:MM> UTC` with
whether VERIFIED stands, changes nothing and exits `0`. Anything else prints `wrong or expired
code`, changes nothing and exits `1`; `75` when the lock was busy
(`deploy/propolis-status.sh#status_ack_test`).

The walk's `ALERTS` line also shows the gate (`gate full`, `gate pointer:<reason>` or `gate
none:notarget`) and when the anonymous-read check last ran, worked out from the answer the
witness stored, without a network request, and at its end `VERIFIED <dur> (shell)` or `NOT
VERIFIED (<word>)` (`deploy/alert-lib.sh#pa_verified`), with `daemon not verified` wherever the
daemon is enabled, and under it `the daemon loaded an older configuration: restart propolis to
apply it` when `propolis.env` changed after the running daemon started; its third line shows when the light and the hourly
pass of the witness last completed and, once a light pass has run, the heartbeat URL: `not set`,
`refused (not an https URL)`, or `set` with when it was last asked and the result, or last
skipped and why. The URL itself is never printed.

## Witness

```
sudo /usr/local/sbin/propolis-witness light    # one light pass, as propolis-witness@light.timer runs it
sudo /usr/local/sbin/propolis-witness hourly   # one hourly pass, as propolis-witness@hourly.timer runs it
```

The root witness's two passes, normally started only by their timers
(`deploy/propolis-witness@light.timer`, `deploy/propolis-witness@hourly.timer`). The hourly pass
runs the installed configuration check, records its findings, and sends three GET requests (four
with a token) to the configured ntfy server to see whether the alert topic can be read without
credentials; it also samples every store's free space and inodes with `df`, reads the database's
state in one read-only session through the daemon binary (and, once a day, the local data
directory as the `postgres` account), hashes the files that configure Propolis to record
changes not in force, and on a single box or control node reads whether the public push is
scheduled and keeping up with the feed and counts the backup sets. The light pass also lists the
gateway spool on a control node or gateway and reads the journal lines of the gateway, the shipper
and the off-host pull's forced command. Neither pass sends a message. Exit `0` after every pass that ran, whatever it found;
`2` an argument other than `light` or `hourly`; `3` the alert library is missing, not trusted,
fails to load or is older than the script needs (`deploy/witness.sh#hourly_pass`). What each
pass does: [health and observability](../operations/health-and-observability.md#witness).

## Migrations

There is no standalone migrate command in the shipped surface. The `propolis`
daemon applies all three migration histories against the one database at
startup, in order: core-scoring (`crates/core-scoring/migrations/`, 12 files),
review (`crates/review/migrations/`, 7 files), then fleet
(`crates/fleet/migrations/`, 1 file), each exiting `1` on failure
(`crates/propolis/src/main.rs#main`). Review and fleet each carry their own
migrator that renames its bookkeeping table (`review::migrator`, table
`_sqlx_migrations_review`, `crates/review/src/lib.rs#migrator`; `fleet::migrator`,
table `_sqlx_migrations_fleet`, `crates/fleet/src/lib.rs#migrator`) because all
three histories number from `0001`.
See [`../development/schema-and-migrations.md`](../development/schema-and-migrations.md)
and [`database.md`](database.md).

## Vendoring

All dependencies are vendored in-tree under `vendor/`. After adding or updating
a dependency:

> **Egress warning.** `cargo vendor` and any dependency add/update fetches from
> the network (crates.io). Do this on a workstation, not on the honeypot node.

```
cargo vendor                                  # re-materialize vendor/ from Cargo.lock
cargo build --release --locked                # MUST re-verify release after re-vendoring
```

The release build after re-vendoring is load-bearing: EOL normalization has
mangled vendored checksums before. See
[`dependencies.md`](dependencies.md).

## Deploy / install

> **Production warning.** The following touch a production host. Read
> [`../operations/installation.md`](../operations/installation.md) first. Build
> release binaries before running the installer.

```
sudo ./deploy/install.sh --dry-run    # prints every action, needs no privilege, touches nothing
sudo ./deploy/install.sh              # installs binaries + units; starts/enables NOTHING
```

`install.sh` provisions OS users (including the `propolis-watch` login for the live watcher),
directories, spool mountpoints, the release binaries (including `propolis-watch`), `propolis.service` + the 12 sensor units, and a logrotate config. It
does **not** start or enable any service, create/migrate the database, or put a value in
any operator-owned `/etc/propolis/*.env` file (provisioning creates them empty at `0600`); the one env file it generates with content is
the secret-free `fleet-listeners.env`
(`deploy/install.sh#This script does NOT`, `deploy/install.sh#fleet-listeners.env`). Starting a
service is a separate operator action taken only after populating the env files:

> **Production warning.** Enabling a unit starts a live honeypot and, if the
> corresponding subsystems are turned on, activates operator-gated egress paths.

```
sudo systemctl enable --now propolis.service      # example, per unit
```

The spool directories still need `noexec,nosuid,nodev` mounts added to
`/etc/fstab` by hand; the installer prints the exact lines and stops there
(`deploy/install.sh#NOT DONE BY THIS SCRIPT`). Verify with `findmnt <path>` that the mount
options are actually in effect.

## Operations

The `review` binary is the operator CLI for the review queue and vendor
submission history (`crates/review/src/cli.rs`). Queries are local; approvals
arm egress.

```
review list                       # every Pending queue entry, oldest-surfaced first
review history <ip>               # vendor submission history for an IP, most recent first
review approve <ip> --notes "..." # mark Approved
review reject  <ip> --notes "..." # never reported, not re-surfaced by a later scan
review snooze  <ip> --notes "..." # defer
review daemon                     # long-running: populate/withdraw queue + submit approved entries

review volume list                        # every Pending volume candidate, oldest-surfaced first
review volume decided                     # Approved and Rejected volume candidates, newest decision first
review volume approve <ip> --notes "..."  # publish in the retention feeds until reopened, delisted or lapsed; not reported to vendors
review volume reject  <ip> --notes "..."  # not published on volume, not offered again
review volume reopen  <ip>                # back to Pending; undoes an approval or a rejection
```

`review volume` decides the other queue: addresses with a thousand or more established TCP
events, which the retention feeds publish only once approved
(`crates/review/src/cli.rs#VolumeCommand`; rules in
[scoring-and-feed.md](scoring-and-feed.md#volume-review)). `review approve` and
`review volume approve` are different decisions on different tables, and each fails on an
address that is only in the other queue.

> **Egress warning.** `review volume approve <ip>` publishes the address in the retention
> feeds at the next feed build and reports it to nobody. `review approve <ip>` does not itself send anything, but
> the submission daemon (`review daemon`, or the review subsystem inside
> `propolis` when `review_enabled`) picks up Approved entries on its next poll
> and submits them to the configured abuse vendors (AbuseIPDB / DShield / OTX).
> These are outbound reports about third parties. They are opt-in and default
> off; see [`../security/outbound-controls.md`](../security/outbound-controls.md)
> and [`integrations.md`](integrations.md).

There is no `Makefile` or `justfile` in the repository.
