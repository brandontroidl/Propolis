<!--
title: Campaigns and indicators
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-07
-->

# Campaigns and indicators

A worm that copies itself, a script run unchanged from fifty addresses and a scanner that touches
every service each produce dozens of separate IP timelines. A **campaign** is one row for all of
them: the addresses (its members), when they were seen, which sensors they reached, and what they
ran or dropped. **Indicators** are what their artifacts and commands name: URLs, keys, persistence
lines, IRC servers. Both are derived from the ledger by the campaign indexer and shown on the
console. Neither is published to the feed or sent to a vendor.

## The three rules

Cheapest first; an address can be a member of several campaigns.

| Rule (`campaign.kind`) | Members | Key |
|---|---|---|
| Same sample (`sample`) | every address that uploaded the captured sample, or reported a URL the fetcher retrieved it from | the sample's SHA-256 |
| Same commands (`command_sequence`) | every address that ran a shell session whose command run has the same fingerprint | the fingerprint |
| Multi-service scan (`scanner`) | every address that reached 3 distinct sensors within one clock hour | the first 3 sensors it reached in that hour, sorted |

**Fingerprint.** Each command is reduced to a shape: escape runs, long hex and base64 runs and
whitespace runs replaced the way the sensors' flood gate does it, then IPv4 and bracketed IPv6
addresses become `<ip>` and a port after an address or host name becomes `<port>`
(`crates/review/src/campaign/fingerprint.rs#normalize`). Consecutive repeats collapse, so an echo
loader's chunk count, a `cat > astats` retried three times, or the repeats the flood gate
summarized away do not split one tool into several campaigns. The fingerprint is a running SHA-256
over the collapsed shapes (`crates/review/src/campaign/fingerprint.rs#RunDigest`).

**Runs.** A session's run ends at a gap of more than 10 minutes between two of its own commands
(`crates/review/src/campaign/mod.rs#SESSION_IDLE_SECS`), once its sensor has logged events an hour
newer than its last command (`crates/review/src/campaign/mod.rs#SESSION_SWEEP_SECS`), or at 64
collapsed shapes (`crates/review/src/campaign/mod.rs#MAX_RUN_SHAPES`). A run whose shapes total
fewer than 20 characters, a bare `enable; system; shell; sh`, joins nothing
(`crates/review/src/campaign/mod.rs#MIN_RUN_CHARS`). Samples a session uploads are linked to the
campaign its run joins.

**Labels.** A campaign's label and representative come from the lowest event id that formed it: a
sample's digest and file name, a command sequence's first three shapes after the shell-entry
preamble with the full shape list, or a scanner's sensor set.

## How it runs

The `campaigns` subsystem of the daemon runs `run_tick`
(`crates/review/src/campaign/mod.rs#run_tick`) every 15 seconds, and every half second while it
works through a backlog (`crates/propolis/src/main.rs#CAMPAIGN_TICK_INTERVAL`). A tick:

1. folds up to 25 batches of 2,000 ledger rows past its cursor into the campaign tables, one
   transaction per batch that also moves the cursor
   (`crates/review/src/campaign/mod.rs#index_batch`);
2. links downloads whose fetch had no outcome yet to the sample the fetcher later captured from
   the URL, and drops links whose fetch failed for good or that waited more than 7 days
   (`crates/review/src/campaign/mod.rs#resolve_pending_fetches`);
3. extracts indicators from up to 16 captured artifacts
   (`crates/review/src/campaign/mod.rs#scan_artifacts`);
4. drops closed sessions and scanner windows two days behind their sensor's clock
   (`crates/review/src/campaign/mod.rs#prune`).

Nothing runs on the append path, and no step reads an address's history: a batch touches the
rows its events name. An advisory lock keeps two nodes sharing a database from indexing at once.
Tables and columns: [database reference](../reference/database.md#campaign-tables).

Indexing a ledger batch by batch, interleaved with appends, leaves the same state as one pass over
the same ledger; `crates/review/tests/campaign_test.rs#incremental_indexing_equals_one_pass_over_the_same_ledger`
holds that over generated ledgers, and checks the sample and scanner memberships against the
ledger by a second method.

### Measured cost

On a disposable database holding a synthetic 1,000,000-row ledger (a development machine also
running other test suites, so the figures are indicative):

| Measurement | Result |
|---|---|
| Catch-up rate | 5,800 to 6,500 events per second, about 21 minutes for a 7.5M-row ledger |
| Append latency, no indexer | mean 3.3 to 3.5 ms (p50 3.1 to 3.3 ms) over six runs of 2,000 appends |
| Append latency, indexer polling | mean 3.5 ms (p50 3.3 ms), within 1% of the run without it |
| Append latency, during a full catch-up | mean 3.8 ms (p50 3.4 ms), 7 to 14% above the run without it |

`crates/review/examples/campaign_catchup.rs` runs a catch-up and prints its rate; run it next to
`crates/intake/examples/append_bench.rs` against a scratch database to repeat the measurement.

### Rebuilding

The campaign tables are derived state. To rebuild them, stop the daemon, empty them and set
`campaign_cursor.last_event_id` to 0; on the next start the indexer reads the whole ledger again.

## On the console

- **Campaigns** (top navigation): every campaign with its rule, host count, distinct hosts per
  day over 14 days, first and last seen, top sensors and linked samples, filterable by rule, and
  the indexer's lag behind the ledger when it has one.
- **A campaign's page**: members with their review state, the representative session's normalized
  commands or the representative sample, linked samples, and indicators with their provenance.
- **Review queue**: a pending row in a campaign says "part of campaign N, M hosts" and links to
  approving the campaign's pending members.
- **IP page** and **Samples page**: the campaigns an address or a sample belongs to; each sample
  has its own page with its indicators.

Approving a campaign is two steps. The confirmation page lists exactly the pending members it will
approve and changes nothing; its form carries that list, and the approval applies to the listed
addresses that are still pending members, through the same `ReviewQueue::approve` call as the
per-row button (`crates/console/src/routes/campaigns.rs#approve_members`). A member that became
pending after the confirmation was shown is not approved. At most 1,000 are approved at once.

### Infected hosts

A sample campaign whose script carries both a scanner (`zmap`, `masscan`, `pnscan`) and a way to
copy itself (`sshpass`, `scp`) is marked self-propagating
(`crates/review/src/ioc.rs#self_propagating`), and its members are shown as **infected host**
rather than attacker (`crates/console/src/routes/campaigns.rs#member_role`). This is console
metadata only: vendor submission text does not use it yet `[planned]`, and that wording is a
separate decision.

## Indicators

Extracted from every command line, every download URL, and every captured artifact
(`crates/review/src/ioc.rs#extract`):

| Kind | What is recognized | Stored value |
|---|---|---|
| `url` | http, https and tftp URLs, resolved the way the fetcher reads droppers | the URL; detail host and port |
| `endpoint` | `/dev/tcp/HOST/PORT` and `/dev/udp/...` | `HOST:PORT` |
| `ssh_key` | an OpenSSH public key whose blob names its own type | `SHA256:` fingerprint as `ssh-keygen -l` prints it; detail type and comment |
| `rsa_key` | a PEM `PUBLIC KEY` or `RSA PUBLIC KEY` block | `SHA256:` of the DER |
| `password_hash` | `$1$`, `$5$`, `$6$`, bcrypt and yescrypt crypt strings | a marker only: the scheme and 16 hex digits of the SHA-256 of the crypt string, never the hash |
| `irc_server`, `irc_channel` | in IRC-speaking text, `irc.` hosts, hosts on IRC ports, channels after `JOIN` or assigned to a `chan` variable | the host, the channel |
| `hosts_entry` | an address and host name on a line writing `/etc/hosts` | `ADDRESS HOST` |
| `persistence` | cron entries and writes to `/etc/crontab`, `/etc/cron.d` or the cron spool; systemd units, `systemctl enable` names and `ExecStart=` lines (also inside a printf-built unit); writes to `/etc/rc.local`; lines creating or removing `/etc/init.d` scripts; lines appended to `.bashrc`, `.profile`, `.bash_profile` or `/etc/profile`; `chattr +i` on a file; and the drop path such a line starts, or a `cp`, `mv` or `install` puts a file at under `/var/tmp`, `/tmp`, `/dev/shm`, `/usr/lib` or a system binary directory | the line or name; detail `cron`, `systemd`, `rc.local`, `init.d`, `shell profile`, `chattr` or `drop path` |
| `proxy` | in text that mentions a proxy or carries an HTTP `CONNECT` request: the `CONNECT` template, a `Proxy-Authorization` template, and host names that name a proxy gateway (`proxy`, `gw`, `gate`, `tunnel`, `socks`, with an alphabetic top-level label that is not a file extension) | the template, or `HOST[:PORT]` |
| `credentials` | a literal `Proxy-Authorization` value, `user:pass@host` before a proxy host, or user information in a URL | only how the credential was carried; the value is never stored, and every other value has such user information and `Authorization` values replaced by `<redacted>` (`crates/review/src/ioc.rs#redact_secrets`) |

A captured artifact that is small UTF-8 text is scanned whole. Anything else, a compiled bot
included, is scanned through its printable strings the way `strings -a` lists them: runs of at
least 6 printable bytes from the first 8 MiB, at most 256 KiB of them
(`crates/review/src/ioc.rs#printable_strings`). A binary's persistence templates, such as an
rc.local `sed` line or an `/etc/init.d/%s` script with `%s` where it fills in its own name, are
kept as written.

Each indicator carries its provenance: the artifact's digest, or the address and the first event
id that carried it. Limits: 64 indicators per artifact, 16 per command, 256 command indicators per
address. Every value and detail passes the sensors' sanitizer and a byte cap (256 and 128 bytes)
before it is stored (`crates/review/src/ioc.rs#sanitize_field`), and the console renders them as
escaped text, never as a link. Indicators are not published to the feed or to vendors; that is a
separate decision.

## Limits

- A session whose later commands the sensor's flood gate summarized has a shorter run than an
  unsummarized one when the summarized commands were new shapes; repeats are not affected.
- A quiet sensor's last sessions are grouped when it next logs anything an hour past them.
- A node feeding a sensor name while lagging another node by most of an hour can have a run cut
  short by the sweep, so the same session lands in a different campaign than one pass would put it.
- A scanner campaign is keyed by the first three sensors an address reached in its window, so
  one tool that sweeps services in a random order shows as several scanner campaigns, one per
  combination it happened to start with.
- A campaign page lists the command indicators of its 2,000 most recent members, one row per
  indicator with the number of members that carried it.
- Commands without a `session_id` (events from before session ids existed) form no command
  sequences.
- A catch-up after an upgrade reads the whole ledger once; the console shows how far it has got.
