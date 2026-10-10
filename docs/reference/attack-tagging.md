<!--
title: ATT&CK tagging reference
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-10
-->

# ATT&CK tagging reference

Canonical owner of the rules that label observed attacker behavior with MITRE ATT&CK technique
ids. A tag is a fixed rule matched against exact evidence in one ledger event. It is not a score
and not a model, it is never published to the feed, and it is never sent to a vendor. Every tag
carries the rule that produced it, the event it came from and the token that matched.

**Matrix version.** Technique ids and names were checked on 2026-10-09 against the ATT&CK
Enterprise matrix, release **v19.2** (2026-04-28, the current release at that date), on
attack.mitre.org. v19 reorganized Impair Defenses: T1562 and T1562.001 now redirect to **T1685
Disable or Modify Tools**, and the firewall sub-technique is **T1686 Disable or Modify System
Firewall**, so those two are the ids used here. The version is stored in code as
`crates/review/src/attack/rules.rs#MATRIX_VERSION` and is returned with every tag read back.
Re-check the ids when the matrix releases.

## What is read

The [campaign indexer](../operations/campaigns.md) calls the rules for each event it already
reads (`crates/review/src/campaign/mod.rs#Batch`):

| event | read as | rules |
|---|---|---|
| `honeypot_command_exec` on `ssh` or `telnet` (the `command_decoded` text when present) | a shell line, parsed into commands | the command rules, and the indicator rules over the indicators the IOC extraction takes from the line |
| `honeypot_command_exec` on `postgresql`, `mysql` or `mssql` (the `command` text) | SQL, parsed into statements and tokens | the SQL rules (`sql-*`) |
| `honeypot_command_exec` on `redis` (the `command`, `param`, `value` and `args` fields) | a structured Redis command | the Redis rules (`redis-*`) |
| `honeypot_file_download` on `ssh` or `telnet` | the URL the sensor resolved, or the command it could not | `download-event`, and the indicator rules over the URL |
| `honeypot_malware_upload` on any sensor but `adb` | the captured sample's SHA-256 | `upload-sample` |
| any event | its signal type | `brute-force-signal` |
| a captured text or binary artifact | the indicators the IOC extraction takes from it | the indicator rules, on the sample's campaign |

Other sensors log protocol commands (an SMTP `DATA`, an HTTP request line) in the same event
shape; those are not shell lines and are not read by the command rules. The `adb` sensor's shell
is Android's, which the Enterprise matrix does not cover, so its events are not tagged.

**Which database sensors record commands.** Today only `postgresql` (every simple query, as
`command`) and `redis` (`CONFIG SET dir|dbfilename`, `SET`, `SLAVEOF`/`REPLICAOF`, `EVAL`,
`SCRIPT`) emit `honeypot_command_exec`. The `mysql` and `mssql` sensors answer the login and
record nothing after it, and `mongodb` and `vnc` likewise. MySQL and SQL Server syntax is
therefore tagged only when a scanner sends it to the `postgresql` sensor, which reads it as
PostgreSQL, until those sensors record queries; their names are already in
`crates/review/src/attack/rules.rs#SQL_SENSORS` so their text is read in its own dialect the day
they do. Redis never records `SAVE`, so the Redis file-write rules read the `CONFIG SET` that
points the save directory or file at the target and cannot see the save itself.

## How SQL is read

`crates/review/src/attack/sql.rs#parse` cuts the text into statements at `;` and into tokens:
words (lowercased, so matching is case-insensitive), quoted identifiers, string literals,
numbers and punctuation. Comments are dropped, and the content of a string literal or quoted
identifier is never a word, so `SELECT 'DROP USER x'`, `-- GRANT ALL TO x` and a table or column
named `program` or `xp_cmdshell_log` hold no keyword. A rule compares whole tokens at known
positions, never substrings. The dialect comes from the sensor: MySQL reads `"` as a string
quote, `\` as an escape, `#` as a comment and runs the body of `/*! ... */`; PostgreSQL reads
`$tag$ ... $tag$` and `E'...'` strings and nested `/* */` comments; SQL Server reads `[name]`.
Dynamic SQL inside a string (`EXEC('xp_cmdshell ...')`) is a literal and is not read. The
sensors fold line breaks into spaces, so a `--` comment hides the rest of the statement, as it
does when the server reads it that way.

**Matched tokens never hold a literal.** Every SQL token is built from fixed keywords and
function names (`ALTER USER PASSWORD`, `xp_cmdshell`), never from a string literal, an account
name or a path, so a password in the statement cannot reach a stored tag. The token still goes
through the same redaction, sanitizing and 256-byte cap as every other.

## How a command line is read

`crates/review/src/attack/parse.rs#parse` splits a line into commands at `;`, `&&`, `||`, `|`,
`&`, newlines, parentheses and backticks, honours quotes and backslashes, collects redirection
targets, drops leading `NAME=value` assignments and wrappers (`sudo`, `busybox`, `nohup`, `env`
and similar), and reads the script of `sh -c` and `eval` (to three levels) as lines of their
own. Command substitution is read as commands of the line. A rule looks at a command's name,
operands and redirection targets, never at a substring of the line, so `echo crontab` and a URL
containing `cron` match nothing, and a read of a file (`cat /etc/crontab`) is not a write to it.
Nothing is expanded or run: a `$VAR` stays the word `$VAR`.

## Rules

`crates/review/src/attack/rules.rs#RULES` is the only rule list; a test fails when this table
and that list disagree on a rule id or its technique.

| rule | technique | condition | matched token |
|---|---|---|---|
| `brute-force-signal` | T1110 Brute Force | an event whose signal type is `ssh_brute_force` | `ssh_brute_force` |
| `download-event` | T1105 Ingress Tool Transfer | a `honeypot_file_download` event | its URL, or the first word of its command |
| `download-command` | T1105 Ingress Tool Transfer | `wget` or `curl` given a URL operand (`curl` without `-T`, `--upload-file`, `-d`, `--data*`, `-F`, `--form`), `tftp -g`, or `ftpget` with two operands | the URL, `tftp -g` or `ftpget` |
| `upload-sample` | T1105 Ingress Tool Transfer | a `honeypot_malware_upload` event | the sample's SHA-256 |
| `unix-shell` | T1059.004 Command and Scripting Interpreter: Unix Shell | `sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, `mksh`, `csh` or `tcsh` in command position | the shell's name |
| `cron-install` | T1053.003 Scheduled Task/Job: Cron | `crontab` given `-` or a file (not `-l`, `-r` or `-e`), or a write to `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/` or `/var/spool/cron/` | `crontab` or the path written |
| `systemd-unit` | T1543.002 Create or Modify System Process: Systemd Service | a write to a `.service` file under `/etc/systemd/system/`, `/lib/systemd/system/`, `/usr/lib/systemd/system/`, `/run/systemd/system/`, `/etc/systemd/user/` or `.config/systemd/user/`, or `systemctl enable UNIT` | the path, or `systemctl enable UNIT` |
| `rc-script` | T1037.004 Boot or Logon Initialization Scripts: RC Scripts | a write to `rc.local` or `rc.common` under `/etc/` (including `/etc/rc.d/`), or to `/etc/rc.local.d/local.sh` | the path written |
| `authorized-keys` | T1098.004 Account Manipulation: SSH Authorized Keys | a write to a file named `authorized_keys` or `authorized_keys2` | the path written |
| `system-info` | T1082 System Information Discovery | `uname`, `nproc`, `lscpu` or `hostnamectl`; or `cat`, `grep`, `head`, `tail`, `less`, `more`, `awk`, `sed`, `wc`, `cut`, `sort` or `strings` reading `/proc/cpuinfo`, `/proc/meminfo`, `/proc/version`, `/etc/os-release`, `/etc/lsb-release` or `/etc/issue` | the command or the file |
| `file-discovery` | T1083 File and Directory Discovery | `ls`, `dir`, `vdir`, `find`, `locate` or `tree` in command position | the command |
| `process-discovery` | T1057 Process Discovery | `ps`, `top`, `htop`, `pgrep`, `pidof` or `pstree` in command position | the command |
| `permissions` | T1222.002 File and Directory Permissions Modification: Linux and Mac Permissions | `chmod` or `chown` with at least one operand | the command and its first operand |
| `file-deletion` | T1070.004 Indicator Removal: File Deletion | `rm`, `unlink` or `shred` with at least one operand | the command and its first operand |
| `miner-script` | T1496.001 Resource Hijacking: Compute Hijacking | a `url` indicator the IOC extraction labels `CoinHive miner script` | the script URL |
| `miner-configured` | T1496.001 Resource Hijacking: Compute Hijacking | the `credentials` indicator `CoinHive site key`, raised for a `CoinHive.Anonymous(` or `CoinHive.User(` call | `CoinHive site key` |
| `firewall-disable` | T1686 Disable or Modify System Firewall | `iptables` or `ip6tables` with `-F` or `--flush`; `nft flush ruleset`; `ufw disable`; `stop`, `disable` or `mask` of `firewalld`, `ufw`, `iptables`, `ip6tables`, `nftables` or `SuSEfirewall2` through `systemctl`, `service` or `/etc/init.d/` | the command |
| `security-tool-kill` | T1685 Disable or Modify Tools | `pkill` or `killall` naming, or `stop`, `disable` or `mask` of, one of `auditd`, `falco`, `osqueryd`, `rsyslog`, `systemd-journald`, `apparmor`, `fail2ban`, `fail2ban-server`, `clamd`, `wazuh-agent`, `aegis`, `AliYunDun`, `AliYunDunUpdate`, `aliyun-service`, `YunJing`, `cloudmonitor` or `bcm-agent` | the command and the tool |
| `sql-account-password` | T1098 Account Manipulation | `ALTER USER`, `ALTER ROLE` or `ALTER LOGIN` given `PASSWORD 'x'`, `PASSWORD = 'x'`, `PASSWORD NULL` or `IDENTIFIED BY\|WITH`; `SET PASSWORD`; `sp_password` | `ALTER USER PASSWORD` (or `ROLE`, `LOGIN`), `SET PASSWORD`, `sp_password` |
| `sql-privilege-change` | T1098 Account Manipulation | `GRANT ... TO`; `ALTER USER` or `ROLE` with `SUPERUSER`; `ALTER SERVER ROLE ... ADD MEMBER`; `sp_addsrvrolemember` or `sp_addrolemember` | `GRANT`, `ALTER USER SUPERUSER`, `ALTER SERVER ROLE ADD MEMBER` or the procedure |
| `sql-account-create` | T1136 Create Account | `CREATE USER` (not `USER MAPPING`) or `CREATE LOGIN`; `CREATE ROLE` with `LOGIN` or `SUPERUSER` (a role without them is a group); `sp_addlogin` | `CREATE USER`, `CREATE LOGIN`, `CREATE ROLE LOGIN`, `CREATE ROLE SUPERUSER` or `sp_addlogin` |
| `sql-os-command` | T1059 Command and Scripting Interpreter | `COPY ... PROGRAM 'command'`; the word `xp_cmdshell`, or `sp_configure` naming it; a call to `sys_exec`, `sys_eval` or `sys_bineval`; `CREATE FUNCTION ... SONAME` | `COPY PROGRAM`, `xp_cmdshell`, `sp_configure xp_cmdshell`, the function, or `CREATE FUNCTION SONAME` |
| `sql-version-discovery` | T1082 System Information Discovery | a call to `version()` with no arguments; the variable `@@version` or `@@version_comment`; `SHOW server_version` | `version()`, the variable, or `SHOW server_version` |
| `sql-user-discovery` | T1033 System Owner/User Discovery | a `SELECT` whose list (before `FROM`) holds `current_user`, `session_user` or `system_user`, a call to `user_name`, `suser_name`, `suser_sname` or `user`, or is the statement `SELECT user` | the word, with `()` for a call |
| `sql-file-read` | T1005 Data from Local System | a call to `pg_read_file`, `pg_read_binary_file`, `lo_import` or `load_file`; `COPY ... FROM 'file'`; `LOAD DATA ... INFILE`; `OPENROWSET(BULK` | the function, `COPY FROM file`, `LOAD DATA INFILE` or `OPENROWSET BULK` |
| `redis-config-cron` | T1053.003 Scheduled Task/Job: Cron | `CONFIG SET dir` to `/var/spool/cron`, `/etc/cron.d`, `/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly` or `/etc/cron.monthly`, or a directory under one | `CONFIG SET dir` |
| `redis-config-authkeys` | T1098.004 Account Manipulation: SSH Authorized Keys | `CONFIG SET dir` to a directory named `.ssh`, or `CONFIG SET dbfilename` to `authorized_keys` or `authorized_keys2` | `CONFIG SET dir` or `CONFIG SET dbfilename` |
| `redis-replicaof` | T1105 Ingress Tool Transfer | `SLAVEOF` or `REPLICAOF` given a host (not `NO ONE`): the rogue-master module load, in which the attacker's server sends the payload during replication | `SLAVEOF` or `REPLICAOF` |

The ids the SQL and Redis rules use were re-checked on 2026-10-10 on attack.mitre.org against the
release it showed as current, v19.2: T1098 Account Manipulation (Persistence, Privilege
Escalation; its procedure examples include an MS-SQL `sp_addlinkedsrvlogin` command), T1136
Create Account (Persistence), T1059 Command and Scripting Interpreter (Execution), T1082 System
Information Discovery and T1033 System Owner/User Discovery (Discovery), T1005 Data from Local
System (Collection), and T1105, T1053.003 and T1098.004 as above. The parent technique is used
for T1098, T1136 and T1059 because none of their sub-techniques is a database account or a
database-launched command.

A matched token is attacker data. It is redacted of URL credentials and authorization values,
sanitized and cut to 256 bytes (`crates/review/src/attack/mod.rs#clean`), and a consumer shows it
as escaped text, never as a link.

## Considered and not tagged

- **T1078 Valid Accounts on success.** Every sensor that takes a login accepts any credential by
  design, so a successful login is not evidence that the account was valid.
- **T1110.001 Password Guessing.** Sensors never store a password (it is read only to advance the
  protocol), so guessing cannot be told from a single attempt. `honeypot_login_attempt` events
  carry a username and nothing more. T1110 is tagged only from the `ssh_brute_force` signal,
  which a classifier outside the sensors raises.
- **T1037.004 for `/etc/init.d/` scripts.** The technique's description names `rc.local` and
  `rc.common`, not init scripts.
- **`chgrp`, `chattr` for T1222.002.** The description of the sub-technique names `chmod` and
  `chown`.
- **Execution of a file the attacker dropped (`./x`).** Running a binary is not, on its own, a
  shell interpreter; the download, `chmod` and `rm` around it are tagged.
- **SQL file writes** (`lo_export`, `COPY ... TO 'file'`, `INTO OUTFILE|DUMPFILE`). Writing a
  file is not Ingress Tool Transfer, and the statement does not say whether the content is a web
  shell, a cron entry or a dump, so no technique fits without guessing. The reads are tagged
  (`sql-file-read`).
- **Database log tampering** (`SET sql_log_bin = 0`, `ALTER SERVER AUDIT ... STATE = OFF`,
  `ALTER SYSTEM SET log_statement`). v19's Disable or Modify Tools (T1685) has sub-techniques for
  the Windows event log, cloud logs and the Linux audit log, none of them a database's own audit
  or query log, and the parent text is about security tooling and event log configuration.
- **Account discovery in SQL** (`SELECT ... FROM pg_user|pg_shadow|mysql.user`). Not requested
  and not yet judged against T1087; recorded as a candidate.
- **Redis `SAVE`, `SET`, `EVAL` and `SCRIPT`.** `SAVE` is never recorded, a `SET` value is
  free-form data, and the Lua body of `EVAL` is not run or classified.
- **MySQL and SQL Server statements on their own sensors.** Those sensors record no statements
  (see above), so the rules are exercised only through the `postgresql` sensor.
- **Obfuscated lines.** A command assembled from base64 or hex, or passed through a variable, is
  tagged only for the parts that appear as words.

## Where tags are stored and read

Migration `0017` adds `attack_tag` (per source and session) and `campaign_attack_tag` (per
campaign), and `campaign_session.attack_pending`
([database reference](database.md#attack-tag-tables)). A shell run keeps its tags until it joins
a command-sequence campaign, the way it keeps its uploaded samples
(`crates/review/src/campaign/mod.rs#merge_pending`); a campaign then carries the union of its
runs' tags, one row per rule, with the lowest event id that satisfied it. A sample campaign is
tagged by how its sample arrived and by the indicators its text carried. A scanner campaign has no
shell session and carries no tags.

Tags exist for events the indexer reads after migration `0017`. There is no backfill; the full
rebuild in [campaigns](../operations/campaigns.md#rebuilding) also repopulates them.

Read-side calls, all returning techniques ordered by id with the matrix version and the evidence
per rule: `crates/review/src/attack/mod.rs#campaign_tags`,
`crates/review/src/attack/mod.rs#source_tags` and
`crates/review/src/attack/mod.rs#session_tags`. Each takes a list of ids and answers them in one
query, returning a map by id (a session id is the UUID text the pages carry). They are
`Serialize`, so a JSON surface is one `serde_json::to_value` away.

The console shows them in four places, all through `crates/console/src/routes/attack.rs`: an
"ATT&CK techniques" panel on the per-address page (`source_tags`, with each rule that tagged a
technique and the token it matched, at most three per technique); a chip per technique in the
header of each session card there (`session_tags`, one query for every session on the page that ran a command);
a chip row under each campaign on the campaign list (`campaign_tags`, four shown and a count of the
rest); and the same panel on a campaign's page. The chip is the technique id with its name and the
matrix release on hover. Tokens are attacker data and are shown as escaped text. A lookup that
fails names the panel in the page's degraded banner rather than showing "none tagged".
