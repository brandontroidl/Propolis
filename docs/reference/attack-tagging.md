<!--
title: ATT&CK tagging reference
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-10-09
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
| `honeypot_file_download` on `ssh` or `telnet` | the URL the sensor resolved, or the command it could not | `download-event`, and the indicator rules over the URL |
| `honeypot_malware_upload` on any sensor but `adb` | the captured sample's SHA-256 | `upload-sample` |
| any event | its signal type | `brute-force-signal` |
| a captured text or binary artifact | the indicators the IOC extraction takes from it | the indicator rules, on the sample's campaign |

Other sensors log protocol commands (an SMTP `DATA`, a Redis `CONFIG`, an HTTP request line) in
the same event shape; those are not shell lines and are not read by the command rules. The `adb`
sensor's shell is Android's, which the Enterprise matrix does not cover, so its events are not
tagged.

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
`crates/review/src/attack/mod.rs#session_tags`. They are `Serialize`, so a JSON surface is one
`serde_json::to_value` away.

The console shows them in four places, all through `crates/console/src/routes/attack.rs`: an
"ATT&CK techniques" panel on the per-address page (`source_tags`, with each rule that tagged a
technique and the token it matched, at most three per technique); a chip per technique in the
header of each session card there (`session_tags`, for the newest 40 sessions that ran a command);
a chip row under each campaign on the campaign list (`campaign_tags`, four shown and a count of the
rest); and the same panel on a campaign's page. The chip is the technique id with its name and the
matrix release on hover. Tokens are attacker data and are shown as escaped text. A lookup that
fails names the panel in the page's degraded banner rather than showing "none tagged".
