//! The rule table: every ATT&CK technique this build tags, the exact condition for it, and the
//! token that satisfied it. One row per rule; [`RULES`] is the only list, and the reference page
//! (`docs/reference/attack-tagging.md`) is checked against it.
//!
//! A rule reads structure, never substrings: a shell line is parsed into commands
//! (`super::parse`) and a rule looks at a command's name, its operands and its redirection
//! targets, so `echo crontab` and a URL containing `cron` match nothing. A rule names the evidence
//! it needs; where the ledger cannot supply it, there is no rule (see the reference page for the
//! techniques considered and left out).

use serde_json::Value;

use super::parse::{Simple, is_shell};
use super::sql::Tok;
use crate::ioc::{Indicator, IocKind, MINER_SCRIPT_DETAIL, MINER_SITE_KEY};

/// A Redis command as the redis sensor records it: structured fields, not a text line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedisCommand {
    /// The command name as the sensor logs it: `CONFIG SET`, `SLAVEOF`, `REPLICAOF`, `SET`, ...
    pub command: String,
    /// `param` of a `CONFIG SET`.
    pub param: Option<String>,
    /// `value` of a `CONFIG SET`.
    pub value: Option<String>,
    /// `args` of `SLAVEOF`, `REPLICAOF`, `EVAL` and `SCRIPT`.
    pub args: Vec<String>,
}

impl RedisCommand {
    /// The command of a `honeypot_command_exec` event's metadata, or `None` when it names none.
    pub fn from_metadata(metadata: &Value) -> Option<Self> {
        let text = |k: &str| metadata.get(k).and_then(Value::as_str).map(str::to_string);
        Some(RedisCommand {
            command: text("command")?,
            param: text("param"),
            value: text("value"),
            args: metadata
                .get("args")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

/// What a rule is shown evidence of.
pub enum Input<'a> {
    /// One statement of SQL a database sensor captured.
    Sql(&'a [Tok]),
    /// One command a redis sensor recorded.
    Redis(&'a RedisCommand),
    /// One command parsed from a shell command line.
    Command(&'a Simple),
    /// A `honeypot_file_download` event: the URL the sensor resolved, or the unparsed command.
    Download {
        url: Option<&'a str>,
        command: Option<&'a str>,
    },
    /// A `honeypot_malware_upload` event: the captured sample's SHA-256.
    Upload { sha256: &'a str },
    /// The `signal_type` of an event.
    Signal(&'a str),
    /// An indicator the IOC extraction took from a command, a URL or a captured artifact.
    Indicator(&'a Indicator),
}

/// Which kind of evidence a rule reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Sql,
    Redis,
    Command,
    Download,
    Upload,
    Signal,
    Indicator,
}

pub struct Rule {
    /// Stable identifier, stored with every tag.
    pub id: &'static str,
    pub technique: &'static str,
    pub technique_name: &'static str,
    pub scope: Scope,
    /// The condition, in a sentence, for the reference page and the console.
    pub condition: &'static str,
    /// The matched token, or `None` when the evidence does not satisfy the rule.
    pub eval: fn(&Input) -> Option<String>,
}

/// The ATT&CK Enterprise release the technique ids and names were checked against (2026-10-09,
/// attack.mitre.org). v19 moved Impair Defenses (T1562) to T1685 and T1686.
pub const MATRIX_VERSION: &str = "v19.2";

pub const RULES: [Rule; 28] = [
    Rule {
        id: "brute-force-signal",
        technique: "T1110",
        technique_name: "Brute Force",
        scope: Scope::Signal,
        condition: "an event whose signal type is ssh_brute_force",
        eval: brute_force_signal,
    },
    Rule {
        id: "download-event",
        technique: "T1105",
        technique_name: "Ingress Tool Transfer",
        scope: Scope::Download,
        condition: "a honeypot_file_download event from a shell sensor; the token is its URL",
        eval: download_event,
    },
    Rule {
        id: "download-command",
        technique: "T1105",
        technique_name: "Ingress Tool Transfer",
        scope: Scope::Command,
        condition: "wget or curl given a URL operand (curl without an upload or data flag), tftp -g, or ftpget with two operands",
        eval: download_command,
    },
    Rule {
        id: "upload-sample",
        technique: "T1105",
        technique_name: "Ingress Tool Transfer",
        scope: Scope::Upload,
        condition: "a honeypot_malware_upload event; the token is the captured sample's SHA-256",
        eval: upload_sample,
    },
    Rule {
        id: "unix-shell",
        technique: "T1059.004",
        technique_name: "Command and Scripting Interpreter: Unix Shell",
        scope: Scope::Command,
        condition: "a shell interpreter (sh, bash, dash, ash, zsh, ksh, mksh, csh, tcsh) in command position",
        eval: unix_shell,
    },
    Rule {
        id: "cron-install",
        technique: "T1053.003",
        technique_name: "Scheduled Task/Job: Cron",
        scope: Scope::Command,
        condition: "crontab given - or a file (not -l, -r, -e), or a write to /etc/crontab, /etc/cron.d/, /etc/cron.{hourly,daily,weekly,monthly}/ or /var/spool/cron/",
        eval: cron_install,
    },
    Rule {
        id: "systemd-unit",
        technique: "T1543.002",
        technique_name: "Create or Modify System Process: Systemd Service",
        scope: Scope::Command,
        condition: "a write to a .service file in a systemd unit directory, or systemctl enable UNIT",
        eval: systemd_unit,
    },
    Rule {
        id: "rc-script",
        technique: "T1037.004",
        technique_name: "Boot or Logon Initialization Scripts: RC Scripts",
        scope: Scope::Command,
        condition: "a write to /etc/rc.local, /etc/rc.common (or a copy of either under /etc/rc.d/) or /etc/rc.local.d/local.sh",
        eval: rc_script,
    },
    Rule {
        id: "authorized-keys",
        technique: "T1098.004",
        technique_name: "Account Manipulation: SSH Authorized Keys",
        scope: Scope::Command,
        condition: "a write to a file named authorized_keys or authorized_keys2",
        eval: authorized_keys,
    },
    Rule {
        id: "system-info",
        technique: "T1082",
        technique_name: "System Information Discovery",
        scope: Scope::Command,
        condition: "uname, nproc, lscpu or hostnamectl; or cat, grep, head, tail, less, more, awk, sed, wc, cut, sort or strings reading /proc/cpuinfo, /proc/meminfo, /proc/version, /etc/os-release, /etc/lsb-release or /etc/issue",
        eval: system_info,
    },
    Rule {
        id: "file-discovery",
        technique: "T1083",
        technique_name: "File and Directory Discovery",
        scope: Scope::Command,
        condition: "ls, dir, vdir, find, locate or tree in command position",
        eval: file_discovery,
    },
    Rule {
        id: "process-discovery",
        technique: "T1057",
        technique_name: "Process Discovery",
        scope: Scope::Command,
        condition: "ps, top, htop, pgrep, pidof or pstree in command position",
        eval: process_discovery,
    },
    Rule {
        id: "permissions",
        technique: "T1222.002",
        technique_name: "File and Directory Permissions Modification: Linux and Mac Permissions",
        scope: Scope::Command,
        condition: "chmod or chown with at least one operand",
        eval: permissions,
    },
    Rule {
        id: "file-deletion",
        technique: "T1070.004",
        technique_name: "Indicator Removal: File Deletion",
        scope: Scope::Command,
        condition: "rm, unlink or shred with at least one operand",
        eval: file_deletion,
    },
    Rule {
        id: "miner-script",
        technique: "T1496.001",
        technique_name: "Resource Hijacking: Compute Hijacking",
        scope: Scope::Indicator,
        condition: "a url indicator the IOC extraction labels a CoinHive-family miner script",
        eval: miner_script,
    },
    Rule {
        id: "miner-configured",
        technique: "T1496.001",
        technique_name: "Resource Hijacking: Compute Hijacking",
        scope: Scope::Indicator,
        condition: "the credentials indicator the IOC extraction raises for a CoinHive.Anonymous( or CoinHive.User( call",
        eval: miner_configured,
    },
    Rule {
        id: "firewall-disable",
        technique: "T1686",
        technique_name: "Disable or Modify System Firewall",
        scope: Scope::Command,
        condition: "iptables or ip6tables with -F or --flush; nft flush ruleset; ufw disable; stop, disable or mask of firewalld, ufw, iptables, ip6tables or nftables",
        eval: firewall_disable,
    },
    Rule {
        id: "security-tool-kill",
        technique: "T1685",
        technique_name: "Disable or Modify Tools",
        scope: Scope::Command,
        condition: "pkill or killall naming, or stop, disable or mask of, a listed security tool or agent",
        eval: security_tool_kill,
    },
    Rule {
        id: "sql-account-password",
        technique: "T1098",
        technique_name: "Account Manipulation",
        scope: Scope::Sql,
        condition: "ALTER USER, ROLE or LOGIN given a PASSWORD value or IDENTIFIED BY; SET PASSWORD; sp_password",
        eval: sql_account_password,
    },
    Rule {
        id: "sql-privilege-change",
        technique: "T1098",
        technique_name: "Account Manipulation",
        scope: Scope::Sql,
        condition: "GRANT ... TO; ALTER USER or ROLE with SUPERUSER; ALTER SERVER ROLE ... ADD MEMBER; sp_addsrvrolemember or sp_addrolemember",
        eval: sql_privilege_change,
    },
    Rule {
        id: "sql-account-create",
        technique: "T1136",
        technique_name: "Create Account",
        scope: Scope::Sql,
        condition: "CREATE USER (not USER MAPPING) or CREATE LOGIN; CREATE ROLE with LOGIN or SUPERUSER; sp_addlogin",
        eval: sql_account_create,
    },
    Rule {
        id: "sql-os-command",
        technique: "T1059",
        technique_name: "Command and Scripting Interpreter",
        scope: Scope::Sql,
        condition: "COPY ... PROGRAM 'command'; xp_cmdshell, or sp_configure naming it; a call to sys_exec, sys_eval or sys_bineval; CREATE FUNCTION ... SONAME",
        eval: sql_os_command,
    },
    Rule {
        id: "sql-version-discovery",
        technique: "T1082",
        technique_name: "System Information Discovery",
        scope: Scope::Sql,
        condition: "a call to version() with no arguments; the @@version or @@version_comment variable; SHOW server_version",
        eval: sql_version_discovery,
    },
    Rule {
        id: "sql-user-discovery",
        technique: "T1033",
        technique_name: "System Owner/User Discovery",
        scope: Scope::Sql,
        condition: "a SELECT whose select list is or holds current_user, session_user, system_user, user_name, suser_name, suser_sname, user() or a bare user",
        eval: sql_user_discovery,
    },
    Rule {
        id: "sql-file-read",
        technique: "T1005",
        technique_name: "Data from Local System",
        scope: Scope::Sql,
        condition: "a call to pg_read_file, pg_read_binary_file, lo_import or load_file; COPY ... FROM 'file'; LOAD DATA ... INFILE; OPENROWSET(BULK",
        eval: sql_file_read,
    },
    Rule {
        id: "redis-config-cron",
        technique: "T1053.003",
        technique_name: "Scheduled Task/Job: Cron",
        scope: Scope::Redis,
        condition: "CONFIG SET dir to /var/spool/cron, /etc/cron.d, /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly or /etc/cron.monthly, or a directory under one",
        eval: redis_config_cron,
    },
    Rule {
        id: "redis-config-authkeys",
        technique: "T1098.004",
        technique_name: "Account Manipulation: SSH Authorized Keys",
        scope: Scope::Redis,
        condition: "CONFIG SET dir to a directory named .ssh, or CONFIG SET dbfilename to authorized_keys or authorized_keys2",
        eval: redis_config_authkeys,
    },
    Rule {
        id: "redis-replicaof",
        technique: "T1105",
        technique_name: "Ingress Tool Transfer",
        scope: Scope::Redis,
        condition: "SLAVEOF or REPLICAOF given a host (not NO ONE)",
        eval: redis_replicaof,
    },
];

/// Sensors whose commands are Unix shell lines. The ADB sensor's shell is Android's, which the
/// Enterprise matrix does not cover, and the protocol sensors log protocol commands (an SMTP
/// `DATA`, a Redis `CONFIG`) in the same event shape, so neither is read as a shell line.
pub const SHELL_SENSORS: [&str; 2] = ["ssh", "telnet"];

/// Sensors whose `command` is SQL text. Only `postgresql` records statements today; the MySQL and
/// SQL Server sensors answer the login and nothing after it, and are listed so their statements
/// are read the day they are recorded.
pub const SQL_SENSORS: [&str; 3] = ["postgresql", "mysql", "mssql"];

/// The sensor whose commands are Redis commands recorded as structured fields.
pub const REDIS_SENSOR: &str = "redis";

fn command<'a>(i: &'a Input) -> Option<&'a Simple> {
    match i {
        Input::Command(s) => Some(s),
        _ => None,
    }
}

fn brute_force_signal(i: &Input) -> Option<String> {
    matches!(i, Input::Signal("ssh_brute_force")).then(|| "ssh_brute_force".to_string())
}

fn download_event(i: &Input) -> Option<String> {
    let Input::Download { url, command } = i else {
        return None;
    };
    match (url, command) {
        (Some(url), _) if !url.is_empty() => Some((*url).to_string()),
        (_, Some(c)) => c.split_whitespace().next().map(str::to_string),
        _ => None,
    }
}

/// Flags that make curl send a local file or data rather than fetch one.
const CURL_SEND_FLAGS: [&str; 9] = [
    "-T",
    "--upload-file",
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "-F",
    "--form",
];

fn download_command(i: &Input) -> Option<String> {
    let s = command(i)?;
    let url = || s.operands().into_iter().find(|o| o.contains("://"));
    match s.name() {
        "wget" => url().map(str::to_string),
        "curl"
            if !s
                .args()
                .iter()
                .any(|a| CURL_SEND_FLAGS.contains(&a.as_str())) =>
        {
            url().map(str::to_string)
        }
        "tftp" if s.args().iter().any(|a| a == "-g") => Some("tftp -g".to_string()),
        "ftpget" if s.operands().len() >= 2 => Some("ftpget".to_string()),
        _ => None,
    }
}

fn upload_sample(i: &Input) -> Option<String> {
    match i {
        Input::Upload { sha256 } => Some((*sha256).to_string()),
        _ => None,
    }
}

fn unix_shell(i: &Input) -> Option<String> {
    let s = command(i)?;
    is_shell(s.name()).then(|| s.name().to_string())
}

/// Every file `s` writes: redirection targets, `tee` operands, the destination of `cp`, `mv`,
/// `install`, `ln` and `rsync`, the file of `sed -i`, and `dd of=`. A read of the same path is not
/// a write.
fn write_targets(s: &Simple) -> Vec<&str> {
    let mut found: Vec<&str> = s.out.iter().map(String::as_str).collect();
    let operands = s.operands();
    match s.name() {
        "tee" => found.extend(operands),
        "cp" | "mv" | "install" | "ln" | "rsync" if operands.len() >= 2 => {
            found.extend(operands.last());
        }
        "sed"
            if operands.len() >= 2
                && s.args().iter().any(|a| {
                    a == "--in-place"
                        || (a.starts_with('-') && !a.starts_with("--") && a.contains('i'))
                }) =>
        {
            found.extend(operands.last());
        }
        "dd" => found.extend(s.args().iter().filter_map(|a| a.strip_prefix("of="))),
        _ => {}
    }
    found
}

fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn under(path: &str, dir: &str) -> bool {
    path.starts_with(dir) && path.len() > dir.len()
}

const CRON_DIRS: [&str; 6] = [
    "/etc/cron.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",
];

fn is_cron_path(p: &str) -> bool {
    p == "/etc/crontab" || CRON_DIRS.iter().any(|d| under(p, d))
}

/// `crontab` installing a table: `-` (read from standard input) or a file operand, and not a
/// listing, removal or interactive edit.
fn crontab_installs(s: &Simple) -> bool {
    let mut args = s.args().iter();
    let mut installs = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-l" | "-r" | "-e" => return false,
            "-u" => {
                args.next();
            }
            "-" => installs = true,
            other if !other.starts_with('-') => installs = true,
            _ => {}
        }
    }
    installs
}

fn cron_install(i: &Input) -> Option<String> {
    let s = command(i)?;
    if s.name() == "crontab" && crontab_installs(s) {
        return Some("crontab".to_string());
    }
    write_targets(s)
        .into_iter()
        .find(|p| is_cron_path(p))
        .map(str::to_string)
}

const UNIT_DIRS: [&str; 5] = [
    "/etc/systemd/system/",
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
    "/run/systemd/system/",
    "/etc/systemd/user/",
];

fn is_unit_path(p: &str) -> bool {
    let in_dir = UNIT_DIRS.iter().any(|d| under(p, d)) || p.contains(".config/systemd/user/");
    in_dir && p.ends_with(".service") && base(p).len() > ".service".len()
}

fn systemd_unit(i: &Input) -> Option<String> {
    let s = command(i)?;
    if let Some(p) = write_targets(s).into_iter().find(|p| is_unit_path(p)) {
        return Some(p.to_string());
    }
    if s.name() == "systemctl" {
        let ops = s.operands();
        if let [action, unit, ..] = ops.as_slice()
            && *action == "enable"
        {
            return Some(format!("systemctl enable {unit}"));
        }
    }
    None
}

fn rc_script(i: &Input) -> Option<String> {
    let s = command(i)?;
    write_targets(s)
        .into_iter()
        .find(|p| {
            *p == "/etc/rc.local.d/local.sh"
                || (p.starts_with("/etc/") && matches!(base(p), "rc.local" | "rc.common"))
        })
        .map(str::to_string)
}

fn authorized_keys(i: &Input) -> Option<String> {
    let s = command(i)?;
    write_targets(s)
        .into_iter()
        .find(|p| matches!(base(p), "authorized_keys" | "authorized_keys2"))
        .map(str::to_string)
}

const READERS: [&str; 11] = [
    "cat", "grep", "head", "tail", "less", "more", "awk", "sed", "wc", "cut", "sort",
];

const SYSINFO_FILES: [&str; 6] = [
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/version",
    "/etc/os-release",
    "/etc/lsb-release",
    "/etc/issue",
];

fn system_info(i: &Input) -> Option<String> {
    let s = command(i)?;
    if matches!(s.name(), "uname" | "nproc" | "lscpu" | "hostnamectl") {
        return Some(s.name().to_string());
    }
    if READERS.contains(&s.name()) || s.name() == "strings" {
        return s
            .operands()
            .into_iter()
            .chain(s.input.iter().map(String::as_str))
            .find(|o| SYSINFO_FILES.contains(o))
            .map(str::to_string);
    }
    None
}

fn named(s: &Simple, names: &[&str]) -> Option<String> {
    names.contains(&s.name()).then(|| s.name().to_string())
}

fn file_discovery(i: &Input) -> Option<String> {
    named(
        command(i)?,
        &["ls", "dir", "vdir", "find", "locate", "tree"],
    )
}

fn process_discovery(i: &Input) -> Option<String> {
    named(
        command(i)?,
        &["ps", "top", "htop", "pgrep", "pidof", "pstree"],
    )
}

fn with_operand(s: &Simple, names: &[&str]) -> Option<String> {
    let name = named(s, names)?;
    let first = s.operands().first().copied()?;
    Some(format!("{name} {first}"))
}

fn permissions(i: &Input) -> Option<String> {
    with_operand(command(i)?, &["chmod", "chown"])
}

fn file_deletion(i: &Input) -> Option<String> {
    with_operand(command(i)?, &["rm", "unlink", "shred"])
}

fn miner_script(i: &Input) -> Option<String> {
    match i {
        Input::Indicator(ind) if ind.kind == IocKind::Url && ind.detail == MINER_SCRIPT_DETAIL => {
            Some(ind.value.clone())
        }
        _ => None,
    }
}

fn miner_configured(i: &Input) -> Option<String> {
    match i {
        Input::Indicator(ind)
            if ind.kind == IocKind::Credentials && ind.value == MINER_SITE_KEY =>
        {
            Some(ind.value.clone())
        }
        _ => None,
    }
}

/// `(action, unit)` of a service-manager command: `systemctl ACTION UNIT`, `service UNIT ACTION`
/// or `/etc/init.d/UNIT ACTION`, the unit without a `.service` suffix.
fn service_action(s: &Simple) -> Option<(&str, &str)> {
    let ops = s.operands();
    let (action, unit) = match s.name() {
        "systemctl" => (*ops.first()?, *ops.get(1)?),
        "service" => (*ops.get(1)?, *ops.first()?),
        _ if s
            .argv
            .first()
            .is_some_and(|a| a.starts_with("/etc/init.d/")) =>
        {
            (*ops.first()?, s.name())
        }
        _ => return None,
    };
    Some((action, unit.strip_suffix(".service").unwrap_or(unit)))
}

fn stops(action: &str) -> bool {
    matches!(action, "stop" | "disable" | "mask")
}

const FIREWALL_UNITS: [&str; 6] = [
    "firewalld",
    "ufw",
    "iptables",
    "ip6tables",
    "nftables",
    "SuSEfirewall2",
];

fn firewall_disable(i: &Input) -> Option<String> {
    let s = command(i)?;
    match s.name() {
        "iptables" | "ip6tables" | "iptables-legacy" | "ip6tables-legacy" | "iptables-nft"
        | "ip6tables-nft" => {
            if let Some(flag) = s.args().iter().find(|a| *a == "-F" || *a == "--flush") {
                return Some(format!("{} {flag}", s.name()));
            }
        }
        "nft" => {
            let ops = s.operands();
            if ops.first() == Some(&"flush") && ops.get(1) == Some(&"ruleset") {
                return Some("nft flush ruleset".to_string());
            }
        }
        "ufw" if s.operands().first() == Some(&"disable") => {
            return Some("ufw disable".to_string());
        }
        // `/etc/init.d/iptables stop` is named like the tool; the service check below reads it.
        _ => {}
    }
    let (action, unit) = service_action(s)?;
    (stops(action) && FIREWALL_UNITS.contains(&unit))
        .then(|| format!("{} {action} {unit}", s.name()))
}

/// Security tools and agents whose stopping is defense impairment: the ones ATT&CK's detection
/// text for Disable or Modify Tools names (auditd, falco, osquery, rsyslog, journald), common
/// host agents, and the cloud monitoring agents miner droppers remove.
const SECURITY_TOOLS: [&str; 17] = [
    "auditd",
    "falco",
    "osqueryd",
    "rsyslog",
    "systemd-journald",
    "apparmor",
    "fail2ban",
    "fail2ban-server",
    "clamd",
    "wazuh-agent",
    "aegis",
    "aliyundun",
    "aliyundunupdate",
    "aliyun-service",
    "yunjing",
    "cloudmonitor",
    "bcm-agent",
];

fn is_security_tool(name: &str) -> bool {
    SECURITY_TOOLS.contains(&name.to_ascii_lowercase().as_str())
}

fn security_tool_kill(i: &Input) -> Option<String> {
    let s = command(i)?;
    if matches!(s.name(), "pkill" | "killall") {
        let target = s.operands().into_iter().find(|o| is_security_tool(o))?;
        return Some(format!("{} {target}", s.name()));
    }
    let (action, unit) = service_action(s)?;
    (stops(action) && is_security_tool(unit)).then(|| format!("{} {action} {unit}", s.name()))
}

// The SQL rules build every matched token from fixed keywords and function names, never from a
// string literal, so a password or a path in the statement cannot reach a stored tag.

fn sql<'a>(i: &'a Input) -> Option<&'a [Tok]> {
    match i {
        Input::Sql(s) => Some(s),
        _ => None,
    }
}

fn word(s: &[Tok], at: usize) -> Option<&str> {
    match s.get(at) {
        Some(Tok::Word(w)) => Some(w),
        _ => None,
    }
}

fn is_word(s: &[Tok], at: usize, w: &str) -> bool {
    word(s, at) == Some(w)
}

fn has_word(s: &[Tok], w: &str) -> bool {
    (0..s.len()).any(|i| is_word(s, i, w))
}

/// Whether `name` is called: the word, then `(`.
fn calls(s: &[Tok], name: &str) -> bool {
    (0..s.len()).any(|i| is_word(s, i, name) && s.get(i + 1) == Some(&Tok::Sym('(')))
}

/// The procedure a statement runs, SQL Server style: an optional `EXEC`, then a name whose last
/// dotted segment counts (`master..xp_cmdshell`, `master.dbo.sp_addlogin`).
fn procedure(s: &[Tok]) -> Option<&str> {
    let mut i = usize::from(is_word(s, 0, "exec") || is_word(s, 0, "execute"));
    let mut name = word(s, i)?;
    while s.get(i + 1) == Some(&Tok::Sym('.')) {
        i += 1;
        while s.get(i) == Some(&Tok::Sym('.')) {
            i += 1;
        }
        name = word(s, i)?;
    }
    Some(name)
}

/// A password being set from token `from` on: `PASSWORD 'x'`, `PASSWORD = 'x'`, `PASSWORD NULL`
/// or `IDENTIFIED BY|WITH`. The word `password` alone (a name, `PASSWORD EXPIRE`) is not one.
fn sets_password(s: &[Tok], from: usize) -> bool {
    (from..s.len()).any(|i| {
        (is_word(s, i, "password")
            && (matches!(s.get(i + 1), Some(Tok::Str(_) | Tok::Sym('=')))
                || is_word(s, i + 1, "null")))
            || (is_word(s, i, "identified") && matches!(word(s, i + 1), Some("by" | "with")))
    })
}

fn sql_account_password(i: &Input) -> Option<String> {
    let s = sql(i)?;
    if is_word(s, 0, "set") && is_word(s, 1, "password") {
        return Some("SET PASSWORD".to_string());
    }
    if is_word(s, 0, "alter")
        && let Some(kind) = word(s, 1).filter(|k| matches!(*k, "user" | "role" | "login"))
        && sets_password(s, 2)
    {
        return Some(format!("ALTER {} PASSWORD", kind.to_ascii_uppercase()));
    }
    (procedure(s) == Some("sp_password")).then(|| "sp_password".to_string())
}

fn sql_privilege_change(i: &Input) -> Option<String> {
    let s = sql(i)?;
    if is_word(s, 0, "grant") && has_word(s, "to") {
        return Some("GRANT".to_string());
    }
    if is_word(s, 0, "alter") {
        if let Some(kind) = word(s, 1).filter(|k| matches!(*k, "user" | "role"))
            && has_word(s, "superuser")
        {
            return Some(format!("ALTER {} SUPERUSER", kind.to_ascii_uppercase()));
        }
        if is_word(s, 1, "server")
            && is_word(s, 2, "role")
            && has_word(s, "add")
            && has_word(s, "member")
        {
            return Some("ALTER SERVER ROLE ADD MEMBER".to_string());
        }
    }
    match procedure(s) {
        Some(p @ ("sp_addsrvrolemember" | "sp_addrolemember")) => Some(p.to_string()),
        _ => None,
    }
}

fn sql_account_create(i: &Input) -> Option<String> {
    let s = sql(i)?;
    if is_word(s, 0, "create") {
        let at = if is_word(s, 1, "or") && is_word(s, 2, "replace") {
            3
        } else {
            1
        };
        match word(s, at) {
            // `CREATE USER MAPPING` binds a foreign server; it is not an account.
            Some("user") if !is_word(s, at + 1, "mapping") => {
                return Some("CREATE USER".to_string());
            }
            Some("login") => return Some("CREATE LOGIN".to_string()),
            Some("role") => {
                // A role that cannot log in is a group.
                let grant = (at + 1..s.len())
                    .find_map(|k| word(s, k).filter(|w| matches!(*w, "login" | "superuser")));
                return grant.map(|w| format!("CREATE ROLE {}", w.to_ascii_uppercase()));
            }
            _ => {}
        }
    }
    (procedure(s) == Some("sp_addlogin")).then(|| "sp_addlogin".to_string())
}

fn sql_os_command(i: &Input) -> Option<String> {
    let s = sql(i)?;
    if is_word(s, 0, "copy")
        && (0..s.len())
            .any(|k| is_word(s, k, "program") && matches!(s.get(k + 1), Some(Tok::Str(_))))
    {
        return Some("COPY PROGRAM".to_string());
    }
    if has_word(s, "xp_cmdshell") {
        return Some("xp_cmdshell".to_string());
    }
    if procedure(s) == Some("sp_configure")
        && s.iter()
            .any(|t| matches!(t, Tok::Str(v) if v.eq_ignore_ascii_case("xp_cmdshell")))
    {
        return Some("sp_configure xp_cmdshell".to_string());
    }
    if let Some(f) = ["sys_exec", "sys_eval", "sys_bineval"]
        .into_iter()
        .find(|f| calls(s, f))
    {
        return Some(f.to_string());
    }
    (is_word(s, 0, "create") && has_word(s, "function") && has_word(s, "soname"))
        .then(|| "CREATE FUNCTION SONAME".to_string())
}

fn sql_version_discovery(i: &Input) -> Option<String> {
    let s = sql(i)?;
    if (0..s.len()).any(|k| {
        is_word(s, k, "version")
            && s.get(k + 1) == Some(&Tok::Sym('('))
            && s.get(k + 2) == Some(&Tok::Sym(')'))
    }) {
        return Some("version()".to_string());
    }
    if let Some(v) = ["@@version", "@@version_comment"]
        .into_iter()
        .find(|v| has_word(s, v))
    {
        return Some(v.to_string());
    }
    (is_word(s, 0, "show") && is_word(s, 1, "server_version"))
        .then(|| "SHOW server_version".to_string())
}

fn sql_user_discovery(i: &Input) -> Option<String> {
    let s = sql(i)?;
    if !is_word(s, 0, "select") {
        return None;
    }
    let end = (1..s.len())
        .find(|k| is_word(s, *k, "from"))
        .unwrap_or(s.len());
    (1..end).find_map(|k| {
        let w = word(s, k)?;
        let called = s.get(k + 1) == Some(&Tok::Sym('('));
        match w {
            // Reserved words: a column cannot be named this, so bare or called both count.
            "current_user" | "session_user" | "system_user" => Some(w.to_string()),
            // Ordinary names: only the function call, since `user_name` is a common column.
            "user_name" | "suser_name" | "suser_sname" | "user" if called => Some(format!("{w}()")),
            // `SELECT user` alone; with more after it, `user` may be a MySQL column.
            "user" if s.len() == 2 => Some("user".to_string()),
            _ => None,
        }
    })
}

fn sql_file_read(i: &Input) -> Option<String> {
    let s = sql(i)?;
    if let Some(f) = [
        "pg_read_file",
        "pg_read_binary_file",
        "lo_import",
        "load_file",
    ]
    .into_iter()
    .find(|f| calls(s, f))
    {
        return Some(f.to_string());
    }
    if is_word(s, 0, "copy")
        && (0..s.len()).any(|k| is_word(s, k, "from") && matches!(s.get(k + 1), Some(Tok::Str(_))))
    {
        return Some("COPY FROM file".to_string());
    }
    if is_word(s, 0, "load") && is_word(s, 1, "data") && has_word(s, "infile") {
        return Some("LOAD DATA INFILE".to_string());
    }
    (0..s.len())
        .any(|k| {
            is_word(s, k, "openrowset")
                && s.get(k + 1) == Some(&Tok::Sym('('))
                && is_word(s, k + 2, "bulk")
        })
        .then(|| "OPENROWSET BULK".to_string())
}

fn redis<'a>(i: &'a Input) -> Option<&'a RedisCommand> {
    match i {
        Input::Redis(r) => Some(r),
        _ => None,
    }
}

/// The value of `CONFIG SET param value`.
fn config_set<'a>(r: &'a RedisCommand, param: &str) -> Option<&'a str> {
    if !r.command.eq_ignore_ascii_case("CONFIG SET")
        || !r
            .param
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(param))
    {
        return None;
    }
    r.value.as_deref()
}

const REDIS_CRON_DIRS: [&str; 6] = [
    "/var/spool/cron",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];

fn redis_config_cron(i: &Input) -> Option<String> {
    let dir = config_set(redis(i)?, "dir")?.trim_end_matches('/');
    REDIS_CRON_DIRS
        .iter()
        .any(|d| {
            dir == *d
                || dir
                    .strip_prefix(d)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .then(|| "CONFIG SET dir".to_string())
}

fn redis_config_authkeys(i: &Input) -> Option<String> {
    let r = redis(i)?;
    if let Some(dir) = config_set(r, "dir")
        && base(dir.trim_end_matches('/')) == ".ssh"
    {
        return Some("CONFIG SET dir".to_string());
    }
    let file = config_set(r, "dbfilename")?;
    matches!(base(file), "authorized_keys" | "authorized_keys2")
        .then(|| "CONFIG SET dbfilename".to_string())
}

fn redis_replicaof(i: &Input) -> Option<String> {
    let r = redis(i)?;
    let cmd = r.command.to_ascii_uppercase();
    if !matches!(cmd.as_str(), "SLAVEOF" | "REPLICAOF") {
        return None;
    }
    let host = r.args.first()?;
    (!host.eq_ignore_ascii_case("no")).then_some(cmd)
}
