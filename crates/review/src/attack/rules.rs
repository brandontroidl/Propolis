//! The rule table: every ATT&CK technique this build tags, the exact condition for it, and the
//! token that satisfied it. One row per rule; [`RULES`] is the only list, and the reference page
//! (`docs/reference/attack-tagging.md`) is checked against it.
//!
//! A rule reads structure, never substrings: a shell line is parsed into commands
//! (`super::parse`) and a rule looks at a command's name, its operands and its redirection
//! targets, so `echo crontab` and a URL containing `cron` match nothing. A rule names the evidence
//! it needs; where the ledger cannot supply it, there is no rule (see the reference page for the
//! techniques considered and left out).

use super::parse::{Simple, is_shell};
use crate::ioc::{Indicator, IocKind, MINER_SCRIPT_DETAIL, MINER_SITE_KEY};

/// What a rule is shown evidence of.
pub enum Input<'a> {
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

pub const RULES: [Rule; 18] = [
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
];

/// Sensors whose commands are Unix shell lines. The ADB sensor's shell is Android's, which the
/// Enterprise matrix does not cover, and the protocol sensors log protocol commands (an SMTP
/// `DATA`, a Redis `CONFIG`) in the same event shape, so neither is read as a shell line.
pub const SHELL_SENSORS: [&str; 2] = ["ssh", "telnet"];

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
