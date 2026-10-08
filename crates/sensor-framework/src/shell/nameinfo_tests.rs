//! `getent`, `nslookup` and `dig` through `handle_input` the way a session reaches them. The
//! answers come from the modeled `/etc` files and nothing else, so these pin the relations that
//! must hold whatever the layout is (`getent` and `cat` agree, a name the hosts file does not list
//! is NXDOMAIN, the resolver the tools name is the synthetic private one) and the privacy rule
//! that no address the sensor holds can reach any output. Layouts are the GNU C library 2.35, bind 9.18 and
//! BusyBox 1.3x as remembered, not captured, so the cases that pin a layout say so.

use chrono::{DateTime, TimeZone, Utc};

use super::{CommandResult, EmitContext, FakeShell, HandlerId, OutputFd};
use crate::fakefs::FakeFs;
use crate::persona;

const SESSION_PEER: &str = "203.0.113.77";
const DEPLOYMENT_HOST: &str = "198.51.100.88";
const UBUNTU_RESOLVER: &str = "172.31.16.1";
const PHONE_RESOLVER: &str = "192.168.1.1";

fn ctx_with(label: &str, source: &str, wan: Option<&str>) -> EmitContext {
    EmitContext {
        source_ip: source.parse().unwrap(),
        wan_ip: wan.map(|ip| ip.parse().unwrap()),
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
    FakeShell::new(
        FakeFs::new(),
        ctx_with("ssh", SESSION_PEER, Some(DEPLOYMENT_HOST)),
    )
    .with_clock(friday)
}

fn phone() -> FakeShell {
    FakeShell::android(
        FakeFs::android(),
        ctx_with("adb", SESSION_PEER, Some(DEPLOYMENT_HOST)),
    )
    .with_clock(friday)
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

fn status(sh: &mut FakeShell, line: &str) -> u8 {
    answer(sh, line).2
}

fn silent_success(sh: &mut FakeShell, line: &str) {
    assert_eq!(
        answer(sh, line),
        (String::new(), String::new(), 0),
        "{line}"
    );
}

fn host() -> String {
    persona::hostname()
}

fn resolved_by(sh: &mut FakeShell, line: &str) -> HandlerId {
    sh.handle_input(line);
    sh.last_trace().segments[0]
        .command
        .as_ref()
        .unwrap()
        .resolved
}

/// The handler of the command a multi-call binary ran: the first re-entry of the line.
fn reentered_by(sh: &mut FakeShell, line: &str) -> HandlerId {
    sh.handle_input(line);
    sh.last_trace().segments[0]
        .command
        .as_ref()
        .unwrap()
        .reentry[0]
        .resolved
}

// ------------------------------------------------------------------------------------- getent

/// `getent hosts` rows for a hosts file, derived here from its words rather than from the module.
fn hosts_rows(file: &str) -> String {
    file.lines()
        .filter_map(|line| {
            let mut words = line.split('#').next().unwrap().split_whitespace();
            let addr = words.next()?;
            let names: Vec<&str> = words.collect();
            (!names.is_empty()).then(|| format!("{addr:<15} {}\n", names.join(" ")))
        })
        .collect()
}

#[test]
fn getent_hosts_agrees_with_the_modeled_hosts_file() {
    let mut sh = shell();
    let file = out(&mut sh, "cat /etc/hosts");
    assert!(file.contains("127.0.0.1 localhost"), "{file}");
    assert_eq!(out(&mut sh, "getent hosts"), hosts_rows(&file));
    // A name resolves to the entry the file lists, IPv6 first as `gethostbyname2` tries it.
    assert_eq!(
        answer(&mut sh, "getent hosts localhost"),
        (
            "::1             localhost ip6-localhost ip6-loopback\n".to_string(),
            String::new(),
            0
        )
    );
    assert_eq!(
        out(&mut sh, "getent hosts 127.0.0.1"),
        "127.0.0.1       localhost\n"
    );
    let name = host();
    assert_eq!(
        out(&mut sh, &format!("getent hosts {name}")),
        format!("127.0.1.1       {name}\n")
    );
    // Several keys answer in order, in one run.
    assert_eq!(
        out(&mut sh, "getent hosts ip6-allnodes 127.0.0.1"),
        "ff02::1         ip6-allnodes\n127.0.0.1       localhost\n"
    );
}

#[test]
fn getent_passwd_and_group_are_the_modeled_files() {
    let mut sh = shell();
    for (database, file) in [("passwd", "/etc/passwd"), ("group", "/etc/group")] {
        let text = out(&mut sh, &format!("cat {file}"));
        assert!(text.lines().count() > 5, "{file}");
        assert_eq!(out(&mut sh, &format!("getent {database}")), text);
        for row in text.lines() {
            let name = row.split(':').next().unwrap();
            assert_eq!(
                out(&mut sh, &format!("getent {database} {name}")),
                format!("{row}\n"),
                "{database} {name}"
            );
        }
    }
    assert_eq!(
        out(&mut sh, "getent passwd ubuntu"),
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
    );
    assert_eq!(out(&mut sh, "getent group sudo"), "sudo:x:27:ubuntu\n");
}

#[test]
fn getent_looks_up_a_uid_or_gid_by_number() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "getent passwd 0"),
        "root:x:0:0:root:/root:/bin/bash\n"
    );
    assert_eq!(
        out(&mut sh, "getent passwd 1000"),
        out(&mut sh, "getent passwd ubuntu")
    );
    assert_eq!(out(&mut sh, "getent group 27"), "sudo:x:27:ubuntu\n");
    assert_eq!(out(&mut sh, "getent group 65534"), "nogroup:x:65534:\n");
    // A uid is not a gid: 105 is sshd's uid and the messagebus group's gid.
    assert_eq!(
        out(&mut sh, "getent passwd 105"),
        "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
    );
    assert_eq!(out(&mut sh, "getent group 105"), "messagebus:x:105:\n");
    // 999 is lxd's uid and no group's gid.
    assert_eq!(
        answer(&mut sh, "getent group 999"),
        (String::new(), String::new(), 2)
    );
}

#[test]
fn getent_key_that_is_not_there_is_status_2_with_no_output() {
    let mut sh = shell();
    for line in [
        "getent hosts example.com",
        "getent hosts 192.0.2.99",
        "getent passwd nosuchuser",
        "getent passwd 4242",
        "getent group nosuchgroup",
        "getent group 4242",
        "getent ahosts example.com",
    ] {
        assert_eq!(
            answer(&mut sh, line),
            (String::new(), String::new(), 2),
            "{line}"
        );
    }
    // The keys that exist still answer, and the status reports the one that did not.
    assert_eq!(
        answer(&mut sh, "getent passwd root nosuchuser daemon"),
        (
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                .to_string(),
            String::new(),
            2
        )
    );
}

#[test]
fn getent_usage_errors_and_unmodeled_databases() {
    let mut sh = shell();
    let (stdout, stderr, code) = answer(&mut sh, "getent bogus");
    assert_eq!(stdout, "");
    assert_eq!(code, 1);
    assert!(stderr.starts_with("Unknown database: bogus\n"), "{stderr}");
    assert!(stderr.contains("getent --help"), "{stderr}");
    let (stdout, stderr, code) = answer(&mut sh, "getent");
    assert_eq!((stdout.as_str(), code), ("", 64));
    assert!(stderr.starts_with("Usage: getent [OPTION...] database [key ...]"));
    let (_, stderr, code) = answer(&mut sh, "getent ahosts");
    assert_eq!(code, 3);
    assert_eq!(stderr, "Enumeration not supported on ahosts\n");
    // Real databases the box does not model, and options it does not: nothing, and success.
    for line in [
        "getent services",
        "getent protocols tcp",
        "getent shadow root",
        "getent -s files hosts localhost",
        "getent --version",
    ] {
        silent_success(&mut sh, line);
    }
}

#[test]
fn getent_ahosts_lists_each_address_per_socket_type() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "getent ahosts localhost"),
        "::1             STREAM localhost\n::1             DGRAM\n::1             RAW\n\
         127.0.0.1       STREAM\n127.0.0.1       DGRAM\n127.0.0.1       RAW\n"
    );
    let name = host();
    assert_eq!(
        out(&mut sh, &format!("getent ahostsv4 {name}")),
        format!("127.0.1.1       STREAM {name}\n127.0.1.1       DGRAM\n127.0.1.1       RAW\n")
    );
    assert_eq!(
        answer(&mut sh, &format!("getent ahostsv6 {name}")),
        (String::new(), String::new(), 2)
    );
}

#[test]
fn getent_reads_the_files_as_the_session_has_edited_them() {
    let mut sh = shell();
    sh.handle_input("echo '10.9.8.7 devbox devbox.lan' >> /etc/hosts");
    assert_eq!(
        out(&mut sh, "getent hosts devbox.lan"),
        "10.9.8.7        devbox devbox.lan\n"
    );
    assert_eq!(
        out(&mut sh, "getent hosts 10.9.8.7"),
        out(&mut sh, "getent hosts devbox")
    );
    assert!(out(&mut sh, "nslookup devbox").contains("Address: 10.9.8.7\n"));
    assert_eq!(out(&mut sh, "dig +short devbox"), "10.9.8.7\n");
    sh.handle_input("echo 'svc:x:777:777::/nonexistent:/bin/false' >> /etc/passwd");
    assert_eq!(
        out(&mut sh, "getent passwd 777"),
        "svc:x:777:777::/nonexistent:/bin/false\n"
    );
}

#[test]
fn every_passwd_group_has_a_group_row_and_the_resolver_file_is_private() {
    let mut sh = shell();
    let groups = out(&mut sh, "cat /etc/group");
    let gids: Vec<&str> = groups
        .lines()
        .map(|row| row.split(':').nth(2).unwrap())
        .collect();
    for row in out(&mut sh, "cat /etc/passwd").lines() {
        let gid = row.split(':').nth(3).unwrap();
        assert!(gids.contains(&gid), "{row} has no group row");
    }
    assert_eq!(
        out(&mut sh, "cat /etc/resolv.conf"),
        "nameserver 172.31.16.1\n"
    );
    let listing = out(&mut sh, "ls /etc");
    assert!(
        listing.contains("group") && listing.contains("resolv.conf"),
        "{listing}"
    );
}

// ----------------------------------------------------------------------------------- nslookup

#[test]
fn nslookup_localhost_is_the_loopback() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "nslookup localhost"),
        (
            "Server:\t\t172.31.16.1\nAddress:\t172.31.16.1#53\n\nNon-authoritative answer:\n\
             Name:\tlocalhost\nAddress: 127.0.0.1\nName:\tlocalhost\nAddress: ::1\n\n"
                .to_string(),
            String::new(),
            0
        )
    );
    let only_v4 = out(&mut sh, "nslookup -type=A localhost");
    assert!(only_v4.contains("Address: 127.0.0.1\n") && !only_v4.contains("::1"));
}

#[test]
fn nslookup_of_a_modeled_host_gives_its_model_address() {
    let mut sh = shell();
    let name = host();
    let text = out(&mut sh, &format!("nslookup {name}"));
    assert!(
        text.contains(&format!("Name:\t{name}\nAddress: 127.0.1.1\n")),
        "{text}"
    );
    assert!(!text.contains("::1"), "{text}");
    // The hosts file's other names resolve to their rows, whatever the case typed.
    assert!(out(&mut sh, "nslookup IP6-LOOPBACK").contains("Address: ::1\n"));
    assert!(out(&mut sh, "nslookup localhost.").contains("Name:\tlocalhost\n"));
}

#[test]
fn nslookup_of_an_arbitrary_name_is_nxdomain_without_resolving() {
    let mut sh = shell();
    for name in [
        "example.com",
        "dl.example.net",
        "pool.supportxmr.com",
        "x",
        "a.b.c.d.e.f.g.example.org",
    ] {
        assert_eq!(
            answer(&mut sh, &format!("nslookup {name}")),
            (
                format!(
                    "Server:\t\t172.31.16.1\nAddress:\t172.31.16.1#53\n\n** server can't find {name}: NXDOMAIN\n\n"
                ),
                String::new(),
                1
            ),
            "{name}"
        );
    }
    // A record type does not turn a name the file lacks into an answer.
    let (text, _, code) = answer(&mut sh, "nslookup -type=MX example.com");
    assert!(text.contains("NXDOMAIN") && code == 1, "{text}");
    // A listed name with nothing of the asked type has no answer, bounded.
    let (text, _, code) = answer(&mut sh, "nslookup -type=MX localhost");
    assert!(
        text.contains("*** Can't find localhost: No answer\n"),
        "{text}"
    );
    assert_eq!(code, 1);
}

#[test]
fn nslookup_reverse_lookup_of_a_modeled_address_gives_its_name_or_nxdomain() {
    let mut sh = shell();
    let text = out(&mut sh, "nslookup 127.0.0.1");
    assert!(
        text.contains("1.0.0.127.in-addr.arpa\tname = localhost.\n"),
        "{text}"
    );
    let name = host();
    assert!(
        out(&mut sh, "nslookup 127.0.1.1")
            .contains(&format!("1.1.0.127.in-addr.arpa\tname = {name}.\n"))
    );
    let loopback_v6 = format!("1.{}ip6.arpa\tname = localhost.\n", "0.".repeat(31));
    assert!(out(&mut sh, "nslookup ::1").contains(&loopback_v6));
    // The box's own interface address is not a hosts entry, so nothing names it.
    let (text, _, code) = answer(&mut sh, "nslookup 172.31.16.42");
    assert!(
        text.contains("** server can't find 42.16.31.172.in-addr.arpa: NXDOMAIN\n"),
        "{text}"
    );
    assert_eq!(code, 1);
}

#[test]
fn the_resolver_line_is_the_synthetic_private_nameserver() {
    let mut sh = shell();
    // It is the model gateway `ip route` shows, so the tools cannot disagree about it.
    assert!(out(&mut sh, "ip route").contains(&format!("default via {UBUNTU_RESOLVER} ")));
    for line in ["nslookup example.com", "nslookup localhost"] {
        let text = out(&mut sh, line);
        assert!(
            text.starts_with(&format!("Server:\t\t{UBUNTU_RESOLVER}\n")),
            "{text}"
        );
    }
    assert!(out(&mut sh, "dig example.com").contains(&format!(
        ";; SERVER: {UBUNTU_RESOLVER}#53({UBUNTU_RESOLVER}) (UDP)\n"
    )));
    // A server typed on the line is accepted and never echoed: nothing is sent to it.
    for line in [
        "nslookup example.com 8.8.8.8",
        "nslookup localhost 1.1.1.1",
        "dig @9.9.9.9 example.com",
        "dig @9.9.9.9 localhost +short",
    ] {
        let (stdout, stderr, _) = answer(&mut sh, line);
        for typed in ["8.8.8.8", "1.1.1.1", "9.9.9.9"] {
            assert!(!stdout.contains(typed) && !stderr.contains(typed), "{line}");
        }
    }
    // The resolver comes from the modeled resolv.conf while that names a private address...
    sh.handle_input("echo 'nameserver 10.0.0.53' > /etc/resolv.conf");
    assert!(out(&mut sh, "nslookup localhost").starts_with("Server:\t\t10.0.0.53\n"));
    // ...and a public one the session wrote is never named: the model gateway answers.
    sh.handle_input("echo 'nameserver 8.8.8.8' > /etc/resolv.conf");
    let text = out(&mut sh, "nslookup localhost");
    assert!(
        text.starts_with(&format!("Server:\t\t{UBUNTU_RESOLVER}\n")),
        "{text}"
    );
    assert!(!out(&mut sh, "dig localhost").contains("8.8.8.8"));
    // The phone has no resolv.conf and names its own gateway.
    let mut ph = phone();
    assert!(out(&mut ph, "ip route").contains(&format!("default via {PHONE_RESOLVER} ")));
    assert!(
        out(&mut ph, "nslookup example.com").starts_with(&format!("Server:\t\t{PHONE_RESOLVER}\n"))
    );
}

#[test]
fn nslookup_without_a_name_or_with_unmodeled_options_prints_nothing_and_succeeds() {
    let mut sh = shell();
    for line in [
        "nslookup",
        "nslookup -debug example.com",
        "nslookup -type=BOGUS localhost",
        "nslookup -port=5353 localhost",
    ] {
        silent_success(&mut sh, line);
    }
}

// --------------------------------------------------------------------------------------- dig

#[test]
fn dig_short_prints_the_address_of_a_modeled_name_and_nothing_for_an_unknown_one() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "dig +short localhost"),
        ("127.0.0.1\n".to_string(), String::new(), 0)
    );
    assert_eq!(out(&mut sh, "dig localhost +short"), "127.0.0.1\n");
    assert_eq!(out(&mut sh, "dig +short localhost AAAA"), "::1\n");
    assert_eq!(out(&mut sh, "dig +short -t aaaa localhost"), "::1\n");
    let name = host();
    assert_eq!(out(&mut sh, &format!("dig +short {name}")), "127.0.1.1\n");
    assert_eq!(out(&mut sh, "dig +short -x 127.0.0.1"), "localhost.\n");
    for line in [
        "dig +short example.com",
        "dig +short example.com AAAA",
        "dig +short -x 172.31.16.42",
        "dig +short localhost MX",
    ] {
        assert_eq!(
            answer(&mut sh, line),
            (String::new(), String::new(), 0),
            "{line}"
        );
    }
}

#[test]
fn dig_answers_a_modeled_name_in_binds_layout() {
    let mut sh = shell();
    let id = {
        let text = out(&mut sh, "dig localhost");
        text.split("status: NOERROR, id: ")
            .nth(1)
            .and_then(|rest| rest.split('\n').next())
            .unwrap()
            .to_string()
    };
    // [unverified] the layout is composed from bind 9.18, the message id is the question's hash.
    let want = format!(
        "\n; <<>> DiG 9.18.39-0ubuntu0.22.04.1-Ubuntu <<>> localhost\n\
         ;; global options: +cmd\n\
         ;; Got answer:\n\
         ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {id}\n\
         ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\
         \n\
         ;; OPT PSEUDOSECTION:\n\
         ; EDNS: version: 0, flags:; udp: 65494\n\
         ;; QUESTION SECTION:\n\
         ;localhost.\t\t\tIN\tA\n\
         \n\
         ;; ANSWER SECTION:\n\
         localhost.\t\t300\tIN\tA\t127.0.0.1\n\
         \n\
         ;; Query time: 0 msec\n\
         ;; SERVER: 172.31.16.1#53(172.31.16.1) (UDP)\n\
         ;; WHEN: Fri Oct 02 12:34:56 UTC 2026\n\
         ;; MSG SIZE  rcvd: 54\n\
         \n"
    );
    assert_eq!(answer(&mut sh, "dig localhost"), (want, String::new(), 0));
    // The same question gets the same id, so a replay is byte-identical.
    assert_eq!(out(&mut sh, "dig localhost"), out(&mut sh, "dig localhost"));
}

#[test]
fn dig_of_an_unknown_name_is_nxdomain_in_the_short_form() {
    let mut sh = shell();
    let (text, stderr, code) = answer(&mut sh, "dig example.com");
    assert_eq!((stderr.as_str(), code), ("", 0), "dig exits 0 on NXDOMAIN");
    assert!(text.contains("status: NXDOMAIN"), "{text}");
    assert!(
        text.contains("ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1"),
        "{text}"
    );
    assert!(text.contains(";example.com.\t\t\tIN\tA\n"), "{text}");
    assert!(
        !text.contains("ANSWER SECTION") && !text.contains("AUTHORITY SECTION"),
        "{text}"
    );
    assert!(text.contains(";; MSG SIZE  rcvd: 40\n"), "{text}");
    assert!(
        text.contains(";; SERVER: 172.31.16.1#53(172.31.16.1) (UDP)\n"),
        "{text}"
    );
}

#[test]
fn dig_types_other_than_a_aaaa_and_ptr_are_noerror_with_no_answer() {
    let mut sh = shell();
    for ty in ["MX", "NS", "TXT", "SOA", "ANY", "CAA"] {
        let text = out(&mut sh, &format!("dig localhost {ty}"));
        assert!(text.contains("status: NOERROR"), "{ty}: {text}");
        assert!(text.contains("ANSWER: 0, AUTHORITY: 0"), "{ty}: {text}");
        assert!(text.contains(&format!("IN\t{ty}\n")), "{ty}: {text}");
        assert!(!text.contains("ANSWER SECTION"), "{ty}");
    }
    let aaaa = out(&mut sh, "dig localhost AAAA");
    assert!(
        aaaa.contains("localhost.\t\t300\tIN\tAAAA\t::1\n"),
        "{aaaa}"
    );
    assert!(aaaa.contains("MSG SIZE  rcvd: 66"), "{aaaa}");
    let ptr = out(&mut sh, "dig -x 127.0.0.1");
    assert!(ptr.contains(";1.0.0.127.in-addr.arpa.\tIN\tPTR\n"), "{ptr}");
    assert!(
        ptr.contains("1.0.0.127.in-addr.arpa.\t300\tIN\tPTR\tlocalhost.\n"),
        "{ptr}"
    );
    assert_eq!(
        out(&mut sh, "dig +short 1.0.0.127.in-addr.arpa PTR"),
        "localhost.\n"
    );
}

#[test]
fn dig_unmodeled_options_and_a_malformed_reverse_address() {
    let mut sh = shell();
    for line in [
        "dig",
        "dig +trace localhost",
        "dig -p 5353 localhost",
        "dig -t BOGUS localhost",
        "dig -x",
    ] {
        silent_success(&mut sh, line);
    }
    let (stdout, stderr, code) = answer(&mut sh, "dig -x not-an-address");
    assert_eq!((stdout.as_str(), code), ("", 1));
    assert_eq!(stderr, "Invalid IP address not-an-address\n");
}

// ----------------------------------------------------------------------------------- personas

#[test]
fn getent_and_dig_are_ubuntu_files_and_nslookup_is_on_both_personas() {
    let mut sh = shell();
    for name in ["getent", "dig", "nslookup"] {
        assert_eq!(
            answer(&mut sh, &format!("command -v {name}")),
            (format!("/usr/bin/{name}\n"), String::new(), 0),
            "{name}"
        );
    }
    let mut ph = phone();
    for name in ["getent", "dig"] {
        assert_eq!(status(&mut ph, &format!("command -v {name}")), 1, "{name}");
        assert_eq!(status(&mut ph, name), 127, "{name}");
    }
    assert_eq!(
        answer(&mut ph, "command -v nslookup"),
        ("/system/bin/nslookup\n".to_string(), String::new(), 0)
    );
    assert!(
        out(&mut ph, "ls /system/bin")
            .split_whitespace()
            .any(|name| name == "nslookup")
    );
    assert_eq!(status(&mut ph, "test -x /system/bin/nslookup"), 0);
    assert_eq!(status(&mut ph, "/system/bin/nslookup localhost"), 0);
}

#[test]
fn the_phone_answers_in_busyboxs_layout_from_its_own_hosts_file() {
    let mut ph = phone();
    assert!(out(&mut ph, "cat /system/etc/hosts").contains("localhost"));
    assert_eq!(
        answer(&mut ph, "nslookup localhost"),
        (
            "Server:\t\t192.168.1.1\nAddress:\t192.168.1.1:53\n\nNon-authoritative answer:\n\
             Name:\tlocalhost\nAddress: 127.0.0.1\n\n"
                .to_string(),
            String::new(),
            0
        )
    );
    assert!(out(&mut ph, "nslookup ip6-localhost").contains("Address: ::1\n"));
    let (text, _, code) = answer(&mut ph, "nslookup example.com");
    assert!(
        text.ends_with("** server can't find example.com: NXDOMAIN\n\n") && code == 1,
        "{text}"
    );
}

#[test]
fn busybox_nslookup_routes_to_the_same_handler_in_its_own_layout() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "busybox nslookup localhost"),
        "Server:\t\t172.31.16.1\nAddress:\t172.31.16.1:53\n\nNon-authoritative answer:\n\
         Name:\tlocalhost\nAddress: 127.0.0.1\nName:\tlocalhost\nAddress: ::1\n\n"
    );
    assert_eq!(
        resolved_by(&mut sh, "busybox nslookup localhost"),
        HandlerId::Busybox
    );
    assert_eq!(
        reentered_by(&mut sh, "busybox nslookup localhost"),
        HandlerId::Nslookup
    );
    // getent and dig are not applets of the banner, so busybox does not have them.
    assert_eq!(status(&mut sh, "busybox getent hosts"), 127);
    assert_eq!(status(&mut sh, "busybox dig localhost"), 127);
    let mut ph = phone();
    assert_eq!(
        reentered_by(&mut ph, "toybox nslookup localhost"),
        HandlerId::Nslookup
    );
}

#[test]
fn each_command_resolves_to_its_handler() {
    let mut sh = shell();
    for (line, want) in [
        ("getent hosts", HandlerId::Getent),
        ("nslookup localhost", HandlerId::Nslookup),
        ("dig localhost", HandlerId::Dig),
    ] {
        assert_eq!(resolved_by(&mut sh, line), want, "{line}");
    }
    assert_eq!(
        resolved_by(&mut phone(), "nslookup localhost"),
        HandlerId::Nslookup
    );
}

// ------------------------------------------------------------------------------ the privacy rule

const UBUNTU_LINES: [&str; 40] = [
    "getent hosts",
    "getent hosts localhost",
    "getent hosts 127.0.0.1",
    "getent hosts example.com",
    "getent ahosts localhost",
    "getent ahostsv4 localhost",
    "getent ahosts",
    "getent passwd",
    "getent passwd root",
    "getent passwd 1000",
    "getent passwd nosuchuser",
    "getent group",
    "getent group sudo",
    "getent group 27",
    "getent bogus",
    "getent",
    "nslookup localhost",
    "nslookup example.com",
    "nslookup example.com 8.8.8.8",
    "nslookup 127.0.0.1",
    "nslookup 172.31.16.1",
    "nslookup ::1",
    "nslookup -type=AAAA localhost",
    "nslookup -type=MX localhost",
    "nslookup -type=PTR 127.0.0.1",
    "busybox nslookup localhost",
    "busybox nslookup example.com",
    "dig localhost",
    "dig +short localhost",
    "dig localhost AAAA",
    "dig -x 127.0.0.1",
    "dig example.com",
    "dig @8.8.8.8 example.com +short",
    "dig example.com MX",
    "dig -t PTR 1.0.0.127.in-addr.arpa",
    "dig -x 172.31.16.42",
    "dig localhost MX",
    "dig -x not-an-address",
    "cat /etc/resolv.conf",
    "cat /etc/group",
];

const ANDROID_LINES: [&str; 9] = [
    "nslookup localhost",
    "nslookup example.com",
    "nslookup 127.0.0.1",
    "nslookup ip6-localhost",
    "nslookup localhost 8.8.8.8",
    "busybox nslookup localhost",
    "toybox nslookup example.com",
    "getent hosts",
    "dig localhost",
];

/// The outputs of every line on both personas, errors included, with the connection's addresses
/// set to `source` and `wan`.
fn every_output(source: &str, wan: Option<&str>) -> Vec<(String, String)> {
    let mut all = Vec::new();
    let mut run = |mut sh: FakeShell, lines: &[&str], tag: &str| {
        for line in lines {
            let (stdout, stderr, code) = answer(&mut sh, line);
            all.push((
                format!("{tag}: {line}"),
                format!("{code}\n{stdout}\n{stderr}"),
            ));
        }
    };
    let ubuntu = FakeShell::new(FakeFs::new(), ctx_with("ssh", source, wan)).with_clock(friday);
    let android =
        FakeShell::android(FakeFs::android(), ctx_with("adb", source, wan)).with_clock(friday);
    run(ubuntu, &UBUNTU_LINES, "ubuntu");
    run(android, &ANDROID_LINES, "android");
    all
}

/// The real source and deployment addresses (set to documentation-range stand-ins) must reach no
/// output of any lookup, and the output must not depend on them at all.
#[test]
fn the_real_source_and_wan_addresses_never_appear_in_any_lookup_output() {
    let first = every_output(SESSION_PEER, Some(DEPLOYMENT_HOST));
    assert!(first.len() > 45, "every line ran: {}", first.len());
    for (line, output) in &first {
        for secret in [SESSION_PEER, DEPLOYMENT_HOST] {
            assert!(
                !output.contains(secret),
                "{line} printed {secret}: {output}"
            );
        }
        assert!(
            !output.contains("203.0.113.") && !output.contains("198.51.100."),
            "{line}: {output}"
        );
    }
    // Different addresses, and none at all, give byte-identical output: nothing reads them.
    assert_eq!(first, every_output("203.0.113.5", None));
    assert_eq!(first, every_output("198.51.100.9", Some("203.0.113.200")));
    // The check can fail: an output that did carry the peer is caught by the same test.
    assert!(format!("Address: {SESSION_PEER}\n").contains(SESSION_PEER));
}

/// The dotted-quad tokens of `text`, leaving out dig's banner (a package version, not an address).
fn quads(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.starts_with("; <<>> DiG"))
        .flat_map(|line| {
            line.split(|c: char| !(c.is_ascii_digit() || c == '.'))
                .filter(|token| {
                    let parts: Vec<&str> = token.split('.').collect();
                    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
                })
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn every_address_a_lookup_prints_is_loopback_or_private() {
    let mut seen = 0;
    for (line, output) in every_output(SESSION_PEER, Some(DEPLOYMENT_HOST)) {
        for quad in quads(&output) {
            seen += 1;
            let n: Vec<u8> = quad.split('.').map(|p| p.parse().unwrap()).collect();
            let private = n[0] == 127
                || n[0] == 10
                || (n[0] == 172 && (16..=31).contains(&n[1]))
                || (n[0] == 192 && n[1] == 168);
            // A reverse lookup echoes the typed address back in its arpa name, reversed, so the
            // typed public address a line carries is excluded by construction (none do).
            assert!(private, "{line} printed {quad}");
        }
    }
    assert!(seen > 40, "addresses were actually checked: {seen}");
}

#[test]
fn the_module_never_execs_or_touches_the_network_or_the_connection() {
    let source = include_str!("nameinfo.rs");
    // Built by concatenation so this file does not trip the shell tree's own source scan.
    let spawn = ["Command", "::new"].concat();
    for banned in [
        "std::net",
        "std::fs",
        "std::process",
        "std::env",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "ToSocketAddrs",
        "lookup_host",
        "getaddrinfo",
        spawn.as_str(),
        ".spawn(",
        "tokio",
        "libc",
        "source_ip",
        "wan_ip",
        "IpAddr",
        "self.ctx",
    ] {
        assert!(!source.contains(banned), "nameinfo.rs mentions {banned}");
    }
}

// ----------------------------------------------------------------------------------- bounds

#[test]
fn every_reply_is_bounded() {
    for (line, output) in every_output(SESSION_PEER, Some(DEPLOYMENT_HOST)) {
        assert!(
            output.len() < 4_096,
            "{line} printed {} bytes",
            output.len()
        );
    }
    let mut sh = shell();
    let long = "a".repeat(5_000);
    for line in [
        format!("nslookup {long}"),
        format!("dig {long}"),
        format!("getent hosts {long}"),
        format!("getent ahosts {long}"),
        format!("getent bogus{long}"),
        format!("dig -x {long}"),
    ] {
        let (stdout, stderr, _) = answer(&mut sh, &line);
        let total = stdout.len() + stderr.len();
        assert!(
            total < 2_048,
            "{} bytes for a {}-byte line",
            total,
            line.len()
        );
    }
    // A flood of keys is cut at the tool's own limit, not echoed whole.
    let keys = vec!["localhost"; 500].join(" ");
    let text = out(&mut sh, &format!("getent hosts {keys}"));
    assert!(text.lines().count() <= 64, "{}", text.lines().count());
}
