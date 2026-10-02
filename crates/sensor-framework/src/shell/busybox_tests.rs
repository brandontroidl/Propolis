//! The multi-call banner and applet dispatch. The banner is pinned to the reference build's own
//! output (ubuntu-2204-ground-truth-2026-09-29, "busybox bare": 2686 bytes, 263 applets, and the
//! pty capture of a bare `/bin/busybox`), so a change that reflows or reorders it fails here.

use super::busybox::{applets, banner, is_applet};
use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::fakefs::FakeFs;
use crate::sanitize::to_hex_bounded;
use sha2::{Digest, Sha256};

fn shell() -> FakeShell {
    FakeShell::new(
        FakeFs::new(),
        EmitContext {
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            authenticated: true,
            protocol_label: "telnet".to_string(),
            session_id: None,
        },
    )
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

#[test]
fn the_banner_is_the_captured_one_byte_for_byte() {
    let text = banner();
    assert_eq!(text.len(), 2686, "the capture's byte count");
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    assert_eq!(
        lines[0],
        "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3.1) multi-call binary.\n"
    );
    assert_eq!(lines[7], "   or: busybox --install [-s] [DIR]\n");
    assert_eq!(
        lines[12],
        "\tis configured to run built-in utilities without $PATH search.\n"
    );
    assert_eq!(lines[16], "Currently defined functions:\n");
    // The build's own wrap: a row ends after `bc,` and the next opens with `blkdiscard`.
    assert_eq!(
        lines[17],
        "\t[, [[, acpid, adjtimex, ar, arch, arp, arping, ash, awk, basename, bc,\n"
    );
    assert_eq!(
        lines[18],
        "\tblkdiscard, blockdev, brctl, bunzip2, busybox, bzcat, bzip2, cal, cat,\n"
    );
    assert!(text.ends_with(
        "\twatchdog, wc, wget, which, who, whoami, xargs, xxd, xz, xzcat, yes,\n\tzcat\n"
    ));
    assert_eq!(lines.len(), 17 + 30);
    // The whole banner, so a changed name anywhere in it fails. This is the digest of the pty
    // capture's bare `/bin/busybox` reply (c-fxcat-sweep.typescript, CRs removed), not of this
    // module's own output.
    assert_eq!(
        to_hex_bounded(&Sha256::digest(text.as_bytes()), 32),
        "80cec454353885652f7d9e23c5e7e13b17f149c7e8e0324d500eaf6735a25bd1"
    );
}

#[test]
fn the_applet_set_is_exactly_what_the_banner_lists() {
    let text = banner();
    let listed: Vec<&str> = text
        .split_once("Currently defined functions:\n")
        .unwrap()
        .1
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|name| !name.is_empty())
        .collect();
    assert_eq!(listed, applets());
    assert_eq!(applets().len(), 263);
    let mut sorted = applets().to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 263, "no name is listed twice");
    for applet in applets() {
        assert!(is_applet(applet), "{applet} listed but not recognized");
    }
}

#[test]
fn no_listed_applet_says_applet_not_found() {
    for applet in applets() {
        let (stdout, stderr, status) = answer(&mut shell(), &format!("busybox {applet}"));
        assert!(
            !stdout.contains("applet not found") && !stderr.contains("applet not found"),
            "`busybox {applet}` contradicts the banner: {stderr:?}"
        );
        assert_ne!(status, 127, "`busybox {applet}`");
    }
}

#[test]
fn a_name_the_banner_does_not_list_is_applet_not_found() {
    for name in ["curl", "bash", "PROBEX", "cd", "/bin/ls", "LS", "busybox2"] {
        assert!(!is_applet(name), "{name}");
        let (stdout, stderr, status) = answer(&mut shell(), &format!("busybox {name} x"));
        assert_eq!(
            (stdout.as_str(), stderr.as_str(), status),
            ("", format!("{name}: applet not found\n").as_str(), 127),
            "{name}"
        );
    }
}

#[test]
fn a_listed_applet_without_a_model_succeeds_silently() {
    // The usage text and behavior of these are not captured, so none is invented.
    for line in [
        "busybox nslookup example.com",
        "busybox nproc",
        "busybox ifconfig",
        "busybox reboot",
        "/bin/busybox vi /tmp/x",
    ] {
        assert_eq!(
            answer(&mut shell(), line),
            (String::new(), String::new(), 0),
            "{line}"
        );
    }
}

#[test]
fn a_listed_applet_with_a_model_runs_it() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "/bin/busybox echo -e '\\x51\\x4a\\x4c'").0,
        "QJL\n"
    );
    assert_eq!(answer(&mut sh, "busybox whoami").0, "root\n");
    assert_eq!(answer(&mut sh, "busybox chmod +x x").0, "");
    // A name that is both an applet and modeled dispatches the same way through busybox.
    let plain = answer(&mut sh, "echo hello | wc -c").0;
    assert_eq!(plain, "6\n");
    assert_eq!(answer(&mut sh, "echo hello | busybox wc -c").0, plain);
}
