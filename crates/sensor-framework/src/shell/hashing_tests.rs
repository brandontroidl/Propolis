//! `sha256sum`, `sha1sum`, `md5sum` and `cksum` through `handle_input`. Digests are the published
//! vectors for the input; the layout is GNU coreutils as run on a current Ubuntu host, not captured
//! on the reference box.

use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::fakefs::FakeFs;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "ssh".to_string(),
        session_id: None,
    }
}

fn shell() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx())
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

fn put(sh: &mut FakeShell, path: &str, bytes: &[u8]) {
    sh.fs.write_file(path, bytes).unwrap();
}

const ABC_MD5: &str = "900150983cd24fb0d6963f7d28e17f72";
const ABC_SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn sha256sum_of_empty_standard_input() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "sha256sum"),
        (format!("{EMPTY_SHA256}  -\n"), "".into(), 0)
    );
    assert_eq!(
        out(&mut sh, "printf '' | sha256sum"),
        format!("{EMPTY_SHA256}  -\n")
    );
}

#[test]
fn each_digest_of_abc_from_standard_input() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "printf '%s' abc | md5sum"),
        format!("{ABC_MD5}  -\n")
    );
    assert_eq!(
        out(&mut sh, "printf '%s' abc | sha1sum"),
        format!("{ABC_SHA1}  -\n")
    );
    assert_eq!(
        out(&mut sh, "printf '%s' abc | sha256sum"),
        format!("{ABC_SHA256}  -\n")
    );
    assert_eq!(
        out(&mut sh, "printf '%s' abc | sha256sum -"),
        format!("{ABC_SHA256}  -\n")
    );
}

#[test]
fn cksum_of_abc_and_a_length_that_needs_two_octets() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "printf '%s' abc | cksum"), "1219131554 3\n");
    // 300 is 0x012c: the length octets go least significant first, so a reversed order differs.
    let line = format!("printf '%s' {} | cksum", "a".repeat(300));
    assert_eq!(out(&mut sh, &line), "1664553091 300\n");
    assert_eq!(out(&mut sh, "printf '' | cksum"), "4294967295 0\n");
    assert_eq!(
        out(&mut sh, "printf '%s' abc | cksum -"),
        "1219131554 3 -\n"
    );
}

#[test]
fn a_modeled_file_prints_its_digest_under_its_own_name() {
    let mut sh = shell();
    put(&mut sh, "/tmp/g", b"abc");
    put(&mut sh, "/tmp/h", b"");
    assert_eq!(
        answer(&mut sh, "sha256sum /tmp/g"),
        (format!("{ABC_SHA256}  /tmp/g\n"), "".into(), 0)
    );
    assert_eq!(
        out(&mut sh, "md5sum /tmp/g"),
        format!("{ABC_MD5}  /tmp/g\n")
    );
    assert_eq!(
        out(&mut sh, "sha1sum /tmp/g"),
        format!("{ABC_SHA1}  /tmp/g\n")
    );
    assert_eq!(out(&mut sh, "cksum /tmp/g"), "1219131554 3 /tmp/g\n");
    assert_eq!(
        out(&mut sh, "sha256sum /tmp/g /tmp/h"),
        format!("{ABC_SHA256}  /tmp/g\n{EMPTY_SHA256}  /tmp/h\n")
    );
}

#[test]
fn a_missing_file_is_reported_and_the_rest_still_run() {
    let mut sh = shell();
    put(&mut sh, "/tmp/g", b"abc");
    assert_eq!(
        answer(&mut sh, "sha256sum /tmp/nope"),
        (
            "".into(),
            "sha256sum: /tmp/nope: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "md5sum /tmp/nope /tmp/g"),
        (
            format!("{ABC_MD5}  /tmp/g\n"),
            "md5sum: /tmp/nope: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "cksum /tmp/nope").1,
        "cksum: /tmp/nope: No such file or directory\n"
    );
}

#[test]
fn unmodeled_options_print_nothing_and_succeed_and_unknown_ones_are_refused() {
    let mut sh = shell();
    put(&mut sh, "/tmp/g", b"abc");
    for line in [
        "sha256sum -c /tmp/g",
        "sha256sum --check /tmp/g",
        "md5sum --tag /tmp/g",
        "sha1sum -b /tmp/g",
        "sha256sum --help",
        "cksum --version",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
    }
    let (stdout, stderr, status) = answer(&mut sh, "sha256sum -Q /tmp/g");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert_eq!(
        stderr,
        "sha256sum: invalid option -- 'Q'\nTry 'sha256sum --help' for more information.\n"
    );
    assert_eq!(
        answer(&mut sh, "md5sum --bogus").1,
        "md5sum: unrecognized option '--bogus'\nTry 'md5sum --help' for more information.\n"
    );
}

#[test]
fn the_sums_are_busybox_applets_and_cksum_is_not() {
    let mut sh = shell();
    put(&mut sh, "/tmp/g", b"abc");
    assert_eq!(
        out(&mut sh, "printf '%s' abc | busybox sha256sum"),
        format!("{ABC_SHA256}  -\n")
    );
    assert_eq!(
        out(&mut sh, "busybox md5sum /tmp/g"),
        format!("{ABC_MD5}  /tmp/g\n")
    );
    assert_eq!(
        out(&mut sh, "busybox sha1sum /tmp/g"),
        format!("{ABC_SHA1}  /tmp/g\n")
    );
    assert_eq!(
        answer(&mut sh, "busybox cksum /tmp/g"),
        ("".into(), "cksum: applet not found\n".into(), 127)
    );
}

#[test]
fn they_are_absent_on_the_phone() {
    let mut phone = FakeShell::android(FakeFs::android(), ctx());
    for name in ["sha256sum", "sha1sum", "md5sum", "cksum"] {
        let (stdout, stderr, status) = answer(&mut phone, name);
        assert_eq!(
            (stdout.as_str(), stderr.as_str(), status),
            ("", format!("sh: {name}: not found\n").as_str(), 127),
            "{name}"
        );
    }
}

/// A probe that fingerprints a binary by its digest sees one answer in every session: the image
/// is a pure function of its table row, so a fresh shell (a new connection) hashes it the same,
/// and that is the digest the image had when it was checked (`binaries.rs#GOLDEN_SHA256` for
/// busybox; the MD5 of `ls` recorded with it).
#[test]
fn a_modeled_binary_hashes_the_same_in_every_session() {
    let ls_md5 = "0ac03ada31e060acf1fcba3006bec368  /bin/ls\n";
    let busybox_sha256 =
        "07a69aaffb5f3e576a2160f81b78286a648007a0a6f0b521f79db2fa7c71ab75  /bin/busybox\n";
    for _ in 0..2 {
        let mut sh = shell();
        assert_eq!(
            answer(&mut sh, "md5sum /bin/ls"),
            (ls_md5.into(), "".into(), 0)
        );
        assert_eq!(
            answer(&mut sh, "sha256sum /bin/busybox"),
            (busybox_sha256.into(), "".into(), 0)
        );
        // `true` and `false` share a header and a size, not a digest.
        assert_ne!(
            answer(&mut sh, "md5sum < /bin/true").0,
            answer(&mut sh, "md5sum < /bin/false").0
        );
    }
}

#[test]
fn a_shell_metacharacter_in_the_data_is_only_bytes() {
    let mut sh = shell();
    let (digest, _, _) = answer(&mut sh, "printf '%s' '$(touch /tmp/x)' | sha256sum");
    assert_eq!(digest.len(), 64 + 4);
    assert_eq!(answer(&mut sh, "ls /tmp/x").2, 2);
    // A file name that looks like a command is only a name.
    let (_, stderr, status) = answer(&mut sh, "sha256sum '$(touch /tmp/x)'");
    assert_eq!(status, 1);
    assert!(stderr.contains("No such file or directory"));
    assert_eq!(answer(&mut sh, "ls /tmp/x").2, 2);
}
