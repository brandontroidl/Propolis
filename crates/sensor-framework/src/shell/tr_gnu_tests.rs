//! The Ubuntu shell's `tr` (GNU coreutils 8.32), at the points the replay fixture
//! `tests/fixtures/sessions/ubuntu-gnu-tr.session` cannot reach: which shells have it, how it
//! splits its streams, and the places GNU and the phone's toybox answer the same line differently.
//! Every expected reply was produced by `/usr/bin/tr` of an `ubuntu:22.04` container with
//! `LANG=C.UTF-8`; the phone's replies are toybox 6.0.1's, per `tr.rs`.

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

fn ubuntu() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx())
}

fn phone() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
}

fn stream(out: &CommandResult, fd: OutputFd) -> Vec<u8> {
    out.output
        .iter()
        .filter(|segment| segment.fd == fd)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect()
}

/// `(stdout, stderr, status)` of one line.
fn answer(sh: &mut FakeShell, line: &str) -> (Vec<u8>, String, u8) {
    let out = sh.handle_input(line).0;
    (
        stream(&out, OutputFd::Stdout),
        String::from_utf8(stream(&out, OutputFd::Stderr)).unwrap(),
        out.status,
    )
}

#[test]
fn the_ubuntu_shell_has_a_tr_file_and_resolves_it() {
    let mut sh = ubuntu();
    assert_eq!(answer(&mut sh, "command -v tr").0, b"/usr/bin/tr\n");
    assert_eq!(
        answer(&mut sh, "printf 'abc' | tr a-c A-C"),
        (b"ABC".to_vec(), String::new(), 0)
    );
}

#[test]
fn busybox_tr_is_not_gnu_trs_wording() {
    // The BusyBox applet's refusals are not captured, so under `busybox` the name succeeds silently
    // rather than answering in GNU's words.
    let mut sh = ubuntu();
    assert_eq!(
        answer(&mut sh, "busybox tr"),
        (Vec::new(), String::new(), 0)
    );
}

#[test]
fn a_warning_goes_to_standard_error_and_the_translation_still_runs() {
    let mut sh = ubuntu();
    let (stdout, stderr, status) = answer(&mut sh, "printf 'abc' | tr 'a\\' x");
    assert_eq!(stdout, b"xbc".to_vec());
    assert_eq!(
        stderr,
        "tr: warning: an unescaped backslash at end of string is not portable\n"
    );
    assert_eq!(status, 0);
}

#[test]
fn bytes_above_127_are_in_no_class_under_the_utf8_c_locale() {
    // 8.32 works on bytes: the two bytes of an e-acute are neither alpha nor lower nor print.
    let mut sh = ubuntu();
    assert_eq!(
        answer(&mut sh, "printf 'caf\\303\\251\\n' | tr -d '[:alpha:]'").0,
        b"\xc3\xa9\n".to_vec()
    );
    assert_eq!(
        answer(
            &mut sh,
            "printf 'caf\\303\\251\\n' | tr '[:lower:]' '[:upper:]'"
        )
        .0,
        b"CAF\xc3\xa9\n".to_vec()
    );
    assert_eq!(
        answer(&mut sh, "printf '\\200\\377\\n' | tr -c '[:print:]' _").0,
        b"___".to_vec()
    );
}

#[test]
fn the_two_personas_answer_the_same_line_in_their_own_tr() {
    // Each pair is a line whose reply tells GNU from toybox 6.0.1.
    let cases = [
        // `\x41` is two ordinary bytes to GNU and an escape to toybox.
        ("printf 'xA\\n' | tr '\\x41' z", "zA\n", "xz\n"),
        // `\e` is an ordinary `e` to GNU and ESC to toybox.
        ("printf 'e\\n' | tr '\\e' z", "z\n", "e\n"),
        // `[y*]` pads SET2 in GNU and is four ordinary bytes in toybox.
        ("printf 'abc\\n' | tr abc 'x[y*]'", "xyy\n", "x[y\n"),
        // `-t` is an option only GNU has.
        ("printf 'abc\\n' | tr -t abc x", "xbc\n", ""),
    ];
    for (line, gnu, toybox) in cases {
        assert_eq!(
            answer(&mut ubuntu(), line).0,
            gnu.as_bytes(),
            "ubuntu: {line}"
        );
        assert_eq!(
            answer(&mut phone(), line).0,
            toybox.as_bytes(),
            "phone: {line}"
        );
    }
}

#[test]
fn a_squeeze_with_two_sets_squeezes_what_set2_names_after_translation() {
    let mut sh = ubuntu();
    // Translating spaces to underscores then squeezing underscores; the input's own underscores are
    // squeezed too, which a squeeze keyed on the input byte would not do.
    assert_eq!(
        answer(&mut sh, "printf 'a  b__c' | tr -s ' ' _").0,
        b"a_b_c".to_vec()
    );
}

/// The bytes of `0..=255` that each class holds under `LANG=C.UTF-8`, as `/usr/bin/tr -cd` printed
/// them for an input of every byte value in order.
const CLASS_BYTES: [(&str, &str); 12] = [
    (
        "alnum",
        "303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a",
    ),
    (
        "alpha",
        "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a",
    ),
    ("blank", "0920"),
    (
        "cntrl",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f7f",
    ),
    ("digit", "30313233343536373839"),
    (
        "graph",
        "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e",
    ),
    (
        "lower",
        "6162636465666768696a6b6c6d6e6f707172737475767778797a",
    ),
    (
        "print",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e",
    ),
    (
        "punct",
        "2122232425262728292a2b2c2d2e2f3a3b3c3d3e3f405b5c5d5e5f607b7c7d7e",
    ),
    ("space", "090a0b0c0d20"),
    (
        "upper",
        "4142434445464748494a4b4c4d4e4f505152535455565758595a",
    ),
    ("xdigit", "30313233343536373839414243444546616263646566"),
];

#[test]
fn each_class_holds_the_bytes_gnu_gives_it() {
    let mut sh = ubuntu();
    let every: Vec<u8> = (0..=255).collect();
    sh.fs.write_file("/tmp/every", &every).unwrap();
    for (name, hex) in CLASS_BYTES {
        let want: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let (stdout, stderr, status) =
            answer(&mut sh, &format!("tr -cd '[:{name}:]' < /tmp/every"));
        assert_eq!((stdout, stderr.as_str(), status), (want, "", 0), "{name}");
    }
}

#[test]
fn output_never_exceeds_input() {
    let mut sh = ubuntu();
    sh.fs.write_file("/tmp/blob", &[b'a'; 4096]).unwrap();
    let (stdout, _, status) = answer(&mut sh, "tr a '[b*]' < /tmp/blob");
    assert_eq!((stdout.len(), status), (4096, 0));
    let (stdout, _, _) = answer(&mut sh, "tr -d a < /tmp/blob");
    assert!(stdout.is_empty());
}
