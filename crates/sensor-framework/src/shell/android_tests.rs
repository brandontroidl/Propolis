//! `getprop` and `setprop` through `handle_input`. The property values are checked against the
//! other places the device states them (the fingerprint, `uname`, `/system/build.prop`, the ELF
//! class of the modeled binaries), so a table that drifts from the persona fails here.

use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::fakefs::FakeFs;
use crate::persona;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "adb".to_string(),
        session_id: None,
    }
}

fn android() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
}

fn bash() -> FakeShell {
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

#[test]
fn getprop_reports_the_modeled_build_and_release() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "getprop ro.build.version.release"),
        ("6.0.1\n".into(), "".into(), 0)
    );
    assert_eq!(out(&mut sh, "getprop ro.build.version.sdk"), "23\n");
    assert_eq!(out(&mut sh, "getprop ro.product.model"), "Nexus 5\n");
    assert_eq!(out(&mut sh, "getprop ro.build.id"), "M4B30Z\n");
    assert_eq!(
        out(&mut sh, "getprop ro.build.fingerprint"),
        format!("{}\n", persona::android_fingerprint())
    );
}

/// The ABI is the 32-bit ARM `uname -m` reports and the 32-bit class the modeled Android
/// executables carry; `/system/build.prop` states the same value.
#[test]
fn the_abi_agrees_with_uname_the_elf_and_build_prop() {
    let mut sh = android();
    let abi = out(&mut sh, "getprop ro.product.cpu.abi");
    assert_eq!(abi, "armeabi-v7a\n");
    assert_eq!(
        out(&mut sh, "uname -m"),
        format!("{}\n", persona::ANDROID_ARCH)
    );
    assert_eq!(persona::ANDROID_ARCH, "armv7l");
    let list = out(&mut sh, "getprop ro.product.cpu.abilist");
    assert!(list.starts_with(abi.trim_end()), "{list}");
    let header = sh.fs.read_all("/system/bin/sh", 8).unwrap();
    assert_eq!(header.get(..4), Some(&b"\x7fELF"[..]));
    assert_eq!(header.get(4), Some(&1), "ELFCLASS32 for a 32-bit ARM ABI");
    let prop = String::from_utf8(sh.fs.read_all("/system/build.prop", 4096).unwrap()).unwrap();
    assert!(prop.contains(&format!("ro.product.cpu.abi={}", abi.trim_end())));
}

/// Every product and build property is derived from the one fingerprint
/// `google/hammerhead/hammerhead:6.0.1/M4B30Z/3565761:user/release-keys`, and agrees with the
/// properties `/system/build.prop` carries.
#[test]
fn the_properties_agree_with_the_fingerprint_and_build_prop() {
    let mut sh = android();
    let fingerprint = out(&mut sh, "getprop ro.build.fingerprint");
    // brand/name/device:release/id/incremental:type/tags
    let fields: Vec<&str> = fingerprint.trim_end().split(['/', ':']).collect();
    assert_eq!(fields.len(), 8, "{fingerprint}");
    let (brand, name, device, release, id, incremental, build_type, tags) = (
        fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7],
    );
    let expect = [
        ("ro.product.brand", brand),
        ("ro.product.name", name),
        ("ro.product.device", device),
        ("ro.hardware", device),
        ("ro.build.version.release", release),
        ("ro.build.id", id),
        ("ro.build.version.incremental", incremental),
        ("ro.build.type", build_type),
        ("ro.build.tags", tags),
    ];
    let prop = String::from_utf8(sh.fs.read_all("/system/build.prop", 4096).unwrap()).unwrap();
    for (key, want) in expect {
        assert_eq!(
            out(&mut sh, &format!("getprop {key}")),
            format!("{want}\n"),
            "{key}"
        );
        if prop.contains(&format!("{key}=")) {
            assert!(
                prop.contains(&format!("{key}={want}\n")),
                "build.prop {key}"
            );
        }
    }
    assert_eq!(out(&mut sh, "getprop ro.product.manufacturer"), "LGE\n");
    assert!(prop.contains("ro.product.manufacturer=LGE\n"));
    assert!(prop.contains("ro.board.platform=msm8974\n"));
    assert_eq!(out(&mut sh, "getprop ro.board.platform"), "msm8974\n");
}

#[test]
fn getprop_without_an_argument_lists_every_property_sorted() {
    let mut sh = android();
    let (listing, err, status) = answer(&mut sh, "getprop");
    assert_eq!((err.as_str(), status), ("", 0));
    assert!(
        listing.contains("[ro.product.model]: [Nexus 5]\n"),
        "{listing}"
    );
    assert!(listing.contains("[ro.build.version.sdk]: [23]\n"));
    let names: Vec<&str> = listing
        .lines()
        .map(|l| l.split(']').next().unwrap())
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
}

#[test]
fn an_unknown_property_is_an_empty_line_unless_a_default_is_given() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "getprop ro.nonesuch"),
        ("\n".into(), "".into(), 0)
    );
    assert_eq!(out(&mut sh, "getprop ro.nonesuch fallback"), "fallback\n");
    assert_eq!(out(&mut sh, "getprop ro.build.version.sdk 99"), "23\n");
}

#[test]
fn setprop_is_read_back_by_getprop_and_listed() {
    let mut sh = android();
    assert_eq!(answer(&mut sh, "setprop x.y z"), ("".into(), "".into(), 0));
    assert_eq!(out(&mut sh, "getprop x.y"), "z\n");
    assert!(out(&mut sh, "getprop").contains("[x.y]: [z]\n"));
    // adbd is root, so a ro.* property is writable and the overlay wins over the table.
    assert_eq!(answer(&mut sh, "setprop ro.product.model Pixel").2, 0);
    assert_eq!(out(&mut sh, "getprop ro.product.model"), "Pixel\n");
    // The overlay is the session's: a subshell's setprop survives it, a fresh session is untouched.
    out(&mut sh, "(setprop sub.shell kept)");
    assert_eq!(out(&mut sh, "getprop sub.shell"), "kept\n");
    assert_eq!(out(&mut android(), "getprop x.y"), "\n");
}

#[test]
fn setprop_with_the_wrong_argument_count_prints_the_usage() {
    let mut sh = android();
    for line in ["setprop", "setprop only.name", "setprop a b c"] {
        assert_eq!(
            answer(&mut sh, line),
            ("".into(), "usage: setprop <key> <value>\n".into(), 1),
            "{line}"
        );
    }
    assert_eq!(out(&mut sh, "getprop only.name"), "\n");
}

#[test]
fn setprop_past_the_property_limits_fails_and_stores_nothing() {
    let mut sh = android();
    let long_name = "n".repeat(32);
    let long_value = "v".repeat(92);
    assert_eq!(
        answer(&mut sh, &format!("setprop {long_name} 1")),
        ("".into(), "could not set property\n".into(), 255)
    );
    assert_eq!(answer(&mut sh, &format!("setprop a.b {long_value}")).2, 255);
    assert_eq!(out(&mut sh, "getprop a.b"), "\n");
    // `ro.` values are exempt from the value limit.
    assert_eq!(
        answer(&mut sh, &format!("setprop ro.a.b {long_value}")).2,
        0
    );
    for i in 0..600 {
        sh.handle_input(format!("setprop p.{i} 1"));
    }
    assert_eq!(out(&mut sh, "getprop p.0"), "1\n");
    assert_eq!(out(&mut sh, "getprop p.599"), "\n");
    // An existing property can still be rewritten once the overlay is full.
    assert_eq!(answer(&mut sh, "setprop p.0 2").2, 0);
    assert_eq!(out(&mut sh, "getprop p.0"), "2\n");
}

#[test]
fn the_ubuntu_shell_has_neither_command() {
    let mut sh = bash();
    for line in ["getprop ro.product.model", "setprop a b"] {
        let (stdout, stderr, status) = answer(&mut sh, line);
        assert_eq!((stdout.as_str(), status), ("", 127), "{line}");
        assert!(stderr.contains("not found"), "{stderr}");
    }
}

/// Nothing `setprop` stores reaches the filesystem the session reads.
#[test]
fn setprop_never_touches_the_filesystem() {
    let mut sh = android();
    let before = sh.fs.read_all("/system/build.prop", 4096).unwrap();
    sh.handle_input("setprop ro.build.version.release 9");
    assert_eq!(sh.fs.read_all("/system/build.prop", 4096).unwrap(), before);
}
