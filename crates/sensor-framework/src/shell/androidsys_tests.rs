//! The Android system commands through `handle_input`. No capture backs their wording, so the
//! tests pin the properties that matter for a honeypot: each reply is bounded, each command ends,
//! the persona facts agree with `getprop`, the commands exist only on the phone, and none of them
//! reaches past the session.

use super::{CommandResult, EmitContext, FakeShell, HandlerId, OutputFd};
use crate::fakefs::FakeFs;

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

const NAMES: [&str; 7] = [
    "getenforce",
    "pm",
    "am",
    "wm",
    "dumpsys",
    "screencap",
    "logcat",
];

#[test]
fn getenforce_reports_enforcing() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "getenforce"),
        ("Enforcing\n".into(), "".into(), 0)
    );
}

#[test]
fn wm_reports_the_nexus_5_panel() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "wm size"),
        ("Physical size: 1080x1920\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "wm density"),
        ("Physical density: 480\n".into(), "".into(), 0)
    );
    let (stdout, stderr, status) = answer(&mut sh, "wm frobnicate");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert!(stderr.starts_with("usage: wm"), "{stderr:?}");
    // Setting is accepted and not applied: the panel stays what it is.
    assert_eq!(answer(&mut sh, "wm size 720x1280").2, 0);
    assert_eq!(out(&mut sh, "wm size"), "Physical size: 1080x1920\n");
}

#[test]
fn pm_list_packages_is_bounded_and_every_line_is_a_package() {
    let mut sh = android();
    let (listing, _, status) = answer(&mut sh, "pm list packages");
    assert_eq!(status, 0);
    let lines: Vec<&str> = listing.lines().collect();
    assert!(!lines.is_empty() && lines.len() <= 32, "{}", lines.len());
    assert!(lines.iter().all(|l| l.starts_with("package:")), "{lines:?}");
    assert!(lines.contains(&"package:android"));
    assert!(lines.contains(&"package:com.google.android.gms"));
    assert!(listing.len() < 2048);
}

#[test]
fn pm_list_packages_options_filter_and_add_paths() {
    let mut sh = android();
    let with_paths = out(&mut sh, "pm list packages -f");
    for line in with_paths.lines() {
        let (path, name) = line
            .strip_prefix("package:")
            .and_then(|rest| rest.split_once('='))
            .unwrap_or_else(|| panic!("{line}"));
        assert!(
            path.starts_with("/system/") && path.ends_with(".apk"),
            "{line}"
        );
        assert!(!name.is_empty());
    }
    assert_eq!(
        out(&mut sh, "pm list packages gms"),
        "package:com.google.android.gms\n"
    );
    // No third-party package is modeled.
    assert_eq!(
        answer(&mut sh, "pm list packages -3"),
        ("".into(), "".into(), 0)
    );
}

#[test]
fn pm_path_agrees_with_the_listing() {
    let mut sh = android();
    let listing = out(&mut sh, "pm list packages -f");
    let path = out(&mut sh, "pm path com.android.settings");
    let want = listing
        .lines()
        .find(|l| l.ends_with("=com.android.settings"))
        .unwrap();
    assert_eq!(
        path.trim_end().strip_prefix("package:").unwrap(),
        want.strip_prefix("package:")
            .unwrap()
            .strip_suffix("=com.android.settings")
            .unwrap()
    );
    assert_eq!(
        answer(&mut sh, "pm path no.such.pkg"),
        ("".into(), "".into(), 1)
    );
}

#[test]
fn pm_install_and_uninstall() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "pm install -r /data/local/tmp/a.apk"),
        ("Success\n".into(), "".into(), 0)
    );
    assert_eq!(out(&mut sh, "pm uninstall com.android.chrome"), "Success\n");
    assert_eq!(out(&mut sh, "pm uninstall no.such.pkg"), "Failure\n");
    let (stdout, stderr, status) = answer(&mut sh, "pm install");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert!(stderr.starts_with("usage: pm"), "{stderr:?}");
    assert!(answer(&mut sh, "pm").1.starts_with("usage: pm"));
}

#[test]
fn am_start_and_broadcast_echo_the_intent() {
    let mut sh = android();
    assert_eq!(
        answer(
            &mut sh,
            "am start -a android.intent.action.VIEW -d http://203.0.113.9/x"
        ),
        (
            "Starting: Intent { act=android.intent.action.VIEW dat=http://203.0.113.9/x }\n".into(),
            "".into(),
            0
        )
    );
    assert_eq!(
        out(&mut sh, "am start -n com.android.settings/.Settings"),
        "Starting: Intent { cmp=com.android.settings/.Settings }\n"
    );
    // A key/value extra is skipped, not mistaken for the component.
    assert_eq!(
        out(&mut sh, "am start -e k v -n a.b/.C"),
        "Starting: Intent { cmp=a.b/.C }\n"
    );
    assert_eq!(
        out(
            &mut sh,
            "am broadcast -a android.intent.action.BOOT_COMPLETED"
        ),
        "Broadcasting: Intent { act=android.intent.action.BOOT_COMPLETED }\n\
         Broadcast completed: result=0\n"
    );
    let (stdout, stderr, status) = answer(&mut sh, "am start");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert!(stderr.starts_with("usage: am"), "{stderr:?}");
    assert!(answer(&mut sh, "am frobnicate").1.starts_with("usage: am"));
}

#[test]
fn am_never_echoes_unbounded_attacker_text() {
    let mut sh = android();
    let long = "x".repeat(5000);
    let reply = out(&mut sh, &format!("am start -a {long}"));
    assert!(reply.len() < 300, "{}", reply.len());
}

#[test]
fn dumpsys_lists_a_bounded_set_of_services() {
    let mut sh = android();
    let (listing, _, status) = answer(&mut sh, "dumpsys");
    assert_eq!(status, 0);
    assert!(listing.starts_with("Currently running services:\n"));
    assert!(listing.lines().count() <= 32 && listing.len() < 1024);
    assert_eq!(out(&mut sh, "dumpsys -l"), listing);
}

#[test]
fn dumpsys_of_one_service_is_a_header_only() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "dumpsys battery"),
        ("DUMP OF SERVICE battery:\n".into(), "".into(), 0)
    );
    // A service the listing names is dumpable; one it does not is not found.
    assert_eq!(
        answer(&mut sh, "dumpsys nonesuch"),
        ("Can't find service: nonesuch\n".into(), "".into(), 0)
    );
    let long = "y".repeat(5000);
    assert!(out(&mut sh, &format!("dumpsys {long}")).len() < 300);
    assert!(out(&mut sh, "dumpsys package com.android.chrome").len() < 64);
}

#[test]
fn screencap_with_a_path_creates_a_small_overlay_file() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "screencap -p /data/local/tmp/s.png"),
        ("".into(), "".into(), 0)
    );
    let size = sh.fs.stat("/data/local/tmp/s.png", true).unwrap();
    assert!(size.size > 0 && size.size <= 16, "{}", size.size);
    assert!(out(&mut sh, "ls /data/local/tmp").contains("s.png"));
    assert!(
        sh.fs
            .read_all("/data/local/tmp/s.png", 8)
            .unwrap()
            .starts_with(b"\x89PNG")
    );
    // The raw form writes its own tiny header and is not a PNG.
    assert_eq!(answer(&mut sh, "screencap /data/local/tmp/r.raw").2, 0);
    assert!(sh.fs.stat("/data/local/tmp/r.raw", true).unwrap().size <= 16);
}

#[test]
fn screencap_without_a_path_prints_nothing_and_a_bad_path_is_refused() {
    let mut sh = android();
    assert_eq!(answer(&mut sh, "screencap"), ("".into(), "".into(), 0));
    assert_eq!(answer(&mut sh, "screencap -p"), ("".into(), "".into(), 0));
    let (stdout, stderr, status) = answer(&mut sh, "screencap -p /system/s.png");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert_eq!(stderr, "screencap: /system/s.png: Read-only file system\n");
    assert!(sh.fs.stat("/system/s.png", true).is_none());
}

#[test]
fn logcat_dump_is_bounded_and_ends() {
    let mut sh = android();
    let (dump, _, status) = answer(&mut sh, "logcat -d");
    assert_eq!(status, 0);
    assert!(!dump.is_empty() && dump.lines().count() <= 16 && dump.len() < 2048);
    // A bare `logcat` would follow the log forever; nothing here appends to it, so it ends with
    // the same lines, as `tail -f` does.
    assert_eq!(answer(&mut sh, "logcat"), (dump.clone(), "".into(), 0));
    assert_eq!(
        out(&mut sh, "logcat -v time -b main -s ActivityManager"),
        dump
    );
    // The bound holds when it is the left side of a pipe a loop could keep feeding.
    assert!(out(&mut sh, "logcat -d | cat").len() <= dump.len());
}

#[test]
fn logcat_clear_prints_nothing() {
    let mut sh = android();
    assert_eq!(answer(&mut sh, "logcat -c"), ("".into(), "".into(), 0));
    assert_eq!(
        answer(&mut sh, "logcat -b all -c"),
        ("".into(), "".into(), 0)
    );
}

#[test]
fn every_command_is_absent_on_bash() {
    let mut sh = bash();
    for name in NAMES {
        let (stdout, stderr, status) = answer(&mut sh, &format!("{name} -d"));
        assert_eq!(stdout, "", "{name}");
        assert_eq!(status, 127, "{name}");
        assert!(stderr.contains("not found"), "{name}: {stderr}");
        assert_ne!(
            answer(&mut sh, &format!("command -v {name}")).2,
            0,
            "{name}"
        );
    }
}

/// They are real nodes of the phone, so the lookup commands find them and agree with dispatch.
#[test]
fn the_lookup_commands_find_each_command_on_the_phone() {
    let mut sh = android();
    let listing = out(&mut sh, "ls /system/bin");
    for name in NAMES {
        assert_eq!(
            answer(&mut sh, &format!("command -v {name}")),
            (format!("/system/bin/{name}\n"), "".into(), 0),
            "{name}"
        );
        assert!(
            listing.split_whitespace().any(|l| l == name),
            "{name} not listed"
        );
        assert!(
            sh.fs.is_executable(&format!("/system/bin/{name}")),
            "{name}"
        );
        assert_eq!(
            answer(&mut sh, &format!("type {name}")).0,
            format!("{name} is /system/bin/{name}\n"),
            "{name}"
        );
    }
}

#[test]
fn the_decision_is_recorded_per_command() {
    let mut sh = android();
    for (line, id) in [
        ("getenforce", HandlerId::Getenforce),
        ("pm list packages", HandlerId::Pm),
        ("am start -a x", HandlerId::Am),
        ("wm size", HandlerId::Wm),
        ("dumpsys", HandlerId::Dumpsys),
        ("screencap", HandlerId::Screencap),
        ("logcat -d", HandlerId::Logcat),
    ] {
        sh.handle_input(line);
        let command = sh.last_trace().segments[0].command.as_ref().unwrap();
        assert_eq!(command.resolved, id, "{line}");
    }
}

/// Canned replies and one bounded overlay write: the source holds no process, socket or file API,
/// and no line the attacker types runs anything.
#[test]
fn the_handlers_never_reach_the_host() {
    let source = include_str!("androidsys.rs");
    for banned in ["std::fs", "std::process", "std::net", "tokio", "libc"] {
        assert!(!source.contains(banned), "androidsys.rs mentions {banned}");
    }
    let mut sh = android();
    // An argument that looks like something to run or fetch is only text.
    for line in [
        "am start -d http://203.0.113.9/payload.sh",
        "pm install /data/local/tmp/payload.apk",
        "dumpsys $(echo evil)",
    ] {
        assert!(answer(&mut sh, line).1.is_empty(), "{line}");
    }
    assert_eq!(out(&mut sh, "pwd"), "/\n");
}
