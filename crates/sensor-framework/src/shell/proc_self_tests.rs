//! `/proc/self/exe` and the modeled executables behind it, through `handle_input` the way a session
//! reaches them. The header bytes are the ones recorded from Ubuntu 22.04; the unit tests of the
//! table (`binaries.rs`) pin them to the golden file, these check who gets which image.

use super::registry::{Registry, resolve_proc_self};
use super::{CommandResult, EmitContext, FakeShell};
use crate::binaries::{self, BINARIES};
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

fn run(sh: &mut FakeShell, line: &str) -> CommandResult {
    sh.handle_input(line).0
}

/// The recorded header and length of the modeled binary `name`.
fn image(name: &str) -> (Vec<u8>, usize) {
    let binary = binaries::find(name).unwrap();
    (
        binary.header().to_vec(),
        usize::try_from(binary.size).unwrap(),
    )
}

/// `out` is exactly the image of `name`: its length, and its first 64 bytes.
fn assert_is_image(out: &CommandResult, name: &str) {
    let (header, len) = image(name);
    assert_eq!(out.bytes().len(), len, "{name}: length");
    assert_eq!(&out.bytes()[..64], header.as_slice(), "{name}: header");
}

#[test]
fn a_busybox_applet_reading_proc_self_exe_reads_busybox_and_the_fallback_does_not_run() {
    let mut sh = shell();
    for line in [
        "/bin/busybox cat /proc/self/exe || cat /proc/self/exe",
        "/bin/busybox cat /proc/self/exe || cat /bin/echo",
        "busybox cat /proc/self/exe || echo unreached",
    ] {
        let out = run(&mut sh, line);
        assert_eq!(out.status, 0, "{line}");
        // One busybox image and nothing after it: the second command never ran.
        assert_is_image(&out, "busybox");
        assert_eq!(
            &out.bytes()[..8],
            b"\x7fELF\x02\x01\x01\x03",
            "ET_EXEC, OS/ABI 3"
        );
    }
}

#[test]
fn a_direct_cat_reading_proc_self_exe_reads_cat() {
    let mut sh = shell();
    for line in [
        "cat /proc/self/exe",
        "/bin/cat /proc/self/exe",
        "/usr/bin/cat /proc/self/exe",
    ] {
        let out = run(&mut sh, line);
        assert_eq!(out.status, 0, "{line}");
        assert_is_image(&out, "cat");
    }
    assert_eq!(
        &run(&mut sh, "cat /proc/self/exe").bytes()[..8],
        b"\x7fELF\x02\x01\x01\0"
    );
}

/// The reading process decides, not the shell and not the applet's name: an applet script run by
/// busybox starts its own commands, and a shell level opened with `sh` reads as dash.
#[test]
fn the_reader_is_the_process_that_opens_the_file() {
    let mut sh = shell();
    assert_is_image(
        &run(&mut sh, "/bin/busybox sh -c 'cat /proc/self/exe'"),
        "cat",
    );
    assert_is_image(&run(&mut sh, "sh -c 'cat /proc/self/exe'"), "cat");
    // Back at the outer level after the script, an applet is busybox again.
    assert_is_image(&run(&mut sh, "/bin/busybox cat /proc/self/exe"), "busybox");
    assert_is_image(&run(&mut sh, "cat /proc/self/exe"), "cat");
    // A pipeline stage is a process of its own and reads its own binary.
    assert_is_image(
        &run(&mut sh, "echo x | /bin/busybox cat /proc/self/exe"),
        "busybox",
    );
    // `cp` copies the binary of the `cp` process.
    assert_eq!(run(&mut sh, "cp /proc/self/exe /tmp/c").status, 0);
    assert_is_image(&run(&mut sh, "cat /tmp/c"), "cp");
}

/// A redirection is opened by the shell before the command replaces it, so `cat < /proc/self/exe`
/// is bash's binary, and `/proc/$$/exe` is the shell's however it is asked for.
#[test]
fn the_shells_own_proc_self_is_the_shell() {
    let mut sh = shell();
    let (bash, _) = image("bash");
    let via_redirect = run(&mut sh, "cat < /proc/self/exe");
    assert_eq!(&via_redirect.bytes()[..64], bash.as_slice());
    assert_is_image(&run(&mut sh, "cat /proc/$$/exe"), "bash");
    assert_is_image(&run(&mut sh, "( cat /proc/$$/exe )"), "bash");
    assert_is_image(&run(&mut sh, "cat $SHELL"), "bash");
    // A shell opened with `sh` is dash, with a process id of its own; the login shell's pid still
    // names bash.
    let login_pid = run(&mut sh, "echo $$").to_string().trim().to_string();
    run(&mut sh, "sh");
    let (dash, _) = image("dash");
    let via_redirect = run(&mut sh, "cat < /proc/self/exe");
    assert_eq!(&via_redirect.bytes()[..64], dash.as_slice());
    assert_is_image(&run(&mut sh, "cat /proc/$$/exe"), "dash");
    assert_is_image(&run(&mut sh, &format!("cat /proc/{login_pid}/exe")), "bash");
    assert_is_image(&run(&mut sh, "cat /proc/self/exe"), "cat");
    // Some other process id is no process.
    assert!(
        run(&mut sh, "cat /proc/1/exe").contains("No such file or directory"),
        "no other pid is modeled"
    );
}

#[test]
fn proc_self_cmdline_keeps_answering_with_the_readers_argv() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "cat /proc/self/cmdline"),
        "cat\0/proc/self/cmdline\0"
    );
    assert_eq!(
        run(&mut sh, "cat /proc/$$/cmdline"),
        "-bash\0",
        "the shell's own argv"
    );
}

/// The chain a probe runs: read the running binary into a file, mark it executable, run it. The
/// copy holds the busybox bytes and takes the mode, and running it answers as a renamed busybox
/// does (`.bb: applet not found`, 127). Nothing is executed.
#[test]
fn the_copy_of_the_running_binary_takes_the_bytes_and_the_exec_bit() {
    let mut sh = shell();
    let out = run(&mut sh, "/bin/busybox cat /proc/self/exe > /tmp/.bb");
    assert_eq!((out.status, out.bytes()), (0, &b""[..]));
    assert_is_image(&run(&mut sh, "cat /tmp/.bb"), "busybox");
    // Made by a redirection, so not executable yet.
    let out = run(&mut sh, "/tmp/.bb PROBE");
    assert_eq!(out.status, 126);
    assert_eq!(out, "-bash: /tmp/.bb: Permission denied\n");
    let out = run(&mut sh, "chmod 755 /tmp/.bb && /tmp/.bb PROBE");
    assert_eq!(out.status, 127);
    assert_eq!(out, ".bb: applet not found\n");
    // Copied by `cp` the mode comes along.
    let out = run(&mut sh, "cp /bin/busybox /tmp/.cc && /tmp/.cc PROBE");
    assert_eq!(
        (out.status, out.to_string()),
        (127, ".cc: applet not found\n".into())
    );
    // The overlay holds each copy's path, not its two megabytes.
    assert_eq!(sh.budget().owned_bytes_used(), 8 + 8);
}

/// A copy kept under a name that begins `busybox` is the multi-call binary: it takes its applet
/// from the first argument.
#[test]
fn a_copy_named_busybox_is_the_multicall_binary() {
    let mut sh = shell();
    run(&mut sh, "cp /usr/bin/busybox /tmp/busybox.x");
    assert_eq!(
        run(&mut sh, "/tmp/busybox.x PROBE"),
        "PROBE: applet not found\n"
    );
    assert_eq!(run(&mut sh, "/tmp/busybox.x PROBE").status, 127);
    assert_eq!(run(&mut sh, "/tmp/busybox.x echo hi"), "hi\n");
    assert!(run(&mut sh, "/tmp/busybox.x").starts_with("BusyBox v"));
    // A file that is not the busybox image runs as an empty program does.
    run(&mut sh, "cp /bin/ls /tmp/l; chmod 755 /tmp/l");
    let out = run(&mut sh, "/tmp/l");
    assert_eq!((out.status, out.is_empty()), (0, true));
}

#[test]
fn cat_of_a_modeled_binary_is_the_whole_image() {
    let mut sh = shell();
    for (line, name) in [
        ("cat /bin/ls", "ls"),
        ("cat /bin/echo", "echo"),
        ("/bin/busybox cat /bin/echo", "echo"),
        ("cat /bin/sh", "dash"),
        ("cat /usr/bin/bash", "bash"),
        ("cat /bin/busybox", "busybox"),
    ] {
        let out = run(&mut sh, line);
        assert_eq!(out.status, 0, "{line}");
        // `bash` is 1.3 MiB, more than one read's cap, and comes through whole.
        assert_is_image(&out, name);
    }
    let ls = run(&mut sh, "cat /bin/ls");
    assert_eq!(ls.bytes().get(409), Some(&0x0a));
    assert!(!ls.bytes()[..409].contains(&0x0a));
}

/// The phone has no modeled binaries, so nothing about `/proc/self/exe` changes there.
#[test]
fn the_phone_still_has_no_proc_self_exe() {
    let mut sh = FakeShell::android(FakeFs::android(), ctx());
    let out = run(&mut sh, "/system/xbin/busybox cat /proc/self/exe");
    assert_eq!(out.status, 1);
    assert_eq!(out, "cat: /proc/self/exe: No such file or directory\n");
    run(&mut sh, "cd /data/local/tmp");
    let out = run(
        &mut sh,
        "/system/xbin/busybox cat /proc/self/exe > .bb; chmod 755 .bb; ./.bb PROBE",
    );
    assert_eq!(out, "cat: /proc/self/exe: No such file or directory\n");
}

/// The registry's facts and the filesystem's nodes come from one table and agree: every command a
/// binary answers to has its path, size and mode in the registry, and the node at that path has the
/// same.
#[test]
fn registry_facts_agree_with_the_filesystem_nodes() {
    let fs = FakeFs::new();
    let registry = Registry::builtin();
    for binary in BINARIES {
        let facts = registry
            .node_facts(binary.name)
            .unwrap_or_else(|| panic!("{} has no facts", binary.name));
        assert_eq!(
            (facts.path, facts.size, facts.mode),
            (binary.path, binary.size, binary.mode)
        );
        let (blob, mode) = fs.content_and_mode(facts.path).unwrap();
        assert_eq!(
            (blob.len(), mode),
            (facts.size, facts.mode),
            "{}",
            binary.name
        );
        assert_eq!(resolve_proc_self(binary.name), Some(binary.path));
    }
    assert_eq!(
        resolve_proc_self("sh"),
        Some("/usr/bin/dash"),
        "the sh link is dash"
    );
    assert_eq!(resolve_proc_self("tftp"), None, "no file behind the name");
    assert_eq!(resolve_proc_self("nosuchcommand"), None);
}

/// The backlog's acceptance transcript, in order, in one session. The lines that need a command
/// family not built yet (`dd` is F3, `readlink` is F4) keep their not-found replies and are pinned
/// as such, so the day they are modeled this test says which line to flip.
#[test]
fn the_backlog_acceptance_transcript_replays_its_f1_lines() {
    let mut sh = shell();
    // The first two replies are the busybox image and nothing else: the fallback never ran.
    for line in [
        "/bin/busybox cat /proc/self/exe || cat /proc/self/exe",
        "/bin/busybox cat /proc/self/exe || cat /bin/echo",
    ] {
        let out = run(&mut sh, line);
        assert_eq!(out.status, 0, "{line}");
        assert_is_image(&out, "busybox");
    }
    // F3: dd is not an applet yet.
    assert_eq!(
        run(&mut sh, "/bin/busybox dd if=/proc/self/exe bs=22 count=1"),
        "dd: applet not found\n"
    );
    assert_eq!(
        run(&mut sh, "/bin/busybox dd if=\"$SHELL\" bs=22 count=1"),
        "dd: applet not found\n"
    );
    // The copy takes the bytes and then the exec bit; running it is simulated.
    assert_eq!(
        run(&mut sh, "/bin/busybox cat /proc/self/exe > /tmp/.bb"),
        ""
    );
    assert_is_image(&run(&mut sh, "cat /tmp/.bb"), "busybox");
    assert_eq!(
        run(&mut sh, "chmod 755 /tmp/.bb && /tmp/.bb PROBE"),
        ".bb: applet not found\n"
    );
    // F4: readlink is not modeled yet.
    assert_eq!(
        run(&mut sh, "readlink /proc/self/exe"),
        "readlink: command not found\n"
    );
}

/// The synthetic images are generated data: nothing in the modules that build them reads a file of
/// the host at run time or starts a process.
#[test]
fn image_generation_touches_no_host_file_and_starts_no_process() {
    for (name, source) in [
        ("binaries.rs", include_str!("../binaries.rs")),
        ("fakefs.rs", include_str!("../fakefs.rs")),
        ("registry.rs", include_str!("registry.rs")),
        ("read.rs", include_str!("read.rs")),
    ] {
        let production = source.split("#[cfg(test)]").next().unwrap();
        for banned in [
            "std::fs",
            "File::open",
            "include_bytes!",
            "include_str!",
            "std::process",
            "read_link",
        ] {
            assert!(!production.contains(banned), "{name} uses {banned}");
        }
    }
}

/// Every command the persona names that is also a real Ubuntu binary has a node, so a registered
/// handler and a `cat` of its file cannot disagree about whether the file exists.
#[test]
fn every_registered_command_with_a_recorded_binary_has_facts() {
    let registry = Registry::builtin();
    for name in [
        "uname", "id", "whoami", "echo", "cat", "head", "ls", "mount", "true", "false", "wget",
        "curl", "ping", "sh", "bash", "busybox", "chmod", "cp", "rm", "mkdir", "sleep", "su",
    ] {
        assert!(registry.node_facts(name).is_some(), "{name}");
    }
}
