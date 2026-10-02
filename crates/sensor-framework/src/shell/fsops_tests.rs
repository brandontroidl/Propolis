//! `touch`, `mv`, `ln`, `rmdir` and `chattr` through `handle_input`: what each leaves in the
//! per-session overlay, what a later `ls`, `cat`, `readlink` or `realpath` then sees, that a fresh
//! session sees none of it, and that every refusal is the kernel's wording. The error text is
//! coreutils' on the Ubuntu persona and toybox's on the phone; neither was recorded for these
//! commands, so the strings pin the model, not a capture.

use std::sync::Arc;

use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::budget::{BudgetLimits, ConnectionBudget};
use crate::fakefs::{ATTR_APPEND_ONLY, ATTR_IMMUTABLE, FakeFs};

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

fn phone() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
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

fn silent_ok(sh: &mut FakeShell, line: &str) {
    assert_eq!(
        answer(sh, line),
        (String::new(), String::new(), 0),
        "{line}"
    );
}

fn fails(sh: &mut FakeShell, line: &str, stderr: &str) {
    assert_eq!(
        answer(sh, line),
        (String::new(), stderr.to_string(), 1),
        "{line}"
    );
}

fn out(sh: &mut FakeShell, line: &str) -> String {
    answer(sh, line).0
}

/// The names `ls` shows in `dir`, sorted (the shell sorts them).
fn names(sh: &mut FakeShell, dir: &str) -> Vec<String> {
    out(sh, &format!("ls -a {dir}"))
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn has(sh: &mut FakeShell, dir: &str, name: &str) -> bool {
    names(sh, dir).iter().any(|n| n == name)
}

#[test]
fn touch_creates_a_file_ls_and_cat_see_and_a_fresh_session_does_not() {
    let mut sh = shell();
    silent_ok(&mut sh, "touch /tmp/t1");
    assert!(has(&mut sh, "/tmp", "t1"));
    assert_eq!(answer(&mut sh, "test -f /tmp/t1").2, 0);
    assert_eq!(
        answer(&mut sh, "cat /tmp/t1"),
        (String::new(), String::new(), 0)
    );
    // Relative names and several operands in one go.
    silent_ok(&mut sh, "cd /tmp; touch a b ./c");
    for name in ["a", "b", "c"] {
        assert!(has(&mut sh, "/tmp", name), "{name}");
    }
    // The overlay is the session's own.
    let mut fresh = shell();
    assert!(!has(&mut fresh, "/tmp", "t1"));
    assert_eq!(answer(&mut fresh, "test -e /tmp/t1").2, 1);
}

#[test]
fn touch_leaves_an_existing_file_and_its_content_alone() {
    let mut sh = shell();
    silent_ok(&mut sh, "echo kept > /tmp/f");
    silent_ok(&mut sh, "touch /tmp/f");
    assert_eq!(out(&mut sh, "cat /tmp/f"), "kept\n");
    // A baked file and a directory are touchable too.
    silent_ok(&mut sh, "touch /etc/hostname /tmp");
    assert!(has(&mut sh, "/etc", "hostname"));
}

#[test]
fn touch_c_does_not_create() {
    let mut sh = shell();
    silent_ok(&mut sh, "touch -c /tmp/never");
    silent_ok(&mut sh, "touch --no-create /tmp/never2");
    silent_ok(&mut sh, "touch -c /nonexistent_q/never");
    assert!(!has(&mut sh, "/tmp", "never"));
    assert!(!has(&mut sh, "/tmp", "never2"));
    // `-c` does not stop it creating alongside a name it does not skip, or touching one that is there.
    silent_ok(&mut sh, "echo x > /tmp/there");
    silent_ok(&mut sh, "touch -c /tmp/there");
    assert_eq!(out(&mut sh, "cat /tmp/there"), "x\n");
}

#[test]
fn touch_refuses_what_a_redirection_refuses() {
    // Under a read-only mount, for a new name and for an existing one.
    let mut sh = phone();
    fails(
        &mut sh,
        "touch /system/x",
        "touch: /system/x: Read-only file system\n",
    );
    fails(
        &mut sh,
        "touch /system/build.prop",
        "touch: /system/build.prop: Read-only file system\n",
    );
    assert!(!has(&mut sh, "/system", "x"));
    // The shell's own `>` reaches the same refusal.
    assert_eq!(answer(&mut sh, ">/system/x").2, 1);

    // A missing parent directory.
    let mut sh = shell();
    fails(
        &mut sh,
        "touch /nonexistent_q/x",
        "touch: cannot touch '/nonexistent_q/x': No such file or directory\n",
    );
    // A file where a directory is needed.
    silent_ok(&mut sh, "touch /tmp/plain");
    fails(
        &mut sh,
        "touch /tmp/plain/x",
        "touch: cannot touch '/tmp/plain/x': Not a directory\n",
    );
    // The mounts the model marks read-only are the only ones refused: `/proc` takes a file in a
    // redirection, so it takes one here, and the two agree.
    let via_touch = answer(&mut sh, "touch /proc/propolis_q").2;
    let via_redirect = answer(&mut sh, ": > /proc/propolis_q2").2;
    assert_eq!(via_touch, via_redirect);
}

#[test]
fn touch_options_and_operand_errors() {
    let mut sh = shell();
    fails(
        &mut sh,
        "touch",
        "touch: missing file operand\nTry 'touch --help' for more information.\n",
    );
    fails(
        &mut sh,
        "touch -z /tmp/x",
        "touch: invalid option -- 'z'\nTry 'touch --help' for more information.\n",
    );
    // Options that take a value consume it and change nothing the model keeps.
    silent_ok(&mut sh, "touch -d '2020-01-01' -m -a /tmp/dated");
    silent_ok(&mut sh, "touch -t 202001010000 -r /tmp/dated /tmp/dated2");
    assert!(has(&mut sh, "/tmp", "dated"));
    assert!(has(&mut sh, "/tmp", "dated2"));
    // `--` ends the options, and `-` is not a file.
    silent_ok(&mut sh, "touch -- -c");
    assert!(has(&mut sh, "/tmp", "-c") || has(&mut sh, "/root", "-c"));
    silent_ok(&mut sh, "touch -");
}

#[test]
fn mv_renames_a_baked_file_and_the_old_name_is_gone() {
    let mut sh = shell();
    let original = out(&mut sh, "cat /etc/hostname");
    assert!(!original.is_empty(), "the premise: the file has content");
    silent_ok(&mut sh, "mv /etc/hostname /tmp/h2");
    assert!(!has(&mut sh, "/etc", "hostname"));
    assert!(has(&mut sh, "/tmp", "h2"));
    assert_eq!(out(&mut sh, "cat /tmp/h2"), original);
    assert_eq!(
        answer(&mut sh, "cat /etc/hostname"),
        (
            String::new(),
            "cat: /etc/hostname: No such file or directory\n".to_string(),
            1
        )
    );
    // A fresh session still has the baked file.
    let mut fresh = shell();
    assert!(has(&mut fresh, "/etc", "hostname"));
}

#[test]
fn mv_a_session_file_onto_a_name_replaces_it_and_keeps_its_exec_bit() {
    let mut sh = shell();
    silent_ok(
        &mut sh,
        "echo new > /tmp/a; chmod +x /tmp/a; echo old > /tmp/b",
    );
    silent_ok(&mut sh, "mv /tmp/a /tmp/b");
    assert!(!has(&mut sh, "/tmp", "a"));
    assert_eq!(out(&mut sh, "cat /tmp/b"), "new\n");
    // The payload a loader chmods, then moves into place, still runs there.
    assert_eq!(answer(&mut sh, "/tmp/b").2, 0);
}

#[test]
fn mv_into_a_directory_keeps_the_basename_and_takes_many_sources() {
    let mut sh = shell();
    silent_ok(&mut sh, "mkdir /tmp/d; echo 1 > /tmp/x; echo 2 > /tmp/y");
    silent_ok(&mut sh, "mv /tmp/x /tmp/d");
    assert_eq!(out(&mut sh, "cat /tmp/d/x"), "1\n");
    assert!(!has(&mut sh, "/tmp", "x"));
    silent_ok(&mut sh, "echo 3 > /tmp/z; mv /tmp/y /tmp/z /tmp/d/");
    assert_eq!(out(&mut sh, "cat /tmp/d/y"), "2\n");
    assert_eq!(out(&mut sh, "cat /tmp/d/z"), "3\n");
    // `-t DIR` names the directory first.
    silent_ok(&mut sh, "echo 4 > /tmp/w; mv -t /tmp/d /tmp/w");
    assert_eq!(out(&mut sh, "cat /tmp/d/w"), "4\n");
    // Several sources need a directory.
    silent_ok(&mut sh, "touch /tmp/p /tmp/q /tmp/notdir");
    fails(
        &mut sh,
        "mv /tmp/p /tmp/q /tmp/notdir",
        "mv: target '/tmp/notdir': Not a directory\n",
    );
}

#[test]
fn mv_a_directory_moves_its_tree() {
    let mut sh = shell();
    silent_ok(
        &mut sh,
        "mkdir -p /tmp/src/sub; echo f > /tmp/src/f; echo g > /tmp/src/sub/g; ln -s f /tmp/src/l",
    );
    silent_ok(&mut sh, "mv /tmp/src /tmp/dst");
    assert_eq!(out(&mut sh, "cat /tmp/dst/f"), "f\n");
    assert_eq!(out(&mut sh, "cat /tmp/dst/sub/g"), "g\n");
    assert_eq!(out(&mut sh, "readlink /tmp/dst/l"), "f\n");
    assert!(!has(&mut sh, "/tmp", "src"));
    assert_eq!(answer(&mut sh, "ls /tmp/src").2, 2);
    // Into itself, and onto a non-empty directory, are refused.
    fails(
        &mut sh,
        "mv /tmp/dst /tmp/dst/inner",
        "mv: cannot move '/tmp/dst' to a subdirectory of itself, '/tmp/dst/inner'\n",
    );
    silent_ok(&mut sh, "mkdir /tmp/full; touch /tmp/full/x");
    silent_ok(&mut sh, "mkdir /tmp/empty2");
    fails(
        &mut sh,
        "mv -T /tmp/empty2 /tmp/full",
        "mv: cannot move '/tmp/empty2' to '/tmp/full': Directory not empty\n",
    );
    // Without -T the directory is the destination and the source goes inside it.
    silent_ok(&mut sh, "mv /tmp/empty2 /tmp/full");
    assert!(has(&mut sh, "/tmp/full", "empty2"));
}

#[test]
fn mv_refusals() {
    let mut sh = shell();
    fails(
        &mut sh,
        "mv /tmp/none /tmp/x",
        "mv: cannot stat '/tmp/none': No such file or directory\n",
    );
    fails(
        &mut sh,
        "mv",
        "mv: missing file operand\nTry 'mv --help' for more information.\n",
    );
    fails(
        &mut sh,
        "mv /tmp/only",
        "mv: missing destination file operand after '/tmp/only'\nTry 'mv --help' for more information.\n",
    );
    silent_ok(&mut sh, "echo a > /tmp/a");
    fails(
        &mut sh,
        "mv /tmp/a /tmp/a",
        "mv: '/tmp/a' and '/tmp/a' are the same file\n",
    );
    fails(
        &mut sh,
        "mv /tmp/a /nonexistent_q/a",
        "mv: cannot move '/tmp/a' to '/nonexistent_q/a': No such file or directory\n",
    );
    assert_eq!(
        out(&mut sh, "cat /tmp/a"),
        "a\n",
        "a refused move keeps the source"
    );
    // `-n` leaves an existing destination alone; `-v` says what it did.
    silent_ok(&mut sh, "echo b > /tmp/b");
    silent_ok(&mut sh, "mv -n /tmp/a /tmp/b");
    assert_eq!(out(&mut sh, "cat /tmp/b"), "b\n");
    assert_eq!(
        answer(&mut sh, "mv -v /tmp/a /tmp/c"),
        (
            "renamed '/tmp/a' -> '/tmp/c'\n".to_string(),
            String::new(),
            0
        )
    );
    fails(
        &mut sh,
        "mv -x /tmp/c /tmp/d",
        "mv: invalid option -- 'x'\nTry 'mv --help' for more information.\n",
    );
}

#[test]
fn mv_will_not_take_a_file_off_a_read_only_mount() {
    let mut sh = phone();
    fails(
        &mut sh,
        "mv /system/build.prop /data/local/tmp/b",
        "mv: /system/build.prop: Read-only file system\n",
    );
    assert!(has(&mut sh, "/system", "build.prop"));
    assert!(!has(&mut sh, "/data/local/tmp", "b"));
    // Nor create one there.
    silent_ok(&mut sh, "echo x > /data/local/tmp/f");
    fails(
        &mut sh,
        "mv /data/local/tmp/f /system/f",
        "mv: /data/local/tmp/f: Read-only file system\n",
    );
    assert!(has(&mut sh, "/data/local/tmp", "f"));
}

#[test]
fn ln_s_makes_a_symlink_readlink_and_realpath_resolve() {
    let mut sh = shell();
    silent_ok(&mut sh, "ln -s /etc/hostname /tmp/l");
    assert_eq!(out(&mut sh, "readlink /tmp/l"), "/etc/hostname\n");
    assert_eq!(out(&mut sh, "realpath /tmp/l"), "/etc/hostname\n");
    assert_eq!(
        out(&mut sh, "cat /tmp/l"),
        out(&mut sh, "cat /etc/hostname")
    );
    assert_eq!(answer(&mut sh, "test -L /tmp/l").2, 0);
    assert!(has(&mut sh, "/tmp", "l"));
    // The target text is stored as typed: not resolved, and a dangling one is fine.
    silent_ok(
        &mut sh,
        "ln -s ../etc/hostname /tmp/rel; ln -s nowhere /tmp/dangling",
    );
    assert_eq!(out(&mut sh, "readlink /tmp/rel"), "../etc/hostname\n");
    assert_eq!(
        out(&mut sh, "cat /tmp/rel"),
        out(&mut sh, "cat /etc/hostname")
    );
    assert_eq!(out(&mut sh, "readlink /tmp/dangling"), "nowhere\n");
    assert_eq!(answer(&mut sh, "cat /tmp/dangling").2, 1);
    // A link to a directory is entered by a path through it.
    silent_ok(&mut sh, "ln -s /etc /tmp/etclink");
    assert_eq!(
        out(&mut sh, "cat /tmp/etclink/hostname"),
        out(&mut sh, "cat /etc/hostname")
    );
    // Nothing of it survives into a fresh session.
    let mut fresh = shell();
    assert!(!has(&mut fresh, "/tmp", "l"));
}

#[test]
fn ln_into_a_directory_and_over_a_name() {
    let mut sh = shell();
    silent_ok(&mut sh, "ln -s /etc/hostname /tmp");
    assert_eq!(out(&mut sh, "readlink /tmp/hostname"), "/etc/hostname\n");
    // A name that is there is refused, then replaced by -f.
    fails(
        &mut sh,
        "ln -s /etc/passwd /tmp/hostname",
        "ln: failed to create symbolic link '/tmp/hostname': File exists\n",
    );
    assert_eq!(out(&mut sh, "readlink /tmp/hostname"), "/etc/hostname\n");
    silent_ok(&mut sh, "ln -sf /etc/passwd /tmp/hostname");
    assert_eq!(out(&mut sh, "readlink /tmp/hostname"), "/etc/passwd\n");
    // Several targets into one directory, and the single-operand form into the working directory.
    silent_ok(
        &mut sh,
        "mkdir /tmp/links; ln -s /etc/hosts /etc/shells /tmp/links",
    );
    assert!(has(&mut sh, "/tmp/links", "hosts"));
    assert!(has(&mut sh, "/tmp/links", "shells"));
    silent_ok(&mut sh, "cd /tmp/links; ln -s /usr/bin/env");
    assert_eq!(out(&mut sh, "readlink /tmp/links/env"), "/usr/bin/env\n");
    silent_ok(&mut sh, "ln -s -t /tmp/links /etc/fstab");
    assert!(has(&mut sh, "/tmp/links", "fstab"));
    // -v names the pair, and a link to a missing directory says so.
    assert_eq!(
        answer(&mut sh, "ln -sv /etc/motd /tmp/v"),
        ("'/tmp/v' -> '/etc/motd'\n".to_string(), String::new(), 0)
    );
    fails(
        &mut sh,
        "ln -s /etc/hostname /nonexistent_q/l",
        "ln: failed to create symbolic link '/nonexistent_q/l': No such file or directory\n",
    );
    silent_ok(&mut sh, "touch /tmp/plainfile");
    fails(
        &mut sh,
        "ln -s a b /tmp/plainfile",
        "ln: target '/tmp/plainfile': Not a directory\n",
    );
    fails(
        &mut sh,
        "ln -s a b /tmp/absent_q",
        "ln: target '/tmp/absent_q': No such file or directory\n",
    );
    fails(
        &mut sh,
        "ln",
        "ln: missing file operand\nTry 'ln --help' for more information.\n",
    );
}

#[test]
fn a_hard_link_is_a_second_name_holding_a_copy_of_the_bytes() {
    let mut sh = shell();
    silent_ok(&mut sh, "echo hi > /tmp/a; ln /tmp/a /tmp/b");
    assert_eq!(out(&mut sh, "cat /tmp/b"), "hi\n");
    assert!(has(&mut sh, "/tmp", "b"));
    // The model has no inode sharing: the two names diverge after a write.
    silent_ok(&mut sh, "echo more >> /tmp/a");
    assert_eq!(out(&mut sh, "cat /tmp/b"), "hi\n");
    // A baked file links too, and keeps its mode.
    silent_ok(&mut sh, "ln /etc/hostname /tmp/h");
    assert_eq!(
        out(&mut sh, "cat /tmp/h"),
        out(&mut sh, "cat /etc/hostname")
    );
    fails(
        &mut sh,
        "ln /tmp/a /tmp/b",
        "ln: failed to create hard link '/tmp/b' => '/tmp/a': File exists\n",
    );
    silent_ok(&mut sh, "ln -f /tmp/a /tmp/b");
    assert_eq!(out(&mut sh, "cat /tmp/b"), "hi\nmore\n");
    fails(
        &mut sh,
        "ln /tmp/none /tmp/c",
        "ln: failed to access '/tmp/none': No such file or directory\n",
    );
    fails(
        &mut sh,
        "ln /etc /tmp/etc2",
        "ln: '/etc': hard link not allowed for directory\n",
    );
    fails(
        &mut sh,
        "ln /tmp/a /tmp/a",
        "ln: '/tmp/a' and '/tmp/a' are the same file\n",
    );
}

#[test]
fn ln_on_the_phone_uses_its_own_wording() {
    let mut sh = phone();
    silent_ok(&mut sh, "ln -s /system/bin/sh /data/local/tmp/sh");
    // The phone has no `readlink`, so the filesystem itself is asked.
    assert_eq!(
        sh.fs.link_target("/data/local/tmp/sh").as_deref(),
        Some("/system/bin/sh")
    );
    fails(
        &mut sh,
        "ln -s /system/bin/sh /data/local/tmp/sh",
        "ln: /data/local/tmp/sh: File exists\n",
    );
    fails(
        &mut sh,
        "ln -s /data/local/tmp/sh /system/sh",
        "ln: /system/sh: Read-only file system\n",
    );
}

#[test]
fn rmdir_removes_an_empty_directory_and_refuses_the_rest() {
    let mut sh = shell();
    silent_ok(&mut sh, "mkdir /tmp/e");
    silent_ok(&mut sh, "rmdir /tmp/e");
    assert!(!has(&mut sh, "/tmp", "e"));
    assert_eq!(answer(&mut sh, "cd /tmp/e").2, 1);

    silent_ok(&mut sh, "mkdir /tmp/full; touch /tmp/full/x");
    fails(
        &mut sh,
        "rmdir /tmp/full",
        "rmdir: failed to remove '/tmp/full': Directory not empty\n",
    );
    assert!(has(&mut sh, "/tmp", "full"));
    // Once emptied it goes.
    silent_ok(&mut sh, "rm /tmp/full/x; rmdir /tmp/full");
    assert!(!has(&mut sh, "/tmp", "full"));

    fails(
        &mut sh,
        "rmdir /tmp/none",
        "rmdir: failed to remove '/tmp/none': No such file or directory\n",
    );
    silent_ok(&mut sh, "touch /tmp/plain");
    fails(
        &mut sh,
        "rmdir /tmp/plain",
        "rmdir: failed to remove '/tmp/plain': Not a directory\n",
    );
    // A symlink to a directory is not a directory to rmdir.
    silent_ok(&mut sh, "ln -s /etc /tmp/etclink");
    fails(
        &mut sh,
        "rmdir /tmp/etclink",
        "rmdir: failed to remove '/tmp/etclink': Not a directory\n",
    );
    fails(
        &mut sh,
        "rmdir",
        "rmdir: missing file operand\nTry 'rmdir --help' for more information.\n",
    );
    // A baked directory with content refuses; the others of one line still go.
    silent_ok(&mut sh, "mkdir /tmp/g1 /tmp/g2");
    assert_eq!(
        answer(&mut sh, "rmdir /tmp/g1 /etc /tmp/g2"),
        (
            String::new(),
            "rmdir: failed to remove '/etc': Directory not empty\n".to_string(),
            1
        )
    );
    assert!(!has(&mut sh, "/tmp", "g1") && !has(&mut sh, "/tmp", "g2"));
}

#[test]
fn rmdir_p_removes_empty_parents_and_stops_at_the_first_that_is_not() {
    let mut sh = shell();
    // The climb goes on until a directory is not empty, `/tmp` here.
    silent_ok(&mut sh, "mkdir -p /tmp/a/b/c; touch /tmp/anchor");
    assert_eq!(
        answer(&mut sh, "rmdir -p /tmp/a/b/c"),
        (
            String::new(),
            "rmdir: failed to remove directory '/tmp': Directory not empty\n".to_string(),
            1
        )
    );
    assert!(!has(&mut sh, "/tmp", "a"));
    assert!(has(&mut sh, "/tmp", "anchor"));

    silent_ok(&mut sh, "mkdir -p /tmp/k/l/m; touch /tmp/k/keep");
    assert_eq!(
        answer(&mut sh, "rmdir -pv /tmp/k/l/m"),
        (
            "rmdir: removing directory, '/tmp/k/l/m'\nrmdir: removing directory, '/tmp/k/l'\n"
                .to_string(),
            "rmdir: failed to remove directory '/tmp/k': Directory not empty\n".to_string(),
            1
        )
    );
    assert!(has(&mut sh, "/tmp/k", "keep"));
    // `--ignore-fail-on-non-empty` is quiet about that.
    silent_ok(&mut sh, "mkdir /tmp/ne; touch /tmp/ne/x");
    silent_ok(&mut sh, "rmdir --ignore-fail-on-non-empty /tmp/ne");
    // Relative operands climb through their own text, not the working directory.
    silent_ok(&mut sh, "mkdir -p /tmp/r1/r2; cd /tmp; rmdir -p r1/r2");
    assert!(!has(&mut sh, "/tmp", "r1"));
}

#[test]
fn rmdir_on_the_phone_uses_its_own_wording() {
    let mut sh = phone();
    silent_ok(
        &mut sh,
        "mkdir /data/local/tmp/d; touch /data/local/tmp/d/x",
    );
    fails(
        &mut sh,
        "rmdir /data/local/tmp/d",
        "rmdir: /data/local/tmp/d: Directory not empty\n",
    );
    fails(
        &mut sh,
        "rmdir /system/bin",
        "rmdir: /system/bin: Read-only file system\n",
    );
}

#[test]
fn chattr_sets_and_clears_the_stored_bits() {
    let mut sh = shell();
    silent_ok(&mut sh, "touch /tmp/f");
    silent_ok(&mut sh, "chattr +ia /tmp/f");
    assert_eq!(
        sh.fs.attrs("/tmp/f"),
        Some(ATTR_IMMUTABLE | ATTR_APPEND_ONLY)
    );
    silent_ok(&mut sh, "chattr -a /tmp/f");
    assert_eq!(sh.fs.attrs("/tmp/f"), Some(ATTR_IMMUTABLE));
    silent_ok(&mut sh, "chattr -ia /tmp/f");
    assert_eq!(sh.fs.attrs("/tmp/f"), Some(0));
    // `=` replaces the set, and separate mode arguments apply in order.
    silent_ok(&mut sh, "chattr +i /tmp/f; chattr =a /tmp/f");
    assert_eq!(sh.fs.attrs("/tmp/f"), Some(ATTR_APPEND_ONLY));
    silent_ok(&mut sh, "chattr +i -a /tmp/f");
    assert_eq!(sh.fs.attrs("/tmp/f"), Some(ATTR_IMMUTABLE));
    // A baked file and a directory carry them too, and a removed file does not keep them.
    silent_ok(&mut sh, "chattr +i /etc/hostname /tmp");
    assert_eq!(sh.fs.attrs("/etc/hostname"), Some(ATTR_IMMUTABLE));
    assert_eq!(sh.fs.attrs("/tmp"), Some(ATTR_IMMUTABLE));
    silent_ok(&mut sh, "chattr -i /tmp; rm /tmp/f; touch /tmp/f");
    assert_eq!(sh.fs.attrs("/tmp/f"), Some(0));
    // Another session's file is untouched.
    assert_eq!(FakeFs::new().attrs("/etc/hostname"), Some(0));
}

#[test]
fn the_persistence_step_clears_immutable_and_append_before_replacing_ssh() {
    let mut sh = shell();
    silent_ok(&mut sh, "mkdir -p /root/.ssh; chattr +ia /root/.ssh");
    assert_eq!(
        sh.fs.attrs("/root/.ssh"),
        Some(ATTR_IMMUTABLE | ATTR_APPEND_ONLY)
    );
    silent_ok(&mut sh, "cd ~; chattr -ia .ssh");
    assert_eq!(sh.fs.attrs("/root/.ssh"), Some(0));
    silent_ok(
        &mut sh,
        "cd ~ && rm -rf .ssh && mkdir .ssh && echo key >> .ssh/authorized_keys && chmod -R go= ~/.ssh",
    );
    assert_eq!(out(&mut sh, "cat /root/.ssh/authorized_keys"), "key\n");
}

#[test]
fn chattr_recursive_reaches_the_children() {
    let mut sh = shell();
    silent_ok(&mut sh, "mkdir -p /tmp/t/u; touch /tmp/t/a /tmp/t/u/b");
    silent_ok(&mut sh, "chattr -R +i /tmp/t");
    for path in ["/tmp/t", "/tmp/t/a", "/tmp/t/u", "/tmp/t/u/b"] {
        assert_eq!(sh.fs.attrs(path), Some(ATTR_IMMUTABLE), "{path}");
    }
    silent_ok(&mut sh, "chattr -R -i /tmp/t");
    assert_eq!(sh.fs.attrs("/tmp/t/u/b"), Some(0));
    // Without -R only the named node changes.
    silent_ok(&mut sh, "chattr +i /tmp/t");
    assert_eq!(sh.fs.attrs("/tmp/t/a"), Some(0));
}

#[test]
fn chattr_accepts_every_standard_letter_and_refuses_the_rest() {
    let mut sh = shell();
    silent_ok(&mut sh, "touch /tmp/f");
    for letter in "aAcCdDeFijPsStTu".chars() {
        silent_ok(&mut sh, &format!("chattr +{letter} /tmp/f"));
        silent_ok(&mut sh, &format!("chattr -{letter} /tmp/f"));
    }
    assert_eq!(sh.fs.attrs("/tmp/f"), Some(0));
    let usage = "Usage: chattr [-pRVf] [-+=aAcCdDeFijPsStTu] [-v version] files...\n";
    fails(&mut sh, "chattr +z /tmp/f", usage);
    fails(&mut sh, "chattr +iz /tmp/f", usage);
    assert_eq!(
        sh.fs.attrs("/tmp/f"),
        Some(0),
        "a refused mode applies nothing"
    );
    // No mode and no file both print the usage.
    fails(&mut sh, "chattr /tmp/f", usage);
    fails(&mut sh, "chattr +i", usage);
    fails(&mut sh, "chattr", usage);
}

#[test]
fn chattr_errors_name_the_file_and_the_step() {
    let mut sh = shell();
    fails(
        &mut sh,
        "chattr -ia /tmp/none",
        "chattr: No such file or directory while trying to stat /tmp/none\n",
    );
    // Later names still get their turn, and -f keeps the message back but not the status.
    silent_ok(&mut sh, "touch /tmp/real");
    assert_eq!(
        answer(&mut sh, "chattr +i /tmp/none /tmp/real"),
        (
            String::new(),
            "chattr: No such file or directory while trying to stat /tmp/none\n".to_string(),
            1
        )
    );
    assert_eq!(sh.fs.attrs("/tmp/real"), Some(ATTR_IMMUTABLE));
    assert_eq!(
        answer(&mut sh, "chattr -f +i /tmp/none"),
        (String::new(), String::new(), 1)
    );
}

#[test]
fn chattr_is_ubuntu_only() {
    let mut phone = phone();
    let (stdout, stderr, status) = answer(&mut phone, "chattr +i /data/local/tmp");
    assert_eq!((stdout.as_str(), status), ("", 127));
    assert!(stderr.contains("chattr: not found"), "{stderr:?}");
    // BusyBox does not carry it either, on any persona.
    assert_eq!(
        answer(&mut shell(), "busybox chattr +i /tmp"),
        (String::new(), "chattr: applet not found\n".to_string(), 127)
    );
    // The four applets are on the phone, as `cp`, `rm` and `mkdir` are.
    silent_ok(
        &mut phone,
        "touch /data/local/tmp/t; ln -s t /data/local/tmp/l",
    );
    silent_ok(
        &mut phone,
        "mkdir /data/local/tmp/d; rmdir /data/local/tmp/d",
    );
    silent_ok(&mut phone, "mv /data/local/tmp/t /data/local/tmp/u");
    assert!(has(&mut phone, "/data/local/tmp", "u"));
}

#[test]
fn busybox_routes_the_applets_to_the_same_handlers() {
    let mut sh = shell();
    silent_ok(&mut sh, "busybox touch /tmp/bb");
    assert!(has(&mut sh, "/tmp", "bb"));
    silent_ok(&mut sh, "/bin/busybox ln -s /etc/hostname /tmp/bl");
    assert_eq!(out(&mut sh, "readlink /tmp/bl"), "/etc/hostname\n");
    silent_ok(&mut sh, "busybox mv /tmp/bb /tmp/bc");
    assert!(has(&mut sh, "/tmp", "bc") && !has(&mut sh, "/tmp", "bb"));
    silent_ok(&mut sh, "mkdir /tmp/bd");
    silent_ok(&mut sh, "busybox rmdir /tmp/bd");
    assert!(!has(&mut sh, "/tmp", "bd"));
    // Through busybox the errors are the handler's, not a silent success.
    assert_eq!(answer(&mut sh, "busybox rmdir /tmp/bd").2, 1);
}

#[test]
fn the_overlay_budget_is_charged_and_refuses_in_the_kernels_words() {
    let mut limits = BudgetLimits::standard();
    limits.overlay_nodes = 3;
    let budget = ConnectionBudget::new(limits);
    let mut sh = FakeShell::new(FakeFs::new(), ctx()).with_budget(Arc::clone(&budget));
    silent_ok(&mut sh, "touch /tmp/a");
    silent_ok(&mut sh, "ln -s /etc/hostname /tmp/b");
    silent_ok(&mut sh, "mkdir /tmp/c");
    fails(
        &mut sh,
        "touch /tmp/d",
        "touch: cannot touch '/tmp/d': No space left on device\n",
    );
    fails(
        &mut sh,
        "ln -s /etc/hostname /tmp/e",
        "ln: failed to create symbolic link '/tmp/e': No space left on device\n",
    );
    // A move that needs a new slot is refused, and the source stays.
    fails(
        &mut sh,
        "mv /etc/hostname /tmp/f",
        "mv: cannot move '/etc/hostname' to '/tmp/f': No space left on device\n",
    );
    assert!(has(&mut sh, "/etc", "hostname"));
    // Attribute bits take a slot of their own on first use.
    fails(
        &mut sh,
        "chattr +i /etc/hostname",
        "chattr: No space left on device while setting flags on /etc/hostname\n",
    );
    // Clearing bits that were never set costs nothing.
    silent_ok(&mut sh, "chattr -i /etc/hostname");
    // The nodes already made are still there.
    assert!(has(&mut sh, "/tmp", "a") && has(&mut sh, "/tmp", "b") && has(&mut sh, "/tmp", "c"));
}

#[test]
fn nothing_here_starts_a_process_or_reaches_the_host() {
    let source = include_str!("fsops.rs");
    // Joined here so this file does not trip the tree-wide scan for the same names.
    let spawn = ["Command", "::new"].concat();
    for banned in [
        "process::",
        spawn.as_str(),
        "std::fs",
        "std::net",
        "std::env",
        "libc",
        "TcpStream",
    ] {
        assert!(!source.contains(banned), "fsops.rs uses {banned}");
    }
    // The names a session creates are the fake filesystem's: none appears on the host.
    let host_probe = "/tmp/propolis-fsops-host-probe-7c1d";
    let mut sh = shell();
    silent_ok(
        &mut sh,
        &format!(
            "touch {host_probe}; ln -s /etc/passwd {host_probe}.l; mv {host_probe} {host_probe}.m; chattr +i {host_probe}.m"
        ),
    );
    assert!(has(&mut sh, "/tmp", "propolis-fsops-host-probe-7c1d.m"));
    for suffix in ["", ".l", ".m"] {
        let path = format!("{host_probe}{suffix}");
        assert!(
            std::fs::symlink_metadata(&path).is_err(),
            "{path} exists on the host"
        );
    }
}
