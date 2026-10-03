//! `stat` and `find` through `handle_input`. No capture backs the layouts, so the cases check
//! what must hold regardless: a `stat` figure is the one the filesystem holds (and agrees with
//! `wc`, `df` and `ls`), and `find` lists exactly the modeled nodes, sorted, inside its bounds. The exact-layout cases pin the
//! wording the module claims.

use super::fileinfo::{FIND_DEPTH_MAX, FIND_VISIT_MAX};
use super::{CommandResult, EmitContext, FakeShell, HandlerId, OutputFd};
use crate::fakefs::{Blob, FakeFs};

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "telnet".to_string(),
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

fn out(sh: &mut FakeShell, line: &str) -> String {
    answer(sh, line).0
}

/// Lines of output, one per path, newline-terminated.
fn lines(paths: &[&str]) -> String {
    paths.iter().map(|path| format!("{path}\n")).collect()
}

fn noon() -> chrono::DateTime<chrono::Utc> {
    "2026-09-29T12:00:00Z".parse().unwrap()
}

fn midnight() -> chrono::DateTime<chrono::Utc> {
    "2031-03-01T00:00:00Z".parse().unwrap()
}

/// `/tmp/t` holds `.hid.txt` (1 byte), `a.txt` (5), `b.log` (5000) and `sub`, which holds `c.txt`
/// (2), `deep` (with `d.TXT` of 3 bytes and the empty directory `e`) and the empty file `zero`.
fn tree(sh: &mut FakeShell) {
    for dir in [
        "/tmp/t",
        "/tmp/t/sub",
        "/tmp/t/sub/deep",
        "/tmp/t/sub/deep/e",
    ] {
        sh.fs.make_dir(dir).unwrap();
    }
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("/tmp/t/.hid.txt", b"x".to_vec()),
        ("/tmp/t/a.txt", b"hello".to_vec()),
        ("/tmp/t/b.log", vec![b'x'; 5000]),
        ("/tmp/t/sub/c.txt", b"y\n".to_vec()),
        ("/tmp/t/sub/deep/d.TXT", b"abc".to_vec()),
        ("/tmp/t/sub/zero", Vec::new()),
    ];
    for (path, bytes) in files {
        sh.fs.write_file(path, &bytes).unwrap();
    }
}

// ------------------------------------------------------------------------------------------ stat

#[test]
fn stat_of_a_modeled_file_shows_the_size_mode_and_owner_the_filesystem_holds() {
    let mut sh = shell();
    let len = sh.fs.read_all("/etc/hostname", 1 << 20).unwrap().len();
    let inode = out(&mut sh, "stat -c %i /etc/hostname")
        .trim_end()
        .to_string();
    let expected = format!(
        "  File: /etc/hostname\n  Size: {len:<10}\tBlocks: 8          IO Block: 4096   regular file\nDevice: 801h/2049d\tInode: {inode:<10}  Links: 1\nAccess: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)\nAccess: 2024-01-01 00:00:00.000000000 +0000\nModify: 2024-01-01 00:00:00.000000000 +0000\nChange: 2024-01-01 00:00:00.000000000 +0000\n Birth: 2024-01-01 00:00:00.000000000 +0000\n"
    );
    assert_eq!(
        answer(&mut sh, "stat /etc/hostname"),
        (expected, "".into(), 0)
    );
    // A user the model names is named: `ubuntu` is uid 1000 in /etc/passwd.
    sh.fs.write_file("/tmp/x", b"1").unwrap();
    assert_eq!(out(&mut sh, "stat -c '%u %U' /tmp/x"), "0 root\n");
    assert_eq!(out(&mut sh, "stat -c '%g %G' /tmp/x"), "0 root\n");
}

#[test]
fn stat_c_size_equals_the_file_length_and_agrees_with_wc() {
    let mut sh = shell();
    sh.fs.write_file("/tmp/five", &[b'z'; 5000]).unwrap();
    assert_eq!(out(&mut sh, "stat -c %s /tmp/five"), "5000\n");
    assert_eq!(out(&mut sh, "wc -c < /tmp/five"), "5000\n");
    for path in ["/etc/passwd", "/etc/hosts", "/etc/os-release"] {
        let len = sh.fs.read_all(path, 1 << 20).unwrap().len();
        assert_eq!(
            out(&mut sh, &format!("stat -c %s {path}")),
            format!("{len}\n"),
            "{path}"
        );
    }
    // A file grown in the session reports the new length.
    out(&mut sh, "echo hello >> /tmp/five");
    assert_eq!(out(&mut sh, "stat -c %s /tmp/five"), "5006\n");
    // Blocks are 512-byte units of whole 4 KiB pages.
    assert_eq!(out(&mut sh, "stat -c %b /tmp/five"), "16\n");
}

#[test]
fn stat_of_bin_ls_is_a_regular_file_of_the_elfs_size() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "stat -c '%F %s %a %A' /bin/ls"),
        "regular file 138216 755 -rwxr-xr-x\n"
    );
    assert_eq!(
        out(&mut sh, "stat -c '%F %s' /bin/busybox"),
        "regular file 2193272\n"
    );
    assert_eq!(
        out(&mut sh, "stat -c '%a %A' /usr/bin/mount"),
        "4755 -rwsr-xr-x\n"
    );
    // The usrmerge link is a link by itself and a directory behind a slash or with -L.
    assert_eq!(out(&mut sh, "stat -c '%F' /bin"), "symbolic link\n");
    assert_eq!(out(&mut sh, "stat -c '%N' /bin"), "'/bin' -> 'usr/bin'\n");
    assert_eq!(out(&mut sh, "stat -c '%F' /bin/"), "directory\n");
    assert_eq!(out(&mut sh, "stat -L -c '%F' /bin"), "directory\n");
    assert_eq!(out(&mut sh, "stat --dereference -c %F /bin"), "directory\n");
    assert!(out(&mut sh, "stat /bin").starts_with("  File: /bin -> usr/bin\n"));
}

#[test]
fn stat_of_a_missing_path_is_the_coreutils_error_with_status_one() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "stat /nonexistent"),
        (
            "".into(),
            "stat: cannot statx '/nonexistent': No such file or directory\n".into(),
            1
        )
    );
    // The paths that exist are still described, and the status is the failure's.
    let (stdout, stderr, status) = answer(&mut sh, "stat -c %n /nope /etc/hostname");
    assert_eq!((stdout.as_str(), status), ("/etc/hostname\n", 1));
    assert_eq!(
        stderr,
        "stat: cannot statx '/nope': No such file or directory\n"
    );
    assert_eq!(answer(&mut sh, "stat ''").2, 1);
    // A path removed in the session stops being described.
    sh.fs.write_file("/tmp/gone", b"x").unwrap();
    assert_eq!(answer(&mut sh, "stat /tmp/gone").2, 0);
    out(&mut sh, "rm /tmp/gone");
    assert_eq!(answer(&mut sh, "stat /tmp/gone").2, 1);
    assert_eq!(
        answer(&mut sh, "stat"),
        (
            "".into(),
            "stat: missing operand\nTry 'stat --help' for more information.\n".into(),
            1
        )
    );
}

#[test]
fn stat_format_directives_read_the_modeled_metadata() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "stat -c '%n|%s|%a|%A|%f|%F' /etc/hostname").replace(
            &sh.fs
                .read_all("/etc/hostname", 64)
                .unwrap()
                .len()
                .to_string(),
            "N"
        ),
        "/etc/hostname|N|644|-rw-r--r--|81a4|regular file\n"
    );
    assert_eq!(
        out(&mut sh, "stat -c '%x|%y|%z|%w' /etc/hostname"),
        "2024-01-01 00:00:00.000000000 +0000|2024-01-01 00:00:00.000000000 +0000|2024-01-01 00:00:00.000000000 +0000|2024-01-01 00:00:00.000000000 +0000\n"
    );
    assert_eq!(
        out(&mut sh, "stat -c '%X %Y %Z %W' /etc/hostname"),
        "1704067200 1704067200 1704067200 1704067200\n"
    );
    assert_eq!(
        out(&mut sh, "stat -c '%F|%a|%A' /tmp"),
        "directory|755|drwxr-xr-x\n"
    );
    assert_eq!(
        out(&mut sh, "stat -c '%F %t,%T' /dev/null"),
        "character special file 1,3\n"
    );
    assert_eq!(
        out(&mut sh, "stat -c '%F %t,%T' /dev/zero"),
        "character special file 1,5\n"
    );
    // Width, left-justify, zero-fill, precision, a literal percent and an unknown directive.
    sh.fs.write_file("/tmp/nine", b"123456789").unwrap();
    assert_eq!(out(&mut sh, "stat -c '[%5s]' /tmp/nine"), "[    9]\n");
    assert_eq!(out(&mut sh, "stat -c '[%-5s]' /tmp/nine"), "[9    ]\n");
    assert_eq!(out(&mut sh, "stat -c '[%05s]' /tmp/nine"), "[00009]\n");
    assert_eq!(out(&mut sh, "stat -c '%04a' /tmp/nine"), "0644\n");
    assert_eq!(out(&mut sh, "stat -c '%.4n' /tmp/nine"), "/tmp\n");
    assert_eq!(out(&mut sh, "stat -c '100%% %q' /tmp/nine"), "100% ?\n");
    // `-c` keeps a backslash literal and adds a newline; `--printf` reads escapes and adds none.
    assert_eq!(out(&mut sh, "stat -c '%s\\t%s' /tmp/nine"), "9\\t9\n");
    assert_eq!(
        out(&mut sh, "stat --printf='%s\\t%s\\n%n\\\\' /tmp/nine"),
        "9\t9\n/tmp/nine\\"
    );
    assert_eq!(out(&mut sh, "stat --format=%s /tmp/nine"), "9\n");
    assert_eq!(out(&mut sh, "stat --printf=%s /tmp/nine"), "9");
    // %N quotes, %n does not.
    assert_eq!(out(&mut sh, "stat -c %N /tmp/nine"), "'/tmp/nine'\n");
}

#[test]
fn stat_terse_and_the_filesystem_form_agree_with_the_models() {
    let mut sh = shell();
    sh.fs.write_file("/tmp/nine", b"123456789").unwrap();
    let inode = out(&mut sh, "stat -c %i /tmp/nine").trim_end().to_string();
    assert_eq!(
        out(&mut sh, "stat -t /tmp/nine"),
        format!(
            "/tmp/nine 9 8 81a4 0 0 801 {inode} 1 0 0 1704067200 1704067200 1704067200 1704067200 4096\n"
        )
    );
    // `-f` takes the capacity `df` shows for the mount, in 4 KiB blocks.
    assert_eq!(
        out(&mut sh, "stat -f -c '%b %f %a %s %T' /"),
        "5033648 3806637 3554954 4096 ext2/ext3\n"
    );
    let df = out(&mut sh, "df /");
    let row: Vec<&str> = df.lines().nth(1).unwrap().split_whitespace().collect();
    let total: u64 = out(&mut sh, "stat -f -c %b /").trim_end().parse().unwrap();
    assert_eq!(row[1].parse::<u64>().unwrap(), total * 4);
    assert_eq!(out(&mut sh, "stat -f -c %T /dev/shm"), "tmpfs\n");
    assert_eq!(out(&mut sh, "stat -f -c %T /proc"), "proc\n");
    let text = out(&mut sh, "stat -f /");
    assert!(text.starts_with("  File: \"/\"\n    ID: "), "{text}");
    assert!(
        text.contains(" Namelen: 255     Type: ext2/ext3\n"),
        "{text}"
    );
    assert!(
        text.contains("Block size: 4096       Fundamental block size: 4096\n"),
        "{text}"
    );
    assert!(
        text.contains("Blocks: Total: 5033648    Free: 3806637    Available: 3554954\n"),
        "{text}"
    );
    assert_eq!(
        answer(&mut sh, "stat -f /nope"),
        (
            "".into(),
            "stat: cannot read file system information for '/nope': No such file or directory\n"
                .into(),
            1
        )
    );
}

#[test]
fn stat_inode_device_and_link_count_come_from_the_node_and_are_stable() {
    let mut sh = shell();
    // Two names of one file are one inode, on one device.
    let a = out(&mut sh, "stat -c '%i %D %d' /bin/ls");
    assert_eq!(a, out(&mut sh, "stat -c '%i %D %d' /usr/bin/ls"));
    assert_ne!(a, out(&mut sh, "stat -c '%i %D %d' /bin/cat"));
    assert_eq!(a, out(&mut sh, "stat -c '%i %D %d' /bin/ls"), "repeatable");
    assert_eq!(out(&mut sh, "stat -c %i /"), "2\n");
    // The device is the mount's: the root disk, then the tmpfs, which is not it.
    assert!(a.contains(" 801 2049\n"), "{a}");
    assert_ne!(
        out(&mut sh, "stat -c %D /run"),
        out(&mut sh, "stat -c %D /")
    );
    // A directory's links are two plus its subdirectories.
    out(&mut sh, "mkdir -p /tmp/l/a /tmp/l/b");
    out(&mut sh, "echo x > /tmp/l/f");
    assert_eq!(out(&mut sh, "stat -c %h /tmp/l"), "4\n");
    assert_eq!(out(&mut sh, "stat -c %h /tmp/l/a"), "2\n");
    assert_eq!(out(&mut sh, "stat -c %h /tmp/l/f"), "1\n");
    let dirs = out(&mut sh, "find / -mindepth 1 -maxdepth 1 -type d")
        .lines()
        .count();
    assert_eq!(
        out(&mut sh, "stat -c %h /"),
        format!("{}\n", dirs + 2),
        "the root's links follow its listing"
    );
    // A file the proc filesystem generates reports no size, as the kernel does.
    assert_eq!(out(&mut sh, "stat -c '%s %b' /proc/cpuinfo"), "0 0\n");
    assert_eq!(out(&mut sh, "stat -c %s /tmp/l"), "4096\n");
    assert_eq!(out(&mut sh, "stat -c %s /proc"), "0\n");
}

#[test]
fn stat_times_are_modeled_metadata_and_never_the_clock() {
    let mut early = shell().with_clock(noon);
    let mut late = shell().with_clock(midnight);
    for line in [
        "stat /etc/hostname",
        "stat /bin/ls",
        "stat -t /tmp",
        "stat /dev/null",
    ] {
        let first = answer(&mut early, line);
        assert_eq!(first, answer(&mut late, line), "{line}");
        assert_eq!(first, answer(&mut early, line), "{line} repeats");
    }
    assert!(
        out(&mut early, "stat /etc/hostname")
            .contains("Modify: 2024-01-01 00:00:00.000000000 +0000\n")
    );
    let device = out(&mut early, "stat /dev/null");
    assert!(
        device.contains("Links: 1     Device type: 1,3\n"),
        "{device}"
    );
}

#[test]
fn stat_options_it_lacks_are_refused_and_unmodeled_ones_print_nothing() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "stat -z /etc"),
        (
            "".into(),
            "stat: invalid option -- 'z'\nTry 'stat --help' for more information.\n".into(),
            1
        )
    );
    assert_eq!(answer(&mut sh, "stat --bogus /etc").2, 1);
    let (_, stderr, status) = answer(&mut sh, "stat -c");
    assert_eq!(status, 1);
    assert!(stderr.starts_with("stat: option requires an argument -- 'c'\n"));
    for line in ["stat --help", "stat --version", "stat -Z /etc"] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
    }
    // Long options may be abbreviated.
    assert!(
        out(&mut sh, "stat --form=%s /etc/hostname")
            .trim_end()
            .parse::<u64>()
            .is_ok()
    );
}

// ------------------------------------------------------------------------------------------ find

#[test]
fn find_name_lists_the_matches_sorted() {
    let mut sh = shell();
    tree(&mut sh);
    assert_eq!(
        answer(&mut sh, "find /tmp/t -name '*.txt'"),
        (
            lines(&["/tmp/t/.hid.txt", "/tmp/t/a.txt", "/tmp/t/sub/c.txt"]),
            "".into(),
            0
        )
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -iname '*.txt'"),
        lines(&[
            "/tmp/t/.hid.txt",
            "/tmp/t/a.txt",
            "/tmp/t/sub/c.txt",
            "/tmp/t/sub/deep/d.TXT"
        ])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t"),
        lines(&[
            "/tmp/t",
            "/tmp/t/.hid.txt",
            "/tmp/t/a.txt",
            "/tmp/t/b.log",
            "/tmp/t/sub",
            "/tmp/t/sub/c.txt",
            "/tmp/t/sub/deep",
            "/tmp/t/sub/deep/d.TXT",
            "/tmp/t/sub/deep/e",
            "/tmp/t/sub/zero"
        ])
    );
    // -name sees the last component only, and `-print` is the same as none.
    assert_eq!(
        out(&mut sh, "find /tmp/t -name 'sub*' -print"),
        lines(&["/tmp/t/sub"])
    );
    assert_eq!(out(&mut sh, "find /tmp/t -name '*/*'"), "");
    // A file the session adds shows up, one it removes does not.
    out(&mut sh, "echo x > /tmp/t/new.txt");
    out(&mut sh, "rm /tmp/t/a.txt");
    assert_eq!(
        out(&mut sh, "find /tmp/t -maxdepth 1 -name '*.txt'"),
        lines(&["/tmp/t/.hid.txt", "/tmp/t/new.txt"])
    );
}

#[test]
fn find_type_selects_the_kind_of_node() {
    let mut sh = shell();
    tree(&mut sh);
    assert_eq!(
        out(&mut sh, "find /tmp/t -type d"),
        lines(&[
            "/tmp/t",
            "/tmp/t/sub",
            "/tmp/t/sub/deep",
            "/tmp/t/sub/deep/e"
        ])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f"),
        lines(&[
            "/tmp/t/.hid.txt",
            "/tmp/t/a.txt",
            "/tmp/t/b.log",
            "/tmp/t/sub/c.txt",
            "/tmp/t/sub/deep/d.TXT",
            "/tmp/t/sub/zero"
        ])
    );
    assert_eq!(
        out(&mut sh, "find /dev -type c"),
        lines(&[
            "/dev/null",
            "/dev/random",
            "/dev/tty",
            "/dev/urandom",
            "/dev/zero"
        ])
    );
    assert_eq!(out(&mut sh, "find /bin -type l"), lines(&["/bin"]));
    assert_eq!(
        out(
            &mut sh,
            "find /tmp/t -type d,f -maxdepth 1 -mindepth 1 -name '[sb]*'"
        ),
        lines(&["/tmp/t/b.log", "/tmp/t/sub"])
    );
    // Block devices, pipes and sockets are not modeled, so nothing is one.
    for kind in ["b", "p", "s"] {
        assert_eq!(
            answer(&mut sh, &format!("find / -type {kind}")),
            ("".into(), "".into(), 0)
        );
    }
    // -L sees through a link to what it names.
    out(&mut sh, "ln -s /tmp/t /tmp/lnk");
    assert_eq!(
        out(&mut sh, "find -L /tmp/lnk -maxdepth 0 -type d"),
        lines(&["/tmp/lnk"])
    );
    assert_eq!(out(&mut sh, "find /tmp/lnk -maxdepth 0 -type d"), "");
    assert_eq!(
        out(&mut sh, "find /tmp/lnk -maxdepth 0 -type l"),
        lines(&["/tmp/lnk"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/lnk/ -maxdepth 1 -name 'a*'"),
        lines(&["/tmp/lnk/a.txt"])
    );
    assert_eq!(
        out(&mut sh, "find -L /tmp/lnk -maxdepth 1 -name 'a*'"),
        lines(&["/tmp/lnk/a.txt"])
    );
    assert_eq!(
        out(&mut sh, "find -H /tmp/lnk -maxdepth 1 -name 'a*'"),
        lines(&["/tmp/lnk/a.txt"])
    );
    assert_eq!(out(&mut sh, "find -P /tmp/lnk -maxdepth 1 -name 'a*'"), "");
    // A link inside the tree is a link unless -L: it is listed, and only -L descends into it.
    out(&mut sh, "ln -s /tmp/t/sub /tmp/t/inner");
    assert_eq!(
        out(&mut sh, "find /tmp/t -name 'c.txt'"),
        lines(&["/tmp/t/sub/c.txt"])
    );
    assert_eq!(
        out(&mut sh, "find -L /tmp/t -name 'c.txt'"),
        lines(&["/tmp/t/inner/c.txt", "/tmp/t/sub/c.txt"])
    );
}

#[test]
fn find_depth_options_and_the_start_path_spelling() {
    let mut sh = shell();
    tree(&mut sh);
    assert_eq!(
        out(&mut sh, "find /tmp/t -maxdepth 1"),
        lines(&[
            "/tmp/t",
            "/tmp/t/.hid.txt",
            "/tmp/t/a.txt",
            "/tmp/t/b.log",
            "/tmp/t/sub"
        ])
    );
    assert_eq!(out(&mut sh, "find /tmp/t -maxdepth 0"), lines(&["/tmp/t"]));
    assert_eq!(
        out(&mut sh, "find /tmp/t -mindepth 1 -maxdepth 1 -type f"),
        lines(&["/tmp/t/.hid.txt", "/tmp/t/a.txt", "/tmp/t/b.log"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -mindepth 3"),
        lines(&["/tmp/t/sub/deep/d.TXT", "/tmp/t/sub/deep/e"])
    );
    // The path is printed as typed, a trailing slash joined without doubling, the root bare.
    assert_eq!(
        out(&mut sh, "find /tmp/t/ -maxdepth 0"),
        lines(&["/tmp/t/"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t/ -maxdepth 1 -name 'a*'"),
        lines(&["/tmp/t/a.txt"])
    );
    assert_eq!(
        out(&mut sh, "find / -mindepth 1 -maxdepth 1 -name 'e*'"),
        lines(&["/etc"])
    );
    // No path means the working directory, named `.`.
    out(&mut sh, "cd /tmp/t/sub");
    assert_eq!(
        out(&mut sh, "find -type f"),
        lines(&["./c.txt", "./deep/d.TXT", "./zero"])
    );
    assert_eq!(out(&mut sh, "find"), out(&mut sh, "find ."));
    assert_eq!(
        out(&mut sh, "find deep -maxdepth 1"),
        lines(&["deep", "deep/d.TXT", "deep/e"])
    );
}

#[test]
fn find_path_perm_size_empty_and_the_operators() {
    let mut sh = shell();
    tree(&mut sh);
    assert_eq!(
        out(&mut sh, "find /tmp/t -path '*/deep/*'"),
        lines(&["/tmp/t/sub/deep/d.TXT", "/tmp/t/sub/deep/e"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -name a.txt -o -name b.log"),
        lines(&["/tmp/t/a.txt", "/tmp/t/b.log"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -maxdepth 1 -type f ! -name '*.txt'"),
        lines(&["/tmp/t/b.log"])
    );
    assert_eq!(
        out(
            &mut sh,
            "find /tmp/t -type f '(' -name a.txt -o -name b.log ')'"
        ),
        lines(&["/tmp/t/a.txt", "/tmp/t/b.log"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -name '*.txt' -a -name 'a*'"),
        lines(&["/tmp/t/a.txt"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -empty"),
        lines(&["/tmp/t/sub/deep/e", "/tmp/t/sub/zero"])
    );
    // Sizes: a bare number counts 512-byte blocks rounded up, `c` bytes, `k` KiB.
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -size 0"),
        lines(&["/tmp/t/sub/zero"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -size 5c"),
        lines(&["/tmp/t/a.txt"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -size +4c"),
        lines(&["/tmp/t/a.txt", "/tmp/t/b.log"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -size -3c"),
        lines(&["/tmp/t/.hid.txt", "/tmp/t/sub/c.txt", "/tmp/t/sub/zero"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -size +1k"),
        lines(&["/tmp/t/b.log"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -size 10"),
        lines(&["/tmp/t/b.log"])
    );
    assert_eq!(
        out(
            &mut sh,
            "find /tmp/t -type f -size -2M -size +2c -name 'd*'"
        ),
        lines(&["/tmp/t/sub/deep/d.TXT"])
    );
    // Permissions: exact, all of the bits (`-`), any of them (`/`).
    out(&mut sh, "chmod 755 /tmp/t/a.txt");
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -perm 755"),
        lines(&["/tmp/t/a.txt"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -perm -100"),
        lines(&["/tmp/t/a.txt"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -perm /111"),
        lines(&["/tmp/t/a.txt"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -type f -perm 644"),
        lines(&[
            "/tmp/t/.hid.txt",
            "/tmp/t/b.log",
            "/tmp/t/sub/c.txt",
            "/tmp/t/sub/deep/d.TXT",
            "/tmp/t/sub/zero"
        ])
    );
    // The setuid hunt reads the modes of the nodes the tree holds, special bits included.
    sh.fs
        .write_blob("/tmp/t/sub/suid", Blob::from_bytes(b"x"), 0o104_755)
        .unwrap();
    sh.fs
        .write_blob("/tmp/t/sgid", Blob::from_bytes(b"x"), 0o102_755)
        .unwrap();
    assert_eq!(
        out(&mut sh, "find /tmp -perm -4000 -type f"),
        lines(&["/tmp/t/sub/suid"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -perm /6000"),
        lines(&["/tmp/t/sgid", "/tmp/t/sub/suid"])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -perm -2755"),
        lines(&["/tmp/t/sgid"])
    );
    // -prune keeps the walk out of a directory, and -print0 ends a path with NUL.
    assert_eq!(
        out(&mut sh, "find /tmp/t -name sub -prune -o -type f -print"),
        lines(&[
            "/tmp/t/.hid.txt",
            "/tmp/t/a.txt",
            "/tmp/t/b.log",
            "/tmp/t/sgid"
        ])
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -maxdepth 1 -name a.txt -print0"),
        "/tmp/t/a.txt\0"
    );
    assert_eq!(
        out(&mut sh, "find /tmp/t -true -maxdepth 0"),
        lines(&["/tmp/t"])
    );
    assert_eq!(out(&mut sh, "find /tmp/t -false"), "");
}

#[test]
fn find_patterns_follow_fnmatch() {
    let mut sh = shell();
    sh.fs.make_dir("/tmp/g").unwrap();
    for name in [".dot", "AbC", "a*c", "abc", "abd", "b[x", "x.y.z"] {
        sh.fs.write_file(&format!("/tmp/g/{name}"), b"").unwrap();
    }
    let hits = |sh: &mut FakeShell, test: &str| {
        out(sh, &format!("find /tmp/g -type f {test}"))
            .lines()
            .map(|line| line.trim_start_matches("/tmp/g/").to_string())
            .collect::<Vec<String>>()
    };
    assert_eq!(
        hits(&mut sh, "-name '*'"),
        [".dot", "AbC", "a*c", "abc", "abd", "b[x", "x.y.z"]
    );
    assert_eq!(hits(&mut sh, "-name 'ab?'"), ["abc", "abd"]);
    assert_eq!(hits(&mut sh, "-name 'a[bc]c'"), ["abc"]);
    assert_eq!(hits(&mut sh, "-name 'a[!b]c'"), ["a*c"]);
    assert_eq!(hits(&mut sh, "-name 'a[^b]c'"), ["a*c"]);
    assert_eq!(hits(&mut sh, "-name '[a-b]b?'"), ["abc", "abd"]);
    assert_eq!(hits(&mut sh, "-iname 'ab?'"), ["AbC", "abc", "abd"]);
    assert_eq!(hits(&mut sh, "-iname '[A-B]B?'"), ["AbC", "abc", "abd"]);
    assert_eq!(hits(&mut sh, "-name 'a\\*c'"), ["a*c"]);
    assert_eq!(hits(&mut sh, "-name '*.*.*'"), ["x.y.z"]);
    assert_eq!(hits(&mut sh, "-name 'b[x'"), ["b[x"]);
    assert_eq!(hits(&mut sh, "-name '*a*b*c'"), ["abc"]);
    assert_eq!(hits(&mut sh, "-name '*b*c*d'"), Vec::<String>::new());
    assert_eq!(hits(&mut sh, "-path '/tmp/g/a*'"), ["a*c", "abc", "abd"]);
    assert_eq!(hits(&mut sh, "-ipath '*/ABC'"), ["AbC", "abc"]);
    assert_eq!(hits(&mut sh, "-wholename '*x.y*'"), ["x.y.z"]);
    // A long run of stars cannot make a match take long: it returns, and finds nothing.
    let stars = "*a".repeat(40);
    assert_eq!(
        hits(&mut sh, &format!("-name '{stars}b'")),
        Vec::<String>::new()
    );
}

#[test]
fn find_a_missing_start_path_errors_and_the_others_are_still_walked() {
    let mut sh = shell();
    tree(&mut sh);
    assert_eq!(
        answer(&mut sh, "find /nope"),
        (
            "".into(),
            "find: '/nope': No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "find /nope /tmp/t -maxdepth 0 /also"),
        (
            "".into(),
            "find: paths must precede expression: `/also'\n".into(),
            1
        )
    );
    let (stdout, stderr, status) = answer(&mut sh, "find /nope /tmp/t/sub/zero /gone");
    assert_eq!(stdout, lines(&["/tmp/t/sub/zero"]));
    assert_eq!(
        stderr,
        "find: '/nope': No such file or directory\nfind: '/gone': No such file or directory\n"
    );
    assert_eq!(status, 1);
    assert_eq!(answer(&mut sh, "find ''").2, 1);
    // A dangling link is a start path that exists.
    out(&mut sh, "ln -s /nope /tmp/dang");
    assert_eq!(
        answer(&mut sh, "find /tmp/dang"),
        (lines(&["/tmp/dang"]), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "find -L /tmp/dang -type l"),
        (lines(&["/tmp/dang"]), "".into(), 0)
    );
}

#[test]
fn find_stops_descending_a_deep_tree() {
    let mut sh = shell();
    let mut path = String::from("/tmp/deep");
    sh.fs.make_dir(&path).unwrap();
    for _ in 0..100 {
        path.push_str("/d");
        sh.fs.make_dir(&path).unwrap();
    }
    let text = out(&mut sh, "find /tmp/deep");
    let listed: Vec<&str> = text.lines().collect();
    // The operand and FIND_DEPTH_MAX levels below it, and nothing deeper.
    let levels = usize::try_from(FIND_DEPTH_MAX).unwrap() + 1;
    assert_eq!(listed.len(), levels, "{text}");
    assert_eq!(
        *listed.last().unwrap(),
        "/tmp/deep".to_string() + &"/d".repeat(levels - 1)
    );
    // The bound is the same as `du`'s, so a walk by either reaches the same nodes.
    assert_eq!(
        out(&mut sh, "du -a /tmp/deep").lines().count(),
        listed.len()
    );
    // A smaller -maxdepth stops sooner.
    assert_eq!(
        out(&mut sh, "find /tmp/deep -maxdepth 3").lines().count(),
        4
    );
}

#[test]
fn find_stops_after_the_node_cap_on_a_wide_tree_and_charges_each_node() {
    let mut sh = shell();
    sh.fs.make_dir("/tmp/wide").unwrap();
    let files = usize::try_from(FIND_VISIT_MAX).unwrap() + 500;
    for i in 0..files {
        sh.fs.write_file(&format!("/tmp/wide/f{i}"), b"").unwrap();
    }
    let text = out(&mut sh, "find /tmp/wide");
    // The directory and the files visited before the cap, never every file.
    assert_eq!(
        text.lines().count(),
        usize::try_from(FIND_VISIT_MAX).unwrap()
    );
    assert!(text.lines().count() < files);
    // The names come out sorted, so which files were reached does not depend on map order.
    let mut sorted: Vec<&str> = text.lines().collect();
    let first = sorted.remove(0);
    assert_eq!(first, "/tmp/wide");
    let mut resorted = sorted.clone();
    resorted.sort_unstable();
    assert_eq!(sorted, resorted);
    assert_eq!(text, out(&mut sh, "find /tmp/wide"), "replay-stable");
    // One unit a node visited, plus the bytes the line produced, plus the parser's own few.
    let produced = u64::try_from(text.len()).unwrap();
    let charged = sh.last_trace().budget.work_charged;
    assert!(
        charged <= u64::from(FIND_VISIT_MAX) + produced + 256,
        "charged {charged}, produced {produced}"
    );
    // The cap is shared by the operands: a second one is not walked past it, and is not an error.
    assert_eq!(answer(&mut sh, "find /tmp/wide /tmp").2, 0);
}

#[test]
fn find_charges_the_lines_work_allowance_and_ends_the_line_when_it_runs_out() {
    use crate::budget::{BudgetLimits, ConnectionBudget};
    let budget = ConnectionBudget::new(BudgetLimits {
        work_per_line: 40,
        ..BudgetLimits::standard()
    });
    let mut sh = shell().with_budget(budget);
    let (stdout, _, status) = answer(&mut sh, "find / ; echo after");
    assert_eq!(status, 1);
    assert!(!stdout.contains("after"), "the line ended: {stdout}");
    assert!(stdout.lines().count() <= 40);
}

#[test]
fn find_runs_nothing_and_removes_nothing() {
    let mut sh = shell();
    tree(&mut sh);
    let before = out(&mut sh, "find /tmp/t");
    for line in [
        "find /tmp/t -exec rm -r {} \\;",
        "find /tmp/t -exec cat {} +",
        "find /tmp/t -execdir rm {} \\;",
        "find /tmp/t -name '*.log' -delete",
        "find /tmp/t -ok rm {} \\;",
        "find /tmp/t -name a.txt -exec sh -c 'echo pwned > /tmp/pwn' \\;",
        "find /tmp/t -fprint /tmp/out",
        "find /tmp/t -ls",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
        let trace = sh.last_trace();
        let mut stack: Vec<&super::CommandTrace> = trace
            .segments
            .iter()
            .filter_map(|s| s.command.as_ref())
            .collect();
        while let Some(command) = stack.pop() {
            assert!(command.fs_effects.is_empty(), "{line}: {command:?}");
            assert!(command.reentry.is_empty(), "{line}: {command:?}");
            stack.extend(command.reentry.iter());
        }
    }
    assert_eq!(out(&mut sh, "find /tmp/t"), before);
    assert!(!sh.fs.file_exists("/tmp/pwn"));
    assert!(!sh.fs.file_exists("/tmp/out"));
}

#[test]
fn find_reports_a_malformed_expression_as_findutils_does() {
    let mut sh = shell();
    tree(&mut sh);
    for (line, text) in [
        ("find /tmp -bogus", "find: unknown predicate `-bogus'\n"),
        ("find /tmp -name", "find: missing argument to `-name'\n"),
        ("find /tmp -type x", "find: Unknown argument to -type: x\n"),
        (
            "find /tmp -maxdepth x",
            "find: Expected a positive decimal integer argument to -maxdepth, but got `x'\n",
        ),
        (
            "find /tmp -size big",
            "find: Invalid argument `big' to -size\n",
        ),
        (
            "find /tmp -name a -o",
            "find: expected an expression after '-o'\n",
        ),
        (
            "find /tmp -o -name a",
            "find: invalid expression; you have used a binary operator '-o' with nothing before it.\n",
        ),
        (
            "find /tmp '(' -name a",
            "find: invalid expression; I was expecting to find a ')' somewhere but did not see one.\n",
        ),
        (
            "find /tmp -name a ')'",
            "find: invalid expression; you have too many ')'\n",
        ),
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), text.into(), 1), "{line}");
    }
    // A global option after a test works, with the warning findutils gives.
    let (stdout, stderr, status) = answer(&mut sh, "find /tmp/t -name a.txt -maxdepth 1");
    assert_eq!((stdout.as_str(), status), ("/tmp/t/a.txt\n", 0));
    assert!(
        stderr.starts_with(
            "find: warning: you have specified the global option -maxdepth after the argument -name,"
        ),
        "{stderr}"
    );
    assert_eq!(answer(&mut sh, "find /tmp/t -maxdepth 1 -name a.txt").1, "");
    // A symbolic -perm mode is not modeled: nothing is printed.
    assert_eq!(
        answer(&mut sh, "find /tmp/t -perm -u=x"),
        ("".into(), "".into(), 0)
    );
}

// --------------------------------------------------------------------------- the phone, BusyBox

#[test]
fn the_phone_has_stat_and_find_with_toybox_wording() {
    let mut sh = phone();
    sh.fs.make_dir("/data/local/tmp/t").unwrap();
    sh.fs.write_file("/data/local/tmp/t/a", b"hello").unwrap();
    assert_eq!(
        out(&mut sh, "stat -c '%s %U %G %a' /data/local/tmp/t/a"),
        "5 root root 644\n"
    );
    let text = out(&mut sh, "stat /data/local/tmp/t/a");
    assert!(
        text.starts_with("  File: '/data/local/tmp/t/a'\n  Size: 5 "),
        "{text}"
    );
    assert!(!text.contains("Birth"), "toybox has no birth time: {text}");
    assert!(text.contains("Modify: 2024-01-01 00:00:00.000000000 +0000\n"));
    assert_eq!(
        out(&mut sh, "find /data/local/tmp/t"),
        lines(&["/data/local/tmp/t", "/data/local/tmp/t/a"])
    );
    assert_eq!(
        out(&mut sh, "find /system/bin -name 'st*'"),
        lines(&["/system/bin/stat"])
    );
    assert_eq!(
        answer(&mut sh, "stat /nope"),
        (
            "".into(),
            "stat: '/nope': No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "find /nope"),
        (
            "".into(),
            "find: /nope: No such file or directory\n".into(),
            1
        )
    );
    let (_, stderr, status) = answer(&mut sh, "stat -z /system");
    assert_eq!(status, 1);
    assert!(stderr.starts_with("stat: Unknown option "), "{stderr}");
    // toybox runs them as its applets, with the same answers.
    assert_eq!(
        out(&mut sh, "toybox stat -c %s /data/local/tmp/t/a"),
        out(&mut sh, "stat -c %s /data/local/tmp/t/a")
    );
    assert_eq!(
        out(&mut sh, "toybox find /system/bin -name 'fi*'"),
        lines(&["/system/bin/find"])
    );
    assert!(out(&mut sh, "toybox").contains("stat\n"));
    assert!(out(&mut sh, "toybox").contains("find\n"));
    assert_eq!(out(&mut sh, "stat -f -c %T /data"), "ext2/ext3\n");
}

#[test]
fn busybox_routes_to_stat_and_find_with_its_own_error_wording() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "busybox stat -c %s /etc/hostname"),
        out(&mut sh, "stat -c %s /etc/hostname")
    );
    assert_eq!(
        out(&mut sh, "busybox find /etc -name hosts"),
        lines(&["/etc/hosts"])
    );
    sh.handle_input("busybox find /etc");
    let trace = sh.last_trace();
    let command = trace.segments[0].command.as_ref().unwrap();
    assert_eq!(command.resolved, HandlerId::Busybox);
    assert_eq!(command.reentry[0].resolved, HandlerId::Find);
    assert_eq!(
        answer(&mut sh, "busybox stat /nope"),
        (
            "".into(),
            "stat: can't stat '/nope': No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "busybox find /nope"),
        (
            "".into(),
            "find: /nope: No such file or directory\n".into(),
            1
        )
    );
}

// -------------------------------------------------------------------------- registration and scope

#[test]
fn stat_and_find_exist_on_both_personas() {
    for (name, id) in [("stat", HandlerId::Stat), ("find", HandlerId::Find)] {
        let mut sh = shell();
        assert_eq!(
            out(&mut sh, &format!("command -v {name}")),
            format!("/usr/bin/{name}\n")
        );
        assert_eq!(
            out(&mut sh, &format!("type {name}")),
            format!("{name} is /usr/bin/{name}\n")
        );
        assert!(sh.fs.is_executable(&format!("/usr/bin/{name}")));
        sh.handle_input(name);
        assert_eq!(
            sh.last_trace().segments[0]
                .command
                .as_ref()
                .unwrap()
                .resolved,
            id,
            "{name}"
        );
        let mut ph = phone();
        assert_eq!(
            out(&mut ph, &format!("command -v {name}")),
            format!("/system/bin/{name}\n")
        );
        assert!(ph.fs.is_executable(&format!("/system/bin/{name}")));
        assert!(
            ph.fs
                .list_dir("/system/bin")
                .unwrap()
                .contains(&name.to_string())
        );
        ph.handle_input(name);
        assert_eq!(
            ph.last_trace().segments[0]
                .command
                .as_ref()
                .unwrap()
                .resolved,
            id,
            "{name}"
        );
    }
}

/// The 2026-09-29 Ubuntu 22.04 recording marks `file`, `xxd` and `hexdump` absent (and never
/// probed `strings`). `file` is no BusyBox applet, so it is not found however it is reached; the
/// other three are applets, so only `busybox NAME` runs them.
/// `name` is "command not found" bare, on the Ubuntu persona and the phone, to `command -v` and to
/// dispatch alike.
fn assert_not_a_bare_command(name: &str) {
    for mut sh in [shell(), phone()] {
        let (stdout, stderr, status) = answer(&mut sh, &format!("{name} /etc/hostname"));
        assert_eq!((stdout.as_str(), status), ("", 127), "{name}");
        assert!(stderr.contains("not found"), "{name}: {stderr}");
        assert_eq!(
            sh.last_trace().segments[0]
                .command
                .as_ref()
                .unwrap()
                .resolved,
            HandlerId::NotFound,
            "{name}"
        );
        assert_eq!(
            answer(&mut sh, &format!("command -v {name}")),
            ("".into(), "".into(), 1),
            "{name}"
        );
    }
}

/// The applet runs on the Ubuntu persona and reaches its own handler.
fn assert_busybox_applet(args: &str, handler: HandlerId) {
    let mut sh = shell();
    let (stdout, stderr, status) = answer(&mut sh, &format!("busybox {args} /etc/hostname"));
    assert_eq!(status, 0, "busybox {args}: {stderr}");
    assert!(!stdout.is_empty(), "busybox {args}");
    let outer = sh.last_trace().segments[0].command.as_ref().unwrap();
    assert_eq!(outer.reentry[0].resolved, handler, "busybox {args}");
}

#[test]
fn file_is_not_a_command_on_any_persona_or_path() {
    assert_not_a_bare_command("file");
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "busybox file /etc"),
        ("".into(), "file: applet not found\n".into(), 127)
    );
}

#[test]
fn xxd_is_absent_bare_and_runs_only_as_a_busybox_applet() {
    assert_not_a_bare_command("xxd");
    assert_busybox_applet("xxd", HandlerId::Xxd);
}

#[test]
fn hexdump_is_absent_bare_and_runs_only_as_a_busybox_applet() {
    assert_not_a_bare_command("hexdump");
    // `hexdump` prints a dump only for the one raw-character format the model carries.
    assert_busybox_applet("hexdump -e '16/1 \"%c\"'", HandlerId::Hexdump);
}

#[test]
fn strings_is_absent_bare_and_runs_only_as_a_busybox_applet() {
    assert_not_a_bare_command("strings");
    assert_busybox_applet("strings", HandlerId::Strings);
}

#[test]
fn the_commands_read_the_model_and_change_nothing() {
    let mut sh = shell();
    tree(&mut sh);
    let before = (
        sh.fs.list_dir("/tmp"),
        sh.fs.list_dir("/tmp/t"),
        sh.fs.list_dir("/"),
        sh.fs.list_dir("/proc"),
    );
    for line in [
        "stat /etc/passwd /bin/ls /tmp/t",
        "stat -f /",
        "find / -name passwd",
        "find /tmp/t | cat",
        "stat /tmp/t | cat",
    ] {
        sh.handle_input(line);
        let trace = sh.last_trace();
        let mut stack: Vec<&super::CommandTrace> = trace
            .segments
            .iter()
            .filter_map(|s| s.command.as_ref())
            .collect();
        while let Some(command) = stack.pop() {
            assert!(command.fs_effects.is_empty(), "{line}: {command:?}");
            stack.extend(command.reentry.iter());
        }
    }
    assert_eq!(
        before,
        (
            sh.fs.list_dir("/tmp"),
            sh.fs.list_dir("/tmp/t"),
            sh.fs.list_dir("/"),
            sh.fs.list_dir("/proc")
        )
    );
}

#[test]
fn the_module_holds_no_process_or_host_access() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/shell/fileinfo.rs");
    let text = std::fs::read_to_string(path).unwrap();
    // Built by concatenation so this file does not trip the scan it runs.
    for banned in [
        ["std::process", "::Command"].concat(),
        ["Command", "::new"].concat(),
        ["std::", "fs"].concat(),
        ["std::", "env"].concat(),
        ["std::", "net"].concat(),
        ["libc", "::"].concat(),
        ["Utc", "::now"].concat(),
        ["System", "Time"].concat(),
    ] {
        assert!(!text.contains(&banned), "fileinfo.rs contains {banned}");
    }
}
