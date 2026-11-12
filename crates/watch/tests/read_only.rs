//! The read-only guarantee, held by the source rather than by care: the watcher reads attacker
//! data and runs under a key that someone may one day lose, so what it CAN do is checked here. It
//! must not write, create, rename or remove a file, open a socket, reach a database, or run
//! anything but journalctl with the fixed argument vector. Same shape as the sensors'
//! `never_exec_static_check`.

use std::path::{Path, PathBuf};

fn src_files() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let files: Vec<(String, String)> = files
        .into_iter()
        .map(|p| {
            assert!(
                p.extension().is_some_and(|e| e == "rs"),
                "src/ holds only flat .rs files, so this scan sees all of it: {}",
                p.display()
            );
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    assert!(files.len() >= 6, "the scan found too few files: {files:?}");
    files
}

#[test]
fn never_writes_a_file() {
    for (name, src) in src_files() {
        for banned in [
            "OpenOptions",
            "File::create",
            "File::options",
            "create_new",
            "fs::write",
            "fs::copy",
            "rename(",
            "remove_file",
            "remove_dir",
            "create_dir",
            "set_permissions",
            "set_len",
            "hard_link",
            "symlink",
            "persist_cursor",
            "LogTailer::new(",
            "DurableCursor",
            "tempfile",
        ] {
            assert!(!src.contains(banned), "{name} must not use {banned}");
        }
    }
}

/// Opening is allowed, read-only `File::open` only, and only where the watcher has a reason to
/// open a file itself: `/etc/propolis/watch.env` (config.rs) and the heartbeat's readability probe
/// (status.rs). The logs are opened inside log-tailer.
#[test]
fn opens_files_only_read_only_and_only_in_the_two_expected_places() {
    let mut open_sites: Vec<String> = Vec::new();
    for (name, src) in src_files() {
        open_sites.extend(src.match_indices("File::open(").map(|_| name.clone()));
    }
    open_sites.dedup();
    assert_eq!(open_sites, ["config.rs", "status.rs"]);
}

#[test]
fn never_opens_a_socket_or_reaches_a_database() {
    for (name, src) in src_files() {
        for banned in [
            "TcpStream",
            "TcpListener",
            "UdpSocket",
            "UnixStream",
            "UnixListener",
            "UnixDatagram",
            "ToSocketAddrs",
            "SocketAddr",
            "tokio",
            "sqlx",
            "reqwest",
            "hyper",
            "connect(",
            "unsafe",
            "libc",
        ] {
            assert!(!src.contains(banned), "{name} must not use {banned}");
        }
        // `std::net` is allowed for exactly one thing: the IpAddr type the --source-ip filter
        // parses into.
        for (at, _) in src.match_indices("std::net") {
            assert!(
                src[at..].starts_with("std::net::IpAddr"),
                "{name} uses std::net for something other than IpAddr"
            );
        }
    }
}

#[test]
fn never_executes_anything_but_the_fixed_journalctl() {
    let mut spawn_sites = Vec::new();
    for (name, src) in src_files() {
        for banned in [
            ".arg(",
            "sh -c",
            "/bin/sh",
            "exec(",
            "Command::new(\"",
            "process::exit",
        ] {
            assert!(!src.contains(banned), "{name} must not use {banned}");
        }
        spawn_sites.extend(src.match_indices("Command::new(").map(|_| name.clone()));
        if src.contains("Command::new(") {
            assert!(
                src.contains("Command::new(JOURNAL_PROGRAM)\n        .args(JOURNAL_ARGS)"),
                "{name}: the one child is JOURNAL_PROGRAM with JOURNAL_ARGS and nothing else"
            );
            assert_eq!(
                src.matches(".args(").count(),
                1,
                "{name}: one argument list"
            );
        } else {
            assert!(!src.contains("Command"), "{name} must not build a Command");
        }
    }
    assert_eq!(spawn_sites, ["journal.rs"], "exactly one spawn site");
}

#[test]
fn the_manifest_names_only_the_three_read_only_dependencies() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps: Vec<&str> = manifest
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .split("\n[")
        .next()
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once(" = ").map(|(name, _)| name.trim()))
        .filter(|name| !name.starts_with('#'))
        .collect();
    assert_eq!(deps, ["chrono", "log-tailer", "serde_json"]);
}
