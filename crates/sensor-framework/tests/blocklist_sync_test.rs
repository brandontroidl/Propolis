//! Runs `deploy/blocklist-sync.sh` against a scratch feed directory, a local git checkout and a
//! local bare "remote", and asserts what reaches the remote. The feed directory belongs to the
//! daemon, which parses every attacker byte, while the script runs from the operator's cron (root
//! on a box set up before the dedicated account existed), so each test plays a compromised daemon
//! planting something in that directory and checks that nothing it plants is published, opened
//! or written through. Real git, stat, head and timeout run as shipped; nothing is stubbed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const FORMATS: [&str; 10] = [
    "txt", "json", "csv", "cidr", "ipset", "nft", "pf", "alias", "hosts", "rpz",
];
const FEEDS: [&str; 3] = ["aggressive", "standard", "all-7d"];
const SECRET: &str = "FAKE-ROOT-ONLY-KEY-MATERIAL";
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    /// A complete build in `feed/current`, a clone of an empty bare `origin.git` in `repo`, the
    /// status directory, and a 0600 file standing in for a key only root could read.
    fn new() -> Self {
        let fx = Fixture {
            dir: tempfile::tempdir().expect("scratch dir"),
        };
        std::fs::create_dir_all(fx.feed()).unwrap();
        for feed in FEEDS {
            for ext in FORMATS {
                std::fs::write(
                    fx.feed().join(format!("{feed}.{ext}")),
                    format!("# {feed}.{ext}\n192.0.2.1\n"),
                )
                .unwrap();
            }
        }
        std::fs::write(
            fx.feed().join("manifest.json"),
            r#"{"build_time":"2026-10-14T00:00:00Z","tiers":{}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(fx.status()).unwrap();
        std::fs::set_permissions(fx.status(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(fx.root().join("secret")).unwrap();
        std::fs::write(fx.secret(), SECRET).unwrap();
        std::fs::set_permissions(fx.secret(), std::fs::Permissions::from_mode(0o600)).unwrap();

        fx.git(&["init", "-q", "--bare", "origin.git"], fx.root());
        fx.git(&["clone", "-q", "origin.git", "repo"], fx.root());
        fx.git(&["config", "user.name", "sync test"], &fx.repo());
        fx.git(
            &["config", "user.email", "sync@example.invalid"],
            &fx.repo(),
        );
        fx
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }
    fn feed(&self) -> PathBuf {
        self.root().join("feed/current")
    }
    fn repo(&self) -> PathBuf {
        self.root().join("repo")
    }
    fn status(&self) -> PathBuf {
        self.root().join("status")
    }
    fn secret(&self) -> PathBuf {
        self.root().join("secret/key")
    }

    /// git with no system or user configuration, so the owner's own settings (signing, hooks,
    /// default branch) cannot change what the test sees.
    fn git_command(&self, args: &[&str], cwd: &Path) -> Command {
        let mut command = Command::new("git");
        command
            .args(args)
            .current_dir(cwd)
            .env("HOME", self.root())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE");
        command
    }

    fn git(&self, args: &[&str], cwd: &Path) -> String {
        let out = self.git_command(args, cwd).output().expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Runs the script with a hard deadline: a script that opens a FIFO the daemon planted blocks
    /// forever, and a test that hung with it would hide the failure instead of reporting it.
    fn run(&self) -> Output {
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/blocklist-sync.sh"
        );
        let mut command = Command::new("bash");
        command
            .arg(script)
            .env("HOME", self.root())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("PROPOLIS_FEED_OUTPUT_DIR", self.feed())
            .env("PROPOLIS_BLOCKLIST_REPO", self.repo())
            .env("PROPOLIS_BLOCKLIST_STATUS_DIR", self.status())
            .env_remove("PROPOLIS_BLOCKLIST_SSH_KEY")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("bash runs");
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if child.try_wait().unwrap().is_some() {
                return child.wait_with_output().unwrap();
            }
            if Instant::now() > deadline {
                child.kill().ok();
                let out = child.wait_with_output().unwrap();
                panic!(
                    "blocklist-sync.sh did not finish within 90 s (blocked on something it \
                     opened?): {}\n{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Every path the remote holds, or empty when nothing was ever pushed.
    fn pushed_paths(&self) -> Vec<String> {
        let refs = self.git(&["for-each-ref", "--format=%(refname)"], &self.origin());
        let Some(head) = refs.lines().next() else {
            return Vec::new();
        };
        self.git(&["ls-tree", "-r", "--name-only", head], &self.origin())
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn pushed_file(&self, path: &str) -> String {
        let refs = self.git(&["for-each-ref", "--format=%(refname)"], &self.origin());
        let head = refs.lines().next().expect("something was pushed");
        self.git(&["show", &format!("{head}:{path}")], &self.origin())
    }

    fn origin(&self) -> PathBuf {
        self.root().join("origin.git")
    }

    /// Asserts the run was refused, nothing reached the remote, and the stand-in secret appears
    /// nowhere in the checkout either (a copy left for the next run to commit is the same leak).
    fn assert_refused_and_nothing_published(&self, out: &Output, why: &str) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "{why}: the run must fail closed; stdout: {}\nstderr: {stderr}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            self.pushed_paths().is_empty(),
            "{why}: nothing may reach the remote: {:?}",
            self.pushed_paths()
        );
        assert!(
            !tree_contains(&self.repo(), SECRET.as_bytes()),
            "{why}: the secret's bytes were copied into the checkout"
        );
        assert!(
            !self.status().join("last-pushed").exists(),
            "{why}: a refused run must not record a push"
        );
    }
}

/// Whether any regular file under `dir`, outside `.git`, contains `needle`.
fn tree_contains(dir: &Path, needle: &[u8]) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() && entry.file_name() != ".git" {
            if tree_contains(&path, needle) {
                return true;
            }
        } else if kind.is_file()
            && std::fs::read(&path)
                .unwrap()
                .windows(needle.len())
                .any(|w| w == needle)
        {
            return true;
        }
    }
    false
}

fn assert_ok(out: &Output) {
    assert!(
        out.status.success(),
        "blocklist-sync.sh failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_normal_build_is_published_in_the_split_layout_and_the_push_is_recorded() {
    let fx = Fixture::new();
    let out = fx.run();
    assert_ok(&out);

    let pushed = fx.pushed_paths();
    for feed in ["aggressive", "standard"] {
        for ext in FORMATS {
            let path = format!("tiers/{feed}.{ext}");
            assert!(pushed.contains(&path), "{path} missing: {pushed:?}");
        }
    }
    for ext in FORMATS {
        let path = format!("retention/all-7d.{ext}");
        assert!(pushed.contains(&path), "{path} missing: {pushed:?}");
    }
    assert!(pushed.contains(&"manifest.json".to_string()));
    assert_eq!(
        fx.pushed_file("tiers/aggressive.txt"),
        "# aggressive.txt\n192.0.2.1\n"
    );
    let log = fx.git(&["log", "--format=%s"], &fx.origin());
    assert_eq!(log.trim(), "feed: 2026-10-14T00:00:00Z");

    // The push is recorded in the status directory, never beside the feed, where the daemon
    // could have planted a link for the cron to write through.
    let marker = fx.status().join("last-pushed");
    assert!(marker.is_file(), "the push marker is written");
    assert!(
        !fx.root().join("feed/.current.last_pushed").exists(),
        "nothing is written into the daemon's directory"
    );
    let staged: Vec<_> = std::fs::read_dir(fx.repo().join(".git"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("blocklist-sync"))
        .collect();
    assert!(staged.is_empty(), "the staging copy is removed: {staged:?}");

    // A second run with no new build commits nothing and still succeeds.
    assert_ok(&fx.run());
    let log = fx.git(&["log", "--format=%s"], &fx.origin());
    assert_eq!(log.lines().count(), 1, "{log}");
}

/// The audit's reproducer: a symlink under an expected name points at a file the daemon cannot
/// read. The cron followed it, so its contents were committed and pushed to the public remote.
#[test]
fn a_symlink_in_the_feed_is_refused() {
    let fx = Fixture::new();
    let planted = fx.feed().join("aggressive.txt");
    std::fs::remove_file(&planted).unwrap();
    std::os::unix::fs::symlink(fx.secret(), &planted).unwrap();
    let out = fx.run();
    fx.assert_refused_and_nothing_published(&out, "symlink");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("aggressive.txt"),
        "the refusal names the file: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A hard link carries no link of its own to refuse: it IS the target's inode under a second name.
/// The daemon can only make one to a file it could already read, unless protected_hardlinks is
/// off; then a hard link to a root-only file is root's file under a name the cron copies. The test
/// user owns the stand-in secret, which is what lets it make the link here.
#[test]
fn a_hard_link_in_the_feed_is_refused() {
    let fx = Fixture::new();
    let planted = fx.feed().join("standard.json");
    std::fs::remove_file(&planted).unwrap();
    std::fs::hard_link(fx.secret(), &planted).unwrap();
    let out = fx.run();
    fx.assert_refused_and_nothing_published(&out, "hard link");
}

/// A FIFO under an expected name: opening it for reading blocks until a writer appears, so a cron
/// that opens it hangs for good, and a fresh one piles up behind it every interval.
#[test]
fn a_fifo_in_the_feed_is_refused_without_being_opened() {
    let fx = Fixture::new();
    let planted = fx.feed().join("aggressive.nft");
    std::fs::remove_file(&planted).unwrap();
    let made = Command::new("mkfifo").arg(&planted).status().unwrap();
    assert!(made.success());
    let started = Instant::now();
    let out = fx.run();
    fx.assert_refused_and_nothing_published(&out, "fifo");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "refused before opening it, not after a timeout"
    );
}

/// A name the publisher never writes, here the audit's `aggressive.leak` pointing at the secret,
/// and a plain regular file with a stray name: neither may be copied, and the build is refused
/// rather than published without them, since the directory is no longer only the publisher's.
#[test]
fn an_unexpected_name_in_the_feed_is_refused() {
    let fx = Fixture::new();
    std::os::unix::fs::symlink(fx.secret(), fx.feed().join("aggressive.leak")).unwrap();
    let out = fx.run();
    fx.assert_refused_and_nothing_published(&out, "unexpected symlinked name");

    let fx = Fixture::new();
    std::fs::write(fx.feed().join("notes.txt"), SECRET).unwrap();
    let out = fx.run();
    fx.assert_refused_and_nothing_published(&out, "unexpected regular name");
}

/// The feed directory itself swapped for a symlink to somewhere else that looks like a build.
#[test]
fn a_feed_directory_that_is_a_symlink_is_refused() {
    let fx = Fixture::new();
    let real = fx.root().join("feed/elsewhere");
    std::fs::rename(fx.feed(), &real).unwrap();
    std::os::unix::fs::symlink(&real, fx.feed()).unwrap();
    let out = fx.run();
    assert!(
        !out.status.success(),
        "a symlinked feed directory is refused"
    );
    assert!(fx.pushed_paths().is_empty());
}

/// A file past the per-file cap is refused before it is read (sparse, so the test writes nothing).
#[test]
fn an_oversized_file_is_refused() {
    let fx = Fixture::new();
    let big = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(fx.feed().join("all-7d.json"))
        .unwrap();
    big.set_len(MAX_FILE_BYTES + 1).unwrap();
    drop(big);
    let out = fx.run();
    fx.assert_refused_and_nothing_published(&out, "oversized");

    // Exactly at the cap is accepted.
    let fx = Fixture::new();
    let big = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(fx.feed().join("all-7d.json"))
        .unwrap();
    big.set_len(MAX_FILE_BYTES).unwrap();
    drop(big);
    assert_ok(&fx.run());
}

/// A build missing one of the formats the publisher always writes is malformed, not published.
#[test]
fn an_incomplete_build_is_refused() {
    let fx = Fixture::new();
    std::fs::remove_file(fx.feed().join("standard.rpz")).unwrap();
    let out = fx.run();
    fx.assert_refused_and_nothing_published(&out, "incomplete");
}

/// The old marker location sat in the daemon's directory, so a link planted there made the cron
/// truncate and chmod any file. Planting one now changes nothing: the marker is not written there.
#[test]
fn a_link_planted_at_the_old_marker_path_is_never_written_through() {
    let fx = Fixture::new();
    let victim = fx.root().join("secret/victim");
    std::fs::write(&victim, "IMPORTANT ORIGINAL CONTENT").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&victim, fx.root().join("feed/.current.last_pushed")).unwrap();
    let dangling = fx.root().join("secret/created-by-cron");
    std::os::unix::fs::symlink(&dangling, fx.root().join("feed/.elsewhere.last_pushed")).unwrap();

    assert_ok(&fx.run());
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "IMPORTANT ORIGINAL CONTENT"
    );
    assert_eq!(
        std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!dangling.exists());
    assert!(fx.status().join("last-pushed").is_file());
}

/// A status directory other accounts can write is somewhere the marker could be redirected, so
/// the marker is skipped with a warning; the push itself still succeeds and is reported.
#[test]
fn a_status_directory_others_can_write_gets_no_marker() {
    let fx = Fixture::new();
    std::fs::set_permissions(fx.status(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let out = fx.run();
    assert_ok(&out);
    assert!(!fx.pushed_paths().is_empty(), "the push itself happened");
    assert!(!fx.status().join("last-pushed").exists());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("push marker"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The script's format list must be exactly what the publisher writes per feed: a format added to
/// the publisher and not here would make every build "unexpected" and stop the sync; one listed
/// here and dropped there would make every build "incomplete".
#[test]
fn the_format_list_matches_the_publisher() {
    let publisher = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../feed/src/publisher.rs"
    ))
    .unwrap();
    let mut written: Vec<String> = publisher
        .lines()
        .filter_map(|l| {
            l.trim()
                .strip_prefix("&staging.join(format!(\"{name}.")
                .or_else(|| {
                    l.trim()
                        .strip_prefix("write_file_synced(&staging.join(format!(\"{name}.")
                })
        })
        .map(|rest| rest.split('"').next().unwrap().to_string())
        .collect();
    written.sort();
    written.dedup();
    let mut ours: Vec<String> = FORMATS.iter().map(|s| s.to_string()).collect();
    ours.sort();
    assert_eq!(written, ours, "the publisher's formats changed");

    let script = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/blocklist-sync.sh"
    ))
    .unwrap();
    let line = script
        .lines()
        .find(|l| l.starts_with("FORMATS=("))
        .expect("blocklist-sync.sh has a FORMATS=(...) line");
    let mut listed: Vec<String> = line
        .trim_start_matches("FORMATS=(")
        .trim_end_matches(')')
        .split_whitespace()
        .map(str::to_string)
        .collect();
    listed.sort();
    assert_eq!(listed, ours, "blocklist-sync.sh's FORMATS drifted");
}
