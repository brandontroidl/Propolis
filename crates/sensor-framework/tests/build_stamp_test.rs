//! Exercises `crates/build-stamp.rs` - the git-derived compile-time version stamp shared verbatim
//! by `crates/console/build.rs` and `crates/propolis/build.rs` - not owned by either of those
//! crates, so it lives here alongside `deploy_test.rs`'s coverage of artifacts no single crate
//! owns.
//!
//! Every test below builds a real, disposable cargo crate whose `build.rs` `include!`s the actual
//! `crates/build-stamp.rs` by absolute path, inside an isolated git repository created under a
//! test-owned `tempfile::tempdir()` - never a branch, stash, or worktree of this project's own
//! repository. The fixture's `src/main.rs` prints both stamped values to stdout, so a test
//! observes the actual compiled-in identity by running the built binary, not by re-deriving the
//! expected string from the same logic under test (which would prove only that two copies of one
//! formula agree with each other).
//!
//! WHY A FIXTURE RATHER THAN TESTING THIS PROJECT'S OWN CHECKOUT. This project's own working tree
//! is not a fixture the tests may make tracked-and-then-restored edits to, worktrees off of, or
//! extra commits against - a test suite must never mutate the repository it runs from. A synthetic
//! repository gives full control over every event under test (a tracked edit with no commit, the
//! same edit one crate further out in a path dependency, a commit made inside a linked worktree, a
//! packed ref, and a checkout with no repository at all) with no risk to real history.

use std::path::Path;
use std::process::Command;

/// Runs `git` with the given working directory and args, panicking with its stderr on failure -
/// every call here is setup for a fixture, not the behavior under test, so a failure is a broken
/// test environment, not a result to assert on.
fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn git {args:?} in {}: {e}", dir.display()));
    assert!(
        out.status.success(),
        "git {args:?} in {} failed: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `git`, returning trimmed stdout instead of asserting success - for a query the caller itself
/// wants to make an assertion about.
fn git_output(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn git {args:?} in {}: {e}", dir.display()));
    assert!(
        out.status.success(),
        "git {args:?} in {} failed: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// The real `crates/build-stamp.rs`, resolved from this test binary's own compile-time manifest
/// directory rather than any path relative to the fixture (which moves around under a tempdir).
fn real_build_stamp_path() -> std::path::PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../build-stamp.rs"))
        .canonicalize()
        .expect("crates/build-stamp.rs must exist next to every crate that stamps itself with it")
}

/// Writes a minimal binary crate at `crate_dir` whose `build.rs` `include!`s the real
/// `crates/build-stamp.rs` and whose `main.rs` prints what that stamped in, exactly mirroring what
/// `crates/console/build.rs` and `crates/propolis/build.rs` do for real.
fn write_fixture_crate(crate_dir: &Path) {
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"stamp_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    std::fs::write(
        crate_dir.join("build.rs"),
        format!(
            "include!({:?});\nfn main() {{ emit_build_stamp(); }}\n",
            real_build_stamp_path()
        ),
    )
    .unwrap();
    std::fs::write(crate_dir.join("src/main.rs"), FIXTURE_MAIN).unwrap();
}

/// Both stamped values, one per line, so a test observes what was actually compiled in rather than
/// re-deriving it from the logic under test.
const FIXTURE_MAIN: &str = "fn main() { println!(\"{}\\n{}\", env!(\"PROPOLIS_GIT_SHA\"), env!(\"PROPOLIS_BUILD_TIMESTAMP\")); }\n";

/// Adds a second crate at `dep_dir` and makes the fixture crate at `crate_dir` depend on it by
/// path, the way every binary in this workspace depends on its siblings (`console = { path =
/// "../console" }`). The dependency is called from `main.rs`, so its source really is compiled
/// into the fixture binary and an edit to it really does change the bytes the stamp claims to
/// describe.
fn add_path_dependency(crate_dir: &Path, dep_dir: &Path) {
    std::fs::create_dir_all(dep_dir.join("src")).unwrap();
    std::fs::write(
        dep_dir.join("Cargo.toml"),
        "[package]\nname = \"stamp_fixture_dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    std::fs::write(
        dep_dir.join("src/lib.rs"),
        "pub fn marker() -> &'static str { \"v1\" }\n",
    )
    .unwrap();

    let manifest = crate_dir.join("Cargo.toml");
    let mut text = std::fs::read_to_string(&manifest).unwrap();
    text.push_str("\n[dependencies]\nstamp_fixture_dep = { path = \"../dep\" }\n");
    std::fs::write(&manifest, text).unwrap();

    std::fs::write(
        crate_dir.join("src/main.rs"),
        FIXTURE_MAIN.replace(
            "fn main() {",
            "fn main() { let _ = stamp_fixture_dep::marker();",
        ),
    )
    .unwrap();
}

/// Builds the fixture crate at `manifest_dir` into `target_dir` and returns the `PROPOLIS_GIT_SHA`
/// its binary reports. A fresh `cargo build` invocation every call - the point of these tests is
/// observing whether the build script picks up a change since the last build, which a cached,
/// unexecuted binary would hide.
fn build_and_read_sha(manifest_dir: &Path, target_dir: &Path) -> String {
    build_and_read_stamp(manifest_dir, target_dir, &[]).0
}

/// Both stamped values, with `env` applied to the `cargo build` invocation - the only way to
/// exercise `SOURCE_DATE_EPOCH`, which the build script reads from its own environment.
fn build_and_read_stamp(
    manifest_dir: &Path,
    target_dir: &Path,
    env: &[(&str, &str)],
) -> (String, String) {
    let manifest = manifest_dir.join("Cargo.toml");
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "-q", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(target_dir);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("failed to spawn cargo build");
    assert!(
        out.status.success(),
        "cargo build of the fixture crate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bin = target_dir.join("debug").join("stamp_fixture");
    let run = Command::new(&bin)
        .output()
        .unwrap_or_else(|e| panic!("failed to run built fixture binary {}: {e}", bin.display()));
    assert!(run.status.success(), "fixture binary exited non-zero");
    let printed = String::from_utf8(run.stdout).unwrap();
    let mut lines = printed.lines();
    let sha = lines.next().unwrap_or_default().trim().to_string();
    let built_at = lines.next().unwrap_or_default().trim().to_string();
    (sha, built_at)
}

/// The core regression this whole file guards: a tracked file edited without a commit moves
/// neither `HEAD` nor any ref, so if the build script only watched git metadata paths, a build
/// made from genuinely modified source would still report the clean commit's id - the exact
/// "binary that cannot be trusted to name what it was built from" failure the stamp exists to
/// prevent. Also proves the flag clears again once the tracked edit is reverted, so this is
/// tracking live state, not latching dirty forever after the first flip.
#[test]
fn dirty_marker_tracks_a_tracked_edit_with_no_commit_and_clears_when_restored() {
    let repo = tempfile::tempdir().unwrap();
    let crate_dir = repo.path().join("crate");
    let target_dir = repo.path().join("target");
    write_fixture_crate(&crate_dir);
    std::fs::write(crate_dir.join("TRACKED.txt"), "v1\n").unwrap();

    git(repo.path(), &["init", "-q", "-b", "main"]);
    git(repo.path(), &["config", "user.email", "test@example.com"]);
    git(repo.path(), &["config", "user.name", "test"]);
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "initial"]);
    // Pack, then commit again: a freshly `git init`-ed repo has no `packed-refs` file at all, and
    // that ABSENT path alone forces cargo's "rerun if this doesn't exist" fallback on every build
    // regardless of anything under test here - real long-lived repositories (this project's own
    // `.git` included) carry both a `packed-refs` (from a clone or an auto-gc) and a loose ref for
    // the branch actually being worked on (rewritten on every commit even though packed). Doing
    // the same here means HEAD, the loose ref, and `packed-refs` are all real, existing, stable
    // files before the edit under test, so a rerun below can only come from the directory watch
    // this test exists to prove, not from an unrelated missing-path fallback.
    git(repo.path(), &["pack-refs", "--all"]);
    git(
        repo.path(),
        &["commit", "-q", "--allow-empty", "-m", "repack fixture"],
    );

    let clean_sha = build_and_read_sha(&crate_dir, &target_dir);
    assert_ne!(
        clean_sha, "unknown",
        "a fresh commit must resolve a real sha"
    );
    assert!(
        !clean_sha.contains("+dirty"),
        "a build from a just-committed, unmodified tree must not read dirty: {clean_sha}"
    );

    std::fs::write(
        crate_dir.join("TRACKED.txt"),
        "v2 - edited, not committed\n",
    )
    .unwrap();
    let dirty_sha = build_and_read_sha(&crate_dir, &target_dir);
    assert_eq!(
        dirty_sha,
        format!("{clean_sha}+dirty"),
        "editing a tracked file without committing must mark the build dirty against the same \
         commit, not silently keep reporting the clean id: got {dirty_sha}"
    );

    git(&crate_dir, &["checkout", "--", "TRACKED.txt"]);
    let restored_sha = build_and_read_sha(&crate_dir, &target_dir);
    assert_eq!(
        restored_sha, clean_sha,
        "restoring the tracked file to its committed content must clear the dirty marker again"
    );
}

/// The same failure one crate further out: a tracked edit to a WORKSPACE CRATE THIS BINARY DEPENDS
/// ON changes the bytes that get compiled in, so the identity must go dirty for that too. Watching
/// only the final binary crate's own directory does not catch it - cargo rebuilds the dependency
/// and relinks the binary without ever re-running the binary crate's build script, so the stamp
/// keeps reporting the last clean commit for a binary that no longer corresponds to it. That
/// matters here specifically because `console` and `propolis` carry almost all of their behavior in
/// sibling crates (`fleet`, `review`, `core-scoring`, ...); an edit to one of those is the ordinary
/// case, not the exotic one.
#[test]
fn dirty_marker_tracks_a_tracked_edit_in_a_path_dependency() {
    let repo = tempfile::tempdir().unwrap();
    let crate_dir = repo.path().join("crate");
    let dep_dir = repo.path().join("dep");
    let target_dir = repo.path().join("target");
    write_fixture_crate(&crate_dir);
    add_path_dependency(&crate_dir, &dep_dir);

    git(repo.path(), &["init", "-q", "-b", "main"]);
    git(repo.path(), &["config", "user.email", "test@example.com"]);
    git(repo.path(), &["config", "user.name", "test"]);
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "initial"]);
    // Same reason as the test above: a repository with no `packed-refs` and no loose ref makes
    // cargo re-run the build script on every build regardless of any watch, which would let this
    // test pass without the dependency watch it exists to prove.
    git(repo.path(), &["pack-refs", "--all"]);
    git(
        repo.path(),
        &["commit", "-q", "--allow-empty", "-m", "repack fixture"],
    );

    let clean_sha = build_and_read_sha(&crate_dir, &target_dir);
    assert!(
        !clean_sha.contains("+dirty") && clean_sha != "unknown",
        "a build from a just-committed tree must name a clean commit: {clean_sha}"
    );

    std::fs::write(
        dep_dir.join("src/lib.rs"),
        "pub fn marker() -> &'static str { \"v2 - edited, not committed\" }\n",
    )
    .unwrap();
    let dirty_sha = build_and_read_sha(&crate_dir, &target_dir);
    assert_eq!(
        dirty_sha,
        format!("{clean_sha}+dirty"),
        "editing a tracked source file in a crate this binary DEPENDS on must mark the build \
         dirty: the dependency's code is compiled in, so the binary no longer matches the commit \
         it would otherwise claim; got {dirty_sha}"
    );

    git(&dep_dir, &["checkout", "--", "src/lib.rs"]);
    let restored_sha = build_and_read_sha(&crate_dir, &target_dir);
    assert_eq!(
        restored_sha, clean_sha,
        "restoring the dependency's source must clear the dirty marker again"
    );
}

/// An untracked file (a scratch note, a local tool's cache directory - `.codex/` in this very
/// repository is exactly this case) was never compiled into the binary and must never be counted
/// as making a clean checkout dirty.
#[test]
fn dirty_marker_ignores_untracked_files() {
    let repo = tempfile::tempdir().unwrap();
    let crate_dir = repo.path().join("crate");
    let target_dir = repo.path().join("target");
    write_fixture_crate(&crate_dir);

    git(repo.path(), &["init", "-q", "-b", "main"]);
    git(repo.path(), &["config", "user.email", "test@example.com"]);
    git(repo.path(), &["config", "user.name", "test"]);
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "initial"]);

    let clean_sha = build_and_read_sha(&crate_dir, &target_dir);
    assert!(!clean_sha.contains("+dirty"));

    std::fs::write(crate_dir.join("scratch_notes.txt"), "never added to git\n").unwrap();
    let after_untracked = build_and_read_sha(&crate_dir, &target_dir);
    assert_eq!(
        after_untracked, clean_sha,
        "an untracked file must not flip the build to dirty: got {after_untracked}"
    );
}

/// A linked worktree's `.git` is a FILE (a `gitdir:` pointer into the main repository's
/// `.git/worktrees/<name>/`), not a directory - so the naive path this file used to guess,
/// `../../.git/HEAD` relative to the crate directory, never exists there. This proves the
/// ERRONEOUS ASSUMPTION directly (the guessed path is absent on disk, ground-truthed against
/// git's own `--git-path` resolution which IS present), then proves the practical consequence:
/// a real commit made inside the worktree is correctly reflected as a clean, non-stale identity.
#[test]
fn worktree_paths_resolve_via_git_path_not_a_guessed_relative_layout() {
    let main_repo = tempfile::tempdir().unwrap();
    let crate_dir = main_repo.path().join("crate");
    write_fixture_crate(&crate_dir);
    git(main_repo.path(), &["init", "-q", "-b", "main"]);
    git(
        main_repo.path(),
        &["config", "user.email", "test@example.com"],
    );
    git(main_repo.path(), &["config", "user.name", "test"]);
    git(main_repo.path(), &["add", "-A"]);
    git(main_repo.path(), &["commit", "-q", "-m", "initial"]);

    let worktree_dir = tempfile::tempdir().unwrap();
    git(
        main_repo.path(),
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "wt-branch",
            worktree_dir.path().to_str().unwrap(),
            "main",
        ],
    );
    let worktree_crate_dir = worktree_dir.path().join("crate");

    // Ground truth: the guessed path this file used to watch does not exist in a worktree, while
    // git's own `--git-path HEAD`, run from the same directory the build script would run in,
    // resolves to a real file.
    let guessed = worktree_crate_dir.join("../../.git/HEAD");
    assert!(
        !guessed.exists(),
        "test assumption broken: the guessed path unexpectedly exists at {}; a linked worktree's \
         .git must be a file, not a directory, for this test to exercise the real defect",
        guessed.display()
    );
    let resolved = git_output(&worktree_crate_dir, &["rev-parse", "--git-path", "HEAD"]);
    let resolved_path = if Path::new(&resolved).is_absolute() {
        std::path::PathBuf::from(&resolved)
    } else {
        worktree_crate_dir.join(&resolved)
    };
    assert!(
        resolved_path.exists(),
        "git --git-path HEAD must resolve to the worktree's real per-worktree HEAD file, got \
         {resolved} which does not exist"
    );

    // Practical consequence: a commit made inside the worktree (moving only that worktree's own
    // HEAD, never the main checkout's) is reflected correctly and is not "unknown" or stale.
    let target_dir = worktree_dir.path().join("target");
    let sha_before = build_and_read_sha(&worktree_crate_dir, &target_dir);
    assert!(!sha_before.contains("+dirty"));
    assert_ne!(sha_before, "unknown");

    git(
        &worktree_crate_dir,
        &["commit", "-q", "--allow-empty", "-m", "second"],
    );
    let sha_after = build_and_read_sha(&worktree_crate_dir, &target_dir);
    assert_ne!(
        sha_after, sha_before,
        "a new commit made inside the worktree must change the reported identity"
    );
    assert!(!sha_after.contains("+dirty"));
    assert_ne!(sha_after, "unknown");

    // The main checkout's own HEAD never moved, proving the worktree's commit is genuinely
    // independent state and not an artifact of both directories sharing one branch tip.
    let main_head = git_output(main_repo.path(), &["rev-parse", "--short=12", "HEAD"]);
    assert_eq!(
        main_head, sha_before,
        "the main checkout's HEAD must be unaffected by a commit made inside the worktree"
    );
}

/// A checkout with no repository at all (a source tarball, a container image built without `.git`)
/// must yield `unknown` rather than a wrong or empty identity, because the console's version panel
/// treats `unknown` as unrecorded and never compares it against the deploy stamp. This is the
/// fail-soft half of the stamp, and it has to keep working now that the build script also walks
/// manifests to decide what to watch.
#[test]
fn a_build_outside_any_git_repository_reports_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let crate_dir = dir.path().join("crate");
    let target_dir = dir.path().join("target");
    write_fixture_crate(&crate_dir);

    let inside_a_repo = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&crate_dir)
        .output()
        .expect("failed to spawn git")
        .status
        .success();
    assert!(
        !inside_a_repo,
        "test assumption broken: the temp directory is itself inside a git repository, so this \
         cannot exercise the no-git path"
    );

    let (sha, built_at) = build_and_read_stamp(&crate_dir, &target_dir, &[]);
    assert_eq!(
        sha, "unknown",
        "a build that cannot identify itself must say unknown, not guess"
    );
    assert!(
        built_at.ends_with('Z') && built_at.len() == 20,
        "the build timestamp must still be recorded even with no repository: {built_at}"
    );
}

/// `SOURCE_DATE_EPOCH` is the reproducible-build convention, and the stamp honours it so a
/// bit-for-bit rebuild does not differ by a timestamp alone. Both values below are the conversion
/// GNU `date -u -d @<epoch>` produces, not a recomputation by the same arithmetic under test; the
/// first is a leap day, where an incorrect civil-date conversion lands on 02-28 or 03-01.
#[test]
fn source_date_epoch_pins_the_build_timestamp_and_a_change_to_it_is_picked_up() {
    let dir = tempfile::tempdir().unwrap();
    let crate_dir = dir.path().join("crate");
    let target_dir = dir.path().join("target");
    write_fixture_crate(&crate_dir);

    let (_, leap_day) = build_and_read_stamp(
        &crate_dir,
        &target_dir,
        &[("SOURCE_DATE_EPOCH", "951782400")],
    );
    assert_eq!(
        leap_day, "2000-02-29T00:00:00Z",
        "SOURCE_DATE_EPOCH must decide the stamped timestamp"
    );

    let (_, later) = build_and_read_stamp(
        &crate_dir,
        &target_dir,
        &[("SOURCE_DATE_EPOCH", "1700000000")],
    );
    assert_eq!(
        later, "2023-11-14T22:13:20Z",
        "changing SOURCE_DATE_EPOCH must re-run the build script rather than keep the cached \
         timestamp"
    );
}

/// A branch ref with no loose file - only an entry in `packed-refs` - is the other guessed-path
/// failure mode this file used to have: `../../.git/refs/heads/<branch>` does not exist once that
/// ref is packed. `--git-path packed-refs` must still resolve to the real, existing file that
/// actually carries the ref's value, so a packed branch move stays watched.
#[test]
fn packed_ref_path_resolves_via_git_path() {
    let repo = tempfile::tempdir().unwrap();
    let crate_dir = repo.path().join("crate");
    write_fixture_crate(&crate_dir);
    git(repo.path(), &["init", "-q", "-b", "main"]);
    git(repo.path(), &["config", "user.email", "test@example.com"]);
    git(repo.path(), &["config", "user.name", "test"]);
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "initial"]);
    git(repo.path(), &["pack-refs", "--all"]);

    assert!(
        !repo.path().join(".git/refs/heads/main").exists(),
        "test assumption broken: main's ref must have no loose file after pack-refs"
    );
    let guessed = crate_dir.join("../../.git/refs/heads/main");
    assert!(
        !guessed.exists(),
        "test assumption broken: the guessed loose-ref path unexpectedly exists"
    );

    let packed = git_output(&crate_dir, &["rev-parse", "--git-path", "packed-refs"]);
    let packed_path = if Path::new(&packed).is_absolute() {
        std::path::PathBuf::from(&packed)
    } else {
        crate_dir.join(&packed)
    };
    assert!(
        packed_path.exists(),
        "git --git-path packed-refs must resolve to the real packed-refs file, got {packed} \
         which does not exist"
    );

    // Practical consequence: identity is still correctly reported (not stale, not "unknown")
    // against a packed ref.
    let target_dir = repo.path().join("target");
    let sha = build_and_read_sha(&crate_dir, &target_dir);
    assert!(!sha.contains("+dirty"));
    assert_ne!(sha, "unknown");
}
