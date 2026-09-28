//! Doc/code agreement gate. Twice this project shipped INSTALL.md documenting an env var name the
//! code does not read (`PROPOLIS_CATCHALL_BIND` vs `CATCHALL_BIND_ADDRS`, and a wrong feed dir),
//! and a sensor refused to start with no hint why. This test makes that class of drift fail CI.
//!
//! Direction is code -> docs: every `PROPOLIS_*` / `CATCHALL_*` env-var NAME that appears as a
//! string literal in the workspace's non-test source must also appear literally in the canonical
//! env-var reference (`docs/reference/environment-variables.md`; INSTALL.md is now a stub). That
//! direction is chosen deliberately: the reverse (every var in the docs must exist in code) false-
//! positives on INSTALL.md's own corrective prose, which quotes wrong names on purpose ("previously
//! documented PROPOLIS_CATCHALL_BIND, which the binary does not read"). Code string literals carry
//! no such prose, so this direction is unambiguous.

mod doc_commands;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

fn workspace_root() -> PathBuf {
    // crates/propolis -> crates -> workspace root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root two levels above the crate manifest")
        .to_path_buf()
}

/// Every non-test `.rs` under `dir`, recursively, one entry per file. Skips `tests/` directories
/// (fixtures deliberately reference example/wrong names) and the vendored tree.
///
/// Files are kept separate on purpose. An earlier version concatenated them and ran one
/// quote-tracking scan over the whole string, so a file with an odd number of `"` characters
/// (one `'"'` char literal is enough) inverted the quote state for every file after it in
/// `read_dir` order. That order differs between filesystems, so the gate passed on one machine
/// and failed in CI on the same tree, and about forty per-sensor variables went undocumented
/// while the local run stayed green.
fn collect_src(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name == "tests" || name == "vendor" || name == "target" {
                continue;
            }
            collect_src(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && let Ok(text) = fs::read_to_string(&path)
        {
            out.push(text);
        }
    }
}

/// Env-var NAMES (`PROPOLIS_*` / `CATCHALL_*`) that appear inside a double-quoted string literal.
/// A `'"'` char literal is skipped so it cannot open a phantom string.
fn env_var_literals(src: &str) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' && bytes.get(i + 1) == Some(&b'"') && bytes.get(i + 2) == Some(&b'\'')
        {
            i += 3;
        } else if bytes[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            let token = &src[start..j.min(src.len())];
            if (token.starts_with("PROPOLIS_") || token.starts_with("CATCHALL_"))
                && token.len() > "PROPOLIS_".len()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                vars.insert(token.to_string());
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    vars
}

#[test]
fn every_env_var_the_code_reads_is_documented_in_the_env_var_reference() {
    // The env-var docs were reorganized (2026-08-26): INSTALL.md is now a compatibility stub and the
    // canonical, complete list lives in docs/reference/environment-variables.md. This gate checks
    // that file. Same code -> docs direction and same rationale as the module doc comment.
    let root = workspace_root();
    let doc_path = root.join("docs/reference/environment-variables.md");
    let doc =
        fs::read_to_string(&doc_path).expect("docs/reference/environment-variables.md exists");
    let mut files = Vec::new();
    collect_src(&root.join("crates"), &mut files);

    let vars: BTreeSet<String> = files.iter().flat_map(|f| env_var_literals(f)).collect();
    assert!(
        !vars.is_empty(),
        "extraction found no env-var literals - the scan is broken, not the docs"
    );

    let missing: Vec<&String> = vars.iter().filter(|v| !doc.contains(v.as_str())).collect();
    assert!(
        missing.is_empty(),
        "env vars read by the code but NOT documented in docs/reference/environment-variables.md \
         (document them or the operator cannot configure them): {missing:?}"
    );
}

/// The project bans the em-dash (U+2014) in prose and code: it reads as generated text, and the
/// maintainer's stated substitute is a spaced hyphen. This walks every tracked Markdown file under
/// `docs/` (excluding the byte-exact `docs/archive/`, which is checksummed) and every non-vendored
/// Rust source file, and fails naming each offending `file:line`. A sweep removed 459 of them from
/// 48 files on 2026-09-01; this keeps them out.
#[test]
fn no_em_dashes_in_live_docs_or_source() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut offenders = Vec::new();
    fn walk(dir: &std::path::Path, out: &mut Vec<String>, root: &std::path::Path) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            if p.is_dir() {
                // `superpowers` under docs/ is gitignored working notes (plans, specs, reports), not a deliverable.
                if matches!(
                    name.as_str(),
                    "archive"
                        | "superpowers"
                        | "target"
                        | "vendor"
                        | ".git"
                        | "node_modules"
                        | ".superpowers"
                ) {
                    continue;
                }
                walk(&p, out, root);
            } else if name.ends_with(".md") || name.ends_with(".rs") {
                let Ok(text) = std::fs::read_to_string(&p) else {
                    continue;
                };
                for (i, line) in text.lines().enumerate() {
                    if line.contains('\u{2014}') {
                        out.push(format!(
                            "{}:{}",
                            p.strip_prefix(root).unwrap_or(&p).display(),
                            i + 1
                        ));
                    }
                }
            }
        }
    }
    walk(&root.join("docs"), &mut offenders, &root);
    walk(&root.join("crates"), &mut offenders, &root);
    assert!(
        offenders.is_empty(),
        "em-dash (U+2014) found; replace with a spaced hyphen or restructure the sentence:\n{}",
        offenders.join("\n")
    );
}

/// Every pair of `tar` inputs where one names the same tree as, or a tree inside, the other.
/// `tar` recurses into a directory, so the audited backup command (P-11), which listed
/// `/var/spool/propolis/fetched` beside `/var/spool/propolis`, stored every fetched sample twice.
/// Comparison is by path component, so `/var/spool/propolis-old` is not inside
/// `/var/spool/propolis`; a `..` component cannot be judged without the filesystem and is
/// reported instead of guessed at.
fn overlapping_inputs(inputs: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for (i, a) in inputs.iter().enumerate() {
        if Path::new(a).components().any(|c| c == Component::ParentDir) {
            found.push(format!("{a} contains `..`; write the path without it"));
        }
        for b in &inputs[i + 1..] {
            let (pa, pb) = (Path::new(a), Path::new(b));
            if pa == pb {
                found.push(format!("{a} is listed twice"));
            } else if pb.starts_with(pa) {
                found.push(format!("{b} is inside {a}"));
            } else if pa.starts_with(pb) {
                found.push(format!("{a} is inside {b}"));
            }
        }
    }
    found
}

/// Live Markdown the gate reads: `docs/` without the checksummed `archive/` and the gitignored
/// `superpowers/` notes, plus the top-level `*.md` files.
fn live_markdown(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if !matches!(entry.file_name().to_str(), Some("archive" | "superpowers")) {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|e| e == "md") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&root.join("docs"), &mut files);
    if let Ok(entries) = fs::read_dir(root) {
        files.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "md")),
        );
    }
    files
}

#[test]
fn documented_archive_commands_name_each_tree_once() {
    let root = workspace_root();
    let backup_doc = root.join("docs/operations/backup-and-restore.md");
    let backup = fs::read_to_string(&backup_doc).expect("docs/operations/backup-and-restore.md");
    // The backup page owns the procedure; if its command stops being found, the reader is broken
    // and every other file's clean result below means nothing.
    assert!(
        doc_commands::tar_create_inputs(&backup)
            .iter()
            .any(|inputs| inputs.len() >= 2),
        "no tar archive command with two or more inputs found in {} - the extraction is broken, \
         not the docs",
        backup_doc.display()
    );

    let mut problems = Vec::new();
    for file in live_markdown(&root) {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for inputs in doc_commands::tar_create_inputs(&text) {
            for problem in overlapping_inputs(&inputs) {
                problems.push(format!(
                    "{}: {problem}",
                    file.strip_prefix(&root).unwrap_or(&file).display()
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "a documented tar command archives the same files twice; name each tree once:\n{}",
        problems.join("\n")
    );
}

/// The reader and the overlap check, held to the exact command the audit found and to the near
/// misses a lexical prefix check would get wrong.
#[test]
fn archive_overlap_check_flags_the_audited_command_and_nothing_else() {
    let audited = "```\n\
        # Example. Run as root to preserve per-service ownership.\n\
        tar --numeric-owner -czf propolis-state-$(date +%F).tgz \\\n\
        \x20 /etc/propolis \\\n\
        \x20 /var/spool/propolis/fetched \\\n\
        \x20 /var/spool/propolis \\\n\
        \x20 /var/lib/propolis/ssh\n\
        ```\n";
    let commands = doc_commands::tar_create_inputs(audited);
    assert_eq!(
        commands,
        vec![vec![
            "/etc/propolis".to_string(),
            "/var/spool/propolis/fetched".to_string(),
            "/var/spool/propolis".to_string(),
            "/var/lib/propolis/ssh".to_string(),
        ]],
        "the archive name and the comment must not read as inputs"
    );
    assert_eq!(
        overlapping_inputs(&commands[0]),
        vec!["/var/spool/propolis/fetched is inside /var/spool/propolis".to_string()]
    );

    let owned = |paths: &[&str]| paths.iter().map(|p| p.to_string()).collect::<Vec<_>>();
    assert!(
        overlapping_inputs(&owned(&["/var/spool/propolis", "/var/spool/propolis-old"])).is_empty(),
        "a sibling sharing a name prefix is not inside the other"
    );
    assert_eq!(
        overlapping_inputs(&owned(&["/etc/propolis/", "/etc/propolis"])).len(),
        1
    );
    assert_eq!(
        doc_commands::tar_create_inputs(
            "```\nsudo tar -C / -cf x.tar a b\ntar -xzf x.tgz -C /\n```"
        ),
        vec![owned(&["a", "b"])],
        "-C's directory is not an input, and extraction is not archiving"
    );
}

// ---- workspace facts the docs restate --------------------------------------------------------
//
// The docs once said 18 crates at 0.3.0, 15 binaries and 1165 tests while the tree had 24 crates
// (most at 0.4.0), 17 binaries and roughly 1650 tests: every figure was right when written and
// nothing noticed when it stopped being. These tests derive each figure from the workspace itself
// and fail when a current document disagrees.

/// One workspace member: identity and targets from `cargo metadata`, test counts from its sources.
struct Member {
    name: String,
    version: String,
    binaries: usize,
    /// Other workspace members this one depends on (normal dependencies only).
    internal_deps: BTreeSet<String>,
    /// Integration test targets, by name.
    integration_targets: BTreeSet<String>,
    unit: TestCount,
    integration: TestCount,
}

/// Test attributes as `build-and-test.md` counts them.
#[derive(Default)]
struct TestCount {
    tests: usize,
    db: usize,
    db_own_migrations: usize,
    db_no_migrations: usize,
    ignored: usize,
}

/// Every test attribute in every `.rs` file under `dir`.
fn count_tests(dir: &Path) -> TestCount {
    let mut count = TestCount::default();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                for line in fs::read_to_string(&path).unwrap().lines() {
                    let line = line.trim_start();
                    let db = line.starts_with("#[sqlx::test");
                    count.tests += usize::from(
                        db || line.starts_with("#[test]") || line.starts_with("#[tokio::test"),
                    );
                    count.db += usize::from(db);
                    count.db_own_migrations +=
                        usize::from(db && line.contains(r#"migrations = "./migrations""#));
                    count.db_no_migrations +=
                        usize::from(db && line.contains("migrations = false"));
                    count.ignored += usize::from(line.starts_with("#[ignore"));
                }
            }
        }
    }
    count
}

fn workspace_members() -> Vec<Member> {
    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version=1",
            "--no-deps",
            "--offline",
            "--locked",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let text = |v: &serde_json::Value| v.as_str().expect("a string").to_string();
    let packages = metadata["packages"].as_array().expect("packages");
    let names: BTreeSet<String> = packages.iter().map(|p| text(&p["name"])).collect();
    let mut members: Vec<Member> = packages
        .iter()
        .map(|package| {
            let dir = Path::new(package["manifest_path"].as_str().unwrap())
                .parent()
                .unwrap()
                .to_path_buf();
            let targets = package["targets"].as_array().unwrap();
            let named = |kind: &str| -> BTreeSet<String> {
                targets
                    .iter()
                    .filter(|t| t["kind"].as_array().unwrap().iter().any(|k| k == kind))
                    .map(|t| text(&t["name"]))
                    .collect()
            };
            Member {
                name: text(&package["name"]),
                version: text(&package["version"]),
                binaries: named("bin").len(),
                internal_deps: package["dependencies"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|d| d["kind"].is_null())
                    .map(|d| text(&d["name"]))
                    .filter(|d| names.contains(d))
                    .collect(),
                integration_targets: named("test"),
                unit: count_tests(&dir.join("src")),
                integration: count_tests(&dir.join("tests")),
            }
        })
        .collect();
    members.sort_by(|a, b| a.name.cmp(&b.name));
    members
}

/// Current documents that restate workspace facts: live markdown minus the changelog, the dated
/// claim ledger and `docs/history/`, which record what was true at a point in time on purpose.
fn current_docs() -> Vec<PathBuf> {
    live_markdown(&workspace_root())
        .into_iter()
        .filter(|p| {
            let s = p.to_string_lossy();
            !s.ends_with("CHANGELOG.md")
                && !s.ends_with("claim-to-source-ledger.md")
                && !s.contains("/docs/history/")
        })
        .collect()
}

/// Every `<number> [qualifier] <noun>` phrase in `text`, wrapped lines and markdown emphasis
/// included, with the count and the phrase plus three words either side of it.
fn counted_phrases(text: &str, noun: &str) -> Vec<(usize, String)> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let bare = |w: &str| {
        w.trim_matches(|c: char| !c.is_ascii_alphanumeric())
            .to_string()
    };
    let mut out = Vec::new();
    for (i, word) in words.iter().enumerate() {
        if bare(word) != noun {
            continue;
        }
        let count = (1..=2)
            .filter_map(|back| i.checked_sub(back))
            .find_map(|j| {
                let is_number = bare(words[j]).chars().all(|c| c.is_ascii_digit());
                let qualifiers_are_words = words[j + 1..i]
                    .iter()
                    .all(|w| bare(w).chars().all(|c| c.is_ascii_alphabetic()));
                (is_number && qualifiers_are_words)
                    .then(|| bare(words[j]).parse::<usize>().ok().map(|n| (n, j)))
                    .flatten()
            });
        if let Some((n, j)) = count {
            let phrase = words[j.saturating_sub(3)..(i + 4).min(words.len())].join(" ");
            out.push((n, phrase));
        }
    }
    out
}

/// Historical and superseded pages, and the claim ledger (a snapshot of one commit), are frozen
/// records and keep the version they were frozen at.
#[test]
fn documents_state_the_version_the_tree_is_at() {
    let version = workspace_members()
        .into_iter()
        .find(|m| m.name == "propolis")
        .expect("the propolis crate")
        .version;
    let (mut checked, mut wrong) = (0, Vec::new());
    for path in live_markdown(&workspace_root()) {
        if path.ends_with("docs/claim-to-source-ledger.md") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let header: Vec<&str> = text.lines().take(12).collect();
        if header
            .iter()
            .any(|l| *l == "status: historical" || *l == "status: superseded")
        {
            continue;
        }
        let Some(line) = header.iter().find(|l| l.starts_with("applies-to:")) else {
            continue;
        };
        checked += 1;
        if !line.starts_with(&format!("applies-to: {version} ")) {
            wrong.push(format!("{}: {line}", path.display()));
        }
    }
    assert!(
        checked >= 50,
        "found only {checked} pages with front matter"
    );
    assert!(
        wrong.is_empty(),
        "front matter must name the tree's version {version}:\n{}",
        wrong.join("\n")
    );
}

/// Every backticked bare version (`1.2.3`) outside fenced code, with the words before it (in
/// reading order) and the word after it. Emphasis markers are dropped so `**`0.4.0` but**` reads
/// like the sentence it is.
fn backticked_versions(text: &str) -> Vec<(String, Vec<String>, String)> {
    let prose: Vec<&str> = text.split("```").step_by(2).collect();
    let flat = prose.join(" ").replace("**", "");
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    let is_version = |s: &str| {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    };
    let word = |w: &str| {
        w.trim_matches(|c: char| !c.is_ascii_alphanumeric())
            .to_ascii_lowercase()
    };
    let segments: Vec<&str> = flat.split('`').collect();
    let mut out = Vec::new();
    for i in (1..segments.len().saturating_sub(1)).step_by(2) {
        if !is_version(segments[i]) {
            continue;
        }
        let before: Vec<String> = segments[..i]
            .join("`")
            .split_whitespace()
            .map(word)
            .collect();
        let before = before[before.len().saturating_sub(8)..].to_vec();
        let after = segments[i + 1]
            .split_whitespace()
            .next()
            .map(word)
            .unwrap_or_default();
        out.push((segments[i].to_string(), before, after));
    }
    out
}

/// Prose restates two versions: the tree's ("the current tree is `0.3.0`", "Crate version:
/// `0.3.0`") and the pinned toolchain's ("Rust `1.96.1`"). Both went stale in the first case, so a
/// version next to those words must be the real one. Other versions (dependencies, the crates
/// still at `0.1.0`, the version a crate was added after) are left alone.
#[test]
fn documents_state_the_real_tree_and_toolchain_versions() {
    let version = workspace_members()
        .into_iter()
        .find(|m| m.name == "propolis")
        .expect("the propolis crate")
        .version;
    let pin = fs::read_to_string(workspace_root().join("rust-toolchain.toml")).unwrap();
    let toolchain = pin
        .lines()
        .find_map(|l| l.strip_prefix("channel = "))
        .expect("a pinned channel")
        .trim_matches('"')
        .to_string();
    let (mut claims, mut wrong) = ([0, 0], Vec::new());
    for path in current_docs() {
        let text = fs::read_to_string(&path).unwrap();
        for (found, before, after) in backticked_versions(&text) {
            let near = &before[before.len().saturating_sub(3)..];
            let about_tree = after == "tree"
                || near.iter().any(|w| w == "tree" || w == "currently")
                || before[before.len().saturating_sub(6)..]
                    .join(" ")
                    .contains("crate version");
            let about_toolchain = before.iter().any(|w| w == "toolchain" || w == "rust");
            let (k, truth) = match (about_tree, about_toolchain) {
                (true, _) => (0, &version),
                (false, true) => (1, &toolchain),
                (false, false) => continue,
            };
            claims[k] += 1;
            if found != *truth {
                wrong.push(format!(
                    "{}: `{found}` should be `{truth}`: ...{} `{found}` {after}...",
                    path.display(),
                    before.join(" ")
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(
        claims.iter().all(|&n| n >= 5),
        "found only {claims:?} tree/toolchain version statements; the scan has stopped seeing them"
    );
}

/// A count of crates, members or binaries is a workspace total unless the words right around it
/// say otherwise (sensor crates, protocols, the binaries an installer copies, a test run's
/// binaries, the members of a tar archive).
#[test]
fn documents_state_the_real_crate_and_binary_totals() {
    let members = workspace_members();
    let totals = [
        ("crates", members.len()),
        ("members", members.len()),
        ("binaries", members.iter().map(|m| m.binaries).sum()),
    ];
    let qualified = ["sensor", "protocol", "install", "test", "archive"];
    let mut wrong = Vec::new();
    let mut stated = [0; 3];
    for path in current_docs() {
        let text = fs::read_to_string(&path).unwrap();
        for (k, (noun, truth)) in totals.iter().enumerate() {
            for (n, phrase) in counted_phrases(&text, noun) {
                let lower = phrase.to_ascii_lowercase();
                if qualified.iter().any(|q| lower.contains(q)) {
                    continue;
                }
                if n == *truth {
                    stated[k] += 1;
                } else {
                    wrong.push(format!(
                        "{}: says {n}, is {truth}: {phrase}",
                        path.display()
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(
        stated.iter().all(|&s| s > 0),
        "the scan found no statement of the totals at all ({stated:?}); it has stopped seeing them"
    );
}

/// `docs/development/build-and-test.md` publishes the test taxonomy; every figure in it is
/// recounted here by the method it states (test attributes, unit = under `src/`, integration =
/// under `tests/`), and its per-crate table must have exactly one row per workspace member.
#[test]
fn the_published_test_taxonomy_matches_the_source() {
    let members = workspace_members();
    let doc =
        fs::read_to_string(workspace_root().join("docs/development/build-and-test.md")).unwrap();
    let flat = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let sum = |f: fn(&Member) -> usize| members.iter().map(f).sum::<usize>();
    let unit = sum(|m| m.unit.tests);
    let integration = sum(|m| m.integration.tests);
    let db = sum(|m| m.unit.db + m.integration.db);
    let own = sum(|m| m.unit.db_own_migrations + m.integration.db_own_migrations);
    let manual = sum(|m| m.unit.db_no_migrations + m.integration.db_no_migrations);
    let ignored = sum(|m| m.unit.ignored + m.integration.ignored);
    let mut db_by_crate: Vec<(usize, &str)> = members
        .iter()
        .map(|m| (m.unit.db + m.integration.db, m.name.as_str()))
        .filter(|(n, _)| *n > 0)
        .collect();
    db_by_crate.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    let db_by_crate: Vec<String> = db_by_crate
        .iter()
        .map(|(n, c)| format!("{c} {n}"))
        .collect();

    let prose = flat(&doc);
    for expected in [
        format!(
            "**Total: {} test functions** ({unit} unit + {integration} integration).",
            unit + integration
        ),
        format!(
            "**DB-backed (`sqlx::test`): {db}** - {}.",
            db_by_crate.join(", ")
        ),
        format!("**Ignored: exactly {ignored}.**"),
        format!(
            r#"`#[sqlx::test(migrations = "./migrations")]` auto-applies that crate's own set ({own} uses)"#
        ),
        format!("applies migrations manually ({manual} uses)"),
        format!("A bare `#[sqlx::test]` ({} uses,", db - own - manual),
    ] {
        assert!(
            prose.contains(&expected),
            "build-and-test.md must say `{expected}`"
        );
    }

    let table: Vec<&str> = doc
        .lines()
        .skip_while(|l| !l.starts_with("| Crate | Unit | Integration | Integration files |"))
        .skip(2)
        .take_while(|l| l.starts_with("| "))
        .collect();
    let mut expected: Vec<String> = members
        .iter()
        .map(|m| {
            let targets = m.integration_targets.iter().cloned().collect::<Vec<_>>();
            let targets = if targets.is_empty() {
                "-".to_string()
            } else {
                targets.join(", ")
            };
            format!(
                "| {} | {} | {} | {targets} |",
                m.name, m.unit.tests, m.integration.tests
            )
        })
        .collect();
    expected.push(format!("| **Total** | **{unit}** | **{integration}** | |"));
    assert_eq!(
        table, expected,
        "the per-crate table in build-and-test.md must match the workspace row for row"
    );
}

/// `docs/architecture/components.md` owns the crate inventory and the internal dependency graph.
/// Six crates were added without either being updated, so both are checked against the manifests:
/// one table row per member, and exactly the members' normal `path` dependencies as graph edges.
#[test]
fn the_component_inventory_matches_cargo_metadata() {
    let members = workspace_members();
    let names: BTreeSet<&str> = members.iter().map(|m| m.name.as_str()).collect();
    let doc = fs::read_to_string(workspace_root().join("docs/architecture/components.md")).unwrap();

    let rows: BTreeSet<&str> = doc
        .lines()
        .filter_map(|l| {
            l.strip_prefix("| `")?
                .split_once("` |")
                .map(|(name, _)| name)
        })
        .collect();
    assert_eq!(
        rows, names,
        "the inventory table must have one row per workspace member"
    );

    let graph = doc
        .split("```mermaid")
        .nth(1)
        .and_then(|g| g.split("```").next())
        .expect("a mermaid dependency graph");
    let mut nodes: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut id_edges = Vec::new();
    for line in graph.lines().map(str::trim) {
        if let Some(edge) = line.split_once(" --> ") {
            id_edges.push(edge);
        } else if let Some((id, label)) = line.split_once('[') {
            // One node may stand for a family: `sensor-{catchall,ssh}` is two crates.
            let label = label
                .trim_end_matches(']')
                .trim_matches('"')
                .replace("<br/>", "");
            let crates = match label.split_once('{') {
                Some((prefix, rest)) => rest
                    .trim_end_matches('}')
                    .split(',')
                    .map(|suffix| format!("{prefix}{}", suffix.trim()))
                    .collect(),
                None => vec![label],
            };
            nodes.insert(id, crates);
        }
    }
    let drawn: BTreeSet<&str> = nodes.values().flatten().map(String::as_str).collect();
    assert_eq!(drawn, names, "the graph must draw every workspace member");

    let mut edges = BTreeSet::new();
    for (from, to) in id_edges {
        let (Some(from), Some(to)) = (nodes.get(from), nodes.get(to)) else {
            panic!("graph edge {from} --> {to} names an undeclared node");
        };
        for f in from {
            for t in to {
                edges.insert((f.clone(), t.clone()));
            }
        }
    }
    let actual: BTreeSet<(String, String)> = members
        .iter()
        .flat_map(|m| m.internal_deps.iter().map(|d| (m.name.clone(), d.clone())))
        .collect();
    assert_eq!(
        edges, actual,
        "the graph's edges must be exactly the members' internal dependencies"
    );
}

/// `docs/reference/database.md` owns the migration list: its change map must have one row per
/// migration file in each crate's `migrations/` directory, and a section for every such crate.
#[test]
fn the_migration_change_map_lists_every_migration() {
    let root = workspace_root();
    let doc = fs::read_to_string(root.join("docs/reference/database.md")).unwrap();
    let mut sets = 0;
    for entry in fs::read_dir(root.join("crates")).unwrap().flatten() {
        let dir = entry.path().join("migrations");
        if !dir.is_dir() {
            continue;
        }
        sets += 1;
        let krate = entry.file_name().to_string_lossy().into_owned();
        let on_disk: Vec<String> = {
            let mut v: Vec<String> = fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|f| f.file_name().to_string_lossy().into_owned())
                .filter(|f| f.ends_with(".sql"))
                .map(|f| f[..4].to_string())
                .collect();
            v.sort();
            v
        };
        let heading = format!("**{krate}** (`crates/{krate}/migrations/`");
        let listed: Vec<String> = doc
            .lines()
            .skip_while(|l| !l.starts_with(&heading))
            .skip(1)
            .skip_while(|l| l.trim().is_empty())
            .take_while(|l| l.starts_with('|'))
            .filter_map(|l| {
                l.strip_prefix("| `")?
                    .split_once('`')
                    .map(|(n, _)| n.to_string())
            })
            .collect();
        assert_eq!(
            listed, on_disk,
            "database.md's change map for {krate} must list exactly its migration files"
        );
    }
    assert!(sets >= 3, "found only {sets} migration sets");
}

/// Citations of the form `path:line` that name a file by its path from the workspace root (or from
/// `crates/`) must name a file that exists and lines it has. Hundreds of line citations drifted as
/// cited files changed; this cannot see a citation that moved within its file, but it does catch
/// one whose file was renamed, split or shortened past the lines it names. Bare filenames are
/// skipped because the file they mean depends on the page's context. The sanitizer results page
/// is a dated record whose citations describe the commit it names.
#[test]
fn documented_line_citations_name_real_files_and_lines() {
    let root = workspace_root();
    let (mut checked, mut wrong) = (0, Vec::new());
    for doc in current_docs() {
        if doc.ends_with("docs/security/sanitizer-results.md") {
            continue;
        }
        let text = fs::read_to_string(&doc).unwrap();
        let tokens = text.split(|c: char| c.is_whitespace() || "`()[];|\"".contains(c));
        for token in tokens {
            let token = token.trim_end_matches(['.', ',', ':']);
            let Some((path, spans)) = token.rsplit_once(':') else {
                continue;
            };
            let is_path = path.contains('/')
                && Path::new(path).extension().is_some()
                && !path.contains("://");
            let is_spans = !spans.is_empty()
                && spans.starts_with(|c: char| c.is_ascii_digit())
                && spans
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '-' || c == ',');
            if !is_path || !is_spans {
                continue;
            }
            // `crates/*/Cargo.toml:4` cites the same line in every crate.
            let targets: Vec<PathBuf> = match path.strip_prefix("crates/*/") {
                Some(rest) => fs::read_dir(root.join("crates"))
                    .unwrap()
                    .flatten()
                    .map(|e| e.path().join(rest))
                    .filter(|p| p.is_file())
                    .collect(),
                None => [root.join(path), root.join("crates").join(path)]
                    .into_iter()
                    .find(|p| p.is_file())
                    .into_iter()
                    .collect(),
            };
            if targets.is_empty() {
                if ["crates/", "deploy/", ".github/"]
                    .iter()
                    .any(|p| path.starts_with(p))
                {
                    wrong.push(format!(
                        "{}: {token} names a file that does not exist",
                        doc.display()
                    ));
                }
                continue;
            }
            let last = spans
                .split([',', '-'])
                .filter_map(|n| n.parse::<usize>().ok())
                .max()
                .unwrap_or(0);
            checked += 1;
            for target in targets {
                let lines = fs::read_to_string(&target).unwrap().lines().count();
                if last == 0 || last > lines {
                    wrong.push(format!(
                        "{}: {token} cites line {last}; {} has {lines}",
                        doc.display(),
                        target.display()
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(
        checked >= 200,
        "checked only {checked} citations; the scan has stopped seeing them"
    );
}
