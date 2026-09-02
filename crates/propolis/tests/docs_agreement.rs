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

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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
