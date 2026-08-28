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

/// Concatenate every non-test `.rs` under `dir`, recursively. Skips `tests/` directories (fixtures
/// deliberately reference example/wrong names) and the vendored tree.
fn collect_src(dir: &Path, out: &mut String) {
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
            out.push_str(&text);
            out.push('\n');
        }
    }
}

/// Env-var NAMES (`PROPOLIS_*` / `CATCHALL_*`) that appear inside a double-quoted string literal.
fn env_var_literals(src: &str) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
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
    let mut src = String::new();
    collect_src(&root.join("crates"), &mut src);

    let vars = env_var_literals(&src);
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
