//! Coverage gate: no binary may build its own stock `tracing_subscriber::fmt` output, because that
//! output is coloured whether or not stdout is a terminal and carries no journald priority.
//! The per-binary tests prove the binaries that exist today; this one derives the population from
//! the source tree, so a binary added later that calls `fmt::init()` fails here instead of
//! silently shipping every line at priority 6 again.

use std::fs;
use std::path::Path;

fn walk(dir: &Path, hits: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, hits);
        } else if path.extension().is_some_and(|e| e == "rs")
            && let Ok(text) = fs::read_to_string(&path)
        {
            for (n, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains("tracing_subscriber::fmt::init")
                    || code.contains("tracing_subscriber::fmt::layer")
                    || code.contains("tracing_subscriber::fmt()")
                    || code.contains("tracing_subscriber::fmt::try_init")
                {
                    hits.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                }
            }
        }
    }
}

#[test]
fn every_binary_uses_the_shared_log_format() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut hits = Vec::new();
    for entry in fs::read_dir(crates).unwrap().flatten() {
        // Only shipped code: `src/`. Tests, examples and the soak harness build throwaway
        // subscribers of their own. This crate wraps the stock layer on purpose.
        if entry.file_name() == "log-format" {
            continue;
        }
        let src = entry.path().join("src");
        if src.is_dir() {
            walk(&src, &mut hits);
        }
    }
    assert!(
        hits.is_empty(),
        "use log_format::init / log_format::layer instead:\n{}",
        hits.join("\n")
    );
}
