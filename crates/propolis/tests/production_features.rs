//! Guards the `review` crate's test-only `test-public-ranges` feature (see `review::reserved`).
//!
//! The feature makes the gatekeeper and the review queue treat 203.0.113.0/24 as public, so it must
//! never be switched on in anything that ships. Its sole enabler is `review`'s own self
//! dev-dependency, which cargo applies to test builds and never to `cargo build`. These tests ask
//! cargo for the feature graph of the build as shipped (`-e no-dev` drops dev-dependency edges, as
//! `cargo build` does) over the whole workspace, because cargo unifies features across a
//! `--workspace` build, and fail if the feature appears there. `review::reserved` also refuses to
//! compile the feature under the release profile.

use std::path::Path;
use std::process::Command;

const FEATURE: &str = "test-public-ranges";

/// `cargo tree` over the given edge kinds, for one package or, with `None`, the whole workspace.
fn tree(package: Option<&str>, edges: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root two levels above the crate manifest");
    let out = Command::new(env!("CARGO"))
        .current_dir(root)
        .args(["tree", "--locked", "--prefix", "none"])
        .args(["-e", edges])
        .args(match package {
            Some(p) => vec!["-p", p],
            None => vec!["--workspace"],
        })
        .output()
        .expect("cargo tree must start");
    assert!(
        out.status.success(),
        "cargo tree {package:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("cargo tree prints UTF-8")
}

/// The instrument can see the feature: with dev-dependency edges included, `review` lists it. If
/// this fails, the shipped-build assertion below would pass vacuously.
#[test]
fn the_feature_graph_check_can_see_the_feature() {
    let with_dev = tree(Some("review"), "features");
    assert!(
        with_dev.contains(FEATURE),
        "cargo tree with dev-dependencies no longer lists {FEATURE}; update this guard:\n{with_dev}"
    );
}

/// The release is built with `cargo build --release --workspace`, and cargo unifies features across
/// every package in that build: one crate enabling the feature on its `review` dependency turns it
/// on in the single `review` library every binary links. So the check covers the whole workspace's
/// shipped graph, not only the `propolis` and `review` packages.
#[test]
fn the_shipped_build_graphs_do_not_enable_the_test_only_feature() {
    let shipped = tree(None, "features,no-dev");
    assert!(
        !shipped.contains(FEATURE),
        "the workspace's shipped dependency graph enables {FEATURE}:\n{shipped}"
    );
}
