//! Stamps this binary with the git revision and build time it was made from.
//!
//! The logic is shared verbatim with `crates/propolis/build.rs`; see `crates/build-stamp.rs` for
//! why it shells out to git, why each binary stamps itself, and why every failure yields
//! "unknown".

include!("../build-stamp.rs");

fn main() {
    emit_build_stamp();
}
