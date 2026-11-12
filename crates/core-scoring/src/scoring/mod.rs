pub mod breadth;
pub mod constants;
pub mod decay;
pub mod eligibility;
pub mod engine;
pub mod persistence;
pub mod tier;

// Executable documentation-truth checks: each test below asserts a specific claim the README's
// "Scoring" section makes, so a behavior change that contradicts the docs fails the build and the
// failing test name points at the doc line to update. See scoring/doc_truth.rs.
#[cfg(test)]
mod doc_truth;
