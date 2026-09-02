//! Reads one env var by its canonical name, falling back to a deprecated legacy spelling when the
//! canonical name is unset. Generalizes the migration shape `sensor-catchall/src/main.rs`
//! established for its own bare `CATCHALL_*` names (see that file's `env_var`/`legacy_name`) to a
//! rename that spans multiple binaries with DIFFERENT legacy spellings each - `COLLECTOR_ID` on
//! every sensor, `PROPOLIS_SHIPPER_COLLECTOR_ID` on `shipper` - so the legacy name cannot be
//! derived from the canonical one by a fixed prefix rule and must be passed explicitly.

use std::env;

/// Which source produced the resolved value, and what (if anything) [`env_with_legacy`] should
/// warn about. Kept separate from the actual `std::env::var` calls so this precedence logic is
/// unit-testable without mutating process-global environment state.
#[derive(Debug, PartialEq)]
enum Resolution {
    /// The canonical name was set. `legacy_ignored` names the deprecated value it overrode, when
    /// the legacy name was ALSO set to a different value - `None` when the legacy name was unset
    /// or matched the canonical value.
    Canonical { legacy_ignored: Option<String> },
    /// The canonical name was unset; the deprecated legacy name was used instead.
    Legacy,
    /// Neither name was set.
    Unset,
}

fn resolve(canonical: Option<&str>, legacy: Option<&str>) -> Resolution {
    match (canonical, legacy) {
        (Some(c), Some(l)) if c != l => Resolution::Canonical {
            legacy_ignored: Some(l.to_string()),
        },
        (Some(_), _) => Resolution::Canonical {
            legacy_ignored: None,
        },
        (None, Some(_)) => Resolution::Legacy,
        (None, None) => Resolution::Unset,
    }
}

/// Reads `canonical`, falling back to the deprecated `legacy` name when `canonical` is unset.
/// `canonical` always wins when both are set; if they disagree, the legacy value is logged as
/// ignored rather than silently discarded. A legacy-only read logs once, naming the canonical
/// replacement, so the fallback is a migration path rather than a second permanent spelling.
pub fn env_with_legacy(canonical: &str, legacy: &str) -> Option<String> {
    let canonical_value = env::var(canonical).ok();
    let legacy_value = env::var(legacy).ok();
    match resolve(canonical_value.as_deref(), legacy_value.as_deref()) {
        Resolution::Canonical {
            legacy_ignored: Some(ignored),
        } => {
            tracing::warn!(
                canonical,
                legacy,
                ignored,
                "both the canonical and a deprecated legacy env var are set to different \
                 values; the canonical value wins and the legacy value is ignored"
            );
            canonical_value
        }
        Resolution::Canonical {
            legacy_ignored: None,
        } => canonical_value,
        Resolution::Legacy => {
            tracing::warn!(
                canonical,
                legacy,
                "read a deprecated env var name; rename it to the canonical replacement (the \
                 legacy spelling will stop being read in a future release)"
            );
            legacy_value
        }
        Resolution::Unset => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_wins_when_both_are_set_and_agree() {
        assert_eq!(
            resolve(Some("v"), Some("v")),
            Resolution::Canonical {
                legacy_ignored: None
            }
        );
    }

    #[test]
    fn canonical_wins_and_names_the_ignored_legacy_value_when_they_disagree() {
        assert_eq!(
            resolve(Some("new-value"), Some("old-value")),
            Resolution::Canonical {
                legacy_ignored: Some("old-value".to_string())
            }
        );
    }

    #[test]
    fn legacy_is_read_when_canonical_is_unset() {
        assert_eq!(resolve(None, Some("old-value")), Resolution::Legacy);
    }

    #[test]
    fn neither_set_resolves_to_unset() {
        assert_eq!(resolve(None, None), Resolution::Unset);
    }
}
