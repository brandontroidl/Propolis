//! The strict env-var reader every sensor uses ([`strict_env_var`]) and the legacy-name fallback
//! built on it ([`env_with_legacy`]). The legacy fallback reads one env var by its canonical name,
//! falling back to a deprecated legacy spelling when the canonical name is unset. It generalizes
//! the migration shape `sensor-catchall/src/main.rs` established for its own bare `CATCHALL_*`
//! names to a rename that spans multiple binaries with DIFFERENT legacy spellings each -
//! `COLLECTOR_ID` on every sensor, `PROPOLIS_SHIPPER_COLLECTOR_ID` on `shipper` - so the legacy
//! name cannot be derived from the canonical one by a fixed prefix rule and must be passed
//! explicitly.

use std::env;
use std::fmt;

/// An env var held a value the strict reader refuses.
#[derive(Debug, PartialEq, Eq)]
pub enum EnvError {
    /// The variable was set to bytes that are not valid UTF-8.
    NotUnicode { var: String },
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUnicode { var } => {
                write!(f, "environment variable {var} is not valid UTF-8")
            }
        }
    }
}

impl std::error::Error for EnvError {}

/// The one reader for every sensor env var, so all sensors apply the same rule. Unset is
/// `Ok(None)`. The value is trimmed of leading and trailing ASCII whitespace, and a value blank
/// after the trim is also `Ok(None)`, matching `deploy/fleet-listeners.sh`, which skips blank
/// binds. A value that is not valid UTF-8 is [`EnvError::NotUnicode`]: never read as unset, which
/// would silently turn TLS off, drop a listener, or fall back to a default, and never converted
/// lossily into a path or address the operator did not write. The caller must treat the error as
/// fatal before binding anything.
pub fn strict_env_var(var: &str) -> Result<Option<String>, EnvError> {
    strict_env_value(var, env::var(var))
}

fn strict_env_value(
    var: &str,
    value: Result<String, env::VarError>,
) -> Result<Option<String>, EnvError> {
    match value {
        Ok(value) => {
            let trimmed = value.trim_matches(|c: char| c.is_ascii_whitespace());
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(EnvError::NotUnicode {
            var: var.to_string(),
        }),
    }
}

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
/// Both names are read with [`strict_env_var`]: a non-UTF-8 value on either is an error, never a
/// fall-through to the other name or to the default, and a blank value counts as unset.
pub fn env_with_legacy(canonical: &str, legacy: &str) -> Result<Option<String>, EnvError> {
    let canonical_value = strict_env_var(canonical)?;
    let legacy_value = strict_env_var(legacy)?;
    Ok(
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
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn strict_unset_is_none() {
        assert_eq!(
            strict_env_value("V", Err(env::VarError::NotPresent)),
            Ok(None)
        );
    }

    #[test]
    fn strict_non_utf8_is_an_error_naming_the_variable() {
        let err = strict_env_value("V", Err(env::VarError::NotUnicode(OsString::new())))
            .expect_err("non-UTF-8 must not read as unset");
        assert_eq!(
            err,
            EnvError::NotUnicode {
                var: "V".to_string()
            }
        );
        let text = err.to_string();
        assert!(text.contains('V') && text.contains("UTF-8"), "{text}");
    }

    #[test]
    fn strict_blank_after_trim_is_unset() {
        for blank in ["", " ", "\t", " \t\r\n "] {
            assert_eq!(
                strict_env_value("V", Ok(blank.to_string())),
                Ok(None),
                "{blank:?}"
            );
        }
    }

    #[test]
    fn strict_value_is_trimmed_of_ascii_whitespace_only() {
        assert_eq!(
            strict_env_value("V", Ok("\t 0.0.0.0:443 \n".to_string())),
            Ok(Some("0.0.0.0:443".to_string()))
        );
        assert_eq!(
            strict_env_value("V", Ok(" /etc/propolis/tls/x.key".to_string())),
            Ok(Some("/etc/propolis/tls/x.key".to_string()))
        );
        // A no-break space is not ASCII whitespace: it is part of the value.
        assert_eq!(
            strict_env_value("V", Ok("\u{a0}".to_string())),
            Ok(Some("\u{a0}".to_string()))
        );
    }

    #[test]
    fn strict_interior_whitespace_is_kept() {
        assert_eq!(
            strict_env_value("V", Ok("a b".to_string())),
            Ok(Some("a b".to_string()))
        );
    }

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
