//! How every sensor reads its configuration: the strict env-var reader ([`strict_env_var`]), the
//! legacy-name fallback built on it ([`env_with_legacy`]), and the typed readers ([`Env`]) that turn
//! a variable into the bound, address, path, flag or table it configures.
//!
//! The typed readers are the one place a value is parsed, so every sensor refuses the same bad
//! shapes with the same message. Before them each sensor binary carried its own
//! `parse_positive_u64`/`parse_positive_u32`/`parse_wan_map`, and two of the twelve copies had
//! drifted into falling back to the default on a value they could not parse: a typo in
//! `/etc/propolis/sensor.env` silently ran the sensor with a limit other than the one written,
//! which is the failure the "zero never means unlimited" rule exists to prevent. A missing or blank
//! variable still takes its documented default; a value that is set and wrong refuses to start.
//!
//! The legacy fallback reads one env var by its canonical name, falling back to a deprecated legacy
//! spelling when the canonical name is unset. It generalizes the migration shape
//! `sensor-catchall/src/main.rs` established for its own bare `CATCHALL_*` names to a rename that
//! spans multiple binaries with DIFFERENT legacy spellings each - `COLLECTOR_ID` on every sensor,
//! `PROPOLIS_SHIPPER_COLLECTOR_ID` on `shipper` - so the legacy name cannot be derived from the
//! canonical one by a fixed prefix rule and must be passed explicitly.

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::Duration;

/// An env var held a value the reader refuses. Every variant names the variable, and every variant
/// but `NotUnicode` quotes the value, so the startup log says exactly which line of the env file to
/// fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvError {
    /// The variable was set to bytes that are not valid UTF-8.
    NotUnicode { var: String },
    /// The variable was set, but not to the shape it takes. `expected` names the shape. A bad value
    /// is never read as unset, so it never falls back to the default.
    Invalid {
        var: String,
        value: String,
        expected: &'static str,
    },
    /// A whole number past the variable's maximum.
    TooLarge {
        var: String,
        value: String,
        max: u64,
    },
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUnicode { var } => {
                write!(f, "environment variable {var} is not valid UTF-8")
            }
            Self::Invalid {
                var,
                value,
                expected,
            } => write!(f, "{var} must be {expected}, got {value:?}"),
            Self::TooLarge { var, value, max } => {
                write!(
                    f,
                    "{var} must be a positive integer at most {max}, got {value:?}"
                )
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

/// What a numeric bound must look like, named in the error when it does not.
const POSITIVE_INTEGER: &str = "a positive integer (zero never means unlimited)";

/// Where a sensor's variables come from: the process environment in production
/// ([`Env::process`]), a fixed table in tests ([`Env::from_lookup`]), so the rules below are
/// testable without mutating process-global state. Every typed reader applies the lookup's own
/// rule first (for [`strict_env_var`]: unset or blank is unset and takes the default, non-UTF-8 is
/// an error) and then refuses any value that is set but not the documented shape, naming the
/// variable and quoting the value. Nothing here ever substitutes a default for a value it could
/// not parse.
pub struct Env {
    get: Box<Lookup>,
}

/// One variable's value under [`strict_env_var`]'s contract.
type Lookup = dyn Fn(&str) -> Result<Option<String>, EnvError>;

impl Env {
    /// The process environment, read through [`strict_env_var`].
    pub fn process() -> Self {
        Self::from_lookup(strict_env_var)
    }

    /// Any lookup with [`strict_env_var`]'s contract: `Ok(None)` for unset, and the value already
    /// trimmed, so what a test hands the readers is exactly what the real reader would.
    pub fn from_lookup(get: impl Fn(&str) -> Result<Option<String>, EnvError> + 'static) -> Self {
        Self { get: Box::new(get) }
    }

    /// A fixed table of raw values, read with [`strict_env_var`]'s trim-and-blank-is-unset rule,
    /// so a test feeds the loader what an env file would.
    pub fn from_table(pairs: &[(&str, &str)]) -> Self {
        let table: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self::from_lookup(move |var| {
            let raw = table.get(var).cloned().ok_or(env::VarError::NotPresent);
            strict_env_value(var, raw)
        })
    }

    /// The raw value, or `None` when unset.
    pub fn string(&self, var: &str) -> Result<Option<String>, EnvError> {
        (self.get)(var)
    }

    /// A filesystem path, `default` when unset. Any non-blank string is a path.
    pub fn path(&self, var: &str, default: &str) -> Result<PathBuf, EnvError> {
        Ok(self
            .string(var)?
            .map_or_else(|| PathBuf::from(default), PathBuf::from))
    }

    /// A positive whole number, `default` when unset. Zero, a sign, a fraction, text or a number
    /// past `u64` is an error: a bound can never be configured off or made nonsense.
    pub fn positive_u64(&self, var: &str, default: u64) -> Result<u64, EnvError> {
        let Some(raw) = self.string(var)? else {
            return Ok(default);
        };
        // Digits only: `u64::from_str` would also take a leading `+`, which no env file means.
        let digits = raw.bytes().all(|b| b.is_ascii_digit());
        match raw.parse::<u64>() {
            Ok(value) if digits && value > 0 => Ok(value),
            _ => Err(EnvError::Invalid {
                var: var.to_string(),
                value: raw,
                expected: POSITIVE_INTEGER,
            }),
        }
    }

    /// [`Self::positive_u64`] with a documented maximum: a value above `max` is an error, never
    /// clamped, so the operator learns the ceiling instead of running under a silently lower one.
    pub fn positive_u64_at_most(&self, var: &str, default: u64, max: u64) -> Result<u64, EnvError> {
        let value = self.positive_u64(var, default)?;
        if value > max {
            return Err(EnvError::TooLarge {
                var: var.to_string(),
                value: value.to_string(),
                max,
            });
        }
        Ok(value)
    }

    /// A positive whole number that fits a `u32` (a concurrency limit, a rate), `default` when
    /// unset. The type carries the guarantee: a caller that needs a plain `u32` takes `.get()`.
    pub fn positive_u32(&self, var: &str, default: u32) -> Result<NonZeroU32, EnvError> {
        let value = self.positive_u64_at_most(var, u64::from(default), u64::from(u32::MAX))?;
        Ok(u32::try_from(value)
            .ok()
            .and_then(NonZeroU32::new)
            .expect("positive_u64_at_most refused 0 and > u32::MAX"))
    }

    /// A positive number of milliseconds as a [`Duration`], `default_ms` when unset.
    pub fn duration_ms(&self, var: &str, default_ms: u64) -> Result<Duration, EnvError> {
        Ok(Duration::from_millis(self.positive_u64(var, default_ms)?))
    }

    /// A positive number of seconds as a [`Duration`], `default_secs` when unset.
    pub fn duration_secs(&self, var: &str, default_secs: u64) -> Result<Duration, EnvError> {
        Ok(Duration::from_secs(self.positive_u64(var, default_secs)?))
    }

    /// An `ip:port` socket address, `None` when unset. There is no default: a bind address is
    /// either written by the operator or absent, and the caller decides whether absent is "this
    /// listener is off" or "the sensor cannot start".
    pub fn socket_addr(&self, var: &str) -> Result<Option<SocketAddr>, EnvError> {
        self.string(var)?
            .map(|raw| {
                raw.parse::<SocketAddr>().map_err(|_| EnvError::Invalid {
                    var: var.to_string(),
                    value: raw,
                    expected: "an ip:port socket address",
                })
            })
            .transpose()
    }

    /// `true` or `false` (any case), `default` when unset. `1`, `yes` and `on` are errors rather
    /// than guesses: a flag that turns a guard off must be spelled out.
    pub fn bool(&self, var: &str, default: bool) -> Result<bool, EnvError> {
        let Some(raw) = self.string(var)? else {
            return Ok(default);
        };
        match raw.to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(EnvError::Invalid {
                var: var.to_string(),
                value: raw,
                expected: "true or false",
            }),
        }
    }

    /// The comma-separated `local_ip=wan_ip` table a sensor attributes connections with. Unset is
    /// the valid empty map (no WAN attribution, the wire contract's `null` `wan_ip`). An entry that
    /// is not two IP addresses around `=` is an error naming that entry: a skipped entry would
    /// silently mis-attribute every connection on that interface.
    pub fn wan_map(&self, var: &str) -> Result<HashMap<IpAddr, IpAddr>, EnvError> {
        let mut map = HashMap::new();
        let raw = self.string(var)?.unwrap_or_default();
        for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let bad = || EnvError::Invalid {
                var: var.to_string(),
                value: entry.to_string(),
                expected: "comma-separated local_ip=wan_ip entries",
            };
            let (local, wan) = entry.split_once('=').ok_or_else(bad)?;
            let local: IpAddr = local.trim().parse().map_err(|_| bad())?;
            let wan: IpAddr = wan.trim().parse().map_err(|_| bad())?;
            map.insert(local, wan);
        }
        Ok(map)
    }
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

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env::from_table(pairs)
    }

    #[test]
    fn a_table_applies_the_strict_readers_trim_and_blank_rule() {
        let e = env(&[("A", " x "), ("B", " \t")]);
        assert_eq!(e.string("A"), Ok(Some("x".to_string())));
        assert_eq!(e.string("B"), Ok(None));
        assert_eq!(e.string("C"), Ok(None));
    }

    fn invalid(var: &str, value: &str, expected: &'static str) -> EnvError {
        EnvError::Invalid {
            var: var.to_string(),
            value: value.to_string(),
            expected,
        }
    }

    // Not `PROPOLIS_*`: the docs gate takes every such literal for a variable to document.
    const V: &str = "SENSOR_TEST_VALUE";

    #[test]
    fn a_lookup_error_reaches_the_caller_unchanged() {
        let env = Env::from_lookup(|var| {
            Err(EnvError::NotUnicode {
                var: var.to_string(),
            })
        });
        let not_unicode = EnvError::NotUnicode { var: V.to_string() };
        assert_eq!(env.string(V), Err(not_unicode));
        assert!(matches!(
            env.path(V, "/d"),
            Err(EnvError::NotUnicode { .. })
        ));
        assert!(matches!(
            env.positive_u64(V, 1),
            Err(EnvError::NotUnicode { .. })
        ));
        assert!(matches!(
            env.positive_u32(V, 1),
            Err(EnvError::NotUnicode { .. })
        ));
        assert!(matches!(
            env.socket_addr(V),
            Err(EnvError::NotUnicode { .. })
        ));
        assert!(matches!(
            env.bool(V, false),
            Err(EnvError::NotUnicode { .. })
        ));
        assert!(matches!(env.wan_map(V), Err(EnvError::NotUnicode { .. })));
    }

    #[test]
    fn unset_or_blank_takes_the_default() {
        for e in [env(&[]), env(&[(V, "  \t")])] {
            assert_eq!(e.string(V), Ok(None));
            assert_eq!(e.path(V, "/var/log/x"), Ok(PathBuf::from("/var/log/x")));
            assert_eq!(e.positive_u64(V, 42), Ok(42));
            assert_eq!(e.positive_u64_at_most(V, 42, 100), Ok(42));
            assert_eq!(e.positive_u32(V, 7).map(NonZeroU32::get), Ok(7));
            assert_eq!(e.duration_ms(V, 30_000), Ok(Duration::from_millis(30_000)));
            assert_eq!(e.duration_secs(V, 600), Ok(Duration::from_secs(600)));
            assert_eq!(e.socket_addr(V), Ok(None));
            assert_eq!(e.bool(V, true), Ok(true));
            assert_eq!(e.bool(V, false), Ok(false));
            assert!(e.wan_map(V).unwrap().is_empty());
        }
    }

    #[test]
    fn positive_integers_accept_the_good_shapes() {
        assert_eq!(env(&[(V, "1")]).positive_u64(V, 42), Ok(1));
        assert_eq!(env(&[(V, " 100 ")]).positive_u64(V, 42), Ok(100));
        assert_eq!(
            env(&[(V, "18446744073709551615")]).positive_u64(V, 42),
            Ok(u64::MAX)
        );
        assert_eq!(env(&[(V, "100")]).positive_u64_at_most(V, 42, 100), Ok(100));
        assert_eq!(
            env(&[(V, "4294967295")])
                .positive_u32(V, 7)
                .map(NonZeroU32::get),
            Ok(u32::MAX)
        );
        assert_eq!(
            env(&[(V, "250")]).duration_ms(V, 1),
            Ok(Duration::from_millis(250))
        );
        assert_eq!(
            env(&[(V, "250")]).duration_secs(V, 1),
            Ok(Duration::from_secs(250))
        );
    }

    #[test]
    fn positive_integers_reject_zero_signs_fractions_text_and_overflow() {
        for bad in [
            "0",
            "-1",
            "-0",
            "+5",
            "1.5",
            "ten",
            "10ms",
            "0x10",
            "1_000",
            "18446744073709551616",
        ] {
            let e = env(&[(V, bad)]);
            let want = invalid(V, bad.trim(), POSITIVE_INTEGER);
            assert_eq!(e.positive_u64(V, 42), Err(want.clone()), "{bad:?}");
            assert_eq!(
                e.positive_u64_at_most(V, 42, 100),
                Err(want.clone()),
                "{bad:?}"
            );
            assert_eq!(e.positive_u32(V, 7), Err(want.clone()), "{bad:?}");
            assert_eq!(e.duration_ms(V, 42), Err(want.clone()), "{bad:?}");
            assert_eq!(e.duration_secs(V, 42), Err(want), "{bad:?}");
        }
    }

    #[test]
    fn a_number_past_the_maximum_is_an_error_naming_the_maximum_never_a_clamp() {
        assert_eq!(
            env(&[(V, "101")]).positive_u64_at_most(V, 42, 100),
            Err(EnvError::TooLarge {
                var: V.to_string(),
                value: "101".to_string(),
                max: 100
            })
        );
        let err = env(&[(V, "4294967296")]).positive_u32(V, 7).unwrap_err();
        assert_eq!(
            err,
            EnvError::TooLarge {
                var: V.to_string(),
                value: "4294967296".to_string(),
                max: u64::from(u32::MAX)
            }
        );
        let text = err.to_string();
        assert!(
            text.contains(V) && text.contains("positive integer") && text.contains("4294967295"),
            "{text}"
        );
    }

    #[test]
    fn a_socket_address_is_ip_and_port_or_an_error() {
        assert_eq!(
            env(&[(V, "0.0.0.0:2222")]).socket_addr(V),
            Ok(Some("0.0.0.0:2222".parse().unwrap()))
        );
        assert_eq!(
            env(&[(V, "[::]:53")]).socket_addr(V),
            Ok(Some("[::]:53".parse().unwrap()))
        );
        for bad in [
            "2222",
            "0.0.0.0",
            "x:53",
            "203.0.113.7:99999",
            "localhost:22",
        ] {
            assert_eq!(
                env(&[(V, bad)]).socket_addr(V),
                Err(invalid(V, bad, "an ip:port socket address")),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_flag_is_true_or_false_in_any_case_and_nothing_else() {
        for (raw, want) in [("true", true), ("TRUE", true), ("False", false)] {
            assert_eq!(env(&[(V, raw)]).bool(V, !want), Ok(want), "{raw:?}");
        }
        for bad in ["1", "0", "yes", "no", "on", "off", "t"] {
            assert_eq!(
                env(&[(V, bad)]).bool(V, false),
                Err(invalid(V, bad, "true or false")),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_wan_map_parses_entries_and_names_the_entry_it_refuses() {
        let map = env(&[(V, "10.0.0.1=198.51.100.4, 10.0.0.2 = 198.51.100.5,")])
            .wan_map(V)
            .unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get(&"10.0.0.1".parse::<IpAddr>().unwrap()),
            Some(&"198.51.100.4".parse::<IpAddr>().unwrap())
        );
        for (raw, entry) in [
            ("not-valid", "not-valid"),
            ("10.0.0.1=", "10.0.0.1="),
            ("x=198.51.100.4", "x=198.51.100.4"),
            ("10.0.0.1=198.51.100.4,also=not=valid", "also=not=valid"),
        ] {
            assert_eq!(
                env(&[(V, raw)]).wan_map(V),
                Err(invalid(V, entry, "comma-separated local_ip=wan_ip entries")),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn every_refusal_names_the_variable_and_quotes_the_value() {
        let errors = [
            env(&[(V, "ten")]).positive_u64(V, 1).unwrap_err(),
            env(&[(V, "99")]).positive_u64_at_most(V, 1, 9).unwrap_err(),
            env(&[(V, "nope")]).socket_addr(V).unwrap_err(),
            env(&[(V, "yes")]).bool(V, false).unwrap_err(),
            env(&[(V, "a=b")]).wan_map(V).unwrap_err(),
        ];
        for (err, value) in errors.iter().zip(["ten", "99", "nope", "yes", "a=b"]) {
            let text = err.to_string();
            assert!(
                text.contains(V) && text.contains(&format!("{value:?}")),
                "{text}"
            );
        }
    }
}
