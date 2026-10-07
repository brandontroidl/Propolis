//! The argument allowlist. Arguments arrive two ways: the process's own argv when run locally,
//! and `SSH_ORIGINAL_COMMAND` when the watcher is an SSH forced command (sshd puts whatever the
//! client typed after the host there). Both go through [`parse`]; the SSH string is split on
//! ASCII whitespace only by [`ssh_command_tokens`], so no quoting, globbing, substitution or
//! separator has any meaning. Every token must be a known flag or a value that passes that
//! flag's own check; anything else is a usage error and the process exits 2 before reading a
//! single file. Nothing parsed here is ever handed to a shell or to journalctl.

use std::fmt;
use std::net::IpAddr;

pub const USAGE: &str = "\
usage: propolis-watch [--sensor <label>]... [--signal <type>] [--source-ip <ip>] [--journal] [--since-start]

Streams every sensor event log named in PROPOLIS_SENSOR_LOGS as JSON Lines on stdout.

  --sensor <label>   only events from this PROPOLIS_SENSOR_LOGS label (repeatable)
  --signal <type>    only events whose signal_type is <type>
  --source-ip <ip>   only events whose source_ip is <ip>
  --journal          also stream the sensor-* and propolis units' journal
  --since-start      replay each log from the start of its current file instead of its end
  --help             print this text and exit

Over SSH the same flags come from the command the client sends, split on whitespace only.";

/// What the arguments asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Watch(Options),
    Help,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Labels to keep; empty keeps every label.
    pub sensors: Vec<String>,
    pub signal: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub journal: bool,
    pub since_start: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    UnknownArgument(String),
    MissingValue(&'static str),
    InvalidValue {
        flag: &'static str,
        value: String,
    },
    Repeated(&'static str),
    /// `SSH_ORIGINAL_COMMAND` held bytes that are not UTF-8.
    NotUnicode,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArgument(a) => write!(f, "unknown argument {a:?}"),
            Self::MissingValue(flag) => write!(f, "{flag} needs a value"),
            Self::InvalidValue { flag, value } => write!(f, "invalid value {value:?} for {flag}"),
            Self::Repeated(flag) => write!(f, "{flag} may be given only once"),
            Self::NotUnicode => write!(f, "SSH_ORIGINAL_COMMAND is not valid UTF-8"),
        }
    }
}

impl std::error::Error for UsageError {}

/// Longest label or signal type accepted. Both are short identifiers in practice; the bound keeps
/// an argument from ever being large.
const MAX_NAME_LEN: usize = 64;

/// The SSH client's command, split on ASCII whitespace and nothing else.
pub fn ssh_command_tokens(raw: &str) -> Vec<String> {
    raw.split_ascii_whitespace().map(str::to_string).collect()
}

pub fn parse<I: IntoIterator<Item = String>>(tokens: I) -> Result<Request, UsageError> {
    let mut options = Options::default();
    let mut tokens = tokens.into_iter();
    while let Some(token) = tokens.next() {
        match token.as_str() {
            "--help" => return Ok(Request::Help),
            "--journal" => options.journal = true,
            "--since-start" => options.since_start = true,
            "--sensor" => {
                let value = value_for(&mut tokens, "--sensor")?;
                check_name(&value, "--sensor", is_label_byte)?;
                options.sensors.push(value);
            }
            "--signal" => {
                if options.signal.is_some() {
                    return Err(UsageError::Repeated("--signal"));
                }
                let value = value_for(&mut tokens, "--signal")?;
                check_name(&value, "--signal", is_signal_byte)?;
                options.signal = Some(value);
            }
            "--source-ip" => {
                if options.source_ip.is_some() {
                    return Err(UsageError::Repeated("--source-ip"));
                }
                let value = value_for(&mut tokens, "--source-ip")?;
                let ip = value
                    .parse::<IpAddr>()
                    .map_err(|_| UsageError::InvalidValue {
                        flag: "--source-ip",
                        value,
                    })?;
                options.source_ip = Some(ip.to_canonical());
            }
            _ => return Err(UsageError::UnknownArgument(token)),
        }
    }
    Ok(Request::Watch(options))
}

fn value_for(
    tokens: &mut impl Iterator<Item = String>,
    flag: &'static str,
) -> Result<String, UsageError> {
    tokens.next().ok_or(UsageError::MissingValue(flag))
}

fn check_name(value: &str, flag: &'static str, allowed: fn(u8) -> bool) -> Result<(), UsageError> {
    if value.is_empty() || value.len() > MAX_NAME_LEN || !value.bytes().all(allowed) {
        return Err(UsageError::InvalidValue {
            flag,
            value: value.to_string(),
        });
    }
    Ok(())
}

/// Labels as operators write them in `PROPOLIS_SENSOR_LOGS` (`ssh`, `cred-vnc`).
fn is_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
}

/// Signal types are lower snake case (`honeypot_login_attempt`).
fn is_signal_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ssh(raw: &str) -> Result<Request, UsageError> {
        parse(ssh_command_tokens(raw))
    }

    fn options(request: Result<Request, UsageError>) -> Options {
        match request {
            Ok(Request::Watch(o)) => o,
            other => panic!("expected options, got {other:?}"),
        }
    }

    #[test]
    fn no_arguments_watch_everything_from_the_end() {
        assert_eq!(options(parse(Vec::new())), Options::default());
        assert_eq!(options(parse_ssh("")), Options::default());
        assert_eq!(options(parse_ssh(" \t\n ")), Options::default());
    }

    #[test]
    fn every_allowed_flag_parses() {
        let o = options(parse_ssh(
            "--sensor ssh --sensor cred-vnc --signal honeypot_login_attempt \
             --source-ip 192.0.2.7 --journal --since-start",
        ));
        assert_eq!(o.sensors, vec!["ssh", "cred-vnc"]);
        assert_eq!(o.signal.as_deref(), Some("honeypot_login_attempt"));
        assert_eq!(o.source_ip, Some("192.0.2.7".parse().unwrap()));
        assert!(o.journal && o.since_start);
        assert_eq!(parse_ssh("--journal --help"), Ok(Request::Help));
    }

    #[test]
    fn a_mapped_ipv6_source_filter_is_canonicalized() {
        let o = options(parse_ssh("--source-ip ::ffff:192.0.2.7"));
        assert_eq!(o.source_ip, Some("192.0.2.7".parse().unwrap()));
    }

    #[test]
    fn unknown_flags_and_stray_words_are_refused() {
        for raw in [
            "--follow",
            "-s ssh",
            "--sensor=ssh",
            "--SENSOR ssh",
            "ssh",
            "--journal yes",
        ] {
            assert!(
                matches!(parse_ssh(raw), Err(UsageError::UnknownArgument(_))),
                "{raw:?} must be refused"
            );
        }
    }

    #[test]
    fn shell_syntax_in_the_ssh_command_is_refused_not_interpreted() {
        for raw in [
            "--sensor ssh; rm -rf /",
            "--sensor ssh;rm",
            "--sensor $(id)",
            "--sensor `id`",
            "--sensor ssh && id",
            "--sensor ssh | sh",
            "--sensor ssh\nrm -rf /",
            "--sensor ssh\r\nid",
            "--signal x>/tmp/f",
            "--sensor ../../etc/passwd",
            "--sensor 'ssh'",
            "--source-ip 192.0.2.7;id",
            "$(id)",
            "`id`",
        ] {
            assert!(parse_ssh(raw).is_err(), "{raw:?} must be refused");
        }
    }

    #[test]
    fn values_are_checked_by_their_own_rule() {
        assert!(matches!(
            parse_ssh("--sensor"),
            Err(UsageError::MissingValue("--sensor"))
        ));
        assert!(matches!(
            parse_ssh("--signal Honeypot"),
            Err(UsageError::InvalidValue { .. })
        ));
        assert!(matches!(
            parse_ssh("--source-ip 999.1.1.1"),
            Err(UsageError::InvalidValue { .. })
        ));
        let long = "a".repeat(MAX_NAME_LEN + 1);
        assert!(parse_ssh(&format!("--sensor {long}")).is_err());
        assert!(matches!(
            parse_ssh("--signal a --signal b"),
            Err(UsageError::Repeated("--signal"))
        ));
        assert!(matches!(
            parse_ssh("--source-ip 192.0.2.1 --source-ip 192.0.2.2"),
            Err(UsageError::Repeated("--source-ip"))
        ));
    }
}
