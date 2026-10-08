//! Toybox's command-line option checking, for the applets the Android shell models: which words
//! it refuses before the applet runs, and the exact line it prints for each.
//!
//! The persona announces Android 6.0.1, whose toybox (`external/toybox`, tag `android-6.0.1_r81`)
//! parses every applet's arguments with `get_optflags` in `lib/args.c` from a per-applet option
//! string. The refusals here are ported from that file, not from GNU, whose wording the shared
//! text tools print. Only the refusals are ported: an accepted option is left to the applet's own
//! handler, and an option string group that only constrains a value (`[-cn]`, `[+cC]`, the `|`
//! "needs one of" flag) is not checked.
//!
//! Every message is `<applet>: <text>` on standard error with status 1, the `error_exit` of
//! `lib/lib.c#verror_msg`.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

/// The option string `NEWTOY` gives `applet` in toybox 6.0.1, for the applets this shell checks.
/// `sha256sum` is not in that release (see `multicall.rs`); it takes `sha1sum`'s.
fn optstring(applet: &str) -> Option<&'static str> {
    Some(match applet {
        "wc" => "mcwl",
        "base64" => "diw#<1[!dw]",
        "md5sum" | "sha1sum" | "sha256sum" => "b",
        "which" => "<1a",
        "cut" => "b:|c:|f:|d:sn[!cbf]",
        "tr" => "^>2<1Ccsd[+cC]",
        "od" => "j#vN#xsodcbA:t*",
        _ => return None,
    })
}

/// One option of an option string.
struct Opt {
    letter: char,
    /// The value type character (`:`, `*`, `#`, ...), when the option takes a value.
    kind: Option<char>,
    low: Option<i64>,
}

struct Spec {
    opts: Vec<Opt>,
    /// `^`: the first operand ends the options.
    stop_early: bool,
    min_args: usize,
    max_args: usize,
    /// `[!xy]` groups: options that may not be given together.
    exclusive: Vec<Vec<char>>,
}

fn digit(text: &str, at: usize) -> Option<usize> {
    text.get(at..)?
        .chars()
        .next()
        .and_then(|c| c.to_digit(10))
        .and_then(|d| usize::try_from(d).ok())
}

fn parse_spec(text: &str) -> Spec {
    let mut spec = Spec {
        opts: Vec::new(),
        stop_early: false,
        min_args: 0,
        max_args: usize::MAX,
        exclusive: Vec::new(),
    };
    let chars: Vec<char> = text.chars().collect();
    let mut at = 0usize;
    // Leading behavior flags, before the first option letter.
    while let Some(&c) = chars.get(at) {
        match c {
            '^' => spec.stop_early = true,
            '<' => {
                at = at.saturating_add(1);
                spec.min_args = digit(text, at).unwrap_or(0);
            }
            '>' => {
                at = at.saturating_add(1);
                spec.max_args = digit(text, at).unwrap_or(0);
            }
            _ => break,
        }
        at = at.saturating_add(1);
    }
    while let Some(&c) = chars.get(at) {
        match c {
            '[' => {
                let rest: String = chars.iter().skip(at.saturating_add(1)).collect();
                let Some(close) = rest.find(']') else { break };
                let group = rest.get(..close).unwrap_or("");
                if let Some(members) = group.strip_prefix('!') {
                    spec.exclusive.push(members.chars().collect());
                }
                at = at.saturating_add(close).saturating_add(2);
                continue;
            }
            ':' | '*' | '#' | '@' | '.' | '-' => {
                if let Some(last) = spec.opts.last_mut() {
                    last.kind = Some(c);
                }
            }
            '<' => {
                // A lower bound on the value of the option before it.
                at = at.saturating_add(1);
                let mut end = at;
                while chars.get(end).is_some_and(|d| d.is_ascii_digit()) {
                    end = end.saturating_add(1);
                }
                let number: String = chars.iter().skip(at).take(end.saturating_sub(at)).collect();
                if let Some(last) = spec.opts.last_mut() {
                    last.low = number.parse().ok();
                }
                at = end;
                continue;
            }
            '|' | ' ' | ';' => {}
            letter => spec.opts.push(Opt {
                letter,
                kind: None,
                low: None,
            }),
        }
        at = at.saturating_add(1);
    }
    spec
}

/// `atolx`'s verdict on a numeric option value: the number, or `None` when it is not an integer.
/// The size suffixes (`k`, `m`, ...) scale but never invalidate.
fn atolx(text: &str) -> Option<i64> {
    let trimmed = text.trim_start();
    let (sign, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let digits: String = body.chars().take_while(char::is_ascii_digit).collect();
    let rest = body.get(digits.len()..).unwrap_or("");
    let value: i64 = digits.parse().ok()?;
    let scaled = match rest.chars().next() {
        None => Some(value),
        Some(c) if "cbkmgtpe".contains(c.to_ascii_lowercase()) => Some(value),
        Some(_) if rest.trim().is_empty() => Some(value),
        Some(_) => None,
    };
    scaled.map(|v| v.saturating_mul(sign))
}

/// The refusal toybox prints for `args` given to `applet`, or `None` when the arguments parse
/// (or the applet is not one this module checks).
pub(super) fn check(applet: &str, args: &[&str]) -> Option<String> {
    let spec = parse_spec(optstring(applet)?);
    let fail = |text: String| Some(format!("{applet}: {text}\n"));
    let mut given: Vec<char> = Vec::new();
    let mut operands = 0usize;
    let mut stopped = false;
    let mut at = 0usize;
    while let Some(&arg) = args.get(at) {
        at = at.saturating_add(1);
        let flags = arg.strip_prefix('-').filter(|rest| !rest.is_empty());
        let Some(cluster) = flags.filter(|_| !stopped) else {
            operands = operands.saturating_add(1);
            stopped |= spec.stop_early;
            continue;
        };
        if let Some(long) = cluster.strip_prefix('-') {
            if long.is_empty() {
                stopped = true;
                continue;
            }
            return fail(format!("Unknown option {long}"));
        }
        let mut rest = cluster;
        while let Some(letter) = rest.chars().next() {
            let Some(opt) = spec.opts.iter().find(|o| o.letter == letter) else {
                return fail(format!("Unknown option {rest}"));
            };
            rest = rest.get(letter.len_utf8()..).unwrap_or("");
            given.push(letter);
            if let Some(group) = spec.exclusive.iter().find(|g| {
                g.contains(&letter) && g.iter().any(|m| *m != letter && given.contains(m))
            }) && let Some(other) = group.iter().find(|m| **m != letter && given.contains(m))
            {
                return fail(format!("No '{letter}' with '{other}'"));
            }
            let Some(kind) = opt.kind else { continue };
            let value = if rest.is_empty() {
                let Some(&next) = args.get(at) else {
                    return fail(format!("Missing argument to -{letter}"));
                };
                at = at.saturating_add(1);
                next
            } else {
                rest
            };
            rest = "";
            if kind == '#' {
                let Some(number) = atolx(value) else {
                    return fail(format!("not integer: {value}"));
                };
                if let Some(low) = opt.low
                    && number < low
                {
                    return fail(format!("-{letter} < {low}"));
                }
            }
        }
    }
    // `Need%s %d argument%s`, with the release's own plural quirk: "Needs 1 argument",
    // "Need 2 arguments".
    if operands < spec.min_args {
        let (verb, plural) = if spec.min_args == 1 {
            ("Needs", "")
        } else {
            ("Need", "s")
        };
        return fail(format!("{verb} {} argument{plural}", spec.min_args));
    }
    if operands > spec.max_args {
        let plural = if spec.max_args == 1 { "" } else { "s" };
        return fail(format!("Max {} argument{plural}", spec.max_args));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_short_option_names_the_rest_of_its_cluster() {
        assert_eq!(
            check("wc", &["-z"]).as_deref(),
            Some("wc: Unknown option z\n")
        );
        // `gof->arg` still points at the unknown letter and everything after it.
        assert_eq!(
            check("wc", &["-czl"]).as_deref(),
            Some("wc: Unknown option zl\n")
        );
        assert_eq!(check("wc", &["-clw", "f"]), None);
    }

    #[test]
    fn a_long_option_that_is_not_registered_is_refused_without_its_dashes() {
        assert_eq!(
            check("base64", &["--decode"]).as_deref(),
            Some("base64: Unknown option decode\n")
        );
    }

    #[test]
    fn a_value_option_takes_the_rest_of_the_word_or_the_next_one() {
        assert_eq!(check("base64", &["-w76"]), None);
        assert_eq!(check("base64", &["-w", "76"]), None);
        assert_eq!(
            check("base64", &["-w"]).as_deref(),
            Some("base64: Missing argument to -w\n")
        );
        assert_eq!(
            check("base64", &["-w", "x"]).as_deref(),
            Some("base64: not integer: x\n")
        );
        assert_eq!(
            check("base64", &["-w", "0"]).as_deref(),
            Some("base64: -w < 1\n")
        );
    }

    #[test]
    fn decode_and_wrap_exclude_each_other() {
        assert_eq!(
            check("base64", &["-d", "-w", "5"]).as_deref(),
            Some("base64: No 'w' with 'd'\n")
        );
        assert_eq!(
            check("base64", &["-w5", "-d"]).as_deref(),
            Some("base64: No 'd' with 'w'\n")
        );
        assert_eq!(check("base64", &["-di"]), None);
    }

    #[test]
    fn operand_counts_use_the_releases_plural_quirk() {
        assert_eq!(
            check("which", &[]).as_deref(),
            Some("which: Needs 1 argument\n")
        );
        assert_eq!(check("which", &["-a", "sh"]), None);
        assert_eq!(check("tr", &[]).as_deref(), Some("tr: Needs 1 argument\n"));
        assert_eq!(
            check("tr", &["a", "b", "c"]).as_deref(),
            Some("tr: Max 2 arguments\n")
        );
    }

    #[test]
    fn a_double_dash_and_a_lone_dash_are_operands_not_options() {
        assert_eq!(check("md5sum", &["--", "-z"]), None);
        assert_eq!(check("md5sum", &["-"]), None);
        assert_eq!(
            check("md5sum", &["-z"]).as_deref(),
            Some("md5sum: Unknown option z\n")
        );
    }

    #[test]
    fn the_first_operand_ends_the_options_where_the_string_says_so() {
        // `tr` is `^`: what follows the first operand is data, not flags.
        assert_eq!(check("tr", &["-d", "a", "-z"]), None);
        // `wc` has no `^`: a later flag is still a flag.
        assert_eq!(
            check("wc", &["f", "-z"]).as_deref(),
            Some("wc: Unknown option z\n")
        );
    }

    #[test]
    fn an_applet_with_no_option_string_is_not_checked() {
        assert_eq!(check("ls", &["--nonsense"]), None);
    }
}
