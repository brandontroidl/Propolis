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
        "getprop" => ">2",
        "setprop" => "<2>2",
        "ifconfig" => "^?a",
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
    /// `?`: an option the string does not name is an operand, not an error.
    noerror: bool,
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
        noerror: false,
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
            '?' => spec.noerror = true,
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
    // An option string with no letters makes the first operand end the options (`args.c`).
    if spec.opts.is_empty() {
        spec.stop_early = true;
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

/// `help_<applet>` of `generated/help.h` at tag `android-6.0.1_r81`, which `show_help` writes to
/// standard error ahead of an option-parsing refusal. Source-verified (`lib/args.c#get_optflags`
/// sets `toys.exithelp`; `lib/lib.c#error_exit` calls `show_help` when
/// `CFG_TOYBOX_HELP` of `generated/config.h` is 1), not captured from a device. `sha256sum` is no
/// applet of that release; it gets `sha1sum`'s text with its name [unverified].
pub(super) fn help_text(applet: &str) -> String {
    let text = match applet {
        "setprop" => "usage: setprop NAME VALUE\n\nSets an Android system property.\n\n",
        "getprop" => {
            "usage: getprop [NAME [DEFAULT]]\n\nGets an Android system property, or lists them all.\n\n"
        }
        "sha1sum" | "sha256sum" => {
            "usage: sha1sum [FILE]...\n\ncalculate sha1 hash for each input file, reading from stdin if none.\nOutput one hash (20 hex digits) for each input file, followed by\nfilename.\n\n-b\tbrief (hash only, no filename)\n\n"
        }
        "md5sum" => {
            "usage: md5sum [FILE]...\n\nCalculate md5 hash for each input file, reading from stdin if none.\nOutput one hash (16 hex digits) for each input file, followed by\nfilename.\n\n-b\tbrief (hash only, no filename)\n\n"
        }
        "which" => {
            "usage: which [-a] filename ...\n\nSearch $PATH for executable files matching filename(s).\n\n-a\tShow all matches\n\n"
        }
        "base64" => {
            "usage: base64 [-di] [-w COLUMNS] [FILE...]\n\nEncode or decode in base64.\n\n-d\tdecode\n-i\tignore non-alphabetic characters\n-w\twrap output at COLUMNS (default 76)\n\n"
        }
        "tr" => {
            "usage: tr [-cds] SET1 [SET2]\n\nTranslate, squeeze, or delete characters from stdin, writing to stdout\n\n-c/-C  Take complement of SET1\n-d     Delete input characters coded SET1\n-s     Squeeze multiple output characters of SET2 into one character\n\n"
        }
        "wc" => {
            "usage: wc -lwcm [FILE...]\n\nCount lines, words, and characters in input.\n\n-l\tshow lines\n-w\tshow words\n-c\tshow bytes\n-m\tshow characters\n\nBy default outputs lines, words, bytes, and filename for each\nargument (or from stdin if none). Displays only either bytes\nor characters.\n\n"
        }
        "od" => {
            "usage: od [-bcdosxv] [-j #] [-N #] [-A doxn] [-t acdfoux[#]]\n\n-A\tAddress base (decimal, octal, hexdecimal, none)\n-j\tSkip this many bytes of input\n-N\tStop dumping after this many bytes\n-t\toutput type a(scii) c(har) d(ecimal) f(loat) o(ctal) u(nsigned) (he)x\n\tplus optional size in bytes\n\taliases: -b=-t o1, -c=-t c, -d=-t u2, -o=-t o2, -s=-t d2, -x=-t x2\n-v\tDon't collapse repeated lines together\n\n"
        }
        "cut" => {
            "usage: cut OPTION... [FILE]...\n\nPrint selected parts of lines from each FILE to standard output.\n\n-b LIST\tselect only these bytes from LIST.\n-c LIST\tselect only these characters from LIST.\n-f LIST\tselect only these fields.\n-d DELIM\tuse DELIM instead of TAB for field delimiter.\n-s\tdo not print lines not containing delimiters.\n-n\tdon't split multibyte characters (Ignored).\n\n"
        }
        _ => return String::new(),
    };
    if applet == "sha256sum" {
        text.replace("sha1", "sha256")
    } else {
        text.to_string()
    }
}

/// The refusal toybox prints for `args` given to `applet`, or `None` when the arguments parse
/// (or the applet is not one this module checks).
pub(super) fn check(applet: &str, args: &[&str]) -> Option<String> {
    let spec = parse_spec(optstring(applet)?);
    // `get_optflags` raises `toys.exithelp` before it parses, so `error_exit` calls `show_help`
    // and the applet's help text precedes every refusal below.
    let help = help_text(applet);
    let fail = |text: String| Some(format!("{help}{applet}: {text}\n"));
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
            if spec.noerror {
                operands = operands.saturating_add(1);
                stopped |= spec.stop_early;
                continue;
            }
            return fail(format!("Unknown option {long}"));
        }
        let mut rest = cluster;
        while let Some(letter) = rest.chars().next() {
            let Some(opt) = spec.opts.iter().find(|o| o.letter == letter) else {
                if spec.noerror {
                    operands = operands.saturating_add(1);
                    stopped |= spec.stop_early;
                    break;
                }
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

    /// The refusal line alone: the tests below are about which refusal, and
    /// `a_refusal_is_preceded_by_the_applets_help_text` pins the help that precedes it.
    fn check(applet: &str, args: &[&str]) -> Option<String> {
        let full = super::check(applet, args)?;
        let help = help_text(applet);
        Some(full.strip_prefix(&help).unwrap_or(&full).to_string())
    }

    #[test]
    fn a_refusal_is_preceded_by_the_applets_help_text() {
        // `help_tr` and `help_wc` of `generated/help.h`, tag `android-6.0.1_r81`.
        assert_eq!(
            super::check("tr", &[]).as_deref(),
            Some(
                "usage: tr [-cds] SET1 [SET2]\n\nTranslate, squeeze, or delete characters from stdin, writing to stdout\n\n-c/-C  Take complement of SET1\n-d     Delete input characters coded SET1\n-s     Squeeze multiple output characters of SET2 into one character\n\ntr: Needs 1 argument\n"
            )
        );
        for applet in [
            "tr", "wc", "base64", "md5sum", "sha1sum", "cut", "od", "which",
        ] {
            let full = super::check(applet, &["-@"]).unwrap_or_default();
            assert!(
                full.starts_with(&format!("usage: {applet}")),
                "{applet}: {full:?}"
            );
            assert!(
                full.ends_with(&format!("{applet}: Unknown option @\n")),
                "{applet}"
            );
        }
        // An argument list that parses prints nothing, help included.
        assert_eq!(super::check("tr", &["a", "b"]), None);
    }

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
    fn a_question_mark_makes_an_unknown_option_an_operand() {
        // `ifconfig` is `^?a`: `-z` is an interface name, and `-a` is still a flag.
        assert_eq!(check("ifconfig", &["-z"]), None);
        assert_eq!(check("ifconfig", &["--zz", "-a"]), None);
        assert_eq!(check("ifconfig", &["-a", "wlan0", "-q"]), None);
        // Without the `?`, the same word is refused.
        assert_eq!(
            check("wc", &["-z"]).as_deref(),
            Some("wc: Unknown option z\n")
        );
    }

    #[test]
    fn an_option_string_with_no_letters_ends_the_options_at_the_first_operand() {
        // `getprop` is `>2`: a dash first is an unknown option, a dash after a name is data.
        assert_eq!(
            check("getprop", &["-x"]).as_deref(),
            Some("getprop: Unknown option x\n")
        );
        assert_eq!(check("getprop", &["name", "-x"]), None);
        assert_eq!(
            check("setprop", &["a"]).as_deref(),
            Some("setprop: Need 2 arguments\n")
        );
    }

    #[test]
    fn an_applet_with_no_option_string_is_not_checked() {
        assert_eq!(check("ls", &["--nonsense"]), None);
    }
}
