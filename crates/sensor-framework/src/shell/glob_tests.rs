//! The glob matcher: it answers exactly as the two backtracking matchers it replaced did (kept
//! here, verbatim, as the reference), its steps grow linearly with the text for a pattern of
//! plain text and stars, and a shell line pays for every step.

use super::glob::Glob;
use super::{BudgetHit, CommandResult, EmitContext, FakeShell, OutputFd};
use crate::budget::{BudgetLimits, ConnectionBudget};
use crate::fakefs::FakeFs;

/// The matchers this module replaced, copied unchanged from `expand.rs` and `fileinfo.rs` at
/// 5560201b: the reference the new one must agree with.
mod reference {
    pub(super) enum GlobToken {
        Literal(char),
        Any,
        Star,
        Class {
            negated: bool,
            ranges: Vec<(char, char)>,
        },
    }

    pub(super) fn compile_glob(segment: &[(char, bool)]) -> Vec<GlobToken> {
        let mut tokens = Vec::new();
        let mut i = 0;
        while let Some(&(c, quoted)) = segment.get(i) {
            i = i.saturating_add(1);
            if quoted {
                tokens.push(GlobToken::Literal(c));
                continue;
            }
            match c {
                '*' => tokens.push(GlobToken::Star),
                '?' => tokens.push(GlobToken::Any),
                '[' => match parse_class(segment, i) {
                    Some((token, next)) => {
                        tokens.push(token);
                        i = next;
                    }
                    None => tokens.push(GlobToken::Literal('[')),
                },
                other => tokens.push(GlobToken::Literal(other)),
            }
        }
        tokens
    }

    fn parse_class(segment: &[(char, bool)], start: usize) -> Option<(GlobToken, usize)> {
        let mut i = start;
        let negated = matches!(segment.get(i), Some(('!' | '^', false)));
        if negated {
            i = i.saturating_add(1);
        }
        let mut chars: Vec<char> = Vec::new();
        let mut first = true;
        loop {
            let &(c, quoted) = segment.get(i)?;
            i = i.saturating_add(1);
            if c == ']' && !quoted && !first {
                break;
            }
            chars.push(c);
            first = false;
        }
        let mut ranges = Vec::new();
        let mut k = 0;
        while let Some(&low) = chars.get(k) {
            if chars.get(k.saturating_add(1)) == Some(&'-')
                && let Some(&high) = chars.get(k.saturating_add(2))
            {
                ranges.push((low, high));
                k = k.saturating_add(3);
            } else {
                ranges.push((low, low));
                k = k.saturating_add(1);
            }
        }
        Some((GlobToken::Class { negated, ranges }, i))
    }

    pub(super) fn glob_match(pattern: &[GlobToken], name: &[char]) -> bool {
        let (mut p, mut n) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        loop {
            match pattern.get(p) {
                Some(GlobToken::Star) => {
                    star = Some((p, n));
                    p = p.saturating_add(1);
                    continue;
                }
                Some(token) if n < name.len() => {
                    let c = name.get(n).copied().unwrap_or('\0');
                    let hit = match token {
                        GlobToken::Literal(l) => *l == c,
                        GlobToken::Any => true,
                        GlobToken::Class { negated, ranges } => {
                            ranges.iter().any(|(low, high)| *low <= c && c <= *high) != *negated
                        }
                        GlobToken::Star => false,
                    };
                    if hit {
                        p = p.saturating_add(1);
                        n = n.saturating_add(1);
                        continue;
                    }
                }
                None if n == name.len() => return true,
                _ => {}
            }
            match star {
                Some((star_p, star_n)) if star_n < name.len() => {
                    star = Some((star_p, star_n.saturating_add(1)));
                    p = star_p.saturating_add(1);
                    n = star_n.saturating_add(1);
                }
                _ => return false,
            }
        }
    }

    pub(super) fn fnmatch(pat: &str, text: &str, fold: bool) -> bool {
        let pat: Vec<char> = pat.chars().collect();
        let text: Vec<char> = text.chars().collect();
        let same = |a: char, b: char| {
            if fold {
                a.eq_ignore_ascii_case(&b)
            } else {
                a == b
            }
        };
        let class = |at: usize, ch: char| -> Option<(bool, usize)> {
            let mut i = at.saturating_add(1);
            let negate = matches!(pat.get(i), Some('!' | '^'));
            if negate {
                i = i.saturating_add(1);
            }
            let mut hit = false;
            let mut first = true;
            loop {
                let lo = *pat.get(i)?;
                if lo == ']' && !first {
                    return Some((hit != negate, i.saturating_add(1)));
                }
                first = false;
                let dash = pat.get(i.saturating_add(1)) == Some(&'-');
                match pat.get(i.saturating_add(2)) {
                    Some(&hi) if dash && hi != ']' => {
                        let (lo_c, hi_c, c) = if fold {
                            (
                                lo.to_ascii_lowercase(),
                                hi.to_ascii_lowercase(),
                                ch.to_ascii_lowercase(),
                            )
                        } else {
                            (lo, hi, ch)
                        };
                        hit |= (lo_c..=hi_c).contains(&c);
                        i = i.saturating_add(3);
                    }
                    _ => {
                        hit |= same(lo, ch);
                        i = i.saturating_add(1);
                    }
                }
            }
        };
        let step = |p: usize, ch: char| -> Option<usize> {
            match *pat.get(p)? {
                '?' => Some(p.saturating_add(1)),
                '[' => match class(p, ch) {
                    Some((true, next)) => Some(next),
                    Some((false, _)) => None,
                    None => same('[', ch).then_some(p.saturating_add(1)),
                },
                '\\' => match pat.get(p.saturating_add(1)) {
                    Some(&quoted) => same(quoted, ch).then_some(p.saturating_add(2)),
                    None => same('\\', ch).then_some(p.saturating_add(1)),
                },
                literal => same(literal, ch).then_some(p.saturating_add(1)),
            }
        };
        let (mut p, mut t) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        while let Some(&ch) = text.get(t) {
            if pat.get(p) == Some(&'*') {
                star = Some((p, t));
                p = p.saturating_add(1);
                continue;
            }
            if let Some(next) = step(p, ch) {
                p = next;
                t = t.saturating_add(1);
                continue;
            }
            let Some((star_p, star_t)) = star else {
                return false;
            };
            p = star_p.saturating_add(1);
            t = star_t.saturating_add(1);
            star = Some((star_p, t));
        }
        while pat.get(p) == Some(&'*') {
            p = p.saturating_add(1);
        }
        p >= pat.len()
    }
}

fn unquoted(text: &str) -> Vec<(char, bool)> {
    text.chars().map(|c| (c, false)).collect()
}

/// The new matcher with no limit on its steps.
fn hit(glob: &Glob, text: &str) -> bool {
    glob.matches_within(text, u64::MAX).0.unwrap()
}

fn matches(pattern: &str, name: &str) -> bool {
    hit(&Glob::shell(&unquoted(pattern)), name)
}

fn steps(glob: &Glob, text: &str) -> u64 {
    let (answer, spent) = glob.matches_within(text, u64::MAX);
    assert!(answer.is_some());
    spent
}

#[test]
fn glob_patterns_match_like_the_shell() {
    assert!(matches("*", "anything"));
    assert!(matches("a*c", "abbbc"));
    assert!(!matches("a*c", "abbbd"));
    assert!(matches("?x", "ax"));
    assert!(!matches("?x", "x"));
    assert!(matches("[abc]x", "bx"));
    assert!(!matches("[!abc]x", "bx"));
    assert!(matches("[a-c]*", "cat"));
    assert!(matches("*.txt", "a.txt"));
    assert!(!matches("*.txt", "a.txt.bak"));
    assert!(matches("[", "["), "an unclosed bracket is a literal");
    assert!(matches("a[]]b", "a]b"), "a leading ] is a member");
    assert!(matches("**a**", "bab"));
    assert!(!matches("a", ""));
    assert!(
        !matches("a*a", "a"),
        "the first and last pieces may not share a character"
    );
    assert!(matches("a*a", "aa"));
    assert!(
        matches("é*[à-ê]", "éxè"),
        "pieces and classes are by character"
    );
}

#[test]
fn a_quoted_star_is_a_plain_character() {
    let glob = Glob::shell(&[('*', true)]);
    assert!(hit(&glob, "*"));
    assert!(!hit(&glob, "a"));
}

#[test]
fn pathological_patterns_finish() {
    let pattern = "a*".repeat(40) + "b";
    assert!(!matches(&pattern, &"a".repeat(200)));
}

#[test]
fn fnmatch_patterns_read_backslashes_and_fold_case() {
    let fnmatch = |pattern: &str, text: &str, fold: bool| hit(&Glob::fnmatch(pattern, fold), text);
    assert!(fnmatch("\\*", "*", false));
    assert!(!fnmatch("\\*", "a", false));
    assert!(
        fnmatch("a\\", "a\\", false),
        "a trailing backslash is itself"
    );
    assert!(fnmatch("[a-]", "-", false));
    assert!(fnmatch("*.CONF", "sshd.conf", true));
    assert!(
        fnmatch("[A-C]x", "bX", true),
        "a folded range holds both cases"
    );
    assert!(!fnmatch("[A-C]x", "bx", false));
    assert!(
        !fnmatch("[Z-a]", "z", true),
        "a range reversed by folding holds nothing"
    );
}

/// A small deterministic generator (xorshift64*), so a failure names its seed and replays.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn string(&mut self, alphabet: &[char], max: usize) -> String {
        let len = self.below(max + 1);
        (0..len)
            .map(|_| alphabet[self.below(alphabet.len())])
            .collect()
    }
}

#[test]
fn shell_patterns_answer_as_the_old_matcher_did() {
    let pattern_chars = ['a', 'b', '*', '?', '[', ']', '!', '^', '-', 'é'];
    let text_chars = ['a', 'b', ']', '-', '[', '!', 'é', '*'];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for case in 0..200_000 {
        let pattern: Vec<(char, bool)> = rng
            .string(&pattern_chars, 8)
            .chars()
            .map(|c| (c, rng.below(4) == 0))
            .collect();
        let text = rng.string(&text_chars, 9);
        let name: Vec<char> = text.chars().collect();
        let expected = reference::glob_match(&reference::compile_glob(&pattern), &name);
        assert_eq!(
            hit(&Glob::shell(&pattern), &text),
            expected,
            "case {case}: pattern {pattern:?} against {text:?}"
        );
    }
}

#[test]
fn fnmatch_patterns_answer_as_the_old_matcher_did() {
    let pattern_chars = ['a', 'B', '*', '?', '[', ']', '!', '^', '-', '\\', 'z', 'é'];
    let text_chars = ['a', 'A', 'b', 'B', ']', '-', '\\', 'Z', 'é', '['];
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for case in 0..200_000 {
        let pattern = rng.string(&pattern_chars, 8);
        let text = rng.string(&text_chars, 9);
        let fold = rng.below(2) == 0;
        assert_eq!(
            hit(&Glob::fnmatch(&pattern, fold), &text),
            reference::fnmatch(&pattern, &text, fold),
            "case {case}: pattern {pattern:?} against {text:?}, fold {fold}"
        );
    }
}

#[test]
fn plain_text_and_stars_match_in_steps_linear_in_the_text() {
    // The shape that held a worker for minutes: `*${a}b` against `$a`, and the same piece
    // between stars against twice the text.
    for n in [1_000usize, 10_000, 100_000] {
        let a = "a".repeat(n);
        let suffix = Glob::shell(&unquoted(&format!("*{a}b")));
        let middle = Glob::shell(&unquoted(&format!("*{a}b*")));
        let itself = Glob::shell(&unquoted(&format!("*{a}")));
        let doubled = a.repeat(2);
        let bound = 8 * u64::try_from(n).unwrap();
        assert!(!hit(&suffix, &a));
        assert!(steps(&suffix, &a) <= bound, "{n}: {}", steps(&suffix, &a));
        assert!(!hit(&middle, &doubled));
        assert!(steps(&middle, &doubled) <= bound, "{n}");
        assert!(hit(&itself, &a));
        assert!(steps(&itself, &a) <= bound, "{n}");
    }
}

#[test]
fn a_long_bracket_expression_costs_one_step_per_character() {
    let class = "b".repeat(8_000);
    let glob = Glob::fnmatch(&format!("*[{class}]x"), false);
    let name = "b".repeat(255);
    assert!(!hit(&glob, &name));
    assert!(steps(&glob, &name) <= 4, "{}", steps(&glob, &name));
    assert!(hit(&glob, &format!("{name}bx")));
}

#[test]
fn a_wildcard_piece_counts_every_comparison_and_stops_at_its_allowance() {
    let piece = "?".repeat(1_000);
    let glob = Glob::shell(&unquoted(&format!("*{piece}b*")));
    let text = "a".repeat(10_000);
    // About 9,000 places of 1,000 comparisons each.
    assert!(steps(&glob, &text) > 8_000_000);
    let (answer, spent) = glob.matches_within(&text, 50_000);
    assert_eq!(answer, None, "past its allowance the match stops");
    assert!(spent > 50_000 && spent <= 50_001, "{spent}");
}

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "telnet".to_string(),
        session_id: None,
    }
}

fn shell_with_allowance(work_per_line: u64) -> FakeShell {
    let limits = BudgetLimits {
        work_per_line,
        ..BudgetLimits::standard()
    };
    FakeShell::new(FakeFs::new(), ctx()).with_budget(ConnectionBudget::new(limits))
}

fn stdout(out: &CommandResult) -> String {
    let bytes: Vec<u8> = out
        .output
        .iter()
        .filter(|segment| segment.fd == OutputFd::Stdout)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect();
    String::from_utf8(bytes).unwrap()
}

/// Set `name` to `unit` repeated 1,024 times.
fn kilo(sh: &mut FakeShell, name: &str, unit: &str) {
    let seed = unit.repeat(32);
    sh.handle_input(format!("{name}='{seed}'"));
    for _ in 0..5 {
        sh.handle_input(format!("{name}=${name}${name}"));
    }
}

#[test]
fn a_case_match_is_charged_and_one_the_line_cannot_pay_for_stops_it() {
    let mut sh = shell_with_allowance(200_000);
    kilo(&mut sh, "a", "a");
    kilo(&mut sh, "q", "?");
    let (out, _) = sh.handle_input("case $a in *${a}) echo self;; esac; echo tail");
    assert_eq!(stdout(&out), "self\ntail\n");
    assert!(sh.last_trace().budget.hit.is_none());

    // 1,024 `?` then `b`, tried at each of 1,024 places in 2,048 characters: about a million
    // comparisons, past this line's allowance.
    let (out, _) = sh.handle_input("case $a$a in *${q}b*) echo yes;; esac; echo tail");
    assert_eq!(stdout(&out), "", "the line stops at the match");
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Work));
    assert!(
        sh.last_trace().budget.work_charged <= 200_001,
        "a refused match charges no more than the line had: {}",
        sh.last_trace().budget.work_charged
    );

    let (out, _) = sh.handle_input("echo next");
    assert_eq!(
        stdout(&out),
        "next\n",
        "the next line has its allowance again"
    );
}

#[test]
fn find_and_package_globs_are_charged_to_the_line() {
    let mut sh = shell_with_allowance(4_194_304);
    let (out, _) = sh.handle_input("find /etc -maxdepth 1 -name 'host*'; echo tail");
    let found = stdout(&out);
    assert!(
        found.contains("/etc/hostname\n") && found.ends_with("tail\n"),
        "{found}"
    );

    // Every node, and every package, is a match the line pays for: at least a step each, where
    // they used to cost nothing (a walk charged one unit a node, a package list nothing).
    let charged = |sh: &mut FakeShell, line: &str| {
        let (out, _) = sh.handle_input(line);
        (stdout(&out), sh.last_trace().budget.work_charged)
    };
    let (tree, _) = charged(&mut sh, "find /");
    let nodes = u64::try_from(tree.lines().count()).unwrap();
    let (_, walked) = charged(&mut sh, "find / -false");
    let (_, patterned) = charged(&mut sh, "find / -name '*[abc]?x*y'");
    assert!(nodes > 100);
    assert!(
        patterned >= walked + nodes,
        "{patterned} against {walked} for {nodes} nodes"
    );

    let (table, _) = charged(&mut sh, "dpkg -l");
    let packages = u64::try_from(table.lines().filter(|l| l.starts_with("ii")).count()).unwrap();
    let (_, patterned) = charged(&mut sh, "dpkg -l '*[abc]?x*y'");
    assert!(packages > 100);
    assert!(patterned >= packages, "{patterned} for {packages} packages");

    // So a line with too little left for the matches stops in the middle of them.
    let mut sh = shell_with_allowance(packages / 2);
    let (out, _) = sh.handle_input("dpkg -l '*[abc]?x*y'; echo tail");
    assert!(!stdout(&out).contains("tail"));
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Work));
}
