//! Word expansion, in the order POSIX 2.6 gives:
//!
//! 1. tilde expansion of a leading `~`;
//! 2. parameter, arithmetic and command substitution, left to right;
//! 3. field splitting at `$IFS` of what step 2 produced from unquoted expansions;
//! 4. removal of empty fields that came from unquoted expansions;
//! 5. pathname expansion of unquoted `*`, `?` and `[..]` against the fake filesystem, capped at
//!    1,024 matches, keeping the pattern itself when nothing matches;
//! 6. quote removal, which here is simply that quoting characters were never kept as text.
//!
//! Quoting is tracked per character until step 5, so a quoted `*` never globs and a quoted
//! expansion never splits.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::arith::{self, ArithError};
use super::ast::{List, Param, ParamName, Word, WordPart};
use super::eval::ShellState;
use super::lex::lex_body;
use super::trace::BudgetHit;
use super::{FakeShell, Frame, FrameKind, ShellLevel, len_u64};

/// Most names one pattern may match.
pub(super) const GLOB_CAP: usize = 1_024;

const DEFAULT_IFS: &str = " \t\n";

/// Why an expansion produced no words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ExpandError {
    /// The shell's own complaint, already worded for the active level.
    Message(String),
    /// A complaint that ends the shell process, as dash's expansion errors do: status 2.
    Fatal(String),
    /// A cap (depth or the line's allowance) stopped it; nothing is printed.
    Refused,
}

/// A piece of expansion output and how it may be treated by the later steps.
enum Seg {
    Text {
        text: String,
        /// Quoted text neither splits nor globs.
        quoted: bool,
        /// Unquoted expansion results split at IFS.
        split: bool,
    },
    /// Between the separate words `"$@"` expands to.
    Break,
}

/// One word being built: each character with whether it was quoted.
#[derive(Default, Clone)]
struct Field {
    chars: Vec<(char, bool)>,
    /// Survives being empty: it held quoted text, or a non-whitespace IFS delimiter made it.
    keep: bool,
}

impl Field {
    fn text(&self) -> String {
        self.chars.iter().map(|(c, _)| *c).collect()
    }

    fn has_glob(&self) -> bool {
        self.chars
            .iter()
            .any(|(c, quoted)| !quoted && matches!(c, '*' | '?' | '['))
    }
}

impl FakeShell {
    /// Expand a command's words to its argument vector.
    pub(super) fn expand_argv(&mut self, words: &[Word]) -> Result<Vec<String>, ExpandError> {
        let mut out = Vec::new();
        for word in words {
            out.extend(self.expand_fields(word)?);
            if self.line.exhausted() {
                return Err(ExpandError::Refused);
            }
        }
        Ok(out)
    }

    /// [`Self::expand_argv`], and for each field whether the word it came from held a variable
    /// that is not set, which expands to nothing and so cannot be told from an empty value.
    pub(super) fn expand_argv_flagged(
        &mut self,
        words: &[Word],
    ) -> Result<(Vec<String>, Vec<bool>), ExpandError> {
        let mut out = Vec::new();
        let mut unset = Vec::new();
        let outer = std::mem::take(&mut self.unset_seen);
        for word in words {
            self.unset_seen = false;
            let fields = match self.expand_fields(word) {
                Ok(fields) => fields,
                Err(error) => {
                    self.unset_seen = outer;
                    return Err(error);
                }
            };
            unset.extend(fields.iter().map(|_| self.unset_seen));
            out.extend(fields);
            if self.line.exhausted() {
                self.unset_seen = outer;
                return Err(ExpandError::Refused);
            }
        }
        self.unset_seen = outer;
        Ok((out, unset))
    }

    /// One word through all six steps.
    pub(super) fn expand_fields(&mut self, word: &Word) -> Result<Vec<String>, ExpandError> {
        let segs = self.parts_segs(&word.parts, false)?;
        self.charge_segs(&segs)?;
        let ifs = self.ifs();
        let mut out = Vec::new();
        for field in build_fields(&segs, &ifs) {
            if field.chars.is_empty() && !field.keep {
                continue;
            }
            if field.has_glob() {
                let matches = self.glob(&field)?;
                if !matches.is_empty() {
                    out.extend(matches);
                    continue;
                }
            }
            out.push(field.text());
        }
        Ok(out)
    }

    /// A word expanded to a single string: no splitting and no globbing, as an assignment's value
    /// and a here-document body are.
    pub(super) fn expand_scalar(&mut self, word: &Word) -> Result<String, ExpandError> {
        let segs = self.parts_segs(&word.parts, false)?;
        self.charge_segs(&segs)?;
        Ok(join_segs(&segs))
    }

    /// Whether a `case` pattern matches `subject`. The pattern is expanded without splitting or
    /// pathname expansion; its unquoted `*`, `?` and `[..]` are special and, unlike a pathname,
    /// match a `/` too.
    pub(super) fn case_pattern_matches(
        &mut self,
        pattern: &Word,
        subject: &str,
    ) -> Result<bool, ExpandError> {
        let segs = self.parts_segs(&pattern.parts, false)?;
        self.charge_segs(&segs)?;
        let mut chars: Vec<(char, bool)> = Vec::new();
        for seg in &segs {
            match seg {
                Seg::Text { text, quoted, .. } => {
                    chars.extend(text.chars().map(|c| (c, *quoted)));
                }
                Seg::Break => chars.push((' ', true)),
            }
        }
        let name: Vec<char> = subject.chars().collect();
        Ok(glob_match(&compile_glob(&chars), &name))
    }

    /// Text expanded the way the inside of double quotes is: a here-document body.
    pub(super) fn expand_text(&mut self, text: &str) -> Result<String, ExpandError> {
        let max_depth = self.budget().limits().max_depth;
        let base = self.current_line();
        let dialect = self.grammar();
        let Ok(parts) = lex_body(
            text,
            base,
            self.depth.current(),
            max_depth,
            dialect,
            &mut self.line,
        ) else {
            // A body that will not parse is text.
            return Ok(text.to_string());
        };
        self.sync_budget_trace();
        let segs = self.parts_segs(&parts, true)?;
        self.charge_segs(&segs)?;
        Ok(join_segs(&segs))
    }

    /// Spend the line's allowance on the bytes an expansion produced, so a word that doubles
    /// itself each trip round a loop runs out of allowance instead of memory.
    fn charge_segs(&mut self, segs: &[Seg]) -> Result<(), ExpandError> {
        let bytes: usize = segs
            .iter()
            .map(|seg| match seg {
                Seg::Text { text, .. } => text.len(),
                Seg::Break => 1,
            })
            .fold(0, usize::saturating_add);
        if self.charge_work(len_u64(bytes)) {
            Ok(())
        } else {
            Err(ExpandError::Refused)
        }
    }

    /// The line number a command being run now is on, for nested parses.
    fn current_line(&self) -> u32 {
        match self.active_level() {
            ShellLevel::Dash { line } => u32::try_from(line).unwrap_or(u32::MAX),
            _ => 1,
        }
    }

    fn ifs(&self) -> String {
        self.state()
            .get("IFS")
            .map_or_else(|| DEFAULT_IFS.to_string(), str::to_string)
    }

    fn parts_segs(&mut self, parts: &[WordPart], quoted: bool) -> Result<Vec<Seg>, ExpandError> {
        let mut segs = Vec::new();
        for part in parts {
            if !self.charge_work(1) {
                return Err(ExpandError::Refused);
            }
            match part {
                WordPart::Literal(text) => segs.push(Seg::Text {
                    text: text.clone(),
                    quoted,
                    split: false,
                }),
                WordPart::Quoted(text) => segs.push(Seg::Text {
                    text: text.clone(),
                    quoted: true,
                    split: false,
                }),
                WordPart::DoubleQuoted(inner) => {
                    let mut inside = self.parts_segs(inner, true)?;
                    let only_empty_at = !inner.is_empty()
                        && self.state().positional.is_empty()
                        && inner.iter().all(|p| {
                            matches!(
                                p,
                                WordPart::Param(Param {
                                    name: ParamName::At,
                                    ..
                                })
                            )
                        });
                    if inside.is_empty() && !only_empty_at {
                        // `""` is an empty argument, not nothing.
                        inside.push(Seg::Text {
                            text: String::new(),
                            quoted: true,
                            split: false,
                        });
                    }
                    segs.append(&mut inside);
                }
                WordPart::Tilde => {
                    let home = self.state().get("HOME").unwrap_or("~").to_string();
                    segs.push(Seg::Text {
                        text: home,
                        quoted: true,
                        split: false,
                    });
                }
                WordPart::Param(param) => self.param_segs(param, quoted, &mut segs)?,
                WordPart::Arith(expr) => {
                    let value = self.eval_arith(expr)?;
                    segs.push(Seg::Text {
                        text: value.to_string(),
                        quoted,
                        split: !quoted,
                    });
                }
                WordPart::CmdSub(list) => {
                    let text = self.eval_cmdsub(list)?;
                    segs.push(Seg::Text {
                        text,
                        quoted,
                        split: !quoted,
                    });
                }
                WordPart::Unsupported(_) => {}
            }
        }
        Ok(segs)
    }

    fn param_segs(
        &mut self,
        param: &Param,
        quoted: bool,
        segs: &mut Vec<Seg>,
    ) -> Result<(), ExpandError> {
        let text_seg = |text: String| Seg::Text {
            text,
            quoted,
            split: !quoted,
        };
        match &param.name {
            ParamName::At => {
                for (i, value) in self.state().positional.clone().into_iter().enumerate() {
                    if i > 0 {
                        segs.push(Seg::Break);
                    }
                    segs.push(text_seg(value));
                }
                return Ok(());
            }
            ParamName::Star => {
                let joiner = match self.state().get("IFS") {
                    Some(ifs) => ifs.chars().next().map(String::from).unwrap_or_default(),
                    None => " ".to_string(),
                };
                let joined = self.state().positional.join(&joiner);
                segs.push(text_seg(joined));
                return Ok(());
            }
            _ => {}
        }
        let value = self.param_value(&param.name);
        if let Some(default) = &param.default {
            let use_default = match &value {
                None => true,
                Some(v) => default.colon && v.is_empty(),
            };
            if use_default {
                let inner = self.parts_segs(&default.word.parts, quoted)?;
                segs.extend(inner);
                return Ok(());
            }
        }
        self.unset_seen |= value.is_none();
        segs.push(text_seg(value.unwrap_or_default()));
        Ok(())
    }

    /// A parameter's value, or `None` when it is unset.
    fn param_value(&self, name: &ParamName) -> Option<String> {
        let state: &ShellState = self.state();
        match name {
            // bash's innermost running function; unset outside one.
            ParamName::Var(var) if var == "FUNCNAME" && self.is_bash() => {
                state.calls.last().map(|call| call.name.clone())
            }
            ParamName::Var(var) => state.get(var).map(str::to_string),
            ParamName::Status => Some(state.last_status.to_string()),
            ParamName::Pid => Some(state.pid.to_string()),
            ParamName::Zero => Some(
                state
                    .argv0
                    .clone()
                    .unwrap_or_else(|| self.argv_zero().to_string()),
            ),
            ParamName::Bang => Some(state.last_bg_pid.map(|p| p.to_string()).unwrap_or_default()),
            ParamName::Count => Some(state.positional.len().to_string()),
            ParamName::Positional(n) => state.positional.get(n.saturating_sub(1)).cloned(),
            ParamName::At | ParamName::Star => None,
        }
    }

    /// `$(( expr ))`: expand what is inside, then evaluate.
    fn eval_arith(&mut self, raw: &str) -> Result<i64, ExpandError> {
        let max_depth = self.budget().limits().max_depth;
        let expr = self.expand_text(raw)?;
        let result = arith::eval(&expr, max_depth, &mut |name| {
            self.state().get(name).unwrap_or("").to_string()
        });
        match result {
            Ok(value) => Ok(value),
            Err(ArithError::TooDeep) => {
                self.record_hit(BudgetHit::Depth);
                Err(ExpandError::Refused)
            }
            Err(error) => {
                let text = self.arith_error_text(&expr, &error);
                // dash's `sh_error`: the shell process ends with status 2.
                Err(if self.is_dash() {
                    ExpandError::Fatal(text)
                } else {
                    ExpandError::Message(text)
                })
            }
        }
    }

    /// The active level's wording of an arithmetic error.
    fn arith_error_text(&self, expr: &str, error: &ArithError) -> String {
        match (self.active_level(), error) {
            (ShellLevel::Bash { .. }, ArithError::DivByZero { token }) => self.shell_error(
                format_args!("{expr}: division by 0 (error token is \"{token}\")"),
            ),
            // [unverified] bash's wording for a malformed expression, and both wordings below for
            // the other shells: only bash's division by zero was checked against the spec.
            (ShellLevel::Bash { .. }, ArithError::Syntax { token }) => self.shell_error(
                format_args!("{expr}: syntax error: operand expected (error token is \"{token}\")"),
            ),
            (ShellLevel::Dash { .. }, ArithError::DivByZero { .. }) => self.shell_error(
                format_args!("arithmetic expression: division by zero: \"{expr}\""),
            ),
            (ShellLevel::Dash { .. }, ArithError::Syntax { .. }) => self.shell_error(format_args!(
                "arithmetic expression: expecting primary: \"{expr}\""
            )),
            (ShellLevel::AndroidMksh, ArithError::DivByZero { .. }) => {
                self.shell_error(format_args!("{expr}: divide by zero"))
            }
            (ShellLevel::AndroidMksh, _) => self.shell_error(format_args!("{expr}: bad number")),
            (_, ArithError::TooDeep) => String::new(),
        }
    }

    /// `$( list )`: run in a copy of the shell state, take the standard output with its trailing
    /// newlines removed, and hand its standard error to the command being expanded.
    pub(super) fn eval_cmdsub(&mut self, list: &List) -> Result<String, ExpandError> {
        let max_depth = self.budget().limits().max_depth;
        if !self.depth.try_enter(max_depth) {
            self.record_hit(BudgetHit::Depth);
            self.note_depth();
            return Err(ExpandError::Refused);
        }
        self.note_depth();
        let copy = self.state().clone();
        self.frames.push(Frame {
            kind: FrameKind::Subshell,
            state: copy,
        });
        self.script_depth = self.script_depth.saturating_add(1);
        let mut ran = self.eval_list(list);
        self.script_depth = self.script_depth.saturating_sub(1);
        self.frames.pop();
        self.depth.leave();
        let stdout = ran.take_stdout();
        self.deferred_stderr.append(&mut ran.output);
        self.last_subst_status = Some(ran.status);
        if ran.stop_line || self.line.exhausted() {
            return Err(ExpandError::Refused);
        }
        let text: String = String::from_utf8_lossy(&stdout)
            .chars()
            .filter(|c| *c != '\0')
            .collect();
        Ok(text.trim_end_matches('\n').to_string())
    }

    // ---- pathnames -----------------------------------------------------------------------------

    /// Names matching a field's pattern, sorted; empty when none match.
    fn glob(&mut self, field: &Field) -> Result<Vec<String>, ExpandError> {
        let absolute = field.chars.first().is_some_and(|(c, _)| *c == '/');
        let mut segments: Vec<Vec<(char, bool)>> = vec![Vec::new()];
        for &(c, quoted) in &field.chars {
            if c == '/' {
                segments.push(Vec::new());
            } else if let Some(last) = segments.last_mut() {
                last.push((c, quoted));
            }
        }
        let trailing_slash = segments.last().is_some_and(Vec::is_empty) && segments.len() > 1;
        segments.retain(|segment| !segment.is_empty());
        let count = segments.len();
        let mut candidates = vec![if absolute {
            "/".to_string()
        } else {
            String::new()
        }];
        for (index, segment) in segments.iter().enumerate() {
            let last = index.saturating_add(1) == count;
            let pattern = compile_glob(segment);
            let literal: String = segment.iter().map(|(c, _)| *c).collect();
            let has_glob = segment
                .iter()
                .any(|(c, quoted)| !quoted && matches!(c, '*' | '?' | '['));
            let mut next: Vec<String> = Vec::new();
            for candidate in &candidates {
                let directory = self.glob_directory(candidate);
                if has_glob {
                    let Some(mut names) = self.fs.list_dir(&directory) else {
                        continue;
                    };
                    if !self.charge_work(len_u64(names.len())) {
                        return Err(ExpandError::Refused);
                    }
                    names.sort();
                    let dot = segment.first().is_some_and(|(c, _)| *c == '.');
                    for name in names {
                        if name.starts_with('.') && !dot {
                            continue;
                        }
                        if glob_match(&pattern, &name.chars().collect::<Vec<_>>()) {
                            next.push(format!("{candidate}{name}{}", if last { "" } else { "/" }));
                        }
                    }
                } else {
                    let path = format!("{directory}/{literal}");
                    let present = if last {
                        self.fs.file_exists(&path) || self.fs.is_dir(&path)
                    } else {
                        self.fs.is_dir(&path)
                    };
                    if present {
                        next.push(format!(
                            "{candidate}{literal}{}",
                            if last { "" } else { "/" }
                        ));
                    }
                }
                if next.len() >= GLOB_CAP {
                    next.truncate(GLOB_CAP);
                    break;
                }
            }
            candidates = next;
            if candidates.is_empty() {
                return Ok(Vec::new());
            }
        }
        if trailing_slash {
            let mut kept = Vec::new();
            for candidate in candidates {
                let directory = self.glob_directory(&candidate);
                if self.fs.is_dir(&directory) {
                    kept.push(format!("{candidate}/"));
                }
            }
            candidates = kept;
        }
        candidates.sort();
        candidates.truncate(GLOB_CAP);
        Ok(candidates)
    }

    /// The absolute directory a partial match so far names.
    fn glob_directory(&self, candidate: &str) -> String {
        let trimmed = candidate.trim_end_matches('/');
        if candidate.starts_with('/') {
            if trimmed.is_empty() {
                "/".to_string()
            } else {
                trimmed.to_string()
            }
        } else if trimmed.is_empty() {
            self.state().cwd.clone()
        } else {
            format!("{}/{trimmed}", self.state().cwd.trim_end_matches('/'))
        }
    }
}

fn join_segs(segs: &[Seg]) -> String {
    let mut out = String::new();
    for seg in segs {
        match seg {
            Seg::Text { text, .. } => out.push_str(text),
            Seg::Break => out.push(' '),
        }
    }
    out
}

/// Split expansion output into fields: literal and quoted text is never split, unquoted expansion
/// text splits at `ifs`. Whitespace IFS characters collapse and trim; any other IFS character
/// ends one field and may leave an empty one behind.
fn build_fields(segs: &[Seg], ifs: &str) -> Vec<Field> {
    let mut fields: Vec<Field> = Vec::new();
    let mut current = Field::default();
    let mut started = false;
    let is_ifs = |c: char| ifs.contains(c);
    let is_ifs_space = |c: char| ifs.contains(c) && matches!(c, ' ' | '\t' | '\n');
    for seg in segs {
        match seg {
            Seg::Break => {
                if started {
                    fields.push(std::mem::take(&mut current));
                }
                started = false;
            }
            Seg::Text {
                text,
                quoted,
                split: false,
            } => {
                for c in text.chars() {
                    current.chars.push((c, *quoted));
                }
                if *quoted {
                    current.keep = true;
                    started = true;
                } else if !text.is_empty() {
                    started = true;
                }
            }
            Seg::Text {
                text, split: true, ..
            } => {
                for c in text.chars() {
                    if is_ifs_space(c) {
                        if started {
                            fields.push(std::mem::take(&mut current));
                            started = false;
                        }
                    } else if is_ifs(c) {
                        current.keep = true;
                        fields.push(std::mem::take(&mut current));
                        started = false;
                    } else {
                        current.chars.push((c, false));
                        started = true;
                    }
                }
            }
        }
    }
    if started {
        fields.push(current);
    }
    fields
}

// ---- glob patterns -----------------------------------------------------------------------------

enum GlobToken {
    Literal(char),
    Any,
    Star,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

/// Compile a pattern segment, where only unquoted characters are special.
fn compile_glob(segment: &[(char, bool)]) -> Vec<GlobToken> {
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

/// A bracket expression whose `[` is just before `start`, and the index after its `]`.
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

/// Whether `name` matches the compiled pattern. Linear in the product of the two lengths at
/// worst, with no recursion.
fn glob_match(pattern: &[GlobToken], name: &[char]) -> bool {
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn quoted_or_not(text: &str) -> Vec<(char, bool)> {
        text.chars().map(|c| (c, false)).collect()
    }

    fn matches(pattern: &str, name: &str) -> bool {
        glob_match(
            &compile_glob(&quoted_or_not(pattern)),
            &name.chars().collect::<Vec<_>>(),
        )
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
    }

    #[test]
    fn a_quoted_star_is_a_plain_character() {
        let pattern = vec![('*', true)];
        assert!(glob_match(&compile_glob(&pattern), &['*']));
        assert!(!glob_match(&compile_glob(&pattern), &['a']));
    }

    #[test]
    fn pathological_patterns_finish() {
        let pattern = "a*".repeat(40) + "b";
        assert!(!matches(&pattern, &"a".repeat(200)));
    }

    fn text(s: &str, quoted: bool, split: bool) -> Seg {
        Seg::Text {
            text: s.to_string(),
            quoted,
            split,
        }
    }

    fn words(fields: Vec<Field>) -> Vec<String> {
        fields
            .into_iter()
            .filter(|f| !f.chars.is_empty() || f.keep)
            .map(|f| f.text())
            .collect()
    }

    #[test]
    fn unquoted_expansions_split_at_whitespace_and_quoted_text_does_not() {
        let segs = [text(" a  b\tc\n", false, true)];
        assert_eq!(words(build_fields(&segs, DEFAULT_IFS)), ["a", "b", "c"]);
        let segs = [text("a b", true, false)];
        assert_eq!(words(build_fields(&segs, DEFAULT_IFS)), ["a b"]);
        // Literal text joins the first and last piece of an expansion.
        let segs = [
            text("x", false, false),
            text("1 2", false, true),
            text("y", false, false),
        ];
        assert_eq!(words(build_fields(&segs, DEFAULT_IFS)), ["x1", "2y"]);
    }

    #[test]
    fn an_empty_unquoted_expansion_vanishes_and_a_quoted_one_stays() {
        assert!(words(build_fields(&[text("", false, true)], DEFAULT_IFS)).is_empty());
        assert_eq!(
            words(build_fields(&[text("", true, false)], DEFAULT_IFS)),
            [""]
        );
    }

    #[test]
    fn a_non_whitespace_ifs_character_keeps_the_empty_field_it_makes() {
        let fields = build_fields(&[text("a::b", false, true)], ":");
        assert_eq!(words(fields), ["a", "", "b"]);
        let fields = build_fields(&[text("a:", false, true)], ":");
        assert_eq!(
            words(fields),
            ["a"],
            "a trailing delimiter adds no empty field"
        );
    }

    #[test]
    fn an_empty_ifs_never_splits() {
        assert_eq!(
            words(build_fields(&[text("a b", false, true)], "")),
            ["a b"]
        );
    }
}
