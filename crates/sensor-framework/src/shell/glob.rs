//! Glob patterns: a `case` arm's pattern, pathname expansion, `find -name`/`-path`, `dpkg -l` and
//! `apt list`.
//!
//! A pattern compiles once into the pieces between its stars, each a run of one-character
//! tokens, with every bracket expression reduced to a sorted set of ranges. Each token is one
//! character wide, so a match is decided greedily: the first piece is anchored at the start of
//! the text, the last at its end, and every piece between takes its leftmost place after the one
//! before. A piece of plain characters is found with the standard library's linear substring
//! search, so a pattern of literal text and stars matches in time linear in the text, however
//! long either is. A piece holding `?` or a bracket expression is tried at each place in turn,
//! which can cost the text's length times the piece's.
//!
//! Every comparison and every byte searched is a step, and the caller charges the steps to the
//! line's work allowance ([`FakeShell::glob_matches`]). A match that would take more steps than
//! the line has left stops there, so no pattern can hold a worker longer than the allowance pays
//! for. The matcher this replaced restarted the whole rest of the pattern at every character
//! after a star and charged nothing, so one `case` with a long subject held a runtime worker for
//! minutes.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::{FakeShell, len_u64};

/// A bracket expression: sorted, non-overlapping inclusive ranges of code points.
#[derive(Debug, Clone)]
struct Class {
    negated: bool,
    ranges: Vec<(u32, u32)>,
}

impl Class {
    /// The set `members` names, merged once so a test costs a binary search however many
    /// members the expression listed. A range whose ends are reversed holds nothing, as before.
    fn new(negated: bool, members: Vec<(char, char)>) -> Self {
        let mut spans: Vec<(u32, u32)> = members
            .into_iter()
            .map(|(low, high)| (u32::from(low), u32::from(high)))
            .filter(|(low, high)| low <= high)
            .collect();
        spans.sort_unstable();
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for (low, high) in spans {
            match ranges.last_mut() {
                Some(last) if low <= last.1.saturating_add(1) => last.1 = last.1.max(high),
                _ => ranges.push((low, high)),
            }
        }
        Self { negated, ranges }
    }

    fn contains(&self, c: char) -> bool {
        let c = u32::from(c);
        let after = self.ranges.partition_point(|(low, _)| *low <= c);
        let inside = after
            .checked_sub(1)
            .and_then(|at| self.ranges.get(at))
            .is_some_and(|(_, high)| c <= *high);
        inside != self.negated
    }
}

/// One character of a pattern. The class is boxed so a long literal pattern stays small.
#[derive(Debug, Clone)]
enum Token {
    Literal(char),
    Any,
    Class(Box<Class>),
}

impl Token {
    fn matches(&self, c: char) -> bool {
        match self {
            Token::Literal(literal) => *literal == c,
            Token::Any => true,
            Token::Class(class) => class.contains(c),
        }
    }
}

/// What lies between two stars: plain text, or tokens of which at least one is `?` or a class.
#[derive(Debug, Clone)]
enum Piece {
    Text(String),
    Tokens(Vec<Token>),
}

impl Piece {
    fn is_empty(&self) -> bool {
        match self {
            Piece::Text(text) => text.is_empty(),
            Piece::Tokens(tokens) => tokens.is_empty(),
        }
    }
}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub(super) struct Glob {
    /// One more than the stars; a piece may be empty.
    pieces: Vec<Piece>,
    /// Whether the pattern held a star: without one it must match the whole text exactly.
    starred: bool,
    /// ASCII case is ignored: the tokens are lowercased and so is the text before matching.
    fold: bool,
}

/// Builds the pieces as the pattern is read. A piece is kept as text until a `?` or a class
/// joins it, so a long literal pattern costs a byte per byte, not a token per character.
struct Builder {
    pieces: Vec<Piece>,
    current: Piece,
    starred: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            pieces: Vec::new(),
            current: Piece::Text(String::new()),
            starred: false,
        }
    }
}

impl Builder {
    fn token(&mut self, token: Token) {
        match (&mut self.current, token) {
            (Piece::Text(text), Token::Literal(c)) => text.push(c),
            (Piece::Text(text), token) => {
                let mut tokens: Vec<Token> = text.chars().map(Token::Literal).collect();
                tokens.push(token);
                self.current = Piece::Tokens(tokens);
            }
            (Piece::Tokens(tokens), token) => tokens.push(token),
        }
    }

    fn star(&mut self) {
        self.starred = true;
        self.close_piece();
    }

    fn close_piece(&mut self) {
        let piece = std::mem::replace(&mut self.current, Piece::Text(String::new()));
        self.pieces.push(piece);
    }

    fn finish(mut self, fold: bool) -> Glob {
        self.close_piece();
        Glob {
            pieces: self.pieces,
            starred: self.starred,
            fold,
        }
    }
}

/// The steps one match may still take, and those it took.
struct Steps {
    left: u64,
    spent: u64,
}

/// The match needed more steps than it was allowed.
struct Spent;

impl Steps {
    fn take(&mut self, n: u64) -> Result<(), Spent> {
        self.spent = self.spent.saturating_add(n);
        if self.spent > self.left {
            Err(Spent)
        } else {
            Ok(())
        }
    }
}

impl Glob {
    /// A shell pattern, each character with whether it was quoted. Unquoted `*`, `?` and `[..]`
    /// are special; `!` or `^` first in a bracket expression negates it, a `]` first in it is a
    /// member, and a `[` with no closing `]` is a literal.
    pub(super) fn shell(segment: &[(char, bool)]) -> Self {
        let mut builder = Builder::default();
        let mut i = 0usize;
        while let Some(&(c, quoted)) = segment.get(i) {
            i = i.saturating_add(1);
            if quoted {
                builder.token(Token::Literal(c));
                continue;
            }
            match c {
                '*' => builder.star(),
                '?' => builder.token(Token::Any),
                '[' => match shell_class(segment, i) {
                    Some((class, next)) => {
                        builder.token(Token::Class(Box::new(class)));
                        i = next;
                    }
                    None => builder.token(Token::Literal('[')),
                },
                other => builder.token(Token::Literal(other)),
            }
        }
        builder.finish(false)
    }

    /// A pattern as `fnmatch` with no flags reads it (`find`, `dpkg`, `apt`): `*`, `?`, bracket
    /// expressions with ranges and `!`/`^` negation, and a backslash quoting the next character.
    /// `fold` ignores ASCII case, ranges included.
    pub(super) fn fnmatch(pattern: &str, fold: bool) -> Self {
        let pat: Vec<char> = pattern.chars().collect();
        let case = |c: char| if fold { c.to_ascii_lowercase() } else { c };
        let mut builder = Builder::default();
        let mut p = 0usize;
        while let Some(&c) = pat.get(p) {
            match c {
                '*' => {
                    builder.star();
                    p = p.saturating_add(1);
                }
                '?' => {
                    builder.token(Token::Any);
                    p = p.saturating_add(1);
                }
                '[' => match fnmatch_class(&pat, p, fold) {
                    Some((class, next)) => {
                        builder.token(Token::Class(Box::new(class)));
                        p = next;
                    }
                    None => {
                        builder.token(Token::Literal('['));
                        p = p.saturating_add(1);
                    }
                },
                '\\' => match pat.get(p.saturating_add(1)) {
                    Some(&quoted) => {
                        builder.token(Token::Literal(case(quoted)));
                        p = p.saturating_add(2);
                    }
                    None => {
                        builder.token(Token::Literal('\\'));
                        p = p.saturating_add(1);
                    }
                },
                other => {
                    builder.token(Token::Literal(case(other)));
                    p = p.saturating_add(1);
                }
            }
        }
        builder.finish(fold)
    }

    /// Whether `text` matches, and the steps that took. `None` when it would take more than
    /// `allowance` steps; the steps returned are then past `allowance`.
    pub(super) fn matches_within(&self, text: &str, allowance: u64) -> (Option<bool>, u64) {
        let mut steps = Steps {
            left: allowance,
            spent: 0,
        };
        let hit = self.run(text, &mut steps).ok();
        (hit, steps.spent)
    }

    fn run(&self, text: &str, steps: &mut Steps) -> Result<bool, Spent> {
        let folded;
        let text = if self.fold {
            steps.take(len_u64(text.len()))?;
            folded = text.to_ascii_lowercase();
            folded.as_str()
        } else {
            text
        };
        let Some((first, rest)) = self.pieces.split_first() else {
            return Ok(text.is_empty());
        };
        if !self.starred {
            return Ok(front(first, text, steps)? == Some(text.len()));
        }
        let Some((last, middle)) = rest.split_last() else {
            return Ok(front(first, text, steps)?.is_some());
        };
        let Some(head) = front(first, text, steps)? else {
            return Ok(false);
        };
        let Some(tail) = back(last, text, steps)? else {
            return Ok(false);
        };
        let Some(mut window) = text.get(head..tail) else {
            // The first and last pieces overlap: the text is too short for both.
            return Ok(false);
        };
        for piece in middle.iter().filter(|piece| !piece.is_empty()) {
            match leftmost(piece, window, steps)? {
                Some(end) => window = window.get(end..).unwrap_or(""),
                None => return Ok(false),
            }
        }
        Ok(true)
    }
}

/// Where `piece` matching from the start of `text` ends, as a byte offset.
fn front(piece: &Piece, text: &str, steps: &mut Steps) -> Result<Option<usize>, Spent> {
    let tokens = match piece {
        Piece::Text(needle) => {
            steps.take(len_u64(needle.len()))?;
            return Ok(text.starts_with(needle.as_str()).then_some(needle.len()));
        }
        Piece::Tokens(tokens) => tokens,
    };
    let mut chars = text.char_indices();
    for token in tokens {
        steps.take(1)?;
        match chars.next() {
            Some((_, c)) if token.matches(c) => {}
            _ => return Ok(None),
        }
    }
    Ok(Some(chars.next().map_or(text.len(), |(at, _)| at)))
}

/// Where `piece` matching up to the end of `text` starts, as a byte offset.
fn back(piece: &Piece, text: &str, steps: &mut Steps) -> Result<Option<usize>, Spent> {
    let tokens = match piece {
        Piece::Text(needle) => {
            steps.take(len_u64(needle.len()))?;
            return Ok(text
                .ends_with(needle.as_str())
                .then(|| text.len().saturating_sub(needle.len())));
        }
        Piece::Tokens(tokens) => tokens,
    };
    let mut chars = text.char_indices().rev();
    let mut start = text.len();
    for token in tokens.iter().rev() {
        steps.take(1)?;
        match chars.next() {
            Some((at, c)) if token.matches(c) => start = at,
            _ => return Ok(None),
        }
    }
    Ok(Some(start))
}

/// Where the leftmost place `piece` matches in `text` ends, as a byte offset.
fn leftmost(piece: &Piece, text: &str, steps: &mut Steps) -> Result<Option<usize>, Spent> {
    if let Piece::Text(needle) = piece {
        // Two-way search: linear in the bytes it reads, which are those up to the match's end.
        let found = text.find(needle.as_str());
        let read = found.map_or(text.len(), |at| at.saturating_add(needle.len()));
        steps.take(len_u64(read).saturating_add(len_u64(needle.len())))?;
        return Ok(found.map(|at| at.saturating_add(needle.len())));
    }
    for (start, _) in text.char_indices() {
        let rest = text.get(start..).unwrap_or("");
        if let Some(end) = front(piece, rest, steps)? {
            return Ok(Some(start.saturating_add(end)));
        }
    }
    Ok(None)
}

/// A shell bracket expression whose `[` is just before `start`, and the index after its `]`.
fn shell_class(segment: &[(char, bool)], start: usize) -> Option<(Class, usize)> {
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
    let mut members = Vec::new();
    let mut k = 0usize;
    while let Some(&low) = chars.get(k) {
        if chars.get(k.saturating_add(1)) == Some(&'-')
            && let Some(&high) = chars.get(k.saturating_add(2))
        {
            members.push((low, high));
            k = k.saturating_add(3);
        } else {
            members.push((low, low));
            k = k.saturating_add(1);
        }
    }
    Some((Class::new(negated, members), i))
}

/// An `fnmatch` bracket expression starting at `at`, and the index after its `]`; `None` for a
/// `[` with no closing `]`. A `-` between two members is a range unless the second is the `]`.
fn fnmatch_class(pat: &[char], at: usize, fold: bool) -> Option<(Class, usize)> {
    let case = |c: char| if fold { c.to_ascii_lowercase() } else { c };
    let mut i = at.saturating_add(1);
    let negated = matches!(pat.get(i), Some('!' | '^'));
    if negated {
        i = i.saturating_add(1);
    }
    let mut members = Vec::new();
    let mut first = true;
    loop {
        let low = *pat.get(i)?;
        if low == ']' && !first {
            return Some((Class::new(negated, members), i.saturating_add(1)));
        }
        first = false;
        let dash = pat.get(i.saturating_add(1)) == Some(&'-');
        match pat.get(i.saturating_add(2)) {
            Some(&high) if dash && high != ']' => {
                members.push((case(low), case(high)));
                i = i.saturating_add(3);
            }
            _ => {
                members.push((case(low), case(low)));
                i = i.saturating_add(1);
            }
        }
    }
}

impl FakeShell {
    /// Whether `text` matches `glob`, with the steps the match took charged to the line. `None`
    /// once the line cannot pay for them, and the caller stops the line: a match is never run past
    /// what the line has left.
    pub(super) fn glob_matches(&mut self, glob: &Glob, text: &str) -> Option<bool> {
        let allowance = self.line.remaining();
        let (hit, steps) = glob.matches_within(text, allowance);
        // A refused match charges one step past what was left: enough to run the allowance out,
        // without counting work that was never done.
        let charge = if hit.is_some() {
            steps
        } else {
            allowance.saturating_add(1)
        };
        if !self.charge_work(charge) {
            return None;
        }
        hit
    }
}
