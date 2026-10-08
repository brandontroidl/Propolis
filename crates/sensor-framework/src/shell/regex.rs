//! POSIX regular expressions for the text tools: basic (BRE, `grep`'s default) and extended (ERE,
//! `grep -E` and `awk`), with the GNU extensions a survey script leans on (`\|`, `\+`, `\?` in a
//! basic expression, `\w`, `\s`, `\b`, `\<`, `\>`).
//!
//! A pattern compiles to a small instruction program run by a Pike machine: every position of the
//! text advances a bounded set of threads at once, so a match costs at most the text length times
//! the program length, whatever the pattern. Nothing backtracks, so no pattern an attacker types
//! can make a line run away; the program size is capped at compile time and the caller charges
//! the scan to the line's work allowance. Matching is by byte (the C locale's view), and a match
//! is leftmost-longest, the POSIX rule `awk`'s `match` and `sub` report.
//!
//! Back-references (`\1`) are not modeled and match the digit itself.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

/// The most instructions one compiled pattern may hold; a bigger pattern is refused as GNU grep
/// refuses one past its own limits.
const MAX_INSTS: usize = 8_192;
/// The largest bound an interval may name, as `RE_DUP_MAX` is on glibc.
const MAX_REPEAT: u32 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Syntax {
    Basic,
    Extended,
    /// `grep -P`, approximated as ERE plus `\d` and `\D`.
    Perl,
}

/// Why a pattern did not compile, worded as GNU grep reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RegexError {
    /// A `[` that ends the pattern.
    Invalid,
    UnmatchedBracket,
    UnmatchedParen,
    UnmatchedCloseParen,
    UnmatchedBrace,
    InvalidRange,
    InvalidClass,
    TrailingBackslash,
    BadInterval,
    BackReference,
    TooBig,
}

impl RegexError {
    /// GNU grep 3.7's wording, recorded on Ubuntu 22.04 (2026-10-07 reference session).
    pub(super) fn message(&self) -> &'static str {
        match self {
            Self::Invalid => "Invalid regular expression",
            Self::UnmatchedBracket => "Unmatched [, [^, [:, [., or [=",
            Self::UnmatchedParen => "Unmatched ( or \\(",
            Self::UnmatchedCloseParen => "Unmatched ) or \\)",
            Self::UnmatchedBrace => "Unmatched \\{",
            Self::InvalidRange => "Invalid range end",
            Self::InvalidClass => "Invalid character class name",
            Self::TrailingBackslash => "Trailing backslash",
            Self::BadInterval => "Invalid content of \\{\\}",
            Self::BackReference => "Invalid back reference",
            Self::TooBig => "Regular expression too big",
        }
    }
}

/// A set of bytes, one bit each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ByteSet([u64; 4]);

impl ByteSet {
    fn insert(&mut self, byte: u8) {
        let index = usize::from(byte >> 6);
        if let Some(word) = self.0.get_mut(index) {
            *word |= 1u64 << (byte & 63);
        }
    }

    fn contains(&self, byte: u8) -> bool {
        self.0
            .get(usize::from(byte >> 6))
            .is_some_and(|word| word & (1u64 << (byte & 63)) != 0)
    }

    fn insert_range(&mut self, low: u8, high: u8) {
        for byte in low..=high {
            self.insert(byte);
        }
    }

    fn negate(&mut self) {
        for word in &mut self.0 {
            *word = !*word;
        }
    }

    /// Add the other case of every ASCII letter in the set.
    fn fold(&mut self) {
        for byte in b'a'..=b'z' {
            let upper = byte.to_ascii_uppercase();
            if self.contains(byte) || self.contains(upper) {
                self.insert(byte);
                self.insert(upper);
            }
        }
    }
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// A zero-width test at a position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assert {
    Start,
    End,
    WordBoundary,
    NotWordBoundary,
    WordStart,
    WordEnd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Empty,
    Set(ByteSet),
    Assert(Assert),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
    },
}

fn class_set(name: &[u8]) -> Option<ByteSet> {
    let test: fn(u8) -> bool = match name {
        b"alpha" => |b| b.is_ascii_alphabetic(),
        b"digit" => |b| b.is_ascii_digit(),
        b"alnum" => |b| b.is_ascii_alphanumeric(),
        b"upper" => |b| b.is_ascii_uppercase(),
        b"lower" => |b| b.is_ascii_lowercase(),
        b"space" => |b| matches!(b, b' ' | 0x09..=0x0d),
        b"blank" => |b| b == b' ' || b == b'\t',
        b"punct" => |b| b.is_ascii_punctuation(),
        b"xdigit" => |b| b.is_ascii_hexdigit(),
        b"cntrl" => |b| b.is_ascii_control(),
        b"print" => |b| (0x20..=0x7e).contains(&b),
        b"graph" => |b| (0x21..=0x7e).contains(&b),
        _ => return None,
    };
    let mut set = ByteSet::default();
    for byte in 0..=u8::MAX {
        if test(byte) {
            set.insert(byte);
        }
    }
    Some(set)
}

fn single(byte: u8) -> ByteSet {
    let mut set = ByteSet::default();
    set.insert(byte);
    set
}

fn any_byte() -> ByteSet {
    let mut set = ByteSet::default();
    set.negate();
    set
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
    syntax: Syntax,
    /// `awk` reads `\n`, `\t` and the like inside a pattern as the control characters.
    awk_escapes: bool,
    perl: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.src.get(self.pos.saturating_add(ahead)).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn basic(&self) -> bool {
        self.syntax == Syntax::Basic
    }

    /// Whether the input at the cursor closes an alternative: `|` or `)` in ERE, `\|` or `\)` in
    /// BRE, or the end.
    fn at_alt_end(&self, depth: u32) -> bool {
        match (self.peek(), self.basic()) {
            (None, _) => true,
            (Some(b'|'), false) => true,
            (Some(b')'), false) => depth > 0,
            (Some(b'\\'), true) => match self.peek_at(1) {
                Some(b'|') => true,
                Some(b')') => depth > 0,
                _ => false,
            },
            _ => false,
        }
    }

    fn alternation(&mut self, depth: u32) -> Result<Node, RegexError> {
        let mut branches = vec![self.branch(depth)?];
        loop {
            match (self.peek(), self.basic()) {
                (Some(b'|'), false) => self.bump(),
                (Some(b'\\'), true) if self.peek_at(1) == Some(b'|') => {
                    self.bump();
                    self.bump();
                }
                _ => break,
            }
            branches.push(self.branch(depth)?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().unwrap_or(Node::Empty)
        } else {
            Node::Alt(branches)
        })
    }

    fn branch(&mut self, depth: u32) -> Result<Node, RegexError> {
        let mut items: Vec<Node> = Vec::new();
        let branch_start = self.pos;
        while !self.at_alt_end(depth) {
            let at_start = self.pos == branch_start;
            let atom = self.atom(depth, at_start, &items)?;
            let atom = self.quantified(atom)?;
            items.push(atom);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    /// One atom. `at_start` is true at the start of a branch, where BRE reads `*` and `^`
    /// specially.
    fn atom(&mut self, depth: u32, at_start: bool, before: &[Node]) -> Result<Node, RegexError> {
        let Some(byte) = self.peek() else {
            return Ok(Node::Empty);
        };
        self.bump();
        match byte {
            b'.' => Ok(Node::Set(any_byte())),
            b'[' => self.bracket().map(Node::Set),
            b'^' if !self.basic() || at_start => Ok(Node::Assert(Assert::Start)),
            b'$' if !self.basic() || self.at_alt_end(depth) => Ok(Node::Assert(Assert::End)),
            // A leading `*` (or one after an anchor) is an ordinary character in BRE.
            b'*' if self.basic()
                && (at_start || matches!(before.last(), Some(Node::Assert(Assert::Start)))) =>
            {
                Ok(Node::Set(single(b'*')))
            }
            b'(' if !self.basic() => self.group(depth),
            b'{' if !self.basic() => Ok(Node::Set(single(b'{'))),
            b'\\' => self.escape(depth),
            other => Ok(Node::Set(single(other))),
        }
    }

    fn group(&mut self, depth: u32) -> Result<Node, RegexError> {
        let inner = self.alternation(depth.saturating_add(1))?;
        match (self.peek(), self.basic()) {
            (Some(b')'), false) => self.bump(),
            (Some(b'\\'), true) if self.peek_at(1) == Some(b')') => {
                self.bump();
                self.bump();
            }
            _ => return Err(RegexError::UnmatchedParen),
        }
        Ok(inner)
    }

    fn escape(&mut self, depth: u32) -> Result<Node, RegexError> {
        let Some(byte) = self.peek() else {
            return Err(RegexError::TrailingBackslash);
        };
        self.bump();
        let set = |b: u8| Ok(Node::Set(single(b)));
        match byte {
            b'(' if self.basic() => self.group(depth),
            b')' if self.basic() => Err(RegexError::UnmatchedCloseParen),
            b'{' if self.basic() => set(b'{'),
            b'1'..=b'9' if !self.awk_escapes => Err(RegexError::BackReference),
            b'd' if self.perl => Ok(Node::Set(class_set(b"digit").unwrap_or_default())),
            b'D' if self.perl => {
                let mut digits = class_set(b"digit").unwrap_or_default();
                digits.negate();
                Ok(Node::Set(digits))
            }
            b'w' | b'W' | b's' | b'S' => {
                let mut class = if matches!(byte, b'w' | b'W') {
                    let mut word = class_set(b"alnum").unwrap_or_default();
                    word.insert(b'_');
                    word
                } else {
                    class_set(b"space").unwrap_or_default()
                };
                if byte.is_ascii_uppercase() {
                    class.negate();
                }
                Ok(Node::Set(class))
            }
            b'b' if self.awk_escapes => set(0x08),
            b'b' => Ok(Node::Assert(Assert::WordBoundary)),
            b'B' => Ok(Node::Assert(Assert::NotWordBoundary)),
            b'<' => Ok(Node::Assert(Assert::WordStart)),
            b'>' => Ok(Node::Assert(Assert::WordEnd)),
            b'n' if self.awk_escapes => set(b'\n'),
            b't' if self.awk_escapes => set(b'\t'),
            b'r' if self.awk_escapes => set(b'\r'),
            b'f' if self.awk_escapes => set(0x0c),
            b'v' if self.awk_escapes => set(0x0b),
            b'a' if self.awk_escapes => set(0x07),
            other => set(other),
        }
    }

    /// A bracket expression, the `[` already consumed.
    fn bracket(&mut self) -> Result<ByteSet, RegexError> {
        if self.peek().is_none() {
            return Err(RegexError::Invalid);
        }
        let mut set = ByteSet::default();
        let negated = self.peek() == Some(b'^');
        if negated {
            self.bump();
        }
        let mut first = true;
        loop {
            let Some(byte) = self.peek() else {
                return Err(RegexError::UnmatchedBracket);
            };
            if byte == b']' && !first {
                self.bump();
                break;
            }
            first = false;
            let low = if byte == b'[' && matches!(self.peek_at(1), Some(b':' | b'.' | b'=')) {
                let kind = self.peek_at(1).unwrap_or(b':');
                let start = self.pos.saturating_add(2);
                let mut end = start;
                loop {
                    match (self.src.get(end), self.src.get(end.saturating_add(1))) {
                        (Some(&a), Some(&b']')) if a == kind => break,
                        (Some(_), _) => end = end.saturating_add(1),
                        (None, _) => return Err(RegexError::UnmatchedBracket),
                    }
                }
                let name = self.src.get(start..end).unwrap_or(&[]);
                self.pos = end.saturating_add(2);
                if kind == b':' {
                    let class = class_set(name).ok_or(RegexError::InvalidClass)?;
                    for b in 0..=u8::MAX {
                        if class.contains(b) {
                            set.insert(b);
                        }
                    }
                    continue;
                }
                // A collating element or equivalence class names its one character here.
                match name {
                    [only] => *only,
                    _ => return Err(RegexError::InvalidClass),
                }
            } else {
                self.bump();
                if byte == b'\\' && self.awk_escapes {
                    let escaped = self.peek().ok_or(RegexError::UnmatchedBracket)?;
                    self.bump();
                    match escaped {
                        b'n' => b'\n',
                        b't' => b'\t',
                        b'r' => b'\r',
                        other => other,
                    }
                } else {
                    byte
                }
            };
            if self.peek() == Some(b'-') && self.peek_at(1).is_some_and(|b| b != b']') {
                self.bump();
                let high = self.peek().ok_or(RegexError::UnmatchedBracket)?;
                self.bump();
                if high < low {
                    return Err(RegexError::InvalidRange);
                }
                set.insert_range(low, high);
            } else {
                set.insert(low);
            }
        }
        if negated {
            set.negate();
        }
        Ok(set)
    }

    /// Any repetition operators after an atom.
    fn quantified(&mut self, mut atom: Node) -> Result<Node, RegexError> {
        loop {
            let (min, max) = match (self.peek(), self.basic()) {
                (Some(b'*'), _) => {
                    self.bump();
                    (0, None)
                }
                (Some(b'+'), false) => {
                    self.bump();
                    (1, None)
                }
                (Some(b'?'), false) => {
                    self.bump();
                    (0, Some(1))
                }
                (Some(b'\\'), true) if self.peek_at(1) == Some(b'+') => {
                    self.pos = self.pos.saturating_add(2);
                    (1, None)
                }
                (Some(b'\\'), true) if self.peek_at(1) == Some(b'?') => {
                    self.pos = self.pos.saturating_add(2);
                    (0, Some(1))
                }
                (Some(b'\\'), true) if self.peek_at(1) == Some(b'{') => {
                    self.pos = self.pos.saturating_add(2);
                    self.interval(true)?.ok_or(RegexError::BadInterval)?
                }
                (Some(b'{'), false) => {
                    let save = self.pos;
                    self.bump();
                    match self.interval(false)? {
                        Some(bounds) => bounds,
                        None => {
                            // Not an interval: the brace is an ordinary character, read next.
                            self.pos = save;
                            return Ok(atom);
                        }
                    }
                }
                _ => return Ok(atom),
            };
            atom = Node::Repeat {
                node: Box::new(atom),
                min,
                max,
            };
        }
    }

    /// `m`, `m,`, `m,n` or `,n` and the closing brace (`\}` in BRE). `None` in ERE when the text
    /// is not an interval at all.
    fn interval(&mut self, basic: bool) -> Result<Option<(u32, Option<u32>)>, RegexError> {
        let number = |parser: &mut Self| -> Option<u32> {
            let start = parser.pos;
            while parser.peek().is_some_and(|b| b.is_ascii_digit()) {
                parser.bump();
            }
            let digits = parser.src.get(start..parser.pos)?;
            std::str::from_utf8(digits).ok()?.parse::<u32>().ok()
        };
        let min = number(self);
        let max = if self.peek() == Some(b',') {
            self.bump();
            number(self)
        } else {
            match min {
                Some(m) => Some(m),
                None if basic => return Err(RegexError::BadInterval),
                None => return Ok(None),
            }
        };
        let closed = if basic {
            if self.peek() == Some(b'\\') && self.peek_at(1) == Some(b'}') {
                self.pos = self.pos.saturating_add(2);
                true
            } else {
                false
            }
        } else if self.peek() == Some(b'}') {
            self.bump();
            true
        } else {
            false
        };
        if !closed {
            return if basic {
                Err(RegexError::UnmatchedBrace)
            } else {
                Ok(None)
            };
        }
        let min = min.unwrap_or(0);
        if min > MAX_REPEAT || max.is_some_and(|m| m > MAX_REPEAT) {
            return Err(RegexError::TooBig);
        }
        if max.is_some_and(|m| m < min) {
            return Err(RegexError::BadInterval);
        }
        Ok(Some((min, max)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inst {
    Set(usize),
    Assert(Assert),
    Split(usize, usize),
    Jmp(usize),
    Match,
}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub(super) struct Regex {
    insts: Vec<Inst>,
    sets: Vec<ByteSet>,
}

struct Compiler {
    insts: Vec<Inst>,
    sets: Vec<ByteSet>,
    fold: bool,
}

impl Compiler {
    fn push(&mut self, inst: Inst) -> Result<usize, RegexError> {
        if self.insts.len() >= MAX_INSTS {
            return Err(RegexError::TooBig);
        }
        self.insts.push(inst);
        Ok(self.insts.len().saturating_sub(1))
    }

    fn patch(&mut self, at: usize, inst: Inst) {
        if let Some(slot) = self.insts.get_mut(at) {
            *slot = inst;
        }
    }

    fn here(&self) -> usize {
        self.insts.len()
    }

    fn emit(&mut self, node: &Node) -> Result<(), RegexError> {
        match node {
            Node::Empty => Ok(()),
            Node::Set(set) => {
                let mut set = *set;
                if self.fold {
                    set.fold();
                }
                let index = match self.sets.iter().position(|s| *s == set) {
                    Some(index) => index,
                    None => {
                        self.sets.push(set);
                        self.sets.len().saturating_sub(1)
                    }
                };
                self.push(Inst::Set(index)).map(|_| ())
            }
            Node::Assert(kind) => self.push(Inst::Assert(*kind)).map(|_| ()),
            Node::Concat(items) => items.iter().try_for_each(|item| self.emit(item)),
            Node::Alt(branches) => {
                let mut jumps = Vec::new();
                let count = branches.len();
                for (index, branch) in branches.iter().enumerate() {
                    if index.saturating_add(1) < count {
                        let split = self.push(Inst::Split(0, 0))?;
                        self.emit(branch)?;
                        jumps.push(self.push(Inst::Jmp(0))?);
                        let next = self.here();
                        self.patch(split, Inst::Split(split.saturating_add(1), next));
                    } else {
                        self.emit(branch)?;
                    }
                }
                let end = self.here();
                for jump in jumps {
                    self.patch(jump, Inst::Jmp(end));
                }
                Ok(())
            }
            Node::Repeat { node, min, max } => {
                for _ in 0..*min {
                    self.emit(node)?;
                }
                match max {
                    None => {
                        let split = self.push(Inst::Split(0, 0))?;
                        self.emit(node)?;
                        self.push(Inst::Jmp(split))?;
                        let end = self.here();
                        self.patch(split, Inst::Split(split.saturating_add(1), end));
                    }
                    Some(max) => {
                        let mut splits = Vec::new();
                        for _ in *min..*max {
                            splits.push(self.push(Inst::Split(0, 0))?);
                            self.emit(node)?;
                        }
                        let end = self.here();
                        for split in splits {
                            self.patch(split, Inst::Split(split.saturating_add(1), end));
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

impl Regex {
    /// Compile `pattern`. `fold` matches letters without regard to case (`grep -i`).
    pub(super) fn new(pattern: &[u8], syntax: Syntax, fold: bool) -> Result<Self, RegexError> {
        Self::build(pattern, syntax, fold, false)
    }

    /// An `awk` pattern: ERE with the escape sequences `awk` reads inside one.
    pub(super) fn awk(pattern: &[u8]) -> Result<Self, RegexError> {
        Self::build(pattern, Syntax::Extended, false, true)
    }

    fn build(
        pattern: &[u8],
        syntax: Syntax,
        fold: bool,
        awk_escapes: bool,
    ) -> Result<Self, RegexError> {
        let mut parser = Parser {
            src: pattern,
            pos: 0,
            syntax: if syntax == Syntax::Perl {
                Syntax::Extended
            } else {
                syntax
            },
            awk_escapes,
            perl: syntax == Syntax::Perl,
        };
        let node = parser.alternation(0)?;
        if parser.pos < pattern.len() {
            return Err(RegexError::UnmatchedParen);
        }
        let mut compiler = Compiler {
            insts: Vec::new(),
            sets: Vec::new(),
            fold,
        };
        compiler.emit(&node)?;
        compiler.push(Inst::Match)?;
        Ok(Self {
            insts: compiler.insts,
            sets: compiler.sets,
        })
    }

    /// The work one scan of `len` bytes costs: every byte steps every live thread.
    pub(super) fn cost(&self, len: usize) -> u64 {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        let insts = u64::try_from(self.insts.len()).unwrap_or(u64::MAX);
        len.saturating_add(1)
            .saturating_mul(insts.div_ceil(16).max(1))
    }

    pub(super) fn is_match(&self, text: &[u8]) -> bool {
        self.find_at(text, 0).is_some()
    }

    /// The leftmost-longest match starting at or after `from`, as `(start, end)`.
    pub(super) fn find_at(&self, text: &[u8], from: usize) -> Option<(usize, usize)> {
        let count = self.insts.len();
        let mut current: Vec<(usize, usize)> = Vec::new();
        let mut next: Vec<(usize, usize)> = Vec::new();
        let mut seen = vec![usize::MAX; count];
        let mut best: Option<(usize, usize)> = None;
        let mut pos = from;
        loop {
            if pos > text.len() {
                break;
            }
            if best.is_none() {
                self.add(&mut current, &mut seen, pos, 0, pos, text, &mut best);
            }
            if current.is_empty() {
                if best.is_some() {
                    break;
                }
                pos = pos.saturating_add(1);
                continue;
            }
            let byte = text.get(pos).copied();
            let step = pos.saturating_add(1);
            next.clear();
            for &(pc, start) in &current {
                if best.is_some_and(|(s, _)| start > s) {
                    continue;
                }
                if let (Some(Inst::Set(index)), Some(b)) = (self.insts.get(pc), byte)
                    && self.sets.get(*index).is_some_and(|set| set.contains(b))
                {
                    self.add(
                        &mut next,
                        &mut seen,
                        step,
                        pc.saturating_add(1),
                        start,
                        text,
                        &mut best,
                    );
                }
            }
            std::mem::swap(&mut current, &mut next);
            if byte.is_none() {
                break;
            }
            pos = step;
        }
        best
    }

    /// Add the thread at `pc`, following jumps, splits and assertions at `pos`; a thread that
    /// reaches the end of the program records a match.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &self,
        list: &mut Vec<(usize, usize)>,
        seen: &mut [usize],
        pos: usize,
        pc: usize,
        start: usize,
        text: &[u8],
        best: &mut Option<(usize, usize)>,
    ) {
        let mut stack = vec![pc];
        while let Some(pc) = stack.pop() {
            match seen.get_mut(pc) {
                Some(mark) if *mark == pos => continue,
                Some(mark) => *mark = pos,
                None => continue,
            }
            match self.insts.get(pc) {
                Some(Inst::Jmp(to)) => stack.push(*to),
                Some(Inst::Split(a, b)) => {
                    // The second is pushed first so the first is explored first.
                    stack.push(*b);
                    stack.push(*a);
                }
                Some(Inst::Assert(kind)) => {
                    if assert_holds(*kind, text, pos) {
                        stack.push(pc.saturating_add(1));
                    }
                }
                Some(Inst::Match) => {
                    let better = match *best {
                        None => true,
                        Some((s, e)) => start < s || (start == s && pos > e),
                    };
                    if better {
                        *best = Some((start, pos));
                    }
                }
                Some(Inst::Set(_)) => list.push((pc, start)),
                None => {}
            }
        }
    }
}

fn assert_holds(kind: Assert, text: &[u8], pos: usize) -> bool {
    let before = pos
        .checked_sub(1)
        .and_then(|i| text.get(i))
        .is_some_and(|&b| is_word(b));
    let after = text.get(pos).is_some_and(|&b| is_word(b));
    match kind {
        Assert::Start => pos == 0,
        Assert::End => pos == text.len(),
        Assert::WordBoundary => before != after,
        Assert::NotWordBoundary => before == after,
        Assert::WordStart => !before && after,
        Assert::WordEnd => before && !after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bre(p: &str) -> Regex {
        Regex::new(p.as_bytes(), Syntax::Basic, false).expect("compiles")
    }

    fn ere(p: &str) -> Regex {
        Regex::new(p.as_bytes(), Syntax::Extended, false).expect("compiles")
    }

    #[test]
    fn the_survey_patterns_match_what_grep_matches() {
        // `grep -i '^%Cpu\|^Cpu'`, `grep -iE 'vga|3d|display'`, `grep -E '^[0-9]+:'`.
        let cpu = Regex::new(b"^%Cpu\\|^Cpu", Syntax::Basic, true).expect("compiles");
        assert!(cpu.is_match(b"%Cpu(s):  0.3 us"));
        assert!(!cpu.is_match(b"MiB Mem :   3923.7 total"));
        let gpu = Regex::new(b"vga|3d|display", Syntax::Extended, true).expect("compiles");
        assert!(gpu.is_match(b"00:02.0 VGA compatible controller: Cirrus Logic GD 5446"));
        assert!(!gpu.is_match(b"00:01.1 IDE interface"));
        let link = ere("^[0-9]+:");
        assert!(link.is_match(b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>"));
        assert!(!link.is_match(b"    link/ether 06:4b:9c:1e:a2:7d"));
        assert!(bre("^processor").is_match(b"processor\t: 0"));
        assert!(!bre("^processor").is_match(b"model name\t: x processor"));
    }

    #[test]
    fn basic_reads_ere_operators_as_ordinary_characters() {
        assert!(bre("a+b").is_match(b"a+b"));
        assert!(!bre("a+b").is_match(b"aab"));
        assert!(bre("a\\+b").is_match(b"aab"));
        assert!(bre("x{2}").is_match(b"x{2}"));
        assert!(bre("x\\{2\\}").is_match(b"xx"));
        assert!(bre("*a").is_match(b"*a"));
        assert!(bre("a|b").is_match(b"a|b"));
        assert!(!bre("a|b").is_match(b"a"));
        assert!(bre("a$b").is_match(b"a$b"));
    }

    #[test]
    fn matches_are_leftmost_longest() {
        assert_eq!(ere("o+").find_at(b"foobar", 0), Some((1, 3)));
        assert_eq!(ere("ob").find_at(b"foobar", 0), Some((2, 4)));
        assert_eq!(ere("a|ab|abc").find_at(b"xabcd", 0), Some((1, 4)));
        assert_eq!(ere("x*").find_at(b"abc", 0), Some((0, 0)));
        assert_eq!(ere("b").find_at(b"abcb", 2), Some((3, 4)));
        assert_eq!(ere("$").find_at(b"ab", 0), Some((2, 2)));
    }

    #[test]
    fn brackets_classes_intervals_and_word_assertions() {
        assert!(ere("^[[:digit:]]{3}$").is_match(b"123"));
        assert!(!ere("^[[:digit:]]{3}$").is_match(b"1234"));
        assert!(ere("[^a-z]").is_match(b"abC"));
        assert!(!ere("[^a-z]").is_match(b"abc"));
        assert!(ere("[]a]").is_match(b"]"));
        assert!(ere("\\<root\\>").is_match(b"x root y"));
        assert!(!ere("\\<root\\>").is_match(b"xrooty"));
        assert!(ere("\\bab").is_match(b"x ab"));
        assert!(ere("a{2,}").is_match(b"caab"));
        assert!(!ere("a{2,}").is_match(b"cab"));
        assert!(ere("a{,2}b").is_match(b"b"));
        assert!(ere("x{").is_match(b"x{"));
    }

    #[test]
    fn errors_are_reported_not_guessed() {
        assert_eq!(
            Regex::new(b"[abc", Syntax::Basic, false).err(),
            Some(RegexError::UnmatchedBracket)
        );
        assert_eq!(
            Regex::new(b"(a", Syntax::Extended, false).err(),
            Some(RegexError::UnmatchedParen)
        );
        assert_eq!(
            Regex::new(b"a\\", Syntax::Basic, false).err(),
            Some(RegexError::TrailingBackslash)
        );
        assert_eq!(
            Regex::new(b"[[:nope:]]", Syntax::Basic, false).err(),
            Some(RegexError::InvalidClass)
        );
        assert_eq!(
            Regex::new(b"a{1000}", Syntax::Extended, false).err(),
            Some(RegexError::TooBig)
        );
        assert_eq!(
            Regex::new(b"a\\{2,1\\}", Syntax::Basic, false).err(),
            Some(RegexError::BadInterval)
        );
        assert_eq!(
            Regex::new(b"[", Syntax::Basic, false).err(),
            Some(RegexError::Invalid)
        );
        assert_eq!(
            Regex::new(b"\\)", Syntax::Basic, false).err(),
            Some(RegexError::UnmatchedCloseParen)
        );
        assert_eq!(
            Regex::new(b"\\1", Syntax::Basic, false).err(),
            Some(RegexError::BackReference)
        );
        // In ERE an unpaired `)` and a brace that opens no interval are ordinary characters.
        assert!(ere("a)").is_match(b"a)"));
        assert!(ere("a{1").is_match(b"a{1"));
        assert!(
            Regex::new(b"\\d+", Syntax::Perl, false)
                .expect("compiles")
                .is_match(b"server01")
        );
    }

    #[test]
    fn a_pathological_pattern_stays_linear() {
        let re = ere("(a*)*(a|aa)*b");
        let text = vec![b'a'; 4096];
        assert!(!re.is_match(&text));
    }

    #[test]
    fn case_folding_covers_sets_and_literals() {
        let re = Regex::new(b"[a-c]x", Syntax::Basic, true).expect("compiles");
        assert!(re.is_match(b"BX"));
        assert!(!bre("[a-c]x").is_match(b"BX"));
    }
}
