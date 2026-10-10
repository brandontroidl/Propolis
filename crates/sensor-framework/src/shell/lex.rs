//! The tokenizer. It reads the decoded input text once, left to right, and produces operators,
//! words (with their quoting and expansions kept as parts) and here-document bodies.
//!
//! Quoting follows POSIX 2.2: single quotes are literal to the next quote; inside double quotes a
//! backslash escapes only `$`, a backtick, `"`, `\` and a newline; outside quotes a backslash
//! escapes the next byte and a backslash-newline is a line continuation. `#` starts a comment
//! only at the start of a word. Anything the subset does not evaluate (`$'..'`, `${x##*/}`, brace
//! expansion, `<(..)`, an array assignment) becomes a [`WordPart::Unsupported`] so the parser can
//! degrade the command instead of raising an error a real shell would not.
//!
//! An unterminated quote, substitution or here-document is [`LexError::NeedMore`] while input may
//! still arrive (the PS2 continuation), and a syntax error once the text is known to be complete.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::ast::{
    Dialect, Line, List, Near, Param, ParamDefault, ParamName, SyntaxError, UnsupportedKind, Word,
    WordPart,
};
use super::eval::LineBudget;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    Semi,
    Amp,
    AndIf,
    OrIf,
    Pipe,
    /// `|&`
    PipeAmp,
    LParen,
    RParen,
    /// `;;`
    DSemi,
    Less,
    Great,
    /// `<<` and `<<-`: `idx` is the body's slot in [`Lexed::heredocs`].
    DLess {
        idx: usize,
    },
    DGreat,
    LessAnd,
    GreatAnd,
    LessGreat,
    /// `>|`
    Clobber,
    /// `<<<`
    TLess,
}

impl Op {
    /// The operator as written, for a diagnostic.
    pub(super) fn text(self) -> &'static str {
        match self {
            Op::Semi => ";",
            Op::Amp => "&",
            Op::AndIf => "&&",
            Op::OrIf => "||",
            Op::Pipe => "|",
            Op::PipeAmp => "|&",
            Op::LParen => "(",
            Op::RParen => ")",
            Op::DSemi => ";;",
            Op::Less => "<",
            Op::Great => ">",
            Op::DLess { .. } => "<<",
            Op::DGreat => ">>",
            Op::LessAnd => "<&",
            Op::GreatAnd => ">&",
            Op::LessGreat => "<>",
            Op::Clobber => ">|",
            Op::TLess => "<<<",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Tok {
    Word(Word),
    /// A digit run directly before `<` or `>`: the file descriptor of a redirection.
    IoNumber(u16),
    Op(Op),
    Newline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Token {
    pub tok: Tok,
    /// Byte offset of the first byte.
    pub pos: usize,
    /// Byte offset just past the last byte.
    pub end: usize,
    pub line: Line,
}

/// A here-document body, its leading tabs already stripped for `<<-`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct HereDoc {
    pub text: String,
    pub expand: bool,
    /// The delimiter with its quoting removed, as the closing line spells it.
    pub delim: String,
    /// `<<-`: the body's leading tabs were stripped.
    pub strip: bool,
}

#[derive(Debug, Default)]
pub(super) struct Lexed {
    pub tokens: Vec<Token>,
    pub heredocs: Vec<HereDoc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LexError {
    /// The text ends inside a quote, substitution or here-document.
    NeedMore,
    Syntax(SyntaxError),
    /// Nesting past the depth cap.
    TooDeep,
    /// The line's work allowance ran out.
    Budget,
}

/// Blanks between tokens. Carriage return counts, as it always has: a terminal turns CR into LF
/// before a real shell reads it, so a stray one never belongs to a word.
fn is_blank(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\x0b' | '\x0c')
}

fn is_meta(c: char) -> bool {
    is_blank(c) || matches!(c, '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>')
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// An ordinary word: ends at a metacharacter.
    Word,
    /// Inside `"..."`: ends at the closing quote, which is left for the caller.
    Double,
    /// The default word of `${x:-word}`: ends at the closing brace, which is left for the caller.
    Brace,
    /// A whole text expanded like double quotes (a here-document body, an arithmetic expression):
    /// runs to the end and treats `"` as an ordinary byte.
    Body,
}

struct PendingHere {
    idx: usize,
    delim: String,
    strip: bool,
}

struct Lexer<'a, 'b> {
    src: &'a str,
    i: usize,
    line: Line,
    tokens: Vec<Token>,
    heredocs: Vec<HereDoc>,
    /// A `<<` whose delimiter word has not been read yet: (slot, strip tabs).
    awaiting: Option<(usize, bool)>,
    /// Here-documents whose bodies start after the next newline, in order.
    pending: Vec<PendingHere>,
    at_eof: bool,
    /// The line number the text's first line has in its shell, so commands inside a substitution
    /// report the line they sit on.
    base_line: Line,
    depth: u32,
    max_depth: u32,
    /// Handed to the parser of a substitution's text.
    dialect: Dialect,
    budget: &'b mut LineBudget,
}

/// Tokenize `src`. `at_eof` says no more input will follow, so an incomplete construct is a syntax
/// error rather than a request for another line.
pub(super) fn lex(
    src: &str,
    at_eof: bool,
    base_line: Line,
    depth: u32,
    max_depth: u32,
    dialect: Dialect,
    budget: &mut LineBudget,
) -> Result<Lexed, LexError> {
    let mut lexer = Lexer {
        src,
        i: 0,
        line: 1,
        tokens: Vec::new(),
        heredocs: Vec::new(),
        awaiting: None,
        pending: Vec::new(),
        at_eof,
        base_line,
        depth,
        max_depth,
        dialect,
        budget,
    };
    lexer.run()?;
    Ok(Lexed {
        tokens: lexer.tokens,
        heredocs: lexer.heredocs,
    })
}

/// Parse `text` the way the inside of double quotes reads: expansions and backslash escapes, no
/// quoting. Used for here-document bodies and arithmetic expressions when they are evaluated.
pub(super) fn lex_body(
    text: &str,
    base_line: Line,
    depth: u32,
    max_depth: u32,
    dialect: Dialect,
    budget: &mut LineBudget,
) -> Result<Vec<WordPart>, LexError> {
    let mut lexer = Lexer {
        src: text,
        i: 0,
        line: 1,
        tokens: Vec::new(),
        heredocs: Vec::new(),
        awaiting: None,
        pending: Vec::new(),
        at_eof: true,
        base_line,
        depth,
        max_depth,
        dialect,
        budget,
    };
    lexer.scan_parts(Mode::Body)
}

fn syntax(near: Near, line: Line) -> LexError {
    LexError::Syntax(SyntaxError::new(near, line))
}

impl Lexer<'_, '_> {
    fn peek(&self) -> Option<char> {
        self.src.get(self.i..)?.chars().next()
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.src.get(self.i..)?.chars().nth(ahead)
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i = self.i.saturating_add(c.len_utf8());
        if c == '\n' {
            self.line = self.line.saturating_add(1);
        }
        Some(c)
    }

    fn charge(&mut self, n: usize) -> Result<(), LexError> {
        if self.budget.charge(u64::try_from(n).unwrap_or(u64::MAX)) {
            Ok(())
        } else {
            Err(LexError::Budget)
        }
    }

    fn incomplete(&self) -> LexError {
        if self.at_eof {
            syntax(Near::EndOfFile, self.line)
        } else {
            LexError::NeedMore
        }
    }

    /// [`Self::incomplete`] for a construct the shells have their own complaint for when the text
    /// ends inside it: dash's `Unterminated quoted string`, and bash's `unexpected EOF while
    /// looking for matching` the `closer` it wanted.
    fn incomplete_with(&self, dash: &'static str, closer: char) -> LexError {
        match (self.at_eof, self.dialect) {
            (true, Dialect::Posix) => syntax(Near::Message(dash), self.line),
            (true, Dialect::Bash) => syntax(Near::Unmatched(closer), self.line),
            _ => self.incomplete(),
        }
    }

    /// [`Self::incomplete`] for text that ends inside `$( ... )`, where dash names the `)` it
    /// wanted.
    fn incomplete_paren(&self) -> LexError {
        match (self.at_eof, self.dialect) {
            (true, Dialect::Posix) => LexError::Syntax(SyntaxError {
                expecting: Some("\")\""),
                ..SyntaxError::new(Near::EndOfFile, self.line)
            }),
            (true, Dialect::Bash) => syntax(Near::Unmatched(')'), self.line),
            _ => self.incomplete(),
        }
    }

    fn push(&mut self, tok: Tok, pos: usize, line: Line) {
        // Only a word can be the delimiter a `<<` is waiting for; the `<<` itself does not end
        // the wait.
        match &tok {
            Tok::Word(word) => {
                if let Some((idx, strip)) = self.awaiting.take() {
                    let mut delim = String::new();
                    let mut quoted = false;
                    collect_delimiter(&word.parts, &mut delim, &mut quoted);
                    if let Some(slot) = self.heredocs.get_mut(idx) {
                        slot.expand = !quoted;
                        slot.delim.clone_from(&delim);
                        slot.strip = strip;
                    }
                    self.pending.push(PendingHere { idx, delim, strip });
                }
            }
            Tok::Op(Op::DLess { .. }) => {}
            _ => self.awaiting = None,
        }
        self.tokens.push(Token {
            tok,
            pos,
            end: self.i,
            line,
        });
    }

    fn run(&mut self) -> Result<(), LexError> {
        self.charge(self.src.len())?;
        loop {
            self.skip_blanks()?;
            let Some(c) = self.peek() else { break };
            self.charge(1)?;
            let (pos, line) = (self.i, self.line);
            match c {
                '\n' => {
                    self.bump();
                    self.push(Tok::Newline, pos, line);
                    self.read_heredoc_bodies()?;
                }
                '#' => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                ';' | '&' | '|' | '(' | ')' | '<' | '>' => {
                    if let Some(word) = self.process_substitution()? {
                        self.push(Tok::Word(word), pos, line);
                    } else {
                        let op = self.operator();
                        self.push(Tok::Op(op), pos, line);
                    }
                }
                _ => {
                    if let Some(n) = self.io_number() {
                        self.push(Tok::IoNumber(n), pos, line);
                    } else {
                        let parts = self.scan_parts(Mode::Word)?;
                        if self.i == pos {
                            self.bump();
                        }
                        let raw = self.src.get(pos..self.i).unwrap_or("").to_string();
                        self.push(Tok::Word(Word { parts, raw }), pos, line);
                    }
                }
            }
        }
        if !self.pending.is_empty() {
            // Input ended on the line that named a here-document, so its body never started.
            if !self.at_eof {
                return Err(LexError::NeedMore);
            }
            self.pending.clear();
        }
        Ok(())
    }

    fn skip_blanks(&mut self) -> Result<(), LexError> {
        loop {
            match self.peek() {
                Some(c) if is_blank(c) => {
                    self.bump();
                }
                Some('\\') => match self.peek_at(1) {
                    Some('\n') => {
                        self.bump();
                        self.bump();
                    }
                    None => {
                        if !self.at_eof {
                            return Err(LexError::NeedMore);
                        }
                        // A lone backslash that ends a script is the word it is (`echo \` prints
                        // it, in dash and in bash); the word scanner takes it from here.
                        return Ok(());
                    }
                    Some(_) => return Ok(()),
                },
                _ => return Ok(()),
            }
        }
    }

    /// A digit run directly followed by `<` or `>` is a file descriptor, not a word.
    fn io_number(&mut self) -> Option<u16> {
        let rest = self.src.get(self.i..)?;
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        // dash takes one digit for a descriptor; `10>f` is the word `10` and a redirection.
        if digits == 0 || (self.dialect == Dialect::Posix && digits != 1) {
            return None;
        }
        let after = rest.chars().nth(digits)?;
        if after != '<' && after != '>' {
            return None;
        }
        let number = rest.get(..digits)?.parse::<u16>().ok()?;
        self.i = self.i.saturating_add(digits);
        Some(number)
    }

    /// `<(..)` and `>(..)`: a process substitution, outside the subset.
    fn process_substitution(&mut self) -> Result<Option<Word>, LexError> {
        let c = self.peek();
        if self.dialect == Dialect::Posix
            || !matches!(c, Some('<' | '>'))
            || self.peek_at(1) != Some('(')
        {
            return Ok(None);
        }
        let start = self.i;
        self.bump();
        self.bump();
        self.skip_balanced_parens()?;
        let raw = self.src.get(start..self.i).unwrap_or("").to_string();
        Ok(Some(Word {
            parts: vec![WordPart::Unsupported(UnsupportedKind::ProcessSubstitution)],
            raw,
        }))
    }

    /// Consume through the `)` closing a `(` already consumed.
    fn skip_balanced_parens(&mut self) -> Result<(), LexError> {
        let rest = self.src.get(self.i..).unwrap_or("");
        match scan_paren_end(rest) {
            Some(end) => {
                let consumed = end.saturating_add(1);
                self.advance_bytes(consumed);
                Ok(())
            }
            None => Err(self.incomplete()),
        }
    }

    /// Move past `n` bytes of the source, counting lines.
    fn advance_bytes(&mut self, n: usize) {
        let target = self.i.saturating_add(n).min(self.src.len());
        while self.i < target {
            if self.bump().is_none() {
                break;
            }
        }
    }

    fn operator(&mut self) -> Op {
        let c = self.bump().unwrap_or(';');
        let next = self.peek();
        let take = |lexer: &mut Self, op: Op| {
            lexer.bump();
            op
        };
        match (c, next) {
            (';', Some(';')) => take(self, Op::DSemi),
            (';', _) => Op::Semi,
            ('&', Some('&')) => take(self, Op::AndIf),
            ('&', _) => Op::Amp,
            ('|', Some('|')) => take(self, Op::OrIf),
            ('|', Some('&')) if self.dialect == Dialect::Bash => take(self, Op::PipeAmp),
            ('|', _) => Op::Pipe,
            ('(', _) => Op::LParen,
            (')', _) => Op::RParen,
            ('<', Some('<')) => {
                self.bump();
                match self.peek() {
                    // dash has no here-string: `<<<` is `<<` and then a `<` where its word
                    // should be.
                    Some('<') if self.dialect == Dialect::Bash => take(self, Op::TLess),
                    Some('-') => {
                        self.bump();
                        self.here_op(true)
                    }
                    _ => self.here_op(false),
                }
            }
            ('<', Some('&')) => take(self, Op::LessAnd),
            ('<', Some('>')) => take(self, Op::LessGreat),
            ('<', _) => Op::Less,
            ('>', Some('>')) => take(self, Op::DGreat),
            ('>', Some('&')) => take(self, Op::GreatAnd),
            ('>', Some('|')) => take(self, Op::Clobber),
            _ => Op::Great,
        }
    }

    fn here_op(&mut self, strip: bool) -> Op {
        let idx = self.heredocs.len();
        self.heredocs.push(HereDoc::default());
        self.awaiting = Some((idx, strip));
        Op::DLess { idx }
    }

    /// After a newline: read the bodies of every here-document named on the line just ended.
    fn read_heredoc_bodies(&mut self) -> Result<(), LexError> {
        let pending = std::mem::take(&mut self.pending);
        for here in pending {
            let mut body = String::new();
            let mut found = false;
            while self.i < self.src.len() {
                let rest = self.src.get(self.i..).unwrap_or("");
                let line_len = rest.find('\n').unwrap_or(rest.len());
                let raw_line = rest.get(..line_len).unwrap_or("");
                let consumed = line_len.saturating_add(1).min(rest.len());
                self.charge(consumed)?;
                self.advance_bytes(consumed);
                let visible = raw_line.strip_suffix('\r').unwrap_or(raw_line);
                let compared = if here.strip {
                    visible.trim_start_matches('\t')
                } else {
                    visible
                };
                if compared == here.delim {
                    found = true;
                    break;
                }
                body.push_str(if here.strip { compared } else { visible });
                body.push('\n');
            }
            if !found && !self.at_eof {
                return Err(LexError::NeedMore);
            }
            if let Some(slot) = self.heredocs.get_mut(here.idx) {
                slot.text = body;
            }
        }
        Ok(())
    }

    // ---- words ----------------------------------------------------------------------------

    fn scan_parts(&mut self, mode: Mode) -> Result<Vec<WordPart>, LexError> {
        let mut parts: Vec<WordPart> = Vec::new();
        let mut lit = String::new();
        let flush = |lit: &mut String, parts: &mut Vec<WordPart>| {
            if !lit.is_empty() {
                parts.push(WordPart::Literal(std::mem::take(lit)));
            }
        };
        while let Some(c) = self.peek() {
            let starts_word = parts.is_empty() && lit.is_empty();
            match mode {
                Mode::Word if is_meta(c) => {
                    // `name=(` opens an array value, which the word keeps consuming.
                    if c == '('
                        && parts.is_empty()
                        && self.dialect == Dialect::Bash
                        && is_array_assignment(&lit)
                    {
                        self.bump();
                        self.skip_balanced_parens()?;
                        flush(&mut lit, &mut parts);
                        parts.push(WordPart::Unsupported(UnsupportedKind::Array));
                        continue;
                    }
                    break;
                }
                Mode::Double if c == '"' => break,
                Mode::Brace if c == '}' => break,
                _ => {}
            }
            self.charge(1)?;
            match c {
                '\\' => {
                    self.bump();
                    match self.peek() {
                        None => {
                            if !self.at_eof && mode == Mode::Word {
                                return Err(LexError::NeedMore);
                            }
                            lit.push('\\');
                        }
                        Some('\n') => {
                            // A backslash-newline joins the lines, quoted or not.
                            self.bump();
                        }
                        Some(next) => {
                            let escapable = matches!(next, '$' | '`' | '"' | '\\');
                            match mode {
                                Mode::Word | Mode::Brace => {
                                    self.bump();
                                    flush(&mut lit, &mut parts);
                                    parts.push(WordPart::Quoted(next.to_string()));
                                }
                                Mode::Double | Mode::Body => {
                                    if escapable {
                                        self.bump();
                                        lit.push(next);
                                    } else {
                                        lit.push('\\');
                                    }
                                }
                            }
                        }
                    }
                }
                '\'' if matches!(mode, Mode::Word | Mode::Brace) => {
                    self.bump();
                    let rest = self.src.get(self.i..).unwrap_or("");
                    let Some(end) = rest.find('\'') else {
                        return Err(self.incomplete_with("Unterminated quoted string", '\''));
                    };
                    let text = rest.get(..end).unwrap_or("").to_string();
                    self.advance_bytes(end.saturating_add(1));
                    flush(&mut lit, &mut parts);
                    parts.push(WordPart::Quoted(text));
                }
                '"' if matches!(mode, Mode::Word | Mode::Brace) => {
                    self.bump();
                    let inner = self.nested(|lexer| lexer.scan_parts(Mode::Double))?;
                    if self.peek() != Some('"') {
                        return Err(self.incomplete_with("Unterminated quoted string", '"'));
                    }
                    self.bump();
                    flush(&mut lit, &mut parts);
                    parts.push(WordPart::DoubleQuoted(inner));
                }
                '`' => {
                    self.bump();
                    let inner = self.backtick_body()?;
                    let list = self.nested_parse(&inner, "`")?;
                    flush(&mut lit, &mut parts);
                    parts.push(WordPart::CmdSub(list));
                }
                '$' => {
                    self.bump();
                    flush(&mut lit, &mut parts);
                    let mut got = self.dollar(mode)?;
                    parts.append(&mut got);
                }
                '~' if mode == Mode::Word && starts_word => {
                    self.bump();
                    let ends = self.peek().is_none_or(|n| is_meta(n) || n == '/');
                    if ends {
                        parts.push(WordPart::Tilde);
                    } else {
                        lit.push('~');
                    }
                }
                '{' if mode == Mode::Word => {
                    // dash has no brace expansion: `{a,b}` stays the text it is.
                    let expansion = if self.dialect == Dialect::Bash {
                        self.brace_expansion_len()
                    } else {
                        None
                    };
                    if let Some(len) = expansion {
                        flush(&mut lit, &mut parts);
                        self.advance_bytes(len);
                        parts.push(WordPart::Unsupported(UnsupportedKind::BraceExpansion));
                    } else {
                        self.bump();
                        lit.push('{');
                    }
                }
                other => {
                    self.bump();
                    lit.push(other);
                }
            }
        }
        flush(&mut lit, &mut parts);
        Ok(parts)
    }

    /// Run `f` one nesting level deeper, refusing past the cap.
    fn nested<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, LexError>,
    ) -> Result<T, LexError> {
        if self.depth >= self.max_depth {
            return Err(LexError::TooDeep);
        }
        self.depth = self.depth.saturating_add(1);
        let result = f(self);
        self.depth = self.depth.saturating_sub(1);
        result
    }

    /// Parse the text of a substitution closed by `closer` (`)` or a backtick). dash's parser
    /// reads the substitution inline, so the closer is the token it meets where the text stops
    /// short, and the one every other complaint inside says it was waiting for.
    fn nested_parse(&mut self, text: &str, closer: &'static str) -> Result<List, LexError> {
        if self.depth >= self.max_depth {
            return Err(LexError::TooDeep);
        }
        let line = self.base_line.saturating_add(self.line).saturating_sub(1);
        let parsed = super::parse::parse_nested(
            text,
            line,
            self.depth.saturating_add(1),
            self.max_depth,
            self.dialect,
            self.budget,
        );
        match parsed {
            Err(LexError::Syntax(mut error)) if self.dialect == Dialect::Posix => {
                if error.near == Near::EndOfFile {
                    error.near = Near::Token(closer.to_string());
                } else if error.expecting.is_none() && !matches!(error.near, Near::Message(_)) {
                    error.expecting = Some(if closer == ")" { "\")\"" } else { "\"`\"" });
                }
                Err(LexError::Syntax(error))
            }
            other => other,
        }
    }

    /// The text of a backtick command substitution, with the backslash escapes it allows removed.
    fn backtick_body(&mut self) -> Result<String, LexError> {
        let mut body = String::new();
        loop {
            match self.bump() {
                None => return Err(self.incomplete_with("EOF in backquote substitution", '`')),
                Some('`') => return Ok(body),
                Some('\\') => match self.peek() {
                    Some(next @ ('$' | '`' | '\\')) => {
                        self.bump();
                        body.push(next);
                    }
                    Some(_) | None => body.push('\\'),
                },
                Some(other) => body.push(other),
            }
        }
    }

    /// What follows a `$` already consumed.
    fn dollar(&mut self, mode: Mode) -> Result<Vec<WordPart>, LexError> {
        let param = |name: ParamName| {
            vec![WordPart::Param(Param {
                name,
                default: None,
            })]
        };
        let Some(c) = self.peek() else {
            return Ok(vec![WordPart::Literal("$".to_string())]);
        };
        match c {
            '(' => {
                if self.peek_at(1) == Some('(')
                    && let Some(expr_len) = arith_len(self.src.get(self.i.saturating_add(2)..))
                {
                    self.bump();
                    self.bump();
                    let start = self.i;
                    self.advance_bytes(expr_len);
                    let expr = self.src.get(start..self.i).unwrap_or("").to_string();
                    self.bump();
                    self.bump();
                    return Ok(vec![WordPart::Arith(expr)]);
                }
                self.bump();
                let rest = self.src.get(self.i..).unwrap_or("");
                let Some(end) = scan_paren_end(rest) else {
                    // `$((` is dash's arithmetic opener, and it wants the `))`.
                    return Err(if rest.starts_with('(') {
                        self.incomplete_with("Missing '))'", ')')
                    } else if ends_inside_quote(rest) {
                        self.incomplete_with("Unterminated quoted string", '"')
                    } else {
                        self.incomplete_paren()
                    });
                };
                let inner = rest.get(..end).unwrap_or("").to_string();
                let list = self.nested_parse(&inner, ")")?;
                self.advance_bytes(end.saturating_add(1));
                Ok(vec![WordPart::CmdSub(list)])
            }
            '{' => {
                self.bump();
                self.braced_param()
            }
            '\'' if matches!(mode, Mode::Word | Mode::Brace) && self.dialect == Dialect::Bash => {
                self.bump();
                let mut escaped = false;
                loop {
                    match self.bump() {
                        None => return Err(self.incomplete()),
                        Some('\\') if !escaped => escaped = true,
                        Some('\'') if !escaped => break,
                        Some(_) => escaped = false,
                    }
                }
                Ok(vec![WordPart::Unsupported(UnsupportedKind::AnsiCQuote)])
            }
            '?' => {
                self.bump();
                Ok(param(ParamName::Status))
            }
            '$' => {
                self.bump();
                Ok(param(ParamName::Pid))
            }
            '!' => {
                self.bump();
                Ok(param(ParamName::Bang))
            }
            '#' => {
                self.bump();
                Ok(param(ParamName::Count))
            }
            '@' => {
                self.bump();
                Ok(param(ParamName::At))
            }
            '*' => {
                self.bump();
                Ok(param(ParamName::Star))
            }
            '-' => {
                self.bump();
                Ok(vec![WordPart::Unsupported(UnsupportedKind::ParamOp)])
            }
            d if d.is_ascii_digit() => {
                self.bump();
                let n = usize::from(u8::try_from(d).unwrap_or(b'0').saturating_sub(b'0'));
                Ok(param(if n == 0 {
                    ParamName::Zero
                } else {
                    ParamName::Positional(n)
                }))
            }
            a if a.is_ascii_alphabetic() || a == '_' => {
                let mut name = String::new();
                while let Some(n) = self.peek() {
                    if n.is_ascii_alphanumeric() || n == '_' {
                        name.push(n);
                        self.bump();
                    } else {
                        break;
                    }
                }
                Ok(param(ParamName::Var(name)))
            }
            _ => Ok(vec![WordPart::Literal("$".to_string())]),
        }
    }

    /// After `${`: a plain name, a `:-`/`-` default, or something outside the subset.
    fn braced_param(&mut self) -> Result<Vec<WordPart>, LexError> {
        let mut name = String::new();
        let first = self.peek();
        let parsed = match first {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                while let Some(n) = self.peek() {
                    if n.is_ascii_alphanumeric() || n == '_' {
                        name.push(n);
                        self.bump();
                    } else {
                        break;
                    }
                }
                Some(ParamName::Var(name))
            }
            Some(c) if c.is_ascii_digit() => {
                while let Some(n) = self.peek().filter(char::is_ascii_digit) {
                    name.push(n);
                    self.bump();
                }
                let n = name.parse::<usize>().unwrap_or(usize::MAX);
                Some(if n == 0 {
                    ParamName::Zero
                } else {
                    ParamName::Positional(n)
                })
            }
            Some(c @ ('?' | '$' | '!' | '@' | '*')) => {
                self.bump();
                Some(match c {
                    '?' => ParamName::Status,
                    '$' => ParamName::Pid,
                    '!' => ParamName::Bang,
                    '@' => ParamName::At,
                    _ => ParamName::Star,
                })
            }
            Some('#') if self.peek_at(1) == Some('}') => {
                self.bump();
                Some(ParamName::Count)
            }
            _ => None,
        };
        let unsupported = |lexer: &mut Self, named: bool| -> Result<Vec<WordPart>, LexError> {
            // dash refuses a `${` its parser cannot read (`${}`, `${a:1}`, `${a/x/y}`, `${a,,}`)
            // when the word is expanded.
            let bad = lexer.dialect == Dialect::Posix && !lexer.dash_param_op_follows(named);
            lexer.skip_braced()?;
            Ok(vec![WordPart::Unsupported(if bad {
                UnsupportedKind::BadSubstitution
            } else {
                UnsupportedKind::ParamOp
            })])
        };
        let Some(name) = parsed else {
            return unsupported(self, false);
        };
        match self.peek() {
            Some('}') => {
                self.bump();
                Ok(vec![WordPart::Param(Param {
                    name,
                    default: None,
                })])
            }
            Some(':') if self.peek_at(1) == Some('-') => {
                self.bump();
                self.bump();
                self.param_default(name, true)
            }
            Some('-') => {
                self.bump();
                self.param_default(name, false)
            }
            _ => unsupported(self, true),
        }
    }

    /// Whether the text just after `${` (or after `${name`, when `named`) is a form dash's parser
    /// reads, so that only the forms it refuses are `Bad substitution`.
    fn dash_param_op_follows(&self, named: bool) -> bool {
        let rest = self.src.get(self.i..).unwrap_or("");
        let mut chars = rest.chars();
        if named {
            return match chars.next() {
                Some('#' | '%' | '=' | '?' | '+') => true,
                Some(':') => matches!(chars.next(), Some('-' | '=' | '?' | '+')),
                _ => false,
            };
        }
        match chars.next() {
            Some('#') => chars.next().is_some_and(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '_' | '?' | '$' | '!' | '@' | '*' | '#' | '-')
            }),
            Some('-') => chars.next() == Some('}'),
            _ => false,
        }
    }

    fn param_default(&mut self, name: ParamName, colon: bool) -> Result<Vec<WordPart>, LexError> {
        let start = self.i;
        let parts = self.nested(|lexer| lexer.scan_parts(Mode::Brace))?;
        if self.peek() != Some('}') {
            return Err(self.incomplete_with("Missing '}'", '}'));
        }
        let raw = self.src.get(start..self.i).unwrap_or("").to_string();
        self.bump();
        Ok(vec![WordPart::Param(Param {
            name,
            default: Some(ParamDefault {
                colon,
                word: Word { parts, raw },
            }),
        })])
    }

    /// Consume through the `}` closing a `${` already consumed.
    fn skip_braced(&mut self) -> Result<(), LexError> {
        let mut depth = 1u32;
        loop {
            match self.bump() {
                None => return Err(self.incomplete_with("Missing '}'", '}')),
                Some('\\') => {
                    self.bump();
                }
                Some('\'') => {
                    let rest = self.src.get(self.i..).unwrap_or("");
                    let Some(end) = rest.find('\'') else {
                        return Err(self.incomplete());
                    };
                    self.advance_bytes(end.saturating_add(1));
                }
                Some('"') => loop {
                    match self.bump() {
                        None => return Err(self.incomplete()),
                        Some('\\') => {
                            self.bump();
                        }
                        Some('"') => break,
                        Some(_) => {}
                    }
                },
                Some('{') => depth = depth.saturating_add(1),
                Some('}') => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Ok(());
                    }
                }
                Some(_) => {}
            }
        }
    }

    /// The byte length of a brace expansion (`{a,b}`, `{1..3}`) starting at the current `{`, or
    /// `None` when it is a plain brace (`{}`, `{a}`, a lone `{`).
    fn brace_expansion_len(&self) -> Option<usize> {
        let rest = self.src.get(self.i..)?;
        let mut depth = 0u32;
        let mut comma = false;
        let mut dots = false;
        let mut prev = '\0';
        let mut chars = rest.char_indices();
        while let Some((offset, c)) = chars.next() {
            match c {
                '\\' => {
                    chars.next();
                }
                '\'' | '"' => {
                    for (_, q) in chars.by_ref() {
                        if q == c {
                            break;
                        }
                    }
                }
                '{' => depth = depth.saturating_add(1),
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return (comma || dots).then(|| offset.saturating_add(1));
                    }
                }
                ',' if depth == 1 => comma = true,
                '.' if depth == 1 && prev == '.' => dots = true,
                c if is_meta(c) => return None,
                _ => {}
            }
            prev = c;
        }
        None
    }
}

/// Whether `text` (a word's leading literal) is `NAME=` or `NAME+=`, the start of an array value.
fn is_array_assignment(text: &str) -> bool {
    let name = text
        .strip_suffix("+=")
        .or_else(|| text.strip_suffix('='))
        .unwrap_or("");
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

/// Gather a here-document delimiter's text with its quoting removed, noting whether any of it was
/// quoted.
fn collect_delimiter(parts: &[WordPart], out: &mut String, quoted: &mut bool) {
    for part in parts {
        match part {
            WordPart::Literal(text) => out.push_str(text),
            WordPart::Quoted(text) => {
                *quoted = true;
                out.push_str(text);
            }
            WordPart::DoubleQuoted(inner) => {
                *quoted = true;
                collect_delimiter(inner, out, &mut false);
            }
            _ => {}
        }
    }
}

/// The offset of the `)` that closes a `(` or `$(` just consumed, reading `rest` from just after
/// it. Quotes, backslashes, backticks and nested parentheses are respected; `case` patterns are
/// not, a limit accepted for a construct outside the subset.
fn scan_paren_end(rest: &str) -> Option<usize> {
    let mut depth = 1u32;
    let mut single = false;
    let mut double = false;
    let mut prev = '\0';
    let mut chars = rest.char_indices();
    while let Some((offset, c)) = chars.next() {
        if single {
            single = c != '\'';
            prev = c;
            continue;
        }
        match c {
            '\\' => {
                chars.next();
                prev = '\0';
                continue;
            }
            '\'' if !double => single = true,
            '"' => double = !double,
            '`' => {
                for (_, q) in chars.by_ref() {
                    if q == '`' {
                        break;
                    }
                }
            }
            '(' if prev == '$' || !double => depth = depth.saturating_add(1),
            ')' if !double => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
        prev = c;
    }
    None
}

/// Whether `rest`, the text of an unclosed `$(`, stops inside a quote.
fn ends_inside_quote(rest: &str) -> bool {
    let (mut single, mut double) = (false, false);
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if !single => {
                chars.next();
            }
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            _ => {}
        }
    }
    single || double
}

/// The length of the expression in `$(( expr ))` when `rest` (just after `$((`) closes with `))`.
/// `None` when the closing parenthesis is a single one, which makes it a command substitution
/// around a subshell.
fn arith_len(rest: Option<&str>) -> Option<usize> {
    let rest = rest?;
    let mut depth = 0u32;
    let mut chars = rest.char_indices().peekable();
    while let Some((offset, c)) = chars.next() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => {
                if depth == 0 {
                    return matches!(chars.peek(), Some((_, ')'))).then_some(offset);
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn lexed(src: &str) -> Lexed {
        let mut budget = LineBudget::new(1 << 20);
        lex(src, true, 1, 0, 16, Dialect::Bash, &mut budget).unwrap()
    }

    fn words(src: &str) -> Vec<Vec<WordPart>> {
        lexed(src)
            .tokens
            .into_iter()
            .filter_map(|t| match t.tok {
                Tok::Word(w) => Some(w.parts),
                _ => None,
            })
            .collect()
    }

    fn lit(s: &str) -> WordPart {
        WordPart::Literal(s.to_string())
    }

    fn quoted(s: &str) -> WordPart {
        WordPart::Quoted(s.to_string())
    }

    #[test]
    fn single_quotes_are_literal_and_double_quotes_keep_their_parts() {
        assert_eq!(
            words("'a $b `c`' x"),
            vec![vec![quoted("a $b `c`")], vec![lit("x")]]
        );
        let w = words("\"a $b\"");
        assert!(matches!(w[0][0], WordPart::DoubleQuoted(_)));
    }

    #[test]
    fn backslash_escapes_one_byte_and_double_quotes_escape_only_the_special_four() {
        assert_eq!(words("a\\ b"), vec![vec![lit("a"), quoted(" "), lit("b")]]);
        let w = words("\"\\$x \\q\"");
        let WordPart::DoubleQuoted(inner) = &w[0][0] else {
            panic!("not a double-quoted part");
        };
        assert_eq!(inner, &vec![lit("$x \\q")]);
    }

    #[test]
    fn a_backslash_newline_is_a_line_continuation() {
        assert_eq!(words("ec\\\nho"), vec![vec![lit("echo")]]);
    }

    #[test]
    fn operators_are_recognised_greedily() {
        let ops: Vec<Op> = lexed("a&&b||c|d;e&f;;(g)>h>>i<j<&0>&2>|k<>l")
            .tokens
            .into_iter()
            .filter_map(|t| match t.tok {
                Tok::Op(op) => Some(op),
                _ => None,
            })
            .collect();
        assert_eq!(
            ops,
            vec![
                Op::AndIf,
                Op::OrIf,
                Op::Pipe,
                Op::Semi,
                Op::Amp,
                Op::DSemi,
                Op::LParen,
                Op::RParen,
                Op::Great,
                Op::DGreat,
                Op::Less,
                Op::LessAnd,
                Op::GreatAnd,
                Op::Clobber,
                Op::LessGreat,
            ]
        );
    }

    #[test]
    fn a_digit_run_before_a_redirection_is_a_descriptor_and_otherwise_a_word() {
        let toks = lexed("2>&1 x2>y 12 34>z").tokens;
        assert!(matches!(toks[0].tok, Tok::IoNumber(2)));
        assert!(matches!(toks[1].tok, Tok::Op(Op::GreatAnd)));
        assert!(matches!(&toks[2].tok, Tok::Word(_)), "1 is the target word");
        // `x2>y` is the word x2 then a redirection, and `12` is a word.
        assert!(matches!(&toks[3].tok, Tok::Word(_)));
        assert!(matches!(toks[4].tok, Tok::Op(Op::Great)));
        assert!(matches!(&toks[6].tok, Tok::Word(w) if w.raw == "12"));
        assert!(matches!(toks[7].tok, Tok::IoNumber(34)));
    }

    #[test]
    fn hash_starts_a_comment_only_at_the_start_of_a_word() {
        assert_eq!(words("a#b c #d e"), vec![vec![lit("a#b")], vec![lit("c")]]);
        assert_eq!(words("# only"), Vec::<Vec<WordPart>>::new());
    }

    #[test]
    fn a_leading_tilde_is_its_own_part() {
        assert_eq!(words("~/x"), vec![vec![WordPart::Tilde, lit("/x")]]);
        assert_eq!(words("~"), vec![vec![WordPart::Tilde]]);
        assert_eq!(words("a~"), vec![vec![lit("a~")]]);
        assert_eq!(words("~root"), vec![vec![lit("~root")]]);
    }

    #[test]
    fn expansions_become_parts() {
        let w = words("$a ${b} ${c:-d e} $? $$ $0 $# $1 $((1+2)) $(id) `id`");
        let kinds: Vec<&str> = w
            .iter()
            .map(|parts| match &parts[0] {
                WordPart::Param(p) if p.default.is_some() => "default",
                WordPart::Param(_) => "param",
                WordPart::Arith(_) => "arith",
                WordPart::CmdSub(_) => "cmdsub",
                _ => "other",
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                "param", "param", "default", "param", "param", "param", "param", "param", "arith",
                "cmdsub", "cmdsub"
            ]
        );
    }

    #[test]
    fn every_unsupported_construct_lexes_to_an_unsupported_part() {
        for (src, kind) in [
            ("$'a\\nb'", UnsupportedKind::AnsiCQuote),
            ("${x##*/}", UnsupportedKind::ParamOp),
            ("${x:=y}", UnsupportedKind::ParamOp),
            ("{a,b}", UnsupportedKind::BraceExpansion),
            ("{1..3}", UnsupportedKind::BraceExpansion),
            ("a=(1 2)", UnsupportedKind::Array),
            ("<(id)", UnsupportedKind::ProcessSubstitution),
        ] {
            let w = words(src);
            assert!(
                w[0].contains(&WordPart::Unsupported(kind)),
                "{src}: {:?}",
                w[0]
            );
        }
        // Plain braces are ordinary text.
        assert_eq!(words("{}"), vec![vec![lit("{}")]]);
        assert_eq!(words("{a}"), vec![vec![lit("{a}")]]);
    }

    #[test]
    fn a_here_document_body_is_read_after_the_newline_and_never_lexed() {
        let l = lexed("cat <<EOF\nid; rm -rf /\nEOF\necho after");
        assert_eq!(l.heredocs[0].text, "id; rm -rf /\n");
        assert!(l.heredocs[0].expand);
        let word_count = l
            .tokens
            .iter()
            .filter(|t| matches!(t.tok, Tok::Word(_)))
            .count();
        // cat, EOF, echo, after: the body's words are not tokens.
        assert_eq!(word_count, 4);

        let quoted = lexed("cat <<'EOF'\n$x\nEOF\n");
        assert!(!quoted.heredocs[0].expand);
        let stripped = lexed("cat <<-EOF\n\t\tone\n\tEOF\n");
        assert_eq!(stripped.heredocs[0].text, "one\n");
    }

    #[test]
    fn incomplete_input_asks_for_more_and_complete_text_does_not() {
        let mut b = LineBudget::new(1 << 20);
        for src in [
            "echo 'a",
            "echo \"a",
            "echo $(id",
            "echo `id",
            "cat <<E",
            "echo a\\",
            "echo ${a",
        ] {
            assert_eq!(
                lex(src, false, 1, 0, 16, Dialect::Bash, &mut b).unwrap_err(),
                LexError::NeedMore,
                "{src}"
            );
            // At the end of a script a here-document is empty and a trailing backslash is a
            // literal one; everything else is unterminated.
            if !matches!(src, "cat <<E" | "echo a\\") {
                let error = lex(src, true, 1, 0, 16, Dialect::Bash, &mut b).unwrap_err();
                assert!(matches!(error, LexError::Syntax(_)), "{src}");
            }
        }
        // A here-document with no body at the very end of a script is an empty one.
        assert_eq!(
            lex("cat <<E", true, 1, 0, 16, Dialect::Bash, &mut b)
                .unwrap()
                .heredocs[0]
                .text,
            ""
        );
        assert!(lex("echo 'a'", false, 1, 0, 16, Dialect::Bash, &mut b).is_ok());
    }

    #[test]
    fn nesting_past_the_depth_cap_is_refused() {
        let mut b = LineBudget::new(1 << 20);
        let src = format!("{}id{}", "$(".repeat(20), ")".repeat(20));
        assert_eq!(
            lex(&src, true, 1, 0, 16, Dialect::Bash, &mut b).unwrap_err(),
            LexError::TooDeep
        );
    }
}
