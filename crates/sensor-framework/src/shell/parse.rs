//! The recursive-descent parser: tokens to the syntax tree, lowest to highest binding
//!
//! ```text
//! program  := list
//! list     := and_or (( ';' | '&' | newline ) and_or)*
//! and_or   := pipeline (( '&&' | '||' ) newline* pipeline)*
//! pipeline := '!'? command ( '|' newline* command )*
//! command  := simple | '(' list ')' | '{' list '}' | if | for | while | until | unsupported
//! ```
//!
//! Redirections attach to the command they follow. A construct outside the subset (`case`,
//! `[[ ]]`, a function definition, `((..))`, a here-string, a word the lexer marked unsupported)
//! is consumed to a safe boundary and returned as [`Command::Unsupported`], never as an error.
//! What is left as an error is what bash and dash also reject: a stray `)` or `;`, a reserved word
//! where a command must start, a redirection with no target.
//!
//! Text that ends inside a construct is [`Tail::NeedMore`] while more input may arrive.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::ast::{
    AndOr, AndOrOp, Assign, Command, Line, List, ListItem, Near, Pipeline, Redir, RedirOp,
    RedirTarget, SimpleCommand, SyntaxError, UnsupportedKind, Word, WordPart, word_unsupported,
};
use super::eval::LineBudget;
use super::lex::{HereDoc, LexError, Op, Tok, Token, lex};

/// What was left of the text after the items that parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Tail {
    Done,
    /// The text ends inside a construct; another line may complete it.
    NeedMore,
    Error(SyntaxError),
    /// Nesting past the depth cap.
    TooDeep,
    /// The line's work allowance ran out while parsing.
    Budget,
}

#[derive(Debug)]
pub(super) struct Parsed {
    /// The items parsed before any error, in order.
    pub items: Vec<ListItem>,
    pub tail: Tail,
}

/// Parse one unit of input. `at_eof` says no more lines will follow; `base_line` is the number the
/// unit's first line has in its shell.
pub(super) fn parse_unit(
    src: &str,
    at_eof: bool,
    max_depth: u32,
    budget: &mut LineBudget,
    base_line: Line,
) -> Parsed {
    let lexed = match lex(src, at_eof, base_line, 0, max_depth, budget) {
        Ok(lexed) => lexed,
        Err(LexError::NeedMore) => {
            return Parsed {
                items: Vec::new(),
                tail: Tail::NeedMore,
            };
        }
        Err(LexError::Syntax(error)) => {
            return Parsed {
                items: Vec::new(),
                tail: Tail::Error(error),
            };
        }
        Err(LexError::TooDeep) => {
            return Parsed {
                items: Vec::new(),
                tail: Tail::TooDeep,
            };
        }
        Err(LexError::Budget) => {
            return Parsed {
                items: Vec::new(),
                tail: Tail::Budget,
            };
        }
    };
    let mut parser = Parser {
        toks: &lexed.tokens,
        heredocs: &lexed.heredocs,
        pos: 0,
        depth: 0,
        max_depth,
        base_line,
    };
    let (items, outcome) = parser.program();
    let tail = match outcome {
        Ok(()) => Tail::Done,
        Err(PErr::Need) if at_eof => Tail::Error(SyntaxError {
            near: Near::EndOfFile,
            line: last_line(&lexed.tokens),
        }),
        Err(PErr::Need) => Tail::NeedMore,
        Err(PErr::Syntax(error)) => Tail::Error(error),
        Err(PErr::TooDeep) => Tail::TooDeep,
    };
    Parsed { items, tail }
}

/// Parse the text inside a `$( )` or backtick pair, which is complete by construction.
pub(super) fn parse_nested(
    text: &str,
    base_line: Line,
    depth: u32,
    max_depth: u32,
    budget: &mut LineBudget,
) -> Result<List, LexError> {
    if depth > max_depth {
        return Err(LexError::TooDeep);
    }
    let lexed = lex(text, true, base_line, depth, max_depth, budget)?;
    let mut parser = Parser {
        toks: &lexed.tokens,
        heredocs: &lexed.heredocs,
        pos: 0,
        depth,
        max_depth,
        base_line,
    };
    let (items, outcome) = parser.program();
    match outcome {
        Ok(()) => Ok(List { items }),
        Err(PErr::Syntax(error)) => Err(LexError::Syntax(error)),
        Err(PErr::Need) => Err(LexError::Syntax(SyntaxError {
            near: Near::EndOfFile,
            line: last_line(&lexed.tokens),
        })),
        Err(PErr::TooDeep) => Err(LexError::TooDeep),
    }
}

fn last_line(tokens: &[Token]) -> Line {
    tokens.last().map_or(1, |t| t.line)
}

#[derive(Debug)]
enum PErr {
    /// The tokens end before the construct does.
    Need,
    Syntax(SyntaxError),
    TooDeep,
}

type PResult<T> = Result<T, PErr>;

/// Where a list stops.
#[derive(Clone, Copy)]
enum Stop {
    Words(&'static [&'static str]),
    RParen,
}

struct Parser<'a> {
    toks: &'a [Token],
    heredocs: &'a [HereDoc],
    pos: usize,
    depth: u32,
    max_depth: u32,
    base_line: Line,
}

/// The reserved word a token spells, when it is one unquoted literal.
fn keyword(tok: &Token) -> Option<&str> {
    match &tok.tok {
        Tok::Word(Word { parts, .. }) => match parts.as_slice() {
            [WordPart::Literal(text)] => Some(text.as_str()),
            _ => None,
        },
        _ => None,
    }
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with(|c: char| c.is_ascii_digit())
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }

    fn peek_ahead(&self, n: usize) -> Option<&Token> {
        self.toks.get(self.pos.saturating_add(n))
    }

    fn peek_op(&self) -> Option<Op> {
        match self.peek()?.tok {
            Tok::Op(op) => Some(op),
            _ => None,
        }
    }

    fn peek_keyword(&self) -> Option<&str> {
        self.peek().and_then(keyword)
    }

    fn line_of(&self, tok: &Token) -> Line {
        self.base_line.saturating_add(tok.line).saturating_sub(1)
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek().map(|t| &t.tok), Some(Tok::Newline)) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    /// The error for a token that cannot appear here. Running out of tokens is not an error: more
    /// may come.
    fn unexpected(&self) -> PErr {
        match self.peek() {
            None => PErr::Need,
            Some(tok) => PErr::Syntax(SyntaxError {
                near: match &tok.tok {
                    Tok::Newline => Near::Newline,
                    Tok::Op(op) => Near::Token(op.text().to_string()),
                    Tok::Word(word) => Near::Token(word.raw.clone()),
                    Tok::IoNumber(n) => Near::Token(n.to_string()),
                },
                line: tok.line,
            }),
        }
    }

    /// A redirection with no target is a complaint about the end of the line, as bash words it,
    /// not a request for more input.
    fn missing_target(&self) -> PErr {
        match self.peek() {
            None => PErr::Syntax(SyntaxError {
                near: Near::Newline,
                line: last_line(self.toks),
            }),
            Some(_) => self.unexpected(),
        }
    }

    fn enter(&mut self) -> PResult<()> {
        if self.depth >= self.max_depth {
            return Err(PErr::TooDeep);
        }
        self.depth = self.depth.saturating_add(1);
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn expect_keyword(&mut self, word: &str) -> PResult<()> {
        if self.peek_keyword() == Some(word) {
            self.pos = self.pos.saturating_add(1);
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    // ---- lists -------------------------------------------------------------------------------

    /// The whole text: every complete item, then how it ended.
    fn program(&mut self) -> (Vec<ListItem>, PResult<()>) {
        let mut items = Vec::new();
        loop {
            self.skip_newlines();
            if self.peek().is_none() {
                return (items, Ok(()));
            }
            match self.list_item() {
                Ok(item) => items.push(item),
                Err(error) => return (items, Err(error)),
            }
        }
    }

    /// One and-or chain and the separator that ends it.
    fn list_item(&mut self) -> PResult<ListItem> {
        let and_or = self.and_or()?;
        let (background, end_line) = match self.peek() {
            None => (false, last_line(self.toks)),
            Some(tok) => {
                let line = tok.line;
                match tok.tok {
                    Tok::Newline | Tok::Op(Op::Semi) => {
                        self.pos = self.pos.saturating_add(1);
                        (false, line)
                    }
                    Tok::Op(Op::Amp) => {
                        self.pos = self.pos.saturating_add(1);
                        (true, line)
                    }
                    _ => return Err(self.unexpected()),
                }
            }
        };
        Ok(ListItem {
            and_or,
            background,
            end_line,
        })
    }

    /// A nested list up to `stop`, which is left unconsumed. It must not be empty.
    fn list(&mut self, stop: Stop) -> PResult<List> {
        let mut items = Vec::new();
        loop {
            self.skip_newlines();
            let Some(tok) = self.peek() else {
                return Err(PErr::Need);
            };
            let at_stop = match stop {
                Stop::Words(words) => keyword(tok).is_some_and(|k| words.contains(&k)),
                Stop::RParen => matches!(tok.tok, Tok::Op(Op::RParen)),
            };
            if at_stop {
                if items.is_empty() {
                    return Err(self.unexpected());
                }
                return Ok(List { items });
            }
            let and_or = self.and_or()?;
            let (background, end_line) = match self.peek() {
                None => return Err(PErr::Need),
                Some(tok) => {
                    let line = tok.line;
                    match tok.tok {
                        Tok::Newline | Tok::Op(Op::Semi) => {
                            self.pos = self.pos.saturating_add(1);
                            (false, line)
                        }
                        Tok::Op(Op::Amp) => {
                            self.pos = self.pos.saturating_add(1);
                            (true, line)
                        }
                        // The stop token itself ends the item: `( a )`.
                        Tok::Op(Op::RParen) if matches!(stop, Stop::RParen) => (false, line),
                        _ => {
                            let closes = match stop {
                                Stop::Words(words) => {
                                    self.peek_keyword().is_some_and(|k| words.contains(&k))
                                }
                                Stop::RParen => false,
                            };
                            if !closes {
                                return Err(self.unexpected());
                            }
                            (false, line)
                        }
                    }
                }
            };
            items.push(ListItem {
                and_or,
                background,
                end_line,
            });
        }
    }

    fn and_or(&mut self) -> PResult<AndOr> {
        let first = self.pipeline()?;
        let mut rest = Vec::new();
        loop {
            let op = match self.peek_op() {
                Some(Op::AndIf) => AndOrOp::And,
                Some(Op::OrIf) => AndOrOp::Or,
                _ => break,
            };
            self.pos = self.pos.saturating_add(1);
            self.skip_newlines();
            if self.peek().is_none() {
                return Err(PErr::Need);
            }
            rest.push((op, self.pipeline()?));
        }
        Ok(AndOr { first, rest })
    }

    fn pipeline(&mut self) -> PResult<Pipeline> {
        let mut bang = false;
        if self.peek_keyword() == Some("!") {
            self.pos = self.pos.saturating_add(1);
            bang = true;
            if self.peek().is_none() {
                return Err(PErr::Need);
            }
        }
        let mut stages = vec![self.command()?];
        loop {
            let with_stderr = match self.peek_op() {
                Some(Op::Pipe) => false,
                Some(Op::PipeAmp) => true,
                _ => break,
            };
            self.pos = self.pos.saturating_add(1);
            if with_stderr && let Some(previous) = stages.last_mut() {
                add_stderr_merge(previous);
            }
            self.skip_newlines();
            if self.peek().is_none() {
                return Err(PErr::Need);
            }
            stages.push(self.command()?);
        }
        Ok(Pipeline { bang, stages })
    }

    // ---- commands ----------------------------------------------------------------------------

    fn command(&mut self) -> PResult<Command> {
        let Some(tok) = self.peek() else {
            return Err(PErr::Need);
        };
        match &tok.tok {
            Tok::Word(_) => match keyword(tok) {
                Some("if") => self.if_command(),
                Some("for") => self.for_command(),
                Some("while") => self.while_command(false),
                Some("until") => self.while_command(true),
                Some("{") => self.brace_command(),
                Some("case") => self.skip_case(),
                Some("[[") => self.skip_double_bracket(),
                Some("function") => self.function_keyword(),
                Some("coproc") => self.skip_coproc(),
                Some("then" | "do" | "done" | "fi" | "elif" | "else" | "esac" | "}") => {
                    Err(self.unexpected())
                }
                _ => self.simple_command(),
            },
            Tok::IoNumber(_) => self.simple_command(),
            Tok::Op(Op::LParen) => self.subshell(),
            Tok::Op(
                Op::Less
                | Op::Great
                | Op::DGreat
                | Op::LessAnd
                | Op::GreatAnd
                | Op::LessGreat
                | Op::Clobber
                | Op::DLess { .. }
                | Op::TLess,
            ) => self.simple_command(),
            _ => Err(self.unexpected()),
        }
    }

    fn simple_command(&mut self) -> PResult<Command> {
        let line = self.peek().map_or(1, |t| self.line_of(t));
        let mut assigns: Vec<Assign> = Vec::new();
        let mut words: Vec<Word> = Vec::new();
        let mut redirs: Vec<Redir> = Vec::new();
        let mut unsupported: Option<UnsupportedKind> = None;
        while let Some(tok) = self.peek() {
            match &tok.tok {
                Tok::Word(word) => {
                    let word = word.clone();
                    if words.is_empty()
                        && let Some(assign) = split_assignment(&word)
                    {
                        assigns.push(assign);
                        self.pos = self.pos.saturating_add(1);
                        continue;
                    }
                    self.pos = self.pos.saturating_add(1);
                    words.push(word);
                    if words.len() == 1
                        && assigns.is_empty()
                        && matches!(self.peek_op(), Some(Op::LParen))
                        && matches!(
                            self.peek_ahead(1).map(|t| &t.tok),
                            Some(Tok::Op(Op::RParen))
                        )
                    {
                        return self.function_definition();
                    }
                }
                Tok::IoNumber(n) => {
                    let fd = *n;
                    self.pos = self.pos.saturating_add(1);
                    if let Some(redir) = self.redirection(Some(fd), &mut unsupported)? {
                        redirs.push(redir);
                    }
                }
                Tok::Op(
                    Op::Less
                    | Op::Great
                    | Op::DGreat
                    | Op::LessAnd
                    | Op::GreatAnd
                    | Op::LessGreat
                    | Op::Clobber
                    | Op::DLess { .. }
                    | Op::TLess,
                ) => {
                    if let Some(redir) = self.redirection(None, &mut unsupported)? {
                        redirs.push(redir);
                    }
                }
                _ => break,
            }
        }
        if unsupported.is_none() {
            unsupported = words
                .iter()
                .chain(assigns.iter().map(|a| &a.value))
                .find_map(word_unsupported);
        }
        if let Some(kind) = unsupported {
            return Ok(Command::Unsupported(kind));
        }
        Ok(Command::Simple(SimpleCommand {
            assigns,
            words,
            redirs,
            line,
        }))
    }

    /// One redirection, its operator (and descriptor, if any) at the current position. A
    /// here-string is consumed and recorded as unsupported.
    fn redirection(
        &mut self,
        fd: Option<u16>,
        unsupported: &mut Option<UnsupportedKind>,
    ) -> PResult<Option<Redir>> {
        let Some(op) = self.peek_op() else {
            return Err(self.unexpected());
        };
        self.pos = self.pos.saturating_add(1);
        let target = match self.peek() {
            Some(Token {
                tok: Tok::Word(word),
                ..
            }) => word.clone(),
            _ => return Err(self.missing_target()),
        };
        self.pos = self.pos.saturating_add(1);
        let redir_op = match op {
            Op::Less => RedirOp::In,
            Op::Great => RedirOp::Out,
            Op::DGreat => RedirOp::Append,
            Op::Clobber => RedirOp::Clobber,
            Op::LessAnd => RedirOp::DupIn,
            Op::GreatAnd => RedirOp::DupOut,
            Op::LessGreat => RedirOp::ReadWrite,
            Op::DLess { idx } => {
                let body = self.heredocs.get(idx).cloned().unwrap_or_default();
                return Ok(Some(Redir {
                    fd,
                    op: RedirOp::HereDoc,
                    target: RedirTarget::HereBody {
                        text: body.text,
                        expand: body.expand,
                    },
                }));
            }
            Op::TLess => {
                unsupported.get_or_insert(UnsupportedKind::HereString);
                return Ok(None);
            }
            _ => return Err(self.unexpected()),
        };
        Ok(Some(Redir {
            fd,
            op: redir_op,
            target: RedirTarget::Word(target),
        }))
    }

    fn redirections(&mut self) -> PResult<Vec<Redir>> {
        let mut redirs = Vec::new();
        let mut ignored = None;
        loop {
            let fd = match self.peek().map(|t| &t.tok) {
                Some(Tok::IoNumber(n)) => {
                    let fd = *n;
                    self.pos = self.pos.saturating_add(1);
                    Some(fd)
                }
                Some(Tok::Op(
                    Op::Less
                    | Op::Great
                    | Op::DGreat
                    | Op::LessAnd
                    | Op::GreatAnd
                    | Op::LessGreat
                    | Op::Clobber
                    | Op::DLess { .. }
                    | Op::TLess,
                )) => None,
                _ => return Ok(redirs),
            };
            if let Some(redir) = self.redirection(fd, &mut ignored)? {
                redirs.push(redir);
            }
        }
    }

    fn if_command(&mut self) -> PResult<Command> {
        self.enter()?;
        let result = self.if_inner();
        self.leave();
        result
    }

    fn if_inner(&mut self) -> PResult<Command> {
        self.pos = self.pos.saturating_add(1);
        let cond = self.list(Stop::Words(&["then"]))?;
        self.expect_keyword("then")?;
        let then = self.list(Stop::Words(&["elif", "else", "fi"]))?;
        let mut elifs = Vec::new();
        let mut els = None;
        loop {
            match self.peek_keyword() {
                Some("elif") => {
                    self.pos = self.pos.saturating_add(1);
                    let cond = self.list(Stop::Words(&["then"]))?;
                    self.expect_keyword("then")?;
                    let body = self.list(Stop::Words(&["elif", "else", "fi"]))?;
                    elifs.push((cond, body));
                }
                Some("else") => {
                    self.pos = self.pos.saturating_add(1);
                    els = Some(self.list(Stop::Words(&["fi"]))?);
                    self.expect_keyword("fi")?;
                    break;
                }
                _ => {
                    self.expect_keyword("fi")?;
                    break;
                }
            }
        }
        let redirs = self.redirections()?;
        Ok(Command::If {
            cond,
            then,
            elifs,
            els,
            redirs,
        })
    }

    fn for_command(&mut self) -> PResult<Command> {
        self.enter()?;
        let result = self.for_inner();
        self.leave();
        result
    }

    fn for_inner(&mut self) -> PResult<Command> {
        self.pos = self.pos.saturating_add(1);
        if matches!(self.peek_op(), Some(Op::LParen)) {
            return self.skip_arith_command(UnsupportedKind::ArithCommand);
        }
        let var = match self.peek() {
            None => return Err(PErr::Need),
            Some(tok) => match keyword(tok) {
                Some(name) if is_name(name) => name.to_string(),
                _ => return Err(self.unexpected()),
            },
        };
        self.pos = self.pos.saturating_add(1);
        let mut words = None;
        if self.peek_keyword() == Some("in") {
            self.pos = self.pos.saturating_add(1);
            let mut list = Vec::new();
            loop {
                match self.peek().map(|t| &t.tok) {
                    Some(Tok::Word(word)) => {
                        list.push(word.clone());
                        self.pos = self.pos.saturating_add(1);
                    }
                    Some(Tok::Newline | Tok::Op(Op::Semi)) => break,
                    None => return Err(PErr::Need),
                    Some(_) => return Err(self.unexpected()),
                }
            }
            words = Some(list);
        }
        if matches!(
            self.peek().map(|t| &t.tok),
            Some(Tok::Newline | Tok::Op(Op::Semi))
        ) {
            self.pos = self.pos.saturating_add(1);
        }
        self.skip_newlines();
        if self.peek().is_none() {
            return Err(PErr::Need);
        }
        self.expect_keyword("do")?;
        let body = self.list(Stop::Words(&["done"]))?;
        self.expect_keyword("done")?;
        let redirs = self.redirections()?;
        if let Some(list) = &words
            && let Some(kind) = list.iter().find_map(word_unsupported)
        {
            return Ok(Command::Unsupported(kind));
        }
        Ok(Command::For {
            var,
            words,
            body,
            redirs,
        })
    }

    fn while_command(&mut self, until: bool) -> PResult<Command> {
        self.enter()?;
        let result = self.while_inner(until);
        self.leave();
        result
    }

    fn while_inner(&mut self, until: bool) -> PResult<Command> {
        self.pos = self.pos.saturating_add(1);
        let cond = self.list(Stop::Words(&["do"]))?;
        self.expect_keyword("do")?;
        let body = self.list(Stop::Words(&["done"]))?;
        self.expect_keyword("done")?;
        let redirs = self.redirections()?;
        Ok(Command::While {
            cond,
            body,
            until,
            redirs,
        })
    }

    fn brace_command(&mut self) -> PResult<Command> {
        self.enter()?;
        let result = self.brace_inner();
        self.leave();
        result
    }

    fn brace_inner(&mut self) -> PResult<Command> {
        self.pos = self.pos.saturating_add(1);
        let body = self.list(Stop::Words(&["}"]))?;
        self.expect_keyword("}")?;
        let redirs = self.redirections()?;
        Ok(Command::Brace { body, redirs })
    }

    fn subshell(&mut self) -> PResult<Command> {
        self.enter()?;
        let result = self.subshell_inner();
        self.leave();
        result
    }

    fn subshell_inner(&mut self) -> PResult<Command> {
        let open = self.pos;
        // `((` with nothing between is an arithmetic command when it closes with `))`.
        if let (Some(a), Some(b)) = (self.peek(), self.peek_ahead(1))
            && matches!(b.tok, Tok::Op(Op::LParen))
            && a.end == b.pos
        {
            self.pos = self.pos.saturating_add(2);
            if self.find_arith_close() {
                return Ok(Command::Unsupported(UnsupportedKind::ArithCommand));
            }
            self.pos = open;
        }
        self.pos = self.pos.saturating_add(1);
        let body = self.list(Stop::RParen)?;
        self.pos = self.pos.saturating_add(1);
        let redirs = self.redirections()?;
        Ok(Command::Subshell { body, redirs })
    }

    /// Past the `((` just consumed: move to just after the `))` that closes it, if there is one.
    fn find_arith_close(&mut self) -> bool {
        let mut depth = 0u32;
        let mut at = self.pos;
        while let Some(tok) = self.toks.get(at) {
            match tok.tok {
                Tok::Op(Op::LParen) => depth = depth.saturating_add(1),
                Tok::Op(Op::RParen) => {
                    let adjacent = self.toks.get(at.saturating_add(1)).is_some_and(|next| {
                        matches!(next.tok, Tok::Op(Op::RParen)) && next.pos == tok.end
                    });
                    if depth == 0 && adjacent {
                        self.pos = at.saturating_add(2);
                        return true;
                    }
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
            at = at.saturating_add(1);
        }
        false
    }

    /// `for ((..))` after the `for`: consume the parenthesised header and the loop to `done`.
    fn skip_arith_command(&mut self, kind: UnsupportedKind) -> PResult<Command> {
        if matches!(self.peek_op(), Some(Op::LParen)) {
            self.pos = self.pos.saturating_add(1);
            if matches!(self.peek_op(), Some(Op::LParen)) {
                self.pos = self.pos.saturating_add(1);
            }
        }
        if !self.find_arith_close() {
            return Err(self.unexpected());
        }
        self.skip_to_matching("do", "done")?;
        Ok(Command::Unsupported(kind))
    }

    /// Skip tokens until the `close` keyword that balances the `open` keyword seen (or, when no
    /// `open` has been seen, the first `open` then its `close`).
    fn skip_to_matching(&mut self, open: &str, close: &str) -> PResult<()> {
        let mut depth = 0u32;
        loop {
            let Some(tok) = self.peek() else {
                return Err(PErr::Need);
            };
            match keyword(tok) {
                Some(k) if k == open => depth = depth.saturating_add(1),
                Some(k) if k == close => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        self.pos = self.pos.saturating_add(1);
                        return Ok(());
                    }
                }
                _ => {}
            }
            self.pos = self.pos.saturating_add(1);
        }
    }

    /// `case ... esac`: skipped whole.
    fn skip_case(&mut self) -> PResult<Command> {
        self.pos = self.pos.saturating_add(1);
        let mut depth = 1u32;
        let mut previous_ends_item = false;
        loop {
            let Some(tok) = self.peek() else {
                return Err(PErr::Need);
            };
            match keyword(tok) {
                Some("case") if previous_ends_item => depth = depth.saturating_add(1),
                Some("esac") if previous_ends_item => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        self.pos = self.pos.saturating_add(1);
                        self.redirections()?;
                        return Ok(Command::Unsupported(UnsupportedKind::Case));
                    }
                }
                _ => {}
            }
            previous_ends_item = matches!(
                tok.tok,
                Tok::Newline | Tok::Op(Op::Semi | Op::DSemi | Op::LParen | Op::RParen)
            );
            self.pos = self.pos.saturating_add(1);
        }
    }

    /// `[[ ... ]]`: skipped whole.
    fn skip_double_bracket(&mut self) -> PResult<Command> {
        self.pos = self.pos.saturating_add(1);
        loop {
            let Some(tok) = self.peek() else {
                return Err(PErr::Need);
            };
            let closes = keyword(tok) == Some("]]");
            self.pos = self.pos.saturating_add(1);
            if closes {
                return Ok(Command::Unsupported(UnsupportedKind::DoubleBracket));
            }
        }
    }

    /// `function name [()] { ... }`: parsed, then skipped.
    fn function_keyword(&mut self) -> PResult<Command> {
        self.pos = self.pos.saturating_add(1);
        match self.peek() {
            None => return Err(PErr::Need),
            Some(tok) if matches!(tok.tok, Tok::Word(_)) => {
                self.pos = self.pos.saturating_add(1);
            }
            Some(_) => return Err(self.unexpected()),
        }
        if matches!(self.peek_op(), Some(Op::LParen)) {
            self.pos = self.pos.saturating_add(1);
            if !matches!(self.peek_op(), Some(Op::RParen)) {
                return Err(self.unexpected());
            }
            self.pos = self.pos.saturating_add(1);
        }
        self.function_body()
    }

    /// After `name` with `(` `)` next.
    fn function_definition(&mut self) -> PResult<Command> {
        self.pos = self.pos.saturating_add(2);
        self.function_body()
    }

    fn function_body(&mut self) -> PResult<Command> {
        self.skip_newlines();
        if self.peek().is_none() {
            return Err(PErr::Need);
        }
        self.command()?;
        Ok(Command::Unsupported(UnsupportedKind::Function))
    }

    /// `coproc ...`: the rest of the command is skipped.
    fn skip_coproc(&mut self) -> PResult<Command> {
        self.pos = self.pos.saturating_add(1);
        while let Some(tok) = self.peek() {
            if matches!(
                tok.tok,
                Tok::Newline | Tok::Op(Op::Semi | Op::Amp | Op::AndIf | Op::OrIf | Op::RParen)
            ) {
                break;
            }
            self.pos = self.pos.saturating_add(1);
        }
        Ok(Command::Unsupported(UnsupportedKind::Coproc))
    }
}

/// `pipeline |& next` merges the left command's stderr into the pipe.
fn add_stderr_merge(command: &mut Command) {
    let merge = Redir {
        fd: Some(2),
        op: RedirOp::DupOut,
        target: RedirTarget::Word(Word {
            parts: vec![WordPart::Literal("1".to_string())],
            raw: "1".to_string(),
        }),
    };
    match command {
        Command::Simple(SimpleCommand { redirs, .. })
        | Command::Subshell { redirs, .. }
        | Command::Brace { redirs, .. }
        | Command::If { redirs, .. }
        | Command::For { redirs, .. }
        | Command::While { redirs, .. } => redirs.push(merge),
        Command::Unsupported(_) => {}
    }
}

/// `NAME=value` at the start of a simple command. The value keeps its parts; a `~` at its start
/// or after a `:` is a tilde, as in an assignment.
fn split_assignment(word: &Word) -> Option<Assign> {
    let (first, rest) = word.parts.split_first()?;
    let WordPart::Literal(text) = first else {
        return None;
    };
    let (name, value_start) = text.split_once('=')?;
    if !is_name(name) {
        return None;
    }
    let mut parts = Vec::new();
    for (i, segment) in value_start.split(':').enumerate() {
        if i > 0 {
            parts.push(WordPart::Literal(":".to_string()));
        }
        match segment.strip_prefix('~') {
            Some(after) if after.is_empty() || after.starts_with('/') => {
                parts.push(WordPart::Tilde);
                if !after.is_empty() {
                    parts.push(WordPart::Literal(after.to_string()));
                }
            }
            _ if segment.is_empty() => {}
            _ => parts.push(WordPart::Literal(segment.to_string())),
        }
    }
    parts.extend(rest.iter().cloned());
    let raw = word
        .raw
        .split_once('=')
        .map_or_else(String::new, |(_, value)| value.to_string());
    Some(Assign {
        name: name.to_string(),
        value: Word { parts, raw },
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Parsed {
        let mut budget = LineBudget::new(1 << 20);
        parse_unit(src, false, 16, &mut budget, 1)
    }

    fn items(src: &str) -> Vec<ListItem> {
        let parsed = parse(src);
        assert_eq!(parsed.tail, Tail::Done, "{src}");
        parsed.items
    }

    fn only_command(src: &str) -> Command {
        let mut items = items(src);
        assert_eq!(items.len(), 1, "{src}");
        let mut and_or = items.remove(0).and_or;
        assert!(and_or.rest.is_empty(), "{src}");
        assert_eq!(and_or.first.stages.len(), 1, "{src}");
        and_or.first.stages.remove(0)
    }

    fn syntax_near(src: &str) -> Near {
        match parse(src).tail {
            Tail::Error(error) => error.near,
            other => panic!("{src}: expected a syntax error, got {other:?}"),
        }
    }

    #[test]
    fn a_list_separates_on_semicolon_ampersand_and_newline() {
        let list = items("a; b & c\nd");
        assert_eq!(list.len(), 4);
        assert!(!list[0].background && list[1].background && !list[2].background);
        assert_eq!(list[3].end_line, 2);
    }

    #[test]
    fn and_or_chains_are_left_associative_and_pipelines_bind_tighter() {
        let list = items("a && b || c | d");
        let chain = &list[0].and_or;
        assert_eq!(chain.rest.len(), 2);
        assert_eq!(chain.rest[0].0, AndOrOp::And);
        assert_eq!(chain.rest[1].0, AndOrOp::Or);
        assert_eq!(chain.rest[1].1.stages.len(), 2);
    }

    #[test]
    fn a_bang_negates_the_whole_pipeline() {
        let list = items("! a | b");
        assert!(list[0].and_or.first.bang);
        assert_eq!(list[0].and_or.first.stages.len(), 2);
    }

    #[test]
    fn simple_commands_split_assignments_words_and_redirections() {
        let Command::Simple(cmd) = only_command("A=1 B=2 cmd x >o 2>&1 <i") else {
            panic!("not simple");
        };
        assert_eq!(cmd.assigns.len(), 2);
        assert_eq!(cmd.words.len(), 2);
        assert_eq!(cmd.redirs.len(), 3);
        assert_eq!(cmd.redirs[0].op, RedirOp::Out);
        assert_eq!(cmd.redirs[1].fd, Some(2));
        assert_eq!(cmd.redirs[1].op, RedirOp::DupOut);
        assert_eq!(cmd.redirs[2].op, RedirOp::In);
        // An assignment after the first word is an argument.
        let Command::Simple(cmd) = only_command("echo A=1") else {
            panic!("not simple");
        };
        assert!(cmd.assigns.is_empty());
        assert_eq!(cmd.words.len(), 2);
    }

    #[test]
    fn a_redirection_only_command_and_a_word_attached_target_parse() {
        let Command::Simple(cmd) = only_command(">/tmp/x") else {
            panic!("not simple");
        };
        assert!(cmd.words.is_empty());
        assert_eq!(cmd.redirs.len(), 1);
        let Command::Simple(cmd) = only_command("cat i>ii") else {
            panic!("not simple");
        };
        assert_eq!(cmd.words.len(), 2, "cat and i");
        assert_eq!(cmd.redirs.len(), 1, "the word-attached operator redirects");
    }

    #[test]
    fn compound_commands_parse_with_their_redirections() {
        assert!(
            matches!(only_command("(a; b) > f"), Command::Subshell { redirs, .. } if redirs.len() == 1)
        );
        assert!(
            matches!(only_command("{ a; b; } 2>&1"), Command::Brace { redirs, .. } if redirs.len() == 1)
        );
        let Command::If { elifs, els, .. } =
            only_command("if a; then b; elif c; then d; else e; fi")
        else {
            panic!("not an if");
        };
        assert_eq!(elifs.len(), 1);
        assert!(els.is_some());
        assert!(
            matches!(only_command("for i in 1 2 3; do echo $i; done"), Command::For { words: Some(w), .. } if w.len() == 3)
        );
        assert!(matches!(
            only_command("for i; do :; done"),
            Command::For { words: None, .. }
        ));
        assert!(
            matches!(only_command("while a; do b; done < f"), Command::While { until: false, redirs, .. } if redirs.len() == 1)
        );
        assert!(matches!(
            only_command("until a; do b; done"),
            Command::While { until: true, .. }
        ));
    }

    #[test]
    fn a_here_document_becomes_a_redirection_with_its_body() {
        let Command::Simple(cmd) = only_command("cat <<EOF\nhi $x\nEOF") else {
            panic!("not simple");
        };
        assert_eq!(cmd.redirs[0].op, RedirOp::HereDoc);
        assert_eq!(
            cmd.redirs[0].target,
            RedirTarget::HereBody {
                text: "hi $x\n".to_string(),
                expand: true
            }
        );
    }

    #[test]
    fn every_unsupported_construct_parses_to_unsupported_without_an_error() {
        for (src, kind) in [
            ("case x in a) echo;; esac", UnsupportedKind::Case),
            (
                "case x in a) case y in b) :;; esac;; esac",
                UnsupportedKind::Case,
            ),
            ("[[ -f x && -d y ]]", UnsupportedKind::DoubleBracket),
            ("f() { echo hi; }", UnsupportedKind::Function),
            ("function f { echo hi; }", UnsupportedKind::Function),
            ("echo $'a'", UnsupportedKind::AnsiCQuote),
            ("((i = 1 + 2))", UnsupportedKind::ArithCommand),
            ("echo ${x##*/}", UnsupportedKind::ParamOp),
            ("echo {a,b}", UnsupportedKind::BraceExpansion),
            ("cat <<< word", UnsupportedKind::HereString),
            ("a=(1 2 3)", UnsupportedKind::Array),
            ("coproc cat", UnsupportedKind::Coproc),
            ("cat <(id)", UnsupportedKind::ProcessSubstitution),
        ] {
            assert_eq!(only_command(src), Command::Unsupported(kind), "{src}");
        }
    }

    #[test]
    fn a_nested_subshell_that_looks_like_arithmetic_stays_a_subshell() {
        assert!(matches!(only_command("( (a) )"), Command::Subshell { .. }));
        assert!(matches!(only_command("((a); b)"), Command::Subshell { .. }));
    }

    #[test]
    fn incomplete_constructs_need_more_input() {
        for src in [
            "if a; then b",
            "for i in 1 2",
            "while a; do",
            "{ a;",
            "( a",
            "a &&",
            "a |",
            "echo 'x",
            "cat <<EOF\nbody",
            "case x in a) echo;;",
            "[[ a",
            "f() {",
        ] {
            assert_eq!(parse(src).tail, Tail::NeedMore, "{src}");
        }
        // Once no more input can come the same text is a syntax error.
        let mut budget = LineBudget::new(1 << 20);
        let done = parse_unit("if a; then b", true, 16, &mut budget, 1);
        assert!(matches!(
            done.tail,
            Tail::Error(SyntaxError {
                near: Near::EndOfFile,
                ..
            })
        ));
    }

    #[test]
    fn a_closing_brace_needs_a_separator_before_it() {
        assert_eq!(parse("{ echo hi }").tail, Tail::NeedMore);
        assert_eq!(parse("{ echo hi; }").tail, Tail::Done);
    }

    #[test]
    fn what_bash_rejects_is_a_syntax_error_naming_the_token() {
        assert_eq!(syntax_near(")"), Near::Token(")".to_string()));
        assert_eq!(syntax_near(";"), Near::Token(";".to_string()));
        assert_eq!(syntax_near("&& a"), Near::Token("&&".to_string()));
        assert_eq!(syntax_near("a | | b"), Near::Token("|".to_string()));
        assert_eq!(syntax_near("fi"), Near::Token("fi".to_string()));
        assert_eq!(syntax_near("done"), Near::Token("done".to_string()));
        assert_eq!(syntax_near("if a; then fi"), Near::Token("fi".to_string()));
        assert_eq!(syntax_near("echo >"), Near::Newline);
        assert_eq!(syntax_near("cat <\n"), Near::Newline);
        assert_eq!(syntax_near("a ;; b"), Near::Token(";;".to_string()));
        assert_eq!(syntax_near("echo a )"), Near::Token(")".to_string()));
        assert_eq!(syntax_near("() :"), Near::Token(")".to_string()));
    }

    #[test]
    fn items_before_a_syntax_error_are_still_reported_for_a_script() {
        let parsed = parse("echo a\n)\necho b");
        assert_eq!(parsed.items.len(), 1);
        assert!(matches!(
            parsed.tail,
            Tail::Error(SyntaxError { line: 2, .. })
        ));
    }

    #[test]
    fn nesting_past_the_depth_cap_is_refused_not_overflowed() {
        let deep = format!("{}:{}", "( ".repeat(40), " )".repeat(40));
        assert_eq!(parse(&deep).tail, Tail::TooDeep);
        let ifs = format!("{}:{}", "if :; then ".repeat(40), "; fi".repeat(40));
        assert_eq!(parse(&ifs).tail, Tail::TooDeep);
    }

    #[test]
    fn an_assignment_value_starts_a_tilde_after_a_colon() {
        let Command::Simple(cmd) = only_command("P=~/a:~:b") else {
            panic!("not simple");
        };
        let parts = &cmd.assigns[0].value.parts;
        assert_eq!(
            parts
                .iter()
                .filter(|p| matches!(p, WordPart::Tilde))
                .count(),
            2
        );
    }
}
