//! bash's listing of a function, the text `type f`, `command -V f` and `set` print for it. bash does
//! not echo the definition back: it prints the parsed command again, in its own layout (four
//! spaces a level, `;` and a newline between commands, `elif` as a nested `else if`, a `function`
//! keyword in front of a function defined inside another), so that is what is rebuilt here from
//! the syntax tree. Words keep their source spelling, as bash keeps them. Every rule below was read
//! off Ubuntu 22.04's bash 5.1.16 (`type f` of the shapes in `ubuntu-bash-functions.session`).
//!
//! A body holding a command this shell skips (`[[ ]]`, `${x##*/}`, ...) has no tree to print, so
//! the listing falls back to the body as it was typed, indented one level. That text is this
//! shell's own and was not compared with bash's.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::ast::{
    AndOr, AndOrOp, Command, FunctionDef, List, Pipeline, Redir, RedirOp, RedirTarget,
    SimpleCommand,
};

/// bash's indentation step.
const STEP: usize = 4;

/// `name () `, `{ `, the body and `}`, each on its own line, ending in a newline.
pub(super) fn bash_function_text(name: &str, def: &FunctionDef) -> String {
    let mut printer = Printer::default();
    printer.function(name, def, false);
    if printer.skipped {
        return fallback(name, def);
    }
    printer.out.push('\n');
    printer.out
}

#[derive(Default)]
struct Printer {
    out: String,
    indent: usize,
    /// Here-document bodies of the commands printed on the current line, as (text, terminator):
    /// bash writes them after the line.
    deferred: Vec<(String, String)>,
    /// The last thing written was a here-document, which ends its own line.
    was_heredoc: bool,
    /// A command this shell skipped was met: the tree cannot be printed.
    skipped: bool,
}

impl Printer {
    fn push(&mut self, text: &str) {
        self.out.push_str(text);
    }

    fn spaces(&mut self, count: usize) {
        self.out.push_str(&" ".repeat(count));
    }

    /// bash's `semicolon()`: a `;` unless the line already ends in `&` or a newline.
    fn semicolon(&mut self) {
        if !matches!(self.out.chars().last(), Some('&' | '\n')) {
            self.out.push(';');
        }
    }

    fn flush_heredocs(&mut self) {
        for (text, terminator) in std::mem::take(&mut self.deferred) {
            self.out.push('\n');
            self.out.push_str(&text);
            self.out.push_str(&terminator);
            self.out.push('\n');
            self.was_heredoc = true;
        }
    }

    fn function(&mut self, name: &str, def: &FunctionDef, nested: bool) {
        if nested {
            self.push("function ");
        }
        self.push(name);
        self.push(" () \n");
        let at = self.indent;
        self.spaces(at);
        self.push("{ \n");
        self.indent = self.indent.saturating_add(STEP);
        let at = self.indent;
        self.spaces(at);
        // The braces are the function's own: a group body is printed inside them, not twice.
        let redirs: &[Redir] = match &def.body {
            Command::Brace { body, redirs } => {
                self.list(body);
                redirs
            }
            other => {
                self.command(other);
                &[]
            }
        };
        self.indent = self.indent.saturating_sub(STEP);
        self.push("\n");
        let at = self.indent;
        self.spaces(at);
        self.push("}");
        self.redirs(redirs);
    }

    fn list(&mut self, list: &List) {
        let count = list.items.len();
        for (index, item) in list.items.iter().enumerate() {
            let last = index.saturating_add(1) == count;
            self.and_or(&item.and_or);
            self.flush_heredocs();
            if item.background {
                self.push(if last { " &" } else { " & " });
            } else if !last {
                if std::mem::take(&mut self.was_heredoc) {
                    // The here-document's own newline ended the line.
                } else {
                    self.push(";");
                }
                self.push("\n");
                let at = self.indent;
                self.spaces(at);
            }
        }
        self.was_heredoc = false;
    }

    fn and_or(&mut self, chain: &AndOr) {
        self.pipeline(&chain.first);
        for (op, pipeline) in &chain.rest {
            self.push(match op {
                AndOrOp::And => " && ",
                AndOrOp::Or => " || ",
            });
            self.pipeline(pipeline);
        }
    }

    fn pipeline(&mut self, pipeline: &Pipeline) {
        match pipeline.timed {
            Some(true) => self.push("time -p "),
            Some(false) => self.push("time "),
            None => {}
        }
        if pipeline.bang {
            self.push("! ");
        }
        for (index, stage) in pipeline.stages.iter().enumerate() {
            if index > 0 {
                if self.deferred.is_empty() {
                    self.push(" | ");
                } else {
                    // bash writes the here-document straight after the `|` it was typed before,
                    // and the next stage follows on a line indented by two.
                    self.push(" |");
                    self.flush_heredocs();
                    self.push("  ");
                }
            }
            self.command(stage);
        }
    }

    fn command(&mut self, command: &Command) {
        match command {
            Command::Simple(simple) => self.simple(simple),
            Command::Subshell { body, redirs } => {
                self.push("( ");
                self.list(body);
                self.push(" )");
                self.redirs(redirs);
            }
            Command::Brace { body, redirs } => {
                self.push("{ \n");
                self.indent = self.indent.saturating_add(STEP);
                let at = self.indent;
                self.spaces(at);
                self.list(body);
                self.indent = self.indent.saturating_sub(STEP);
                self.push("\n");
                let at = self.indent;
                self.spaces(at);
                self.push("}");
                self.redirs(redirs);
            }
            Command::If {
                cond,
                then,
                elifs,
                els,
                redirs,
            } => {
                self.push("if ");
                self.list(cond);
                self.semicolon();
                self.push(" then\n");
                self.body(then);
                self.if_rest(elifs, els.as_ref());
                self.close("fi");
                self.redirs(redirs);
            }
            Command::For {
                var,
                words,
                body,
                redirs,
            } => {
                self.push("for ");
                self.push(var);
                self.push(" in ");
                match words {
                    Some(words) => {
                        let text: Vec<&str> = words.iter().map(|w| w.raw.as_str()).collect();
                        self.push(&text.join(" "));
                    }
                    None => self.push("\"$@\""),
                }
                self.push(";\n");
                let at = self.indent;
                self.spaces(at);
                self.push("do\n");
                self.body(body);
                self.close("done");
                self.redirs(redirs);
            }
            Command::While {
                cond,
                body,
                until,
                redirs,
            } => {
                self.push(if *until { "until " } else { "while " });
                self.list(cond);
                self.semicolon();
                self.push(" do\n");
                self.body(body);
                self.close("done");
                self.redirs(redirs);
            }
            Command::Case { word, arms, redirs } => {
                self.push("case ");
                self.push(&word.raw);
                self.push(" in ");
                for arm in arms {
                    self.push("\n");
                    let at = self.indent.saturating_add(STEP);
                    self.spaces(at);
                    let patterns: Vec<&str> = arm.patterns.iter().map(|p| p.raw.as_str()).collect();
                    self.push(&patterns.join(" | "));
                    self.push(")\n");
                    if !arm.body.items.is_empty() {
                        self.indent = self.indent.saturating_add(STEP.saturating_mul(2));
                        let at = self.indent;
                        self.spaces(at);
                        self.list(&arm.body);
                        self.indent = self.indent.saturating_sub(STEP.saturating_mul(2));
                    }
                    self.push("\n");
                    let at = self.indent.saturating_add(STEP);
                    self.spaces(at);
                    self.push(";;");
                }
                self.close("esac");
                self.redirs(redirs);
            }
            Command::Function(def) => {
                self.function(&def.name, def, true);
            }
            Command::Unsupported(_) => self.skipped = true,
        }
    }

    /// A loop or `if` branch: one level in, ended by the `;` bash adds.
    fn body(&mut self, list: &List) {
        self.indent = self.indent.saturating_add(STEP);
        let at = self.indent;
        self.spaces(at);
        self.list(list);
        self.indent = self.indent.saturating_sub(STEP);
        self.semicolon();
    }

    /// The closing word of a compound command, on a line of its own.
    fn close(&mut self, word: &str) {
        self.push("\n");
        let at = self.indent;
        self.spaces(at);
        self.push(word);
    }

    /// bash reads `elif` as an `else` holding an `if`, and prints it so.
    fn if_rest(&mut self, elifs: &[(List, List)], els: Option<&List>) {
        if let Some(((cond, branch), rest)) = elifs.split_first() {
            self.push("\n");
            let at = self.indent;
            self.spaces(at);
            self.push("else\n");
            self.indent = self.indent.saturating_add(STEP);
            let at = self.indent;
            self.spaces(at);
            self.push("if ");
            self.list(cond);
            self.semicolon();
            self.push(" then\n");
            self.body(branch);
            self.if_rest(rest, els);
            self.close("fi");
            self.indent = self.indent.saturating_sub(STEP);
            self.semicolon();
        } else if let Some(list) = els {
            self.push("\n");
            let at = self.indent;
            self.spaces(at);
            self.push("else\n");
            self.body(list);
        }
    }

    fn simple(&mut self, simple: &SimpleCommand) {
        let mut words: Vec<String> = simple
            .assigns
            .iter()
            .map(|assign| format!("{}={}", assign.name, assign.value.raw))
            .collect();
        words.extend(simple.words.iter().map(|word| word.raw.clone()));
        self.push(&words.join(" "));
        self.redirs(&simple.redirs);
    }

    /// Each redirection after a space; the descriptor is written when it is not the operator's
    /// default, and always for the duplicating forms and `<>`.
    fn redirs(&mut self, redirs: &[Redir]) {
        for redir in redirs {
            self.push(" ");
            let fd = |default: u16| {
                redir
                    .fd
                    .filter(|fd| *fd != default)
                    .map_or_else(String::new, |fd| fd.to_string())
            };
            let always = |default: u16| redir.fd.unwrap_or(default).to_string();
            match (&redir.op, &redir.target) {
                (
                    RedirOp::HereDoc,
                    RedirTarget::HereBody {
                        text, delim, strip, ..
                    },
                ) => {
                    self.push(&fd(0));
                    self.push(if *strip { "<<-" } else { "<<" });
                    self.push(delim);
                    let terminator: String = delim
                        .chars()
                        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
                        .collect();
                    self.deferred.push((text.clone(), terminator));
                }
                (op, RedirTarget::Word(target)) => {
                    let (lead, operator, spaced) = match op {
                        RedirOp::In => (fd(0), "<", true),
                        RedirOp::Out => (fd(1), ">", true),
                        RedirOp::Append => (fd(1), ">>", true),
                        RedirOp::Clobber => (fd(1), ">|", true),
                        RedirOp::DupOut => (always(1), ">&", false),
                        RedirOp::DupIn => (always(0), "<&", false),
                        RedirOp::ReadWrite => (always(0), "<>", true),
                        RedirOp::HereDoc => (String::new(), "<<", false),
                    };
                    self.push(&lead);
                    self.push(operator);
                    if spaced {
                        self.push(" ");
                    }
                    self.push(&target.raw);
                }
                (_, RedirTarget::HereBody { .. }) => {}
            }
        }
    }
}

/// The body as it was typed, between the braces of `{ ... }` when there are some, in the frame of
/// a listing.
fn fallback(name: &str, def: &FunctionDef) -> String {
    let source = def.source.as_str();
    let inner = source
        .find('{')
        .and_then(|open| {
            let close = source.rfind('}')?;
            source.get(open.saturating_add(1)..close)
        })
        .unwrap_or(source)
        .trim();
    let mut out = format!("{name} () \n{{ \n");
    for line in inner.lines() {
        out.push_str("    ");
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out.push_str("}\n");
    out
}
