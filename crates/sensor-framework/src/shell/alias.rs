//! `alias` and `unalias`, and the table the lexer expands from.
//!
//! An alias is text, not a command: the lexer replaces a word at command position with the alias's
//! value and reads on from there (`lex::lex_with_aliases`), so the value may hold quotes, operators
//! or the start of a construct, a trailing blank lets the next word be an alias too, and a name is
//! not expanded again inside its own value. Because the table is read when a line is parsed, an
//! alias defined on a line takes effect from the next one. A bash that runs a script expands none
//! unless `shopt -s expand_aliases` was run; dash and the phone's shell always do.
//!
//! The wording is bash 5.1.16's and dash 0.5.11's, checked in the reference container. bash sorts
//! its listing by name and refuses names holding a quote, a blank, a shell metacharacter, `$`, a
//! backtick or `/`; dash lists in the order of its 39-bucket hash table, takes any name, and calls
//! `-p` and `--` names to look up. mksh has no recording [inferred]: it lists like dash, sorted.
//!
//! Every limit is a bound on attacker input: 128 aliases, a name of 255 bytes, a value of 4096,
//! and the total counts against the connection's content allowance with the variables.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{BudgetHit, CommandResult, FakeShell, HandlerId, ShellLevel};

/// One alias: a name and the text that replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Alias {
    pub name: String,
    pub value: String,
}

/// Most aliases one shell holds.
pub(super) const ALIASES_MAX: usize = 128;
const NAME_MAX: usize = 255;
const VALUE_MAX: usize = 4096;

/// dash's alias table: buckets of a chain each, in the order the names were first defined.
const DASH_BUCKETS: u32 = 39;

pub(super) fn register(r: &mut Registry) {
    r.register_builtin("alias", HandlerId::Alias, FakeShell::builtin_alias);
    r.register_builtin("unalias", HandlerId::Alias, FakeShell::builtin_unalias);
}

/// bash refuses an alias name holding a blank, a quote, a shell metacharacter, `$`, a backtick,
/// a backslash or `/`.
fn bash_name_ok(name: &str) -> bool {
    !name.is_empty()
        && !name.chars().any(|c| {
            matches!(
                c,
                ' ' | '\t'
                    | '\n'
                    | '&'
                    | '('
                    | ')'
                    | ';'
                    | '|'
                    | '<'
                    | '>'
                    | '"'
                    | '\''
                    | '\\'
                    | '`'
                    | '$'
                    | '/'
            )
        })
}

/// dash's hash of a name: the first byte shifted by four plus the sum of the bytes, over 39.
fn dash_bucket(name: &str) -> u32 {
    let first = name.bytes().next().map_or(0u32, u32::from);
    let sum = name
        .bytes()
        .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(byte)));
    (first << 4).wrapping_add(sum) % DASH_BUCKETS
}

impl FakeShell {
    /// The value of the alias `name` in the running shell.
    pub(super) fn alias_value(&self, name: &str) -> Option<&str> {
        self.state()
            .aliases
            .iter()
            .find(|alias| alias.name == name)
            .map(|alias| alias.value.as_str())
    }

    /// Whether the lexer expands aliases in what the running shell reads: always in dash and on the
    /// phone, in bash only where it is interactive or `expand_aliases` was set.
    pub(super) fn aliases_expand(&self) -> bool {
        match self.active_level() {
            ShellLevel::Bash { .. } => !self.bash_is_scripted() || self.shopt_on("expand_aliases"),
            ShellLevel::Dash { .. } | ShellLevel::AndroidMksh => true,
        }
    }

    /// `'value'` quoted as the active shell's listing quotes it: bash closes the quote around a
    /// quote (`'it'\''s'`), dash and mksh put it in double quotes (`'it'"'"'s'`).
    pub(super) fn alias_quoted(&self, value: &str) -> String {
        let inner = if self.is_bash() {
            value.replace('\'', "'\\''")
        } else {
            value.replace('\'', "'\"'\"'")
        };
        format!("'{inner}'")
    }

    /// The aliases in the order the active shell lists them.
    fn alias_order(&self) -> Vec<&Alias> {
        let mut listed: Vec<&Alias> = self.state().aliases.iter().collect();
        match self.active_level() {
            ShellLevel::Bash { .. } | ShellLevel::AndroidMksh => {
                listed.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
            }
            ShellLevel::Dash { .. } => {
                // A stable sort by bucket keeps the definition order inside one.
                listed.sort_by_key(|alias| dash_bucket(&alias.name));
            }
        }
        listed
    }

    /// One alias as a listing prints it: `alias NAME='VALUE'` in bash, `NAME='VALUE'` elsewhere.
    pub(super) fn alias_line(&self, alias: &Alias) -> String {
        let quoted = self.alias_quoted(&alias.value);
        if self.is_bash() {
            let separator = if alias.name.starts_with('-') {
                "-- "
            } else {
                ""
            };
            format!("alias {separator}{}={quoted}\n", alias.name)
        } else {
            format!("{}={quoted}\n", alias.name)
        }
    }

    fn alias_listing(&self) -> String {
        self.alias_order()
            .into_iter()
            .map(|alias| self.alias_line(alias))
            .collect()
    }

    /// Define or redefine an alias, keeping its place in the table. False when the table or the
    /// connection's content allowance has no room: nothing changes and nothing is printed.
    fn alias_define(&mut self, name: &str, value: &str) -> bool {
        if name.len() > NAME_MAX || value.len() > VALUE_MAX {
            return false;
        }
        let cap = usize::try_from(self.budget().limits().owned_bytes).unwrap_or(usize::MAX);
        let state = self.state();
        let existing = state.aliases.iter().find(|alias| alias.name == name);
        let before = existing.map_or(0, |alias| {
            alias.name.len().saturating_add(alias.value.len())
        });
        let after = state
            .owned_bytes()
            .saturating_sub(before)
            .saturating_add(name.len())
            .saturating_add(value.len());
        let full = existing.is_none() && state.aliases.len() >= ALIASES_MAX;
        if after > cap || full {
            self.record_hit(BudgetHit::OwnedBytes);
            return false;
        }
        let aliases = &mut self.state_mut().aliases;
        match aliases.iter_mut().find(|alias| alias.name == name) {
            Some(alias) => alias.value = value.to_string(),
            None => aliases.push(Alias {
                name: name.to_string(),
                value: value.to_string(),
            }),
        }
        true
    }

    /// `alias [-p] [NAME[=VALUE]]...`
    pub(super) fn builtin_alias(&mut self, parts: &[&str]) -> CommandResult {
        let mut args = parts.get(1..).unwrap_or(&[]);
        let bash = self.is_bash();
        let mut print_all = false;
        if bash {
            // Leading options only: a `-p` after a name is a name.
            while let Some(arg) = args.first() {
                if *arg == "--" {
                    args = args.get(1..).unwrap_or(&[]);
                    break;
                }
                let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
                    break;
                };
                for flag in flags.chars() {
                    if flag == 'p' {
                        print_all = true;
                    } else {
                        return CommandResult::stderr(
                            2,
                            format!(
                                "{}alias: usage: alias [-p] [name[=value] ... ]\n",
                                self.shell_error(format_args!("alias: -{flag}: invalid option"))
                            ),
                        );
                    }
                }
                args = args.get(1..).unwrap_or(&[]);
            }
        }
        let mut out = CommandResult::silent(0);
        if args.is_empty() || print_all {
            // bash returns at once when it holds none, so the operands after `-p` go unread.
            if self.state().aliases.is_empty() && bash {
                return out;
            }
            out.append(CommandResult::stdout(self.alias_listing()));
            if args.is_empty() {
                return out;
            }
        }
        let mut failed = false;
        for arg in args {
            // dash looks for the `=` after the first character, so `=x=y` names `=x`.
            let skip = if bash {
                0
            } else {
                arg.chars().next().map_or(0, char::len_utf8)
            };
            let rest = arg.get(skip..).unwrap_or("");
            let split = rest
                .find('=')
                .map(|at| at.saturating_add(skip))
                .filter(|at| !bash || *at > 0);
            match split {
                Some(at) => {
                    let name = arg.get(..at).unwrap_or("");
                    let value = arg.get(at.saturating_add(1)..).unwrap_or("");
                    if bash && !bash_name_ok(name) {
                        out.append(CommandResult::stderr(
                            1,
                            self.shell_error(format_args!("alias: `{name}': invalid alias name")),
                        ));
                        failed = true;
                    } else if !self.alias_define(name, value) {
                        failed = true;
                    }
                }
                None => match self.alias_value(arg).map(str::to_string) {
                    Some(value) => {
                        let line = self.alias_line(&Alias {
                            name: (*arg).to_string(),
                            value,
                        });
                        out.append(CommandResult::stdout(line));
                    }
                    None => {
                        let message = if bash {
                            self.shell_error(format_args!("alias: {arg}: not found"))
                        } else {
                            format!("alias: {arg} not found\n")
                        };
                        out.append(CommandResult::stderr(1, message));
                        failed = true;
                    }
                },
            }
        }
        out.status = u8::from(failed);
        out
    }

    /// `unalias [-a] NAME...`
    pub(super) fn builtin_unalias(&mut self, parts: &[&str]) -> CommandResult {
        let mut args = parts.get(1..).unwrap_or(&[]);
        let bash = self.is_bash();
        let mut all = false;
        while let Some(arg) = args.first() {
            if *arg == "--" {
                args = args.get(1..).unwrap_or(&[]);
                break;
            }
            let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
                break;
            };
            for flag in flags.chars() {
                if flag == 'a' {
                    all = true;
                } else if bash {
                    return CommandResult::stderr(
                        2,
                        format!(
                            "{}unalias: usage: unalias [-a] name [name ...]\n",
                            self.shell_error(format_args!("unalias: -{flag}: invalid option"))
                        ),
                    );
                } else {
                    return CommandResult::stderr(
                        2,
                        self.shell_error(format_args!("unalias: Illegal option -{flag}")),
                    );
                }
            }
            args = args.get(1..).unwrap_or(&[]);
        }
        if all {
            self.state_mut().aliases.clear();
            return CommandResult::silent(0);
        }
        if args.is_empty() {
            // bash wants a name; dash takes none to mean nothing to do.
            return if bash {
                CommandResult::stderr(2, "unalias: usage: unalias [-a] name [name ...]\n")
            } else {
                CommandResult::silent(0)
            };
        }
        let mut out = CommandResult::silent(0);
        let mut failed = false;
        for name in args {
            let aliases = &mut self.state_mut().aliases;
            let before = aliases.len();
            aliases.retain(|alias| alias.name != *name);
            if aliases.len() == before {
                let message = if bash {
                    self.shell_error(format_args!("unalias: {name}: not found"))
                } else {
                    format!("unalias: {name} not found\n")
                };
                out.append(CommandResult::stderr(1, message));
                failed = true;
            }
        }
        out.status = u8::from(failed);
        out
    }
}
