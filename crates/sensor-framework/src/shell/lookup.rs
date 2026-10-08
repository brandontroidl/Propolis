//! The lookup commands: `command -v`/`-V`, `type` and `which`. Each asks the registry what the name
//! is and asks the filesystem where its file is, so what they advertise is exactly what dispatch
//! runs. There is no list of commands here: a name is a command when [`Registry::kind`] says
//! dispatch has an entry for it, a builtin when the entry was registered as one, and otherwise a
//! file found by walking `$PATH` over [`crate::fakefs::FakeFs`].
//!
//! A name dispatch answers but no `$PATH` directory holds a file for (`more`; a session's own
//! `PATH=` emptied) is reported at the persona's standard
//! directory, because dispatch does not consult `$PATH`: agreeing with dispatch outranks
//! agreeing with the recorded Ubuntu 22.04 layout, where those names are absent.
//!
//! Wording, from the 2026-09-29 recordings on Ubuntu 22.04: bash prints `command -v` of a builtin as
//! its name and of a file as its path, `type` as `X is a shell builtin` or `X is /path`, and
//! reports a missing `type` name on standard error with status 1; `dash` prints `X: not found` on
//! standard output for `type` and nothing for `command -v`, status 127 for both. The dash-family
//! wordings that were not recorded (`command -V`, an invalid option, mksh's status) are marked
//! [unverified] where they are written.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::{CommandKind, Registry};
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, ShellLevel, command_basename};

pub(super) fn register(r: &mut Registry) {
    r.register_builtin(
        "command",
        HandlerId::CommandBuiltin,
        FakeShell::builtin_command,
    );
    r.register_builtin("type", HandlerId::Type, FakeShell::builtin_type);
    r.register_if(
        "which",
        super::multicall::bare_applet,
        HandlerId::Which,
        FakeShell::cmd_which,
    );
}

/// The words the grammar reserves, which `type` calls keywords. They are parser syntax, not
/// commands, so they are not in the registry; the parser's own `if`, `for`, `while`, `until`, `{`
/// and `!` are the ones the engine acts on.
const BASH_KEYWORDS: &[&str] = &[
    "!", "[[", "]]", "{", "}", "case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for",
    "function", "if", "in", "select", "then", "time", "until", "while",
];
const DASH_KEYWORDS: &[&str] = &[
    "!", "{", "}", "case", "do", "done", "elif", "else", "esac", "fi", "for", "if", "in", "then",
    "until", "while",
];

/// What a name is to the running shell.
struct Located {
    keyword: bool,
    builtin: bool,
    /// The files that answer the name, in `$PATH` order. Filled for a file command and, when every
    /// file was asked for, for a builtin that also has one (`echo`, `true`).
    files: Vec<String>,
}

/// How much of a name `command` prints.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Detail {
    /// `command -v`: the name of a builtin, the path of a file.
    Short,
    /// `command -V`: a sentence.
    Sentence,
}

impl FakeShell {
    fn keywords(&self) -> &'static [&'static str] {
        if self.is_bash() {
            BASH_KEYWORDS
        } else {
            DASH_KEYWORDS
        }
    }

    /// The directory a name that dispatch runs but no `$PATH` directory holds is reported in.
    fn standard_bin_dir(&self) -> &'static str {
        match self.flavor {
            ShellFlavor::Bash => "/usr/bin",
            ShellFlavor::AndroidSh => "/system/bin",
        }
    }

    /// The executable files named `name` in the `$PATH` directories, in order; only the first
    /// unless `every`. An empty directory entry is the working directory, as in the shell.
    pub(super) fn path_matches(&mut self, name: &str, every: bool) -> Vec<String> {
        let path = self.state().get("PATH").unwrap_or("").to_string();
        let mut found = Vec::new();
        for directory in path.split(':') {
            // `$PATH` is the session's to set, so its length is the walk's, charged to the line.
            if !self.charge_work(1) {
                break;
            }
            let directory = if directory.is_empty() { "." } else { directory };
            let candidate = format!("{directory}/{name}");
            let absolute = if candidate.starts_with('/') {
                candidate.clone()
            } else {
                format!("{}/{candidate}", self.cwd().trim_end_matches('/'))
            };
            if self.fs.is_executable(&absolute) {
                found.push(candidate);
                if !every {
                    break;
                }
            }
        }
        found
    }

    /// What `name` is, or `None` when dispatch would not run it. Mirrors [`FakeShell::resolve`]: a
    /// bare name is a command exactly when the registry has a live entry for it, and a name with a
    /// slash runs when the registry knows its basename or the path is an executable file.
    fn locate(&mut self, name: &str, every_file: bool) -> Option<Located> {
        if name.contains('/') {
            let runs = match Registry::builtin().kind(command_basename(name), self) {
                Some(kind) => kind != CommandKind::Unresolved,
                None => {
                    let absolute = self.normalize_logical(name);
                    self.fs.is_executable(&absolute)
                }
            };
            return runs.then(|| Located {
                keyword: false,
                builtin: false,
                files: vec![name.to_string()],
            });
        }
        let keyword = self.keywords().contains(&name);
        let kind = Registry::builtin()
            .kind(name, self)
            .filter(|kind| *kind != CommandKind::Unresolved);
        if kind.is_none() && !keyword {
            return None;
        }
        let files = match kind {
            Some(CommandKind::External) => {
                let mut files = self.path_matches(name, every_file);
                if files.is_empty() {
                    files.push(format!("{}/{name}", self.standard_bin_dir()));
                }
                files
            }
            Some(CommandKind::Builtin) if every_file => self.path_matches(name, true),
            _ => Vec::new(),
        };
        Some(Located {
            keyword,
            builtin: kind == Some(CommandKind::Builtin),
            files,
        })
    }

    /// The status a lookup ends with when something asked for was not found.
    fn missing_status(&self) -> u8 {
        match self.active_level() {
            ShellLevel::Bash { .. } | ShellLevel::AndroidMksh => 1,
            ShellLevel::Dash { .. } => 127,
        }
    }

    /// `command [-p] [-v|-V] NAME [ARG...]`. Described with `-v`/`-V`; otherwise `NAME` runs through
    /// dispatch as it would bare, which is all `command` changes here: functions and aliases, the
    /// two things it skips, are not modeled.
    pub(super) fn builtin_command(&mut self, parts: &[&str]) -> CommandResult {
        let mut detail = None;
        let mut at = 1;
        while let Some(arg) = parts.get(at) {
            if *arg == "--" {
                at = at.saturating_add(1);
                break;
            }
            let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
                break;
            };
            for flag in flags.chars() {
                match flag {
                    'p' => {}
                    'v' => detail = Some(Detail::Short),
                    'V' => detail = Some(Detail::Sentence),
                    other => return self.command_option_error(other),
                }
            }
            at = at.saturating_add(1);
        }
        let operands = parts.get(at..).unwrap_or(&[]);
        let Some(detail) = detail else {
            return if operands.is_empty() {
                CommandResult::silent(0)
            } else {
                self.dispatch_nested(operands)
            };
        };
        // dash describes only the first name it is given; bash describes each.
        let names = if self.is_bash() {
            operands
        } else {
            operands.get(..1).unwrap_or(&[])
        };
        let mut result = CommandResult::silent(0);
        let mut any_found = names.is_empty();
        for name in names {
            match self.locate(name, false) {
                Some(located) => {
                    any_found = true;
                    result.append(CommandResult::stdout(describe(name, &located, detail)));
                }
                None if detail == Detail::Sentence => {
                    result.append(self.not_found_report("command", name))
                }
                None => {}
            }
        }
        result.status = if any_found { 0 } else { self.missing_status() };
        result
    }

    fn command_option_error(&self, flag: char) -> CommandResult {
        if self.is_bash() {
            CommandResult::stderr(
                2,
                format!(
                    "{}command: usage: command [-pVv] command [arg ...]\n",
                    self.shell_error(format_args!("command: -{flag}: invalid option"))
                ),
            )
        } else {
            // [unverified] dash's and mksh's wording.
            CommandResult::stderr(
                2,
                self.shell_error(format_args!("command: Illegal option -{flag}")),
            )
        }
    }

    /// How the active shell reports that `builtin` was asked about a name it cannot find: bash on
    /// standard error, with the builtin's name; dash on standard output, bare.
    fn not_found_report(&self, builtin: &str, name: &str) -> CommandResult {
        if self.is_bash() {
            CommandResult::stderr(
                1,
                self.shell_error(format_args!("{builtin}: {name}: not found")),
            )
        } else {
            CommandResult::stdout(format!("{name}: not found\n"))
        }
    }

    /// `type [-afptP] NAME...`. bash takes the flags; the shells without them (dash, mksh) take
    /// every argument as a name.
    pub(super) fn builtin_type(&mut self, parts: &[&str]) -> CommandResult {
        let bash = self.is_bash();
        let (mut all, mut terse, mut only_files, mut force_path) = (false, false, false, false);
        let mut at = 1;
        while bash && let Some(arg) = parts.get(at) {
            if *arg == "--" {
                at = at.saturating_add(1);
                break;
            }
            let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
                break;
            };
            for flag in flags.chars() {
                match flag {
                    'a' => all = true,
                    't' => terse = true,
                    'p' => only_files = true,
                    'P' => force_path = true,
                    'f' => {}
                    other => {
                        return CommandResult::stderr(
                            2,
                            format!(
                                "{}type: usage: type [-afptP] name [name ...]\n",
                                self.shell_error(format_args!("type: -{other}: invalid option"))
                            ),
                        );
                    }
                }
            }
            at = at.saturating_add(1);
        }
        let mut result = CommandResult::silent(0);
        let mut missing = false;
        for name in parts.get(at..).unwrap_or(&[]) {
            let wants_files = all || only_files || force_path;
            let Some(located) = self.locate(name, wants_files) else {
                missing = true;
                // `-t`, `-p` and `-P` say nothing about a name they do not find.
                if !(terse || only_files || force_path) {
                    result.append(self.not_found_report("type", name));
                }
                continue;
            };
            let files: &[String] = if all {
                &located.files
            } else {
                located.files.get(..1).unwrap_or(&[])
            };
            if force_path || only_files {
                // `-P` looks in `$PATH` only; `-p` prints a path only for what `-t` calls a file.
                let is_file = !located.keyword && !located.builtin;
                if force_path || is_file {
                    for file in files {
                        result.append(CommandResult::stdout(format!("{file}\n")));
                    }
                }
                missing |= force_path && located.files.is_empty();
                continue;
            }
            let mut forms: Vec<(&str, String)> = Vec::new();
            if located.keyword {
                forms.push(("keyword", format!("{name} is a shell keyword\n")));
            }
            if located.builtin {
                forms.push(("builtin", format!("{name} is a shell builtin\n")));
            }
            for file in files {
                forms.push(("file", format!("{name} is {file}\n")));
            }
            let shown = if all { forms.len() } else { 1 };
            for (word, sentence) in forms.into_iter().take(shown) {
                result.append(CommandResult::stdout(if terse {
                    format!("{word}\n")
                } else {
                    sentence
                }));
            }
        }
        result.status = if missing {
            self.type_missing_status()
        } else {
            0
        };
        result
    }

    /// bash's `type` fails with 1; the dash family's with 127.
    fn type_missing_status(&self) -> u8 {
        match self.active_level() {
            ShellLevel::Bash { .. } => 1,
            ShellLevel::Dash { .. } | ShellLevel::AndroidMksh => 127,
        }
    }

    /// `which [-a] NAME...`, debianutils' script: each name's first executable match in `$PATH`
    /// (every match under `-a`) on its own line, status 1 when any name has none or no name was
    /// given. The search is the registry's, so a name dispatch runs is found and one it does not
    /// run is not.
    pub(super) fn cmd_which(&mut self, parts: &[&str]) -> CommandResult {
        let mut all = false;
        let mut at = 1;
        while let Some(arg) = parts.get(at) {
            if *arg == "--" {
                at = at.saturating_add(1);
                break;
            }
            let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
                break;
            };
            for flag in flags.chars() {
                if flag == 'a' {
                    all = true;
                } else {
                    // [unverified] the script's getopts complaint and usage line.
                    let mut usage = CommandResult::stderr(2, format!("Illegal option -{flag}\n"));
                    usage.append(CommandResult::stdout(
                        "Usage: /usr/bin/which [-a] args\n".to_string(),
                    ));
                    usage.status = 2;
                    return usage;
                }
            }
            at = at.saturating_add(1);
        }
        let names = parts.get(at..).unwrap_or(&[]);
        let mut result = CommandResult::silent(0);
        let mut missing = names.is_empty();
        for name in names {
            let files = self
                .locate(name, true)
                .map(|located| located.files)
                .unwrap_or_default();
            if files.is_empty() {
                missing = true;
            }
            let shown = if all { files.len() } else { 1 };
            for file in files.iter().take(shown) {
                result.append(CommandResult::stdout(format!("{file}\n")));
            }
        }
        result.status = u8::from(missing);
        result
    }
}

/// The line `command -v` or `-V` prints for a name that was found: a keyword or builtin by name,
/// a file by path.
fn describe(name: &str, located: &Located, detail: Detail) -> String {
    let file = located.files.first();
    match (detail, located.keyword, located.builtin, file) {
        (Detail::Short, true, _, _) | (Detail::Short, _, true, _) => format!("{name}\n"),
        (Detail::Short, _, _, Some(file)) => format!("{file}\n"),
        (Detail::Sentence, true, _, _) => format!("{name} is a shell keyword\n"),
        (Detail::Sentence, _, true, _) => format!("{name} is a shell builtin\n"),
        (Detail::Sentence, _, _, Some(file)) => format!("{name} is {file}\n"),
        (_, _, _, None) => String::new(),
    }
}
