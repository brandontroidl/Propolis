//! `exec`: the redirections of the shell itself, and the command that replaces it.
//!
//! `exec` with redirections and no command changes the descriptors of the running shell for good
//! (`exec 3>file`, `exec >/dev/null 2>&1`, `exec 3<&-`): they are kept in the shell's state, every
//! later command and every shell it starts inherits them, and an interactive shell whose standard
//! error is redirected stops showing its prompt, as bash does (it writes the prompt there).
//! `exec <file` at the terminal makes the shell read the file's commands, run them, and end.
//!
//! `exec COMMAND` replaces the shell: the command runs with the redirections written on the line,
//! and the shell, or the subshell or script it was running in, ends with the command's status
//! without running its `EXIT` handler. A command that cannot be started is a message and status 127
//! (126 for a file that is not executable); an interactive bash goes on, any other shell ends.
//! Only a command with a file behind it can be exec'd: a builtin or a function is `not found`.
//! `exec bash`/`exec sh` at the terminal replaces the shell by a fresh interactive one. A download
//! run through `exec` is recorded as one run any other way is, with the URL it expanded to.
//!
//! Replies are from bash 5.1.16 and dash 0.5.11 in the reference container
//! (`ubuntu-bash-exec.session`, `ubuntu-dash-exec.session`); mksh's are dash's [inferred].
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::eval::Fds;
use super::registry::{CommandKind, Registry};
use super::{CommandResult, FakeShell, Flow, FrameKind, HandlerId, ShellLevel, command_basename};

pub(super) fn register(r: &mut Registry) {
    r.register_builtin("exec", HandlerId::Exec, FakeShell::builtin_exec);
}

/// What the options before an `exec` command asked for.
struct ExecArgs<'a> {
    clear_env: bool,
    login: bool,
    name: Option<&'a str>,
    /// Where the command starts in the words; the length of the words when there is none.
    command_at: usize,
}

const BASH_USAGE: &str =
    "exec: usage: exec [-cl] [-a name] [command [argument ...]] [redirection ...]\n";

impl FakeShell {
    /// The options of `exec`. bash has `-c`, `-l` and `-a NAME`; dash and mksh have none, so a word
    /// that starts with a hyphen is the command (`exec -z` is `-z: not found`).
    fn exec_args<'a>(&self, parts: &'a [&'a str]) -> Result<ExecArgs<'a>, CommandResult> {
        let mut args = ExecArgs {
            clear_env: false,
            login: false,
            name: None,
            command_at: 1,
        };
        while let Some(arg) = parts.get(args.command_at).copied() {
            if arg == "--" {
                args.command_at = args.command_at.saturating_add(1);
                break;
            }
            let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
                break;
            };
            if !self.is_bash() {
                break;
            }
            for (at, flag) in flags.char_indices() {
                match flag {
                    'c' => args.clear_env = true,
                    'l' => args.login = true,
                    'a' => {
                        let attached = flags.get(at.saturating_add(1)..).filter(|s| !s.is_empty());
                        if let Some(name) = attached {
                            args.name = Some(name);
                        } else if let Some(name) =
                            parts.get(args.command_at.saturating_add(1)).copied()
                        {
                            args.name = Some(name);
                            args.command_at = args.command_at.saturating_add(1);
                        } else {
                            return Err(CommandResult::stderr(
                                2,
                                format!(
                                    "{}{BASH_USAGE}",
                                    self.shell_error("exec: -a: option requires an argument")
                                ),
                            ));
                        }
                        break;
                    }
                    other => {
                        return Err(CommandResult::stderr(
                            2,
                            format!(
                                "{}{BASH_USAGE}",
                                self.shell_error(format_args!("exec: -{other}: invalid option"))
                            ),
                        ));
                    }
                }
            }
            args.command_at = args.command_at.saturating_add(1);
        }
        Ok(args)
    }

    /// The error `exec` reports for options it does not take, if there is one.
    pub(super) fn exec_args_check(&self, parts: &[&str]) -> Result<(), CommandResult> {
        self.exec_args(parts).map(|_| ())
    }

    /// Whether the running `exec` is the builtin, with a command to run (an option error counts as
    /// none: it is reported by whichever path sees it).
    pub(super) fn exec_has_command(&self, parts: &[&str]) -> bool {
        self.exec_args(parts)
            .is_ok_and(|args| args.command_at < parts.len())
    }

    /// Whether the shell goes on after an `exec` that could not start its command: an interactive
    /// bash, and the phone's shell, do; any shell that is reading a script, and dash, do not.
    fn exec_survives(&self) -> bool {
        !self.is_dash() && !self.bash_is_scripted() && !self.top_frame_is_scoped()
    }

    /// The process the running `exec` replaces ends with `result`'s status: a subshell, a pipeline
    /// stage or a script alone, a nested shell level quietly, the login shell with its session.
    fn finish_process(&mut self, mut result: CommandResult) -> CommandResult {
        if self.top_frame_is_scoped() {
            result.flow = Flow::ExitSubshell;
            return result;
        }
        result.stop_line = true;
        if self.open_levels() > 1 {
            self.frames.pop();
        } else {
            result.close_session = true;
        }
        result
    }

    /// An `exec` that could not start: `result` is the message; the shell ends unless it survives,
    /// and then runs its `EXIT` handler as any ending shell does.
    fn exec_refused(&mut self, mut result: CommandResult) -> CommandResult {
        if self.exec_survives() {
            return result;
        }
        self.append_exit_trap(&mut result);
        self.finish_process(result)
    }

    /// Whether `name` can be started by `exec`, or the message and status that say it cannot.
    fn exec_lookup(&mut self, name: &str) -> Result<(), CommandResult> {
        let prefix = self.error_prefix();
        let dash = self.is_dash();
        if name.contains('/') {
            let modeled = Registry::builtin()
                .kind(command_basename(name), self)
                .is_some_and(|kind| kind != CommandKind::Unresolved);
            let path = self.resolve_logical(name);
            if modeled && !self.fs.is_dir(&path) || self.fs.is_executable(&path) {
                return Ok(());
            }
            let refusal = |reason: &str| -> CommandResult {
                if dash {
                    CommandResult::stderr(126, format!("{prefix}: exec: {name}: {reason}\n"))
                } else {
                    CommandResult::stderr(
                        126,
                        format!(
                            "{prefix}: {name}: {reason}\n{prefix}: exec: {name}: cannot execute: {reason}\n"
                        ),
                    )
                }
            };
            return Err(if self.fs.is_dir(&path) {
                refusal(if dash {
                    "Permission denied"
                } else {
                    "Is a directory"
                })
            } else if self.fs.file_exists(&path) {
                refusal("Permission denied")
            } else if dash {
                CommandResult::stderr(127, format!("{prefix}: exec: {name}: not found\n"))
            } else {
                CommandResult::stderr(
                    127,
                    format!("{prefix}: {name}: No such file or directory\n"),
                )
            });
        }
        let found = match Registry::builtin().kind(name, self) {
            Some(CommandKind::External) => true,
            // A builtin has a file too only when the filesystem holds one (`echo`, `kill`).
            Some(CommandKind::Builtin) => !self.path_matches(name, false).is_empty(),
            Some(CommandKind::Unresolved) | None => false,
        };
        if found {
            Ok(())
        } else {
            Err(CommandResult::stderr(
                127,
                format!("{prefix}: exec: {name}: not found\n"),
            ))
        }
    }

    /// `exec COMMAND [ARG...]` (the command is run with the redirections written on the line, and
    /// replaces the shell); `exec` with redirections only is handled before this, by the evaluator.
    pub(super) fn builtin_exec(&mut self, parts: &[&str]) -> CommandResult {
        let args = match self.exec_args(parts) {
            Ok(args) => args,
            Err(usage) => return usage,
        };
        let Some(command) = parts.get(args.command_at..).filter(|c| !c.is_empty()) else {
            return CommandResult::silent(0);
        };
        let Some(&name) = command.first() else {
            return CommandResult::silent(0);
        };
        if let Err(refusal) = self.exec_lookup(name) {
            return self.exec_refused(refusal);
        }
        // A shell exec'd with nothing to run takes the terminal over: a fresh interactive one.
        if self.replaces_shell_level(command) {
            let login = args.login;
            return self.replace_level(command_basename(name), login);
        }
        self.note_exec_fetch(command);
        // The shell is gone once the command starts: nothing of it runs again.
        self.state_mut().traps.clear();
        if args.clear_env {
            self.state_mut().vars.clear();
            // Nothing set `_` for the command either.
            self.env_launch = true;
        }
        // `-a NAME` and `-l` name the process a shell is: its `$0` when it has no operand for it.
        let renamed: Vec<String>;
        let argv: Vec<&str> = match self.exec_argv0(&args, command) {
            Some(name) => {
                renamed = command.iter().map(|word| (*word).to_string()).collect();
                let mut words: Vec<&str> = renamed.iter().map(String::as_str).collect();
                words.push(name);
                words
            }
            None => command.to_vec(),
        };
        let result = self.dispatch_nested(&argv);
        self.finish_process(result)
    }

    /// The `$0` an `exec -a NAME` or `exec -l` gives a shell it starts with `-c SCRIPT` and no
    /// operand after the script.
    fn exec_argv0<'a>(&self, args: &ExecArgs<'a>, command: &[&str]) -> Option<&'a str> {
        let shell = matches!(
            command_basename(command.first()?),
            "sh" | "bash" | "dash" | "ash"
        );
        let script_last =
            command.len() >= 3 && command.get(command.len().saturating_sub(2)) == Some(&"-c");
        if !shell || !script_last {
            return None;
        }
        match (args.name, args.login) {
            (Some(name), _) => Some(name),
            (None, true)
                if command
                    .first()
                    .is_some_and(|c| command_basename(c) == "bash") =>
            {
                Some("-bash")
            }
            (None, true) => Some("-sh"),
            (None, false) => None,
        }
    }

    /// Whether `command` is a shell started with no script, which at the terminal replaces the
    /// shell the user is typing to.
    fn replaces_shell_level(&self, command: &[&str]) -> bool {
        let shell = command
            .first()
            .is_some_and(|name| matches!(command_basename(name), "sh" | "bash" | "dash" | "ash"));
        let plain = command
            .iter()
            .skip(1)
            .all(|word| word.starts_with('-') && !word.contains('c'));
        let at_terminal = !self.bash_is_scripted()
            && !self.in_script()
            && matches!(
                self.frames.last().map(|frame| frame.kind),
                Some(FrameKind::Level(_))
            );
        shell && plain && at_terminal
    }

    /// `exec bash`, `exec sh`: the level being typed to becomes a new interactive shell with
    /// the exported variables and nothing else, and no history yet.
    fn replace_level(&mut self, shell: &str, login: bool) -> CommandResult {
        let level = match (self.active_level(), shell) {
            (ShellLevel::AndroidMksh, _) => ShellLevel::AndroidMksh,
            (_, "bash") => ShellLevel::Bash { login },
            _ => ShellLevel::Dash { line: 0 },
        };
        let state = self.child_state(level);
        if let Some(frame) = self.frames.last_mut() {
            frame.kind = FrameKind::Level(level);
            frame.state = state;
        }
        self.history.clear();
        CommandResult::silent(0)
    }

    /// `exec` with redirections and no command: they change the shell's own descriptors for good.
    /// `plan` is what the redirections made of them.
    pub(super) fn commit_descriptors(
        &mut self,
        sinks: Vec<super::eval::Sink>,
        ins: std::collections::BTreeMap<u16, super::eval::OpenInput>,
    ) {
        let out = sinks
            .into_iter()
            .map(|sink| match sink {
                // A file opened for writing is written on from its end.
                super::eval::Sink::File { path, .. } => {
                    super::eval::Sink::File { path, append: true }
                }
                other => other,
            })
            .collect();
        self.state_mut().fds = Fds { out, ins };
    }

    /// `exec <FILE` at the terminal: the shell reads its commands from the file, runs them, and
    /// ends where the input does.
    pub(super) fn exec_input_script(&mut self, bytes: &[u8]) -> CommandResult {
        let text = String::from_utf8_lossy(bytes).into_owned();
        if !self.charge_work(super::len_u64(text.len())) {
            let mut stopped = CommandResult::silent(1);
            stopped.stop_line = true;
            return stopped;
        }
        let mut result = self.run_script_text(&text);
        if result.stop_line || result.close_session {
            return result;
        }
        let status = result.status;
        let ended = self.exit_shell(status);
        result.append(ended);
        result
    }

    /// Whether `exec <FILE` is the shell's own input being replaced: it is typing to a terminal.
    pub(super) fn exec_reads_commands(&self) -> bool {
        self.tty_input
            && !self.bash_is_scripted()
            && !self.in_script()
            && matches!(
                self.frames.last().map(|frame| frame.kind),
                Some(FrameKind::Level(_))
            )
    }
}
