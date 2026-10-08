//! The builtins that act on the shell itself: the working directory, variables, positional
//! parameters, the umask, loop control, `read`, and leaving. Each returns a [`CommandResult`] like
//! any other handler and reaches the shell's state through the evaluator, so they behave the same
//! in a subshell copy as in the login shell.
//!
//! `source`, `.` and `eval` only record intent: what they name is checked for existence and
//! nothing is run, in keeping with the never-exec guarantee that no file is ever handed to an
//! interpreter here.

use super::{CommandResult, FakeShell, Flow, FrameKind, ShellLevel};

/// The default field separators: space, tab, newline.
const DEFAULT_IFS: &str = " \t\n";

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with(|c: char| c.is_ascii_digit())
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Quote a value the way a listing of variables does: bare when it holds only safe characters,
/// else in single quotes.
fn quote_value(value: &str, always: bool) -> String {
    let safe = !always
        && !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    if safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

impl FakeShell {
    pub(super) fn builtin_true(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::silent(0)
    }

    pub(super) fn builtin_false(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::silent(1)
    }

    pub(super) fn builtin_cd(&mut self, parts: &[&str]) -> CommandResult {
        // Only into a directory the box presents: a silent `cd` into a directory that
        // `ls /` never showed is a tell, and a loader's `>/x/.x && cd /x` chain relies on
        // the two agreeing about what exists.
        let operand = parts
            .iter()
            .skip(1)
            .find(|a| !a.starts_with('-') || **a == "-");
        let (typed, announce) = match operand {
            Some(&"-") => match self.state().oldpwd.clone() {
                Some(previous) => (previous, true),
                None => {
                    return CommandResult::stderr(1, self.shell_error("cd: OLDPWD not set"));
                }
            },
            Some(arg) => ((*arg).to_string(), false),
            None => (
                self.state().get("HOME").unwrap_or("/root").to_string(),
                false,
            ),
        };
        let target = self.resolve_logical(&typed);
        if self.fs.is_dir(&target) {
            let out = if announce {
                format!("{target}\n")
            } else {
                String::new()
            };
            self.state_mut().set_cwd(target);
            // `/proc/<login pid>/cwd` is the login shell's directory.
            self.install_processes();
            CommandResult::stdout(out)
        } else {
            CommandResult::stderr(
                1,
                self.shell_error(format_args!("cd: {typed}: No such file or directory")),
            )
        }
    }

    /// `exit [n]`. In a subshell, a pipeline stage or a script run by `sh -c` it ends only that;
    /// in a shell level it leaves the level, and from the login shell it ends the session.
    pub(super) fn builtin_exit(&mut self, parts: &[&str]) -> CommandResult {
        let mut complaint = None;
        let status = match parts.get(1) {
            None => self.state().last_status,
            Some(arg) => match arg.parse::<i64>() {
                Ok(n) => u8::try_from(n & 0xff).unwrap_or(0),
                Err(_) => {
                    complaint = Some(
                        self.shell_error(format_args!("exit: {arg}: numeric argument required")),
                    );
                    2
                }
            },
        };
        let mut result = if self.top_frame_is_scoped() {
            let mut scoped = CommandResult::silent(status);
            scoped.flow = Flow::ExitSubshell;
            scoped
        } else {
            self.exit_shell(status)
        };
        if let Some(message) = complaint {
            let mut first = CommandResult::stderr(2, message);
            first.append(result);
            result = first;
        }
        result
    }

    pub(super) fn builtin_logout(&mut self, _parts: &[&str]) -> CommandResult {
        self.logout_shell()
    }

    /// bash's `history`. An interactive login shell lists what was typed as `%5d  %s` lines
    /// (recorded on Ubuntu 22.04: `    1  echo one`); a shell run by `bash -c`, as an SSH exec is,
    /// keeps no history and lists nothing (recorded: `history | tail -5` printed nothing, status
    /// 0). `-c` clears, `-d N` deletes, `N` lists the last N, and a word that is no number is
    /// bash's `numeric argument required`, status 1, in either shell.
    pub(super) fn builtin_history(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let mut count: Option<usize> = None;
        let mut iter = args.iter();
        while let Some(&arg) = iter.next() {
            match arg {
                "-c" => {
                    self.history.clear();
                    return CommandResult::silent(0);
                }
                "-d" => {
                    let Some(position) = iter.next().and_then(|n| n.parse::<usize>().ok()) else {
                        return CommandResult::stderr(
                            1,
                            self.shell_error("history: -d: option requires an argument"),
                        );
                    };
                    if position == 0 || position > self.history.len() {
                        return CommandResult::stderr(
                            1,
                            self.shell_error(format_args!(
                                "history: {position}: history position out of range"
                            )),
                        );
                    }
                    self.history.remove(position.saturating_sub(1));
                    return CommandResult::silent(0);
                }
                "-a" | "-n" | "-r" | "-w" | "-p" | "-s" => return CommandResult::silent(0),
                "--" => {}
                word => match word.parse::<usize>() {
                    Ok(n) => count = Some(n),
                    Err(_) => {
                        return CommandResult::stderr(
                            1,
                            self.shell_error(format_args!(
                                "history: {word}: numeric argument required"
                            )),
                        );
                    }
                },
            }
        }
        let keeps = self.context == super::ShellContext::LoginInteractive;
        if !keeps {
            return CommandResult::silent(0);
        }
        let total = self.history.len();
        let skip = count.map_or(0, |n| total.saturating_sub(n));
        let mut out = String::new();
        for (index, line) in self.history.iter().enumerate().skip(skip) {
            out.push_str(&format!("{:5}  {line}\n", index.saturating_add(1)));
        }
        CommandResult::stdout(out)
    }

    /// `history` in a shell that has no such builtin (dash, mksh).
    pub(super) fn builtin_history_not_found(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::stderr(127, self.not_found("history"))
    }

    /// Note a line typed at the interactive login shell, as bash with Ubuntu's stock
    /// `HISTCONTROL=ignoreboth` does: a line starting with a space is not kept, nor a repeat of
    /// the line before it. A login shell without a terminal is not interactive and keeps none.
    pub(super) fn record_history(&mut self, raw: &str) {
        if self.context != super::ShellContext::LoginInteractive
            || !self.tty_input
            || !matches!(self.active_level(), ShellLevel::Bash { .. })
            || !self.pending.is_empty()
        {
            return;
        }
        let line = raw.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() || line.starts_with(' ') {
            return;
        }
        let line = super::sanitize_value(line, super::MAX_COMMAND_LEN);
        if self.history.last() == Some(&line) {
            return;
        }
        if self.history.len() >= super::HISTORY_MAX {
            self.history.remove(0);
        }
        self.history.push(line);
    }

    fn top_frame_is_scoped(&self) -> bool {
        self.frames
            .last()
            .is_some_and(|f| matches!(f.kind, FrameKind::Subshell | FrameKind::Script(_)))
    }

    // ---- variables and parameters ----------------------------------------------------------

    /// `export [-p] [-n] [NAME[=value]]...`. Alone it lists what is exported.
    pub(super) fn builtin_export(&mut self, parts: &[&str]) -> CommandResult {
        let mut unexport = false;
        let mut operands: Vec<&str> = Vec::new();
        for arg in parts.iter().skip(1) {
            match *arg {
                "-n" => unexport = true,
                a if a.starts_with('-') && operands.is_empty() => {}
                a => operands.push(a),
            }
        }
        if operands.is_empty() {
            return CommandResult::stdout(self.list_exported());
        }
        let mut errors = String::new();
        for operand in operands {
            let (name, value) = match operand.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (operand, None),
            };
            if !is_name(name) {
                errors.push_str(
                    &self.shell_error(format_args!("export: `{operand}': not a valid identifier")),
                );
                continue;
            }
            if let Some(value) = value {
                self.assign_var(name, value.to_string());
            }
            let state = self.state_mut();
            match state.vars.get_mut(name) {
                Some(var) => var.exported = !unexport,
                None if !unexport => state.set_var(name, String::new(), true),
                None => {}
            }
        }
        if errors.is_empty() {
            CommandResult::silent(0)
        } else {
            CommandResult::stderr(1, errors)
        }
    }

    fn list_exported(&self) -> String {
        let bash = self.is_bash();
        let mut out = String::new();
        for (name, var) in &self.state().vars {
            if !var.exported {
                continue;
            }
            if bash {
                let mut escaped = String::new();
                for c in var.value.chars() {
                    if matches!(c, '\\' | '"' | '$' | '`') {
                        escaped.push('\\');
                    }
                    escaped.push(c);
                }
                out.push_str(&format!("declare -x {name}=\"{escaped}\"\n"));
            } else {
                out.push_str(&format!(
                    "export {name}={}\n",
                    quote_value(&var.value, true)
                ));
            }
        }
        out
    }

    /// `unset [-v] NAME...`.
    pub(super) fn builtin_unset(&mut self, parts: &[&str]) -> CommandResult {
        for arg in parts.iter().skip(1).filter(|a| !a.starts_with('-')) {
            self.state_mut().vars.remove(*arg);
        }
        CommandResult::silent(0)
    }

    /// `set`: alone it lists the variables; `set -- a b` and `set a b` replace the positional
    /// parameters; option flags are accepted and have no effect.
    pub(super) fn builtin_set(&mut self, parts: &[&str]) -> CommandResult {
        let args: Vec<&str> = parts.iter().skip(1).copied().collect();
        if args.is_empty() {
            let bash = self.is_bash();
            let mut out = String::new();
            for (name, var) in &self.state().vars {
                out.push_str(&format!("{name}={}\n", quote_value(&var.value, !bash)));
            }
            return CommandResult::stdout(out);
        }
        let mut i = 0;
        while let Some(arg) = args.get(i) {
            if *arg == "--" {
                i = i.saturating_add(1);
                break;
            }
            if arg.starts_with(['-', '+']) && arg.len() > 1 {
                // `-o name` and `+o name` take the option's name.
                if matches!(*arg, "-o" | "+o") {
                    i = i.saturating_add(1);
                }
                i = i.saturating_add(1);
                continue;
            }
            break;
        }
        let rest: Vec<String> = args.iter().skip(i).map(|a| (*a).to_string()).collect();
        let only_flags = i == args.len() && !args.contains(&"--");
        if !only_flags {
            self.state_mut().positional = rest;
        }
        CommandResult::silent(0)
    }

    /// `shift [n]`.
    pub(super) fn builtin_shift(&mut self, parts: &[&str]) -> CommandResult {
        let count = match parts.get(1) {
            None => 1usize,
            Some(arg) => match arg.parse::<usize>() {
                Ok(n) => n,
                Err(_) => {
                    return CommandResult::stderr(
                        1,
                        self.shell_error(format_args!("shift: {arg}: numeric argument required")),
                    );
                }
            },
        };
        if count > self.state().positional.len() {
            return match self.active_level() {
                ShellLevel::Bash { .. } => CommandResult::stderr(
                    1,
                    self.shell_error(format_args!("shift: {count}: shift count out of range")),
                ),
                _ => CommandResult::stderr(2, self.shell_error("shift: can't shift that many")),
            };
        }
        self.state_mut().positional.drain(..count);
        CommandResult::silent(0)
    }

    /// `umask [-S] [mode]`. The mask is remembered and reported; created files take a fixed mode.
    pub(super) fn builtin_umask(&mut self, parts: &[&str]) -> CommandResult {
        let symbolic = parts.iter().skip(1).any(|a| *a == "-S");
        let mode = parts.iter().skip(1).find(|a| !a.starts_with('-'));
        let Some(mode) = mode else {
            let mask = self.state().umask;
            if symbolic {
                let part = |shift: u16| {
                    let bits = (!mask >> shift) & 0o7;
                    format!(
                        "{}{}{}",
                        if bits & 4 != 0 { "r" } else { "" },
                        if bits & 2 != 0 { "w" } else { "" },
                        if bits & 1 != 0 { "x" } else { "" }
                    )
                };
                return CommandResult::stdout(format!(
                    "u={},g={},o={}\n",
                    part(6),
                    part(3),
                    part(0)
                ));
            }
            return CommandResult::stdout(format!("{mask:04o}\n"));
        };
        match u16::from_str_radix(mode, 8) {
            Ok(mask) if mask <= 0o777 => {
                self.state_mut().umask = mask;
                CommandResult::silent(0)
            }
            _ => CommandResult::stderr(
                1,
                self.shell_error(format_args!("umask: {mode}: octal number out of range")),
            ),
        }
    }

    // ---- loop control ----------------------------------------------------------------------

    pub(super) fn builtin_break(&mut self, parts: &[&str]) -> CommandResult {
        self.loop_control(parts, "break", Flow::Break)
    }

    pub(super) fn builtin_continue(&mut self, parts: &[&str]) -> CommandResult {
        self.loop_control(parts, "continue", Flow::Continue)
    }

    fn loop_control(
        &mut self,
        parts: &[&str],
        name: &str,
        flow: impl Fn(u32) -> Flow,
    ) -> CommandResult {
        let levels = match parts.get(1) {
            None => 1u32,
            Some(arg) => match arg.parse::<u32>() {
                Ok(0) => {
                    return CommandResult::stderr(
                        1,
                        self.shell_error(format_args!("{name}: 0: loop count out of range")),
                    );
                }
                Ok(n) => n,
                Err(_) => {
                    return CommandResult::stderr(
                        1,
                        self.shell_error(format_args!("{name}: {arg}: numeric argument required")),
                    );
                }
            },
        };
        if self.loop_depth == 0 {
            // Bash says so; dash ignores it.
            return match self.active_level() {
                ShellLevel::Bash { .. } => CommandResult::stderr(
                    0,
                    self.shell_error(format_args!(
                        "{name}: only meaningful in a `for', `while', or `until' loop"
                    )),
                ),
                _ => CommandResult::silent(0),
            };
        }
        let mut result = CommandResult::silent(0);
        result.flow = flow(levels);
        result
    }

    // ---- read ------------------------------------------------------------------------------

    /// `read [-r] [-p prompt] [name...]`: one line of standard input into the variables, split at
    /// `$IFS`, the last taking the remainder. Status 1 at end of input. From the terminal there is
    /// nothing to read without another input line, so it reports end of input.
    pub(super) fn builtin_read(&mut self, parts: &[&str]) -> CommandResult {
        let mut raw = false;
        let mut names: Vec<&str> = Vec::new();
        let mut i = 1;
        while let Some(arg) = parts.get(i) {
            if *arg == "--" {
                names.extend(parts.iter().skip(i.saturating_add(1)));
                break;
            }
            match arg.strip_prefix('-').filter(|flags| !flags.is_empty()) {
                Some(flags) => {
                    let takes_value = "pnNtduai";
                    for (at, c) in flags.char_indices() {
                        if c == 'r' {
                            raw = true;
                        } else if takes_value.contains(c) {
                            if at.saturating_add(c.len_utf8()) == flags.len() {
                                i = i.saturating_add(1);
                            }
                            break;
                        }
                    }
                }
                None => names.push(arg),
            }
            i = i.saturating_add(1);
        }
        for name in &names {
            if !is_name(name) {
                return CommandResult::stderr(
                    1,
                    self.shell_error(format_args!("read: `{name}': not a valid identifier")),
                );
            }
        }
        let Some((mut line, mut ended)) = self.stdin.read_line() else {
            return CommandResult::silent(1);
        };
        let mut text = String::from_utf8_lossy(&line).into_owned();
        if !raw {
            // A trailing backslash joins the next line.
            while ended && text.ends_with('\\') && !text.ends_with("\\\\") {
                text.pop();
                match self.stdin.read_line() {
                    Some((next, next_ended)) => {
                        line = next;
                        ended = next_ended;
                        text.push_str(&String::from_utf8_lossy(&line));
                    }
                    None => {
                        ended = false;
                        break;
                    }
                }
            }
            text = unescape_backslashes(&text);
        }
        let ifs = self
            .state()
            .get("IFS")
            .map_or_else(|| DEFAULT_IFS.to_string(), str::to_string);
        if names.is_empty() {
            self.assign_var("REPLY", text);
        } else {
            let values = split_for_read(&text, &ifs, names.len());
            for (index, name) in names.iter().enumerate() {
                let value = values.get(index).cloned().unwrap_or_default();
                self.assign_var(name, value);
            }
        }
        CommandResult::silent(u8::from(!ended))
    }

    // ---- source, . and eval ----------------------------------------------------------------

    /// `. FILE` and `source FILE`: the file is looked up and nothing is run.
    pub(super) fn builtin_source(&mut self, parts: &[&str]) -> CommandResult {
        let Some(file) = parts.get(1) else {
            return CommandResult::stderr(
                2,
                self.shell_error(format_args!(
                    "{}: filename argument required",
                    parts.first().unwrap_or(&".")
                )),
            );
        };
        let path = self.resolve_logical(file);
        if self.fs.file_exists(&path) {
            return CommandResult::silent(0);
        }
        match self.active_level() {
            ShellLevel::Bash { .. } => CommandResult::stderr(
                1,
                self.shell_error(format_args!(
                    "{}: {file}: file not found",
                    parts.first().unwrap_or(&".")
                )),
            ),
            // [unverified] dash's and mksh's wording.
            _ => CommandResult::stderr(2, self.shell_error(format_args!(".: {file}: not found"))),
        }
    }

    /// `eval ARGS`: recorded, not run.
    pub(super) fn builtin_eval(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::silent(0)
    }

    /// What a bare `sh` or `bash` does with a script piped to it: run it as a script in a shell
    /// level of its own. `None` when standard input is a terminal.
    pub(super) fn take_piped_script(&mut self) -> Option<String> {
        self.stdin
            .take_script()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// `\c` becomes `c`, as `read` without `-r` does.
fn unescape_backslashes(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Split a line into `count` fields at `ifs`, the last holding what remains.
fn split_for_read(line: &str, ifs: &str, count: usize) -> Vec<String> {
    let is_ifs = |c: char| ifs.contains(c);
    let is_space = |c: char| ifs.contains(c) && matches!(c, ' ' | '\t' | '\n');
    let mut rest = line.trim_start_matches(is_space);
    let mut fields: Vec<String> = Vec::new();
    while fields.len() < count.saturating_sub(1) && !rest.is_empty() {
        let end = rest.find(is_ifs).unwrap_or(rest.len());
        fields.push(rest.get(..end).unwrap_or("").to_string());
        rest = rest.get(end..).unwrap_or("");
        // One delimiter: surrounding whitespace plus at most one non-whitespace character.
        rest = rest.trim_start_matches(is_space);
        if let Some(c) = rest.chars().next()
            && is_ifs(c)
        {
            rest = rest.get(c.len_utf8()..).unwrap_or("");
            rest = rest.trim_start_matches(is_space);
        }
    }
    if fields.len() < count {
        fields.push(rest.trim_end_matches(is_space).to_string());
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_splits_at_ifs_and_the_last_variable_takes_the_rest() {
        assert_eq!(split_for_read("a b c d", DEFAULT_IFS, 2), ["a", "b c d"]);
        assert_eq!(split_for_read("  a   b  ", DEFAULT_IFS, 3), ["a", "b", ""]);
        assert_eq!(split_for_read("a:b:c", ":", 2), ["a", "b:c"]);
        assert_eq!(split_for_read("only", DEFAULT_IFS, 1), ["only"]);
        assert_eq!(split_for_read("x y  ", DEFAULT_IFS, 1), ["x y"]);
    }

    #[test]
    fn values_are_quoted_only_when_they_need_it() {
        assert_eq!(quote_value("/root", false), "/root");
        assert_eq!(quote_value("a b", false), "'a b'");
        assert_eq!(quote_value("it's", false), "'it'\\''s'");
        assert_eq!(quote_value("plain", true), "'plain'");
        assert_eq!(quote_value("", false), "''");
    }
}
