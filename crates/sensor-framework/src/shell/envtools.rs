//! `env` and `printenv`: the commands an enumeration script reads the environment with.
//!
//! Both read the session's own variables, the exported ones, so what they print cannot disagree
//! with `export`, `$HOME` or what a nested shell inherits. Nothing here starts a process, reads
//! the host or opens a socket. `env COMMAND` runs `COMMAND` through the shell's depth-capped
//! nested dispatch, and only when the registry models it as an executable file: a shell builtin
//! that changes the shell (`cd`, `export`) is no file, so `env cd /` is "No such file or
//! directory", as it is on a real system.
//!
//! Output order is by variable name, always. GNU `env` and `printenv` print in the process's
//! environment order, which is not name order; this shell sorts [unverified] so a replay with a
//! fixed session is byte-stable and does not depend on how a map iterates.
//!
//! `env` exists on both personas (coreutils on Ubuntu, toybox on the phone); `printenv` is GNU
//! coreutils and exists on the Ubuntu persona only, because no toybox build was captured that
//! carries it. Wording below the persona's own facts is composed from knowledge of coreutils 8.32
//! and toybox, not captured, and is marked `[unverified]` where written.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;

use super::eval::Var;
use super::multicall::PURE_BUILTINS;
use super::registry::{CommandKind, Registry};
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, command_basename};

pub(super) fn register(r: &mut Registry) {
    r.register("env", HandlerId::Env, FakeShell::cmd_env);
    r.register_if(
        "printenv",
        ubuntu,
        HandlerId::Printenv,
        FakeShell::cmd_printenv,
    );
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// GNU `env`'s exit status for a failure of `env` itself, and `printenv`'s for a bad option.
const ENV_CANCELED: u8 = 125;
const ENV_CANNOT_INVOKE: u8 = 126;
const ENV_NOT_FOUND: u8 = 127;
const PRINTENV_USAGE: u8 = 2;

fn try_help(cmd: &str) -> String {
    format!("Try '{cmd} --help' for more information.\n")
}

fn invalid_short(cmd: &str, flag: char) -> String {
    format!("{cmd}: invalid option -- '{flag}'\n{}", try_help(cmd))
}

fn unrecognized_long(cmd: &str, arg: &str) -> String {
    format!("{cmd}: unrecognized option '{arg}'\n{}", try_help(cmd))
}

/// The exported variables of `vars` as `(name, value)`, sorted by name.
fn exported_sorted(vars: &BTreeMap<String, Var>) -> Vec<(&str, &str)> {
    let mut listed: Vec<(&str, &str)> = vars
        .iter()
        .filter(|(_, var)| var.exported)
        .map(|(name, var)| (name.as_str(), var.value.as_str()))
        .collect();
    listed.sort_unstable();
    listed
}

fn render(vars: &BTreeMap<String, Var>, terminator: char) -> String {
    let mut out = String::new();
    for (name, value) in exported_sorted(vars) {
        out.push_str(name);
        out.push('=');
        out.push_str(value);
        out.push(terminator);
    }
    out
}

/// What `env`'s options and operands ask for: the edits to the environment, in the order they
/// apply, and the command to run under them.
struct EnvPlan<'a> {
    ignore: bool,
    null: bool,
    unsets: Vec<&'a str>,
    sets: Vec<(&'a str, &'a str)>,
    command: &'a [&'a str],
}

impl EnvPlan<'_> {
    /// The environment these edits make of `vars`: `-i` first, then each `-u`, then each
    /// assignment.
    fn apply(&self, vars: &mut BTreeMap<String, Var>) {
        if self.ignore {
            vars.retain(|_, var| !var.exported);
        }
        for name in &self.unsets {
            vars.remove(*name);
        }
        for (name, value) in &self.sets {
            vars.insert(
                (*name).to_string(),
                Var {
                    value: (*value).to_string(),
                    exported: true,
                },
            );
        }
    }
}

impl FakeShell {
    /// `printenv [-0] [NAME]...`: the exported variables, or the value of each name given.
    pub(super) fn cmd_printenv(&mut self, parts: &[&str]) -> CommandResult {
        let mut null = false;
        let mut names: Vec<&str> = Vec::new();
        let mut options_done = false;
        for arg in parts.iter().skip(1) {
            if options_done || !arg.starts_with('-') || *arg == "-" {
                names.push(arg);
            } else if *arg == "--" {
                options_done = true;
            } else if let Some(long) = arg.strip_prefix("--") {
                if long == "null" {
                    null = true;
                } else {
                    return CommandResult::stderr(
                        PRINTENV_USAGE,
                        unrecognized_long("printenv", arg),
                    );
                }
            } else {
                for flag in arg.chars().skip(1) {
                    if flag == '0' {
                        null = true;
                    } else {
                        return CommandResult::stderr(
                            PRINTENV_USAGE,
                            invalid_short("printenv", flag),
                        );
                    }
                }
            }
        }
        let terminator = if null { '\0' } else { '\n' };
        let vars = &self.state().vars;
        if names.is_empty() {
            return CommandResult::stdout(render(vars, terminator));
        }
        let mut out = String::new();
        let mut missing = false;
        for name in names {
            // A name holding `=` can never be a variable's name, so it is never found.
            let found = vars
                .get(name)
                .filter(|var| var.exported && !name.contains('='));
            match found {
                Some(var) => {
                    out.push_str(&var.value);
                    out.push(terminator);
                }
                None => missing = true,
            }
        }
        let mut result = CommandResult::stdout(out);
        result.status = u8::from(missing);
        result
    }

    /// `env [-i] [-u NAME]... [NAME=VALUE]... [COMMAND [ARG]...]`.
    pub(super) fn cmd_env(&mut self, parts: &[&str]) -> CommandResult {
        let gnu = self.flavor == ShellFlavor::Bash;
        let plan = match parse_env(parts, gnu) {
            Ok(plan) => plan,
            Err(refusal) => return refusal,
        };
        if plan.command.is_empty() {
            let mut vars = self.state().vars.clone();
            plan.apply(&mut vars);
            let terminator = if plan.null { '\0' } else { '\n' };
            return CommandResult::stdout(render(&vars, terminator));
        }
        if plan.null {
            return CommandResult::stderr(
                ENV_CANCELED,
                format!(
                    "env: cannot specify --null (-0) with command\n{}",
                    try_help("env")
                ),
            );
        }
        let Some(program) = plan.command.first().copied() else {
            return CommandResult::silent(0);
        };
        if let Some(refusal) = self.env_cannot_run(program, gnu) {
            return refusal;
        }
        // The edits are the command's environment alone. They go on the frame that is active now,
        // and that same frame gets the session's variables back, so a command that opens or leaves
        // a shell level cannot make the restore land on another level's state.
        let frame = self.frames.len().saturating_sub(1);
        let saved = self.state().vars.clone();
        plan.apply(&mut self.state_mut().vars);
        let result = self.dispatch_nested(plan.command);
        if let Some(level) = self.frames.get_mut(frame) {
            level.state.vars = saved;
        }
        result
    }

    /// The refusal for a COMMAND `env` could not execute, or `None` when the shell models it as
    /// an executable file.
    fn env_cannot_run(&mut self, program: &str, gnu: bool) -> Option<CommandResult> {
        let base = command_basename(program);
        let modeled = match Registry::builtin().kind(base, self) {
            Some(CommandKind::External) => true,
            Some(CommandKind::Builtin) => PURE_BUILTINS.contains(&base),
            Some(CommandKind::Unresolved) => false,
            None => {
                program.contains('/') && {
                    let path = self.resolve_logical(program);
                    self.fs.is_executable(&path)
                }
            }
        };
        if modeled {
            return None;
        }
        let blocked = program.contains('/') && {
            let path = self.resolve_logical(program);
            self.fs.file_exists(&path) || self.fs.is_dir(&path)
        };
        let (status, reason) = if blocked {
            (ENV_CANNOT_INVOKE, "Permission denied")
        } else {
            (ENV_NOT_FOUND, "No such file or directory")
        };
        // [unverified] coreutils 8.32 quotes the name with ASCII quotes in the C locale; toybox
        // reports a failed exec as `env: exec NAME: reason`.
        let text = if gnu {
            format!("env: '{program}': {reason}\n")
        } else {
            format!("env: exec {program}: {reason}\n")
        };
        Some(CommandResult::stderr(status, text))
    }
}

/// Read `env`'s options, then its `NAME=VALUE` operands, then the command. Options end at the
/// first operand, as GNU's do, so the command's own flags are never read as `env`'s.
fn parse_env<'a>(parts: &'a [&'a str], gnu: bool) -> Result<EnvPlan<'a>, CommandResult> {
    let usage_error =
        |text: String| CommandResult::stderr(if gnu { ENV_CANCELED } else { 1 }, text);
    let bad_flag = |flag: char| {
        usage_error(if gnu {
            invalid_short("env", flag)
        } else {
            // [unverified] toybox's wording.
            format!("env: Unknown option '{flag}'\n")
        })
    };
    let mut plan = EnvPlan {
        ignore: false,
        null: false,
        unsets: Vec::new(),
        sets: Vec::new(),
        command: &[],
    };
    let mut at = 1usize;
    while let Some(arg) = parts.get(at).copied() {
        if arg == "--" {
            at = at.saturating_add(1);
            break;
        }
        if arg == "-" {
            plan.ignore = true;
            at = at.saturating_add(1);
            continue;
        }
        let Some(flags) = arg.strip_prefix('-') else {
            break;
        };
        at = at.saturating_add(1);
        if let Some(long) = flags.strip_prefix('-') {
            match long.split_once('=') {
                None if long == "ignore-environment" => plan.ignore = true,
                None if long == "null" && gnu => plan.null = true,
                None if long == "unset" => {
                    let Some(name) = parts.get(at).copied() else {
                        return Err(usage_error(format!(
                            "env: option '--unset' requires an argument\n{}",
                            try_help("env")
                        )));
                    };
                    at = at.saturating_add(1);
                    plan.unsets.push(name);
                }
                Some(("unset", name)) => plan.unsets.push(name),
                _ => return Err(usage_error(unrecognized_long("env", arg))),
            }
            continue;
        }
        for (index, flag) in flags.char_indices() {
            match flag {
                'i' => plan.ignore = true,
                '0' if gnu => plan.null = true,
                'u' => {
                    let attached = flags.get(index.saturating_add(1)..).unwrap_or("");
                    if attached.is_empty() {
                        let Some(name) = parts.get(at).copied() else {
                            return Err(usage_error(format!(
                                "env: option requires an argument -- 'u'\n{}",
                                try_help("env")
                            )));
                        };
                        at = at.saturating_add(1);
                        plan.unsets.push(name);
                    } else {
                        plan.unsets.push(attached);
                    }
                    break;
                }
                other => return Err(bad_flag(other)),
            }
        }
    }
    if gnu
        && let Some(name) = plan
            .unsets
            .iter()
            .find(|name| name.is_empty() || name.contains('='))
    {
        return Err(usage_error(format!(
            "env: cannot unset '{name}': Invalid argument\n"
        )));
    }
    while let Some(arg) = parts.get(at).copied() {
        match arg.split_once('=') {
            Some((name, value)) if !name.is_empty() => plan.sets.push((name, value)),
            _ => break,
        }
        at = at.saturating_add(1);
    }
    plan.command = parts.get(at..).unwrap_or(&[]);
    Ok(plan)
}
