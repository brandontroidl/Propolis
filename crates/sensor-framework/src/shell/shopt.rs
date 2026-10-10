//! bash's `shopt`: the shell options it lists, sets and unsets, and `shopt -o`, the `set -o` ones.
//!
//! The settings are kept and listed as bash 5.1.16 lists them (the 53 `shopt` names and the 27
//! `set -o` names, in its order, defaults recorded in the reference container with no startup
//! files). Only `expand_aliases` changes what the shell does, through [`FakeShell::aliases_expand`];
//! a bash that runs a script starts with it off, an interactive one with it on. The settings a
//! stock `~/.bashrc` makes (`histappend`) are not applied [unverified]. dash and the phone's mksh
//! have no `shopt`: the name is not found there.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellLevel};

const SHOPT_NAMES: [&str; 53] = [
    "autocd",
    "assoc_expand_once",
    "cdable_vars",
    "cdspell",
    "checkhash",
    "checkjobs",
    "checkwinsize",
    "cmdhist",
    "compat31",
    "compat32",
    "compat40",
    "compat41",
    "compat42",
    "compat43",
    "compat44",
    "complete_fullquote",
    "direxpand",
    "dirspell",
    "dotglob",
    "execfail",
    "expand_aliases",
    "extdebug",
    "extglob",
    "extquote",
    "failglob",
    "force_fignore",
    "globasciiranges",
    "globstar",
    "gnu_errfmt",
    "histappend",
    "histreedit",
    "histverify",
    "hostcomplete",
    "huponexit",
    "inherit_errexit",
    "interactive_comments",
    "lastpipe",
    "lithist",
    "localvar_inherit",
    "localvar_unset",
    "login_shell",
    "mailwarn",
    "no_empty_cmd_completion",
    "nocaseglob",
    "nocasematch",
    "nullglob",
    "progcomp",
    "progcomp_alias",
    "promptvars",
    "restricted_shell",
    "shift_verbose",
    "sourcepath",
    "xpg_echo",
];

const SET_O_NAMES: [&str; 27] = [
    "allexport",
    "braceexpand",
    "emacs",
    "errexit",
    "errtrace",
    "functrace",
    "hashall",
    "histexpand",
    "history",
    "ignoreeof",
    "interactive-comments",
    "keyword",
    "monitor",
    "noclobber",
    "noexec",
    "noglob",
    "nolog",
    "notify",
    "nounset",
    "onecmd",
    "physical",
    "pipefail",
    "posix",
    "privileged",
    "verbose",
    "vi",
    "xtrace",
];

/// The `shopt` options that are on in a fresh bash, besides `expand_aliases` and `login_shell`.
const SHOPT_ON: [&str; 11] = [
    "checkwinsize",
    "cmdhist",
    "complete_fullquote",
    "extquote",
    "force_fignore",
    "globasciiranges",
    "hostcomplete",
    "interactive_comments",
    "progcomp",
    "promptvars",
    "sourcepath",
];

/// The `set -o` options that are on in a fresh bash, besides `histexpand` and `history`.
const SET_O_ON: [&str; 3] = ["braceexpand", "hashall", "interactive-comments"];

/// Most settings one shell keeps different from the default: the names are a closed set, so this
/// is the count of them.
const OVERRIDES_MAX: usize = 80;

pub(super) fn register(r: &mut Registry) {
    r.register_builtin_if("shopt", is_bash, HandlerId::Shopt, FakeShell::builtin_shopt);
    r.register_unresolved(
        "shopt",
        HandlerId::Shopt,
        FakeShell::builtin_shopt_not_found,
    );
}

fn is_bash(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.is_bash()
}

impl FakeShell {
    /// The default of a `shopt` name in the running bash.
    fn shopt_default(&self, name: &str) -> bool {
        let interactive = !self.bash_is_scripted();
        match name {
            "expand_aliases" => interactive,
            "login_shell" => {
                interactive && matches!(self.active_level(), ShellLevel::Bash { login: true })
            }
            other => SHOPT_ON.contains(&other),
        }
    }

    /// The default of a `set -o` name.
    fn set_o_default(&self, name: &str) -> bool {
        match name {
            "histexpand" | "history" => !self.bash_is_scripted(),
            other => SET_O_ON.contains(&other),
        }
    }

    /// Whether the `shopt` option `name` is on in the running shell.
    pub(super) fn shopt_on(&self, name: &str) -> bool {
        self.state()
            .shopt
            .get(name)
            .copied()
            .unwrap_or_else(|| self.shopt_default(name))
    }

    fn set_o_on(&self, name: &str) -> bool {
        self.state()
            .set_o
            .get(name)
            .copied()
            .unwrap_or_else(|| self.set_o_default(name))
    }

    pub(super) fn builtin_shopt_not_found(&mut self, _parts: &[&str]) -> CommandResult {
        CommandResult::stderr(127, self.not_found("shopt"))
    }

    /// `shopt [-pqsu] [-o] [NAME...]`
    pub(super) fn builtin_shopt(&mut self, parts: &[&str]) -> CommandResult {
        let mut args = parts.get(1..).unwrap_or(&[]);
        let (mut print, mut quiet, mut set, mut unset, mut set_o) =
            (false, false, false, false, false);
        while let Some(arg) = args.first() {
            if *arg == "--" {
                args = args.get(1..).unwrap_or(&[]);
                break;
            }
            let Some(flags) = arg.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
                break;
            };
            for flag in flags.chars() {
                match flag {
                    'p' => print = true,
                    'q' => quiet = true,
                    's' => set = true,
                    'u' => unset = true,
                    'o' => set_o = true,
                    other => {
                        return CommandResult::stderr(
                            2,
                            format!(
                                "{}shopt: usage: shopt [-pqsu] [-o] [optname ...]\n",
                                self.shell_error(format_args!("shopt: -{other}: invalid option"))
                            ),
                        );
                    }
                }
            }
            args = args.get(1..).unwrap_or(&[]);
        }
        if set && unset {
            return CommandResult::stderr(
                1,
                self.shell_error("shopt: cannot set and unset shell options simultaneously"),
            );
        }
        let names: Vec<&'static str> = if set_o {
            SET_O_NAMES.to_vec()
        } else {
            SHOPT_NAMES.to_vec()
        };
        let state_of = |shell: &Self, name: &str| {
            if set_o {
                shell.set_o_on(name)
            } else {
                shell.shopt_on(name)
            }
        };
        let line = |shell: &Self, name: &str| -> String {
            let on = state_of(shell, name);
            match (print, set_o) {
                (true, false) => format!("shopt -{} {name}\n", if on { 's' } else { 'u' }),
                (true, true) => format!("set {}o {name}\n", if on { '-' } else { '+' }),
                (false, _) => format!("{name:<15}\t{}\n", if on { "on" } else { "off" }),
            }
        };
        let mut out = CommandResult::silent(0);
        if args.is_empty() {
            if quiet {
                return out;
            }
            for name in names {
                let on = state_of(self, name);
                if (set && !on) || (unset && on) {
                    continue;
                }
                out.append(CommandResult::stdout(line(self, name)));
            }
            return out;
        }
        let invalid = if set_o {
            "invalid option name"
        } else {
            "invalid shell option name"
        };
        let mut status = 0u8;
        for arg in args {
            let Some(name) = names.iter().copied().find(|name| name == arg) else {
                out.append(CommandResult::stderr(
                    1,
                    self.shell_error(format_args!("shopt: {arg}: {invalid}")),
                ));
                // bash 5.1 reports success for a name `-o` could not set or unset.
                if !(set_o && (set || unset)) {
                    status = 1;
                }
                continue;
            };
            if set || unset {
                let table = if set_o {
                    &mut self.state_mut().set_o
                } else {
                    &mut self.state_mut().shopt
                };
                if table.len() < OVERRIDES_MAX {
                    table.insert(name.to_string(), set);
                }
                continue;
            }
            let on = state_of(self, name);
            if !on {
                status = 1;
            }
            if !quiet {
                out.append(CommandResult::stdout(line(self, name)));
            }
        }
        out.status = status;
        out
    }
}
