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

/// The bucket of bash 5.1's 1024-bucket variable table that `name` hashes to (FNV-1, 32 bits).
/// bash builds a child's environment by walking that table bucket by bucket, so this is the order
/// `env` prints in: recorded on Ubuntu 22.04 (2026-10-07), an SSH session's `env` lists `SHELL`,
/// `PWD`, `LOGNAME`, `XDG_SESSION_TYPE`, ..., `PATH`, exactly the ascending buckets of the names.
fn bash_bucket(name: &str) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(16_777_619);
        hash ^= u32::from(byte);
    }
    hash & 1_023
}

/// The exported variables of `vars` as `(name, value)`: in bash's environment order for the
/// Ubuntu shell, by name for the phone's (whose order no capture shows) [unverified for mksh].
fn exported_in_order(vars: &BTreeMap<String, Var>, bash: bool) -> Vec<(&str, &str)> {
    let mut listed: Vec<(&str, &str)> = vars
        .iter()
        .filter(|(_, var)| var.exported)
        .map(|(name, var)| (name.as_str(), var.value.as_str()))
        .collect();
    if bash {
        // `_`, the command's own path, is put last when bash runs it.
        listed.sort_by_key(|(name, _)| (*name == "_", bash_bucket(name), *name));
    } else {
        listed.sort_unstable();
    }
    listed
}

fn render(vars: &BTreeMap<String, Var>, terminator: char, bash: bool) -> String {
    let mut out = String::new();
    for (name, value) in exported_in_order(vars, bash) {
        out.push_str(name);
        out.push('=');
        out.push_str(value);
        out.push(terminator);
    }
    out
}

/// The `LS_COLORS` Ubuntu 22.04's `.bashrc` exports through `dircolors -b` (recorded from an
/// interactive SSH session on the reference, 2026-10-07).
const LS_COLORS: &str = "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:";

/// The persona's own address, the server half of `SSH_CONNECTION` (the one `ip addr` shows).
const SERVER_ADDRESS: &str = "172.31.16.42";

impl FakeShell {
    /// logind's number for this login (`XDG_SESSION_ID`, the `session-N.scope` systemd lists),
    /// fixed by the session.
    pub(super) fn login_session_number(&self) -> u32 {
        let pid = self.frames.first().map_or(0, |frame| frame.state.pid);
        (pid % 9_000).saturating_add(120)
    }

    /// The source port of the client's connection as `SSH_CLIENT` reports it, fixed by the
    /// session.
    pub(super) fn client_port(&self) -> u32 {
        let pid = self.frames.first().map_or(0, |frame| frame.state.pid);
        32_768u32.saturating_add(pid.wrapping_mul(7_919) % 28_232)
    }

    /// The variables a session's login puts in the environment, beyond what every shell has.
    /// Recorded on Ubuntu 22.04 over SSH (2026-10-07): `pam_env` sets `LANG` from
    /// `/etc/default/locale`, `pam_systemd` the `XDG_*` session variables, `pam_motd`
    /// `MOTD_SHOWN=pam`, sshd `SSH_CLIENT`/`SSH_CONNECTION` (and `SSH_TTY` with a terminal), and
    /// the stock `.bashrc` of an interactive shell `LS_COLORS`, `LESSOPEN` and `LESSCLOSE`.
    /// sshd under PAM sets no `MAIL` (recorded: absent from both an exec and an interactive
    /// session). `DBUS_SESSION_BUS_ADDRESS` is the user bus of a server with `dbus-user-session`
    /// [unverified: the reference had no user bus]. A telnet login goes through `login(1)`, which
    /// sets `MAIL` and no `SSH_*` [unverified]. The client half of the SSH variables is the
    /// session's own peer and a port fixed by the session; the server half is the persona's.
    pub(super) fn install_session_env(&mut self) {
        if self.flavor != ShellFlavor::Bash {
            return;
        }
        let ssh = self.ctx.protocol_label == "ssh";
        let interactive = self.context == super::ShellContext::LoginInteractive;
        let session_id = self.login_session_number().to_string();
        let client_port = self.client_port();
        let client = self.ctx.source_ip.to_string();
        let mut set = |name: &str, value: String| self.state_mut().set_var(name, value, true);
        set("LANG", "C.UTF-8".to_string());
        set("SHLVL", "1".to_string());
        set("MOTD_SHOWN", "pam".to_string());
        set("XDG_SESSION_TYPE", "tty".to_string());
        set("XDG_SESSION_CLASS", "user".to_string());
        set("XDG_SESSION_ID", session_id);
        set("XDG_RUNTIME_DIR", "/run/user/0".to_string());
        set(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/run/user/0/bus".to_string(),
        );
        if ssh {
            set("SSH_CLIENT", format!("{client} {client_port} 22"));
            set(
                "SSH_CONNECTION",
                format!("{client} {client_port} {SERVER_ADDRESS} 22"),
            );
        } else {
            set("MAIL", "/var/mail/root".to_string());
        }
        if interactive {
            set("LS_COLORS", LS_COLORS.to_string());
            set("LESSOPEN", "| /usr/bin/lesspipe %s".to_string());
            set("LESSCLOSE", "/usr/bin/lesspipe %s %s".to_string());
        }
        self.set_terminal_env(interactive);
    }

    /// `TERM`, and for SSH `SSH_TTY`, exactly when the session has a terminal.
    pub(super) fn set_terminal_env(&mut self, tty: bool) {
        if self.flavor != ShellFlavor::Bash {
            return;
        }
        let ssh = self.ctx.protocol_label == "ssh";
        let state = self.state_mut();
        if tty {
            // The client's own terminal type is not passed down; the common one stands in
            // [unverified].
            state.set_var("TERM", "xterm-256color".to_string(), true);
            if ssh {
                state.set_var("SSH_TTY", "/dev/pts/0".to_string(), true);
            }
        } else {
            // Without a terminal bash is not interactive and the stock `.bashrc` returns before
            // it sets the `less` and `ls` variables.
            for name in ["TERM", "SSH_TTY", "LS_COLORS", "LESSOPEN", "LESSCLOSE"] {
                state.vars.remove(name);
            }
        }
    }

    /// The environment the shell hands a command it starts from `path`: its exported variables,
    /// `_` set to the command's path, and, under `bash -c` (an SSH exec), `SHLVL` one lower than
    /// the shell's own, as bash exports it to the commands it execs (recorded on Ubuntu 22.04:
    /// `echo $SHLVL` is 1 and `printenv SHLVL` is 0 in the same exec session).
    pub(super) fn child_environment(&self, path: &str) -> BTreeMap<String, Var> {
        let mut vars = self.state().vars.clone();
        if self.flavor == ShellFlavor::Bash && !self.env_launch {
            vars.insert(
                "_".to_string(),
                Var {
                    value: path.to_string(),
                    exported: true,
                },
            );
            if self.context == super::ShellContext::ExecC
                && let Some(level) = vars.get_mut("SHLVL")
                && let Ok(n) = level.value.parse::<i64>()
            {
                level.value = n.saturating_sub(1).max(0).to_string();
            }
        }
        vars
    }
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
        let vars = &self.child_environment("/usr/bin/printenv");
        if names.is_empty() {
            return CommandResult::stdout(render(vars, terminator, true));
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
            // env prints its own environment: what it inherited, in bash's order, edited in
            // place, then each new assignment appended in the order given, as setenv(3) leaves
            // it.
            let mut vars = self.child_environment("/usr/bin/env");
            if plan.ignore {
                vars.retain(|_, var| !var.exported);
            }
            for name in &plan.unsets {
                vars.remove(*name);
            }
            let mut listed: Vec<(String, String)> = exported_in_order(&vars, gnu)
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();
            for (name, value) in &plan.sets {
                match listed
                    .iter_mut()
                    .find(|(listed_name, _)| listed_name == name)
                {
                    Some(slot) => slot.1 = (*value).to_string(),
                    None => listed.push(((*name).to_string(), (*value).to_string())),
                }
            }
            let terminator = if plan.null { '\0' } else { '\n' };
            let mut out = String::new();
            for (name, value) in listed {
                out.push_str(&format!("{name}={value}{terminator}"));
            }
            return CommandResult::stdout(out);
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
        // The command inherits env's own environment, `_` included (bash set it for env), with
        // env's edits applied; no `_` of its own is added for it.
        let mut inherited = self.child_environment("/usr/bin/env");
        plan.apply(&mut inherited);
        self.state_mut().vars = inherited;
        let launched = std::mem::replace(&mut self.env_launch, true);
        let result = self.dispatch_nested(plan.command);
        self.env_launch = launched;
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
