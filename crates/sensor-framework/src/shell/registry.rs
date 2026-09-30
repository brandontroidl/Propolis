//! The command registry: which handler answers which command name. A command is added by
//! registering an entry here (or, for a command family, from that family's own `register`
//! function called from [`Registry::builtin`]), not by editing the dispatcher.
//!
//! The registry holds no handler bodies and builds no `CommandResult`, so the
//! `trace_type_never_feeds_wire_output` source scan of the shell module still covers every place
//! attacker-facing bytes are made.

use std::collections::HashMap;
use std::sync::LazyLock;

use super::{CommandResult, FakeShell, HandlerId};

/// A command's handler: the shell it runs on and the tokenized command, `parts[0]` included.
pub(super) type HandlerFn = fn(&mut FakeShell, &[&str]) -> CommandResult;

/// Whether an entry applies to this invocation, for a name whose handler depends on the shell
/// level or the arguments (`echo $0`, `enable`).
type GuardFn = fn(&FakeShell, &[&str]) -> bool;

struct CommandEntry {
    guard: Option<GuardFn>,
    /// What the trace records as the decision for this entry.
    id: HandlerId,
    handler: HandlerFn,
}

/// Command entries by basename. A name may hold several entries: they are tried in registration
/// order and the first whose guard passes (or that has none) answers.
pub(super) struct Registry {
    by_name: HashMap<&'static str, Vec<CommandEntry>>,
}

static BUILTIN: LazyLock<Registry> = LazyLock::new(Registry::build);

impl Registry {
    /// The registry every shell dispatches through, built once.
    pub(super) fn builtin() -> &'static Registry {
        &BUILTIN
    }

    fn build() -> Self {
        let mut registry = Self {
            by_name: HashMap::new(),
        };
        register_core(&mut registry);
        registry
    }

    /// Register `handler` as the answer for `name`.
    ///
    /// Panics if `name` already has an unguarded entry: it would answer every invocation and the
    /// new one could never run.
    fn register(&mut self, name: &'static str, id: HandlerId, handler: HandlerFn) {
        self.push(name, None, id, handler);
    }

    /// Register `handler` for `name` when `guard` holds. Guarded entries go before the unguarded
    /// entry for the same name.
    fn register_if(
        &mut self,
        name: &'static str,
        guard: GuardFn,
        id: HandlerId,
        handler: HandlerFn,
    ) {
        self.push(name, Some(guard), id, handler);
    }

    fn push(
        &mut self,
        name: &'static str,
        guard: Option<GuardFn>,
        id: HandlerId,
        handler: HandlerFn,
    ) {
        let entries = self.by_name.entry(name).or_default();
        assert!(
            entries.iter().all(|entry| entry.guard.is_some()),
            "command `{name}` is already registered without a guard"
        );
        entries.push(CommandEntry { guard, id, handler });
    }

    /// The decision and handler for `name` invoked as `parts` on `shell`, if registered.
    pub(super) fn lookup(
        &self,
        name: &str,
        shell: &FakeShell,
        parts: &[&str],
    ) -> Option<(HandlerId, HandlerFn)> {
        self.by_name
            .get(name)?
            .iter()
            .find(|entry| entry.guard.is_none_or(|guard| guard(shell, parts)))
            .map(|entry| (entry.id, entry.handler))
    }
}

fn is_bash(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.is_bash()
}

fn register_core(r: &mut Registry) {
    r.register("uname", HandlerId::Uname, FakeShell::builtin_uname);
    r.register("id", HandlerId::Id, FakeShell::builtin_id);
    r.register("whoami", HandlerId::Whoami, FakeShell::builtin_whoami);
    r.register("pwd", HandlerId::Pwd, FakeShell::builtin_pwd);
    r.register("echo", HandlerId::Echo, FakeShell::builtin_echo);
    r.register("cat", HandlerId::Cat, FakeShell::cmd_cat);
    r.register("ls", HandlerId::Ls, FakeShell::cmd_ls);
    r.register("mount", HandlerId::Mount, FakeShell::builtin_mount);
    r.register_if(
        "enable",
        is_bash,
        HandlerId::EnableBuiltin,
        FakeShell::builtin_enable,
    );
    r.register(
        "enable",
        HandlerId::EnableNotFound,
        FakeShell::builtin_enable_not_found,
    );
    for name in ["true", ":"] {
        r.register(name, HandlerId::TrueColon, FakeShell::builtin_true);
    }
    r.register("false", HandlerId::False, FakeShell::builtin_false);
    r.register("wget", HandlerId::Wget, FakeShell::builtin_wget);
    r.register("curl", HandlerId::Curl, FakeShell::builtin_curl);
    r.register("ping", HandlerId::Ping, FakeShell::builtin_ping);
    // Shell-availability fingerprint: every real system has /bin/sh, so "command not found"
    // for sh/bash instantly outs the honeypot and the dropper leaves. Model a nested shell.
    // `ash` is BusyBox's shell and appears in the applet list, so it resolves here too.
    for name in ["sh", "bash", "ash"] {
        r.register(name, HandlerId::ShellSpawn, FakeShell::cmd_shell_spawn);
    }
    // The canonical Mirai/Gafgyt probe is `/bin/busybox <TOKEN>`, which they confirm by the
    // exact "<TOKEN>: applet not found" reply; they also fetch payloads via `busybox wget`
    // and `busybox tftp`.
    r.register("busybox", HandlerId::Busybox, FakeShell::cmd_busybox);
    for name in ["tftp", "ftpget"] {
        r.register(name, HandlerId::Fetcher, FakeShell::builtin_fetcher);
    }
    r.register("chmod", HandlerId::Chmod, FakeShell::builtin_chmod);
    // These change the filesystem the rest of the session sees. Answering silent
    // success while changing nothing let a loader `cp` a payload and then fail to find
    // it, and left a file it had just `rm`ed still readable.
    r.register("cp", HandlerId::Cp, FakeShell::cmd_cp);
    r.register("rm", HandlerId::Rm, FakeShell::cmd_rm);
    r.register("mkdir", HandlerId::Mkdir, FakeShell::cmd_mkdir);
    r.register("sleep", HandlerId::Sleep, FakeShell::builtin_sleep);
    r.register("cd", HandlerId::Cd, FakeShell::builtin_cd);
    r.register("su", HandlerId::Su, FakeShell::builtin_su);
    r.register("exit", HandlerId::Exit, FakeShell::builtin_exit);
    r.register("logout", HandlerId::Logout, FakeShell::builtin_logout);
    // The builtins that act on the shell itself. `source` is bash's; dash and mksh have only `.`.
    r.register("read", HandlerId::Read, FakeShell::builtin_read);
    r.register("export", HandlerId::Export, FakeShell::builtin_export);
    r.register("unset", HandlerId::Unset, FakeShell::builtin_unset);
    r.register("set", HandlerId::Set, FakeShell::builtin_set);
    r.register("shift", HandlerId::Shift, FakeShell::builtin_shift);
    r.register("umask", HandlerId::Umask, FakeShell::builtin_umask);
    r.register("break", HandlerId::Break, FakeShell::builtin_break);
    r.register("continue", HandlerId::Continue, FakeShell::builtin_continue);
    r.register(".", HandlerId::SourceEval, FakeShell::builtin_source);
    r.register_if(
        "source",
        is_bash,
        HandlerId::SourceEval,
        FakeShell::builtin_source,
    );
    r.register("eval", HandlerId::SourceEval, FakeShell::builtin_eval);
}
