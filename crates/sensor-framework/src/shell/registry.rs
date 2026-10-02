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

/// What a registered name is to the shell that runs it, the one fact `command -v`, `type` and
/// `which` need beyond "dispatch answers it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CommandKind {
    /// Part of the shell itself (`cd`, `echo`), found before any file on `$PATH`.
    Builtin,
    /// An executable file: found by searching `$PATH`.
    External,
    /// The entry only produces this shell's "not found" reply (`enable` outside bash), so the
    /// name is no command there and every lookup says so.
    Unresolved,
}

struct CommandEntry {
    guard: Option<GuardFn>,
    kind: CommandKind,
    /// What the trace records as the decision for this entry.
    id: HandlerId,
    handler: HandlerFn,
}

/// What the registry knows about the file behind a command name: the physical path of the
/// executable a process running that command has open as `/proc/self/exe`, and the size and mode
/// its node carries. Derived from the binaries table, the same table the filesystem builds its
/// nodes from, so a lookup here and a read of the node cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NodeFacts {
    pub path: &'static str,
    pub size: u64,
    pub mode: u32,
}

/// Command entries by basename. A name may hold several entries: they are tried in registration
/// order and the first whose guard passes (or that has none) answers.
pub(super) struct Registry {
    by_name: HashMap<&'static str, Vec<CommandEntry>>,
    nodes: HashMap<&'static str, NodeFacts>,
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
            nodes: HashMap::new(),
        };
        register_core(&mut registry);
        super::read::register(&mut registry);
        super::dd::register(&mut registry);
        super::readlink::register(&mut registry);
        super::test_builtin::register(&mut registry);
        super::lookup::register(&mut registry);
        super::texttools::register(&mut registry);
        super::printf::register(&mut registry);
        super::base64::register(&mut registry);
        register_nodes(&mut registry);
        registry
    }

    /// The node facts for the command `name`, an alias (`sh`) answering with its target's.
    pub(super) fn node_facts(&self, name: &str) -> Option<NodeFacts> {
        self.nodes.get(name).copied()
    }

    /// Register `handler` as the answer for the executable file `name`.
    ///
    /// Panics if `name` already has an unguarded entry: it would answer every invocation and the
    /// new one could never run.
    pub(super) fn register(&mut self, name: &'static str, id: HandlerId, handler: HandlerFn) {
        self.push(name, None, CommandKind::External, id, handler);
    }

    /// [`Self::register`] for a name that is a file only when `guard` holds. Guarded entries go
    /// before the unguarded entry for the same name.
    pub(super) fn register_if(
        &mut self,
        name: &'static str,
        guard: GuardFn,
        id: HandlerId,
        handler: HandlerFn,
    ) {
        self.push(name, Some(guard), CommandKind::External, id, handler);
    }

    /// Register `handler` as the shell builtin `name`.
    pub(super) fn register_builtin(
        &mut self,
        name: &'static str,
        id: HandlerId,
        handler: HandlerFn,
    ) {
        self.push(name, None, CommandKind::Builtin, id, handler);
    }

    /// [`Self::register_builtin`] for a builtin only when `guard` holds.
    pub(super) fn register_builtin_if(
        &mut self,
        name: &'static str,
        guard: GuardFn,
        id: HandlerId,
        handler: HandlerFn,
    ) {
        self.push(name, Some(guard), CommandKind::Builtin, id, handler);
    }

    /// Register the unguarded fallback for a builtin that only some shells have: `handler` gives
    /// the reply of the shells without it, and every lookup reports the name as not a command.
    pub(super) fn register_unresolved(
        &mut self,
        name: &'static str,
        id: HandlerId,
        handler: HandlerFn,
    ) {
        self.push(name, None, CommandKind::Unresolved, id, handler);
    }

    fn push(
        &mut self,
        name: &'static str,
        guard: Option<GuardFn>,
        kind: CommandKind,
        id: HandlerId,
        handler: HandlerFn,
    ) {
        let entries = self.by_name.entry(name).or_default();
        assert!(
            entries.iter().all(|entry| entry.guard.is_some()),
            "command `{name}` is already registered without a guard"
        );
        entries.push(CommandEntry {
            guard,
            kind,
            id,
            handler,
        });
    }

    /// The entry that answers `name` invoked as `parts` on `shell`: the first whose guard passes.
    fn entry(&self, name: &str, shell: &FakeShell, parts: &[&str]) -> Option<&CommandEntry> {
        self.by_name
            .get(name)?
            .iter()
            .find(|entry| entry.guard.is_none_or(|guard| guard(shell, parts)))
    }

    /// The decision and handler for `name` invoked as `parts` on `shell`, if registered.
    pub(super) fn lookup(
        &self,
        name: &str,
        shell: &FakeShell,
        parts: &[&str],
    ) -> Option<(HandlerId, HandlerFn)> {
        self.entry(name, shell, parts)
            .map(|entry| (entry.id, entry.handler))
    }

    /// What `name` is on `shell`, from the same entry [`Self::lookup`] runs, so a lookup command
    /// and dispatch cannot disagree. `None` when dispatch has no entry for it.
    pub(super) fn kind(&self, name: &str, shell: &FakeShell) -> Option<CommandKind> {
        self.entry(name, shell, &[name]).map(|entry| entry.kind)
    }

    /// Every registered name, for the tests that walk the whole table.
    #[cfg(test)]
    pub(super) fn names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.by_name.keys().copied().collect();
        names.sort_unstable();
        names
    }
}

fn is_bash(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.is_bash()
}

/// The executable `/proc/self/exe` names for a process running the command `exe_of`: the file the
/// kernel reports as the process's binary, not the name it was started by, so a busybox applet is
/// busybox and `sh` is dash. `None` for a command with no file behind it. The one place that
/// answers this, for the byte readers and `readlink`.
pub(super) fn resolve_proc_self(exe_of: &str) -> Option<&'static str> {
    Registry::builtin()
        .node_facts(exe_of)
        .map(|facts| facts.path)
}

/// Record the file behind every command name the binaries table models.
fn register_nodes(r: &mut Registry) {
    for binary in crate::binaries::BINARIES {
        r.nodes.insert(
            binary.name,
            NodeFacts {
                path: binary.path,
                size: binary.size,
                mode: binary.mode,
            },
        );
    }
    for alias in crate::binaries::ALIASES {
        if let Some(facts) = r.nodes.get(alias.target).copied() {
            r.nodes.insert(alias.name, facts);
        }
    }
}

fn register_core(r: &mut Registry) {
    r.register("uname", HandlerId::Uname, FakeShell::builtin_uname);
    r.register("id", HandlerId::Id, FakeShell::builtin_id);
    r.register("whoami", HandlerId::Whoami, FakeShell::builtin_whoami);
    r.register_builtin("pwd", HandlerId::Pwd, FakeShell::builtin_pwd);
    r.register_builtin("echo", HandlerId::Echo, FakeShell::builtin_echo);
    r.register("ls", HandlerId::Ls, FakeShell::cmd_ls);
    r.register("mount", HandlerId::Mount, FakeShell::builtin_mount);
    r.register_builtin_if(
        "enable",
        is_bash,
        HandlerId::EnableBuiltin,
        FakeShell::builtin_enable,
    );
    r.register_unresolved(
        "enable",
        HandlerId::EnableNotFound,
        FakeShell::builtin_enable_not_found,
    );
    for name in ["true", ":"] {
        r.register_builtin(name, HandlerId::TrueColon, FakeShell::builtin_true);
    }
    r.register_builtin("false", HandlerId::False, FakeShell::builtin_false);
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
    r.register_builtin("cd", HandlerId::Cd, FakeShell::builtin_cd);
    r.register("su", HandlerId::Su, FakeShell::builtin_su);
    r.register_builtin("exit", HandlerId::Exit, FakeShell::builtin_exit);
    // Only bash has `logout`; the shells without it answer with their not-found reply.
    r.register_builtin_if(
        "logout",
        is_bash,
        HandlerId::Logout,
        FakeShell::builtin_logout,
    );
    r.register_unresolved("logout", HandlerId::Logout, FakeShell::builtin_logout);
    // The builtins that act on the shell itself. `source` is bash's; dash and mksh have only `.`.
    r.register_builtin("read", HandlerId::Read, FakeShell::builtin_read);
    r.register_builtin("export", HandlerId::Export, FakeShell::builtin_export);
    r.register_builtin("unset", HandlerId::Unset, FakeShell::builtin_unset);
    r.register_builtin("set", HandlerId::Set, FakeShell::builtin_set);
    r.register_builtin("shift", HandlerId::Shift, FakeShell::builtin_shift);
    r.register_builtin("umask", HandlerId::Umask, FakeShell::builtin_umask);
    r.register_builtin("break", HandlerId::Break, FakeShell::builtin_break);
    r.register_builtin("continue", HandlerId::Continue, FakeShell::builtin_continue);
    r.register_builtin(".", HandlerId::SourceEval, FakeShell::builtin_source);
    r.register_builtin_if(
        "source",
        is_bash,
        HandlerId::SourceEval,
        FakeShell::builtin_source,
    );
    r.register_builtin("eval", HandlerId::SourceEval, FakeShell::builtin_eval);
}
