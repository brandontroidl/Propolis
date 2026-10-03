//! The process table and the commands that read it: `ps`, `top`, `pgrep`, `pidof`, `kill`,
//! `killall` and `pkill`, plus the `/proc/<pid>` tree the filesystem serves for the same rows.
//!
//! Attackers enumerate and clear processes (`ps w | grep -E 'miner|bot'`, `pkill -9 miner`,
//! `killall -9 bot`, a loop over `/proc/[0-9]*`). Nothing here starts, signals or inspects a
//! process of the host. The table is a small set of modeled rows built from the persona and the
//! session, the commands read it, and `kill`, `killall` and `pkill` report what a signal sent to
//! those rows would report. A signal is intent only: it is never delivered, so the table does not
//! change, and the command line that asked for it is already the recorded evidence (the command
//! event). Killing the shell's own row or the daemon's therefore leaves the session running.
//!
//! The rows, per persona (every pid, size and time below is [unverified]; no capture exists):
//!
//! * Ubuntu over SSH: `systemd` (1), `cron` (641), the `sshd` listener (721), the session's
//!   `sshd` child and the login `bash`. Over telnet the listener is `telnetd` and the shell is its
//!   direct child.
//! * Android: `init` (1), `adbd` (143), `zygote` (598) and the login `sh` under `adbd`.
//!
//! The login shell's row is the shell's own: its pid is `$$`, its argv is what
//! `/proc/$$/cmdline` already answers, and its binary is the one `/proc/self/exe` gives a shell
//! (the same `resolve_proc_self` lookup). A process the attacker tries to kill (a miner, a bot) is
//! not in the table, which is correct: nothing of the kind runs here, so the not-found replies
//! below are the honest ones. Pids the session itself spawns (a background job, a nested shell)
//! take the allocator's next numbers; `kill` accepts those as live, and `ps` does not list them.
//!
//! The filesystem side is the `generated` layer of [`crate::fakefs::FakeFs`]: this module hands it
//! `/proc/<pid>/{cmdline,comm,stat,status,exe,cwd,mounts,mountinfo}` for every row, rebuilt from the
//! table whenever the session clock or the login shell's directory changes. A pid outside the table
//! has no node and reads as absent, as on a real `/proc`.
//!
//! Only `ps` and `top` are transient processes: each lists itself, with the next pid the session
//! allocator hands out, as the real tools list themselves.
//!
//! Output wording is composed from knowledge of procps-ng 3.3.17, psmisc 23.4, sysvinit's `pidof`,
//! BusyBox 1.30 and Android 6's toolbox, not from a capture, and every layout and message below is
//! [unverified] unless a comment says otherwise. No pattern engine exists elsewhere in the shell,
//! so `pgrep` and `pkill` carry a small one: alternation, a single level of groups, `^`, `$`, `.`,
//! bracket classes and the `*`, `+`, `?` quantifiers on one atom.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::collections::HashMap;

use chrono::{DateTime, Datelike, TimeDelta, Utc};

use super::hostinfo::{expand, load_average, uptime_secs, uptime_short};
use super::registry::{Registry, resolve_proc_self};
use super::{CommandResult, FakeShell, HandlerId, ShellContext, ShellFlavor};
use crate::fakefs::{Blob, ELF_HEADER_LEN, ElfImage, Node};

pub(super) fn register(r: &mut Registry) {
    r.register("ps", HandlerId::Ps, FakeShell::cmd_ps);
    r.register("top", HandlerId::Top, FakeShell::cmd_top);
    r.register_builtin("kill", HandlerId::Kill, FakeShell::cmd_kill);
    // The phone's toolbox ships none of these [unverified], so there they are "not found".
    r.register_if("pgrep", ubuntu, HandlerId::Pgrep, FakeShell::cmd_pgrep);
    r.register_if("pidof", ubuntu, HandlerId::Pidof, FakeShell::cmd_pidof);
    r.register_if(
        "killall",
        ubuntu,
        HandlerId::Killall,
        FakeShell::cmd_killall,
    );
    r.register_if("pkill", ubuntu, HandlerId::Pkill, FakeShell::cmd_pkill);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// Kernel clock ticks per second, as `/proc/<pid>/stat` counts start times.
const HZ: u64 = 100;
/// The memory the modeled host reports in `top` and for `%MEM`: 3923.7 MiB [unverified].
const MEM_TOTAL_KIB: u64 = 4_017_836;
const MEM_FREE_KIB: u64 = 2_405_196;
const MEM_USED_KIB: u64 = 330_212;
const MEM_CACHE_KIB: u64 = 1_282_428;
const MEM_AVAIL_KIB: u64 = 3_452_180;
/// The most text any one reply holds.
const OUT_MAX: usize = 16_384;
/// The longest pattern or process name the matcher looks at.
const PATTERN_MAX: usize = 256;
const TEXT_MAX: usize = 512;
/// The most alternatives a pattern with groups expands to.
const ALTERNATIVES_MAX: usize = 64;

// ---------------------------------------------------------------------------------------- model

/// When a process started, which is what its start-time columns show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Started {
    /// Clock ticks after boot.
    Boot(u64),
    /// When this session began.
    Session,
    /// The moment the command that lists it runs (`ps` and `top` themselves).
    Now,
}

#[derive(Debug, Clone)]
struct Proc {
    pid: u32,
    ppid: u32,
    /// The kernel's short name, at most 15 characters.
    comm: String,
    /// The argument vector, empty for none.
    argv: Vec<String>,
    /// The `/proc/<pid>/stat` state letter: `S` or `R`.
    state: char,
    /// What follows the state letter in the BSD `STAT` column.
    mark: &'static str,
    /// `pts/0`, or `?` for none.
    tty: &'static str,
    started: Started,
    vsz_kib: u64,
    rss_kib: u64,
    cpu_secs: u64,
    /// The android toolbox `WCHAN` column.
    wchan: &'static str,
    exe: String,
    cwd: String,
    /// Part of this session's terminal group: what a bare `ps` lists.
    attached: bool,
}

impl Proc {
    fn stat_column(&self) -> String {
        format!("{}{}", self.state, self.mark)
    }

    /// The command line as `ps` prints it: the arguments joined by spaces, or `[comm]` for a
    /// process with none.
    fn args(&self) -> String {
        if self.argv.is_empty() {
            format!("[{}]", self.comm)
        } else {
            self.argv.join(" ")
        }
    }
}

struct Table {
    procs: Vec<Proc>,
    boot: DateTime<Utc>,
    session: DateTime<Utc>,
    now: DateTime<Utc>,
    android: bool,
}

fn seconds(n: u64) -> TimeDelta {
    i64::try_from(n)
        .ok()
        .and_then(TimeDelta::try_seconds)
        .unwrap_or_default()
}

impl Table {
    fn started_at(&self, p: &Proc) -> DateTime<Utc> {
        match p.started {
            Started::Boot(ticks) => self
                .boot
                .checked_add_signed(seconds(ticks.div_euclid(HZ)))
                .unwrap_or(self.boot),
            Started::Session => self.session,
            Started::Now => self.now,
        }
    }

    /// Clock ticks between boot and the process's start, the figure `stat` carries.
    fn start_ticks(&self, p: &Proc) -> u64 {
        match p.started {
            Started::Boot(ticks) => ticks,
            Started::Session | Started::Now => {
                let at = self.started_at(p);
                let secs = at.signed_duration_since(self.boot).num_seconds();
                u64::try_from(secs).unwrap_or(0).saturating_mul(HZ)
            }
        }
    }

    fn elapsed_secs(&self, p: &Proc) -> u64 {
        let secs = self
            .now
            .signed_duration_since(self.started_at(p))
            .num_seconds();
        u64::try_from(secs).unwrap_or(0).max(1)
    }

    fn find(&self, pid: u32) -> Option<&Proc> {
        self.procs.iter().find(|p| p.pid == pid)
    }
}

/// The recorded-shape ELF64 header the stand-in system binaries start with: little-endian
/// x86-64 shared object, 13 program headers. Not recorded from a host [unverified].
const GENERIC_HEADER: [u8; ELF_HEADER_LEN] = [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x14, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x0d, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00,
];

impl FakeShell {
    /// The login shell's pid and working directory: the first frame, whatever nested shells or
    /// subshells are open above it.
    fn login_shell(&self) -> (u32, String) {
        self.frames
            .first()
            .map(|frame| (frame.state.pid, frame.state.cwd.clone()))
            .unwrap_or_default()
    }

    /// The session's terminal: a pty for an interactive shell, none for an exec request.
    fn session_tty(&self) -> &'static str {
        match self.context {
            ShellContext::ExecC => "?",
            ShellContext::LoginInteractive | ShellContext::AndroidMksh => "pts/0",
        }
    }

    /// The modeled process table as of the shell clock.
    fn process_table(&self) -> Table {
        let now = self.now();
        let boot = now
            .checked_sub_signed(seconds(uptime_secs(&now)))
            .unwrap_or(now);
        let session = self.session_started.clamp(boot, now);
        let (login, cwd) = self.login_shell();
        let tty = self.session_tty();
        let android = self.flavor == ShellFlavor::AndroidSh;
        let shell_argv = match self.context {
            ShellContext::LoginInteractive => "-bash",
            ShellContext::ExecC => "bash",
            ShellContext::AndroidMksh => "sh",
        };
        let procs = if android {
            android_rows(login, cwd, shell_argv, tty)
        } else {
            let telnet = self.ctx.protocol_label == "telnet";
            let exec = self.context == ShellContext::ExecC;
            ubuntu_rows(login, cwd, shell_argv, tty, telnet, exec)
        };
        Table {
            procs,
            boot,
            session,
            now,
            android,
        }
    }

    /// Rebuild the `/proc/<pid>` tree from the table and hand it to the filesystem. Called when
    /// the shell is built, when its clock is replaced, and when the login shell changes
    /// directory: everything the nodes show is a function of those.
    pub(super) fn install_processes(&mut self) {
        let table = self.process_table();
        let mounts = self
            .fs
            .read_all("/proc/self/mounts", 16_384)
            .unwrap_or_default();
        let mountinfo = self
            .fs
            .read_all("/proc/self/mountinfo", 16_384)
            .unwrap_or_default();
        let nodes = process_nodes(&table, &mounts, &mountinfo);
        self.fs.set_generated(nodes);
    }
}

fn root_proc(
    pid: u32,
    ppid: u32,
    comm: &str,
    argv: &[&str],
    exe: &str,
    started: Started,
    sizes: (u64, u64, u64),
) -> Proc {
    Proc {
        pid,
        ppid,
        comm: comm.chars().take(15).collect(),
        argv: argv.iter().map(|a| (*a).to_string()).collect(),
        state: 'S',
        mark: "s",
        tty: "?",
        started,
        vsz_kib: sizes.0,
        rss_kib: sizes.1,
        cpu_secs: sizes.2,
        wchan: "SyS_epoll_",
        exe: exe.to_string(),
        cwd: "/".to_string(),
        attached: false,
    }
}

fn ubuntu_rows(
    login: u32,
    cwd: String,
    shell_argv: &str,
    tty: &'static str,
    telnet: bool,
    exec: bool,
) -> Vec<Proc> {
    const DAEMON_PID: u32 = 721;
    let mut rows = vec![
        root_proc(
            1,
            0,
            "systemd",
            &["/sbin/init"],
            "/usr/lib/systemd/systemd",
            Started::Boot(100),
            (167_800, 11_484, 3),
        ),
        root_proc(
            641,
            1,
            "cron",
            &["/usr/sbin/cron", "-f", "-P"],
            "/usr/sbin/cron",
            Started::Boot(1_480),
            (8_536, 2_940, 0),
        ),
    ];
    let shell_parent = if telnet {
        rows.push(root_proc(
            DAEMON_PID,
            1,
            "telnetd",
            &["/usr/sbin/telnetd"],
            "/usr/sbin/telnetd",
            Started::Boot(1_790),
            (7_320, 1_780, 0),
        ));
        DAEMON_PID
    } else {
        rows.push(root_proc(
            DAEMON_PID,
            1,
            "sshd",
            &["sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"],
            "/usr/sbin/sshd",
            Started::Boot(1_790),
            (15_440, 9_060, 0),
        ));
        // sshd forks the session's child a few pids before the shell it starts.
        let child = login.saturating_sub(6).max(DAEMON_PID.saturating_add(1));
        let title = if exec {
            "sshd: root@notty"
        } else {
            "sshd: root@pts/0"
        };
        let mut session = root_proc(
            child,
            DAEMON_PID,
            "sshd",
            &[title],
            "/usr/sbin/sshd",
            Started::Session,
            (17_236, 10_184, 0),
        );
        session.wchan = "do_select";
        rows.push(session);
        child
    };
    rows.push(Proc {
        tty,
        attached: true,
        cwd,
        wchan: "do_wait",
        ..root_proc(
            login,
            shell_parent,
            "bash",
            &[shell_argv],
            resolve_proc_self("bash").unwrap_or("/usr/bin/bash"),
            Started::Session,
            (10_548, 5_380, 0),
        )
    });
    rows.sort_by_key(|p| p.pid);
    rows
}

fn android_rows(login: u32, cwd: String, shell_argv: &str, tty: &'static str) -> Vec<Proc> {
    const ADBD_PID: u32 = 143;
    let mut rows = vec![
        root_proc(
            1,
            0,
            "init",
            &["/init"],
            "/init",
            Started::Boot(1),
            (3_588, 604, 1),
        ),
        root_proc(
            ADBD_PID,
            1,
            "adbd",
            &["/sbin/adbd"],
            "/sbin/adbd",
            Started::Boot(612),
            (5_392, 1_264, 0),
        ),
        Proc {
            wchan: "poll_sche",
            ..root_proc(
                598,
                1,
                "zygote",
                &["zygote"],
                "/system/bin/app_process",
                Started::Boot(1_542),
                (1_533_992, 83_640, 4),
            )
        },
    ];
    rows.push(Proc {
        tty,
        attached: true,
        cwd,
        wchan: "do_wait",
        ..root_proc(
            login,
            ADBD_PID,
            "sh",
            &[shell_argv],
            "/system/bin/sh",
            Started::Session,
            (2_196, 1_112, 0),
        )
    });
    rows.sort_by_key(|p| p.pid);
    rows
}

// ---------------------------------------------------------------------------------- /proc nodes

fn file_node(text: impl Into<Vec<u8>>, mtime: i64) -> Node {
    let mut node = Node::regular(Blob::from_bytes(text), 0o100_444);
    node.meta.mtime = mtime;
    node
}

fn link_node(target: &str, mtime: i64) -> Node {
    let mut node = Node::symlink(target);
    node.meta.mtime = mtime;
    node
}

/// A modeled system binary: the generic header and filler out to `len`.
fn stub_binary(len: u64) -> Node {
    Node::regular(
        Blob::elf(ElfImage {
            header: GENERIC_HEADER,
            len,
            newline_at: None,
        }),
        0o100_755,
    )
}

fn process_nodes(table: &Table, mounts: &[u8], mountinfo: &[u8]) -> HashMap<String, Node> {
    let mut nodes = HashMap::new();
    for p in &table.procs {
        let mtime = table.started_at(p).timestamp();
        let base = format!("/proc/{}", p.pid);
        let entries = [
            "cmdline",
            "comm",
            "cwd",
            "exe",
            "mountinfo",
            "mounts",
            "stat",
            "status",
        ];
        let mut dir = Node::directory(entries.iter().map(|e| (*e).to_string()).collect());
        dir.meta.mode = 0o040_555;
        dir.meta.mtime = mtime;
        nodes.insert(base.clone(), dir);
        nodes.insert(
            format!("{base}/cmdline"),
            file_node(cmdline_bytes(p), mtime),
        );
        nodes.insert(
            format!("{base}/comm"),
            file_node(format!("{}\n", p.comm), mtime),
        );
        nodes.insert(format!("{base}/cwd"), link_node(&p.cwd, mtime));
        nodes.insert(format!("{base}/exe"), link_node(&p.exe, mtime));
        nodes.insert(format!("{base}/mountinfo"), file_node(mountinfo, mtime));
        nodes.insert(format!("{base}/mounts"), file_node(mounts, mtime));
        nodes.insert(
            format!("{base}/stat"),
            file_node(stat_line(table, p), mtime),
        );
        nodes.insert(
            format!("{base}/status"),
            file_node(status_text(table, p), mtime),
        );
    }
    let boot = table.boot.timestamp();
    if table.android {
        // The two binaries the persona's listing already names but holds no node for.
        for path in ["/init", "/sbin/adbd"] {
            let mut stub = Node::regular(
                Blob::from_bytes(b"\x7fELF\x01\x01\x01\0".to_vec()),
                0o100_750,
            );
            stub.meta.mtime = boot;
            nodes.insert(path.to_string(), stub);
        }
    } else {
        let binaries: [(&str, u64); 4] = [
            ("/usr/lib/systemd/systemd", 1_841_488),
            ("/usr/sbin/sshd", 1_070_560),
            ("/usr/sbin/cron", 56_048),
            ("/usr/sbin/telnetd", 51_512),
        ];
        for (path, len) in binaries {
            if table.procs.iter().any(|p| p.exe == path) {
                let mut node = stub_binary(len);
                node.meta.mtime = boot;
                nodes.insert(path.to_string(), node);
            }
        }
        let mut dir = Node::directory(vec!["systemd".to_string()]);
        dir.meta.mtime = boot;
        nodes.insert("/usr/lib/systemd".to_string(), dir);
        nodes.insert(
            "/usr/sbin/init".to_string(),
            link_node("../lib/systemd/systemd", boot),
        );
    }
    nodes
}

/// `/proc/<pid>/cmdline`: the arguments each followed by a NUL, nothing for a kernel thread.
fn cmdline_bytes(p: &Proc) -> Vec<u8> {
    let mut out = Vec::new();
    for arg in &p.argv {
        out.extend_from_slice(arg.as_bytes());
        out.push(0);
    }
    out
}

/// The 52 fields of `/proc/<pid>/stat`. Counters that nothing else shows are fixed figures that
/// scale with the row, not measurements.
fn stat_line(table: &Table, p: &Proc) -> String {
    let pages = p.rss_kib.div_euclid(4);
    let tty_nr: i64 = if p.tty == "?" { 0 } else { 34_816 };
    let tpgid: i64 = if p.attached { i64::from(p.pid) } else { -1 };
    let (code, stack): (u64, u64) = if table.android {
        (0x0001_0000, 0xbe80_0000)
    } else {
        (0x5580_0000_0000, 0x7ffd_0000_0000)
    };
    let image = code.saturating_add(u64::from(p.pid).saturating_mul(0x10_0000));
    let top = stack.saturating_add(u64::from(p.pid).saturating_mul(0x1000));
    let fields: Vec<String> = vec![
        p.pid.to_string(),
        format!("({})", p.comm),
        p.state.to_string(),
        p.ppid.to_string(),
        p.pid.to_string(),
        p.pid.to_string(),
        tty_nr.to_string(),
        tpgid.to_string(),
        "4194560".to_string(),
        pages.saturating_mul(2).to_string(),
        "0".to_string(),
        pages.div_euclid(40).to_string(),
        "0".to_string(),
        p.cpu_secs.saturating_mul(HZ).to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "20".to_string(),
        "0".to_string(),
        "1".to_string(),
        "0".to_string(),
        table.start_ticks(p).to_string(),
        p.vsz_kib.saturating_mul(1024).to_string(),
        pages.to_string(),
        "18446744073709551615".to_string(),
        image.to_string(),
        image.saturating_add(0x2_0000).to_string(),
        top.to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "4096".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "17".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        image.saturating_add(0x3_0000).to_string(),
        image.saturating_add(0x3_1000).to_string(),
        image.saturating_add(0x4_0000).to_string(),
        top.saturating_add(0x100).to_string(),
        top.saturating_add(0x180).to_string(),
        top.saturating_add(0x200).to_string(),
        top.saturating_add(0x2f0).to_string(),
        "0".to_string(),
    ];
    format!("{}\n", fields.join(" "))
}

fn status_text(table: &Table, p: &Proc) -> String {
    let state = match p.state {
        'R' => "R (running)",
        _ => "S (sleeping)",
    };
    let kb = |kib: u64| format!("{kib:>8} kB");
    let mut lines: Vec<String> = vec![format!("Name:\t{}", p.comm)];
    if !table.android {
        lines.push("Umask:\t0022".to_string());
    }
    lines.push(format!("State:\t{state}"));
    lines.push(format!("Tgid:\t{}", p.pid));
    if !table.android {
        lines.push("Ngid:\t0".to_string());
    }
    lines.push(format!("Pid:\t{}", p.pid));
    lines.push(format!("PPid:\t{}", p.ppid));
    lines.push("TracerPid:\t0".to_string());
    lines.push("Uid:\t0\t0\t0\t0".to_string());
    lines.push("Gid:\t0\t0\t0\t0".to_string());
    lines.push("FDSize:\t64".to_string());
    lines.push("Groups:\t".to_string());
    if !table.android {
        for key in ["NStgid", "NSpid", "NSpgid", "NSsid"] {
            lines.push(format!("{key}:\t{}", p.pid));
        }
    }
    lines.push(format!("VmPeak:\t{}", kb(p.vsz_kib)));
    lines.push(format!("VmSize:\t{}", kb(p.vsz_kib)));
    lines.push(format!("VmLck:\t{}", kb(0)));
    lines.push(format!("VmPin:\t{}", kb(0)));
    lines.push(format!("VmHWM:\t{}", kb(p.rss_kib)));
    lines.push(format!("VmRSS:\t{}", kb(p.rss_kib)));
    if !table.android {
        let file = p.rss_kib.saturating_mul(3).div_euclid(5);
        lines.push(format!("RssAnon:\t{}", kb(p.rss_kib.saturating_sub(file))));
        lines.push(format!("RssFile:\t{}", kb(file)));
        lines.push(format!("RssShmem:\t{}", kb(0)));
    }
    lines.push(format!("VmData:\t{}", kb(p.vsz_kib.div_euclid(8))));
    lines.push(format!("VmStk:\t{}", kb(132)));
    lines.push(format!("VmSwap:\t{}", kb(0)));
    lines.push("Threads:\t1".to_string());
    lines.push("SigQ:\t0/15650".to_string());
    for key in ["SigPnd", "ShdPnd", "SigBlk"] {
        lines.push(format!("{key}:\t0000000000000000"));
    }
    lines.push("SigIgn:\t0000000000001000".to_string());
    lines.push("SigCgt:\t0000000180014a07".to_string());
    lines.push("CapInh:\t0000000000000000".to_string());
    for key in ["CapPrm", "CapEff", "CapBnd"] {
        lines.push(format!("{key}:\t000001ffffffffff"));
    }
    if !table.android {
        lines.push("CapAmb:\t0000000000000000".to_string());
        lines.push("NoNewPrivs:\t0".to_string());
        lines.push("Seccomp:\t0".to_string());
    }
    lines.push("Cpus_allowed:\t1".to_string());
    lines.push("Cpus_allowed_list:\t0".to_string());
    lines.push(format!(
        "voluntary_ctxt_switches:\t{}",
        40u64.saturating_add(p.cpu_secs.saturating_mul(97))
    ));
    lines.push(format!(
        "nonvoluntary_ctxt_switches:\t{}",
        p.cpu_secs.saturating_mul(3)
    ));
    format!("{}\n", lines.join("\n"))
}

// ------------------------------------------------------------------------------------ the pattern

/// One position a pattern can match.
#[derive(Debug, Clone)]
enum Atom {
    Any,
    Lit(char),
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

impl Atom {
    fn matches(&self, c: char) -> bool {
        match self {
            Atom::Any => true,
            Atom::Lit(lit) => *lit == c,
            Atom::Class { negated, ranges } => {
                ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&c)) != *negated
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quant {
    One,
    Opt,
    Star,
    Plus,
}

#[derive(Debug, Clone)]
struct Alternative {
    start: bool,
    end: bool,
    items: Vec<(Atom, Quant)>,
}

/// A compiled pattern: a match is any alternative matching.
#[derive(Debug, Clone)]
struct Pattern {
    alternatives: Vec<Alternative>,
}

/// Split `text` at its top-level `|` (outside brackets and groups).
fn split_alternatives(text: &[char]) -> Vec<Vec<char>> {
    let mut parts: Vec<Vec<char>> = vec![Vec::new()];
    let (mut depth, mut in_class, mut escaped) = (0u32, false, false);
    for &c in text {
        let split = !escaped && !in_class && depth == 0 && c == '|';
        if split {
            parts.push(Vec::new());
            continue;
        }
        if !escaped {
            match c {
                '[' if !in_class => in_class = true,
                ']' if in_class => in_class = false,
                '(' if !in_class => depth = depth.saturating_add(1),
                ')' if !in_class => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        escaped = !escaped && c == '\\';
        if let Some(last) = parts.last_mut() {
            last.push(c);
        }
    }
    parts
}

/// Expand the first group of `text` into one string per alternative inside it, recursively, so
/// `a(b|c)d` becomes `abd` and `acd`. A group with a quantifier after it, or an unbalanced one,
/// is left as written and its parentheses read as literals.
fn expand_groups(text: &[char], out: &mut Vec<Vec<char>>, depth: u32) {
    if out.len() >= ALTERNATIVES_MAX {
        return;
    }
    let (mut open, mut in_class, mut escaped) = (None, false, false);
    let mut level = 0u32;
    let mut close = None;
    for (at, &c) in text.iter().enumerate() {
        if !escaped {
            match c {
                '[' if !in_class => in_class = true,
                ']' if in_class => in_class = false,
                '(' if !in_class => {
                    if open.is_none() {
                        open = Some(at);
                    }
                    level = level.saturating_add(1);
                }
                ')' if !in_class && open.is_some() => {
                    level = level.saturating_sub(1);
                    if level == 0 {
                        close = Some(at);
                        break;
                    }
                }
                _ => {}
            }
        }
        escaped = !escaped && c == '\\';
    }
    let (Some(open), Some(close), true) = (open, close, depth < 4) else {
        out.push(text.to_vec());
        return;
    };
    let head = text.get(..open).unwrap_or(&[]);
    let inner = text.get(open.saturating_add(1)..close).unwrap_or(&[]);
    let tail = text.get(close.saturating_add(1)..).unwrap_or(&[]);
    for choice in split_alternatives(inner) {
        let mut joined = head.to_vec();
        joined.extend_from_slice(&choice);
        joined.extend_from_slice(tail);
        expand_groups(&joined, out, depth.saturating_add(1));
    }
}

fn parse_alternative(text: &[char]) -> Alternative {
    let mut chars = text.iter().copied().peekable();
    let mut alt = Alternative {
        start: false,
        end: false,
        items: Vec::new(),
    };
    if chars.peek() == Some(&'^') {
        alt.start = true;
        chars.next();
    }
    while let Some(c) = chars.next() {
        let atom = match c {
            '$' if chars.peek().is_none() => {
                alt.end = true;
                break;
            }
            '.' => Atom::Any,
            '\\' => Atom::Lit(chars.next().unwrap_or('\\')),
            '[' => {
                let negated = chars.peek() == Some(&'^');
                if negated {
                    chars.next();
                }
                let mut ranges: Vec<(char, char)> = Vec::new();
                let mut first = true;
                while let Some(member) = chars.next() {
                    if member == ']' && !first {
                        break;
                    }
                    first = false;
                    if chars.peek() == Some(&'-') {
                        let mut look = chars.clone();
                        look.next();
                        if let Some(high) = look.next().filter(|h| *h != ']') {
                            chars = look;
                            ranges.push((member, high));
                            continue;
                        }
                    }
                    ranges.push((member, member));
                }
                Atom::Class { negated, ranges }
            }
            '*' | '+' | '?' if !alt.items.is_empty() => {
                let quant = match c {
                    '*' => Quant::Star,
                    '+' => Quant::Plus,
                    _ => Quant::Opt,
                };
                if let Some(last) = alt.items.last_mut() {
                    last.1 = quant;
                }
                continue;
            }
            other => Atom::Lit(other),
        };
        alt.items.push((atom, Quant::One));
    }
    alt
}

impl Pattern {
    /// Compile `text`; `exact` anchors every alternative at both ends and `fold` ignores case.
    fn new(text: &str, exact: bool, fold: bool) -> Self {
        let text: Vec<char> = text
            .chars()
            .take(PATTERN_MAX)
            .flat_map(|c| {
                if fold {
                    c.to_lowercase().collect::<Vec<_>>()
                } else {
                    vec![c]
                }
            })
            .collect();
        let mut expanded = Vec::new();
        for part in split_alternatives(&text) {
            expand_groups(&part, &mut expanded, 0);
        }
        let alternatives = expanded
            .iter()
            .take(ALTERNATIVES_MAX)
            .map(|alt| {
                let mut alt = parse_alternative(alt);
                if exact {
                    alt.start = true;
                    alt.end = true;
                }
                alt
            })
            .collect();
        Self { alternatives }
    }

    /// Whether the pattern matches anywhere in `text` (`text` is lowercased by the caller when
    /// the pattern folds case). Runs in time proportional to pattern length times text length.
    fn is_match(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().take(TEXT_MAX).collect();
        self.alternatives.iter().any(|alt| alt_matches(alt, &chars))
    }
}

/// Mark `at` in `set` when it is in range.
fn mark(set: &mut [bool], at: usize) {
    if let Some(slot) = set.get_mut(at) {
        *slot = true;
    }
}

fn marked(set: &[bool], at: usize) -> bool {
    set.get(at).copied().unwrap_or(false)
}

/// Positions of `chars` an item can step over, one atom wide.
fn step(set: &[bool], atom: &Atom, chars: &[char]) -> Vec<bool> {
    let mut next = vec![false; set.len()];
    for (at, c) in chars.iter().enumerate() {
        if marked(set, at) && atom.matches(*c) {
            mark(&mut next, at.saturating_add(1));
        }
    }
    next
}

/// Extend `set` over runs of `atom`.
fn close_over(set: &mut [bool], atom: &Atom, chars: &[char]) {
    for (at, c) in chars.iter().enumerate() {
        if marked(set, at) && atom.matches(*c) {
            mark(set, at.saturating_add(1));
        }
    }
}

fn alt_matches(alt: &Alternative, chars: &[char]) -> bool {
    let width = chars.len().saturating_add(1);
    let mut current = if alt.start {
        let mut set = vec![false; width];
        mark(&mut set, 0);
        set
    } else {
        vec![true; width]
    };
    for (atom, quant) in &alt.items {
        let stepped = step(&current, atom, chars);
        current = match quant {
            Quant::One => stepped,
            Quant::Opt => current
                .iter()
                .zip(&stepped)
                .map(|(a, b)| *a || *b)
                .collect(),
            Quant::Star => {
                close_over(&mut current, atom, chars);
                current
            }
            Quant::Plus => {
                let mut run = stepped;
                close_over(&mut run, atom, chars);
                run
            }
        };
    }
    if alt.end {
        marked(&current, chars.len())
    } else {
        current.iter().any(|on| *on)
    }
}

// ------------------------------------------------------------------------------------- signals

/// The classic names, signals 1 to 31 on Linux.
const SIGNAL_NAMES: [&str; 31] = [
    "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2",
    "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG",
    "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS",
];

/// The name `kill -l N` prints for signal `n` (no `SIG` prefix), `None` for a number that is no
/// signal. 32 and 33 are reserved by the C library, and 34 to 64 are the real-time range.
fn signal_name(n: u32) -> Option<String> {
    match n {
        1..=31 => SIGNAL_NAMES
            .get(usize::try_from(n.saturating_sub(1)).ok()?)
            .map(|name| (*name).to_string()),
        34 => Some("RTMIN".to_string()),
        35..=49 => Some(format!("RTMIN+{}", n.saturating_sub(34))),
        50..=63 => Some(format!("RTMAX-{}", 64u32.saturating_sub(n))),
        64 => Some("RTMAX".to_string()),
        _ => None,
    }
}

/// The signal a spec names: a number from 0 to 64 that is a signal, or a name with or without
/// `SIG`, in either case.
fn parse_signal(spec: &str) -> Option<u32> {
    if spec.is_empty() {
        return None;
    }
    if spec.chars().all(|c| c.is_ascii_digit()) {
        let n: u32 = spec.parse().ok()?;
        return (n == 0 || signal_name(n).is_some()).then_some(n);
    }
    let upper = spec.to_ascii_uppercase();
    let bare = upper.strip_prefix("SIG").unwrap_or(&upper);
    (1..=64u32).find(|n| signal_name(*n).is_some_and(|name| name == bare))
}

// ------------------------------------------------------------------------------------------ ps

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Col {
    Pid,
    Ppid,
    Uid,
    User,
    UidName,
    Comm,
    Args,
    CmdComm,
    CmdArgs,
    TtyHead,
    TtyOut,
    Stat,
    State,
    TimeHms,
    TimeMs,
    Pcpu,
    Pmem,
    Vsz,
    Rss,
    /// `lstart`: the full start time.
    Started,
    /// `ps aux`'s `START` and `-o start`.
    StartAux,
    /// `ps -ef`'s `STIME`.
    Stime,
    Etime,
    C,
}

impl Col {
    /// The header, the column width (0 for none) and whether it is left-aligned.
    fn spec(self) -> (&'static str, usize, bool) {
        match self {
            Col::Pid => ("PID", 7, false),
            Col::Ppid => ("PPID", 7, false),
            Col::Uid => ("UID", 5, false),
            Col::User => ("USER", 8, true),
            Col::UidName => ("UID", 8, true),
            Col::Comm => ("COMMAND", 15, true),
            Col::Args => ("COMMAND", 0, true),
            Col::CmdComm | Col::CmdArgs => ("CMD", 0, true),
            Col::TtyHead => ("TTY", 8, true),
            Col::TtyOut => ("TT", 8, true),
            Col::Stat => ("STAT", 4, true),
            Col::State => ("S", 1, true),
            Col::TimeHms => ("TIME", 8, false),
            Col::TimeMs => ("TIME", 6, false),
            Col::Pcpu => ("%CPU", 4, false),
            Col::Pmem => ("%MEM", 4, false),
            Col::Vsz => ("VSZ", 6, false),
            Col::Rss => ("RSS", 5, false),
            Col::Started => ("STARTED", 24, false),
            Col::StartAux => ("START", 5, false),
            Col::Stime => ("STIME", 5, true),
            Col::Etime => ("ELAPSED", 11, false),
            Col::C => ("C", 2, false),
        }
    }
}

fn hms(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs.div_euclid(3_600),
        secs.rem_euclid(3_600).div_euclid(60),
        secs.rem_euclid(60)
    )
}

fn minutes_seconds(secs: u64) -> String {
    format!("{}:{:02}", secs.div_euclid(60), secs.rem_euclid(60))
}

/// `num / den` as a figure with one decimal place, rounded down.
fn tenths(num: u64, den: u64) -> String {
    let t = num.saturating_mul(10).checked_div(den).unwrap_or(0);
    format!("{}.{}", t.div_euclid(10), t.rem_euclid(10))
}

fn elapsed_text(secs: u64) -> String {
    let (days, hours) = (
        secs.div_euclid(86_400),
        secs.rem_euclid(86_400).div_euclid(3_600),
    );
    let (minutes, seconds) = (secs.rem_euclid(3_600).div_euclid(60), secs.rem_euclid(60));
    if days > 0 {
        format!("{days}-{hours:02}:{minutes:02}:{seconds:02}")
    } else if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

impl Table {
    /// `HH:MM` for a process started today, `MonDD` for an older one, as procps prints it.
    fn start_label(&self, p: &Proc) -> String {
        let at = self.started_at(p);
        if at.date_naive() == self.now.date_naive() {
            expand("%H:%M", &at)
        } else {
            format!("{}{:02}", expand("%b", &at), at.day())
        }
    }

    fn cell(&self, col: Col, p: &Proc) -> String {
        match col {
            Col::Pid => p.pid.to_string(),
            Col::Ppid => p.ppid.to_string(),
            Col::Uid => "0".to_string(),
            Col::User | Col::UidName => "root".to_string(),
            Col::Comm => p.comm.clone(),
            Col::Args | Col::CmdArgs => p.args(),
            Col::CmdComm => p.comm.clone(),
            Col::TtyHead | Col::TtyOut => p.tty.to_string(),
            Col::Stat => p.stat_column(),
            Col::State => p.state.to_string(),
            Col::TimeHms => hms(p.cpu_secs),
            Col::TimeMs => minutes_seconds(p.cpu_secs),
            Col::Pcpu => tenths(p.cpu_secs.saturating_mul(100), self.elapsed_secs(p)),
            Col::Pmem => tenths(p.rss_kib.saturating_mul(100), MEM_TOTAL_KIB),
            Col::Vsz => p.vsz_kib.to_string(),
            Col::Rss => p.rss_kib.to_string(),
            Col::Started => expand("%a %b %e %H:%M:%S %Y", &self.started_at(p)),
            Col::StartAux | Col::Stime => self.start_label(p),
            Col::Etime => elapsed_text(self.elapsed_secs(p)),
            Col::C => "0".to_string(),
        }
    }
}

fn render_row(cells: &[(String, usize, bool)]) -> String {
    let mut line = String::new();
    let last = cells.len().saturating_sub(1);
    for (at, (text, width, left)) in cells.iter().enumerate() {
        if at > 0 {
            line.push(' ');
        }
        if at == last && *left {
            line.push_str(text);
        } else if *left {
            line.push_str(&format!("{text:<width$}"));
        } else {
            line.push_str(&format!("{text:>width$}"));
        }
    }
    line.trim_end().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    Short,
    Bsd,
    Aux,
    Full,
}

impl Layout {
    fn columns(self) -> &'static [Col] {
        match self {
            Layout::Short => &[Col::Pid, Col::TtyHead, Col::TimeHms, Col::CmdComm],
            Layout::Bsd => &[Col::Pid, Col::TtyHead, Col::Stat, Col::TimeMs, Col::Args],
            Layout::Aux => &[
                Col::User,
                Col::Pid,
                Col::Pcpu,
                Col::Pmem,
                Col::Vsz,
                Col::Rss,
                Col::TtyHead,
                Col::Stat,
                Col::StartAux,
                Col::TimeMs,
                Col::Args,
            ],
            Layout::Full => &[
                Col::UidName,
                Col::Pid,
                Col::Ppid,
                Col::C,
                Col::Stime,
                Col::TtyHead,
                Col::TimeHms,
                Col::CmdArgs,
            ],
        }
    }
}

struct PsPlan {
    layout: Layout,
    /// `-e`, `-A`, `ax`: every process, not just this terminal's.
    all: bool,
    /// `-p` or a bare pid list: only these.
    pids: Option<Vec<u32>>,
    /// `-C`: only processes with these command names.
    names: Option<Vec<String>>,
    /// `-u`, `-U`, `-G`: no process belongs to anyone but root.
    nobody: bool,
    /// `-o`: the columns, with a header of its own where one was given.
    custom: Option<Vec<(Col, Option<String>)>>,
    headers: bool,
    version: bool,
}

/// What procps prints after a usage error.
const PS_TAIL: &str = "Usage:\n ps [options]\n\n Try 'ps --help <simple|list|output|threads|misc|all>'\n  or 'ps --help <s|l|o|t|m|a>'\n for additional help text.\n\nFor more details see ps(1).\n";

fn ps_error(text: &str) -> CommandResult {
    CommandResult::stderr(1, format!("error: {text}\n{PS_TAIL}"))
}

fn parse_pid_list(text: &str) -> Option<Vec<u32>> {
    text.split([',', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<u32>().ok())
        .collect()
}

fn output_column(name: &str) -> Option<Col> {
    Some(match name {
        "pid" => Col::Pid,
        "ppid" => Col::Ppid,
        "uid" => Col::Uid,
        "user" | "euser" | "ruser" | "uname" => Col::User,
        "comm" | "ucmd" | "ucomm" => Col::Comm,
        "args" | "command" => Col::Args,
        "cmd" => Col::CmdArgs,
        "tty" | "tt" | "tname" => Col::TtyOut,
        "stat" => Col::Stat,
        "s" | "state" => Col::State,
        "time" | "cputime" => Col::TimeHms,
        "pcpu" | "%cpu" => Col::Pcpu,
        "pmem" | "%mem" => Col::Pmem,
        "vsz" | "vsize" => Col::Vsz,
        "rss" | "rsz" => Col::Rss,
        "start" => Col::StartAux,
        "lstart" => Col::Started,
        "stime" => Col::Stime,
        "etime" => Col::Etime,
        "c" => Col::C,
        _ => return None,
    })
}

/// The `-o` list `spec`: each `name` or `name=HEADER`, comma or space separated.
fn parse_output_list(spec: &str) -> Result<Vec<(Col, Option<String>)>, String> {
    let mut cols = Vec::new();
    for item in spec.split([',', ' ']).filter(|item| !item.is_empty()) {
        let (name, header) = match item.split_once('=') {
            Some((name, header)) => (name, Some(header.to_string())),
            None => (item, None),
        };
        match output_column(name) {
            Some(col) => cols.push((col, header)),
            None => {
                return Err(format!("unknown user-defined format specifier \"{name}\""));
            }
        }
    }
    if cols.is_empty() {
        return Err("improper list".to_string());
    }
    Ok(cols)
}

/// `ps`'s command line: procps accepts SysV flags (`-ef`), BSD flags (`aux`) and mixes of the
/// two. The few it models are enough for what enumeration scripts run; anything else is the
/// tool's own usage error.
fn parse_ps(args: &[&str]) -> Result<PsPlan, String> {
    let mut plan = PsPlan {
        layout: Layout::Short,
        all: false,
        pids: None,
        names: None,
        nobody: false,
        custom: None,
        headers: true,
        version: false,
    };
    // `a` (every process with a terminal) selects what the default selection already does, the
    // processes of this terminal, so it is read and has no effect of its own.
    let (mut full, mut bsd, mut user_format, mut bsd_x) = (false, false, false, false);
    let mut at = 0usize;
    while let Some(arg) = args.get(at).copied() {
        at = at.saturating_add(1);
        if arg == "--no-headers" || arg == "--no-heading" {
            plan.headers = false;
        } else if arg == "--headers" {
            plan.headers = true;
        } else if arg == "--version" {
            plan.version = true;
        } else if arg.starts_with("--") {
            return Err("unknown gnu long option".to_string());
        } else if let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) {
            for (index, flag) in flags.char_indices() {
                let rest = flags
                    .get(index.saturating_add(flag.len_utf8())..)
                    .unwrap_or("");
                let valued = matches!(flag, 'o' | 'p' | 'C' | 'u' | 'U' | 'G' | 'g' | 't' | 'O');
                let value = if !valued {
                    None
                } else if rest.is_empty() {
                    let next = args.get(at).copied();
                    at = at.saturating_add(1);
                    Some(next.ok_or_else(|| "improper list".to_string())?)
                } else {
                    Some(rest)
                };
                match (flag, value) {
                    ('e' | 'A', _) => plan.all = true,
                    ('f', _) => full = true,
                    ('a', _) => {}
                    ('x', _) => bsd_x = true,
                    ('w' | 'W' | 'H' | 'V', _) => {
                        plan.version |= flag == 'V';
                    }
                    ('o', Some(spec)) => plan.custom = Some(parse_output_list(spec)?),
                    ('p', Some(list)) => {
                        plan.pids = Some(parse_pid_list(list).ok_or("improper list")?);
                    }
                    ('C', Some(list)) => {
                        plan.names = Some(list.split(',').map(str::to_string).collect());
                    }
                    ('u' | 'U' | 'G' | 'g', Some(list)) => {
                        plan.nobody = !list.split(',').any(|id| id == "root" || id == "0");
                    }
                    ('t' | 'O', Some(_)) => {}
                    _ => return Err("unsupported SysV option".to_string()),
                }
                if valued {
                    break;
                }
            }
        } else if let Some(list) =
            parse_pid_list(arg).filter(|_| arg.chars().all(|c| c.is_ascii_digit() || c == ','))
        {
            plan.pids = Some(list);
        } else {
            bsd = true;
            for flag in arg.chars() {
                match flag {
                    'a' => {}
                    'x' => bsd_x = true,
                    'u' => user_format = true,
                    'w' | 'e' | 'f' | 'h' | 'l' => {
                        if flag == 'h' {
                            plan.headers = false;
                        }
                    }
                    _ => return Err("garbage option".to_string()),
                }
            }
        }
    }
    plan.all |= bsd_x;
    plan.layout = if user_format {
        Layout::Aux
    } else if full {
        Layout::Full
    } else if bsd {
        Layout::Bsd
    } else {
        Layout::Short
    };
    Ok(plan)
}

impl FakeShell {
    /// The transient row `ps` and `top` list for themselves: the next pid the session hands out.
    fn self_row(&mut self, parts: &[&str], exe_name: &str) -> Proc {
        let pid = self.pids.next();
        let mut argv: Vec<String> = parts.iter().map(|p| (*p).to_string()).collect();
        if self.busybox_depth > 0 {
            argv.insert(0, "busybox".to_string());
        }
        let exe = if self.flavor == ShellFlavor::AndroidSh {
            format!("/system/bin/{exe_name}")
        } else {
            resolve_proc_self(exe_name)
                .map_or_else(|| format!("/usr/bin/{exe_name}"), str::to_string)
        };
        Proc {
            pid,
            ppid: self.state().pid,
            comm: exe_name.to_string(),
            argv,
            state: 'R',
            mark: "+",
            tty: self.session_tty(),
            started: Started::Now,
            vsz_kib: 12_648,
            rss_kib: 3_352,
            cpu_secs: 0,
            wchan: "-",
            exe,
            cwd: self.cwd().to_string(),
            attached: true,
        }
    }

    /// `ps`. Lists the table and itself in the layout asked for; BusyBox and Android's toolbox
    /// each have a layout of their own.
    pub(super) fn cmd_ps(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let android = self.flavor == ShellFlavor::AndroidSh;
        if !android && self.busybox_depth == 0 {
            return self.ps_procps(parts, args);
        }
        let table = self.process_table();
        let mut rows = table.procs.clone();
        rows.push(self.self_row(parts, "ps"));
        if android && self.busybox_depth == 0 {
            return android_ps(rows, args);
        }
        busybox_ps(rows)
    }

    fn ps_procps(&mut self, parts: &[&str], args: &[&str]) -> CommandResult {
        let plan = match parse_ps(args) {
            Ok(plan) => plan,
            Err(reason) => return ps_error(&reason),
        };
        if plan.version {
            return CommandResult::stdout("ps from procps-ng 3.3.17\n");
        }
        let table = self.process_table();
        let own = self.self_row(parts, "ps");
        let mut rows: Vec<Proc> = table.procs.clone();
        rows.push(own);
        if plan.nobody {
            rows.clear();
        }
        if let Some(pids) = &plan.pids {
            rows.retain(|p| pids.contains(&p.pid));
        } else if let Some(names) = &plan.names {
            rows.retain(|p| names.contains(&p.comm));
        } else if !plan.all {
            rows.retain(|p| p.attached);
        }
        let columns: Vec<(Col, Option<String>)> = match &plan.custom {
            Some(custom) => custom.clone(),
            None => plan.layout.columns().iter().map(|c| (*c, None)).collect(),
        };
        let mut out = String::new();
        let headers: Vec<String> = columns
            .iter()
            .map(|(col, header)| header.clone().unwrap_or_else(|| col.spec().0.to_string()))
            .collect();
        if plan.headers && headers.iter().any(|h| !h.is_empty()) {
            let cells: Vec<(String, usize, bool)> = columns
                .iter()
                .zip(&headers)
                .map(|((col, _), head)| (head.clone(), col.spec().1, col.spec().2))
                .collect();
            out.push_str(&render_row(&cells));
            out.push('\n');
        }
        for p in &rows {
            let cells: Vec<(String, usize, bool)> = columns
                .iter()
                .map(|(col, _)| (table.cell(*col, p), col.spec().1, col.spec().2))
                .collect();
            out.push_str(&render_row(&cells));
            out.push('\n');
        }
        clip(out)
    }
}

/// The toolbox `ps` of Android 6: every process, one row each, with the pid and name filters it
/// takes as operands (a number is a pid, anything else is part of a name). Flags are accepted and
/// change nothing [unverified].
fn android_ps(rows: Vec<Proc>, args: &[&str]) -> CommandResult {
    let mut pid: Option<u32> = None;
    let mut name: Option<&str> = None;
    for arg in args.iter().filter(|a| !a.starts_with('-')) {
        match arg.parse::<u32>() {
            Ok(n) => pid = Some(n),
            Err(_) => name = Some(arg),
        }
    }
    let mut out = format!(
        "{:<9} {:<5} {:<5} {:<6} {:<5} {:<10} {:<8}   NAME\n",
        "USER", "PID", "PPID", "VSIZE", "RSS", "WCHAN", "PC"
    );
    for p in &rows {
        let shown = if p.argv.is_empty() {
            format!("[{}]", p.comm)
        } else {
            p.argv.first().cloned().unwrap_or_default()
        };
        if pid.is_some_and(|n| n != p.pid) || name.is_some_and(|n| !shown.contains(n)) {
            continue;
        }
        out.push_str(&format!(
            "{:<9} {:<5} {:<5} {:<6} {:<5} {:<10} {:08x} {} {}\n",
            "root", p.pid, p.ppid, p.vsz_kib, p.rss_kib, p.wchan, 0, p.state, shown
        ));
    }
    clip(out)
}

/// BusyBox's `ps`, which ignores the options this shell models: every process with its virtual
/// size and state [unverified].
fn busybox_ps(rows: Vec<Proc>) -> CommandResult {
    let mut out = String::from("  PID USER       VSZ STAT COMMAND\n");
    for p in &rows {
        out.push_str(&format!(
            "{:>5} {:<8} {:>6} {:<4} {}\n",
            p.pid,
            "root",
            p.vsz_kib,
            p.stat_column(),
            p.args()
        ));
    }
    clip(out)
}

fn clip(mut text: String) -> CommandResult {
    if text.len() > OUT_MAX {
        let mut cut = OUT_MAX;
        while !text.is_char_boundary(cut) {
            cut = cut.saturating_sub(1);
        }
        text.truncate(cut);
    }
    CommandResult::stdout(text)
}

// ----------------------------------------------------------------------------------------- top

/// MiB to one decimal place for `top`'s memory lines, as `{:8.1}` prints it.
fn mib(kib: u64) -> String {
    let t = kib.saturating_mul(10).saturating_add(512).div_euclid(1_024);
    format!(
        "{:>8}",
        format!("{}.{}", t.div_euclid(10), t.rem_euclid(10))
    )
}

impl FakeShell {
    /// `top`. Standard output is never a terminal here, so the interactive form cannot loop: it
    /// and `-b` print one snapshot and exit, whatever `-n` asks for. The memory and CPU lines
    /// are fixed figures [unverified].
    pub(super) fn cmd_top(&mut self, parts: &[&str]) -> CommandResult {
        let table = self.process_table();
        let mut rows = table.procs.clone();
        rows.push(self.self_row(parts, "top"));
        if table.android {
            return android_top(&rows);
        }
        let (running, total) = (rows.iter().filter(|p| p.state == 'R').count(), rows.len());
        let secs = uptime_secs(&table.now);
        let mut out = format!(
            "top - {} up {},  1 user,  load average: {}\n",
            expand("%H:%M:%S", &table.now),
            uptime_short(secs),
            load_average(&table.now)
        );
        out.push_str(&format!(
            "Tasks: {total:>3} total, {running:>3} running, {:>3} sleeping,   0 stopped,   0 zombie\n",
            total.saturating_sub(running)
        ));
        out.push_str(
            "%Cpu(s):  0.3 us,  0.3 sy,  0.0 ni, 99.3 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n",
        );
        out.push_str(&format!(
            "MiB Mem : {} total, {} free, {} used, {} buff/cache\n",
            mib(MEM_TOTAL_KIB),
            mib(MEM_FREE_KIB),
            mib(MEM_USED_KIB),
            mib(MEM_CACHE_KIB)
        ));
        out.push_str(&format!(
            "MiB Swap: {} total, {} free, {} used. {} avail Mem \n\n",
            mib(0),
            mib(0),
            mib(0),
            mib(MEM_AVAIL_KIB)
        ));
        out.push_str(
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n",
        );
        for p in &rows {
            let shared = p.rss_kib.saturating_mul(3).div_euclid(5);
            out.push_str(&format!(
                "{:>7} {:<9} {:>2} {:>3} {:>7} {:>6} {:>6} {} {:>5} {:>5} {:>9} {}\n",
                p.pid,
                "root",
                20,
                0,
                p.vsz_kib,
                p.rss_kib,
                shared,
                p.state,
                "0.0",
                tenths(p.rss_kib.saturating_mul(100), MEM_TOTAL_KIB),
                format!(
                    "{}:{:02}.00",
                    p.cpu_secs.div_euclid(60),
                    p.cpu_secs.rem_euclid(60)
                ),
                p.comm
            ));
        }
        clip(out)
    }
}

fn android_top(rows: &[Proc]) -> CommandResult {
    let mut out = String::from(
        "User 1%, System 3%, IOW 0%, IRQ 0%\nUser 4 + Nice 0 + Sys 12 + Idle 289 + IOW 0 + IRQ 0 + SIRQ 0 = 305\n\n  PID PR CPU% S  #THR     VSS     RSS PCY UID      Name\n",
    );
    for p in rows {
        let name = p.argv.first().cloned().unwrap_or_else(|| p.comm.clone());
        out.push_str(&format!(
            "{:>5} {:>2} {:>3}% {} {:>5} {:>6}K {:>6}K {:>3} {:<8} {}\n",
            p.pid, 0, 0, p.state, 1, p.vsz_kib, p.rss_kib, "fg", "root", name
        ));
    }
    clip(out)
}

// ----------------------------------------------------------------------------------- selectors

/// What `pgrep`, `pkill` and `killall` read from their command lines.
#[derive(Default)]
struct Selector {
    full: bool,
    exact: bool,
    fold: bool,
    invert: bool,
    newest: bool,
    oldest: bool,
    count: bool,
    list_name: bool,
    list_full: bool,
    echo: bool,
    delimiter: Option<String>,
    parents: Option<Vec<u32>>,
    tty: Option<String>,
    /// `-u`, `-U`: the processes of a user that owns none.
    nobody: bool,
    signal: Option<u32>,
    pattern: Option<String>,
    version: bool,
}

impl Selector {
    /// The rows that match, in pid order (or the one newest or oldest of them).
    fn select<'a>(&self, table: &'a Table) -> Vec<&'a Proc> {
        if self.nobody {
            return Vec::new();
        }
        let pattern = self
            .pattern
            .as_deref()
            .map(|text| Pattern::new(text, self.exact, self.fold));
        let mut hits: Vec<&Proc> = table
            .procs
            .iter()
            .filter(|p| {
                let text = if self.full { p.args() } else { p.comm.clone() };
                let text = if self.fold { text.to_lowercase() } else { text };
                let named = pattern.as_ref().is_none_or(|pat| pat.is_match(&text));
                let parent = self
                    .parents
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&p.ppid));
                let tty = self.tty.as_ref().is_none_or(|t| *t == p.tty);
                (named && parent && tty) != self.invert
            })
            .collect();
        hits.sort_by_key(|p| p.pid);
        if self.newest || self.oldest {
            let key = |p: &&Proc| (table.start_ticks(p), p.pid);
            let picked = if self.newest {
                hits.iter().copied().max_by_key(key)
            } else {
                hits.iter().copied().min_by_key(key)
            };
            return picked.into_iter().collect();
        }
        hits
    }
}

const PGREP_NO_CRITERIA: &str =
    "no matching criteria specified\nTry `{cmd} --help' for more information.\n";

/// The shared command-line reader of `pgrep` and `pkill`. `Err` is the finished reply.
fn parse_selector(cmd: &str, args: &[&str]) -> Result<Selector, CommandResult> {
    let mut sel = Selector::default();
    let mut at = 0usize;
    let mut options = true;
    let mut filtered = false;
    while let Some(arg) = args.get(at).copied() {
        at = at.saturating_add(1);
        if !options || arg == "-" || !arg.starts_with('-') {
            if sel.pattern.is_none() {
                sel.pattern = Some(arg.to_string());
            } else {
                return Err(CommandResult::stderr(
                    2,
                    format!(
                        "{cmd}: only one pattern can be provided\nTry `{cmd} --help' for more information.\n"
                    ),
                ));
            }
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let mut value = || {
                attached.or_else(|| {
                    let next = args.get(at).copied();
                    at = at.saturating_add(1);
                    next
                })
            };
            match name {
                "full" => sel.full = true,
                "exact" => sel.exact = true,
                "ignore-case" => sel.fold = true,
                "inverse" => sel.invert = true,
                "newest" => sel.newest = true,
                "oldest" => sel.oldest = true,
                "count" => sel.count = true,
                "list-name" => sel.list_name = true,
                "list-full" => sel.list_full = true,
                "echo" => sel.echo = true,
                "delimiter" => sel.delimiter = value().map(str::to_string),
                "signal" => {
                    let spec = value().unwrap_or_default();
                    match parse_signal(spec) {
                        Some(n) => sel.signal = Some(n),
                        None => return Err(bad_signal(cmd, spec)),
                    }
                }
                "parent" => {
                    sel.parents = value().and_then(parse_pid_list);
                    filtered = true;
                }
                "terminal" => {
                    sel.tty = value().map(str::to_string);
                    filtered = true;
                }
                "euid" | "uid" => {
                    sel.nobody = !value()
                        .unwrap_or_default()
                        .split(',')
                        .any(|id| id == "root" || id == "0");
                    filtered = true;
                }
                "version" => sel.version = true,
                "pgroup" | "group" | "session" | "pidfile" | "runstates" | "ns" | "nslist" => {
                    value();
                }
                _ => {
                    return Err(CommandResult::stderr(
                        2,
                        format!(
                            "{cmd}: unrecognized option '{arg}'\nTry `{cmd} --help' for more information.\n"
                        ),
                    ));
                }
            }
            continue;
        }
        let body = arg.get(1..).unwrap_or("");
        if let Some(n) = parse_signal(body).filter(|_| cmd == "pkill") {
            sel.signal = Some(n);
            continue;
        }
        for (index, flag) in body.char_indices() {
            let rest = body
                .get(index.saturating_add(flag.len_utf8())..)
                .unwrap_or("");
            let valued = matches!(
                flag,
                'd' | 'u' | 'U' | 'g' | 'G' | 'P' | 's' | 't' | 'F' | 'r'
            );
            let value = if !valued {
                None
            } else if rest.is_empty() {
                let next = args.get(at).copied();
                at = at.saturating_add(1);
                next
            } else {
                Some(rest)
            };
            match flag {
                'f' => sel.full = true,
                'x' => sel.exact = true,
                'i' => sel.fold = true,
                'v' => sel.invert = true,
                'n' => sel.newest = true,
                'o' => sel.oldest = true,
                'c' => sel.count = true,
                'l' => sel.list_name = true,
                'a' => sel.list_full = true,
                'e' => sel.echo = true,
                'V' => sel.version = true,
                'L' => {}
                'd' => sel.delimiter = value.map(str::to_string),
                'P' => {
                    sel.parents = value.and_then(parse_pid_list);
                    filtered = true;
                }
                't' => {
                    sel.tty = value.map(str::to_string);
                    filtered = true;
                }
                'u' | 'U' => {
                    sel.nobody = !value
                        .unwrap_or_default()
                        .split(',')
                        .any(|id| id == "root" || id == "0");
                    filtered = true;
                }
                'g' | 'G' | 's' | 'F' | 'r' => {}
                other => {
                    return Err(CommandResult::stderr(
                        2,
                        format!(
                            "{cmd}: invalid option -- '{other}'\nTry `{cmd} --help' for more information.\n"
                        ),
                    ));
                }
            }
            if valued {
                break;
            }
        }
    }
    if !sel.version && sel.pattern.is_none() && !filtered {
        return Err(CommandResult::stderr(
            2,
            format!("{cmd}: {}", PGREP_NO_CRITERIA.replace("{cmd}", cmd)),
        ));
    }
    Ok(sel)
}

fn bad_signal(cmd: &str, spec: &str) -> CommandResult {
    CommandResult::stderr(1, format!("{cmd}: Unknown signal \"{spec}\"\n"))
}

impl FakeShell {
    /// `pgrep [-flanovxic] [-d DELIM] [-P PPID] [-t TTY] [-u USER] [PATTERN]`: the matching pids,
    /// one per line, status 1 when none match.
    pub(super) fn cmd_pgrep(&mut self, parts: &[&str]) -> CommandResult {
        let sel = match parse_selector("pgrep", parts.get(1..).unwrap_or(&[])) {
            Ok(sel) => sel,
            Err(reply) => return reply,
        };
        if sel.version {
            return CommandResult::stdout("pgrep from procps-ng 3.3.17\n");
        }
        let table = self.process_table();
        let hits = sel.select(&table);
        if sel.count {
            let mut result = CommandResult::stdout(format!("{}\n", hits.len()));
            result.status = u8::from(hits.is_empty());
            return result;
        }
        let lines: Vec<String> = hits
            .iter()
            .map(|p| {
                if sel.list_full {
                    format!("{} {}", p.pid, p.args())
                } else if sel.list_name {
                    format!("{} {}", p.pid, p.comm)
                } else {
                    p.pid.to_string()
                }
            })
            .collect();
        let mut result = match sel.delimiter.as_deref() {
            Some(delimiter) if !lines.is_empty() => {
                CommandResult::stdout(format!("{}\n", lines.join(delimiter)))
            }
            _ if lines.is_empty() => CommandResult::silent(1),
            _ => CommandResult::stdout(format!("{}\n", lines.join("\n"))),
        };
        result.status = u8::from(hits.is_empty());
        result
    }

    /// `pkill [-SIGNAL] [-f] [-x] [-i] [-v] [-n|-o] [-e] [-c] [-P PPID] [-t TTY] [-u USER] PATTERN`.
    /// A match succeeds silently and signals nothing; no match is status 1 with no output.
    pub(super) fn cmd_pkill(&mut self, parts: &[&str]) -> CommandResult {
        let sel = match parse_selector("pkill", parts.get(1..).unwrap_or(&[])) {
            Ok(sel) => sel,
            Err(reply) => return reply,
        };
        if sel.version {
            return CommandResult::stdout("pkill from procps-ng 3.3.17\n");
        }
        let table = self.process_table();
        let hits = sel.select(&table);
        let mut out = String::new();
        if sel.count {
            out.push_str(&format!("{}\n", hits.len()));
        } else if sel.echo {
            for p in &hits {
                out.push_str(&format!("{} killed (pid {})\n", p.comm, p.pid));
            }
        }
        let mut result = CommandResult::stdout(out);
        result.status = u8::from(hits.is_empty());
        result
    }

    /// `pidof [-s] [-c] [-n] [-x] [-q] [-o PID] [-S SEP] NAME...`: the pids of the processes named,
    /// highest first on one line, status 1 and no output when there are none.
    pub(super) fn cmd_pidof(&mut self, parts: &[&str]) -> CommandResult {
        let table = self.process_table();
        let (mut single, mut quiet) = (false, false);
        let mut separator = " ".to_string();
        let mut names: Vec<&str> = Vec::new();
        let mut omit: Vec<u32> = Vec::new();
        let mut args = parts.get(1..).unwrap_or(&[]).iter().copied();
        while let Some(arg) = args.next() {
            match arg {
                "-s" => single = true,
                "-q" => quiet = true,
                "-c" | "-n" | "-x" => {}
                "-o" => {
                    omit.extend(args.next().and_then(parse_pid_list).unwrap_or_default());
                }
                "-S" => separator = args.next().unwrap_or(" ").to_string(),
                _ => names.push(arg),
            }
        }
        let mut pids: Vec<u32> = table
            .procs
            .iter()
            .filter(|p| !omit.contains(&p.pid))
            .filter(|p| {
                names.iter().any(|name| {
                    let base = p
                        .argv
                        .first()
                        .map_or("", |a| a.rsplit('/').next().unwrap_or(a));
                    p.comm == *name
                        || base == *name
                        || (name.contains('/')
                            && (p.exe == *name || p.argv.first().is_some_and(|a| a == name)))
                })
            })
            .map(|p| p.pid)
            .collect();
        pids.sort_unstable_by(|a, b| b.cmp(a));
        if single {
            pids.truncate(1);
        }
        if pids.is_empty() {
            return CommandResult::silent(1);
        }
        if quiet {
            return CommandResult::silent(0);
        }
        let line: Vec<String> = pids.iter().map(u32::to_string).collect();
        CommandResult::stdout(format!("{}\n", line.join(&separator)))
    }
}

// ------------------------------------------------------------------------------------- killall

const KILLALL_USAGE: &str = "Usage: killall [ -Z CONTEXT ] [ -u USER ] [ -y TIME ] [ -o TIME ] [ -eIgiqrvw ]\n               [ -s SIGNAL | -SIGNAL ] NAME...\n       killall -l\n       killall -V, --version\n\n  -e,--exact          require exact match for very long names\n  -I,--ignore-case    case insensitive process name match\n  -g,--process-group  kill process group instead of process\n  -y,--younger-than   kill processes younger than TIME\n  -o,--older-than     kill processes older than TIME\n  -i,--interactive    ask for confirmation before killing\n  -l,--list           list all known signal names\n  -q,--quiet          don't print complaints\n  -r,--regexp         interpret NAME as an extended regular expression\n  -s,--signal SIGNAL  send this signal instead of SIGTERM\n  -u,--user USER      kill only process(es) running as USER\n  -v,--verbose        report if the signal was successfully sent\n  -V,--version        display version information\n  -w,--wait           wait for processes to die\n  -n,--ns PID         match processes that belong to the same namespaces\n                      as PID\n  -Z,--context REGEXP kill only process(es) having context\n                      (must precede other arguments)\n";

/// The signal names `killall -l` and `kill -l` print on the shells that list names alone, wrapped
/// to a line of at most 72 characters.
fn wrapped_signal_names(extra: &[&str]) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for name in SIGNAL_NAMES.iter().chain(extra) {
        if !line.is_empty() && line.len().saturating_add(name.len()).saturating_add(1) > 72 {
            out.push_str(&line);
            out.push('\n');
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(name);
    }
    out.push_str(&line);
    out.push('\n');
    out
}

impl FakeShell {
    /// `killall [-SIGNAL] [-qvwe] NAME...`. A name that is running succeeds silently, a name that
    /// is not says so and the command fails, as psmisc does. The table does not change.
    pub(super) fn cmd_killall(&mut self, parts: &[&str]) -> CommandResult {
        let busybox = self.busybox_depth > 0;
        let (mut quiet, mut verbose, mut fold) = (false, false, false);
        let mut signal = 15u32;
        let mut names: Vec<&str> = Vec::new();
        let mut options = true;
        let mut args = parts.get(1..).unwrap_or(&[]).iter().copied();
        while let Some(arg) = args.next() {
            if !options || arg == "-" || !arg.starts_with('-') {
                names.push(arg);
                continue;
            }
            if arg == "--" {
                options = false;
                continue;
            }
            let body = arg.get(1..).unwrap_or("");
            if let Some(n) = parse_signal(body) {
                signal = n;
                continue;
            }
            match arg {
                "--version" | "-V" => {
                    return CommandResult::stdout(
                        "killall (PSmisc) 23.4\nCopyright (C) 1993-2021 Werner Almesberger and Craig Small\n\nPSmisc comes with ABSOLUTELY NO WARRANTY.\nThis is free software, and you are welcome to redistribute it under\nthe terms of the GNU General Public License.\nFor more information about these matters, see the files named COPYING.\n",
                    );
                }
                "--list" | "-l" => return CommandResult::stdout(wrapped_signal_names(&[])),
                "--quiet" => quiet = true,
                "--verbose" => verbose = true,
                "--signal" => match args.next().and_then(parse_signal) {
                    Some(n) => signal = n,
                    None => return CommandResult::stderr(1, KILLALL_USAGE),
                },
                "--exact" | "--wait" | "--regexp" | "--interactive" | "--process-group" => {}
                "--ignore-case" => fold = true,
                _ if arg.starts_with("--") => return CommandResult::stderr(1, KILLALL_USAGE),
                _ => {
                    for (index, flag) in body.char_indices() {
                        let rest = body
                            .get(index.saturating_add(flag.len_utf8())..)
                            .unwrap_or("");
                        match flag {
                            'q' => quiet = true,
                            'v' => verbose = true,
                            'I' => fold = true,
                            'e' | 'w' | 'r' | 'g' | 'i' => {}
                            's' | 'u' | 'o' | 'y' | 'n' | 'Z' => {
                                let value = if rest.is_empty() {
                                    args.next()
                                } else {
                                    Some(rest)
                                };
                                if flag == 's' {
                                    match value.and_then(parse_signal) {
                                        Some(n) => signal = n,
                                        None => return CommandResult::stderr(1, KILLALL_USAGE),
                                    }
                                }
                                break;
                            }
                            _ => return CommandResult::stderr(1, KILLALL_USAGE),
                        }
                    }
                }
            }
        }
        if names.is_empty() {
            return CommandResult::stderr(1, KILLALL_USAGE);
        }
        let table = self.process_table();
        let mut out = CommandResult::silent(0);
        let mut missing = false;
        for name in names {
            let wanted: String = name.chars().take(15).collect();
            let hits: Vec<&Proc> = table
                .procs
                .iter()
                .filter(|p| {
                    if fold {
                        p.comm.to_lowercase() == wanted.to_lowercase()
                    } else {
                        p.comm == wanted
                    }
                })
                .collect();
            if hits.is_empty() {
                missing = true;
                if busybox {
                    out.append(CommandResult::stderr(
                        1,
                        format!("killall: {name}: no process killed\n"),
                    ));
                } else if !quiet {
                    out.append(CommandResult::stderr(
                        1,
                        format!("{name}: no process found\n"),
                    ));
                }
            } else if verbose {
                for p in hits {
                    out.append(CommandResult::stdout(format!(
                        "Killed {}({}) with signal {signal}\n",
                        p.comm, p.pid
                    )));
                }
            }
        }
        out.status = u8::from(missing);
        out
    }
}

// ----------------------------------------------------------------------------------------- kill

/// bash's `kill -l` with no argument: the signals in rows of five, each as `N) SIGNAME`, a tab
/// after each but the fifth, as bash's `display_signal_list` lays them out.
fn bash_signal_list() -> String {
    let mut out = String::new();
    let mut column = 0u32;
    for n in 1..=64u32 {
        let Some(name) = signal_name(n) else { continue };
        out.push_str(&format!("{n:>2}) SIG{name}"));
        column = column.saturating_add(1);
        if column < 5 {
            out.push('\t');
        } else {
            out.push('\n');
            column = 0;
        }
    }
    if column != 0 {
        out.push('\n');
    }
    out
}

/// Which `kill` is answering, which decides the wording of its messages.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KillForm {
    /// bash's builtin.
    Bash,
    /// dash's or mksh's builtin.
    Posix,
    /// procps' `/bin/kill` file.
    File,
    /// The BusyBox applet.
    Busybox,
}

impl FakeShell {
    fn kill_form(&self, command: &str) -> KillForm {
        if self.busybox_depth > 0 {
            KillForm::Busybox
        } else if command.contains('/') {
            KillForm::File
        } else if self.is_bash() {
            KillForm::Bash
        } else {
            KillForm::Posix
        }
    }

    /// Whether a signal sent to `pid` would reach something: a row of the table, the group of
    /// one, or a process this session started (a background job or a nested shell).
    fn signal_target_exists(&self, table: &Table, pid: i64) -> bool {
        match pid {
            0 | -1 => true,
            n if n > 0 => u32::try_from(n).is_ok_and(|id| {
                let (login, _) = self.login_shell();
                table.find(id).is_some() || (login < id && id < self.pids.peek())
            }),
            n => n
                .checked_abs()
                .and_then(|id| u32::try_from(id).ok())
                .is_some_and(|id| table.find(id).is_some()),
        }
    }

    /// `kill [-s SIG | -n NUM | -SIG] PID...` and `kill -l [SIG]`. A pid in the table, the group
    /// of one, or one this session started succeeds silently and signals nothing; any other pid
    /// is "No such process". A job spec is "no such job": no jobs are modeled.
    pub(super) fn cmd_kill(&mut self, parts: &[&str]) -> CommandResult {
        let form = self.kill_form(parts.first().copied().unwrap_or("kill"));
        let args = parts.get(1..).unwrap_or(&[]);
        let mut at = 0usize;
        let mut listing: Option<&[&str]> = None;
        while let Some(arg) = args.get(at).copied() {
            if arg == "--" {
                at = at.saturating_add(1);
                break;
            }
            let Some(flag) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
                break;
            };
            if matches!(flag, "l" | "L") {
                listing = Some(args.get(at.saturating_add(1)..).unwrap_or(&[]));
                break;
            }
            if matches!(flag, "s" | "n") {
                let spec = args.get(at.saturating_add(1)).copied().unwrap_or("");
                if parse_signal(spec).is_none() {
                    return self.kill_bad_signal(form, spec);
                }
                at = at.saturating_add(2);
                continue;
            }
            if parse_signal(flag).is_none() {
                return self.kill_bad_signal(form, flag);
            }
            at = at.saturating_add(1);
        }
        if let Some(specs) = listing {
            return self.kill_list(form, specs);
        }
        let targets = args.get(at..).unwrap_or(&[]);
        if targets.is_empty() {
            return CommandResult::stderr(2, self.kill_usage(form));
        }
        let table = self.process_table();
        let mut result = CommandResult::silent(0);
        let mut failed = false;
        for target in targets {
            match self.kill_one(form, &table, target) {
                Ok(()) => {}
                Err(text) => {
                    failed = true;
                    result.append(CommandResult::stderr(1, text));
                }
            }
        }
        result.status = u8::from(failed);
        result
    }

    fn kill_one(&self, form: KillForm, table: &Table, target: &str) -> Result<(), String> {
        if target.starts_with('%') {
            return Err(match form {
                KillForm::Bash => self.shell_error(format_args!("kill: {target}: no such job")),
                _ => self.kill_word(target, "no such job"),
            });
        }
        let Ok(pid) = target.parse::<i64>() else {
            return Err(match form {
                KillForm::Bash => self.shell_error(format_args!(
                    "kill: {target}: arguments must be process or job IDs"
                )),
                KillForm::File => format!("kill: failed to parse argument: '{target}'\n"),
                KillForm::Busybox => format!("kill: bad pid '{target}'\n"),
                KillForm::Posix => self.shell_error(format_args!("kill: Illegal number: {target}")),
            });
        };
        if self.signal_target_exists(table, pid) {
            return Ok(());
        }
        Err(match form {
            KillForm::Bash => self.shell_error(format_args!("kill: ({pid}) - No such process")),
            KillForm::File => format!("kill: ({pid}): No such process\n"),
            KillForm::Busybox => format!("kill: can't kill pid {pid}: No such process\n"),
            KillForm::Posix => self.kill_word(&pid.to_string(), "No such process"),
        })
    }

    fn kill_word(&self, subject: &str, reason: &str) -> String {
        self.shell_error(format_args!("kill: {subject}: {reason}"))
    }

    fn kill_bad_signal(&self, form: KillForm, spec: &str) -> CommandResult {
        let text = match form {
            KillForm::Bash => {
                self.shell_error(format_args!("kill: {spec}: invalid signal specification"))
            }
            KillForm::File => format!("kill: unknown signal: {spec}\n"),
            KillForm::Busybox => format!("kill: bad signal name '{spec}'\n"),
            KillForm::Posix => self.shell_error(format_args!("kill: Illegal option -{spec}")),
        };
        CommandResult::stderr(if form == KillForm::Bash { 1 } else { 2 }, text)
    }

    fn kill_usage(&self, form: KillForm) -> String {
        match form {
            KillForm::Bash => "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n".to_string(),
            KillForm::File => "\nUsage:\n kill [options] <pid> [...]\n\nOptions:\n <pid> [...]            send signal to every <pid> listed\n -<signal>, -s, --signal <signal>\n                        specify the <signal> to be sent\n -l, --list=[<signal>]  list all signal names, or convert one to a name\n -L, --table            list all signal names in a nice table\n\n -h, --help     display this help and exit\n -V, --version  output version information and exit\n\nFor more details see kill(1).\n".to_string(),
            KillForm::Busybox => "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3.1) multi-call binary.\n\nUsage: kill [-l] [-SIG] PID...\n\nSend a signal (default: TERM) to the given PIDs\n\n\t-l\tList all signal names and numbers\n".to_string(),
            KillForm::Posix => "kill: usage: kill [-s sigspec | -signum | -sigspec] [pid | job]... or\nkill -l [exitstatus]\n".to_string(),
        }
    }

    /// `kill -l [SIG...]`: with no operand the whole list, bash's as numbered rows and the other
    /// shells' as bare names; with operands each number becomes its name and each name its number.
    fn kill_list(&self, form: KillForm, specs: &[&str]) -> CommandResult {
        if specs.is_empty() {
            return CommandResult::stdout(match form {
                KillForm::Bash | KillForm::File => bash_signal_list(),
                KillForm::Posix | KillForm::Busybox => wrapped_signal_names(&[]),
            });
        }
        let mut result = CommandResult::silent(0);
        let mut failed = false;
        for spec in specs {
            let answer = match spec.parse::<u32>() {
                Ok(n) => signal_name(n),
                Err(_) => parse_signal(spec).map(|n| n.to_string()),
            };
            match answer {
                Some(text) => result.append(CommandResult::stdout(format!("{text}\n"))),
                None => {
                    failed = true;
                    result.append(CommandResult::stderr(
                        1,
                        self.shell_error(format_args!(
                            "kill: {spec}: invalid signal specification"
                        )),
                    ));
                }
            }
        }
        result.status = u8::from(failed);
        result
    }
}
