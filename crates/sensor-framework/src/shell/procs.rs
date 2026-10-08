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
//! has no node and reads as absent, as on a real `/proc`. The same set carries `/proc/net`, which
//! `netinfo.rs` renders, because the filesystem takes one whole generated set at a time.
//!
//! The login shell's row also has `maps` and `fd`, and `/proc/self/{status,maps,fd}` are those
//! same nodes under the other name: `/proc/self` is the shell's own row (the one `$$` names), not
//! the reading command's, as `/proc/self/exe` is for the byte readers. `status` is the one
//! `status_text` renderer, so the two names cannot differ. Everything is synthesized from the
//! table and fixed constants: no byte comes from the host's `/proc`, and every address is a fixed
//! function of the pid. The descriptor links name the session's tty, or `pipe:[inode]` for an exec
//! request, and make `/dev/stdin`, `/dev/stdout` and `/dev/stderr` resolve.
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
use crate::fakefs::{Blob, Device, ELF_HEADER_LEN, ElfImage, Node};

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
    /// This many seconds before the command that lists it runs: a worker thread the kernel
    /// started recently.
    Ago(u64),
}

#[derive(Debug, Clone)]
struct Proc {
    pid: u32,
    ppid: u32,
    /// The kernel's short name, at most 15 characters.
    comm: String,
    /// The argument vector, empty for none (a kernel thread, shown as `[comm]`).
    argv: Vec<String>,
    /// The `/proc/<pid>/stat` state letter: `S`, `R` or `I` (an idle kernel worker).
    state: char,
    /// What follows the state letter in the BSD `STAT` column.
    mark: &'static str,
    /// `pts/0`, `tty1`, or `?` for none.
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
    /// The owner, as `/etc/passwd` names it.
    user: &'static str,
    uid: u32,
    /// `rt` for a real-time process; anything else is a normal one, whose `top` `PR` is 20 plus
    /// its nice value.
    prio: &'static str,
    nice: i8,
}

impl Proc {
    fn stat_column(&self) -> String {
        format!("{}{}", self.state, self.mark)
    }

    /// The owner as procps' 8-wide `USER` column shows it: a longer name is cut to seven
    /// characters and a `+` (recorded: `systemd+` for `systemd-resolve`, `message+`).
    fn user_column(&self) -> String {
        if self.user.len() > 8 {
            format!("{}+", self.user.get(..7).unwrap_or(self.user))
        } else {
            self.user.to_string()
        }
    }

    /// `top`'s `PR`: `rt` for a real-time process, else 20 plus the nice value.
    fn top_priority(&self) -> String {
        if self.prio == "rt" {
            "rt".to_string()
        } else {
            20i16.saturating_add(i16::from(self.nice)).to_string()
        }
    }

    /// The `priority` field of `/proc/<pid>/stat`: -100 for real-time priority 99.
    fn stat_priority(&self) -> String {
        if self.prio == "rt" {
            "-100".to_string()
        } else {
            self.top_priority()
        }
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
            Started::Ago(secs) => self
                .now
                .checked_sub_signed(seconds(secs))
                .unwrap_or(self.now)
                .max(self.boot),
        }
    }

    /// Clock ticks between boot and the process's start, the figure `stat` carries.
    fn start_ticks(&self, p: &Proc) -> u64 {
        match p.started {
            Started::Boot(ticks) => ticks,
            Started::Session | Started::Now | Started::Ago(_) => {
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
        let mut nodes = process_nodes(&table, &mounts, &mountinfo);
        // `/proc/net` joins the process nodes in the same set: `set_generated` replaces the
        // whole set, so it has to be handed everything at once.
        nodes.extend(self.net_nodes(table.boot.timestamp()));
        self.fs.set_generated(nodes);
        self.refresh_clock_nodes();
    }

    /// `/proc/uptime` and `/proc/loadavg` as of the shell clock: refreshed at every input line,
    /// so they agree with `uptime`, `top` and `ps` run on the same line. The uptime is the one
    /// [`uptime_secs`] gives every command and the load the figures `uptime` prints; the idle time
    /// is a one-CPU box idle 99.2% of the time [unverified], and the task count is the table's
    /// rows plus a few threads for each multi-threaded daemon [unverified].
    pub(super) fn refresh_clock_nodes(&mut self) {
        let now = self.now();
        let secs = uptime_secs(&now);
        let centis = u64::from(now.timestamp_subsec_millis() / 10);
        let total = secs.saturating_mul(100).saturating_add(centis);
        let idle = total.saturating_mul(992) / 1_000;
        let uptime = format!("{secs}.{centis:02} {}.{:02}\n", idle / 100, idle % 100);
        let table = self.process_table();
        let threads: usize = table
            .procs
            .iter()
            .map(|p| if p.mark.contains('l') { 4 } else { 1 })
            .sum();
        let last_pid = self.pids.peek().saturating_sub(1);
        let loadavg = format!(
            "{} 1/{threads} {last_pid}\n",
            load_average(&now).replace(", ", " ")
        );
        let boot = table.boot.timestamp();
        self.fs
            .put_generated("/proc/uptime", file_node(uptime, now.timestamp()));
        self.fs
            .put_generated("/proc/loadavg", file_node(loadavg, boot));
    }

    /// The pid of the daemon the modeled init started under the kernel name `comm` (`sshd`,
    /// `telnetd`, `adbd`), the process a listening socket belongs to.
    pub(super) fn listener_pid(&self, comm: &str) -> Option<u32> {
        self.process_table()
            .procs
            .iter()
            .find(|p| p.ppid == 1 && p.comm == comm)
            .map(|p| p.pid)
    }

    /// What `systemctl status` reads of a service's main process: the first child of init (or,
    /// for `user@0.service`, the session's user manager) under the kernel name `comm` and, when
    /// given, on the terminal `tty` (the two gettys share a name).
    pub(super) fn service_process(&self, comm: &str, tty: Option<&str>) -> Option<ServiceProc> {
        let table = self.process_table();
        table
            .procs
            .iter()
            .find(|p| p.ppid == 1 && p.pid != 1 && p.comm == comm && tty.is_none_or(|t| p.tty == t))
            .map(|p| ServiceProc {
                pid: p.pid,
                started: table.started_at(p),
                argv: p.argv.clone(),
                comm: p.comm.clone(),
                rss_kib: p.rss_kib,
                cpu_secs: p.cpu_secs,
            })
    }

    /// When the box booted, on the shell clock: what every boot-started unit's `since` reads.
    pub(super) fn boot_time(&self) -> DateTime<Utc> {
        self.process_table().boot
    }

    /// When this session logged in, on the shell clock.
    pub(super) fn session_time(&self) -> DateTime<Utc> {
        self.process_table().session
    }
}

/// A service's main process, as `systemctl status` shows it.
pub(super) struct ServiceProc {
    pub(super) pid: u32,
    pub(super) started: DateTime<Utc>,
    pub(super) argv: Vec<String>,
    pub(super) comm: String,
    pub(super) rss_kib: u64,
    pub(super) cpu_secs: u64,
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
        user: "root",
        uid: 0,
        prio: "20",
        nice: 0,
    }
}

/// One kernel thread of the modeled 5.15 kernel on a one-vCPU Xen guest: pid, name, state, `STAT`
/// suffix, and the clock tick after boot it started at.
type Kthread = (u32, &'static str, char, &'static str, u64);

/// The kernel threads a freshly booted Ubuntu 22.04 EC2 (Xen HVM, one vCPU) instance shows, in pid
/// order [unverified: composed from knowledge of 5.15's threads, not captured].
const UBUNTU_KTHREADS: &[Kthread] = &[
    (2, "kthreadd", 'S', "", 0),
    (3, "rcu_gp", 'I', "<", 0),
    (4, "rcu_par_gp", 'I', "<", 0),
    (5, "slub_flushwq", 'I', "<", 0),
    (6, "netns", 'I', "<", 0),
    (8, "kworker/0:0H-events_highpri", 'I', "<", 1),
    (10, "mm_percpu_wq", 'I', "<", 1),
    (11, "rcu_tasks_rude_", 'S', "", 1),
    (12, "rcu_tasks_trace", 'S', "", 1),
    (13, "ksoftirqd/0", 'S', "", 1),
    (14, "rcu_sched", 'I', "", 1),
    (15, "migration/0", 'S', "", 1),
    (16, "idle_inject/0", 'S', "", 1),
    (18, "cpuhp/0", 'S', "", 1),
    (19, "kdevtmpfs", 'S', "", 2),
    (20, "inet_frag_wq", 'I', "<", 2),
    (21, "kauditd", 'S', "", 2),
    (22, "xenbus", 'S', "", 2),
    (23, "xenwatch", 'S', "", 2),
    (24, "khungtaskd", 'S', "", 2),
    (25, "oom_reaper", 'S', "", 2),
    (26, "writeback", 'I', "<", 2),
    (27, "kcompactd0", 'S', "", 2),
    (28, "ksmd", 'S', "N", 2),
    (29, "khugepaged", 'S', "N", 2),
    (76, "kintegrityd", 'I', "<", 3),
    (77, "kblockd", 'I', "<", 3),
    (78, "blkcg_punt_bio", 'I', "<", 3),
    (79, "tpm_dev_wq", 'I', "<", 3),
    (80, "ata_sff", 'I', "<", 3),
    (81, "md", 'I', "<", 3),
    (82, "edac-poller", 'I', "<", 3),
    (83, "devfreq_wq", 'I', "<", 3),
    (84, "watchdogd", 'S', "", 3),
    (85, "kworker/0:1H-kblockd", 'I', "<", 3),
    (87, "kswapd0", 'S', "", 3),
    (88, "ecryptfs-kthrea", 'S', "", 3),
    (90, "kthrotld", 'I', "<", 3),
    (91, "acpi_thermal_pm", 'I', "<", 3),
    (92, "scsi_eh_0", 'S', "", 4),
    (93, "scsi_tmf_0", 'I', "<", 4),
    (94, "scsi_eh_1", 'S', "", 4),
    (95, "scsi_tmf_1", 'I', "<", 4),
    (97, "vfio-irqfd-clea", 'I', "<", 4),
    (98, "mld", 'I', "<", 4),
    (99, "ipv6_addrconf", 'I', "<", 4),
    (110, "kstrp", 'I', "<", 4),
    (113, "zswap-shrink", 'I', "<", 4),
    (114, "kworker/u31:0", 'I', "<", 4),
    (119, "charger_manager", 'I', "<", 5),
    (189, "jbd2/xvda1-8", 'S', "", 112),
    (190, "ext4-rsv-conver", 'I', "<", 112),
    (264, "kaluad", 'I', "<", 160),
    (266, "kmpath_rdacd", 'I', "<", 160),
    (267, "kmpathd", 'I', "<", 160),
    (268, "kmpath_handlerd", 'I', "<", 160),
];

/// One daemon systemd starts on the modeled box.
struct Daemon {
    pid: u32,
    user: &'static str,
    uid: u32,
    comm: &'static str,
    argv: &'static [&'static str],
    exe: &'static str,
    /// The clock tick after boot it started at.
    started: u64,
    /// Virtual size, resident size (KiB) and CPU seconds used.
    sizes: (u64, u64, u64),
    mark: &'static str,
    tty: &'static str,
    prio: &'static str,
    nice: i8,
}

// One positional row per service keeps the table below readable as a `ps` listing.
#[allow(clippy::too_many_arguments)]
const fn daemon(
    pid: u32,
    who: (&'static str, u32),
    comm: &'static str,
    argv: &'static [&'static str],
    exe: &'static str,
    started: u64,
    sizes: (u64, u64, u64),
    mark: &'static str,
) -> Daemon {
    Daemon {
        pid,
        user: who.0,
        uid: who.1,
        comm,
        argv,
        exe,
        started,
        sizes,
        mark,
        tty: "?",
        prio: "20",
        nice: 0,
    }
}

const ROOT: (&str, u32) = ("root", 0);

/// The services of a stock Ubuntu 22.04 server image, each the main process of a unit
/// `systemctl list-units --state=running` lists, owned by the account `/etc/passwd` gives it
/// [unverified: sizes and pids composed, not captured]. `cron` (641) and the `sshd` listener
/// (721) keep the pids recorded sessions and the tests have always seen.
const UBUNTU_DAEMONS: &[Daemon] = &[
    Daemon {
        nice: -1,
        ..daemon(
            239,
            ROOT,
            "systemd-journal",
            &["/lib/systemd/systemd-journald"],
            "/usr/lib/systemd/systemd-journald",
            215,
            (64_116, 15_628, 1),
            "<s",
        )
    },
    Daemon {
        prio: "rt",
        ..daemon(
            269,
            ROOT,
            "multipathd",
            &["/sbin/multipathd", "-d", "-s"],
            "/usr/sbin/multipathd",
            240,
            (289_312, 27_080, 5),
            "Lsl",
        )
    },
    daemon(
        272,
        ROOT,
        "systemd-udevd",
        &["/lib/systemd/systemd-udevd"],
        "/usr/lib/systemd/systemd-udevd",
        243,
        (25_404, 6_148, 0),
        "s",
    ),
    daemon(
        540,
        ("systemd-network", 101),
        "systemd-network",
        &["/lib/systemd/systemd-networkd"],
        "/usr/lib/systemd/systemd-networkd",
        1_160,
        (16_120, 8_004, 0),
        "s",
    ),
    daemon(
        542,
        ("systemd-resolve", 102),
        "systemd-resolve",
        &["/lib/systemd/systemd-resolved"],
        "/usr/lib/systemd/systemd-resolved",
        1_210,
        (25_536, 12_896, 0),
        "s",
    ),
    daemon(
        544,
        ("systemd-timesync", 106),
        "systemd-timesyn",
        &["/lib/systemd/systemd-timesyncd"],
        "/usr/lib/systemd/systemd-timesyncd",
        1_212,
        (89_352, 6_488, 0),
        "sl",
    ),
    daemon(
        641,
        ROOT,
        "cron",
        &["/usr/sbin/cron", "-f", "-P"],
        "/usr/sbin/cron",
        1_480,
        (7_288, 4_636, 0),
        "s",
    ),
    daemon(
        642,
        ("messagebus", 103),
        "dbus-daemon",
        &[
            "@dbus-daemon",
            "--system",
            "--address=systemd:",
            "--nofork",
            "--nopidfile",
            "--systemd-activation",
            "--syslog-only",
        ],
        "/usr/bin/dbus-daemon",
        1_482,
        (8_540, 4_564, 0),
        "s",
    ),
    daemon(
        648,
        ROOT,
        "networkd-dispat",
        &[
            "/usr/bin/python3",
            "/usr/bin/networkd-dispatcher",
            "--run-startup-triggers",
        ],
        "/usr/bin/python3.10",
        1_490,
        (33_076, 19_120, 0),
        "s",
    ),
    daemon(
        649,
        ROOT,
        "polkitd",
        &["/usr/libexec/polkitd", "--no-debug"],
        "/usr/libexec/polkitd",
        1_492,
        (234_484, 6_764, 0),
        "sl",
    ),
    daemon(
        650,
        ("syslog", 104),
        "rsyslogd",
        &["/usr/sbin/rsyslogd", "-n", "-iNONE"],
        "/usr/sbin/rsyslogd",
        1_493,
        (222_400, 5_168, 0),
        "sl",
    ),
    daemon(
        652,
        ROOT,
        "snapd",
        &["/usr/lib/snapd/snapd"],
        "/usr/lib/snapd/snapd",
        1_495,
        (1_171_912, 35_764, 4),
        "sl",
    ),
    daemon(
        655,
        ROOT,
        "systemd-logind",
        &["/lib/systemd/systemd-logind"],
        "/usr/lib/systemd/systemd-logind",
        1_497,
        (15_336, 6_880, 0),
        "s",
    ),
    daemon(
        658,
        ROOT,
        "udisksd",
        &["/usr/libexec/udisks2/udisksd"],
        "/usr/libexec/udisks2/udisksd",
        1_499,
        (392_840, 12_324, 0),
        "sl",
    ),
    Daemon {
        tty: "ttyS0",
        ..daemon(
            670,
            ROOT,
            "agetty",
            &[
                "/sbin/agetty",
                "-o",
                "-p -- \\u",
                "--keep-baud",
                "115200,57600,38400,9600",
                "ttyS0",
                "vt220",
            ],
            "/usr/sbin/agetty",
            1_560,
            (6_216, 1_052, 0),
            "s+",
        )
    },
    Daemon {
        tty: "tty1",
        ..daemon(
            674,
            ROOT,
            "agetty",
            &[
                "/sbin/agetty",
                "-o",
                "-p -- \\u",
                "--noclear",
                "tty1",
                "linux",
            ],
            "/usr/sbin/agetty",
            1_562,
            (6_172, 1_076, 0),
            "s+",
        )
    },
    daemon(
        679,
        ROOT,
        "unattended-upgr",
        &[
            "/usr/bin/python3",
            "/usr/share/unattended-upgrades/unattended-upgrade-shutdown",
            "--wait-for-signal",
        ],
        "/usr/bin/python3.10",
        1_590,
        (109_748, 21_312, 0),
        "sl",
    ),
    daemon(
        690,
        ROOT,
        "ModemManager",
        &["/usr/sbin/ModemManager"],
        "/usr/sbin/ModemManager",
        1_640,
        (317_012, 11_904, 0),
        "sl",
    ),
];

fn kthread(row: &Kthread) -> Proc {
    let &(pid, comm, state, mark, ticks) = row;
    // A `<` worker runs at the highest priority; `ksmd` and `khugepaged` are niced.
    let nice = match (mark, comm) {
        ("<", _) => -20,
        (_, "ksmd") => 5,
        (_, "khugepaged") => 19,
        _ => 0,
    };
    Proc {
        state,
        mark,
        nice,
        wchan: "-",
        exe: String::new(),
        ..root_proc(
            pid,
            if pid == 2 { 0 } else { 2 },
            comm,
            &[],
            "",
            Started::Boot(ticks),
            (0, 0, 0),
        )
    }
}

fn daemon_row(d: &Daemon) -> Proc {
    Proc {
        mark: d.mark,
        tty: d.tty,
        user: d.user,
        uid: d.uid,
        prio: d.prio,
        nice: d.nice,
        ..root_proc(
            d.pid,
            1,
            d.comm,
            d.argv,
            d.exe,
            Started::Boot(d.started),
            d.sizes,
        )
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
    let mut rows = vec![root_proc(
        1,
        0,
        "systemd",
        &["/sbin/init"],
        "/usr/lib/systemd/systemd",
        Started::Boot(100),
        (167_800, 12_916, 3),
    )];
    rows.extend(UBUNTU_KTHREADS.iter().map(kthread));
    rows.extend(UBUNTU_DAEMONS.iter().map(daemon_row));
    // Workers the kernel started and retired since boot, as any box that has been up a while has.
    for (offset, comm, ago) in [
        (41, "kworker/0:2-events", 1_340),
        (17, "kworker/u30:1-events_unbound", 610),
        (9, "kworker/0:0-events", 95),
    ] {
        let pid = login.saturating_sub(offset);
        if pid > DAEMON_PID.saturating_add(1) {
            rows.push(Proc {
                state: 'I',
                mark: "",
                wchan: "-",
                exe: String::new(),
                ..root_proc(pid, 2, comm, &[], "", Started::Ago(ago), (0, 0, 0))
            });
        }
    }
    // The session's user manager: pam_systemd starts `user@0.service` for the login.
    let manager = login.saturating_sub(4);
    if manager > DAEMON_PID.saturating_add(1) {
        rows.push(root_proc(
            manager,
            1,
            "systemd",
            &["/lib/systemd/systemd", "--user"],
            "/usr/lib/systemd/systemd",
            Started::Session,
            (17_064, 9_652, 0),
        ));
        rows.push(Proc {
            mark: "",
            ..root_proc(
                manager.saturating_add(1),
                manager,
                "(sd-pam)",
                &["(sd-pam)"],
                "/usr/lib/systemd/systemd",
                Started::Session,
                (170_252, 4_812, 0),
            )
        });
    }
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
    // One copy of each mount table, shared by every row's node.
    let mounts_blob = Blob::from_bytes(mounts.to_vec());
    let mountinfo_blob = Blob::from_bytes(mountinfo.to_vec());
    let shared_node = |blob: &Blob, mtime: i64| {
        let mut node = Node::regular(blob.clone(), 0o100_444);
        node.meta.mtime = mtime;
        node
    };
    for p in &table.procs {
        let mtime = table.started_at(p).timestamp();
        let base = format!("/proc/{}", p.pid);
        if p.argv.is_empty() && p.exe.is_empty() {
            // A kernel thread: the files a reader of its row looks at, and no image or tables.
            let mut dir = Node::directory(
                ["cmdline", "comm", "stat", "status"]
                    .iter()
                    .map(|e| (*e).to_string())
                    .collect(),
            );
            dir.meta.mode = 0o040_555;
            dir.meta.mtime = mtime;
            nodes.insert(base.clone(), dir);
            nodes.insert(format!("{base}/cmdline"), file_node(Vec::new(), mtime));
            nodes.insert(
                format!("{base}/comm"),
                file_node(format!("{}\n", p.comm), mtime),
            );
            nodes.insert(
                format!("{base}/stat"),
                file_node(stat_line(table, p), mtime),
            );
            nodes.insert(
                format!("{base}/status"),
                file_node(status_text(table, p), mtime),
            );
            continue;
        }
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
        // `fd` and `maps` are modeled for the shell's own row only: nothing of any other row's
        // memory or descriptors is described, so those stay absent as on a `/proc` that denies them.
        let mut names: Vec<String> = entries.iter().map(|e| (*e).to_string()).collect();
        if p.attached {
            names.push("fd".to_string());
            names.push("maps".to_string());
            names.sort_unstable();
        }
        let mut dir = Node::directory(names);
        dir.meta.mode = 0o040_555;
        dir.meta.mtime = mtime;
        nodes.insert(base.clone(), dir);
        if p.attached {
            // `/proc/self` is the shell's own row: one set of nodes, built once and placed under
            // both names, so `/proc/self/status` cannot differ from `/proc/<pid>/status`.
            for (rel, node) in own_nodes(table, p, mountinfo, mtime) {
                nodes.insert(format!("/proc/self/{rel}"), node.clone());
                nodes.insert(format!("{base}/{rel}"), node);
            }
            nodes.insert(
                "/proc/self/status".to_string(),
                file_node(status_text(table, p), mtime),
            );
            if let Some(tty) = p.tty.strip_prefix("pts/").filter(|_| !table.android) {
                // The target of the Ubuntu fd links and so of `/dev/stdin`: the same tty
                // `/dev/tty` is, which reads empty.
                let mut node = Node::device(Device::Tty);
                node.meta.mtime = mtime;
                nodes.insert(format!("/dev/pts/{tty}"), node);
            }
        }
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
        nodes.insert(
            format!("{base}/mountinfo"),
            shared_node(&mountinfo_blob, mtime),
        );
        nodes.insert(format!("{base}/mounts"), shared_node(&mounts_blob, mtime));
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
        // The images behind the daemons' `exe` links. Sizes [unverified]: plausible for jammy's
        // packages, not recorded (sshd's recorded image is in the binaries table and wins).
        let binaries: [(&str, u64); 19] = [
            ("/usr/lib/systemd/systemd", 1_841_488),
            ("/usr/sbin/sshd", 1_070_560),
            ("/usr/sbin/cron", 56_048),
            ("/usr/sbin/telnetd", 51_512),
            ("/usr/lib/systemd/systemd-journald", 162_256),
            ("/usr/sbin/multipathd", 128_920),
            ("/usr/lib/systemd/systemd-udevd", 2_166_744),
            ("/usr/lib/systemd/systemd-networkd", 2_166_744),
            ("/usr/lib/systemd/systemd-resolved", 538_168),
            ("/usr/lib/systemd/systemd-timesyncd", 51_856),
            ("/usr/bin/dbus-daemon", 248_496),
            ("/usr/bin/python3.10", 5_904_904),
            ("/usr/libexec/polkitd", 129_336),
            ("/usr/sbin/rsyslogd", 727_248),
            ("/usr/lib/snapd/snapd", 25_620_472),
            ("/usr/lib/systemd/systemd-logind", 265_720),
            ("/usr/libexec/udisks2/udisksd", 559_232),
            ("/usr/sbin/agetty", 64_840),
            ("/usr/sbin/ModemManager", 2_093_216),
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

/// The nodes only the shell's own row has, as paths relative to its `/proc/<pid>`: `maps`, and
/// `fd` with the three standard descriptors.
///
/// The descriptors point at the session's tty (`/dev/pts/0`) when it has one. An exec request has
/// none, and sshd hands the command pipes, whose links read `pipe:[inode]` and name no file, as the
/// kernel prints them. The inode numbers are fixed functions of the pid [unverified]. The links
/// are stored in the generated layer, so `readlink`, `ls -l` and every path through them resolve
/// as any other link does, and `/dev/stdin`, `/dev/stdout` and `/dev/stderr` reach the tty by way
/// of `/proc/self/fd`.
fn own_nodes(table: &Table, p: &Proc, mountinfo: &[u8], mtime: i64) -> Vec<(String, Node)> {
    let mut fd = Node::directory(vec!["0".to_string(), "1".to_string(), "2".to_string()]);
    fd.meta.mode = 0o040_500;
    fd.meta.mtime = mtime;
    let mut nodes = vec![
        (
            "maps".to_string(),
            file_node(render_maps(table, p, mountinfo), mtime),
        ),
        ("fd".to_string(), fd),
    ];
    for n in 0u64..3 {
        let target = if p.tty == "?" {
            let inode = u64::from(p.pid)
                .saturating_mul(8)
                .saturating_add(20_000)
                .saturating_add(n.saturating_mul(2));
            format!("pipe:[{inode}]")
        } else {
            format!("/dev/{}", p.tty)
        };
        nodes.push((format!("fd/{n}"), link_node(&target, mtime)));
    }
    nodes
}

/// A run of one mapped file (or of anonymous memory) as `maps` lists it.
struct Seg {
    len: u64,
    perms: &'static str,
    /// The offset into the file.
    off: u64,
}

const fn seg(len: u64, perms: &'static str, off: u64) -> Seg {
    Seg { len, perms, off }
}

struct Mapping {
    start: u64,
    end: u64,
    perms: &'static str,
    off: u64,
    /// A file path, a bracketed kernel name (`[heap]`), or empty for anonymous memory.
    name: String,
    inode: u64,
}

/// Lay `segs` end to end from `start` and return the address after the last.
fn place(out: &mut Vec<Mapping>, start: u64, name: &str, inode: u64, segs: &[Seg]) -> u64 {
    let mut at = start;
    for s in segs {
        let end = at.saturating_add(s.len);
        out.push(Mapping {
            start: at,
            end,
            perms: s.perms,
            off: s.off,
            name: name.to_string(),
            inode,
        });
        at = end;
    }
    at
}

// Segment sizes below follow the shape of Ubuntu 22.04's bash 5.1, glibc 2.35 and ncurses 6.3
// and of Android 6's mksh and bionic. None is read from a host or a capture [unverified], and
// every inode number is invented.
const UBUNTU_BASH: &[Seg] = &[
    seg(0x2c000, "r--p", 0),
    seg(0xcd000, "r-xp", 0x2c000),
    seg(0x31000, "r--p", 0xf9000),
    seg(0x4000, "r--p", 0x12a000),
    seg(0x9000, "rw-p", 0x12e000),
    seg(0x6000, "rw-p", 0),
];
const UBUNTU_LOCALE: &[Seg] = &[seg(0x2e0000, "r--p", 0)];
const UBUNTU_TINFO: &[Seg] = &[
    seg(0x2000, "r--p", 0),
    seg(0x1b000, "r-xp", 0x2000),
    seg(0x8000, "r--p", 0x1d000),
    seg(0x4000, "r--p", 0x25000),
    seg(0x2000, "rw-p", 0x29000),
];
const UBUNTU_LIBC: &[Seg] = &[
    seg(0x28000, "r--p", 0),
    seg(0x195000, "r-xp", 0x28000),
    seg(0x58000, "r--p", 0x1bd000),
    seg(0x4000, "r--p", 0x214000),
    seg(0x2000, "rw-p", 0x218000),
    seg(0xd000, "rw-p", 0),
];
const UBUNTU_LD: &[Seg] = &[
    seg(0x2000, "r--p", 0),
    seg(0x29000, "r-xp", 0x2000),
    seg(0xb000, "r--p", 0x2b000),
    seg(0x2000, "r--p", 0x36000),
    seg(0x2000, "rw-p", 0x38000),
];
const ANDROID_SH: &[Seg] = &[
    seg(0x56000, "r-xp", 0),
    seg(0x1000, "r--p", 0x56000),
    seg(0x2000, "rw-p", 0x57000),
    seg(0x1000, "rw-p", 0),
];
const ANDROID_LIBC: &[Seg] = &[
    seg(0x6c000, "r-xp", 0),
    seg(0x1000, "r--p", 0x6c000),
    seg(0x3000, "rw-p", 0x6d000),
    seg(0x2000, "rw-p", 0),
];
const ANDROID_LINKER: &[Seg] = &[
    seg(0x2a000, "r-xp", 0),
    seg(0x1000, "r--p", 0x2a000),
    seg(0x2000, "rw-p", 0x2b000),
];
const ANDROID_PROPERTIES: &[Seg] = &[seg(0x20000, "r--s", 0)];

/// The address-space layout of the shell. Every address is a fixed function of the pid, so two
/// reads agree and a replay reproduces it; the binary and the stack sit where `stat` says they do.
fn shell_mappings(table: &Table, p: &Proc) -> Vec<Mapping> {
    let mut out = Vec::new();
    let top = stack_top(table.android, p.pid);
    if table.android {
        // 32-bit ARM, PIE, from the 3.4 kernel the persona reports: no vdso, the vectors page
        // instead. The `stat` image address is not a PIE address, which `stat` already was.
        let sh = place(&mut out, 0xb6d8_8000, &p.exe, 1_161, ANDROID_SH);
        place(
            &mut out,
            sh.max(0xb6e0_0000),
            "[heap]",
            0,
            &[seg(0x21000, "rw-p", 0)],
        );
        let at = place(
            &mut out,
            0xb6e4_0000,
            "/system/lib/libc.so",
            1_184,
            ANDROID_LIBC,
        );
        let at = place(&mut out, at, "/system/bin/linker", 1_149, ANDROID_LINKER);
        place(
            &mut out,
            at,
            "/dev/__properties__",
            1_087,
            ANDROID_PROPERTIES,
        );
        place(
            &mut out,
            top.saturating_sub(0x2_0000),
            "[stack]",
            0,
            &[seg(0x2_1000, "rw-p", 0)],
        );
        place(
            &mut out,
            0xffff_0000,
            "[vectors]",
            0,
            &[seg(0x1000, "r-xp", 0)],
        );
        return out;
    }
    let image = image_base(false, p.pid);
    place(&mut out, image, &p.exe, 1_310_791, UBUNTU_BASH);
    place(
        &mut out,
        image.saturating_add(0x20_0000),
        "[heap]",
        0,
        &[seg(0x22000, "rw-p", 0)],
    );
    let lib = "/usr/lib/x86_64-linux-gnu";
    let at = place(
        &mut out,
        0x7f3c_9a40_0000,
        "/usr/lib/locale/locale-archive",
        1_054_872,
        UBUNTU_LOCALE,
    );
    let at = place(&mut out, at, "", 0, &[seg(0x3000, "rw-p", 0)]);
    let at = place(
        &mut out,
        at,
        &format!("{lib}/libtinfo.so.6.3"),
        1_311_127,
        UBUNTU_TINFO,
    );
    let at = place(
        &mut out,
        at,
        &format!("{lib}/libc.so.6"),
        1_311_102,
        UBUNTU_LIBC,
    );
    let at = place(&mut out, at, "", 0, &[seg(0x2000, "rw-p", 0)]);
    place(
        &mut out,
        at,
        &format!("{lib}/ld-linux-x86-64.so.2"),
        1_311_098,
        UBUNTU_LD,
    );
    let stack_end = place(
        &mut out,
        top.saturating_sub(0x2_0000),
        "[stack]",
        0,
        &[seg(0x2_1000, "rw-p", 0)],
    );
    let vvar = stack_end.saturating_add(0x8000);
    let vdso = place(&mut out, vvar, "[vvar]", 0, &[seg(0x4000, "r--p", 0)]);
    place(&mut out, vdso, "[vdso]", 0, &[seg(0x2000, "r-xp", 0)]);
    place(
        &mut out,
        0xffff_ffff_ff60_0000,
        "[vsyscall]",
        0,
        &[seg(0x1000, "--xp", 0)],
    );
    out
}

/// The `major:minor` of the mount the path `file` sits on, from the same mount table
/// `/proc/self/mountinfo` prints; `(0, 0)` for a name that is no path or no mount holds.
fn device_of(file: &str, mountinfo: &[u8]) -> (u32, u32) {
    let text = String::from_utf8_lossy(mountinfo);
    let mut best: Option<(usize, (u32, u32))> = None;
    for line in text.lines().take(64) {
        let mut fields = line.split_whitespace();
        let (Some(dev), Some(point)) = (fields.nth(2), fields.nth(1)) else {
            continue;
        };
        let under = point == "/"
            || file
                .strip_prefix(point)
                .is_some_and(|rest| rest.starts_with('/'));
        let parsed = dev
            .split_once(':')
            .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)));
        if let (true, Some(parsed)) = (under, parsed)
            && best.is_none_or(|(len, _)| point.len() > len)
        {
            best = Some((point.len(), parsed));
        }
    }
    best.map_or((0, 0), |(_, dev)| dev)
}

/// `/proc/<pid>/maps` in the kernel's layout: `start-end perms offset dev inode`, then the name
/// from the column after the 72nd (the 48th on 32-bit), lowercase hex, and a trailing space after
/// an anonymous mapping's inode.
fn render_maps(table: &Table, p: &Proc, mountinfo: &[u8]) -> String {
    let width = if table.android { 48 } else { 72 };
    let mut out = String::new();
    for m in shell_mappings(table, p) {
        let (major, minor) = if m.name.starts_with('/') {
            device_of(&m.name, mountinfo)
        } else {
            (0, 0)
        };
        let mut line = format!(
            "{:08x}-{:08x} {} {:08x} {:02x}:{:02x} {} ",
            m.start, m.end, m.perms, m.off, major, minor, m.inode
        );
        if !m.name.is_empty() {
            while line.len() < width {
                line.push(' ');
            }
            line.push(' ');
            line.push_str(&m.name);
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
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

/// The load address `stat` reports for a process's image, a fixed function of its pid.
fn image_base(android: bool, pid: u32) -> u64 {
    let code: u64 = if android {
        0x0001_0000
    } else {
        0x5580_0000_0000
    };
    code.saturating_add(u64::from(pid).saturating_mul(0x10_0000))
}

/// The address `stat` reports for the start of a process's stack, which `maps` keeps inside its
/// `[stack]` range.
fn stack_top(android: bool, pid: u32) -> u64 {
    let stack: u64 = if android {
        0xbe80_0000
    } else {
        0x7ffd_0000_0000
    };
    stack.saturating_add(u64::from(pid).saturating_mul(0x1000))
}

/// The 52 fields of `/proc/<pid>/stat`. Counters that nothing else shows are fixed figures that
/// scale with the row, not measurements.
fn stat_line(table: &Table, p: &Proc) -> String {
    let pages = p.rss_kib.div_euclid(4);
    let tty_nr: i64 = if p.tty == "?" { 0 } else { 34_816 };
    let tpgid: i64 = if p.attached { i64::from(p.pid) } else { -1 };
    let image = image_base(table.android, p.pid);
    let top = stack_top(table.android, p.pid);
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
        p.stat_priority(),
        p.nice.to_string(),
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
        'I' => "I (idle)",
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
    lines.push(format!("Uid:\t{0}\t{0}\t{0}\t{0}", p.uid));
    // Each service account's primary group is its own; root's is root.
    let gid = match p.uid {
        0 => 0,
        101 => 102,
        102 => 103,
        103 => 105,
        104 => 106,
        106 => 108,
        other => other,
    };
    lines.push(format!("Gid:\t{gid}\t{gid}\t{gid}\t{gid}"));
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
            Col::Uid => p.uid.to_string(),
            Col::User | Col::UidName => p.user_column(),
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
    /// `-u`, `-U`, `-G`: only processes owned by these names or ids.
    users: Option<Vec<String>>,
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
        users: None,
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
                        plan.users = Some(list.split(',').map(str::to_string).collect());
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
        let tty = self.session_tty();
        Proc {
            pid,
            ppid: self.state().pid,
            comm: exe_name.to_string(),
            argv,
            state: 'R',
            // In the terminal's foreground group only when there is a terminal (recorded: an SSH
            // exec's `ps` shows `R`, an interactive one `R+`).
            mark: if tty == "?" { "" } else { "+" },
            tty,
            started: Started::Now,
            vsz_kib: 12_648,
            rss_kib: 3_352,
            cpu_secs: 0,
            wchan: "-",
            exe,
            cwd: self.cwd().to_string(),
            attached: true,
            user: "root",
            uid: 0,
            prio: "20",
            nice: 0,
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
        if let Some(users) = &plan.users {
            rows.retain(|p| {
                users
                    .iter()
                    .any(|u| u == p.user || u.parse::<u32>().is_ok_and(|id| id == p.uid))
            });
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
            "top - {} up {},  {},  load average: {}\n",
            expand("%H:%M:%S", &table.now),
            uptime_short(secs),
            self.users_text(),
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
        // procps sorts by %CPU: `top` itself, running, first (recorded on Ubuntu 22.04, where it
        // led the list at 6.7), then the rest in pid order.
        rows.sort_by_key(|p| (p.state != 'R', p.pid));
        for p in &rows {
            let shared = p.rss_kib.saturating_mul(3).div_euclid(5);
            let cpu = if p.state == 'R' { "6.2" } else { "0.0" };
            out.push_str(&format!(
                "{:>7} {:<9} {:>2} {:>3} {:>7} {:>6} {:>6} {} {:>5} {:>5} {:>9} {}\n",
                p.pid,
                p.user_column(),
                p.top_priority(),
                p.nice,
                p.vsz_kib,
                p.rss_kib,
                shared,
                p.state,
                cpu,
                tenths(p.rss_kib.saturating_mul(100), MEM_TOTAL_KIB),
                format!(
                    "{}:{:02}.00",
                    p.cpu_secs.div_euclid(60),
                    p.cpu_secs.rem_euclid(60)
                ),
                top_command(&p.comm)
            ));
        }
        clip(out)
    }

    /// `N users` as `uptime`, `w` and `top` print it: an SSH exec request logs no user in (no
    /// utmp entry; recorded `0 users` on Ubuntu 22.04), an interactive login logs in one.
    pub(super) fn users_text(&self) -> &'static str {
        match self.context {
            ShellContext::ExecC => "0 users",
            ShellContext::LoginInteractive | ShellContext::AndroidMksh => "1 user",
        }
    }
}

/// The `COMMAND` cell of a non-terminal `top`: its 80 columns leave the last column eight, so a
/// longer name is cut to seven and a `+` (recorded: `systemd+`, `dbus-da+`, `rsyslogd`).
fn top_command(comm: &str) -> String {
    if comm.chars().count() > 8 {
        format!("{}+", comm.chars().take(7).collect::<String>())
    } else {
        comm.to_string()
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
