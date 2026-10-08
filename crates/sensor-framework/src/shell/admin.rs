//! `systemctl` (systemd 249), `crontab` (Debian cron 3.0pl1) and `who`/`w` (coreutils 8.32,
//! procps 3.3.17): the administration commands a survey or a persistence step runs.
//!
//! The units are one model with the rest of the box: a service is running exactly when its main
//! process is a row of the modeled process table, and the main PID, start time, memory and command
//! line `systemctl status` prints are that row's. Whether a unit is enabled is the symlink in
//! `/etc/systemd/system/*.wants` the filesystem holds, so `enable` and `disable` change what
//! `is-enabled` and `ls` read. A unit file the session writes (the `kworker.service` a dropper
//! installs) is loaded from where it was written; enabling it links it as systemd would, and
//! starting it runs nothing: it stays `inactive (dead)` [unverified as an outcome: nothing is ever
//! executed]. `crontab` reads and writes `/var/spool/cron/crontabs/<user>` with the header Debian's
//! cron writes, so `crontab -l`, `cat` and `ls` agree.
//!
//! Recorded on the 2026-10-07 Ubuntu 22.04 reference: the `list-units` layout and legend, the
//! `status` layout, the not-found and not-loaded errors and their statuses (5, 4, 3), `is-active`
//! and `is-enabled` and their status rules, `Created symlink`/`Removed` on standard error,
//! `--version`, the `inactive (dead)` status of an installed but never-started unit; `crontab`'s
//! usage, `no crontab for root`, the missing-newline and `bad minute` errors and the installed
//! file's header; `who` and `w` over SSH exec (no login) and a pty. The service set, descriptions
//! the reference did not have, journal lines, task limits and non-service units are composed for
//! a stock 22.04 cloud server [unverified].
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use chrono::{DateTime, Utc};

use super::procs::ServiceProc;
use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellContext, ShellFlavor};
use crate::etc;
use crate::fakefs::READ_CAP;

pub(super) fn register(r: &mut Registry) {
    r.register_if(
        "systemctl",
        ubuntu,
        HandlerId::Systemctl,
        FakeShell::cmd_systemctl,
    );
    r.register_if(
        "crontab",
        ubuntu,
        HandlerId::Crontab,
        FakeShell::cmd_crontab,
    );
    r.register_if("who", ubuntu, HandlerId::Who, FakeShell::cmd_who);
    r.register_if("w", ubuntu, HandlerId::W, FakeShell::cmd_w);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

const SYSTEM_DIR: &str = "/etc/systemd/system";
const USER_DIR: &str = "/root/.config/systemd/user";
const LIB_DIR: &str = "/lib/systemd/system";
/// systemd's `DefaultTasksMax` (15% of the kernel's thread limit) on the persona's 4 GiB box
/// [unverified].
const TASKS_LIMIT: u32 = 4_557;

/// What runs a stock service.
#[derive(Clone, Copy)]
enum Main {
    /// The process table's child of init by this kernel name, on this terminal when given.
    Process(&'static str, Option<&'static str>),
    /// A oneshot that ran at boot and exited.
    Exited,
}

/// A service the stock image ships.
struct Stock {
    name: &'static str,
    description: &'static str,
    main: Main,
    /// The unit file, when it is a template's (`getty@.service`).
    file: Option<&'static str>,
    /// `static` or `enabled-runtime`; `None` reads the `.wants` links.
    fixed_state: Option<&'static str>,
    preset_enabled: bool,
    docs: &'static [&'static str],
    /// Only on the SSH persona: the telnet one runs telnetd instead.
    ssh_only: bool,
}

const fn running(
    name: &'static str,
    description: &'static str,
    comm: &'static str,
    docs: &'static [&'static str],
) -> Stock {
    Stock {
        name,
        description,
        main: Main::Process(comm, None),
        file: None,
        fixed_state: None,
        preset_enabled: true,
        docs,
        ssh_only: false,
    }
}

const fn exited(
    name: &'static str,
    description: &'static str,
    fixed: Option<&'static str>,
) -> Stock {
    Stock {
        name,
        description,
        main: Main::Exited,
        file: None,
        fixed_state: fixed,
        preset_enabled: true,
        docs: &[],
        ssh_only: false,
    }
}

const STATIC: Option<&str> = Some("static");

const SERVICES: &[Stock] = &[
    exited("apparmor.service", "Load AppArmor profiles", None),
    exited(
        "blk-availability.service",
        "Availability of block devices",
        None,
    ),
    exited("console-setup.service", "Set console font and keymap", None),
    running(
        "cron.service",
        "Regular background program processing daemon",
        "cron",
        &["man:cron(8)"],
    ),
    Stock {
        fixed_state: STATIC,
        ..running(
            "dbus.service",
            "D-Bus System Message Bus",
            "dbus-daemon",
            &["man:dbus-daemon(1)"],
        )
    },
    Stock {
        main: Main::Process("agetty", Some("tty1")),
        file: Some("getty@.service"),
        ..running(
            "getty@tty1.service",
            "Getty on tty1",
            "agetty",
            &[
                "man:agetty(8)",
                "man:systemd-getty-generator(8)",
                "http://0pointer.de/blog/projects/serial-console.html",
            ],
        )
    },
    exited(
        "keyboard-setup.service",
        "Set the console keyboard layout",
        None,
    ),
    exited(
        "kmod-static-nodes.service",
        "Create List of Static Device Nodes",
        STATIC,
    ),
    exited(
        "lvm2-monitor.service",
        "Monitoring of LVM2 mirrors, snapshots etc. using dmeventd or progress polling",
        None,
    ),
    running("ModemManager.service", "Modem Manager", "ModemManager", &[]),
    running(
        "multipathd.service",
        "Device-Mapper Multipath Device Controller",
        "multipathd",
        &["man:multipathd(8)"],
    ),
    running(
        "networkd-dispatcher.service",
        "Dispatcher daemon for systemd-networkd",
        "networkd-dispat",
        &[],
    ),
    Stock {
        fixed_state: STATIC,
        ..running(
            "polkit.service",
            "Authorization Manager",
            "polkitd",
            &["man:polkit(8)"],
        )
    },
    running(
        "rsyslog.service",
        "System Logging Service",
        "rsyslogd",
        &[
            "man:rsyslogd(8)",
            "man:rsyslog.conf(5)",
            "https://www.rsyslog.com/doc/",
        ],
    ),
    Stock {
        main: Main::Process("agetty", Some("ttyS0")),
        file: Some("serial-getty@.service"),
        ..running(
            "serial-getty@ttyS0.service",
            "Serial Getty on ttyS0",
            "agetty",
            &[
                "man:agetty(8)",
                "man:systemd-getty-generator(8)",
                "http://0pointer.de/blog/projects/serial-console.html",
            ],
        )
    },
    exited("setvtrgb.service", "Set console scheme", None),
    exited(
        "snapd.apparmor.service",
        "Load AppArmor profiles managed internally by snapd",
        None,
    ),
    exited(
        "snapd.seeded.service",
        "Wait until snapd is fully seeded",
        None,
    ),
    running("snapd.service", "Snap Daemon", "snapd", &[]),
    Stock {
        ssh_only: true,
        ..running(
            "ssh.service",
            "OpenBSD Secure Shell server",
            "sshd",
            &["man:sshd(8)", "man:sshd_config(5)"],
        )
    },
    exited(
        "systemd-binfmt.service",
        "Set Up Additional Binary Formats",
        STATIC,
    ),
    exited(
        "systemd-fsck-root.service",
        "File System Check on Root Device",
        STATIC,
    ),
    exited(
        "systemd-journal-flush.service",
        "Flush Journal to Persistent Storage",
        STATIC,
    ),
    Stock {
        fixed_state: STATIC,
        ..running(
            "systemd-journald.service",
            "Journal Service",
            "systemd-journal",
            &["man:systemd-journald.service(8)", "man:journald.conf(5)"],
        )
    },
    Stock {
        fixed_state: STATIC,
        ..running(
            "systemd-logind.service",
            "User Login Management",
            "systemd-logind",
            &[
                "man:sd-login(3)",
                "man:systemd-logind.service(8)",
                "man:logind.conf(5)",
                "man:org.freedesktop.login1(5)",
            ],
        )
    },
    exited(
        "systemd-modules-load.service",
        "Load Kernel Modules",
        STATIC,
    ),
    running(
        "systemd-networkd.service",
        "Network Configuration",
        "systemd-network",
        &["man:systemd-networkd.service(8)"],
    ),
    exited(
        "systemd-random-seed.service",
        "Load/Save Random Seed",
        STATIC,
    ),
    exited(
        "systemd-remount-fs.service",
        "Remount Root and Kernel File Systems",
        Some("enabled-runtime"),
    ),
    running(
        "systemd-resolved.service",
        "Network Name Resolution",
        "systemd-resolve",
        &[
            "man:systemd-resolved.service(8)",
            "man:org.freedesktop.resolve1(5)",
        ],
    ),
    exited("systemd-sysctl.service", "Apply Kernel Variables", STATIC),
    exited("systemd-sysusers.service", "Create System Users", STATIC),
    running(
        "systemd-timesyncd.service",
        "Network Time Synchronization",
        "systemd-timesyn",
        &["man:systemd-timesyncd.service(8)"],
    ),
    exited(
        "systemd-tmpfiles-setup-dev.service",
        "Create Static Device Nodes in /dev",
        STATIC,
    ),
    exited(
        "systemd-tmpfiles-setup.service",
        "Create Volatile Files and Directories",
        STATIC,
    ),
    exited(
        "systemd-udev-trigger.service",
        "Coldplug All udev Devices",
        STATIC,
    ),
    Stock {
        fixed_state: STATIC,
        ..running(
            "systemd-udevd.service",
            "Rule-based Manager for Device Events and Files",
            "systemd-udevd",
            &["man:systemd-udevd.service(8)", "man:udev(7)"],
        )
    },
    exited(
        "systemd-update-utmp.service",
        "Record System Boot/Shutdown in UTMP",
        STATIC,
    ),
    exited(
        "systemd-user-sessions.service",
        "Permit User Sessions",
        STATIC,
    ),
    running(
        "udisks2.service",
        "Disk Manager",
        "udisksd",
        &["man:udisks(8)"],
    ),
    running(
        "unattended-upgrades.service",
        "Unattended Upgrades Shutdown",
        "unattended-upgr",
        &["man:unattended-upgrade(8)"],
    ),
    Stock {
        file: Some("user-runtime-dir@.service"),
        ..exited(
            "user-runtime-dir@0.service",
            "User Runtime Directory /run/user/0",
            STATIC,
        )
    },
    Stock {
        file: Some("user@.service"),
        fixed_state: STATIC,
        ..running(
            "user@0.service",
            "User Manager for UID 0",
            "systemd",
            &["man:user@.service(5)"],
        )
    },
];

/// The loaded units that are not services, as a bare `systemctl` lists them: `(name, sub,
/// description)`, all loaded and active. `session-N.scope` is added per session.
const OTHER_UNITS: &[(&str, &str, &str)] = &[
    ("-.mount", "mounted", "Root Mount"),
    ("boot-efi.mount", "mounted", "/boot/efi"),
    ("dev-hugepages.mount", "mounted", "Huge Pages File System"),
    (
        "dev-mqueue.mount",
        "mounted",
        "POSIX Message Queue File System",
    ),
    ("run-user-0.mount", "mounted", "/run/user/0"),
    (
        "sys-fs-fuse-connections.mount",
        "mounted",
        "FUSE Control File System",
    ),
    (
        "sys-kernel-config.mount",
        "mounted",
        "Kernel Configuration File System",
    ),
    (
        "sys-kernel-debug.mount",
        "mounted",
        "Kernel Debug File System",
    ),
    (
        "sys-kernel-tracing.mount",
        "mounted",
        "Kernel Trace File System",
    ),
    (
        "systemd-ask-password-console.path",
        "waiting",
        "Dispatch Password Requests to Console Directory Watch",
    ),
    (
        "systemd-ask-password-wall.path",
        "waiting",
        "Forward Password Requests to Wall Directory Watch",
    ),
    ("init.scope", "running", "System and Service Manager"),
    ("-.slice", "active", "Root Slice"),
    ("system-getty.slice", "active", "Slice /system/getty"),
    ("system-modprobe.slice", "active", "Slice /system/modprobe"),
    (
        "system-serial\\x2dgetty.slice",
        "active",
        "Slice /system/serial-getty",
    ),
    ("system.slice", "active", "System Slice"),
    ("user-0.slice", "active", "User Slice of UID 0"),
    ("user.slice", "active", "User and Session Slice"),
    ("dbus.socket", "running", "D-Bus System Message Bus Socket"),
    (
        "dm-event.socket",
        "listening",
        "Device-mapper event daemon FIFOs",
    ),
    (
        "lvm2-lvmpolld.socket",
        "listening",
        "LVM2 poll daemon socket",
    ),
    ("multipathd.socket", "running", "multipathd control socket"),
    (
        "snapd.socket",
        "running",
        "Socket activation for snappy daemon",
    ),
    ("syslog.socket", "running", "Syslog Socket"),
    (
        "systemd-initctl.socket",
        "listening",
        "initctl Compatibility Named Pipe",
    ),
    (
        "systemd-journald-audit.socket",
        "running",
        "Journal Audit Socket",
    ),
    (
        "systemd-journald-dev-log.socket",
        "running",
        "Journal Socket (/dev/log)",
    ),
    ("systemd-journald.socket", "running", "Journal Socket"),
    (
        "systemd-networkd.socket",
        "running",
        "Network Service Netlink Socket",
    ),
    (
        "systemd-udevd-control.socket",
        "running",
        "udev Control Socket",
    ),
    (
        "systemd-udevd-kernel.socket",
        "running",
        "udev Kernel Socket",
    ),
    ("uuidd.socket", "listening", "UUID daemon activation socket"),
    ("basic.target", "active", "Basic System"),
    ("cryptsetup.target", "active", "Local Encrypted Volumes"),
    ("getty.target", "active", "Login Prompts"),
    ("graphical.target", "active", "Graphical Interface"),
    (
        "local-fs-pre.target",
        "active",
        "Preparation for Local File Systems",
    ),
    ("local-fs.target", "active", "Local File Systems"),
    ("multi-user.target", "active", "Multi-User System"),
    ("network-online.target", "active", "Network is Online"),
    ("network-pre.target", "active", "Preparation for Network"),
    ("network.target", "active", "Network"),
    (
        "nss-lookup.target",
        "active",
        "Host and Network Name Lookups",
    ),
    ("paths.target", "active", "Path Units"),
    ("remote-fs.target", "active", "Remote File Systems"),
    ("slices.target", "active", "Slice Units"),
    ("sockets.target", "active", "Socket Units"),
    ("swap.target", "active", "Swaps"),
    ("sysinit.target", "active", "System Initialization"),
    ("time-set.target", "active", "System Time Set"),
    ("timers.target", "active", "Timer Units"),
    (
        "veritysetup.target",
        "active",
        "Local Verity Protected Volumes",
    ),
    (
        "apt-daily-upgrade.timer",
        "waiting",
        "Daily apt upgrade and clean activities",
    ),
    (
        "apt-daily.timer",
        "waiting",
        "Daily apt download activities",
    ),
    (
        "dpkg-db-backup.timer",
        "waiting",
        "Daily dpkg database backup timer",
    ),
    (
        "e2scrub_all.timer",
        "waiting",
        "Periodic ext4 Online Metadata Check for All Filesystems",
    ),
    (
        "fstrim.timer",
        "waiting",
        "Discard unused blocks once a week",
    ),
    ("logrotate.timer", "waiting", "Daily rotation of log files"),
    ("man-db.timer", "waiting", "Daily man-db regeneration"),
    ("motd-news.timer", "waiting", "Message of the Day"),
    (
        "systemd-tmpfiles-clean.timer",
        "waiting",
        "Daily Cleanup of Temporary Directories",
    ),
];

/// One row of a unit listing.
struct Row {
    name: String,
    active: &'static str,
    sub: &'static str,
    description: String,
}

/// A unit as `status` and `is-*` see it.
enum Unit {
    Stock(&'static Stock),
    /// A unit file the session wrote: its path, its description, and its `WantedBy=` targets.
    Written {
        name: String,
        path: String,
        description: Option<String>,
        wanted_by: Vec<String>,
    },
}

/// `name` with `.service` added when it has no unit suffix, as systemctl does.
fn unit_name(name: &str) -> String {
    let suffixes = [
        ".service",
        ".socket",
        ".target",
        ".timer",
        ".mount",
        ".path",
        ".slice",
        ".scope",
        ".device",
        ".swap",
        ".automount",
    ];
    if suffixes.iter().any(|s| name.ends_with(s)) {
        name.to_string()
    } else {
        format!("{name}.service")
    }
}

fn suffix(name: &str) -> &str {
    name.rsplit_once('.').map_or("", |(_, s)| s)
}

/// systemd's `format_timestamp_relative`.
fn ago(now: DateTime<Utc>, then: DateTime<Utc>) -> String {
    let us = now
        .signed_duration_since(then)
        .num_microseconds()
        .unwrap_or(0)
        .max(0);
    let us = u64::try_from(us).unwrap_or(0);
    const SEC: u64 = 1_000_000;
    const MIN: u64 = 60 * SEC;
    const HOUR: u64 = 60 * MIN;
    const DAY: u64 = 24 * HOUR;
    const WEEK: u64 = 7 * DAY;
    const MONTH: u64 = 2_629_800 * SEC;
    const YEAR: u64 = 31_557_600 * SEC;
    if us >= YEAR {
        format!("{} years {} months ago", us / YEAR, (us % YEAR) / MONTH)
    } else if us >= MONTH {
        format!("{} months {} days ago", us / MONTH, (us % MONTH) / DAY)
    } else if us >= WEEK {
        format!("{} weeks {} days ago", us / WEEK, (us % WEEK) / DAY)
    } else if us >= 2 * DAY {
        format!("{} days ago", us / DAY)
    } else if us >= 25 * HOUR {
        format!("1 day {}h ago", us.saturating_sub(DAY) / HOUR)
    } else if us >= 6 * HOUR {
        format!("{}h ago", us / HOUR)
    } else if us >= HOUR {
        format!("{}h {}min ago", us / HOUR, (us % HOUR) / MIN)
    } else if us >= 5 * MIN {
        format!("{}min ago", us / MIN)
    } else if us >= MIN {
        format!("{}min {}s ago", us / MIN, (us % MIN) / SEC)
    } else if us >= SEC {
        format!("{}s ago", us / SEC)
    } else if us >= 1_000 {
        format!("{}ms ago", us / 1_000)
    } else {
        "now".to_string()
    }
}

fn since(t: DateTime<Utc>) -> String {
    t.format("%a %Y-%m-%d %H:%M:%S UTC").to_string()
}

/// systemd's `format_bytes`: one decimal in the largest binary unit that fits.
fn bytes_text(bytes: u64) -> String {
    for (shift, unit) in [(30u32, "G"), (20, "M"), (10, "K")] {
        let whole = bytes.checked_shr(shift).unwrap_or(0);
        if whole > 0 {
            let rest = bytes.wrapping_sub(whole.checked_shl(shift).unwrap_or(0));
            let tenth = rest.saturating_mul(10).checked_shr(shift).unwrap_or(0);
            return format!("{whole}.{tenth}{unit}");
        }
    }
    format!("{bytes}B")
}

/// systemd's `format_timespan` at millisecond accuracy, for a `CPU:` line.
fn cpu_text(ms: u64) -> String {
    if ms >= 60_000 {
        format!(
            "{}min {}.{:03}s",
            ms / 60_000,
            (ms % 60_000) / 1_000,
            ms % 1_000
        )
    } else if ms >= 1_000 {
        format!("{}.{:03}s", ms / 1_000, ms % 1_000)
    } else {
        format!("{ms}ms")
    }
}

/// One argument as systemd 249 prints a command line: quoted when it holds whitespace or a shell
/// metacharacter, with `"` and `\` escaped.
fn quote_arg(arg: &str) -> String {
    let special = |c: char| c.is_whitespace() || "\"\\`$*?[]'()<>|&;!".contains(c);
    if arg.chars().any(special) {
        let escaped: String = arg
            .chars()
            .flat_map(|c| match c {
                '"' | '\\' | '`' | '$' => vec!['\\', c],
                other => vec![other],
            })
            .collect();
        format!("\"{escaped}\"")
    } else {
        arg.to_string()
    }
}

/// The value of `key=` in the `[Unit]` or `[Install]` section text, every occurrence joined.
fn unit_key(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
        .collect()
}

impl FakeShell {
    /// The stock service `name` on this persona, if it exists here.
    fn stock_unit(&self, name: &str) -> Option<&'static Stock> {
        let telnet = self.ctx.protocol_label == "telnet";
        SERVICES
            .iter()
            .find(|s| s.name == name && !(s.ssh_only && telnet))
    }

    fn unit(&self, name: &str, user: bool) -> Option<Unit> {
        let dirs: &[&str] = if user {
            &[USER_DIR, "/etc/systemd/user"]
        } else {
            &[SYSTEM_DIR]
        };
        for dir in dirs {
            let path = format!("{dir}/{name}");
            if let Ok(bytes) = self.fs.read_all(&path, READ_CAP) {
                let is_link = self
                    .fs
                    .stat(&path, false)
                    .is_some_and(|stat| stat.mode & 0o170_000 == 0o120_000);
                if is_link {
                    continue;
                }
                let text = String::from_utf8_lossy(&bytes).into_owned();
                return Some(Unit::Written {
                    name: name.to_string(),
                    path,
                    description: unit_key(&text, "Description").into_iter().next(),
                    wanted_by: unit_key(&text, "WantedBy")
                        .iter()
                        .flat_map(|v| v.split_whitespace().map(str::to_string).collect::<Vec<_>>())
                        .collect(),
                });
            }
        }
        if user {
            return None;
        }
        self.stock_unit(name).map(Unit::Stock)
    }

    fn stock_process(&self, stock: &Stock) -> Option<ServiceProc> {
        match stock.main {
            Main::Process(comm, tty) => self.service_process(comm, tty),
            Main::Exited => None,
        }
    }

    /// Whether the `.wants` link for `unit` exists under `dir`, for any target.
    fn wanted_link(&self, dir: &str, unit: &str, targets: &[String]) -> bool {
        targets.iter().any(|target| {
            self.fs
                .stat(&format!("{dir}/{target}.wants/{unit}"), false)
                .is_some()
        })
    }

    fn enabled_state(&self, unit: &Unit, user: bool) -> String {
        match unit {
            Unit::Stock(stock) => {
                if let Some(fixed) = stock.fixed_state {
                    return fixed.to_string();
                }
                let targets: Vec<String> = etc::ENABLED_UNITS
                    .iter()
                    .filter(|(_, u)| *u == stock.name)
                    .map(|(t, _)| (*t).to_string())
                    .collect();
                let targets = if targets.is_empty() {
                    vec!["multi-user.target".to_string()]
                } else {
                    targets
                };
                if self.wanted_link(SYSTEM_DIR, stock.name, &targets) {
                    "enabled".to_string()
                } else {
                    "disabled".to_string()
                }
            }
            Unit::Written {
                name, wanted_by, ..
            } => {
                let dir = if user { USER_DIR } else { SYSTEM_DIR };
                if wanted_by.is_empty() {
                    "static".to_string()
                } else if self.wanted_link(dir, name, wanted_by) {
                    "enabled".to_string()
                } else {
                    "disabled".to_string()
                }
            }
        }
    }

    /// The service rows `list-units` shows: the stock services whose process runs or which ran
    /// at boot, and none of the session's own (never started).
    fn service_rows(&self) -> Vec<Row> {
        SERVICES
            .iter()
            .filter(|s| self.stock_unit(s.name).is_some())
            .filter_map(|s| {
                let (active, sub) = match s.main {
                    Main::Process(..) => {
                        self.stock_process(s)?;
                        ("active", "running")
                    }
                    Main::Exited => ("active", "exited"),
                };
                Some(Row {
                    name: s.name.to_string(),
                    active,
                    sub,
                    description: s.description.to_string(),
                })
            })
            .collect()
    }

    fn all_rows(&self) -> Vec<Row> {
        let mut rows = self.service_rows();
        for &(name, sub, description) in OTHER_UNITS {
            rows.push(Row {
                name: name.to_string(),
                active: "active",
                sub,
                description: description.to_string(),
            });
        }
        if self.context != ShellContext::ExecC || self.ctx.protocol_label == "ssh" {
            let n = self.login_session_number();
            rows.push(Row {
                name: format!("session-{n}.scope"),
                active: "active",
                sub: "running",
                description: format!("Session {n} of User root"),
            });
        }
        rows.sort_by(|a, b| {
            (suffix(&a.name), a.name.to_ascii_lowercase())
                .cmp(&(suffix(&b.name), b.name.to_ascii_lowercase()))
        });
        rows
    }

    fn list_units(&self, args: &[&str], user: bool) -> CommandResult {
        let mut types: Vec<String> = Vec::new();
        let mut states: Vec<String> = Vec::new();
        let mut legend = true;
        let mut iter = args.iter();
        while let Some(&arg) = iter.next() {
            let mut take = |prefix: &str, short: &str, into: &mut Vec<String>| -> bool {
                if let Some(value) = arg.strip_prefix(prefix) {
                    into.extend(value.split(',').map(str::to_string));
                    true
                } else if arg == short || arg == prefix.trim_end_matches('=') {
                    if let Some(value) = iter.next() {
                        into.extend(value.split(',').map(str::to_string));
                    }
                    true
                } else {
                    false
                }
            };
            if take("--type=", "-t", &mut types) || take("--state=", "--state", &mut states) {
                continue;
            }
            if arg == "--no-legend" {
                legend = false;
            }
        }
        let rows: Vec<Row> = if user {
            Vec::new()
        } else {
            self.all_rows()
                .into_iter()
                .filter(|row| types.is_empty() || types.iter().any(|t| suffix(&row.name) == t))
                .filter(|row| {
                    states.is_empty()
                        || states
                            .iter()
                            .any(|s| s == "loaded" || s == row.active || s == row.sub)
                })
                .collect()
        };
        let width =
            |header: usize, cells: &mut dyn Iterator<Item = usize>| cells.fold(header, usize::max);
        let uw = width(4, &mut rows.iter().map(|r| r.name.chars().count()));
        let aw = width(6, &mut rows.iter().map(|r| r.active.len()));
        let sw = width(3, &mut rows.iter().map(|r| r.sub.len()));
        // Every column is as wide as its widest cell or its heading: `LOAD` alone is 4.
        let lw = if rows.is_empty() { 4 } else { 6 };
        let mut out = String::new();
        if legend {
            out.push_str(&format!(
                "  {:<uw$} {:<lw$} {:<aw$} {:<sw$} DESCRIPTION\n",
                "UNIT", "LOAD", "ACTIVE", "SUB"
            ));
        }
        for row in &rows {
            out.push_str(&format!(
                "  {:<uw$} {:<lw$} {:<aw$} {:<sw$} {}\n",
                row.name, "loaded", row.active, row.sub, row.description
            ));
        }
        if legend {
            if !rows.is_empty() {
                out.push_str(
                    "\nLOAD   = Reflects whether the unit definition was properly loaded.\n\
                     ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n\
                     SUB    = The low-level unit activation state, values depend on unit type.\n",
                );
            }
            if states.is_empty() {
                out.push_str(&format!(
                    "{} loaded units listed. Pass --all to see loaded but inactive units, too.\n\
                     To show all installed unit files use 'systemctl list-unit-files'.\n",
                    rows.len()
                ));
            } else {
                out.push_str(&format!("{} loaded units listed.\n", rows.len()));
            }
        }
        CommandResult::stdout(out)
    }

    fn list_unit_files(&self, user: bool) -> CommandResult {
        let mut rows: Vec<(String, String, &'static str)> = Vec::new();
        if !user {
            for stock in SERVICES {
                if self.stock_unit(stock.name).is_none() || stock.file.is_some() {
                    continue;
                }
                let state = self.enabled_state(&Unit::Stock(stock), false);
                let preset = if state == "static" {
                    "-"
                } else if stock.preset_enabled {
                    "enabled"
                } else {
                    "disabled"
                };
                rows.push((stock.name.to_string(), state, preset));
            }
        }
        let dir = if user { USER_DIR } else { SYSTEM_DIR };
        for name in self.fs.list_dir(dir).unwrap_or_default() {
            if !name.ends_with(".service") || rows.iter().any(|(n, ..)| *n == name) {
                continue;
            }
            if let Some(unit @ Unit::Written { .. }) = self.unit(&name, user) {
                let state = self.enabled_state(&unit, user);
                rows.push((name, state, "enabled"));
            }
        }
        rows.sort_by_key(|row| row.0.to_ascii_lowercase());
        let nw = rows
            .iter()
            .map(|(n, ..)| n.chars().count())
            .fold("UNIT FILE".len(), usize::max);
        let mut out = format!("{:<nw$} {:<15} VENDOR PRESET\n", "UNIT FILE", "STATE");
        for (name, state, preset) in &rows {
            out.push_str(&format!("{name:<nw$} {state:<15} {preset}\n"));
        }
        out.push_str(&format!("\n{} unit files listed.\n", rows.len()));
        CommandResult::stdout(out)
    }

    fn unit_status(&self, name: &str, user: bool, color: bool) -> (String, u8) {
        let Some(unit) = self.unit(name, user) else {
            return (String::new(), 4);
        };
        let now = self.now();
        let dot = |active: bool| match (active, color) {
            (true, true) => "\u{1b}[0;1;32m\u{25cf}\u{1b}[0m",
            (true, false) => "\u{25cf}",
            (false, _) => "\u{25cb}",
        };
        let paint = |text: &str| {
            if color {
                format!("\u{1b}[0;1;32m{text}\u{1b}[0m")
            } else {
                text.to_string()
            }
        };
        match &unit {
            Unit::Written {
                name,
                path,
                description,
                ..
            } => {
                let state = self.enabled_state(&unit, user);
                let title = match description {
                    Some(d) => format!("{name} - {d}"),
                    None => name.clone(),
                };
                let loaded = if state == "static" {
                    format!("{path}; static")
                } else {
                    format!("{path}; {state}; vendor preset: enabled")
                };
                (
                    format!(
                        "{} {title}\n     Loaded: loaded ({loaded})\n     Active: inactive (dead)\n",
                        dot(false)
                    ),
                    3,
                )
            }
            Unit::Stock(stock) => {
                let state = self.enabled_state(&unit, false);
                let file = format!("{LIB_DIR}/{}", stock.file.unwrap_or(stock.name));
                let loaded = if state == "static" {
                    format!("{file}; static")
                } else {
                    let preset = if stock.preset_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    };
                    format!("{file}; {state}; vendor preset: {preset}")
                };
                let mut out = format!(
                    "{} {} - {}\n     Loaded: loaded ({loaded})\n",
                    dot(true),
                    stock.name,
                    stock.description
                );
                let process = self.stock_process(stock);
                let started = process
                    .as_ref()
                    .map_or_else(|| self.boot_time(), |p| p.started);
                let activity = if process.is_some() {
                    "active (running)"
                } else {
                    "active (exited)"
                };
                out.push_str(&format!(
                    "     Active: {} since {}; {}\n",
                    paint(activity),
                    since(started),
                    ago(now, started)
                ));
                for (index, doc) in stock.docs.iter().enumerate() {
                    let label = if index == 0 {
                        "       Docs: "
                    } else {
                        "             "
                    };
                    out.push_str(&format!("{label}{doc}\n"));
                }
                if let Some(p) = &process {
                    let threads: u32 = if matches!(
                        p.comm.as_str(),
                        "multipathd"
                            | "snapd"
                            | "polkitd"
                            | "rsyslogd"
                            | "udisksd"
                            | "ModemManager"
                            | "systemd-timesyn"
                    ) {
                        4
                    } else {
                        1
                    };
                    let tasks = if stock.name == "user@0.service" {
                        2
                    } else {
                        threads
                    };
                    let cpu_ms = p
                        .cpu_secs
                        .saturating_mul(1_000)
                        .saturating_add(u64::from(p.pid.wrapping_mul(37) % 997));
                    out.push_str(&format!(
                        "   Main PID: {} ({})\n      Tasks: {tasks} (limit: {TASKS_LIMIT})\n     Memory: {}\n        CPU: {}\n",
                        p.pid,
                        p.comm,
                        bytes_text(p.rss_kib.saturating_mul(1_024)),
                        cpu_text(cpu_ms)
                    ));
                    let line: Vec<String> = p.argv.iter().map(|a| quote_arg(a)).collect();
                    if stock.name == "user@0.service" {
                        out.push_str(&format!(
                            "     CGroup: /user.slice/user-0.slice/user@0.service\n\
                             \x20            \u{2514}\u{2500}init.scope\n\
                             \x20              \u{251c}\u{2500}{} {}\n\
                             \x20              \u{2514}\u{2500}{} \"(sd-pam)\"\n",
                            p.pid,
                            line.join(" "),
                            p.pid.saturating_add(1)
                        ));
                    } else {
                        out.push_str(&format!(
                            "     CGroup: /system.slice/{}\n             \u{2514}\u{2500}{} {}\n",
                            stock.name,
                            p.pid,
                            line.join(" ")
                        ));
                    }
                    let stamp = p.started.format("%b %d %H:%M:%S");
                    let host = &self.hostname;
                    out.push_str(&format!(
                        "\n{stamp} {host} systemd[1]: Starting {}...\n",
                        stock.description
                    ));
                    if stock.name == "ssh.service" {
                        out.push_str(&format!(
                            "{stamp} {host} sshd[{0}]: Server listening on 0.0.0.0 port 22.\n\
                             {stamp} {host} sshd[{0}]: Server listening on :: port 22.\n",
                            p.pid
                        ));
                    }
                    out.push_str(&format!(
                        "{stamp} {host} systemd[1]: Started {}.\n",
                        stock.description
                    ));
                }
                (out, 0)
            }
        }
    }

    /// `systemctl [--user] VERB [UNIT...]`.
    pub(super) fn cmd_systemctl(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let user = args.contains(&"--user");
        let now_flag = args.contains(&"--now");
        if args.contains(&"--version") {
            return CommandResult::stdout(SYSTEMD_VERSION);
        }
        let words: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-'))
            .collect();
        let (verb, units) = match words.split_first() {
            Some((verb, units)) => (*verb, units),
            None => ("list-units", &[][..]),
        };
        let units: Vec<String> = units
            .iter()
            .map(|u| unit_name(&crate::sanitize_value(u, 128)))
            .collect();
        let color = self.stdout_is_terminal();
        match verb {
            "list-units" => self.list_units(args, user),
            "list-unit-files" => self.list_unit_files(user),
            "status" => {
                if units.is_empty() {
                    return CommandResult::stdout(self.system_status());
                }
                let mut result = CommandResult::silent(0);
                let mut worst = 0u8;
                for (index, name) in units.iter().enumerate() {
                    let (text, status) = self.unit_status(name, user, color);
                    if status == 4 {
                        result.append(CommandResult::stderr(
                            4,
                            format!("Unit {name} could not be found.\n"),
                        ));
                    } else {
                        let separator = if index > 0 { "\n" } else { "" };
                        result.append(CommandResult::stdout(format!("{separator}{text}")));
                    }
                    worst = worst.max(status);
                }
                result.status = worst;
                result
            }
            "is-active" => {
                let mut out = String::new();
                let mut any = false;
                for name in &units {
                    let active = matches!(self.unit(name, user), Some(Unit::Stock(_)));
                    any |= active;
                    out.push_str(if active { "active\n" } else { "inactive\n" });
                }
                let mut result = CommandResult::stdout(out);
                result.status = if any { 0 } else { 3 };
                result
            }
            "is-enabled" => {
                let mut result = CommandResult::silent(1);
                let mut any = false;
                for name in &units {
                    match self.unit(name, user) {
                        Some(unit) => {
                            let state = self.enabled_state(&unit, user);
                            any |= state != "disabled";
                            result.append(CommandResult::stdout(format!("{state}\n")));
                        }
                        None => result.append(CommandResult::stderr(
                            1,
                            format!(
                                "Failed to get unit file state for {name}: No such file or directory\n"
                            ),
                        )),
                    }
                }
                result.status = if any { 0 } else { 1 };
                result
            }
            "start" | "restart" | "reload" | "try-restart" | "reload-or-restart" | "stop" => {
                for name in &units {
                    if self.unit(name, user).is_none() {
                        let action = match verb {
                            "reload-or-restart" | "try-restart" => "restart",
                            other => other,
                        };
                        let reason = if verb == "stop" {
                            "not loaded"
                        } else {
                            "not found"
                        };
                        return CommandResult::stderr(
                            5,
                            format!("Failed to {action} {name}: Unit {name} {reason}.\n"),
                        );
                    }
                }
                CommandResult::silent(0)
            }
            "enable" | "disable" => {
                self.systemctl_install(verb == "enable", &units, user, now_flag)
            }
            "daemon-reload" | "daemon-reexec" | "reset-failed" | "mask" | "unmask" => {
                CommandResult::silent(0)
            }
            other => CommandResult::stderr(
                1,
                format!(
                    "Unknown command verb {}.\n",
                    crate::sanitize_value(other, 64)
                ),
            ),
        }
    }

    /// `enable`/`disable`: create or remove the `.wants` links the unit's `WantedBy=` names,
    /// reporting each on standard error as systemctl does.
    fn systemctl_install(
        &mut self,
        enable: bool,
        units: &[String],
        user: bool,
        _now: bool,
    ) -> CommandResult {
        let dir = if user { USER_DIR } else { SYSTEM_DIR };
        let mut messages = String::new();
        for name in units {
            let Some(unit) = self.unit(name, user) else {
                return CommandResult::stderr(
                    1,
                    format!(
                        "Failed to {} unit: Unit file {name} does not exist.\n",
                        if enable { "enable" } else { "disable" }
                    ),
                );
            };
            let (targets, file) = match &unit {
                Unit::Stock(stock) => {
                    if stock.fixed_state.is_some() {
                        continue;
                    }
                    let targets: Vec<String> = etc::ENABLED_UNITS
                        .iter()
                        .filter(|(_, u)| *u == stock.name)
                        .map(|(t, _)| (*t).to_string())
                        .collect();
                    (
                        targets,
                        format!("{LIB_DIR}/{}", stock.file.unwrap_or(stock.name)),
                    )
                }
                Unit::Written {
                    wanted_by, path, ..
                } => (wanted_by.clone(), path.clone()),
            };
            if targets.is_empty() && enable {
                messages.push_str(NO_INSTALL_CONFIG);
                continue;
            }
            for target in targets {
                let wants = format!("{dir}/{target}.wants");
                let link = format!("{wants}/{name}");
                let present = self.fs.stat(&link, false).is_some();
                if enable && !present {
                    if !self.fs.is_dir(&wants) {
                        let _ = self.traced_make_dir(&wants);
                    }
                    if self.traced_symlink(&link, &file).is_ok() {
                        messages.push_str(&format!("Created symlink {link} \u{2192} {file}.\n"));
                    }
                } else if !enable && present && self.traced_remove(&link).is_ok() {
                    messages.push_str(&format!("Removed {link}.\n"));
                }
            }
        }
        CommandResult::stderr(0, messages)
    }

    /// `systemctl status` with no unit: the manager's summary.
    fn system_status(&self) -> String {
        let boot = self.boot_time();
        format!(
            "\u{25cf} {}\n    State: running\n     Jobs: 0 queued\n   Failed: 0 units\n    Since: {}; {}\n   CGroup: /\n",
            self.hostname,
            since(boot),
            ago(self.now(), boot)
        )
    }

    // ------------------------------------------------------------------------------- crontab

    /// `crontab [-u USER] { -l | -r | -e | FILE | - }`.
    pub(super) fn cmd_crontab(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let mut user = "root".to_string();
        let mut action: Option<char> = None;
        let mut file: Option<&str> = None;
        let mut iter = args.iter();
        while let Some(&arg) = iter.next() {
            if arg == "-" || !arg.starts_with('-') {
                file = Some(arg);
                continue;
            }
            for flag in arg.chars().skip(1) {
                match flag {
                    'l' | 'r' | 'e' => action = Some(flag),
                    'i' => {}
                    'u' => {
                        if let Some(name) = iter.next() {
                            user = crate::sanitize_value(name, 32);
                        }
                    }
                    other => {
                        return CommandResult::stderr(
                            1,
                            format!("crontab: invalid option -- '{other}'\n{CRONTAB_USAGE}"),
                        );
                    }
                }
            }
        }
        let path = format!("/var/spool/cron/crontabs/{user}");
        let no_crontab = || CommandResult::stderr(1, format!("no crontab for {user}\n"));
        match (action, file) {
            (Some('l'), _) => match self.fs.read_all(&path, READ_CAP) {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let body: String = if text.starts_with("# DO NOT EDIT THIS FILE") {
                        text.split_inclusive('\n').skip(3).collect()
                    } else {
                        text.into_owned()
                    };
                    CommandResult::stdout(body)
                }
                Err(_) => no_crontab(),
            },
            (Some('r'), _) => match self.traced_remove(&path) {
                Ok(true) => CommandResult::silent(0),
                _ => no_crontab(),
            },
            (Some('e'), _) => {
                let mut text = String::new();
                if self.fs.read_all(&path, READ_CAP).is_err() {
                    text.push_str(&format!("no crontab for {user} - using an empty one\n"));
                }
                text.push_str("crontab: \"/usr/bin/sensible-editor\" exited with status 1\n");
                CommandResult::stderr(1, text)
            }
            (_, None) => CommandResult::stderr(
                1,
                format!(
                    "crontab: usage error: file name must be specified for replace\n{CRONTAB_USAGE}"
                ),
            ),
            (_, Some(source)) => self.crontab_install(source, &path),
        }
    }

    fn crontab_install(&mut self, source: &str, path: &str) -> CommandResult {
        let shown = crate::sanitize_value(source, 256);
        let body = if source == "-" {
            let cap = self.read_cap();
            self.stdin.take(cap)
        } else {
            let resolved = self.resolve_logical(source);
            match self.fs.read_all(&resolved, READ_CAP) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return CommandResult::stderr(
                        1,
                        format!("{shown}: No such file or directory\n"),
                    );
                }
            }
        };
        let text = String::from_utf8_lossy(&body).into_owned();
        if !text.is_empty() && !text.ends_with('\n') {
            return CommandResult::stderr(
                1,
                "new crontab file is missing newline before EOF, can't install.\n",
            );
        }
        if let Some((line, field)) = crontab_error(&text) {
            return CommandResult::stderr(
                1,
                format!(
                    "\"{shown}\":{line}: bad {field}\nerrors in crontab file, can't install.\n"
                ),
            );
        }
        let stamp = self.now().format("%a %b %e %H:%M:%S %Y");
        let header = format!(
            "# DO NOT EDIT THIS FILE - edit the master and reinstall.\n\
             # ({shown} installed on {stamp})\n\
             # (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)\n"
        );
        let content = format!("{header}{text}");
        let _ = self.traced_remove(path);
        if self
            .fs
            .write_file_mode(path, content.as_bytes(), 0o600)
            .is_ok()
        {
            self.trace_fs(super::trace::FsEffect::Wrote {
                path: path.to_string(),
                bytes: content.len(),
            });
            self.note_input_sink(path);
            self.fs.set_written_group(path, etc::CRONTAB_GID);
        }
        CommandResult::silent(0)
    }

    // ---------------------------------------------------------------------------- who and w

    /// The session's utmp entry: `(line, login time, host)`. An exec request logs nobody in.
    fn utmp_entry(&self) -> Option<(&'static str, DateTime<Utc>, String)> {
        if self.context == ShellContext::ExecC {
            return None;
        }
        Some(("pts/0", self.session_time(), self.ctx.source_ip.to_string()))
    }

    /// `who [-b] [-H] [-q] [am i]`.
    pub(super) fn cmd_who(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let entry = self.utmp_entry();
        if args.iter().any(|a| matches!(*a, "-b" | "--boot")) {
            return CommandResult::stdout(format!(
                "         system boot  {}\n",
                self.boot_time().format("%Y-%m-%d %H:%M")
            ));
        }
        if args.iter().any(|a| matches!(*a, "-q" | "--count")) {
            let users = u8::from(entry.is_some());
            let names = if entry.is_some() { "root\n" } else { "\n" };
            return CommandResult::stdout(format!("{names}# users={users}\n"));
        }
        let mut out = String::new();
        if args.iter().any(|a| matches!(*a, "-H" | "--heading")) {
            out.push_str("NAME     LINE         TIME             COMMENT\n");
        }
        if let Some((line, at, host)) = entry {
            out.push_str(&format!(
                "{:<8} {:<12} {} ({host})\n",
                "root",
                line,
                at.format("%Y-%m-%d %H:%M")
            ));
        }
        CommandResult::stdout(out)
    }

    /// `w [-h]`: `uptime`'s line, the column heads, and the session's row.
    pub(super) fn cmd_w(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let mut out = String::new();
        if !args.iter().any(|a| matches!(*a, "-h" | "--no-header")) {
            let uptime = self.cmd_uptime(&["uptime"]);
            out.push_str(&String::from_utf8_lossy(uptime.bytes()));
            out.push_str("USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n");
        }
        if let Some((line, at, host)) = self.utmp_entry() {
            let host: String = host.chars().take(16).collect();
            out.push_str(&format!(
                "{:<8} {:<8} {host:<16} {}    0.00s  0.02s  0.00s w\n",
                "root",
                line,
                at.format("%H:%M")
            ));
        }
        CommandResult::stdout(out)
    }
}

const SYSTEMD_VERSION: &str = "systemd 249 (249.11-0ubuntu3.22)
+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 -PWQUALITY -P11KIT -QRENCODE +BZIP2 +LZ4 +XZ +ZLIB +ZSTD -XKBCOMMON +UTMP +SYSVINIT default-hierarchy=unified
";

const NO_INSTALL_CONFIG: &str =
    "The unit files have no installation config (WantedBy=, RequiredBy=, Also=,
Alias= settings in the [Install] section, and DefaultInstance= for template
units). This means they are not meant to be enabled using systemctl.

Possible reasons for having this kind of units are:
\u{2022} A unit may be statically enabled by being symlinked from another unit's
  .wants/ or .requires/ directory.
\u{2022} A unit's purpose may be to act as a helper for some other unit which has
  a requirement dependency on it.
\u{2022} A unit may be started when needed via activation (socket, path, timer,
  D-Bus, udev, scripted systemctl call, ...).
\u{2022} In case of template units, the unit is meant to be enabled with some
  instance name specified.
";

const CRONTAB_USAGE: &str = "crontab: usage error: unrecognized option
usage:\tcrontab [-u user] file
\tcrontab [ -u user ] [ -i ] { -e | -l | -r }
\t\t(default operation is replace, per 1003.2)
\t-e\t(edit user's crontab)
\t-l\t(list user's crontab)
\t-r\t(delete user's crontab)
\t-i\t(prompt before deleting user's crontab)
";

/// The first line of `text` cron would refuse, as `(line index, field)`: Debian cron numbers the
/// lines it reports from 0 (recorded: a bad first line is `"-":0: bad minute`).
fn crontab_error(text: &str) -> Option<(usize, &'static str)> {
    const FIELDS: [&str; 5] = ["minute", "hour", "day-of-month", "month", "day-of-week"];
    const KEYWORDS: [&str; 8] = [
        "@reboot",
        "@yearly",
        "@annually",
        "@monthly",
        "@weekly",
        "@daily",
        "@midnight",
        "@hourly",
    ];
    // Numbers, ranges, steps and lists everywhere; names (`jan`, `mon`) only for the month and
    // the day of the week.
    let field_ok = |field: &str, named: bool| {
        !field.is_empty()
            && field.chars().all(|c| {
                c.is_ascii_digit()
                    || matches!(c, '*' | '/' | ',' | '-')
                    || (named && c.is_ascii_alphabetic())
            })
    };
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=')
            && !name.trim().is_empty()
            && !name.trim().contains(char::is_whitespace)
        {
            continue;
        }
        let mut words = trimmed.split_whitespace();
        let first = words.next().unwrap_or_default();
        if first.starts_with('@') {
            if !KEYWORDS.contains(&first) {
                return Some((index, "minute"));
            }
            if words.next().is_none() {
                return Some((index, "command"));
            }
            continue;
        }
        let mut fields = std::iter::once(first).chain(words.by_ref().take(4));
        for name in FIELDS {
            let named = matches!(name, "month" | "day-of-week");
            match fields.next() {
                Some(field) if field_ok(field, named) => {}
                _ => return Some((index, name)),
            }
        }
        if words.next().is_none() {
            return Some((index, "command"));
        }
    }
    None
}
