//! The process table, its `/proc/<pid>` tree and the seven commands that read it, through
//! `handle_input` the way a session reaches them. The table is modeled data, so these pin what a
//! replay sees: init, the sensor's daemon and the login shell, with `$$` agreeing across `ps`,
//! `/proc` and `kill`, and nothing an attacker would kill present. Layouts and wording are
//! procps-ng 3.3.17, psmisc 23.4, BusyBox 1.30 and Android 6's toolbox as remembered, not
//! captured; the cases that pin a layout say so, and the rest assert relations (one fact, many
//! readers) that hold whatever the layout is.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::fakefs::{FakeFs, GENERATED_MAX, Node};

fn ctx_for(label: &str) -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: label.to_string(),
        session_id: None,
    }
}

/// Friday 2026-10-02 12:34:56 UTC.
fn friday() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 12, 34, 56).unwrap()
}

fn shell() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx_for("ssh")).with_clock(friday)
}

fn telnet() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx_for("telnet")).with_clock(friday)
}

fn exec() -> FakeShell {
    FakeShell::exec(FakeFs::new(), ctx_for("ssh")).with_clock(friday)
}

fn phone() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx_for("adb")).with_clock(friday)
}

fn stream(out: &CommandResult, fd: OutputFd) -> String {
    let bytes: Vec<u8> = out
        .output
        .iter()
        .filter(|segment| segment.fd == fd)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect();
    String::from_utf8(bytes).unwrap()
}

/// `(stdout, stderr, status)` of one line.
fn answer(sh: &mut FakeShell, line: &str) -> (String, String, u8) {
    let out = sh.handle_input(line).0;
    (
        stream(&out, OutputFd::Stdout),
        stream(&out, OutputFd::Stderr),
        out.status,
    )
}

fn out(sh: &mut FakeShell, line: &str) -> String {
    answer(sh, line).0
}

fn pid_of_shell(sh: &mut FakeShell) -> String {
    out(sh, "echo $$").trim().to_string()
}

/// The data rows of a layout that has a header line.
fn rows(listing: &str) -> Vec<&str> {
    listing.lines().skip(1).collect()
}

/// The whitespace-separated fields of the row whose second-or-first field is `pid`.
fn row_of<'a>(listing: &'a str, pid: &str) -> Vec<&'a str> {
    listing
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| fields.iter().take(2).any(|f| *f == pid))
        .unwrap_or_else(|| panic!("no row for pid {pid} in:\n{listing}"))
}

// ------------------------------------------------------------------------------------------ ps

#[test]
fn ps_aux_lists_init_the_daemon_and_the_shell_and_dollar_dollar_is_the_shell_row() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    let listing = out(&mut sh, "ps aux");
    let init = row_of(&listing, "1");
    assert_eq!(init[0], "root");
    assert_eq!(init.last().copied(), Some("/sbin/init"));
    let daemon = rows(&listing)
        .into_iter()
        .find(|line| line.contains("sshd: /usr/sbin/sshd -D [listener]"))
        .expect("the listening daemon");
    assert!(daemon.starts_with("root "), "{daemon}");
    let shell_row = row_of(&listing, &me);
    assert_eq!(shell_row[0], "root");
    assert_eq!(shell_row.last().copied(), Some("-bash"));
    // The shell row's parent is the session's sshd child, whose parent is the listener.
    let full = out(&mut sh, "ps -ef");
    let session = row_of(&full, &me)[2].to_string();
    let child = row_of(&full, &session);
    assert!(child.contains(&"sshd:"), "{child:?}");
    let listener_pid = child[2];
    assert!(
        row_of(&full, listener_pid).contains(&"/usr/sbin/sshd"),
        "{full}"
    );
    assert_eq!(
        row_of(&full, listener_pid)[2],
        "1",
        "the listener is init's"
    );
}

#[test]
fn ps_aux_has_the_aux_column_shape() {
    let mut sh = shell();
    let listing = out(&mut sh, "ps aux");
    assert_eq!(
        listing.lines().next().unwrap(),
        "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
        "[unverified] procps-ng 3.3.17 header"
    );
    for line in rows(&listing) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert!(fields.len() >= 11, "{line}");
        assert!(fields[1].parse::<u32>().is_ok(), "pid: {line}");
        assert!(fields[2].contains('.') && fields[3].contains('.'), "{line}");
        assert!(fields[4].parse::<u64>().is_ok() && fields[5].parse::<u64>().is_ok());
        assert!(fields[6] == "?" || fields[6].starts_with("pts/"), "{line}");
        assert!(fields[7].starts_with(['S', 'R']), "{line}");
        assert!(fields[9].contains(':'), "TIME is M:SS: {line}");
    }
    // The process listing itself, running, last.
    let last = rows(&listing).last().copied().unwrap();
    assert!(last.contains(" R+ ") && last.ends_with("ps aux"), "{last}");
}

#[test]
fn ps_ef_has_the_full_format_column_shape() {
    let mut sh = shell();
    let listing = out(&mut sh, "ps -ef");
    assert_eq!(
        listing.lines().next().unwrap(),
        "UID          PID    PPID  C STIME TTY          TIME CMD",
        "[unverified] procps-ng 3.3.17 header"
    );
    let init = row_of(&listing, "1");
    assert_eq!(init[2], "0", "init's parent is the kernel");
    assert_eq!(init[3], "0", "C");
    assert!(
        init[6].contains(':') && init[6].matches(':').count() == 2,
        "{init:?}"
    );
    // `-f` alone is the same layout limited to this terminal.
    let own = out(&mut sh, "ps -f");
    assert_eq!(
        own.lines().next(),
        listing.lines().next(),
        "same header, fewer rows"
    );
    assert_eq!(own.lines().count(), 3, "the shell and ps itself: {own}");
}

#[test]
fn a_bare_ps_and_ps_w_list_this_terminal_in_their_own_layouts() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    let bare = out(&mut sh, "ps");
    assert_eq!(
        bare.lines().next().unwrap(),
        "    PID TTY          TIME CMD",
        "[unverified] procps-ng 3.3.17 header"
    );
    let lines: Vec<&str> = rows(&bare);
    assert_eq!(lines.len(), 2, "{bare}");
    assert_eq!(
        lines[0].split_whitespace().collect::<Vec<_>>(),
        [me.as_str(), "pts/0", "00:00:00", "bash"]
    );
    assert!(lines[1].ends_with(" ps"), "{bare}");

    let wide = out(&mut sh, "ps w");
    assert_eq!(
        wide.lines().next().unwrap(),
        "    PID TTY      STAT   TIME COMMAND",
        "[unverified] procps-ng 3.3.17 header"
    );
    assert_eq!(
        row_of(&wide, &me),
        [me.as_str(), "pts/0", "Ss", "0:00", "-bash"]
    );
    // `-e` and `-A` list every process in the short layout, `ax` in the BSD one.
    for line in ["ps -e", "ps -A"] {
        let all = out(&mut sh, line);
        assert_eq!(all.lines().next(), bare.lines().next(), "{line}");
        assert_eq!(rows(&all).len(), 6, "{line}: {all}");
    }
    let ax = out(&mut sh, "ps ax");
    assert_eq!(ax.lines().next(), wide.lines().next());
    assert_eq!(rows(&ax).len(), 6, "{ax}");
}

#[test]
fn ps_lists_itself_with_a_new_pid_each_time_and_after_the_shells_own() {
    let mut sh = shell();
    let me: u32 = pid_of_shell(&mut sh).parse().unwrap();
    let first = out(&mut sh, "ps -e");
    let second = out(&mut sh, "ps -e");
    let ps_pid = |listing: &str| -> u32 {
        listing
            .lines()
            .find(|line| line.ends_with(" ps"))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|pid| pid.parse().ok())
            .expect("ps lists itself")
    };
    let (a, b) = (ps_pid(&first), ps_pid(&second));
    assert!(a > me && b > a, "{me} {a} {b}");
    // The pid it took is the one a background job would have had next.
    assert_eq!(
        out(&mut sh, "sleep 1 & echo $!").trim(),
        (b + 1).to_string()
    );
}

#[test]
fn ps_o_takes_a_column_list_with_headers_of_its_own() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    let listing = out(&mut sh, "ps -eo pid,ppid,comm");
    assert_eq!(
        listing.lines().next().unwrap(),
        "    PID    PPID COMMAND",
        "[unverified] procps-ng 3.3.17"
    );
    let shell_row = row_of(&listing, &me);
    assert_eq!(shell_row[2], "bash");
    let renamed = out(&mut sh, "ps -o pid=ID,comm= -p 1");
    assert_eq!(renamed, "     ID\n      1 systemd\n");
    let bare = out(&mut sh, "ps -o pid=,comm= -p 1");
    assert_eq!(
        bare, "      1 systemd\n",
        "every header empty: no header line"
    );
    let (stdout, stderr, status) = answer(&mut sh, "ps -o nonesuch");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert!(
        stderr.starts_with("error: unknown user-defined format specifier \"nonesuch\"\n"),
        "{stderr}"
    );
    let (_, stderr, status) = answer(&mut sh, "ps -Z9");
    assert_eq!(status, 1);
    assert!(
        stderr.starts_with("error: unsupported SysV option\n"),
        "{stderr}"
    );
}

#[test]
fn the_phone_ps_is_the_toolbox_layout_over_its_own_rows() {
    let mut sh = phone();
    let me = pid_of_shell(&mut sh);
    let listing = out(&mut sh, "ps");
    assert!(
        listing
            .lines()
            .next()
            .unwrap()
            .starts_with("USER      PID   PPID  VSIZE"),
        "[unverified] toolbox header: {listing}"
    );
    let names: Vec<&str> = rows(&listing)
        .into_iter()
        .map(|line| line.split_whitespace().last().unwrap())
        .collect();
    assert_eq!(names, ["/init", "/sbin/adbd", "zygote", "sh", "ps"]);
    let own = row_of(&listing, &me);
    assert_eq!(own[0], "root");
    assert_eq!(own[1], me);
    assert_eq!(own[2], "143", "the shell is adbd's child");
    // A pid operand and a name operand filter, the toolbox's way.
    assert_eq!(rows(&out(&mut sh, "ps 598")).len(), 1);
    assert!(out(&mut sh, "ps 598").contains("zygote"));
    assert_eq!(rows(&out(&mut sh, "ps adbd")).len(), 1);
    assert_eq!(rows(&out(&mut sh, "ps nothingnamedthis")).len(), 0);
}

#[test]
fn busybox_ps_and_kill_use_the_busybox_forms() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    let listing = out(&mut sh, "busybox ps");
    assert_eq!(
        listing.lines().next().unwrap(),
        "  PID USER       VSZ STAT COMMAND",
        "[unverified] BusyBox 1.30 header"
    );
    assert_eq!(row_of(&listing, &me).last().copied(), Some("-bash"));
    assert!(
        listing.contains("busybox ps"),
        "it lists itself as it was run"
    );
    let (stdout, stderr, status) = answer(&mut sh, "busybox kill 99999");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert_eq!(stderr, "kill: can't kill pid 99999: No such process\n");
    let (_, stderr, status) = answer(&mut sh, "busybox killall nosuchthing");
    assert_eq!(status, 1);
    assert_eq!(stderr, "killall: nosuchthing: no process killed\n");
    // `pkill` is no applet of the Ubuntu build.
    assert_eq!(
        answer(&mut sh, "busybox pkill x"),
        ("".into(), "pkill: applet not found\n".into(), 127)
    );
}

// -------------------------------------------------------------------------------------- top

#[test]
fn top_batch_prints_one_bounded_snapshot_of_the_table() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    for line in ["top -b -n1", "top -bn1", "top", "top -b -n 50"] {
        let (text, stderr, status) = answer(&mut sh, line);
        assert_eq!((stderr.as_str(), status), ("", 0), "{line}");
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines[0].starts_with("top - 12:34:56 up "),
            "{line}: {}",
            lines[0]
        );
        assert!(lines[0].contains(" load average: "), "{}", lines[0]);
        // Tasks counts the rows below, `top` itself among them and running.
        let table_rows = lines
            .iter()
            .skip_while(|l| !l.trim_start().starts_with("PID"))
            .skip(1)
            .count();
        assert_eq!(table_rows, 6, "{line}: {text}");
        assert!(
            lines[1].starts_with("Tasks:   6 total,   1 running,   5 sleeping"),
            "{}",
            lines[1]
        );
        assert!(lines[3].starts_with("MiB Mem :"), "{}", lines[3]);
        // One snapshot whatever -n asks: the header appears once.
        assert_eq!(text.matches("top - ").count(), 1, "{line}");
        assert!(row_of(&text, &me).contains(&"bash"), "{line}");
        assert_eq!(
            text.lines().last().unwrap().split_whitespace().last(),
            Some("top")
        );
    }
}

#[test]
fn the_phone_top_is_the_toolbox_layout_and_bounded() {
    let mut sh = phone();
    let (text, _, status) = answer(&mut sh, "top -n 1");
    assert_eq!(status, 0);
    assert!(
        text.starts_with("User "),
        "[unverified] toolbox layout: {text}"
    );
    assert!(text.contains("  PID PR CPU% S  #THR     VSS     RSS PCY UID      Name\n"));
    assert_eq!(text.matches("PCY").count(), 1, "one snapshot");
    assert!(text.lines().last().unwrap().ends_with(" top"));
}

// ------------------------------------------------------------------------------------- /proc

#[test]
fn proc_1_is_init_in_cmdline_and_comm() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "cat /proc/1/cmdline"), "/sbin/init\0");
    assert_eq!(out(&mut sh, "cat /proc/1/comm"), "systemd\n");
    assert_eq!(
        out(&mut sh, "readlink /proc/1/exe"),
        "/usr/lib/systemd/systemd\n"
    );
    assert_eq!(out(&mut sh, "readlink /proc/1/cwd"), "/\n");
    // The phone's init is /init.
    let mut phone = phone();
    assert_eq!(out(&mut phone, "cat /proc/1/cmdline"), "/init\0");
    assert_eq!(out(&mut phone, "cat /proc/1/comm"), "init\n");
}

#[test]
fn the_shells_own_pid_node_equals_what_proc_self_gives_a_shell() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    // A redirection is opened by the shell, so `/proc/self/exe` through one is the shell's binary;
    // the node under the shell's pid is the same file.
    let via_self = sh.handle_input("cat < /proc/self/exe").0;
    let via_pid = sh.handle_input(format!("cat /proc/{me}/exe")).0;
    assert!(via_self.bytes().len() > 100_000, "bash is more than a stub");
    // A redirected standard input is read to one allowance (1 MiB), a named file whole: the same
    // image, so the redirect is a prefix of the file.
    assert_eq!(via_self.bytes(), &via_pid.bytes()[..via_self.bytes().len()]);
    let bash = sh.handle_input("cat /usr/bin/bash").0;
    assert_eq!(via_pid.bytes(), bash.bytes());
    assert_eq!(
        out(&mut sh, &format!("readlink /proc/{me}/exe")),
        "/usr/bin/bash\n"
    );
    assert_eq!(
        out(&mut sh, &format!("readlink -f /proc/{me}/exe")),
        out(&mut sh, "readlink -f /usr/bin/bash"),
    );
    // And the argv is the one `$0` shows.
    assert_eq!(out(&mut sh, &format!("cat /proc/{me}/cmdline")), "-bash\0");
    assert_eq!(out(&mut sh, &format!("cat /proc/{me}/comm")), "bash\n");
}

#[test]
fn a_pid_outside_the_table_reads_as_absent() {
    let mut sh = shell();
    for path in [
        "/proc/4/cmdline",
        "/proc/4/exe",
        "/proc/4/status",
        "/proc/4/comm",
        "/proc/99999/stat",
        "/proc/2/cwd",
    ] {
        let (stdout, stderr, status) = answer(&mut sh, &format!("cat {path}"));
        assert_eq!((stdout.as_str(), status), ("", 1), "{path}");
        assert_eq!(
            stderr,
            format!("cat: {path}: No such file or directory\n"),
            "{path}"
        );
    }
    assert_eq!(answer(&mut sh, "ls /proc/4").2, 2);
    assert_eq!(answer(&mut sh, "test -d /proc/4").2, 1);
    assert_eq!(answer(&mut sh, "test -d /proc/1").2, 0);
    // The phone too.
    let mut phone = phone();
    assert_eq!(answer(&mut phone, "cat /proc/4/cmdline").2, 1);
}

#[test]
fn every_row_has_the_six_nodes_and_they_agree_with_ps() {
    let mut sh = shell();
    let table = out(&mut sh, "ps -eo pid,ppid,comm,args");
    for line in rows(&table) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (pid, ppid, comm) = (fields[0], fields[1], fields[2]);
        if fields.last() == Some(&"args") || line.ends_with("ps -eo pid,ppid,comm,args") {
            continue;
        }
        assert_eq!(
            out(&mut sh, &format!("cat /proc/{pid}/comm")),
            format!("{comm}\n")
        );
        let cmdline = out(&mut sh, &format!("cat /proc/{pid}/cmdline"));
        assert_eq!(
            cmdline.trim_end_matches('\0').replace('\0', " "),
            fields[3..].join(" "),
            "pid {pid}"
        );
        // stat: pid (comm) S ppid ...
        let stat = out(&mut sh, &format!("cat /proc/{pid}/stat"));
        let stat_fields: Vec<&str> = stat.split_whitespace().collect();
        assert_eq!(stat_fields.len(), 52, "pid {pid}: {stat}");
        assert_eq!(stat_fields[0], pid);
        assert_eq!(stat_fields[1], format!("({comm})"));
        assert!(matches!(stat_fields[2], "S" | "R"));
        assert_eq!(stat_fields[3], ppid);
        let status = out(&mut sh, &format!("cat /proc/{pid}/status"));
        let field = |name: &str| -> String {
            status
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{name}:")))
                .unwrap_or_else(|| panic!("{name} in {status}"))
                .trim()
                .to_string()
        };
        assert_eq!(field("Name"), comm);
        assert_eq!(field("Pid"), pid);
        assert_eq!(field("Tgid"), pid);
        assert_eq!(field("PPid"), ppid);
        assert_eq!(field("Uid"), "0\t0\t0\t0");
        assert!(field("State").starts_with(stat_fields[2]));
        assert!(!out(&mut sh, &format!("readlink /proc/{pid}/exe")).is_empty());
        assert!(!out(&mut sh, &format!("readlink /proc/{pid}/cwd")).is_empty());
        // The VM figures ps prints are the ones the node carries.
        let ps = out(&mut sh, &format!("ps -o vsz=,rss= -p {pid}"));
        let ps_fields: Vec<&str> = ps.split_whitespace().collect();
        assert_eq!(field("VmSize"), format!("{} kB", ps_fields[0]));
        assert_eq!(field("VmRSS"), format!("{} kB", ps_fields[1]));
    }
}

#[test]
fn the_directory_lists_the_nodes_and_proc_lists_the_pids() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    assert_eq!(
        out(&mut sh, "ls /proc/1"),
        "cmdline  comm  cwd  exe  mountinfo  mounts  stat  status\n"
    );
    let listing = out(&mut sh, "ls /proc");
    let mut found: Vec<&str> = listing.split_whitespace().collect();
    found.sort_unstable();
    let ps = out(&mut sh, "ps -eo pid=");
    let mut want: Vec<&str> = ps.split_whitespace().collect();
    // `ps` itself is no row of the table.
    want.pop();
    want.sort_unstable();
    assert_eq!(found, want, "{listing}");
    assert!(found.contains(&me.as_str()));
    // The kill loop attackers write: every glob match names a process that answers.
    let looped = out(
        &mut sh,
        "for p in /proc/[0-9]*; do echo $(basename $p):$(cat $p/comm); done",
    );
    assert_eq!(looped.lines().count(), want.len(), "{looped}");
    assert!(looped.contains("1:systemd\n") && looped.contains(&format!("{me}:bash\n")));
    let cmdlines = out(&mut sh, "cat /proc/[0-9]*/comm");
    assert_eq!(cmdlines.lines().count(), want.len(), "{cmdlines}");
}

#[test]
fn proc_mounts_of_a_row_is_the_same_table_as_proc_self_mounts() {
    let mut sh = shell();
    let mounts = out(&mut sh, "cat /proc/self/mounts");
    assert!(!mounts.is_empty());
    assert_eq!(out(&mut sh, "cat /proc/1/mounts"), mounts);
    assert_eq!(
        out(&mut sh, "cat /proc/1/mountinfo"),
        out(&mut sh, "cat /proc/self/mountinfo")
    );
}

#[test]
fn the_login_shells_cwd_link_follows_cd() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    assert_eq!(out(&mut sh, &format!("readlink /proc/{me}/cwd")), "/root\n");
    out(&mut sh, "cd /tmp");
    assert_eq!(out(&mut sh, &format!("readlink /proc/{me}/cwd")), "/tmp\n");
    // A subshell's own `cd` is not the login shell's.
    out(&mut sh, "(cd /var; true)");
    assert_eq!(out(&mut sh, &format!("readlink /proc/{me}/cwd")), "/tmp\n");
}

#[test]
fn the_nodes_are_per_persona_and_per_clock() {
    let mut phone = phone();
    assert_eq!(out(&mut phone, "cat /proc/143/comm"), "adbd\n");
    assert_eq!(out(&mut phone, "cat /proc/598/cmdline"), "zygote\0");
    assert_eq!(out(&mut phone, "readlink /system/bin/ps"), "");
    assert_eq!(
        answer(&mut phone, "cat /proc/721/comm").2,
        1,
        "no sshd on the phone"
    );
    let mut ubuntu = shell();
    assert_eq!(
        answer(&mut ubuntu, "cat /proc/143/comm").2,
        1,
        "no adbd on the server"
    );
    assert_eq!(
        out(&mut ubuntu, "cat /proc/641/cmdline"),
        "/usr/sbin/cron\0-f\0-P\0"
    );
}

// ----------------------------------------------------------------------------- start times

fn start_of(sh: &mut FakeShell, pid: &str) -> NaiveDateTime {
    let text = out(sh, &format!("ps -o lstart= -p {pid}"));
    NaiveDateTime::parse_from_str(text.trim(), "%a %b %e %H:%M:%S %Y")
        .unwrap_or_else(|e| panic!("{text:?}: {e}"))
}

#[test]
fn start_times_are_the_session_clocks_and_agree_across_ps_and_proc_stat() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    // The box booted before the session, the way `uptime -s` says.
    let boot_text = out(&mut sh, "uptime -s");
    let boot = NaiveDateTime::parse_from_str(boot_text.trim(), "%Y-%m-%d %H:%M:%S").unwrap();
    // init started within the boot second; the shell with the session.
    let init = start_of(&mut sh, "1");
    assert_eq!((init - boot).num_seconds(), 1);
    assert_eq!(start_of(&mut sh, &me), friday().naive_utc());
    // `STIME` and `START` print a clock time for today's processes, a date for older ones.
    let aux = out(&mut sh, "ps aux");
    assert!(row_of(&aux, &me).contains(&"12:34"));
    assert!(!row_of(&aux, "1").contains(&"12:34"));
    // stat's starttime is ticks after boot, the same two instants.
    let ticks = |sh: &mut FakeShell, pid: &str| -> i64 {
        out(sh, &format!("cat /proc/{pid}/stat"))
            .split_whitespace()
            .nth(21)
            .unwrap()
            .parse()
            .unwrap()
    };
    assert_eq!(ticks(&mut sh, "1"), 100);
    assert_eq!(
        ticks(&mut sh, &me),
        (friday().naive_utc() - boot).num_seconds() * 100
    );
    // `etime` is how long since: nothing for the session, the box's uptime for init.
    assert_eq!(
        out(&mut sh, &format!("ps -o etime= -p {me}")).trim(),
        "00:01"
    );
}

#[test]
fn the_same_clock_makes_the_same_table() {
    let (mut a, mut b) = (shell(), shell());
    assert_eq!(
        out(&mut a, "cat /proc/1/stat"),
        out(&mut b, "cat /proc/1/stat")
    );
    assert_eq!(
        out(&mut a, "cat /proc/2211/status"),
        out(&mut b, "cat /proc/2211/status")
    );
    assert_eq!(out(&mut a, "ps aux"), out(&mut b, "ps aux"));
}

// ----------------------------------------------------------------------------------- pgrep

#[test]
fn pgrep_and_pidof_name_the_modeled_processes() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    assert_eq!(
        answer(&mut sh, "pgrep cron"),
        ("641\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "pgrep -x systemd"),
        ("1\n".into(), "".into(), 0)
    );
    assert_eq!(out(&mut sh, "pgrep bash"), format!("{me}\n"));
    // Two sshd rows: the listener first by pid, the session's child after.
    let both = out(&mut sh, "pgrep sshd");
    let pids: Vec<u32> = both.lines().map(|l| l.parse().unwrap()).collect();
    assert_eq!(pids.len(), 2);
    assert_eq!(pids[0], 721);
    assert!(pids[1] > pids[0]);
    assert_eq!(out(&mut sh, "pgrep -l cron"), "641 cron\n");
    assert_eq!(out(&mut sh, "pgrep -a cron"), "641 /usr/sbin/cron -f -P\n");
    assert_eq!(out(&mut sh, "pgrep -c sshd"), "2\n");
    assert_eq!(out(&mut sh, "pgrep -d, sshd"), format!("721,{}\n", pids[1]));
    assert_eq!(
        out(&mut sh, "pgrep -n sshd"),
        format!("{}\n", pids[1]),
        "newest"
    );
    assert_eq!(out(&mut sh, "pgrep -o sshd"), "721\n", "oldest");
    // Without -f the pattern reads the command name; with it, the whole command line.
    assert_eq!(answer(&mut sh, "pgrep listener").2, 1);
    assert_eq!(out(&mut sh, "pgrep -f listener"), "721\n");
    // pidof prints on one line, newest pid first, as sysvinit does.
    assert_eq!(
        answer(&mut sh, "pidof cron"),
        ("641\n".into(), "".into(), 0)
    );
    assert_eq!(out(&mut sh, "pidof sshd"), format!("{} 721\n", pids[1]));
    assert_eq!(out(&mut sh, "pidof -s sshd"), format!("{}\n", pids[1]));
    assert_eq!(out(&mut sh, "pidof bash cron"), format!("{me} 641\n"));
    assert_eq!(out(&mut sh, "pidof /usr/sbin/cron"), "641\n");
    assert_eq!(out(&mut sh, "echo $(pidof sshd) | wc -w"), "2\n");
}

#[test]
fn pgrep_and_pidof_find_nothing_for_what_is_not_running_and_say_so_by_status() {
    let mut sh = shell();
    for line in [
        "pgrep miner",
        "pgrep -f xmrig",
        "pgrep -x cro",
        "pgrep -u nobody sshd",
        "pidof miner",
        "pidof kinsing",
        "pidof",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 1), "{line}");
    }
    // No criteria at all is a usage error, not a silent miss.
    let (stdout, stderr, status) = answer(&mut sh, "pgrep");
    assert_eq!((stdout.as_str(), status), ("", 2));
    assert_eq!(
        stderr,
        "pgrep: no matching criteria specified\nTry `pgrep --help' for more information.\n"
    );
    assert_eq!(
        answer(&mut sh, "pgrep -c miner"),
        ("0\n".into(), "".into(), 1)
    );
}

#[test]
fn the_pattern_engine_reads_the_regular_expressions_scripts_write() {
    let mut sh = shell();
    // (pattern, whether it matches the name `cron`, which is process 641)
    for (pattern, matches) in [
        ("cron", true),
        ("cr", true),
        ("^cr", true),
        ("^ron", false),
        ("ron$", true),
        ("^cron$", true),
        ("^cro$", false),
        ("miner|cron", true),
        ("miner|bot|xmrig", false),
        ("^(cron|crond)$", true),
        ("^(miner|bot)$", false),
        ("c.on", true),
        ("cr?on", true),
        ("cr+on", true),
        ("cr*on", true),
        ("cx*ron", true),
        ("cx+ron", false),
        ("[a-d]ron", true),
        ("[^c]ron", false),
        ("[xyz]ron", false),
        ("c\\.on", false),
        ("CRON", false),
    ] {
        let plain = answer(&mut sh, &format!("pgrep '{pattern}'")).0 == "641\n";
        assert_eq!(plain, matches, "pgrep '{pattern}'");
    }
    assert_eq!(out(&mut sh, "pgrep -i CRON"), "641\n");
    assert_eq!(out(&mut sh, "pgrep -x cron"), "641\n");
    assert_eq!(
        answer(&mut sh, "pgrep -v -x cron | wc -l").0,
        "4\n",
        "every row but cron"
    );
}

// ------------------------------------------------------------------------------------- kill

#[test]
fn kill_of_a_modeled_pid_is_silent_success_and_changes_nothing() {
    let mut sh = shell();
    let me = pid_of_shell(&mut sh);
    let before = out(&mut sh, "ps -eo pid,comm,args");
    for line in [
        "kill 1".to_string(),
        "kill -9 721".to_string(),
        "kill -KILL 641".to_string(),
        "kill -s TERM 641 721".to_string(),
        "kill -n 15 641".to_string(),
        "kill -0 1".to_string(),
        format!("kill -9 {me}"),
        "kill -9 -- -721".to_string(),
        "kill 0".to_string(),
    ] {
        assert_eq!(answer(&mut sh, &line), ("".into(), "".into(), 0), "{line}");
    }
    // Nothing was signaled: every row is still there and the session still answers.
    let after = out(&mut sh, "ps -eo pid,comm,args");
    let strip = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|l| !l.contains(" ps "))
            .map(str::to_string)
            .collect()
    };
    assert_eq!(strip(&before), strip(&after));
    assert_eq!(out(&mut sh, "echo alive"), "alive\n");
}

#[test]
fn kill_of_a_pid_not_in_the_table_says_no_such_process() {
    let mut sh = shell();
    let (stdout, stderr, status) = answer(&mut sh, "kill 99999");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert_eq!(stderr, "-bash: kill: (99999) - No such process\n");
    // One reply per missing pid, a present pid among them is silent, and the status is the failure.
    let (_, stderr, status) = answer(&mut sh, "kill -9 99998 1 99997");
    assert_eq!(status, 1);
    assert_eq!(
        stderr,
        "-bash: kill: (99998) - No such process\n-bash: kill: (99997) - No such process\n"
    );
    // The same forms through the file and a nested shell.
    assert_eq!(
        answer(&mut sh, "/bin/kill 99999").1,
        "kill: (99999): No such process\n",
        "[unverified] procps kill"
    );
    assert_eq!(
        answer(&mut sh, "/usr/bin/kill 99999").2,
        1,
        "the path form reaches the same table"
    );
    out(&mut sh, "sh");
    let (_, stderr, status) = answer(&mut sh, "kill 99999");
    assert_eq!(status, 1);
    assert!(
        stderr.ends_with("kill: 99999: No such process\n"),
        "[unverified] dash: {stderr}"
    );
    // The phone's shell.
    let mut phone = phone();
    assert_eq!(
        answer(&mut phone, "kill 99999"),
        ("".into(), "sh: kill: 99999: No such process\n".into(), 1),
        "[unverified] mksh"
    );
    assert_eq!(answer(&mut phone, "kill -9 143").2, 0);
}

#[test]
fn kill_accepts_the_pids_the_session_itself_started() {
    let mut sh = shell();
    out(&mut sh, "sleep 100 &");
    assert_eq!(answer(&mut sh, "kill $!"), ("".into(), "".into(), 0));
    // A pid past what the session allocated is not one.
    let past = out(&mut sh, "echo $(( $! + 50 ))");
    assert_eq!(answer(&mut sh, &format!("kill {}", past.trim())).2, 1);
}

#[test]
fn kill_reports_bad_operands_the_way_the_shell_does() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "kill abc"),
        (
            "".into(),
            "-bash: kill: abc: arguments must be process or job IDs\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "kill %1"),
        ("".into(), "-bash: kill: %1: no such job\n".into(), 1)
    );
    assert_eq!(
        answer(&mut sh, "kill -NOSUCH 1"),
        (
            "".into(),
            "-bash: kill: NOSUCH: invalid signal specification\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "kill -9"),
        (
            "".into(),
            "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n".into(),
            2
        )
    );
    assert_eq!(answer(&mut sh, "kill -s 99 1").2, 1);
}

#[test]
fn kill_l_lists_the_signals_and_converts_between_names_and_numbers() {
    let mut sh = shell();
    let list = out(&mut sh, "kill -l");
    assert!(list.starts_with(" 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\t 5) SIGTRAP\n"));
    assert!(list.contains("\n 6) SIGABRT\t 7) SIGBUS\t 8) SIGFPE\t 9) SIGKILL\t10) SIGUSR1\n"));
    assert!(list.contains("15) SIGTERM") && list.contains("31) SIGSYS\t34) SIGRTMIN"));
    assert!(
        list.ends_with("63) SIGRTMAX-1\t64) SIGRTMAX\t\n"),
        "{list:?}"
    );
    assert_eq!(list.matches(") SIG").count(), 62, "1-31 and 34-64");
    assert_eq!(out(&mut sh, "kill -l 9"), "KILL\n");
    assert_eq!(out(&mut sh, "kill -l SIGTERM"), "15\n");
    assert_eq!(out(&mut sh, "kill -l kill"), "9\n");
    assert_eq!(answer(&mut sh, "kill -l 99").2, 1);
    // The phone's shell lists bare names.
    let mut phone = phone();
    let names = out(&mut phone, "kill -l");
    assert!(
        names.starts_with("HUP INT QUIT ILL TRAP ABRT BUS FPE KILL USR1"),
        "{names}"
    );
    assert!(names.lines().all(|l| l.len() <= 72));
}

// ----------------------------------------------------------------------------------- killall

#[test]
fn killall_of_a_missing_name_is_no_process_found_with_status_1() {
    let mut sh = shell();
    for line in ["killall miner", "killall -9 bot", "killall -KILL kinsing"] {
        let name = line.split_whitespace().last().unwrap();
        assert_eq!(
            answer(&mut sh, line),
            ("".into(), format!("{name}: no process found\n"), 1),
            "{line}"
        );
    }
    // Several names: each missing one is reported, and the status is the failure.
    let (_, stderr, status) = answer(&mut sh, "killall -9 miner cron bot");
    assert_eq!(status, 1);
    assert_eq!(stderr, "miner: no process found\nbot: no process found\n");
    // -q keeps the status and drops the complaint.
    assert_eq!(
        answer(&mut sh, "killall -q miner"),
        ("".into(), "".into(), 1)
    );
}

#[test]
fn killall_of_a_present_name_succeeds_silently_and_leaves_the_table() {
    let mut sh = shell();
    let before = out(&mut sh, "pgrep -l .");
    for line in [
        "killall cron",
        "killall -9 sshd",
        "killall -s TERM cron",
        "killall -u root cron",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
    }
    assert_eq!(
        out(&mut sh, "pgrep -l ."),
        before,
        "intent only: nothing was removed"
    );
    let verbose = out(&mut sh, "killall -v -HUP cron");
    assert_eq!(verbose, "Killed cron(641) with signal 1\n");
    assert_eq!(
        out(&mut sh, "killall -l").split_whitespace().next(),
        Some("HUP")
    );
    let (_, usage, status) = answer(&mut sh, "killall");
    assert_eq!(status, 1);
    assert!(
        usage.starts_with("Usage: killall [ -Z CONTEXT ]"),
        "{usage}"
    );
    // The phone ships none of these.
    let mut phone = phone();
    assert_eq!(answer(&mut phone, "killall zygote").2, 127);
}

// ------------------------------------------------------------------------------------ pkill

#[test]
fn pkill_of_no_match_is_status_1_and_silent() {
    let mut sh = shell();
    for line in [
        "pkill miner",
        "pkill -9 miner",
        "pkill -f 'xmrig|kdevtmpfsi'",
        "pkill -9 -f bot",
        "pkill -KILL -x min",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 1), "{line}");
    }
}

#[test]
fn pkill_of_a_match_is_status_0_and_signals_nothing() {
    let mut sh = shell();
    let before = out(&mut sh, "pgrep -l .");
    assert_eq!(answer(&mut sh, "pkill cron"), ("".into(), "".into(), 0));
    assert_eq!(
        answer(&mut sh, "pkill -9 -f 'miner|listener'"),
        ("".into(), "".into(), 0)
    );
    assert_eq!(answer(&mut sh, "pkill --signal TERM -x sshd").2, 0);
    assert_eq!(out(&mut sh, "pgrep -l ."), before);
    assert_eq!(out(&mut sh, "pkill -e cron"), "cron killed (pid 641)\n");
    assert_eq!(out(&mut sh, "pkill -c sshd"), "2\n");
    let (_, stderr, status) = answer(&mut sh, "pkill");
    assert_eq!(status, 2);
    assert_eq!(
        stderr,
        "pkill: no matching criteria specified\nTry `pkill --help' for more information.\n"
    );
    assert_eq!(
        answer(&mut sh, "pkill -9").2,
        2,
        "a signal alone is no criterion"
    );
    assert_eq!(
        answer(&mut sh, "pkill -V").0,
        "pkill from procps-ng 3.3.17\n"
    );
}

// ---------------------------------------------------------------------------- the sequence

/// The enumerate-then-clear shapes attackers run, in order, in one session: the listing comes
/// back empty of their targets, every clearing command reports "nothing there", and the loop over
/// `/proc` signals only what exists.
#[test]
fn the_enumerate_and_clear_sequence_finds_nothing_to_kill() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "ps w | grep -E 'miner|bot'"),
        ("".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "ps aux | grep -v grep | grep -F miner").2,
        1
    );
    assert_eq!(answer(&mut sh, "ps -ef | grep -F kinsing").2, 1);
    assert_eq!(answer(&mut sh, "pkill -9 miner").2, 1);
    assert_eq!(
        answer(&mut sh, "killall -9 bot").1,
        "bot: no process found\n"
    );
    assert_eq!(answer(&mut sh, "pgrep -f 'miner|bot'").2, 1);
    // A loop that kills what its grep finds in each cmdline finds nothing, so it kills nothing.
    let looped = answer(
        &mut sh,
        "for p in /proc/[0-9]*; do grep -F miner $p/cmdline >/dev/null && kill -9 $(basename $p); done; echo done",
    );
    assert_eq!(looped, ("done\n".into(), "".into(), 0));
    // The unfiltered kill loop only ever names processes that exist, so none of it errors.
    let blanket = answer(
        &mut sh,
        "for p in /proc/[0-9]*; do kill -9 $(basename $p); done",
    );
    assert_eq!(blanket, ("".into(), "".into(), 0));
    let counted = out(
        &mut sh,
        "for p in /proc/[0-9]*; do kill -0 $(basename $p) && echo $(basename $p); done",
    );
    assert_eq!(
        counted.lines().count(),
        5,
        "every pid the glob names is a live target: {counted}"
    );
    assert_eq!(
        answer(&mut sh, "kill -9 $(pidof miner)").1,
        "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n"
    );
    assert_eq!(out(&mut sh, "echo still here"), "still here\n");
}

// ------------------------------------------------------------------------------- personas

#[test]
fn each_persona_has_its_own_rows_and_the_commands_it_ships() {
    // Ubuntu over SSH.
    let mut ssh = shell();
    let me = pid_of_shell(&mut ssh);
    assert_eq!(
        out(&mut ssh, "pgrep -l .")
            .lines()
            .map(|l| l.split_once(' ').unwrap().1)
            .collect::<Vec<_>>(),
        ["systemd", "cron", "sshd", "sshd", "bash"]
    );
    assert!(out(&mut ssh, "pgrep -f 'sshd: root@pts/0'").lines().count() == 1);
    // Over telnet the daemon is telnetd and the shell is its direct child.
    let mut tel = telnet();
    let me_tel = pid_of_shell(&mut tel);
    let full = out(&mut tel, "ps -ef");
    assert!(full.contains("/usr/sbin/telnetd"), "{full}");
    assert!(!full.contains("sshd"), "{full}");
    let telnetd = out(&mut tel, "pgrep telnetd").trim().to_string();
    assert_eq!(row_of(&full, &me_tel)[2], telnetd);
    // An exec request has no terminal.
    let mut ex = exec();
    let listing = out(&mut ex, "ps -ef");
    assert!(listing.contains("sshd: root@notty"), "{listing}");
    let me_ex = pid_of_shell(&mut ex);
    assert_eq!(row_of(&listing, &me_ex)[5], "?");
    assert_eq!(
        rows(&out(&mut ex, "ps")).len(),
        2,
        "the shell and ps even without a tty"
    );
    // Android.
    let mut ph = phone();
    let me_ph = pid_of_shell(&mut ph);
    assert_eq!(me_ph, me, "one session, one pid, whichever persona");
    for command in ["ps", "top", "kill"] {
        let found = answer(&mut ph, &format!("command -v {command}"));
        assert_eq!(found.2, 0, "{command}");
    }
    for command in ["pgrep", "pidof", "killall", "pkill"] {
        assert_eq!(
            answer(&mut ph, command).2,
            127,
            "{command} is not on the phone"
        );
        assert_eq!(
            answer(&mut ph, &format!("command -v {command}")).2,
            1,
            "{command}"
        );
        assert_ne!(
            answer(&mut ssh, &format!("command -v {command}")).2,
            1,
            "{command} is on the server"
        );
    }
    // The nodes behind the names the phone does ship.
    let bin = out(&mut ph, "ls /system/bin");
    for name in ["ps", "top"] {
        assert!(bin.split_whitespace().any(|n| n == name), "{name}: {bin}");
        assert_eq!(
            answer(&mut ph, &format!("test -x /system/bin/{name}")).2,
            0,
            "{name}"
        );
    }
    // `toolbox ps` is the same command as `ps`.
    assert_eq!(
        out(&mut ph, "toolbox ps").lines().count(),
        out(&mut ph, "ps").lines().count()
    );
}

#[test]
fn lookup_commands_agree_with_dispatch_for_the_new_names() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "command -v kill"), "kill\n", "bash's builtin");
    assert_eq!(out(&mut sh, "type kill"), "kill is a shell builtin\n");
    assert_eq!(
        out(&mut sh, "which kill ps"),
        "/usr/bin/kill\n/usr/bin/ps\n"
    );
    for name in ["ps", "top", "pgrep", "pidof", "killall", "pkill"] {
        assert_eq!(
            out(&mut sh, &format!("command -v {name}")),
            format!("/usr/bin/{name}\n")
        );
    }
    // `ps` and `kill` have recorded files; the rest are reported at the standard directory.
    assert_eq!(answer(&mut sh, "test -x /usr/bin/ps").2, 0);
    assert_eq!(answer(&mut sh, "test -x /usr/bin/kill").2, 0);
}

// ----------------------------------------------------------------------------------- bounds

#[test]
fn the_table_is_small_and_every_row_is_well_formed() {
    for (label, mut sh, floor, ceiling) in [
        ("ssh", shell(), 5usize, 6usize),
        ("telnet", telnet(), 4, 6),
        ("phone", phone(), 4, 6),
    ] {
        let count = out(&mut sh, "ls /proc").split_whitespace().count();
        assert!((floor..=ceiling).contains(&count), "{label}: {count} rows");
        let mut seen = std::collections::HashSet::new();
        for pid in out(&mut sh, "ls /proc").split_whitespace() {
            assert!(seen.insert(pid.to_string()), "{label}: pid {pid} twice");
            let comm = out(&mut sh, &format!("cat /proc/{pid}/comm"));
            assert!(
                comm.ends_with('\n') && comm.trim_end().len() <= 15,
                "{label}: {comm:?}"
            );
            let cmdline = out(&mut sh, &format!("cat /proc/{pid}/cmdline"));
            assert!(cmdline.ends_with('\0'), "{label}: {cmdline:?}");
            let status = out(&mut sh, &format!("cat /proc/{pid}/status"));
            assert!(status.len() < 2_048, "{label}: status is bounded");
        }
    }
}

#[test]
fn ps_and_top_output_is_bounded_whatever_the_arguments() {
    let mut sh = shell();
    let many = std::iter::repeat_n("-e", 500).collect::<Vec<_>>().join(" ");
    for line in [
        format!("ps {many}"),
        format!("top {many}"),
        format!("pgrep {many} x"),
        format!("killall {many} x"),
    ] {
        let reply = sh.handle_input(&line).0;
        assert!(reply.bytes().len() < 20_000, "{}", &line[..8]);
    }
    let long = "x".repeat(5_000);
    assert_eq!(answer(&mut sh, &format!("pgrep '{long}'")).2, 1);
    assert_eq!(answer(&mut sh, &format!("pkill -f '({long}|{long})'")).2, 1);
    let nested = "(".repeat(300) + "a" + &")".repeat(300);
    assert!(answer(&mut sh, &format!("pgrep -f '{nested}'")).2 <= 1);
    let alternatives = (0..400).map(|i| format!("(a{i}|b{i})")).collect::<String>();
    assert!(answer(&mut sh, &format!("pgrep -f '{alternatives}'")).2 <= 1);
    // The filesystem keeps at most GENERATED_MAX generated nodes, in path order.
    let mut fs = FakeFs::new();
    let nodes = (0..GENERATED_MAX + 50)
        .map(|i| {
            (
                format!("/proc/{}", 100_000 + i),
                Node::directory(Vec::new()),
            )
        })
        .collect();
    fs.set_generated(nodes);
    assert_eq!(fs.list_dir("/proc").unwrap().len(), GENERATED_MAX);
    assert!(fs.is_dir("/proc/100000") && !fs.is_dir(&format!("/proc/{}", 100_000 + GENERATED_MAX)));
}

#[test]
fn the_generated_nodes_do_not_leak_into_the_persona_snapshot() {
    // A filesystem no shell has installed processes on has the listing it always had.
    assert_eq!(FakeFs::new().list_dir("/proc"), Some(Vec::new()));
    assert_eq!(FakeFs::android().list_dir("/proc"), Some(Vec::new()));
    assert!(FakeFs::new().list_dir("/usr/sbin").unwrap().is_empty());
    // A session's own removals and writes still win over the generated nodes.
    let mut sh = shell();
    assert_eq!(answer(&mut sh, "rm /proc/641/comm").2, 0);
    assert_eq!(answer(&mut sh, "cat /proc/641/comm").2, 1);
    out(&mut sh, "echo cronx > /proc/641/status");
    assert_eq!(out(&mut sh, "cat /proc/641/status"), "cronx\n");
}

// -------------------------------------------------------------------------------- never-exec

/// The table is generated data: the module that holds it reads no file of the host and starts
/// nothing. The pids and names are literals; the clock is the shell's own.
#[test]
fn the_process_model_touches_no_host_file_starts_no_process_and_opens_no_socket() {
    let source = include_str!("procs.rs");
    let production = source.split("#[cfg(test)]").next().unwrap();
    for banned in [
        "std::fs",
        "File::open",
        "include_bytes!",
        "include_str!",
        "std::process",
        "::Command",
        "std::net",
        "tokio",
        "libc",
        "getpid",
        "read_dir",
        "/proc/self/",
        "SystemTime",
    ] {
        let hits: Vec<&str> = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains(banned))
            .collect();
        // `/proc/self/mounts` and `mountinfo` are read from the modeled filesystem, which is not
        // the host's; nothing else of that path may be named.
        let allowed =
            banned == "/proc/self/" && hits.iter().all(|line| line.contains("/proc/self/mount"));
        assert!(hits.is_empty() || allowed, "{banned}: {hits:?}");
    }
}

#[test]
fn the_new_commands_are_recorded_under_their_own_handler_ids() {
    use super::HandlerId;
    let mut sh = shell();
    for (line, id) in [
        ("ps", HandlerId::Ps),
        ("top", HandlerId::Top),
        ("pgrep cron", HandlerId::Pgrep),
        ("pidof cron", HandlerId::Pidof),
        ("kill 1", HandlerId::Kill),
        ("killall cron", HandlerId::Killall),
        ("pkill cron", HandlerId::Pkill),
    ] {
        sh.handle_input(line);
        let trace = sh.last_trace();
        let command = trace.segments[0].command.as_ref().expect("segment ran");
        assert_eq!(command.resolved, id, "{line}");
    }
}
