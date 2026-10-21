//! One typed line must not exhaust a sensor's memory or CPU, however many operands, however long
//! an operand, however large a directive it names. Each case runs a line shaped like the audit's
//! reproduction in an accounted session under the production allocator and checks what the line
//! cost: the heap it grew past its start (the line working set bounds it), the time it took, and
//! that the session still answers afterwards. A line that runs past the per-line work allowance
//! must stop with the shell's normal over-budget behaviour (`BudgetHit::Work`), not run to
//! completion first.
//!
//! The counting allocator wraps the production `AccountingAlloc`, and the slot table and the peak
//! counter are process-global, so the cases take a lock and run one at a time.

use std::alloc::{GlobalAlloc, Layout};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use sensor_framework::LINE_WORKING_SET_BYTES;
use sensor_framework::fakefs::FakeFs;
use sensor_framework::session_memory::{self, AccountingAlloc};
use sensor_framework::shell::{EmitContext, FakeShell};

static CURRENT: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

struct Counting;

fn grow(by: usize) {
    let now = CURRENT
        .fetch_add(by as u64, Ordering::Relaxed)
        .saturating_add(by as u64);
    PEAK.fetch_max(now, Ordering::Relaxed);
}

// SAFETY: every call forwards to `AccountingAlloc` with the caller's own layout and pointer.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { AccountingAlloc.alloc(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { AccountingAlloc.alloc_zeroed(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        unsafe { AccountingAlloc.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { AccountingAlloc.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            CURRENT.fetch_sub(layout.size() as u64, Ordering::Relaxed);
            grow(new_size);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn ctx(label: &str) -> EmitContext {
    EmitContext {
        source_ip: "192.0.2.1".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: label.to_string(),
        session_id: None,
    }
}

/// What one probe line cost.
#[derive(Debug)]
struct Cost {
    elapsed: Duration,
    peak_growth: u64,
    output: usize,
    hit: Option<String>,
    /// The first bytes it printed, for a reader of the log.
    head: String,
    /// The line after the probe ran and answered.
    alive: bool,
}

const MIB: f64 = 1024.0 * 1024.0;

/// Run `setup`, then `probe`, in one accounted session and report what the probe cost.
fn measure(android: bool, setup: &[String], probe: &str) -> Cost {
    let setup = setup.to_vec();
    let probe = probe.to_string();
    let body = async move {
        let mut shell = if android {
            FakeShell::android(FakeFs::android(), ctx("adb"))
        } else {
            FakeShell::new(FakeFs::new(), ctx("ssh"))
        };
        for line in &setup {
            let _ = shell.handle_input(line);
        }
        let base = CURRENT.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let started = Instant::now();
        let (out, _) = shell.handle_input(&probe);
        let elapsed = started.elapsed();
        let peak_growth = PEAK.load(Ordering::Relaxed).saturating_sub(base);
        let output = out.bytes().len();
        let head = String::from_utf8_lossy(out.bytes().get(..output.min(100)).unwrap_or(&[]))
            .replace('\n', "\\n");
        let hit = shell.last_trace().budget.hit.map(|hit| format!("{hit:?}"));
        drop(out);
        let (after, _) = shell.handle_input("echo still-alive");
        let alive = after.contains("still-alive");
        Cost {
            elapsed,
            peak_growth,
            output,
            hit,
            head,
            alive,
        }
    };
    let mut scoped = Box::pin(session_memory::scope(body));
    let Poll::Ready(cost) = Pin::as_mut(&mut scoped).poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("one poll");
    };
    cost
}

thread_local! {
    /// What the probes of the running test found wrong; [`finish`] fails the test on them, so one
    /// run reports every case that broke its bound and not only the first.
    static BROKEN: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The time a line may take beyond its control's (a debug build runs the handlers an order of
/// magnitude slower than a release one, and every handler's cost is a step count).
const TIME_BOUND: Duration = Duration::from_secs(5);

/// The bound every case holds: the heap the line grew past what its control did (the same
/// operands given to `true`, which is what building the argument list costs) stays within one
/// line's working set, the line ends in seconds past its control's time, and the session still
/// answers.
fn check_bounded(name: &str, cost: &Cost, control: Option<&Cost>) -> Vec<String> {
    println!(
        "CHARGING {name}: elapsed={:.3}s peak_growth={:.1}MiB output={}B hit={:?} alive={} control={} head={:?}",
        cost.elapsed.as_secs_f64(),
        cost.peak_growth as f64 / MIB,
        cost.output,
        cost.hit,
        cost.alive,
        control.map_or_else(
            || "none".to_string(),
            |c| format!(
                "{:.3}s/{:.1}MiB",
                c.elapsed.as_secs_f64(),
                c.peak_growth as f64 / MIB
            )
        ),
        cost.head
    );
    let (spent, grown) = control.map_or((Duration::ZERO, 0), |c| (c.elapsed, c.peak_growth));
    let mut broken = Vec::new();
    if cost.peak_growth > grown.saturating_add(LINE_WORKING_SET_BYTES) {
        broken.push(format!(
            "{name}: the line grew the heap by {:.1} MiB past its {:.1} MiB control, over the {:.1} MiB line working set",
            cost.peak_growth as f64 / MIB,
            grown as f64 / MIB,
            LINE_WORKING_SET_BYTES as f64 / MIB
        ));
    }
    if cost.elapsed >= spent + TIME_BOUND {
        broken.push(format!(
            "{name}: the line took {:.1} s",
            cost.elapsed.as_secs_f64()
        ));
    }
    if !cost.alive {
        broken.push(format!("{name}: the session did not answer afterwards"));
    }
    broken
}

fn probe(android: bool, name: &str, setup: &[String], line: &str) {
    run_probe(android, name, setup, None, line);
}

/// [`probe`] with a control: `control_line` is the same line with its command swapped for `true`.
fn probe_against(android: bool, name: &str, setup: &[String], control_line: &str, line: &str) {
    run_probe(android, name, setup, Some(control_line), line);
}

fn run_probe(android: bool, name: &str, setup: &[String], control_line: Option<&str>, line: &str) {
    let _lock = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let control = control_line.map(|control_line| measure(android, setup, control_line));
    let broken = check_bounded(name, &measure(android, setup, line), control.as_ref());
    BROKEN.with(|all| all.borrow_mut().extend(broken));
}

/// End of a test: fail on every bound a probe of it broke.
fn finish() {
    let broken = BROKEN.with(|all| std::mem::take(&mut *all.borrow_mut()));
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

fn rep(word: &str, n: usize) -> String {
    std::iter::repeat_n(word, n).collect::<Vec<_>>().join(" ")
}

/// An `awk` that prints `text` `n` times with no separator.
fn awk_repeat(text: &str, n: usize) -> String {
    format!("awk 'BEGIN{{for(i=0;i<{n};i++)printf \"{text}\"}}'")
}

/// An `awk` that prints `text` on `n` lines.
fn awk_lines(text: &str, n: usize) -> String {
    format!("awk 'BEGIN{{for(i=0;i<{n};i++)print \"{text}\"}}'")
}

// SYS-1: GNU tr SET parsing was quadratic in the SET's length.
#[test]
fn sys1_gnu_tr_set_parsing_is_linear() {
    let sets = [
        ("class opener, no closer", awk_repeat("[:", 20_000)),
        ("equivalence opener, no closer", awk_repeat("[=", 20_000)),
        ("repeat opener, no closer", awk_repeat("[a*", 14_000)),
        (
            "repeats that close at the end",
            format!(
                "$({})$({})",
                awk_repeat("[:*5]", 10_000),
                awk_repeat(":]", 1)
            ),
        ),
    ];
    for (shape, set) in sets {
        let set = if set.starts_with("$(") {
            set
        } else {
            format!("$({set})")
        };
        probe(
            false,
            &format!("SYS-1 tr {shape}"),
            &[],
            &format!("tr \"{set}\" x < /dev/null; echo rc=$?"),
        );
    }
    finish();
}

// SYS-2: stat -c / --printf pads each directive to 4096 with no output bound.
#[test]
fn sys2_stat_format_padding_is_bounded() {
    let format = format!("$({})", awk_repeat("%%4096n", 1_000));
    probe(
        false,
        "SYS-2 stat -c over eight operands",
        &[],
        &format!("stat -c \"{format}\" {} > /dev/null", rep("/", 8)),
    );
    probe(
        false,
        "SYS-2 stat --printf over eight operands",
        &[],
        &format!("stat --printf=\"{format}\" {} > /dev/null", rep("/", 8)),
    );
    probe(
        false,
        "SYS-2 stat -f -c over eight operands",
        &[],
        &format!("stat -f -c \"{format}\" {} > /dev/null", rep("/", 8)),
    );
    finish();
}

// SYS-3: pgrep -d repeats an attacker-sized delimiter between rows.
#[test]
fn sys3_pgrep_delimiter_is_charged() {
    probe(
        false,
        "SYS-3 pgrep -d with a 1 MB delimiter",
        &[],
        "pgrep -d \"$(head -c 1000000 /dev/zero | tr '\\0' x)\" . > /dev/null; echo rc=$?",
    );
    probe(
        false,
        "SYS-3 pidof -S with a 1 MB separator",
        &[],
        "pidof -S \"$(head -c 1000000 /dev/zero | tr '\\0' x)\" sshd systemd init bash sh cron > /dev/null; echo rc=$?",
    );
    finish();
}

// SYS-4: printenv, alias, type, command -V, dpkg -s and apt show answer per operand.
#[test]
fn sys4_printenv_is_charged_per_operand() {
    probe(
        false,
        "SYS-4 printenv X x4000, 150 KB value",
        &["export X=$(head -c 150000 /dev/zero | tr '\\0' a)".to_string()],
        &format!("printenv {} > /dev/null", rep("X", 4000)),
    );
    finish();
}

#[test]
fn sys4_alias_and_type_are_charged_per_operand() {
    let setup = vec!["alias A=\"$(head -c 4096 /dev/zero | tr '\\0' \"'\")\"".to_string()];
    for (name, verb) in [
        ("alias", "alias"),
        ("type", "type"),
        ("command -V", "command -V"),
    ] {
        probe(
            false,
            &format!("SYS-4 {name} A x4000"),
            &setup,
            &format!("{verb} {} > /dev/null", rep("A", 4000)),
        );
    }
    finish();
}

#[test]
fn sys4_dpkg_and_apt_are_charged_per_operand() {
    let setup = vec![
        format!("{} > /tmp/g", awk_lines("openssh-server", 12_000)),
        "wc -c /tmp/g".to_string(),
    ];
    for (name, verb) in [
        ("dpkg -s", "dpkg -s"),
        ("apt show", "apt show"),
        ("apt install", "apt-get install"),
        ("apt remove", "apt-get remove"),
    ] {
        let operands = format!("$(cat {})", rep("/tmp/g", 11));
        probe_against(
            false,
            &format!("SYS-4 {name} over 132k names"),
            &setup,
            &format!("true {operands}"),
            &format!("{verb} {operands} > /dev/null"),
        );
    }
    finish();
}

// SYS-5: chattr applied every change to every file with no charge for the product.
#[test]
fn sys5_chattr_charges_changes_times_files() {
    let setup = vec![
        format!("{} > /tmp/changes", awk_lines("+i", 4_000)),
        format!("{} > /tmp/files", awk_lines("/tmp/x", 4_000)),
        "touch /tmp/x".to_string(),
    ];
    probe_against(
        false,
        "SYS-5 chattr 4000 changes x 4000 files",
        &setup,
        "true $(cat /tmp/changes) $(cat /tmp/files); echo rc=$?",
        "chattr $(cat /tmp/changes) $(cat /tmp/files); echo rc=$?",
    );
    let missing = awk_lines("/nonexistent/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 40_000);
    probe_against(
        false,
        "SYS-5 chattr 4000 changes x 40000 missing files",
        &setup,
        &format!("true $(cat /tmp/changes) $({missing}) > /dev/null 2>&1; echo rc=$?"),
        &format!("chattr $(cat /tmp/changes) $({missing}) > /dev/null 2>&1; echo rc=$?"),
    );
    finish();
}

// SYS-6: the toybox option check was quadratic and uncharged.
#[test]
fn sys6_toybox_option_check_is_linear() {
    let setup = vec![
        "head -c 6000 /dev/zero | tr '\\0' d > /data/local/tmp/f".to_string(),
        "head -c 6000 /dev/zero | tr '\\0' i > /data/local/tmp/l".to_string(),
    ];
    probe(
        true,
        "SYS-6 base64 -ddd... 96k letters",
        &setup,
        &format!(
            "base64 -$(cat {}) </dev/null; echo rc=$?",
            rep("/data/local/tmp/f", 16)
        ),
    );
    probe(
        true,
        "SYS-6 base64 -iii... 96k letters (no exclusive group)",
        &setup,
        &format!(
            "base64 -$(cat {}) </dev/null; echo rc=$?",
            rep("/data/local/tmp/l", 16)
        ),
    );
    finish();
}

// SYS-7: multi-operand listers answered every operand before the budget could stop the line.
#[test]
fn sys7_listers_are_charged_per_operand() {
    let setup = vec![
        format!("{} > /tmp/g", awk_lines("/proc", 12_000)),
        format!("{} > /tmp/h", awk_lines("x", 12_000)),
        format!("{} > /tmp/m", awk_lines("/no/x", 12_000)),
    ];
    let (proc_names, same_names, missing_names) = (
        format!("$(cat {})", rep("/tmp/g", 8)),
        format!("$(cat {})", rep("/tmp/h", 8)),
        format!("$(cat {})", rep("/tmp/m", 8)),
    );
    for (name, verb, operands, tail) in [
        ("ls", "ls", &proc_names, "> /dev/null"),
        ("df", "df", &proc_names, "> /dev/null"),
        ("mv", "mv", &same_names, "/tmp"),
        ("touch", "touch", &missing_names, "> /dev/null"),
        ("ln", "ln -s", &same_names, "/tmp"),
    ] {
        probe_against(
            false,
            &format!("SYS-7 {name} x96k"),
            &setup,
            &format!("true {operands}"),
            &format!("{verb} {operands} {tail}"),
        );
    }
    let deep = std::iter::repeat_n("a".repeat(200), 18)
        .collect::<Vec<_>>()
        .join("/");
    let deep_setup = vec![
        format!("{} > /tmp/h", awk_lines("x", 12_000)),
        format!("mkdir -p /tmp/{deep}"),
        format!("cd /tmp/{deep}"),
    ];
    for (name, verb) in [
        ("realpath -m", "realpath -m"),
        ("readlink -f", "readlink -f"),
    ] {
        probe_against(
            false,
            &format!("SYS-7 {name} x96k in an 18-level cwd"),
            &deep_setup,
            &format!("true $(cat {})", rep("/tmp/h", 8)),
            &format!("{verb} $(cat {}) > /dev/null", rep("/tmp/h", 8)),
        );
    }
    finish();
}

// SYS-8: configuration files of up to 64 KB were re-read on every call, uncharged.
#[test]
fn sys8_config_reads_are_charged() {
    let grown = vec![
        "awk 'BEGIN{for(i=0;i<10500;i++)print \"a:x:7\"}' > /tmp/p; cat /etc/passwd >> /tmp/p; cp /tmp/p /etc/passwd; rm /tmp/p".to_string(),
        "awk 'BEGIN{for(i=0;i<30000;i++)print \"#\"}' >> /etc/hosts".to_string(),
        "awk 'BEGIN{for(i=0;i<30000;i++)print \"x\"}' >> /proc/meminfo".to_string(),
        "awk 'BEGIN{for(i=0;i<30000;i++)print \"x\"}' >> /proc/cpuinfo".to_string(),
    ];
    for (name, line) in [
        ("getent hosts", "while :; do getent hosts nosuchname; done"),
        (
            "nslookup",
            "while :; do nslookup nosuchname; done >/dev/null",
        ),
        ("free", "while :; do free; done >/dev/null"),
        ("nproc", "while :; do nproc; done >/dev/null"),
        ("stat -c %U", "while :; do stat -c %U / ; done >/dev/null"),
        ("ls -l /proc", "while :; do ls -l /proc >/dev/null; done"),
    ] {
        probe(false, &format!("SYS-8 {name}, grown files"), &grown, line);
    }
    finish();
}

// SYS-9: env NAME=VALUE operands were merged one by one against the whole list.
#[test]
fn sys9_env_assignments_are_linear() {
    let names = "$(awk 'BEGIN{for(i=0;i<80000;i++)print \"v\" i \"=1\"}')";
    probe_against(
        false,
        "SYS-9 env with 80k assignments",
        &[],
        &format!("true {names} | wc -l"),
        &format!("env {names} | wc -l"),
    );
    probe_against(
        false,
        "SYS-9 env with 80k assignments and a command",
        &[],
        &format!("true {names}; echo rc=$?"),
        &format!("env {names} true; echo rc=$?"),
    );
    finish();
}

// The same root cause beyond the audit's named commands: every command that takes a list of
// operands stops where the allowance does when given 96k of them, nonexistent or not.
#[test]
fn operand_loops_of_the_other_commands_are_charged() {
    let setup = vec![
        format!("{} > /tmp/h", awk_lines("x", 12_000)),
        format!("{} > /tmp/r", awk_lines("/etc/hostname", 12_000)),
    ];
    let (missing, present) = (
        format!("$(cat {})", rep("/tmp/h", 8)),
        format!("$(cat {})", rep("/tmp/r", 8)),
    );
    let commands = [
        "cat",
        "chmod 644",
        "rm -f",
        "mkdir -p",
        "rmdir",
        "md5sum",
        "sha256sum",
        "cksum",
        "wc",
        "head",
        "tail",
        "which",
        "kill",
        "export",
        "od",
    ];
    for verb in commands {
        for (shape, operands) in [("missing", &missing), ("present", &present)] {
            probe_against(
                false,
                &format!("operands {verb} x96k {shape}"),
                &setup,
                &format!("true {operands}"),
                &format!("{verb} {operands} > /dev/null 2>&1; echo rc=$?"),
            );
        }
    }
    finish();
}

// SYS-10: the Android tr expanded ranges and classes into memory with no charge.
#[test]
fn sys10_android_tr_sets_are_charged() {
    // The phone has no awk: the SET is doubled up in a variable 15 times, to 32,768 ranges of
    // `!-~` (98 KB, under the variable allowance) and given eight times over as one operand:
    // 786 KB of text that expands to 24 MB of set.
    let ranges = "s='!-~'; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do s=\"$s$s\"; done";
    let operand = "\"$s$s$s$s$s$s$s$s\"";
    for (name, flags) in [
        ("tr", ""),
        ("tr -c", "-c "),
        ("tr -d", "-d "),
        ("tr -s", "-s "),
    ] {
        probe(
            true,
            &format!("SYS-10 {name} with 262k ranges of 94 bytes"),
            &[],
            &format!("{ranges}; tr {flags}{operand} x </dev/null; echo rc=$?"),
        );
    }
    // The same SET for the second operand.
    probe(
        true,
        "SYS-10 tr with 262k ranges as SET2",
        &[],
        &format!("{ranges}; tr a {operand} </dev/null; echo rc=$?"),
    );
    finish();
}
