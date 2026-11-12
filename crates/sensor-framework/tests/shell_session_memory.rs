//! A fake shell inside an accounted session, under the accounting allocator: the ways a client
//! has grown one shell's memory (doubling positional parameters, descriptors `exec` holds open,
//! nested shells, function bombs) each end with the line stopped on the memory limit, and the
//! session never holds more than its peak limit by more than one line's last step. One test,
//! because the slot table is process-global.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use sensor_framework::fakefs::FakeFs;
use sensor_framework::session_memory::{self, AccountingAlloc, PEAK_LIMIT_BYTES};
use sensor_framework::shell::{BudgetHit, EmitContext, FakeShell};

#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "192.0.2.1".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "ssh".to_string(),
        session_id: None,
    }
}

/// What one attack session ended with: whether a line stopped on the memory limit, and the most
/// the session held after any line.
struct Outcome {
    stopped_on_memory: bool,
    most_held: u64,
}

/// Run `lines` in a shell built inside a fresh accounted session, checking the retained limit
/// after each line as the sensors do, and stop at the first line the memory limit ended.
fn attack(lines: Vec<String>) -> Outcome {
    let body = async move {
        let account = session_memory::current_account().expect("accounted");
        let mut shell = FakeShell::new(FakeFs::new(), ctx());
        let mut outcome = Outcome {
            stopped_on_memory: false,
            most_held: 0,
        };
        for line in &lines {
            let _ = shell.handle_input(line);
            outcome.most_held = outcome.most_held.max(account.live());
            account.check_retained();
            if shell.last_trace().budget.hit == Some(BudgetHit::Memory) {
                outcome.stopped_on_memory = true;
                break;
            }
        }
        outcome
    };
    let mut scoped = Box::pin(session_memory::scope(body));
    let Poll::Ready(outcome) =
        Pin::as_mut(&mut scoped).poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("the session completes in one poll");
    };
    outcome
}

#[test]
fn every_known_way_to_grow_a_shell_stops_at_the_memory_limit() {
    // A line may run past the limit by its last step before it is stopped: one step's output, a
    // buffer doubling, or one capped read.
    let overshoot = 16 * 1024 * 1024;

    let positional: Vec<String> = std::iter::once("set -- \"\" \"\"".to_string())
        .chain(std::iter::repeat_n("set -- \"$@\" \"$@\"".to_string(), 30))
        .collect();
    let descriptors: Vec<String> = (0..4)
        .flat_map(|level| {
            let opens = (3..64).map(|fd| format!("exec {fd}</dev/zero"));
            std::iter::once(if level == 0 {
                ":".to_string()
            } else {
                "bash".to_string()
            })
            .chain(opens)
            .collect::<Vec<_>>()
        })
        .collect();
    let nesting: Vec<String> = std::iter::repeat_n("bash".to_string(), 20_000).collect();
    let functions: Vec<String> = (0..2_000)
        .map(|i| format!("f{i}() {{ {} }}", ":;".repeat(495)))
        .collect();

    for (name, lines) in [
        ("positional", positional),
        ("descriptors", descriptors),
        ("nesting", nesting),
        ("functions", functions),
    ] {
        let outcome = attack(lines);
        assert!(
            outcome.stopped_on_memory,
            "{name}: no line stopped on the memory limit (most held {})",
            outcome.most_held
        );
        assert!(
            outcome.most_held <= PEAK_LIMIT_BYTES + overshoot,
            "{name}: held {} past the peak limit",
            outcome.most_held
        );
    }
}
