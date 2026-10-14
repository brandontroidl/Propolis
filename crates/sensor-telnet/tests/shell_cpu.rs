//! The shell's pattern matchers over a real telnet socket: a line whose operands an attacker
//! sized for the worst case of a matcher answers within a few seconds, because every matcher is
//! linear or charges the line for the work it does. A line runs synchronously on a runtime
//! worker, so before this a single such line held that worker for minutes and stalled every
//! session on the sensor.
//!
//! The server runs on its own two-worker runtime (the SSH sensor's shape) and the client is a
//! blocking socket, so the client's clock keeps running whatever the server's workers do. A
//! runtime still busy when a test ends is shut down in the background rather than waited for.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::{ConnectionBounds, WanResolver};

/// The most one adversarial line may take here. Every line below took from half a minute to
/// hours before matching was linear or charged; the fixed build answers each in well under a
/// second, so this leaves room for a loaded machine and an unoptimized build.
const BOUND: Duration = Duration::from_secs(20);

struct Sensor {
    runtime: Option<tokio::runtime::Runtime>,
    addr: SocketAddr,
    _dir: tempfile::TempDir,
}

impl Drop for Sensor {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

fn sensor() -> Sensor {
    let dir = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let bounds = ConnectionBounds {
        read_timeout: Duration::from_secs(120),
        idle_timeout: Duration::from_secs(120),
        max_duration: Duration::from_secs(600),
        max_captured_bytes: 1_000_000,
        max_concurrent: 10,
    };
    let (addr, _handle) = runtime
        .block_on(sensor_telnet::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            dir.path().join("events.jsonl"),
            dir.path().join("spool"),
            Arc::new(WanResolver::new(HashMap::new())),
            bounds,
            "test".to_string(),
            dir.path().join("outbox"),
        ))
        .unwrap();
    Sensor {
        runtime: Some(runtime),
        addr,
        _dir: dir,
    }
}

struct Client {
    stream: TcpStream,
    seen: Vec<u8>,
    marks: u32,
}

impl Client {
    fn login(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut client = Self {
            stream,
            seen: Vec::new(),
            marks: 0,
        };
        let soon = Duration::from_secs(10);
        client.wait_for(b"login: ", soon).unwrap();
        client.send("root");
        client.wait_for(b"Password: ", soon).unwrap();
        client.send("root");
        client.wait_for(b"# ", soon).unwrap();
        client
    }

    fn send(&mut self, line: &str) {
        self.seen.clear();
        self.stream
            .write_all(format!("{line}\r\n").as_bytes())
            .unwrap();
    }

    /// Wait until `needle` has arrived since the last send, or `within` has passed.
    fn wait_for(&mut self, needle: &[u8], within: Duration) -> Result<(), String> {
        let deadline = Instant::now() + within;
        let mut chunk = [0u8; 65_536];
        while !self.seen.windows(needle.len()).any(|w| w == needle) {
            if Instant::now() >= deadline {
                return Err(format!(
                    "no {:?} within {within:?}",
                    String::from_utf8_lossy(needle)
                ));
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err("the sensor closed the connection".to_string()),
                Ok(n) => self.seen.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    }

    /// Send `line` followed by a marker command on a line of its own, and return how long the
    /// marker took to come back and what was printed before it. The marker's output is computed
    /// (`M$((n))K` prints `M<n>K`), so the echoed command text never satisfies the wait.
    fn timed(&mut self, line: &str) -> (Duration, String) {
        self.marks += 1;
        let mark = self.marks;
        let started = Instant::now();
        self.send(line);
        self.stream
            .write_all(format!("echo M$(({mark}))K\r\n").as_bytes())
            .unwrap();
        let needle = format!("M{mark}K");
        if let Err(error) = self.wait_for(needle.as_bytes(), BOUND) {
            panic!("{error}: the line did not finish: {line:.120}");
        }
        (
            started.elapsed(),
            String::from_utf8_lossy(&self.seen).into_owned(),
        )
    }

    /// Run a setup line and wait for it to finish.
    fn run(&mut self, line: &str) {
        let (elapsed, _) = self.timed(line);
        assert!(elapsed < BOUND, "setup line took {elapsed:?}");
    }
}

/// `NAME=` followed by 48,000 copies of `unit`, built in two lines a telnet client can send.
fn grow(client: &mut Client, name: &str, unit: char) {
    let seed: String = std::iter::repeat_n(unit, 1_000).collect();
    client.run(&format!("{name}='{seed}'"));
    client.run(&format!(
        "{name}=${name}${name}${name}${name}${name}${name}${name}${name}; \
         {name}=${name}${name}${name}${name}${name}${name}"
    ));
}

#[test]
fn a_case_pattern_against_a_long_subject_answers_in_linear_time() {
    let sensor = sensor();
    let mut client = Client::login(sensor.addr);
    grow(&mut client, "a", 'a');

    // Old matcher: about forty seconds per arm in an unoptimized build, quadratic in 48,000.
    let (elapsed, out) = client.timed(
        "case $a in *${a}b) echo H$((1))T;; esac; \
         case $a in *${a}) echo S$((2))F;; esac; \
         case $a$a in *${a}b*) echo M$((3))D;; *${a}*) echo B$((4))C;; esac",
    );
    assert!(elapsed < BOUND, "took {elapsed:?}");
    assert!(
        !out.contains("H1T"),
        "a pattern ending in b matched: {out:.200}"
    );
    assert!(out.contains("S2F"), "the subject did not match itself");
    assert!(!out.contains("M3D"), "a missing middle piece matched");
    assert!(out.contains("B4C"), "a present middle piece did not match");
}

#[test]
fn a_case_pattern_of_wildcards_is_charged_to_the_line() {
    let sensor = sensor();
    let mut client = Client::login(sensor.addr);
    grow(&mut client, "a", 'a');
    grow(&mut client, "q", '?');

    // 48,000 `?` then `b`, looked for in 96,000 characters: about 2.3e9 steps whatever the
    // algorithm, so the line's allowance refuses it rather than a worker running it for minutes.
    let (elapsed, out) = client.timed("case $a$a in *${q}b*) echo H$((1))T;; esac");
    assert!(elapsed < BOUND, "took {elapsed:?}");
    assert!(!out.contains("H1T"));

    // The session is still served, and a wildcard pattern that fits the allowance still matches.
    let (_, out) = client.timed("case $a in ${q}*) echo W$((5))X;; esac");
    assert!(
        out.contains("W5X"),
        "a fitting wildcard pattern did not match"
    );
}

#[test]
fn grep_fixed_strings_scan_in_linear_time() {
    let sensor = sensor();
    let mut client = Client::login(sensor.addr);
    let seed = "a".repeat(375);
    client.run(&format!("a='{seed}'"));
    client.run("a=$a$a; a=$a$a; a=$a$a; a=$a$a; a=$a$a; a=$a$a; a=$a$a; a=$a$a; a=$a$a");

    // A 192,001-byte needle that fails at its last byte, at each of 192,000 offsets: about
    // three seconds per grep before, and eight minutes with -i, in an unoptimized build.
    for (line, count) in [
        ("echo $a$a | grep -F -c \"${a}b\"", "\n0"),
        ("echo $a$a | grep -iF -c \"${a}B\"", "\n0"),
        ("echo $a$a | grep -F -c \"$a\"", "\n1"),
    ] {
        let (elapsed, out) = client.timed(line);
        assert!(elapsed < BOUND, "{line} took {elapsed:?}");
        assert!(out.contains(count), "{line} printed {out:.300}");
    }

    // -w rejects the match at every offset and looks again one byte on: 192,000 matches of
    // 192,000 bytes each. That work is charged, so the line runs out of allowance instead.
    let (elapsed, _) = client.timed("echo $a$a | grep -F -w -c \"$a\"");
    assert!(elapsed < BOUND, "took {elapsed:?}");
}

#[test]
fn find_and_package_globs_with_a_long_bracket_expression_are_linear() {
    let sensor = sensor();
    let mut client = Client::login(sensor.addr);
    let class = "b".repeat(7_000);
    client.run(&format!("c='{class}'"));

    // The old matcher re-read the 7,000-member class at every character it tried: over a
    // second per walk or package list in an unoptimized build.
    let (elapsed, _) = client.timed(
        "i=0; while [ $i -lt 10 ]; do find / -name \"*[$c]x\"; find / -path \"*[$c]x\"; \
         dpkg -l \"*[$c]x\"; apt list \"*[$c]x\"; i=$((i+1)); done",
    );
    assert!(elapsed < BOUND, "took {elapsed:?}");

    let (_, out) = client.timed("find /etc -maxdepth 1 -name \"[${c}h]ostnam[e]\"");
    assert!(
        out.contains("/etc/hostname"),
        "a long class still matches: {out:.300}"
    );
}
