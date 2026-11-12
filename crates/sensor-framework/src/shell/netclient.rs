//! `ping` (iputils 20211215) and the `ssh` client (OpenSSH 8.9p1) of the Ubuntu persona: the two
//! network clients a survey runs to see whether the box can reach out.
//!
//! Neither sends anything. `ping`'s replies are invented text: a target the box can resolve (a
//! dotted address, or a name the modeled `/etc/hosts` lists) answers every probe, with a round
//! trip and TTL that are a pure function of the address, so two pings of one host agree. A name
//! the box cannot resolve fails the way `getent hosts` and `nslookup` already report it. `ssh`
//! never connects: it prints its version, its usage, or the error a host that does not answer on
//! port 22 gives after the connect timeout. The time either would have waited is charged to the
//! shell's clock for `time`.
//!
//! Recorded on the 2026-10-07 Ubuntu 22.04 reference: `ssh -V` (with the persona's package
//! revision), `ssh`'s usage and status 255, the pseudo-terminal warning, `Connection timed out`
//! and `Could not resolve hostname`. The reference container could not send ICMP, so `ping`'s
//! layout, its `time=` precision rules and its messages are from iputils' source [unverified].
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};
use crate::persona;

pub(super) fn register(r: &mut Registry) {
    r.register_if("ping", iputils, HandlerId::Ping, FakeShell::cmd_ping);
    r.register("ping", HandlerId::Ping, FakeShell::builtin_ping);
    r.register_if("ssh", ubuntu, HandlerId::Ssh, FakeShell::cmd_ssh);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// Ubuntu's own `ping`; `busybox ping` keeps the applet's layout.
fn iputils(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash && shell.busybox_depth == 0
}

const NS_PER_MS: u64 = 1_000_000;
/// The most probes one `ping` answers, whatever `-c` asks for: the output stays bounded.
const PING_MAX: u64 = 1_000;
/// Probes a `ping` without `-c` or `-w` answers before it stops as if interrupted
/// [unverified: a real one runs until it is].
const PING_UNBOUNDED: u64 = 4;
/// What the kernel waits for a connect that gets no answer: six SYN retries [unverified].
const CONNECT_TIMEOUT_SECS: u64 = 127;

/// FNV-1a over the bytes, the stable hash the invented figures are drawn from.
fn hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |acc, &b| {
        (acc ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The modeled path to `addr`: its TTL and base round trip in microseconds.
fn path_to(addr: &str, own: &[String]) -> (u8, u64) {
    let octets: Vec<u8> = addr.split('.').filter_map(|o| o.parse().ok()).collect();
    let private = match octets.as_slice() {
        [127, ..] => return (64, 30),
        [10, ..] | [192, 168, ..] => true,
        [172, second, ..] => (16..32).contains(second),
        _ => false,
    };
    if own.iter().any(|mine| mine == addr) {
        return (64, 30);
    }
    if private {
        return (64, 420);
    }
    let h = hash(addr.as_bytes());
    const TTLS: [u8; 6] = [47, 52, 54, 57, 117, 118];
    let ttl = TTLS
        .get(usize::try_from(h % 6).unwrap_or(0))
        .copied()
        .unwrap_or(54);
    (ttl, 1_800u64.saturating_add((h >> 8) % 58_000))
}

/// iputils' `time=` field: whole milliseconds from 100 ms, then one, two or three decimals.
fn rtt_text(us: u64) -> String {
    let ms = us / 1_000;
    let frac = us % 1_000;
    if us >= 99_950 {
        format!("{} ms", us.saturating_add(500) / 1_000)
    } else if us >= 9_995 {
        format!("{ms}.{} ms", frac / 100)
    } else if us >= 1_000 {
        format!("{ms}.{:02} ms", frac / 10)
    } else {
        format!("{ms}.{frac:03} ms")
    }
}

fn ms3(us: u64) -> String {
    format!("{}.{:03}", us / 1_000, us % 1_000)
}

/// What a `ping` command line asks for.
struct PingPlan<'a> {
    target: &'a str,
    count: Option<u64>,
    deadline: Option<u64>,
    size: u64,
    quiet: bool,
}

fn parse_ping<'a>(args: &[&'a str]) -> Result<PingPlan<'a>, CommandResult> {
    let mut plan = PingPlan {
        target: "",
        count: None,
        deadline: None,
        size: 56,
        quiet: false,
    };
    let invalid =
        |value: &str| CommandResult::stderr(1, format!("ping: invalid argument: '{value}'\n"));
    let number = |value: &str, max: u64| -> Result<u64, CommandResult> {
        value
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=max).contains(n))
            .ok_or_else(|| invalid(value))
    };
    let mut iter = args.iter();
    while let Some(&arg) = iter.next() {
        if !arg.starts_with('-') || arg == "-" {
            if plan.target.is_empty() {
                plan.target = arg;
            }
            continue;
        }
        let mut flags = arg.chars().skip(1).peekable();
        while let Some(flag) = flags.next() {
            if matches!(
                flag,
                'c' | 'w' | 's' | 'i' | 'W' | 'I' | 't' | 'Q' | 'l' | 'p' | 'M'
            ) {
                let rest: String = flags.by_ref().collect();
                let value = if rest.is_empty() {
                    match iter.next() {
                        Some(value) => (*value).to_string(),
                        None => {
                            return Err(CommandResult::stderr(
                                2,
                                format!("ping: option requires an argument -- '{flag}'\n"),
                            ));
                        }
                    }
                } else {
                    rest
                };
                match flag {
                    'c' => plan.count = Some(number(&value, u64::MAX)?),
                    'w' => plan.deadline = Some(number(&value, 2_147_483)?),
                    's' if value == "0" => plan.size = 0,
                    's' => plan.size = number(&value, 65_507)?,
                    _ => {}
                }
                break;
            }
            match flag {
                'q' => plan.quiet = true,
                '4' | '6' | 'n' | 'v' | 'D' | 'a' | 'A' | 'b' | 'B' | 'd' | 'f' | 'L' | 'O'
                | 'r' | 'R' | 'U' => {}
                other => {
                    return Err(CommandResult::stderr(
                        2,
                        format!("ping: invalid option -- '{other}'\n"),
                    ));
                }
            }
        }
    }
    if plan.target.is_empty() {
        return Err(CommandResult::stderr(
            1,
            "ping: usage error: Destination address required\n",
        ));
    }
    Ok(plan)
}

impl FakeShell {
    /// `ping [-c N] [-w S] [-s SIZE] [-q] TARGET`: iputils' report of a host that answers every
    /// probe, sent nowhere.
    pub(super) fn cmd_ping(&mut self, parts: &[&str]) -> CommandResult {
        let plan = match parse_ping(parts.get(1..).unwrap_or(&[])) {
            Ok(plan) => plan,
            Err(result) => return result,
        };
        let target = crate::sanitize_value(plan.target, 253);
        if target.contains(':') {
            return CommandResult::stderr(2, "ping: connect: Network is unreachable\n");
        }
        let Some(addr) = self.resolve_host_v4(&target) else {
            return CommandResult::stderr(
                2,
                format!("ping: {target}: Name or service not known\n"),
            );
        };
        let own = self.interface_addresses();
        let (ttl, base_us) = path_to(&addr, &own);
        let count = match (plan.count, plan.deadline) {
            (Some(count), Some(deadline)) => count.min(deadline),
            (Some(count), None) => count,
            (None, Some(deadline)) => deadline,
            (None, None) => PING_UNBOUNDED,
        }
        .min(PING_MAX);
        let named = addr != target;
        let from = if named {
            format!("{target} ({addr})")
        } else {
            addr.clone()
        };
        let mut out = format!(
            "PING {target} ({addr}) {}({}) bytes of data.\n",
            plan.size,
            plan.size.saturating_add(28)
        );
        let jitter_span = (base_us / 8).saturating_add(1);
        let mut rtts: Vec<u64> = Vec::new();
        for seq in 1..=count {
            if !self.charge_work(1) {
                break;
            }
            let jitter = hash(format!("{addr}#{seq}").as_bytes())
                .checked_rem(jitter_span)
                .unwrap_or(0);
            let rtt = base_us.saturating_add(jitter);
            rtts.push(rtt);
            if !plan.quiet {
                out.push_str(&format!(
                    "{} bytes from {from}: icmp_seq={seq} ttl={ttl} time={}\n",
                    plan.size.saturating_add(8),
                    rtt_text(rtt)
                ));
            }
        }
        let sent = u64::try_from(rtts.len()).unwrap_or(0);
        let elapsed_ms = sent.saturating_sub(1).saturating_mul(1_001);
        out.push_str(&format!(
            "\n--- {target} ping statistics ---\n\
             {sent} packets transmitted, {sent} received, 0% packet loss, time {elapsed_ms}ms\n"
        ));
        if let (Some(min), Some(max)) = (rtts.iter().min(), rtts.iter().max()) {
            let n = rtts.len().max(1) as f64;
            let mean = rtts.iter().map(|&r| r as f64).sum::<f64>() / n;
            let square = rtts.iter().map(|&r| (r as f64) * (r as f64)).sum::<f64>() / n;
            let mdev = (square - mean * mean).max(0.0).sqrt();
            out.push_str(&format!(
                "rtt min/avg/max/mdev = {}/{}/{}/{} ms\n",
                ms3(*min),
                ms3(mean.round() as u64),
                ms3(*max),
                ms3(mdev.round() as u64)
            ));
        }
        let waited = elapsed_ms
            .saturating_mul(NS_PER_MS)
            .saturating_add(rtts.last().copied().unwrap_or(0).saturating_mul(1_000));
        self.timing.wait(waited);
        CommandResult::stdout(out)
    }

    /// `ssh`: OpenSSH 8.9p1's client, which connects to nothing. `-V` prints the version the
    /// banner and the `openssh-client` package carry; no destination prints the usage; a name
    /// the box cannot resolve is that error; any address times out on connect.
    pub(super) fn cmd_ssh(&mut self, parts: &[&str]) -> CommandResult {
        const WITH_VALUE: &str = "BbcDEeFIiJLlmOopQRSWw";
        const FLAGS: &str = "46AaCfGgKkMNnqsTtVvXxYy";
        let mut destination: Option<&str> = None;
        let mut port = "22".to_string();
        let mut connect_timeout: Option<u64> = None;
        let mut command = false;
        let mut quiet = false;
        let mut iter = parts.get(1..).unwrap_or(&[]).iter();
        while let Some(&arg) = iter.next() {
            // ssh parses options after the destination too (recorded: `ssh HOST -o
            // ConnectTimeout=2` honours the timeout); the first other word starts the command.
            if destination.is_some() && !arg.starts_with('-') {
                command = true;
                break;
            }
            let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) else {
                destination = Some(arg);
                continue;
            };
            let mut chars = cluster.chars();
            while let Some(flag) = chars.next() {
                if flag == 'V' {
                    return CommandResult::stderr(
                        0,
                        format!("{}, OpenSSL 3.0.2 15 Mar 2022\n", persona::OPENSSH_VERSION),
                    );
                }
                if WITH_VALUE.contains(flag) {
                    let rest: String = chars.by_ref().collect();
                    let value = if rest.is_empty() {
                        match iter.next() {
                            Some(value) => (*value).to_string(),
                            None => {
                                return CommandResult::stderr(
                                    255,
                                    format!("option requires an argument -- {flag}\n{SSH_USAGE}"),
                                );
                            }
                        }
                    } else {
                        rest
                    };
                    match flag {
                        'p' => port = value,
                        'o' => {
                            if let Some(seconds) = value
                                .split_once(['=', ' '])
                                .filter(|(key, _)| key.eq_ignore_ascii_case("ConnectTimeout"))
                                .and_then(|(_, n)| n.trim().parse::<u64>().ok())
                            {
                                connect_timeout = Some(seconds);
                            }
                        }
                        _ => {}
                    }
                    break;
                }
                if flag == 'q' {
                    quiet = true;
                } else if !FLAGS.contains(flag) {
                    return CommandResult::stderr(
                        255,
                        format!("unknown option -- {flag}\n{SSH_USAGE}"),
                    );
                }
            }
        }
        let Some(destination) = destination else {
            return CommandResult::stderr(255, SSH_USAGE);
        };
        let host = destination
            .rsplit_once('@')
            .map_or(destination, |(_, host)| host)
            .to_ascii_lowercase();
        let host = crate::sanitize_value(&host, 253);
        let port = crate::sanitize_value(&port, 16);
        let mut err = String::new();
        if !command && !quiet && !self.stdout_is_terminal() {
            err.push_str(
                "Pseudo-terminal will not be allocated because stdin is not a terminal.\n",
            );
        }
        if self.resolve_host_v4(&host).is_none() {
            err.push_str(&format!(
                "ssh: Could not resolve hostname {host}: Name or service not known\n"
            ));
            return CommandResult::stderr(255, err);
        }
        let waited = connect_timeout
            .filter(|seconds| *seconds > 0)
            .unwrap_or(CONNECT_TIMEOUT_SECS)
            .min(CONNECT_TIMEOUT_SECS);
        self.timing
            .wait(waited.saturating_mul(1_000).saturating_mul(NS_PER_MS));
        err.push_str(&format!(
            "ssh: connect to host {host} port {port}: Connection timed out\n"
        ));
        CommandResult::stderr(255, err)
    }
}

/// OpenSSH 8.9p1's usage text (recorded).
const SSH_USAGE: &str = "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]
           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]
           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]
           [-i identity_file] [-J [user@]host[:port]] [-L address]
           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]
           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]
           [-w local_tun[:remote_tun]] destination [command [argument ...]]
";
