//! `ip`, `ss`, `ifconfig`, `netstat` and `route`, plus the `/proc/net` files the filesystem serves
//! for the same rows.
//!
//! Attackers enumerate the network first (`ip a`, `netstat -tulpn`, `route -n`, `cat /proc/net/tcp`).
//! Nothing here reads the host's network, resolves a name or opens a socket: every answer is
//! rendered from one fixed, synthetic model per persona, so the commands and the `/proc/net`
//! files cannot disagree. The model never reads the connection's peer address or the deployment
//! host's address (`EmitContext` is not consulted for either), so a real address cannot reach an
//! attacker through any output below, and the established session is deliberately not modeled
//! (listing it would need the real peer). Addresses come only from private and documentation
//! ranges: RFC 1918 for the interface and its gateway, loopback for `lo`.
//!
//! The model, per persona (every address, MAC, counter, inode and descriptor number is
//! [unverified]; no capture exists):
//!
//! * Ubuntu: `lo` and `eth0` (172.31.16.42/20, gateway 172.31.16.1, the gateway the only neighbor),
//!   listening only on what the process table runs: the `sshd` listener, or `telnetd` over telnet.
//! * Android: `lo` and `wlan0` (192.168.1.23/24, gateway 192.168.1.1), `adbd` listening on 5555.
//!
//! Which commands exist is the recorded persona, not this module's choice. The Ubuntu 22.04
//! recording has `iproute2` but not `net-tools` (`ifconfig` answers "not found, but can be
//! installed with: apt install net-tools"), so `ifconfig`, `netstat` and `route` are not Ubuntu
//! files and `ip` and `ss` are. The phone ships toolbox and toybox, so it has `ifconfig`,
//! `netstat` and `route` (toolbox's one-line `ifconfig`) and `ip`, and no `ss` or `arp`. The
//! neighbor table is reachable through `ip neigh` and `/proc/net/arp`; there is no `arp` command
//! on either persona.
//!
//! An option or subcommand not modeled prints nothing and succeeds, never a table this module made
//! up. Wording is composed from knowledge of iproute2 5.15, net-tools 2.10 and Android 6's
//! toolbox, not from a capture, and every layout below is [unverified] unless a comment says
//! otherwise.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::collections::HashMap;

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};
use crate::fakefs::{Blob, Node};

pub(super) fn register(r: &mut Registry) {
    r.register("ip", HandlerId::Ip, FakeShell::cmd_ip);
    r.register_if("ss", ubuntu, HandlerId::Ss, FakeShell::cmd_ss);
    r.register_if(
        "ifconfig",
        android,
        HandlerId::Ifconfig,
        FakeShell::cmd_ifconfig,
    );
    r.register_if(
        "netstat",
        android,
        HandlerId::Netstat,
        FakeShell::cmd_netstat,
    );
    r.register_if("route", android, HandlerId::Route, FakeShell::cmd_route);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

fn android(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::AndroidSh
}

// ---------------------------------------------------------------------------------------- model

type V4 = [u8; 4];
type Mac = [u8; 6];

struct Counters {
    bytes: u64,
    packets: u64,
}

struct Iface {
    name: &'static str,
    index: u32,
    loopback: bool,
    mtu: u32,
    mac: Mac,
    addr: V4,
    prefix: u8,
    /// The link-local (or loopback) IPv6 address, as text, with its prefix length.
    v6: &'static str,
    v6_prefix: u8,
    qdisc: &'static str,
    qlen: u32,
    rx: Counters,
    tx: Counters,
}

struct Route {
    dest: V4,
    prefix: u8,
    gateway: Option<V4>,
    dev: &'static str,
    /// `static` for an administered route, `kernel` for the on-link one.
    proto: &'static str,
    src: Option<V4>,
    metric: u32,
}

struct Neighbor {
    addr: V4,
    mac: Mac,
    dev: &'static str,
}

/// A listening TCP socket or a bound UDP one. Its owner is a process of the modeled table, found
/// by its kernel name when the line is rendered.
struct Listener {
    v6: bool,
    /// A UDP socket (`UNCONN` to `ss`) rather than a TCP one in LISTEN.
    udp: bool,
    /// The address it is bound to and the interface it is scoped to (`127.0.0.53%lo`), or `None`
    /// for the wildcard.
    bind: Option<(V4, &'static str)>,
    port: u16,
    comm: &'static str,
    inode: u32,
    fd: u32,
    backlog: u32,
}

impl Listener {
    const fn wildcard(v6: bool, port: u16, comm: &'static str, inode: u32, fd: u32) -> Self {
        Self {
            v6,
            udp: false,
            bind: None,
            port,
            comm,
            inode,
            fd,
            backlog: 128,
        }
    }
}

struct Net {
    /// A recent iproute2 (Ubuntu) prints `group default` and the phone's old one does not.
    modern: bool,
    ifaces: Vec<Iface>,
    routes: Vec<Route>,
    neighbors: Vec<Neighbor>,
    listeners: Vec<Listener>,
}

fn loopback() -> Iface {
    Iface {
        name: "lo",
        index: 1,
        loopback: true,
        mtu: 65_536,
        mac: [0; 6],
        addr: [127, 0, 0, 1],
        prefix: 8,
        v6: "::1",
        v6_prefix: 128,
        qdisc: "noqueue",
        qlen: 0,
        rx: Counters {
            bytes: 5_612_048,
            packets: 61_204,
        },
        tx: Counters {
            bytes: 5_612_048,
            packets: 61_204,
        },
    }
}

impl Net {
    fn ubuntu(telnet: bool) -> Self {
        let comm = if telnet { "telnetd" } else { "sshd" };
        let port = if telnet { 23 } else { 22 };
        // systemd-resolved's stub listener, on UDP and TCP, as on every 22.04 box that runs it
        // (recorded on the reference: `udp UNCONN 0 0 127.0.0.53%lo:53` and the TCP twin with a
        // backlog of 4096); it is listed first, as the kernel's tables give it.
        let stub = |udp: bool, inode: u32, fd: u32| Listener {
            udp,
            bind: Some(([127, 0, 0, 53], "lo")),
            backlog: if udp { 0 } else { 4_096 },
            ..Listener::wildcard(false, 53, "systemd-resolve", inode, fd)
        };
        let mut listeners = vec![
            stub(true, 17_806, 13),
            stub(false, 17_807, 14),
            Listener::wildcard(false, port, comm, 18_412, 3),
        ];
        if !telnet {
            listeners.push(Listener::wildcard(true, port, comm, 18_414, 4));
        }
        Self {
            modern: true,
            ifaces: vec![
                Iface {
                    qlen: 1000,
                    ..loopback()
                },
                Iface {
                    name: "eth0",
                    index: 2,
                    loopback: false,
                    mtu: 1500,
                    mac: [0x06, 0x4b, 0x9c, 0x1e, 0xa2, 0x7d],
                    addr: [172, 31, 16, 42],
                    prefix: 20,
                    v6: "fe80::44b:9cff:fe1e:a27d",
                    v6_prefix: 64,
                    qdisc: "fq_codel",
                    qlen: 1000,
                    rx: Counters {
                        bytes: 48_332_190,
                        packets: 61_947,
                    },
                    tx: Counters {
                        bytes: 4_104_776,
                        packets: 31_882,
                    },
                },
            ],
            routes: vec![
                Route {
                    dest: [0; 4],
                    prefix: 0,
                    gateway: Some([172, 31, 16, 1]),
                    dev: "eth0",
                    proto: "static",
                    src: None,
                    metric: 0,
                },
                Route {
                    dest: [172, 31, 16, 0],
                    prefix: 20,
                    gateway: None,
                    dev: "eth0",
                    proto: "kernel",
                    src: Some([172, 31, 16, 42]),
                    metric: 0,
                },
            ],
            neighbors: vec![Neighbor {
                addr: [172, 31, 16, 1],
                mac: [0x06, 0x7d, 0x2a, 0xf1, 0x00, 0xc3],
                dev: "eth0",
            }],
            listeners,
        }
    }

    fn android() -> Self {
        Self {
            modern: false,
            ifaces: vec![
                loopback(),
                Iface {
                    name: "wlan0",
                    index: 2,
                    loopback: false,
                    mtu: 1500,
                    mac: [0x10, 0x68, 0x3f, 0x4a, 0x91, 0xc2],
                    addr: [192, 168, 1, 23],
                    prefix: 24,
                    v6: "fe80::1268:3fff:fe4a:91c2",
                    v6_prefix: 64,
                    qdisc: "pfifo_fast",
                    qlen: 1000,
                    rx: Counters {
                        bytes: 18_422_901,
                        packets: 23_017,
                    },
                    tx: Counters {
                        bytes: 2_908_114,
                        packets: 14_320,
                    },
                },
            ],
            routes: vec![
                Route {
                    dest: [0; 4],
                    prefix: 0,
                    gateway: Some([192, 168, 1, 1]),
                    dev: "wlan0",
                    proto: "static",
                    src: None,
                    metric: 0,
                },
                Route {
                    dest: [192, 168, 1, 0],
                    prefix: 24,
                    gateway: None,
                    dev: "wlan0",
                    proto: "kernel",
                    src: Some([192, 168, 1, 23]),
                    metric: 0,
                },
            ],
            neighbors: vec![Neighbor {
                addr: [192, 168, 1, 1],
                mac: [0xa4, 0x2b, 0xb0, 0x5e, 0x17, 0x90],
                dev: "wlan0",
            }],
            listeners: vec![Listener {
                backlog: 4,
                ..Listener::wildcard(true, 5555, "adbd", 4_821, 6)
            }],
        }
    }

    fn iface(&self, name: &str) -> Option<&Iface> {
        self.ifaces.iter().find(|iface| iface.name == name)
    }
}

// ------------------------------------------------------------------------------------ formatting

fn v4_text(addr: V4) -> String {
    let [a, b, c, d] = addr;
    format!("{a}.{b}.{c}.{d}")
}

fn mac_text(mac: Mac) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

fn mask_bits(prefix: u8) -> u32 {
    let shift = 32u32.saturating_sub(u32::from(prefix));
    u32::MAX.checked_shl(shift).unwrap_or(0)
}

fn mask_of(prefix: u8) -> V4 {
    mask_bits(prefix).to_be_bytes()
}

fn broadcast_of(addr: V4, prefix: u8) -> V4 {
    (u32::from_be_bytes(addr) | !mask_bits(prefix)).to_be_bytes()
}

/// `/proc/net`'s byte order: the address as the kernel's little-endian word, in upper-case hex.
fn hex_v4(addr: V4) -> String {
    format!("{:08X}", u32::from_le_bytes(addr))
}

/// `text` followed by spaces up to `width` characters, as the kernel pads its `/proc/net` lines.
fn padded(text: &str, width: usize) -> String {
    format!("{text:<width$}\n")
}

impl Iface {
    fn broadcast(&self) -> V4 {
        broadcast_of(self.addr, self.prefix)
    }

    fn link_kind(&self) -> &'static str {
        if self.loopback { "loopback" } else { "ether" }
    }

    fn link_broadcast(&self) -> String {
        if self.loopback {
            mac_text([0; 6])
        } else {
            mac_text([0xff; 6])
        }
    }

    fn ip_flags(&self) -> &'static str {
        if self.loopback {
            "LOOPBACK,UP,LOWER_UP"
        } else {
            "BROADCAST,MULTICAST,UP,LOWER_UP"
        }
    }

    fn ip_state(&self) -> &'static str {
        if self.loopback { "UNKNOWN" } else { "UP" }
    }

    fn v6_scope(&self) -> &'static str {
        if self.loopback { "host" } else { "link" }
    }

    /// net-tools' `Flg` letters for `netstat -i`.
    fn flag_letters(&self) -> &'static str {
        if self.loopback { "LRU" } else { "BMRU" }
    }
}

impl Route {
    fn flags(&self) -> &'static str {
        if self.gateway.is_some() { "UG" } else { "U" }
    }
}

// ---------------------------------------------------------------------------------- the commands

impl FakeShell {
    /// The persona's network model.
    fn net_model(&self) -> Net {
        match self.flavor {
            ShellFlavor::AndroidSh => Net::android(),
            ShellFlavor::Bash => Net::ubuntu(self.ctx.protocol_label == "telnet"),
        }
    }

    /// The default route's gateway: the synthetic resolver `nslookup` and `dig` name, so the
    /// name tools and `ip route` cannot disagree about the one nameserver the box has.
    pub(super) fn model_gateway(&self) -> [u8; 4] {
        self.net_model()
            .routes
            .iter()
            .find(|route| route.prefix == 0)
            .and_then(|route| route.gateway)
            .unwrap_or([127, 0, 0, 1])
    }

    /// The addresses of every interface but loopback, as `hostname -I` lists them, from the one
    /// network model `ip addr` renders.
    pub(super) fn interface_addresses(&self) -> Vec<String> {
        self.net_model()
            .ifaces
            .iter()
            .filter(|iface| !iface.loopback)
            .map(|iface| v4_text(iface.addr))
            .collect()
    }

    /// The pid and name a listener shows: the modeled process of that name, or none if the table
    /// holds no such process.
    fn listener_owner(&self, listener: &Listener) -> Option<(u32, &'static str)> {
        self.listener_pid(listener.comm)
            .map(|pid| (pid, listener.comm))
    }
}

/// Which address family a command was restricted to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Any,
    V4,
    V6,
}

fn nothing() -> CommandResult {
    CommandResult::silent(0)
}

// -------------------------------------------------------------------------------------------- ip

#[derive(Clone, Copy, PartialEq, Eq)]
enum Object {
    Address,
    Link,
    Route,
    Neighbor,
}

/// The objects `ip` knows and this model does not answer, which succeed silently.
const OTHER_OBJECTS: [&str; 20] = [
    "addrlabel",
    "fou",
    "ila",
    "l2tp",
    "macsec",
    "maddress",
    "monitor",
    "mroute",
    "mrule",
    "netconf",
    "netns",
    "nexthop",
    "ntable",
    "rule",
    "tcpmetrics",
    "token",
    "tunnel",
    "tuntap",
    "vrf",
    "xfrm",
];

fn is_prefix(word: &str, full: &str) -> bool {
    !word.is_empty() && full.starts_with(word)
}

fn object_of(word: &str) -> Option<Object> {
    if is_prefix(word, "address") {
        Some(Object::Address)
    } else if is_prefix(word, "link") {
        Some(Object::Link)
    } else if is_prefix(word, "route") {
        Some(Object::Route)
    } else if is_prefix(word, "neighbor") || is_prefix(word, "neighbour") {
        Some(Object::Neighbor)
    } else {
        None
    }
}

/// Whether `word` is a spelling of the default listing subcommand.
fn is_show(word: &str) -> bool {
    is_prefix(word, "show") || is_prefix(word, "list") || word == "lst"
}

impl FakeShell {
    /// `ip [-4|-6] {address|link|route|neighbour} [show [dev IFACE]]`. Changing anything
    /// (`add`, `del`, `set`) succeeds silently and changes nothing [unverified].
    pub(super) fn cmd_ip(&mut self, parts: &[&str]) -> CommandResult {
        let net = self.net_model();
        let mut family = Family::Any;
        let mut args = parts.get(1..).unwrap_or(&[]);
        while let Some(&option) = args.first() {
            if !option.starts_with('-') {
                break;
            }
            match option {
                "-4" => family = Family::V4,
                "-6" => family = Family::V6,
                _ => return nothing(),
            }
            args = args.get(1..).unwrap_or(&[]);
        }
        let Some(&word) = args.first() else {
            return nothing();
        };
        let Some(object) = object_of(word) else {
            if OTHER_OBJECTS.iter().any(|name| is_prefix(word, name)) {
                return nothing();
            }
            return CommandResult::stderr(
                1,
                format!("Object \"{word}\" is unknown, try \"ip help\".\n"),
            );
        };
        let rest = args.get(1..).unwrap_or(&[]);
        match rest.first() {
            Some(&sub) if !is_show(sub) => return nothing(),
            _ => {}
        }
        let tail = rest.get(1..).unwrap_or(&[]);
        let device = match tail {
            [] => None,
            ["dev", name] | [name] if object != Object::Route && *name != "up" => Some(*name),
            _ => return nothing(),
        };
        if let Some(name) = device
            && net.iface(name).is_none()
        {
            return CommandResult::stderr(1, format!("Device \"{name}\" does not exist.\n"));
        }
        let text = match object {
            Object::Address => ip_addr(&net, family, device),
            Object::Link => ip_link(&net, device),
            Object::Route => ip_route(&net, family),
            Object::Neighbor => ip_neigh(&net, family),
        };
        CommandResult::stdout(text)
    }
}

fn ip_head(net: &Net, iface: &Iface, link_view: bool) -> String {
    let mode = if link_view { " mode DEFAULT" } else { "" };
    let group = if net.modern { " group default" } else { "" };
    let qlen = if iface.qlen == 0 {
        String::new()
    } else {
        format!(" qlen {}", iface.qlen)
    };
    format!(
        "{}: {}: <{}> mtu {} qdisc {} state {}{mode}{group}{qlen}\n    link/{} {} brd {}\n",
        iface.index,
        iface.name,
        iface.ip_flags(),
        iface.mtu,
        iface.qdisc,
        iface.ip_state(),
        iface.link_kind(),
        mac_text(iface.mac),
        iface.link_broadcast(),
    )
}

fn ip_addr(net: &Net, family: Family, device: Option<&str>) -> String {
    let mut out = String::new();
    for iface in net
        .ifaces
        .iter()
        .filter(|i| device.is_none_or(|d| d == i.name))
    {
        out.push_str(&ip_head(net, iface, false));
        if family != Family::V6 {
            let brd = if iface.loopback {
                String::new()
            } else {
                format!(" brd {}", v4_text(iface.broadcast()))
            };
            let scope = if iface.loopback { "host" } else { "global" };
            out.push_str(&format!(
                "    inet {}/{}{brd} scope {scope} {}\n       valid_lft forever preferred_lft forever\n",
                v4_text(iface.addr),
                iface.prefix,
                iface.name,
            ));
        }
        if family != Family::V4 {
            out.push_str(&format!(
                "    inet6 {}/{} scope {} \n       valid_lft forever preferred_lft forever\n",
                iface.v6,
                iface.v6_prefix,
                iface.v6_scope(),
            ));
        }
    }
    out
}

fn ip_link(net: &Net, device: Option<&str>) -> String {
    net.ifaces
        .iter()
        .filter(|i| device.is_none_or(|d| d == i.name))
        .map(|iface| ip_head(net, iface, true))
        .collect()
}

fn ip_route(net: &Net, family: Family) -> String {
    let mut out = String::new();
    if family == Family::V6 {
        for iface in &net.ifaces {
            let (dest, metric) = if iface.loopback {
                (iface.v6.to_string(), 256)
            } else {
                ("fe80::/64".to_string(), 256)
            };
            out.push_str(&format!(
                "{dest} dev {} proto kernel metric {metric} pref medium\n",
                iface.name
            ));
        }
        return out;
    }
    for route in &net.routes {
        let dest = if route.prefix == 0 {
            "default".to_string()
        } else {
            format!("{}/{}", v4_text(route.dest), route.prefix)
        };
        out.push_str(&dest);
        if let Some(gateway) = route.gateway {
            out.push_str(&format!(" via {}", v4_text(gateway)));
        }
        out.push_str(&format!(" dev {} proto {}", route.dev, route.proto));
        if route.gateway.is_none() {
            out.push_str(" scope link");
        }
        if let Some(src) = route.src {
            out.push_str(&format!(" src {}", v4_text(src)));
        }
        if route.metric != 0 {
            out.push_str(&format!(" metric {}", route.metric));
        }
        out.push('\n');
    }
    out
}

fn ip_neigh(net: &Net, family: Family) -> String {
    if family == Family::V6 {
        return String::new();
    }
    net.neighbors
        .iter()
        .map(|n| {
            format!(
                "{} dev {} lladdr {} REACHABLE\n",
                v4_text(n.addr),
                n.dev,
                mac_text(n.mac)
            )
        })
        .collect()
}

// ------------------------------------------------------------------------------------------ ifconfig

impl FakeShell {
    /// Toolbox's `ifconfig [-a] [IFACE]`: one line per interface, `NAME: ip A mask M flags [...]`.
    /// Configuring an interface (`ifconfig wlan0 down`) succeeds silently and changes nothing
    /// [unverified], and an unknown name fails without text.
    pub(super) fn cmd_ifconfig(&mut self, parts: &[&str]) -> CommandResult {
        let net = self.net_model();
        let args = parts.get(1..).unwrap_or(&[]);
        let wanted = match args {
            [] | ["-a"] => None,
            [name] if !name.starts_with('-') => Some(*name),
            _ => return nothing(),
        };
        let mut out = String::new();
        for iface in net
            .ifaces
            .iter()
            .filter(|i| wanted.is_none_or(|w| w == i.name))
        {
            let flags = if iface.loopback {
                "up loopback running"
            } else {
                "up broadcast running multicast"
            };
            out.push_str(&format!(
                "{}: ip {} mask {} flags [{flags}]\n",
                iface.name,
                v4_text(iface.addr),
                v4_text(mask_of(iface.prefix)),
            ));
        }
        if out.is_empty() {
            return CommandResult::silent(1);
        }
        CommandResult::stdout(out)
    }
}

// ------------------------------------------------------------------------------- routing tables

/// net-tools' `route`: `-n` prints numbers, otherwise the default route is `default` and an
/// on-link route's gateway is `*`.
fn route_text(net: &Net, numeric: bool) -> String {
    let mut out = String::from(
        "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n",
    );
    for route in &net.routes {
        let dest = if route.prefix == 0 && !numeric {
            "default".to_string()
        } else {
            v4_text(route.dest)
        };
        let gateway = match route.gateway {
            Some(addr) => v4_text(addr),
            None if numeric => v4_text([0; 4]),
            None => "*".to_string(),
        };
        out.push_str(&format!(
            "{dest:<15} {gateway:<15} {:<15} {:<5} {:<6} {:<2} {:>7} {}\n",
            v4_text(mask_of(route.prefix)),
            route.flags(),
            route.metric,
            0,
            0,
            route.dev,
        ));
    }
    out
}

/// net-tools' `netstat -r`.
fn netstat_routes(net: &Net, numeric: bool) -> String {
    let mut out = String::from(
        "Kernel IP routing table\nDestination     Gateway         Genmask         Flags   MSS Window  irtt Iface\n",
    );
    for route in &net.routes {
        let dest = if route.prefix == 0 && !numeric {
            "default".to_string()
        } else {
            v4_text(route.dest)
        };
        let gateway = route.gateway.map_or_else(|| v4_text([0; 4]), v4_text);
        out.push_str(&format!(
            "{dest:<15} {gateway:<15} {:<16}{:<6} {:>5} {:<5} {:>6} {}\n",
            v4_text(mask_of(route.prefix)),
            route.flags(),
            0,
            0,
            0,
            route.dev,
        ));
    }
    out
}

/// net-tools' `netstat -i`.
fn netstat_ifaces(net: &Net) -> String {
    let mut out = String::from(
        "Kernel Interface table\nIface             MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg\n",
    );
    for iface in &net.ifaces {
        out.push_str(&format!(
            "{:<15} {:>5} {:>8} {:>6} {:>6} {:>6} {:>8} {:>6} {:>6} {:>6} {}\n",
            iface.name,
            iface.mtu,
            iface.rx.packets,
            0,
            0,
            0,
            iface.tx.packets,
            0,
            0,
            0,
            iface.flag_letters(),
        ));
    }
    out
}

impl FakeShell {
    /// `route [-n]`. Adding or deleting a route succeeds silently and changes nothing
    /// [unverified].
    pub(super) fn cmd_route(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let numeric = match args {
            [] => false,
            ["-n"] => true,
            _ => return nothing(),
        };
        CommandResult::stdout(route_text(&self.net_model(), numeric))
    }
}

// ----------------------------------------------------------------------------------------- netstat

/// What a `netstat` command line asks for.
#[derive(Default)]
struct NetstatPlan {
    tcp: bool,
    udp: bool,
    unix: bool,
    listening: bool,
    all: bool,
    numeric: bool,
    program: bool,
    routes: bool,
    interfaces: bool,
}

/// The plan for `args`, or `None` for an option this model does not answer.
fn parse_netstat(args: &[&str]) -> Option<NetstatPlan> {
    let mut plan = NetstatPlan::default();
    for &arg in args {
        if let Some(long) = arg.strip_prefix("--") {
            match long {
                "tcp" => plan.tcp = true,
                "udp" => plan.udp = true,
                "unix" => plan.unix = true,
                "listening" => plan.listening = true,
                "all" => plan.all = true,
                "numeric" => plan.numeric = true,
                "programs" => plan.program = true,
                "route" => plan.routes = true,
                "interfaces" => plan.interfaces = true,
                _ => return None,
            }
            continue;
        }
        let flags = arg.strip_prefix('-').filter(|f| !f.is_empty())?;
        for flag in flags.chars() {
            match flag {
                't' => plan.tcp = true,
                'u' => plan.udp = true,
                'x' => plan.unix = true,
                'l' => plan.listening = true,
                'a' => plan.all = true,
                'n' => plan.numeric = true,
                'p' => plan.program = true,
                'r' => plan.routes = true,
                'i' => plan.interfaces = true,
                _ => return None,
            }
        }
    }
    Some(plan)
}

impl FakeShell {
    /// Toybox's `netstat`, in net-tools' layout, over the modeled listeners. Only listening
    /// sockets exist in the model, so a plain `netstat` lists none.
    pub(super) fn cmd_netstat(&mut self, parts: &[&str]) -> CommandResult {
        let Some(mut plan) = parse_netstat(parts.get(1..).unwrap_or(&[])) else {
            return nothing();
        };
        let net = self.net_model();
        if plan.routes {
            return CommandResult::stdout(netstat_routes(&net, plan.numeric));
        }
        if plan.interfaces {
            return CommandResult::stdout(netstat_ifaces(&net));
        }
        if !plan.tcp && !plan.udp && !plan.unix {
            plan.tcp = true;
            plan.udp = true;
            plan.unix = true;
        }
        let scope = if plan.all {
            "servers and established"
        } else if plan.listening {
            "only servers"
        } else {
            "w/o servers"
        };
        let mut out = String::new();
        if plan.tcp || plan.udp {
            out.push_str(&format!("Active Internet connections ({scope})\n"));
            out.push_str(
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State      ",
            );
            out.push_str(if plan.program {
                " PID/Program name    \n"
            } else {
                "\n"
            });
            if (plan.all || plan.listening) && plan.tcp {
                for listener in &net.listeners {
                    out.push_str(&self.netstat_row(listener, plan.program));
                }
            }
        }
        if plan.unix {
            out.push_str(&format!(
                "Active UNIX domain sockets ({scope})\nProto RefCnt Flags       Type       State         I-Node   Path\n"
            ));
        }
        CommandResult::stdout(out)
    }

    fn netstat_row(&self, listener: &Listener, program: bool) -> String {
        let (proto, local, foreign) = if listener.v6 {
            ("tcp6", format!(":::{}", listener.port), ":::*".to_string())
        } else {
            (
                "tcp",
                format!("0.0.0.0:{}", listener.port),
                "0.0.0.0:*".to_string(),
            )
        };
        let mut row = format!(
            "{proto:<5} {:>6} {:>6} {local:<23} {foreign:<23} {:<11}",
            0, 0, "LISTEN"
        );
        if program {
            let owner = self
                .listener_owner(listener)
                .map_or_else(|| "-".to_string(), |(pid, name)| format!("{pid}/{name}"));
            row.push_str(&format!(" {owner:<20}"));
        }
        row.push('\n');
        row
    }
}

// ---------------------------------------------------------------------------------------------- ss

/// The services `ss` names without `-n`, from the `/etc/services` the box would have.
fn service_name(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("ssh"),
        23 => Some("telnet"),
        53 => Some("domain"),
        _ => None,
    }
}

#[derive(Default)]
struct SsPlan {
    tcp: bool,
    udp: bool,
    listening: bool,
    all: bool,
    numeric: bool,
    program: bool,
    no_header: bool,
    family: Option<bool>,
}

fn parse_ss(args: &[&str]) -> Option<SsPlan> {
    let mut plan = SsPlan::default();
    for &arg in args {
        let flags = arg
            .strip_prefix('-')
            .filter(|f| !f.is_empty() && !f.starts_with('-'))?;
        for flag in flags.chars() {
            match flag {
                't' => plan.tcp = true,
                'u' => plan.udp = true,
                'l' => plan.listening = true,
                'a' => plan.all = true,
                'n' => plan.numeric = true,
                'p' => plan.program = true,
                'H' => plan.no_header = true,
                '4' => plan.family = Some(false),
                '6' => plan.family = Some(true),
                _ => return None,
            }
        }
    }
    Some(plan)
}

struct SsRow {
    netid: &'static str,
    state: &'static str,
    recv_q: String,
    send_q: String,
    local_addr: String,
    local_port: String,
    peer_addr: String,
    peer_port: String,
    /// ` users:((...))` with its leading space, or empty.
    process: String,
}

impl FakeShell {
    /// `ss [-tulanpH46]` over the modeled sockets; no socket other than a listening or bound one
    /// exists, so without `-l` or `-a` it lists none. UDP sockets come before TCP ones, as the
    /// kernel's tables give them.
    pub(super) fn cmd_ss(&mut self, parts: &[&str]) -> CommandResult {
        let Some(plan) = parse_ss(parts.get(1..).unwrap_or(&[])) else {
            return nothing();
        };
        let net = self.net_model();
        let neither = !plan.tcp && !plan.udp;
        let (tcp, udp) = (plan.tcp || neither, plan.udp || neither);
        let mut rows = Vec::new();
        if plan.all || plan.listening {
            let mut sockets: Vec<&Listener> = net
                .listeners
                .iter()
                .filter(|l| plan.family.is_none_or(|v6| v6 == l.v6))
                .filter(|l| if l.udp { udp } else { tcp })
                .collect();
            sockets.sort_by_key(|l| !l.udp);
            for listener in sockets {
                let port = match service_name(listener.port) {
                    Some(name) if !plan.numeric => name.to_string(),
                    _ => listener.port.to_string(),
                };
                let (local_addr, peer_addr) = match (listener.bind, listener.v6) {
                    (Some((addr, dev)), _) => (format!("{}%{dev}", v4_text(addr)), "0.0.0.0"),
                    (None, true) => ("[::]".to_string(), "[::]"),
                    (None, false) => ("0.0.0.0".to_string(), "0.0.0.0"),
                };
                let process = match self.listener_owner(listener) {
                    Some((pid, name)) if plan.program => {
                        format!(" users:((\"{name}\",pid={pid},fd={}))", listener.fd)
                    }
                    _ => String::new(),
                };
                rows.push(SsRow {
                    netid: if listener.udp { "udp" } else { "tcp" },
                    state: if listener.udp { "UNCONN" } else { "LISTEN" },
                    recv_q: "0".to_string(),
                    send_q: listener.backlog.to_string(),
                    local_addr,
                    local_port: port,
                    peer_addr: peer_addr.to_string(),
                    peer_port: "*".to_string(),
                    process,
                });
            }
        }
        let netid = tcp && udp;
        CommandResult::stdout(render_ss(&rows, netid, !plan.no_header))
    }
}

/// iproute2 5.15's column layout, recorded on Ubuntu 22.04 (2026-10-07, `ss -tuln | cat -A` and
/// friends): every column as wide as its widest cell or its title, one space between columns, an
/// address right-aligned and its port left-aligned around the `:`, and the `Process` column glued
/// to the peer's port, its cells padded out to its width (so a row ends in spaces) and a `users:`
/// cell carrying its own leading space. `Netid` is shown when both TCP and UDP are listed.
fn render_ss(rows: &[SsRow], netid: bool, header: bool) -> String {
    let width =
        |title: &str, cells: Vec<usize>| cells.into_iter().chain([title.len()]).max().unwrap_or(0);
    let w_state = width("State", rows.iter().map(|r| r.state.len()).collect());
    let w_recv = width("Recv-Q", rows.iter().map(|r| r.recv_q.len()).collect());
    let w_send = width("Send-Q", rows.iter().map(|r| r.send_q.len()).collect());
    let w_laddr = width(
        "Local Address",
        rows.iter().map(|r| r.local_addr.len()).collect(),
    );
    let w_lport = width("Port", rows.iter().map(|r| r.local_port.len()).collect());
    let w_paddr = width(
        "Peer Address",
        rows.iter().map(|r| r.peer_addr.len()).collect(),
    );
    let w_pport = width("Port", rows.iter().map(|r| r.peer_port.len()).collect());
    let w_proc = width("Process", rows.iter().map(|r| r.process.len()).collect());
    let line = |cells: [&str; 10]| {
        let [
            id,
            state,
            recv,
            send,
            laddr,
            lport,
            paddr,
            pport,
            process,
            _,
        ] = cells;
        let mut text = String::new();
        if netid {
            text.push_str(&format!("{id:<5} "));
        }
        text.push_str(&format!(
            "{state:<w_state$} {recv:<w_recv$} {send:<w_send$} {laddr:>w_laddr$}:{lport:<w_lport$} {paddr:>w_paddr$}:{pport:<w_pport$}{process:<w_proc$}\n"
        ));
        text
    };
    let mut out = String::new();
    if header {
        // The titles sit in the address columns: `Local Address` right-aligned to its width, the
        // `Port` titles left-aligned, as the cells are.
        out.push_str(&line([
            "Netid",
            "State",
            "Recv-Q",
            "Send-Q",
            "Local Address",
            "Port",
            "Peer Address",
            "Port",
            "Process",
            "",
        ]));
    }
    for row in rows {
        out.push_str(&line([
            row.netid,
            row.state,
            &row.recv_q,
            &row.send_q,
            &row.local_addr,
            &row.local_port,
            &row.peer_addr,
            &row.peer_port,
            &row.process,
            "",
        ]));
    }
    out
}

// --------------------------------------------------------------------------------------- /proc/net

fn proc_node(text: impl Into<Vec<u8>>, mtime: i64) -> Node {
    let mut node = Node::regular(Blob::from_bytes(text), 0o100_444);
    node.meta.mtime = mtime;
    node
}

const TCP_HEAD: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
const TCP6_HEAD: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
const UDP_HEAD: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops";
const UDP6_HEAD: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops";
const TCP_PAD: usize = 149;
const UDP_PAD: usize = 127;
const ROUTE_PAD: usize = 127;

fn proc_net_dev(net: &Net) -> String {
    let mut out = String::from(
        "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for iface in &net.ifaces {
        out.push_str(&format!(
            "{:>6}:{:>8} {:>7} {:>4} {:>4} {:>4} {:>5} {:>10} {:>9} {:>8} {:>7} {:>4} {:>4} {:>4} {:>5} {:>7} {:>10}\n",
            iface.name,
            iface.rx.bytes,
            iface.rx.packets,
            0,
            0,
            0,
            0,
            0,
            0,
            iface.tx.bytes,
            iface.tx.packets,
            0,
            0,
            0,
            0,
            0,
            0,
        ));
    }
    out
}

fn proc_net_route(net: &Net) -> String {
    let mut out = padded(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
        ROUTE_PAD,
    );
    for route in &net.routes {
        let flags: u32 = if route.gateway.is_some() {
            0x0003
        } else {
            0x0001
        };
        let line = format!(
            "{}\t{}\t{}\t{flags:04X}\t0\t0\t{}\t{}\t0\t0\t0",
            route.dev,
            hex_v4(route.dest),
            hex_v4(route.gateway.unwrap_or([0; 4])),
            route.metric,
            hex_v4(mask_of(route.prefix)),
        );
        out.push_str(&padded(&line, ROUTE_PAD));
    }
    out
}

fn proc_net_arp(net: &Net) -> String {
    let mut out = String::from(
        "IP address       HW type     Flags       HW address            Mask     Device\n",
    );
    for n in &net.neighbors {
        out.push_str(&format!(
            "{:<16} 0x{:<10x}0x{:<10x}{}     *        {}\n",
            v4_text(n.addr),
            1,
            2,
            mac_text(n.mac),
            n.dev,
        ));
    }
    out
}

fn proc_net_tcp(net: &Net, v6: bool) -> String {
    let (head, any) = if v6 {
        (TCP6_HEAD, "0".repeat(32))
    } else {
        (TCP_HEAD, "0".repeat(8))
    };
    let mut out = padded(head, TCP_PAD);
    for (slot, listener) in net
        .listeners
        .iter()
        .filter(|l| l.v6 == v6 && !l.udp)
        .enumerate()
    {
        let local = listener
            .bind
            .map_or_else(|| any.clone(), |(addr, _)| hex_v4(addr));
        let line = format!(
            "{slot:>4}: {local}:{:04X} {any}:0000 0A 00000000:00000000 00:00000000 00000000 {:>5} {:>8} {} 1 0000000000000000 100 0 0 10 0",
            listener.port,
            owner_uid(listener),
            0,
            listener.inode,
        );
        out.push_str(&padded(&line, TCP_PAD));
    }
    out
}

/// `/proc/net/udp`: the bound UDP sockets, in the kernel's layout [unverified slot numbers].
fn proc_net_udp(net: &Net) -> String {
    let mut out = padded(UDP_HEAD, UDP_PAD);
    for listener in net.listeners.iter().filter(|l| !l.v6 && l.udp) {
        let local = listener
            .bind
            .map_or_else(|| "00000000".to_string(), |(addr, _)| hex_v4(addr));
        let slot = u32::from(listener.port) % 1_024;
        let line = format!(
            "{slot:>5}: {local}:{:04X} 00000000:0000 07 00000000:00000000 00:00000000 00000000 {:>5} {:>8} {} 2 0000000000000000 0",
            listener.port,
            owner_uid(listener),
            0,
            listener.inode,
        );
        out.push_str(&padded(&line, UDP_PAD));
    }
    out
}

/// The uid of the account a socket's owner runs as: resolved's own, root for the rest.
fn owner_uid(listener: &Listener) -> u32 {
    if listener.comm == "systemd-resolve" {
        102
    } else {
        0
    }
}

impl FakeShell {
    /// The `/proc/net` directory and its files, for the filesystem's generated layer. Added to
    /// the process nodes, never in place of them.
    pub(super) fn net_nodes(&self, mtime: i64) -> HashMap<String, Node> {
        let net = self.net_model();
        let files: [(&str, String); 7] = [
            ("arp", proc_net_arp(&net)),
            ("dev", proc_net_dev(&net)),
            ("route", proc_net_route(&net)),
            ("tcp", proc_net_tcp(&net, false)),
            ("tcp6", proc_net_tcp(&net, true)),
            ("udp", proc_net_udp(&net)),
            ("udp6", padded(UDP6_HEAD, UDP_PAD)),
        ];
        let mut dir = Node::directory(files.iter().map(|(name, _)| (*name).to_string()).collect());
        dir.meta.mode = 0o040_555;
        dir.meta.mtime = mtime;
        let mut nodes = HashMap::new();
        nodes.insert("/proc/net".to_string(), dir);
        for (name, text) in files {
            nodes.insert(format!("/proc/net/{name}"), proc_node(text, mtime));
        }
        nodes
    }
}
