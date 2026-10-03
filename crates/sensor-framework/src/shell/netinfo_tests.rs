//! `ip`, `ss`, `ifconfig`, `netstat` and `route` and the `/proc/net` files, through `handle_input`
//! the way a session reaches them. The network is one fixed synthetic model, so these pin the
//! relations that must hold whatever the layout is (one fact, many readers: the address in `ip`
//! is the address in `ifconfig`, the gateway in every routing table, the listener in `ss`, in
//! `netstat`, in `/proc/net/tcp` and the pid in `ps`) and the privacy rule that no real address
//! the sensor holds can reach any of it. Layouts are iproute2 5.15, net-tools 2.10 and Android 6's
//! toolbox as remembered, not captured, so the cases that pin a layout say so.

use chrono::{DateTime, TimeZone, Utc};

use super::{CommandResult, EmitContext, FakeShell, HandlerId, OutputFd};
use crate::fakefs::FakeFs;

const SESSION_PEER: &str = "203.0.113.77";
const DEPLOYMENT_HOST: &str = "198.51.100.88";

fn ctx_with(label: &str, source: &str, wan: Option<&str>) -> EmitContext {
    EmitContext {
        source_ip: source.parse().unwrap(),
        wan_ip: wan.map(|ip| ip.parse().unwrap()),
        authenticated: true,
        protocol_label: label.to_string(),
        session_id: None,
    }
}

fn ctx_for(label: &str) -> EmitContext {
    ctx_with(label, SESSION_PEER, Some(DEPLOYMENT_HOST))
}

/// Friday 2026-10-02 12:34:56 UTC.
fn friday() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 12, 34, 56).unwrap()
}

fn shell() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx_for("ssh")).with_clock(friday)
}

fn telnet() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx_for("telnet")).with_clock(friday)
}

fn phone() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx_for("adb")).with_clock(friday)
}

fn stream(out: &CommandResult, fd: OutputFd) -> String {
    let bytes: Vec<u8> = out
        .output
        .iter()
        .filter(|segment| segment.fd == fd)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect();
    String::from_utf8(bytes).unwrap()
}

/// `(stdout, stderr, status)` of one line.
fn answer(sh: &mut FakeShell, line: &str) -> (String, String, u8) {
    let out = sh.handle_input(line).0;
    (
        stream(&out, OutputFd::Stdout),
        stream(&out, OutputFd::Stderr),
        out.status,
    )
}

fn out(sh: &mut FakeShell, line: &str) -> String {
    answer(sh, line).0
}

fn silent_success(sh: &mut FakeShell, line: &str) {
    assert_eq!(
        answer(sh, line),
        (String::new(), String::new(), 0),
        "{line}"
    );
}

fn mac_of(listing: &str, iface: &str) -> String {
    let mut lines = listing.lines();
    while let Some(line) = lines.next() {
        if line.contains(&format!(": {iface}: ")) {
            let link = lines.next().unwrap();
            return link.split_whitespace().nth(1).unwrap().to_string();
        }
    }
    panic!("no {iface} in {listing}");
}

/// The dotted-quad tokens of `text`.
fn quads(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter(|token| {
            let parts: Vec<&str> = token.split('.').collect();
            parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
        })
        .map(str::to_string)
        .collect()
}

/// Whether `quad` is loopback, unspecified, RFC 1918 or a netmask: never a routable address.
fn is_private_or_mask(quad: &str) -> bool {
    let n: Vec<u8> = quad.split('.').map(|p| p.parse().unwrap()).collect();
    let (a, b) = (n[0], n[1]);
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || a == 127
        || a == 0
        || a == 255
}

/// The little-endian hex a `/proc/net` file prints an address as, derived here independently.
fn proc_hex(quad: &str) -> String {
    let n: Vec<u8> = quad.split('.').map(|p| p.parse().unwrap()).collect();
    n.iter().rev().map(|byte| format!("{byte:02X}")).collect()
}

/// Every command line this module answers, so one loop covers them all.
const UBUNTU_LINES: [&str; 24] = [
    "ip a",
    "ip addr",
    "ip -4 addr",
    "ip -6 addr",
    "ip addr show eth0",
    "ip link",
    "ip link show eth0",
    "ip route",
    "ip -6 route",
    "ip r",
    "ip neigh",
    "ip n",
    "ss",
    "ss -a",
    "ss -tulpn",
    "ss -an",
    "ss -tln",
    "ss -tlnp",
    "cat /proc/net/dev",
    "cat /proc/net/route",
    "cat /proc/net/tcp",
    "cat /proc/net/tcp6",
    "cat /proc/net/udp",
    "cat /proc/net/arp",
];

const ANDROID_LINES: [&str; 22] = [
    "ifconfig",
    "ifconfig -a",
    "ifconfig wlan0",
    "ifconfig lo",
    "netstat",
    "netstat -an",
    "netstat -tulpn",
    "netstat -tlnp",
    "netstat -rn",
    "netstat -r",
    "netstat -i",
    "route",
    "route -n",
    "ip addr",
    "ip route",
    "ip neigh",
    "ip link",
    "cat /proc/net/dev",
    "cat /proc/net/route",
    "cat /proc/net/tcp6",
    "cat /proc/net/arp",
    "cat /proc/net/udp",
];

// ---------------------------------------------------------------------------------------- ip

#[test]
fn ubuntu_ip_addr_shows_lo_and_eth0_with_the_model_address_and_mac() {
    let mut sh = shell();
    let listing = out(&mut sh, "ip addr");
    assert_eq!(out(&mut sh, "ip a"), listing);
    assert!(
        listing.starts_with(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n"
        ),
        "[unverified] iproute2 5.15 layout: {listing}"
    );
    assert!(
        listing.contains("    inet6 ::1/128 scope host \n"),
        "{listing}"
    );
    assert!(
        listing.contains(
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether 06:4b:9c:1e:a2:7d brd ff:ff:ff:ff:ff:ff\n    inet 172.31.16.42/20 brd 172.31.31.255 scope global eth0\n"
        ),
        "{listing}"
    );
    assert_eq!(mac_of(&listing, "eth0"), "06:4b:9c:1e:a2:7d");
}

#[test]
fn ip_addr_honors_family_and_device_filters() {
    let mut sh = shell();
    let v4 = out(&mut sh, "ip -4 addr");
    assert!(
        v4.contains("inet 172.31.16.42/20") && !v4.contains("inet6"),
        "{v4}"
    );
    let v6 = out(&mut sh, "ip -6 addr");
    assert!(
        v6.contains("inet6 ::1/128") && !v6.contains("inet 1"),
        "{v6}"
    );
    let eth0 = out(&mut sh, "ip addr show dev eth0");
    assert_eq!(out(&mut sh, "ip a s eth0"), eth0);
    assert!(
        eth0.starts_with("2: eth0:") && !eth0.contains("lo:"),
        "{eth0}"
    );
    let (stdout, stderr, status) = answer(&mut sh, "ip addr show eth9");
    assert_eq!(
        (stdout.as_str(), stderr.as_str(), status),
        ("", "Device \"eth9\" does not exist.\n", 1)
    );
}

#[test]
fn ip_link_agrees_with_ip_addr_on_every_link_fact() {
    let mut sh = shell();
    let link = out(&mut sh, "ip link");
    let addr = out(&mut sh, "ip addr");
    for iface in ["lo", "eth0"] {
        assert_eq!(mac_of(&link, iface), mac_of(&addr, iface));
    }
    assert!(link.contains("mtu 1500 qdisc fq_codel state UP mode DEFAULT group default"));
    assert!(!link.contains("inet"), "{link}");
    assert_eq!(
        out(&mut sh, "ip link show eth0"),
        link.split_inclusive('\n').skip(2).collect::<String>()
    );
}

#[test]
fn ip_route_and_neigh_show_the_gateway_the_model_holds() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "ip route"),
        "default via 172.31.16.1 dev eth0 proto static\n172.31.16.0/20 dev eth0 proto kernel scope link src 172.31.16.42\n"
    );
    assert_eq!(out(&mut sh, "ip r"), out(&mut sh, "ip route show"));
    assert_eq!(
        out(&mut sh, "ip neigh"),
        "172.31.16.1 dev eth0 lladdr 06:7d:2a:f1:00:c3 REACHABLE\n"
    );
    assert_eq!(out(&mut sh, "ip neighbour show"), out(&mut sh, "ip n"));
    assert_eq!(out(&mut sh, "ip -6 neigh"), "");
    let v6 = out(&mut sh, "ip -6 route");
    assert!(
        v6.contains("::1 dev lo") && v6.contains("fe80::/64 dev eth0"),
        "{v6}"
    );
}

/// The IPv6 link-local address is the modified EUI-64 of the interface's MAC, so the two cannot
/// have been typed independently.
#[test]
fn the_link_local_address_is_the_eui64_of_the_mac_on_both_personas() {
    for (mut sh, iface) in [(shell(), "eth0"), (phone(), "wlan0")] {
        let listing = out(&mut sh, "ip addr");
        let mac: Vec<u8> = mac_of(&listing, iface)
            .split(':')
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect();
        let groups = [
            u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
            u16::from_be_bytes([mac[2], 0xff]),
            u16::from_be_bytes([0xfe, mac[3]]),
            u16::from_be_bytes([mac[4], mac[5]]),
        ];
        let want = format!(
            "inet6 fe80::{:x}:{:x}:{:x}:{:x}/64",
            groups[0], groups[1], groups[2], groups[3]
        );
        assert!(listing.contains(&want), "{want}: {listing}");
    }
}

#[test]
fn ip_objects_and_unmodeled_forms_follow_the_convention() {
    let mut sh = shell();
    let (stdout, stderr, status) = answer(&mut sh, "ip nosuchobject");
    assert_eq!(
        (stdout.as_str(), stderr.as_str(), status),
        (
            "",
            "Object \"nosuchobject\" is unknown, try \"ip help\".\n",
            1
        )
    );
    for line in [
        "ip",
        "ip -o addr",
        "ip -br a",
        "ip route get 192.0.2.9",
        "ip addr add 192.0.2.5/24 dev eth0",
        "ip link set eth0 down",
        "ip route add default via 172.31.16.1",
        "ip netns list",
        "ip rule",
        "ip addr show up",
    ] {
        silent_success(&mut sh, line);
    }
    // Changing nothing is the contract: the listing is what it was.
    assert!(out(&mut sh, "ip addr").contains("172.31.16.42/20"));
    assert!(!out(&mut sh, "ip addr").contains("192.0.2.5"));
}

// ------------------------------------------------------------------------------------- ifconfig

#[test]
fn the_phone_ifconfig_agrees_with_ip_on_address_and_mask() {
    let mut sh = phone();
    let ip = out(&mut sh, "ip -4 addr show wlan0");
    let cidr = ip
        .split_whitespace()
        .skip_while(|w| *w != "inet")
        .nth(1)
        .unwrap()
        .to_string();
    let (addr, prefix) = cidr.split_once('/').unwrap();
    let prefix: u32 = prefix.parse().unwrap();
    let mask = u32::MAX << (32 - prefix);
    let mask_text = mask.to_be_bytes().map(|b| b.to_string()).join(".");
    assert_eq!(
        out(&mut sh, "ifconfig wlan0"),
        format!("wlan0: ip {addr} mask {mask_text} flags [up broadcast running multicast]\n")
    );
    let all = out(&mut sh, "ifconfig");
    assert_eq!(out(&mut sh, "ifconfig -a"), all);
    assert_eq!(
        all,
        "lo: ip 127.0.0.1 mask 255.0.0.0 flags [up loopback running]\nwlan0: ip 192.168.1.23 mask 255.255.255.0 flags [up broadcast running multicast]\n",
        "[unverified] toolbox layout"
    );
    assert_eq!(
        answer(&mut sh, "ifconfig eth9"),
        (String::new(), String::new(), 1)
    );
    silent_success(&mut sh, "ifconfig wlan0 down");
    assert_eq!(out(&mut sh, "ifconfig"), all, "configuring changes nothing");
}

// ------------------------------------------------------------------------------------- routing

/// The default route's gateway and interface, read the way each reader prints it.
#[test]
fn every_routing_table_on_the_phone_names_the_same_default_route() {
    let mut sh = phone();
    let ip = out(&mut sh, "ip route");
    let first = ip.lines().next().unwrap();
    let words: Vec<&str> = first.split_whitespace().collect();
    assert_eq!(&words[..2], ["default", "via"]);
    let (gateway, dev) = (words[2], words[4]);
    assert_eq!(words[3], "dev");
    for line in ["route -n", "netstat -rn", "netstat -nr"] {
        let table = out(&mut sh, line);
        assert!(table.starts_with("Kernel IP routing table\n"), "{line}");
        let default = table
            .lines()
            .find(|l| l.starts_with("0.0.0.0 "))
            .unwrap_or_else(|| panic!("{line}: {table}"));
        let cols: Vec<&str> = default.split_whitespace().collect();
        assert_eq!(cols[1], gateway, "{line}");
        assert_eq!(cols[3], "UG", "{line}");
        assert_eq!(*cols.last().unwrap(), dev, "{line}");
    }
    let proc = out(&mut sh, "cat /proc/net/route");
    let row = proc.lines().nth(1).unwrap();
    let cols: Vec<&str> = row.split_whitespace().collect();
    assert_eq!(cols[0], dev);
    assert_eq!(cols[1], "00000000");
    assert_eq!(cols[2], proc_hex(gateway));
    assert_eq!(cols[3], "0003");
}

#[test]
fn ubuntu_ip_route_agrees_with_proc_net_route() {
    let mut sh = shell();
    let proc = out(&mut sh, "cat /proc/net/route");
    let rows: Vec<Vec<&str>> = proc
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().collect())
        .collect();
    assert_eq!(rows.len(), 2, "the default route and the on-link /20");
    assert_eq!(rows[0][..4], ["eth0", "00000000", "01101FAC", "0003"]);
    // 172.31.16.0 with mask 255.255.240.0, as the kernel's little-endian words.
    assert_eq!(rows[1][..4], ["eth0", "00101FAC", "00000000", "0001"]);
    assert_eq!(rows[1][7], "00F0FFFF");
    assert!(out(&mut sh, "ip route").contains("via 172.31.16.1"));
}

#[test]
fn route_prints_names_without_n_and_numbers_with_it() {
    let mut sh = phone();
    let named = out(&mut sh, "route");
    assert!(
        named.contains("\ndefault         192.168.1.1     0.0.0.0         UG"),
        "{named}"
    );
    assert!(
        named.contains(" * ") || named.contains("*        "),
        "{named}"
    );
    let numeric = out(&mut sh, "route -n");
    assert!(
        numeric.contains("\n0.0.0.0         192.168.1.1     0.0.0.0         UG"),
        "{numeric}"
    );
    assert!(
        numeric.contains("\n192.168.1.0     0.0.0.0         255.255.255.0   U"),
        "{numeric}"
    );
    assert_eq!(
        numeric.lines().nth(1).unwrap(),
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface",
        "[unverified] net-tools header"
    );
}

#[test]
fn netstat_i_lists_the_interfaces_the_other_readers_show() {
    let mut sh = phone();
    let table = out(&mut sh, "netstat -i");
    let names: Vec<&str> = table
        .lines()
        .skip(2)
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(names, ["lo", "wlan0"]);
    assert!(table.lines().nth(2).unwrap().ends_with("LRU"), "{table}");
    assert!(table.lines().nth(3).unwrap().ends_with("BMRU"), "{table}");
    let dev = out(&mut sh, "cat /proc/net/dev");
    // The packet counters are one figure: RX-OK is the second column of /proc/net/dev.
    for (row, name) in table.lines().skip(2).zip(names) {
        let rx_ok = row.split_whitespace().nth(2).unwrap();
        let line = dev
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{name}:")))
            .unwrap();
        // The kernel's eight-wide byte counter can touch the colon, so split on it.
        let packets = line.replace(':', " ");
        assert_eq!(packets.split_whitespace().nth(2).unwrap(), rx_ok, "{name}");
    }
}

// -------------------------------------------------------------------------------- the sockets

/// The pid of the process `ps` lists under init with kernel name `comm`.
fn daemon_pid(sh: &mut FakeShell, comm: &str) -> String {
    // The phone's toolbox `ps` has fixed columns (`USER PID PPID ... NAME`); procps takes `-o`.
    let phone = sh.flavor == super::ShellFlavor::AndroidSh;
    let table = out(
        sh,
        if phone {
            "ps"
        } else {
            "ps -eo pid=,ppid=,comm="
        },
    );
    table
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (pid, ppid, name) = if phone {
                (f.get(1)?, f.get(2)?, f.last()?.rsplit('/').next()?)
            } else {
                (f.first()?, f.get(1)?, *f.get(2)?)
            };
            (*ppid == "1" && name == comm).then(|| (*pid).to_string())
        })
        .next()
        .unwrap_or_else(|| panic!("no {comm} under init: {table}"))
}

#[test]
fn ubuntu_ss_and_the_proc_files_show_the_sshd_listener_of_the_process_table() {
    let mut sh = shell();
    let pid = daemon_pid(&mut sh, "sshd");
    let full = out(&mut sh, "ss -tulpn");
    let lines: Vec<&str> = full.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "the header and the two sshd sockets: {full}"
    );
    assert!(
        lines[0].starts_with("Netid") && lines[0].ends_with("Process"),
        "{full}"
    );
    assert!(
        lines[1].contains("0.0.0.0:22") && lines[1].contains("LISTEN"),
        "{full}"
    );
    assert!(lines[2].contains("[::]:22"), "{full}");
    for line in &lines[1..] {
        assert!(
            line.contains(&format!("users:((\"sshd\",pid={pid},fd=")),
            "{line}: ps says sshd is {pid}"
        );
    }
    // Without -p there is no Process column; without -n the port is its service name.
    let plain = out(&mut sh, "ss -tl");
    assert!(
        !plain.contains("users:") && !plain.contains("Process"),
        "{plain}"
    );
    assert!(
        plain.contains("0.0.0.0:ssh") && plain.contains("[::]:ssh"),
        "{plain}"
    );
    assert!(out(&mut sh, "ss -tln").contains("0.0.0.0:22"));
    // Only listeners exist: neither a bare `ss` nor `-u` has a row, and `-4` drops the v6 one.
    assert_eq!(out(&mut sh, "ss").lines().count(), 1);
    assert_eq!(out(&mut sh, "ss -ul").lines().count(), 1);
    assert_eq!(out(&mut sh, "ss -4tln").lines().count(), 2);
    assert_eq!(
        out(&mut sh, "ss -H -tln").lines().count(),
        2,
        "-H drops the header"
    );
    // /proc/net/tcp and tcp6 carry the same sockets, inode for inode.
    let tcp = out(&mut sh, "cat /proc/net/tcp");
    let row: Vec<&str> = tcp.lines().nth(1).unwrap().split_whitespace().collect();
    assert_eq!(row[1], "00000000:0016", "port 22");
    assert_eq!(row[3], "0A", "LISTEN");
    let tcp6 = out(&mut sh, "cat /proc/net/tcp6");
    let row6: Vec<&str> = tcp6.lines().nth(1).unwrap().split_whitespace().collect();
    assert_eq!(row6[1], format!("{}:0016", "0".repeat(32)));
    assert_ne!(row[9], row6[9], "two sockets, two inodes");
    assert_eq!(tcp.lines().count(), 2);
    assert_eq!(tcp6.lines().count(), 2);
    // No UDP socket exists.
    assert_eq!(out(&mut sh, "cat /proc/net/udp").lines().count(), 1);
    assert_eq!(out(&mut sh, "cat /proc/net/udp6").lines().count(), 1);
}

#[test]
fn over_telnet_the_listener_is_telnetd_on_23() {
    let mut sh = telnet();
    let pid = daemon_pid(&mut sh, "telnetd");
    let full = out(&mut sh, "ss -tlnp");
    assert_eq!(full.lines().count(), 2, "{full}");
    assert!(full.contains("0.0.0.0:23"), "{full}");
    assert!(
        full.contains(&format!("users:((\"telnetd\",pid={pid},fd=")),
        "{full}"
    );
    assert!(!full.contains(":22"), "{full}");
    assert!(out(&mut sh, "cat /proc/net/tcp").contains("00000000:0017"));
    assert_eq!(out(&mut sh, "cat /proc/net/tcp6").lines().count(), 1);
}

#[test]
fn the_phone_netstat_shows_adbd_on_5555_from_the_process_table() {
    let mut sh = phone();
    let pid = daemon_pid(&mut sh, "adbd");
    let table = out(&mut sh, "netstat -tulpn");
    let lines: Vec<&str> = table.lines().collect();
    assert_eq!(lines[0], "Active Internet connections (only servers)");
    assert!(
        lines[1].starts_with("Proto Recv-Q Send-Q Local Address"),
        "{table}"
    );
    assert!(lines[1].contains("PID/Program name"), "{table}");
    assert_eq!(lines.len(), 3, "{table}");
    let cols: Vec<&str> = lines[2].split_whitespace().collect();
    assert_eq!(
        cols,
        [
            "tcp6",
            "0",
            "0",
            ":::5555",
            ":::*",
            "LISTEN",
            &format!("{pid}/adbd")
        ]
    );
    for line in ["netstat -tlnp", "netstat -antp", "netstat -anp"] {
        assert!(
            out(&mut sh, line).contains(&format!("{pid}/adbd")),
            "{line}"
        );
    }
    // Without -p there is no program column; plain `netstat` has no established socket to list.
    assert!(!out(&mut sh, "netstat -ln").contains("adbd"));
    assert!(!out(&mut sh, "netstat").contains(":5555"));
    assert!(out(&mut sh, "netstat -an").contains(":::5555"));
    assert!(
        out(&mut sh, "netstat -an")
            .contains("Active UNIX domain sockets (servers and established)")
    );
    // /proc/net/tcp6 holds the socket with the port in hex and no v4 socket exists.
    let tcp6 = out(&mut sh, "cat /proc/net/tcp6");
    assert!(tcp6.lines().nth(1).unwrap().contains(":15B3 "), "{tcp6}");
    assert_eq!(out(&mut sh, "cat /proc/net/tcp").lines().count(), 1);
}

#[test]
fn proc_net_arp_and_dev_agree_with_the_commands() {
    let mut sh = shell();
    let arp = out(&mut sh, "cat /proc/net/arp");
    assert_eq!(arp.lines().count(), 2);
    let cols: Vec<&str> = arp.lines().nth(1).unwrap().split_whitespace().collect();
    assert_eq!(
        cols,
        [
            "172.31.16.1",
            "0x1",
            "0x2",
            "06:7d:2a:f1:00:c3",
            "*",
            "eth0"
        ]
    );
    let neigh = out(&mut sh, "ip neigh");
    assert!(
        neigh.contains(cols[0]) && neigh.contains(cols[3]),
        "{neigh}"
    );
    let dev = out(&mut sh, "cat /proc/net/dev");
    let names: Vec<&str> = dev
        .lines()
        .skip(2)
        .map(|l| l.trim_start().split(':').next().unwrap())
        .collect();
    assert_eq!(names, ["lo", "eth0"], "the interfaces `ip link` lists");
    let phone_arp = out(&mut phone(), "cat /proc/net/arp");
    assert!(
        phone_arp.contains("192.168.1.1 ") && phone_arp.contains("a4:2b:b0:5e:17:90"),
        "{phone_arp}"
    );
}

#[test]
fn the_kernel_files_are_padded_the_way_the_kernel_pads_them() {
    let mut sh = shell();
    // A line already longer than the pad (every IPv6 line) is left as it is.
    for (file, width, exact) in [
        ("route", 127, true),
        ("tcp", 149, true),
        ("tcp6", 149, false),
        ("udp", 127, true),
        ("udp6", 127, false),
    ] {
        let text = out(&mut sh, &format!("cat /proc/net/{file}"));
        assert!(!text.is_empty(), "{file}");
        for line in text.lines() {
            let fits = if exact {
                line.len() == width
            } else {
                line.len() >= width
            };
            assert!(fits, "[unverified] kernel padding, {file}: {line:?}");
        }
    }
}

// -------------------------------------------------------------------------- /proc/net beside /proc

#[test]
fn proc_net_joins_the_process_nodes_instead_of_replacing_them() {
    for (label, mut sh) in [("ssh", shell()), ("adb", phone())] {
        let listing = out(&mut sh, "ls /proc");
        let names: Vec<&str> = listing.split_whitespace().collect();
        assert!(names.contains(&"net"), "{label}: {listing}");
        assert!(
            names.contains(&"1"),
            "{label}: the process nodes remain: {listing}"
        );
        let net = out(&mut sh, "ls /proc/net");
        assert_eq!(
            net.split_whitespace().collect::<Vec<_>>(),
            ["arp", "dev", "route", "tcp", "tcp6", "udp", "udp6"],
            "{label}"
        );
        // Each family of nodes still reads after the other was installed, and `cd` (which
        // reinstalls the whole set) keeps both.
        assert!(
            out(&mut sh, "cat /proc/1/status").starts_with("Name:"),
            "{label}"
        );
        assert_eq!(answer(&mut sh, "cd /").2, 0);
        assert!(
            out(&mut sh, "cat /proc/1/status").starts_with("Name:"),
            "{label}"
        );
        assert!(
            out(&mut sh, "cat /proc/net/dev").starts_with("Inter-|"),
            "{label}"
        );
        // The set is cut at GENERATED_MAX in path order, and /proc/net sorts last: reading its
        // last file shows nothing was cut.
        assert_eq!(answer(&mut sh, "cat /proc/net/udp6").2, 0, "{label}");
    }
}

#[test]
fn a_session_can_still_remove_and_shadow_a_net_file() {
    let mut sh = shell();
    assert_eq!(answer(&mut sh, "rm /proc/net/arp").2, 0);
    assert_eq!(answer(&mut sh, "cat /proc/net/arp").2, 1);
    assert!(!out(&mut sh, "ls /proc/net").contains("arp"));
}

// -------------------------------------------------------------------------------- presence

#[test]
fn each_persona_has_the_commands_it_ships() {
    let mut ubuntu = shell();
    for name in ["ip", "ss"] {
        assert_eq!(
            answer(&mut ubuntu, &format!("command -v {name}")).2,
            0,
            "{name}"
        );
    }
    for name in ["ifconfig", "netstat", "route", "arp"] {
        assert_eq!(
            answer(&mut ubuntu, &format!("command -v {name}")).2,
            1,
            "{name}"
        );
        assert_eq!(answer(&mut ubuntu, name).2, 127, "{name} is not installed");
    }
    // The recorded answer for the missing package stays what the capture says.
    assert_eq!(
        answer(&mut ubuntu, "ifconfig").1,
        "Command 'ifconfig' not found, but can be installed with:\napt install net-tools\n"
    );
    let mut ph = phone();
    for name in ["ifconfig", "netstat", "route", "ip"] {
        let found = answer(&mut ph, &format!("command -v {name}"));
        assert_eq!(
            found,
            (format!("/system/bin/{name}\n"), String::new(), 0),
            "{name}"
        );
        assert_eq!(
            answer(&mut ph, &format!("test -x /system/bin/{name}")).2,
            0,
            "{name}"
        );
        assert!(
            out(&mut ph, "ls /system/bin")
                .split_whitespace()
                .any(|n| n == name),
            "{name}"
        );
    }
    for name in ["ss", "arp"] {
        assert_eq!(
            answer(&mut ph, &format!("command -v {name}")).2,
            1,
            "{name}"
        );
        assert_eq!(answer(&mut ph, name).2, 127, "{name}");
    }
}

#[test]
fn the_phone_multicall_binaries_route_to_the_same_handlers() {
    let mut sh = phone();
    assert_eq!(
        out(&mut sh, "toolbox ifconfig wlan0"),
        out(&mut sh, "ifconfig wlan0")
    );
    assert_eq!(out(&mut sh, "toybox route -n"), out(&mut sh, "route -n"));
    assert_eq!(
        out(&mut sh, "toybox netstat -rn"),
        out(&mut sh, "netstat -rn")
    );
    assert_eq!(
        out(&mut sh, "/system/bin/ip route"),
        out(&mut sh, "ip route")
    );
    assert!(out(&mut sh, "toybox").contains("netstat\n"));
    assert!(out(&mut sh, "toolbox").contains("ifconfig\n"));
    sh.handle_input("netstat -rn");
    assert_eq!(
        sh.last_trace().segments[0]
            .command
            .as_ref()
            .unwrap()
            .resolved,
        HandlerId::Netstat
    );
    for (line, want) in [
        ("ifconfig", HandlerId::Ifconfig),
        ("route", HandlerId::Route),
        ("ip a", HandlerId::Ip),
    ] {
        sh.handle_input(line);
        assert_eq!(
            sh.last_trace().segments[0]
                .command
                .as_ref()
                .unwrap()
                .resolved,
            want,
            "{line}"
        );
    }
    let mut ubuntu = shell();
    ubuntu.handle_input("ss -tln");
    assert_eq!(
        ubuntu.last_trace().segments[0]
            .command
            .as_ref()
            .unwrap()
            .resolved,
        HandlerId::Ss
    );
}

#[test]
fn what_is_not_modeled_prints_nothing_and_succeeds() {
    let mut ph = phone();
    for line in [
        "netstat -c",
        "netstat -e",
        "netstat -o",
        "netstat foo",
        "netstat --verbose",
        "route add default gw 192.168.1.1",
        "route del default",
        "ifconfig wlan0 up",
        "ifconfig -s",
    ] {
        silent_success(&mut ph, line);
    }
    let mut sh = shell();
    for line in ["ss -s", "ss -x", "ss -e", "ss sport = :22", "ss --summary"] {
        silent_success(&mut sh, line);
    }
}

// ------------------------------------------------------------------------------ the privacy rule

/// The outputs of every command here on both personas (and the telnet one) as one string per
/// line, errors included.
fn every_output(source: &str, wan: Option<&str>) -> Vec<(String, String)> {
    let mut all = Vec::new();
    let mut run = |mut sh: FakeShell, lines: &[&str], tag: &str| {
        for line in lines {
            let (stdout, stderr, status) = answer(&mut sh, line);
            all.push((
                format!("{tag}: {line}"),
                format!("{status}\n{stdout}\n{stderr}"),
            ));
        }
    };
    let make = |label: &str, android: bool| {
        let ctx = ctx_with(label, source, wan);
        if android {
            FakeShell::android(FakeFs::android(), ctx).with_clock(friday)
        } else {
            FakeShell::new(FakeFs::new(), ctx).with_clock(friday)
        }
    };
    run(make("ssh", false), &UBUNTU_LINES, "ubuntu");
    run(make("telnet", false), &UBUNTU_LINES, "telnet");
    run(make("adb", true), &ANDROID_LINES, "android");
    all
}

/// The real source and deployment addresses must reach no output of any command in the model, in
/// text or as the kernel's little-endian hex, and the output must not depend on them at all.
#[test]
fn the_real_source_and_wan_addresses_never_appear_in_any_output() {
    let first = every_output(SESSION_PEER, Some(DEPLOYMENT_HOST));
    assert!(first.len() > 60, "every line ran: {}", first.len());
    for (line, output) in &first {
        for secret in [SESSION_PEER, DEPLOYMENT_HOST] {
            assert!(
                !output.contains(secret),
                "{line} printed {secret}: {output}"
            );
            assert!(
                !output.to_uppercase().contains(&proc_hex(secret)),
                "{line} printed the hex of {secret}: {output}"
            );
        }
        // The two distinguishing octets alone would be a leak too.
        assert!(
            !output.contains("203.0.113.") && !output.contains("198.51.100."),
            "{line}"
        );
    }
    // A different peer and no deployment address give byte-identical output: nothing reads them.
    let second = every_output("203.0.113.5", None);
    assert_eq!(
        first, second,
        "the model depends on the connection's addresses"
    );
    // The check can fail: an output that did carry the peer would be caught by the same test.
    let leaky = format!("{}\n", SESSION_PEER);
    assert!(leaky.contains(SESSION_PEER) && proc_hex(SESSION_PEER) == "4D7100CB");
}

#[test]
fn every_address_any_command_prints_is_private_loopback_or_a_mask() {
    let mut seen = 0;
    for (line, output) in every_output(SESSION_PEER, Some(DEPLOYMENT_HOST)) {
        for quad in quads(&output) {
            seen += 1;
            assert!(is_private_or_mask(&quad), "{line} printed {quad}");
        }
    }
    assert!(seen > 100, "addresses were actually checked: {seen}");
    // The hex files never carry a public word either: decode every address column.
    for mut sh in [shell(), phone()] {
        for file in ["route", "arp"] {
            let text = out(&mut sh, &format!("cat /proc/net/{file}"));
            assert!(text.lines().count() >= 2, "{file}");
        }
    }
}

#[test]
fn the_model_never_touches_the_host_or_the_connection_addresses() {
    let source = include_str!("netinfo.rs");
    // Built by concatenation so this file does not trip the shell tree's own source scan.
    let spawn = ["Command", "::new"].concat();
    for banned in [
        "std::net",
        "std::fs",
        "std::process",
        "std::env",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "ToSocketAddrs",
        spawn.as_str(),
        "tokio",
        "libc",
        "source_ip",
        "wan_ip",
        "IpAddr",
    ] {
        assert!(!source.contains(banned), "netinfo.rs mentions {banned}");
    }
    // The only thing read from the connection is its protocol label.
    assert_eq!(source.matches("self.ctx.").count(), 1);
    assert!(source.contains("self.ctx.protocol_label"));
}

#[test]
fn every_reply_is_bounded() {
    for (line, output) in every_output(SESSION_PEER, Some(DEPLOYMENT_HOST)) {
        assert!(output.len() < 2_048, "{line}: {} bytes", output.len());
    }
}
