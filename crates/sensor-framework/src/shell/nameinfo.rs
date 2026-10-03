//! `getent`, `nslookup` and `dig`: the name lookups an enumeration script makes, answered from
//! the modeled `/etc` files and nothing else.
//!
//! There is no resolver here and no outbound query, ever. A name is known exactly when the
//! persona's hosts file lists it (`/etc/hosts` on Ubuntu, `/system/etc/hosts` on the phone); any
//! other name is NXDOMAIN without being looked up, so the shell can neither be used to probe a
//! name nor leak one. The server a lookup names is the synthetic resolver: the nameserver of the
//! modeled `/etc/resolv.conf` when that is a loopback or RFC 1918 address, otherwise the model
//! gateway `ip route` shows (the only resolver on the phone, which has no such file). A server
//! argument typed on the command line is accepted and ignored: nothing is sent to it, and its
//! address is never echoed. No address from the connection or the deployment host is read (the
//! module does not consult the emit context at all), so none can reach an answer.
//!
//! `getent` reads the very files `cat` shows (`hosts`, `ahosts*`, `passwd`, `group`), so the two
//! cannot disagree; a key that is not there is status 2 with no output, as the GNU C library's
//! `getent` answers. `getent
//! hosts` does not go beyond the hosts file, a safe honest subset. `nslookup` answers `A`, `AAAA`
//! and `PTR`; `dig` the same, with `+short`. Other record types on a known name get a bounded
//! NOERROR with no answer. An option not modeled prints nothing and succeeds, never an answer this
//! module made up.
//!
//! Which commands exist is the persona: `getent` (GNU C library) and `dig` (bind9 `dnsutils`) are
//! Ubuntu files [unverified: neither was in the 22.04 recording]. `nslookup` is registered on both personas because BusyBox, which
//! the phone ships, has it as an applet [unverified: stock Android 6 toolbox and toybox have no
//! `nslookup`, so its presence in `/system/bin` is a modeling choice]. It answers in bind's layout
//! on Ubuntu and in BusyBox's on the phone and under `busybox nslookup`.
//!
//! Every layout, wording, version string and status below is composed from knowledge of the GNU C
//! library 2.35, bind 9.18 and BusyBox 1.3x, not from a capture, and is [unverified] unless a comment
//! says otherwise.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor};

pub(super) fn register(r: &mut Registry) {
    r.register_if("getent", ubuntu, HandlerId::Getent, FakeShell::cmd_getent);
    r.register("nslookup", HandlerId::Nslookup, FakeShell::cmd_nslookup);
    r.register_if("dig", ubuntu, HandlerId::Dig, FakeShell::cmd_dig);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

/// The most bytes of a modeled file a lookup reads.
const FILE_MAX: u64 = 65_536;
/// The most hosts, passwd or group rows one lookup considers.
const ENTRY_MAX: usize = 512;
/// The most names one hosts row contributes.
const NAMES_PER_ENTRY: usize = 16;
/// The most command-line words one lookup examines.
const ARGS_MAX: usize = 64;
/// The longest DNS name, and the most of a typed name any answer repeats.
const NAME_MAX: usize = 253;
/// The most of the typed command line `dig` repeats in its banner.
const BANNER_MAX: usize = 256;
/// The fixed TTL of every `dig` answer.
const TTL: u32 = 300;
/// [unverified] the `dig` banner version, Ubuntu 22.04's bind9 9.18 package.
const DIG_VERSION: &str = "9.18.39-0ubuntu0.22.04.1-Ubuntu";

fn nothing() -> CommandResult {
    CommandResult::silent(0)
}

fn with_status(mut result: CommandResult, status: u8) -> CommandResult {
    result.status = status;
    result
}

// -------------------------------------------------------------------------------------- addresses

#[derive(Clone, Copy, PartialEq, Eq)]
enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
}

fn parse_v4(text: &str) -> Option<[u8; 4]> {
    let octets: Vec<u8> = text
        .split('.')
        .map(|part| {
            let digits = !part.is_empty() && part.len() <= 3;
            (digits && part.bytes().all(|b| b.is_ascii_digit()))
                .then(|| part.parse::<u8>().ok())
                .flatten()
        })
        .collect::<Option<_>>()?;
    match octets.as_slice() {
        [a, b, c, d] => Some([*a, *b, *c, *d]),
        _ => None,
    }
}

/// A colon-hex IPv6 literal, without the dotted-quad tail form.
fn parse_v6(text: &str) -> Option<[u8; 16]> {
    if text.len() > 39 || !text.contains(':') {
        return None;
    }
    let (head, tail) = match text.split_once("::") {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    };
    let groups = |part: &str| -> Option<Vec<u16>> {
        if part.is_empty() {
            return Some(Vec::new());
        }
        part.split(':')
            .map(|group| {
                let valid = !group.is_empty()
                    && group.len() <= 4
                    && group.bytes().all(|b| b.is_ascii_hexdigit());
                valid.then(|| u16::from_str_radix(group, 16).ok()).flatten()
            })
            .collect()
    };
    let mut words = groups(head)?;
    match tail {
        None if words.len() != 8 => return None,
        None => {}
        Some(tail) => {
            let tail_words = groups(tail)?;
            let used = words.len().saturating_add(tail_words.len());
            if used > 7 {
                return None;
            }
            words.extend(std::iter::repeat_n(0, 8usize.saturating_sub(used)));
            words.extend(tail_words);
        }
    }
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
    bytes.try_into().ok()
}

fn parse_addr(text: &str) -> Option<Addr> {
    parse_v4(text)
        .map(Addr::V4)
        .or_else(|| parse_v6(text).map(Addr::V6))
}

fn v4_text(addr: [u8; 4]) -> String {
    let [a, b, c, d] = addr;
    format!("{a}.{b}.{c}.{d}")
}

/// Loopback and RFC 1918: the only addresses the synthetic resolver may have.
fn is_private(addr: [u8; 4]) -> bool {
    match addr {
        [127, ..] | [10, ..] | [192, 168, ..] => true,
        [172, second, ..] => (16..=31).contains(&second),
        _ => false,
    }
}

fn is_v6(text: &str) -> bool {
    text.contains(':')
}

/// The reverse-lookup name of `addr`.
fn arpa_name(addr: Addr) -> String {
    match addr {
        Addr::V4([a, b, c, d]) => format!("{d}.{c}.{b}.{a}.in-addr.arpa"),
        Addr::V6(bytes) => {
            let mut name = String::new();
            for byte in bytes.iter().rev() {
                name.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            name.push_str("ip6.arpa");
            name
        }
    }
}

/// The address a reverse-lookup name stands for, if it is one.
fn arpa_addr(name: &str) -> Option<Addr> {
    let lower = name.to_ascii_lowercase();
    if let Some(labels) = lower.strip_suffix(".in-addr.arpa") {
        let mut octets: Vec<&str> = labels.split('.').collect();
        octets.reverse();
        return parse_v4(&octets.join(".")).map(Addr::V4);
    }
    let nibbles = lower.strip_suffix(".ip6.arpa")?;
    let digits: Vec<u8> = nibbles
        .split('.')
        .map(|label| {
            let mut chars = label.chars();
            let digit = chars.next()?.to_digit(16)?;
            chars.next().is_none().then(|| u8::try_from(digit).ok())?
        })
        .collect::<Option<_>>()?;
    if digits.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (slot, pair) in bytes.iter_mut().rev().zip(digits.chunks(2)) {
        if let [low, high] = pair {
            *slot = high.wrapping_shl(4) | low;
        }
    }
    Some(Addr::V6(bytes))
}

// -------------------------------------------------------------------------------------- hosts file

struct HostEntry {
    addr: String,
    names: Vec<String>,
}

struct Hosts(Vec<HostEntry>);

impl Hosts {
    fn parse(text: &str) -> Self {
        Self(
            text.lines()
                .filter_map(|line| {
                    let line = line.split('#').next().unwrap_or("");
                    let mut words = line.split_whitespace();
                    let addr = words.next()?.to_string();
                    let names: Vec<String> =
                        words.take(NAMES_PER_ENTRY).map(str::to_string).collect();
                    (!names.is_empty()).then_some(HostEntry { addr, names })
                })
                .take(ENTRY_MAX)
                .collect(),
        )
    }

    fn matching<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a HostEntry> {
        self.0
            .iter()
            .filter(move |entry| entry.names.iter().any(|n| n.eq_ignore_ascii_case(name)))
    }

    fn known(&self, name: &str) -> bool {
        self.matching(name).next().is_some()
    }

    fn by_addr(&self, addr: Addr) -> Option<&HostEntry> {
        self.0
            .iter()
            .find(|entry| parse_addr(&entry.addr) == Some(addr))
    }

    /// The addresses of one family listed for `name`, in file order, without repeats.
    fn addrs<'a>(&'a self, name: &'a str, v6: bool) -> Vec<&'a str> {
        let mut found: Vec<&str> = Vec::new();
        for entry in self.matching(name).filter(|e| is_v6(&e.addr) == v6) {
            if !found.contains(&entry.addr.as_str()) {
                found.push(&entry.addr);
            }
        }
        found
    }
}

fn host_line(entry: &HostEntry) -> String {
    format!("{:<15} {}\n", entry.addr, entry.names.join(" "))
}

/// A typed name without its trailing dot, capped so no answer repeats an unbounded string.
fn clip(name: &str) -> String {
    name.strip_suffix('.')
        .unwrap_or(name)
        .chars()
        .take(NAME_MAX)
        .collect()
}

impl FakeShell {
    fn read_text(&self, path: &str) -> String {
        let bytes = self.fs.read_all(path, FILE_MAX).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn hosts(&self) -> Hosts {
        let path = match self.flavor {
            ShellFlavor::Bash => "/etc/hosts",
            ShellFlavor::AndroidSh => "/system/etc/hosts",
        };
        Hosts::parse(&self.read_text(path))
    }

    /// The synthetic resolver: the modeled `/etc/resolv.conf`'s first private nameserver, else the
    /// model gateway. Never an address the session typed on a command line.
    fn resolver(&self) -> String {
        if self.flavor == ShellFlavor::Bash {
            let configured = self.read_text("/etc/resolv.conf").lines().find_map(|line| {
                let mut words = line.split_whitespace();
                (words.next()? == "nameserver").then_some(())?;
                parse_v4(words.next()?).filter(|addr| is_private(*addr))
            });
            if let Some(addr) = configured {
                return v4_text(addr);
            }
        }
        v4_text(self.model_gateway())
    }
}

// --------------------------------------------------------------------------------------- getent

const GETENT_TRY: &str = "Try `getent --help' or `getent --usage' for more information.\n";

/// Databases `getent` has that this shell does not model.
const OTHER_DATABASES: [&str; 10] = [
    "aliases",
    "ethers",
    "gshadow",
    "initgroups",
    "netgroup",
    "networks",
    "protocols",
    "rpc",
    "services",
    "shadow",
];

/// The rows of `getent hosts`: the whole file for no key, otherwise per key the entries of the
/// address (a literal) or of the name, IPv6 first as `gethostbyname2` tries it.
fn getent_hosts(hosts: &Hosts, keys: &[&str]) -> (String, bool) {
    let mut out = String::new();
    if keys.is_empty() {
        hosts
            .0
            .iter()
            .for_each(|entry| out.push_str(&host_line(entry)));
        return (out, false);
    }
    let mut missing = false;
    for key in keys {
        let rows: Vec<&HostEntry> = match parse_addr(key) {
            Some(addr) => hosts.by_addr(addr).into_iter().collect(),
            None => {
                let v6: Vec<&HostEntry> = hosts
                    .matching(key)
                    .filter(|entry| is_v6(&entry.addr))
                    .collect();
                if v6.is_empty() {
                    hosts
                        .matching(key)
                        .filter(|entry| !is_v6(&entry.addr))
                        .collect()
                } else {
                    v6
                }
            }
        };
        missing |= rows.is_empty();
        rows.iter()
            .for_each(|entry| out.push_str(&host_line(entry)));
    }
    (out, missing)
}

/// The rows of `getent ahosts`, `ahostsv4` or `ahostsv6`: one STREAM, DGRAM and RAW row per
/// address, the canonical name on the very first.
fn getent_ahosts(hosts: &Hosts, keys: &[&str], v4: bool, v6: bool) -> (String, bool) {
    let mut out = String::new();
    let mut missing = false;
    for key in keys {
        let mut rows: Vec<(&str, &str)> = Vec::new();
        if let Some(addr) = parse_addr(key) {
            if let Some(entry) = hosts.by_addr(addr) {
                let family = is_v6(&entry.addr);
                if (family && v6) || (!family && v4) {
                    let canonical = entry.names.first().map_or("", String::as_str);
                    rows.push((entry.addr.as_str(), canonical));
                }
            }
        } else {
            for (wanted, v6_family) in [(v6, true), (v4, false)] {
                if !wanted {
                    continue;
                }
                let canonical = hosts
                    .matching(key)
                    .next()
                    .and_then(|entry| entry.names.first())
                    .map_or("", String::as_str);
                rows.extend(
                    hosts
                        .addrs(key, v6_family)
                        .into_iter()
                        .map(|a| (a, canonical)),
                );
            }
        }
        missing |= rows.is_empty();
        let mut first = true;
        for (addr, canonical) in rows {
            for kind in ["STREAM", "DGRAM", "RAW"] {
                if first {
                    out.push_str(&format!("{addr:<15} {kind:<6} {canonical}\n"));
                    first = false;
                } else {
                    out.push_str(&format!("{addr:<15} {kind}\n"));
                }
            }
        }
    }
    (out, missing)
}

/// The rows of `getent passwd` or `group`: the file's own lines, all of them for no key, else per
/// key the first row whose name (or, for a number, whose id) it is.
fn getent_rows(text: &str, keys: &[&str]) -> (String, bool) {
    let rows: Vec<&str> = text
        .lines()
        .filter(|line| {
            let line = line.trim_end();
            !line.is_empty() && !line.starts_with('#') && line.split(':').count() >= 3
        })
        .take(ENTRY_MAX)
        .collect();
    let mut out = String::new();
    if keys.is_empty() {
        rows.iter().for_each(|row| {
            out.push_str(row);
            out.push('\n');
        });
        return (out, false);
    }
    let mut missing = false;
    for key in keys {
        let id = (!key.is_empty() && key.bytes().all(|b| b.is_ascii_digit()))
            .then(|| key.parse::<u64>().ok())
            .flatten();
        let found = rows.iter().find(|row| match id {
            Some(id) => {
                row.split(':')
                    .nth(2)
                    .and_then(|field| field.parse::<u64>().ok())
                    == Some(id)
            }
            None => row.split(':').next() == Some(*key),
        });
        match found {
            Some(row) => {
                out.push_str(row);
                out.push('\n');
            }
            None => missing = true,
        }
    }
    (out, missing)
}

impl FakeShell {
    /// `getent DATABASE [KEY...]` over the modeled `hosts`, `passwd` and `group`. A missing key is
    /// status 2 with no output; an unknown database is status 1 with the usage hint, and `ahosts`
    /// cannot be enumerated (status 3), as the GNU C library's `getent` answers.
    pub(super) fn cmd_getent(&mut self, parts: &[&str]) -> CommandResult {
        let args: Vec<&str> = parts
            .get(1..)
            .unwrap_or(&[])
            .iter()
            .copied()
            .take(ARGS_MAX)
            .collect();
        let Some((&database, keys)) = args.split_first() else {
            return CommandResult::stderr(
                64,
                format!("Usage: getent [OPTION...] database [key ...]\n{GETENT_TRY}"),
            );
        };
        if args.iter().any(|arg| arg.starts_with('-')) {
            return nothing();
        }
        let (text, missing) = match database {
            "hosts" => getent_hosts(&self.hosts(), keys),
            "ahosts" | "ahostsv4" | "ahostsv6" => {
                if keys.is_empty() {
                    return CommandResult::stderr(
                        3,
                        format!("Enumeration not supported on {database}\n"),
                    );
                }
                let (v4, v6) = match database {
                    "ahostsv4" => (true, false),
                    "ahostsv6" => (false, true),
                    _ => (true, true),
                };
                getent_ahosts(&self.hosts(), keys, v4, v6)
            }
            "passwd" => getent_rows(&self.read_text("/etc/passwd"), keys),
            "group" => getent_rows(&self.read_text("/etc/group"), keys),
            other if OTHER_DATABASES.contains(&other) => return nothing(),
            other => {
                return CommandResult::stderr(
                    1,
                    format!("Unknown database: {}\n{GETENT_TRY}", clip(other)),
                );
            }
        };
        with_status(CommandResult::stdout(text), if missing { 2 } else { 0 })
    }
}

// ------------------------------------------------------------------------------------ the queries

/// The record types the resolver tools accept, uppercase. A, AAAA and PTR are answered.
const RECORD_TYPES: [&str; 16] = [
    "A", "AAAA", "PTR", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "ANY", "CAA", "DS", "DNSKEY",
    "NAPTR", "SPF", "HINFO",
];

fn record_type(word: &str) -> Option<&'static str> {
    RECORD_TYPES
        .iter()
        .find(|known| known.eq_ignore_ascii_case(word))
        .copied()
}

/// One answer record.
struct Answer {
    rtype: &'static str,
    data: String,
    /// The wire length of the data, for `dig`'s message size.
    rdlen: usize,
}

enum Outcome {
    Answers(Vec<Answer>),
    NoAnswer,
    NxDomain,
}

/// What the hosts file says for a query of `rtype` on `name`: forward for a name, reverse for an
/// address in a reverse zone. A name the file does not list is NXDOMAIN; a listed name with
/// nothing of the asked type is NOERROR with no answer.
fn resolve(hosts: &Hosts, name: &str, rtype: &str) -> Outcome {
    if rtype == "PTR"
        && let Some(addr) = arpa_addr(name)
    {
        return match hosts.by_addr(addr).and_then(|entry| entry.names.first()) {
            Some(target) => Outcome::Answers(vec![Answer {
                rtype: "PTR",
                data: format!("{target}."),
                rdlen: target.len().saturating_add(2),
            }]),
            None => Outcome::NxDomain,
        };
    }
    if !hosts.known(name) {
        return Outcome::NxDomain;
    }
    let (type_name, v6, rdlen) = match rtype {
        "A" => ("A", false, 4),
        "AAAA" => ("AAAA", true, 16),
        _ => return Outcome::NoAnswer,
    };
    let answers: Vec<Answer> = hosts
        .addrs(name, v6)
        .into_iter()
        .map(|addr| Answer {
            rtype: type_name,
            data: addr.to_string(),
            rdlen,
        })
        .collect();
    if answers.is_empty() {
        Outcome::NoAnswer
    } else {
        Outcome::Answers(answers)
    }
}

// ----------------------------------------------------------------------------------------- nslookup

/// The default `nslookup` question: the A answers, then the AAAA answers.
fn resolve_both_families(hosts: &Hosts, name: &str) -> Outcome {
    match (resolve(hosts, name, "A"), resolve(hosts, name, "AAAA")) {
        (Outcome::Answers(mut v4), Outcome::Answers(v6)) => {
            v4.extend(v6);
            Outcome::Answers(v4)
        }
        (Outcome::Answers(answers), _) | (_, Outcome::Answers(answers)) => {
            Outcome::Answers(answers)
        }
        (Outcome::NxDomain, _) | (_, Outcome::NxDomain) => Outcome::NxDomain,
        _ => Outcome::NoAnswer,
    }
}

/// What a `nslookup` command line asks for.
struct NslookupPlan<'a> {
    name: &'a str,
    /// `None` for the default, which asks for both address families.
    rtype: Option<&'static str>,
}

/// The plan for `args`, or `None` when it asks for something this model does not answer: an
/// option other than a record type, or no name (the interactive mode).
fn parse_nslookup<'a>(args: &[&'a str]) -> Option<NslookupPlan<'a>> {
    let mut name = None;
    let mut rtype = None;
    let mut operands = 0usize;
    for &arg in args.iter().take(ARGS_MAX) {
        if let Some(option) = arg.strip_prefix('-').filter(|o| !o.is_empty()) {
            let (key, value) = option.split_once('=')?;
            if !matches!(key, "type" | "querytype" | "query" | "q" | "t") {
                return None;
            }
            rtype = Some(record_type(value)?);
        } else {
            if operands == 0 {
                name = Some(arg);
            }
            operands = operands.saturating_add(1);
        }
    }
    Some(NslookupPlan { name: name?, rtype })
}

impl FakeShell {
    /// `nslookup [-type=T] NAME [SERVER]`. The answer is the hosts file's or NXDOMAIN, headed by
    /// the synthetic resolver; a typed server is ignored (nothing is queried). The status is 1 for
    /// a failed lookup [unverified].
    pub(super) fn cmd_nslookup(&mut self, parts: &[&str]) -> CommandResult {
        let args = parts.get(1..).unwrap_or(&[]);
        let Some(plan) = parse_nslookup(args) else {
            return nothing();
        };
        let busybox = self.flavor == ShellFlavor::AndroidSh || self.busybox_depth > 0;
        let resolver = self.resolver();
        let hosts = self.hosts();
        let name = clip(plan.name);
        let header = if busybox {
            format!("Server:\t\t{resolver}\nAddress:\t{resolver}:53\n\n")
        } else {
            format!("Server:\t\t{resolver}\nAddress:\t{resolver}#53\n\n")
        };
        let literal = parse_addr(&name);
        let reverse = literal.filter(|_| matches!(plan.rtype, None | Some("PTR")));
        let (shown, outcome) = match reverse {
            Some(addr) => {
                let arpa = arpa_name(addr);
                let outcome = resolve(&hosts, &arpa, "PTR");
                (arpa, outcome)
            }
            None => {
                let outcome = match plan.rtype {
                    None => resolve_both_families(&hosts, &name),
                    Some(rtype) => resolve(&hosts, &name, rtype),
                };
                (name.clone(), outcome)
            }
        };
        match outcome {
            Outcome::Answers(answers) => {
                let mut out = format!("{header}Non-authoritative answer:\n");
                for answer in &answers {
                    if answer.rtype == "PTR" {
                        out.push_str(&format!("{shown}\tname = {}\n", answer.data));
                    } else {
                        out.push_str(&format!("Name:\t{name}\nAddress: {}\n", answer.data));
                    }
                }
                out.push('\n');
                CommandResult::stdout(out)
            }
            Outcome::NoAnswer => with_status(
                CommandResult::stdout(format!("{header}*** Can't find {name}: No answer\n\n")),
                1,
            ),
            Outcome::NxDomain => with_status(
                CommandResult::stdout(format!(
                    "{header}** server can't find {shown}: NXDOMAIN\n\n"
                )),
                1,
            ),
        }
    }
}

// --------------------------------------------------------------------------------------------- dig

/// What a `dig` command line asks for.
struct DigPlan {
    name: String,
    rtype: &'static str,
    short: bool,
}

/// The plan for `args`; `Ok(None)` for something this model does not answer (an option beyond
/// `+short`, `-t`, `-x`, `-4`, `-6`, or no name, which asks for the root), `Err` for a malformed
/// reverse address.
fn parse_dig(args: &[&str]) -> Result<Option<DigPlan>, String> {
    let mut name: Option<String> = None;
    let mut rtype: Option<&'static str> = None;
    let mut short = false;
    let mut reverse = None;
    let mut words = args.iter().take(ARGS_MAX).copied();
    while let Some(arg) = words.next() {
        match arg {
            "+short" => short = true,
            "-4" | "-6" => {}
            "-t" => match words.next().and_then(record_type) {
                Some(found) => rtype = Some(found),
                None => return Ok(None),
            },
            "-x" => match words.next() {
                Some(text) => reverse = Some(text),
                None => return Ok(None),
            },
            _ if arg.starts_with('+') || arg.starts_with('-') => return Ok(None),
            _ if arg.starts_with('@') => {}
            _ if name.is_none() && reverse.is_none() => name = Some(clip(arg)),
            _ => {
                if let Some(found) = record_type(arg) {
                    rtype = Some(found);
                }
            }
        }
    }
    if let Some(text) = reverse {
        let Some(addr) = parse_addr(text) else {
            return Err(format!("Invalid IP address {}\n", clip(text)));
        };
        return Ok(Some(DigPlan {
            name: arpa_name(addr),
            rtype: "PTR",
            short,
        }));
    }
    Ok(name.map(|name| DigPlan {
        name,
        rtype: rtype.unwrap_or("A"),
        short,
    }))
}

/// Tabs from column `used` out to the next stop at or past `width`, at least one, as `dig` pads.
fn tabs(used: usize, width: usize) -> String {
    "\t".repeat(width.saturating_sub(used).div_ceil(8).max(1))
}

/// A message id that depends only on the question, so a replay prints the same bytes.
fn query_id(name: &str, rtype: &str) -> u16 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in name.bytes().chain(rtype.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    u16::try_from(hash & 0xffff).unwrap_or(0)
}

impl FakeShell {
    /// `dig [@SERVER] NAME [TYPE] [+short]`, `dig -x ADDR`, `dig -t TYPE NAME`. The reply is the
    /// hosts file's or NXDOMAIN, from the synthetic resolver; the status is 0 either way, as
    /// dig's is. A typed `@SERVER` is ignored.
    pub(super) fn cmd_dig(&mut self, parts: &[&str]) -> CommandResult {
        let plan = match parse_dig(parts.get(1..).unwrap_or(&[])) {
            Ok(Some(plan)) => plan,
            Ok(None) => return nothing(),
            Err(text) => return CommandResult::stderr(1, text),
        };
        let outcome = resolve(&self.hosts(), &plan.name, plan.rtype);
        if plan.short {
            return match outcome {
                Outcome::Answers(answers) => CommandResult::stdout(
                    answers
                        .iter()
                        .map(|answer| format!("{}\n", answer.data))
                        .collect::<String>(),
                ),
                Outcome::NoAnswer | Outcome::NxDomain => nothing(),
            };
        }
        let resolver = self.resolver();
        let (status, answers) = match outcome {
            Outcome::Answers(answers) => ("NOERROR", answers),
            Outcome::NoAnswer => ("NOERROR", Vec::new()),
            Outcome::NxDomain => ("NXDOMAIN", Vec::new()),
        };
        let owner = format!("{}.", plan.name);
        // Header, the question (name, type, class), the answers (a name pointer, type, class, TTL,
        // length, data) and the EDNS record.
        let question = plan.name.len().saturating_add(2).saturating_add(4);
        let records = answers.iter().fold(0usize, |total, answer| {
            total.saturating_add(12).saturating_add(answer.rdlen)
        });
        let size = 12usize
            .saturating_add(question)
            .saturating_add(records)
            .saturating_add(11);
        // The typed words, minus any `@server`: it is ignored, and never repeated.
        let banner: String = parts
            .get(1..)
            .unwrap_or(&[])
            .iter()
            .filter(|word| !word.starts_with('@'))
            .copied()
            .collect::<Vec<&str>>()
            .join(" ")
            .chars()
            .take(BANNER_MAX)
            .collect();
        let mut out = format!(
            "\n; <<>> DiG {DIG_VERSION} <<>> {banner}\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: {status}, id: {}\n;; flags: qr rd ra; QUERY: 1, ANSWER: {}, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 65494\n;; QUESTION SECTION:\n;{owner}{}IN\t{}\n\n",
            query_id(&plan.name, plan.rtype),
            answers.len(),
            tabs(owner.len().saturating_add(1), 32),
            plan.rtype,
        );
        if !answers.is_empty() {
            out.push_str(";; ANSWER SECTION:\n");
            for answer in &answers {
                out.push_str(&format!(
                    "{owner}{}{TTL}\tIN\t{}\t{}\n",
                    tabs(owner.len(), 24),
                    answer.rtype,
                    answer.data,
                ));
            }
            out.push('\n');
        }
        out.push_str(&format!(
            ";; Query time: 0 msec\n;; SERVER: {resolver}#53({resolver}) (UDP)\n;; WHEN: {}\n;; MSG SIZE  rcvd: {size}\n\n",
            self.now().format("%a %b %d %H:%M:%S UTC %Y"),
        ));
        CommandResult::stdout(out)
    }
}
