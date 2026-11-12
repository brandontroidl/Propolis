//! Reading a `tftp` command line: which server and file it names, and whether it fetches or sends.
//!
//! Loaders run three families of `tftp`, and the shell has to read all of them to record what the
//! attacker tried to fetch:
//!
//! - BusyBox: `tftp -g -r REMOTE [-l LOCAL] HOST [PORT]`, flags in any order, `-gr`-style clusters
//!   and attached values (`-rFILE`) included.
//! - tftp-hpa / netkit, one-shot: `tftp HOST [PORT] -c get REMOTE [LOCAL]`. Everything after `-c`
//!   is the command and its arguments. Loaders also write the server last
//!   (`tftp -c get REMOTE HOST`) or inside the file argument (`get HOST:REMOTE`).
//! - `put` / `-p`: an upload to the attacker's server. That fetches nothing, so it yields no
//!   download target and no local file.
//!
//! The URL is only produced when host and file both validate; a token that could make the URL
//! mean something else (a `?`, a `#`, a space, an out-of-range port, a malformed address) leaves
//! the target empty, and the caller records the raw command instead. A URL built from a
//! half-parsed command line reaches the review fetcher as a real target, so none is ever guessed.

use std::net::{Ipv4Addr, Ipv6Addr};

/// What a `tftp` command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Tftp {
    pub op: Op,
    /// `tftp://HOST[:PORT]/FILE`, only for a download whose host and file both validated.
    pub url: Option<String>,
    /// The local file a download writes: the `-l`/second `get` argument, else the remote name.
    /// Independent of the host so a command with an unreadable server still leaves its file.
    pub save: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    Get,
    Put,
}

/// Parse the arguments after the `tftp` token.
pub(super) fn parse(args: &[&str]) -> Tftp {
    let Some(words) = args.iter().map(|a| unquote(a)).collect::<Option<Vec<_>>>() else {
        return unparsed(Op::Get);
    };
    let mut op = Op::Get;
    let (mut remote, mut local): (Option<String>, Option<String>) = (None, None);
    let mut positional: Vec<String> = Vec::new();
    let mut classic: Option<Vec<String>> = None;
    let mut i = 0;
    while let Some(word) = words.get(i) {
        i += 1;
        let cluster = match word.strip_prefix('-') {
            Some(c) if !c.is_empty() && !c.starts_with('-') => c,
            Some(_) if word.starts_with("--") => continue,
            _ => {
                positional.push(word.clone());
                continue;
            }
        };
        for (at, flag) in cluster.char_indices() {
            match flag {
                'g' => op = Op::Get,
                'p' => op = Op::Put,
                'r' | 'l' | 'b' | 'm' | 'R' | 'c' => {
                    let attached = cluster.get(at + flag.len_utf8()..).unwrap_or("");
                    let value = if attached.is_empty() {
                        i += 1;
                        words.get(i - 1).cloned()
                    } else {
                        Some(attached.to_string())
                    };
                    match flag {
                        'r' => remote = value,
                        'l' => local = value,
                        'c' => {
                            // The command and everything after it belong to the tftp prompt.
                            let rest = words.get(i..).unwrap_or(&[]);
                            classic = Some(value.into_iter().chain(rest.iter().cloned()).collect());
                            i = words.len();
                        }
                        _ => {}
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    match classic {
        Some(command) => classic_command(&positional, &command),
        None if op == Op::Put => unparsed(Op::Put),
        None => {
            // BusyBox names the local file after the last component of the remote one
            // (networking/tftp.c, 1.30: `local_file = strrchr(remote_file, '/') + 1`).
            let save = local.clone().or_else(|| {
                remote
                    .as_deref()
                    .map(|r| r.rsplit('/').next().unwrap_or(r).to_string())
            });
            let file = remote.or(local);
            let url = positional.first().and_then(|host| {
                build_url(host, positional.get(1).map(String::as_str), file.as_deref())
            });
            Tftp {
                op: Op::Get,
                url,
                save,
            }
        }
    }
}

/// `tftp [HOST [PORT]] -c COMMAND ARGS...`.
fn classic_command(before: &[String], command: &[String]) -> Tftp {
    let mut it = command.iter();
    let get = match it.next().map(String::as_str) {
        Some("get") => true,
        Some("put") => return unparsed(Op::Put),
        _ => false,
    };
    if !get {
        return unparsed(Op::Get);
    }
    let args: Vec<&str> = it.map(String::as_str).collect();
    let (host, port, remote) = if let Some(host) = before.first() {
        (
            Some(host.as_str()),
            before.get(1).map(String::as_str),
            args.first().copied(),
        )
    } else if args.len() >= 2
        && let Some(last) = args.last().copied()
        && is_ip_literal(last)
    {
        // `get REMOTE [LOCAL] HOST`: only an address is trusted as the trailing server, since a
        // trailing LOCAL file name is also a valid host name.
        (Some(last), None, args.first().copied())
    } else if let Some((host, file)) = args.first().and_then(|a| split_host_file(a)) {
        (Some(host), None, Some(file))
    } else {
        (None, None, None)
    };
    // No local name: a bare `tftp` is not a file on either persona (see the registry), so the
    // prompt form never runs here and has nothing to save.
    Tftp {
        op: Op::Get,
        url: host.and_then(|h| build_url(h, port, remote)),
        save: None,
    }
}

fn unparsed(op: Op) -> Tftp {
    Tftp {
        op,
        url: None,
        save: None,
    }
}

/// Shell quote removal for one token: `'a'`, `"a"` and `\a` become `a`. A token whose quote is
/// never closed (a quoted name with a space, which the whitespace tokenizer has already cut apart)
/// returns `None`, since what follows it is no longer a separate argument.
fn unquote(token: &str) -> Option<String> {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None, '\\') | (Some('"'), '\\') => out.push(chars.next()?),
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            _ => out.push(c),
        }
    }
    quote.is_none().then_some(out)
}

fn build_url(host_token: &str, port_token: Option<&str>, file: Option<&str>) -> Option<String> {
    let (host, inline_port) = split_host_port(host_token)?;
    let port = match (inline_port, port_token) {
        (Some(p), None) | (None, Some(p)) => parse_port(p)?,
        (None, None) => None,
        (Some(_), Some(_)) => return None,
    };
    let host = normalize_host(host)?;
    let file = file?.trim_start_matches('/');
    if file.is_empty() || !file.chars().all(is_file_char) {
        return None;
    }
    Some(super::join_fetch_url(
        "tftp",
        &host,
        port.as_deref(),
        Some(file),
    ))
}

/// A port as URL text. BusyBox accepts the service name `tftp`, which is the default port.
fn parse_port(token: &str) -> Option<Option<String>> {
    if token == "tftp" {
        return Some(None);
    }
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u16 = token.parse().ok().filter(|n| *n != 0)?;
    Some(Some(n.to_string()))
}

/// Split `[v6]:port`, `v4:port` or `name:port` into host and port. A bare IPv6 address, which has
/// several colons, is not split.
fn split_host_port(token: &str) -> Option<(&str, Option<&str>)> {
    if token.starts_with('[') {
        // The brackets stay on the host so `normalize_host` can tell `[v6]` from a bare address.
        let close = token.find(']')?;
        let host = token.get(..=close)?;
        return match token.get(close + 1..)? {
            "" => Some((host, None)),
            rest => Some((host, Some(rest.strip_prefix(':')?))),
        };
    }
    if token.matches(':').count() == 1 {
        let (host, port) = token.split_once(':')?;
        return Some((host, Some(port)));
    }
    Some((token, None))
}

/// `HOST:FILE` or `[v6]:FILE`, the form the tftp prompt's `get` takes.
fn split_host_file(arg: &str) -> Option<(&str, &str)> {
    if let Some(inner) = arg.strip_prefix('[') {
        let (host, rest) = inner.split_once("]:")?;
        return Some((host, rest)).filter(|(h, f)| !f.is_empty() && h.parse::<Ipv6Addr>().is_ok());
    }
    let (host, file) = arg.split_once(':')?;
    (!file.is_empty() && !file.contains(':') && valid_name_or_v4(host)).then_some((host, file))
}

fn is_ip_literal(token: &str) -> bool {
    let inner = token
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(token);
    inner.parse::<Ipv4Addr>().is_ok() || inner.parse::<Ipv6Addr>().is_ok()
}

/// The host as URL text: an IPv4 address, an IPv6 address in brackets, or a DNS name. `None` for
/// anything else, including dotted-number tokens that are not valid IPv4.
fn normalize_host(host: &str) -> Option<String> {
    let inner = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if inner.parse::<Ipv6Addr>().is_ok() {
        return Some(format!("[{inner}]"));
    }
    if host.starts_with('[') {
        return None;
    }
    valid_name_or_v4(host).then(|| host.to_string())
}

fn valid_name_or_v4(host: &str) -> bool {
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host.parse::<Ipv4Addr>().is_ok();
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Characters a file name may carry into the URL path unescaped. Anything else (`?`, `#`, `%`,
/// whitespace, control bytes) would change what the URL means.
fn is_file_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '+' | ',' | '=' | '@' | '~')
}
