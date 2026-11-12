//! Credential redaction for the request event. The platform invariant (see
//! `docs/security/sample-and-credential-privacy.md`) is that a submitted password is never placed
//! in any event field. The SSH sensor meets it by never reading the password into anything that
//! outlives the parser; HTTP cannot, because the credential arrives inside the same bytes (query
//! string, form body, headers) that are the evidence worth keeping. So the evidence is kept with
//! the secret cut out: parameter names and usernames stay (which fields a scanner targets, and
//! with what account, is intelligence), and every value under a password-like name becomes
//! [`REDACTED`].
//!
//! Every function here returns `None` when it replaced nothing, so the handler can leave a
//! credential-free request's fields byte-identical to what they were before redaction existed.
//! The scanners are textual and tolerant: a body cut at the capture cap, or one whose
//! Content-Type lies about its syntax, still has its secrets removed, because each scanner is a
//! no-op on syntax it does not recognise and all of them run. They match the names and shapes
//! real clients send; a sender that disguises its own request (an escaped JSON key, a NUL inside a
//! name) is outside what a textual scanner can promise, and the privacy doc lists those classes.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

/// The text that stands in for a dropped credential: the same marker the review crate's
/// `redact_secrets` writes, so an analyst reads one token across the ledger.
pub const REDACTED: &str = "<redacted>";

/// Parameter, header, cookie and element names whose values are credentials, written with the
/// non-alphanumerics removed. A name matches when, lowercased, it contains `pass` (`password2`,
/// `userpass`, `mot_de_passe`), when its alphanumerics joined equal one of these (`api-key`,
/// `Access.Key`), or when any of its alphanumeric segments does (`client_secret`, `user[pin]`,
/// `auth-token`). Over-matching (`passage`, `compass`) costs a value that was not a secret, the
/// cheap direction under the invariant; under-matching stores a password.
const SECRET_NAMES: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pw",
    "psw",
    "pswd",
    "pass",
    "passcode",
    "passphrase",
    "senha",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "auth",
    "credential",
    "credentials",
    "pin",
    "otp",
];

/// A name ending in one of these describes a credential's kind (`auth_type=basic`,
/// `token_type=bearer`), which is protocol detail worth keeping, not the credential itself.
const KIND_SUFFIXES: &[&str] = &["type", "method", "kind"];

pub fn is_secret_name(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    let segments: Vec<&str> = name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments
        .last()
        .is_some_and(|last| KIND_SUFFIXES.contains(last))
    {
        return false;
    }
    if name.contains("pass") {
        return true;
    }
    let joined = segments.concat();
    SECRET_NAMES.contains(&joined.as_str())
        || segments
            .iter()
            .any(|segment| SECRET_NAMES.contains(segment))
}

/// `key=value&key=value` text (a query string or a url-encoded form) with every non-empty value
/// under a secret name replaced. Pairs split on `&` and on `;`, which PHP and older HTML accept
/// as the separator. Names are percent-decoded for the match only; the text keeps the attacker's
/// own spelling and separators.
pub fn redact_form(text: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(text.len());
    for piece in text.split_inclusive(['&', ';']) {
        let (pair, separator) = match piece.strip_suffix(['&', ';']) {
            Some(pair) => (pair, &piece[pair.len()..]),
            None => (piece, ""),
        };
        match pair.split_once('=') {
            Some((name, value)) if !value.is_empty() && is_secret_name(&percent_decode(name)) => {
                changed = true;
                out.push_str(name);
                out.push('=');
                out.push_str(REDACTED);
            }
            _ => out.push_str(pair),
        }
        out.push_str(separator);
    }
    changed.then_some(out)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The request target with the password of an absolute-form `user:password@host` cut out and
/// any `name=value` pair in the rest (a `;` matrix parameter, a `%3F`-encoded query that the
/// request-line split did not see as a query) treated as form text.
pub fn redact_target(target: &str) -> Option<String> {
    let mut current: Option<String> = None;
    if let Some(scheme_end) = target.find("://") {
        let authority_start = scheme_end + 3;
        let authority_end = target[authority_start..]
            .find(['/', '?', '#'])
            .map_or(target.len(), |at| authority_start + at);
        let authority = &target[authority_start..authority_end];
        if let Some(at) = authority.rfind('@')
            && let Some(colon) = authority[..at].find(':')
            && colon + 1 < at
        {
            current = Some(format!(
                "{}{REDACTED}{}",
                &target[..authority_start + colon + 1],
                &target[authority_start + at..]
            ));
        }
    }
    if let Some(redacted) = redact_form(current.as_deref().unwrap_or(target)) {
        current = Some(redacted);
    }
    current
}

/// JSON text with the value of every `"name": value` pair under a secret name replaced, at any
/// depth, by the quoted marker; a value that is an object or array is replaced whole, since a
/// secret split into fields is still the secret. Works on the text rather than a parsed tree so a
/// body cut at the capture cap (unparseable, its last string possibly unterminated) still loses
/// its secrets: an unterminated secret value is redacted to the end of the text.
pub fn redact_json(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        let Some(quote) = text[i..].find('"').map(|q| i + q) else {
            out.push_str(&text[i..]);
            break;
        };
        out.push_str(&text[i..quote]);
        let Some(name_end) = json_string_end(bytes, quote) else {
            out.push_str(&text[quote..]);
            break;
        };
        out.push_str(&text[quote..=name_end]);
        i = name_end + 1;
        let colon = skip_ws(bytes, i);
        if colon >= bytes.len()
            || bytes[colon] != b':'
            || !is_secret_name(&text[quote + 1..name_end].replace('\\', ""))
        {
            continue;
        }
        let value = skip_ws(bytes, colon + 1);
        if value >= bytes.len() {
            continue;
        }
        let value_end = match bytes[value] {
            b'"' => match json_string_end(bytes, value) {
                Some(end) if end == value + 1 => continue,
                Some(end) => end + 1,
                None => bytes.len(),
            },
            b'{' | b'[' => {
                let end = json_container_end(bytes, value).map_or(bytes.len(), |end| end + 1);
                if text[value + 1..end]
                    .trim_end_matches(['}', ']'])
                    .trim()
                    .is_empty()
                {
                    continue;
                }
                end
            }
            _ => {
                let end = value
                    + bytes[value..]
                        .iter()
                        .take_while(|b| !b",}] \t\r\n".contains(b))
                        .count();
                if end == value {
                    continue;
                }
                end
            }
        };
        out.push_str(&text[i..value]);
        out.push('"');
        out.push_str(REDACTED);
        out.push('"');
        changed = true;
        i = value_end;
    }
    changed.then_some(out)
}

/// The index of the quote closing the JSON string that opens at `start`, honouring backslash
/// escapes; `None` when the text ends first.
fn json_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// The index of the bracket closing the JSON object or array that opens at `start`, with
/// strings skipped so a bracket inside one does not count; `None` when the text ends first.
fn json_container_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = json_string_end(bytes, i)?,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// The boundary a `multipart/*` Content-Type declares, or, when it declares none, the one the
/// body's first delimiter line uses. An empty boundary is no boundary: `--` alone would split
/// the body at every double hyphen.
pub fn multipart_boundary(content_type: &str, body: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    if let Some(at) = lower.find("boundary=") {
        let rest = &content_type[at + "boundary=".len()..];
        let value = rest
            .split(|c: char| c == ';' || c.is_whitespace())
            .next()
            .unwrap_or("")
            .trim_matches('"');
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    let first = body.lines().next()?;
    first
        .strip_prefix("--")
        .map(|b| b.trim_end().to_string())
        .filter(|b| !b.is_empty())
}

/// A `multipart/form-data` body with the content of every part whose `name` is a secret name
/// replaced; part headers, delimiters, line endings and the other parts are untouched.
pub fn redact_multipart(text: &str, boundary: &str) -> Option<String> {
    let delimiter = format!("--{boundary}");
    let mut changed = false;
    let parts: Vec<String> = text
        .split(delimiter.as_str())
        .map(|part| {
            let Some((headers, blank_line, content)) = split_part(part) else {
                return part.to_string();
            };
            let value = content
                .strip_suffix("\r\n")
                .or_else(|| content.strip_suffix('\n'))
                .unwrap_or(content);
            let line_end = &content[value.len()..];
            if value.is_empty() || !part_name(headers).is_some_and(|n| is_secret_name(&n)) {
                return part.to_string();
            }
            changed = true;
            format!("{headers}{blank_line}{REDACTED}{line_end}")
        })
        .collect();
    changed.then(|| parts.join(&delimiter))
}

/// A part split at its first blank line into headers, the blank line as sent (`\r\n\r\n`, or a
/// hand-rolled client's bare `\n\n`) and content.
fn split_part(part: &str) -> Option<(&str, &str, &str)> {
    let bytes = part.as_bytes();
    let mut from = 0;
    while let Some(newline) = part[from..].find('\n').map(|at| from + at) {
        let mut next = newline + 1;
        if bytes.get(next) == Some(&b'\r') {
            next += 1;
        }
        if bytes.get(next) == Some(&b'\n') {
            let start = if newline > 0 && bytes[newline - 1] == b'\r' {
                newline - 1
            } else {
                newline
            };
            return Some((&part[..start], &part[start..=next], &part[next + 1..]));
        }
        from = newline + 1;
    }
    None
}

/// The `name` parameter of a part's Content-Disposition: quoted or a bare token, and only where
/// a parameter starts, so the tail of `filename="x"` is never read as the name.
fn part_name(headers: &str) -> Option<String> {
    let lower = headers.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find("name=").map(|n| from + n) {
        let starts_parameter = at == 0
            || matches!(
                lower.as_bytes()[at - 1],
                b';' | b' ' | b'\t' | b'\r' | b'\n'
            );
        if starts_parameter {
            let rest = &headers[at + "name=".len()..];
            let name = match rest.strip_prefix('"') {
                Some(quoted) => quoted.split('"').next().unwrap_or(""),
                None => rest
                    .split(|c: char| c == ';' || c.is_whitespace())
                    .next()
                    .unwrap_or(""),
            };
            return Some(name.to_string());
        }
        from = at + 1;
    }
    None
}

/// XML-RPC method families whose parameters carry a login: every WordPress, MetaWeblog, Blogger
/// and Movable Type call takes `username, password` among its leading positional parameters, and
/// `system.multicall` wraps any of them. `xmlrpc.php` brute force is the most common
/// credential-carrying request a web honeypot sees.
const XMLRPC_LOGIN_METHODS: &[&str] =
    &["wp.", "metaweblog.", "blogger.", "mt.", "system.multicall"];

/// The XML-RPC scalar wrappers a leaf `<value>` may carry.
const XMLRPC_SCALARS: &[&str] = &[
    "string",
    "i4",
    "int",
    "boolean",
    "double",
    "base64",
    "datetime.iso8601",
];

/// XML text with the content of every element and attribute under a secret name replaced
/// (`<password>`, `<ns:Password>`, `password="..."`), the value of every struct member under a
/// secret name (`<name>password</name><value>...`), and, inside a login-shaped XML-RPC call,
/// every scalar parameter after the first: those parameters are positional and anonymous, so the
/// password cannot be told from the username by name. The first parameter (the username of
/// `wp.getUsersBlogs`, the blog id of the rest) and a multicall member's `methodName` stay.
pub fn redact_xml(text: &str) -> Option<String> {
    let mut current = redact_xml_elements(text);
    if let Some(redacted) = redact_xmlrpc_values(current.as_deref().unwrap_or(text)) {
        current = Some(redacted);
    }
    current
}

fn redact_xml_elements(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        let Some(open) = text[i..].find('<').map(|at| i + at) else {
            out.push_str(&text[i..]);
            break;
        };
        let name_start = open + 1;
        let name_len = bytes[name_start..]
            .iter()
            .take_while(|b| !b" \t\r\n/>".contains(b))
            .count();
        let name = &text[name_start..name_start + name_len];
        let Some(close) = text[name_start + name_len..]
            .find('>')
            .map(|at| name_start + name_len + at)
        else {
            out.push_str(&text[i..]);
            break;
        };
        let is_element = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !is_element {
            out.push_str(&text[i..=close]);
            i = close + 1;
            continue;
        }
        out.push_str(&text[i..name_start + name_len]);
        match redact_attributes(&text[name_start + name_len..close]) {
            Some(attributes) => {
                changed = true;
                out.push_str(&attributes);
            }
            None => out.push_str(&text[name_start + name_len..close]),
        }
        out.push('>');
        i = close + 1;
        let local = name.rsplit(':').next().unwrap_or(name);
        if bytes[close - 1] == b'/' || !is_secret_name(local) {
            continue;
        }
        let closing = format!("</{name}");
        let content_end = text[i..].find(&closing).map_or(bytes.len(), |at| i + at);
        if text[i..content_end].trim().is_empty() {
            continue;
        }
        out.push_str(REDACTED);
        changed = true;
        i = content_end;
    }
    changed.then_some(out)
}

/// The attribute text of one open tag with every quoted value under a secret name replaced; an
/// unterminated value (a body cut at the cap) is replaced to the end.
fn redact_attributes(attributes: &str) -> Option<String> {
    let bytes = attributes.as_bytes();
    let mut out = String::with_capacity(attributes.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        let Some(eq) = attributes[i..].find('=').map(|at| i + at) else {
            out.push_str(&attributes[i..]);
            break;
        };
        let name = attributes[i..eq]
            .trim()
            .rsplit(char::is_whitespace)
            .next()
            .unwrap_or("");
        let secret = is_secret_name(name.rsplit(':').next().unwrap_or(name));
        let quote_at = skip_ws(bytes, eq + 1);
        let Some(&quote) = bytes.get(quote_at).filter(|b| matches!(**b, b'"' | b'\'')) else {
            out.push_str(&attributes[i..=eq]);
            i = eq + 1;
            continue;
        };
        let value_start = quote_at + 1;
        match attributes[value_start..]
            .find(quote as char)
            .map(|at| value_start + at)
        {
            Some(end) if end == value_start || !secret => {
                out.push_str(&attributes[i..=end]);
                i = end + 1;
            }
            Some(end) => {
                out.push_str(&attributes[i..value_start]);
                out.push_str(REDACTED);
                out.push(quote as char);
                changed = true;
                i = end + 1;
            }
            None if secret && value_start < bytes.len() => {
                out.push_str(&attributes[i..value_start]);
                out.push_str(REDACTED);
                changed = true;
                break;
            }
            None => {
                out.push_str(&attributes[i..]);
                break;
            }
        }
    }
    changed.then_some(out)
}

fn redact_xmlrpc_values(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let login = lower
        .find("<methodname>")
        .map(|at| at + "<methodname>".len())
        .and_then(|start| {
            lower[start..]
                .find("</methodname>")
                .map(|end| lower[start..start + end].trim().to_string())
        })
        .is_some_and(|method| {
            XMLRPC_LOGIN_METHODS
                .iter()
                .any(|family| method.starts_with(family))
        });
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut leaves = 0usize;
    let mut i = 0;
    let mut from = 0;
    while let Some(open) = lower[from..].find("<value>").map(|at| from + at) {
        let after = open + "<value>".len();
        from = after;
        let mut content_start = skip_ws(bytes, after);
        if bytes.get(content_start) == Some(&b'<') {
            let Some(tag_end) = lower[content_start..]
                .find('>')
                .map(|at| content_start + at)
            else {
                break;
            };
            if !XMLRPC_SCALARS.contains(&&lower[content_start + 1..tag_end]) {
                continue;
            }
            content_start = tag_end + 1;
        }
        let content_end = lower[content_start..]
            .find("</")
            .map_or(bytes.len(), |at| content_start + at);
        let content = &text[content_start..content_end];
        if content.contains('<') {
            continue;
        }
        let index = leaves;
        leaves += 1;
        if content.trim().is_empty() {
            continue;
        }
        let member = member_name(&lower[..open]);
        let positional_secret = login && index > 0 && member != Some("methodname");
        if !(positional_secret || member.is_some_and(is_secret_name)) {
            continue;
        }
        out.push_str(&text[i..content_start]);
        out.push_str(REDACTED);
        changed = true;
        i = content_end;
        from = content_end;
    }
    out.push_str(&text[i..]);
    changed.then_some(out)
}

/// The `<name>` of the struct member whose `<value>` opens right after `prefix`, if one does.
fn member_name(prefix: &str) -> Option<&str> {
    let mut start = prefix.len().saturating_sub(256);
    while !prefix.is_char_boundary(start) {
        start += 1;
    }
    let tail = prefix[start..].trim_end().strip_suffix("</name>")?;
    tail.rsplit_once("<name>").map(|(_, name)| name.trim())
}

/// The whole captured body with its credentials removed, whatever its declared Content-Type: a
/// multipart body is handled by its boundary, and every body goes through the JSON, XML and form
/// scanners, which are no-ops on syntax they do not see. `None` when there was nothing to redact.
pub fn redact_body(body: &str, content_type: Option<&str>) -> Option<String> {
    let content_type = content_type.unwrap_or("");
    let mut current: Option<String> = None;
    if content_type.to_ascii_lowercase().contains("multipart/")
        && let Some(boundary) = multipart_boundary(content_type, body)
        && let Some(redacted) = redact_multipart(body, &boundary)
    {
        current = Some(redacted);
    }
    for scanner in [redact_json, redact_xml, redact_form] {
        if let Some(redacted) = scanner(current.as_deref().unwrap_or(body)) {
            current = Some(redacted);
        }
    }
    current
}

/// The IANA-registered HTTP authentication schemes plus the common unregistered ones. A lone
/// word that is one of these is a scheme with nothing after it; any other lone word is the
/// credential itself, sent without its scheme word.
const AUTH_SCHEMES: &[&str] = &[
    "basic",
    "bearer",
    "digest",
    "hoba",
    "mutual",
    "negotiate",
    "ntlm",
    "oauth",
    "privatetoken",
    "scram-sha-1",
    "scram-sha-256",
    "vapid",
    "dpop",
    "aws4-hmac-sha256",
    "token",
    "apikey",
];

/// What an `Authorization` or `Proxy-Authorization` value may leave in the event: its scheme,
/// and for `Basic` the username from the decoded `user:password` pair, for `Digest` the
/// `username` field. The password, a bearer token, a digest response, or anything else after
/// the scheme is dropped.
pub struct AuthHeader {
    /// The scheme word, or [`REDACTED`] when the value had no recognisable one (a bare token or
    /// Basic blob sent without its scheme word is the credential, not a scheme).
    pub scheme: String,
    pub username: Option<String>,
    /// Whether a credential was dropped: false for a scheme word alone.
    pub credential_dropped: bool,
}

pub fn redact_authorization(value: &str) -> Option<AuthHeader> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (word, credentials) = value.split_once(char::is_whitespace).unwrap_or((value, ""));
    let credentials = credentials.trim();
    let known = AUTH_SCHEMES.contains(&word.to_ascii_lowercase().as_str());
    // RFC 7235: `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`. A token68 is
    // itself a valid token, so a lone unknown word is read as the credential, never the scheme.
    let scheme = if known || (!credentials.is_empty() && is_token(word)) {
        word.to_string()
    } else {
        REDACTED.to_string()
    };
    let username = if word.eq_ignore_ascii_case("basic") {
        basic_username(credentials)
    } else if word.eq_ignore_ascii_case("digest") {
        digest_username(credentials)
    } else {
        None
    };
    Some(AuthHeader {
        credential_dropped: !credentials.is_empty() || scheme == REDACTED,
        scheme,
        username,
    })
}

/// RFC 7230 `token`: one or more `tchar`.
fn is_token(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn basic_username(encoded: &str) -> Option<String> {
    let decoded = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded.trim_end_matches('=')))
        .ok()?;
    let decoded = String::from_utf8_lossy(&decoded).into_owned();
    decoded.split_once(':').map(|(user, _)| user.to_string())
}

/// The `username="..."` (or bare token) field of a Digest challenge response; the `response`,
/// `cnonce` and the rest are dropped with the credentials.
fn digest_username(credentials: &str) -> Option<String> {
    let lower = credentials.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find("username=").map(|n| from + n) {
        let starts_field = at == 0 || matches!(lower.as_bytes()[at - 1], b',' | b' ' | b'\t');
        if starts_field {
            let rest = &credentials[at + "username=".len()..];
            let name = match rest.strip_prefix('"') {
                Some(quoted) => quoted.split('"').next().unwrap_or(""),
                None => rest.split(',').next().unwrap_or("").trim(),
            };
            return (!name.is_empty()).then(|| name.to_string());
        }
        from = at + 1;
    }
    None
}

/// A `Cookie` header with every non-empty value replaced; cookie names and separators stay. A
/// token without `=` is a value with no name (a raw session or API token sent as the whole
/// header) and is replaced too.
pub fn redact_cookie(value: &str) -> Option<String> {
    let mut changed = false;
    let cookies: Vec<String> = value
        .split(';')
        .map(|cookie| match cookie.split_once('=') {
            Some((name, v)) if !v.trim().is_empty() => {
                changed = true;
                format!("{name}={REDACTED}")
            }
            Some(_) => cookie.to_string(),
            None if cookie.trim().is_empty() => cookie.to_string(),
            None => {
                changed = true;
                let lead = cookie.len() - cookie.trim_start().len();
                format!("{}{REDACTED}", &cookie[..lead])
            }
        })
        .collect();
    changed.then(|| cookies.join(";"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_names_match_whole_words_segments_and_pass() {
        for name in [
            "password",
            "PASSWORD",
            "Passwd",
            "pwd",
            "pass",
            "passphrase",
            "secret",
            "token",
            "api_key",
            "ApiKey",
            "access_key",
            "auth",
            "credential",
            "pin",
            "otp",
            "new_password2",
            "user[password]",
            "client_secret",
            "auth-token",
            "user[pin]",
            // Names real login forms and scanners use that the first list missed.
            "userpass",
            "loginpass",
            "pass1",
            "passcode",
            "credentials",
            "api-key",
            "access-key",
            "pw",
            "psw",
            "pswd",
            "senha",
            "mot_de_passe",
            // Over-matched on purpose: a non-secret value lost costs less than a password kept.
            "passage",
        ] {
            assert!(is_secret_name(name), "{name}");
        }
        for name in [
            "username",
            "user",
            "email",
            "q",
            "lang",
            "pinned",
            "x-api-version",
            // The kind of a credential is protocol detail, not the credential.
            "auth_type",
            "token_type",
            "auth-method",
            "grant_type",
        ] {
            assert!(!is_secret_name(name), "{name}");
        }
    }

    #[test]
    fn form_keeps_names_and_usernames_and_drops_secret_values() {
        assert_eq!(
            redact_form("username=admin&password=hunter2&remember=1").as_deref(),
            Some("username=admin&password=<redacted>&remember=1")
        );
        assert_eq!(
            redact_form("user=admin&pass%5Fword=x").as_deref(),
            Some("user=admin&pass%5Fword=<redacted>")
        );
        assert_eq!(
            redact_form("user=a;password=x;next=/").as_deref(),
            Some("user=a;password=<redacted>;next=/"),
            "a semicolon separates pairs the way PHP reads it"
        );
    }

    #[test]
    fn form_without_a_secret_or_with_an_empty_one_is_unchanged() {
        assert_eq!(redact_form("q=test&lang=en"), None);
        assert_eq!(redact_form("user=admin&pass="), None);
        assert_eq!(redact_form(""), None);
    }

    #[test]
    fn target_drops_the_userinfo_password_and_encoded_query_secrets() {
        assert_eq!(
            redact_target("http://admin:hunter2@example.com/").as_deref(),
            Some("http://admin:<redacted>@example.com/")
        );
        assert_eq!(
            redact_target("http://admin@example.com/?x=1"),
            None,
            "a username alone is kept"
        );
        assert_eq!(
            redact_target("/login%3Fpassword=hunter2").as_deref(),
            Some("/login%3Fpassword=<redacted>")
        );
        assert_eq!(
            redact_target("/cgi;password=x").as_deref(),
            Some("/cgi;password=<redacted>")
        );
        assert_eq!(redact_target("/../../../etc/passwd"), None);
        assert_eq!(redact_target("http://example.com/a:b@c"), None);
    }

    #[test]
    fn json_redacts_at_any_depth_and_keeps_the_rest_byte_for_byte() {
        let body = r#"{"user": "admin", "password": "hun\"ter2", "pin": 1234, "nested": {"creds": {"token": "abc"}}, "ok": true}"#;
        assert_eq!(
            redact_json(body).as_deref(),
            Some(
                r#"{"user": "admin", "password": "<redacted>", "pin": "<redacted>", "nested": {"creds": {"token": "<redacted>"}}, "ok": true}"#
            )
        );
        assert_eq!(redact_json(r#"{"user":"admin","lang":"en"}"#), None);
        assert_eq!(redact_json(r#"{"password":""}"#), None);
        assert_eq!(
            redact_json(r#"["password", "token"]"#),
            None,
            "a secret name that is a value is not a secret"
        );
    }

    #[test]
    fn json_secret_container_is_replaced_whole() {
        assert_eq!(
            redact_json(r#"{"password":["hunter2"],"x":1}"#).as_deref(),
            Some(r#"{"password":"<redacted>","x":1}"#)
        );
        assert_eq!(
            redact_json(r#"{"password":{"value":"hun]ter2","n":[1,{"a":"}"}]},"user":"admin"}"#)
                .as_deref(),
            Some(r#"{"password":"<redacted>","user":"admin"}"#)
        );
        assert_eq!(redact_json(r#"{"password":{},"token":[ ]}"#), None);
        assert_eq!(
            redact_json(r#"{"password":{"value":"hunter2 cut"#).as_deref(),
            Some(r#"{"password":"<redacted>""#)
        );
    }

    #[test]
    fn json_cut_at_the_capture_cap_still_loses_the_secret() {
        assert_eq!(
            redact_json(r#"{"user":"admin","password":"hunter2 and the te"#).as_deref(),
            Some(r#"{"user":"admin","password":"<redacted>""#)
        );
    }

    #[test]
    fn multipart_redacts_the_secret_part_only() {
        let body = "--XX\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n--XX\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--XX--\r\n";
        assert_eq!(
            redact_multipart(body, "XX").as_deref(),
            Some(
                "--XX\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n--XX\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n<redacted>\r\n--XX--\r\n"
            )
        );
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"XX\"", "").as_deref(),
            Some("XX")
        );
        assert_eq!(
            multipart_boundary("multipart/form-data", body).as_deref(),
            Some("XX")
        );
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"\"", "--\r\n"),
            None,
            "an empty boundary would split the body at every double hyphen"
        );
    }

    #[test]
    fn multipart_tolerates_what_real_senders_do() {
        assert_eq!(
            redact_multipart(
                "--bb\nContent-Disposition: form-data; name=\"password\"\n\nhunter2\n--bb--\n",
                "bb"
            )
            .as_deref(),
            Some("--bb\nContent-Disposition: form-data; name=\"password\"\n\n<redacted>\n--bb--\n"),
            "bare LF line endings"
        );
        assert_eq!(
            redact_multipart(
                "--bb\r\nContent-Disposition: form-data; filename=\"x\"; name=\"password\"\r\n\r\nhunter2\r\n--bb--\r\n",
                "bb"
            )
            .as_deref(),
            Some(
                "--bb\r\nContent-Disposition: form-data; filename=\"x\"; name=\"password\"\r\n\r\n<redacted>\r\n--bb--\r\n"
            ),
            "filename before name"
        );
        assert_eq!(
            redact_multipart(
                "--bb\r\nContent-Disposition: form-data; name=password\r\n\r\nhunter2\r\n--bb--\r\n",
                "bb"
            )
            .as_deref(),
            Some("--bb\r\nContent-Disposition: form-data; name=password\r\n\r\n<redacted>\r\n--bb--\r\n"),
            "an unquoted name token"
        );
        assert_eq!(
            part_name("Content-Disposition: form-data; filename=\"secret.txt\"").as_deref(),
            None,
            "a filename is not a name"
        );
    }

    #[test]
    fn xml_redacts_secret_elements_attributes_and_members() {
        assert_eq!(
            redact_xml("<login><username>admin</username><password>hunter2</password></login>")
                .as_deref(),
            Some("<login><username>admin</username><password><redacted></password></login>")
        );
        assert_eq!(
            redact_xml(
                "<soap:Body><ns:Password>hunter2</ns:Password><ns:Token/><ns:Empty></ns:Empty></soap:Body>"
            )
            .as_deref(),
            Some("<soap:Body><ns:Password><redacted></ns:Password><ns:Token/><ns:Empty></ns:Empty></soap:Body>")
        );
        assert_eq!(
            redact_xml(r#"<login user="admin" password='hun"ter2' token=""/>"#).as_deref(),
            Some(r#"<login user="admin" password='<redacted>' token=""/>"#)
        );
        assert_eq!(
            redact_xml("<methodCall><methodName>custom.save</methodName><params><param><value><struct><member><name>user</name><value><string>admin</string></value></member><member><name>password</name><value><string>hunter2</string></value></member></struct></value></param></params></methodCall>").as_deref(),
            Some("<methodCall><methodName>custom.save</methodName><params><param><value><struct><member><name>user</name><value><string>admin</string></value></member><member><name>password</name><value><string><redacted></string></value></member></struct></value></param></params></methodCall>")
        );
        assert_eq!(
            redact_xml("<?xml version=\"1.0\"?><a b=\"c\">text</a>"),
            None
        );
        assert_eq!(
            redact_xml("<password>hunter2 cut off").as_deref(),
            Some("<password><redacted>")
        );
        assert_eq!(redact_xml("<password>  </password>"), None);
    }

    #[test]
    fn xmlrpc_login_call_keeps_the_first_parameter_and_drops_the_rest() {
        let call = "<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>hunter2</string></value></param></params></methodCall>";
        assert_eq!(
            redact_xml(call).as_deref(),
            Some(
                "<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string><redacted></string></value></param></params></methodCall>"
            )
        );
        let multicall = "<methodCall><methodName>system.multicall</methodName><params><param><value><array><data><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value>admin</value><value><string>hunter2</string></value></data></array></value></member></struct></value></data></array></value></param></params></methodCall>";
        assert_eq!(
            redact_xml(multicall).as_deref(),
            Some(
                "<methodCall><methodName>system.multicall</methodName><params><param><value><array><data><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><redacted></value><value><string><redacted></string></value></data></array></value></member></struct></value></data></array></value></param></params></methodCall>"
            )
        );
        assert_eq!(
            redact_xml(
                "<methodCall><methodName>demo.sayHello</methodName><params><param><value><string>a</string></value></param><param><value><string>b</string></value></param></params></methodCall>"
            ),
            None,
            "a method outside the login families keeps its parameters"
        );
    }

    #[test]
    fn body_scanners_run_whatever_the_declared_type() {
        assert_eq!(
            redact_body(
                r#"{"password":"x"}"#,
                Some("application/x-www-form-urlencoded")
            )
            .as_deref(),
            Some(r#"{"password":"<redacted>"}"#)
        );
        assert_eq!(
            redact_body("password=x", Some("application/json")).as_deref(),
            Some("password=<redacted>")
        );
        assert_eq!(
            redact_body("<password>x</password>", Some("application/json")).as_deref(),
            Some("<password><redacted></password>")
        );
        assert_eq!(redact_body("GET / HTTP/1.1", None), None);
    }

    #[test]
    fn authorization_keeps_the_scheme_and_only_the_basic_username() {
        let basic = redact_authorization("Basic YWRtaW46aHVudGVyMg==").unwrap();
        assert_eq!(basic.scheme, "Basic");
        assert_eq!(basic.username.as_deref(), Some("admin"));
        assert!(basic.credential_dropped);
        let unpadded = redact_authorization("basic YWRtaW46aHVudGVyMg").unwrap();
        assert_eq!(unpadded.username.as_deref(), Some("admin"));
        let bearer = redact_authorization("Bearer eyJhbGciOiJIUzI1NiJ9.x.y").unwrap();
        assert_eq!(bearer.scheme, "Bearer");
        assert_eq!(bearer.username, None);
        assert_eq!(
            redact_authorization("Basic !!notbase64").unwrap().username,
            None
        );
        assert_eq!(
            redact_authorization("Basic bm9jb2xvbg==").unwrap().username,
            None,
            "a blob without a colon has no username to keep"
        );
        let custom = redact_authorization("X-Custom abc.def").unwrap();
        assert_eq!(custom.scheme, "X-Custom");
        assert!(custom.credential_dropped);
        assert!(redact_authorization("   ").is_none());
    }

    #[test]
    fn authorization_without_a_scheme_word_is_the_credential() {
        for value in ["WlpTRUNSRVRaWjp4", "ZZSECRETZZ", "eyJhbGciOiJIUzI1NiJ9.x.y"] {
            let auth = redact_authorization(value).unwrap();
            assert_eq!(auth.scheme, REDACTED, "{value}");
            assert_eq!(auth.username, None);
            assert!(auth.credential_dropped);
        }
        let alone = redact_authorization("Basic").unwrap();
        assert_eq!(alone.scheme, "Basic");
        assert!(!alone.credential_dropped, "nothing followed the scheme");
        assert_eq!(
            redact_authorization("Basic ").unwrap().scheme,
            "Basic",
            "trailing whitespace is not a credential"
        );
    }

    #[test]
    fn digest_keeps_the_username_field_only() {
        let digest = redact_authorization(
            "Digest username=\"admin\", realm=\"r\", nonce=\"n1\", uri=\"/\", response=\"6629fae49393a05397450978507c4ef1\"",
        )
        .unwrap();
        assert_eq!(digest.scheme, "Digest");
        assert_eq!(digest.username.as_deref(), Some("admin"));
        assert!(digest.credential_dropped);
        assert_eq!(
            redact_authorization("Digest realm=\"r\",username=root,response=\"x\"")
                .unwrap()
                .username
                .as_deref(),
            Some("root")
        );
        assert_eq!(
            redact_authorization("Digest realm=\"r\", response=\"x\"")
                .unwrap()
                .username,
            None
        );
    }

    #[test]
    fn cookie_keeps_names_and_drops_every_value() {
        assert_eq!(
            redact_cookie("session=abc123; theme=dark; flag=").as_deref(),
            Some("session=<redacted>; theme=<redacted>; flag=")
        );
        assert_eq!(
            redact_cookie("ZZSECRETZZ; other").as_deref(),
            Some("<redacted>; <redacted>"),
            "a token without a name is a value"
        );
        assert_eq!(redact_cookie("flag=; "), None);
    }
}
