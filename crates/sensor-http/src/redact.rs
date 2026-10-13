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
//! no-op on syntax it does not recognise and all of them run.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

/// The text that stands in for a dropped credential: the same marker the review crate's
/// `redact_secrets` writes, so an analyst reads one token across the ledger.
pub const REDACTED: &str = "<redacted>";

/// Parameter, header and cookie names whose values are credentials. A name matches when, lowercased,
/// it equals one of these, when any of its alphanumeric segments does (`client_secret`,
/// `user[pin]`, `auth-token`), or when it contains `passw` (`password2`, `new_passwd`,
/// `password_confirmation`).
const SECRET_NAMES: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "auth",
    "credential",
    "pin",
    "otp",
];

pub fn is_secret_name(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    if name.contains("passw") || SECRET_NAMES.contains(&name.as_str()) {
        return true;
    }
    name.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|segment| !segment.is_empty() && SECRET_NAMES.contains(&segment))
}

/// `key=value&key=value` text (a query string or a url-encoded form) with every non-empty value
/// under a secret name replaced. Names are percent-decoded for the match only; the text keeps
/// the attacker's own spelling.
pub fn redact_form(text: &str) -> Option<String> {
    let mut changed = false;
    let pairs: Vec<String> = text
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) if !value.is_empty() && is_secret_name(&percent_decode(name)) => {
                changed = true;
                format!("{name}={REDACTED}")
            }
            _ => pair.to_string(),
        })
        .collect();
    changed.then(|| pairs.join("&"))
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

/// JSON text with the value of every `"name": value` pair under a secret name replaced, at any
/// depth, by the quoted marker. Works on the text rather than a parsed tree so a body cut at the
/// capture cap (unparseable, its last string possibly unterminated) still loses its secrets:
/// an unterminated secret value is redacted to the end of the text.
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
            b'{' | b'[' => continue,
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

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// The boundary a `multipart/*` Content-Type declares, or, when it declares none, the one the
/// body's first delimiter line uses.
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
    first.strip_prefix("--").map(|b| b.trim_end().to_string())
}

/// A `multipart/form-data` body with the content of every part whose `name` is a secret name
/// replaced; part headers, delimiters and the other parts are untouched.
pub fn redact_multipart(text: &str, boundary: &str) -> Option<String> {
    let delimiter = format!("--{boundary}");
    let mut changed = false;
    let parts: Vec<String> = text
        .split(delimiter.as_str())
        .map(|part| {
            let Some((headers, content)) = part.split_once("\r\n\r\n") else {
                return part.to_string();
            };
            let name = part_name(headers);
            let value = content.strip_suffix("\r\n").unwrap_or(content);
            if value.is_empty() || !name.is_some_and(|n| is_secret_name(&n)) {
                return part.to_string();
            }
            changed = true;
            format!("{headers}\r\n\r\n{REDACTED}\r\n")
        })
        .collect();
    changed.then(|| parts.join(&delimiter))
}

fn part_name(headers: &str) -> Option<String> {
    let lower = headers.to_ascii_lowercase();
    let at = lower.find("name=\"")? + "name=\"".len();
    let end = headers[at..].find('"')? + at;
    Some(headers[at..end].to_string())
}

/// The whole captured body with its credentials removed, whatever its declared Content-Type: a
/// multipart body is handled by its boundary, and every body goes through the JSON and form
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
    for scanner in [redact_json, redact_form] {
        if let Some(redacted) = scanner(current.as_deref().unwrap_or(body)) {
            current = Some(redacted);
        }
    }
    current
}

/// What an `Authorization` or `Proxy-Authorization` value may leave in the event: its scheme, and
/// for `Basic` the username from the decoded `user:password` pair. The password, a bearer token,
/// a digest response, or anything else after the scheme is dropped.
pub struct AuthHeader {
    pub scheme: String,
    pub username: Option<String>,
}

pub fn redact_authorization(value: &str) -> AuthHeader {
    let value = value.trim();
    let (scheme, credentials) = value.split_once(char::is_whitespace).unwrap_or((value, ""));
    let username = scheme
        .eq_ignore_ascii_case("basic")
        .then(|| {
            let encoded = credentials.trim();
            STANDARD
                .decode(encoded)
                .or_else(|_| STANDARD_NO_PAD.decode(encoded.trim_end_matches('=')))
                .ok()
        })
        .flatten()
        .and_then(|decoded| {
            let decoded = String::from_utf8_lossy(&decoded).into_owned();
            decoded.split_once(':').map(|(user, _)| user.to_string())
        });
    AuthHeader {
        scheme: scheme.to_string(),
        username,
    }
}

/// A `Cookie` header with every non-empty value replaced; cookie names and separators stay.
pub fn redact_cookie(value: &str) -> Option<String> {
    let mut changed = false;
    let cookies: Vec<String> = value
        .split(';')
        .map(|cookie| match cookie.split_once('=') {
            Some((name, v)) if !v.trim().is_empty() => {
                changed = true;
                format!("{name}={REDACTED}")
            }
            _ => cookie.to_string(),
        })
        .collect();
    changed.then(|| cookies.join(";"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_names_match_whole_words_segments_and_passw() {
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
        ] {
            assert!(is_secret_name(name), "{name}");
        }
        for name in [
            "username",
            "user",
            "email",
            "q",
            "lang",
            "passage",
            "pinned",
            "x-api-version",
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
    }

    #[test]
    fn form_without_a_secret_or_with_an_empty_one_is_unchanged() {
        assert_eq!(redact_form("q=test&lang=en"), None);
        assert_eq!(redact_form("user=admin&pass="), None);
        assert_eq!(redact_form(""), None);
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
            redact_json(r#"["password", {"password": {"inner": "x"}}]"#),
            None,
            "a secret name that is a value, or whose value is a container, is not a secret"
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
        assert_eq!(redact_body("GET / HTTP/1.1", None), None);
    }

    #[test]
    fn authorization_keeps_the_scheme_and_only_the_basic_username() {
        let basic = redact_authorization("Basic YWRtaW46aHVudGVyMg==");
        assert_eq!(basic.scheme, "Basic");
        assert_eq!(basic.username.as_deref(), Some("admin"));
        let unpadded = redact_authorization("basic YWRtaW46aHVudGVyMg");
        assert_eq!(unpadded.username.as_deref(), Some("admin"));
        let bearer = redact_authorization("Bearer eyJhbGciOiJIUzI1NiJ9.x.y");
        assert_eq!(bearer.scheme, "Bearer");
        assert_eq!(bearer.username, None);
        assert_eq!(redact_authorization("Basic !!notbase64").username, None);
        assert_eq!(
            redact_authorization("Basic bm9jb2xvbg==").username,
            None,
            "a blob without a colon has no username to keep"
        );
    }

    #[test]
    fn cookie_keeps_names_and_drops_every_value() {
        assert_eq!(
            redact_cookie("session=abc123; theme=dark; flag").as_deref(),
            Some("session=<redacted>; theme=<redacted>; flag")
        );
        assert_eq!(redact_cookie("flag; other"), None);
    }
}
