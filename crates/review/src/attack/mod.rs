//! Rule-based MITRE ATT&CK technique tags for what the sensors observed (docs/reference/attack-tagging.md).
//!
//! Deterministic and local: a tag is the result of a fixed rule over exact evidence in one ledger
//! event (a command line, a download, an upload, a signal type, an indicator the IOC extraction
//! already took), never a score and never a model. Every tag carries the rule that produced it,
//! the event it came from and the token that matched. The rules are the table in [`rules`]; the
//! shell reader they share is [`parse`].
//!
//! The campaign indexer calls this module where it already reads each event
//! (`crate::campaign`), stores tags per session and per source in `attack_tag`, and folds a
//! command-sequence run's tags into its campaign's `campaign_attack_tag` rows the way it links the
//! run's samples. Tags are labels for the operator. They are not published to the feed and not
//! sent to any vendor.
//!
//! Matched tokens are attacker data. They are redacted of URL credentials and authorization
//! values, sanitized and capped here, and a consumer shows them as escaped text, never as a link.

pub mod parse;
pub mod rules;

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use crate::ioc::{self, Indicator};
use rules::Input;
pub use rules::{MATRIX_VERSION, RULES, Rule, SHELL_SENSORS, Scope};

/// Longest stored matched token, in bytes.
pub const MAX_MATCHED_BYTES: usize = 256;

/// A rule that matched, before it is tied to an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub rule: &'static str,
    pub matched: String,
}

/// A rule that matched in a stored event: what a run remembers until its campaign is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub rule: String,
    pub event_id: i64,
    pub matched: String,
}

/// The rule with this id.
pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

/// Whether `sensor` logs Unix shell lines (and downloads they start) that the command rules read.
pub fn is_shell_sensor(sensor: &str) -> bool {
    SHELL_SENSORS.contains(&sensor)
}

/// Redacted, sanitized and capped, as stored.
pub fn clean(matched: &str) -> String {
    ioc::sanitize_field(&ioc::redact_secrets(matched), MAX_MATCHED_BYTES)
}

/// The first match of each rule of `scope` over `inputs`, in rule-table order.
fn evaluate(scope: Scope, inputs: &[Input]) -> Vec<Match> {
    let mut found = Vec::new();
    for rule in RULES.iter().filter(|r| r.scope == scope) {
        if let Some(matched) = inputs.iter().find_map(|i| (rule.eval)(i)) {
            let matched = clean(&matched);
            if !matched.is_empty() {
                found.push(Match {
                    rule: rule.id,
                    matched,
                });
            }
        }
    }
    found
}

/// Tags for a shell command line.
pub fn tag_command(line: &str) -> Vec<Match> {
    let simples = parse::parse(line);
    let inputs: Vec<Input> = simples.iter().map(Input::Command).collect();
    evaluate(Scope::Command, &inputs)
}

/// Tags for a `honeypot_file_download` event: the URL it resolved, or the command it could not.
pub fn tag_download(url: Option<&str>, command: Option<&str>) -> Vec<Match> {
    evaluate(Scope::Download, &[Input::Download { url, command }])
}

/// Tags for a `honeypot_malware_upload` event carrying the sample `sha256`.
pub fn tag_upload(sha256: &str) -> Vec<Match> {
    evaluate(Scope::Upload, &[Input::Upload { sha256 }])
}

/// Tags for an event's signal type alone.
pub fn tag_signal(signal: &str) -> Vec<Match> {
    evaluate(Scope::Signal, &[Input::Signal(signal)])
}

/// Tags for indicators the IOC extraction took from a command, a URL or a captured artifact.
pub fn tag_indicators(found: &[Indicator]) -> Vec<Match> {
    let inputs: Vec<Input> = found.iter().map(Input::Indicator).collect();
    evaluate(Scope::Indicator, &inputs)
}

/// One rule's evidence for a technique on a campaign, session or source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleEvidence {
    pub rule: String,
    /// The lowest event id that satisfied the rule; `None` for evidence that is a captured
    /// artifact.
    pub event_id: Option<i64>,
    pub artifact_sha256: Option<String>,
    /// The token that matched. Attacker data: render as escaped text.
    pub matched: String,
}

/// A technique and the rules that tagged it, for display and for JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TagView {
    pub technique: String,
    pub name: String,
    pub matrix_version: &'static str,
    pub evidence: Vec<RuleEvidence>,
}

/// Rows `(key, rule, evidence)` grouped by key, then by technique, ordered by technique id. A
/// rule id this build does not know (a retired one) is left out rather than shown unnamed.
fn group<K: std::hash::Hash + Eq>(rows: Vec<(K, RuleEvidence)>) -> HashMap<K, Vec<TagView>> {
    let mut by_key: HashMap<K, BTreeMap<&'static str, TagView>> = HashMap::new();
    for (key, ev) in rows {
        let Some(rule) = rule(&ev.rule) else {
            continue;
        };
        by_key
            .entry(key)
            .or_default()
            .entry(rule.technique)
            .or_insert_with(|| TagView {
                technique: rule.technique.to_string(),
                name: rule.technique_name.to_string(),
                matrix_version: MATRIX_VERSION,
                evidence: Vec::new(),
            })
            .evidence
            .push(ev);
    }
    by_key
        .into_iter()
        .map(|(k, v)| (k, v.into_values().collect()))
        .collect()
}

/// The techniques tagged on each of the campaigns `ids`, by campaign id. A command-sequence
/// campaign carries the tags of the runs that joined it; a sample campaign the tags of how its
/// sample arrived and what its text carried.
///
/// This is the hook for the console's campaign pages: `routes::campaigns` reads the campaign
/// tables directly, and this is the one call that adds the tags to a list or detail page.
pub async fn campaign_tags(
    pool: &PgPool,
    ids: &[i64],
) -> Result<HashMap<i64, Vec<TagView>>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query(
        "SELECT campaign_id, rule_id, event_id, artifact_sha256, matched FROM campaign_attack_tag \
         WHERE campaign_id = ANY($1) ORDER BY campaign_id, technique_id, rule_id",
    )
    .bind(ids)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push((
            r.try_get::<i64, _>("campaign_id")?,
            RuleEvidence {
                rule: r.try_get("rule_id")?,
                event_id: r.try_get("event_id")?,
                artifact_sha256: r.try_get("artifact_sha256")?,
                matched: r.try_get("matched")?,
            },
        ));
    }
    Ok(group(out))
}

/// The techniques tagged on each of the source addresses `ips`, over all their sessions, by
/// address, with the lowest event that satisfied each rule.
pub async fn source_tags(
    pool: &PgPool,
    ips: &[String],
) -> Result<HashMap<String, Vec<TagView>>, sqlx::Error> {
    if ips.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query(
        "SELECT DISTINCT ON (source_ip, rule_id) host(source_ip) AS ip, rule_id, event_id, matched \
         FROM attack_tag WHERE source_ip = ANY($1::inet[]) \
         ORDER BY source_ip, rule_id, event_id",
    )
    .bind(ips)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push((
            r.try_get::<String, _>("ip")?,
            RuleEvidence {
                rule: r.try_get("rule_id")?,
                event_id: Some(r.try_get("event_id")?),
                artifact_sha256: None,
                matched: r.try_get("matched")?,
            },
        ));
    }
    Ok(group(out))
}

/// The techniques tagged in each of the shell sessions `session_ids` (UUID text, as the pages
/// carry them), by session id as given. A session with no tags is absent. One query for any number
/// of sessions, like [`source_tags`] and [`campaign_tags`]; a string that is not a UUID fails the
/// whole call.
pub async fn session_tags(
    pool: &PgPool,
    session_ids: &[String],
) -> Result<HashMap<String, Vec<TagView>>, sqlx::Error> {
    if session_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query(
        "SELECT session_id::text AS session_id, rule_id, event_id, matched FROM attack_tag \
         WHERE session_id = ANY($1::uuid[]) ORDER BY session_id, technique_id, rule_id",
    )
    .bind(session_ids)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push((
            r.try_get::<String, _>("session_id")?,
            RuleEvidence {
                rule: r.try_get("rule_id")?,
                event_id: Some(r.try_get("event_id")?),
                artifact_sha256: None,
                matched: r.try_get("matched")?,
            },
        ));
    }
    Ok(group(out))
}

#[cfg(test)]
mod tests;
