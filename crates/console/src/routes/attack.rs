//! How ATT&CK technique tags (`review::attack`) reach the pages: the view types the templates
//! render and the one conversion from `TagView`, so the IP page, its session cards and both
//! campaign pages show a tag the same way.
//!
//! Every string that came from an attacker (`matched`) is passed through to the template as plain
//! text; the template's autoescaping is the only escaping, as for every other value on these pages.

use review::attack::TagView;
use serde::Serialize;

/// Evidence lines shown per technique before "+N more".
const EVIDENCE_SHOWN: usize = 3;

/// A technique as a chip: its id, with the name and matrix release as the hover text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TagChip {
    pub id: String,
    /// "Unix Shell, ATT&CK v19.2".
    pub title: String,
}

/// One technique with the evidence that tagged it, for a panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TechniqueView {
    pub id: String,
    pub name: String,
    pub matrix: String,
    pub evidence: Vec<EvidenceView>,
    /// Evidence rows beyond the ones shown.
    pub more: usize,
}

/// One rule that tagged a technique and the token it matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EvidenceView {
    pub rule: String,
    /// Attacker data.
    pub matched: String,
    pub event_id: Option<i64>,
    /// Set when the evidence is a captured artifact rather than an event.
    pub artifact: Option<String>,
}

pub(crate) fn chips(tags: &[TagView]) -> Vec<TagChip> {
    tags.iter()
        .map(|t| TagChip {
            id: t.technique.clone(),
            title: format!("{}, ATT&CK {}", t.name, t.matrix_version),
        })
        .collect()
}

pub(crate) fn techniques(tags: Vec<TagView>) -> Vec<TechniqueView> {
    tags.into_iter()
        .map(|t| {
            let more = t.evidence.len().saturating_sub(EVIDENCE_SHOWN);
            TechniqueView {
                id: t.technique,
                name: t.name,
                matrix: t.matrix_version.to_string(),
                evidence: t
                    .evidence
                    .into_iter()
                    .take(EVIDENCE_SHOWN)
                    .map(|e| EvidenceView {
                        rule: e.rule,
                        matched: e.matched,
                        event_id: e.event_id,
                        artifact: e.artifact_sha256,
                    })
                    .collect(),
                more,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use review::attack::RuleEvidence;

    fn tag(technique: &str, evidence: usize) -> TagView {
        TagView {
            technique: technique.to_string(),
            name: "Unix Shell".to_string(),
            matrix_version: "v19.2",
            evidence: (0..evidence)
                .map(|i| RuleEvidence {
                    rule: format!("rule-{i}"),
                    event_id: Some(i as i64),
                    artifact_sha256: None,
                    matched: format!("tok{i}"),
                })
                .collect(),
        }
    }

    #[test]
    fn evidence_is_capped_and_the_remainder_counted() {
        let t = techniques(vec![tag("T1059.004", EVIDENCE_SHOWN + 2)]);
        assert_eq!(t[0].evidence.len(), EVIDENCE_SHOWN);
        assert_eq!(t[0].more, 2);
        let exact = techniques(vec![tag("T1059.004", EVIDENCE_SHOWN)]);
        assert_eq!(exact[0].more, 0);
    }

    #[test]
    fn a_chip_names_the_technique_and_the_matrix_release_on_hover() {
        let c = chips(&[tag("T1059.004", 1)]);
        assert_eq!(c[0].id, "T1059.004");
        assert_eq!(c[0].title, "Unix Shell, ATT&CK v19.2");
    }
}
