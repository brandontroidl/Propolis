//! Labels a request whose User-Agent CLAIMS to be a well-known declared crawler.
//!
//! This is a display annotation and nothing else. A User-Agent is whatever the client chooses to
//! send, so a match proves only that the client said so: the label is stored as
//! `claimed_crawler` on the event metadata for the operator reading the timeline, and no scoring,
//! exclusion, or feed code reads it. Exempting a crawler requires the address to be in a range
//! the operator listed (`PROPOLIS_FEED_ALLOWLIST_FILE`), never this label.

/// `(User-Agent token, label)`. Tokens are the product names the operators document for their
/// crawlers, matched case-insensitively anywhere in the header. The label is a fixed string, so a
/// hostile header can never put attacker-chosen text into the metadata through this path.
const CLAIMED_CRAWLERS: &[(&str, &str)] = &[
    ("claudebot", "ClaudeBot"),
    ("claude-user", "Claude-User"),
    ("claude-searchbot", "Claude-SearchBot"),
    ("anthropic-ai", "anthropic-ai"),
    ("gptbot", "GPTBot"),
    ("oai-searchbot", "OAI-SearchBot"),
    ("chatgpt-user", "ChatGPT-User"),
    ("perplexitybot", "PerplexityBot"),
    ("ccbot", "CCBot"),
    ("googlebot", "Googlebot"),
    ("bingbot", "bingbot"),
    ("applebot", "Applebot"),
    ("duckduckbot", "DuckDuckBot"),
    ("yandexbot", "YandexBot"),
    ("baiduspider", "Baiduspider"),
    ("censysinspect", "CensysInspect"),
    ("ahrefsbot", "AhrefsBot"),
    ("semrushbot", "SemrushBot"),
];

/// The crawler `user_agent` claims to be, if any. Display only: see the module doc.
pub fn claimed_crawler(user_agent: &str) -> Option<&'static str> {
    let ua = user_agent.to_ascii_lowercase();
    CLAIMED_CRAWLERS
        .iter()
        .find(|(token, _)| ua.contains(token))
        .map(|(_, label)| *label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_the_documented_anthropic_user_agents() {
        assert_eq!(
            claimed_crawler("Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"),
            Some("ClaudeBot")
        );
        assert_eq!(claimed_crawler("Claude-User/1.0"), Some("Claude-User"));
        assert_eq!(
            claimed_crawler("Claude-SearchBot/1.0"),
            Some("Claude-SearchBot")
        );
    }

    #[test]
    fn matching_is_case_insensitive_and_returns_the_fixed_label() {
        assert_eq!(claimed_crawler("claudebot"), Some("ClaudeBot"));
        assert_eq!(
            claimed_crawler("Mozilla/5.0 (compatible; CENSYSINSPECT/1.1)"),
            Some("CensysInspect")
        );
    }

    #[test]
    fn ordinary_and_empty_user_agents_get_no_label() {
        assert_eq!(claimed_crawler(""), None);
        assert_eq!(claimed_crawler("curl/8.5.0"), None);
        assert_eq!(claimed_crawler("Mozilla/5.0 (X11; Linux x86_64)"), None);
    }

    #[test]
    fn the_label_never_echoes_attacker_text() {
        let label = claimed_crawler("ClaudeBot'); DROP TABLE event;--").unwrap();
        assert_eq!(label, "ClaudeBot");
    }
}
