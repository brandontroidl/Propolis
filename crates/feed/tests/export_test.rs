//! Pure, no-database tests for the four exporters (`export_plaintext`, `export_json`,
//! `export_csv`, `export_cidr`). Every exporter is a pure function over already-built
//! `FeedEntry` values, so unlike `builder_test.rs`/`exclusion_test.rs` this file never touches
//! Postgres.
//!
//! Fixture IPs (`203.0.113.7`, `203.0.113.12`) are RFC5737 documentation-range addresses,
//! deliberately matching `internal/design/05-blocklist-feed.md`'s own worked examples for these
//! formats - safe here because these tests exercise the exporters directly, never the
//! `ExclusionEngine`/`FeedBuilder` (which is exactly what filters RFC5737 out of a real build;
//! see `tests/exclusion_test.rs`'s doc comment for the same tradeoff from the other side).
//!
//! The two sample entries deliberately carry distinct values in every field (never the same
//! number twice across the two entries), so a test asserting per-entry content can actually catch
//! a swapped or mixed-up field mapping, not just its presence.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use core_scoring::FeedTier;
use feed::{FeedEntry, export_cidr, export_csv, export_json, export_plaintext};

const GENERATED: &str = "2026-07-29T14:00:00Z";
const VALID_UNTIL: &str = "2026-07-30T14:00:00Z";

fn dt(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sample_entries() -> Vec<FeedEntry> {
    vec![
        FeedEntry {
            source_ip: ip("203.0.113.7"),
            tier: FeedTier::Aggressive,
            first_seen: dt("2026-07-20T10:00:00Z"),
            last_seen: dt("2026-07-29T13:00:00Z"),
            event_count: 47,
            distinct_categories: 3,
            valid_from: dt(GENERATED),
            valid_until: dt(VALID_UNTIL),
        },
        FeedEntry {
            source_ip: ip("203.0.113.12"),
            tier: FeedTier::Aggressive,
            first_seen: dt("2026-07-21T11:00:00Z"),
            last_seen: dt("2026-07-28T09:00:00Z"),
            event_count: 12,
            distinct_categories: 2,
            valid_from: dt(GENERATED),
            valid_until: dt(VALID_UNTIL),
        },
    ]
}

// ---------- plain text ----------

#[test]
fn plaintext_header_names_tier_generated_valid_until_and_count() {
    let out = export_plaintext(
        "aggressive",
        dt(GENERATED),
        dt(VALID_UNTIL),
        &sample_entries(),
    );
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("# Propolis blocklist - Aggressive tier"));
    assert_eq!(lines.next(), Some("# Generated: 2026-07-29T14:00:00Z"));
    assert_eq!(lines.next(), Some("# Valid until: 2026-07-30T14:00:00Z"));
    assert_eq!(lines.next(), Some("# Entries: 2"));
}

#[test]
fn plaintext_lists_exactly_one_ip_per_line_after_the_header_in_input_order() {
    let out = export_plaintext(
        "aggressive",
        dt(GENERATED),
        dt(VALID_UNTIL),
        &sample_entries(),
    );
    let body: Vec<&str> = out.lines().skip(4).collect();
    assert_eq!(body, vec!["203.0.113.7", "203.0.113.12"]);
}

#[test]
fn plaintext_zero_entries_still_renders_a_valid_header_and_no_ip_lines() {
    let out = export_plaintext("standard", dt(GENERATED), dt(VALID_UNTIL), &[]);
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("# Propolis blocklist - Standard tier"));
    assert_eq!(lines.next(), Some("# Generated: 2026-07-29T14:00:00Z"));
    assert_eq!(lines.next(), Some("# Valid until: 2026-07-30T14:00:00Z"));
    assert_eq!(lines.next(), Some("# Entries: 0"));
    assert_eq!(lines.next(), None, "no IP lines must follow the header");
}

// ---------- json ----------

#[test]
fn json_output_parses_and_has_meta_and_entries() {
    let out = export_json(
        "aggressive",
        dt(GENERATED),
        dt(VALID_UNTIL),
        &sample_entries(),
    );
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("must be valid json");
    assert!(parsed.get("meta").is_some());
    assert!(parsed.get("entries").is_some());
}

#[test]
fn json_meta_matches_the_spec_fields_exactly() {
    let out = export_json(
        "aggressive",
        dt(GENERATED),
        dt(VALID_UNTIL),
        &sample_entries(),
    );
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let meta = &parsed["meta"];
    assert_eq!(meta["generator"], "propolis");
    assert_eq!(meta["tier"], "aggressive");
    assert_eq!(meta["generated"], "2026-07-29T14:00:00Z");
    assert_eq!(meta["valid_until"], "2026-07-30T14:00:00Z");
    assert_eq!(meta["count"], 2);
}

#[test]
fn json_entries_have_exactly_the_documented_fields_no_more_no_less() {
    let out = export_json(
        "aggressive",
        dt(GENERATED),
        dt(VALID_UNTIL),
        &sample_entries(),
    );
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let entries = parsed["entries"]
        .as_array()
        .expect("entries must be an array");
    assert_eq!(entries.len(), 2);
    for entry in entries {
        let obj = entry.as_object().expect("each entry must be a json object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["categories", "events", "first_seen", "ip", "last_seen"],
            "an entry must carry exactly these fields - anything else (raw_score, \
             max_confidence, a per-entry tier label) is a deanonymization leak"
        );
    }
}

#[test]
fn json_entry_fields_are_correctly_mapped_per_ip_not_swapped_or_averaged() {
    let out = export_json(
        "aggressive",
        dt(GENERATED),
        dt(VALID_UNTIL),
        &sample_entries(),
    );
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let entries = parsed["entries"].as_array().unwrap();

    let e0 = entries
        .iter()
        .find(|e| e["ip"] == "203.0.113.7")
        .expect("first sample ip missing");
    assert_eq!(e0["first_seen"], "2026-07-20T10:00:00Z");
    assert_eq!(e0["last_seen"], "2026-07-29T13:00:00Z");
    assert_eq!(e0["categories"], 3);
    assert_eq!(e0["events"], 47);

    let e1 = entries
        .iter()
        .find(|e| e["ip"] == "203.0.113.12")
        .expect("second sample ip missing");
    assert_eq!(e1["first_seen"], "2026-07-21T11:00:00Z");
    assert_eq!(e1["last_seen"], "2026-07-28T09:00:00Z");
    assert_eq!(e1["categories"], 2);
    assert_eq!(e1["events"], 12);
}

#[test]
fn json_zero_entries_is_a_valid_empty_array_not_an_error() {
    let out = export_json("standard", dt(GENERATED), dt(VALID_UNTIL), &[]);
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("must still be valid json");
    assert_eq!(parsed["meta"]["count"], 0);
    assert_eq!(parsed["entries"].as_array().unwrap().len(), 0);
}

// ---------- csv ----------

#[test]
fn csv_header_row_matches_the_spec_columns_exactly() {
    let out = export_csv(&sample_entries());
    assert_eq!(
        out.lines().next(),
        Some("ip,first_seen,last_seen,categories,events")
    );
}

#[test]
fn csv_rows_are_parseable_with_five_columns_correctly_mapped_per_ip() {
    let out = export_csv(&sample_entries());
    let rows: Vec<Vec<&str>> = out
        .lines()
        .skip(1)
        .map(|l| l.split(',').collect())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0],
        vec![
            "203.0.113.7",
            "2026-07-20T10:00:00Z",
            "2026-07-29T13:00:00Z",
            "3",
            "47"
        ]
    );
    assert_eq!(
        rows[1],
        vec![
            "203.0.113.12",
            "2026-07-21T11:00:00Z",
            "2026-07-28T09:00:00Z",
            "2",
            "12"
        ]
    );
}

#[test]
fn csv_zero_entries_is_header_only() {
    let out = export_csv(&[]);
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        vec!["ip,first_seen,last_seen,categories,events"]
    );
}

// ---------- cidr ----------

#[test]
fn cidr_ipv4_entries_are_slash_32_host_routes() {
    let out = export_cidr(&sample_entries());
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        vec!["203.0.113.7/32", "203.0.113.12/32"]
    );
}

#[test]
fn cidr_ipv6_entries_are_slash_128_host_routes_never_slash_32() {
    // The design's "Inherited invariants" section: host routes are /32 for IPv4 *and /128 for
    // IPv6*. A /32 on an IPv6 address would cover roughly 2^96 addresses instead of one - exactly
    // the collateral-blocking failure the design's "Collateral safety" invariant forbids.
    let mut entries = sample_entries();
    entries.push(FeedEntry {
        source_ip: ip("2003:aaaa:bbbb::7"),
        tier: FeedTier::Aggressive,
        first_seen: dt(GENERATED),
        last_seen: dt(GENERATED),
        event_count: 5,
        distinct_categories: 2,
        valid_from: dt(GENERATED),
        valid_until: dt(VALID_UNTIL),
    });
    let out = export_cidr(&entries);
    assert!(out.lines().any(|l| l == "2003:aaaa:bbbb::7/128"));
    assert!(!out.contains("2003:aaaa:bbbb::7/32"));
}

#[test]
fn cidr_zero_entries_is_an_empty_string() {
    assert_eq!(export_cidr(&[]), "");
}

// ---------- cross-format anti-deanonymization ----------

fn assert_no_score_or_confidence(rendered: &str) {
    let lower = rendered.to_lowercase();
    for banned in ["raw_score", "rawscore", "confidence", "max_confidence"] {
        assert!(
            !lower.contains(banned),
            "rendered output must never contain {banned:?}: {rendered}"
        );
    }
}

/// Scans `rendered` for every `HH:MM:SS` timestamp-shaped substring (our fixed-width RFC3339
/// output is always exactly `YYYY-MM-DDTHH:MM:SSZ`) and asserts the minutes and seconds are
/// always `00` - i.e. no format can ever leak a sub-hour timestamp, regardless of which field it
/// came from. A manual byte scan rather than a `regex` dependency: the output is fixed-width
/// ASCII, so this is a direct, dependency-free proof.
fn assert_no_sub_hour_timestamp(rendered: &str) {
    let bytes = rendered.as_bytes();
    let mut found_any = false;
    let mut i = 0;
    while i + 10 <= bytes.len() {
        if bytes[i] == b'T'
            && bytes[i + 3] == b':'
            && bytes[i + 6] == b':'
            && bytes[i + 9] == b'Z'
            && bytes[i + 1..i + 3].iter().all(u8::is_ascii_digit)
            && bytes[i + 4..i + 6].iter().all(u8::is_ascii_digit)
            && bytes[i + 7..i + 9].iter().all(u8::is_ascii_digit)
        {
            found_any = true;
            let minute = &rendered[i + 4..i + 6];
            let second = &rendered[i + 7..i + 9];
            assert_eq!(minute, "00", "sub-hour minute leaked in: {rendered}");
            assert_eq!(second, "00", "sub-hour second leaked in: {rendered}");
        }
        i += 1;
    }
    assert!(
        found_any,
        "sanity check failed: expected at least one timestamp in the rendered output"
    );
}

#[test]
fn no_export_format_ever_renders_a_sub_hour_timestamp_even_from_ragged_input() {
    // Deliberately ragged (non-coarsened) input across every timestamp field, proving the
    // defensive re-coarsening in the shared `format_timestamp` helper holds through every format,
    // not merely the exact-hour fixture used by the tests above.
    let mut ragged = sample_entries();
    ragged[0].first_seen = dt("2026-07-20T10:42:17Z");
    ragged[0].last_seen = dt("2026-07-29T13:59:59Z");
    ragged[1].first_seen = dt("2026-07-21T11:01:01Z");
    let generated = dt("2026-07-29T14:29:00Z");
    let valid_until = dt("2026-07-30T14:31:31Z");

    assert_no_sub_hour_timestamp(&export_plaintext(
        "aggressive",
        generated,
        valid_until,
        &ragged,
    ));
    assert_no_sub_hour_timestamp(&export_json("aggressive", generated, valid_until, &ragged));
    assert_no_sub_hour_timestamp(&export_csv(&ragged));
    // `export_cidr` renders no timestamps at all, so it has nothing to scan here.
}

#[test]
fn no_export_format_ever_leaks_raw_score_or_confidence_across_all_four_formats() {
    let entries = sample_entries();
    assert_no_score_or_confidence(&export_plaintext(
        "aggressive",
        dt(GENERATED),
        dt(VALID_UNTIL),
        &entries,
    ));
    assert_no_score_or_confidence(&export_json(
        "aggressive",
        dt(GENERATED),
        dt(VALID_UNTIL),
        &entries,
    ));
    assert_no_score_or_confidence(&export_csv(&entries));
    assert_no_score_or_confidence(&export_cidr(&entries));
}
