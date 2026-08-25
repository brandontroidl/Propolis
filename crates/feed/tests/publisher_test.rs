//! No-database tests for `Publisher::publish`: fail-closed re-validation, atomic publish, and
//! manifest correctness. Like `export_test.rs`, these never touch Postgres - `Publisher::publish`
//! takes an already-built `FeedSnapshot`, and every `FeedSnapshot`/`FeedEntry` here is constructed
//! directly (the same "bypass the builder" technique `export_test.rs`'s module doc comment
//! describes), writing only to a `tempfile` directory.
//!
//! `entry()`'s reserved-IP fixture (`10.0.0.1`, RFC1918) stands in for a hypothetical bug in
//! `FeedBuilder` that let a reserved address slip into a snapshot - exactly the scenario the
//! publisher's re-validation exists to catch. See `internal/design/05-blocklist-feed.md`'s
//! "Publisher": it "re-validates every entry before writing... If ANY entry fails, the entire
//! build is rejected".

use std::net::IpAddr;
use std::path::Path;

use chrono::{DateTime, Utc};
use core_scoring::FeedTier;
use feed::{ExclusionEngine, FeedConfig, FeedEntry, FeedSnapshot, PublishError, Publisher};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn dt(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn permissive() -> ExclusionEngine {
    ExclusionEngine::new(Vec::new(), Vec::new())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Builds one `FeedEntry` whose `valid_from`/`valid_until` are derived from `config`, matching how
/// `FeedBuilder::build` itself computes them - see `crates/feed/src/builder.rs`.
fn entry(
    source_ip: IpAddr,
    tier: FeedTier,
    build_time: DateTime<Utc>,
    config: &FeedConfig,
) -> FeedEntry {
    let ttl = match tier {
        FeedTier::Aggressive => config.aggressive_ttl,
        FeedTier::Standard => config.standard_ttl,
    };
    FeedEntry {
        source_ip,
        tier: Some(tier),
        first_seen: build_time,
        last_seen: build_time,
        event_count: 2,
        distinct_categories: 2,
        categories: vec!["ssh_brute_force".into(), "port_scan".into()],
        valid_from: build_time,
        valid_until: build_time + ttl,
    }
}

fn manifest_json(output_dir: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(output_dir.join("manifest.json")).unwrap())
        .expect("manifest.json must be valid json")
}

// ---------- fail-closed re-validation ----------

#[test]
fn fail_closed_rejects_the_entire_build_when_any_entry_is_excluded() {
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    let legit = entry(ip("45.10.30.7"), FeedTier::Aggressive, build_time, &config);
    // Bypasses FeedBuilder entirely: a reserved RFC1918 address constructed directly into the
    // snapshot, exactly as if a bug in the builder had let it through.
    let leaked = entry(ip("10.0.0.1"), FeedTier::Standard, build_time, &config);

    let snapshot = FeedSnapshot {
        build_time,
        aggressive: vec![legit],
        standard: vec![leaked],
        windows: Vec::new(),
    };

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");

    let result = Publisher::publish(&snapshot, &output_dir, &permissive(), &config);
    match result {
        Err(PublishError::ExclusionViolation { ip: bad_ip, tier }) => {
            assert_eq!(bad_ip, ip("10.0.0.1"));
            assert_eq!(tier, Some(FeedTier::Standard));
        }
        other => panic!("expected ExclusionViolation, got {other:?}"),
    }
    assert!(
        !output_dir.exists(),
        "a rejected build must never create the output directory"
    );
}

#[test]
fn fail_closed_rejects_a_violation_hiding_in_a_retention_window() {
    // The re-validation pass originally iterated only the two tiers, so an address leaking into a
    // retention feed was published unchecked - a check that only guards the surfaces which existed
    // when it was written stops guarding the moment a new one is added. A reserved address in
    // all-90d.txt discredits the feed exactly as much as one in aggressive.txt.
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    let leaked = entry(ip("192.168.4.4"), FeedTier::Standard, build_time, &config);

    let snapshot = FeedSnapshot {
        build_time,
        aggressive: Vec::new(),
        standard: Vec::new(),
        windows: vec![feed::WindowFeed {
            label: "90d".into(),
            retention: chrono::Duration::days(90),
            entries: vec![leaked],
        }],
    };

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");

    match Publisher::publish(&snapshot, &output_dir, &permissive(), &config) {
        Err(PublishError::ExclusionViolation { ip: bad_ip, .. }) => {
            assert_eq!(bad_ip, ip("192.168.4.4"));
        }
        other => panic!("expected ExclusionViolation, got {other:?}"),
    }
    assert!(
        !output_dir.exists(),
        "a rejected build must never create the output directory"
    );
}

#[test]
fn retention_windows_are_written_as_all_label_files_and_listed_in_the_manifest() {
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    let e = entry(ip("45.10.30.11"), FeedTier::Standard, build_time, &config);

    let snapshot = FeedSnapshot {
        build_time,
        aggressive: Vec::new(),
        standard: Vec::new(),
        windows: vec![
            feed::WindowFeed {
                label: "7d".into(),
                retention: chrono::Duration::days(7),
                entries: vec![e.clone()],
            },
            feed::WindowFeed {
                label: "90d".into(),
                retention: chrono::Duration::days(90),
                entries: vec![e],
            },
        ],
    };

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");
    Publisher::publish(&snapshot, &output_dir, &permissive(), &config).unwrap();

    // Every format the tiers get, the windows get too.
    for ext in [
        "txt", "json", "csv", "cidr", "ipset", "nft", "pf", "alias", "hosts", "rpz",
    ] {
        assert!(
            output_dir.join(format!("all-7d.{ext}")).exists(),
            "all-7d.{ext} must be published"
        );
    }

    let manifest = manifest_json(&output_dir);
    let windows = manifest["windows"].as_array().expect("windows array");
    assert_eq!(windows.len(), 2);
    assert_eq!(windows[0]["label"], "7d");
    assert_eq!(windows[0]["count"], 1);
    assert_eq!(windows[1]["label"], "90d");

    // The stated validity must be the window's own retention, not a tier TTL or a default.
    assert_eq!(windows[0]["valid_until"], "2026-08-05T14:00:00Z");
    assert_eq!(windows[1]["valid_until"], "2026-10-27T14:00:00Z");
}

#[test]
fn manifest_records_the_exclusion_engine_counts_under_the_names_the_console_reads() {
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    // A published entry NOT in the delist, so revalidation passes and the manifest is written.
    let e = entry(ip("45.10.30.11"), FeedTier::Standard, build_time, &config);
    let snapshot = FeedSnapshot {
        build_time,
        aggressive: Vec::new(),
        standard: vec![e],
        windows: Vec::new(),
    };
    let exclusions = ExclusionEngine::new(Vec::new(), vec![ip("203.0.113.9")]);

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");
    Publisher::publish(&snapshot, &output_dir, &exclusions, &config).unwrap();

    // Assert the exact field names the console's `ExclusionsManifest` deserializes - this is the
    // both-ends check for the manifest contract, so the console fixtures cannot silently drift from
    // what `publish` actually writes.
    let ex = &manifest_json(&output_dir)["exclusions"];
    assert_eq!(ex["allowlist_count"], 0);
    assert_eq!(ex["delist_count"], 1);
    assert_eq!(ex["asn_allowlist_count"], 0);
    assert_eq!(ex["asn_db_loaded"], false);
}

#[test]
fn fail_closed_rejects_when_the_violation_is_in_the_aggressive_tier_too() {
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    // 2001:db8::/32 (RFC5737's IPv6 documentation-range analogue) leaked into Aggressive.
    let leaked = entry(ip("2001:db8::1"), FeedTier::Aggressive, build_time, &config);
    let snapshot = FeedSnapshot {
        build_time,
        aggressive: vec![leaked],
        standard: Vec::new(),
        windows: Vec::new(),
    };

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");
    let result = Publisher::publish(&snapshot, &output_dir, &permissive(), &config);
    assert!(matches!(
        result,
        Err(PublishError::ExclusionViolation {
            tier: Some(FeedTier::Aggressive),
            ..
        })
    ));
}

#[test]
fn operator_delisted_ip_bypassing_the_builder_is_also_rejected() {
    // Defense-in-depth covers the delist/allowlist paths too, not only the hardcoded reserved
    // ranges: an ordinary public address that the OPERATOR has delisted must still be caught if a
    // builder bug lets it through.
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    let delisted_ip = ip("45.10.30.5");
    let snapshot = FeedSnapshot {
        build_time,
        aggressive: vec![entry(
            delisted_ip,
            FeedTier::Aggressive,
            build_time,
            &config,
        )],
        standard: Vec::new(),
        windows: Vec::new(),
    };
    let exclusions = ExclusionEngine::new(Vec::new(), vec![delisted_ip]);

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");
    let result = Publisher::publish(&snapshot, &output_dir, &exclusions, &config);
    assert!(matches!(
        result,
        Err(PublishError::ExclusionViolation { ip: i, .. }) if i == delisted_ip
    ));
}

// ---------- empty feed ----------

#[test]
fn empty_feed_publishes_normally_with_zero_counts() {
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    let snapshot = FeedSnapshot {
        build_time,
        aggressive: Vec::new(),
        standard: Vec::new(),
        windows: Vec::new(),
    };

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");
    Publisher::publish(&snapshot, &output_dir, &permissive(), &config).unwrap();

    for name in ["aggressive", "standard"] {
        for ext in ["txt", "json", "csv", "cidr"] {
            assert!(
                output_dir.join(format!("{name}.{ext}")).exists(),
                "missing {name}.{ext}"
            );
        }
    }
    assert!(output_dir.join("manifest.json").exists());

    let manifest = manifest_json(&output_dir);
    assert_eq!(manifest["tiers"]["aggressive"]["count"], 0);
    assert_eq!(manifest["tiers"]["standard"]["count"], 0);

    let agg_txt = std::fs::read_to_string(output_dir.join("aggressive.txt")).unwrap();
    assert!(agg_txt.contains("# Entries: 0"));
    let std_csv = std::fs::read_to_string(output_dir.join("standard.csv")).unwrap();
    assert_eq!(
        std_csv,
        "ip,first_seen,last_seen,categories,events,signals\n"
    );
}

// ---------- manifest correctness ----------

#[test]
fn manifest_has_correct_counts_checksums_and_valid_until() {
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    let snapshot = FeedSnapshot {
        build_time,
        aggressive: vec![
            entry(ip("45.10.30.7"), FeedTier::Aggressive, build_time, &config),
            entry(ip("45.10.30.8"), FeedTier::Aggressive, build_time, &config),
        ],
        standard: vec![entry(
            ip("45.10.30.50"),
            FeedTier::Standard,
            build_time,
            &config,
        )],
        windows: Vec::new(),
    };

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");
    Publisher::publish(&snapshot, &output_dir, &permissive(), &config).unwrap();

    let manifest = manifest_json(&output_dir);
    assert_eq!(manifest["build_time"], "2026-07-29T14:00:00Z");
    assert_eq!(manifest["tiers"]["aggressive"]["count"], 2);
    assert_eq!(manifest["tiers"]["standard"]["count"], 1);
    // FeedConfig::default(): aggressive 24h, standard 48h TTLs from build_time.
    assert_eq!(
        manifest["tiers"]["aggressive"]["valid_until"],
        "2026-07-30T14:00:00Z"
    );
    assert_eq!(
        manifest["tiers"]["standard"]["valid_until"],
        "2026-07-31T14:00:00Z"
    );

    // Independently recompute the sha256 from the on-disk plaintext file - never trust the
    // manifest's own claim about itself.
    let agg_txt = std::fs::read(output_dir.join("aggressive.txt")).unwrap();
    assert_eq!(
        manifest["tiers"]["aggressive"]["sha256"],
        sha256_hex(&agg_txt)
    );
    let std_txt = std::fs::read(output_dir.join("standard.txt")).unwrap();
    assert_eq!(
        manifest["tiers"]["standard"]["sha256"],
        sha256_hex(&std_txt)
    );
    // Sanity: the two tiers' plain-text files actually differ, so a passing checksum comparison
    // above isn't vacuously true from both being empty/identical.
    assert_ne!(agg_txt, std_txt);
}

#[test]
fn manifest_valid_until_is_correct_even_for_a_zero_entry_tier() {
    // The one case FeedSnapshot cannot supply valid_until for on its own (no entry to read it
    // from) - Publisher::publish must derive it from `config` instead. See publisher.rs's own doc
    // comment on this exact point.
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    let snapshot = FeedSnapshot {
        build_time,
        aggressive: Vec::new(),
        standard: vec![entry(
            ip("45.10.30.50"),
            FeedTier::Standard,
            build_time,
            &config,
        )],
        windows: Vec::new(),
    };

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");
    Publisher::publish(&snapshot, &output_dir, &permissive(), &config).unwrap();

    let manifest = manifest_json(&output_dir);
    assert_eq!(
        manifest["tiers"]["aggressive"]["valid_until"], "2026-07-30T14:00:00Z",
        "an empty tier must still carry the TTL-derived valid_until, not a null/zero placeholder"
    );
    let agg_txt = std::fs::read_to_string(output_dir.join("aggressive.txt")).unwrap();
    assert!(agg_txt.contains("# Valid until: 2026-07-30T14:00:00Z"));
}

// ---------- atomic publish ----------

#[test]
fn atomic_publish_replaces_the_old_version_wholesale_never_mixing_old_and_new() {
    let config = FeedConfig::default();
    let build_time_v1 = dt("2026-07-29T14:00:00Z");
    let snapshot_v1 = FeedSnapshot {
        build_time: build_time_v1,
        aggressive: vec![entry(
            ip("45.10.30.7"),
            FeedTier::Aggressive,
            build_time_v1,
            &config,
        )],
        standard: Vec::new(),
        windows: Vec::new(),
    };

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");

    Publisher::publish(&snapshot_v1, &output_dir, &permissive(), &config).unwrap();
    let v1_txt = std::fs::read_to_string(output_dir.join("aggressive.txt")).unwrap();
    assert!(v1_txt.contains("45.10.30.7"));

    // A rejected v2 build (fail-closed re-validation) must leave v1 completely untouched.
    let bad_v2 = FeedSnapshot {
        build_time: build_time_v1,
        aggressive: vec![entry(
            ip("10.0.0.1"),
            FeedTier::Aggressive,
            build_time_v1,
            &config,
        )],
        standard: Vec::new(),
        windows: Vec::new(),
    };
    assert!(Publisher::publish(&bad_v2, &output_dir, &permissive(), &config).is_err());
    let still_v1 = std::fs::read_to_string(output_dir.join("aggressive.txt")).unwrap();
    assert_eq!(
        still_v1, v1_txt,
        "a rejected build must leave the previously published version untouched"
    );

    // A real v2 build replaces v1's content wholesale.
    let build_time_v2 = dt("2026-07-29T15:00:00Z");
    let snapshot_v2 = FeedSnapshot {
        build_time: build_time_v2,
        aggressive: vec![entry(
            ip("45.10.30.99"),
            FeedTier::Aggressive,
            build_time_v2,
            &config,
        )],
        standard: Vec::new(),
        windows: Vec::new(),
    };
    Publisher::publish(&snapshot_v2, &output_dir, &permissive(), &config).unwrap();
    let v2_txt = std::fs::read_to_string(output_dir.join("aggressive.txt")).unwrap();
    assert!(v2_txt.contains("45.10.30.99"));
    assert!(
        !v2_txt.contains("45.10.30.7\n"),
        "v1's entry must not survive into v2's published output"
    );

    // No leftover staging/previous directories after a successful publish - the parent must hold
    // exactly the one published directory.
    let parent_entries: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        parent_entries,
        vec!["current".to_string()],
        "no staging/previous leftovers should remain after a successful publish: {parent_entries:?}"
    );
}

#[test]
fn publish_works_when_output_dir_does_not_exist_yet_first_ever_publish() {
    let config = FeedConfig::default();
    let build_time = dt("2026-07-29T14:00:00Z");
    let snapshot = FeedSnapshot {
        build_time,
        aggressive: Vec::new(),
        standard: Vec::new(),
        windows: Vec::new(),
    };

    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("current");
    assert!(!output_dir.exists());

    Publisher::publish(&snapshot, &output_dir, &permissive(), &config).unwrap();
    assert!(output_dir.join("manifest.json").exists());
}

#[test]
fn root_path_as_output_dir_is_rejected_before_any_write() {
    let config = FeedConfig::default();
    let snapshot = FeedSnapshot {
        build_time: dt("2026-07-29T14:00:00Z"),
        aggressive: Vec::new(),
        standard: Vec::new(),
        windows: Vec::new(),
    };
    let result = Publisher::publish(&snapshot, Path::new("/"), &permissive(), &config);
    assert!(matches!(result, Err(PublishError::InvalidOutputDir(_))));
}
