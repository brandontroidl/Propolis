//! What the publisher writes must be what `deploy/blocklist-sync.sh` is prepared to push.
//!
//! The script stands between the daemon and a public repository whose files consumers apply to
//! their firewalls as root. It reads every file back and refuses a build in which any line is
//! not one the publisher writes for that format. Those rules restate the exporters, in another
//! language, in another directory: nothing but a test ties the two together. This one publishes
//! real builds and runs the script's own `--check` over them, so an exporter that changes without
//! the script following fails here, and so does a script rule that no longer admits real output.
//!
//! The second half tampers with a real build, one file at a time, and requires the refusal: a
//! rule that admitted everything would pass the first half.

use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Output};

use chrono::{DateTime, Duration, Utc};
use core_scoring::FeedTier;
use feed::{ExclusionEngine, FeedConfig, FeedEntry, FeedSnapshot, Publisher, WindowFeed};

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/blocklist-sync.sh"
);

fn build_time() -> DateTime<Utc> {
    "2026-07-29T14:00:00Z".parse().unwrap()
}

fn entry(ip: &str, tier: Option<FeedTier>, signals: &[&str]) -> FeedEntry {
    let at = build_time() - Duration::hours(3);
    FeedEntry {
        source_ip: ip.parse::<IpAddr>().unwrap(),
        tier,
        first_seen: at - Duration::days(2),
        last_seen: at,
        event_count: 1234,
        distinct_categories: signals.len() as i32,
        categories: signals.iter().map(|s| s.to_string()).collect(),
        valid_from: at,
        valid_until: at + Duration::hours(24),
    }
}

/// Everything the formats have to carry: both families, an IPv4-mapped IPv6 address, an entry
/// with no signal names, a volume listing (no tier), an empty tier, and two retention windows.
fn full_snapshot() -> FeedSnapshot {
    let aggressive = vec![
        entry(
            "45.10.30.7",
            Some(FeedTier::Aggressive),
            &["honeypot_login_attempt", "ssh_brute_force"],
        ),
        entry("45.10.30.90", Some(FeedTier::Aggressive), &[]),
        entry(
            "2003:aaaa:bbbb::7",
            Some(FeedTier::Aggressive),
            &["catchall_probe"],
        ),
        entry(
            "::ffff:45.10.31.1",
            Some(FeedTier::Aggressive),
            &["honeypot_command_exec"],
        ),
    ];
    let mut week = aggressive.clone();
    week.push(entry("45.10.40.1", None, &["honeypot_connection"]));
    week.sort_by_key(|e| e.source_ip);
    FeedSnapshot {
        build_time: build_time(),
        aggressive: aggressive.clone(),
        standard: Vec::new(),
        windows: vec![
            WindowFeed {
                label: "24h".into(),
                retention: Duration::hours(24),
                entries: aggressive,
            },
            WindowFeed {
                label: "7d".into(),
                retention: Duration::days(7),
                entries: week,
            },
        ],
    }
}

fn publish(snapshot: &FeedSnapshot, dir: &Path) {
    Publisher::publish(
        snapshot,
        dir,
        &ExclusionEngine::new(Vec::new(), Vec::new()),
        &FeedConfig::default(),
    )
    .expect("the build publishes");
}

fn check(dir: &Path) -> Output {
    Command::new("bash")
        .arg(SCRIPT)
        .arg("--check")
        .arg(dir)
        .env("LC_ALL", "C")
        .output()
        .expect("bash runs the script")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_real_build_with_both_families_and_windows_passes_every_check() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("current");
    publish(&full_snapshot(), &dir);

    let out = check(&dir);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("passes every check"), "{}", text(&out));
    assert!(
        !tmp.path().join("current/.git").exists() && !tmp.path().join("repo").exists(),
        "--check touches no checkout"
    );
}

#[test]
fn an_empty_build_with_no_windows_passes_every_check() {
    // A quiet node with no retention windows configured: every file is its header alone, or
    // nothing at all.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("current");
    let snapshot = FeedSnapshot {
        build_time: build_time(),
        aggressive: Vec::new(),
        standard: Vec::new(),
        windows: Vec::new(),
    };
    publish(&snapshot, &dir);

    let out = check(&dir);
    assert!(out.status.success(), "{}", text(&out));
}

/// Publishes the full build, applies `tamper` to one file, and requires `--check` to refuse and
/// to name that file.
fn refused(file: &str, tamper: impl FnOnce(String) -> String) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("current");
    publish(&full_snapshot(), &dir);
    let path = dir.join(file);
    let original = std::fs::read_to_string(&path).unwrap();
    let changed = tamper(original.clone());
    assert_ne!(changed, original, "{file}: the tamper changed nothing");
    std::fs::write(&path, changed).unwrap();

    let out = check(&dir);
    assert!(
        !out.status.success(),
        "{file}: a tampered file passed the check\n{}",
        text(&out)
    );
    assert!(
        text(&out).contains(file),
        "{file}: the refusal does not name the file\n{}",
        text(&out)
    );
}

#[test]
fn a_firewall_file_carrying_a_command_of_its_own_is_refused() {
    // The files a consumer runs as root. One extra statement is a rule on every consumer's
    // firewall.
    refused("aggressive.nft", |s| {
        s + "add rule inet filter input tcp dport 22 accept\n"
    });
    refused("aggressive.nft", |s| {
        s.replace(
            "flush set inet propolis propolis_aggressive_v4",
            "flush ruleset",
        )
    });
    refused("aggressive.nft", |s| {
        s.replace("\t45.10.30.90,", "\t0.0.0.0/0,")
    });
    refused("aggressive.ipset", |s| s + "destroy\n");
    refused("aggressive.ipset", |s| {
        s.replace(
            "add propolis_aggressive_v4-new 45.10.30.90",
            "add some_other_set 45.10.30.90",
        )
    });
    refused("all-7d.ipset", |s| {
        s.replace("maxelem 1048576", "maxelem 1")
    });
    refused("aggressive.rpz", |s| s + "example.com CNAME .\n");
    refused("aggressive.rpz", |s| {
        s + "*.example.com CNAME rpz-passthru.\n"
    });
    refused("aggressive.pf", |s| s + "pass in all\n");
}

#[test]
fn an_address_of_the_wrong_family_in_a_typed_set_is_refused() {
    refused("aggressive.nft", |s| {
        s.replace("\t2003:aaaa:bbbb::7\n", "\t45.10.30.7\n")
    });
    refused("aggressive.ipset", |s| {
        s.replace(
            "add propolis_aggressive_v6-new 2003:aaaa:bbbb::7",
            "add propolis_aggressive_v6-new 45.10.30.7",
        )
    });
}

#[test]
fn a_list_file_holding_anything_but_addresses_is_refused() {
    refused("aggressive.txt", |s| {
        s + "root:x:0:0:root:/root:/bin/bash\n"
    });
    refused("aggressive.txt", |s| {
        s.replace("# Entries: 4", "# Entries: 3")
    });
    refused("aggressive.alias", |s| s + "db.internal.example\n");
    refused("aggressive.cidr", |s| {
        s.replace("45.10.30.7/32", "45.10.30.0/24")
    });
    refused("aggressive.cidr", |s| {
        s.replace("45.10.30.7/32", "45.10.30.7/128")
    });
    refused("standard.alias", |_| "\u{0}".into());
    refused("aggressive.txt", |s| {
        s.replace("45.10.30.90\n", "45.10.30.90\r\n")
    });
    refused("aggressive.txt", |s| {
        s.replace("45.10.30.90\n", "45.10.30.090\n")
    });
    refused("aggressive.alias", |s| s.trim_end().to_string());
}

#[test]
fn a_data_file_with_a_field_the_publisher_does_not_write_is_refused() {
    refused("aggressive.json", |s| {
        s.replace(r#""count":4}"#, r#""count":4,"note":"x"}"#)
    });
    refused("aggressive.json", |s| {
        s.replace(
            r#""signals":["catchall_probe"]"#,
            r#""signals":["Catchall Probe"]"#,
        )
    });
    refused("aggressive.json", |s| {
        s.replace(r#""count":4"#, r#""count":5"#)
    });
    refused("aggressive.json", |s| s + "\n{}");
    refused("aggressive.csv", |s| s.replace(",1234,", ",1234,extra,"));
    refused("aggressive.csv", |s| {
        s.replace("ip,first_seen", "ip,hostname,first_seen")
    });
    refused("all-7d.json", |s| {
        s.replace(r#""tier":"all-7d""#, r#""tier":"aggressive""#)
    });
}

#[test]
fn a_time_finer_than_the_hour_is_refused_wherever_it_appears() {
    // The feed states hour boundaries only. A file that says more is not one the publisher wrote.
    refused("aggressive.txt", |s| s.replace("T14:00:00Z", "T14:37:52Z"));
    refused("aggressive.json", |s| s.replace("T11:00:00Z", "T11:00:01Z"));
    refused("aggressive.pf", |s| {
        s.replace("T14:00:00Z", "T14:00:00+02:00")
    });
    refused("manifest.json", |s| s.replace("T14:00:00Z", "T14:05:00Z"));
}

#[test]
fn a_manifest_that_is_not_the_publishers_or_disagrees_with_the_files_is_refused() {
    refused("manifest.json", |s| {
        s.replace(
            r#"{"build_time""#,
            r#"{"host":"node-7.internal","build_time""#,
        )
    });
    refused("manifest.json", |s| {
        s.replace(r#""label":"7d""#, r#""label":"30d""#)
    });
    refused("manifest.json", |_| "{}".into());

    // A window file the manifest does not list.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("current");
    let mut snapshot = full_snapshot();
    publish(&snapshot, &dir);
    let manifest = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
    snapshot.windows.pop();
    let fewer = tempfile::tempdir().unwrap();
    let fewer_dir = fewer.path().join("current");
    publish(&snapshot, &fewer_dir);
    let fewer_manifest = std::fs::read_to_string(fewer_dir.join("manifest.json")).unwrap();
    assert_ne!(manifest, fewer_manifest);
    std::fs::write(dir.join("manifest.json"), fewer_manifest).unwrap();
    let out = check(&dir);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("all-7d"), "{}", text(&out));
}
