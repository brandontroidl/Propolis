//! Executable documentation-truth checks for the README "Scoring" section.
//!
//! Each test asserts a specific, load-bearing claim the README makes about scoring/eligibility
//! behavior against the shipped code. If the behavior drifts from the docs, the matching test
//! fails and its name identifies the README claim that must be updated (or the regression fixed).
//!
//! This module exists because the README previously drifted from the code: it claimed a two-category
//! eligibility gate (that leg was dropped 2026-08-19) and a decay-out feed (the feed is actually
//! retention-based). See README.md, section "## Scoring".
//!
//! The feed-membership / retention claim ("membership is decided by retention windows, not the live
//! score") is guarded in the `feed` crate's builder tests, since that behavior lives there.

use super::constants::HALF_LIFE_SECONDS;
use super::eligibility::eligible;

// README "Confirmed-real gate": an IP is reportable only after a completed TCP handshake proves the
// source address is genuine.
#[test]
fn readme_confirmed_real_is_required_for_eligibility() {
    // No amount of volume or category breadth makes an unconfirmed source eligible.
    assert!(!eligible(false, 1_000, 9, false));
    assert!(eligible(true, 2, 0, false));
}

// README "Eligibility latch": an IP becomes feed-eligible once it is confirmed-real and has at least
// two recorded events.
#[test]
fn readme_eligibility_needs_confirmed_real_and_at_least_two_events() {
    assert!(!eligible(true, 1, 9, false)); // one event is not enough
    assert!(eligible(true, 2, 0, false)); // two events + confirmed-real is enough
}

// README "Eligibility latch": "Signal category breadth ... is not itself an eligibility gate."
// This is the exact claim that had drifted - the README used to require signals from two distinct
// categories, a leg dropped 2026-08-19. If a category gate is ever re-added to `eligible`, this test
// fails and points right here.
#[test]
fn readme_eligibility_has_no_distinct_category_gate() {
    // The distinct-category count never changes the eligibility outcome for an otherwise-eligible IP.
    for categories in [0u32, 1, 2, 50] {
        assert!(
            eligible(true, 2, categories, false),
            "distinct_categories={categories} must not gate eligibility"
        );
    }
}

// README "Eligibility latch": "a sticky latch - once earned it persists (it is not re-derived from
// the live decaying score) until the address is explicitly delisted."
#[test]
fn readme_eligibility_is_not_derived_from_a_decaying_score() {
    // `eligible` takes no score input at all, so a decayed score can never revoke eligibility, and a
    // very high cumulative event_count stays eligible regardless. The stickiness is that event_count
    // is monotonic and no score feeds this decision.
    assert!(eligible(true, u32::MAX, 0, false));
}

// README "Eligibility latch": "until the address is explicitly delisted."
#[test]
fn readme_delist_is_the_only_removal() {
    assert!(eligible(true, 100, 5, false));
    assert!(!eligible(true, 100, 5, true)); // an explicit delist, and only that, removes it
}

// README "Score decay and retention": "the score decays with a 6-hour half-life".
#[test]
fn readme_score_half_life_is_six_hours() {
    assert_eq!(HALF_LIFE_SECONDS, 6 * 60 * 60);
}

// README "Confirmed-real gate": the MECHANISM behind "spoofable UDP or lone-SYN traffic never
// latches this". Only a TCP connection that authenticated against a honeypot sensor is confirmed-
// real; UDP, ICMP, and unauthenticated (lone-SYN-style) traffic never are. Vendor reports and the
// feed TIERS gate on this via `eligible`, so a spoofed source can earn neither.
//
// VOLUME EXCEPTION, and how it stays spoofing-safe: the volume-listed RETENTION path does NOT gate
// on confirmed-real (see the feed builder's `eligible = false` query and its
// `a_volume_flood_lands_in_retention_but_not_the_tier_files` test). But it counts only ESTABLISHED
// (completed-TCP) connections, never spoofable UDP/ICMP - `sensor-catchall` DOES run a live UDP
// listener, so this gating is load-bearing, not hypothetical. A spoofed UDP flood therefore cannot
// volume-list an innocent third party; guarded by `engine`'s
// `a_udp_only_flood_is_not_volume_listed_even_over_the_threshold` (spoofable) vs
// `a_high_volume_tcp_flood_is_blocklisted_on_volume_without_confirmed_real` (non-spoofable).
#[test]
fn readme_confirmed_real_requires_a_tcp_authenticated_honeypot_hit() {
    use crate::domain::enums::{Category, Protocol, is_confirmed_real};
    assert!(is_confirmed_real(Protocol::Tcp, true, Category::Honeypot));
    // Any missing leg means not confirmed-real - i.e. spoofable / non-handshake traffic never latches.
    assert!(!is_confirmed_real(Protocol::Udp, true, Category::Honeypot)); // UDP is spoofable
    assert!(!is_confirmed_real(Protocol::Icmp, true, Category::Honeypot)); // ICMP is spoofable
    assert!(!is_confirmed_real(Protocol::Tcp, false, Category::Honeypot)); // no completed app auth
    assert!(!is_confirmed_real(Protocol::Tcp, true, Category::Network)); // not a honeypot hit
}
