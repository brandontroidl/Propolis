//! End-to-end scenarios against a real Postgres, using ONLY the crate's
//! public API (`core_scoring::...`) — no submodule paths.
//!
//! Run with `DATABASE_URL` exported (see `.env`):
//!   set -a; . ./.env; set +a; cargo test -p core-scoring --test end_to_end
//! `#[sqlx::test]` provisions a fresh, isolated database per test and applies
//! the migrations, so the three scenarios never share state.
//!
//! Three scenarios, each proving one load-bearing anti-spoof/scoring
//! invariant end-to-end (real DB, real transactional append path, real
//! projection read), not just at the pure-function level:
//!
//!   (A) breadth from non-confirmed-real signals — even genuine (not spoofed)
//!       authenticated-TCP breadth across several distinct WANs, multiple
//!       categories, and multiple events — never confers eligibility, because
//!       no event was ever tcp+authenticated+honeypot.
//!   (B) one confirmed-real honeypot event plus a second corroborating
//!       category crosses into eligible, with the tier/vendor recommendation
//!       following the RAW score.
//!   (C) breadth raises the effective score (and so the blocklist
//!       recommendation) but never the RAW score the vendor tier is gated on.

use core_scoring::{append_event, EventInput, FeedTier, Protocol, RepoError, SignalType};

use sqlx::PgPool;

/// Builds an `EventInput` via the public `from_signal` constructor, which
/// derives weight/confidence/category from the signal-weight table.
#[allow(clippy::too_many_arguments)]
fn ev(
    ip: &str,
    wan: Option<&str>,
    sensor: &str,
    signal: SignalType,
    protocol: Protocol,
    authenticated: bool,
    ts: &str,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        wan.map(|w| w.parse().unwrap()),
        sensor.into(),
        signal,
        protocol,
        authenticated,
        ts.parse().unwrap(),
        serde_json::json!({}),
    )
}

/// (A) Spoof stays unreportable: several NON-confirmed-real events from one
/// source, spread across three distinct authenticated-TCP WAN vantages (real
/// breadth, not the spoofed unauthenticated kind) and three distinct
/// categories (Auth, Waf, Network) — but never a tcp+authenticated+honeypot
/// event. `has_confirmed_real` must never latch, so `eligible` and
/// `recommended_for_vendor` must stay false no matter how much breadth,
/// category diversity, or event count accrues.
#[sqlx::test(migrations = "./migrations")]
async fn spoof_without_confirmed_real_stays_unreportable(pool: PgPool) -> Result<(), RepoError> {
    const IP: &str = "203.0.113.50";

    // Auth category, tcp+authenticated, on wan1 — real (non-spoofed) breadth.
    append_event(
        &pool,
        ev(
            IP,
            Some("192.0.2.10"),
            "ssh-sensor",
            SignalType::SshBruteForce,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:00Z",
        ),
    )
    .await?;

    // Auth category (different signal_type, so no dedup), tcp+authenticated,
    // on a second distinct /24 WAN vantage.
    append_event(
        &pool,
        ev(
            IP,
            Some("198.51.100.10"),
            "auth-sensor",
            SignalType::RemoteAuthFailure,
            Protocol::Tcp,
            true,
            "2026-07-17T00:01:00Z",
        ),
    )
    .await?;

    // Waf category, tcp+authenticated, on a third distinct /24 WAN vantage —
    // three real authenticated vantages now, plus a third distinct category.
    append_event(
        &pool,
        ev(
            IP,
            Some("203.0.113.99"),
            "waf-sensor",
            SignalType::WafGenericBlock,
            Protocol::Tcp,
            true,
            "2026-07-17T00:02:00Z",
        ),
    )
    .await?;

    // Two classic spoofable udp probes, no wan (never counted for breadth
    // anyway), still never honeypot.
    append_event(
        &pool,
        ev(
            IP,
            None,
            "probe-sensor",
            SignalType::CatchallProbe,
            Protocol::Udp,
            false,
            "2026-07-17T00:03:00Z",
        ),
    )
    .await?;
    let s = append_event(
        &pool,
        ev(
            IP,
            None,
            "probe-sensor",
            SignalType::PortScan,
            Protocol::Udp,
            false,
            "2026-07-17T00:04:00Z",
        ),
    )
    .await?;

    // Sanity: this scenario really did accrue event count, category
    // diversity, and authenticated WAN breadth — so the negative assertions
    // below are not vacuous.
    assert_eq!(s.event_count, 5);
    assert!(s.distinct_categories >= 2, "expected multi-category corroboration to have accrued");
    assert!(s.distinct_wan_count >= 2, "expected authenticated-WAN breadth to have accrued");

    // The load-bearing assertions: no confirmed-real event was ever fed, so
    // eligibility and the vendor recommendation must stay false regardless.
    assert!(!s.has_confirmed_real);
    assert!(!s.eligible);
    assert!(!s.recommended_for_vendor);

    Ok(())
}

/// (B) Confirmed-real, corroborated -> eligible + tiered.
///
/// One `honeypot_malware_upload` (tcp+authenticated) event alone raises raw
/// to 80 (weight 80, confidence 0.980, category Honeypot) — already above the
/// STANDARD floor (raw >= 75) on its own. A second, small `suricata_sev3`
/// event (weight 5, confidence 0.300, category Ids) supplies the second
/// distinct category and second event `eligible` requires, without pushing
/// raw (85) up to the AGGRESSIVE floor (raw >= 90).
#[sqlx::test(migrations = "./migrations")]
async fn confirmed_real_plus_second_category_is_eligible_and_tiered(
    pool: PgPool,
) -> Result<(), RepoError> {
    const IP: &str = "198.51.100.42";

    append_event(
        &pool,
        ev(
            IP,
            None,
            "honeypot-sensor",
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:00Z",
        ),
    )
    .await?;

    let s = append_event(
        &pool,
        ev(
            IP,
            None,
            "ids-sensor",
            SignalType::SuricataSev3,
            Protocol::Udp,
            false,
            "2026-07-17T00:01:00Z", // close in time: no decay-driven category fade
        ),
    )
    .await?;

    assert_eq!(s.event_count, 2);
    assert_eq!(s.distinct_categories, 2);
    // 80 + 5, no dedup/cap; ~1 minute of decay between the two events is
    // negligible against the 6h half-life, so compare with a small epsilon.
    assert!((s.raw_score - rust_decimal_macros::dec!(85)).abs() < rust_decimal_macros::dec!(0.5));
    assert!(s.has_confirmed_real);

    assert!(s.eligible);
    assert_eq!(s.tier, Some(FeedTier::Standard)); // raw 85 in [75,90), conf 0.980 >= 0.70
    assert!(s.recommended_for_vendor);

    Ok(())
}

/// (C) Breadth raises the blocklist recommendation, never the vendor tier.
///
/// A confirmed-real, eligible IP whose RAW score (55 = 40 + 15) sits in
/// [50, 75): a `honeypot_connection` event (weight 40, Honeypot) plus a
/// `suricata_sev2` event (weight 15, Ids) for the second category. A THIRD
/// event repeats `honeypot_connection` within the dedup window (so it adds NO
/// weight) but on a third distinct authenticated-TCP WAN vantage, so it still
/// raises `distinct_wan_count` to 3 — breadth accrued without inflating raw.
/// `effective_score = raw * breadth_factor(3) = 55 * 1.3 = 71.5 >= 50`, so
/// blocklist fires; but `tier` is computed from RAW (55 < 75), so it stays
/// `None` and the vendor recommendation stays false.
#[sqlx::test(migrations = "./migrations")]
async fn breadth_raises_blocklist_never_vendor_tier(pool: PgPool) -> Result<(), RepoError> {
    const IP: &str = "192.0.2.77";

    // e1: confirmed-real honeypot connection, wan1 (first authenticated vantage).
    append_event(
        &pool,
        ev(
            IP,
            Some("192.0.2.10"),
            "honeypot-sensor",
            SignalType::HoneypotConnection,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:00Z",
        ),
    )
    .await?;

    // e2: second category (Ids), wan2 (second authenticated vantage).
    append_event(
        &pool,
        ev(
            IP,
            Some("198.51.100.20"),
            "ids-sensor",
            SignalType::SuricataSev2,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:20Z",
        ),
    )
    .await?;

    // e3: SAME signal_type as e1, 50s after e1 -> within the 60s dedup window,
    // so it adds NO weight — but it lands on wan3, a third distinct
    // authenticated-TCP vantage, so distinct_wan_count still rises to 3.
    let s = append_event(
        &pool,
        ev(
            IP,
            Some("203.0.113.30"),
            "honeypot-sensor",
            SignalType::HoneypotConnection,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:50Z",
        ),
    )
    .await?;

    assert_eq!(s.event_count, 3);
    assert_eq!(s.distinct_categories, 2); // Honeypot, Ids
    assert!(s.has_confirmed_real);
    // 40 + 15; e3 deduped, adds 0. Seconds-scale decay against a 6h half-life
    // is negligible, so compare with a small epsilon.
    assert!((s.raw_score - rust_decimal_macros::dec!(55)).abs() < rust_decimal_macros::dec!(0.5));
    assert!(s.raw_score >= rust_decimal_macros::dec!(50) && s.raw_score < rust_decimal_macros::dec!(75));
    assert_eq!(s.distinct_wan_count, 3);

    assert!(s.eligible);

    // The load-bearing assertions: breadth-boosted effective score clears the
    // blocklist floor, but the vendor tier is gated on RAW alone and RAW never
    // reached 75, so tier/vendor recommendation stay off.
    assert!(s.recommended_for_blocklist, "effective 55*1.3=71.5 >= 50 floor");
    assert_eq!(s.tier, None, "tier is gated on raw (55), never effective");
    assert!(!s.recommended_for_vendor);

    Ok(())
}
