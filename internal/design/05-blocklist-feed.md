# Sub-project 5: blocklist feed builder + exporters + publisher

Detailed design spec for the Propolis-new feed layer (Rust). This layer reads approved, eligible,
recommended-for-blocklist IP scores and publishes a two-tier public blocklist in multiple
machine-readable formats.

## Purpose and scope

This layer owns four things and nothing else:

1. The feed builder: queries ip_score for IPs where `recommended_for_blocklist = true` AND
   `eligible = true`, decays scores to now, groups by tier (Aggressive, Standard), and applies
   exclusions. Produces a `FeedSnapshot` - a timestamped, immutable list of entries per tier.
2. The exclusion engine: fail-closed filtering that prevents private, reserved, allowlisted, or
   delisted addresses from reaching any export. Applied at build time AND re-validated at publish.
3. The exporters: convert a FeedSnapshot to plain text, JSON, CSV, and CIDR formats with
   anti-deanonymization coarsening applied uniformly.
4. The publisher: writes exported files to a configurable output directory with fail-closed
   validation. Out-of-band distribution (rsync, S3, web server) is the operator's deployment concern.

This layer has no sensor, no intake, no vendor client, and no web console. It reads ip_score
projections (read-only database access) and writes files to a local directory.

## Inherited invariants

- **Human-approval gate.** The feed reads only IPs that passed through the review queue's approval
  flow. `recommended_for_blocklist` is derived from eligibility + effective score, which in turn
  requires confirmed-real evidence. The feed never invents entries.
- **Collateral safety.** Entries are host routes (/32 for IPv4, /128 for IPv6) by default. Block
  aggregation to a shorter prefix happens ONLY when every address in the block is independently
  listed, so aggregation never blocks an unlisted address.
- **No self-deanonymization.** Per-entry confidence, raw scores, and precise timestamps are not
  exported. All timestamps are coarsened uniformly across every exporter and every derived field
  (validity start, validity end, expiry, build time) so that subtracting a publicly known tier
  window from one field cannot recover the value of another.

## Architecture

One crate, added to the workspace:

- `crates/feed` - the feed builder, exporters, publisher, and binary. Depends on `core-scoring`
  (IpScore, read_score, FeedTier), `sqlx`, `tokio`, `serde`/`serde_json`, `chrono`, `tracing`.

### Crate structure

```
crates/feed/
  Cargo.toml
  src/
    lib.rs              # public API
    builder.rs          # FeedBuilder - query, decay, tier, exclude -> FeedSnapshot
    exclusion.rs        # ExclusionEngine - RFC1918/5737, operator allowlist, delist set
    export/
      mod.rs            # Exporter trait, FeedSnapshot, FeedEntry, coarsening helpers
      plaintext.rs      # one-IP-per-line with comment header
      json.rs           # structured JSON with metadata
      csv.rs            # IP,tier,first_seen,last_seen
      cidr.rs           # CIDR notation with safe aggregation
    publisher.rs        # write files to output dir with fail-closed validation
    main.rs             # binary entry point, periodic build loop
  tests/
    builder_test.rs     # build from real DB, exclusion, tier grouping
    exclusion_test.rs   # RFC1918/5737 filtering, allowlist, delist
    export_test.rs      # format correctness, coarsening, round-trip
    publisher_test.rs   # fail-closed validation, file writing
```

## The feed builder

### FeedSnapshot

```rust
pub struct FeedSnapshot {
    pub build_time: DateTime<Utc>,        // coarsened to hour
    pub aggressive: Vec<FeedEntry>,
    pub standard: Vec<FeedEntry>,
}

pub struct FeedEntry {
    pub source_ip: IpAddr,
    pub tier: FeedTier,
    pub first_seen: DateTime<Utc>,        // coarsened to hour
    pub last_seen: DateTime<Utc>,         // coarsened to hour
    pub event_count: i32,
    pub distinct_categories: i32,
    pub valid_from: DateTime<Utc>,        // = coarsened build_time
    pub valid_until: DateTime<Utc>,       // = valid_from + tier_ttl
}
```

### Build process

1. Query ip_score for all IPs where `recommended_for_blocklist = true` AND `eligible = true`.
2. For each IP, read the score decayed to now via `core_scoring::read_score`.
3. Determine tier from `ip_score.tier` (Aggressive or Standard). IPs with `tier = None` are
   excluded (they are recommended for blocklist but below the tier floor - this should not happen
   if the scoring logic is consistent, but fail-closed means we exclude rather than assume).
4. Apply exclusions (see Exclusion engine).
5. Coarsen all timestamps to the nearest hour (truncate to hour boundary).
6. Compute validity windows: Aggressive tier gets 24h TTL, Standard gets 48h.
7. Return a FeedSnapshot sorted by tier then by IP address.

### Timestamp coarsening (anti-deanonymization)

All timestamps in the feed are truncated to the nearest hour boundary:
- `build_time`: truncated to the current hour
- `first_seen`, `last_seen`: truncated to the hour
- `valid_from` = `build_time` (already coarsened)
- `valid_until` = `valid_from` + tier-specific TTL

This prevents the attack described in SP2's deferred items: if `valid_until` were derived from a
precise `last_seen`, subtracting the known TTL would recover the exact `last_seen`. By coarsening
all timestamps to the same granularity, the precision loss is uniform and the recovery is bounded
to a 1-hour window.

## Exclusion engine

The exclusion engine is a fail-closed filter. An IP is excluded if ANY of the following is true:

1. **Reserved ranges:** RFC1918 (10/8, 172.16/12, 192.168/16), RFC5737 (192.0.2/24, 198.51.100/24,
   203.0.113/24), loopback (127/8), link-local (169.254/16), multicast (224/4), broadcast.
   IPv6 equivalents: ::1, fe80::/10, fc00::/7, ff00::/8, 2001:db8::/32.
2. **Operator allowlist:** a configurable set of IPs or CIDR blocks the operator exempts from the
   feed (e.g., their own infrastructure, known partners).
3. **Delist set:** IPs the operator has explicitly delisted. A delisted IP stays in the scoring
   database but is removed from the feed.

The exclusion engine is applied at build time. The publisher re-validates every entry before writing,
providing defense-in-depth. If any entry fails the re-validation, the entire feed build is rejected
(fail-closed at the snapshot level, not per-entry - a single leaked reserved IP would invalidate the
operator's trust in the whole feed).

## Exporters

Each exporter converts a FeedSnapshot (or one tier from it) to a specific format. All exporters
share the same coarsened timestamps.

### Plain text

```
# Propolis blocklist - Aggressive tier
# Generated: 2026-07-29T14:00:00Z
# Valid until: 2026-07-30T14:00:00Z
# Entries: 42
203.0.113.7
203.0.113.12
198.51.100.99
```

### JSON

```json
{
  "meta": {
    "generator": "propolis",
    "tier": "aggressive",
    "generated": "2026-07-29T14:00:00Z",
    "valid_until": "2026-07-30T14:00:00Z",
    "count": 42
  },
  "entries": [
    {
      "ip": "203.0.113.7",
      "first_seen": "2026-07-20T10:00:00Z",
      "last_seen": "2026-07-29T13:00:00Z",
      "categories": 3,
      "events": 47
    }
  ]
}
```

No raw score, no confidence, no per-entry tier label (the tier is the file, not the entry).

### CSV

```
ip,first_seen,last_seen,categories,events
203.0.113.7,2026-07-20T10:00:00Z,2026-07-29T13:00:00Z,3,47
```

### CIDR

Host routes by default. Aggregation to a shorter prefix ONLY when every address in the block is
independently listed. For example, if all 256 addresses in 203.0.113.0/24 are independently in the
feed, the exporter MAY emit `203.0.113.0/24` instead of 256 separate /32 entries. But if even one
address in the block is not listed, the block stays as individual /32s. This is the collateral-safety
guarantee.

For the initial implementation, CIDR export emits only /32 host routes (no aggregation). Safe
aggregation is a future optimization that requires proving every address in the block is
independently listed, which is complex and can be deferred without losing functionality.

## Publisher

The publisher writes exported files to a configurable output directory:

```
/var/lib/propolis/feed/
  aggressive.txt
  aggressive.json
  aggressive.csv
  aggressive.cidr
  standard.txt
  standard.json
  standard.csv
  standard.cidr
  manifest.json     # build metadata, checksums
```

### Fail-closed validation

Before writing any file, the publisher re-validates every entry against the exclusion engine. If
ANY entry fails, the entire build is rejected and no files are written. This is defense-in-depth:
the builder already applied exclusions, but a bug in the builder should not leak a reserved IP.

### Atomic publish

Files are written to a temporary directory, then atomically renamed to the output directory (or
symlink-swapped). This ensures consumers never see a partially-written feed.

### Manifest

```json
{
  "build_time": "2026-07-29T14:00:00Z",
  "tiers": {
    "aggressive": { "count": 42, "sha256": "...", "valid_until": "2026-07-30T14:00:00Z" },
    "standard": { "count": 187, "sha256": "...", "valid_until": "2026-07-31T14:00:00Z" }
  }
}
```

The manifest's `build_time` is coarsened to the same hour as the feed entries.

## Configuration

```rust
pub struct FeedConfig {
    pub database_url: String,
    pub output_dir: PathBuf,
    pub build_interval: Duration,           // default 15 minutes
    pub aggressive_ttl: Duration,           // default 24 hours
    pub standard_ttl: Duration,             // default 48 hours
    pub allowlist: Vec<IpNet>,              // operator-exempted ranges
    pub delist: Vec<IpAddr>,                // explicitly delisted IPs
}
```

Loaded from environment variables.

## Error handling

- A database error during the build query fails the entire build. No partial feed is published.
- An exclusion check that cannot be evaluated (e.g., allowlist file unreadable) fails the entire
  build. Fail-closed.
- A file write error fails the entire publish. The previous feed version stays in place.
- An empty feed (zero entries) is published normally (the output files are valid, just empty).
  This is not an error - it means no IPs currently meet the recommendation threshold.

## Testing strategy

- **Builder from real DB.** Seed ip_score data via append_event, build the feed, verify entries
  match the expected IPs with correct tier assignment.
- **Exclusion filtering.** RFC1918/5737 IPs are excluded. Allowlisted IPs are excluded. Delisted
  IPs are excluded.
- **Timestamp coarsening.** Verify all timestamps in the snapshot are truncated to hour boundaries.
  Verify no raw score or confidence appears in any export format.
- **Export format correctness.** Each exporter produces valid, parseable output. JSON round-trips.
  CSV parses. Plain text has the correct header and one IP per line.
- **Publisher fail-closed.** Inject a reserved IP into a snapshot (bypassing the builder's
  exclusion), verify the publisher rejects the entire build.
- **Atomic publish.** Verify the output directory is updated atomically (old version stays until
  new version is complete).

## Decisions closed by this spec

1. Export formats: **plain text, JSON, CSV, CIDR** per tier.
2. Expiry policy: **Aggressive 24h, Standard 48h** from coarsened build time.
3. Timestamp coarsening: **hourly truncation** applied uniformly across all fields and all exporters.
4. CIDR aggregation: **host routes only (/32) for initial implementation.** Safe aggregation
   deferred as a future optimization.
5. Publish transport: **local directory.** Out-of-band distribution is the operator's deployment
   concern, not this crate's.
6. Anti-deanonymization: **no raw score, no confidence, no precise timestamps** in any export.

## Open questions - deferred

- Safe CIDR aggregation (proving every address in a block is independently listed) - future
  optimization.
- Out-of-band distribution (rsync, S3, CDN) - operator deployment concern.
- Feed signing (cryptographic signature on the manifest) - future hardening.
