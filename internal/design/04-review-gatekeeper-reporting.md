# Sub-project 4: review queue + gatekeeper + vendor reporting

Detailed design spec for the Propolis-new review and reporting layer (Rust). This layer sits on top
of the core scoring layer (sub-project 1) and the intake layer (sub-project 3): it reads ip_score
projections, surfaces recommended IPs for operator review, and submits approved reports to vendor
abuse-reporting services.

## Purpose and scope

This layer owns four things and nothing else:

1. The review queue: a state machine that surfaces one open decision per source IP when
   `recommended_for_vendor` becomes true, and holds it for the operator's explicit approval,
   rejection, or snooze. Nothing auto-fires.
2. The gatekeeper: a per-vendor, per-submission check sequence (cooldown, rate limit, score floor,
   category filter) that runs at submission time, after operator approval. Fail-closed: any failed
   or unreadable check holds the submission.
3. The vendor adapters: protocol-specific clients for AbuseIPDB, DShield, and OTX that build the
   report payload, submit it, and record the result. Idempotent under retry.
4. The submission daemon + operator CLI: a binary that polls for approved entries and submits them,
   plus a command-line interface for the operator to approve, reject, or snooze queue entries until
   the web console (sub-project 6) is built.

This layer has no sensor, no feed publisher, no web console, and no VirusTotal integration. It reads
ip_score projections (read-only access to the scoring layer's tables) and writes to its own tables
(review_queue, vendor_submission). VirusTotal sample forwarding, quarantine retention, and the
remaining sensors are sub-project 8's scope.

## Inherited invariants

- **Human-approval gate.** The foundational invariant this layer realizes. Nothing is reported to a
  vendor without explicit operator approval. The review queue holds a Pending entry indefinitely;
  the submission daemon processes only Approved entries. There is no auto-approve path, no timeout
  that defaults to approve, and no bulk-approve-by-score.
- **Eligible before reportable.** The review queue only surfaces IPs where `eligible = true` and
  `recommended_for_vendor = true` on the current ip_score projection. An IP that loses eligibility
  (e.g., its confirmed-real event decays below the threshold) is removed from the queue even if it
  was previously Pending.
- **Breadth raises weight, never confers eligibility.** This layer does not re-derive eligibility;
  it reads the projection as-is. The invariant is inherited, not re-implemented.

## Architecture

One crate, added to the workspace:

- `crates/review` - the review queue, gatekeeper, vendor adapters, and binary. Depends on
  `core-scoring` (ip_score projection, domain types), `sqlx` (PostgreSQL), `reqwest` (vendor API
  calls), `tokio`, `serde`/`serde_json`, `tracing`.

### Crate structure

```
crates/review/
  Cargo.toml
  migrations/
    0001_review_queue.sql
    0002_vendor_submission.sql
  src/
    lib.rs              # public API
    queue.rs            # ReviewQueue - state machine, queue population, operator decisions
    gatekeeper.rs       # Gatekeeper - per-vendor submission checks
    submit.rs           # SubmissionRunner - poll approved entries, submit through gatekeeper
    vendor/
      mod.rs            # VendorAdapter trait, VendorReport struct, category mapping
      abuseipdb.rs      # AbuseIPDB REST adapter
      dshield.rs        # DShield HTTP adapter
      otx.rs            # OTX pulse adapter
    cli.rs              # CLI for operator review decisions
    main.rs             # binary entry point (submission daemon + CLI dispatch)
  tests/
    queue_test.rs       # state machine, population, eligibility withdrawal
    gatekeeper_test.rs  # check sequence, cooldown, rate limit, fail-closed
    submit_test.rs      # end-to-end with mock vendor
    vendor_test.rs      # category mapping, payload construction
```

## Database schema

Two new tables, added via migrations in the `review` crate. These extend the same PostgreSQL
database that holds the event ledger and ip_score projection.

### review_queue

```sql
CREATE TABLE review_queue (
    source_ip         INET PRIMARY KEY,
    state             review_state_enum NOT NULL DEFAULT 'pending',
    score_at_surface  NUMERIC(10,3) NOT NULL,
    categories_at_surface JSONB NOT NULL,
    surfaced_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at        TIMESTAMPTZ,
    notes             TEXT
);
```

- One row per source IP. The primary key prevents duplicate entries.
- `state` uses the existing `review_state_enum` (Pending, Approved, Rejected, Snoozed).
- `score_at_surface` and `categories_at_surface` snapshot the ip_score at the time the IP was
  surfaced, so the operator sees what triggered the recommendation even if the score decays later.
- `decided_at` is set when the operator acts (approve/reject/snooze).
- `notes` is a free-text field for the operator to record reasoning.

### vendor_submission

```sql
CREATE TABLE vendor_submission (
    id                BIGSERIAL PRIMARY KEY,
    source_ip         INET NOT NULL,
    vendor            TEXT NOT NULL,
    idempotency_key   TEXT NOT NULL UNIQUE,
    categories        TEXT[] NOT NULL,
    comment           TEXT NOT NULL,
    submitted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    response_status   INTEGER,
    response_body     TEXT,
    success           BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_vendor_submission_ip_vendor
    ON vendor_submission (source_ip, vendor, submitted_at DESC);
```

- One row per submission attempt. The `idempotency_key` (UNIQUE) prevents double-submission on retry.
- `vendor` is the vendor name string (e.g., "abuseipdb", "dshield", "otx").
- `categories` is the vendor-specific abuse category codes submitted.
- `response_status` and `response_body` record the vendor's response for audit.
- `success` is true if the vendor accepted the report.

## The review queue

### Population

The queue is populated by a periodic scan that runs inside the submission daemon:

```sql
INSERT INTO review_queue (source_ip, score_at_surface, categories_at_surface)
SELECT source_ip, raw_score, category_breakdown
FROM ip_score
WHERE recommended_for_vendor = TRUE
  AND eligible = TRUE
  AND source_ip NOT IN (SELECT source_ip FROM review_queue)
ON CONFLICT DO NOTHING;
```

This surfaces newly-recommended IPs that are not already in the queue. The scan runs on a
configurable interval (default: every 60 seconds). An IP that was previously Rejected or Snoozed
is not re-surfaced unless the operator explicitly clears it.

### Withdrawal

If an IP's projection changes so that `recommended_for_vendor` or `eligible` becomes false while
the queue entry is still Pending, the entry is removed:

```sql
DELETE FROM review_queue
WHERE state = 'pending'
  AND source_ip NOT IN (
    SELECT source_ip FROM ip_score
    WHERE recommended_for_vendor = TRUE AND eligible = TRUE
  );
```

Only Pending entries are withdrawn. Approved entries stay (the operator's decision stands even if the
score decays). Rejected and Snoozed entries stay as a record.

### Operator decisions

Three actions, exposed via CLI (and later via the web console in SP6):

- **Approve:** sets `state = 'approved'`, `decided_at = now()`. The submission daemon picks it up.
- **Reject:** sets `state = 'rejected'`, `decided_at = now()`. The IP is not reported. The entry
  stays as a record so the same IP is not re-surfaced.
- **Snooze:** sets `state = 'snoozed'`, `decided_at = now()`. The IP is held for later review. A
  snoozed entry can be re-opened by the operator.

The CLI also supports listing the queue (pending entries, with score and categories) and viewing
the submission history for an IP.

## The gatekeeper

The gatekeeper runs an ordered sequence of checks for each (IP, vendor) pair at submission time.
Every check is fail-closed: if the check cannot be evaluated (missing config, database error), the
submission is held.

### Check sequence (per vendor)

1. **Vendor enabled.** The vendor must be configured and enabled. Disabled vendors silently skip.
2. **Cooldown.** The same IP must not have been successfully submitted to this vendor within
   `cooldown_hours` (configurable per vendor, default 24). Checked via `vendor_submission` table.
3. **Rate limit.** The total submissions to this vendor in the last `rate_window_hours` must not
   exceed `rate_limit` (configurable per vendor). Prevents accidentally flooding a vendor API.
4. **Score floor.** The IP's current `raw_score` (decayed to now) must be at or above a per-vendor
   minimum (configurable, default 0 - no additional floor beyond the recommendation threshold).
5. **Category filter.** The IP's categories must include at least one that the vendor accepts
   (configurable per vendor). Some vendors only accept certain abuse types.

If all checks pass, the submission proceeds. If any check fails, the submission is held and the
reason is logged. The submission daemon retries held submissions on the next poll cycle (checks
may pass later, e.g., cooldown expires).

## Vendor adapters

Each vendor adapter implements a common trait:

```rust
pub struct VendorReport {
    pub source_ip: IpAddr,
    pub categories: Vec<String>,  // vendor-specific category codes
    pub comment: String,          // human-readable evidence summary
    pub evidence_window: (DateTime<Utc>, DateTime<Utc>),  // first_seen..last_seen
}

#[async_trait]
pub trait VendorAdapter: Send + Sync {
    fn name(&self) -> &str;
    async fn submit(&self, report: &VendorReport) -> Result<VendorResponse, VendorError>;
}

pub struct VendorResponse {
    pub status: u16,
    pub body: String,
    pub accepted: bool,
}
```

### Category mapping

The mapping from internal representation to vendor-specific categories uses `protocol_label` from
event metadata (frozen in the wire contract) plus the internal `Category` enum:

| protocol_label | Category | AbuseIPDB | DShield | OTX |
|---|---|---|---|---|
| `ssh` | Honeypot/Auth | 22 (SSH) | ssh | ssh-bruteforce |
| `telnet` | Honeypot | 23 (Telnet) | telnet | telnet-bruteforce |
| `ftp` | Honeypot | 5 (FTP) | ftp | ftp-bruteforce |
| (none) | Network | 14 (Port Scan) | scan | portscan |
| (none) | Waf | 21 (Web App Attack) | web | web-attack |
| (none) | Ids | 15 (Hacking) | intrusion | intrusion-attempt |

The mapping is a static table, not a runtime configuration. A `protocol_label` that does not match
any known mapping falls through to the generic category for that `Category` enum value. This is the
behavior the SP2 spec warns about ("silently collapses to the generic category with no error").

### AbuseIPDB adapter

- Endpoint: `https://api.abuseipdb.com/api/v2/report`
- Auth: API key via `X-Key` header (from config, never logged)
- Payload: `ip`, `categories` (comma-separated integers), `comment`, `timestamp`
- Rate limit: 15 reports per minute per API key (enforced by the gatekeeper, not the adapter)

### DShield adapter

- Endpoint: `https://www.dshield.org/api/submit`
- Auth: API key + user ID
- Payload: source IP, destination port, protocol, timestamp
- Simpler than AbuseIPDB; no category taxonomy, just port/protocol

### OTX adapter

- Endpoint: `https://otx.alienvault.com/api/v1/pulses/create`
- Auth: API key via header
- Payload: pulse with indicator (IPv4 type), tags from categories
- Creates or updates a pulse per reporting batch

### Idempotency

Each submission attempt is assigned an idempotency key before the HTTP call:

```rust
fn idempotency_key(source_ip: IpAddr, vendor: &str, date: NaiveDate) -> String {
    format!("{source_ip}:{vendor}:{date}")
}
```

The key is inserted into `vendor_submission` with `success = false` before the HTTP call. If the
call succeeds, `success` is updated to `true`. If the call fails (network error, timeout), the
row stays with `success = false` and is retried on the next poll (same key, so the INSERT hits
the UNIQUE constraint and skips - the retry updates the existing row).

If the vendor API returns "already reported" (e.g., AbuseIPDB returns 429 with "IP already
reported"), the submission is marked successful. The idempotency key's date component ensures that
a new day allows re-reporting (some vendors want periodic refreshes).

## Configuration

```rust
pub struct ReviewConfig {
    pub database_url: String,
    pub queue_scan_interval: Duration,
    pub submission_poll_interval: Duration,
    pub vendors: Vec<VendorConfig>,
}

pub struct VendorConfig {
    pub name: String,
    pub enabled: bool,
    pub api_key: String,        // from EnvironmentFile, never logged
    pub api_url: String,
    pub cooldown_hours: u32,
    pub rate_limit: u32,
    pub rate_window_hours: u32,
    pub score_floor: Option<Decimal>,
    pub category_filter: Option<Vec<String>>,
}
```

Loaded from environment variables. API keys are read from the environment, never from a config file
on disk (they are secrets).

## Error handling

- A vendor API call that times out or returns a 5xx is a transient error. The submission stays in
  the queue and is retried on the next poll. The `vendor_submission` row records the failure.
- A vendor API call that returns a 4xx (other than "already reported") is a permanent error. The
  submission is marked failed and not retried. The operator can manually re-queue it.
- A database error during queue population or submission recording is logged and retried on the
  next poll cycle. The daemon does not crash on transient DB errors.
- API keys that are missing or empty fail-closed: the vendor is treated as disabled.

## Testing strategy

- **Queue population.** Insert an ip_score with `recommended_for_vendor = true`, run the population
  scan, verify a Pending entry appears.
- **Eligibility withdrawal.** Surface an IP, then update its ip_score to `eligible = false`, run the
  withdrawal scan, verify the Pending entry is removed.
- **Operator decisions.** Approve, reject, snooze a queue entry. Verify state transitions.
- **Gatekeeper checks.** Cooldown (submit, then attempt again within window - held). Rate limit
  (exceed the limit - held). Score floor (IP below floor - held). Category filter (IP has no
  matching category - held). All fail-closed.
- **Idempotency.** Submit, record success. Retry with same key - no double submission.
- **Category mapping.** Each protocol_label + category pair maps to the expected vendor category
  codes. Unknown protocol_label falls through to generic.
- **Vendor adapter (mocked).** Each adapter builds the correct payload and handles success, transient
  error, permanent error, and "already reported" responses.
- **End-to-end (with real DB, mocked vendor).** Surface an IP, approve it, run the submission
  daemon, verify the vendor_submission row is created with `success = true`.

## Decisions closed by this spec

1. Review queue state machine: **Pending/Approved/Rejected/Snoozed**, one entry per IP, populated by
   periodic scan of ip_score, withdrawn when eligibility lapses.
2. Gatekeeper check sequence: **enabled, cooldown, rate limit, score floor, category filter**, all
   fail-closed.
3. Idempotency model: **date-scoped key (ip:vendor:date)**, INSERT-before-call with
   success-on-completion.
4. Category mapping: **static table from protocol_label + Category to vendor-specific codes**, with
   generic fallback.
5. VirusTotal sample forwarding: **deferred to SP8** (separate requirements around timing
   decorrelation and sensitivity ceilings).

## Open questions - deferred

- VirusTotal hash lookup + sample upload, quarantine retention - sub-project 8.
- Web console for operator review - sub-project 6. Until then, the CLI serves.
- Bulk operations (approve all pending above score X) - not in this spec. The human-approval gate
  means one decision per IP. Bulk approve could be added later if the operator requests it, with
  appropriate safeguards.
