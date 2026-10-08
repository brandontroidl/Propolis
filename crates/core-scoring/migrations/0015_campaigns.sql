-- Campaigns and indicators (docs/operations/campaigns.md). Additive only: new tables, no change to
-- the event ledger, ip_score or the append path.
--
-- Every table here is derived from the ledger by the campaign indexer (crates/review/src/campaign),
-- a bounded background job that reads event rows past its cursor in id order, a batch at a time,
-- and folds them into these tables in one transaction per batch. Nothing here is written by
-- append_event, so the per-append cost is untouched. Ids are a safe cursor because every insert
-- into event runs under the append advisory lock and the chain-linkage trigger, so a row with a
-- lower id has always committed before a higher one is allocated.
--
-- There is no backfill: the cursor starts at zero and the indexer works through an existing ledger
-- a batch per step, so a large ledger is indexed over the first minutes of uptime rather than in a
-- migration that would hold up startup.

CREATE TABLE campaign_cursor (
    singleton     BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    last_event_id BIGINT      NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO campaign_cursor DEFAULT VALUES;

-- One row per campaign. kind: 'sample' (key = the sample's lowercase hex sha256),
-- 'command_sequence' (key = hex of the session fingerprint) or 'scanner' (key = the sorted,
-- comma-joined sensors one source reached in one window). label and representative come from the
-- lowest event id seen for the campaign (rep_event_id), so they do not depend on batch boundaries.
-- self_propagating is set by the indicator pass for a sample whose text carries both a scanner and a
-- remote-copy tool; it is metadata for the console, not used in any vendor submission.
CREATE TABLE campaign (
    id               BIGSERIAL   PRIMARY KEY,
    kind             TEXT        NOT NULL CHECK (kind IN ('sample', 'command_sequence', 'scanner')),
    key              TEXT        NOT NULL CHECK (char_length(key) <= 512),
    label            TEXT        NOT NULL CHECK (char_length(label) <= 256),
    representative   JSONB       NOT NULL DEFAULT '{}'::jsonb,
    rep_event_id     BIGINT      NOT NULL,
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    member_count     INTEGER     NOT NULL DEFAULT 0,
    sightings        BIGINT      NOT NULL DEFAULT 0,
    self_propagating BOOLEAN     NOT NULL DEFAULT FALSE,
    UNIQUE (kind, key)
);
CREATE INDEX campaign_last_seen_idx ON campaign (last_seen DESC);

-- uploaded: the source sent the sample itself (a sensor capture), as opposed to reporting a URL the
-- fetcher retrieved it from. Only meaningful for kind 'sample'.
CREATE TABLE campaign_member (
    campaign_id BIGINT      NOT NULL REFERENCES campaign (id) ON DELETE CASCADE,
    source_ip   INET        NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    sightings   BIGINT      NOT NULL,
    uploaded    BOOLEAN     NOT NULL DEFAULT FALSE,
    PRIMARY KEY (campaign_id, source_ip)
);
CREATE INDEX campaign_member_source_idx ON campaign_member (source_ip);

-- The days each member was seen, for the distinct-addresses-per-day sparkline.
CREATE TABLE campaign_member_day (
    campaign_id BIGINT NOT NULL REFERENCES campaign (id) ON DELETE CASCADE,
    day         DATE   NOT NULL,
    source_ip   INET   NOT NULL,
    PRIMARY KEY (campaign_id, day, source_ip)
);

CREATE TABLE campaign_sensor (
    campaign_id BIGINT NOT NULL REFERENCES campaign (id) ON DELETE CASCADE,
    sensor      TEXT   NOT NULL,
    sightings   BIGINT NOT NULL,
    PRIMARY KEY (campaign_id, sensor)
);

-- Samples linked to a campaign: the sample itself for kind 'sample', and for a command sequence the
-- samples its members' sessions uploaded.
CREATE TABLE campaign_sample (
    campaign_id BIGINT NOT NULL REFERENCES campaign (id) ON DELETE CASCADE,
    sha256      TEXT   NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (campaign_id, sha256)
);
CREATE INDEX campaign_sample_sha_idx ON campaign_sample (sha256);

-- The indexer's working state. One row per shell session: the current run of its commands, folded
-- into a running digest of their normalized shapes (consecutive repeats collapsed). A run ends at an
-- idle gap or at the shape cap; a run long enough to mean something becomes a campaign membership.
CREATE TABLE campaign_session (
    session_id      UUID        PRIMARY KEY,
    source_ip       INET        NOT NULL,
    sensor          TEXT        NOT NULL,
    run             INTEGER     NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    first_event_id  BIGINT      NOT NULL,
    last_event_id   BIGINT      NOT NULL,
    shapes          INTEGER     NOT NULL,
    shape_chars     INTEGER     NOT NULL,
    last_shape      BYTEA       NOT NULL,
    chain           BYTEA       NOT NULL,
    campaign_key    TEXT,
    closed          BOOLEAN     NOT NULL DEFAULT FALSE,
    pending_samples TEXT[]      NOT NULL DEFAULT '{}'
);
CREATE INDEX campaign_session_open_idx ON campaign_session (sensor, last_seen) WHERE NOT closed;
CREATE INDEX campaign_session_seen_idx ON campaign_session (last_seen);

-- The newest observed_at the indexer has read per sensor: the clock a session's idle gap is
-- measured against, since one sensor's log is written in time order while sensors lag differently.
CREATE TABLE campaign_watermark (
    sensor   TEXT        PRIMARY KEY,
    observed TIMESTAMPTZ NOT NULL
);

-- Distinct sensors one source reached in one window, until it crosses the scanner threshold.
CREATE TABLE campaign_scan_window (
    source_ip    INET        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    sensors      TEXT[]      NOT NULL,
    crossed      BOOLEAN     NOT NULL DEFAULT FALSE,
    PRIMARY KEY (source_ip, window_start)
);
CREATE INDEX campaign_scan_window_start_idx ON campaign_scan_window (window_start);

-- A download URL whose fetch had no outcome yet when the indexer read the event. Resolved against
-- fetch_attempt on later passes: a captured body links the source to that sample's campaign.
CREATE TABLE campaign_pending_fetch (
    url_hash   BYTEA       NOT NULL,
    source_ip  INET        NOT NULL,
    sensor     TEXT        NOT NULL,
    event_id   BIGINT      NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    sightings  BIGINT      NOT NULL,
    queued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (url_hash, source_ip)
);

-- Indicators, each with its provenance: a captured artifact (artifact_sha256) or the first command
-- or download event that carried it (event_id, with its source). Values are sanitized and capped
-- before they are written and are attacker data all the same. A password hash is stored only as a
-- marker (its scheme and a digest prefix of the crypt string), never the hash itself.
CREATE TABLE ioc (
    id              BIGSERIAL   PRIMARY KEY,
    kind            TEXT        NOT NULL CHECK (kind IN ('url', 'endpoint', 'ssh_key', 'rsa_key',
                        'password_hash', 'irc_server', 'irc_channel', 'hosts_entry', 'persistence')),
    value           TEXT        NOT NULL CHECK (char_length(value) BETWEEN 1 AND 256),
    detail          TEXT        NOT NULL DEFAULT '' CHECK (char_length(detail) <= 128),
    artifact_sha256 TEXT        CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    event_id        BIGINT,
    source_ip       INET,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    sightings       BIGINT      NOT NULL DEFAULT 1,
    CHECK ((artifact_sha256 IS NULL) = (event_id IS NOT NULL AND source_ip IS NOT NULL))
);
CREATE UNIQUE INDEX ioc_artifact_uq ON ioc (artifact_sha256, kind, value) WHERE artifact_sha256 IS NOT NULL;
CREATE UNIQUE INDEX ioc_source_uq ON ioc (source_ip, kind, value) WHERE artifact_sha256 IS NULL;

-- Captured artifacts waiting for, or done with, indicator extraction.
CREATE TABLE ioc_artifact_scan (
    sha256       TEXT        PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    state        TEXT        NOT NULL DEFAULT 'pending'
                     CHECK (state IN ('pending', 'done', 'not_text', 'too_big', 'missing')),
    attempts     INTEGER     NOT NULL DEFAULT 0,
    next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
    indicators   INTEGER     NOT NULL DEFAULT 0,
    scanned_at   TIMESTAMPTZ
);
CREATE INDEX ioc_artifact_scan_due_idx ON ioc_artifact_scan (next_attempt) WHERE state = 'pending';
