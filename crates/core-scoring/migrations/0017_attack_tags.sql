-- ATT&CK technique tags (docs/reference/attack-tagging.md). Additive only: new tables and one
-- defaulted column, no change to the event ledger, ip_score, the append path or migrations 0015
-- and 0016.
--
-- Derived from the ledger by the campaign indexer (crates/review/src/campaign), in the same
-- transaction as the rest of its batch. A tag is a deterministic rule matched against one event;
-- the rule id fixes the technique, so the technique id is stored for querying only. Nothing here
-- is published to the feed or sent to a vendor. There is no backfill: events the indexer read
-- before this migration are tagged only after the "rebuild them all" procedure in
-- docs/operations/campaigns.md, which also empties these two tables.

-- One row per (source, session, rule): the lowest event that satisfied the rule and the token that
-- matched, with how many events satisfied it. session_id is NULL for an event with no session (a
-- classified signal such as ssh_brute_force). matched is attacker data, redacted and capped before
-- it is written.
CREATE TABLE attack_tag (
    id           BIGSERIAL   PRIMARY KEY,
    source_ip    INET        NOT NULL,
    session_id   UUID,
    technique_id TEXT        NOT NULL CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    rule_id      TEXT        NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 64),
    event_id     BIGINT      NOT NULL,
    matched      TEXT        NOT NULL CHECK (char_length(matched) BETWEEN 1 AND 256),
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    sightings    BIGINT      NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX attack_tag_session_uq ON attack_tag (source_ip, session_id, rule_id)
    WHERE session_id IS NOT NULL;
CREATE UNIQUE INDEX attack_tag_sessionless_uq ON attack_tag (source_ip, rule_id)
    WHERE session_id IS NULL;
CREATE INDEX attack_tag_session_idx ON attack_tag (session_id) WHERE session_id IS NOT NULL;

-- A campaign's tags: the union over the runs and samples that formed it, one row per rule with the
-- lowest event that satisfied it. Evidence is an event, or for a rule over a captured artifact's
-- indicators the artifact.
CREATE TABLE campaign_attack_tag (
    campaign_id     BIGINT NOT NULL REFERENCES campaign (id) ON DELETE CASCADE,
    technique_id    TEXT   NOT NULL CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    rule_id         TEXT   NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 64),
    event_id        BIGINT,
    artifact_sha256 TEXT   CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    matched         TEXT   NOT NULL CHECK (char_length(matched) BETWEEN 1 AND 256),
    PRIMARY KEY (campaign_id, technique_id, rule_id),
    CHECK (event_id IS NOT NULL OR artifact_sha256 IS NOT NULL)
);

-- The tags a shell session's current run has collected before it joins a campaign (a JSON array of
-- {rule, event_id, matched}), carried like pending_samples and flushed to the campaign when the
-- run is grouped.
ALTER TABLE campaign_session
    ADD COLUMN attack_pending JSONB NOT NULL DEFAULT '[]'::jsonb;
