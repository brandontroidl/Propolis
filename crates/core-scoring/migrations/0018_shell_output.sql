-- What the fake shell answered to a command (docs/reference/database.md, "Shell output table").
-- Additive only: one new table, no change to the event ledger, ip_score or the append path.
--
-- The text is kept once per distinct reply, keyed by its SHA-256, so the many sessions that run the
-- same command share one row. A command_exec event refers to it by metadata.output_sha256, which
-- intake writes into the event before the hash chain covers it; the ledger itself never holds the
-- text. Nothing here is published to the feed or sent to a vendor. There is no backfill: events
-- recorded before this migration carry no output_sha256 and the console shows no reply for them.

-- text is attacker-influenced (a reply can echo the command) and is capped at 4 KiB by the sensor
-- and again here; intake refuses a line whose digest does not match its text, so sha256 is always
-- the digest of text.
CREATE TABLE shell_output (
    sha256     TEXT        PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    text       TEXT        NOT NULL CHECK (octet_length(text) <= 4096),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);
