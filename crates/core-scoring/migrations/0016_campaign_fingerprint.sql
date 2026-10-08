-- The command-sequence fingerprint keys on a run's opening commands, not its whole length
-- (docs/operations/campaigns.md), and a campaign records how long its runs were. Additive only:
-- new columns, no change to the event ledger, ip_score, the append path or migration 0015.
--
-- The campaign indexer owns the rebuild. fingerprint_version is the version of the fingerprint
-- that built campaign_session and the command_sequence campaigns; existing rows are version 1,
-- the key over the whole normalized run. A build whose version differs deletes those rows on its
-- next indexing batch and reads the ledger again from the start, up to the event the cursor had
-- reached (rebuild_until), in a mode that rebuilds only the command-sequence state. Nothing is
-- rewritten here, so the migration is instant on a large ledger.

ALTER TABLE campaign_cursor
    ADD COLUMN fingerprint_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN rebuild_until       BIGINT;

-- Shapes in the run (shell-entry lines included): the fewest and most over a campaign's runs, for
-- its label. NULL for campaigns that are not command sequences.
ALTER TABLE campaign
    ADD COLUMN min_shapes INTEGER,
    ADD COLUMN max_shapes INTEGER;

-- Shapes of the run folded into campaign_session.chain, the opening commands the key is over.
ALTER TABLE campaign_session
    ADD COLUMN payload INTEGER NOT NULL DEFAULT 0;
