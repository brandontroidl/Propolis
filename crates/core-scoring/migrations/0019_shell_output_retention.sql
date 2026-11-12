-- Retention for shell_output (docs/operations/retention.md). Additive: one defaulted column and
-- one partial index; the event ledger, ip_score and the append path are unchanged.
--
-- last_stored is when intake last stored this reply. A reply that arrives again is touched at most
-- once an hour, so a hot reply costs one write an hour rather than one per event, and the pruner
-- (core_scoring::prune_orphan_outputs) can never delete a row an in-flight batch is about to name:
-- it only removes rows no event names AND not stored for longer than its grace period.
ALTER TABLE shell_output ADD COLUMN last_stored TIMESTAMPTZ NOT NULL DEFAULT now();

-- Lets the pruner ask "does any event name this digest?" without scanning the ledger. Partial, so
-- it holds only events that carry a reply; none do at the time this runs (0018 is new), so the
-- build only reads the table once, inside the migration transaction like 0013.
CREATE INDEX event_output_sha256_idx ON event ((metadata ->> 'output_sha256'))
    WHERE metadata ? 'output_sha256';
