-- Session ID plumbing for console forensics: correlate ledger events that
-- belong to one sensor session (e.g. one SSH connection's login attempts,
-- command execs, and file transfers) without changing the hash chain.
-- Nullable: pre-existing events have no session_id and degrade gracefully
-- (console forensics views simply show no session grouping for them).
ALTER TABLE event ADD COLUMN session_id UUID;
CREATE INDEX event_session_idx ON event (source_ip, session_id);
