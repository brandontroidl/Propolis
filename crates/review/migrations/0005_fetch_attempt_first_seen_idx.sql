-- select_candidates orders the whole eligible set by first_seen DESC (spec section 9: newest
-- payload URLs first, since a botnet's staging url typically dies within minutes) with no
-- existing index covering that sort - only host/last_attempt and status/next_attempt exist
-- (0003_fetch_attempt.sql). Under a backlog larger than one cycle's batch this forces a sort over
-- every qualifying row each cycle; this index lets the planner satisfy the ORDER BY directly.
CREATE INDEX ON fetch_attempt (first_seen DESC);
