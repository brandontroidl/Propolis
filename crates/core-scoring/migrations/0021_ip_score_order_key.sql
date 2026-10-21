-- An index for the console's score ordering: the dashboard's top attacker and the Attackers table
-- (default sort) both ranked every ip_score row by its live effective score to keep one row or
-- the first 500. The live score decays with the clock, so no index can hold it, but every row
-- decays by the same factor, so
--     ln(raw_score * breadth) + ln 2 * epoch(decay_anchor) / half_life
-- orders rows exactly as their live scores order at any instant, and it does not change between
-- two reads. This function is that key; the index holds it, so the top rows are read off the
-- index instead of scoring the whole table. Measured on 500,000 scored addresses: the dashboard's
-- top-attacker statement 3.5 s to 0.8 ms, the Attackers first page 490 ms to 5.6 ms.
--
-- The constants mirror core-scoring/src/scoring/constants.rs (HALF_LIFE_SECONDS 21600,
-- BREADTH_PER_WAN 0.15, BREADTH_CAP 0.60) as the console's LIVE_EFFECTIVE_SCORE_SQL already does;
-- crates/console/tests/ledger_scan_test.rs holds the key to the live score's order. A zero score
-- has no logarithm and sorts last.
--
-- IMMUTABLE is accurate: EXTRACT(EPOCH FROM timestamptz) does not depend on the session time zone
-- (PostgreSQL labels date_part STABLE because its other fields do), and nothing else here reads
-- state. An index expression must be immutable, which is why this is a function at all.
--
-- Every scored append rewrites the address's ip_score row, and raw_score and decay_anchor are now
-- indexed columns, so those updates are no longer heap-only: measured at 9 us per row without the
-- index and 24 us with it for 100,000 updates. That cost lands inside the append lock, once per
-- scored event.
--
-- A plain CREATE INDEX, not CONCURRENTLY, for the reasons given in 0013: sqlx runs this file in
-- its own transaction at daemon startup, before any intake task exists. The build reads ip_score
-- only (one row per address, never the ledger): 2 s for 500,000 rows.
CREATE FUNCTION ip_score_order_key(raw_score numeric, distinct_wan_count integer, decay_anchor timestamptz)
RETURNS float8
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT CASE WHEN raw_score > 0
        THEN ln(raw_score::float8 * (1.0 + LEAST(0.60, 0.15 * GREATEST(0, distinct_wan_count - 1))))
             + EXTRACT(EPOCH FROM decay_anchor)::float8 * ln(2.0) / 21600.0
        ELSE '-Infinity'::float8 END
$$;

CREATE INDEX ip_score_order_idx ON ip_score (
    ip_score_order_key(raw_score, distinct_wan_count, decay_anchor) DESC, source_ip DESC
);
