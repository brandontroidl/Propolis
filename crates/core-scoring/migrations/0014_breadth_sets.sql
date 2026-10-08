-- The two per-source sets the breadth inputs are counted from, kept as projection tables so a
-- scored append reads a handful of rows instead of every earlier event of its source. Before this,
-- each append ran a GROUP BY wan_ip and a COUNT(DISTINCT sensor) over the source's whole history
-- while holding the global append lock: about 0.7 s per event for a source with 100k events and
-- 7 s for one with 1.5M, a cost every other sensor waited behind.
--
-- ip_vantage holds one row per (source, non-null WAN) with whether any scored event on that WAN
-- was an authenticated TCP event; ip_sensor holds one row per (source, sensor). append_event folds
-- each scored event into both inside the append transaction (repository/events.rs,
-- fold_breadth_sets). Telemetry never touches them: append_telemetry_event does not write them,
-- and the backfill below excludes those rows exactly as the old aggregates did.
--
-- Like ip_score they are derived from the ledger, not part of it, and nothing references them
-- from ip_score: the console's delete_ip removes a score row but leaves the ledger, so a later
-- event must still see the address's full history here.
CREATE TABLE ip_vantage (
    source_ip             INET    NOT NULL,
    wan_ip                INET    NOT NULL,
    saw_authenticated_tcp BOOLEAN NOT NULL,
    PRIMARY KEY (source_ip, wan_ip)
);

CREATE TABLE ip_sensor (
    source_ip INET NOT NULL,
    sensor    TEXT NOT NULL,
    PRIMARY KEY (source_ip, sensor)
);

-- The backfill reads the ledger as it stands. SHARE mode makes that exact: an append committed by
-- some other writer while this runs would otherwise be in the ledger and missing from both sets
-- for good. The daemon runs this at startup before any intake task exists, so the lock waits on
-- nothing of its own. Reads of event proceed throughout. The two statements each read the whole
-- event heap once: on a 7.5M-row (3.9 GB) ledger held in RAM they took 26 s together with two
-- parallel workers and 23 s with none, and wrote 580k vantage and 1.1M sensor rows. A
-- disk-backed server reads the heap from disk twice, so plan on up to a few minutes of startup at
-- that size (an estimate).
LOCK TABLE event IN SHARE MODE;

INSERT INTO ip_vantage (source_ip, wan_ip, saw_authenticated_tcp)
SELECT source_ip, wan_ip, bool_or(protocol = 'tcp' AND authenticated)
FROM event
WHERE wan_ip IS NOT NULL AND signal_type <> 'honeypot_session_end'
GROUP BY source_ip, wan_ip;

INSERT INTO ip_sensor (source_ip, sensor)
SELECT source_ip, sensor
FROM event
WHERE signal_type <> 'honeypot_session_end'
GROUP BY source_ip, sensor;
