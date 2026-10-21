-- Hourly roll-up of the event ledger by listener, for the console's windowed counts. The dashboard
-- and the fleet pane answer "how many events in the last 24 hours, by sensor / listener" and
-- "events per hour / per day" by grouping every event in the window: 160 ms for the hourly chart,
-- 161 ms for the sensor split, 314 ms for the fleet listeners and 1.2 s for the 30-day chart on
-- 1,500,000 events, on every page load and every 30 s poll of every open tab, and each grows with
-- the ledger. This table holds the same counts already grouped by hour, so a window costs the
-- number of hours in it (10 to 13 ms on the same ledger).
--
-- It is derived from the ledger and never part of it (like ip_score, ip_vantage and ip_sensor):
-- nothing here changes the event table, its trigger, the append path or the hash chain. It is kept
-- current by the console (crates/console/src/rollup.rs), which folds the events appended since
-- `event_rollup_cursor.last_event_id` into it in the same transaction that advances the cursor.
-- The console never trusts it for events past the cursor: it counts those from the ledger itself,
-- and counts the partial hour at the start of a window from the ledger too, so every number is
-- exact whether or not the roll-up has caught up.
--
-- Hours are UTC-aligned (event_hour), independent of the session time zone.
--
--   event_hour_listener - per (hour, sensor, protocol, port): events and the newest observed_at.
--     The port is the sensor-stamped metadata.local_port, '' when absent (see 0022). Kept for 45
--     days, which covers the 30-day chart; older hours are dropped by the fold.
--
-- The backfill reads the ledger once under the same SHARE lock 0014 takes, so no append can land
-- between the read and the cursor: writes to event wait, reads do not. The daemon runs this
-- before any intake task exists. It reads the heap once (1.7 s for 1,500,000 events).

CREATE FUNCTION event_hour(ts timestamptz) RETURNS timestamptz
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT date_bin('1 hour', ts, TIMESTAMPTZ '2000-01-01 00:00:00+00') $$;

CREATE TABLE event_hour_listener (
    hour          timestamptz   NOT NULL,
    sensor        text          NOT NULL,
    protocol      protocol_enum NOT NULL,
    local_port    text          NOT NULL,
    events        bigint        NOT NULL,
    last_event_at timestamptz   NOT NULL,
    PRIMARY KEY (hour, sensor, protocol, local_port)
);

-- The highest event id folded into the table. One row.
CREATE TABLE event_rollup_cursor (
    singleton     boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_event_id bigint  NOT NULL
);

LOCK TABLE event IN SHARE MODE;

INSERT INTO event_hour_listener (hour, sensor, protocol, local_port, events, last_event_at)
SELECT event_hour(observed_at), sensor, protocol, COALESCE(metadata->>'local_port', ''),
       count(*), max(observed_at)
FROM event
WHERE observed_at >= now() - interval '45 days'
GROUP BY 1, 2, 3, 4;

INSERT INTO event_rollup_cursor (last_event_id) SELECT COALESCE(max(id), 0) FROM event;
