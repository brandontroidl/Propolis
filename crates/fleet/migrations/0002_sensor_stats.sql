-- The latest `sensor_stats` line each capturing sensor wrote: its capture hand-off counters and
-- capture-memory budget. One row per sensor, replaced by each newer line.
--
-- This is operational telemetry, not evidence: it lives here and never in the hash-chained ledger,
-- so it cannot be scored, fed, campaign-clustered or submitted to a vendor.
--
-- `reported_at` is the sensor's own clock (the line's `observed_at`) and is what staleness is read
-- from: a sensor that stops writing, or a pipeline that stops delivering, ages out instead of
-- showing its last numbers as current. A line older than the stored one is ignored (the upsert
-- guard), so a replayed or out-of-order line cannot move a row backwards.
--
-- Every counter is NOT NULL with no default: a row exists only because a line arrived.
CREATE TABLE sensor_stats (
    sensor             TEXT        PRIMARY KEY CHECK (sensor <> '' AND length(sensor) <= 64),
    reported_at        TIMESTAMPTZ NOT NULL,
    received_at        TIMESTAMPTZ NOT NULL,
    uptime_secs        BIGINT      NOT NULL CHECK (uptime_secs >= 0),
    is_final           BOOLEAN     NOT NULL,
    dropped            BIGINT      NOT NULL CHECK (dropped >= 0),
    spool_refused      BIGINT      NOT NULL CHECK (spool_refused >= 0),
    truncated          BIGINT      NOT NULL CHECK (truncated >= 0),
    refused            BIGINT      NOT NULL CHECK (refused >= 0),
    budget_current     BIGINT      NOT NULL CHECK (budget_current >= 0),
    budget_high_water  BIGINT      NOT NULL CHECK (budget_high_water >= 0),
    budget_refused     BIGINT      NOT NULL CHECK (budget_refused >= 0)
);
