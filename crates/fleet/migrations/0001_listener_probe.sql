-- The durable result of the control plane's reachability probe, one row per listener.
--
-- There is deliberately no row created at config time and no `ok` default: a configured listener
-- with NO row here is UNKNOWN, which the fleet pane renders as an alarm rather than as health. A
-- row appears only when a probe attempt actually completed, so a sweep that never ran leaves
-- `attempted_at` where it was and the row ages into staleness on its own. That is the fail-closed
-- invariant this table exists to hold, and `fleet::health` tests it.
--
-- `confirmed_at` is written by a different path from the rest of the row (intake seeing the probe's
-- own line arrive at the far end of the collection chain), so it is never touched by the probe
-- upsert: a fresh attempt leaves the previous confirmation visible with its own timestamp, and the
-- gap between the two is what localizes a break to the log/shipper/gateway/intake path.
CREATE TABLE listener_probe (
    collector_id  TEXT        NOT NULL CHECK (collector_id <> ''),
    sensor        TEXT        NOT NULL CHECK (sensor <> ''),
    protocol      TEXT        NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port          INTEGER     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    target        TEXT        NOT NULL,
    attempted_at  TIMESTAMPTZ NOT NULL,
    outcome       TEXT        NOT NULL CHECK (outcome IN
                    ('reachable', 'refused', 'timeout', 'error', 'not_probeable')),
    detail        TEXT,
    latency_ms    INTEGER     CHECK (latency_ms >= 0),
    confirmed_at  TIMESTAMPTZ,
    PRIMARY KEY (collector_id, sensor, protocol, port)
);

CREATE INDEX listener_probe_sensor_idx ON listener_probe (sensor, attempted_at DESC);
