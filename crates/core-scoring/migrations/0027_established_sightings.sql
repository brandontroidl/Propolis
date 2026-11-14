-- What a forgeable sighting may change, and how long a listing lasts.
--
-- A UDP (or ICMP) source address is whatever the sender wrote. Until now such an event still
-- added its signal weight to the address it named, re-derived that address's tier, and advanced
-- `last_seen`, which is the clock the feed and the vendor gate ran on. One forged datagram could
-- therefore raise a third party's score, end an approved address's listing early (the score had
-- decayed, so the re-derived tier was none), or keep an approved address listed and reported
-- for as long as the datagrams kept coming. The fold (engine::apply_event) now lets an event
-- that is not a completed TCP connection change only the record of the sighting: `event_count`,
-- `last_seen`, `distinct_sensor_count`. These columns carry what the rest needs instead:
--
--   established_last_seen  the latest observed_at of an established (completed-TCP) event, NULL
--                          for an address only datagrams have named. Volume listing and the
--                          volume approval's lapse run on it.
--   aggressive_earned_at   the last time an established event left the address eligible and
--   standard_earned_at     holding that tier. The feed lists an approved address in a tier file
--                          for that tier's TTL after this time and in the retention windows
--                          after the later of the two; the vendor gate reports within its
--                          freshness window of it. A later event that leaves the address below
--                          the tier neither clears nor advances it.
--
-- Nullable and additive, so a row inserted with a column subset still validates.
ALTER TABLE ip_score
    ADD COLUMN established_last_seen TIMESTAMPTZ,
    ADD COLUMN aggressive_earned_at TIMESTAMPTZ,
    ADD COLUMN standard_earned_at TIMESTAMPTZ;

-- `established_last_seen` is exactly reproducible from the ledger: the fold keeps it as a running
-- maximum over the same rows (telemetry is never folded). One pass over the event heap.
UPDATE ip_score s
SET established_last_seen = t.seen
FROM (
    SELECT source_ip, max(observed_at) AS seen
    FROM event
    WHERE protocol = 'tcp' AND signal_type <> 'honeypot_session_end'
    GROUP BY source_ip
) t
WHERE s.source_ip = t.source_ip;

-- Eligibility now asks for two ESTABLISHED events where it asked for two events of any kind, so
-- a forged datagram can no longer be the second sighting of an address that authenticated once.
-- A forgeable sighting no longer re-derives the stored flags either, so a row left eligible by
-- the old rule would stay so until its next connection, offered for review the whole time. The
-- rule is one comparison and `established_event_count` is exact (0011 took it from the ledger),
-- so it is applied to the stored rows here. Volume listing needs a thousand established events,
-- so no row this touches has it.
UPDATE ip_score
SET eligible = FALSE, recommended_for_vendor = FALSE, recommended_for_blocklist = FALSE
WHERE established_event_count < 2
  AND (eligible OR recommended_for_vendor OR recommended_for_blocklist);

-- The earned times cannot be recomputed in SQL without duplicating the tier rules (which live
-- once, in Rust). They are seeded for the rows the feed lists today, from the last ESTABLISHED
-- sighting and not from `last_seen` or the anchor, which a datagram may have moved: an address
-- that has only been named by datagrams for the last two days stops being listed and reported
-- at this upgrade instead of running one more TTL on a clock nothing earned. The seed is the
-- latest time the tier can have been earned under the new rule; a row corrects itself on its
-- next established event. A stored tier may still rest in part on weight datagrams added before
-- the upgrade, which decays with the usual half-life. A delisted address earns nothing.
UPDATE ip_score
SET aggressive_earned_at = established_last_seen
WHERE tier = 'aggressive' AND eligible AND recommended_for_blocklist AND NOT delisted
  AND established_last_seen IS NOT NULL;

UPDATE ip_score
SET standard_earned_at = established_last_seen
WHERE tier = 'standard' AND eligible AND recommended_for_blocklist AND NOT delisted
  AND established_last_seen IS NOT NULL;

-- The dedup read every scored append makes (see 0013) now asks for the newest ESTABLISHED event
-- of the same signal type, so a forgeable datagram cannot turn a real connection into a
-- no-weight duplicate. With only event_dedup_idx the planner would walk that index backwards
-- past every datagram newer than the source's last TCP event of the type, fetching each row to
-- test its protocol, while holding the append lock; a source that sends datagrams for days and
-- then connects would cost one long walk. This partial index holds only the rows the read can
-- return, so the read stays one backward step. Plain CREATE INDEX, not CONCURRENTLY, for the
-- reasons given in 0013; the build reads the event heap once.
CREATE INDEX event_dedup_tcp_idx ON event (source_ip, signal_type, observed_at)
    WHERE protocol = 'tcp';
