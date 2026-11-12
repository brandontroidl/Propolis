-- Persistence bonus support (scoring::persistence). `active_days` is an unbounded, non-decaying
-- count of distinct calendar days (UTC) an address was seen; it feeds a score-point bonus added at
-- the tier gate so slow, methodical attackers that the 6h decay would otherwise erase still earn
-- their way onto the tiers. `last_active_day` lets the next event tell whether it opens a new day.
-- Both are maintained by engine::apply_event (the incremental path) and reproduced by a full
-- replay, which folds the same events in order.
ALTER TABLE ip_score ADD COLUMN active_days INTEGER NOT NULL DEFAULT 1;
ALTER TABLE ip_score ADD COLUMN last_active_day DATE;

-- Backfill the day count from the retained event ledger. This is the distinct-UTC-date count,
-- which equals the incremental fold for in-order histories (the normal case); a full replay
-- reconciles it exactly where events arrived out of order. Rows whose events have been pruned keep
-- the DEFAULT 1. The bonus itself takes effect per address on its next event (which a persistent
-- attacker, by definition, keeps sending) or on an explicit replay - this migration seeds the
-- counter, it does not re-derive the tier/recommendation flags in SQL (that logic lives once, in
-- Rust, and must not be duplicated here where it could drift).
UPDATE ip_score s SET
    active_days = GREATEST(1, sub.d),
    last_active_day = s.last_seen::date
FROM (
    SELECT source_ip, COUNT(DISTINCT (observed_at AT TIME ZONE 'UTC')::date) AS d
    FROM event
    GROUP BY source_ip
) sub
WHERE sub.source_ip = s.source_ip;

-- Any row without a matching ledger event still gets a non-NULL last_active_day.
UPDATE ip_score SET last_active_day = last_seen::date WHERE last_active_day IS NULL;
