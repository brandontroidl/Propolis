-- Backfill stored eligibility and recommendation flags after relaxing the eligibility
-- gate from (has_confirmed_real AND event_count >= 2 AND distinct_categories >= 2)
-- to (has_confirmed_real AND event_count >= 2). Without this, existing ip_score rows
-- that were denied by the old distinct_categories >= 2 requirement stay invisible to
-- the review queue and feed builder until their next event arrives.

UPDATE ip_score SET
  eligible = TRUE,
  recommended_for_vendor = (tier IS NOT NULL),
  recommended_for_blocklist = (
    LEAST(100, raw_score * (1.0 + LEAST(0.60, 0.15 * GREATEST(0, distinct_wan_count - 1)))) >= 50
  )
WHERE has_confirmed_real = TRUE
  AND event_count >= 2
  AND eligible = FALSE;
