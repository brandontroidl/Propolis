-- Operator decisions on volume candidates: addresses the connection-volume rule would list in the
-- retention feeds (all-24h ... all-90d) on their count of established TCP events alone.
--
-- Those addresses used to be published with no decision at all. The count that lists them is
-- taken from what a sensor's own log line declares, so one forged line could put any address in
-- every retention feed. A volume candidate now waits here, and the feed builder publishes it only
-- once its row is 'approved' (or the address was already approved in review_queue).
--
-- A table of its own rather than a kind column on review_queue: the vendor submission runner
-- reports every approved review_queue row, and an approval given here must never reach a vendor.
--
-- state reuses review_state_enum, but only 'pending', 'approved' and 'rejected' are written.
-- established_events_at_surface is ip_score.established_event_count when the row was created, so
-- the operator can see what the count was when the address was offered and what it is now.
--
-- The table starts empty: after this migration no volume entry is published until an operator
-- approves it. PROPOLIS_FEED_VOLUME_AUTO_PUBLISH=true restores publication without a decision.
CREATE TABLE volume_review (
    source_ip                     INET PRIMARY KEY,
    state                         review_state_enum NOT NULL DEFAULT 'pending',
    established_events_at_surface INTEGER NOT NULL,
    surfaced_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at                    TIMESTAMPTZ,
    notes                         TEXT
);
