-- Volume-based blocklisting must count only NON-SPOOFABLE events. A UDP/ICMP datagram's source
-- address is forgeable, so counting it toward the volume threshold let a spoofed flood publish an
-- innocent third party to the blocklist feed (the catch-all UDP listener is the live producer of
-- such events). `established_event_count` tracks completed-TCP-connection events only - a spoofed
-- source cannot finish a handshake - and `recommended_by_volume` now gates on it instead of the raw
-- event_count.
--
-- Additive: NOT NULL DEFAULT 0 so existing rows still validate. The backfill recomputes each IP's
-- TCP-event count from the append-only event ledger, so legitimate TCP-flood listings survive the
-- upgrade and any prior UDP-only (possibly spoofed) volume listings correctly drop off at the next
-- feed build. Rows with no TCP events keep the default 0.
ALTER TABLE ip_score ADD COLUMN established_event_count INTEGER NOT NULL DEFAULT 0;

UPDATE ip_score s
SET established_event_count = t.cnt
FROM (
    SELECT source_ip, count(*)::int AS cnt
    FROM event
    WHERE protocol = 'tcp'
    GROUP BY source_ip
) t
WHERE s.source_ip = t.source_ip;
