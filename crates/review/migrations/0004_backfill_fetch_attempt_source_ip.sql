-- Backfill fetch_attempt.source_ip, which was NULL on every row before the host() fix.
--
-- Cause: source_ip was read as `event.source_ip::text` and parsed with IpAddr::from_str. Postgres
-- renders inet as "1.2.3.4/32" even for a plain address, so the parse always failed and the .ok()
-- swallowed it, writing NULL. Every captured sample was therefore unattributable to the attacker
-- that caused its retrieval. The read now uses host(); this recovers the rows already written.
--
-- Needed as a migration rather than left to self-heal: insert_pending_if_absent is
-- ON CONFLICT (url_hash) DO NOTHING and record_attempt's DO UPDATE does not touch source_ip, so an
-- existing NULL row is never corrected by a later fetch.
--
-- Only ever fills NULLs, so re-running is a no-op and a row written correctly post-fix is never
-- overwritten.

-- 1. Depth-0 rows: the URL came from a honeypot_file_download event, so that event's source_ip is
--    the attacker that reported it. Where several attackers reported the same URL, attribute the
--    EARLIEST - matching the first-reporter semantics fetch_attempt's ON CONFLICT DO NOTHING
--    already encodes, rather than inventing a different rule during a backfill.
--    TRIM on both sides matches the equivalence class url_hash partitions by (sha256(trim(url))).
UPDATE fetch_attempt fa
SET source_ip = ev.source_ip
FROM (
    SELECT DISTINCT ON (TRIM(metadata->>'url'))
           TRIM(metadata->>'url') AS url,
           source_ip
    FROM event
    WHERE signal_type = 'honeypot_file_download'
      AND metadata->>'url' IS NOT NULL
      AND source_ip IS NOT NULL
    ORDER BY TRIM(metadata->>'url'), observed_at ASC
) ev
WHERE fa.source_ip IS NULL
  AND TRIM(fa.url) = ev.url;

-- 2. Recursion children: a URL discovered INSIDE a fetched body has no event of its own, so it
--    inherits the attacker from its parent chain. This is what attributes a loader's per-architecture
--    payloads (mirai.arm, mirai.mips, ...) back to the attacker that pulled the dropper.
--    depth < 16 is a cycle guard: parent_hash is a single link and the fetcher caps recursion well
--    below this, but a cycle would otherwise make the recursive term non-terminating.
WITH RECURSIVE lineage(url_hash, source_ip, depth) AS (
    SELECT url_hash, source_ip, 0
    FROM fetch_attempt
    WHERE source_ip IS NOT NULL

    UNION ALL

    SELECT child.url_hash, parent.source_ip, parent.depth + 1
    FROM fetch_attempt child
    JOIN lineage parent ON child.parent_hash = parent.url_hash
    WHERE child.source_ip IS NULL
      AND parent.depth < 16
)
UPDATE fetch_attempt fa
SET source_ip = inherited.source_ip
FROM (
    SELECT DISTINCT ON (url_hash) url_hash, source_ip
    FROM lineage
    ORDER BY url_hash, depth ASC
) inherited
WHERE fa.url_hash = inherited.url_hash
  AND fa.source_ip IS NULL;
