-- The address page reads every ATT&CK tag of one source address (review::attack::source_tags). The
-- table's two unique indexes both start with source_ip, but one is partial on session_id IS NOT
-- NULL and the other on session_id IS NULL, and that read states neither, so the planner cannot
-- use either and read the whole table on every page load: 45 ms for 300,000 tags (0.5 ms with this
-- index). attack_tag has no retention, so the cost only grows.
--
-- A plain CREATE INDEX: attack_tag is a derived table the campaign indexer writes, and sqlx runs
-- this file at daemon startup before any task exists (see 0013). It builds in well under a second
-- at 300,000 rows (2.5 MB).
CREATE INDEX attack_tag_source_idx ON attack_tag (source_ip);
