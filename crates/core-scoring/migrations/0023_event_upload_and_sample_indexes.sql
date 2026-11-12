-- Two partial indexes over the small slice of the ledger that carries a captured sample, for the
-- console pages that ask about uploads and samples and used to read every event to find them.
--
--   event_upload_observed_idx - the uploads, by time. The fleet pane's capture-completeness panel
--     reads every honeypot_malware_upload of the last 7 days twice per 30 s poll (its rate, then
--     its dominant end reason); both statements filter on exactly this predicate and range, and
--     walked the whole 7 days of the ledger to find the 1-2% that are uploads (240 ms and 250 ms
--     on 1,500,000 events; 15 ms and 32 ms with the index).
--
--   event_sample_sha_idx - the events that name a sample, by the sample's digest. The Samples page
--     asked which source addresses delivered a sample, and which samples a sensor kept only a
--     prefix of, by reading every event and testing its metadata (250 ms and 150 ms on the same
--     ledger); the address page does the same for one address. With the index the page asks only
--     about the digests it is showing.
--
-- Both are partial on a predicate the statements repeat, so each statement states it. The sample
-- index tests `metadata ? 'sample_sha256'`, as event_output_sha256_idx (0019) does for replies,
-- because the planner estimates a jsonb key test at about 1% of the table, where an `->> ... IS NOT
-- NULL` test on a partial index's own expression is estimated at every row and keeps the planner
-- on the table.
--
-- Both hold only the events they name: 504 kB and 2 MB per 1,500,000 events, and an entry is
-- written only for an upload or an event that names a sample.
--
-- Plain CREATE INDEX, not CONCURRENTLY, for the reasons given in 0013: sqlx runs this file in its
-- own transaction at daemon startup, before any intake task exists. The builds read the event heap
-- once each, about as long as 0013's.
CREATE INDEX event_upload_observed_idx ON event (observed_at)
    WHERE signal_type = 'honeypot_malware_upload';

CREATE INDEX event_sample_sha_idx ON event ((metadata ->> 'sample_sha256'), source_ip)
    WHERE metadata ? 'sample_sha256';
