-- Watermark for the fetcher's event sync. Before this, every claim re-read each
-- honeypot_file_download event and anti-joined it against fetch_attempt on TRIM(url). An event
-- whose URL the fetcher never stores (a scheme it cannot dispatch such as ftp, or text that is not
-- a URL) never gets a fetch_attempt row, so it never left that anti-join: one live node re-read
-- the same ~6,000 events every 12 s for 1.5 s each. The sync now walks event ids once, past this
-- watermark, so an event is decided exactly once whether or not it yields a row.
--
-- One row, enforced by the CHECK: every node sharing the database advances the same watermark
-- under a row lock. It starts at 0, so the first sync after this migration walks the existing
-- ledger once (in bounded chunks) and inserts nothing it did not already have.
CREATE TABLE fetch_event_cursor (
  singleton     BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  last_event_id BIGINT  NOT NULL DEFAULT 0 CHECK (last_event_id >= 0)
);
INSERT INTO fetch_event_cursor (singleton, last_event_id) VALUES (TRUE, 0);
