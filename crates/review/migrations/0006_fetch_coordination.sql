-- Cross-node coordination for the malware fetcher. Nodes sharing one database used to select
-- the same eligible rows with a plain SELECT and each enforce the per-host hourly and daily caps
-- from their own memory, so N nodes fetched the same URL up to N times and spent N times each cap.
--
-- claim_expires: a row is claimed by the cycle that will fetch it, in the same transaction that
-- selects it (FOR UPDATE SKIP LOCKED), and a claimed row is invisible to every other cycle until
-- the outcome is recorded (which clears it) or the lease lapses (a crashed node's claims come
-- back on their own). NULL means unclaimed; existing rows start unclaimed.
ALTER TABLE fetch_attempt ADD COLUMN claim_expires TIMESTAMPTZ;

-- Rows currently claimed count against their host's hourly cap alongside completed attempts.
CREATE INDEX ON fetch_attempt (host, claim_expires) WHERE claim_expires IS NOT NULL;

-- Fetches charged against the daily cap, per UTC day, shared by every node. Charged when a row is
-- claimed, so a cycle that claims nothing costs nothing.
CREATE TABLE fetch_daily_usage (
  day   DATE    PRIMARY KEY,
  used  INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0)
);
