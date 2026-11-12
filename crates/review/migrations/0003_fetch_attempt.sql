CREATE TABLE fetch_attempt (
  url_hash      BYTEA PRIMARY KEY,          -- sha256(normalized url)
  url           TEXT        NOT NULL,
  host          TEXT        NOT NULL,
  scheme        TEXT        NOT NULL,
  pinned_ip     TEXT,                       -- the IP actually dialed (IOC)
  port          INTEGER,
  source_ip     INET,                       -- attacker src from the event row
  parent_hash   BYTEA,                      -- NULL, or the script this was extracted from
  depth         INTEGER     NOT NULL DEFAULT 0,
  status        TEXT        NOT NULL,        -- pending|success|dead|rejected|too_big|timeout|empty
  reject_reason TEXT,                        -- guard reason when status=rejected
  sha256        BYTEA,                       -- NULL unless captured
  bytes         INTEGER,
  content_type  TEXT,                        -- server-declared; recorded, never trusted
  attempts      INTEGER     NOT NULL DEFAULT 0,
  next_attempt  TIMESTAMPTZ,                 -- backoff schedule
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_attempt  TIMESTAMPTZ NOT NULL
);
CREATE INDEX ON fetch_attempt (host, last_attempt);
CREATE INDEX ON fetch_attempt (status, next_attempt);
