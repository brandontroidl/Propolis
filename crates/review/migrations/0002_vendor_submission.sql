CREATE TABLE vendor_submission (
    id                BIGSERIAL PRIMARY KEY,
    source_ip         INET NOT NULL,
    vendor            TEXT NOT NULL,
    idempotency_key   TEXT NOT NULL UNIQUE,
    categories        TEXT[] NOT NULL,
    comment           TEXT NOT NULL,
    submitted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    response_status   INTEGER,
    response_body     TEXT,
    success           BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_vendor_submission_ip_vendor
    ON vendor_submission (source_ip, vendor, submitted_at DESC);
