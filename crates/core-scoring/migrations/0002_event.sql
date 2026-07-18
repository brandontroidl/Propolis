CREATE TABLE event (
    id            BIGSERIAL       PRIMARY KEY,
    source_ip     INET            NOT NULL,
    wan_ip        INET,           -- null for corroborating sensors with no bindable WAN IP
    sensor        TEXT            NOT NULL,
    signal_type   signal_type_enum NOT NULL,
    protocol      protocol_enum   NOT NULL,
    authenticated BOOLEAN         NOT NULL,
    category      category_enum   NOT NULL,
    weight        INTEGER         NOT NULL,
    confidence    NUMERIC(4,3)    NOT NULL,
    observed_at   TIMESTAMPTZ     NOT NULL,
    ingested_at   TIMESTAMPTZ     NOT NULL DEFAULT now(),
    metadata      JSONB           NOT NULL DEFAULT '{}'::jsonb,  -- sanitized at capture
    prev_hash     BYTEA,
    hash          BYTEA           NOT NULL
);

CREATE INDEX event_source_ip_idx   ON event (source_ip);
CREATE INDEX event_observed_at_idx ON event (observed_at);
