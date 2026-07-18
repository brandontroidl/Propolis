CREATE TABLE ip_score (
    source_ip            INET          PRIMARY KEY,
    raw_score            NUMERIC       NOT NULL,
    decay_anchor         TIMESTAMPTZ   NOT NULL,
    max_confidence       NUMERIC       NOT NULL,
    event_count          INTEGER       NOT NULL,
    distinct_categories  INTEGER       NOT NULL,
    category_breakdown   JSONB         NOT NULL DEFAULT '{}'::jsonb,
    has_confirmed_real   BOOLEAN       NOT NULL DEFAULT false,
    distinct_wan_count   INTEGER       NOT NULL DEFAULT 0,
    distinct_sensor_count INTEGER      NOT NULL DEFAULT 0,
    first_seen           TIMESTAMPTZ   NOT NULL,
    last_seen            TIMESTAMPTZ   NOT NULL,
    eligible                  BOOLEAN  NOT NULL DEFAULT false,
    recommended_for_vendor    BOOLEAN  NOT NULL DEFAULT false,
    recommended_for_blocklist BOOLEAN  NOT NULL DEFAULT false,
    tier                      feed_tier_enum
);
