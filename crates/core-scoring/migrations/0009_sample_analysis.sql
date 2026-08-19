CREATE TABLE sample_analysis (
    sha256 TEXT PRIMARY KEY,
    detected INTEGER NOT NULL,
    total INTEGER NOT NULL,
    vt_link TEXT NOT NULL DEFAULT '',
    source_sensor TEXT NOT NULL DEFAULT '',
    analyzed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
