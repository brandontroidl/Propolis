CREATE TABLE review_queue (
    source_ip         INET PRIMARY KEY,
    state             review_state_enum NOT NULL DEFAULT 'pending',
    score_at_surface  NUMERIC(10,3) NOT NULL,
    categories_at_surface JSONB NOT NULL,
    surfaced_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at        TIMESTAMPTZ,
    notes             TEXT
);
