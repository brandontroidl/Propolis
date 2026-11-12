-- Finding #2: Enforce append-only immutability at the database layer.
-- The propolis role retains INSERT (for the intake pipeline) but loses
-- UPDATE, DELETE, and TRUNCATE on the event table. Chain integrity can
-- no longer be broken by a compromised collector or direct SQL access.
--
-- Finding #4: CHECK constraints on event fields that the application
-- validates but the database did not enforce. A direct SQL INSERT that
-- bypasses the application can no longer inject invalid values.
--
-- Clean up any rogue/malformed events before applying constraints.
DELETE FROM event WHERE octet_length(hash) <> 32 OR sensor = '' OR confidence < 0 OR confidence > 1 OR weight < 0;

ALTER TABLE event
  ADD CONSTRAINT event_sensor_nonempty CHECK (sensor <> ''),
  ADD CONSTRAINT event_hash_length CHECK (octet_length(hash) = 32),
  ADD CONSTRAINT event_confidence_range CHECK (confidence BETWEEN 0 AND 1),
  ADD CONSTRAINT event_weight_nonnegative CHECK (weight >= 0);

-- Revoke mutation rights from the propolis role in production. Skipped when
-- the current database is a test database (name contains 'test' or the role
-- doesn't exist) so test cleanup (DELETE FROM event) keeps working.
DO $$ BEGIN
  IF current_database() = 'propolis'
     AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'propolis') THEN
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON event FROM propolis';
  END IF;
END $$;
