-- Finding #3: Enforce hash chain linkage at the database layer.
-- Every INSERT must carry a prev_hash that matches the most recent
-- event's hash. The first event (no predecessor) must have prev_hash
-- NULL. A rogue INSERT with a fabricated or missing prev_hash is
-- rejected before it lands.
--
-- The hash itself is still computed application-side (the canonical
-- encoding is in Rust, not SQL), but the chain LINKAGE is now
-- enforced by the database: you cannot insert an event whose
-- prev_hash does not match the current chain head.

CREATE OR REPLACE FUNCTION enforce_chain_linkage()
RETURNS TRIGGER AS $$
DECLARE
  head_hash BYTEA;
BEGIN
  SELECT hash INTO head_hash FROM event ORDER BY id DESC LIMIT 1;

  IF head_hash IS NULL THEN
    IF NEW.prev_hash IS NOT NULL THEN
      RAISE EXCEPTION 'first event must have NULL prev_hash';
    END IF;
  ELSE
    IF NEW.prev_hash IS NULL OR NEW.prev_hash <> head_hash THEN
      RAISE EXCEPTION 'prev_hash does not match chain head';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_enforce_chain_linkage
  BEFORE INSERT ON event
  FOR EACH ROW
  EXECUTE FUNCTION enforce_chain_linkage();
