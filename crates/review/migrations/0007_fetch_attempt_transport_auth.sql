-- Whether the transport that delivered a captured body authenticated its sender (audit P-08).
--
-- The fetcher used to accept any TLS certificate, so an https capture carried no evidence that
-- its bytes came from the named host rather than an on-path party, yet read exactly like one that
-- did. It now verifies the certificate first and, only when validation fails, fetches again from
-- the same pinned address without it. This records which happened, per captured body, over every
-- redirect hop that delivered it:
--
--   verified    every hop was https and its certificate verified for the host name
--   unverified  at least one https hop failed certificate validation and was fetched again
--               without it; tls_verify_error holds the first such failure
--   plaintext   no certificate failed validation, but at least one hop was http or tftp
--   unknown     no body was captured, or it was captured before this column existed
--
-- Existing rows take 'unknown': nothing recorded how they were fetched, and the client that
-- fetched them verified no certificate, so none of them may read as verified.
ALTER TABLE fetch_attempt
    ADD COLUMN transport_auth TEXT NOT NULL DEFAULT 'unknown'
        CONSTRAINT fetch_attempt_transport_auth_known
        CHECK (transport_auth IN ('verified', 'unverified', 'plaintext', 'unknown')),
    ADD COLUMN tls_verify_error TEXT,
    ADD CONSTRAINT fetch_attempt_tls_verify_error_iff_unverified
        CHECK ((transport_auth = 'unverified') = (tls_verify_error IS NOT NULL));
