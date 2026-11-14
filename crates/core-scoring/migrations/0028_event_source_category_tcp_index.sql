-- The index the vendor report's label lookup reads.
--
-- The submission runner picks the category codes of a report from the newest event of each
-- category (review's PROTOCOL_LABELS_SQL, one probe per category, see 0020). Since 0027 that
-- lookup asks for established events only (`protocol = 'tcp'`), so a datagram under a forged
-- source cannot change the codes a vendor is sent. Read from event_source_category_observed_idx,
-- which holds every event, the probe stepped over each datagram at or after the address in index
-- order before it reached a TCP row: 138 ms against 0.08 ms for an address with 200,000
-- datagrams behind it, a cost anyone can raise by sending datagrams.
--
-- This partial index holds only the rows the lookup can return, in the order it reads them, so
-- each probe is one descent again. Plain CREATE INDEX, not CONCURRENTLY, for the reasons given
-- in 0013; the build reads the event heap once.
CREATE INDEX event_source_category_tcp_idx ON event (source_ip, category, observed_at DESC)
    WHERE protocol = 'tcp';
