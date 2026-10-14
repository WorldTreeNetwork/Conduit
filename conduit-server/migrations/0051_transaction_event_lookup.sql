-- Look up client transaction IDs by the event they created (conduit-y99.27):
-- sync marks the sending device's own events with unsigned.transaction_id.
CREATE INDEX transactions_client_event ON transactions (owner, (result->>'event_id'))
    WHERE scope = 'client';
