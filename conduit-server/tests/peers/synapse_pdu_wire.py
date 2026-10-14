#!/usr/bin/env python3
"""Required PDU wire contract regression. Currently fails pending add-pdu-wire.

Uses the same pinned peer lifecycle as the to-device journey and exits nonzero
when Conduit rejects a standard no-event_id PDU or loses extension fields.
"""
from synapse_to_device import main

if __name__ == "__main__":
    main(pdu_wire=True)
