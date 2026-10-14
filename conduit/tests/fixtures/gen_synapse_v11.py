#!/usr/bin/env python3
"""Generate conduit/tests/fixtures/synapse_v11.json from the pinned Synapse.

Run from the repo root with the pinned peer venv (Synapse 1.162.0):

    .spawns/synapse-venv/bin/python conduit/tests/fixtures/gen_synapse_v11.py

Every hash, event ID, signature and verdict in the fixture is computed by
Synapse code (add_hashes_and_signatures, make_event_from_dict,
_check_sigs_on_pdu with a fixed-key keyring), never by Conduit. Keys are
derived from fixed seeds so the output is deterministic.
"""
import asyncio
import importlib.metadata
import json
from pathlib import Path

import base64

from signedjson.key import decode_signing_key_base64, get_verify_key, encode_verify_key_base64
from signedjson.sign import verify_signed_json

from synapse.api.room_versions import RoomVersions
from synapse.crypto.event_signing import add_hashes_and_signatures, compute_event_signature
from synapse.events import make_event_from_dict
from synapse.events.utils import prune_event
from synapse.federation.federation_base import _check_sigs_on_pdu

assert importlib.metadata.version("matrix-synapse") == "1.162.0"
V11 = RoomVersions.V11
TS = 1_700_000_000_000


def key(seed_byte, version):
    seed = base64.b64encode(bytes([seed_byte]) * 32).decode().rstrip("=")
    return decode_signing_key_base64("ed25519", version, seed)


SERVERS = {"a.example": key(1, "a1"), "c.example": key(3, "c1"), "x.example": key(7, "x1")}


class FixedKeyring:
    """verify_event_for_server against the fixed keys, as Synapse's Keyring
    does: on the pruned event, every signature from the server must verify."""

    async def verify_event_for_server(self, server_name, event, validity_time):
        signing_key = SERVERS.get(server_name)
        if signing_key is None:
            raise Exception(f"unknown server {server_name}")
        pruned = prune_event(event).get_pdu_json()
        verify_signed_json(pruned, server_name, get_verify_key(signing_key))


def verdict(pdu):
    event = make_event_from_dict(dict(pdu), V11)
    try:
        asyncio.run(_check_sigs_on_pdu(FixedKeyring(), V11, event))
        return "accepted"
    except Exception as error:  # InvalidEventSignatureError
        return "dropped: " + type(error).__name__


def sign(pdu, server):
    add_hashes_and_signatures(V11, pdu, server, SERVERS[server])
    return pdu


def cosign(pdu, server):
    pdu = json.loads(json.dumps(pdu))
    sigs = compute_event_signature(V11, pdu, server, SERVERS[server])
    pdu.setdefault("signatures", {}).update(sigs)
    return pdu


def base(**fields):
    pdu = {"room_id": "!room:a.example", "sender": "@alice:a.example", "type": "m.room.message",
           "content": {"body": "Hello, 世界", "msgtype": "m.text"}, "origin_server_ts": TS,
           "auth_events": ["$auth"], "prev_events": ["$prev"], "depth": 2}
    pdu.update(fields)
    return pdu


def member(membership, authoriser="@admin:c.example"):
    content = {"membership": membership, "join_authorised_via_users_server": authoriser}
    return base(type="m.room.member", sender="@joiner:a.example", state_key="@joiner:a.example", content=content)


def vector(name, pdu):
    return {"name": name, "pdu": pdu, "event_id": make_event_from_dict(dict(pdu), V11).event_id,
            "synapse_signature_stage": verdict(pdu)}


fixture = {
    "generated_by": "matrix-synapse 1.162.0 via conduit/tests/fixtures/gen_synapse_v11.py",
    "keys": {server: {"key_id": f"ed25519:{k.version}", "seed_byte": seed,
                      "public": encode_verify_key_base64(get_verify_key(k))}
             for (server, k), seed in zip(SERVERS.items(), [1, 3, 7])},
}

# 1. A v11 PDU with an extension key and no event_id.
extended = sign(base(**{"org.example.extension": {"opaque": True, "unicode": "世界"}}), "a.example")
fixture["extended"] = vector("extended", extended)

# 2. The same PDU with an explicit event_id: Synapse refuses to build it.
explicit = dict(extended, event_id=fixture["extended"]["event_id"])
try:
    make_event_from_dict(explicit, V11)
    fixture["explicit_event_id"] = {"pdu": explicit, "synapse": "accepted"}
except Exception as error:
    chain = []
    while error is not None:
        chain.append(str(error))
        error = error.__cause__ or error.__context__
    fixture["explicit_event_id"] = {"pdu": explicit, "synapse": " / ".join(chain)}

# 3. An `outlier` extension: Synapse's content hash pops it, the spec's does not.
fixture["outlier"] = vector("outlier", sign(base(outlier=True), "a.example"))

# 4. Restricted-join signature vectors.
sender_only = sign(member("join"), "a.example")
co_signed = cosign(sender_only, "c.example")
invalid = json.loads(json.dumps(co_signed))
invalid["signatures"]["c.example"]["ed25519:c1"] = invalid["signatures"]["a.example"]["ed25519:a1"]
fixture["restricted_join"] = [
    vector("sender_only", sender_only),
    vector("invalid_authoriser", invalid),
    vector("co_signed", co_signed),
]

# 5. Non-join memberships carrying the key: Synapse does not check the
#    authoriser at the signature stage (Conduit applies rule 4.2 in auth).
non_join = []
for membership in ["invite", "leave"]:
    missing = sign(member(membership), "a.example")
    valid = cosign(missing, "c.example")
    bad = json.loads(json.dumps(valid))
    bad["signatures"]["c.example"]["ed25519:c1"] = bad["signatures"]["a.example"]["ed25519:a1"]
    non_join += [vector(f"{membership}_missing", missing), vector(f"{membership}_valid", valid),
                 vector(f"{membership}_invalid", bad)]
fixture["non_join_authoriser"] = non_join

# 6. Third-party invite: exempt from the sender-server signature.
tpi = base(type="m.room.member", sender="@inviter:x.example", state_key="@invitee:a.example",
           content={"membership": "invite", "third_party_invite": {"display_name": "I",
                    "signed": {"mxid": "@invitee:a.example", "token": "t", "signatures": {}}}})
fixture["third_party_invite"] = vector("third_party_invite_signed_elsewhere", sign(tpi, "a.example"))

out = Path(__file__).with_name("synapse_v11.json")
out.write_text(json.dumps(fixture, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
print(f"wrote {out}")
