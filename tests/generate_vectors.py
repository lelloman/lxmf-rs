#!/usr/bin/env python3
"""Generate msgpack test vectors for Rust LXMF interop tests.

Requires: pip install umsgpack
Uses the same umsgpack that Python RNS/LXMF uses internally.
"""

import umsgpack
import json
import base64
import os

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def generate_msgpack_vectors():
    vectors = []

    # 1: Simple LXMF payload array (4 elements, no stamp)
    timestamp = 1700000000.0
    title = b"Hello"
    content = b"World"
    fields = {}
    payload = [timestamp, title, content, fields]
    packed = umsgpack.packb(payload)
    vectors.append({
        "name": "payload_no_stamp",
        "timestamp": timestamp,
        "title": b64(title),
        "content": b64(content),
        "fields": [],
        "packed": b64(packed),
    })

    # 2: Payload with stamp (5 elements)
    stamp = bytes(range(32))
    payload_with_stamp = [timestamp, title, content, fields, stamp]
    packed_with_stamp = umsgpack.packb(payload_with_stamp)
    vectors.append({
        "name": "payload_with_stamp",
        "timestamp": timestamp,
        "title": b64(title),
        "content": b64(content),
        "fields": [],
        "stamp": b64(stamp),
        "packed": b64(packed_with_stamp),
    })

    # 3: Fields with int keys
    fields_with_renderer = {0x0F: 0x02}
    payload_fields = [timestamp, title, content, fields_with_renderer]
    packed_fields = umsgpack.packb(payload_fields)
    vectors.append({
        "name": "payload_with_fields",
        "timestamp": timestamp,
        "title": b64(title),
        "content": b64(content),
        "fields": [[15, {"type": "uint", "value": 2}]],
        "packed": b64(packed_fields),
    })

    # 4: Empty dict
    vectors.append({
        "name": "empty_dict",
        "packed": b64(umsgpack.packb({})),
    })

    # 5: Empty list
    vectors.append({
        "name": "empty_list",
        "packed": b64(umsgpack.packb([])),
    })

    # 6: Large binary (256 bytes)
    large_bin = bytes(range(256))
    vectors.append({
        "name": "large_binary",
        "input": b64(large_bin),
        "packed": b64(umsgpack.packb(large_bin)),
    })

    # 7: File container
    container = {
        "state": 0x01,
        "lxmf_bytes": b"test_data",
        "transport_encrypted": True,
        "transport_encryption": "Curve25519",
        "method": 0x02,
    }
    vectors.append({
        "name": "file_container",
        "packed": b64(umsgpack.packb(container)),
    })

    # 8: PN announce data
    announce_data = [
        False, 1700000000, True, 256, 10240,
        [16, 3, 18], {}
    ]
    vectors.append({
        "name": "pn_announce_data",
        "packed": b64(umsgpack.packb(announce_data)),
    })

    # 9: Delivery announce app_data
    peer_data = [b"TestNode", 16]
    vectors.append({
        "name": "delivery_announce_data",
        "packed": b64(umsgpack.packb(peer_data)),
    })

    # 10: Integer encoding edge cases
    int_vectors = []
    for n in [0, 1, 127, 128, 255, 256, 65535]:
        int_vectors.append({
            "value": n,
            "packed": b64(umsgpack.packb(n)),
        })
    vectors.append({
        "name": "integer_encoding",
        "values": int_vectors,
    })

    # 11: Propagation pack format
    lxmf_data = bytes(range(64))
    prop_pack = [1700000000.0, [lxmf_data]]
    vectors.append({
        "name": "propagation_pack",
        "packed": b64(umsgpack.packb(prop_pack)),
    })

    # 12: Nil
    vectors.append({"name": "nil_value", "packed": b64(umsgpack.packb(None))})

    # 13: Booleans
    vectors.append({"name": "bool_true", "packed": b64(umsgpack.packb(True))})
    vectors.append({"name": "bool_false", "packed": b64(umsgpack.packb(False))})

    # 14: String
    vectors.append({
        "name": "string_curve25519",
        "packed": b64(umsgpack.packb("Curve25519")),
    })

    return vectors


def generate_storage_vectors():
    """Generate test vectors for storage format interop."""
    import hashlib
    vectors = []

    # 1: Transient ID cache: dict of 32-byte hash -> float timestamp
    tid1 = hashlib.sha256(b"message_one").digest()
    tid2 = hashlib.sha256(b"message_two").digest()
    transient_ids = {tid1: 1700000000.0, tid2: 1700001000.5}
    vectors.append({
        "name": "transient_ids",
        "packed": b64(umsgpack.packb(transient_ids)),
        "entries": [
            {"key": b64(tid1), "value": 1700000000.0},
            {"key": b64(tid2), "value": 1700001000.5},
        ],
    })

    # 2: Stamp costs: dict of 16-byte dest_hash -> [timestamp, cost]
    dh1 = hashlib.sha256(b"dest_one").digest()[:16]
    dh2 = hashlib.sha256(b"dest_two").digest()[:16]
    stamp_costs = {dh1: [1700000000.0, 16], dh2: [1700002000.0, 8]}
    vectors.append({
        "name": "stamp_costs",
        "packed": b64(umsgpack.packb(stamp_costs)),
        "entries": [
            {"key": b64(dh1), "timestamp": 1700000000.0, "cost": 16},
            {"key": b64(dh2), "timestamp": 1700002000.0, "cost": 8},
        ],
    })

    # 3: Node statistics: dict of string -> uint
    node_stats = {"messages_received": 42, "messages_sent": 17, "peers_connected": 3}
    vectors.append({
        "name": "node_stats",
        "packed": b64(umsgpack.packb(node_stats)),
        "entries": [
            {"key": "messages_received", "value": 42},
            {"key": "messages_sent", "value": 17},
            {"key": "peers_connected", "value": 3},
        ],
    })

    # 4: Peers list: array of peer dicts (simplified)
    peer1 = {
        "destination_hash": hashlib.sha256(b"peer_one").digest()[:16],
        "last_heard": 1700000000.0,
        "alive": True,
    }
    peer2 = {
        "destination_hash": hashlib.sha256(b"peer_two").digest()[:16],
        "last_heard": 1700001000.0,
        "alive": False,
    }
    peers = [peer1, peer2]
    vectors.append({
        "name": "peers",
        "packed": b64(umsgpack.packb(peers)),
        "count": 2,
    })

    # 5: Destination hash computation
    # dest_hash = SHA256(SHA256("lxmf.delivery") + identity_hash)[:16]
    identity_hash = bytes(range(16))
    name_hash = hashlib.sha256(b"lxmf.delivery").digest()
    material = name_hash + identity_hash
    full_hash = hashlib.sha256(material).digest()
    dest_hash = full_hash[:16]
    vectors.append({
        "name": "dest_hash_delivery",
        "identity_hash": b64(identity_hash),
        "expected_hash": b64(dest_hash),
    })

    # 6: Propagation destination hash
    name_hash_prop = hashlib.sha256(b"lxmf.propagation").digest()
    material_prop = name_hash_prop + identity_hash
    full_hash_prop = hashlib.sha256(material_prop).digest()
    dest_hash_prop = full_hash_prop[:16]
    vectors.append({
        "name": "dest_hash_propagation",
        "identity_hash": b64(identity_hash),
        "expected_hash": b64(dest_hash_prop),
    })

    # 7: Control destination hash
    name_hash_ctrl = hashlib.sha256(b"lxmf.propagation.control").digest()
    material_ctrl = name_hash_ctrl + identity_hash
    full_hash_ctrl = hashlib.sha256(material_ctrl).digest()
    dest_hash_ctrl = full_hash_ctrl[:16]
    vectors.append({
        "name": "dest_hash_control",
        "identity_hash": b64(identity_hash),
        "expected_hash": b64(dest_hash_ctrl),
    })

    return vectors


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "fixtures")
    os.makedirs(out_dir, exist_ok=True)

    vectors = generate_msgpack_vectors()
    out_path = os.path.join(out_dir, "msgpack_vectors.json")
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"Wrote {len(vectors)} msgpack vectors to {out_path}")

    storage_vectors = generate_storage_vectors()
    out_path = os.path.join(out_dir, "storage_vectors.json")
    with open(out_path, "w") as f:
        json.dump(storage_vectors, f, indent=2)
    print(f"Wrote {len(storage_vectors)} storage vectors to {out_path}")


if __name__ == "__main__":
    main()
