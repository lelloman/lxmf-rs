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


def main():
    vectors = generate_msgpack_vectors()
    out_dir = os.path.join(os.path.dirname(__file__), "fixtures")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "msgpack_vectors.json")
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"Wrote {len(vectors)} vectors to {out_path}")


if __name__ == "__main__":
    main()
