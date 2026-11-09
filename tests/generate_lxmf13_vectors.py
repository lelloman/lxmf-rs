#!/usr/bin/env python3
"""Generate LXMF 1.3 interop vectors from the upstream Python implementation.

Unlike generate_vectors.py, which re-implements wire formats with umsgpack,
this script calls upstream LXMF/RNS code directly, so the vectors capture
what Python LXMF 1.3 actually emits and accepts: fractional stamp costs and
values, the transitional announce formats, and the corrected packet limits.

Usage (with upstream checkouts at the reviewed commits):

    LXMF_SRC=../LXMF RNS_SRC=../Reticulum \\
        python3 tests/generate_lxmf13_vectors.py tests/fixtures/lxmf13_vectors.json
"""

import base64
import json
import os
import subprocess
import sys
import types

for var in ("RNS_SRC", "LXMF_SRC"):
    path = os.environ.get(var)
    if not path:
        sys.exit(f"{var} must point at an upstream checkout")
    sys.path.insert(0, os.path.abspath(path))

import RNS  # noqa: E402
import RNS.Stamps as Stamps  # noqa: E402
import RNS.vendor.umsgpack as msgpack  # noqa: E402
import LXMF  # noqa: E402
import LXMF.LXMRouter  # noqa: E402,F401
import LXMF.LXStamper as LXStamper  # noqa: E402
from LXMF.LXMessage import LXMessage  # noqa: E402
from LXMF.LXMRouter import LXMRouter  # noqa: E402
from LXMF._version import __version__ as LXMF_VERSION  # noqa: E402
from RNS._version import __version__ as RNS_VERSION  # noqa: E402

# The package re-exports the LXMRouter class under the module name.
LXMRouterModule = sys.modules["LXMF.LXMRouter"]


def b64(data):
    return base64.b64encode(data).decode()


def git_head(var):
    try:
        return subprocess.check_output(
            ["git", "-C", os.environ[var], "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        return None


def constants():
    return {
        "ENCRYPTED_PACKET_MDU": LXMessage.ENCRYPTED_PACKET_MDU,
        "ENCRYPTED_PACKET_MAX_CONTENT": LXMessage.ENCRYPTED_PACKET_MAX_CONTENT,
        "LINK_PACKET_MDU": LXMessage.LINK_PACKET_MDU,
        "LINK_PACKET_MAX_CONTENT": LXMessage.LINK_PACKET_MAX_CONTENT,
        "PLAIN_PACKET_MDU": LXMessage.PLAIN_PACKET_MDU,
        "PLAIN_PACKET_MAX_CONTENT": LXMessage.PLAIN_PACKET_MAX_CONTENT,
        "LXMF_OVERHEAD": LXMessage.LXMF_OVERHEAD,
        "ENCRYPTION_DESCRIPTION_AES": LXMessage.ENCRYPTION_DESCRIPTION_AES,
        "PEERING_COST": LXMRouter.PEERING_COST,
        "MAX_PEERING_COST": LXMRouter.MAX_PEERING_COST,
        "PROPAGATION_COST_MIN": LXMRouter.PROPAGATION_COST_MIN,
        "PROPAGATION_COST_FLEX": LXMRouter.PROPAGATION_COST_FLEX,
        "PROPAGATION_COST": LXMRouter.PROPAGATION_COST,
        "PN_STAMP_THROTTLE": LXMRouter.PN_STAMP_THROTTLE,
        "DELIVERY_LINK_COST": LXMRouter.DELIVERY_LINK_COST,
        "PROPAGATION_LINK_COST": LXMRouter.PROPAGATION_LINK_COST,
        "MESSAGE_EXPIRY": LXMRouter.MESSAGE_EXPIRY,
        "PATH_REQUEST_WAIT": LXMRouter.PATH_REQUEST_WAIT,
        "PATH_REQUEST_DEBOUNCE": LXMRouter.PATH_REQUEST_DEBOUNCE,
        "SLOW_INTERFACE_BITRATE": LXMRouter.SLOW_INTERFACE_BITRATE,
        "AIRTIME_AWARE_MTU_TIME": LXMRouter.AIRTIME_AWARE_MTU_TIME,
        "DELIVERY_RETRY_WAIT": LXMRouter.DELIVERY_RETRY_WAIT,
        "MAX_DELIVERY_ATTEMPTS": LXMRouter.MAX_DELIVERY_ATTEMPTS,
        "STAMP_COST_CAP": RNS.Transport.STAMP_COST_CAP,
        "PN_META_IMPL_NAME": LXMF.PN_META_IMPL_NAME,
        "PN_META_VERSION": LXMF.PN_META_VERSION,
        "PN_META_NAME": LXMF.PN_META_NAME,
    }


def delivery_announces():
    """Delivery announce app_data as LXMRouter.get_announce_app_data builds it."""
    cases = [
        ("named_whole_cost", "Alice", 16),
        ("named_fractional_cost", "Bob", 8.5),
        ("fine_fractional_cost", "Carol", 12.3),
        ("no_cost", "Dave", None),
        ("cost_below_one_is_sent", None, 0.5),
        ("cost_at_cap_is_dropped", "Eve", 100),
        ("unnamed_whole_cost", None, 7),
    ]
    vectors = []
    for name, display_name, stamp_cost in cases:
        dest_hash = os.urandom(16)
        stub = types.SimpleNamespace(
            delivery_destinations={
                dest_hash: types.SimpleNamespace(display_name=display_name, stamp_cost=stamp_cost)
            }
        )
        app_data = LXMRouter.get_announce_app_data(stub, dest_hash)
        parsed = LXMF.stamp_cost_from_app_data(app_data)
        vectors.append(
            {
                "name": name,
                "display_name": display_name,
                "stamp_cost": stamp_cost,
                "app_data": b64(app_data),
                "parsed_stamp_cost": parsed,
                "parsed_display_name": LXMF.display_name_from_app_data(app_data),
            }
        )
    return vectors


def delivery_announce_parsing():
    """Hand-made delivery app_data and what upstream reads from it."""
    cases = [
        ("legacy_three_elements", [b"Old", 12, [0x00]]),
        ("legacy_two_elements", [b"Older", 9]),
        ("exact_cost_preferred", [b"N", 9, [0x00], 8.25]),
        ("integer_exact_cost", [b"N", 9, [0x00], 9]),
        ("nil_exact_cost_falls_back", [b"N", 9, [0x00], None]),
        ("string_exact_cost_falls_back", [b"N", 9, [0x00], "x"]),
        ("float_in_second_element", [b"N", 10.5, [0x00]]),
    ]
    vectors = []
    for name, data in cases:
        app_data = msgpack.packb(data)
        vectors.append(
            {
                "name": name,
                "app_data": b64(app_data),
                "stamp_cost": LXMF.stamp_cost_from_app_data(app_data),
            }
        )
    return vectors


def pn_announces():
    """PN announce app_data as LXMRouter.get_propagation_node_app_data builds it."""
    cases = [
        ("defaults", 256, 10240, 16.0, 3.0, 18.0, "PN Alpha", False),
        ("fractional_costs", 256, 10240, 16.5, 2.25, 18.75, None, False),
        ("float_limits", 256.0, 10240.0, 17.0, 3.0, 20.0, "Float Limits", False),
        ("static_only_disables", 128, 4096, 13.0, 0.0, 18.0, "Static", True),
    ]
    vectors = []
    timebase = 1_760_000_000
    original_time = LXMRouterModule.time.time
    LXMRouterModule.time.time = lambda: float(timebase)
    try:
        for name, transfer, sync, cost, flex, peering, node_name, static_only in cases:
            stub = types.SimpleNamespace(
                propagation_node=True,
                from_static_only=static_only,
                propagation_per_transfer_limit=transfer,
                propagation_per_sync_limit=sync,
                propagation_stamp_cost=cost,
                propagation_stamp_cost_flexibility=flex,
                peering_cost=peering,
                name=node_name,
            )
            stub.get_propagation_node_announce_metadata = types.MethodType(
                LXMRouter.get_propagation_node_announce_metadata, stub
            )
            app_data = LXMRouter.get_propagation_node_app_data(stub)
            vectors.append(
                {
                    "name": name,
                    "timebase": timebase,
                    "propagation_enabled": not static_only,
                    "transfer_limit": transfer,
                    "sync_limit": sync,
                    "stamp_cost": cost,
                    "stamp_cost_flexibility": flex,
                    "peering_cost": peering,
                    "node_name": node_name,
                    "implementation": "lxmd",
                    "version": LXMF_VERSION,
                    "app_data": b64(app_data),
                    "valid": LXMF.pn_announce_data_is_valid(app_data),
                    "pn_stamp_cost": LXMF.pn_stamp_cost_from_app_data(app_data),
                    "pn_name": LXMF.pn_name_from_app_data(app_data),
                }
            )
    finally:
        LXMRouterModule.time.time = original_time
    return vectors


def pn_announce_validation():
    """Hand-made PN app_data and upstream's validity and cost readings."""
    base = [False, 1_760_000_000, True, 256, 10240, [16, 3, 18], {}]

    def variant(**changes):
        data = list(base)
        for index, value in changes.items():
            data[int(index[1:])] = value
        return data

    cases = [
        ("pre_1_3_integers", base),
        ("float_transfer_limit", variant(i3=256.0)),
        ("float_sync_limit", variant(i4=10240.0)),
        ("float_costs_in_5", variant(i5=[16.5, 3.0, 18.0])),
        ("transitional_costs_in_7", base + [[15.75, 2.5, 18.25]]),
        ("malformed_7_not_list", base + [16.5]),
        ("short_7", base + [[16.5, 3.0]]),
        ("string_cost", variant(i5=["16", 3, 18])),
        ("metadata_not_map", variant(i6=[])),
        ("too_short", base[:6]),
        ("non_bool_state", variant(i2=2)),
        ("float_timebase", variant(i1=1_760_000_000.5)),
    ]
    vectors = []
    for name, data in cases:
        app_data = msgpack.packb(data)
        vectors.append(
            {
                "name": name,
                "app_data": b64(app_data),
                "valid": bool(LXMF.pn_announce_data_is_valid(app_data)),
                "pn_stamp_cost": LXMF.pn_stamp_cost_from_app_data(app_data),
            }
        )
    return vectors


def quantization():
    costs = [0, 0.001, 0.5, 1, 3.0, 8.25, 12.3, 16.30078125, 16.5, 18.75, 26, 99.999, 100, 150, -3]
    return [
        {
            "cost": cost,
            "fp": Stamps.cost_to_fp(cost),
            "quantized": Stamps.quantize_cost(cost),
            "store_component": f"_{Stamps.quantize_cost(cost)}",
        }
        for cost in costs
    ]


def stamp_values():
    """Fractional stamp values and validity at fractional costs."""
    vectors = []
    material = bytes(range(32))
    workblock = LXStamper.stamp_workblock(material, expand_rounds=2)
    for i in range(24):
        stamp = RNS.Identity.full_hash(b"stamp-%d" % i)
        value = Stamps.stamp_value(workblock, stamp)
        costs = sorted({max(0.0, value - 0.5), value, value + 0.00390625, value + 0.5, 1.0, 2.5})
        vectors.append(
            {
                "material": b64(material),
                "rounds": 2,
                "stamp": b64(stamp),
                "value": value,
                "legacy_value": Stamps.stamp_value_legacy(workblock, stamp),
                "valid_at": [[cost, bool(Stamps.stamp_valid(stamp, cost, workblock))] for cost in costs],
            }
        )
    return vectors


def generated_stamps():
    """Stamps upstream generates at fractional costs, for Rust to validate."""
    vectors = []
    for i, (cost, rounds) in enumerate([(6.5, 25), (8.25, 25), (7.0, 1000)]):
        material = RNS.Identity.full_hash(b"generated-%d" % i)
        stamp, value = LXStamper.generate_stamp(material, cost, expand_rounds=rounds)
        vectors.append(
            {
                "material": b64(material),
                "rounds": rounds,
                "cost": cost,
                "stamp": b64(stamp),
                "value": value,
            }
        )
    return vectors


def pn_stamps():
    """Propagation stamps validated by LXStamper.validate_pn_stamp."""
    vectors = []
    for i, cost in enumerate([4.5, 6.0]):
        lxm_data = RNS.Identity.full_hash(b"dest-%d" % i)[:16] + os.urandom(140)
        transient_id = RNS.Identity.full_hash(lxm_data)
        stamp, value = LXStamper.generate_stamp(
            transient_id, cost, expand_rounds=LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN
        )
        transient_data = lxm_data + stamp
        tid, _, validated_value, _ = LXStamper.validate_pn_stamp(transient_data, cost)
        rejected = LXStamper.validate_pn_stamp(transient_data, value + 1.0)[0] is None
        vectors.append(
            {
                "transient_data": b64(transient_data),
                "target_cost": cost,
                "transient_id": b64(tid),
                "value": validated_value,
                "quantized_value": Stamps.quantize_cost(validated_value),
                "rejected_above_value": rejected,
            }
        )
    return vectors


def peering_keys():
    vectors = []
    for i, cost in enumerate([5.5, 7.25]):
        peering_id = RNS.Identity.full_hash(b"remote-%d" % i)[:16] + RNS.Identity.full_hash(b"local-%d" % i)[:16]
        key, value = LXStamper.generate_stamp(
            peering_id, cost, expand_rounds=LXStamper.WORKBLOCK_EXPAND_ROUNDS_PEERING
        )
        vectors.append(
            {
                "peering_id": b64(peering_id),
                "cost": cost,
                "peering_key": b64(key),
                "value": value,
                "valid": LXStamper.validate_peering_key(peering_id, key, cost),
            }
        )
    return vectors


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/lxmf13_vectors.json"
    vectors = {
        "upstream": {
            "lxmf_version": LXMF_VERSION,
            "rns_version": RNS_VERSION,
            "lxmf_commit": git_head("LXMF_SRC"),
            "rns_commit": git_head("RNS_SRC"),
        },
        "constants": constants(),
        "delivery_announces": delivery_announces(),
        "delivery_announce_parsing": delivery_announce_parsing(),
        "pn_announces": pn_announces(),
        "pn_announce_validation": pn_announce_validation(),
        "quantization": quantization(),
        "stamp_values": stamp_values(),
        "generated_stamps": generated_stamps(),
        "pn_stamps": pn_stamps(),
        "peering_keys": peering_keys(),
    }
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)
        f.write("\n")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
