#!/usr/bin/env python3
"""Live interop between upstream Python LXMF 1.3 and the lxmf-rs router.

Runs a Python LXMF router with an RNS TCP server interface, starts the Rust
`interop_peer` example as a client of it, and exercises both directions over
the real wire protocol:

  1. announces parse both ways, including fractional stamp costs
  2. opportunistic Python -> Rust with a fractional stamp, proven (DELIVERED),
     and echoed back opportunistically
  3. direct Python -> Rust as a link packet, proven, and echoed back
  4. direct Python -> Rust as a resource, concluded, and echoed back
  5. propagated Python -> Rust via the Rust propagation node: the packet is
     proven (SENT) and delivered locally on the Rust side
  6. a propagated resource (app flag set) for a third party, stored by the
     Rust propagation node
  7. the Rust propagation node peers with the Python one and syncs that
     message to it (Rust generates a fractional-cost peering key)
  8. the Python propagation node syncs a message to the Rust one

Usage:
    LXMF_SRC=../LXMF RNS_SRC=../Reticulum \\
        python3 tests/interop/lxmf13_live.py <path/to/interop_peer>
"""

import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

for var in ("RNS_SRC", "LXMF_SRC"):
    path = os.environ.get(var)
    if not path:
        sys.exit(f"{var} must point at an upstream checkout")
    sys.path.insert(0, os.path.abspath(path))

import RNS  # noqa: E402
import LXMF  # noqa: E402
import LXMF.LXStamper  # noqa: E402,F401
from LXMF.LXMessage import LXMessage  # noqa: E402

TIMEOUT = float(os.environ.get("INTEROP_TIMEOUT", "90"))
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{': ' + str(detail) if detail else ''}", flush=True)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(predicate, timeout=TIMEOUT, interval=0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


class RustPeer:
    def __init__(self, binary, port, storage):
        os.makedirs(storage, exist_ok=True)
        self.events = []
        self.lock = threading.Lock()
        self.proc = subprocess.Popen(
            [binary, f"127.0.0.1:{port}", storage],
            stdout=subprocess.PIPE,
            stderr=open(os.path.join(os.path.dirname(storage), "rust.log"), "w"),
            text=True,
        )
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            with self.lock:
                self.events.append(event)
            print(f"  rust> {line.strip()}", flush=True)

    def find(self, kind, **match):
        with self.lock:
            for event in self.events:
                if event.get("event") == kind and all(event.get(k) == v for k, v in match.items()):
                    return event
        return None

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    binary = os.path.abspath(sys.argv[1])
    workdir = tempfile.mkdtemp(prefix="lxmf13_live_", dir=os.environ.get("INTEROP_TMPDIR"))
    port = free_port()

    configdir = os.path.join(workdir, "rns")
    os.makedirs(configdir)
    with open(os.path.join(configdir, "config"), "w") as f:
        f.write(
            f"""[reticulum]
  enable_transport = Yes
  share_instance = No
  panic_on_interface_error = Yes

[logging]
  loglevel = {os.environ.get("RNS_LOGLEVEL", "2")}

[interfaces]
  [[Interop TCP Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {port}
"""
        )

    RNS.Reticulum(configdir=configdir)
    router = LXMF.LXMRouter(
        identity=RNS.Identity(),
        storagepath=os.path.join(workdir, "lxmf"),
        propagation_cost=13.0,
        peering_cost=7.5,
    )
    identity = RNS.Identity()
    source = router.register_delivery_identity(identity, display_name="python 1.3 interop")
    inbox = queue.Queue()
    router.register_delivery_callback(lambda message: inbox.put(message))
    router.enable_propagation()
    python_pn = RNS.Destination.hash_from_name_and_identity("lxmf.propagation", router.identity)

    rust = RustPeer(binary, port, os.path.join(workdir, "rust"))
    try:
        ready = wait_for(lambda: rust.find("ready"), timeout=30)
        if not ready:
            check("rust peer starts", False)
            return
        rust_delivery = bytes.fromhex(ready["delivery_hash"])
        rust_pn = bytes.fromhex(ready["propagation_hash"])

        # 1. Announces both ways.
        router.announce(source.hash)
        router.announce_propagation_node()
        got_path = wait_for(lambda: RNS.Transport.has_path(rust_delivery) and RNS.Identity.recall(rust_delivery))
        check("python learns rust delivery destination", got_path)
        if not got_path:
            return
        app_data = RNS.Identity.recall_app_data(rust_delivery)
        check(
            "rust delivery announce parses in python",
            LXMF.stamp_cost_from_app_data(app_data) == ready["delivery_stamp_cost"]
            and LXMF.display_name_from_app_data(app_data) == "lxmf-rs interop",
            (LXMF.display_name_from_app_data(app_data), LXMF.stamp_cost_from_app_data(app_data)),
        )
        check(
            "python stores rust's fractional stamp cost",
            wait_for(lambda: router.get_outbound_stamp_cost(rust_delivery) == ready["delivery_stamp_cost"], 15),
            router.get_outbound_stamp_cost(rust_delivery),
        )
        got_pn = wait_for(lambda: LXMF.pn_announce_data_is_valid(RNS.Identity.recall_app_data(rust_pn)))
        pn_data = RNS.Identity.recall_app_data(rust_pn) if got_pn else None
        check(
            "rust propagation node announce is valid in python",
            got_pn
            and LXMF.pn_stamp_cost_from_app_data(pn_data) == ready["propagation_stamp_cost"]
            and LXMF.pn_name_from_app_data(pn_data) == "lxmf-rs interop PN",
            (LXMF.pn_stamp_cost_from_app_data(pn_data), LXMF.pn_name_from_app_data(pn_data)) if pn_data else None,
        )

        rust_identity = RNS.Identity.recall(rust_delivery)
        destination = RNS.Destination(rust_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")

        def send(title, content, method):
            message = LXMessage(destination, source, content, title, desired_method=method)
            router.handle_outbound(message)
            return message

        def expect_echo(title, label):
            deadline = time.time() + TIMEOUT
            while time.time() < deadline:
                try:
                    message = inbox.get(timeout=1)
                except queue.Empty:
                    continue
                if message.title_as_string() == f"Echo: {title}":
                    check(f"{label}: echo received from rust", message.signature_validated, message.method)
                    return message
            check(f"{label}: echo received from rust", False)
            return None

        def run_case(label, title, content, method, final_state):
            message = send(title, content, method)
            reached = wait_for(lambda: message.state in (final_state, LXMessage.FAILED))
            check(f"{label}: python message reaches {final_state:#x}", message.state == final_state, f"state={message.state:#x}")
            delivered = wait_for(lambda: rust.find("delivered", title=title))
            check(
                f"{label}: rust delivers with valid signature and stamp",
                delivered and delivered["signature_valid"] and delivered["has_stamp"],
                delivered,
            )
            return reached

        # 2. Opportunistic, stamped at the fractional cost Rust announced.
        run_case("opportunistic", "opp", "hello from python", LXMessage.OPPORTUNISTIC, LXMessage.DELIVERED)
        expect_echo("opp", "opportunistic")

        # 3. Direct, as a single link packet.
        run_case("direct packet", "link", "small direct", LXMessage.DIRECT, LXMessage.DELIVERED)
        expect_echo("link", "direct packet")

        # 4. Direct, as a resource.
        run_case("direct resource", "resource", "R" * 4000, LXMessage.DIRECT, LXMessage.DELIVERED)
        expect_echo("resource", "direct resource")

        # 5. Propagated to Rust through its propagation node.
        router.set_outbound_propagation_node(rust_pn)
        run_case("propagated to rust", "via-pn", "through the rust pn", LXMessage.PROPAGATED, LXMessage.SENT)
        expect_echo("via-pn", "propagated to rust")

        # 6. Propagated resource for a third party, stored by the Rust PN.
        third = RNS.Destination(RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
        message = LXMessage(third, source, "P" * 3000, "stored", desired_method=LXMessage.PROPAGATED)
        router.handle_outbound(message)
        wait_for(lambda: message.state in (LXMessage.SENT, LXMessage.FAILED))
        check("propagated resource: python message reaches SENT", message.state == LXMessage.SENT, f"state={message.state:#x}")
        third_tid = RNS.hexrep(message.transient_id, delimit=False) if message.transient_id else None

        def rust_state():
            with rust.lock:
                states = [e for e in rust.events if e.get("event") == "propagation_state"]
            return states[-1] if states else {}

        stored = wait_for(lambda: third_tid in rust_state().get("transient_ids", []), 30)
        check("propagated resource: rust PN stores the message", stored, third_tid)

        # 7. Rust PN -> Python PN peer sync.
        def rust_peer(hash_bytes):
            for peer in rust_state().get("peers", []):
                if peer["hash"] == hash_bytes.hex():
                    return peer
            return None

        check("rust PN peers with the python PN", wait_for(lambda: rust_peer(python_pn), 60), rust_peer(python_pn))
        synced = wait_for(lambda: message.transient_id in router.propagation_entries, 180)
        check(
            "rust PN syncs the stored message to the python PN",
            synced,
            rust_peer(python_pn),
        )
        check(
            "python accounts the transfer to its rust peer",
            rust_pn in router.peers and router.peers[rust_pn].incoming >= 1,
            router.peers[rust_pn].incoming if rust_pn in router.peers else "not peered",
        )

        # 8. Python PN -> Rust PN peer sync, with a stamp meeting the Rust
        # node's fractional target.
        lxmf_data = RNS.Identity.full_hash(b"third-party")[:16] + os.urandom(200)
        transient_id = RNS.Identity.full_hash(lxmf_data)
        stamp, value = LXMF.LXStamper.generate_stamp(
            transient_id, 10.5, expand_rounds=LXMF.LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN
        )
        router.lxmf_propagation(lxmf_data, stamp_value=value, stamp_data=stamp)
        check("python PN stores the ingested message", transient_id in router.propagation_entries)
        synced = wait_for(lambda: transient_id.hex() in rust_state().get("transient_ids", []), 180)
        check("python PN syncs the message to the rust PN", synced, rust_peer(python_pn))
        peer = rust_peer(python_pn)
        check("rust accounts the transfer to its python peer", peer and peer["incoming"] >= 1, peer)
    finally:
        rust.stop()
        failed = [name for name, ok, _ in results if not ok]
        print(f"\n{len(results) - len(failed)}/{len(results)} checks passed", flush=True)
        if os.environ.get("KEEP_WORKDIR"):
            print(f"workdir: {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
        os._exit(1 if failed or not results else 0)


if __name__ == "__main__":
    main()
