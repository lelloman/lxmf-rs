# Changelog

## 0.3.1

### lxmf-server

- Supervised processes get 120 seconds, up from 30, to write their ready
  file before they are restarted. A propagation node scans its whole
  message store first: on a node with a large store and little free memory
  that took about 30 seconds, so `lxmd` was killed and restarted several
  times on every start before one attempt made it.
- `lxmd.ready_timeout_secs` and a sidecar's `ready_timeout_secs` set the
  timeout per process.

### Testing

- The live interop test gives link packet proofs a one-second deadline.
  Over its localhost link Python allowed about 11 ms, less than the Rust
  propagation node takes to validate and store a client upload in a debug
  build, so about half of the CI runs failed.

## 0.3.0

On `rns-crypto` 0.2.2, `rns-core` 0.8.0 and `rns-net` 0.13.0. `rns-net`
0.13 no longer lets a forged proof complete a packet receipt, which
lxmf-rs relies on to mark messages delivered.

### Fixes

- A message sent as a single packet over a link (direct delivery, or an
  upload to a propagation node) is delivered, or accepted by the node, only
  once the peer proves that packet, as upstream. If the proof is overdue
  (six round trips of the link, and no sooner than one second), the link is
  torn down and the message is sent again. Before, the message was marked
  delivered as soon as it was sent, so a packet lost on the link was never
  retried.
- Messages downloaded from a propagation node are acknowledged, and the
  download reported `Complete`, only after their delivery callbacks ran, as
  upstream. Before, a client that stopped inside its callback lost the
  messages: the node had already deleted them.

### Breaking API changes

- `OutboundNetwork::send_link_packet` returns a `SentLinkPacket`, which
  reports the hash of the packet once it is sent.
- `OutboundNetwork` has a new required method, `close_link`.
- `OutboundMessage` gains `link_packet`, and `LxmRouter` gains `link_rtts`.

### Other changes

- `LxmRouter::handle_delivery_proof` concludes the message a proof is for;
  `LxmfCallbacks` calls it from `on_proof`.
- Applications that build `rns-net` interface configs must set
  `InterfaceConfig::announce_limits`, new in `rns-net` 0.13.

## 0.2.0

Brings lxmf-rs to behavioral parity with upstream Python LXMF 1.3.0
(`101fd44`), on `rns-crypto` 0.2.2, `rns-core` 0.7.0 and `rns-net` 0.12.0.
Remaining differences, all waiting on `rns-net` APIs, are listed in
[docs/parity-gaps.md](docs/parity-gaps.md).

### Interop fixes

- Delivery and propagation destinations prove packets. Before, nothing
  sent to a Rust node was ever confirmed as delivered.
- Outbound messages carry stamps: proof-of-work at the cost the recipient
  announced, or a ticket stamp. Propagated messages carry a propagation
  stamp at the node's cost. Before, stamp-enforcing recipients and nodes
  dropped Rust messages.
- Request errors are msgpack integers. Before, they decoded as negative
  numbers on the other side.
- Fractional stamp costs and values (`StampCost`, `StampValue`) and the
  LXMF 1.3 announce formats. Propagation node announces with float limits
  are accepted.
- `ENCRYPTED_PACKET_MDU` is 383, so the opportunistic content limit is
  287 bytes. Larger opportunistic messages fall back to link delivery.
- Inbound payloads without a stamp are verified over the bytes as received.

### Propagation nodes

- Accept client uploads (resources and packets) and serve `/get`: clients
  can list, download and acknowledge their messages.
- Generate peering keys, sync to peers (one peer per cycle, as upstream),
  rotate low acceptance rate peers and cull unreachable ones.
- Activate static peers on enable, persist node statistics, and auto-peer
  with nodes that sync to us.
- The message store limit comes from `message_storage_limit`. Before, the
  store was culled to the 256 KB per-transfer limit.
- Serve `/pn/get/stats`, `/pn/peer/sync` and `/pn/peer/unpeer` with
  upstream's access rules and statistics.

### Clients

- Download messages from a propagation node
  (`request_messages_from_propagation_node`).
- Medium-aware retries, debounced path requests, slow-path holds, and
  `cancel_outbound`.
- Tickets: issue, learn, stamp with and accept.
- Ratchets on the delivery destination (`enforce_ratchets` supported).
- Paper messages (`ingest_lxm_uri`), backchannel replies over direct links,
  and rejected resources failing the message.
- Delivery callbacks run without the router lock and report stamp validity,
  stamp value, unverified reason and the packed bytes.

### lxmd

- Remote control, status output, exit codes, example config and inbound
  message files as upstream `lxmd`.
- `on_inbound` with arguments, `--service` logging, fractional costs and
  limits, `propagation_stamp_throttle`, and upstream announce scheduling.

### Breaking API changes

- Stamp costs are `StampCost` and stamp values `StampValue` throughout,
  including in `RouterConfig`, `LxmPeer` and the stamp functions.
- `register_delivery_identity` takes the stamp cost as `Option<f64>`.
- `OutboundMessage` has new fields (`tracking`, `include_ticket`); build it
  with `OutboundMessage::new`.
- `RouterConfig::propagation_limit` and `sync_limit` are `f64`.
  `RouterConfig` gains `pn_stamp_throttle` and `message_storage_limit`.
- `LxmDelivery` gains `stamp_valid`, `stamp_value`, `unverified_reason` and
  `lxmf_bytes`.
- `PropagationStore::new` takes the storage limit in bytes as an `Option`.
- `announce_propagation_node` waits `NODE_ANNOUNCE_DELAY`, as upstream;
  `announce_propagation_node_now` announces immediately.
- Removed: `handle_delivery_announce`, `select_peers_for_sync`,
  `peers_to_drop`, `PropagationStore::compile_stats` and
  `announce_control_destination`.

### Testing

- Interop vectors generated by the upstream Python code, and a live
  Python ↔ Rust interop test, which runs in CI.
- `lxmf-core` builds without `std`.
