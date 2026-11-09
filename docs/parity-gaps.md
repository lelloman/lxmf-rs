# Upstream Parity Gaps

Behavioral gaps between lxmf-rs and upstream Python LXMF at the reviewed
baseline in `UPSTREAM.md` (LXMF 1.3.0, `101fd44`), from a full audit of
`LXMessage.py`, `LXMRouter.py`, `LXMPeer.py`, `Handlers.py` and
`Utilities/lxmd.py` on 2026-11-09. Unlike `upstream-lxmf-backlog.md`, which
tracks upstream commits, this tracks behavior that was never ported.

Status: `open`, `done` (with the commit), or `blocked` (with the reason).

## Messages and outbound

| Gap | Status |
| --- | --- |
| Outbound message stamps and propagation stamps generated in the background | done (`ce79538`) |
| `cancel_outbound`, outbound progress, pre-emptive opportunistic path request | done (`ce79538`) |
| Tickets: learn `FIELD_TICKET` from inbound messages, stamp with outbound tickets, issue tickets (`include_ticket`), record deliveries, accept ticket stamps inbound, persist `available_tickets` | done (`51fbb3d`) |
| Hash inbound payloads from the original bytes when no stamp is present (`unpack_from_bytes`) | done (`fd7bac9`) |
| Changing the outbound propagation node tears down the old propagation link | done (`fd7bac9`) |
| Backchannel identification on the direct link after delivery | open |
| Rejected outbound resources fail the message instead of retrying | open |
| Paper messages: `ingest_lxm_uri`, `from_uri` stripping `/` | open |
| Ratchets for propagated encryption and on delivery destinations (`enforce_ratchets`) | open |
| Direct and propagated link packets wait for their proof | blocked: `rns-net` exposes no link packet receipt |

## Inbound delivery

| Gap | Status |
| --- | --- |
| Messages for another destination hash are dropped | done (`fd7bac9`) |
| Stamps are validated whenever a cost is set; validity and value reach the app | done (`51fbb3d`) |
| Unknown source is distinguished from an invalid signature; identities recalled from the transport | open |
| Delivery callback runs without the router lock held | open |
| Delivery announce handling only for `lxmf.delivery` destinations | done (`fd7bac9`) |
| Delivery resource limit checks the uncompressed size | open |

## Propagation node and peers

| Gap | Status |
| --- | --- |
| Message store size limit comes from `message_storage_limit`, not the per-transfer limit | done (`fd7bac9`) |
| `/get` request handler: clients list, download and acknowledge messages | done (`38eb76e`) |
| Client download from a propagation node (`request_messages_from_propagation_node`) | done (`b525e3a`) |
| Control paths `/pn/get/stats`, `/pn/peer/sync`, `/pn/peer/unpeer` with upstream access rules, error codes and `compile_stats` payload | done (`38eb76e`) |
| PN access control (`auth_required`, allowed list) | done (`38eb76e`) |
| Static peers created and resolved when propagation is enabled | done (`f68d899`) |
| `sync_peers` selection, `rotate_peers`, unreachable peer culling | done (`f68d899`) |
| Offer accounting (`offered`), purging oversized and low-value messages when offering | done (`f68d899`) |
| Identify immediately on peer link establishment, then sync | done (`f68d899`) |
| Node stats persisted and loaded | done (`f68d899`) |
| `disable_propagation` keeps peers | done (`f68d899`) |
| Propagation node announced on enable after `NODE_ANNOUNCE_DELAY` | done (`f68d899`) |
| Path responses do not trigger auto-peering | blocked: `rns-net` does not flag path responses |

## lxmd

| Gap | Status |
| --- | --- |
| `prioritise_destinations` applied | done (`fd7bac9`) |
| Inbound messages written as upstream containers to `storage/messages/<hash>` | done (`5c2b906`, `a85eab2`) |
| `on_inbound` commands with arguments | done (`5c2b906`) |
| Remote control: `-r` takes any destination of the node, exit codes, default timeouts, messages | done (`5c2b906`) |
| Status and peers output in upstream format | done (`5c2b906`) |
| Unreadable identity files abort instead of being replaced | done (`5c2b906`) |
| `-s/--service` logs to `<configdir>/logfile` | done (`5c2b906`) |
| Announce scheduling: deferred start, control destination only with a control list | done (`5c2b906`) |
| Logging default level, config dir detection, fractional KB limits | done (`5c2b906`, `a85eab2`) |
