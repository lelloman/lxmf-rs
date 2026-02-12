# LXMF Design Document for Rust Port

> Comprehensive reference for porting LXMF (Lightweight Extensible Message Format) v0.9.4 from Python to Rust.
> Generated from the Python source code in this repository.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Dependencies on Reticulum (RNS)](#2-dependencies-on-reticulum-rns)
3. [LXMessage - Wire Format & Serialization](#3-lxmessage---wire-format--serialization)
4. [Message Fields](#4-message-fields)
5. [Delivery Methods](#5-delivery-methods)
6. [Message State Machine](#6-message-state-machine)
7. [Stamp System (Proof-of-Work)](#7-stamp-system-proof-of-work)
8. [LXMRouter - Core Engine](#8-lxmrouter---core-engine)
9. [Propagation Node](#9-propagation-node)
10. [Peer Synchronization Protocol](#10-peer-synchronization-protocol)
11. [Announce Handlers](#11-announce-handlers)
12. [lxmd Daemon](#12-lxmd-daemon)
13. [Threading & Concurrency Model](#13-threading--concurrency-model)
14. [Key Constants Reference Table](#14-key-constants-reference-table)

---

## 1. Overview

### What LXMF Is

LXMF (Lightweight Extensible Message Format) is a message format and delivery protocol built on top of [Reticulum](https://reticulum.network) (RNS). It provides reliable message delivery over delay-tolerant, low-bandwidth networks.

### Core Purpose

- Reliable message delivery over extremely constrained links (packet radio, LoRa)
- Zero-configuration message routing with end-to-end encryption
- Store-and-forward capability via Propagation Nodes
- Support for analog paper message transport (QR codes, URIs)

### Architecture Summary

The system is composed of these major components:

| Component | Python Module | Responsibility |
|-----------|---------------|----------------|
| **LXMessage** | `LXMessage.py` (~825 lines) | Message format, packing/unpacking, signing, stamp handling |
| **LXMRouter** | `LXMRouter.py` (~2730 lines) | Delivery queue, propagation, peer management, announce handling |
| **LXMPeer** | `LXMPeer.py` (~642 lines) | Peer state machine, synchronization, offer/response protocol |
| **LXStamper** | `LXStamper.py` (~396 lines) | Proof-of-work stamp generation and validation |
| **Handlers** | `Handlers.py` (~92 lines) | Announce handlers for delivery and propagation |
| **LXMF** | `LXMF.py` (~198 lines) | Constants, field definitions, helper functions |
| **lxmd** | `Utilities/lxmd.py` (~1127 lines) | CLI daemon, configuration, remote control |

### Application Name

The RNS application name is `"lxmf"` (constant `APP_NAME`). All destinations are registered under this namespace.

### Destination Aspects

- `lxmf.delivery` - Endpoint for receiving messages directly
- `lxmf.propagation` - Propagation node endpoint for store-and-forward
- `lxmf.propagation.control` - Control interface for propagation node management

---

## 2. Dependencies on Reticulum (RNS)

This section enumerates every RNS primitive that LXMF depends on. This is critical for the Rust port - every API call listed here needs a corresponding Rust implementation or binding.

### 2.1 RNS.Identity

Ed25519 keypairs for signing, verification, encryption, and hashing.

| Method/Property | Usage in LXMF |
|-----------------|---------------|
| `Identity()` | Create new random identity |
| `Identity.from_file(path)` | Load identity from file |
| `identity.to_file(path)` | Save identity to file |
| `identity.hash` | 16-byte truncated hash of public key |
| `identity.get_public_key()` | Get raw public key bytes |
| `identity.sign(data)` | Ed25519 signature (returns 64 bytes) |
| `identity.validate(signature, data)` | Verify Ed25519 signature |
| `Identity.recall(destination_hash)` | Look up identity by destination hash |
| `Identity.recall_app_data(destination_hash)` | Get cached announce app_data |
| `Identity.remember(packet_hash, destination_hash, public_key, app_data)` | Cache identity |
| `Identity.full_hash(data)` | SHA-256 hash (returns 32 bytes) |
| `Identity.truncated_hash(data)` | Truncated hash (returns 16 bytes) |
| `Identity.from_bytes(data)` | Reconstruct identity from bytes |

**Key constants (all in bits):**

| Constant | Value | Bytes |
|----------|-------|-------|
| `Identity.HASHLENGTH` | 256 | 32 |
| `Identity.TRUNCATED_HASHLENGTH` | 128 | 16 |
| `Identity.SIGLENGTH` | 512 | 64 |

### 2.2 RNS.Destination

Named endpoints for routing.

| Method/Property | Usage in LXMF |
|-----------------|---------------|
| `Destination(identity, direction, type, app_name, *aspects)` | Create destination |
| `destination.hash` | 16-byte destination hash |
| `destination.type` | `SINGLE`, `GROUP`, `PLAIN`, or `LINK` |
| `destination.encrypt(data)` | Encrypt data to this destination's public key |
| `destination.decrypt(data)` | Decrypt data with this destination's private key |
| `destination.sign(data)` | Sign data with destination's identity |
| `destination.announce(app_data=...)` | Send announce |
| `destination.set_default_app_data(callable)` | Set dynamic app_data generator |
| `destination.set_packet_callback(callback)` | Register packet handler |
| `destination.set_link_established_callback(callback)` | Register link handler |
| `destination.register_request_handler(path, handler, allow, allowed_list)` | Register request handler |
| `destination.deregister_request_handler(path)` | Remove request handler |
| `destination.enable_ratchets(path)` | Enable forward secrecy ratchets |
| `destination.enforce_ratchets()` | Require ratchets |
| `destination.latest_ratchet_id` | Current ratchet ID |
| `destination.display_name` | Custom attribute set by LXMF |
| `destination.stamp_cost` | Custom attribute set by LXMF |
| `destination.links` | List of active links to this destination |
| `Destination.hash_from_name_and_identity(name, identity)` | Compute destination hash |

**Direction constants:**
- `Destination.IN` - Incoming (we own it)
- `Destination.OUT` - Outgoing (someone else owns it)

**Type constants:**
- `Destination.SINGLE` - Single destination (one identity)
- `Destination.GROUP` - Group destination (symmetric key)
- `Destination.PLAIN` - Plaintext destination
- `Destination.LINK` - Link destination (virtual circuit)

**Access constants:**
- `Destination.ALLOW_ALL`
- `Destination.ALLOW_LIST`

### 2.3 RNS.Link

Encrypted virtual circuits over Reticulum.

| Method/Property | Usage in LXMF |
|-----------------|---------------|
| `Link(destination, established_callback, closed_callback)` | Create outbound link |
| `link.status` | `ACTIVE`, `CLOSED`, etc. |
| `link.link_id` | Link identifier |
| `link.type` | Destination type of link |
| `link.rssi`, `link.snr`, `link.q` | Physical layer stats |
| `link.identify(identity)` | Identify on link |
| `link.request(path, data, response_callback, failed_callback, progress_callback)` | Make request on link |
| `link.teardown()` | Close link |
| `link.set_packet_callback(callback)` | Register packet handler |
| `link.set_resource_strategy(strategy)` | Set resource acceptance strategy |
| `link.set_resource_callback(callback)` | Resource advertised callback |
| `link.set_resource_started_callback(callback)` | Resource started callback |
| `link.set_resource_concluded_callback(callback)` | Resource completed callback |
| `link.set_remote_identified_callback(callback)` | Remote identification callback |
| `link.track_phy_stats(enabled)` | Enable physical stats tracking |
| `link.get_remote_identity()` | Get remote peer's identity |
| `link.no_data_for()` | Seconds since last data exchange |
| `link.get_establishment_rate()` | Link establishment speed |
| `link.initiator` | Whether we initiated the link |
| `link.activated_at` | Timestamp of activation |
| `Link.MDU` | Maximum Data Unit for link packets (431 bytes default) |
| `Link.ACCEPT_APP` | Resource acceptance strategy constant |

### 2.4 RNS.Packet

Single datagrams.

| Method/Property | Usage in LXMF |
|-----------------|---------------|
| `Packet(destination, data)` | Create packet |
| `packet.send()` | Send packet, returns receipt |
| `packet.prove()` | Prove receipt of packet |
| `packet.destination` | Packet destination |
| `packet.destination_type` | Type of destination |
| `packet.ratchet_id` | Ratchet ID used |
| `packet.rssi`, `packet.snr`, `packet.q` | Physical stats |
| `packet.packet_hash` | Packet hash |
| `packet.link` | Link associated with packet |
| `Packet.ENCRYPTED_MDU` | Max data in encrypted packet |
| `Packet.PLAIN_MDU` | Max data in plain packet |

**Receipt methods:**
- `receipt.set_delivery_callback(callback)` - Called on proof received
- `receipt.set_timeout_callback(callback)` - Called on timeout
- `receipt.destination` - The destination (link)
- `receipt.get_status()` - `RequestReceipt.READY` etc.
- `receipt.get_response()` - The response data
- `receipt.get_progress()` - Transfer progress (0.0-1.0)

### 2.5 RNS.Resource

Multi-packet transfers over links.

| Method/Property | Usage in LXMF |
|-----------------|---------------|
| `Resource(data, link, callback, progress_callback)` | Create and start transfer |
| `resource.status` | `COMPLETE`, `REJECTED`, etc. |
| `resource.data.read()` | Read received data |
| `resource.link` | Associated link |
| `resource.cancel()` | Cancel transfer |
| `resource.get_progress()` | Transfer progress (0.0-1.0) |
| `resource.get_data_size()` | Total data size |
| `resource.get_transfer_size()` | Wire transfer size |
| `Resource.COMPLETE` | Status constant |
| `Resource.REJECTED` | Status constant |

### 2.6 RNS.Transport

Path discovery and announce handling.

| Method/Property | Usage in LXMF |
|-----------------|---------------|
| `Transport.has_path(destination_hash)` | Check if path exists |
| `Transport.request_path(destination_hash)` | Request path discovery |
| `Transport.hops_to(destination_hash)` | Get hop count to destination |
| `Transport.register_announce_handler(handler)` | Register announce handler |
| `Transport.PATHFINDER_M` | Constant for unknown hops |

### 2.7 RNS.Reticulum

Core Reticulum instance.

| Method/Property | Usage in LXMF |
|-----------------|---------------|
| `Reticulum(configdir, loglevel, logdest)` | Initialize Reticulum |
| `Reticulum.get_instance()` | Get singleton instance |
| `Reticulum.userdir` | User's home directory |
| `Reticulum.TRUNCATED_HASHLENGTH` | Same as Identity.TRUNCATED_HASHLENGTH |
| `reticulum.get_packet_rssi(hash)` | Get RSSI for packet |
| `reticulum.get_packet_snr(hash)` | Get SNR for packet |
| `reticulum.get_packet_q(hash)` | Get quality for packet |
| `reticulum.drop_path(destination_hash)` | Drop known path |

### 2.8 Serialization

All structured data is serialized using MessagePack:

```python
import RNS.vendor.umsgpack as msgpack
msgpack.packb(data)    # Serialize
msgpack.unpackb(data)  # Deserialize
```

For the Rust port, use the `rmp-serde` or `msgpack-rust` crate. The wire format must be byte-identical to Python's umsgpack output.

### 2.9 Cryptography

| Function | Usage |
|----------|-------|
| `RNS.Cryptography.hkdf(length, derive_from, salt, context)` | HKDF expansion for stamp workblocks |
| `RNS.Identity.full_hash(data)` | SHA-256 hash |

### 2.10 Platform Utilities

| Function | Usage |
|----------|-------|
| `RNS.vendor.platformutils.is_android()` | Platform detection for stamp generation strategy |
| `RNS.vendor.platformutils.is_windows()` | Platform detection |
| `RNS.vendor.platformutils.is_darwin()` | Platform detection |
| `RNS.vendor.platformutils.get_platform()` | Platform name string |

---

## 3. LXMessage - Wire Format & Serialization

### 3.1 Binary Layout

An LXMF message is packed as a contiguous byte sequence:

```
+-------------------+-------------------+---------------------+-------------------+
| destination_hash  |   source_hash     |     signature       | msgpack(payload)  |
|    (16 bytes)     |    (16 bytes)     |     (64 bytes)      |   (variable)      |
+-------------------+-------------------+---------------------+-------------------+
```

**Total fixed overhead: 96 bytes** (destination + source + signature)

### 3.2 Payload Structure

The payload is a msgpack-encoded array:

```
[timestamp, title, content, fields]           -- without stamp
[timestamp, title, content, fields, stamp]    -- with stamp
```

| Index | Type | Description |
|-------|------|-------------|
| 0 | `f64` | UNIX timestamp (seconds since epoch, double precision) |
| 1 | `bytes` | Title (UTF-8 encoded) |
| 2 | `bytes` | Content (UTF-8 encoded) |
| 3 | `map` | Fields dictionary (can be empty `{}`) |
| 4 | `bytes` (optional) | Stamp (32 bytes, present only if stamp was generated) |

### 3.3 LXMF Overhead Calculation

```
DESTINATION_LENGTH = 16  (TRUNCATED_HASHLENGTH / 8 = 128 / 8)
SIGNATURE_LENGTH   = 64  (SIGLENGTH / 8 = 512 / 8)
TIMESTAMP_SIZE     = 8   (f64 in msgpack)
STRUCT_OVERHEAD    = 8   (msgpack array/structure overhead)

LXMF_OVERHEAD = 2 * DESTINATION_LENGTH + SIGNATURE_LENGTH + TIMESTAMP_SIZE + STRUCT_OVERHEAD
              = 2 * 16 + 64 + 8 + 8
              = 112 bytes
```

### 3.4 Message Hash (message_id)

```python
hashed_part  = destination_hash + source_hash + msgpack.packb(payload)
message_hash = SHA256(hashed_part)    # 32 bytes
```

The message hash is NEVER included in the packed message; it is always recomputed from the message contents.

### 3.5 Signature

```python
signed_part = destination_hash + source_hash + msgpack.packb(payload) + message_hash
signature   = Ed25519_sign(source_identity_private_key, signed_part)   # 64 bytes
```

The signature covers the entire hashed part plus the message hash itself.

### 3.6 Signature Validation on Unpack

When unpacking, if a stamp is present (payload has >4 elements):
1. Extract the stamp from index 4
2. Truncate the payload back to 4 elements
3. Re-pack the 4-element payload to get the canonical `packed_payload`
4. Compute `hashed_part = destination_hash + source_hash + packed_payload`
5. Compute `message_hash = SHA256(hashed_part)`
6. Compute `signed_part = hashed_part + message_hash`
7. Validate `signature` against `signed_part` using source identity

### 3.7 Size Limits Per Delivery Method

| Method | Max Content | Calculation |
|--------|-------------|-------------|
| **Opportunistic (SINGLE)** | 295 bytes | `Packet.ENCRYPTED_MDU + TIMESTAMP_SIZE - LXMF_OVERHEAD + DESTINATION_LENGTH` |
| **Opportunistic (PLAIN)** | 368 bytes | `Packet.PLAIN_MDU - LXMF_OVERHEAD + DESTINATION_LENGTH` |
| **Direct/Propagated (packet)** | 319 bytes | `Link.MDU - LXMF_OVERHEAD` (Link MDU = 431) |
| **Direct/Propagated (resource)** | Unlimited | Transferred as RNS.Resource over link |
| **Paper/QR** | 2,953 bytes total | `(QR_MAX_STORAGE - len("lxm://")) * 6 / 8` |

Note: For opportunistic delivery, the destination hash is inferred from the packet's destination field, so `DESTINATION_LENGTH` (16) is added back to the available space.

### 3.8 Propagation Packing

For propagated messages, the packed message is encrypted for the destination:

```python
# Encrypt everything except the destination hash
encrypted_data = destination.encrypt(packed[DESTINATION_LENGTH:])

# Propagation data = destination_hash + encrypted_data
lxmf_data = packed[:DESTINATION_LENGTH] + encrypted_data

# Transient ID = full hash of the propagation data (before appending propagation stamp)
transient_id = SHA256(lxmf_data)

# If propagation stamp exists, append it
if propagation_stamp:
    lxmf_data += propagation_stamp

# Final propagation pack: msgpack([timestamp, [lxmf_data]])
propagation_packed = msgpack.packb([time.time(), [lxmf_data]])
```

The `ratchet_id` is captured from `destination.latest_ratchet_id` after encryption.

### 3.9 Paper Format

Paper messages use `lxm://` URI scheme with base64url encoding:

```python
paper_packed = packed[:DESTINATION_LENGTH] + destination.encrypt(packed[DESTINATION_LENGTH:])
uri = "lxm://" + base64url_encode(paper_packed).rstrip("=")
```

Decoding:
```python
lxmf_data = base64url_decode(uri.replace("lxm://", "") + "==")
```

### 3.10 File Container Format

When written to disk, messages are wrapped in a msgpack dict:

```python
container = {
    "state": int,
    "lxmf_bytes": bytes,
    "transport_encrypted": bool,
    "transport_encryption": str,
    "method": int
}
file_contents = msgpack.packb(container)
```

Filename is the hex-encoded message hash (no delimiter).

---

## 4. Message Fields

### 4.1 Core Field IDs

| ID | Constant | Type | Purpose |
|----|----------|------|---------|
| `0x01` | `FIELD_EMBEDDED_LXMS` | list | Embedded LXM messages |
| `0x02` | `FIELD_TELEMETRY` | bytes | Telemetry data |
| `0x03` | `FIELD_TELEMETRY_STREAM` | bytes | Telemetry stream data |
| `0x04` | `FIELD_ICON_APPEARANCE` | bytes | Icon/appearance data |
| `0x05` | `FIELD_FILE_ATTACHMENTS` | list | File attachments |
| `0x06` | `FIELD_IMAGE` | bytes | Image data |
| `0x07` | `FIELD_AUDIO` | bytes | Audio data |
| `0x08` | `FIELD_THREAD` | bytes | Thread reference |
| `0x09` | `FIELD_COMMANDS` | dict | Command structure |
| `0x0A` | `FIELD_RESULTS` | dict | Command results |
| `0x0B` | `FIELD_GROUP` | bytes | Group information |
| `0x0C` | `FIELD_TICKET` | list | Stamp bypass ticket `[expires: f64, ticket: bytes[16]]` |
| `0x0D` | `FIELD_EVENT` | dict | Event data |
| `0x0E` | `FIELD_RNR_REFS` | list | RNR references |
| `0x0F` | `FIELD_RENDERER` | int | Renderer hint |

### 4.2 Custom Fields

| ID | Constant | Purpose |
|----|----------|---------|
| `0xFB` | `FIELD_CUSTOM_TYPE` | Format/type/protocol identifier |
| `0xFC` | `FIELD_CUSTOM_DATA` | Embedded custom payload |
| `0xFD` | `FIELD_CUSTOM_META` | Custom metadata |
| `0xFE` | `FIELD_NON_SPECIFIC` | Non-specific (development/testing) |
| `0xFF` | `FIELD_DEBUG` | Debug field |

### 4.3 Audio Codec Modes

For use in `FIELD_AUDIO`:

| ID | Constant | Codec |
|----|----------|-------|
| `0x01` | `AM_CODEC2_450PWB` | Codec2 450 PWB |
| `0x02` | `AM_CODEC2_450` | Codec2 450 |
| `0x03` | `AM_CODEC2_700C` | Codec2 700C |
| `0x04` | `AM_CODEC2_1200` | Codec2 1200 |
| `0x05` | `AM_CODEC2_1300` | Codec2 1300 |
| `0x06` | `AM_CODEC2_1400` | Codec2 1400 |
| `0x07` | `AM_CODEC2_1600` | Codec2 1600 |
| `0x08` | `AM_CODEC2_2400` | Codec2 2400 |
| `0x09` | `AM_CODEC2_3200` | Codec2 3200 |
| `0x10` | `AM_OPUS_OGG` | Opus OGG |
| `0x11` | `AM_OPUS_LBW` | Opus Low Bandwidth |
| `0x12` | `AM_OPUS_MBW` | Opus Medium Bandwidth |
| `0x13` | `AM_OPUS_PTT` | Opus Push-to-Talk |
| `0x14` | `AM_OPUS_RT_HDX` | Opus Real-Time Half Duplex |
| `0x15` | `AM_OPUS_RT_FDX` | Opus Real-Time Full Duplex |
| `0x16` | `AM_OPUS_STANDARD` | Opus Standard |
| `0x17` | `AM_OPUS_HQ` | Opus High Quality |
| `0x18` | `AM_OPUS_BROADCAST` | Opus Broadcast |
| `0x19` | `AM_OPUS_LOSSLESS` | Opus Lossless |
| `0xFF` | `AM_CUSTOM` | Custom/unspecified |

### 4.4 Renderer Hints

For use in `FIELD_RENDERER`:

| ID | Constant | Description |
|----|----------|-------------|
| `0x00` | `RENDERER_PLAIN` | Plain text |
| `0x01` | `RENDERER_MICRON` | Micron markup |
| `0x02` | `RENDERER_MARKDOWN` | Markdown |
| `0x03` | `RENDERER_BBCODE` | BBCode |

### 4.5 Ticket Field Structure

The `FIELD_TICKET` contains: `[expires: float, ticket: bytes]`

- `expires`: UNIX timestamp when the ticket expires
- `ticket`: 16 bytes (`TICKET_LENGTH = TRUNCATED_HASHLENGTH / 8`)
- Tickets allow the recipient to reply without generating a proof-of-work stamp
- Default expiry: 21 days, with 5-day grace period
- Auto-renewal when <14 days remain
- Minimum interval between ticket deliveries: 1 day

---

## 5. Delivery Methods

### 5.1 OPPORTUNISTIC (0x01)

**When to use:** Short messages to known destinations that can be reached without an established link.

**Size constraint:** Content must fit in a single RNS packet.
- SINGLE destination: max 295 bytes content
- PLAIN destination: max 368 bytes content
- If content exceeds limit, automatically falls back to DIRECT

**Transport encryption:**
- SINGLE: Curve25519 ECDH (per-packet ephemeral keys)
- GROUP: AES-128 (symmetric group key)
- PLAIN: Unencrypted

**Packet format:** The destination hash is NOT included in the packet data (inferred from packet destination). The packet carries: `source_hash + signature + msgpack(payload)`.

**Delivery confirmation:** Via packet delivery receipt (proof). State transitions: OUTBOUND -> SENDING -> SENT -> DELIVERED.

**On send:**
```python
packet = RNS.Packet(destination, packed[DESTINATION_LENGTH:])
packet.send().set_delivery_callback(mark_delivered)
```

### 5.2 DIRECT (0x02)

**When to use:** Messages sent directly to the recipient over an RNS Link (encrypted virtual circuit).

**Size constraint:**
- If content <= 319 bytes: sent as link packet (representation = PACKET)
- If content > 319 bytes: sent as RNS Resource (representation = RESOURCE)

**Transport encryption:** Always Curve25519 ECDH (link encryption provides forward secrecy).

**Packet format:** Full packed message: `destination_hash + source_hash + signature + msgpack(payload)`.

**Delivery confirmation:**
- PACKET: Via packet receipt delivery callback
- RESOURCE: Via resource concluded callback with COMPLETE status

**Link management:** Router maintains `direct_links` dict mapping `destination_hash -> RNS.Link`. Links are established on demand, reused for subsequent messages, and cleaned up after `LINK_MAX_INACTIVITY` (10 minutes).

### 5.3 PROPAGATED (0x03)

**When to use:** Messages delivered via propagation nodes (store-and-forward) for offline recipients.

**Size constraint:**
- Propagation-packed data size determines representation
- If propagation_packed <= 431 bytes: PACKET
- If propagation_packed > 431 bytes: RESOURCE

**Transport encryption:** Message content is encrypted to the destination's public key before being handed to the propagation node. The propagation node cannot read message content.

**Propagation packing process:**
1. Pack message normally
2. Encrypt `packed[16:]` (everything except destination hash) with destination's public key
3. Prepend destination hash: `destination_hash + encrypted_data`
4. Compute `transient_id = SHA256(destination_hash + encrypted_data)`
5. If propagation stamp exists, append it
6. Wrap in msgpack: `[timestamp, [lxmf_data]]`

**Delivery confirmation:** Propagation success (receipt from propagation node) transitions to SENT (not DELIVERED). The message is considered delivered only when the recipient downloads it from the propagation node.

### 5.4 PAPER (0x05)

**When to use:** Offline message transport via QR codes or URI links.

**Size constraint:** Total paper_packed size must fit in `PAPER_MDU` bytes.

```
QR_MAX_STORAGE = 2953 (QR code capacity at ERROR_CORRECT_L)
PAPER_MDU = (QR_MAX_STORAGE - len("lxm://")) * 6 / 8 = 2210 bytes (approx)
```

**Transport encryption:** Same as opportunistic (encrypted to destination's public key).

**Paper packing:** Same as propagation packing but without the timestamp wrapper:
```
paper_packed = destination_hash + destination.encrypt(packed[DESTINATION_LENGTH:])
```

**URI format:** `lxm://` + base64url(paper_packed) with padding stripped.

**No delivery confirmation.** State transitions: GENERATING -> PAPER (via `__mark_paper_generated`).

---

## 6. Message State Machine

### 6.1 States

| Value | Name | Description |
|-------|------|-------------|
| `0x00` | `GENERATING` | Initial state, message being constructed |
| `0x01` | `OUTBOUND` | Queued for delivery |
| `0x02` | `SENDING` | Actively being transferred |
| `0x04` | `SENT` | Transfer complete (propagated: confirmed received by PN) |
| `0x08` | `DELIVERED` | Delivery confirmed by recipient |
| `0xFD` | `REJECTED` | Rejected by receiver |
| `0xFE` | `CANCELLED` | Cancelled by sender |
| `0xFF` | `FAILED` | Delivery failed after max attempts |

### 6.2 Representation Types

| Value | Name | Description |
|-------|------|-------------|
| `0x00` | `UNKNOWN` | Not yet determined |
| `0x01` | `PACKET` | Single packet representation |
| `0x02` | `RESOURCE` | Multi-packet resource representation |

### 6.3 State Transitions Per Method

**Opportunistic:**
```
GENERATING -> OUTBOUND -> SENT -> DELIVERED
                      \-> FAILED (max attempts)
```

**Direct (packet):**
```
GENERATING -> OUTBOUND -> SENDING -> DELIVERED
                      \-> OUTBOUND (timeout, retry)
                      \-> FAILED (max attempts)
```

**Direct (resource):**
```
GENERATING -> OUTBOUND -> SENDING -> DELIVERED
                      \-> OUTBOUND (transfer failed, retry)
                      \-> REJECTED (resource rejected)
                      \-> FAILED (max attempts)
```

**Propagated:**
```
GENERATING -> OUTBOUND -> SENDING -> SENT (propagation confirmed)
                      \-> OUTBOUND (link closed, retry)
                      \-> REJECTED (invalid stamp)
                      \-> FAILED (max attempts)
```

**Paper:**
```
GENERATING -> PAPER
```

### 6.4 Callback Triggers

| Callback | When Triggered |
|----------|----------------|
| `delivery_callback(message)` | Message state becomes DELIVERED (direct) or SENT (propagated) |
| `failed_callback(message)` | Message state becomes FAILED, CANCELLED, or REJECTED |
| `progress_callback` | During resource transfer (progress 0.10 to 1.0) |

### 6.5 Retry Logic

- `MAX_DELIVERY_ATTEMPTS = 5`
- `DELIVERY_RETRY_WAIT = 10` seconds between attempts
- `PATH_REQUEST_WAIT = 7` seconds to wait for path resolution
- `MAX_PATHLESS_TRIES = 1` - attempts without known path before requesting

For opportunistic messages, after `MAX_PATHLESS_TRIES + 1` attempts, the path is dropped and re-requested (rediscovery).

---

## 7. Stamp System (Proof-of-Work)

### 7.1 Overview

Stamps are proof-of-work tokens that prevent message spam. A sender must find a nonce that, combined with a computationally expensive workblock, produces a hash with a required number of leading zero bits.

There are three types of stamps:
1. **Message stamps** - Prove work for direct delivery (workblock expand rounds: 3000)
2. **Propagation stamps** - Prove work for propagation node delivery (workblock expand rounds: 1000)
3. **Peering keys** - Prove work for peer synchronization (workblock expand rounds: 25)

### 7.2 Workblock Generation

```python
def stamp_workblock(material, expand_rounds=3000):
    workblock = b""
    for n in range(expand_rounds):
        workblock += HKDF(
            length=256,
            derive_from=material,
            salt=SHA256(material + msgpack.packb(n)),
            context=None
        )
    return workblock
```

**Workblock sizes:**
- Normal stamp: 3000 rounds x 256 bytes = 750,000 bytes (~732 KB)
- PN stamp: 1000 rounds x 256 bytes = 250,000 bytes (~244 KB)
- Peering key: 25 rounds x 256 bytes = 6,400 bytes (~6.25 KB)

**Constants:**
```
WORKBLOCK_EXPAND_ROUNDS          = 3000  # For message stamps
WORKBLOCK_EXPAND_ROUNDS_PN       = 1000  # For propagation node stamps
WORKBLOCK_EXPAND_ROUNDS_PEERING  = 25    # For peering keys
STAMP_SIZE                       = 32    # HASHLENGTH / 8 = 256 / 8
```

### 7.3 Stamp Generation

```python
def generate_stamp(message_id, stamp_cost, expand_rounds):
    workblock = stamp_workblock(message_id, expand_rounds)
    # Find a 32-byte nonce where:
    #   SHA256(workblock + nonce) has >= stamp_cost leading zero bits
    target = 1 << (256 - stamp_cost)
    while True:
        nonce = os.urandom(32)
        result = SHA256(workblock + nonce)
        if int.from_bytes(result, "big") <= target:
            return nonce
```

The stamp is the 32-byte nonce.

### 7.4 Stamp Validation

```python
def stamp_valid(stamp, target_cost, workblock):
    target = 1 << (256 - target_cost)
    result = SHA256(workblock + stamp)
    return int.from_bytes(result, "big") <= target
```

### 7.5 Stamp Value Calculation

```python
def stamp_value(workblock, stamp):
    value = 0
    material = SHA256(workblock + stamp)
    i = int.from_bytes(material, "big")
    while (i & (1 << 255)) == 0:
        i <<= 1
        value += 1
    return value
```

The value is the number of leading zero bits in the hash.

### 7.6 Ticket-Based Stamp Bypass

Tickets allow bypassing stamp generation for replies:

```python
# Generating a stamp from an outbound ticket:
stamp = truncated_hash(ticket + message_id)  # 16 bytes
stamp_value = COST_TICKET  # 0x100 = 256

# Validating a ticket stamp:
for ticket in available_tickets:
    if stamp == truncated_hash(ticket + message_id):
        return True  # Valid ticket stamp
```

**Ticket constants:**
- `TICKET_LENGTH = 16` bytes
- `TICKET_EXPIRY = 21 * 24 * 60 * 60` (21 days)
- `TICKET_GRACE = 5 * 24 * 60 * 60` (5 days grace after expiry)
- `TICKET_RENEW = 14 * 24 * 60 * 60` (renew if <14 days remaining)
- `TICKET_INTERVAL = 1 * 24 * 60 * 60` (min 1 day between ticket deliveries)
- `COST_TICKET = 0x100` (sentinel value for ticket-based stamps)

### 7.7 Propagation Node Stamp Validation

For messages arriving at a propagation node:

```python
def validate_pn_stamp(transient_data, target_cost):
    if len(transient_data) <= LXMF_OVERHEAD + STAMP_SIZE:
        return None  # Too short to contain a stamp

    lxm_data     = transient_data[:-STAMP_SIZE]       # Everything before stamp
    stamp        = transient_data[-STAMP_SIZE:]        # Last 32 bytes
    transient_id = SHA256(lxm_data)
    workblock    = stamp_workblock(transient_id, expand_rounds=1000)

    if stamp_valid(stamp, target_cost, workblock):
        value = stamp_value(workblock, stamp)
        return transient_id, lxm_data, value, stamp
    else:
        return None
```

### 7.8 Peering Key Validation

```python
def validate_peering_key(peering_id, peering_key, target_cost):
    workblock = stamp_workblock(peering_id, expand_rounds=25)
    return stamp_valid(peering_key, target_cost, workblock)
```

Where `peering_id = peer_identity.hash + local_identity.hash`.

### 7.9 Multi-Process Stamp Generation

On Linux, stamp generation uses multiple processes via `fork`:
- Number of workers: `min(cpu_count, 12)` or `cpu_count / 2` if >12 cores
- Workers share a `multiprocessing.Event` stop signal and `Queue` for results
- First worker to find a valid stamp signals all others to stop

On Android: Dispatches batches of 1000 rounds per worker using `multiprocessing.Manager`.

On Windows/macOS: Single-process fallback using `os.urandom` in a loop.

### 7.10 Stamp Validation Pool

For validating multiple PN stamps in parallel:
- If <= 256 stamps OR on Android: sequential validation
- Otherwise: spawn `min(cpu_count, ceil(count/256))` processes via `spawn` context
- Uses `multiprocessing.Pool.starmap`

---

## 8. LXMRouter - Core Engine

### 8.1 Responsibilities

- Manage delivery queue (outbound messages)
- Handle inbound message delivery (packet, link, resource)
- Propagation node functionality (store-and-forward)
- Peer management and synchronization
- Stamp cost tracking and enforcement
- Ticket management
- Announce handling
- Link lifecycle management
- Deferred stamp generation

### 8.2 Initialization

```python
LXMRouter(
    identity=None,              # RNS.Identity (auto-generated if None)
    storagepath=None,           # Required: base path for storage
    autopeer=True,              # Auto-peer with discovered PN nodes
    autopeer_maxdepth=4,        # Max hops for auto-peering (lxmd default: 6)
    propagation_limit=256,      # Per-transfer limit in KB
    delivery_limit=1000,        # Delivery transfer limit in KB
    sync_limit=10240,           # Sync limit in KB (propagation_limit * 40)
    enforce_ratchets=False,     # Require ratchets
    enforce_stamps=False,       # Reject messages with invalid stamps
    static_peers=[],            # List of static peer destination hashes
    max_peers=20,               # Maximum number of auto-discovered peers
    from_static_only=False,     # Only accept from static peers
    sync_strategy=PERSISTENT,   # Default peer sync strategy
    propagation_cost=16,        # Required stamp cost for propagation
    propagation_cost_flexibility=3, # Accept stamps with cost >= target - flex
    peering_cost=18,            # Required peering key cost
    max_peering_cost=26,        # Max remote peering cost we'll accept
    name=None                   # Optional node name
)
```

### 8.3 Destination Registration

On init, the router creates:
```python
self.propagation_destination = RNS.Destination(identity, IN, SINGLE, "lxmf", "propagation")
```

When `register_delivery_identity()` is called:
```python
delivery_destination = RNS.Destination(identity, IN, SINGLE, "lxmf", "delivery")
delivery_destination.enable_ratchets(ratchet_file_path)
delivery_destination.set_packet_callback(self.delivery_packet)
delivery_destination.set_link_established_callback(self.delivery_link_established)
```

When `enable_propagation()` is called, additionally:
```python
propagation_destination.set_link_established_callback(self.propagation_link_established)
propagation_destination.set_packet_callback(self.propagation_packet)
propagation_destination.register_request_handler("/offer", self.offer_request, ALLOW_ALL)
propagation_destination.register_request_handler("/get", self.message_get_request, ALLOW_ALL)

control_destination = RNS.Destination(identity, IN, SINGLE, "lxmf", "propagation", "control")
control_destination.register_request_handler("/pn/get/stats", ...)
control_destination.register_request_handler("/pn/peer/sync", ...)
control_destination.register_request_handler("/pn/peer/unpeer", ...)
```

### 8.4 Announce App Data

**Delivery destination announce data** (version 0.5.0+):
```python
peer_data = [display_name_bytes_or_none, stamp_cost_int_or_none]
app_data = msgpack.packb(peer_data)
```

Detection: First byte is in range `0x90-0x9F` or is `0xDC` (msgpack array header).

**Propagation node announce data:**
```python
announce_data = [
    False,                          # 0: Legacy flag (always False)
    int(time.time()),               # 1: Current node timebase
    node_state_bool,                # 2: Propagation node enabled
    propagation_per_transfer_limit, # 3: Per-transfer limit in KB
    propagation_per_sync_limit,     # 4: Sync limit in KB
    [stamp_cost, flexibility, peering_cost], # 5: Stamp cost config
    metadata_dict                   # 6: Node metadata
]
app_data = msgpack.packb(announce_data)
```

### 8.5 Outbound Processing Loop

The router runs a job loop on a daemon thread with `PROCESSING_INTERVAL = 4` seconds.

**Job schedule** (based on `processing_count`):

| Job | Interval (cycles) | Effective Interval |
|-----|-------------------|-------------------|
| `process_outbound()` | 1 | 4s |
| `process_deferred_stamps()` | 1 | 4s (in background thread) |
| `clean_links()` | 1 | 4s |
| `clean_transient_id_caches()` | 60 | 240s (4 min) |
| `clean_message_store()` | 120 | 480s (8 min) |
| `flush_queues()` / `flush_peer_distribution_queue()` | 6 | 24s |
| `rotate_peers()` | 336 | 1344s (~22 min) |
| `sync_peers()` | 6 | 24s |
| `clean_throttled_peers()` | 6 | 24s |

### 8.6 Inbound Processing

**Packet delivery** (`delivery_packet`):
1. Prove receipt of packet (`packet.prove()`)
2. For non-link packets: prepend destination hash (opportunistic)
3. For link packets: use data as-is (direct)
4. Call `lxmf_delivery()`

**Link delivery** (`delivery_link_established`):
1. Enable physical stats tracking
2. Set packet callback, resource strategy (`ACCEPT_APP`), resource callbacks
3. Set remote identified callback (for backchannel)

**Resource delivery** (`delivery_resource_concluded`):
1. On COMPLETE: read data, extract ratchet_id from link, call `lxmf_delivery()`

**`lxmf_delivery()` core logic:**
1. Unpack message from bytes
2. If signature is valid and ticket is present: remember ticket
3. Validate stamp against delivery destination's stamp cost
4. If stamp invalid and enforcement is on: drop message
5. Set transport encryption info based on destination type
6. Check source against ignored list
7. Check for duplicates via `locally_delivered_transient_ids`
8. Call external delivery callback

### 8.7 Link Management

```python
direct_links = {}           # destination_hash -> RNS.Link
backchannel_links = {}      # destination_hash -> RNS.Link (reverse channel)
active_propagation_links = [] # Inbound propagation links

LINK_MAX_INACTIVITY   = 600  # 10 minutes
P_LINK_MAX_INACTIVITY = 180  # 3 minutes (propagation links)
```

`clean_links()` runs every cycle:
- Tears down direct links inactive for >10 minutes
- Tears down propagation links inactive for >3 minutes
- Handles outbound propagation link cleanup and state transitions

### 8.8 Backchannel Identification

When a direct link delivers a message and the link was initiated by us, the router identifies itself on the link to enable the remote side to use the same link for replies:

```python
direct_link.identify(backchannel_identity)
delivery_link_established(direct_link)  # Set up packet/resource callbacks
```

### 8.9 Storage Paths

All paths are relative to `storagepath + "/lxmf"`:

| Path | Content |
|------|---------|
| `lxmf/messagestore/` | Propagation node message files |
| `lxmf/ratchets/` | Ratchet key storage |
| `lxmf/peers` | Serialized peer states (msgpack) |
| `lxmf/local_deliveries` | Locally delivered transient ID cache (msgpack dict) |
| `lxmf/locally_processed` | Locally processed transient ID cache (msgpack dict) |
| `lxmf/outbound_stamp_costs` | Known stamp costs per destination (msgpack dict) |
| `lxmf/available_tickets` | Ticket storage (msgpack dict with "outbound", "inbound", "last_deliveries") |
| `lxmf/node_stats` | Propagation node statistics (msgpack dict) |

### 8.10 Outbound Stamp Cost Tracking

When a delivery announce is received, the stamp cost is extracted and stored:

```python
outbound_stamp_costs[destination_hash] = [timestamp, stamp_cost]
```

- Costs expire after `STAMP_COST_EXPIRY = 45 days`
- When sending a message, if no stamp cost is set, the cached cost is applied automatically

### 8.11 Authentication & Access Control

```python
auth_required = False       # Require authentication for message download
allowed_list = []           # Identity hashes allowed to download
ignored_list = []           # Source hashes whose messages are dropped
prioritised_list = []       # Destination hashes with priority storage
control_allowed_list = []   # Identity hashes allowed to control the node
```

### 8.12 Message Download from Propagation Node

Client-side flow:
1. `request_messages_from_propagation_node(identity, max_messages)`
2. Establish link to propagation node if not active
3. Identify on link
4. Request message list: `link.request("/get", [None, None])`
5. Receive list of available transient IDs
6. Determine wants (not already locally delivered) and haves
7. Request messages: `link.request("/get", [wants, haves, delivery_limit])`
8. Receive messages as response
9. Process each message via `lxmf_propagation()`
10. Report haves back to node (allows node to delete delivered messages)

---

## 9. Propagation Node

### 9.1 Purpose

Store-and-forward messages for offline recipients. Nodes automatically peer with each other and synchronize messages, forming an encrypted, distributed message store.

### 9.2 Message Entry Structure

Each propagation entry in `self.propagation_entries` is indexed by `transient_id`:

```python
propagation_entries[transient_id] = [
    destination_hash,   # 0: 16-byte destination hash
    filepath,           # 1: Path to message file on disk
    received_timestamp, # 2: When message was received (float)
    msg_size,           # 3: File size in bytes
    handled_peers,      # 4: List of peer destination_hashes that have this message
    unhandled_peers,    # 5: List of peer destination_hashes that need this message
    stamp_value,        # 6: Proof-of-work stamp value (int)
]
```

### 9.3 Message Store File Naming

Files are stored in `messagestore/` with names:
```
{transient_id_hex}_{received_timestamp}_{stamp_value}
```

Example: `a1b2c3d4..._{1234567890.123}_{16}`

The file content is: `lxmf_data + stamp_data` (stamp appended to the encrypted message data).

### 9.4 Propagation Node Announce Data

```python
announce_data = [
    False,                              # 0: Legacy flag
    int(time.time()),                   # 1: Timebase
    propagation_node and not from_static_only, # 2: Node state
    propagation_per_transfer_limit,     # 3: Transfer limit (KB)
    propagation_per_sync_limit,         # 4: Sync limit (KB)
    [stamp_cost, flexibility, peering_cost], # 5: Costs
    metadata                            # 6: Metadata dict
]
```

### 9.5 Metadata Fields

| ID | Constant | Type | Description |
|----|----------|------|-------------|
| `0x00` | `PN_META_VERSION` | bytes | Software version |
| `0x01` | `PN_META_NAME` | bytes | Node name (UTF-8) |
| `0x02` | `PN_META_SYNC_STRATUM` | int | Sync stratum level |
| `0x03` | `PN_META_SYNC_THROTTLE` | int | Sync throttle setting |
| `0x04` | `PN_META_AUTH_BAND` | bytes | Auth band info |
| `0x05` | `PN_META_UTIL_PRESSURE` | float | Utilization pressure |
| `0xFF` | `PN_META_CUSTOM` | any | Custom metadata |

### 9.6 Storage Limits & Culling

- `message_storage_limit`: Configurable (default: 500 MB via lxmd config)
- **Expiry**: Messages older than `MESSAGE_EXPIRY = 30 days` are removed
- **Weight-based culling**: When storage limit is exceeded, messages are removed by weight (highest weight first)

**Weight calculation:**
```python
def get_weight(transient_id):
    age_weight = max(1, (now - received) / (4 * 24 * 60 * 60))  # 4-day units
    priority_weight = 0.1 if destination in prioritised_list else 1.0
    return priority_weight * age_weight * message_size
```

Older and larger messages have higher weight and are removed first. Prioritised destinations get 10x weight reduction.

### 9.7 Propagation Node Statistics

Tracked and persisted in `node_stats`:
```python
{
    "client_propagation_messages_received": int,
    "client_propagation_messages_served": int,
    "unpeered_propagation_incoming": int,
    "unpeered_propagation_rx_bytes": int,
}
```

---

## 10. Peer Synchronization Protocol

### 10.1 Peer States

| Value | Name | Description |
|-------|------|-------------|
| `0x00` | `IDLE` | No sync in progress |
| `0x01` | `LINK_ESTABLISHING` | RNS Link being established |
| `0x02` | `LINK_READY` | Link established, ready to sync |
| `0x03` | `REQUEST_SENT` | Offer request sent, waiting for response |
| `0x04` | `RESPONSE_RECEIVED` | Response received, processing |
| `0x05` | `RESOURCE_TRANSFERRING` | Transferring messages |
| `0xF0` | `ERROR_NO_IDENTITY` | Remote didn't send identity |
| `0xF1` | `ERROR_NO_ACCESS` | Access denied |
| `0xF3` | `ERROR_INVALID_KEY` | Invalid peering key |
| `0xF4` | `ERROR_INVALID_DATA` | Invalid data format |
| `0xF5` | `ERROR_INVALID_STAMP` | Invalid stamp |
| `0xF6` | `ERROR_THROTTLED` | Peer is throttled |
| `0xFD` | `ERROR_NOT_FOUND` | Peer not found |
| `0xFE` | `ERROR_TIMEOUT` | Operation timed out |

### 10.2 Sync Strategies

| Value | Name | Description |
|-------|------|-------------|
| `0x01` | `STRATEGY_LAZY` | Sync once per cycle |
| `0x02` | `STRATEGY_PERSISTENT` | Keep syncing until all unhandled messages are sent |

### 10.3 Sync Flow (Outbound - Our Node to Peer)

**Pre-sync checks:**
1. Sync time reached (backoff expired)?
2. Stamp costs known for peer?
3. Peering key generated and valid?

If any check fails, sync is postponed. If peering key is missing, generation is started in a background thread.

**Sync procedure:**

1. **Path resolution**: If no path exists, request it and wait `PATH_REQUEST_GRACE = 7.5s`
2. **Identity resolution**: Recall peer identity, create destination
3. **Link establishment**: `RNS.Link(peer_destination, established_callback, closed_callback)`
4. **On link established**: Identify with local identity, set state to `LINK_READY`, call `sync()` again
5. **Prepare offer**:
   - Collect unhandled messages (that still exist in propagation_entries)
   - Filter out messages with stamp value below peer's minimum accepted cost
   - Sort by weight (ascending - smallest/newest first)
   - Apply per-message transfer limit and sync limit
   - Build offer: `[peering_key_nonce, [transient_id_1, transient_id_2, ...]]`
6. **Send offer**: `link.request("/offer", offer, response_callback, failed_callback)`
7. **Handle response**:
   - `ERROR_NO_IDENTITY`: Re-identify and retry
   - `ERROR_NO_ACCESS`: Break peering
   - `ERROR_THROTTLED`: Postpone sync
   - `False`: Peer has all offered messages (mark all as handled)
   - `True`: Peer wants all offered messages
   - `[list]`: Peer wants specific messages
8. **Transfer**: Read requested message files, pack as `msgpack([timestamp, [lxm_data_1, lxm_data_2, ...]])`, send as `RNS.Resource`
9. **Resource concluded**:
   - On COMPLETE: Mark all transferred messages as handled, record transfer rate, if PERSISTENT strategy and more unhandled messages exist, sync again
   - On failure: Return to IDLE, clear transfer state

### 10.4 Sync Flow (Inbound - Peer to Our Node)

**Offer request handler** (`offer_request`):

1. Check remote identity (reject if None)
2. Check throttle list
3. Check `from_static_only` access
4. Extract peering key and transient IDs from offer data
5. Validate peering key: `validate_peering_key(our_hash + their_hash, key, peering_cost)`
6. Compare offered transient IDs against our propagation_entries
7. Return:
   - `False` if we have all offered messages
   - `True` if we want all
   - `[wanted_ids]` if we want some

**Resource reception** (`propagation_resource_concluded`):

1. Unpack msgpack data: `[timebase, [message_1, message_2, ...]]`
2. Verify peering key was validated for this link
3. If not validated and >1 message: reject (clients can only send 1 at a time)
4. Validate stamps on all messages using `validate_pn_stamps()`
5. For each valid message: call `lxmf_propagation()`, update peer stats
6. If any invalid stamps: teardown link, throttle peer for `PN_STAMP_THROTTLE = 180s`

### 10.5 Peer Persistence

Peers are serialized via msgpack dictionary:

```python
{
    "destination_hash": bytes,
    "peering_timebase": float,
    "alive": bool,
    "last_heard": float,
    "link_establishment_rate": float,
    "sync_transfer_rate": float,
    "propagation_transfer_limit": float_or_none,
    "propagation_sync_limit": int_or_none,
    "propagation_stamp_cost": int_or_none,
    "propagation_stamp_cost_flexibility": int_or_none,
    "peering_cost": int_or_none,
    "sync_strategy": int,
    "peering_key": [bytes, int]_or_none,  # [nonce, value]
    "metadata": dict_or_none,
    "last_sync_attempt": float,
    "offered": int,
    "outgoing": int,
    "incoming": int,
    "rx_bytes": int,
    "tx_bytes": int,
    "handled_ids": [bytes, ...],
    "unhandled_ids": [bytes, ...],
}
```

Serialized as a list of peer dictionaries, stored at `{storagepath}/lxmf/peers`.

### 10.6 Autopeer

When a propagation announce is received:
- If the source is a static peer: always update peering config (not on path responses unless never heard)
- If autopeer is enabled and not a path response:
  - If propagation is enabled and `hops_to(source) <= autopeer_maxdepth`: peer
  - If source moved outside range: unpeer
  - If propagation disabled: unpeer

Also triggered during incoming resource reception: if the sender's announce data indicates a propagation node within autopeer range, auto-peer with it.

### 10.7 Peer Rotation

Runs every `JOB_ROTATE_INTERVAL = 336` cycles (~22 minutes).

**Purpose:** Maintain headroom in the peer list by removing low-performing peers.

**Process:**
1. Calculate `rotation_headroom = max(1, floor(max_peers * 10%))`
2. Calculate `required_drops = len(peers) - (max_peers - rotation_headroom)`
3. Skip if many untested peers (newly added, never synced)
4. Prefer rotating from fully-synced peers
5. Build drop pool: unresponsive peers first, then alive peers
6. Sort by acceptance rate (ascending): `outgoing / offered`
7. Drop peers with acceptance rate < `ROTATION_AR_MAX = 50%`

### 10.8 Sync Backoff

- `SYNC_BACKOFF_STEP = 12 * 60` (12 minutes)
- Each failed sync attempt adds one step to the backoff
- On successful link establishment: backoff resets to 0
- `MAX_UNREACHABLE = 14 * 24 * 60 * 60` (14 days) - peers unreachable for this long are removed

### 10.9 Peer Selection for Sync

Every `JOB_PEERSYNC_INTERVAL = 6` cycles:
1. Collect alive peers with unhandled messages (`waiting_peers`)
2. Collect unresponsive peers past their backoff (`unresponsive_peers`)
3. If waiting peers exist:
   - Take `FASTEST_N_RANDOM_POOL = 2` fastest by `sync_transfer_rate`
   - Add unknown-speed peers (up to same count)
   - Randomly select one from this pool
4. If only unresponsive peers: randomly select one
5. Call `selected_peer.sync()`

### 10.10 Message Distribution Queue

When a new message is ingested by the propagation node:
1. `enqueue_peer_distribution(transient_id, from_peer)` adds to `peer_distribution_queue`
2. Every `JOB_PEERINGEST_INTERVAL` cycles, `flush_peer_distribution_queue()` processes the queue:
   - For each entry, add transient_id as unhandled for every peer EXCEPT the originating peer
3. Then `flush_queues()` calls `peer.process_queues()` for each peer to update its handled/unhandled message sets

### 10.11 Handled/Unhandled Message Tracking

Messages are tracked at the propagation entry level (not per-peer). Each entry has:
- `[4]`: `handled_peers` list - destination hashes of peers who have this message
- `[5]`: `unhandled_peers` list - destination hashes of peers who need this message

Per-peer views are computed via filtering:
```python
# Handled messages for this peer
handled = [tid for tid in entries if self.destination_hash in entries[tid][4]]

# Unhandled messages for this peer
unhandled = [tid for tid in entries if self.destination_hash in entries[tid][5]]
```

---

## 11. Announce Handlers

### 11.1 LXMFDeliveryAnnounceHandler

**Aspect filter:** `"lxmf.delivery"`
**Receives path responses:** Yes

**On announce received:**
1. Extract stamp cost from app_data (if v0.5.0+ format)
2. Update outbound stamp cost for the announcing destination
3. For each pending outbound message destined to this hash:
   - If method is DIRECT or OPPORTUNISTIC: trigger immediate delivery attempt
   - Spawns a thread that waits for outbound processing lock, then calls `process_outbound()`

### 11.2 LXMFPropagationAnnounceHandler

**Aspect filter:** `"lxmf.propagation"`
**Receives path responses:** Yes

**On announce received (only if we are a propagation node):**
1. Validate announce data structure via `pn_announce_data_is_valid()`
2. Extract: timebase, propagation_enabled, transfer_limit, sync_limit, stamp costs, metadata
3. If source is a static peer: update peering config (not on path responses unless never heard)
4. If autopeer enabled and not a path response:
   - If propagation enabled AND within `autopeer_maxdepth` hops: peer
   - If outside range: unpeer existing peer
   - If propagation disabled: unpeer

---

## 12. lxmd Daemon

### 12.1 CLI Interface

```
lxmd [-h] [--config CONFIG] [--rnsconfig RNSCONFIG] [-p] [-i PATH]
     [-v] [-q] [-s] [--status] [--peers] [--sync HASH] [-b HASH]
     [--timeout SECONDS] [-r REMOTE] [--identity PATH]
     [--exampleconfig] [--version]
```

| Flag | Description |
|------|-------------|
| `--config` | Alternative lxmd config directory |
| `--rnsconfig` | Alternative Reticulum config directory |
| `-p, --propagation-node` | Run as propagation node |
| `-i, --on-inbound PATH` | Script to run on message receipt |
| `-v, --verbose` | Increase log level |
| `-q, --quiet` | Decrease log level |
| `-s, --service` | Run as service (log to file) |
| `--status` | Display node status |
| `--peers` | Display peer information |
| `--sync HASH` | Request sync with specific peer |
| `-b, --break HASH` | Break peering with specific peer |
| `--timeout SECONDS` | Timeout for query operations |
| `-r, --remote HASH` | Remote propagation node destination |
| `--identity PATH` | Identity file for remote requests |
| `--exampleconfig` | Print example configuration |
| `--version` | Show version |

### 12.2 Configuration File Format

INI-style configuration using Python's ConfigObj. Default location: `~/.lxmd/config` or `/etc/lxmd/config`.

**Sections:**

**`[propagation]`:**
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enable_node` | bool | `no` | Enable propagation node |
| `node_name` | string | None | Optional node name |
| `announce_interval` | int (minutes) | 360 | Announce interval |
| `announce_at_start` | bool | `yes` | Announce on startup |
| `autopeer` | bool | `yes` | Auto-peer with discovered nodes |
| `autopeer_maxdepth` | int | 6 | Max hops for auto-peering |
| `message_storage_limit` | float (MB) | 500 | Max message store size |
| `propagation_message_max_accepted_size` | float (KB) | 256 | Max single message size |
| `propagation_sync_max_accepted_size` | float (KB) | 10240 | Max sync transfer size |
| `propagation_stamp_cost_target` | int | 16 | Required stamp cost |
| `propagation_stamp_cost_flexibility` | int | 3 | Stamp cost flexibility |
| `peering_cost` | int | 18 | Required peering key cost |
| `remote_peering_cost_max` | int | 26 | Max remote peering cost |
| `prioritise_destinations` | list (hex) | [] | Priority destination hashes |
| `max_peers` | int | 20 | Maximum peer count |
| `static_peers` | list (hex) | [] | Static peer destination hashes |
| `from_static_only` | bool | `False` | Only accept from static peers |
| `auth_required` | bool | `no` | Require authentication |
| `control_allowed` | list (hex) | [] | Identity hashes for control access |

**`[lxmf]`:**
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `display_name` | string | "Anonymous Peer" | Display name |
| `announce_at_start` | bool | `no` | Announce delivery on startup |
| `announce_interval` | int (minutes) | None | Delivery announce interval |
| `delivery_transfer_max_accepted_size` | float (KB) | 1000 | Max delivery transfer size |
| `on_inbound` | string | None | Script to run on message receipt |

**`[logging]`:**
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `loglevel` | int (0-7) | 4 | Log level |

### 12.3 On-Inbound Script Execution

When a message is received:
1. Write message to `{storagedir}/messages/` using `lxm.write_to_directory()`
2. If `on_inbound` is configured: `subprocess.call(command + " " + filepath)`
3. The script receives the full path to the message file as its argument

### 12.4 Remote Control

The daemon supports remote control via the propagation control destination:

- **`/pn/get/stats`**: Returns comprehensive node statistics
- **`/pn/peer/sync`**: Triggers sync with a specified peer
- **`/pn/peer/unpeer`**: Breaks peering with a specified peer

All control requests require identity in `control_allowed_list`.

---

## 13. Threading & Concurrency Model

### 13.1 Main Job Loop

The `LXMRouter` runs a daemon thread (`jobloop`) that calls `jobs()` every `PROCESSING_INTERVAL = 4` seconds. This is the central scheduler for all periodic tasks.

```python
def jobloop(self):
    while True:
        self.jobs()
        time.sleep(PROCESSING_INTERVAL)
```

### 13.2 Threading Locks

| Lock | Protects |
|------|----------|
| `outbound_processing_lock` | Outbound queue processing (threading.Lock) |
| `cost_file_lock` | Outbound stamp costs file I/O (threading.Lock) |
| `ticket_file_lock` | Available tickets file I/O (threading.Lock) |
| `stamp_gen_lock` | Deferred stamp generation (threading.Lock) |
| `_peering_key_lock` (per peer) | Peering key generation (threading.Lock) |

### 13.3 Background Threads

| Operation | Thread Type | Trigger |
|-----------|-------------|---------|
| Deferred stamp generation | `threading.Thread` (daemon) | Every job cycle |
| Peering key generation | `threading.Thread` (daemon) | When sync finds missing key |
| Announce delivery trigger | `threading.Thread` (daemon) | On delivery announce received |
| Delayed announce | `threading.Thread` (daemon) | `announce_propagation_node()` (20s delay) |
| Save outbound stamp costs | `threading.Thread` (daemon) | On stamp cost update |
| Save available tickets | `threading.Thread` (daemon) | On ticket remembered |
| Outbound processing trigger | `threading.Thread` (daemon) | `handle_outbound()` |
| Path request job | `threading.Thread` (daemon) | Message download path resolution |

### 13.4 Multiprocessing

Stamp generation and validation use `multiprocessing`:

**Stamp generation (Linux):**
- `multiprocessing.get_context("fork").Process` for worker processes
- `multiprocessing.Event` for stop signaling
- `multiprocessing.Queue` for result and round count passing

**Stamp generation (Android):**
- `multiprocessing.Process` with `multiprocessing.Manager().dict()` for result sharing
- Batched: 1000 rounds per worker, respawned until stamp found

**Stamp validation:**
- `multiprocessing.get_context("spawn").Pool` for parallel validation
- Pool size: `min(cpu_count, ceil(message_count / 256))`

### 13.5 Signal Handling

```python
atexit.register(self.exit_handler)
signal.signal(signal.SIGINT, self.sigint_handler)
signal.signal(signal.SIGTERM, self.sigterm_handler)
```

Exit handler:
1. Set `exit_handler_running = True` (prevents job loop from running)
2. Tear down all delivery destination links
3. If propagation node: tear down propagation destination, deregister handlers
4. Flush peer distribution queues
5. Save peers to storage
6. Save locally delivered/processed transient IDs
7. Save node stats

### 13.6 Rust Port Considerations

- Replace `threading.Thread` with Tokio tasks or std threads
- Replace `threading.Lock` with `std::sync::Mutex` or `tokio::sync::Mutex`
- Replace `multiprocessing` with `rayon` for parallel stamp generation/validation
- The job loop pattern can be replaced with a Tokio interval timer
- File I/O locks should use `std::fs` with proper locking (or `flock`)
- Consider using channels (`mpsc`) instead of shared mutable state where possible
- The `deque` usage in peer queues maps to `VecDeque` in Rust

---

## 14. Key Constants Reference Table

### Time Intervals

| Constant | Value | Human |
|----------|-------|-------|
| `LXMRouter.PROCESSING_INTERVAL` | 4 | 4 seconds |
| `LXMRouter.DELIVERY_RETRY_WAIT` | 10 | 10 seconds |
| `LXMRouter.PATH_REQUEST_WAIT` | 7 | 7 seconds |
| `LXMRouter.LINK_MAX_INACTIVITY` | 600 | 10 minutes |
| `LXMRouter.P_LINK_MAX_INACTIVITY` | 180 | 3 minutes |
| `LXMRouter.NODE_ANNOUNCE_DELAY` | 20 | 20 seconds |
| `LXMRouter.PR_PATH_TIMEOUT` | 10 | 10 seconds |
| `LXMRouter.PN_STAMP_THROTTLE` | 180 | 3 minutes |
| `LXMRouter.MESSAGE_EXPIRY` | 2,592,000 | 30 days |
| `LXMRouter.STAMP_COST_EXPIRY` | 3,888,000 | 45 days |
| `LXMPeer.MAX_UNREACHABLE` | 1,209,600 | 14 days |
| `LXMPeer.SYNC_BACKOFF_STEP` | 720 | 12 minutes |
| `LXMPeer.PATH_REQUEST_GRACE` | 7.5 | 7.5 seconds |
| `LXMessage.TICKET_EXPIRY` | 1,814,400 | 21 days |
| `LXMessage.TICKET_GRACE` | 432,000 | 5 days |
| `LXMessage.TICKET_RENEW` | 1,209,600 | 14 days |
| `LXMessage.TICKET_INTERVAL` | 86,400 | 1 day |

### Job Intervals (in processing cycles, multiply by PROCESSING_INTERVAL for seconds)

| Constant | Cycles | Effective |
|----------|--------|-----------|
| `JOB_OUTBOUND_INTERVAL` | 1 | 4s |
| `JOB_STAMPS_INTERVAL` | 1 | 4s |
| `JOB_LINKS_INTERVAL` | 1 | 4s |
| `JOB_TRANSIENT_INTERVAL` | 60 | 240s |
| `JOB_STORE_INTERVAL` | 120 | 480s |
| `JOB_PEERSYNC_INTERVAL` | 6 | 24s |
| `JOB_PEERINGEST_INTERVAL` | 6 | 24s |
| `JOB_ROTATE_INTERVAL` | 336 | 1344s |

### Delivery & Propagation Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `LXMRouter.MAX_DELIVERY_ATTEMPTS` | 5 | Max retries per message |
| `LXMRouter.MAX_PATHLESS_TRIES` | 1 | Attempts without known path |
| `LXMRouter.MAX_PEERS` | 20 | Default max peer count |
| `LXMRouter.PROPAGATION_LIMIT` | 256 | Default per-transfer limit (KB) |
| `LXMRouter.SYNC_LIMIT` | 10,240 | Default sync limit (KB) |
| `LXMRouter.DELIVERY_LIMIT` | 1,000 | Default delivery limit (KB) |

### Stamp Costs

| Constant | Value | Description |
|----------|-------|-------------|
| `LXMRouter.PROPAGATION_COST` | 16 | Default propagation stamp cost |
| `LXMRouter.PROPAGATION_COST_MIN` | 13 | Minimum propagation stamp cost |
| `LXMRouter.PROPAGATION_COST_FLEX` | 3 | Default stamp cost flexibility |
| `LXMRouter.PEERING_COST` | 18 | Default peering key cost |
| `LXMRouter.MAX_PEERING_COST` | 26 | Max acceptable remote peering cost |
| `LXStamper.WORKBLOCK_EXPAND_ROUNDS` | 3,000 | Normal stamp workblock rounds |
| `LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN` | 1,000 | PN stamp workblock rounds |
| `LXStamper.WORKBLOCK_EXPAND_ROUNDS_PEERING` | 25 | Peering key workblock rounds |
| `LXStamper.PN_VALIDATION_POOL_MIN_SIZE` | 256 | Min stamps before multiprocessing |

### Peer Rotation

| Constant | Value | Description |
|----------|-------|-------------|
| `LXMRouter.FASTEST_N_RANDOM_POOL` | 2 | Top-N fastest peers to consider |
| `LXMRouter.ROTATION_HEADROOM_PCT` | 10 | Percent headroom for rotation |
| `LXMRouter.ROTATION_AR_MAX` | 0.5 | Max acceptance rate for culling (50%) |

### Size Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `LXMessage.DESTINATION_LENGTH` | 16 bytes | Truncated hash length |
| `LXMessage.SIGNATURE_LENGTH` | 64 bytes | Ed25519 signature length |
| `LXMessage.TICKET_LENGTH` | 16 bytes | Ticket size |
| `LXMessage.TIMESTAMP_SIZE` | 8 bytes | msgpack f64 size |
| `LXMessage.STRUCT_OVERHEAD` | 8 bytes | msgpack structure overhead |
| `LXMessage.LXMF_OVERHEAD` | 112 bytes | Total per-message overhead |
| `LXStamper.STAMP_SIZE` | 32 bytes | Proof-of-work stamp size |
| `LXMessage.QR_MAX_STORAGE` | 2,953 bytes | QR code storage capacity |
| `LXMessage.COST_TICKET` | 0x100 (256) | Sentinel stamp value for tickets |

### Message State Values

| Constant | Value |
|----------|-------|
| `GENERATING` | `0x00` |
| `OUTBOUND` | `0x01` |
| `SENDING` | `0x02` |
| `SENT` | `0x04` |
| `DELIVERED` | `0x08` |
| `REJECTED` | `0xFD` |
| `CANCELLED` | `0xFE` |
| `FAILED` | `0xFF` |

### Delivery Method Values

| Constant | Value |
|----------|-------|
| `OPPORTUNISTIC` | `0x01` |
| `DIRECT` | `0x02` |
| `PROPAGATED` | `0x03` |
| `PAPER` | `0x05` |

### Representation Values

| Constant | Value |
|----------|-------|
| `UNKNOWN` | `0x00` |
| `PACKET` | `0x01` |
| `RESOURCE` | `0x02` |

### Unverified Reason Values

| Constant | Value |
|----------|-------|
| `SOURCE_UNKNOWN` | `0x01` |
| `SIGNATURE_INVALID` | `0x02` |

### Request Paths

| Path | Handler | Description |
|------|---------|-------------|
| `/offer` | `offer_request` | Peer sync offer |
| `/get` | `message_get_request` | Message download/list |
| `/pn/get/stats` | `stats_get_request` | Node statistics |
| `/pn/peer/sync` | `peer_sync_request` | Trigger peer sync |
| `/pn/peer/unpeer` | `peer_unpeer_request` | Break peering |

### Propagation Transfer States (Client-Side)

| Constant | Value | Description |
|----------|-------|-------------|
| `PR_IDLE` | `0x00` | No transfer in progress |
| `PR_PATH_REQUESTED` | `0x01` | Path requested |
| `PR_LINK_ESTABLISHING` | `0x02` | Link being established |
| `PR_LINK_ESTABLISHED` | `0x03` | Link active |
| `PR_REQUEST_SENT` | `0x04` | Download request sent |
| `PR_RECEIVING` | `0x05` | Receiving messages |
| `PR_RESPONSE_RECEIVED` | `0x06` | Response received |
| `PR_COMPLETE` | `0x07` | Transfer complete |
| `PR_NO_PATH` | `0xF0` | No path to node |
| `PR_LINK_FAILED` | `0xF1` | Link establishment failed |
| `PR_TRANSFER_FAILED` | `0xF2` | Transfer failed |
| `PR_NO_IDENTITY_RCVD` | `0xF3` | No identity received |
| `PR_NO_ACCESS` | `0xF4` | Access denied |
| `PR_FAILED` | `0xFE` | General failure |
| `PR_ALL_MESSAGES` | `0x00` | Download all messages |

### Encryption Description Strings

| Constant | Value |
|----------|-------|
| `ENCRYPTION_DESCRIPTION_AES` | `"AES-128"` |
| `ENCRYPTION_DESCRIPTION_EC` | `"Curve25519"` |
| `ENCRYPTION_DESCRIPTION_UNENCRYPTED` | `"Unencrypted"` |

### URI/QR Constants

| Constant | Value |
|----------|-------|
| `URI_SCHEMA` | `"lxm"` |
| `QR_ERROR_CORRECTION` | `"ERROR_CORRECT_L"` |
| `QR_MAX_STORAGE` | `2953` |
