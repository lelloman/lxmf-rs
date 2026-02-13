# lxmf-rs

[![crates.io](https://img.shields.io/crates/v/lxmf-rs)](https://crates.io/crates/lxmf-rs)
[![docs.rs](https://img.shields.io/docsrs/lxmf-rs)](https://docs.rs/lxmf-rs)
[![License](https://img.shields.io/badge/license-Reticulum-blue)](./LICENSE)

A Rust implementation of LXMF (LoRa eXtended Messaging Format) for delay-tolerant, low-bandwidth networks. LXMF provides reliable message delivery with end-to-end encryption over networks like LoRa, packet radio, and other constrained communication channels.

## Overview

LXMF is a messaging protocol built on [Reticulum](https://reticulum.network), designed for reliable communication over extremely constrained networks. It enables store-and-forward messaging, automatic retries, and proof-of-work stamping for spam prevention. This is a Rust port of the Python LXMF v0.9.4 implementation, maintaining full wire compatibility with the Python version.

This implementation is built on top of [rns-rs](https://github.com/lelloman/rns-rs), the Rust implementation of Reticulum, providing a robust foundation for delay-tolerant networking. LXMF-rs is particularly well-suited for embedded systems, Android applications, and any scenario where Rust's performance and `no_std` support are advantageous.

The project is organized as a Cargo workspace with three crates: `lxmf-core` (lightweight, `no_std` compatible), `lxmf` (full-featured message router), and `lxmd` (propagation daemon with configurable logging). All 129 tests pass, and the implementation is ready for crates.io publication.

## Workspace Crates

| Crate | Description | no_std |
|-------|-------------|--------|
| **lxmf-core** | Core message format, constants, and stamp validation | Yes |
| **lxmf** | Full message router with delivery engine | No |
| **lxmd** | Propagation daemon with configurable logging | No |

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
lxmf = "0.1"
```

A minimal example that sends a message:

```rust
use lxmf::router::{LxmRouter, RouterConfig, OutboundMessage};
use lxmf_core::{constants::*, message};
use rns_crypto::identity::Identity;
use rns_net::node::{RnsNode, NodeConfig};

fn main() {
    // Create identity and router
    let identity = Identity::new(&mut rns_crypto::OsRng);
    let mut router = LxmRouter::new(
        identity,
        RouterConfig::default(),
    );

    // Pack a message
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let packed = message::pack(
        &destination_hash,
        &source_hash,
        timestamp,
        b"Hello",
        b"World!",
        vec![],
        None,
        |data| identity.sign(data).map_err(|_| message::Error::SignError),
    ).expect("pack message");

    // Send via the router (handles retries automatically)
    router.handle_outbound(OutboundMessage {
        destination_hash,
        source_hash,
        packed: packed.packed,
        message_hash: packed.message_hash,
        method: DeliveryMethod::Opportunistic,
        ..Default::default()
    });
}
```

## Key Features

### Messaging
- **Multiple Delivery Methods**: Opportunistic, direct (link-based), propagated (store-and-forward), and paper (QR/URI)
- **Encryption**: End-to-end encryption using Ed25519 signatures and Curve25519 ECDH
- **Automatic Retries**: Configurable retry logic with exponential backoff
- **Stamp System**: Proof-of-work stamps for spam prevention with ticket-based bypass
- **Message Fields**: Extensible field system for attachments, telemetry, and custom data

### Propagation
- **Store-and-Forward**: Deliver messages to offline recipients via propagation nodes
- **Peer Synchronization**: Automatic peer discovery and message distribution
- **Stamp Costs**: Configurable proof-of-work requirements for anti-spam
- **Message Prioritization**: Weighted culling and priority destination support

### Platform
- **no_std Support**: `lxmf-core` works in embedded environments
- **Swappable Logger**: Use `env_logger`, Android logcat, or your own logger
- **Cross-Platform**: Linux, Android, Windows, macOS support

## Delivery Methods

| Method | Max Content | When to Use |
|--------|-------------|-------------|
| **Opportunistic** | 295 bytes (SINGLE)<br>368 bytes (PLAIN) | Short messages to known destinations without established links |
| **Direct** | Unlimited (via resource) | Link-based delivery to online recipients |
| **Propagated** | Via PN (unlimited) | Offline recipients, store-and-forward via propagation nodes |
| **Paper** | ~2.2KB total | Offline transport via QR codes or `lxm://` URIs |

## Documentation

- **[Design Document](./design.md)** - Comprehensive protocol reference
- **[lxmd README](./lxmd/README.md)** - Propagation daemon documentation
- **[Reticulum](https://reticulum.network)** - Underlying network layer
- **[rns-rs](https://github.com/lelloman/rns-rs)** - Rust Reticulum implementation

## Examples

| Example | Description |
|---------|-------------|
| `echo` | Echo server for testing |
| `send_message` | Send messages to a destination |
| `live_test` | Live network interoperability testing |

Run examples:

```bash
# Send a message (requires RNS transport node)
RUST_LOG=info cargo run --example send_message -- <host:port> <dest_hash>

# Listen for announces
RUST_LOG=info cargo run --example send_message -- <host:port> listen
```

## Project Status

- **Version**: 0.1.0
- **Tests**: 129 passing
- **Compatibility**: Wire-compatible with Python LXMF v0.9.4
- **Repository**: [https://github.com/lelloman/lxmf-rs](https://github.com/lelloman/lxmf-rs)

## Contributing

Contributions are welcome! Please see the [design document](./design.md) for detailed technical information about the protocol and implementation architecture.

## License

This project is licensed under the **Reticulum License** - see [LICENSE](./LICENSE) for details.

Key license restrictions:
- The software shall not be used in systems designed to harm human beings
- The software shall not be used to train AI/ML models or create training datasets

Copyright (c) 2016-2026 Mark Qvist
Copyright (c) 2025-2026 lxmf-rs contributors
