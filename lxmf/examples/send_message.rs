//! Send a message to an LXMF destination and print the response.
//!
//! Usage:
//!   RUST_LOG=info cargo run --example send_message -- <node_host:port> <target_dest_hash_hex>
//!
//! The target_dest_hash_hex is the 32-char hex destination hash you see in announces.
//! Queues the message via the router's outbound system which handles path discovery
//! and retries automatically. Prints any incoming messages (e.g. echo responses).

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lxmf_core::constants::*;
use lxmf_core::message;
use lxmf_rs::router::{LxmDelivery, LxmRouter, LxmfCallbacks, OutboundMessage, RouterConfig};
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_net::destination::AnnouncedIdentity;
use rns_net::driver::Callbacks;
use rns_net::interface::tcp::TcpClientConfig;
use rns_net::node::{InterfaceConfig, InterfaceVariant, NodeConfig, RnsNode};
use rns_net::{InterfaceId, ManagementConfig};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

enum AppEvent {
    MessageReceived {
        source_hash: [u8; 16],
        title: Vec<u8>,
        content: Vec<u8>,
        method: DeliveryMethod,
    },
    Announce(AnnouncedIdentity),
}

struct AppCallbacks {
    inner: LxmfCallbacks,
    tx: mpsc::Sender<AppEvent>,
}

impl Callbacks for AppCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.tx.send(AppEvent::Announce(announced.clone()));
        self.inner.on_announce(announced);
    }
    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        self.inner.on_path_updated(dest_hash, hops);
    }
    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, packet_hash: PacketHash) {
        self.inner.on_local_delivery(dest_hash, raw, packet_hash);
    }
    fn on_link_established(&mut self, link_id: LinkId, dest_hash: DestHash, rtt: f64, is_initiator: bool) {
        self.inner.on_link_established(link_id, dest_hash, rtt, is_initiator);
    }
    fn on_link_closed(&mut self, link_id: LinkId, reason: Option<rns_core::link::TeardownReason>) {
        self.inner.on_link_closed(link_id, reason);
    }
    fn on_remote_identified(&mut self, link_id: LinkId, identity_hash: IdentityHash, public_key: [u8; 64]) {
        self.inner.on_remote_identified(link_id, identity_hash, public_key);
    }
    fn on_resource_received(&mut self, link_id: LinkId, data: Vec<u8>, metadata: Option<Vec<u8>>) {
        self.inner.on_resource_received(link_id, data, metadata);
    }
    fn on_resource_completed(&mut self, link_id: LinkId) {
        self.inner.on_resource_completed(link_id);
    }
    fn on_resource_failed(&mut self, link_id: LinkId, error: String) {
        self.inner.on_resource_failed(link_id, error);
    }
    fn on_response(&mut self, link_id: LinkId, request_id: [u8; 16], data: Vec<u8>) {
        self.inner.on_response(link_id, request_id, data);
    }
    fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
        self.inner.on_proof(dest_hash, packet_hash, rtt);
    }
    fn on_proof_requested(&mut self, dest_hash: DestHash, packet_hash: PacketHash) -> bool {
        self.inner.on_proof_requested(dest_hash, packet_hash)
    }
    fn on_link_data(&mut self, link_id: LinkId, context: u8, data: Vec<u8>) {
        self.inner.on_link_data(link_id, context, data);
    }
}

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <host:port> <target_dest_hash_hex>", args[0]);
        eprintln!();
        eprintln!("  host:port             - TCP address of an RNS transport node");
        eprintln!("  target_dest_hash_hex  - 32-char hex destination hash of the target");
        eprintln!();
        eprintln!("Run without target to discover dest hashes:");
        eprintln!("  {} <host:port> listen", args[0]);
        std::process::exit(1);
    }

    let addr = &args[1];
    let listen_only = args[2] == "listen";

    let mut target_dest = [0u8; 16];
    if !listen_only {
        let target_hex = &args[2];
        if target_hex.len() != 32 {
            eprintln!("Error: dest hash must be 32 hex chars, got {}", target_hex.len());
            std::process::exit(1);
        }
        let bytes = parse_hex(target_hex);
        target_dest.copy_from_slice(&bytes);
    }

    let (host, port) = addr.rsplit_once(':').unwrap_or_else(|| {
        eprintln!("Error: address must be host:port");
        std::process::exit(1);
    });
    let port: u16 = port.parse().unwrap_or_else(|_| {
        eprintln!("Error: invalid port: {}", port);
        std::process::exit(1);
    });

    // Persistent identity
    let tmp_dir = std::env::temp_dir().join("lxmf_send_message");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let id_path = tmp_dir.join("identity");
    let identity = if id_path.exists() {
        let bytes = std::fs::read(&id_path).expect("read identity");
        let mut key = [0u8; 64];
        key.copy_from_slice(&bytes);
        Identity::from_private_key(&key)
    } else {
        let id = Identity::new(&mut rns_crypto::OsRng);
        std::fs::write(&id_path, id.get_private_key().unwrap()).expect("save identity");
        id
    };

    let src_hash = rns_core::destination::destination_hash(APP_NAME, &["delivery"], Some(identity.hash()));

    println!("Own identity: {}", hex(identity.hash()));
    println!("Own dest:     {}", hex(&src_hash));
    if listen_only {
        println!("Mode:         listen (will print all announces)");
    } else {
        println!("Target dest:  {}", hex(&target_dest));
    }
    println!("Connecting to {}:{}", host, port);
    println!();

    // Router + delivery callback
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let mut router = LxmRouter::new(
        Identity::from_private_key(&identity.get_private_key().unwrap()),
        RouterConfig { storagepath: tmp_dir.clone(), ..RouterConfig::default() },
    );
    let delivery_tx = tx.clone();
    router.set_delivery_callback(Box::new(move |d: &LxmDelivery| {
        let _ = delivery_tx.send(AppEvent::MessageReceived {
            source_hash: d.source_hash,
            title: d.title.clone(),
            content: d.content.clone(),
            method: d.method,
        });
    }));

    let router = Arc::new(Mutex::new(router));
    let app_callbacks = AppCallbacks {
        inner: LxmfCallbacks::new(router.clone()),
        tx,
    };

    // Start node
    let node = Arc::new(RnsNode::start(
        NodeConfig {
            transport_enabled: false,
            identity: Some(Identity::new(&mut rns_crypto::OsRng)),
            interfaces: vec![InterfaceConfig {
                variant: InterfaceVariant::TcpClient(TcpClientConfig {
                    name: "send_msg".into(),
                    target_host: host.to_string(),
                    target_port: port,
                    interface_id: InterfaceId(1),
                    ..TcpClientConfig::default()
                }),
                mode: rns_core::constants::MODE_FULL,
                ifac: None,
            }],
            share_instance: false,
            rpc_port: 0,
            cache_dir: Some(tmp_dir.clone()),
            management: ManagementConfig::default(),
            probe_port: None,
            probe_addr: None,
            device: None,
        },
        Box::new(app_callbacks),
    ).expect("Failed to start RNS node"));

    {
        let mut r = router.lock().unwrap();
        r.set_node(node.clone());
        r.register_delivery_identity(&identity, None, Some("lxmf-rs".to_string()));
    }

    std::thread::sleep(Duration::from_secs(2));
    router.lock().unwrap().announce_delivery(&identity);
    println!("Announced. Waiting for announce to propagate...");

    // Give our announce time to reach the target before sending
    std::thread::sleep(Duration::from_secs(6));

    // Queue the message — the router handles path discovery and retries
    if !listen_only {
        let sign_identity = Identity::from_private_key(&identity.get_private_key().unwrap());
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let packed = message::pack(
            &target_dest, &src_hash, timestamp,
            b"hello", b"Hello from lxmf-rs!",
            vec![], None,
            |data| sign_identity.sign(data).map_err(|_| message::Error::SignError),
        ).expect("pack message");

        println!("[QUEUE] message queued for {}", hex(&target_dest));

        let mut r = router.lock().unwrap();
        r.handle_outbound(OutboundMessage {
            destination_hash: target_dest,
            source_hash: src_hash,
            packed: packed.packed,
            message_hash: packed.message_hash,
            method: DeliveryMethod::Opportunistic,
            state: MessageState::Outbound,
            representation: Representation::Unknown,
            attempts: 0,
            last_attempt: 0.0,
            stamp: None,
            stamp_cost: None,
            propagation_packed: None,
            propagation_stamp: None,
            transient_id: None,
            delivery_callback: None,
            failed_callback: None,
            progress_callback: None,
            link_id: None,
            packet_hash: None,
        });
    }
    println!("Waiting...");
    println!();

    loop {
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::Announce(announced) => {
                    println!("[ANN] dest={} hops={}", hex(&announced.dest_hash.0), announced.hops);
                }
                AppEvent::MessageReceived { source_hash, title, content, method } => {
                    println!(
                        "[RECV] from={} method={:?} title=\"{}\" content=\"{}\"",
                        hex(&source_hash),
                        method,
                        String::from_utf8_lossy(&title),
                        String::from_utf8_lossy(&content),
                    );
                }
            }
        }

        router.lock().unwrap().jobs();
        std::thread::sleep(Duration::from_secs(2));
    }
}
