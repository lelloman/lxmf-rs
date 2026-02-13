//! LXMF Echo Server for lxmf-rs.
//!
//! Connects to a real RNS node, announces itself, and automatically echoes back
//! any received LXMF messages to their sender with "Echo: " prefix.
//!
//! Usage:
//!   RUST_LOG=info cargo run --example echo -- <node_host:port>
//!
//! Arguments:
//!   node_host:port - TCP address of an RNS transport node (e.g. 192.168.1.10:4242)

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lxmf_rs::router::{LxmDelivery, LxmRouter, LxmfCallbacks, RouterConfig, OutboundMessage};
use lxmf_core::constants::*;
use lxmf_core::message;
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

/// Events from the network forwarded to the main loop.
enum AppEvent {
    MessageReceived {
        source_hash: [u8; 16],
        title: Vec<u8>,
        content: Vec<u8>,
        method: DeliveryMethod,
    },
    Announce(AnnouncedIdentity),
}

/// Wraps LxmfCallbacks, forwarding delivery events to a channel.
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

    fn on_link_closed(
        &mut self,
        link_id: LinkId,
        reason: Option<rns_core::link::TeardownReason>,
    ) {
        self.inner.on_link_closed(link_id, reason);
    }

    fn on_remote_identified(
        &mut self,
        link_id: LinkId,
        identity_hash: IdentityHash,
        public_key: [u8; 64],
    ) {
        self.inner
            .on_remote_identified(link_id, identity_hash, public_key);
    }

    fn on_resource_received(
        &mut self,
        link_id: LinkId,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    ) {
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
    if args.len() != 2 {
        eprintln!(
            "Usage: {} <node_host:port>",
            args[0]
        );
        eprintln!("  node_host:port - TCP address of an RNS transport node");
        std::process::exit(1);
    }

    let addr = &args[1];

    // Parse host:port
    let (host, port) = addr.rsplit_once(':').unwrap_or_else(|| {
        eprintln!("Error: address must be host:port, got: {}", addr);
        std::process::exit(1);
    });
    let port: u16 = port.parse().unwrap_or_else(|_| {
        eprintln!("Error: invalid port: {}", port);
        std::process::exit(1);
    });

    // Stable temp dir (not per-process) so identity persists across runs
    let tmp_dir = std::env::temp_dir().join("lxmf_echo");
    let _ = std::fs::create_dir_all(&tmp_dir);

    // Load or generate a persistent identity for ourselves
    let own_identity_path = tmp_dir.join("identity");
    let identity = if own_identity_path.exists() {
        let key_bytes = std::fs::read(&own_identity_path).expect("read own identity");
        let mut prv_key = [0u8; 64];
        prv_key.copy_from_slice(&key_bytes);
        Identity::from_private_key(&prv_key)
    } else {
        let id = Identity::new(&mut rns_crypto::OsRng);
        std::fs::write(&own_identity_path, id.get_private_key().unwrap()).expect("save own identity");
        id
    };
    let delivery_dest_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(identity.hash()),
    );

    println!("=== lxmf-rs echo server ===");
    println!("Own identity hash: {}", hex(identity.hash()));
    println!("Own delivery dest:  {}", hex(&delivery_dest_hash));
    println!("Connecting to:      {}:{}", host, port);
    println!();

    // Set up router
    let router_config = RouterConfig {
        storagepath: tmp_dir.clone(),
        ..RouterConfig::default()
    };

    let mut router = LxmRouter::new(
        Identity::from_private_key(&identity.get_private_key().unwrap()),
        router_config,
    );

    // Delivery callback sends events to main loop
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let delivery_tx = tx.clone();
    let own_delivery_hash = delivery_dest_hash;
    router.set_delivery_callback(Box::new(move |delivery: &LxmDelivery| {
        let _ = delivery_tx.send(AppEvent::MessageReceived {
            source_hash: delivery.source_hash,
            title: delivery.title.clone(),
            content: delivery.content.clone(),
            method: delivery.method,
        });
    }));

    let router = Arc::new(Mutex::new(router));
    let inner_callbacks = LxmfCallbacks::new(router.clone());
    let app_callbacks = AppCallbacks {
        inner: inner_callbacks,
        tx,
    };

    // Start RNS node with TCP client interface
    let node_config = NodeConfig {
        transport_enabled: false,
        identity: Some(Identity::new(&mut rns_crypto::OsRng)),
        interfaces: vec![InterfaceConfig {
            variant: InterfaceVariant::TcpClient(TcpClientConfig {
                name: "echo".into(),
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
    };

    let node = Arc::new(
        RnsNode::start(node_config, Box::new(app_callbacks)).expect("Failed to start RNS node"),
    );

    // Wire node into router and register delivery identity
    {
        let mut r = router.lock().unwrap();
        r.set_node(node.clone());
        r.register_delivery_identity(&identity, None, Some("lxmf-rs-echo".to_string()));
    }

    // Wait for connection to establish
    println!("Waiting for network connection...");
    std::thread::sleep(Duration::from_secs(2));

    // Announce ourselves
    {
        let r = router.lock().unwrap();
        r.announce_delivery(&identity);
    }
    println!("Announced delivery destination");

    let src_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(identity.hash()),
    );

    let sign_identity = Identity::from_private_key(&identity.get_private_key().unwrap());

    println!();
    println!("Running... (Ctrl+C to stop)");
    println!();

    // Main loop — listen for incoming events
    loop {
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::MessageReceived {
                    source_hash,
                    title,
                    content,
                    method,
                } => {
                    let title_str = String::from_utf8_lossy(&title);
                    let content_str = String::from_utf8_lossy(&content);
                    println!(
                        "[RECV] from={} method={:?} title=\"{}\" content=\"{}\"",
                        hex(&source_hash),
                        method,
                        title_str,
                        content_str
                    );

                    // Self-echo prevention: skip if source is our own destination
                    if source_hash == own_delivery_hash {
                        println!("[SKIP] Self-echo prevented");
                        continue;
                    }

                    // Check if sender is in identity_cache (must have announced)
                    let (pub_key, announced) = {
                        let r = router.lock().unwrap();
                        if let Some(pk) = r.identity_cache.get(&source_hash) {
                            let announced = if let Ok(Some(ann)) = node.recall_identity(&DestHash(source_hash)) {
                                Some(ann)
                            } else {
                                None
                            };
                            (Some(*pk), announced)
                        } else {
                            (None, None)
                        }
                    };

                    match (pub_key, announced) {
                        (Some(_pk), Some(_ann)) => {},
                        _ => {
                            println!("[SKIP] Sender not in identity cache (must announce first)");
                            continue;
                        }
                    };

                    // Create echo message with "Echo: " prefix
                    let echo_title = format!("Echo: {}", title_str);
                    let echo_content = format!("Echo: {}", content_str);

                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs_f64();

                    let echo_msg = match message::pack(
                        &source_hash,  // destination becomes original source
                        &src_hash,     // source becomes us
                        timestamp,
                        echo_title.as_bytes(),
                        echo_content.as_bytes(),
                        vec![], None,
                        |data| sign_identity.sign(data).map_err(|_| message::Error::SignError),
                    ) {
                        Ok(msg) => msg,
                        Err(e) => {
                            println!("[FAIL] Failed to pack echo message: {:?}", e);
                            continue;
                        }
                    };

                    // Queue as Direct delivery (will create link and send)
                    {
                        let mut r = router.lock().unwrap();
                        let msg = OutboundMessage {
                            destination_hash: source_hash,
                            source_hash: src_hash,
                            packed: echo_msg.packed,
                            message_hash: echo_msg.message_hash,
                            method: DeliveryMethod::Direct,
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
                        };
                        r.handle_outbound(msg);
                    }
                    println!("[SEND] Echo queued for direct link delivery");
                }
                AppEvent::Announce(announced) => {
                    println!(
                        "[ANN ] dest={} hops={}",
                        hex(&announced.dest_hash.0),
                        announced.hops
                    );
                }
            }
        }

        // Periodic outbound processing (retry queued messages)
        { router.lock().unwrap().jobs(); }

        std::thread::sleep(Duration::from_secs(4));
    }
}
