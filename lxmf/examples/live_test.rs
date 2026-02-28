//! Live interop test for lxmf-rs.
//!
//! Connects to a real RNS node, announces itself, optionally sends a message
//! to a target destination, and prints any messages received (replying with an echo).
//!
//! Usage:
//!   RUST_LOG=info cargo run --example live_test -- <node_host:port> [target_identity_file]
//!
//! Arguments:
//!   node_host:port        - TCP address of an RNS transport node (e.g. 192.168.1.10:4242)
//!   target_identity_file  - Optional path to target's 64-byte RNS identity private key file.
//!                           When provided, sends a message directly without waiting for announce.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lxmf_rs::router::{LxmDelivery, LxmRouter, LxmfCallbacks, RouterConfig};
use lxmf_core::constants::*;
use lxmf_core::message;
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_net::destination::{AnnouncedIdentity, Destination};
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
    if args.len() < 2 || args.len() > 3 {
        eprintln!(
            "Usage: {} <node_host:port> [target_identity_file]",
            args[0]
        );
        eprintln!("  node_host:port        - TCP address of an RNS transport node");
        eprintln!("  target_identity_file  - Optional path to target's 64-byte identity key file");
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

    // Load target identity if provided
    let target_identity: Option<Identity> = if args.len() == 3 {
        let path = &args[2];
        let key_bytes = std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Error: failed to read target identity file '{}': {}", path, e);
            std::process::exit(1);
        });
        if key_bytes.len() != 64 {
            eprintln!("Error: identity file must be 64 bytes, got {}", key_bytes.len());
            std::process::exit(1);
        }
        let mut prv_key = [0u8; 64];
        prv_key.copy_from_slice(&key_bytes);
        Some(Identity::from_private_key(&prv_key))
    } else {
        None
    };

    // Stable temp dir (not per-process) so identity persists across runs
    let tmp_dir = std::env::temp_dir().join("lxmf_live_test");
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

    println!("=== lxmf-rs live test ===");
    println!("Own identity hash: {}", hex(identity.hash()));
    println!("Own delivery dest:  {}", hex(&delivery_dest_hash));
    if let Some(ref target_id) = target_identity {
        let target_dest = rns_core::destination::destination_hash(
            APP_NAME, &["delivery"], Some(target_id.hash()),
        );
        println!("Target identity:    {}", hex(target_id.hash()));
        println!("Target dest:        {}", hex(&target_dest));
    } else {
        println!("Target:             (none — listen only)");
    }
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
                name: "live_test".into(),
                target_host: host.to_string(),
                target_port: port,
                interface_id: InterfaceId(1),
                ..TcpClientConfig::default()
            }),
            mode: rns_core::constants::MODE_FULL,
            ifac: None,
            discovery: None,
        }],
        share_instance: false,
        instance_name: "default".into(),
        shared_instance_port: 37428,
        rpc_port: 0,
        cache_dir: Some(tmp_dir.clone()),
        management: ManagementConfig::default(),
        probe_port: None,
        probe_addrs: vec![],
        probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
        device: None,
        hooks: vec![],
        discover_interfaces: false,
        discovery_required_value: None,
        respond_to_probes: false,
        prefer_shorter_path: false,
        max_paths_per_destination: 1,
    };

    let node = Arc::new(
        RnsNode::start(node_config, Box::new(app_callbacks)).expect("Failed to start RNS node"),
    );

    // Wire node into router and register delivery identity
    {
        let mut r = router.lock().unwrap();
        r.set_node(node.clone());
        r.register_delivery_identity(&identity, None, Some("lxmf-rs-live".to_string()));
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

    // Send messages if we have a target identity
    if let Some(ref target_id) = target_identity {
        let target_dest = rns_core::destination::destination_hash(
            APP_NAME, &["delivery"], Some(target_id.hash()),
        );
        let pub_key = target_id.get_public_key().unwrap();
        let announced = AnnouncedIdentity {
            dest_hash: DestHash(target_dest),
            identity_hash: IdentityHash(*target_id.hash()),
            public_key: pub_key,
            app_data: None,
            hops: 0,
            received_at: 0.0,
            receiving_interface: rns_core::transport::types::InterfaceId(0),
        };

        // 1) Small opportunistic message
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let small_msg = message::pack(
            &target_dest, &src_hash, timestamp,
            b"small", b"Hello from lxmf-rs!",
            vec![], None,
            |data| sign_identity.sign(data).map_err(|_| message::Error::SignError),
        ).expect("pack small");

        let dest = Destination::single_out(APP_NAME, &["delivery"], &announced);
        let lxmf_payload = &small_msg.packed[DESTINATION_LENGTH..];
        match node.send_packet(&dest, lxmf_payload) {
            Ok(ph) => println!("[SEND] small opportunistic (packet {})", hex(&ph.0)),
            Err(e) => println!("[SEND] small failed: {}", e),
        }

        // 2) Big message via direct link delivery
        let big_content = "B".repeat(500).into_bytes();
        let timestamp2 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let big_msg = message::pack(
            &target_dest, &src_hash, timestamp2,
            b"big", &big_content,
            vec![], None,
            |data| sign_identity.sign(data).map_err(|_| message::Error::SignError),
        ).expect("pack big");

        // Queue as Direct delivery (will create link and send)
        {
            use lxmf_rs::router::OutboundMessage;
            let mut r = router.lock().unwrap();
            let msg = OutboundMessage {
                destination_hash: target_dest,
                source_hash: src_hash,
                packed: big_msg.packed,
                message_hash: big_msg.message_hash,
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
        println!("[SEND] big message queued for direct link delivery");

        // Trigger outbound processing (outside router lock)
        { router.lock().unwrap().jobs(); }
    }
    println!();
    println!("Running... (Ctrl+C to stop)");

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
