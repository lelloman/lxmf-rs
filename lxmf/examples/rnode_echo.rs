//! Headless LXMF echo server over RNode LoRa.
//!
//! Usage:
//!   RUST_LOG=info cargo run --example rnode_echo -- [serial_port] [frequency_mhz]
//!
//! Defaults: /dev/ttyUSB0, 868 MHz

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lxmf_core::constants::*;
use lxmf_core::message;
use lxmf_rs::router::{LxmDelivery, LxmRouter, LxmfCallbacks, OutboundMessage, RouterConfig};
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_net::destination::AnnouncedIdentity;
use rns_net::driver::Callbacks;
use rns_net::node::{InterfaceConfig, InterfaceVariant, NodeConfig, RnsNode};
use rns_net::{InterfaceId, ManagementConfig, RNodeConfig, RNodeSubConfig};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
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
    let port = args.get(1).cloned().unwrap_or_else(|| "/dev/ttyUSB0".into());
    let freq_mhz: f64 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(868.0);
    let frequency = (freq_mhz * 1_000_000.0) as u32;

    let data_dir = std::env::temp_dir().join("lxmf_rnode_echo");
    let _ = std::fs::create_dir_all(&data_dir);
    let id_path = data_dir.join("identity");
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

    println!("=== lxmf rnode echo ===");
    println!("Identity: {}", hex(identity.hash()));
    println!("Dest:     {}", hex(&src_hash));
    println!("RNode:    {} at {} MHz", port, freq_mhz);
    println!();

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let mut router = LxmRouter::new(
        Identity::from_private_key(&identity.get_private_key().unwrap()),
        RouterConfig { storagepath: data_dir.clone(), ..RouterConfig::default() },
    );
    let delivery_tx = tx.clone();
    let own_dest = src_hash;
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

    let node = Arc::new(
        RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: Some(Identity::new(&mut rns_crypto::OsRng)),
                interfaces: vec![InterfaceConfig {
                    variant: InterfaceVariant::RNode(RNodeConfig {
                        name: format!("RNode {}", port),
                        port: port.clone(),
                        speed: 115200,
                        subinterfaces: vec![RNodeSubConfig {
                            name: "LoRa".into(),
                            frequency,
                            bandwidth: 125000,
                            txpower: 14,
                            spreading_factor: 8,
                            coding_rate: 5,
                            flow_control: false,
                            st_alock: None,
                            lt_alock: None,
                        }],
                        id_interval: None,
                        id_callsign: None,
                        base_interface_id: InterfaceId(1),
                    }),
                    mode: rns_core::constants::MODE_FULL,
                    ifac: None,
                    discovery: None,
                }],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: Some(data_dir.clone()),
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
            },
            Box::new(app_callbacks),
        )
        .expect("Failed to start RNS node"),
    );

    {
        let mut r = router.lock().unwrap();
        r.set_node(node.clone());
        r.register_delivery_identity(&identity, None, Some("rnode-echo".to_string()));
    }

    // Wait for RNode detection + configuration (takes ~4-5s)
    println!("Waiting for RNode to initialize...");
    std::thread::sleep(Duration::from_secs(6));
    {
        let r = router.lock().unwrap();
        r.announce_delivery(&identity);
    }
    println!("Announced. Waiting for messages...");
    println!();

    let sign_identity = Identity::from_private_key(&identity.get_private_key().unwrap());
    let announce_identity = Identity::from_private_key(&identity.get_private_key().unwrap());
    let mut last_jobs = Instant::now();
    let mut last_announce = Instant::now();

    loop {
        // Re-announce every 30 seconds
        if last_announce.elapsed() >= Duration::from_secs(30) {
            let r = router.lock().unwrap();
            r.announce_delivery(&announce_identity);
            drop(r);
            println!("[ANN ] Re-announced");
            last_announce = Instant::now();
        }

        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::MessageReceived { source_hash, title, content, method } => {
                    let title_str = String::from_utf8_lossy(&title);
                    let content_str = String::from_utf8_lossy(&content);
                    println!(
                        "[RECV] from={} method={:?} title=\"{}\" content=\"{}\"",
                        hex(&source_hash), method, title_str, content_str
                    );

                    if source_hash == own_dest {
                        println!("[SKIP] Self-echo");
                        continue;
                    }

                    // Check identity cache
                    let has_identity = {
                        let r = router.lock().unwrap();
                        r.identity_cache.contains_key(&source_hash)
                    };
                    if !has_identity {
                        println!("[SKIP] Sender not in identity cache");
                        continue;
                    }

                    let echo_content = format!("Echo: {}", content_str);
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs_f64();

                    match message::pack(
                        &source_hash, &src_hash, timestamp,
                        b"echo", echo_content.as_bytes(),
                        vec![], None,
                        |data| sign_identity.sign(data).map_err(|_| message::Error::SignError),
                    ) {
                        Ok(packed) => {
                            let mut r = router.lock().unwrap();
                            r.handle_outbound(OutboundMessage {
                                destination_hash: source_hash,
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
                            println!("[SEND] Echo queued to {}", hex(&source_hash));
                        }
                        Err(e) => println!("[FAIL] Pack error: {:?}", e),
                    }
                }
                AppEvent::Announce(announced) => {
                    let app_str = announced.app_data.as_ref()
                        .and_then(|d| std::str::from_utf8(d).ok())
                        .unwrap_or("");
                    println!(
                        "[ANN ] dest={} hops={} \"{}\"",
                        hex(&announced.dest_hash.0), announced.hops, app_str
                    );
                }
            }
        }

        if last_jobs.elapsed() >= Duration::from_secs(4) {
            router.lock().unwrap().jobs();
            last_jobs = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}
