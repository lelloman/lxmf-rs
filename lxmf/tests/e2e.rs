//! End-to-end tests for the LXMF router.
//!
//! Spins up real RNS nodes on localhost TCP, wires LxmRouter + LxmfCallbacks,
//! and validates message delivery, announce handling, and deduplication.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fs, thread};

use lxmf_core::constants::*;
use lxmf_core::message;
use lxmf_rs::router::{LxmDelivery, LxmRouter, LxmfCallbacks, OutboundMessage, RouterConfig};
use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_net::destination::{AnnouncedIdentity, Destination};
use rns_net::driver::Callbacks;
use rns_net::interface::tcp::TcpClientConfig;
use rns_net::interface::tcp_server::TcpServerConfig;
use rns_net::node::{InterfaceConfig, NodeConfig, RnsNode};
use rns_net::{Event, InterfaceId};

// ============================================================
// Constants
// ============================================================

/// Time to wait for network/announce settling after setup.
const SETTLE_MS: u64 = 1500;
/// Default timeout for event waits.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

// ============================================================
// Test event types
// ============================================================

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum LxmfTestEvent {
    Announce(AnnouncedIdentity),
    PathUpdated {
        dest_hash: DestHash,
        hops: u8,
    },
    MessageDelivered {
        destination_hash: [u8; 16],
        source_hash: [u8; 16],
        title: Vec<u8>,
        content: Vec<u8>,
        message_hash: [u8; 32],
        method: DeliveryMethod,
    },
    LinkEstablished {
        link_id: [u8; 16],
        rtt: f64,
        is_initiator: bool,
    },
    LinkClosed {
        link_id: [u8; 16],
    },
    Proof {
        dest_hash: DestHash,
        packet_hash: PacketHash,
        rtt: f64,
    },
}

// ============================================================
// Test callbacks wrapper
// ============================================================

/// Wraps `LxmfCallbacks` and forwards events to a test channel.
struct LxmfTestCallbacks {
    inner: LxmfCallbacks,
    tx: mpsc::Sender<LxmfTestEvent>,
}

impl LxmfTestCallbacks {
    fn new(inner: LxmfCallbacks, tx: mpsc::Sender<LxmfTestEvent>) -> Self {
        Self { inner, tx }
    }
}

impl Callbacks for LxmfTestCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.tx.send(LxmfTestEvent::Announce(announced.clone()));
        self.inner.on_announce(announced);
    }

    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        let _ = self.tx.send(LxmfTestEvent::PathUpdated { dest_hash, hops });
        self.inner.on_path_updated(dest_hash, hops);
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, packet_hash: PacketHash) {
        self.inner.on_local_delivery(dest_hash, raw, packet_hash);
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        dest_hash: DestHash,
        rtt: f64,
        is_initiator: bool,
    ) {
        let _ = self.tx.send(LxmfTestEvent::LinkEstablished {
            link_id: link_id.0,
            rtt,
            is_initiator,
        });
        self.inner
            .on_link_established(link_id, dest_hash, rtt, is_initiator);
    }

    fn on_link_closed(&mut self, link_id: LinkId, reason: Option<rns_core::link::TeardownReason>) {
        let _ = self
            .tx
            .send(LxmfTestEvent::LinkClosed { link_id: link_id.0 });
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
        let _ = self.tx.send(LxmfTestEvent::Proof {
            dest_hash,
            packet_hash,
            rtt,
        });
        self.inner.on_proof(dest_hash, packet_hash, rtt);
    }

    fn on_proof_requested(&mut self, dest_hash: DestHash, packet_hash: PacketHash) -> bool {
        self.inner.on_proof_requested(dest_hash, packet_hash)
    }

    fn on_link_data(&mut self, link_id: LinkId, context: u8, data: Vec<u8>) {
        self.inner.on_link_data(link_id, context, data);
    }
}

// ============================================================
// Node handle
// ============================================================

struct LxmfNodeHandle {
    node: Arc<RnsNode>,
    router: Arc<Mutex<LxmRouter>>,
    identity: Identity,
    delivery_dest_hash: [u8; 16],
    rx: mpsc::Receiver<LxmfTestEvent>,
    temp_dir: PathBuf,
}

impl LxmfNodeHandle {
    fn shutdown(self) {
        if let Ok(mut r) = self.router.lock() {
            r.exit_handler();
        }
        match Arc::try_unwrap(self.node) {
            Ok(node) => node.shutdown(),
            Err(node) => {
                let _ = node.event_sender().send(Event::Shutdown);
                // Give the driver a moment to process
                thread::sleep(Duration::from_millis(100));
            }
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

// ============================================================
// Helper functions
// ============================================================

/// Thread-safe port allocator. Starts above ephemeral range to avoid conflicts.
static NEXT_PORT: AtomicU16 = AtomicU16::new(17100);
static NEXT_TEMP_ID: AtomicU16 = AtomicU16::new(1);

fn find_free_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

fn temp_dir(name: &str) -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lxmf_e2e_{}_{}_{}", name, std::process::id(), id));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Wait for an event matching the predicate, with timeout.
fn wait_for_event<F>(
    rx: &mpsc::Receiver<LxmfTestEvent>,
    timeout: Duration,
    mut predicate: F,
) -> Option<LxmfTestEvent>
where
    F: FnMut(&LxmfTestEvent) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match rx.recv_timeout(remaining) {
            Ok(event) => {
                if predicate(&event) {
                    return Some(event);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => return None,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

fn wait_for_announce(
    rx: &mpsc::Receiver<LxmfTestEvent>,
    expected_hash: &[u8; 16],
    timeout: Duration,
) -> Option<AnnouncedIdentity> {
    let hash = *expected_hash;
    wait_for_event(
        rx,
        timeout,
        move |e| matches!(e, LxmfTestEvent::Announce(a) if a.dest_hash.0 == hash),
    )
    .and_then(|e| match e {
        LxmfTestEvent::Announce(a) => Some(a),
        _ => None,
    })
}

fn wait_for_message_delivery(
    rx: &mpsc::Receiver<LxmfTestEvent>,
    timeout: Duration,
) -> Option<LxmfTestEvent> {
    wait_for_event(rx, timeout, |e| {
        matches!(e, LxmfTestEvent::MessageDelivered { .. })
    })
}

#[allow(dead_code)]
fn wait_for_proof(rx: &mpsc::Receiver<LxmfTestEvent>, timeout: Duration) -> Option<LxmfTestEvent> {
    wait_for_event(rx, timeout, |e| matches!(e, LxmfTestEvent::Proof { .. }))
}

#[allow(dead_code)]
fn wait_for_link_established(
    rx: &mpsc::Receiver<LxmfTestEvent>,
    timeout: Duration,
) -> Option<LxmfTestEvent> {
    wait_for_event(rx, timeout, |e| {
        matches!(e, LxmfTestEvent::LinkEstablished { .. })
    })
}

fn known_destination_retained(node: &RnsNode, dest_hash: &[u8; 16]) -> bool {
    node.known_destinations()
        .unwrap_or_default()
        .iter()
        .any(|entry| entry.dest_hash == *dest_hash && entry.retained)
}

fn wait_for_known_destination_retained(
    node: &RnsNode,
    dest_hash: &[u8; 16],
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if known_destination_retained(node, dest_hash) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

// ============================================================
// RNS node helpers
// ============================================================

/// Start a transport node (TCP server) that routes announces between clients.
fn start_transport_node(port: u16) -> (RnsNode, PathBuf) {
    let dir = temp_dir(&format!("transport_{}", port));
    let config = NodeConfig {
        transport_enabled: true,
        identity: Some(Identity::new(&mut rns_crypto::OsRng)),
        interfaces: vec![InterfaceConfig {
            name: String::new(),
            type_name: "TCPServerInterface".to_string(),
            config_data: Box::new(TcpServerConfig {
                name: "e2e_server".into(),
                listen_ip: "127.0.0.1".into(),
                listen_port: port,
                interface_id: InterfaceId(1),
                ..TcpServerConfig::default()
            }),
            mode: rns_core::constants::MODE_FULL,
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            stamp_costs: Default::default(),
            ifac: None,
            discovery: None,
        }],
        cache_dir: Some(dir.clone()),
        ..NodeConfig::default()
    };

    struct NoopCallbacks;
    impl Callbacks for NoopCallbacks {
        fn on_announce(&mut self, _: AnnouncedIdentity) {}
        fn on_path_updated(&mut self, _: DestHash, _: u8) {}
        fn on_local_delivery(&mut self, _: DestHash, _: Vec<u8>, _: PacketHash) {}
    }

    let node = RnsNode::start(config, Box::new(NoopCallbacks)).expect("transport node start");
    (node, dir)
}

/// Start a client RNS node (TCP client) connected to the transport.
fn start_client_node(port: u16, callbacks: Box<dyn Callbacks>) -> RnsNode {
    let config = NodeConfig {
        transport_enabled: false,
        identity: Some(Identity::new(&mut rns_crypto::OsRng)),
        interfaces: vec![InterfaceConfig {
            name: String::new(),
            type_name: "TCPClientInterface".to_string(),
            config_data: Box::new(TcpClientConfig {
                name: "e2e_client".into(),
                target_host: "127.0.0.1".into(),
                target_port: port,
                interface_id: InterfaceId(1),
                ..TcpClientConfig::default()
            }),
            mode: rns_core::constants::MODE_FULL,
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            stamp_costs: Default::default(),
            ifac: None,
            discovery: None,
        }],
        ..NodeConfig::default()
    };

    RnsNode::start(config, callbacks).expect("client node start")
}

// ============================================================
// LXMF node setup
// ============================================================

/// Create a fully wired LXMF node connected to the transport on `port`.
fn setup_lxmf_node(port: u16, name: &str, stamp_cost: Option<u8>) -> LxmfNodeHandle {
    let dir = temp_dir(name);
    let identity = Identity::new(&mut rns_crypto::OsRng);

    let router_config = RouterConfig {
        storagepath: dir.clone(),
        ..RouterConfig::default()
    };

    let mut router = LxmRouter::new(
        Identity::from_private_key(&identity.get_private_key().unwrap()),
        router_config,
    );

    // Wire delivery callback that sends MessageDelivered events
    let (tx, rx) = mpsc::channel::<LxmfTestEvent>();
    let delivery_tx = tx.clone();
    router.set_delivery_callback(Box::new(move |delivery: &LxmDelivery| {
        let _ = delivery_tx.send(LxmfTestEvent::MessageDelivered {
            destination_hash: delivery.destination_hash,
            source_hash: delivery.source_hash,
            title: delivery.title.clone(),
            content: delivery.content.clone(),
            message_hash: delivery.message_hash,
            method: delivery.method,
        });
    }));

    let router = Arc::new(Mutex::new(router));
    let inner_callbacks = LxmfCallbacks::new(router.clone());
    let test_callbacks = LxmfTestCallbacks::new(inner_callbacks, tx);

    let node = Arc::new(start_client_node(port, Box::new(test_callbacks)));

    // Compute delivery dest hash for assertions
    let delivery_dest_hash =
        rns_core::destination::destination_hash(APP_NAME, &["delivery"], Some(identity.hash()));

    {
        let mut r = router.lock().unwrap();
        r.set_node(node.clone());
        r.register_delivery_identity(&identity, stamp_cost.map(f64::from), Some(name.to_string()));
    }

    LxmfNodeHandle {
        node,
        router,
        identity,
        delivery_dest_hash,
        rx,
        temp_dir: dir,
    }
}

/// Two LXMF peers connected through a transport node.
struct TwoPeers {
    transport_node: RnsNode,
    transport_dir: PathBuf,
    alice: LxmfNodeHandle,
    bob: LxmfNodeHandle,
}

impl TwoPeers {
    fn shutdown(self) {
        self.alice.shutdown();
        self.bob.shutdown();
        self.transport_node.shutdown();
        let _ = fs::remove_dir_all(&self.transport_dir);
    }
}

fn setup_two_lxmf_peers(alice_stamp_cost: Option<u8>, bob_stamp_cost: Option<u8>) -> TwoPeers {
    let port = find_free_port();
    let (transport_node, transport_dir) = start_transport_node(port);

    // Give server time to bind
    thread::sleep(Duration::from_millis(500));

    let alice = setup_lxmf_node(port, "alice", alice_stamp_cost);
    let bob = setup_lxmf_node(port, "bob", bob_stamp_cost);

    // Let nodes connect and settle
    thread::sleep(Duration::from_millis(SETTLE_MS));

    TwoPeers {
        transport_node,
        transport_dir,
        alice,
        bob,
    }
}

fn setup_two_lxmf_peers_announced(
    alice_stamp_cost: Option<u8>,
    bob_stamp_cost: Option<u8>,
) -> TwoPeers {
    let peers = setup_two_lxmf_peers(alice_stamp_cost, bob_stamp_cost);

    // Alice announces
    {
        let r = peers.alice.router.lock().unwrap();
        r.announce_delivery(&peers.alice.identity);
    }

    // Wait for Bob to receive Alice's announce before Bob announces,
    // to avoid announce burst detection on the transport node.
    let alice_announce = wait_for_announce(
        &peers.bob.rx,
        &peers.alice.delivery_dest_hash,
        DEFAULT_TIMEOUT,
    );
    assert!(
        alice_announce.is_some(),
        "Bob should receive Alice's announce"
    );

    // Bob announces
    {
        let r = peers.bob.router.lock().unwrap();
        r.announce_delivery(&peers.bob.identity);
    }

    // Wait for Alice to receive Bob's announce
    let bob_announce = wait_for_announce(
        &peers.alice.rx,
        &peers.bob.delivery_dest_hash,
        DEFAULT_TIMEOUT,
    );
    assert!(
        bob_announce.is_some(),
        "Alice should receive Bob's announce"
    );

    // Allow announce processing to complete
    thread::sleep(Duration::from_millis(500));

    peers
}

/// Pack a test LXMF message from source to destination.
fn pack_test_message(
    source_identity: &Identity,
    dest_hash: &[u8; 16],
    title: &[u8],
    content: &[u8],
) -> message::PackResult {
    let src_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(source_identity.hash()),
    );
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    let prv_key = source_identity.get_private_key().unwrap();
    let sign_identity = Identity::from_private_key(&prv_key);

    message::pack(
        dest_hash,
        &src_hash,
        timestamp,
        title,
        content,
        vec![],
        None,
        |data| {
            sign_identity
                .sign(data)
                .map_err(|_| message::Error::SignError)
        },
    )
    .expect("message pack")
}

#[allow(dead_code)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================
// Test A: Delivery announce received
// ============================================================

#[test]
fn test_delivery_announce_received() {
    let port = find_free_port();
    let (transport_node, transport_dir) = start_transport_node(port);
    thread::sleep(Duration::from_millis(500));

    let alice = setup_lxmf_node(port, "alice_ann", Some(8));
    let bob = setup_lxmf_node(port, "bob_ann", None);

    thread::sleep(Duration::from_millis(SETTLE_MS));

    // Alice announces with stamp_cost=8
    {
        let r = alice.router.lock().unwrap();
        r.announce_delivery(&alice.identity);
    }

    // Bob should receive the announce
    let announced = wait_for_announce(&bob.rx, &alice.delivery_dest_hash, DEFAULT_TIMEOUT);
    assert!(
        announced.is_some(),
        "Bob should receive Alice's delivery announce"
    );

    let announced = announced.unwrap();
    assert_eq!(
        announced.dest_hash.0, alice.delivery_dest_hash,
        "Announce dest_hash should match Alice's delivery dest"
    );

    // Bob's router should have stored the stamp cost
    {
        let r = bob.router.lock().unwrap();
        let cost = r.get_stamp_cost(&alice.delivery_dest_hash);
        assert_eq!(
            cost,
            Some(lxmf_core::stamp::StampCost::from_whole(8)),
            "Bob's router should store Alice's stamp cost of 8, got {:?}",
            cost
        );
        assert_eq!(
            r.compression_cache.get(&alice.delivery_dest_hash),
            Some(&true),
            "legacy two-field delivery announces should default to compression-capable"
        );
    }

    alice.shutdown();
    bob.shutdown();
    transport_node.shutdown();
    let _ = fs::remove_dir_all(&transport_dir);
}

#[test]
fn test_delivery_announce_records_compression_unsupported() {
    let dir = temp_dir("compression_unsupported");
    let identity = Identity::new(&mut rns_crypto::OsRng);
    let router = Arc::new(Mutex::new(LxmRouter::new(
        identity,
        RouterConfig {
            storagepath: dir.clone(),
            ..RouterConfig::default()
        },
    )));
    let mut callbacks = LxmfCallbacks::new(router.clone());

    let peer_identity = Identity::new(&mut rns_crypto::OsRng);
    // Only lxmf.delivery announces are read, so the destination hash must
    // belong to the announced identity.
    let dest_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(peer_identity.hash()),
    );
    let app_data = msgpack::pack(&Value::Array(vec![
        Value::Nil,
        Value::Nil,
        Value::Array(vec![]),
    ]));
    callbacks.on_announce(AnnouncedIdentity {
        dest_hash: DestHash(dest_hash),
        identity_hash: IdentityHash(*peer_identity.hash()),
        public_key: peer_identity.get_public_key().unwrap(),
        app_data: Some(app_data),
        hops: 0,
        received_at: 0.0,
        receiving_interface: InterfaceId(0),
        rssi: None,
        snr: None,
    });

    assert_eq!(
        router.lock().unwrap().compression_cache.get(&dest_hash),
        Some(&false),
        "empty supported-functionality list should disable resource compression"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_link_data_delivery_returns_before_user_callback_completes() {
    let dir = temp_dir("link_data_async");
    let local_identity = Identity::new(&mut rns_crypto::OsRng);
    let source_identity = Identity::new(&mut rns_crypto::OsRng);
    let dest_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(local_identity.hash()),
    );
    let source_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(source_identity.hash()),
    );
    let link_id = [0x77; DESTINATION_LENGTH];

    let mut router = LxmRouter::new(
        local_identity,
        RouterConfig {
            storagepath: dir.clone(),
            ..RouterConfig::default()
        },
    );
    router.delivery_dest_hash = Some(dest_hash);
    router.link_destinations.insert(link_id, dest_hash);
    router
        .identity_cache
        .insert(source_hash, source_identity.get_public_key().unwrap());

    let (callback_started_tx, callback_started_rx) = mpsc::channel();
    let (release_callback_tx, release_callback_rx) = mpsc::channel();
    router.set_delivery_callback(Box::new(move |_delivery: &LxmDelivery| {
        let _ = callback_started_tx.send(());
        let _ = release_callback_rx.recv_timeout(DEFAULT_TIMEOUT);
    }));

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router);
    let packed = pack_test_message(
        &source_identity,
        &dest_hash,
        b"Async",
        b"callback should not hold driver callback",
    )
    .packed;

    let (returned_tx, returned_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        callbacks.on_link_data(LinkId(link_id), 0, packed);
        let _ = returned_tx.send(());
    });

    let returned_before_release = returned_rx.recv_timeout(Duration::from_millis(200)).is_ok();
    assert!(
        callback_started_rx.recv_timeout(DEFAULT_TIMEOUT).is_ok(),
        "delivery callback should still run"
    );
    let _ = release_callback_tx.send(());
    handle.join().unwrap();

    assert!(
        returned_before_release,
        "on_link_data should return before user delivery callback completes"
    );

    let _ = fs::remove_dir_all(dir);
}

// ============================================================
// Test B: Propagation node announce received
// ============================================================

#[test]
fn test_propagation_node_announce_received() {
    let port = find_free_port();
    let (transport_node, transport_dir) = start_transport_node(port);
    thread::sleep(Duration::from_millis(500));

    // Create propagation node
    let prop_dir = temp_dir("prop_node");
    let prop_identity = Identity::new(&mut rns_crypto::OsRng);

    let prop_config = RouterConfig {
        storagepath: prop_dir.clone(),
        ..RouterConfig::default()
    };

    let prop_router = LxmRouter::new(
        Identity::from_private_key(&prop_identity.get_private_key().unwrap()),
        prop_config,
    );

    let (prop_tx, _prop_rx) = mpsc::channel::<LxmfTestEvent>();
    let prop_router = Arc::new(Mutex::new(prop_router));
    let prop_inner_cb = LxmfCallbacks::new(prop_router.clone());
    let prop_test_cb = LxmfTestCallbacks::new(prop_inner_cb, prop_tx);

    let prop_node = Arc::new(start_client_node(port, Box::new(prop_test_cb)));

    let propagation_dest_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["propagation"],
        Some(prop_identity.hash()),
    );

    {
        let mut r = prop_router.lock().unwrap();
        r.set_node(prop_node.clone());
        r.enable_propagation();
    }

    // Create client node
    let client = setup_lxmf_node(port, "client_pn", None);

    thread::sleep(Duration::from_millis(SETTLE_MS));

    // Propagation node announces
    {
        let r = prop_router.lock().unwrap();
        r.announce_propagation_node_now();
    }

    // Client should receive the propagation announce
    let announced = wait_for_announce(&client.rx, &propagation_dest_hash, DEFAULT_TIMEOUT);
    assert!(
        announced.is_some(),
        "Client should receive propagation node announce"
    );

    let announced = announced.unwrap();
    assert_eq!(
        announced.dest_hash.0, propagation_dest_hash,
        "Announce dest_hash should match propagation dest"
    );

    // Verify app_data is parseable as propagation announce
    assert!(
        announced.app_data.is_some(),
        "Propagation announce should have app_data"
    );
    let app_data = announced.app_data.unwrap();
    assert!(
        lxmf_core::announce::pn_announce_data_is_valid(&app_data),
        "Propagation announce app_data should be valid"
    );

    let parsed = lxmf_core::announce::parse_pn_announce_data(&app_data);
    assert!(
        parsed.is_some(),
        "Propagation announce data should be parseable"
    );
    let parsed = parsed.unwrap();
    assert!(
        parsed.propagation_enabled,
        "Propagation should be enabled in announce"
    );

    // Cleanup
    client.shutdown();
    {
        if let Ok(mut r) = prop_router.lock() {
            r.exit_handler();
        }
    }
    match Arc::try_unwrap(prop_node) {
        Ok(node) => node.shutdown(),
        Err(node) => {
            let _ = node.event_sender().send(Event::Shutdown);
            thread::sleep(Duration::from_millis(100));
        }
    }
    transport_node.shutdown();
    let _ = fs::remove_dir_all(&transport_dir);
    let _ = fs::remove_dir_all(&prop_dir);
}

// ============================================================
// Test C: Opportunistic delivery
// ============================================================

/// Tests end-to-end opportunistic LXMF delivery through a real network:
///
/// Alice sends a message to Bob via send_packet. The encrypted SINGLE DATA
/// packet travels through the transport node to Bob. Bob's on_local_delivery
/// callback unpacks the wire format, decrypts with the delivery identity,
/// verifies the signature using the cached public key from Alice's announce,
/// and fires the delivery callback.
#[test]
fn test_opportunistic_delivery() {
    let peers = setup_two_lxmf_peers_announced(None, None);

    // Alice packs a message for Bob
    let pack_result = pack_test_message(
        &peers.alice.identity,
        &peers.bob.delivery_dest_hash,
        b"Hello",
        b"World",
    );

    let alice_src_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(peers.alice.identity.hash()),
    );

    // --- Send via real network ---
    // Perform node RPCs outside the router lock. Calling jobs() while
    // holding the lock deadlocks because process_outbound() does
    // synchronous RPCs to the driver, which may be mid-callback trying
    // to acquire the same router lock.
    assert!(
        peers
            .alice
            .node
            .has_path(&DestHash(peers.bob.delivery_dest_hash))
            .unwrap(),
        "Alice should have Bob's path from the announce exchange"
    );

    let announced = peers
        .alice
        .node
        .recall_identity(&DestHash(peers.bob.delivery_dest_hash))
        .unwrap()
        .expect("Alice should have Bob's announced identity");

    let dest = Destination::single_out(APP_NAME, &["delivery"], &announced);
    let lxmf_payload = &pack_result.packed[DESTINATION_LENGTH..];
    let _packet_hash = peers
        .alice
        .node
        .try_send_packet(&dest, lxmf_payload)
        .expect("send_packet should succeed");

    // --- Bob receives via real network transport ---
    // The packet travels: Alice → transport node → Bob.
    // Bob's on_local_delivery unpacks wire format → decrypts → delivers.
    let event = wait_for_message_delivery(&peers.bob.rx, DEFAULT_TIMEOUT);
    assert!(event.is_some(), "Bob should receive the delivered message");

    if let Some(LxmfTestEvent::MessageDelivered {
        destination_hash,
        source_hash,
        title,
        content,
        method,
        ..
    }) = event
    {
        assert_eq!(destination_hash, peers.bob.delivery_dest_hash);
        assert_eq!(source_hash, alice_src_hash);
        assert_eq!(title, b"Hello");
        assert_eq!(content, b"World");
        assert_eq!(method, DeliveryMethod::Opportunistic);
    } else {
        panic!("Expected MessageDelivered event");
    }

    peers.shutdown();
}

// ============================================================
// Test D: Message deduplication
// ============================================================

#[test]
fn test_message_deduplication() {
    let peers = setup_two_lxmf_peers_announced(None, None);

    // Pack a message from Alice to Bob
    let pack_result = pack_test_message(
        &peers.alice.identity,
        &peers.bob.delivery_dest_hash,
        b"Dedup",
        b"Test",
    );

    // Deliver the same message twice directly into Bob's router
    {
        let mut r = peers.bob.router.lock().unwrap();
        r.lxmf_delivery(
            &pack_result.packed,
            false,
            ENCRYPTION_DESCRIPTION_UNENCRYPTED,
            DeliveryMethod::Opportunistic,
        );
        r.lxmf_delivery(
            &pack_result.packed,
            false,
            ENCRYPTION_DESCRIPTION_UNENCRYPTED,
            DeliveryMethod::Opportunistic,
        );
    }

    // First delivery should succeed
    let first = wait_for_message_delivery(&peers.bob.rx, Duration::from_secs(2));
    assert!(first.is_some(), "First delivery should fire callback");

    // Second delivery should be silently dropped (dedup)
    let second = wait_for_message_delivery(&peers.bob.rx, Duration::from_secs(2));
    assert!(
        second.is_none(),
        "Second delivery of same message should be dropped (dedup)"
    );

    peers.shutdown();
}

// ============================================================
// Test E: Stamp cost propagation via announce
// ============================================================

#[test]
fn test_stamp_cost_propagation_via_announce() {
    let peers = setup_two_lxmf_peers(Some(4), Some(16));

    // Bob announces with stamp_cost=16
    {
        let r = peers.bob.router.lock().unwrap();
        r.announce_delivery(&peers.bob.identity);
    }

    // Alice should receive Bob's announce and store stamp_cost=16
    let bob_ann = wait_for_announce(
        &peers.alice.rx,
        &peers.bob.delivery_dest_hash,
        DEFAULT_TIMEOUT,
    );
    assert!(bob_ann.is_some(), "Alice should receive Bob's announce");

    // Alice announces with stamp_cost=4
    {
        let r = peers.alice.router.lock().unwrap();
        r.announce_delivery(&peers.alice.identity);
    }

    // Bob should receive Alice's announce and store stamp_cost=4
    let alice_ann = wait_for_announce(
        &peers.bob.rx,
        &peers.alice.delivery_dest_hash,
        DEFAULT_TIMEOUT,
    );
    assert!(alice_ann.is_some(), "Bob should receive Alice's announce");

    // Allow announce processing
    thread::sleep(Duration::from_millis(500));

    // Verify stamp costs
    {
        let r = peers.alice.router.lock().unwrap();
        let cost = r.get_stamp_cost(&peers.bob.delivery_dest_hash);
        assert_eq!(
            cost,
            Some(lxmf_core::stamp::StampCost::from_whole(16)),
            "Alice should store Bob's stamp cost of 16, got {:?}",
            cost
        );
    }

    {
        let r = peers.bob.router.lock().unwrap();
        let cost = r.get_stamp_cost(&peers.alice.delivery_dest_hash);
        assert_eq!(
            cost,
            Some(lxmf_core::stamp::StampCost::from_whole(4)),
            "Bob should store Alice's stamp cost of 4, got {:?}",
            cost
        );
    }

    peers.shutdown();
}

// ============================================================
// Test F: Direct delivery via link
// ============================================================

#[test]
fn test_direct_delivery_via_link() {
    let peers = setup_two_lxmf_peers_announced(None, None);

    let pack_result = pack_test_message(
        &peers.alice.identity,
        &peers.bob.delivery_dest_hash,
        b"Direct",
        b"LinkMsg",
    );

    let alice_src_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(peers.alice.identity.hash()),
    );

    // Queue as OutboundMessage with Direct method
    {
        let mut r = peers.alice.router.lock().unwrap();
        let msg = OutboundMessage::new(
            peers.bob.delivery_dest_hash,
            alice_src_hash,
            pack_result.packed,
            pack_result.message_hash,
            DeliveryMethod::Direct,
        );
        r.handle_outbound(msg).unwrap();
    }

    // Trigger outbound processing outside the router lock to avoid
    // deadlock (jobs → process_outbound → node RPCs).
    {
        peers.alice.router.lock().unwrap().jobs();
    }

    // Bob should receive via direct link delivery. Link establishment happens
    // asynchronously, so keep driving Alice's router jobs until the link is
    // promoted and the queued message is sent.
    let deadline = Instant::now() + DEFAULT_TIMEOUT;
    let mut event = None;
    while Instant::now() < deadline {
        {
            peers.alice.router.lock().unwrap().jobs();
        }
        if let Some(delivery) = wait_for_message_delivery(&peers.bob.rx, Duration::from_millis(200))
        {
            event = Some(delivery);
            break;
        }
    }
    assert!(
        event.is_some(),
        "Bob should receive the message via direct link"
    );

    if let Some(LxmfTestEvent::MessageDelivered {
        method,
        title,
        content,
        ..
    }) = event
    {
        assert_eq!(method, DeliveryMethod::Direct);
        assert_eq!(title, b"Direct");
        assert_eq!(content, b"LinkMsg");
    }

    // Delivered messages leave the queue, retaining the destination's
    // announce data, on the next outbound pass (as upstream does).
    peers.alice.router.lock().unwrap().jobs();
    assert!(peers.alice.router.lock().unwrap().outbound.is_empty());

    assert!(
        wait_for_known_destination_retained(
            &peers.alice.node,
            &peers.bob.delivery_dest_hash,
            DEFAULT_TIMEOUT
        ),
        "successful outbound delivery should retain Bob's announce data"
    );

    peers.shutdown();
}

// ============================================================
// Test F: Download from a propagation node
// ============================================================

/// Tests the order of a download from a propagation node, through a real
/// network, as upstream `message_get_response`:
///
/// A node holds two messages for the client. While the client's delivery
/// callback runs for either of them, the client has not acknowledged the
/// batch (the node still holds both), has not saved their transient IDs and
/// does not report the download complete, so a client that stops inside its
/// callback finds the messages again. All three follow once the callbacks
/// returned.
#[test]
fn test_downloaded_messages_are_delivered_before_acknowledgement() {
    let port = find_free_port();
    let (transport_node, transport_dir) = start_transport_node(port);
    thread::sleep(Duration::from_millis(500));

    // Create propagation node
    let prop_dir = temp_dir("prop_node_download");
    let prop_identity = Identity::new(&mut rns_crypto::OsRng);
    let prop_router = Arc::new(Mutex::new(LxmRouter::new(
        Identity::from_private_key(&prop_identity.get_private_key().unwrap()),
        RouterConfig {
            storagepath: prop_dir.clone(),
            ..RouterConfig::default()
        },
    )));
    let (prop_tx, _prop_rx) = mpsc::channel::<LxmfTestEvent>();
    let prop_test_cb = LxmfTestCallbacks::new(LxmfCallbacks::new(prop_router.clone()), prop_tx);
    let prop_node = Arc::new(start_client_node(port, Box::new(prop_test_cb)));
    LxmRouter::register_propagation_request_handlers(&prop_node, prop_router.clone())
        .expect("propagation request handlers");
    let propagation_dest_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["propagation"],
        Some(prop_identity.hash()),
    );
    {
        let mut r = prop_router.lock().unwrap();
        r.set_node(prop_node.clone());
        r.enable_propagation();
    }

    // Create client node
    let client = setup_lxmf_node(port, "client_download", None);
    thread::sleep(Duration::from_millis(SETTLE_MS));
    {
        let r = prop_router.lock().unwrap();
        r.announce_propagation_node_now();
    }
    assert!(
        wait_for_announce(&client.rx, &propagation_dest_hash, DEFAULT_TIMEOUT).is_some(),
        "Client should receive propagation node announce"
    );

    // The node holds two messages for the client
    let sender_identity = Identity::new(&mut rns_crypto::OsRng);
    let mut transient_ids = Vec::new();
    for content in [&b"first"[..], &b"second"[..]] {
        let packed = pack_test_message(
            &sender_identity,
            &client.delivery_dest_hash,
            b"Stored",
            content,
        )
        .packed;
        let mut lxmf_data = packed[..DESTINATION_LENGTH].to_vec();
        lxmf_data.extend(
            client
                .identity
                .encrypt(&packed[DESTINATION_LENGTH..], &mut rns_crypto::OsRng)
                .expect("encrypt for client"),
        );
        let transient_id = prop_router.lock().unwrap().lxmf_propagation(
            &lxmf_data,
            lxmf_core::stamp::StampValue::from_whole(8),
            Some(&[0x5A; STAMP_SIZE]),
            None,
        );
        transient_ids.push(transient_id.expect("node should store the message"));
    }
    let stored_on_node = || {
        let r = prop_router.lock().unwrap();
        r.propagation_store.message_count()
    };
    assert_eq!(stored_on_node(), 2);

    // A delivery callback that holds each delivery until released
    let (delivered_tx, delivered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    {
        let mut r = client.router.lock().unwrap();
        r.set_delivery_callback(Box::new(move |delivery: &LxmDelivery| {
            let _ = delivered_tx.send(delivery.content.clone());
            let _ = release_rx.recv_timeout(DEFAULT_TIMEOUT);
        }));
        r.set_outbound_propagation_node(propagation_dest_hash);
        r.request_messages_from_propagation_node(None);
    }
    let saved_transient_ids = || {
        let paths = lxmf_rs::storage::StoragePaths::new(&client.temp_dir);
        lxmf_rs::storage::load_transient_ids(&paths.local_deliveries)
    };

    let mut delivered = Vec::new();
    for _ in 0..2 {
        let content = delivered_rx
            .recv_timeout(DEFAULT_TIMEOUT)
            .expect("Downloaded message should reach the delivery callback");
        delivered.push(content);

        // The callback is running. Give an acknowledgement sent too early
        // time to reach the node.
        thread::sleep(Duration::from_millis(500));
        assert_eq!(
            stored_on_node(),
            2,
            "Messages should not be acknowledged while a delivery callback runs"
        );
        assert_ne!(
            client.router.lock().unwrap().propagation_transfer_state,
            PropagationTransferState::Complete,
            "Download should not be complete while a delivery callback runs"
        );
        let saved = saved_transient_ids();
        assert!(
            !transient_ids.iter().any(|id| saved.contains_key(id)),
            "Transient IDs should not be saved while a delivery callback runs"
        );
        release_tx.send(()).unwrap();
    }
    delivered.sort();
    assert_eq!(delivered, [b"first".to_vec(), b"second".to_vec()]);

    // With both callbacks done, the batch is acknowledged and complete
    let deadline = Instant::now() + DEFAULT_TIMEOUT;
    while Instant::now() < deadline
        && (stored_on_node() > 0
            || client.router.lock().unwrap().propagation_transfer_state
                != PropagationTransferState::Complete)
    {
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        stored_on_node(),
        0,
        "Node should delete the acknowledged messages"
    );
    {
        let r = client.router.lock().unwrap();
        assert_eq!(
            r.propagation_transfer_state,
            PropagationTransferState::Complete
        );
        assert_eq!(r.propagation_transfer_last_result, Some(2));
        assert_eq!(r.propagation_transfer_last_duplicates, 0);
    }
    let saved = saved_transient_ids();
    assert!(
        transient_ids.iter().all(|id| saved.contains_key(id)),
        "Transient IDs should be saved once the download completed"
    );

    // Cleanup
    client.shutdown();
    {
        if let Ok(mut r) = prop_router.lock() {
            r.exit_handler();
        }
    }
    match Arc::try_unwrap(prop_node) {
        Ok(node) => node.shutdown(),
        Err(node) => {
            let _ = node.event_sender().send(Event::Shutdown);
            thread::sleep(Duration::from_millis(100));
        }
    }
    transport_node.shutdown();
    let _ = fs::remove_dir_all(&transport_dir);
    let _ = fs::remove_dir_all(&prop_dir);
}
