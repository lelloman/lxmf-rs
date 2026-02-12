//! End-to-end tests for the LXMF router.
//!
//! Spins up real RNS nodes on localhost TCP, wires LxmRouter + LxmfCallbacks,
//! and validates message delivery, announce handling, and deduplication.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fs, thread};

use lxmf::router::{LxmDelivery, LxmRouter, LxmfCallbacks, OutboundMessage, RouterConfig};
use lxmf_core::constants::*;
use lxmf_core::message;
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_net::destination::{AnnouncedIdentity, Destination};
use rns_net::driver::Callbacks;
use rns_net::interface::tcp::TcpClientConfig;
use rns_net::interface::tcp_server::TcpServerConfig;
use rns_net::node::{InterfaceConfig, InterfaceVariant, NodeConfig, RnsNode};
use rns_net::{Event, InterfaceId, ManagementConfig};

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

    fn on_link_established(&mut self, link_id: LinkId, dest_hash: DestHash, rtt: f64, is_initiator: bool) {
        let _ = self.tx.send(LxmfTestEvent::LinkEstablished {
            link_id: link_id.0,
            rtt,
            is_initiator,
        });
        self.inner.on_link_established(link_id, dest_hash, rtt, is_initiator);
    }

    fn on_link_closed(
        &mut self,
        link_id: LinkId,
        reason: Option<rns_core::link::TeardownReason>,
    ) {
        let _ = self.tx.send(LxmfTestEvent::LinkClosed {
            link_id: link_id.0,
        });
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

fn find_free_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("lxmf_e2e_{}_{}", name, std::process::id()));
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
    wait_for_event(rx, timeout, move |e| {
        matches!(e, LxmfTestEvent::Announce(a) if a.dest_hash.0 == hash)
    })
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
fn wait_for_proof(
    rx: &mpsc::Receiver<LxmfTestEvent>,
    timeout: Duration,
) -> Option<LxmfTestEvent> {
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
            variant: InterfaceVariant::TcpServer(TcpServerConfig {
                name: "e2e_server".into(),
                listen_ip: "127.0.0.1".into(),
                listen_port: port,
                interface_id: InterfaceId(1),
            }),
            mode: rns_core::constants::MODE_FULL,
            ifac: None,
        }],
        share_instance: false,
        rpc_port: 0,
        cache_dir: Some(dir.clone()),
        management: ManagementConfig::default(),
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
            variant: InterfaceVariant::TcpClient(TcpClientConfig {
                name: "e2e_client".into(),
                target_host: "127.0.0.1".into(),
                target_port: port,
                interface_id: InterfaceId(1),
                ..TcpClientConfig::default()
            }),
            mode: rns_core::constants::MODE_FULL,
            ifac: None,
        }],
        share_instance: false,
        rpc_port: 0,
        cache_dir: None,
        management: ManagementConfig::default(),
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
    let delivery_dest_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(identity.hash()),
    );

    {
        let mut r = router.lock().unwrap();
        r.set_node(node.clone());
        r.register_delivery_identity(
            &identity,
            stamp_cost,
            Some(name.to_string()),
        );
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

fn setup_two_lxmf_peers(
    alice_stamp_cost: Option<u8>,
    bob_stamp_cost: Option<u8>,
) -> TwoPeers {
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

    // Bob announces
    {
        let r = peers.bob.router.lock().unwrap();
        r.announce_delivery(&peers.bob.identity);
    }

    // Wait for Bob to receive Alice's announce
    let alice_announce = wait_for_announce(
        &peers.bob.rx,
        &peers.alice.delivery_dest_hash,
        DEFAULT_TIMEOUT,
    );
    assert!(
        alice_announce.is_some(),
        "Bob should receive Alice's announce"
    );

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
            Some(8),
            "Bob's router should store Alice's stamp cost of 8, got {:?}",
            cost
        );
    }

    alice.shutdown();
    bob.shutdown();
    transport_node.shutdown();
    let _ = fs::remove_dir_all(&transport_dir);
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
        r.announce_propagation_node();
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
        peers.alice.node.has_path(&DestHash(peers.bob.delivery_dest_hash)).unwrap(),
        "Alice should have Bob's path from the announce exchange"
    );

    let announced = peers.alice.node
        .recall_identity(&DestHash(peers.bob.delivery_dest_hash))
        .unwrap()
        .expect("Alice should have Bob's announced identity");

    let dest = Destination::single_out(APP_NAME, &["delivery"], &announced);
    let lxmf_payload = &pack_result.packed[DESTINATION_LENGTH..];
    let _packet_hash = peers.alice.node
        .send_packet(&dest, lxmf_payload)
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

    // Alice announces with stamp_cost=4
    {
        let r = peers.alice.router.lock().unwrap();
        r.announce_delivery(&peers.alice.identity);
    }

    // Alice should receive Bob's announce and store stamp_cost=16
    let bob_ann = wait_for_announce(
        &peers.alice.rx,
        &peers.bob.delivery_dest_hash,
        DEFAULT_TIMEOUT,
    );
    assert!(
        bob_ann.is_some(),
        "Alice should receive Bob's announce"
    );

    // Bob should receive Alice's announce and store stamp_cost=4
    let alice_ann = wait_for_announce(
        &peers.bob.rx,
        &peers.alice.delivery_dest_hash,
        DEFAULT_TIMEOUT,
    );
    assert!(
        alice_ann.is_some(),
        "Bob should receive Alice's announce"
    );

    // Allow announce processing
    thread::sleep(Duration::from_millis(500));

    // Verify stamp costs
    {
        let r = peers.alice.router.lock().unwrap();
        let cost = r.get_stamp_cost(&peers.bob.delivery_dest_hash);
        assert_eq!(
            cost,
            Some(16),
            "Alice should store Bob's stamp cost of 16, got {:?}",
            cost
        );
    }

    {
        let r = peers.bob.router.lock().unwrap();
        let cost = r.get_stamp_cost(&peers.alice.delivery_dest_hash);
        assert_eq!(
            cost,
            Some(4),
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
        let msg = OutboundMessage {
            destination_hash: peers.bob.delivery_dest_hash,
            source_hash: alice_src_hash,
            packed: pack_result.packed,
            message_hash: pack_result.message_hash,
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

    // Trigger outbound processing outside the router lock to avoid
    // deadlock (jobs → process_outbound → node RPCs).
    {
        peers.alice.router.lock().unwrap().jobs();
    }

    // Bob should receive via direct link delivery
    let event = wait_for_message_delivery(&peers.bob.rx, DEFAULT_TIMEOUT);
    assert!(
        event.is_some(),
        "Bob should receive the message via direct link"
    );

    if let Some(LxmfTestEvent::MessageDelivered {
        method, title, content, ..
    }) = event
    {
        assert_eq!(method, DeliveryMethod::Direct);
        assert_eq!(title, b"Direct");
        assert_eq!(content, b"LinkMsg");
    }

    peers.shutdown();
}
