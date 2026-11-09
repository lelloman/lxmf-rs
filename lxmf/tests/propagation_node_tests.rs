//! Propagation node behaviour: client uploads, static-only admission with
//! the resource app flag, client packet proofs, peer path backoff and
//! peering key generation.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use lxmf_core::constants::*;
use lxmf_core::stamp::{StampCost, StampValue};
use lxmf_rs::outbound::{LinkCreation, OutboundNetwork, SendFailed, DEFAULT_PER_HOP_TIMEOUT};
use lxmf_rs::peer::LxmPeer;
use lxmf_rs::router::{LxmRouter, LxmfCallbacks, RouterConfig};
use rns_core::msgpack::{pack, Value};
use rns_core::types::{DestHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_net::driver::Callbacks;

static NEXT_DIR: AtomicUsize = AtomicUsize::new(1);

fn test_router(name: &str) -> (LxmRouter, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "lxmf_pn_{}_{}_{}",
        name,
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = RouterConfig {
        storagepath: dir.clone(),
        propagation_cost: StampCost::ZERO,
        propagation_cost_flexibility: StampCost::ZERO,
        ..RouterConfig::default()
    };
    let mut router = LxmRouter::new(Identity::new(&mut rns_crypto::OsRng), config);
    router.propagation_node = true;
    (router, dir)
}

/// A propagation transient: LXMF data for `dest` plus a stamp, valid at
/// cost zero.
fn transient(dest: u8, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![dest; DESTINATION_LENGTH];
    data.extend(std::iter::repeat_n(
        0x11u8,
        LXMF_OVERHEAD - DESTINATION_LENGTH,
    ));
    data.extend_from_slice(payload);
    data.extend_from_slice(&[0x5A; STAMP_SIZE]);
    data
}

fn batch(transients: Vec<Vec<u8>>) -> Vec<u8> {
    pack(&Value::Array(vec![
        Value::Float(1_700_000_000.0),
        Value::Array(transients.into_iter().map(Value::Bin).collect()),
    ]))
}

fn wait_until(router: &Arc<Mutex<LxmRouter>>, predicate: impl Fn(&LxmRouter) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if predicate(&router.lock().unwrap()) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn client_resources_are_accepted_on_propagation_links_only() {
    let (mut router, dir) = test_router("client_accept");
    let link = [0x01; 16];
    assert!(!router.accept_inbound_propagation_resource(link, 1_000, false));

    router.active_propagation_links.push(link);
    assert!(router.accept_inbound_propagation_resource(link, 1_000, false));
    router.config.sync_limit = 1;
    assert!(!router.accept_inbound_propagation_resource(link, 1_001, false));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn static_only_nodes_accept_static_peers_and_app_flagged_client_resources() {
    let (mut router, dir) = test_router("static_only");
    router.config.from_static_only = true;
    let link = [0x02; 16];
    router.active_propagation_links.push(link);

    // Unidentified clients need the app flag (LXMF 1.3 client resources).
    assert!(!router.accept_inbound_propagation_resource(link, 100, false));
    assert!(router.accept_inbound_propagation_resource(link, 100, true));

    // Identified remotes are admitted when they are static peers.
    let remote_identity = [0x33; 16];
    router.link_remote_identities.insert(link, remote_identity);
    assert!(!router.accept_inbound_propagation_resource(link, 100, false));
    let remote_pn =
        rns_core::destination::destination_hash(APP_NAME, &["propagation"], Some(&remote_identity));
    router.config.static_peers.push(remote_pn);
    assert!(router.accept_inbound_propagation_resource(link, 100, false));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn client_upload_resource_is_validated_stored_and_counted() {
    let (mut router, dir) = test_router("client_upload");
    let link = [0x03; 16];
    router.active_propagation_links.push(link);
    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());

    callbacks.on_resource_received(LinkId(link), batch(vec![transient(0xA1, b"one")]), None);

    assert!(wait_until(&router, |r| r.propagation_store.message_count() == 1));
    let guard = router.lock().unwrap();
    assert_eq!(
        guard.propagation_store.client_propagation_messages_received,
        1
    );
    assert_eq!(guard.propagation_store.unpeered_propagation_incoming, 0);
    let entry = guard.propagation_store.entries.values().next().unwrap();
    assert!(entry.stamp_value > StampValue::ZERO);
    drop(guard);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn unidentified_multi_message_transfers_are_ignored() {
    let (mut router, dir) = test_router("multi_without_key");
    let link = [0x04; 16];
    router.active_propagation_links.push(link);
    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());

    callbacks.on_resource_received(
        LinkId(link),
        batch(vec![transient(0xA1, b"one"), transient(0xA2, b"two")]),
        None,
    );
    std::thread::sleep(Duration::from_millis(100));

    let guard = router.lock().unwrap();
    assert_eq!(guard.propagation_store.message_count(), 0);
    assert_eq!(
        guard.propagation_store.client_propagation_messages_received,
        0
    );
    drop(guard);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn client_propagation_packets_are_proven_only_when_valid() {
    let (mut router, dir) = test_router("packet_proof");
    let link = [0x05; 16];
    router.active_propagation_links.push(link);
    let propagation_dest = router.propagation_dest_hash;
    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());

    callbacks.on_link_data(LinkId(link), 0, batch(vec![transient(0xB1, b"packet")]));
    assert!(callbacks.on_proof_requested(DestHash(propagation_dest), PacketHash([0; 32])));
    assert!(
        !callbacks.on_proof_requested(DestHash(propagation_dest), PacketHash([0; 32])),
        "each validation result proves one packet"
    );
    assert_eq!(router.lock().unwrap().propagation_store.message_count(), 1);
    assert_eq!(
        router
            .lock()
            .unwrap()
            .propagation_store
            .client_propagation_messages_received,
        1
    );

    // A stamp far below the required cost is rejected and not proven.
    router.lock().unwrap().config.propagation_cost = StampCost::from_whole(60);
    callbacks.on_link_data(LinkId(link), 0, batch(vec![transient(0xB2, b"cheap")]));
    assert!(!callbacks.on_proof_requested(DestHash(propagation_dest), PacketHash([0; 32])));
    assert_eq!(router.lock().unwrap().propagation_store.message_count(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn propagated_messages_for_us_are_delivered_locally_once() {
    let (mut router, dir) = test_router("local_delivery");
    let delivery_hash = [0xC0; 16];
    router.delivery_dest_hash = Some(delivery_hash);
    let data = transient(0xC0, b"for me");
    let lxm = &data[..data.len() - STAMP_SIZE];

    assert!(router
        .lxmf_propagation(lxm, StampValue::from_whole(8), None, None)
        .is_some());
    assert_eq!(router.propagation_store.message_count(), 0, "not stored");
    assert!(
        router
            .lxmf_propagation(lxm, StampValue::from_whole(8), None, None)
            .is_none(),
        "duplicates are filtered"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[derive(Default)]
struct PathlessNetwork {
    path_requests: Mutex<Vec<[u8; 16]>>,
    links: Mutex<Vec<[u8; 16]>>,
    has_path: Mutex<bool>,
}

impl OutboundNetwork for PathlessNetwork {
    fn has_path(&self, _dest_hash: &[u8; 16]) -> bool {
        *self.has_path.lock().unwrap()
    }
    fn request_path(&self, dest_hash: &[u8; 16]) {
        self.path_requests.lock().unwrap().push(*dest_hash);
    }
    fn drop_path(&self, _dest_hash: &[u8; 16]) {}
    fn medium_path_timeout(&self) -> f64 {
        0.0
    }
    fn lowest_interface_bitrate(&self) -> Option<u64> {
        None
    }
    fn first_hop_timeout(&self, _dest_hash: &[u8; 16]) -> f64 {
        DEFAULT_PER_HOP_TIMEOUT
    }
    fn recall_public_key(&self, _dest_hash: &[u8; 16]) -> Option<[u8; 64]> {
        Some([0x42; 64])
    }
    fn send_opportunistic(
        &self,
        _dest_hash: &[u8; 16],
        _public_key: &[u8; 64],
        _data: &[u8],
    ) -> Result<[u8; 32], SendFailed> {
        Err(SendFailed)
    }
    fn send_link_packet(&self, _link_id: [u8; 16], _data: Vec<u8>) -> Result<(), SendFailed> {
        Err(SendFailed)
    }
    fn send_link_resource(
        &self,
        _link_id: [u8; 16],
        _data: Vec<u8>,
        _auto_compress: bool,
        _app_flag: bool,
    ) -> Result<(), SendFailed> {
        Err(SendFailed)
    }
    fn begin_link(
        &self,
        dest_hash: [u8; 16],
        _sig_pub: [u8; 32],
        _results: mpsc::Sender<LinkCreation>,
    ) {
        self.links.lock().unwrap().push(dest_hash);
    }
    fn retain_destination(&self, _dest_hash: [u8; 16]) {}
}

fn sync_ready_peer(hash: [u8; 16]) -> LxmPeer {
    let mut peer = LxmPeer::new(hash);
    peer.propagation_stamp_cost = Some(StampCost::from_whole(16));
    peer.propagation_stamp_cost_flexibility = Some(StampCost::from_whole(3));
    peer.peering_cost = Some(StampCost::from_whole(4));
    peer.peering_key = Some((vec![0; 32], StampValue::from_whole(4)));
    peer.unhandled_ids.push([0x77; 32]);
    peer
}

#[test]
fn unanswered_peer_path_requests_back_off() {
    let (mut router, dir) = test_router("peer_backoff");
    let peer_hash = [0xD1; 16];
    router.peers.insert(peer_hash, sync_ready_peer(peer_hash));
    let network = PathlessNetwork::default();
    let now = lxmf_rs::router::now_timestamp();

    router.ensure_peer_sync_links_at(&network, now);
    assert_eq!(*network.path_requests.lock().unwrap(), vec![peer_hash]);
    assert_eq!(router.peers[&peer_hash].sync_backoff, 0.0);

    // Still no path after the grace period: back off and mark not alive.
    router.ensure_peer_sync_links_at(&network, now + PATH_REQUEST_GRACE + 1.0);
    let peer = &router.peers[&peer_hash];
    assert_eq!(peer.sync_backoff, SYNC_BACKOFF_STEP as f64);
    assert!(!peer.alive);
    assert!(peer.next_sync_attempt > now);

    // With a path, a link is established once the backoff has elapsed
    // (peer sync checks read the wall clock, so expire it directly).
    *network.has_path.lock().unwrap() = true;
    router.peers.get_mut(&peer_hash).unwrap().next_sync_attempt = 0.0;
    router.ensure_peer_sync_links_at(&network, lxmf_rs::router::now_timestamp());
    assert_eq!(*network.links.lock().unwrap(), vec![peer_hash]);
    assert_eq!(router.peers[&peer_hash].state, PeerState::LinkEstablishing);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn missing_peering_keys_are_generated_in_the_background() {
    let (mut router, dir) = test_router("peering_key");
    let peer_hash = [0xE1; 16];
    let mut peer = sync_ready_peer(peer_hash);
    peer.peering_key = None;
    peer.peering_cost = Some(StampCost::from_f64(3.5));
    router.peers.insert(peer_hash, peer);
    router.identity_hash_cache.insert(peer_hash, [0xE2; 16]);
    let network = PathlessNetwork::default();

    router.ensure_peer_sync_links_at(&network, lxmf_rs::router::now_timestamp());
    assert!(
        network.links.lock().unwrap().is_empty(),
        "no sync without a key"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    while router.peers[&peer_hash].peering_key.is_none() {
        assert!(Instant::now() < deadline, "peering key was not generated");
        std::thread::sleep(Duration::from_millis(20));
        router.drain_peering_keys();
    }

    // The key validates the way the remote node checks it: a stamp over the
    // remote's identity hash followed by ours.
    let (key, value) = router.peers[&peer_hash].peering_key.clone().unwrap();
    assert!(value.meets(StampCost::from_f64(3.5)));
    let mut peering_id = vec![0xE2; 16];
    peering_id.extend_from_slice(router.identity.hash());
    assert!(lxmf_core::stamp::validate_peering_key(
        &peering_id,
        &key,
        StampCost::from_f64(3.5)
    ));
    let _ = std::fs::remove_dir_all(dir);
}
