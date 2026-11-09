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
    // Heard recently: peers unheard for MAX_UNREACHABLE are culled.
    peer.last_heard = lxmf_rs::router::now_timestamp();
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

fn pn_announced(identity_hash: [u8; 16], hops: u8) -> rns_net::destination::AnnouncedIdentity {
    let dest_hash =
        rns_core::destination::destination_hash(APP_NAME, &["propagation"], Some(&identity_hash));
    let app_data =
        lxmf_core::announce::build_pn_announce_data(&lxmf_core::announce::PnAnnounceParams {
            node_timebase: 1_700_000_000,
            propagation_enabled: true,
            propagation_transfer_limit: 256,
            propagation_sync_limit: 10240,
            propagation_stamp_cost: StampCost::from_whole(16),
            propagation_stamp_cost_flexibility: StampCost::from_whole(3),
            peering_cost: StampCost::from_whole(18),
            implementation: None,
            name: None,
        });
    rns_net::destination::AnnouncedIdentity {
        dest_hash: DestHash(dest_hash),
        identity_hash: rns_core::types::IdentityHash(identity_hash),
        public_key: [0x42; 64],
        app_data: Some(app_data),
        hops,
        received_at: 0.0,
        receiving_interface: rns_net::InterfaceId(1),
        rssi: None,
        snr: None,
    }
}

#[test]
fn incoming_sync_from_announced_node_auto_peers() {
    let (router, dir) = test_router("autopeer_incoming");
    let remote_identity = [0xF1; 16];
    let link = [0xF2; 16];
    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());

    let announced = pn_announced(remote_identity, 1);
    let remote_hash = announced.dest_hash.0;
    callbacks.on_announce(announced);
    {
        let mut r = router.lock().unwrap();
        assert!(r.peers.contains_key(&remote_hash));
        // Unpeered since (e.g. rotated out); it syncs to us anyway.
        r.unpeer(&remote_hash).unwrap();
        r.active_propagation_links.push(link);
        r.link_remote_identities.insert(link, remote_identity);
    }

    callbacks.on_resource_received(LinkId(link), batch(vec![transient(0xA9, b"synced")]), None);

    assert!(wait_until(&router, |r| r.propagation_store.message_count() == 1));
    let r = router.lock().unwrap();
    let peer = r
        .peers
        .get(&remote_hash)
        .expect("auto-peered via incoming sync");
    assert_eq!(peer.incoming, 1, "the transfer counts as peer traffic");
    assert_eq!(r.propagation_store.unpeered_propagation_incoming, 0);
    drop(r);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn incoming_sync_does_not_auto_peer_distant_or_unannounced_nodes() {
    let (mut router, dir) = test_router("autopeer_limits");
    assert!(
        !router.autopeer_from_incoming_sync([0xF3; 16]),
        "never announced"
    );

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    let announced = pn_announced([0xF4; 16], AUTOPEER_MAXDEPTH + 1);
    let remote_hash = announced.dest_hash.0;
    callbacks.on_announce(announced);

    let mut r = router.lock().unwrap();
    assert!(
        !r.autopeer_from_incoming_sync(remote_hash),
        "beyond autopeer depth"
    );
    assert!(!r.peers.contains_key(&remote_hash));
    r.config.autopeer = false;
    assert!(!r.autopeer_from_incoming_sync(remote_hash));
    drop(r);
    let _ = std::fs::remove_dir_all(dir);
}

fn decode(bytes: &[u8]) -> Value {
    rns_core::msgpack::unpack_exact(bytes).unwrap()
}

#[test]
fn message_get_lists_serves_and_purges_client_messages() {
    let (mut router, dir) = test_router("message_get");
    let client_identity = [0x61; 16];
    let client =
        rns_core::destination::destination_hash(APP_NAME, &["delivery"], Some(&client_identity));
    let mut ids = Vec::new();
    for (i, size) in [300usize, 100, 200].iter().enumerate() {
        let mut data = client.to_vec();
        data.extend(std::iter::repeat_n(
            i as u8,
            LXMF_OVERHEAD - DESTINATION_LENGTH + size,
        ));
        ids.push(
            router
                .propagation_store
                .store_message(
                    &data,
                    Some(&[0x5A; STAMP_SIZE]),
                    StampValue::from_whole(8),
                    None,
                )
                .unwrap(),
        );
    }
    // Someone else's message is never listed or served.
    let other = transient(0x99, b"not yours");
    router
        .lxmf_propagation(
            &other[..other.len() - STAMP_SIZE],
            StampValue::from_whole(8),
            Some(&other[other.len() - STAMP_SIZE..]),
            None,
        )
        .unwrap();

    let list = decode(&router.handle_message_get(
        Some(client_identity),
        &pack(&Value::Array(vec![Value::Nil, Value::Nil])),
    ));
    let listed: Vec<Vec<u8>> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_bin().unwrap().to_vec())
        .collect();
    assert_eq!(
        listed,
        vec![ids[1].to_vec(), ids[2].to_vec(), ids[0].to_vec()],
        "smallest first"
    );

    let request = pack(&Value::Array(vec![
        Value::Array(vec![Value::Bin(ids[1].to_vec())]),
        Value::Array(vec![Value::Bin(ids[0].to_vec())]),
        Value::Float(100.0),
    ]));
    let served = decode(&router.handle_message_get(Some(client_identity), &request));
    let served = served.as_array().unwrap();
    assert_eq!(served.len(), 1);
    assert_eq!(
        rns_crypto::sha256::sha256(served[0].as_bin().unwrap()),
        ids[1],
        "served without its stamp"
    );
    assert!(
        !router.propagation_store.entries.contains_key(&ids[0]),
        "haves are purged"
    );
    assert_eq!(
        router.propagation_store.client_propagation_messages_served,
        1
    );

    assert_eq!(
        router.handle_message_get(None, &pack(&Value::Array(vec![Value::Nil, Value::Nil]))),
        lxmf_rs::router::error_response(PeerError::NoIdentity)
    );
    router.auth_required = true;
    assert_eq!(
        router.handle_message_get(
            Some(client_identity),
            &pack(&Value::Array(vec![Value::Nil, Value::Nil]))
        ),
        lxmf_rs::router::error_response(PeerError::NoAccess)
    );
    router.allowed_list.push(client_identity);
    assert_ne!(
        router.handle_message_get(
            Some(client_identity),
            &pack(&Value::Array(vec![Value::Nil, Value::Nil]))
        ),
        lxmf_rs::router::error_response(PeerError::NoAccess)
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn control_access_and_stats_follow_upstream() {
    let (mut router, dir) = test_router("control");
    router.enable_propagation();
    let own = *router.identity.hash();
    assert_eq!(router.check_control_access(Some(&own)), Ok(()));
    assert_eq!(
        router.check_control_access(None),
        Err(PeerError::NoIdentity)
    );
    assert_eq!(
        router.check_control_access(Some(&[0x01; 16])),
        Err(PeerError::NoAccess)
    );
    router.control_allowed_list.push([0x01; 16]);
    assert_eq!(router.check_control_access(Some(&[0x01; 16])), Ok(()));

    let peer_hash = [0xA7; 16];
    router.peers.insert(peer_hash, LxmPeer::new(peer_hash));
    let stats = router.compile_stats();
    let get = |map: &Value, key: &str| -> Value {
        map.as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("missing {key}"))
    };
    for key in [
        "identity_hash",
        "destination_hash",
        "uptime",
        "delivery_limit",
        "propagation_limit",
        "sync_limit",
        "target_stamp_cost",
        "stamp_cost_flexibility",
        "peering_cost",
        "max_peering_cost",
        "autopeer_maxdepth",
        "from_static_only",
        "messagestore",
        "clients",
        "unpeered_propagation_incoming",
        "unpeered_propagation_rx_bytes",
        "static_peers",
        "discovered_peers",
        "total_peers",
        "max_peers",
        "peers",
    ] {
        get(&stats, key);
    }
    let peers = get(&stats, "peers");
    let peer = &peers.as_map().unwrap()[0].1;
    for key in [
        "type",
        "state",
        "alive",
        "name",
        "last_heard",
        "next_sync_attempt",
        "last_sync_attempt",
        "sync_backoff",
        "peering_timebase",
        "ler",
        "str",
        "transfer_limit",
        "sync_limit",
        "target_stamp_cost",
        "stamp_cost_flexibility",
        "peering_cost",
        "peering_key",
        "network_distance",
        "rx_bytes",
        "tx_bytes",
        "acceptance_rate",
        "messages",
    ] {
        get(peer, key);
    }
    assert_eq!(
        get(peer, "network_distance").as_uint(),
        Some(128),
        "unknown distance is PATHFINDER_M"
    );
    assert_eq!(get(peer, "type").as_str(), Some("discovered"));
    router.propagation_node = false;
    assert!(router.compile_stats().is_nil());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sync_peers_syncs_one_peer_per_cycle_and_culls_unreachable_peers() {
    let (mut router, dir) = test_router("sync_peers");
    let network = PathlessNetwork::default();
    *network.has_path.lock().unwrap() = true;
    for i in 0..3u8 {
        let mut peer = sync_ready_peer([0xB0 + i; 16]);
        peer.alive = true;
        router.peers.insert(peer.destination_hash, peer);
    }
    let stale = [0xBF; 16];
    let mut stale_peer = sync_ready_peer(stale);
    stale_peer.last_heard = lxmf_rs::router::now_timestamp() - MAX_UNREACHABLE as f64 - 10.0;
    router.peers.insert(stale, stale_peer);
    let static_stale = [0xBE; 16];
    router.config.static_peers.push(static_stale);
    let mut static_peer = sync_ready_peer(static_stale);
    static_peer.last_heard = 0.0;
    router.peers.insert(static_stale, static_peer);

    router.ensure_peer_sync_links_at(&network, lxmf_rs::router::now_timestamp());
    assert_eq!(
        network.links.lock().unwrap().len(),
        1,
        "one peer per sync cycle"
    );
    assert!(
        !router.peers.contains_key(&stale),
        "unreachable peer culled"
    );
    assert!(
        router.peers.contains_key(&static_stale),
        "static peers are kept"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn rotation_drops_low_acceptance_peers_but_not_static_ones() {
    let (mut router, dir) = test_router("rotation");
    router.config.max_peers = 4;
    for i in 0..5u8 {
        let hash = [0xC0 + i; 16];
        let mut peer = sync_ready_peer(hash);
        peer.unhandled_ids.clear();
        peer.alive = true;
        peer.last_sync_attempt = 1.0;
        peer.offered = 10;
        peer.outgoing = if i == 0 { 1 } else { 9 };
        router.peers.insert(hash, peer);
    }
    router.config.static_peers.push([0xC1; 16]);
    router.peers.get_mut(&[0xC1; 16]).unwrap().outgoing = 0;

    router.rotate_peers();
    // 5 peers, max 4 with headroom 1: two drops needed, but only the
    // non-static peer below the acceptance threshold goes.
    assert!(!router.peers.contains_key(&[0xC0; 16]));
    assert!(router.peers.contains_key(&[0xC1; 16]));
    assert_eq!(router.peers.len(), 4);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn enabling_propagation_activates_static_peers_and_restores_stats() {
    let (mut router, dir) = test_router("enable");
    router.propagation_node = false;
    let static_peer = [0xD5; 16];
    router.config.static_peers.push(static_peer);
    router
        .propagation_store
        .client_propagation_messages_received = 7;
    router.propagation_store.unpeered_propagation_rx_bytes = 99;
    router.save_node_stats();
    router
        .propagation_store
        .client_propagation_messages_received = 0;
    router.propagation_store.unpeered_propagation_rx_bytes = 0;

    router.enable_propagation();
    assert!(router.peers.contains_key(&static_peer));
    assert_eq!(
        router
            .propagation_store
            .client_propagation_messages_received,
        7
    );
    assert_eq!(router.propagation_store.unpeered_propagation_rx_bytes, 99);

    router.disable_propagation();
    assert!(!router.propagation_node);
    assert!(
        router.peers.contains_key(&static_peer),
        "disabling keeps peers"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn offers_drop_stale_and_low_value_messages_and_skip_oversized_ones() {
    use lxmf_rs::peer::OfferEntry;
    let mut peer = sync_ready_peer([0xE9; 16]);
    peer.unhandled_ids.clear();
    peer.propagation_transfer_limit = Some(1.0); // 1 KB per message
    let entry = |id: u8, size: usize, value: u32| OfferEntry {
        transient_id: [id; 32],
        weight: 1.0,
        size,
        stamp_value: StampValue::from_whole(value),
    };
    let available = vec![entry(1, 100, 20), entry(2, 100, 2), entry(3, 5_000, 20)];
    peer.unhandled_ids = vec![[1; 32], [2; 32], [3; 32], [4; 32]];

    assert!(peer.build_offer(&available).is_some());
    assert_eq!(peer.last_offer, vec![[1; 32]]);
    assert_eq!(
        peer.unhandled_ids,
        vec![[1; 32]],
        "stale, low-value and oversized removed"
    );
    assert!(
        peer.handled_ids.contains(&[3; 32]),
        "oversized counts as handled"
    );
    assert!(!peer.handled_ids.contains(&[2; 32]));
}
