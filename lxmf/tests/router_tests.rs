use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use lxmf_core::constants::{
    DeliveryMethod, MessageState, Representation, APP_NAME, DESTINATION_LENGTH,
    ENCRYPTION_DESCRIPTION_UNENCRYPTED,
};
use lxmf_core::message;
use lxmf_rs::router::{LxmRouter, LxmfCallbacks, OutboundError, OutboundMessage, RouterConfig};
use rns_core::msgpack::{pack, Value};
use rns_core::types::{DestHash, IdentityHash};
use rns_crypto::identity::Identity;
use rns_net::destination::AnnouncedIdentity;
use rns_net::driver::Callbacks;
use rns_net::InterfaceId;

static NEXT_TEMP_ID: AtomicU16 = AtomicU16::new(1);

fn temp_dir(name: &str) -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "lxmf_router_{}_{}_{}",
        name,
        std::process::id(),
        id
    ));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn test_router(name: &str) -> (LxmRouter, PathBuf) {
    let dir = temp_dir(name);
    let identity = Identity::new(&mut rns_crypto::OsRng);
    let config = RouterConfig {
        storagepath: dir.clone(),
        ..RouterConfig::default()
    };
    (LxmRouter::new(identity, config), dir)
}

fn outbound(method: DeliveryMethod) -> OutboundMessage {
    OutboundMessage {
        destination_hash: [0xAA; DESTINATION_LENGTH],
        source_hash: [0xBB; DESTINATION_LENGTH],
        packed: vec![0xCC; 128],
        message_hash: [0xDD; 32],
        method,
        state: MessageState::Outbound,
        representation: Representation::Unknown,
        attempts: 0,
        last_attempt: 0.0,
        stamp: None,
        stamp_cost: None,
        propagation_packed: Some(vec![0xEE; 64]),
        propagation_stamp: None,
        transient_id: Some([0x11; 32]),
        delivery_callback: None,
        failed_callback: None,
        progress_callback: None,
        link_id: None,
        packet_hash: None,
    }
}

fn pack_delivery_message(
    source_identity: &Identity,
    destination_hash: &[u8; DESTINATION_LENGTH],
) -> (message::PackResult, [u8; DESTINATION_LENGTH]) {
    let source_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(source_identity.hash()),
    );
    let signing_identity = Identity::from_private_key(&source_identity.get_private_key().unwrap());
    let packed = message::pack(
        destination_hash,
        &source_hash,
        1_700_000_000.0,
        b"Test",
        b"Message",
        vec![],
        None,
        |data| {
            signing_identity
                .sign(data)
                .map_err(|_| message::Error::SignError)
        },
    )
    .unwrap();

    (packed, source_hash)
}

fn pn_announce(dest_hash: [u8; DESTINATION_LENGTH], valid: bool) -> AnnouncedIdentity {
    pn_announce_full(dest_hash, valid, true, 1, 1_700_000_000, 18)
}

fn pn_announce_with(
    dest_hash: [u8; DESTINATION_LENGTH],
    valid: bool,
    propagation_enabled: bool,
    hops: u8,
) -> AnnouncedIdentity {
    pn_announce_full(
        dest_hash,
        valid,
        propagation_enabled,
        hops,
        1_700_000_000,
        18,
    )
}

fn pn_announce_full(
    dest_hash: [u8; DESTINATION_LENGTH],
    valid: bool,
    propagation_enabled: bool,
    hops: u8,
    node_timebase: u64,
    peering_cost: u8,
) -> AnnouncedIdentity {
    let app_data = if valid {
        pack(&Value::Array(vec![
            Value::Bin(b"TestPN".to_vec()),
            Value::UInt(node_timebase),
            Value::Bool(propagation_enabled),
            Value::UInt(256),
            Value::UInt(10_240),
            Value::Array(vec![
                Value::UInt(16),
                Value::UInt(3),
                Value::UInt(peering_cost as u64),
            ]),
            Value::Map(vec![]),
        ]))
    } else {
        b"not-pn-announce-data".to_vec()
    };

    AnnouncedIdentity {
        dest_hash: DestHash(dest_hash),
        identity_hash: IdentityHash([0x12; 16]),
        public_key: [0x34; 64],
        app_data: Some(app_data),
        hops,
        received_at: 1_700_000_000.0,
        receiving_interface: InterfaceId(1),
        rssi: None,
        snr: None,
    }
}

#[test]
fn propagated_outbound_requires_configured_propagation_node() {
    let (mut router, dir) = test_router("propagated_requires_node");
    let failed = Arc::new(AtomicBool::new(false));
    let failed_cb = failed.clone();
    let mut msg = outbound(DeliveryMethod::Propagated);
    msg.failed_callback = Some(Box::new(move |msg| {
        assert_eq!(msg.state, MessageState::Failed);
        failed_cb.store(true, Ordering::SeqCst);
    }));

    let err = router.handle_outbound(msg).unwrap_err();

    assert_eq!(err, OutboundError::MissingOutboundPropagationNode);
    assert!(failed.load(Ordering::SeqCst));
    assert!(router.outbound.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagated_outbound_queues_after_configuring_propagation_node() {
    let (mut router, dir) = test_router("propagated_with_node");
    let target = [0x42; DESTINATION_LENGTH];

    router.set_propagation_dest_hash(target);
    router
        .handle_outbound(outbound(DeliveryMethod::Propagated))
        .unwrap();

    assert_eq!(router.outbound_propagation_node, Some(target));
    assert_ne!(router.propagation_dest_hash, target);
    assert_eq!(router.outbound.len(), 1);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn blackholed_source_is_dropped_before_delivery_callback() {
    let (mut router, dir) = test_router("blackholed_source");
    let destination_hash = [0x51; DESTINATION_LENGTH];
    let source_identity = Identity::new(&mut rns_crypto::OsRng);
    let (packed, source_hash) = pack_delivery_message(&source_identity, &destination_hash);

    router.delivery_dest_hash = Some(destination_hash);
    router
        .identity_cache
        .insert(source_hash, source_identity.get_public_key().unwrap());
    router
        .identity_hash_cache
        .insert(source_hash, *source_identity.hash());
    router.set_blackholed_identities(vec![*source_identity.hash()]);

    let delivered = Arc::new(AtomicBool::new(false));
    let delivered_cb = delivered.clone();
    router.set_delivery_callback(Box::new(move |_| {
        delivered_cb.store(true, Ordering::SeqCst);
    }));

    router.lxmf_delivery(
        &packed.packed,
        false,
        ENCRYPTION_DESCRIPTION_UNENCRYPTED,
        DeliveryMethod::Opportunistic,
    );

    assert!(!delivered.load(Ordering::SeqCst));
    assert!(router.locally_delivered_transient_ids.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_wakes_matching_propagated_outbound() {
    let (mut router, dir) = test_router("pn_announce_wakes");
    let target = [0x42; DESTINATION_LENGTH];
    router.set_propagation_dest_hash(target);

    let mut msg = outbound(DeliveryMethod::Propagated);
    msg.last_attempt = 123_456.0;
    router.handle_outbound(msg).unwrap();

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce(target, true));

    let router_guard = router.lock().unwrap();
    assert_eq!(router_guard.outbound[0].last_attempt, 0.0);
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_ignores_unrelated_or_invalid_announces() {
    let (mut router, dir) = test_router("pn_announce_ignores");
    let target = [0x42; DESTINATION_LENGTH];
    router.set_propagation_dest_hash(target);

    let mut msg = outbound(DeliveryMethod::Propagated);
    msg.last_attempt = 123_456.0;
    router.handle_outbound(msg).unwrap();

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce([0x43; DESTINATION_LENGTH], true));
    callbacks.on_announce(pn_announce(target, false));

    let router_guard = router.lock().unwrap();
    assert_eq!(router_guard.outbound[0].last_attempt, 123_456.0);
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_does_not_autopeer_when_not_propagation_node() {
    let (router, dir) = test_router("pn_announce_not_pn");
    let peer_hash = [0x46; DESTINATION_LENGTH];

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce(peer_hash, true));

    let router_guard = router.lock().unwrap();
    assert!(!router_guard.peers.contains_key(&peer_hash));
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_records_autopeer() {
    let (mut router, dir) = test_router("pn_announce_records_peer");
    let peer_hash = [0x43; DESTINATION_LENGTH];
    router.enable_propagation();

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce(peer_hash, true));

    let router_guard = router.lock().unwrap();
    let peer = router_guard
        .peers
        .get(&peer_hash)
        .expect("propagation announce should create peer");
    assert!(peer.alive);
    assert_eq!(peer.propagation_transfer_limit, Some(256.0));
    assert_eq!(peer.propagation_sync_limit, Some(10_240));
    assert_eq!(peer.propagation_stamp_cost, Some(16));
    assert_eq!(peer.propagation_stamp_cost_flexibility, Some(3));
    assert_eq!(peer.peering_cost, Some(18));
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_unpeers_existing_autopeer_out_of_range() {
    let (mut router, dir) = test_router("pn_announce_unpeers_out_of_range");
    let peer_hash = [0x44; DESTINATION_LENGTH];
    router.enable_propagation();
    router
        .peers
        .insert(peer_hash, lxmf_rs::peer::LxmPeer::new(peer_hash));

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce_with(peer_hash, true, true, 5));

    let router_guard = router.lock().unwrap();
    assert!(!router_guard.peers.contains_key(&peer_hash));
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_unpeers_existing_autopeer_when_disabled() {
    let (mut router, dir) = test_router("pn_announce_unpeers_disabled");
    let peer_hash = [0x45; DESTINATION_LENGTH];
    router.enable_propagation();
    router
        .peers
        .insert(peer_hash, lxmf_rs::peer::LxmPeer::new(peer_hash));

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce_with(peer_hash, true, false, 1));

    let router_guard = router.lock().unwrap();
    assert!(!router_guard.peers.contains_key(&peer_hash));
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_ignores_peer_above_max_peering_cost() {
    let (mut router, dir) = test_router("pn_announce_high_cost");
    let peer_hash = [0x47; DESTINATION_LENGTH];
    router.config.max_peering_cost = 10;
    router.enable_propagation();

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce_full(
        peer_hash,
        true,
        true,
        1,
        1_700_000_000,
        18,
    ));

    let router_guard = router.lock().unwrap();
    assert!(!router_guard.peers.contains_key(&peer_hash));
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_unpeers_existing_peer_above_max_peering_cost() {
    let (mut router, dir) = test_router("pn_announce_high_cost_existing");
    let peer_hash = [0x48; DESTINATION_LENGTH];
    router.config.max_peering_cost = 10;
    router.enable_propagation();
    router
        .peers
        .insert(peer_hash, lxmf_rs::peer::LxmPeer::new(peer_hash));

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce_full(
        peer_hash,
        true,
        true,
        1,
        1_700_000_000,
        18,
    ));

    let router_guard = router.lock().unwrap();
    assert!(!router_guard.peers.contains_key(&peer_hash));
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_ignores_new_peer_when_max_peers_reached() {
    let (mut router, dir) = test_router("pn_announce_max_peers");
    let peer_hash = [0x49; DESTINATION_LENGTH];
    router.config.max_peers = 0;
    router.enable_propagation();

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce(peer_hash, true));

    let router_guard = router.lock().unwrap();
    assert!(!router_guard.peers.contains_key(&peer_hash));
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_node_announce_ignores_stale_peer_update_and_unpeer() {
    let (mut router, dir) = test_router("pn_announce_stale_peer");
    let peer_hash = [0x4A; DESTINATION_LENGTH];
    router.enable_propagation();
    let mut peer = lxmf_rs::peer::LxmPeer::new(peer_hash);
    peer.peering_timebase = 2_000_000_000.0;
    peer.peering_cost = Some(7);
    router.peers.insert(peer_hash, peer);

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_announce(pn_announce_full(
        peer_hash,
        true,
        true,
        1,
        1_700_000_000,
        18,
    ));
    callbacks.on_announce(pn_announce_full(
        peer_hash,
        true,
        false,
        1,
        1_700_000_000,
        18,
    ));

    let router_guard = router.lock().unwrap();
    let peer = router_guard
        .peers
        .get(&peer_hash)
        .expect("stale announce should not remove peer");
    assert_eq!(peer.peering_timebase, 2_000_000_000.0);
    assert_eq!(peer.peering_cost, Some(7));
    drop(router_guard);
    let _ = fs::remove_dir_all(dir);
}
