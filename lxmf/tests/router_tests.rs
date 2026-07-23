use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use lxmf_core::constants::{
    DeliveryMethod, MessageState, PeerError, PeerState, Representation, APP_NAME,
    DESTINATION_LENGTH, ENCRYPTION_DESCRIPTION_UNENCRYPTED, LXMF_OVERHEAD, STAMP_COST_EXPIRY,
    STAMP_SIZE,
};
use lxmf_core::message;
use lxmf_rs::router::{
    InboundOfferState, InboundResourceControl, InboundResourceControlError, LxmRouter,
    LxmfCallbacks, OutboundError, OutboundMessage, PeerOfferResponseResult, PeerSyncTransport,
    PeerSyncTransportError, RouterConfig,
};
use rns_core::msgpack::{pack, unpack_exact, Value};
use rns_core::types::{DestHash, IdentityHash, LinkId};
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

#[derive(Default)]
struct FakePeerSyncTransport {
    offers: Mutex<Vec<([u8; 16], Vec<u8>)>>,
    identities: Mutex<Vec<([u8; 16], [u8; 64])>>,
    resources: Mutex<Vec<([u8; 16], Vec<u8>)>>,
    teardowns: Mutex<Vec<[u8; 16]>>,
}

impl PeerSyncTransport for FakePeerSyncTransport {
    fn send_peer_offer(
        &self,
        link_id: [u8; 16],
        offer: &[u8],
    ) -> Result<(), PeerSyncTransportError> {
        self.offers.lock().unwrap().push((link_id, offer.to_vec()));
        Ok(())
    }

    fn identify_peer_link(
        &self,
        link_id: [u8; 16],
        identity_prv_key: [u8; 64],
    ) -> Result<(), PeerSyncTransportError> {
        self.identities
            .lock()
            .unwrap()
            .push((link_id, identity_prv_key));
        Ok(())
    }

    fn send_peer_resource(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
    ) -> Result<(), PeerSyncTransportError> {
        self.resources.lock().unwrap().push((link_id, data));
        Ok(())
    }

    fn teardown_peer_link(&self, link_id: [u8; 16]) -> Result<(), PeerSyncTransportError> {
        self.teardowns.lock().unwrap().push(link_id);
        Ok(())
    }
}

#[derive(Default)]
struct FakeInboundResourceControl {
    cancellations: Mutex<Vec<([u8; 16], Vec<u8>)>>,
}

impl InboundResourceControl for FakeInboundResourceControl {
    fn cancel_inbound_resource(
        &self,
        link_id: [u8; 16],
        resource_hash: &[u8],
    ) -> Result<(), InboundResourceControlError> {
        self.cancellations
            .lock()
            .unwrap()
            .push((link_id, resource_hash.to_vec()));
        Ok(())
    }
}

fn make_lxm_data(dest_hash: &[u8; DESTINATION_LENGTH], payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(dest_hash);
    let padding_needed = LXMF_OVERHEAD.saturating_sub(DESTINATION_LENGTH + payload.len());
    data.extend(std::iter::repeat(0u8).take(padding_needed));
    data.extend_from_slice(payload);
    data
}

fn prepared_peer_sync_router(
    name: &str,
) -> (
    LxmRouter,
    PathBuf,
    [u8; DESTINATION_LENGTH],
    [u8; DESTINATION_LENGTH],
    [u8; 32],
    Vec<u8>,
) {
    let (mut router, dir) = test_router(name);
    let peer_hash = [0x61; DESTINATION_LENGTH];
    let link_id = [0x71; DESTINATION_LENGTH];
    let message_dest = [0x81; DESTINATION_LENGTH];
    let lxm_data = make_lxm_data(&message_dest, b"peer sync payload");
    let stamp = [0x42u8; STAMP_SIZE];
    let transient_id = router
        .propagation_store
        .store_message(&lxm_data, Some(&stamp), 16, None)
        .expect("test message should store");

    let mut peer = lxmf_rs::peer::LxmPeer::new(peer_hash);
    peer.handle_link_established(link_id, 0.1);
    peer.peering_key = Some((vec![0x99; 32], 20));
    peer.peering_cost = Some(18);
    peer.propagation_stamp_cost = Some(16);
    peer.propagation_stamp_cost_flexibility = Some(3);
    peer.propagation_transfer_limit = Some(256.0);
    peer.propagation_sync_limit = Some(10_240);
    peer.unhandled_ids.push(transient_id);
    router.peers.insert(peer_hash, peer);

    (router, dir, peer_hash, link_id, transient_id, lxm_data)
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

#[test]
fn peer_sync_no_identity_identifies_with_router_identity_and_retries_offer() {
    let (mut router, dir, peer_hash, link_id, _tid, _lxm_data) =
        prepared_peer_sync_router("peer_sync_no_identity");
    let transport = FakePeerSyncTransport::default();

    assert_eq!(
        router.send_peer_sync_offer_with_transport(peer_hash, &transport),
        PeerOfferResponseResult::OfferSent
    );

    let response = pack(&Value::UInt(PeerError::NoIdentity as u64));
    let result = router.handle_peer_offer_response_with_transport(link_id, &response, &transport);

    assert_eq!(result, PeerOfferResponseResult::RetriedAfterIdentify);
    assert!(router.peers.contains_key(&peer_hash));
    assert_eq!(
        router.peers.get(&peer_hash).unwrap().state,
        PeerState::RequestSent
    );

    let identities = transport.identities.lock().unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].0, link_id);
    assert_eq!(identities[0].1, router.identity.get_private_key().unwrap());
    drop(identities);

    let offers = transport.offers.lock().unwrap();
    assert_eq!(offers.len(), 2, "offer should be retried after identify");
    assert_eq!(offers[0].0, link_id);
    assert_eq!(offers[1].0, link_id);
    assert!(transport.teardowns.lock().unwrap().is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn peer_sync_no_access_unpeers_and_closes_link() {
    let (mut router, dir, peer_hash, link_id, _tid, _lxm_data) =
        prepared_peer_sync_router("peer_sync_no_access");
    let transport = FakePeerSyncTransport::default();
    router.send_peer_sync_offer_with_transport(peer_hash, &transport);

    let response = pack(&Value::UInt(PeerError::NoAccess as u64));
    let result = router.handle_peer_offer_response_with_transport(link_id, &response, &transport);

    assert_eq!(result, PeerOfferResponseResult::Unpeered);
    assert!(!router.peers.contains_key(&peer_hash));
    assert_eq!(*transport.teardowns.lock().unwrap(), vec![link_id]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn peer_sync_throttled_postpones_next_attempt_and_closes_link() {
    let (mut router, dir, peer_hash, link_id, _tid, _lxm_data) =
        prepared_peer_sync_router("peer_sync_throttled");
    let transport = FakePeerSyncTransport::default();
    router.send_peer_sync_offer_with_transport(peer_hash, &transport);

    let before = router.peers.get(&peer_hash).unwrap().next_sync_attempt;
    let response = pack(&Value::UInt(PeerError::Throttled as u64));
    let result = router.handle_peer_offer_response_with_transport(link_id, &response, &transport);

    assert_eq!(result, PeerOfferResponseResult::Teardown);
    let peer = router.peers.get(&peer_hash).unwrap();
    assert!(peer.next_sync_attempt > before);
    assert!(peer.next_sync_attempt > lxmf_rs::router::now_timestamp());
    assert_eq!(*transport.teardowns.lock().unwrap(), vec![link_id]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn peer_sync_wanted_messages_send_resource_and_track_transfer() {
    let (mut router, dir, peer_hash, link_id, transient_id, lxm_data) =
        prepared_peer_sync_router("peer_sync_transfer");
    let transport = FakePeerSyncTransport::default();
    router.send_peer_sync_offer_with_transport(peer_hash, &transport);

    let response = pack(&Value::Bool(true));
    let result = router.handle_peer_offer_response_with_transport(link_id, &response, &transport);

    assert_eq!(result, PeerOfferResponseResult::TransferStarted(1));
    let peer = router.peers.get(&peer_hash).unwrap();
    assert_eq!(peer.state, PeerState::ResourceTransferring);
    assert_eq!(
        peer.currently_transferring_messages,
        Some(vec![transient_id])
    );

    let resources = transport.resources.lock().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].0, link_id);
    let packed = unpack_exact(&resources[0].1).expect("resource should be msgpack");
    let arr = packed.as_array().expect("resource should be array");
    assert_eq!(arr.len(), 2);
    let messages = arr[1].as_array().expect("messages should be array");
    assert_eq!(messages.len(), 1);
    let message_bytes = messages[0].as_bin().expect("message should be binary");
    assert_eq!(&message_bytes[..lxm_data.len()], &lxm_data[..]);
    assert_eq!(&message_bytes[lxm_data.len()..], &[0x42u8; STAMP_SIZE][..]);
    let _ = fs::remove_dir_all(dir);
}

fn remote_propagation_hash(identity_hash: [u8; 16]) -> [u8; 16] {
    rns_core::destination::destination_hash(APP_NAME, &["propagation"], Some(&identity_hash))
}

#[test]
fn inbound_offer_admission_serializes_validation_by_default() {
    let (mut router, dir) = test_router("inbound_sequential");
    let validating_peer = [0x21; 16];
    let new_peer = [0x22; 16];
    router
        .validating_pn_stamps_from
        .insert(validating_peer, lxmf_rs::router::now_timestamp());

    assert_eq!(
        router.check_inbound_offer_admission(new_peer),
        Err(PeerError::Throttled)
    );

    router.config.sequential_validation = false;
    assert_eq!(router.check_inbound_offer_admission(new_peer), Ok(()));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn inbound_offer_admission_enforces_transfer_cap() {
    let (mut router, dir) = test_router("inbound_cap");
    router.config.max_inbound_syncs = 2;
    router
        .accepted_offer_links
        .insert([0x31; 16], InboundOfferState::Transferring);
    assert_eq!(
        router.check_inbound_offer_admission([0x41; 16]),
        Ok(()),
        "one transfer remains below the cap"
    );

    router
        .accepted_offer_links
        .insert([0x32; 16], InboundOfferState::Validating);
    assert_eq!(
        router.check_inbound_offer_admission([0x41; 16]),
        Err(PeerError::Throttled)
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn static_peer_bypass_is_configurable_for_both_pressure_limits() {
    let (mut router, dir) = test_router("static_bypass");
    let static_peer = [0x51; 16];
    router.config.static_peers.push(static_peer);
    router.config.max_inbound_syncs = 1;
    router
        .accepted_offer_links
        .insert([0x52; 16], InboundOfferState::Transferring);
    router
        .validating_pn_stamps_from
        .insert([0x53; 16], lxmf_rs::router::now_timestamp());

    assert_eq!(router.check_inbound_offer_admission(static_peer), Ok(()));

    router.config.static_sequential = true;
    assert_eq!(
        router.check_inbound_offer_admission(static_peer),
        Err(PeerError::Throttled)
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn from_static_only_rejects_unlisted_inbound_offer() {
    let (mut router, dir) = test_router("inbound_static_only");
    router.config.from_static_only = true;

    assert_eq!(
        router.check_inbound_offer_admission([0x61; 16]),
        Err(PeerError::NoAccess)
    );

    router.config.static_peers.push([0x61; 16]);
    assert_eq!(router.check_inbound_offer_admission([0x61; 16]), Ok(()));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn inbound_offer_admission_honors_active_but_not_expired_stamp_throttle() {
    let (mut router, dir) = test_router("inbound_stamp_throttle");
    let remote_hash = [0x62; 16];
    router
        .throttled_peers
        .insert(remote_hash, lxmf_rs::router::now_timestamp() + 60.0);
    assert_eq!(
        router.check_inbound_offer_admission(remote_hash),
        Err(PeerError::Throttled)
    );

    router
        .throttled_peers
        .insert(remote_hash, lxmf_rs::router::now_timestamp() - 1.0);
    assert_eq!(router.check_inbound_offer_admission(remote_hash), Ok(()));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn valid_inbound_offer_records_link_and_returns_wanted_ids() {
    let (mut router, dir) = test_router("inbound_offer");
    router.config.peering_cost = 0;
    let link_id = [0x71; 16];
    let remote_identity = [0x72; 16];
    let remote_hash = remote_propagation_hash(remote_identity);
    let first = [0x73; 32];
    let second = [0x74; 32];
    let offer = pack(&Value::Array(vec![
        Value::Bin(vec![0; STAMP_SIZE]),
        Value::Array(vec![
            Value::Bin(first.to_vec()),
            Value::Bin(second.to_vec()),
        ]),
    ]));

    let response = router.handle_inbound_offer(link_id, remote_identity, &offer);

    assert_eq!(unpack_exact(&response).unwrap().as_bool(), Some(true));
    assert_eq!(
        router.accepted_offer_links.get(&link_id),
        Some(&InboundOfferState::Accepted)
    );
    assert_eq!(router.inbound_offer_peers.get(&link_id), Some(&remote_hash));
    assert!(router.validated_peer_links.contains(&link_id));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn inbound_offer_rejects_invalid_shape_and_invalid_peering_key() {
    let (mut router, dir) = test_router("inbound_offer_invalid");
    let link_id = [0x81; 16];
    let remote_identity = [0x82; 16];

    assert_eq!(
        router.handle_inbound_offer(link_id, remote_identity, b"not msgpack"),
        vec![PeerError::InvalidData as u8]
    );

    router.config.peering_cost = 255;
    let offer = pack(&Value::Array(vec![
        Value::Bin(vec![0; STAMP_SIZE]),
        Value::Array(vec![Value::Bin(vec![0x83; 32])]),
    ]));
    assert_eq!(
        router.handle_inbound_offer(link_id, remote_identity, &offer),
        vec![PeerError::InvalidKey as u8]
    );
    assert!(router.accepted_offer_links.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn inbound_resource_admission_tracks_state_and_cleans_on_link_close() {
    let (mut router, dir) = test_router("inbound_resource_state");
    let link_id = [0x91; 16];
    let remote_hash = [0x92; 16];
    router
        .accepted_offer_links
        .insert(link_id, InboundOfferState::Accepted);
    router.inbound_offer_peers.insert(link_id, remote_hash);

    assert!(router.accept_inbound_propagation_resource(link_id, 1024));
    assert_eq!(
        router.accepted_offer_links.get(&link_id),
        Some(&InboundOfferState::Transferring)
    );

    assert_eq!(router.begin_inbound_validation(link_id), Some(remote_hash));
    assert_eq!(
        router.accepted_offer_links.get(&link_id),
        Some(&InboundOfferState::Validating)
    );
    assert!(router.validating_pn_stamps_from.contains_key(&remote_hash));

    router.finish_inbound_sync(link_id);
    assert!(!router.accepted_offer_links.contains_key(&link_id));
    assert!(!router.inbound_offer_peers.contains_key(&link_id));
    assert!(!router.validating_pn_stamps_from.contains_key(&remote_hash));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn inbound_resource_admission_rejects_unknown_and_oversized_resources() {
    let (mut router, dir) = test_router("inbound_resource_reject");
    let link_id = [0xA1; 16];
    router.config.sync_limit = 1;

    assert!(!router.accept_inbound_propagation_resource(link_id, 10));

    router
        .accepted_offer_links
        .insert(link_id, InboundOfferState::Accepted);
    assert!(!router.accept_inbound_propagation_resource(link_id, 1001));
    assert_eq!(
        router.accepted_offer_links.get(&link_id),
        Some(&InboundOfferState::Accepted)
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn resource_accept_query_enforces_delivery_and_propagation_limits() {
    let (mut router, dir) = test_router("resource_accept_query");
    let delivery_link = [0xB1; 16];
    let propagation_link = [0xB2; 16];
    router.delivery_dest_hash = Some([0xB3; 16]);
    router.link_destinations.insert(delivery_link, [0xB3; 16]);
    router
        .accepted_offer_links
        .insert(propagation_link, InboundOfferState::Accepted);
    router.config.delivery_limit = 1.0;
    router.config.sync_limit = 2;

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());

    assert!(callbacks.on_resource_accept_query(LinkId(delivery_link), vec![0; 32], 1000, false));
    assert!(!callbacks.on_resource_accept_query(LinkId(delivery_link), vec![0; 32], 1001, false));
    assert!(callbacks.on_resource_accept_query(LinkId(propagation_link), vec![0; 32], 2000, false));

    let guard = router.lock().unwrap();
    assert_eq!(
        guard.inbound_count(),
        1,
        "the rejected direct resource must not be tracked"
    );
    assert_eq!(
        guard.accepted_offer_links.get(&propagation_link),
        Some(&InboundOfferState::Transferring)
    );
    drop(guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn inbound_propagation_resource_validates_stores_and_cleans_accounting() {
    let (mut router, dir) = test_router("inbound_resource_processing");
    let link_id = [0xC1; 16];
    let remote_hash = [0xC2; 16];
    router.config.propagation_cost = 0;
    router.config.propagation_cost_flexibility = 0;
    router
        .accepted_offer_links
        .insert(link_id, InboundOfferState::Transferring);
    router.inbound_offer_peers.insert(link_id, remote_hash);

    let mut lxm_data = make_lxm_data(&[0xC3; 16], b"inbound propagation");
    lxm_data.push(0x01);
    let mut stamped = lxm_data.clone();
    stamped.extend_from_slice(&[0; STAMP_SIZE]);
    let batch = pack(&Value::Array(vec![
        Value::Float(1_700_000_000.0),
        Value::Array(vec![Value::Bin(stamped)]),
    ]));

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_resource_received(LinkId(link_id), batch, None);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let guard = router.lock().unwrap();
        if guard.propagation_store.message_count() == 1 {
            assert!(!guard.accepted_offer_links.contains_key(&link_id));
            assert!(!guard.inbound_offer_peers.contains_key(&link_id));
            assert!(!guard.validating_pn_stamps_from.contains_key(&remote_hash));
            assert_eq!(guard.propagation_store.unpeered_propagation_incoming, 1);
            assert_eq!(
                guard.propagation_store.unpeered_propagation_rx_bytes,
                lxm_data.len() as u64
            );
            break;
        }
        drop(guard);
        assert!(
            std::time::Instant::now() < deadline,
            "validation worker did not store inbound message"
        );
        std::thread::yield_now();
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn invalid_inbound_propagation_payload_cleans_offer_accounting() {
    let (mut router, dir) = test_router("invalid_inbound_payload");
    let link_id = [0xD1; 16];
    let remote_hash = [0xD2; 16];
    router
        .accepted_offer_links
        .insert(link_id, InboundOfferState::Transferring);
    router.inbound_offer_peers.insert(link_id, remote_hash);

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_resource_received(LinkId(link_id), b"invalid".to_vec(), None);

    let guard = router.lock().unwrap();
    assert!(!guard.accepted_offer_links.contains_key(&link_id));
    assert!(!guard.inbound_offer_peers.contains_key(&link_id));
    drop(guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn link_close_cleans_every_inbound_offer_state() {
    let (mut router, dir) = test_router("inbound_link_cleanup");
    let link_id = [0xE1; 16];
    let remote_hash = [0xE2; 16];
    router
        .accepted_offer_links
        .insert(link_id, InboundOfferState::Validating);
    router.inbound_offer_peers.insert(link_id, remote_hash);
    router
        .validating_pn_stamps_from
        .insert(remote_hash, lxmf_rs::router::now_timestamp());
    router.validated_peer_links.insert(link_id);

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_link_closed(LinkId(link_id), None);

    let guard = router.lock().unwrap();
    assert!(!guard.accepted_offer_links.contains_key(&link_id));
    assert!(!guard.inbound_offer_peers.contains_key(&link_id));
    assert!(!guard.validating_pn_stamps_from.contains_key(&remote_hash));
    assert!(!guard.validated_peer_links.contains(&link_id));
    drop(guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn direct_resource_tracking_reports_count_details_and_progress() {
    let (mut router, dir) = test_router("direct_resource_tracking");
    let first_hash = vec![0x11; 32];
    let second_hash = vec![0x12; 32];

    router.track_inbound_delivery_resource([0x21; 16], first_hash.clone(), 4000);
    router.track_inbound_delivery_resource([0x22; 16], second_hash.clone(), 8000);
    router.update_inbound_resource_progress([0x21; 16], 1000, 4000);

    assert_eq!(router.inbound_count(), 2);
    let resources = router.inbound_resources();
    assert_eq!(resources.len(), 2);
    let first = resources
        .iter()
        .find(|resource| resource.resource_hash == first_hash)
        .unwrap();
    assert_eq!(first.link_id, [0x21; 16]);
    assert_eq!(first.received, 1000);
    assert_eq!(first.total, 4000);
    assert_eq!(first.progress(), 0.25);

    let second = resources
        .iter()
        .find(|resource| resource.resource_hash == second_hash)
        .unwrap();
    assert_eq!(second.received, 0);
    assert_eq!(second.progress(), 0.0);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn inbound_resource_progress_is_monotonic_and_clamped_to_total() {
    let (mut router, dir) = test_router("resource_progress_clamp");
    let resource_hash = vec![0x31; 32];
    router.track_inbound_delivery_resource([0x32; 16], resource_hash.clone(), 100);

    router.update_inbound_resource_progress([0x32; 16], 70, 100);
    router.update_inbound_resource_progress([0x32; 16], 20, 100);
    router.update_inbound_resource_progress([0x32; 16], 150, 100);

    let resource = router
        .inbound_resources()
        .into_iter()
        .find(|resource| resource.resource_hash == resource_hash)
        .unwrap();
    assert_eq!(resource.received, 100);
    assert_eq!(resource.progress(), 1.0);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn cancel_inbound_targets_exact_resource_and_removes_tracking() {
    let (mut router, dir) = test_router("cancel_inbound");
    let control = FakeInboundResourceControl::default();
    let first_hash = vec![0x41; 32];
    let second_hash = vec![0x42; 32];
    router.track_inbound_delivery_resource([0x51; 16], first_hash.clone(), 100);
    router.track_inbound_delivery_resource([0x52; 16], second_hash.clone(), 200);

    assert!(router.cancel_inbound_with(&first_hash, &control));
    assert!(!router.cancel_inbound_with(&first_hash, &control));
    assert_eq!(router.inbound_count(), 1);
    assert_eq!(
        *control.cancellations.lock().unwrap(),
        vec![([0x51; 16], first_hash)]
    );
    assert_eq!(router.inbound_resources()[0].resource_hash, second_hash);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn cancel_all_inbound_attempts_every_resource() {
    let (mut router, dir) = test_router("cancel_all_inbound");
    let control = FakeInboundResourceControl::default();
    for index in 0..3u8 {
        router.track_inbound_delivery_resource([0x60 + index; 16], vec![0x70 + index; 32], 100);
    }

    assert_eq!(router.cancel_all_inbound_with(&control), 3);
    assert_eq!(router.inbound_count(), 0);
    assert_eq!(control.cancellations.lock().unwrap().len(), 3);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn delivery_resource_callbacks_track_progress_and_remove_completed_transfer() {
    let (mut router, dir) = test_router("delivery_resource_callbacks");
    let link_id = [0x81; 16];
    let delivery_hash = [0x82; 16];
    let resource_hash = vec![0x83; 32];
    router.delivery_dest_hash = Some(delivery_hash);
    router.link_destinations.insert(link_id, delivery_hash);
    router.config.delivery_limit = 2.0;

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    assert!(callbacks.on_resource_accept_query(
        LinkId(link_id),
        resource_hash.clone(),
        1500,
        false
    ));
    callbacks.on_resource_progress(LinkId(link_id), 750, 1500);

    {
        let guard = router.lock().unwrap();
        assert_eq!(guard.inbound_count(), 1);
        let resource = &guard.inbound_resources()[0];
        assert_eq!(resource.resource_hash, resource_hash);
        assert_eq!(resource.progress(), 0.5);
    }

    callbacks.on_resource_received(LinkId(link_id), vec![0; LXMF_OVERHEAD], None);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if router.lock().unwrap().inbound_count() == 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "completed inbound resource was not cleaned"
        );
        std::thread::yield_now();
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn failed_delivery_resource_is_removed_from_tracking() {
    let (mut router, dir) = test_router("failed_delivery_resource");
    let link_id = [0x88; 16];
    router.track_inbound_delivery_resource(link_id, vec![0x89; 32], 1000);

    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());
    callbacks.on_resource_failed(LinkId(link_id), "test failure".into());

    assert_eq!(router.lock().unwrap().inbound_count(), 0);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn propagation_resource_progress_records_total_response_size() {
    let (router, dir) = test_router("propagation_transfer_size");
    let link_id = [0x91; 16];
    let router = Arc::new(Mutex::new(router));
    router.lock().unwrap().propagation_link = Some(link_id);
    let mut callbacks = LxmfCallbacks::new(router.clone());

    callbacks.on_resource_progress(LinkId(link_id), 250, 1000);
    {
        let guard = router.lock().unwrap();
        assert_eq!(guard.propagation_transfer_size, Some(1000));
        assert_eq!(guard.propagation_transfer_progress, 0.25);
    }

    router.lock().unwrap().reset_propagation_transfer_progress();
    let guard = router.lock().unwrap();
    assert_eq!(guard.propagation_transfer_size, None);
    assert_eq!(guard.propagation_transfer_progress, 0.0);
    drop(guard);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn stamp_cost_update_replaces_cache_and_persists_all_destinations() {
    let (mut router, dir) = test_router("stamp_cost_update");
    let first = [0xA1; 16];
    let second = [0xA2; 16];

    router.update_stamp_cost(first, 7);
    router.update_stamp_cost(second, 11);
    let first_timestamp = router.outbound_stamp_costs[&first].0;
    router.update_stamp_cost(first, 13);

    assert_eq!(router.get_stamp_cost(&first), Some(13));
    assert_eq!(router.get_stamp_cost(&second), Some(11));
    assert!(router.outbound_stamp_costs[&first].0 >= first_timestamp);
    assert_eq!(
        lxmf_rs::storage::load_stamp_costs(&router.paths.outbound_stamp_costs),
        router.outbound_stamp_costs
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn expired_stamp_cost_is_not_returned_but_remains_persistable() {
    let (mut router, dir) = test_router("expired_stamp_cost");
    let destination = [0xB1; 16];
    router.outbound_stamp_costs.insert(
        destination,
        (
            lxmf_rs::router::now_timestamp() - STAMP_COST_EXPIRY as f64 - 1.0,
            17,
        ),
    );

    assert_eq!(router.get_stamp_cost(&destination), None);
    router.update_stamp_cost(destination, 19);
    assert_eq!(router.get_stamp_cost(&destination), Some(19));
    let _ = fs::remove_dir_all(dir);
}
