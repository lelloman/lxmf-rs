use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use lxmf_core::constants::{DeliveryMethod, MessageState, Representation, DESTINATION_LENGTH};
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

fn pn_announce(dest_hash: [u8; DESTINATION_LENGTH], valid: bool) -> AnnouncedIdentity {
    let app_data = if valid {
        pack(&Value::Array(vec![
            Value::Bin(b"TestPN".to_vec()),
            Value::UInt(1_700_000_000),
            Value::Bool(true),
            Value::UInt(256),
            Value::UInt(10_240),
            Value::Array(vec![Value::UInt(16), Value::UInt(3), Value::UInt(18)]),
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
        hops: 1,
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
