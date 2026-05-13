use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;

use lxmf_core::constants::{DeliveryMethod, MessageState, Representation, DESTINATION_LENGTH};
use lxmf_rs::router::{LxmRouter, OutboundError, OutboundMessage, RouterConfig};
use rns_crypto::identity::Identity;

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
