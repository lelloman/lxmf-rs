//! Outbound processing against a mock network: medium-aware retries, path
//! rediscovery, slow-path holds, debounced path requests and failure handling
//! (upstream LXMF 1.2/1.3 outbound behaviour).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use lxmf_core::constants::*;
use lxmf_rs::outbound::{LinkCreation, OutboundNetwork, SendFailed, DEFAULT_PER_HOP_TIMEOUT};
use lxmf_rs::router::{LxmRouter, OutboundMessage, RouterConfig};
use rns_crypto::identity::Identity;

static NEXT_DIR: AtomicUsize = AtomicUsize::new(1);

fn test_router(name: &str) -> (LxmRouter, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "lxmf_outbound_{}_{}_{}",
        name,
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = RouterConfig {
        storagepath: dir.clone(),
        ..RouterConfig::default()
    };
    (
        LxmRouter::new(Identity::new(&mut rns_crypto::OsRng), config),
        dir,
    )
}

#[derive(Default)]
struct MockNetwork {
    paths: Mutex<HashSet<[u8; 16]>>,
    first_hop: Mutex<HashMap<[u8; 16], f64>>,
    medium_path_timeout: Mutex<f64>,
    lowest_bitrate: Mutex<Option<u64>>,
    fail_sends: Mutex<bool>,
    opportunistic: Mutex<Vec<[u8; 16]>>,
    link_packets: Mutex<Vec<[u8; 16]>>,
    resources: Mutex<Vec<([u8; 16], usize, bool)>>,
    path_requests: Mutex<Vec<[u8; 16]>>,
    drops: Mutex<Vec<[u8; 16]>>,
    links: Mutex<Vec<[u8; 16]>>,
    retained: Mutex<Vec<[u8; 16]>>,
}

impl MockNetwork {
    fn with_path(dest: [u8; 16]) -> Self {
        let network = Self::default();
        network.paths.lock().unwrap().insert(dest);
        network
    }
}

impl OutboundNetwork for MockNetwork {
    fn has_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.paths.lock().unwrap().contains(dest_hash)
    }
    fn request_path(&self, dest_hash: &[u8; 16]) {
        self.path_requests.lock().unwrap().push(*dest_hash);
    }
    fn drop_path(&self, dest_hash: &[u8; 16]) {
        self.drops.lock().unwrap().push(*dest_hash);
    }
    fn medium_path_timeout(&self) -> f64 {
        *self.medium_path_timeout.lock().unwrap()
    }
    fn lowest_interface_bitrate(&self) -> Option<u64> {
        *self.lowest_bitrate.lock().unwrap()
    }
    fn first_hop_timeout(&self, dest_hash: &[u8; 16]) -> f64 {
        self.first_hop
            .lock()
            .unwrap()
            .get(dest_hash)
            .copied()
            .unwrap_or(DEFAULT_PER_HOP_TIMEOUT)
    }
    fn recall_public_key(&self, _dest_hash: &[u8; 16]) -> Option<[u8; 64]> {
        Some([0x42; 64])
    }
    fn send_opportunistic(
        &self,
        dest_hash: &[u8; 16],
        _public_key: &[u8; 64],
        _data: &[u8],
    ) -> Result<[u8; 32], SendFailed> {
        if *self.fail_sends.lock().unwrap() {
            return Err(SendFailed);
        }
        let mut sent = self.opportunistic.lock().unwrap();
        sent.push(*dest_hash);
        let mut hash = [0u8; 32];
        hash[0] = sent.len() as u8;
        Ok(hash)
    }
    fn send_link_packet(&self, link_id: [u8; 16], _data: Vec<u8>) -> Result<(), SendFailed> {
        if *self.fail_sends.lock().unwrap() {
            return Err(SendFailed);
        }
        self.link_packets.lock().unwrap().push(link_id);
        Ok(())
    }
    fn send_link_resource(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        _auto_compress: bool,
        app_flag: bool,
    ) -> Result<(), SendFailed> {
        if *self.fail_sends.lock().unwrap() {
            return Err(SendFailed);
        }
        self.resources
            .lock()
            .unwrap()
            .push((link_id, data.len(), app_flag));
        Ok(())
    }
    fn begin_link(
        &self,
        dest_hash: [u8; 16],
        _sig_pub: [u8; 32],
        results: mpsc::Sender<LinkCreation>,
    ) {
        self.links.lock().unwrap().push(dest_hash);
        let mut link_id = dest_hash;
        link_id[15] ^= 0xFF;
        let _ = results.send(LinkCreation {
            dest_hash,
            link_id: Some(link_id),
        });
    }
    fn retain_destination(&self, dest_hash: [u8; 16]) {
        self.retained.lock().unwrap().push(dest_hash);
    }
}

const DEST: [u8; 16] = [0xD0; 16];

fn message(method: DeliveryMethod, packed_len: usize) -> OutboundMessage {
    let mut packed = vec![0u8; packed_len];
    packed[..16].copy_from_slice(&DEST);
    OutboundMessage::new(DEST, [0x50; 16], packed, [0x77; 32], method)
}

/// Make every queued message due, as if its retry wait had elapsed.
fn advance(router: &mut LxmRouter) {
    for msg in &mut router.outbound {
        msg.tracking.next_delivery_attempt = Some(0.0);
    }
}

fn counting_failed_callback(msg: &mut OutboundMessage) -> Arc<AtomicUsize> {
    let failed = Arc::new(AtomicUsize::new(0));
    let counter = failed.clone();
    msg.failed_callback = Some(Box::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    failed
}

#[test]
fn opportunistic_retries_rediscovers_path_then_fails() {
    let (mut router, dir) = test_router("opportunistic_retries");
    let network = MockNetwork::with_path(DEST);
    let mut msg = message(DeliveryMethod::Opportunistic, 200);
    let failed = counting_failed_callback(&mut msg);
    router.handle_outbound(msg).unwrap();

    for _ in 0..12 {
        router.process_outbound_with(&network);
        advance(&mut router);
    }

    // Five sends, with one stale-path rediscovery after the second, then the
    // message fails once its attempts are exhausted.
    assert_eq!(network.opportunistic.lock().unwrap().len(), 5);
    assert_eq!(*network.drops.lock().unwrap(), vec![DEST]);
    assert_eq!(*network.path_requests.lock().unwrap(), vec![DEST]);
    assert_eq!(failed.load(Ordering::SeqCst), 1);
    assert!(
        router.outbound.is_empty(),
        "failed messages leave the queue"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn opportunistic_message_waits_for_retry_wait() {
    let (mut router, dir) = test_router("opportunistic_wait");
    let network = MockNetwork::with_path(DEST);
    router
        .handle_outbound(message(DeliveryMethod::Opportunistic, 200))
        .unwrap();

    router.process_outbound_with(&network);
    router.process_outbound_with(&network);

    assert_eq!(network.opportunistic.lock().unwrap().len(), 1);
    let msg = &router.outbound[0];
    assert_eq!(msg.state, MessageState::Sent);
    let next = msg.tracking.next_delivery_attempt.unwrap();
    let wait = next - lxmf_rs::router::now_timestamp();
    assert!(
        (DELIVERY_RETRY_WAIT as f64 - 1.0..=DELIVERY_RETRY_WAIT as f64).contains(&wait),
        "retry scheduled after the delivery retry wait, got {wait}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn delivered_messages_are_removed_and_retained() {
    let (mut router, dir) = test_router("delivered_removed");
    let network = MockNetwork::with_path(DEST);
    router
        .handle_outbound(message(DeliveryMethod::Opportunistic, 200))
        .unwrap();
    router.process_outbound_with(&network);
    router.outbound[0].state = MessageState::Delivered;

    router.process_outbound_with(&network);

    assert!(router.outbound.is_empty());
    assert_eq!(*network.retained.lock().unwrap(), vec![DEST]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn oversized_opportunistic_message_falls_back_to_direct() {
    let (mut router, dir) = test_router("opportunistic_fallback");
    // Content of ENCRYPTED_PACKET_MAX_CONTENT fits a single packet...
    router
        .handle_outbound(message(
            DeliveryMethod::Opportunistic,
            LXMF_OVERHEAD + ENCRYPTED_PACKET_MAX_CONTENT,
        ))
        .unwrap();
    // ...one byte more needs a link.
    router
        .handle_outbound(message(
            DeliveryMethod::Opportunistic,
            LXMF_OVERHEAD + ENCRYPTED_PACKET_MAX_CONTENT + 1,
        ))
        .unwrap();

    assert_eq!(router.outbound[0].method, DeliveryMethod::Opportunistic);
    assert_eq!(router.outbound[1].method, DeliveryMethod::Direct);
    assert_eq!(router.outbound[1].representation, Representation::Packet);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn direct_delivery_establishes_link_then_sends() {
    let (mut router, dir) = test_router("direct_link");
    let network = MockNetwork::with_path(DEST);
    router
        .handle_outbound(message(DeliveryMethod::Direct, 300))
        .unwrap();

    router.process_outbound_with(&network);
    assert_eq!(*network.links.lock().unwrap(), vec![DEST]);
    assert_eq!(router.outbound[0].state, MessageState::Outbound);

    // The link comes up (normally reported by on_link_established).
    router.process_outbound_with(&network);
    let link_id = router.pending_direct_links.remove(&DEST).unwrap();
    router.direct_links.insert(DEST, link_id);

    router.process_outbound_with(&network);
    assert_eq!(*network.link_packets.lock().unwrap(), vec![link_id]);
    assert_eq!(router.outbound[0].state, MessageState::Delivered);

    router.process_outbound_with(&network);
    assert!(router.outbound.is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn large_direct_message_is_sent_as_resource() {
    let (mut router, dir) = test_router("direct_resource");
    let network = MockNetwork::with_path(DEST);
    let link_id = [0xEE; 16];
    router.direct_links.insert(DEST, link_id);
    router
        .handle_outbound(message(DeliveryMethod::Direct, 2_000))
        .unwrap();

    router.process_outbound_with(&network);

    assert_eq!(
        *network.resources.lock().unwrap(),
        vec![(link_id, 2_000, false)]
    );
    assert_eq!(router.outbound[0].state, MessageState::Sending);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn propagated_resources_carry_the_app_flag() {
    let (mut router, dir) = test_router("propagated_app_flag");
    let propagation_node = [0xB0; 16];
    let network = MockNetwork::with_path(propagation_node);
    let link_id = [0xB1; 16];
    router.set_propagation_dest_hash(propagation_node);
    router.propagation_link = Some(link_id);

    let mut msg = message(DeliveryMethod::Propagated, 600);
    msg.propagation_packed = Some(vec![0u8; LINK_PACKET_MAX_CONTENT + 1]);
    router.handle_outbound(msg).unwrap();
    assert_eq!(router.outbound[0].representation, Representation::Resource);

    router.process_outbound_with(&network);

    assert_eq!(
        *network.resources.lock().unwrap(),
        vec![(link_id, LINK_PACKET_MAX_CONTENT + 1, true)]
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn small_propagated_message_is_sent_as_link_packet() {
    let (mut router, dir) = test_router("propagated_packet");
    let propagation_node = [0xB0; 16];
    let network = MockNetwork::with_path(propagation_node);
    let link_id = [0xB1; 16];
    router.set_propagation_dest_hash(propagation_node);
    router.propagation_link = Some(link_id);

    let mut msg = message(DeliveryMethod::Propagated, 200);
    msg.propagation_packed = Some(vec![0u8; LINK_PACKET_MAX_CONTENT]);
    router.handle_outbound(msg).unwrap();
    router.process_outbound_with(&network);

    assert_eq!(*network.link_packets.lock().unwrap(), vec![link_id]);
    assert_eq!(router.outbound[0].state, MessageState::Sent);
    router.process_outbound_with(&network);
    assert!(router.outbound.is_empty(), "propagated and accepted");
    assert_eq!(*network.retained.lock().unwrap(), vec![DEST]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn slow_path_holds_later_messages_to_the_same_target() {
    let (mut router, dir) = test_router("slow_path_hold");
    let network = MockNetwork::with_path(DEST);
    // A first hop 20 s above the per-hop allowance: round trip 46 s.
    network
        .first_hop
        .lock()
        .unwrap()
        .insert(DEST, DEFAULT_PER_HOP_TIMEOUT + 20.0);
    router
        .handle_outbound(message(DeliveryMethod::Opportunistic, 200))
        .unwrap();
    router
        .handle_outbound(message(DeliveryMethod::Opportunistic, 210))
        .unwrap();

    router.process_outbound_with(&network);

    assert_eq!(network.opportunistic.lock().unwrap().len(), 1);
    assert_eq!(router.outbound[0].state, MessageState::Sent);
    assert!(router.outbound[0].tracking.sent_on_slow_path);
    assert_eq!(router.outbound[0].tracking.max_delivery_attempts, Some(3));
    assert_eq!(router.outbound[1].attempts, 0, "second message is held");

    // Once the first is delivered, the second goes out.
    router.outbound[0].state = MessageState::Delivered;
    router.process_outbound_with(&network);
    assert_eq!(network.opportunistic.lock().unwrap().len(), 2);
    assert_eq!(router.outbound.len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn path_requests_are_debounced() {
    let (mut router, dir) = test_router("path_debounce");
    let network = MockNetwork::default();
    router
        .handle_outbound(message(DeliveryMethod::Opportunistic, 200))
        .unwrap();
    router
        .handle_outbound(message(DeliveryMethod::Opportunistic, 210))
        .unwrap();

    for _ in 0..3 {
        router.process_outbound_with(&network);
        advance(&mut router);
    }

    assert_eq!(
        *network.path_requests.lock().unwrap(),
        vec![DEST],
        "one path request within the debounce window"
    );
    assert!(router.outbound.iter().all(|msg| msg.tracking.awaiting_path));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn send_errors_fail_the_message() {
    let (mut router, dir) = test_router("send_error");
    let network = MockNetwork::with_path(DEST);
    *network.fail_sends.lock().unwrap() = true;
    let mut msg = message(DeliveryMethod::Opportunistic, 200);
    let failed = counting_failed_callback(&mut msg);
    router.handle_outbound(msg).unwrap();

    router.process_outbound_with(&network);

    assert_eq!(failed.load(Ordering::SeqCst), 1);
    assert!(router.outbound.is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn closed_link_requests_path_and_reschedules() {
    let (mut router, dir) = test_router("closed_link");
    let network = MockNetwork::with_path(DEST);
    let mut msg = message(DeliveryMethod::Direct, 300);
    msg.tracking.link_closed = Some(true);
    router.handle_outbound(msg).unwrap();

    router.process_outbound_with(&network);

    assert_eq!(*network.path_requests.lock().unwrap(), vec![DEST]);
    assert!(router.outbound[0].tracking.link_closed.is_none());
    let _ = std::fs::remove_dir_all(dir);
}
