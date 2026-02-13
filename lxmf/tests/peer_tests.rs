use lxmf_rs::peer::{LxmPeer, SyncAction, SyncPostponeReason};
use lxmf_core::constants::*;
use rns_core::msgpack::{pack, unpack_exact, Value};

// Simple base64 decoder
mod base64_impl {
    pub fn decode(input: &str) -> Vec<u8> {
        const TABLE: [u8; 128] = {
            let mut t = [255u8; 128];
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut i = 0;
            while i < 64 {
                t[chars[i] as usize] = i as u8;
                i += 1;
            }
            t
        };

        let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=' && b != b'\n' && b != b'\r').collect();
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
        let chunks = bytes.chunks(4);
        for chunk in chunks {
            let mut buf = [0u8; 4];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = TABLE[b as usize & 0x7F];
            }
            out.push((buf[0] << 2) | (buf[1] >> 4));
            if chunk.len() > 2 { out.push((buf[1] << 4) | (buf[2] >> 2)); }
            if chunk.len() > 3 { out.push((buf[2] << 6) | buf[3]); }
        }
        out
    }
}

fn b64(s: &str) -> Vec<u8> {
    base64_impl::decode(s)
}

#[derive(Debug, serde::Deserialize)]
struct PeerVector {
    name: String,
    #[serde(default)]
    packed: Option<String>,
    #[serde(default)]
    destination_hash: Option<String>,
    #[serde(default)]
    alive: Option<bool>,
    #[serde(default)]
    last_heard: Option<f64>,
    #[serde(default)]
    offered: Option<u64>,
    #[serde(default)]
    outgoing: Option<u64>,
    #[serde(default)]
    handled_count: Option<usize>,
    #[serde(default)]
    unhandled_count: Option<usize>,
    #[serde(default)]
    propagation_stamp_cost: Option<u8>,
    #[serde(default)]
    peering_cost: Option<u8>,
    #[serde(default)]
    peering_key_value: Option<u32>,
    #[serde(default)]
    peering_key: Option<String>,
    #[serde(default)]
    transient_ids: Option<Vec<String>>,
    #[serde(default)]
    wanted: Option<Vec<String>>,
}

fn load_peer_vectors() -> Vec<PeerVector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/peer_vectors.json"
    );
    let data = std::fs::read_to_string(path).expect("Failed to read peer_vectors.json");
    serde_json::from_str(&data).expect("Failed to parse peer_vectors.json")
}

fn find_peer_vector<'a>(vectors: &'a [PeerVector], name: &str) -> &'a PeerVector {
    vectors
        .iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("Peer vector '{}' not found", name))
}

#[test]
fn test_peer_deserialize_minimal() {
    let vectors = load_peer_vectors();
    let v = find_peer_vector(&vectors, "minimal_peer");
    let packed_bytes = b64(v.packed.as_ref().unwrap());

    let peer = LxmPeer::from_bytes(&packed_bytes)
        .expect("Failed to deserialize minimal peer");

    let expected_hash = b64(v.destination_hash.as_ref().unwrap());
    assert_eq!(&peer.destination_hash[..], &expected_hash[..]);
    assert!(!peer.alive);
    assert_eq!(peer.last_heard, 0.0);
    assert_eq!(peer.sync_strategy, SyncStrategy::Persistent);
    assert!(peer.peering_key.is_none());
    assert!(peer.propagation_stamp_cost.is_none());
    assert_eq!(peer.offered, 0);
    assert!(peer.handled_ids.is_empty());
    assert!(peer.unhandled_ids.is_empty());
}

#[test]
fn test_peer_deserialize_full() {
    let vectors = load_peer_vectors();
    let v = find_peer_vector(&vectors, "full_peer");
    let packed_bytes = b64(v.packed.as_ref().unwrap());

    let peer = LxmPeer::from_bytes(&packed_bytes)
        .expect("Failed to deserialize full peer");

    let expected_hash = b64(v.destination_hash.as_ref().unwrap());
    assert_eq!(&peer.destination_hash[..], &expected_hash[..]);
    assert_eq!(peer.alive, v.alive.unwrap());
    assert!((peer.last_heard - v.last_heard.unwrap()).abs() < 0.01);
    assert_eq!(peer.offered, v.offered.unwrap());
    assert_eq!(peer.outgoing, v.outgoing.unwrap());
    assert_eq!(peer.handled_ids.len(), v.handled_count.unwrap());
    assert_eq!(peer.unhandled_ids.len(), v.unhandled_count.unwrap());
    assert_eq!(
        peer.propagation_stamp_cost,
        Some(v.propagation_stamp_cost.unwrap())
    );
    assert_eq!(peer.peering_cost, Some(v.peering_cost.unwrap()));
    assert_eq!(peer.peering_key_value(), Some(v.peering_key_value.unwrap()));
}

#[test]
fn test_peer_serialize_roundtrip() {
    let mut peer = LxmPeer::new([0xAA; 16]);
    peer.alive = true;
    peer.last_heard = 1700000000.0;
    peer.peering_timebase = 1700000000.0;
    peer.sync_strategy = SyncStrategy::Persistent;
    peer.peering_key = Some((vec![0x42; 32], 20));
    peer.peering_cost = Some(18);
    peer.propagation_stamp_cost = Some(16);
    peer.propagation_stamp_cost_flexibility = Some(3);
    peer.propagation_transfer_limit = Some(256.0);
    peer.propagation_sync_limit = Some(10240);
    peer.offered = 100;
    peer.outgoing = 80;
    peer.incoming = 20;
    peer.rx_bytes = 1000;
    peer.tx_bytes = 2000;
    peer.handled_ids.push([0x11; 32]);
    peer.unhandled_ids.push([0x22; 32]);
    peer.unhandled_ids.push([0x33; 32]);

    let bytes = peer.to_bytes();
    let loaded = LxmPeer::from_bytes(&bytes).expect("Failed to deserialize roundtrip peer");

    assert_eq!(loaded.destination_hash, [0xAA; 16]);
    assert!(loaded.alive);
    assert!((loaded.last_heard - 1700000000.0).abs() < 0.01);
    assert_eq!(loaded.peering_cost, Some(18));
    assert_eq!(loaded.peering_key_value(), Some(20));
    assert_eq!(loaded.propagation_stamp_cost, Some(16));
    assert_eq!(loaded.propagation_stamp_cost_flexibility, Some(3));
    assert_eq!(loaded.offered, 100);
    assert_eq!(loaded.outgoing, 80);
    assert_eq!(loaded.handled_ids.len(), 1);
    assert_eq!(loaded.unhandled_ids.len(), 2);
    assert_eq!(loaded.handled_ids[0], [0x11; 32]);
}

#[test]
fn test_peer_offer_format() {
    let vectors = load_peer_vectors();
    let v = find_peer_vector(&vectors, "offer_format");
    let packed_bytes = b64(v.packed.as_ref().unwrap());

    let val = unpack_exact(&packed_bytes).expect("Failed to unpack offer");
    let arr = val.as_array().expect("Offer should be array");
    assert_eq!(arr.len(), 2);

    let key = arr[0].as_bin().expect("Key should be bin");
    let expected_key = b64(v.peering_key.as_ref().unwrap());
    assert_eq!(key, &expected_key[..]);

    let tids = arr[1].as_array().expect("IDs should be array");
    let expected_tids: Vec<Vec<u8>> = v
        .transient_ids
        .as_ref()
        .unwrap()
        .iter()
        .map(|s| b64(s))
        .collect();
    assert_eq!(tids.len(), expected_tids.len());
    for (tid, expected) in tids.iter().zip(expected_tids.iter()) {
        assert_eq!(tid.as_bin().unwrap(), &expected[..]);
    }
}

#[test]
fn test_peer_response_false() {
    let vectors = load_peer_vectors();
    let v = find_peer_vector(&vectors, "response_has_all");
    let packed_bytes = b64(v.packed.as_ref().unwrap());
    let val = unpack_exact(&packed_bytes).expect("Failed to unpack");
    assert_eq!(val.as_bool(), Some(false));
}

#[test]
fn test_peer_response_true() {
    let vectors = load_peer_vectors();
    let v = find_peer_vector(&vectors, "response_wants_all");
    let packed_bytes = b64(v.packed.as_ref().unwrap());
    let val = unpack_exact(&packed_bytes).expect("Failed to unpack");
    assert_eq!(val.as_bool(), Some(true));
}

#[test]
fn test_peer_response_specific() {
    let vectors = load_peer_vectors();
    let v = find_peer_vector(&vectors, "response_wants_specific");
    let packed_bytes = b64(v.packed.as_ref().unwrap());

    let val = unpack_exact(&packed_bytes).expect("Failed to unpack");
    let arr = val.as_array().expect("Should be array");
    let expected: Vec<Vec<u8>> = v.wanted.as_ref().unwrap().iter().map(|s| b64(s)).collect();
    assert_eq!(arr.len(), expected.len());
    assert_eq!(arr[0].as_bin().unwrap(), &expected[0][..]);
}

#[test]
fn test_peer_sync_checks() {
    let mut peer = LxmPeer::new([0xBB; 16]);

    let (ok, reason) = peer.sync_checks();
    assert!(!ok);
    assert_eq!(reason, SyncPostponeReason::StampCostsUnknown);

    peer.propagation_stamp_cost = Some(16);
    peer.propagation_stamp_cost_flexibility = Some(3);
    peer.peering_cost = Some(18);
    let (ok, reason) = peer.sync_checks();
    assert!(!ok);
    assert_eq!(reason, SyncPostponeReason::PeeringKeyNotReady);

    peer.peering_key = Some((vec![0; 32], 20));
    let (ok, _) = peer.sync_checks();
    assert!(ok);
}

#[test]
fn test_peer_backoff() {
    let mut peer = LxmPeer::new([0xCC; 16]);
    assert_eq!(peer.sync_backoff, 0.0);

    peer.apply_backoff();
    assert_eq!(peer.sync_backoff, SYNC_BACKOFF_STEP as f64);
    assert!(peer.next_sync_attempt > 0.0);

    peer.apply_backoff();
    assert_eq!(peer.sync_backoff, 2.0 * SYNC_BACKOFF_STEP as f64);

    peer.reset_backoff();
    assert_eq!(peer.sync_backoff, 0.0);
}

#[test]
fn test_peer_message_queues() {
    let mut peer = LxmPeer::new([0xDD; 16]);
    let tid1 = [0x11; 32];
    let tid2 = [0x22; 32];

    peer.queue_unhandled_message(tid1);
    peer.queue_unhandled_message(tid2);
    assert!(peer.has_queued_items());

    peer.process_queues();
    assert!(!peer.has_queued_items());
    assert_eq!(peer.unhandled_ids.len(), 2);
    assert!(peer.handled_ids.is_empty());

    peer.queue_handled_message(tid1);
    peer.process_queues();
    assert_eq!(peer.handled_ids.len(), 1);
    assert_eq!(peer.unhandled_ids.len(), 1);
    assert_eq!(peer.handled_ids[0], tid1);
    assert_eq!(peer.unhandled_ids[0], tid2);

    // Already-handled message should not be re-added as unhandled
    peer.queue_unhandled_message(tid1);
    peer.process_queues();
    assert_eq!(peer.unhandled_ids.len(), 1);

    peer.purge_message(&tid2);
    assert!(peer.unhandled_ids.is_empty());
}

#[test]
fn test_peer_offer_response_false() {
    let mut peer = LxmPeer::new([0xEE; 16]);
    let tid1 = [0x11; 32];
    let tid2 = [0x22; 32];
    peer.last_offer = vec![tid1, tid2];
    peer.unhandled_ids = vec![tid1, tid2];

    let response = pack(&Value::Bool(false));
    let action = peer.handle_offer_response(&response);
    assert!(matches!(action, SyncAction::TeardownLink));
    assert_eq!(peer.handled_ids.len(), 2);
    assert!(peer.unhandled_ids.is_empty());
}

#[test]
fn test_peer_offer_response_wants_all() {
    let mut peer = LxmPeer::new([0xFF; 16]);
    let tid1 = [0x11; 32];
    let tid2 = [0x22; 32];
    peer.last_offer = vec![tid1, tid2];

    let response = pack(&Value::Bool(true));
    let action = peer.handle_offer_response(&response);
    match action {
        SyncAction::TransferMessages(msgs) => {
            assert_eq!(msgs.len(), 2);
            assert_eq!(msgs[0], tid1);
            assert_eq!(msgs[1], tid2);
        }
        _ => panic!("Expected TransferMessages"),
    }
    assert_eq!(peer.state, PeerState::ResourceTransferring);
}

#[test]
fn test_peer_offer_response_wants_specific() {
    let mut peer = LxmPeer::new([0xAA; 16]);
    let tid1 = [0x11; 32];
    let tid2 = [0x22; 32];
    peer.last_offer = vec![tid1, tid2];
    peer.unhandled_ids = vec![tid1, tid2];

    let response = pack(&Value::Array(vec![Value::Bin(tid1.to_vec())]));
    let action = peer.handle_offer_response(&response);
    match action {
        SyncAction::TransferMessages(msgs) => {
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0], tid1);
        }
        _ => panic!("Expected TransferMessages"),
    }
    assert!(peer.handled_ids.contains(&tid2));
}

#[test]
fn test_peer_selection() {
    let mut peers = vec![
        LxmPeer::new([0x01; 16]),
        LxmPeer::new([0x02; 16]),
        LxmPeer::new([0x03; 16]),
    ];

    peers[0].unhandled_ids.push([0xAA; 32]);
    peers[1].unhandled_ids.push([0xBB; 32]);
    peers[2].unhandled_ids.push([0xCC; 32]);

    peers[0].sync_transfer_rate = 100000.0;
    peers[1].sync_transfer_rate = 50000.0;

    let selected = lxmf_rs::peer::select_peers_for_sync(&peers, 2);
    assert!(!selected.is_empty());
    assert!(selected.contains(&0)); // fastest
    assert!(selected.contains(&1)); // second fastest
    assert!(selected.contains(&2)); // unknown pool
}

#[test]
fn test_peer_resource_completed() {
    let mut peer = LxmPeer::new([0xAA; 16]);
    let tid1 = [0x11; 32];
    let tid2 = [0x22; 32];

    peer.unhandled_ids = vec![tid1, tid2];
    peer.currently_transferring_messages = Some(vec![tid1, tid2]);
    peer.current_sync_transfer_started = lxmf_rs::router::now_timestamp() - 1.0;
    peer.state = PeerState::ResourceTransferring;

    peer.handle_resource_completed(1024);

    assert_eq!(peer.state, PeerState::Idle);
    assert!(peer.currently_transferring_messages.is_none());
    assert_eq!(peer.handled_ids.len(), 2);
    assert!(peer.unhandled_ids.is_empty());
    assert_eq!(peer.offered, 2);
    assert_eq!(peer.outgoing, 2);
    assert_eq!(peer.tx_bytes, 1024);
    assert!(peer.alive);
}
