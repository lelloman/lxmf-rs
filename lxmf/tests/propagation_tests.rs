use lxmf_rs::propagation::{ConfigStats, PropagationStore};
use lxmf_core::constants::*;
use rns_crypto::sha256::sha256;
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lxmf_test_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn cleanup(dir: &PathBuf) {
    let _ = fs::remove_dir_all(dir);
}

/// Build fake lxm_data: 16 bytes dest_hash + enough filler to exceed LXMF_OVERHEAD.
fn make_lxm_data(dest_hash: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(dest_hash);
    // Pad to meet LXMF_OVERHEAD requirement (112 bytes minimum)
    let padding_needed = if payload.len() + 16 >= LXMF_OVERHEAD {
        0
    } else {
        LXMF_OVERHEAD - 16 - payload.len()
    };
    data.extend(std::iter::repeat(0u8).take(padding_needed));
    data.extend_from_slice(payload);
    data
}

#[test]
fn test_store_message_basic() {
    let dir = temp_dir("store_basic");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0xAA; 16];
    let lxm_data = make_lxm_data(&dest, b"hello world");
    let stamp = [0x42u8; STAMP_SIZE];
    let expected_tid = sha256(&lxm_data);

    let tid = store
        .store_message(&lxm_data, Some(&stamp), 16, None)
        .expect("store should succeed");

    assert_eq!(tid, expected_tid);
    assert_eq!(store.message_count(), 1);

    let entry = store.entries.get(&tid).unwrap();
    assert_eq!(entry.destination_hash, dest);
    assert_eq!(entry.stamp_value, 16);
    assert_eq!(entry.size, lxm_data.len() + STAMP_SIZE);
    assert!(entry.has_stamp);
    assert!(entry.filepath.exists());

    // Verify file contents
    let file_data = fs::read(&entry.filepath).unwrap();
    assert_eq!(&file_data[..lxm_data.len()], &lxm_data[..]);
    assert_eq!(&file_data[lxm_data.len()..], &stamp[..]);

    cleanup(&dir);
}

#[test]
fn test_store_message_no_stamp() {
    let dir = temp_dir("store_no_stamp");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0xBB; 16];
    let lxm_data = make_lxm_data(&dest, b"no stamp");

    let tid = store.store_message(&lxm_data, None, 0, None).unwrap();
    let entry = store.entries.get(&tid).unwrap();
    assert_eq!(entry.size, lxm_data.len());
    assert!(!entry.has_stamp);

    cleanup(&dir);
}

#[test]
fn test_store_message_duplicate_rejected() {
    let dir = temp_dir("store_dup");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0xCC; 16];
    let lxm_data = make_lxm_data(&dest, b"unique message");

    let first = store.store_message(&lxm_data, None, 0, None);
    assert!(first.is_some());

    let second = store.store_message(&lxm_data, None, 0, None);
    assert!(second.is_none());
    assert_eq!(store.message_count(), 1);

    cleanup(&dir);
}

#[test]
fn test_store_message_too_small() {
    let dir = temp_dir("store_small");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let small_data = vec![0u8; LXMF_OVERHEAD - 1];
    let result = store.store_message(&small_data, None, 0, None);
    assert!(result.is_none());
    assert_eq!(store.message_count(), 0);

    cleanup(&dir);
}

#[test]
fn test_store_distribution_queue() {
    let dir = temp_dir("store_distqueue");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0xDD; 16];
    let lxm1 = make_lxm_data(&dest, b"msg1");
    let lxm2 = make_lxm_data(&dest, b"msg2");
    let from_peer = [0x01; 16];

    let tid1 = store
        .store_message(&lxm1, None, 0, Some(from_peer))
        .unwrap();
    let tid2 = store.store_message(&lxm2, None, 0, None).unwrap();

    let queue = store.flush_distribution_queue();
    assert_eq!(queue.len(), 2);
    assert_eq!(queue[0].0, tid1);
    assert_eq!(queue[0].1, Some(from_peer));
    assert_eq!(queue[1].0, tid2);
    assert_eq!(queue[1].1, None);

    // Queue should be empty after flush
    let queue2 = store.flush_distribution_queue();
    assert!(queue2.is_empty());

    cleanup(&dir);
}

#[test]
fn test_scan_messagestore() {
    let dir = temp_dir("scan");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0xEE; 16];
    let lxm1 = make_lxm_data(&dest, b"scan msg 1");
    let lxm2 = make_lxm_data(&dest, b"scan msg 2");
    let stamp = [0x55u8; STAMP_SIZE];

    let tid1 = store
        .store_message(&lxm1, Some(&stamp), 10, None)
        .unwrap();
    let tid2 = store.store_message(&lxm2, Some(&stamp), 5, None).unwrap();

    // Create a new store and scan
    let mut store2 = PropagationStore::new(dir.clone(), 1024);
    assert_eq!(store2.message_count(), 0);

    store2.scan_messagestore();
    assert_eq!(store2.message_count(), 2);

    let e1 = store2.entries.get(&tid1).unwrap();
    assert_eq!(e1.destination_hash, dest);
    assert_eq!(e1.stamp_value, 10);
    assert_eq!(e1.size, lxm1.len() + STAMP_SIZE);
    assert!(e1.has_stamp);

    let e2 = store2.entries.get(&tid2).unwrap();
    assert_eq!(e2.destination_hash, dest);
    assert_eq!(e2.stamp_value, 5);
    assert!(e2.has_stamp);

    cleanup(&dir);
}

#[test]
fn test_scan_ignores_invalid_files() {
    let dir = temp_dir("scan_invalid");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    // Create invalid files
    fs::write(dir.join("not_a_message.txt"), b"garbage").unwrap();
    fs::write(dir.join("short_1234"), b"short").unwrap();
    // Valid hex but too short (only 32 hex chars = 16 bytes)
    fs::write(
        dir.join("aabbccdd00112233aabbccdd00112233_1234.0"),
        b"short",
    )
    .unwrap();

    store.scan_messagestore();
    assert_eq!(store.message_count(), 0);

    cleanup(&dir);
}

#[test]
fn test_handle_offer_has_all() {
    let dir = temp_dir("offer_all");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0x11; 16];
    let lxm = make_lxm_data(&dest, b"existing");
    let tid = store.store_message(&lxm, None, 0, None).unwrap();

    let response = store.handle_offer(&[tid]);
    match response {
        rns_core::msgpack::Value::Bool(false) => {} // correct
        other => panic!("Expected Bool(false), got {:?}", other),
    }

    cleanup(&dir);
}

#[test]
fn test_handle_offer_wants_all() {
    let dir = temp_dir("offer_want_all");
    let store = PropagationStore::new(dir.clone(), 1024);

    let unknown1 = [0x11; 32];
    let unknown2 = [0x22; 32];

    let response = store.handle_offer(&[unknown1, unknown2]);
    match response {
        rns_core::msgpack::Value::Bool(true) => {} // correct
        other => panic!("Expected Bool(true), got {:?}", other),
    }

    cleanup(&dir);
}

#[test]
fn test_handle_offer_wants_specific() {
    let dir = temp_dir("offer_specific");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0x22; 16];
    let lxm = make_lxm_data(&dest, b"known message");
    let known_tid = store.store_message(&lxm, None, 0, None).unwrap();

    let unknown_tid = [0xFF; 32];

    let response = store.handle_offer(&[known_tid, unknown_tid]);
    match response {
        rns_core::msgpack::Value::Array(arr) => {
            assert_eq!(arr.len(), 1);
            assert_eq!(arr[0].as_bin().unwrap(), &unknown_tid[..]);
        }
        other => panic!("Expected Array with 1 element, got {:?}", other),
    }

    cleanup(&dir);
}

#[test]
fn test_handle_get_wants() {
    let dir = temp_dir("get_wants");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0x33; 16];
    let lxm = make_lxm_data(&dest, b"serve this message");
    let stamp = [0x77u8; STAMP_SIZE];

    let tid = store
        .store_message(&lxm, Some(&stamp), 16, None)
        .unwrap();

    let messages = store.handle_get_wants(&dest, &[tid], None);
    assert_eq!(messages.len(), 1);
    // Stamp should be stripped - message data should be lxm_data without stamp
    assert_eq!(messages[0], lxm);
    assert_eq!(store.client_propagation_messages_served, 1);

    cleanup(&dir);
}

#[test]
fn test_handle_get_wants_wrong_dest() {
    let dir = temp_dir("get_wrong_dest");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0x44; 16];
    let wrong_dest = [0x55; 16];
    let lxm = make_lxm_data(&dest, b"for dest 0x44");

    let tid = store.store_message(&lxm, None, 0, None).unwrap();

    // Request with wrong destination
    let messages = store.handle_get_wants(&wrong_dest, &[tid], None);
    assert!(messages.is_empty());

    cleanup(&dir);
}

#[test]
fn test_handle_get_wants_transfer_limit() {
    let dir = temp_dir("get_limit");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0x55; 16];
    let lxm1 = make_lxm_data(&dest, b"message one with some content");
    let lxm2 = make_lxm_data(&dest, b"message two with some more content here");

    let tid1 = store
        .store_message(&lxm1, Some(&[0u8; STAMP_SIZE]), 8, None)
        .unwrap();
    let tid2 = store
        .store_message(&lxm2, Some(&[0u8; STAMP_SIZE]), 8, None)
        .unwrap();

    // Set a tight transfer limit that fits only the first message
    let limit = lxm1.len() + 24 + 16 + 1; // structure_overhead + per_message_overhead + 1
    let messages = store.handle_get_wants(&dest, &[tid1, tid2], Some(limit));
    assert_eq!(messages.len(), 1);

    cleanup(&dir);
}

#[test]
fn test_handle_get_haves() {
    let dir = temp_dir("get_haves");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0x66; 16];
    let lxm1 = make_lxm_data(&dest, b"msg1 to delete");
    let lxm2 = make_lxm_data(&dest, b"msg2 to keep");

    let tid1 = store.store_message(&lxm1, None, 0, None).unwrap();
    let _tid2 = store.store_message(&lxm2, None, 0, None).unwrap();

    assert_eq!(store.message_count(), 2);

    store.handle_get_haves(&dest, &[tid1]);
    assert_eq!(store.message_count(), 1);
    assert!(!store.entries.contains_key(&tid1));

    cleanup(&dir);
}

#[test]
fn test_handle_get_haves_wrong_dest() {
    let dir = temp_dir("haves_wrong_dest");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0x77; 16];
    let wrong_dest = [0x88; 16];
    let lxm = make_lxm_data(&dest, b"should not be deleted");

    let tid = store.store_message(&lxm, None, 0, None).unwrap();

    store.handle_get_haves(&wrong_dest, &[tid]);
    assert_eq!(store.message_count(), 1); // Not deleted

    cleanup(&dir);
}

#[test]
fn test_list_messages_for_dest() {
    let dir = temp_dir("list_dest");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest1 = [0xAA; 16];
    let dest2 = [0xBB; 16];
    let lxm1 = make_lxm_data(&dest1, b"for dest1 a");
    let lxm2 = make_lxm_data(&dest1, b"for dest1 b with more data");
    let lxm3 = make_lxm_data(&dest2, b"for dest2");

    let tid1 = store.store_message(&lxm1, None, 0, None).unwrap();
    let tid2 = store.store_message(&lxm2, None, 0, None).unwrap();
    let _tid3 = store.store_message(&lxm3, None, 0, None).unwrap();

    let list = store.list_messages_for_dest(&dest1);
    assert_eq!(list.len(), 2);
    // Sorted by size ascending
    let ids: Vec<[u8; 32]> = list.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&tid1));
    assert!(ids.contains(&tid2));
    assert!(list[0].1 <= list[1].1); // size ascending

    let list2 = store.list_messages_for_dest(&dest2);
    assert_eq!(list2.len(), 1);

    cleanup(&dir);
}

#[test]
fn test_clean_expired_messages() {
    let dir = temp_dir("clean_expired");
    let mut store = PropagationStore::new(dir.clone(), 1024 * 1024);

    let dest = [0xCC; 16];
    let lxm = make_lxm_data(&dest, b"will expire");

    let tid = store.store_message(&lxm, None, 0, None).unwrap();

    // Manually backdate the entry past MESSAGE_EXPIRY
    let entry = store.entries.get_mut(&tid).unwrap();
    entry.received = lxmf_rs::router::now_timestamp() - MESSAGE_EXPIRY as f64 - 100.0;

    store.clean_messagestore(&[]);
    assert_eq!(store.message_count(), 0);

    cleanup(&dir);
}

#[test]
fn test_clean_keeps_fresh_messages() {
    let dir = temp_dir("clean_fresh");
    let mut store = PropagationStore::new(dir.clone(), 1024 * 1024);

    let dest = [0xDD; 16];
    let lxm = make_lxm_data(&dest, b"still fresh");

    store.store_message(&lxm, None, 0, None).unwrap();

    store.clean_messagestore(&[]);
    assert_eq!(store.message_count(), 1);

    cleanup(&dir);
}

#[test]
fn test_clean_weight_culling() {
    // Use a very small storage limit to trigger culling
    let dir = temp_dir("clean_cull");
    let mut store = PropagationStore::new(dir.clone(), 1); // 1 KB = 1000 bytes

    let dest = [0xEE; 16];
    // Each message is ~112 bytes + payload, store several to exceed 1000 bytes
    for i in 0..20u8 {
        let payload = vec![i; 50];
        let lxm = make_lxm_data(&dest, &payload);
        store.store_message(&lxm, None, 0, None);
    }

    let count_before = store.message_count();
    assert!(count_before > 0);
    assert!(store.storage_size() > 1000);

    store.clean_messagestore(&[]);

    // After culling, storage should be within limit
    assert!(store.storage_size() <= 1000);
    assert!(store.message_count() < count_before);

    cleanup(&dir);
}

#[test]
fn test_clean_weight_prioritised() {
    let dir = temp_dir("clean_priority");
    let mut store = PropagationStore::new(dir.clone(), 1); // 1 KB limit

    let priority_dest = [0x11; 16];
    let normal_dest = [0x22; 16];

    // Store messages for both destinations
    for i in 0..10u8 {
        let lxm = make_lxm_data(&priority_dest, &vec![i; 50]);
        store.store_message(&lxm, None, 0, None);
    }
    for i in 10..20u8 {
        let lxm = make_lxm_data(&normal_dest, &vec![i; 50]);
        store.store_message(&lxm, None, 0, None);
    }

    // Cull with priority_dest in prioritised list (0.1x weight)
    store.clean_messagestore(&[priority_dest]);

    // Priority messages should survive preferentially
    let priority_count = store
        .entries
        .values()
        .filter(|e| e.destination_hash == priority_dest)
        .count();
    let normal_count = store
        .entries
        .values()
        .filter(|e| e.destination_hash == normal_dest)
        .count();

    // Priority messages should survive more than normal ones
    assert!(
        priority_count >= normal_count,
        "priority {} should be >= normal {}",
        priority_count,
        normal_count
    );

    cleanup(&dir);
}

#[test]
fn test_peer_tracking() {
    let dir = temp_dir("peer_track");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0xFF; 16];
    let lxm = make_lxm_data(&dest, b"peer tracked msg");
    let tid = store.store_message(&lxm, None, 0, None).unwrap();

    let peer1 = [0x01; 16];
    let peer2 = [0x02; 16];

    store.add_unhandled_peer(&tid, peer1);
    store.add_unhandled_peer(&tid, peer2);
    {
        let entry = store.entries.get(&tid).unwrap();
        assert_eq!(entry.unhandled_peers.len(), 2);
        assert_eq!(entry.handled_peers.len(), 0);
    }

    // Mark peer1 as handled
    store.add_handled_peer(&tid, peer1);
    {
        let entry = store.entries.get(&tid).unwrap();
        assert_eq!(entry.handled_peers.len(), 1);
        assert_eq!(entry.unhandled_peers.len(), 1);
        assert!(entry.handled_peers.contains(&peer1));
        assert!(!entry.unhandled_peers.contains(&peer1));
    }

    // Duplicate add should be idempotent
    store.add_handled_peer(&tid, peer1);
    {
        let entry = store.entries.get(&tid).unwrap();
        assert_eq!(entry.handled_peers.len(), 1);
    }

    cleanup(&dir);
}

#[test]
fn test_storage_size() {
    let dir = temp_dir("storage_size");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    assert_eq!(store.storage_size(), 0);

    let dest = [0xAB; 16];
    let lxm1 = make_lxm_data(&dest, b"first");
    let lxm2 = make_lxm_data(&dest, b"second message");

    store.store_message(&lxm1, None, 0, None).unwrap();
    let size1 = store.storage_size();
    assert_eq!(size1, lxm1.len());

    store.store_message(&lxm2, None, 0, None).unwrap();
    let size2 = store.storage_size();
    assert_eq!(size2, lxm1.len() + lxm2.len());

    cleanup(&dir);
}

#[test]
fn test_compile_stats() {
    let dir = temp_dir("stats");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0xCD; 16];
    let lxm = make_lxm_data(&dest, b"stats message");
    store.store_message(&lxm, None, 0, None).unwrap();
    store.client_propagation_messages_received = 10;
    store.client_propagation_messages_served = 5;

    let identity_hash = [0x11; 16];
    let prop_dest_hash = [0x22; 16];
    let start_time = lxmf_rs::router::now_timestamp() - 3600.0;

    let config = ConfigStats {
        delivery_limit: 256,
        propagation_limit: 512,
        sync_limit: 10240,
        propagation_cost: 16,
        propagation_cost_flexibility: 3,
        peering_cost: 18,
        max_peering_cost: 22,
        total_peers: 5,
        max_peers: 20,
    };

    let stats = store.compile_stats(
        &identity_hash,
        &prop_dest_hash,
        start_time,
        &config,
        vec![],
    );

    // Verify it's a map with expected keys
    let map = stats.as_map().unwrap();
    let keys: Vec<&str> = map
        .iter()
        .filter_map(|(k, _)| k.as_str())
        .collect();

    assert!(keys.contains(&"identity_hash"));
    assert!(keys.contains(&"destination_hash"));
    assert!(keys.contains(&"uptime"));
    assert!(keys.contains(&"messagestore"));
    assert!(keys.contains(&"clients"));
    assert!(keys.contains(&"peers"));
    assert!(keys.contains(&"target_stamp_cost"));

    // Check messagestore sub-map
    let ms = map
        .iter()
        .find(|(k, _)| k.as_str() == Some("messagestore"))
        .unwrap()
        .1
        .as_map()
        .unwrap();
    let count = ms
        .iter()
        .find(|(k, _)| k.as_str() == Some("count"))
        .unwrap()
        .1
        .as_uint()
        .unwrap();
    assert_eq!(count, 1);

    cleanup(&dir);
}

#[test]
fn test_filename_format() {
    let dir = temp_dir("filename");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0xAA; 16];
    let lxm = make_lxm_data(&dest, b"filename test");

    let tid = store
        .store_message(&lxm, Some(&[0u8; STAMP_SIZE]), 42, None)
        .unwrap();
    let entry = store.entries.get(&tid).unwrap();
    let filename = entry
        .filepath
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Verify format: {hex_transient_id}_{timestamp}_{stamp_value}
    let parts: Vec<&str> = filename.splitn(3, '_').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].len(), 64); // 32 bytes hex
    let _ts: f64 = parts[1].parse().expect("timestamp should be float");
    assert!(parts[2].starts_with("42"));

    cleanup(&dir);
}

#[test]
fn test_filename_format_no_stamp_value() {
    let dir = temp_dir("filename_no_sv");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0xBB; 16];
    let lxm = make_lxm_data(&dest, b"no stamp value");

    let tid = store.store_message(&lxm, None, 0, None).unwrap();
    let entry = store.entries.get(&tid).unwrap();
    let filename = entry
        .filepath
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // No stamp_value component when value is 0
    let parts: Vec<&str> = filename.splitn(3, '_').collect();
    assert_eq!(parts.len(), 2); // just hex_id and timestamp

    cleanup(&dir);
}

#[test]
fn test_handle_get_wants_without_stamp_keeps_payload() {
    let dir = temp_dir("get_wants_no_stamp");
    let mut store = PropagationStore::new(dir.clone(), 1024);

    let dest = [0x34; 16];
    let lxm = make_lxm_data(&dest, b"unstamped payload");
    let tid = store.store_message(&lxm, None, 0, None).unwrap();

    let messages = store.handle_get_wants(&dest, &[tid], None);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0], lxm);

    cleanup(&dir);
}
