use lxmf_rs::handlers::{
    decide_propagation_action, handle_delivery_announce, parse_propagation_announce,
    PropagationAnnounceResult, PropagationPeerInfo,
};
use lxmf_rs::tickets::{ticket_stamp, validate_stamp_with_tickets, TicketStore};
use lxmf_core::constants::*;
use rns_crypto::sha256::sha256;

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

        let bytes: Vec<u8> = input
            .bytes()
            .filter(|&b| b != b'=' && b != b'\n' && b != b'\r')
            .collect();
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
        let chunks = bytes.chunks(4);
        for chunk in chunks {
            let mut buf = [0u8; 4];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = TABLE[b as usize & 0x7F];
            }
            out.push((buf[0] << 2) | (buf[1] >> 4));
            if chunk.len() > 2 {
                out.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if chunk.len() > 3 {
                out.push((buf[2] << 6) | buf[3]);
            }
        }
        out
    }
}

fn b64(s: &str) -> Vec<u8> {
    base64_impl::decode(s)
}

#[derive(Debug, serde::Deserialize)]
struct TicketVector {
    name: String,
    ticket: String,
    message_id: String,
    expected_stamp: String,
}

fn load_ticket_vectors() -> Vec<TicketVector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/ticket_vectors.json"
    );
    let data = std::fs::read_to_string(path).expect("Failed to read ticket_vectors.json");
    serde_json::from_str(&data).expect("Failed to parse ticket_vectors.json")
}

// ============================================================
// Delivery announce handler tests
// ============================================================

#[test]
fn test_delivery_announce_with_stamp_cost() {
    // v0.5.0+ format: msgpack([b"TestNode", 16])
    let app_data = rns_core::msgpack::pack(&rns_core::msgpack::Value::Array(vec![
        rns_core::msgpack::Value::Bin(b"TestNode".to_vec()),
        rns_core::msgpack::Value::UInt(16),
    ]));

    let result = handle_delivery_announce([0xAA; 16], Some(&app_data));
    assert_eq!(result.destination_hash, [0xAA; 16]);
    assert_eq!(result.stamp_cost, Some(16));
}

#[test]
fn test_delivery_announce_no_app_data() {
    let result = handle_delivery_announce([0xBB; 16], None);
    assert_eq!(result.stamp_cost, None);
}

#[test]
fn test_delivery_announce_legacy_format() {
    let app_data = b"LegacyNode";
    let result = handle_delivery_announce([0xCC; 16], Some(app_data));
    assert_eq!(result.stamp_cost, None);
}

// ============================================================
// Propagation announce handler tests
// ============================================================

fn make_pn_announce_data(enabled: bool, timebase: u64) -> Vec<u8> {
    use rns_core::msgpack::{pack, Value};
    pack(&Value::Array(vec![
        Value::Bin(b"TestPN".to_vec()),
        Value::UInt(timebase),
        Value::Bool(enabled),
        Value::UInt(256),
        Value::UInt(10240),
        Value::Array(vec![Value::UInt(16), Value::UInt(3), Value::UInt(18)]),
        Value::Map(vec![]),
    ]))
}

#[test]
fn test_propagation_announce_parse() {
    let data = make_pn_announce_data(true, 1700000000);
    let info = parse_propagation_announce([0xDD; 16], Some(&data)).unwrap();

    assert_eq!(info.destination_hash, [0xDD; 16]);
    assert_eq!(info.node_timebase, 1700000000);
    assert!(info.propagation_enabled);
    assert_eq!(info.propagation_transfer_limit, 256);
    assert_eq!(info.propagation_sync_limit, 10240);
    assert_eq!(info.propagation_stamp_cost, 16);
    assert_eq!(info.propagation_stamp_cost_flexibility, 3);
    assert_eq!(info.peering_cost, 18);
}

#[test]
fn test_propagation_announce_invalid() {
    let result = parse_propagation_announce([0xEE; 16], Some(b"garbage"));
    assert!(result.is_none());
}

#[test]
fn test_propagation_announce_no_data() {
    let result = parse_propagation_announce([0xFF; 16], None);
    assert!(result.is_none());
}

// ============================================================
// Propagation action decision tests
// ============================================================

#[test]
fn test_decide_static_peer_updates() {
    let data = make_pn_announce_data(true, 1700000000);
    let info = parse_propagation_announce([0x11; 16], Some(&data)).unwrap();

    let action = decide_propagation_action(
        &info,
        false, // not path response
        true,  // is static peer
        true,  // existing peer
        1000.0,
        false,
        Some(2),
        4,
    );
    assert!(matches!(action, PropagationAnnounceResult::Peer(_)));
}

#[test]
fn test_decide_static_peer_path_response_ignores() {
    let data = make_pn_announce_data(true, 1700000000);
    let info = parse_propagation_announce([0x22; 16], Some(&data)).unwrap();

    let action = decide_propagation_action(
        &info,
        true,  // is path response
        true,  // is static peer
        true,  // existing peer
        1000.0, // already heard from
        false,
        Some(2),
        4,
    );
    assert!(matches!(action, PropagationAnnounceResult::Ignore));
}

#[test]
fn test_decide_static_peer_path_response_first_time() {
    let data = make_pn_announce_data(true, 1700000000);
    let info = parse_propagation_announce([0x33; 16], Some(&data)).unwrap();

    let action = decide_propagation_action(
        &info,
        true, // is path response
        true, // is static peer
        true,
        0.0,  // never heard from
        false,
        Some(2),
        4,
    );
    assert!(matches!(action, PropagationAnnounceResult::Peer(_)));
}

#[test]
fn test_decide_autopeer_in_range() {
    let data = make_pn_announce_data(true, 1700000000);
    let info = parse_propagation_announce([0x44; 16], Some(&data)).unwrap();

    let action = decide_propagation_action(
        &info,
        false, // not path response
        false, // not static
        false, // not existing
        0.0,
        true,  // autopeer enabled
        Some(3),
        4,     // maxdepth
    );
    assert!(matches!(action, PropagationAnnounceResult::Peer(_)));
}

#[test]
fn test_decide_autopeer_out_of_range_existing() {
    let data = make_pn_announce_data(true, 1700000000);
    let info = parse_propagation_announce([0x55; 16], Some(&data)).unwrap();

    let action = decide_propagation_action(
        &info,
        false,
        false,
        true,  // existing peer
        1000.0,
        true,
        Some(5), // hops > maxdepth
        4,
    );
    assert!(matches!(action, PropagationAnnounceResult::Unpeer { .. }));
}

#[test]
fn test_decide_autopeer_out_of_range_new() {
    let data = make_pn_announce_data(true, 1700000000);
    let info = parse_propagation_announce([0x66; 16], Some(&data)).unwrap();

    let action = decide_propagation_action(
        &info,
        false,
        false,
        false, // not existing
        0.0,
        true,
        Some(5), // out of range
        4,
    );
    assert!(matches!(action, PropagationAnnounceResult::Ignore));
}

#[test]
fn test_decide_autopeer_disabled_propagation() {
    let data = make_pn_announce_data(false, 1700000000); // propagation disabled
    let info = parse_propagation_announce([0x77; 16], Some(&data)).unwrap();

    let action = decide_propagation_action(
        &info,
        false,
        false,
        true,
        1000.0,
        true,
        Some(2),
        4,
    );
    assert!(matches!(action, PropagationAnnounceResult::Unpeer { .. }));
}

#[test]
fn test_decide_no_autopeer_ignores() {
    let data = make_pn_announce_data(true, 1700000000);
    let info = parse_propagation_announce([0x88; 16], Some(&data)).unwrap();

    let action = decide_propagation_action(
        &info,
        false,
        false,
        false,
        0.0,
        false, // autopeer disabled
        Some(2),
        4,
    );
    assert!(matches!(action, PropagationAnnounceResult::Ignore));
}

// ============================================================
// Ticket stamp computation tests (with Python vectors)
// ============================================================

#[test]
fn test_ticket_stamp_basic_vector() {
    let vectors = load_ticket_vectors();
    let v = &vectors[0];

    let ticket = b64(&v.ticket);
    let message_id = b64(&v.message_id);
    let expected = b64(&v.expected_stamp);

    let stamp = ticket_stamp(&ticket, &message_id);
    assert_eq!(&stamp[..], &expected[..]);
}

#[test]
fn test_ticket_stamp_ff_vector() {
    let vectors = load_ticket_vectors();
    let v = &vectors[1];

    let ticket = b64(&v.ticket);
    let message_id = b64(&v.message_id);
    let expected = b64(&v.expected_stamp);

    let stamp = ticket_stamp(&ticket, &message_id);
    assert_eq!(&stamp[..], &expected[..]);
}

#[test]
fn test_validate_stamp_with_matching_ticket() {
    let ticket = vec![0x42u8; TICKET_LENGTH];
    let message_id = sha256(b"test_msg");

    let stamp = ticket_stamp(&ticket, &message_id);

    let tickets: Vec<&[u8]> = vec![&ticket];
    let result = validate_stamp_with_tickets(&stamp, &message_id, &tickets);
    assert_eq!(result, Some(COST_TICKET));
}

#[test]
fn test_validate_stamp_no_matching_ticket() {
    let ticket = vec![0x42u8; TICKET_LENGTH];
    let wrong_ticket = vec![0x99u8; TICKET_LENGTH];
    let message_id = sha256(b"test_msg");

    let stamp = ticket_stamp(&ticket, &message_id);

    let tickets: Vec<&[u8]> = vec![&wrong_ticket];
    let result = validate_stamp_with_tickets(&stamp, &message_id, &tickets);
    assert_eq!(result, None);
}

#[test]
fn test_validate_stamp_multiple_tickets() {
    let ticket1 = vec![0x11u8; TICKET_LENGTH];
    let ticket2 = vec![0x22u8; TICKET_LENGTH];
    let ticket3 = vec![0x33u8; TICKET_LENGTH];
    let message_id = sha256(b"test_msg");

    // Stamp generated from ticket2
    let stamp = ticket_stamp(&ticket2, &message_id);

    let tickets: Vec<&[u8]> = vec![&ticket1, &ticket2, &ticket3];
    let result = validate_stamp_with_tickets(&stamp, &message_id, &tickets);
    assert_eq!(result, Some(COST_TICKET));
}

// ============================================================
// TicketStore tests
// ============================================================

#[test]
fn test_ticket_store_generate() {
    let mut store = TicketStore::new();
    let dest = [0xAA; 16];

    let ticket = store.generate_ticket(dest);
    assert!(ticket.is_some());

    let (expiry, ticket_bytes) = ticket.unwrap();
    assert_eq!(ticket_bytes.len(), TICKET_LENGTH);
    assert!(expiry > lxmf_rs::router::now_timestamp());
}

#[test]
fn test_ticket_store_throttle() {
    let mut store = TicketStore::new();
    let dest = [0xBB; 16];

    // Generate first ticket
    let first = store.generate_ticket(dest).unwrap();

    // Record delivery
    store.record_delivery(dest);

    // Second generation should be throttled
    let second = store.generate_ticket(dest);
    assert!(second.is_none());

    // But without the delivery record, it should reuse the existing ticket
    store.last_deliveries.clear();
    let third = store.generate_ticket(dest).unwrap();
    // Should reuse the same ticket since it has enough validity
    assert_eq!(third.0, first.0);
    assert_eq!(third.1, first.1);
}

#[test]
fn test_ticket_store_outbound() {
    let mut store = TicketStore::new();
    let dest = [0xCC; 16];
    let ticket = vec![0x42u8; TICKET_LENGTH];
    let expiry = lxmf_rs::router::now_timestamp() + 86400.0; // +1 day

    store.remember_ticket(dest, expiry, ticket.clone());

    let retrieved = store.get_outbound_ticket(&dest);
    assert_eq!(retrieved, Some(ticket.as_slice()));

    let retrieved_expiry = store.get_outbound_ticket_expiry(&dest);
    assert_eq!(retrieved_expiry, Some(expiry));
}

#[test]
fn test_ticket_store_outbound_expired() {
    let mut store = TicketStore::new();
    let dest = [0xDD; 16];
    let ticket = vec![0x42u8; TICKET_LENGTH];
    let expiry = lxmf_rs::router::now_timestamp() - 1.0; // already expired

    store.remember_ticket(dest, expiry, ticket);

    assert!(store.get_outbound_ticket(&dest).is_none());
    assert!(store.get_outbound_ticket_expiry(&dest).is_none());
}

#[test]
fn test_ticket_store_inbound() {
    let mut store = TicketStore::new();
    let dest = [0xEE; 16];

    // Generate inbound tickets
    let t1 = store.generate_ticket(dest).unwrap();
    store.last_deliveries.clear(); // clear throttle

    // Create a second ticket manually
    let ticket2 = vec![0x99u8; TICKET_LENGTH];
    let expiry2 = lxmf_rs::router::now_timestamp() + TICKET_EXPIRY as f64;
    store
        .inbound
        .entry(dest)
        .or_default()
        .insert(ticket2.clone(), expiry2);

    let tickets = store.get_inbound_tickets(&dest).unwrap();
    assert_eq!(tickets.len(), 2);
}

#[test]
fn test_ticket_store_clean() {
    let mut store = TicketStore::new();
    let dest = [0xFF; 16];

    // Add expired outbound
    store.remember_ticket(dest, lxmf_rs::router::now_timestamp() - 100.0, vec![0x11; 16]);

    // Add valid outbound
    let dest2 = [0xFE; 16];
    store.remember_ticket(
        dest2,
        lxmf_rs::router::now_timestamp() + 86400.0,
        vec![0x22; 16],
    );

    // Add expired inbound (past grace period)
    let expired_ticket = vec![0x33u8; TICKET_LENGTH];
    let expired_expiry =
        lxmf_rs::router::now_timestamp() - TICKET_GRACE as f64 - 100.0;
    store
        .inbound
        .entry(dest)
        .or_default()
        .insert(expired_ticket, expired_expiry);

    store.clean();

    assert!(store.outbound.get(&dest).is_none()); // expired, cleaned
    assert!(store.outbound.get(&dest2).is_some()); // valid, kept
    assert!(
        store.inbound.get(&dest).is_none()
            || store.inbound.get(&dest).unwrap().is_empty()
    );
}

#[test]
fn test_ticket_store_no_tickets_for_unknown_dest() {
    let store = TicketStore::new();
    assert!(store.get_inbound_tickets(&[0x00; 16]).is_none());
    assert!(store.get_outbound_ticket(&[0x00; 16]).is_none());
}
