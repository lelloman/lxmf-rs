use rns_core::msgpack::{pack, unpack_exact, Value};
use serde::Deserialize;
use serde_json;
use std::fs;

// Simple base64 decoder (standard alphabet, with padding)
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

        let input = input.trim_end_matches('=');
        let mut out = Vec::with_capacity(input.len() * 3 / 4);
        let bytes: Vec<u8> = input.bytes().collect();

        let mut i = 0;
        while i + 3 < bytes.len() {
            let a = TABLE[bytes[i] as usize] as u32;
            let b = TABLE[bytes[i + 1] as usize] as u32;
            let c = TABLE[bytes[i + 2] as usize] as u32;
            let d = TABLE[bytes[i + 3] as usize] as u32;
            let triple = (a << 18) | (b << 12) | (c << 6) | d;
            out.push((triple >> 16) as u8);
            out.push((triple >> 8) as u8);
            out.push(triple as u8);
            i += 4;
        }

        let remaining = bytes.len() - i;
        if remaining == 2 {
            let a = TABLE[bytes[i] as usize] as u32;
            let b = TABLE[bytes[i + 1] as usize] as u32;
            let triple = (a << 18) | (b << 12);
            out.push((triple >> 16) as u8);
        } else if remaining == 3 {
            let a = TABLE[bytes[i] as usize] as u32;
            let b = TABLE[bytes[i + 1] as usize] as u32;
            let c = TABLE[bytes[i + 2] as usize] as u32;
            let triple = (a << 18) | (b << 12) | (c << 6);
            out.push((triple >> 16) as u8);
            out.push((triple >> 8) as u8);
        }

        out
    }
}

fn b64(s: &str) -> Vec<u8> {
    base64_impl::decode(s)
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    packed: Option<String>,
    #[serde(default)]
    timestamp: Option<f64>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    fields: Option<serde_json::Value>,
    #[serde(default)]
    stamp: Option<String>,
    #[serde(default)]
    input: Option<serde_json::Value>,
    #[serde(default)]
    values: Option<Vec<IntVector>>,
}

#[derive(Deserialize)]
struct IntVector {
    value: u64,
    packed: String,
}

fn load_vectors() -> Vec<Vector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/msgpack_vectors.json"
    );
    let data = fs::read_to_string(path).expect("Failed to read test vectors");
    serde_json::from_str(&data).expect("Failed to parse test vectors")
}

fn find_vector<'a>(vectors: &'a [Vector], name: &str) -> &'a Vector {
    vectors
        .iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("Vector '{}' not found", name))
}

// ============================================================
// Payload pack/unpack round-trip tests
// ============================================================

#[test]
fn test_payload_no_stamp_pack() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_no_stamp");
    let expected = b64(v.packed.as_ref().unwrap());

    let timestamp = v.timestamp.unwrap();
    let title = b64(v.title.as_ref().unwrap());
    let content = b64(v.content.as_ref().unwrap());

    let payload = Value::Array(vec![
        Value::Float(timestamp),
        Value::Bin(title),
        Value::Bin(content),
        Value::Map(vec![]),
    ]);
    let packed = pack(&payload);
    assert_eq!(packed, expected, "payload_no_stamp pack mismatch");
}

#[test]
fn test_payload_no_stamp_unpack() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_no_stamp");
    let packed = b64(v.packed.as_ref().unwrap());

    let value = unpack_exact(&packed).expect("Failed to unpack payload_no_stamp");
    let arr = value.as_array().expect("Expected array");
    assert_eq!(arr.len(), 4);

    let ts = arr[0].as_float().expect("Expected float");
    assert_eq!(ts, 1700000000.0);

    let title = arr[1].as_bin().expect("Expected bin");
    assert_eq!(title, b"Hello");

    let content = arr[2].as_bin().expect("Expected bin");
    assert_eq!(content, b"World");

    let fields = arr[3].as_map().expect("Expected map");
    assert_eq!(fields.len(), 0);
}

#[test]
fn test_payload_with_stamp_pack() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_with_stamp");
    let expected = b64(v.packed.as_ref().unwrap());

    let timestamp = v.timestamp.unwrap();
    let title = b64(v.title.as_ref().unwrap());
    let content = b64(v.content.as_ref().unwrap());
    let stamp = b64(v.stamp.as_ref().unwrap());

    let payload = Value::Array(vec![
        Value::Float(timestamp),
        Value::Bin(title),
        Value::Bin(content),
        Value::Map(vec![]),
        Value::Bin(stamp),
    ]);
    let packed = pack(&payload);
    assert_eq!(packed, expected, "payload_with_stamp pack mismatch");
}

#[test]
fn test_payload_with_stamp_unpack() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_with_stamp");
    let packed = b64(v.packed.as_ref().unwrap());

    let value = unpack_exact(&packed).expect("Failed to unpack payload_with_stamp");
    let arr = value.as_array().expect("Expected array");
    assert_eq!(arr.len(), 5);

    let stamp = arr[4].as_bin().expect("Expected bin");
    let expected_stamp: Vec<u8> = (0..32).collect();
    assert_eq!(stamp, &expected_stamp);
}

#[test]
fn test_payload_with_fields_pack() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_with_fields");
    let expected = b64(v.packed.as_ref().unwrap());

    let timestamp = v.timestamp.unwrap();
    let title = b64(v.title.as_ref().unwrap());
    let content = b64(v.content.as_ref().unwrap());

    let payload = Value::Array(vec![
        Value::Float(timestamp),
        Value::Bin(title),
        Value::Bin(content),
        Value::Map(vec![(Value::UInt(15), Value::UInt(2))]),
    ]);
    let packed = pack(&payload);
    assert_eq!(packed, expected, "payload_with_fields pack mismatch");
}

// ============================================================
// Primitive type tests
// ============================================================

#[test]
fn test_empty_dict() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "empty_dict");
    let expected = b64(v.packed.as_ref().unwrap());

    let packed = pack(&Value::Map(vec![]));
    assert_eq!(packed, expected);

    let unpacked = unpack_exact(&expected).unwrap();
    assert_eq!(unpacked.as_map().unwrap().len(), 0);
}

#[test]
fn test_empty_list() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "empty_list");
    let expected = b64(v.packed.as_ref().unwrap());

    let packed = pack(&Value::Array(vec![]));
    assert_eq!(packed, expected);

    let unpacked = unpack_exact(&expected).unwrap();
    assert_eq!(unpacked.as_array().unwrap().len(), 0);
}

#[test]
fn test_large_binary() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "large_binary");
    let expected = b64(v.packed.as_ref().unwrap());
    let input_data = b64(v.input.as_ref().unwrap().as_str().unwrap());

    let packed = pack(&Value::Bin(input_data.clone()));
    assert_eq!(packed, expected, "large_binary pack mismatch");

    let unpacked = unpack_exact(&expected).unwrap();
    assert_eq!(unpacked.as_bin().unwrap(), &input_data);
}

#[test]
fn test_nil() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "nil_value");
    let expected = b64(v.packed.as_ref().unwrap());

    let packed = pack(&Value::Nil);
    assert_eq!(packed, expected);

    let unpacked = unpack_exact(&expected).unwrap();
    assert!(unpacked.is_nil());
}

#[test]
fn test_bool_true() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "bool_true");
    let expected = b64(v.packed.as_ref().unwrap());

    let packed = pack(&Value::Bool(true));
    assert_eq!(packed, expected);

    let unpacked = unpack_exact(&expected).unwrap();
    assert_eq!(unpacked.as_bool().unwrap(), true);
}

#[test]
fn test_bool_false() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "bool_false");
    let expected = b64(v.packed.as_ref().unwrap());

    let packed = pack(&Value::Bool(false));
    assert_eq!(packed, expected);

    let unpacked = unpack_exact(&expected).unwrap();
    assert_eq!(unpacked.as_bool().unwrap(), false);
}

#[test]
fn test_string_curve25519() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "string_curve25519");
    let expected = b64(v.packed.as_ref().unwrap());

    let packed = pack(&Value::Str("Curve25519".into()));
    assert_eq!(packed, expected);

    let unpacked = unpack_exact(&expected).unwrap();
    assert_eq!(unpacked.as_str().unwrap(), "Curve25519");
}

// ============================================================
// Integer encoding edge cases (critical for stamp workblock)
// ============================================================

#[test]
fn test_integer_encoding() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "integer_encoding");
    let int_vecs = v.values.as_ref().unwrap();

    for iv in int_vecs {
        let expected = b64(&iv.packed);
        let packed = pack(&Value::UInt(iv.value));
        assert_eq!(
            packed, expected,
            "Integer {} pack mismatch: got {:?}, expected {:?}",
            iv.value, packed, expected
        );

        let unpacked = unpack_exact(&expected).unwrap();
        assert_eq!(
            unpacked.as_uint().unwrap(),
            iv.value,
            "Integer {} unpack mismatch",
            iv.value
        );
    }
}

// ============================================================
// Complex structure tests
// ============================================================

#[test]
fn test_file_container_unpack() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "file_container");
    let packed = b64(v.packed.as_ref().unwrap());

    let value = unpack_exact(&packed).expect("Failed to unpack file_container");
    let map = value.as_map().expect("Expected map");
    assert_eq!(map.len(), 5);

    // Verify string keys and values
    let mut found_state = false;
    let mut found_method = false;
    let mut found_encrypted = false;
    for (k, v) in map {
        match k.as_str() {
            Some("state") => {
                assert_eq!(v.as_uint().unwrap(), 1);
                found_state = true;
            }
            Some("method") => {
                assert_eq!(v.as_uint().unwrap(), 2);
                found_method = true;
            }
            Some("transport_encrypted") => {
                assert_eq!(v.as_bool().unwrap(), true);
                found_encrypted = true;
            }
            Some("transport_encryption") => {
                assert_eq!(v.as_str().unwrap(), "Curve25519");
            }
            Some("lxmf_bytes") => {
                assert_eq!(v.as_bin().unwrap(), b"test_data");
            }
            _ => panic!("Unexpected key: {:?}", k),
        }
    }
    assert!(found_state && found_method && found_encrypted);
}

#[test]
fn test_pn_announce_data_unpack() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "pn_announce_data");
    let packed = b64(v.packed.as_ref().unwrap());

    let value = unpack_exact(&packed).expect("Failed to unpack pn_announce_data");
    let arr = value.as_array().expect("Expected array");
    assert_eq!(arr.len(), 7);

    assert_eq!(arr[0].as_bool().unwrap(), false); // legacy flag
    assert_eq!(arr[1].as_uint().unwrap(), 1700000000); // timebase
    assert_eq!(arr[2].as_bool().unwrap(), true); // enabled
    assert_eq!(arr[3].as_uint().unwrap(), 256); // transfer limit
    assert_eq!(arr[4].as_uint().unwrap(), 10240); // sync limit

    let costs = arr[5].as_array().unwrap();
    assert_eq!(costs[0].as_uint().unwrap(), 16); // stamp_cost
    assert_eq!(costs[1].as_uint().unwrap(), 3); // flex
    assert_eq!(costs[2].as_uint().unwrap(), 18); // peering_cost

    assert_eq!(arr[6].as_map().unwrap().len(), 0); // empty metadata
}

#[test]
fn test_delivery_announce_data_unpack() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "delivery_announce_data");
    let packed = b64(v.packed.as_ref().unwrap());

    let value = unpack_exact(&packed).expect("Failed to unpack delivery_announce_data");
    let arr = value.as_array().expect("Expected array");
    assert_eq!(arr.len(), 2);

    assert_eq!(arr[0].as_bin().unwrap(), b"TestNode");
    assert_eq!(arr[1].as_uint().unwrap(), 16);
}

#[test]
fn test_propagation_pack_unpack() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "propagation_pack");
    let packed = b64(v.packed.as_ref().unwrap());

    let value = unpack_exact(&packed).expect("Failed to unpack propagation_pack");
    let arr = value.as_array().expect("Expected array");
    assert_eq!(arr.len(), 2);

    assert_eq!(arr[0].as_float().unwrap(), 1700000000.0);
    let inner = arr[1].as_array().unwrap();
    assert_eq!(inner.len(), 1);
    let data = inner[0].as_bin().unwrap();
    let expected_data: Vec<u8> = (0..64).collect();
    assert_eq!(data, &expected_data);
}

// ============================================================
// Round-trip: pack then unpack equals original
// ============================================================

#[test]
fn test_pn_announce_data_roundtrip() {
    // Build the same structure as Python
    let value = Value::Array(vec![
        Value::Bool(false),
        Value::UInt(1700000000),
        Value::Bool(true),
        Value::UInt(256),
        Value::UInt(10240),
        Value::Array(vec![Value::UInt(16), Value::UInt(3), Value::UInt(18)]),
        Value::Map(vec![]),
    ]);

    let vectors = load_vectors();
    let v = find_vector(&vectors, "pn_announce_data");
    let expected = b64(v.packed.as_ref().unwrap());

    let packed = pack(&value);
    assert_eq!(packed, expected, "pn_announce_data roundtrip pack mismatch");

    let unpacked = unpack_exact(&packed).unwrap();
    assert_eq!(unpacked, value);
}

#[test]
fn test_delivery_announce_data_roundtrip() {
    let value = Value::Array(vec![
        Value::Bin(b"TestNode".to_vec()),
        Value::UInt(16),
    ]);

    let vectors = load_vectors();
    let v = find_vector(&vectors, "delivery_announce_data");
    let expected = b64(v.packed.as_ref().unwrap());

    let packed = pack(&value);
    assert_eq!(
        packed, expected,
        "delivery_announce_data roundtrip pack mismatch"
    );
}

// ============================================================
// Constants validation
// ============================================================

#[test]
fn test_lxmf_overhead_calculation() {
    use lxmf_core::constants::*;
    assert_eq!(DESTINATION_LENGTH, 16);
    assert_eq!(SIGNATURE_LENGTH, 64);
    assert_eq!(TIMESTAMP_SIZE, 8);
    assert_eq!(STRUCT_OVERHEAD, 8);
    assert_eq!(LXMF_OVERHEAD, 112);
}

#[test]
fn test_content_size_limits() {
    use lxmf_core::constants::*;
    // These must match the Python values
    assert_eq!(ENCRYPTED_PACKET_MDU, 399);
    assert_eq!(LINK_PACKET_MDU, 431);
    assert_eq!(PLAIN_PACKET_MDU, 464);
    assert_eq!(ENCRYPTED_PACKET_MAX_CONTENT, 303);
    assert_eq!(LINK_PACKET_MAX_CONTENT, 319);
    assert_eq!(PLAIN_PACKET_MAX_CONTENT, 368);
}

#[test]
fn test_time_constants() {
    use lxmf_core::constants::*;
    assert_eq!(TICKET_EXPIRY, 21 * 24 * 60 * 60);
    assert_eq!(TICKET_GRACE, 5 * 24 * 60 * 60);
    assert_eq!(TICKET_RENEW, 14 * 24 * 60 * 60);
    assert_eq!(TICKET_INTERVAL, 1 * 24 * 60 * 60);
    assert_eq!(MESSAGE_EXPIRY, 30 * 24 * 60 * 60);
    assert_eq!(STAMP_COST_EXPIRY, 45 * 24 * 60 * 60);
    assert_eq!(MAX_UNREACHABLE, 14 * 24 * 60 * 60);
    assert_eq!(SYNC_BACKOFF_STEP, 12 * 60);
}

#[test]
fn test_enum_values() {
    use lxmf_core::constants::*;

    // Message states
    assert_eq!(MessageState::Generating as u8, 0x00);
    assert_eq!(MessageState::Outbound as u8, 0x01);
    assert_eq!(MessageState::Sending as u8, 0x02);
    assert_eq!(MessageState::Sent as u8, 0x04);
    assert_eq!(MessageState::Delivered as u8, 0x08);
    assert_eq!(MessageState::Rejected as u8, 0xFD);
    assert_eq!(MessageState::Cancelled as u8, 0xFE);
    assert_eq!(MessageState::Failed as u8, 0xFF);

    // Delivery methods
    assert_eq!(DeliveryMethod::Opportunistic as u8, 0x01);
    assert_eq!(DeliveryMethod::Direct as u8, 0x02);
    assert_eq!(DeliveryMethod::Propagated as u8, 0x03);
    assert_eq!(DeliveryMethod::Paper as u8, 0x05);

    // Peer states
    assert_eq!(PeerState::Idle as u8, 0x00);
    assert_eq!(PeerState::ResourceTransferring as u8, 0x05);

    // Peer errors
    assert_eq!(PeerError::NoIdentity as u8, 0xF0);
    assert_eq!(PeerError::Timeout as u8, 0xFE);

    // Sync strategies
    assert_eq!(SyncStrategy::Lazy as u8, 0x01);
    assert_eq!(SyncStrategy::Persistent as u8, 0x02);

    // Propagation transfer states
    assert_eq!(PropagationTransferState::Idle as u8, 0x00);
    assert_eq!(PropagationTransferState::Complete as u8, 0x07);
    assert_eq!(PropagationTransferState::Failed as u8, 0xFE);
}

#[test]
fn test_enum_from_u8_roundtrip() {
    use lxmf_core::constants::*;

    // MessageState
    for v in [0x00, 0x01, 0x02, 0x04, 0x08, 0xFD, 0xFE, 0xFF] {
        let state = MessageState::from_u8(v).unwrap();
        assert_eq!(state as u8, v);
    }
    assert!(MessageState::from_u8(0x03).is_none());

    // DeliveryMethod
    for v in [0x01, 0x02, 0x03, 0x05] {
        let method = DeliveryMethod::from_u8(v).unwrap();
        assert_eq!(method as u8, v);
    }
    assert!(DeliveryMethod::from_u8(0x04).is_none());

    // PeerError
    for v in [0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xF6, 0xFD, 0xFE] {
        let err = PeerError::from_u8(v).unwrap();
        assert_eq!(err as u8, v);
    }
    assert!(PeerError::from_u8(0xF2).is_none());
}
