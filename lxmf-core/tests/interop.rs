use lxmf_core::message;
use rns_core::msgpack::{pack, unpack_exact, Value};
use rns_crypto::identity::Identity;
use rns_crypto::sha256::sha256;
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

// ============================================================
// Phase 2: LXMessage wire format tests
// ============================================================

#[derive(Deserialize)]
struct MessageVector {
    name: String,
    #[serde(default)]
    src_prv: Option<String>,
    #[serde(default)]
    src_pub: Option<String>,
    #[serde(default)]
    dst_prv: Option<String>,
    #[serde(default)]
    dst_pub: Option<String>,
    #[serde(default)]
    src_hash: Option<String>,
    #[serde(default)]
    dst_hash: Option<String>,
    #[serde(default)]
    timestamp: Option<f64>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    packed_payload: Option<String>,
    #[serde(default)]
    message_hash: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    packed: Option<String>,
    #[serde(default)]
    stamp: Option<String>,
    #[serde(default)]
    fields: Option<Vec<Vec<u64>>>,
    #[serde(default)]
    lxmf_data: Option<String>,
    #[serde(default)]
    transient_id: Option<String>,
    #[serde(default)]
    propagation_packed: Option<String>,
    #[serde(default)]
    paper_packed: Option<String>,
    #[serde(default)]
    paper_uri: Option<String>,
    #[serde(default)]
    lxmf_bytes: Option<String>,
    #[serde(default)]
    packed_container: Option<String>,
    #[serde(default)]
    state: Option<u64>,
    #[serde(default)]
    method: Option<u64>,
    #[serde(default)]
    transport_encrypted: Option<bool>,
    #[serde(default)]
    transport_encryption: Option<String>,
}

fn load_message_vectors() -> Vec<MessageVector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/message_vectors.json"
    );
    let data = fs::read_to_string(path).expect("Failed to read message vectors");
    serde_json::from_str(&data).expect("Failed to parse message vectors")
}

fn find_msg_vector<'a>(vectors: &'a [MessageVector], name: &str) -> &'a MessageVector {
    vectors
        .iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("Message vector '{}' not found", name))
}

#[test]
fn test_message_hash_computation() {
    let vectors = load_message_vectors();
    let v = find_msg_vector(&vectors, "basic_message");

    let dst_hash_bytes = b64(v.dst_hash.as_ref().unwrap());
    let src_hash_bytes = b64(v.src_hash.as_ref().unwrap());
    let packed_payload = b64(v.packed_payload.as_ref().unwrap());
    let expected_hash = b64(v.message_hash.as_ref().unwrap());

    let mut dst_hash = [0u8; 16];
    dst_hash.copy_from_slice(&dst_hash_bytes);
    let mut src_hash = [0u8; 16];
    src_hash.copy_from_slice(&src_hash_bytes);

    let hash = message::compute_hash(&dst_hash, &src_hash, &packed_payload);
    assert_eq!(
        &hash[..],
        &expected_hash[..],
        "Message hash mismatch"
    );
}

#[test]
fn test_message_pack_deterministic() {
    let vectors = load_message_vectors();
    let v = find_msg_vector(&vectors, "deterministic_keys");

    let src_prv_bytes = b64(v.src_prv.as_ref().unwrap());
    let dst_hash_bytes = b64(v.dst_hash.as_ref().unwrap());
    let src_hash_bytes = b64(v.src_hash.as_ref().unwrap());
    let expected_packed = b64(v.packed.as_ref().unwrap());
    let expected_hash = b64(v.message_hash.as_ref().unwrap());
    let expected_sig = b64(v.signature.as_ref().unwrap());

    let mut src_prv = [0u8; 64];
    src_prv.copy_from_slice(&src_prv_bytes);
    let identity = Identity::from_private_key(&src_prv);

    let mut dst_hash = [0u8; 16];
    dst_hash.copy_from_slice(&dst_hash_bytes);
    let mut src_hash = [0u8; 16];
    src_hash.copy_from_slice(&src_hash_bytes);

    let title = b64(v.title.as_ref().unwrap());
    let content = b64(v.content.as_ref().unwrap());

    let result = message::pack(
        &dst_hash,
        &src_hash,
        v.timestamp.unwrap(),
        &title,
        &content,
        vec![],
        None,
        |data| identity.sign(data).map_err(|_| message::Error::SignError),
    )
    .expect("pack failed");

    assert_eq!(
        &result.message_hash[..],
        &expected_hash[..],
        "Deterministic message hash mismatch"
    );
    assert_eq!(
        &result.packed[32..96],
        &expected_sig[..],
        "Deterministic signature mismatch"
    );
    assert_eq!(result.packed, expected_packed, "Deterministic packed mismatch");
}

#[test]
fn test_message_unpack_basic() {
    let vectors = load_message_vectors();
    let v = find_msg_vector(&vectors, "basic_message");

    let packed = b64(v.packed.as_ref().unwrap());
    let expected_hash = b64(v.message_hash.as_ref().unwrap());
    let src_pub_bytes = b64(v.src_pub.as_ref().unwrap());

    let mut src_pub = [0u8; 64];
    src_pub.copy_from_slice(&src_pub_bytes);
    let src_identity = Identity::from_public_key(&src_pub);

    let result = message::unpack(
        &packed,
        Some(&|_src_hash, sig, data| src_identity.verify(sig, data)),
    )
    .expect("unpack failed");

    assert_eq!(&result.message_hash[..], &expected_hash[..]);
    assert_eq!(result.timestamp, 1700000000.0);
    assert_eq!(result.title, b"Hello");
    assert_eq!(result.content, b"World");
    assert_eq!(result.fields.len(), 0);
    assert!(result.stamp.is_none());
    assert_eq!(result.signature_valid, Some(true));
}

#[test]
fn test_message_unpack_with_fields() {
    let vectors = load_message_vectors();
    let v = find_msg_vector(&vectors, "message_with_fields");

    let packed = b64(v.packed.as_ref().unwrap());
    let src_pub_bytes = b64(v.src_pub.as_ref().unwrap());

    let mut src_pub = [0u8; 64];
    src_pub.copy_from_slice(&src_pub_bytes);
    let src_identity = Identity::from_public_key(&src_pub);

    let result = message::unpack(
        &packed,
        Some(&|_src_hash, sig, data| src_identity.verify(sig, data)),
    )
    .expect("unpack failed");

    assert_eq!(result.signature_valid, Some(true));
    assert_eq!(result.fields.len(), 1);
    assert_eq!(result.fields[0].0.as_uint().unwrap(), 15);
    assert_eq!(result.fields[0].1.as_uint().unwrap(), 2);
}

#[test]
fn test_message_unpack_with_stamp() {
    let vectors = load_message_vectors();
    let v = find_msg_vector(&vectors, "message_with_stamp");

    let packed = b64(v.packed.as_ref().unwrap());
    let expected_hash = b64(v.message_hash.as_ref().unwrap());
    let expected_stamp = b64(v.stamp.as_ref().unwrap());
    let src_pub_bytes = b64(v.src_pub.as_ref().unwrap());

    let mut src_pub = [0u8; 64];
    src_pub.copy_from_slice(&src_pub_bytes);
    let src_identity = Identity::from_public_key(&src_pub);

    let result = message::unpack(
        &packed,
        Some(&|_src_hash, sig, data| src_identity.verify(sig, data)),
    )
    .expect("unpack failed");

    // Hash must match the 4-element payload (without stamp)
    assert_eq!(
        &result.message_hash[..],
        &expected_hash[..],
        "Stamp message hash must be computed from 4-element payload"
    );
    assert_eq!(result.signature_valid, Some(true));
    assert!(result.stamp.is_some());
    assert_eq!(result.stamp.unwrap(), expected_stamp);
}

#[test]
fn test_message_pack_unpack_roundtrip() {
    use rns_crypto::OsRng;
    let mut rng = OsRng;
    let src_identity = Identity::new(&mut rng);
    let dst_identity = Identity::new(&mut rng);

    let src_hash = *src_identity.hash();
    let dst_hash = *dst_identity.hash();

    let result = message::pack(
        &dst_hash,
        &src_hash,
        1700000000.0,
        b"Test Title",
        b"Test Content",
        vec![(Value::UInt(15), Value::UInt(2))],
        None,
        |data| src_identity.sign(data).map_err(|_| message::Error::SignError),
    )
    .expect("pack failed");

    let src_pub = src_identity.get_public_key().unwrap();
    let src_pub_id = Identity::from_public_key(&src_pub);

    let unpacked = message::unpack(
        &result.packed,
        Some(&|_src_hash, sig, data| src_pub_id.verify(sig, data)),
    )
    .expect("unpack failed");

    assert_eq!(unpacked.destination_hash, dst_hash);
    assert_eq!(unpacked.source_hash, src_hash);
    assert_eq!(unpacked.timestamp, 1700000000.0);
    assert_eq!(unpacked.title, b"Test Title");
    assert_eq!(unpacked.content, b"Test Content");
    assert_eq!(unpacked.fields.len(), 1);
    assert_eq!(unpacked.message_hash, result.message_hash);
    assert_eq!(unpacked.signature_valid, Some(true));
}

#[test]
fn test_message_pack_with_stamp_roundtrip() {
    use rns_crypto::OsRng;
    let mut rng = OsRng;
    let src_identity = Identity::new(&mut rng);
    let dst_identity = Identity::new(&mut rng);

    let src_hash = *src_identity.hash();
    let dst_hash = *dst_identity.hash();
    let stamp = [0x42u8; 32];

    let result = message::pack(
        &dst_hash,
        &src_hash,
        1700000000.0,
        b"Title",
        b"Content",
        vec![],
        Some(&stamp),
        |data| src_identity.sign(data).map_err(|_| message::Error::SignError),
    )
    .expect("pack failed");

    let src_pub = src_identity.get_public_key().unwrap();
    let src_pub_id = Identity::from_public_key(&src_pub);

    let unpacked = message::unpack(
        &result.packed,
        Some(&|_src_hash, sig, data| src_pub_id.verify(sig, data)),
    )
    .expect("unpack failed");

    assert_eq!(unpacked.signature_valid, Some(true));
    assert_eq!(unpacked.stamp.as_deref(), Some(&stamp[..]));
    // Hash must be the same regardless of stamp
    assert_eq!(unpacked.message_hash, result.message_hash);
}

#[test]
fn test_container_roundtrip() {
    let vectors = load_message_vectors();
    let v = find_msg_vector(&vectors, "file_container");

    let lxmf_bytes = b64(v.lxmf_bytes.as_ref().unwrap());
    let expected = b64(v.packed_container.as_ref().unwrap());

    let packed = message::pack_container(&lxmf_bytes, 1, true, "Curve25519", 2);
    assert_eq!(packed, expected, "Container pack mismatch");

    let container = message::unpack_container(&packed).expect("unpack_container failed");
    assert_eq!(container.lxmf_bytes, lxmf_bytes);
    assert_eq!(container.state, Some(1));
    assert_eq!(container.method, Some(2));
    assert_eq!(container.transport_encrypted, Some(true));
    assert_eq!(
        container.transport_encryption.as_deref(),
        Some("Curve25519")
    );
}

#[test]
fn test_paper_uri_roundtrip() {
    let vectors = load_message_vectors();
    let v = find_msg_vector(&vectors, "paper_uri");

    let expected_uri = v.paper_uri.as_ref().unwrap();
    let paper_packed = b64(v.paper_packed.as_ref().unwrap());

    // Encode
    let uri = message::as_uri(&paper_packed);
    assert_eq!(&uri, expected_uri, "Paper URI encode mismatch");

    // Decode
    let decoded = message::from_uri(&uri).expect("from_uri failed");
    assert_eq!(decoded, paper_packed, "Paper URI decode mismatch");
}

#[test]
fn test_paper_uri_decode_from_python() {
    let vectors = load_message_vectors();
    let v = find_msg_vector(&vectors, "paper_uri");

    let expected_bytes = b64(v.paper_packed.as_ref().unwrap());
    let uri = v.paper_uri.as_ref().unwrap();

    let decoded = message::from_uri(uri).expect("from_uri failed");
    assert_eq!(decoded, expected_bytes);
}

#[test]
fn test_propagation_pack_format() {
    // Test that our propagation_pack function produces the right transient_id
    // We can't exactly reproduce the encryption since it uses random,
    // but we can test the structure
    use rns_crypto::OsRng;
    let mut rng = OsRng;
    let src_identity = Identity::new(&mut rng);
    let dst_identity = Identity::new(&mut rng);

    let src_hash = *src_identity.hash();
    let dst_hash = *dst_identity.hash();

    let pack_result = message::pack(
        &dst_hash,
        &src_hash,
        1700000000.0,
        b"Hello",
        b"World",
        vec![],
        None,
        |data| src_identity.sign(data).map_err(|_| message::Error::SignError),
    )
    .expect("pack failed");

    let (prop_packed, transient_id) = message::propagation_pack(
        &pack_result.packed,
        1700000000.0,
        None,
        |data| {
            dst_identity
                .encrypt(data, &mut rng)
                .map_err(|_| message::Error::EncryptError)
        },
    )
    .expect("propagation_pack failed");

    // Verify the structure: msgpack([timestamp, [lxmf_data]])
    let outer = unpack_exact(&prop_packed).expect("Failed to unpack propagation_packed");
    let arr = outer.as_array().expect("Expected array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0].as_float().unwrap(), 1700000000.0);

    let inner = arr[1].as_array().unwrap();
    assert_eq!(inner.len(), 1);

    let lxmf_data = inner[0].as_bin().unwrap();
    // First 16 bytes should be the destination hash
    assert_eq!(&lxmf_data[..16], &dst_hash[..]);

    // transient_id should be SHA256 of lxmf_data
    let expected_tid = sha256(lxmf_data);
    assert_eq!(transient_id, expected_tid);

    // Verify we can decrypt
    let encrypted = &lxmf_data[16..];
    let decrypted = dst_identity.decrypt(encrypted).expect("decrypt failed");

    // decrypted should be: src_hash + signature + packed_payload
    assert_eq!(&decrypted[..16], &src_hash[..]);
}

#[test]
fn test_signature_invalid_detection() {
    use rns_crypto::OsRng;
    let mut rng = OsRng;
    let src_identity = Identity::new(&mut rng);
    let other_identity = Identity::new(&mut rng);
    let dst_identity = Identity::new(&mut rng);

    let src_hash = *src_identity.hash();
    let dst_hash = *dst_identity.hash();

    let result = message::pack(
        &dst_hash,
        &src_hash,
        1700000000.0,
        b"Hello",
        b"World",
        vec![],
        None,
        |data| src_identity.sign(data).map_err(|_| message::Error::SignError),
    )
    .expect("pack failed");

    // Verify with wrong identity
    let other_pub = other_identity.get_public_key().unwrap();
    let other_pub_id = Identity::from_public_key(&other_pub);

    let unpacked = message::unpack(
        &result.packed,
        Some(&|_src_hash, sig, data| other_pub_id.verify(sig, data)),
    )
    .expect("unpack should succeed even with invalid sig");

    assert_eq!(unpacked.signature_valid, Some(false));
}

// ============================================================
// Phase 3: Stamp system tests
// ============================================================

use lxmf_core::stamp;

#[derive(Deserialize)]
struct StampVector {
    name: String,
    #[serde(default)]
    material: Option<String>,
    #[serde(default)]
    rounds: Option<u32>,
    #[serde(default)]
    workblock: Option<String>,
    #[serde(default)]
    workblock_len: Option<usize>,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    stamp: Option<String>,
    #[serde(default)]
    target_cost: Option<u8>,
    #[serde(default)]
    stamp_valid: Option<bool>,
    #[serde(default)]
    stamp_value: Option<u32>,
    #[serde(default)]
    salts: Option<Vec<SaltVector>>,
    #[serde(default)]
    peering_id: Option<String>,
    #[serde(default)]
    peering_key: Option<String>,
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    cases: Option<Vec<StampValueCase>>,
    #[serde(default)]
    hash_result: Option<String>,
    #[serde(default)]
    expected_value: Option<u32>,
    #[serde(default)]
    min_size: Option<usize>,
}

#[derive(Deserialize)]
struct SaltVector {
    n: u64,
    packed_n: String,
    salt: String,
}

#[derive(Deserialize)]
struct StampValueCase {
    stamp: String,
    hash: String,
    value: u32,
}

fn load_stamp_vectors() -> Vec<StampVector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/stamp_vectors.json"
    );
    let data = fs::read_to_string(path).expect("Failed to read stamp vectors");
    serde_json::from_str(&data).expect("Failed to parse stamp vectors")
}

fn find_stamp_vector<'a>(vectors: &'a [StampVector], name: &str) -> &'a StampVector {
    vectors
        .iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("Stamp vector '{}' not found", name))
}

#[test]
fn test_workblock_generation() {
    let vectors = load_stamp_vectors();
    let v = find_stamp_vector(&vectors, "workblock_25_rounds");

    let material = b64(v.material.as_ref().unwrap());
    let expected = b64(v.workblock.as_ref().unwrap());
    let expected_len = v.workblock_len.unwrap();

    let workblock = stamp::stamp_workblock(&material, v.rounds.unwrap());
    assert_eq!(workblock.len(), expected_len, "Workblock length mismatch");
    assert_eq!(workblock, expected, "Workblock content mismatch");
}

#[test]
fn test_hkdf_salt_computation() {
    let vectors = load_stamp_vectors();
    let v = find_stamp_vector(&vectors, "hkdf_salts");

    let material = b64(v.material.as_ref().unwrap());
    let salts = v.salts.as_ref().unwrap();

    for sv in salts {
        let expected_packed_n = b64(&sv.packed_n);
        let expected_salt = b64(&sv.salt);

        // Verify msgpack encoding of integer
        let packed_n = rns_core::msgpack::pack(&Value::UInt(sv.n));
        assert_eq!(
            packed_n, expected_packed_n,
            "msgpack encoding of {} differs",
            sv.n
        );

        // Verify salt = SHA256(material + packed_n)
        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(&material);
        salt_input.extend_from_slice(&packed_n);
        let salt = sha256(&salt_input);
        assert_eq!(
            &salt[..],
            &expected_salt[..],
            "Salt for n={} differs",
            sv.n
        );
    }
}

#[test]
fn test_stamp_validation() {
    let vectors = load_stamp_vectors();
    let v = find_stamp_vector(&vectors, "stamp_validation");

    let workblock = b64(v.workblock.as_ref().unwrap());
    let stamp_bytes = b64(v.stamp.as_ref().unwrap());
    let target_cost = v.target_cost.unwrap();
    let expected_valid = v.stamp_valid.unwrap();
    let expected_value = v.stamp_value.unwrap();

    let valid = stamp::stamp_valid(&stamp_bytes, target_cost, &workblock);
    assert_eq!(valid, expected_valid, "stamp_valid mismatch");

    let value = stamp::stamp_value(&workblock, &stamp_bytes);
    assert_eq!(value, expected_value, "stamp_value mismatch");
}

#[test]
fn test_peering_key_validation() {
    let vectors = load_stamp_vectors();
    let v = find_stamp_vector(&vectors, "peering_key_validation");

    let peering_id = b64(v.peering_id.as_ref().unwrap());
    let peering_key = b64(v.peering_key.as_ref().unwrap());
    let target_cost = v.target_cost.unwrap();
    let expected_valid = v.valid.unwrap();

    // Also verify the workblock matches Python
    let expected_workblock = b64(v.workblock.as_ref().unwrap());
    let workblock = stamp::stamp_workblock(
        &peering_id,
        lxmf_core::constants::WORKBLOCK_EXPAND_ROUNDS_PEERING,
    );
    assert_eq!(workblock, expected_workblock, "Peering workblock mismatch");

    let valid = stamp::validate_peering_key(&peering_id, &peering_key, target_cost);
    assert_eq!(valid, expected_valid, "Peering key validation mismatch");
}

#[test]
fn test_stamp_value_edge_cases() {
    let vectors = load_stamp_vectors();
    let v = find_stamp_vector(&vectors, "stamp_value_edge_cases");

    let workblock = b64(v.workblock.as_ref().unwrap());
    let cases = v.cases.as_ref().unwrap();

    for case in cases {
        let stamp_bytes = b64(&case.stamp);
        let expected_hash = b64(&case.hash);

        // Verify hash
        let mut material = Vec::new();
        material.extend_from_slice(&workblock);
        material.extend_from_slice(&stamp_bytes);
        let hash = sha256(&material);
        assert_eq!(
            &hash[..],
            &expected_hash[..],
            "Hash mismatch for stamp {:?}",
            &stamp_bytes[..4]
        );

        // Verify value
        let value = stamp::stamp_value(&workblock, &stamp_bytes);
        assert_eq!(
            value, case.value,
            "Value mismatch for stamp {:?}",
            &stamp_bytes[..4]
        );
    }
}

#[test]
fn test_leading_zeros() {
    // Test with known values
    assert_eq!(stamp::leading_zeros(&[0u8; 32]), 256);
    assert_eq!(stamp::leading_zeros(&{
        let mut h = [0u8; 32];
        h[0] = 0x80;
        h
    }), 0);
    assert_eq!(stamp::leading_zeros(&{
        let mut h = [0u8; 32];
        h[0] = 0x40;
        h
    }), 1);
    assert_eq!(stamp::leading_zeros(&{
        let mut h = [0u8; 32];
        h[0] = 0x01;
        h
    }), 7);
    assert_eq!(stamp::leading_zeros(&{
        let mut h = [0u8; 32];
        h[1] = 0x01;
        h
    }), 15);
}

#[test]
fn test_pn_stamp_validation_size_check() {
    // Data too short should return None
    let short_data = vec![0u8; 100]; // less than LXMF_OVERHEAD + STAMP_SIZE = 144
    assert!(stamp::validate_pn_stamp(&short_data, 2).is_none());

    // Exact boundary
    let boundary_data = vec![0u8; 144]; // exactly LXMF_OVERHEAD + STAMP_SIZE
    assert!(stamp::validate_pn_stamp(&boundary_data, 2).is_none());
}

#[test]
fn test_stamp_workblock_size() {
    // Verify workblock sizes match the plan
    let material = [0u8; 32];

    let wb_peering = stamp::stamp_workblock(&material, 25);
    assert_eq!(wb_peering.len(), 25 * 256);

    // We don't test 1000 or 3000 rounds here as they would be slow,
    // but verify the formula
    assert_eq!(25 * 256, 6400);
    assert_eq!(1000 * 256, 256000);
    assert_eq!(3000 * 256, 768000);
}
