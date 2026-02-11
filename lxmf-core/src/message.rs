use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use rns_core::msgpack::{self, Value};
use rns_crypto::sha256::sha256;

use crate::constants::*;

#[derive(Debug)]
pub enum Error {
    Msgpack(msgpack::Error),
    InvalidPayload(&'static str),
    InvalidContainer(&'static str),
    SignError,
    EncryptError,
    DecryptError,
    InvalidUri,
}

impl From<msgpack::Error> for Error {
    fn from(e: msgpack::Error) -> Self {
        Error::Msgpack(e)
    }
}

/// Result of packing a message.
pub struct PackResult {
    /// The full packed message bytes: dest_hash + src_hash + signature + msgpack(payload)
    pub packed: Vec<u8>,
    /// SHA-256 hash of (dest_hash + src_hash + packed_payload_without_stamp), the message ID
    pub message_hash: [u8; 32],
}

/// Result of unpacking a message.
pub struct UnpackResult {
    pub destination_hash: [u8; DESTINATION_LENGTH],
    pub source_hash: [u8; DESTINATION_LENGTH],
    pub signature: [u8; SIGNATURE_LENGTH],
    pub timestamp: f64,
    pub title: Vec<u8>,
    pub content: Vec<u8>,
    pub fields: Vec<(Value, Value)>,
    pub stamp: Option<Vec<u8>>,
    pub message_hash: [u8; 32],
    /// Whether the signature was verified (None if no verify_fn provided)
    pub signature_valid: Option<bool>,
}

/// Compute the message hash from destination_hash, source_hash, and packed_payload.
///
/// `packed_payload` MUST be the 4-element payload (without stamp).
pub fn compute_hash(
    dest_hash: &[u8; DESTINATION_LENGTH],
    src_hash: &[u8; DESTINATION_LENGTH],
    packed_payload: &[u8],
) -> [u8; 32] {
    let mut hashed_part = Vec::with_capacity(
        DESTINATION_LENGTH + DESTINATION_LENGTH + packed_payload.len(),
    );
    hashed_part.extend_from_slice(dest_hash);
    hashed_part.extend_from_slice(src_hash);
    hashed_part.extend_from_slice(packed_payload);
    sha256(&hashed_part)
}

/// Pack an LXMF message.
///
/// The `sign_fn` takes the data to sign and returns a 64-byte signature.
/// The stamp, if present, is included in the packed payload but NOT in the hash/signature.
pub fn pack(
    dest_hash: &[u8; DESTINATION_LENGTH],
    src_hash: &[u8; DESTINATION_LENGTH],
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    fields: Vec<(Value, Value)>,
    stamp: Option<&[u8]>,
    sign_fn: impl FnOnce(&[u8]) -> Result<[u8; SIGNATURE_LENGTH], Error>,
) -> Result<PackResult, Error> {
    // Build 4-element payload (without stamp) for hash and signature
    let payload_no_stamp = Value::Array(vec![
        Value::Float(timestamp),
        Value::Bin(title.to_vec()),
        Value::Bin(content.to_vec()),
        Value::Map(fields.clone()),
    ]);
    let packed_payload_no_stamp = msgpack::pack(&payload_no_stamp);

    // Compute message hash
    let message_hash = compute_hash(dest_hash, src_hash, &packed_payload_no_stamp);

    // Build signed_part = hashed_part + message_hash
    let mut signed_part = Vec::with_capacity(
        DESTINATION_LENGTH + DESTINATION_LENGTH + packed_payload_no_stamp.len() + 32,
    );
    signed_part.extend_from_slice(dest_hash);
    signed_part.extend_from_slice(src_hash);
    signed_part.extend_from_slice(&packed_payload_no_stamp);
    signed_part.extend_from_slice(&message_hash);

    let signature = sign_fn(&signed_part)?;

    // Build final payload (may include stamp)
    let final_packed_payload = if let Some(stamp_data) = stamp {
        let payload_with_stamp = Value::Array(vec![
            Value::Float(timestamp),
            Value::Bin(title.to_vec()),
            Value::Bin(content.to_vec()),
            Value::Map(fields),
            Value::Bin(stamp_data.to_vec()),
        ]);
        msgpack::pack(&payload_with_stamp)
    } else {
        packed_payload_no_stamp
    };

    // Build packed message: dest_hash + src_hash + signature + payload
    let mut packed = Vec::with_capacity(
        DESTINATION_LENGTH + DESTINATION_LENGTH + SIGNATURE_LENGTH + final_packed_payload.len(),
    );
    packed.extend_from_slice(dest_hash);
    packed.extend_from_slice(src_hash);
    packed.extend_from_slice(&signature);
    packed.extend_from_slice(&final_packed_payload);

    Ok(PackResult {
        packed,
        message_hash,
    })
}

/// Unpack an LXMF message from packed bytes.
///
/// The `verify_fn` takes (source_hash, signature, signed_data) and returns whether valid.
/// If None, signature validation is skipped.
pub fn unpack(
    data: &[u8],
    verify_fn: Option<&dyn Fn(&[u8; DESTINATION_LENGTH], &[u8; SIGNATURE_LENGTH], &[u8]) -> bool>,
) -> Result<UnpackResult, Error> {
    let min_size = DESTINATION_LENGTH + DESTINATION_LENGTH + SIGNATURE_LENGTH;
    if data.len() < min_size + 1 {
        return Err(Error::InvalidPayload("Message too short"));
    }

    // Extract fixed-size header fields
    let mut dest_hash = [0u8; DESTINATION_LENGTH];
    dest_hash.copy_from_slice(&data[..DESTINATION_LENGTH]);

    let mut src_hash = [0u8; DESTINATION_LENGTH];
    src_hash.copy_from_slice(&data[DESTINATION_LENGTH..DESTINATION_LENGTH * 2]);

    let mut signature = [0u8; SIGNATURE_LENGTH];
    signature.copy_from_slice(&data[DESTINATION_LENGTH * 2..DESTINATION_LENGTH * 2 + SIGNATURE_LENGTH]);

    let payload_bytes = &data[min_size..];

    // Unpack payload
    let payload_value = msgpack::unpack_exact(payload_bytes)?;
    let payload_arr = payload_value
        .as_array()
        .ok_or(Error::InvalidPayload("Payload is not an array"))?;

    if payload_arr.len() < 4 {
        return Err(Error::InvalidPayload("Payload has fewer than 4 elements"));
    }

    // Extract stamp if present
    let stamp = if payload_arr.len() > 4 {
        payload_arr[4].as_bin().map(|b| b.to_vec())
    } else {
        None
    };

    // Re-pack 4-element payload for hash/signature verification
    let payload_4 = Value::Array(payload_arr[..4].to_vec());
    let packed_payload_no_stamp = msgpack::pack(&payload_4);

    // Compute message hash
    let message_hash = compute_hash(&dest_hash, &src_hash, &packed_payload_no_stamp);

    // Build signed_part for verification
    let signature_valid = verify_fn.map(|vf| {
        let mut signed_part = Vec::with_capacity(
            DESTINATION_LENGTH + DESTINATION_LENGTH + packed_payload_no_stamp.len() + 32,
        );
        signed_part.extend_from_slice(&dest_hash);
        signed_part.extend_from_slice(&src_hash);
        signed_part.extend_from_slice(&packed_payload_no_stamp);
        signed_part.extend_from_slice(&message_hash);
        vf(&src_hash, &signature, &signed_part)
    });

    // Extract payload fields
    let timestamp = payload_arr[0]
        .as_float()
        .or_else(|| payload_arr[0].as_number())
        .ok_or(Error::InvalidPayload("Invalid timestamp"))?;
    let title = payload_arr[1]
        .as_bin()
        .ok_or(Error::InvalidPayload("Invalid title"))?
        .to_vec();
    let content = payload_arr[2]
        .as_bin()
        .ok_or(Error::InvalidPayload("Invalid content"))?
        .to_vec();
    let fields = payload_arr[3]
        .as_map()
        .ok_or(Error::InvalidPayload("Invalid fields"))?
        .to_vec();

    Ok(UnpackResult {
        destination_hash: dest_hash,
        source_hash: src_hash,
        signature,
        timestamp,
        title,
        content,
        fields,
        stamp,
        message_hash,
        signature_valid,
    })
}

/// Create propagation-packed data from a packed message.
///
/// Returns (propagation_packed, transient_id).
/// `encrypt_fn` encrypts data with the destination's public key.
pub fn propagation_pack(
    packed: &[u8],
    timestamp: f64,
    propagation_stamp: Option<&[u8]>,
    encrypt_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>, Error>,
) -> Result<(Vec<u8>, [u8; 32]), Error> {
    if packed.len() < DESTINATION_LENGTH + 1 {
        return Err(Error::InvalidPayload("Packed message too short"));
    }

    // Encrypt everything except destination hash
    let dest_hash = &packed[..DESTINATION_LENGTH];
    let encrypted = encrypt_fn(&packed[DESTINATION_LENGTH..])?;

    // Build lxmf_data = dest_hash + encrypted_data
    let mut lxmf_data = Vec::with_capacity(DESTINATION_LENGTH + encrypted.len());
    lxmf_data.extend_from_slice(dest_hash);
    lxmf_data.extend_from_slice(&encrypted);

    // Compute transient_id BEFORE appending stamp
    let transient_id = sha256(&lxmf_data);

    // Append propagation stamp if present
    if let Some(stamp) = propagation_stamp {
        lxmf_data.extend_from_slice(stamp);
    }

    // Wrap in msgpack: [timestamp, [lxmf_data]]
    let propagation_packed = msgpack::pack(&Value::Array(vec![
        Value::Float(timestamp),
        Value::Array(vec![Value::Bin(lxmf_data)]),
    ]));

    Ok((propagation_packed, transient_id))
}

/// Create paper-packed data from a packed message.
///
/// Returns the raw paper-packed bytes (dest_hash + encrypted_rest).
pub fn paper_pack(
    packed: &[u8],
    encrypt_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    if packed.len() < DESTINATION_LENGTH + 1 {
        return Err(Error::InvalidPayload("Packed message too short"));
    }

    let dest_hash = &packed[..DESTINATION_LENGTH];
    let encrypted = encrypt_fn(&packed[DESTINATION_LENGTH..])?;

    let mut paper_packed = Vec::with_capacity(DESTINATION_LENGTH + encrypted.len());
    paper_packed.extend_from_slice(dest_hash);
    paper_packed.extend_from_slice(&encrypted);

    Ok(paper_packed)
}

/// Encode paper-packed bytes as an lxm:// URI.
pub fn as_uri(paper_packed: &[u8]) -> String {
    let encoded = base64url_encode(paper_packed);
    let mut uri = String::with_capacity(6 + encoded.len());
    uri.push_str("lxm://");
    uri.push_str(&encoded);
    uri
}

/// Decode an lxm:// URI back to paper-packed bytes.
pub fn from_uri(uri: &str) -> Result<Vec<u8>, Error> {
    let data_str = uri
        .strip_prefix("lxm://")
        .ok_or(Error::InvalidUri)?;
    base64url_decode(data_str).ok_or(Error::InvalidUri)
}

/// Pack a message into file container format.
pub fn pack_container(
    packed: &[u8],
    state: u8,
    transport_encrypted: bool,
    transport_encryption: &str,
    method: u8,
) -> Vec<u8> {
    let container = Value::Map(vec![
        (Value::Str("state".into()), Value::UInt(state as u64)),
        (Value::Str("lxmf_bytes".into()), Value::Bin(packed.to_vec())),
        (
            Value::Str("transport_encrypted".into()),
            Value::Bool(transport_encrypted),
        ),
        (
            Value::Str("transport_encryption".into()),
            Value::Str(transport_encryption.into()),
        ),
        (Value::Str("method".into()), Value::UInt(method as u64)),
    ]);
    msgpack::pack(&container)
}

/// Result of unpacking a file container.
pub struct ContainerData {
    pub lxmf_bytes: Vec<u8>,
    pub state: Option<u8>,
    pub transport_encrypted: Option<bool>,
    pub transport_encryption: Option<String>,
    pub method: Option<u8>,
}

/// Unpack a file container.
pub fn unpack_container(data: &[u8]) -> Result<ContainerData, Error> {
    let value = msgpack::unpack_exact(data)?;
    let map = value
        .as_map()
        .ok_or(Error::InvalidContainer("Container is not a map"))?;

    let mut lxmf_bytes = None;
    let mut state = None;
    let mut transport_encrypted = None;
    let mut transport_encryption = None;
    let mut method = None;

    for (k, v) in map {
        match k.as_str() {
            Some("lxmf_bytes") => {
                lxmf_bytes = v.as_bin().map(|b| b.to_vec());
            }
            Some("state") => {
                state = v.as_uint().map(|n| n as u8);
            }
            Some("transport_encrypted") => {
                transport_encrypted = v.as_bool();
            }
            Some("transport_encryption") => {
                transport_encryption = v.as_str().map(|s| String::from(s));
            }
            Some("method") => {
                method = v.as_uint().map(|n| n as u8);
            }
            _ => {}
        }
    }

    let lxmf_bytes = lxmf_bytes.ok_or(Error::InvalidContainer("Missing lxmf_bytes"))?;

    Ok(ContainerData {
        lxmf_bytes,
        state,
        transport_encrypted,
        transport_encryption,
        method,
    })
}

// ============================================================
// Base64url encoding/decoding helpers
// ============================================================

fn base64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
        out.push(ALPHABET[n as usize & 0x3F] as char);
        i += 3;
    }
    let remaining = data.len() - i;
    if remaining == 1 {
        let n = (data[i] as u32) << 16;
        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        // No padding
    } else if remaining == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
        // No padding
    }
    out
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: [u8; 128] = {
        let mut t = [255u8; 128];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut i = 0;
        while i < 64 {
            t[chars[i] as usize] = i as u8;
            i += 1;
        }
        t
    };

    let input = input.trim_end_matches('=');
    let bytes: Vec<u8> = input.bytes().collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);

    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = *TABLE.get(bytes[i] as usize)?;
        let b = *TABLE.get(bytes[i + 1] as usize)?;
        let c = *TABLE.get(bytes[i + 2] as usize)?;
        let d = *TABLE.get(bytes[i + 3] as usize)?;
        if a == 255 || b == 255 || c == 255 || d == 255 {
            return None;
        }
        let triple =
            ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push((triple >> 16) as u8);
        out.push((triple >> 8) as u8);
        out.push(triple as u8);
        i += 4;
    }

    let remaining = bytes.len() - i;
    if remaining == 2 {
        let a = *TABLE.get(bytes[i] as usize)?;
        let b = *TABLE.get(bytes[i + 1] as usize)?;
        if a == 255 || b == 255 {
            return None;
        }
        let triple = ((a as u32) << 18) | ((b as u32) << 12);
        out.push((triple >> 16) as u8);
    } else if remaining == 3 {
        let a = *TABLE.get(bytes[i] as usize)?;
        let b = *TABLE.get(bytes[i + 1] as usize)?;
        let c = *TABLE.get(bytes[i + 2] as usize)?;
        if a == 255 || b == 255 || c == 255 {
            return None;
        }
        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6);
        out.push((triple >> 16) as u8);
        out.push((triple >> 8) as u8);
    } else if remaining == 1 {
        return None; // Invalid
    }

    Some(out)
}
