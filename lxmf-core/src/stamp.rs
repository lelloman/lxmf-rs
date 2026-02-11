use alloc::vec::Vec;

use rns_core::msgpack::{self, Value};
use rns_crypto::hkdf::hkdf;
use rns_crypto::sha256::sha256;

use crate::constants::*;

/// Generate a workblock from material with the specified number of HKDF expansion rounds.
///
/// Each round produces 256 bytes via HKDF with a salt derived from SHA256(material + msgpack(n)).
/// Total workblock size = rounds * 256 bytes.
pub fn stamp_workblock(material: &[u8], expand_rounds: u32) -> Vec<u8> {
    let mut workblock = Vec::with_capacity(expand_rounds as usize * 256);
    for n in 0..expand_rounds {
        let packed_n = msgpack::pack(&Value::UInt(n as u64));
        let mut salt_input = Vec::with_capacity(material.len() + packed_n.len());
        salt_input.extend_from_slice(material);
        salt_input.extend_from_slice(&packed_n);
        let salt = sha256(&salt_input);

        let expanded = hkdf(256, material, Some(&salt), None)
            .expect("HKDF expansion should not fail");
        workblock.extend_from_slice(&expanded);
    }
    workblock
}

/// Count leading zero bits in a 32-byte hash.
pub fn leading_zeros(hash: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for &byte in hash.iter() {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Calculate the stamp value (number of leading zero bits in SHA256(workblock + stamp)).
pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u32 {
    let mut material = Vec::with_capacity(workblock.len() + stamp.len());
    material.extend_from_slice(workblock);
    material.extend_from_slice(stamp);
    let hash = sha256(&material);
    leading_zeros(&hash)
}

/// Check if a stamp meets the target cost.
///
/// Returns true if SHA256(workblock + stamp) has >= target_cost leading zero bits.
pub fn stamp_valid(stamp: &[u8], target_cost: u8, workblock: &[u8]) -> bool {
    let mut material = Vec::with_capacity(workblock.len() + stamp.len());
    material.extend_from_slice(workblock);
    material.extend_from_slice(stamp);
    let result = sha256(&material);

    // Check: int.from_bytes(result, "big") <= (1 << (256 - target_cost))
    // Equivalent to: leading_zeros(result) >= target_cost
    // But Python uses `>` not `>=` for the comparison with target:
    //   target = 1 << (256 - target_cost)
    //   int.from_bytes(result) > target -> invalid
    // So valid means: int.from_bytes(result) <= target
    // Which is: leading_zeros >= target_cost
    leading_zeros(&result) >= target_cost as u32
}

/// Validate a peering key against a peering ID and target cost.
///
/// Uses WORKBLOCK_EXPAND_ROUNDS_PEERING (25) rounds.
pub fn validate_peering_key(peering_id: &[u8], key: &[u8], target_cost: u8) -> bool {
    let workblock = stamp_workblock(peering_id, WORKBLOCK_EXPAND_ROUNDS_PEERING);
    stamp_valid(key, target_cost, &workblock)
}

/// Result of validating a propagation node stamp.
pub struct PnStampResult {
    pub transient_id: [u8; 32],
    pub lxm_data: Vec<u8>,
    pub value: u32,
    pub stamp: Vec<u8>,
}

/// Validate a propagation node stamp within transient data.
///
/// The stamp is the last STAMP_SIZE bytes. Returns None if data is too short
/// or stamp is invalid.
pub fn validate_pn_stamp(transient_data: &[u8], target_cost: u8) -> Option<PnStampResult> {
    if transient_data.len() <= LXMF_OVERHEAD + STAMP_SIZE {
        return None;
    }

    let split = transient_data.len() - STAMP_SIZE;
    let lxm_data = &transient_data[..split];
    let stamp = &transient_data[split..];

    let transient_id = sha256(lxm_data);
    let workblock = stamp_workblock(&transient_id, WORKBLOCK_EXPAND_ROUNDS_PN);

    if !stamp_valid(stamp, target_cost, &workblock) {
        return None;
    }

    let value = stamp_value(&workblock, stamp);
    Some(PnStampResult {
        transient_id,
        lxm_data: lxm_data.to_vec(),
        value,
        stamp: stamp.to_vec(),
    })
}
