//! LXMF-specific stamp validation functions.
//!
//! Core stamp functions are re-exported from rns_core::stamp.

// Re-export core stamp functions from rns-core
pub use rns_core::stamp::{leading_zeros, stamp_valid, stamp_value, stamp_workblock};

use alloc::vec::Vec;

use rns_crypto::sha256::sha256;

use crate::constants::*;

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
