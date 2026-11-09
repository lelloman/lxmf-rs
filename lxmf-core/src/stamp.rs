//! LXMF-specific stamp validation functions.
//!
//! Core stamp functions are re-exported from rns_core::stamp. Since upstream
//! LXMF 1.3 (6e898e6, 98e09bb) stamp costs and values are fractional, held on
//! the 1/256 fixed-point grid of `RNS.Stamps` as [`StampCost`] and
//! [`StampValue`].

// Re-export core stamp functions from rns-core
pub use rns_core::stamp::{
    clamp_cost, leading_zeros, stamp_valid, stamp_value, stamp_workblock, StampCost, StampValue,
};

use alloc::string::String;
use alloc::vec::Vec;

use rns_crypto::sha256::sha256;

use crate::constants::*;

/// Quantize a value onto the cost grid, clamped to the stamp cost cap
/// (`RNS.Stamps.quantize_cost`). Upstream applies this to stamp values before
/// storing or comparing them.
pub fn quantize_value(value: StampValue) -> StampCost {
    StampCost::from_fp(value.fp())
}

/// Format a quantized cost or value the way Python's `str(float)` does, as
/// used in propagation message store filenames (`<id>_<received>_<value>`).
pub fn format_cost(cost: StampCost) -> String {
    format_py_float(cost.as_f64())
}

/// Format an `f64` like Python's `repr(float)` for values that are finite:
/// the shortest round-tripping representation, always with a decimal point.
pub fn format_py_float(value: f64) -> String {
    let text = alloc::format!("{}", value);
    if value.is_finite() && !text.contains('.') && !text.contains('e') {
        alloc::format!("{}.0", text)
    } else {
        text
    }
}

/// The minimum stamp cost a propagation node accepts from clients:
/// `max(0, target - flexibility)`.
pub fn min_accepted_cost(target: StampCost, flexibility: StampCost) -> StampCost {
    StampCost::from_fp(target.fp().saturating_sub(flexibility.fp()))
}

/// Validate a peering key against a peering ID and target cost.
///
/// Uses WORKBLOCK_EXPAND_ROUNDS_PEERING (25) rounds.
pub fn validate_peering_key(peering_id: &[u8], key: &[u8], target_cost: StampCost) -> bool {
    let workblock = stamp_workblock(peering_id, WORKBLOCK_EXPAND_ROUNDS_PEERING);
    stamp_valid(key, target_cost, &workblock)
}

/// Result of validating a propagation node stamp.
pub struct PnStampResult {
    pub transient_id: [u8; 32],
    pub lxm_data: Vec<u8>,
    pub value: StampValue,
    pub stamp: Vec<u8>,
}

/// Validate a propagation node stamp within transient data.
///
/// The stamp is the last STAMP_SIZE bytes. Returns None if data is too short
/// or stamp is invalid.
pub fn validate_pn_stamp(transient_data: &[u8], target_cost: StampCost) -> Option<PnStampResult> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn py_float_formatting_matches_python_repr() {
        assert_eq!(format_py_float(17.0), "17.0");
        assert_eq!(format_py_float(17.25390625), "17.25390625");
        assert_eq!(format_py_float(0.5), "0.5");
        assert_eq!(format_cost(StampCost::from_whole(16)), "16.0");
    }

    #[test]
    fn min_accepted_cost_saturates_at_zero() {
        let target = StampCost::from_f64(16.0);
        assert_eq!(
            min_accepted_cost(target, StampCost::from_f64(3.0)),
            StampCost::from_f64(13.0)
        );
        assert_eq!(
            min_accepted_cost(StampCost::from_f64(2.0), StampCost::from_f64(3.0)),
            StampCost::ZERO
        );
    }
}
