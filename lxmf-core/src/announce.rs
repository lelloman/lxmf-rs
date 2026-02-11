use alloc::string::String;
use alloc::vec::Vec;

use rns_core::msgpack::{unpack_exact, Value};

use crate::constants::PN_META_NAME;

/// Extract display name from delivery announce app_data.
///
/// Handles both v0.5.0+ msgpack array format and legacy raw string format.
pub fn display_name_from_app_data(app_data: &[u8]) -> Option<String> {
    if app_data.is_empty() {
        return None;
    }

    // v0.5.0+ format: first byte is msgpack array marker
    if is_msgpack_array(app_data[0]) {
        let val = unpack_exact(app_data).ok()?;
        let arr = val.as_array()?;
        if arr.is_empty() {
            return None;
        }
        let dn = arr[0].as_bin()?;
        core::str::from_utf8(dn).ok().map(|s| String::from(s))
    } else {
        // Legacy format: raw UTF-8 string
        core::str::from_utf8(app_data).ok().map(|s| String::from(s))
    }
}

/// Extract stamp cost from delivery announce app_data.
///
/// Only available in v0.5.0+ msgpack array format (second element).
pub fn stamp_cost_from_app_data(app_data: &[u8]) -> Option<u8> {
    if app_data.is_empty() {
        return None;
    }

    if is_msgpack_array(app_data[0]) {
        let val = unpack_exact(app_data).ok()?;
        let arr = val.as_array()?;
        if arr.len() < 2 {
            return None;
        }
        arr[1].as_uint().map(|v| v as u8)
    } else {
        None
    }
}

/// Validate propagation node announce data structure.
///
/// Expected format: msgpack array with 7+ elements:
///   [0]: display_name (bytes or nil)
///   [1]: node_timebase (int)
///   [2]: propagation_enabled (bool)
///   [3]: propagation_transfer_limit (int)
///   [4]: propagation_sync_limit (int)
///   [5]: [target_stamp_cost, stamp_cost_flexibility, peering_cost]
///   [6]: metadata (map)
pub fn pn_announce_data_is_valid(app_data: &[u8]) -> bool {
    let val = match unpack_exact(app_data) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let arr = match val.as_array() {
        Some(a) => a,
        None => return false,
    };

    if arr.len() < 7 {
        return false;
    }

    // data[1]: timebase must be numeric
    if arr[1].as_uint().is_none() && arr[1].as_int().is_none() && arr[1].as_float().is_none() {
        return false;
    }

    // data[2]: must be bool
    if arr[2].as_bool().is_none() {
        return false;
    }

    // data[3]: propagation_transfer_limit must be numeric
    if arr[3].as_uint().is_none() && arr[3].as_int().is_none() {
        return false;
    }

    // data[4]: propagation_sync_limit must be numeric
    if arr[4].as_uint().is_none() && arr[4].as_int().is_none() {
        return false;
    }

    // data[5]: stamp costs must be array of 3 ints
    let costs = match arr[5].as_array() {
        Some(c) => c,
        None => return false,
    };
    if costs.len() < 3 {
        return false;
    }
    for cost in &costs[..3] {
        if cost.as_uint().is_none() && cost.as_int().is_none() {
            return false;
        }
    }

    // data[6]: metadata must be map
    if arr[6].as_map().is_none() {
        return false;
    }

    true
}

/// Extract stamp cost from propagation node announce data.
pub fn pn_stamp_cost_from_app_data(app_data: &[u8]) -> Option<u8> {
    if !pn_announce_data_is_valid(app_data) {
        return None;
    }
    let val = unpack_exact(app_data).ok()?;
    let arr = val.as_array()?;
    let costs = arr[5].as_array()?;
    costs[0].as_uint().map(|v| v as u8)
}

/// Extract propagation node name from announce metadata.
pub fn pn_name_from_app_data(app_data: &[u8]) -> Option<String> {
    if !pn_announce_data_is_valid(app_data) {
        return None;
    }
    let val = unpack_exact(app_data).ok()?;
    let arr = val.as_array()?;
    let metadata = arr[6].as_map()?;

    for (k, v) in metadata {
        if k.as_uint() == Some(PN_META_NAME as u64) {
            let name_bytes = v.as_bin()?;
            return core::str::from_utf8(name_bytes).ok().map(|s| String::from(s));
        }
    }
    None
}

/// Parsed propagation node announce data.
pub struct PnAnnounceData {
    pub node_timebase: u64,
    pub propagation_enabled: bool,
    pub propagation_transfer_limit: u64,
    pub propagation_sync_limit: u64,
    pub propagation_stamp_cost: u8,
    pub propagation_stamp_cost_flexibility: u8,
    pub peering_cost: u8,
    pub metadata: Vec<(Value, Value)>,
}

/// Parse full propagation node announce data.
pub fn parse_pn_announce_data(app_data: &[u8]) -> Option<PnAnnounceData> {
    if !pn_announce_data_is_valid(app_data) {
        return None;
    }
    let val = unpack_exact(app_data).ok()?;
    let arr = match val {
        Value::Array(a) => a,
        _ => return None,
    };

    let node_timebase = arr[1].as_uint()?;
    let propagation_enabled = arr[2].as_bool()?;
    let propagation_transfer_limit = arr[3].as_uint()?;
    let propagation_sync_limit = arr[4].as_uint()?;

    let costs = arr[5].as_array()?;
    let propagation_stamp_cost = costs[0].as_uint()? as u8;
    let propagation_stamp_cost_flexibility = costs[1].as_uint()? as u8;
    let peering_cost = costs[2].as_uint()? as u8;

    let metadata = match &arr[6] {
        Value::Map(m) => m.clone(),
        _ => return None,
    };

    Some(PnAnnounceData {
        node_timebase,
        propagation_enabled,
        propagation_transfer_limit,
        propagation_sync_limit,
        propagation_stamp_cost,
        propagation_stamp_cost_flexibility,
        peering_cost,
        metadata,
    })
}

/// Check if byte is a msgpack array header (fixarray 0x90-0x9f or array16 0xdc).
fn is_msgpack_array(byte: u8) -> bool {
    (byte >= 0x90 && byte <= 0x9f) || byte == 0xdc
}
