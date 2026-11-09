use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use rns_core::msgpack::{pack, unpack_exact, Value};

use crate::constants::{
    PN_META_IMPL_NAME, PN_META_NAME, PN_META_VERSION, SF_COMPRESSION, STAMP_COST_CAP,
};
use crate::stamp::StampCost;

/// Read a msgpack value the way Python's `float()` reads an announce field:
/// ints, floats, bools and numeric strings are numbers. NaN is rejected, as
/// no cost or limit can meaningfully be NaN.
fn py_number(value: &Value) -> Option<f64> {
    let number = match value {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Str(text) => text.trim().replace('_', "").parse::<f64>().ok(),
        other => other.as_number(),
    }?;
    (!number.is_nan()).then_some(number)
}

/// Read a msgpack value the way Python's `int()` reads an announce field:
/// floats truncate toward zero, strings must hold an integer, and
/// infinities are rejected.
fn py_int(value: &Value) -> Option<i64> {
    match value {
        Value::UInt(v) => i64::try_from(*v).ok(),
        Value::Int(v) => Some(*v),
        Value::Str(text) => text.trim().replace('_', "").parse::<i64>().ok(),
        other => {
            let number = py_number(other)?;
            // `as` truncates toward zero, as `int()` does.
            number.is_finite().then_some(number as i64)
        }
    }
}

/// Python's `data[2] != True and data[2] != False` check: bools, and the
/// integers 0 and 1 that compare equal to them.
fn py_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::UInt(v @ (0 | 1)) => Some(*v == 1),
        Value::Int(v @ (0 | 1)) => Some(*v == 1),
        Value::Float(v) if *v == 0.0 || *v == 1.0 => Some(*v == 1.0),
        _ => None,
    }
}

/// Whether a value is a Python `int` or `float` (bools excluded, as
/// `type(x) == int` excludes them).
fn is_int_or_float(value: &Value) -> bool {
    matches!(value, Value::UInt(_) | Value::Int(_) | Value::Float(_))
}

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
        core::str::from_utf8(dn)
            .ok()
            .map(|s| s.replace('\0', "").trim().into())
    } else {
        // Legacy format: raw UTF-8 string
        core::str::from_utf8(app_data).ok().map(String::from)
    }
}

/// Extract stamp cost from delivery announce app_data.
///
/// Only available in v0.5.0+ msgpack array format. Since LXMF 1.3 the exact
/// fractional cost travels in the transitional fourth element, with the
/// second element carrying `ceil(cost)` for older readers; the fourth element
/// is preferred when it is a number.
pub fn stamp_cost_from_app_data(app_data: &[u8]) -> Option<StampCost> {
    if app_data.is_empty() || !is_msgpack_array(app_data[0]) {
        return None;
    }

    let val = unpack_exact(app_data).ok()?;
    let arr = val.as_array()?;
    if arr.len() < 2 {
        return None;
    }
    let cost = if arr.len() > 3 && is_int_or_float(&arr[3]) {
        &arr[3]
    } else {
        &arr[1]
    };
    py_number(cost).map(StampCost::from_f64)
}

/// Extract whether a delivery destination supports compressed resources.
///
/// LXMF 0.9.6 adds an optional third delivery announce field containing a list
/// of supported functionality codes. Legacy announce data and v0.5+ announce
/// arrays without that field are treated as compression-capable.
pub fn compression_support_from_app_data(app_data: &[u8]) -> Option<bool> {
    if app_data.is_empty() {
        return None;
    }

    if is_msgpack_array(app_data[0]) {
        let val = unpack_exact(app_data).ok()?;
        let arr = val.as_array()?;
        if arr.len() < 3 {
            return Some(true);
        }

        let Some(supported) = arr[2].as_array() else {
            return Some(true);
        };

        Some(
            supported
                .iter()
                .any(|item| item.as_uint() == Some(SF_COMPRESSION as u64)),
        )
    } else {
        Some(true)
    }
}

/// An inbound stamp cost at or above `STAMP_COST_CAP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StampCostAboveCap;

/// Whether an inbound stamp cost is acceptable for a delivery destination
/// (`set_inbound_stamp_cost`): costs below 1 disable stamps, and costs at or
/// above `STAMP_COST_CAP` are rejected.
pub fn inbound_stamp_cost(cost: Option<f64>) -> Result<Option<StampCost>, StampCostAboveCap> {
    match cost {
        None => Ok(None),
        Some(cost) if cost.is_nan() || cost < 1.0 => Ok(None),
        Some(cost) if cost < f64::from(STAMP_COST_CAP) => Ok(Some(StampCost::from_f64(cost))),
        Some(_) => Err(StampCostAboveCap),
    }
}

/// Build delivery announce app_data (LXMF 1.3 format):
/// `[display_name, ceil(cost), [supported functionality], cost]`.
///
/// The fourth element is upstream's transitional carrier for the exact
/// fractional cost; the second keeps older readers working.
pub fn build_delivery_announce_data(
    display_name: Option<&str>,
    stamp_cost: Option<StampCost>,
) -> Vec<u8> {
    let display_name_val = match display_name {
        Some(name) => Value::Bin(name.as_bytes().to_vec()),
        None => Value::Nil,
    };
    let stamp_cost = stamp_cost
        .filter(|cost| *cost > StampCost::ZERO && cost.whole() < u32::from(STAMP_COST_CAP));
    let (ceil_val, exact_val) = match stamp_cost {
        Some(cost) => (Value::UInt(ceil_cost(cost)), Value::Float(cost.as_f64())),
        None => (Value::Nil, Value::Nil),
    };
    pack(&Value::Array(vec![
        display_name_val,
        ceil_val,
        Value::Array(vec![Value::UInt(SF_COMPRESSION as u64)]),
        exact_val,
    ]))
}

/// Validate propagation node announce data structure.
///
/// Expected format: msgpack array with 7+ elements:
///   [0]: legacy flag
///   [1]: node_timebase (int)
///   [2]: propagation_enabled (bool)
///   [3]: propagation_transfer_limit (number)
///   [4]: propagation_sync_limit (number)
///   [5]: [target_stamp_cost, stamp_cost_flexibility, peering_cost]
///   [6]: metadata (map)
///   [7]: optional transitional fractional costs, same layout as [5]
pub fn pn_announce_data_is_valid(app_data: &[u8]) -> bool {
    let Ok(val) = unpack_exact(app_data) else {
        return false;
    };
    let Some(arr) = val.as_array() else {
        return false;
    };
    pn_announce_fields_are_valid(arr)
}

fn pn_cost_triplet_is_valid(value: &Value) -> bool {
    match value.as_array() {
        Some(costs) if costs.len() >= 3 => costs[..3].iter().all(|c| py_number(c).is_some()),
        _ => false,
    }
}

fn pn_announce_fields_are_valid(arr: &[Value]) -> bool {
    arr.len() >= 7
        && py_int(&arr[1]).is_some()
        && py_bool(&arr[2]).is_some()
        && py_int(&arr[3]).is_some()
        && py_int(&arr[4]).is_some()
        && pn_cost_triplet_is_valid(&arr[5])
        && arr[6].as_map().is_some()
        && (arr.len() == 7 || pn_cost_triplet_is_valid(&arr[7]))
}

/// The cost triplet a reader should use: the transitional fractional
/// element [7] when present, otherwise [5].
fn pn_costs(arr: &[Value]) -> Option<[StampCost; 3]> {
    let costs = if arr.len() > 7 { &arr[7] } else { &arr[5] };
    let costs = costs.as_array()?;
    Some([
        StampCost::from_f64(py_number(&costs[0])?),
        StampCost::from_f64(py_number(&costs[1])?),
        StampCost::from_f64(py_number(&costs[2])?),
    ])
}

/// Extract stamp cost from propagation node announce data.
pub fn pn_stamp_cost_from_app_data(app_data: &[u8]) -> Option<StampCost> {
    parse_pn_announce_data(app_data).map(|data| data.propagation_stamp_cost)
}

/// Extract propagation node name from announce metadata.
pub fn pn_name_from_app_data(app_data: &[u8]) -> Option<String> {
    let parsed = parse_pn_announce_data(app_data)?;
    pn_metadata_name(&parsed.metadata)
}

/// Read the node name (`PN_META_NAME`, UTF-8 bytes) from PN metadata.
pub fn pn_metadata_name(metadata: &[(Value, Value)]) -> Option<String> {
    metadata
        .iter()
        .find(|(k, _)| k.as_uint() == Some(PN_META_NAME as u64))
        .and_then(|(_, v)| core::str::from_utf8(v.as_bin()?).ok().map(String::from))
}

/// Parsed propagation node announce data.
pub struct PnAnnounceData {
    pub node_timebase: u64,
    pub propagation_enabled: bool,
    pub propagation_transfer_limit: u64,
    pub propagation_sync_limit: u64,
    pub propagation_stamp_cost: StampCost,
    pub propagation_stamp_cost_flexibility: StampCost,
    pub peering_cost: StampCost,
    pub metadata: Vec<(Value, Value)>,
}

/// Parse full propagation node announce data.
pub fn parse_pn_announce_data(app_data: &[u8]) -> Option<PnAnnounceData> {
    let val = unpack_exact(app_data).ok()?;
    let arr = val.as_array()?;
    if !pn_announce_fields_are_valid(arr) {
        return None;
    }

    let [propagation_stamp_cost, propagation_stamp_cost_flexibility, peering_cost] = pn_costs(arr)?;

    Some(PnAnnounceData {
        node_timebase: py_int(&arr[1])?.max(0) as u64,
        propagation_enabled: py_bool(&arr[2])?,
        propagation_transfer_limit: py_int(&arr[3])?.max(0) as u64,
        propagation_sync_limit: py_int(&arr[4])?.max(0) as u64,
        propagation_stamp_cost,
        propagation_stamp_cost_flexibility,
        peering_cost,
        metadata: arr[6].as_map()?.to_vec(),
    })
}

/// Inputs for [`build_pn_announce_data`].
pub struct PnAnnounceParams<'a> {
    pub node_timebase: u64,
    pub propagation_enabled: bool,
    /// Per-transfer limit in kilobytes; may be fractional.
    pub propagation_transfer_limit: f64,
    /// Sync limit in kilobytes; may be fractional.
    pub propagation_sync_limit: f64,
    pub propagation_stamp_cost: StampCost,
    pub propagation_stamp_cost_flexibility: StampCost,
    pub peering_cost: StampCost,
    /// Implementation name and version announced in the metadata.
    pub implementation: Option<(&'a str, &'a str)>,
    /// Operator-configured node name.
    pub name: Option<&'a str>,
}

/// Build the propagation node announce metadata map
/// (`get_propagation_node_announce_metadata`).
pub fn build_pn_metadata(implementation: Option<(&str, &str)>, name: Option<&str>) -> Value {
    let mut metadata = Vec::new();
    if let Some((impl_name, version)) = implementation {
        metadata.push((
            Value::UInt(PN_META_IMPL_NAME as u64),
            Value::Str(impl_name.into()),
        ));
        metadata.push((
            Value::UInt(PN_META_VERSION as u64),
            Value::Str(version.into()),
        ));
    }
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        metadata.push((
            Value::UInt(PN_META_NAME as u64),
            Value::Bin(name.as_bytes().to_vec()),
        ));
    }
    Value::Map(metadata)
}

/// Build propagation node announce app_data (LXMF 1.3 format), with
/// `ceil`ed integer costs in [5] and the exact fractional costs in the
/// transitional element [7].
pub fn build_pn_announce_data(params: &PnAnnounceParams<'_>) -> Vec<u8> {
    let costs = [
        params.propagation_stamp_cost,
        params.propagation_stamp_cost_flexibility,
        params.peering_cost,
    ];
    let ceil_costs = costs
        .iter()
        .map(|cost| Value::UInt(ceil_cost(*cost)))
        .collect();
    let exact_costs = costs
        .iter()
        .map(|cost| Value::Float(cost.as_f64()))
        .collect();

    pack(&Value::Array(vec![
        Value::Bool(false),
        Value::UInt(params.node_timebase),
        Value::Bool(params.propagation_enabled),
        kilobyte_value(params.propagation_transfer_limit),
        kilobyte_value(params.propagation_sync_limit),
        Value::Array(ceil_costs),
        build_pn_metadata(params.implementation, params.name),
        Value::Array(exact_costs),
    ]))
}

/// A kilobyte limit as an integer when whole, else a float, as Python
/// writes whatever numeric type the limit was configured with.
fn kilobyte_value(kb: f64) -> Value {
    if kb >= 0.0 && kb == (kb as u64) as f64 {
        Value::UInt(kb as u64)
    } else {
        Value::Float(kb)
    }
}

/// `ceil(cost)` on the fixed-point grid (no float math needed).
fn ceil_cost(cost: StampCost) -> u64 {
    u64::from(cost.fp().div_ceil(StampCost::from_whole(1).fp()))
}

/// Check if byte is a msgpack array header (fixarray 0x90-0x9f or array16 0xdc).
fn is_msgpack_array(byte: u8) -> bool {
    (0x90..=0x9f).contains(&byte) || byte == 0xdc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pn_data(costs5: Vec<Value>, costs7: Option<Vec<Value>>) -> Vec<u8> {
        let mut arr = vec![
            Value::Bool(false),
            Value::UInt(1_700_000_000),
            Value::Bool(true),
            Value::Float(256.0),
            Value::UInt(10240),
            Value::Array(costs5),
            Value::Map(vec![]),
        ];
        if let Some(costs7) = costs7 {
            arr.push(Value::Array(costs7));
        }
        pack(&Value::Array(arr))
    }

    #[test]
    fn pn_announce_accepts_float_limits_and_costs() {
        let data = pn_data(
            vec![Value::Float(16.5), Value::Float(3.0), Value::Float(18.0)],
            None,
        );
        assert!(pn_announce_data_is_valid(&data));
        let parsed = parse_pn_announce_data(&data).unwrap();
        assert_eq!(parsed.propagation_transfer_limit, 256);
        assert_eq!(parsed.propagation_stamp_cost, StampCost::from_f64(16.5));
    }

    #[test]
    fn pn_announce_prefers_transitional_fractional_costs() {
        let data = pn_data(
            vec![Value::UInt(17), Value::UInt(3), Value::UInt(19)],
            Some(vec![
                Value::Float(16.25),
                Value::Float(2.5),
                Value::Float(18.75),
            ]),
        );
        let parsed = parse_pn_announce_data(&data).unwrap();
        assert_eq!(parsed.propagation_stamp_cost, StampCost::from_f64(16.25));
        assert_eq!(
            parsed.propagation_stamp_cost_flexibility,
            StampCost::from_f64(2.5)
        );
        assert_eq!(parsed.peering_cost, StampCost::from_f64(18.75));
    }

    #[test]
    fn pn_announce_rejects_malformed_transitional_costs() {
        let data = pn_data(
            vec![Value::UInt(16), Value::UInt(3), Value::UInt(18)],
            Some(vec![Value::Float(16.0)]),
        );
        assert!(!pn_announce_data_is_valid(&data));
    }

    #[test]
    fn pn_announce_roundtrips_with_metadata() {
        let data = build_pn_announce_data(&PnAnnounceParams {
            node_timebase: 42,
            propagation_enabled: true,
            propagation_transfer_limit: 256.0,
            propagation_sync_limit: 10240.0,
            propagation_stamp_cost: StampCost::from_f64(16.25),
            propagation_stamp_cost_flexibility: StampCost::from_f64(3.0),
            peering_cost: StampCost::from_f64(18.0),
            implementation: Some(("lxmf-rs", "0.1.7")),
            name: Some("Test PN"),
        });
        let parsed = parse_pn_announce_data(&data).unwrap();
        assert_eq!(parsed.node_timebase, 42);
        assert_eq!(parsed.propagation_stamp_cost, StampCost::from_f64(16.25));
        assert_eq!(pn_name_from_app_data(&data).as_deref(), Some("Test PN"));

        let arr = unpack_exact(&data).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 8);
        assert_eq!(arr[5].as_array().unwrap()[0].as_uint(), Some(17));
        let metadata = arr[6].as_map().unwrap();
        assert!(metadata.iter().any(|(k, v)| {
            k.as_uint() == Some(PN_META_IMPL_NAME as u64) && v.as_str() == Some("lxmf-rs")
        }));
    }

    #[test]
    fn delivery_announce_carries_ceil_and_exact_cost() {
        let data = build_delivery_announce_data(Some("Node"), Some(StampCost::from_f64(8.5)));
        let val = unpack_exact(&data).unwrap();
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[1].as_uint(), Some(9));
        assert_eq!(arr[3].as_float(), Some(8.5));
        assert_eq!(
            stamp_cost_from_app_data(&data),
            Some(StampCost::from_f64(8.5))
        );

        let none = build_delivery_announce_data(None, None);
        assert_eq!(stamp_cost_from_app_data(&none), None);
    }

    #[test]
    fn delivery_stamp_cost_falls_back_to_second_element() {
        let data = pack(&Value::Array(vec![
            Value::Nil,
            Value::UInt(12),
            Value::Array(vec![]),
            Value::Str("not a cost".into()),
        ]));
        assert_eq!(
            stamp_cost_from_app_data(&data),
            Some(StampCost::from_whole(12))
        );
    }

    #[test]
    fn inbound_stamp_cost_is_capped() {
        assert_eq!(inbound_stamp_cost(Some(0.5)), Ok(None));
        assert_eq!(
            inbound_stamp_cost(Some(12.5)),
            Ok(Some(StampCost::from_f64(12.5)))
        );
        assert!(inbound_stamp_cost(Some(100.0)).is_err());
    }
}
