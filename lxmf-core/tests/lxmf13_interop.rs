//! Interop with upstream Python LXMF 1.3 / RNS 1.6.
//!
//! The vectors in `tests/fixtures/lxmf13_vectors.json` are produced by
//! `tests/generate_lxmf13_vectors.py`, which calls the upstream Python code
//! itself: announce builders and parsers, stamp valuation and generation.

use lxmf_core::announce::{self, PnAnnounceParams};
use lxmf_core::constants::*;
use lxmf_core::stamp::{self, StampCost};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    constants: Constants,
    delivery_announces: Vec<DeliveryAnnounce>,
    delivery_announce_parsing: Vec<AnnounceParse>,
    pn_announces: Vec<PnAnnounce>,
    pn_announce_validation: Vec<PnValidation>,
    quantization: Vec<Quantization>,
    stamp_values: Vec<StampValueVector>,
    generated_stamps: Vec<GeneratedStamp>,
    pn_stamps: Vec<PnStamp>,
    peering_keys: Vec<PeeringKey>,
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
struct Constants {
    ENCRYPTED_PACKET_MDU: usize,
    ENCRYPTED_PACKET_MAX_CONTENT: usize,
    LINK_PACKET_MDU: usize,
    LINK_PACKET_MAX_CONTENT: usize,
    PLAIN_PACKET_MDU: usize,
    PLAIN_PACKET_MAX_CONTENT: usize,
    LXMF_OVERHEAD: usize,
    ENCRYPTION_DESCRIPTION_AES: String,
    PEERING_COST: f64,
    MAX_PEERING_COST: f64,
    PROPAGATION_COST_MIN: f64,
    PROPAGATION_COST_FLEX: f64,
    PROPAGATION_COST: f64,
    PN_STAMP_THROTTLE: u64,
    DELIVERY_LINK_COST: f64,
    PROPAGATION_LINK_COST: f64,
    MESSAGE_EXPIRY: u64,
    PATH_REQUEST_WAIT: u64,
    PATH_REQUEST_DEBOUNCE: u64,
    SLOW_INTERFACE_BITRATE: u64,
    AIRTIME_AWARE_MTU_TIME: f64,
    DELIVERY_RETRY_WAIT: u64,
    MAX_DELIVERY_ATTEMPTS: u32,
    STAMP_COST_CAP: u8,
    PN_META_IMPL_NAME: u8,
    PN_META_VERSION: u8,
    PN_META_NAME: u8,
}

#[derive(Deserialize)]
struct DeliveryAnnounce {
    name: String,
    display_name: Option<String>,
    stamp_cost: Option<f64>,
    app_data: String,
    parsed_stamp_cost: Option<f64>,
    parsed_display_name: Option<String>,
}

#[derive(Deserialize)]
struct AnnounceParse {
    name: String,
    app_data: String,
    stamp_cost: Option<f64>,
}

#[derive(Deserialize)]
struct PnAnnounce {
    name: String,
    timebase: u64,
    propagation_enabled: bool,
    transfer_limit: f64,
    sync_limit: f64,
    stamp_cost: f64,
    stamp_cost_flexibility: f64,
    peering_cost: f64,
    node_name: Option<String>,
    implementation: String,
    version: String,
    app_data: String,
    valid: bool,
    pn_stamp_cost: Option<f64>,
    pn_name: Option<String>,
}

#[derive(Deserialize)]
struct PnValidation {
    name: String,
    app_data: String,
    valid: bool,
    pn_stamp_cost: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Quantization {
    cost: f64,
    fp: u32,
    quantized: f64,
    store_component: String,
}

#[derive(Deserialize)]
struct StampValueVector {
    material: String,
    rounds: u32,
    stamp: String,
    value: f64,
    legacy_value: u32,
    valid_at: Vec<(f64, bool)>,
}

#[derive(Deserialize)]
struct GeneratedStamp {
    material: String,
    rounds: u32,
    cost: f64,
    stamp: String,
    value: f64,
}

#[derive(Deserialize)]
struct PnStamp {
    transient_data: String,
    target_cost: f64,
    transient_id: String,
    value: f64,
    quantized_value: f64,
    rejected_above_value: bool,
}

#[derive(Deserialize)]
struct PeeringKey {
    peering_id: String,
    cost: f64,
    peering_key: String,
    value: f64,
    valid: bool,
}

fn vectors() -> Vectors {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/lxmf13_vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read LXMF 1.3 vectors"))
        .expect("parse LXMF 1.3 vectors")
}

fn b64(input: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in input.bytes().filter(|b| *b != b'=') {
        let value = ALPHABET.iter().position(|c| *c == byte).expect("base64") as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

fn cost(value: f64) -> StampCost {
    StampCost::from_f64(value)
}

#[test]
fn constants_match_upstream() {
    let c = vectors().constants;
    assert_eq!(ENCRYPTED_PACKET_MDU, c.ENCRYPTED_PACKET_MDU);
    assert_eq!(ENCRYPTED_PACKET_MAX_CONTENT, c.ENCRYPTED_PACKET_MAX_CONTENT);
    assert_eq!(LINK_PACKET_MDU, c.LINK_PACKET_MDU);
    assert_eq!(LINK_PACKET_MAX_CONTENT, c.LINK_PACKET_MAX_CONTENT);
    assert_eq!(PLAIN_PACKET_MDU, c.PLAIN_PACKET_MDU);
    assert_eq!(PLAIN_PACKET_MAX_CONTENT, c.PLAIN_PACKET_MAX_CONTENT);
    assert_eq!(LXMF_OVERHEAD, c.LXMF_OVERHEAD);
    assert_eq!(ENCRYPTION_DESCRIPTION_AES, c.ENCRYPTION_DESCRIPTION_AES);
    assert_eq!(PEERING_COST.as_f64(), c.PEERING_COST);
    assert_eq!(MAX_PEERING_COST.as_f64(), c.MAX_PEERING_COST);
    assert_eq!(PROPAGATION_COST_MIN.as_f64(), c.PROPAGATION_COST_MIN);
    assert_eq!(PROPAGATION_COST_FLEX.as_f64(), c.PROPAGATION_COST_FLEX);
    assert_eq!(PROPAGATION_COST.as_f64(), c.PROPAGATION_COST);
    assert_eq!(PN_STAMP_THROTTLE, c.PN_STAMP_THROTTLE);
    assert_eq!(DELIVERY_LINK_COST, c.DELIVERY_LINK_COST);
    assert_eq!(PROPAGATION_LINK_COST, c.PROPAGATION_LINK_COST);
    assert_eq!(MESSAGE_EXPIRY, c.MESSAGE_EXPIRY);
    assert_eq!(PATH_REQUEST_WAIT, c.PATH_REQUEST_WAIT);
    assert_eq!(PATH_REQUEST_DEBOUNCE, c.PATH_REQUEST_DEBOUNCE);
    assert_eq!(SLOW_INTERFACE_BITRATE, c.SLOW_INTERFACE_BITRATE);
    assert_eq!(AIRTIME_AWARE_MTU_TIME, c.AIRTIME_AWARE_MTU_TIME);
    assert_eq!(DELIVERY_RETRY_WAIT, c.DELIVERY_RETRY_WAIT);
    assert_eq!(MAX_DELIVERY_ATTEMPTS, c.MAX_DELIVERY_ATTEMPTS);
    assert_eq!(STAMP_COST_CAP, c.STAMP_COST_CAP);
    assert_eq!(PN_META_IMPL_NAME, c.PN_META_IMPL_NAME);
    assert_eq!(PN_META_VERSION, c.PN_META_VERSION);
    assert_eq!(PN_META_NAME, c.PN_META_NAME);
}

#[test]
fn delivery_announces_are_byte_identical_and_parse_alike() {
    for v in vectors().delivery_announces {
        let expected = b64(&v.app_data);
        let built = announce::build_delivery_announce_data(
            v.display_name.as_deref(),
            v.stamp_cost.map(cost),
        );
        assert_eq!(
            built, expected,
            "{}: app_data differs from upstream",
            v.name
        );
        assert_eq!(
            announce::stamp_cost_from_app_data(&expected).map(StampCost::as_f64),
            v.parsed_stamp_cost,
            "{}: stamp cost",
            v.name
        );
        assert_eq!(
            announce::display_name_from_app_data(&expected),
            v.parsed_display_name,
            "{}: display name",
            v.name
        );
    }
}

#[test]
fn delivery_stamp_costs_parse_like_upstream() {
    for v in vectors().delivery_announce_parsing {
        assert_eq!(
            announce::stamp_cost_from_app_data(&b64(&v.app_data)).map(StampCost::as_f64),
            v.stamp_cost.map(|c| cost(c).as_f64()),
            "{}",
            v.name
        );
    }
}

#[test]
fn pn_announces_match_upstream() {
    for v in vectors().pn_announces {
        let expected = b64(&v.app_data);
        assert!(v.valid, "{}: upstream rejects its own announce", v.name);
        assert!(announce::pn_announce_data_is_valid(&expected), "{}", v.name);

        let parsed = announce::parse_pn_announce_data(&expected).expect("parse PN announce");
        assert_eq!(parsed.node_timebase, v.timebase, "{}", v.name);
        assert_eq!(
            parsed.propagation_enabled, v.propagation_enabled,
            "{}",
            v.name
        );
        assert_eq!(parsed.propagation_transfer_limit, v.transfer_limit as u64);
        assert_eq!(parsed.propagation_sync_limit, v.sync_limit as u64);
        assert_eq!(
            parsed.propagation_stamp_cost,
            cost(v.stamp_cost),
            "{}",
            v.name
        );
        assert_eq!(
            parsed.propagation_stamp_cost_flexibility,
            cost(v.stamp_cost_flexibility)
        );
        assert_eq!(parsed.peering_cost, cost(v.peering_cost), "{}", v.name);
        assert_eq!(
            announce::pn_stamp_cost_from_app_data(&expected).map(StampCost::as_f64),
            v.pn_stamp_cost
        );
        assert_eq!(announce::pn_name_from_app_data(&expected), v.pn_name);

        // Upstream writes limits as the configured type; for integer limits
        // the Rust builder must produce the exact same bytes.
        if v.transfer_limit.fract() == 0.0 && !v.name.contains("float") {
            let built = announce::build_pn_announce_data(&PnAnnounceParams {
                node_timebase: v.timebase,
                propagation_enabled: v.propagation_enabled,
                propagation_transfer_limit: v.transfer_limit as u64,
                propagation_sync_limit: v.sync_limit as u64,
                propagation_stamp_cost: cost(v.stamp_cost),
                propagation_stamp_cost_flexibility: cost(v.stamp_cost_flexibility),
                peering_cost: cost(v.peering_cost),
                implementation: Some((&v.implementation, &v.version)),
                name: v.node_name.as_deref(),
            });
            assert_eq!(
                built, expected,
                "{}: app_data differs from upstream",
                v.name
            );
        }
    }
}

#[test]
fn pn_announce_validation_matches_upstream() {
    for v in vectors().pn_announce_validation {
        let data = b64(&v.app_data);
        assert_eq!(
            announce::pn_announce_data_is_valid(&data),
            v.valid,
            "{}: validity",
            v.name
        );
        let expected_cost = v.pn_stamp_cost.as_ref().and_then(|c| match c {
            serde_json::Value::Number(n) => n.as_f64(),
            serde_json::Value::String(s) => s.parse().ok(),
            _ => None,
        });
        assert_eq!(
            announce::pn_stamp_cost_from_app_data(&data).map(StampCost::as_f64),
            expected_cost,
            "{}: stamp cost",
            v.name
        );
    }
}

#[test]
fn cost_quantization_matches_upstream() {
    for v in vectors().quantization {
        let quantized = StampCost::from_f64(v.cost);
        assert_eq!(quantized.fp(), v.fp, "cost_to_fp({})", v.cost);
        assert_eq!(quantized.as_f64(), v.quantized, "quantize_cost({})", v.cost);
        assert_eq!(
            format!("_{}", stamp::format_cost(quantized)),
            v.store_component,
            "message store value component for {}",
            v.cost
        );
    }
}

#[test]
fn fractional_stamp_values_and_validity_match_upstream() {
    for v in vectors().stamp_values {
        let workblock = stamp::stamp_workblock(&b64(&v.material), v.rounds);
        let stamp_bytes = b64(&v.stamp);
        let value = stamp::stamp_value(&workblock, &stamp_bytes);
        assert_eq!(value.as_f64(), v.value, "stamp value");
        assert_eq!(value.whole(), v.legacy_value, "legacy stamp value");
        for (target, valid) in v.valid_at {
            assert_eq!(
                stamp::stamp_valid(&stamp_bytes, cost(target), &workblock),
                valid,
                "stamp of value {} at cost {}",
                v.value,
                target
            );
        }
    }
}

#[test]
fn upstream_generated_stamps_validate() {
    for v in vectors().generated_stamps {
        let workblock = stamp::stamp_workblock(&b64(&v.material), v.rounds);
        let stamp_bytes = b64(&v.stamp);
        assert!(stamp::stamp_valid(&stamp_bytes, cost(v.cost), &workblock));
        assert_eq!(
            stamp::stamp_value(&workblock, &stamp_bytes).as_f64(),
            v.value
        );
        assert!(stamp::stamp_value(&workblock, &stamp_bytes).meets(cost(v.cost)));
    }
}

#[test]
fn upstream_propagation_stamps_validate_with_the_same_value() {
    for v in vectors().pn_stamps {
        let data = b64(&v.transient_data);
        let result = stamp::validate_pn_stamp(&data, cost(v.target_cost)).expect("valid PN stamp");
        assert_eq!(result.transient_id.to_vec(), b64(&v.transient_id));
        assert_eq!(result.value.as_f64(), v.value);
        assert_eq!(
            stamp::quantize_value(result.value).as_f64(),
            v.quantized_value
        );
        assert_eq!(
            stamp::validate_pn_stamp(&data, cost(v.value + 1.0)).is_none(),
            v.rejected_above_value
        );
    }
}

#[test]
fn upstream_peering_keys_validate() {
    for v in vectors().peering_keys {
        let peering_id = b64(&v.peering_id);
        let key = b64(&v.peering_key);
        assert_eq!(
            stamp::validate_peering_key(&peering_id, &key, cost(v.cost)),
            v.valid
        );
        let workblock = stamp::stamp_workblock(&peering_id, WORKBLOCK_EXPAND_ROUNDS_PEERING);
        assert_eq!(stamp::stamp_value(&workblock, &key).as_f64(), v.value);
    }
}
