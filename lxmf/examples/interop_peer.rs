//! LXMF interop peer: a Rust LXMF node driven by `tests/interop/lxmf13_live.py`.
//!
//! Connects to an RNS TCP server, announces a delivery destination with a
//! fractional inbound stamp cost (enforced) and a propagation node, echoes
//! every delivered message back to its sender with the method it arrived
//! with, and prints one JSON event per line on stdout for the driver.
//!
//! Usage:
//!   cargo run --example interop_peer -- <host:port> <storage_dir>

use std::io::Write;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lxmf_core::constants::*;
use lxmf_core::message;
use lxmf_core::stamp::StampCost;
use lxmf_rs::router::{LxmDelivery, LxmRouter, LxmfCallbacks, OutboundMessage, RouterConfig};
use rns_crypto::identity::Identity;
use rns_net::interface::tcp::TcpClientConfig;
use rns_net::node::{InterfaceConfig, NodeConfig, RnsNode};
use rns_net::InterfaceId;

/// Inbound stamp cost the peer requires from senders.
const DELIVERY_STAMP_COST: f64 = 6.5;
/// Propagation stamp cost the peer's propagation node requires.
const PROPAGATION_STAMP_COST: f64 = 7.25;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn emit(event: serde_json::Value) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", event);
    let _ = stdout.flush();
}

struct Delivered {
    source_hash: [u8; DESTINATION_LENGTH],
    title: Vec<u8>,
    content: Vec<u8>,
    method: DeliveryMethod,
    signature_valid: Option<bool>,
    has_stamp: bool,
}

fn main() {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <host:port> <storage_dir>", args[0]);
        std::process::exit(2);
    }
    let (host, port) = args[1].rsplit_once(':').expect("host:port");
    let port: u16 = port.parse().expect("port");
    let storage = std::path::PathBuf::from(&args[2]);
    std::fs::create_dir_all(&storage).expect("storage dir");

    let identity = Identity::new(&mut rns_crypto::OsRng);
    let delivery_hash =
        rns_core::destination::destination_hash(APP_NAME, &["delivery"], Some(identity.hash()));

    let config = RouterConfig {
        storagepath: storage.clone(),
        enforce_stamps: true,
        propagation_cost: StampCost::from_f64(PROPAGATION_STAMP_COST),
        propagation_cost_flexibility: StampCost::ZERO,
        name: Some("lxmf-rs interop PN".into()),
        ..RouterConfig::default()
    };
    let mut router = LxmRouter::new(
        Identity::from_private_key(&identity.get_private_key().unwrap()),
        config,
    );

    let (tx, rx) = mpsc::channel::<Delivered>();
    router.set_delivery_callback(Box::new(move |delivery: &LxmDelivery| {
        let _ = tx.send(Delivered {
            source_hash: delivery.source_hash,
            title: delivery.title.clone(),
            content: delivery.content.clone(),
            method: delivery.method,
            signature_valid: delivery.signature_valid,
            has_stamp: delivery.stamp.is_some(),
        });
    }));

    let router = Arc::new(Mutex::new(router));
    let node_config = NodeConfig {
        transport_enabled: false,
        identity: Some(Identity::new(&mut rns_crypto::OsRng)),
        interfaces: vec![InterfaceConfig {
            name: "interop".into(),
            type_name: "TCPClientInterface".to_string(),
            config_data: Box::new(TcpClientConfig {
                name: "interop".into(),
                target_host: host.to_string(),
                target_port: port,
                interface_id: InterfaceId(1),
                ..TcpClientConfig::default()
            }),
            mode: rns_core::constants::MODE_FULL,
            ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
            gravity: 0,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            stamp_costs: Default::default(),
            ifac: None,
            discovery: None,
        }],
        cache_dir: Some(storage.join("rns")),
        ..NodeConfig::default()
    };
    let node = Arc::new(
        RnsNode::start(node_config, Box::new(LxmfCallbacks::new(router.clone())))
            .expect("start RNS node"),
    );

    {
        let mut r = router.lock().unwrap();
        r.set_node(node.clone());
        r.register_delivery_identity(
            &identity,
            Some(DELIVERY_STAMP_COST),
            Some("lxmf-rs interop".into()),
        );
        r.enable_propagation();
    }
    let propagation_hash = router.lock().unwrap().propagation_dest_hash;
    emit(serde_json::json!({
        "event": "ready",
        "delivery_hash": hex(&delivery_hash),
        "propagation_hash": hex(&propagation_hash),
        "delivery_stamp_cost": DELIVERY_STAMP_COST,
        "propagation_stamp_cost": PROPAGATION_STAMP_COST,
    }));

    let mut last_announce = Instant::now() - Duration::from_secs(3600);
    let mut stored_reported = 0usize;
    loop {
        if last_announce.elapsed() > Duration::from_secs(8) {
            let r = router.lock().unwrap();
            r.announce_delivery(&identity);
            r.announce_propagation_node();
            last_announce = Instant::now();
        }

        while let Ok(delivered) = rx.try_recv() {
            emit(serde_json::json!({
                "event": "delivered",
                "source": hex(&delivered.source_hash),
                "title": String::from_utf8_lossy(&delivered.title),
                "content_len": delivered.content.len(),
                "method": format!("{:?}", delivered.method),
                "signature_valid": delivered.signature_valid,
                "has_stamp": delivered.has_stamp,
            }));
            let echo = message::pack(
                &delivered.source_hash,
                &delivery_hash,
                lxmf_rs::router::now_timestamp(),
                format!("Echo: {}", String::from_utf8_lossy(&delivered.title)).as_bytes(),
                &delivered.content,
                vec![],
                None,
                |data| identity.sign(data).map_err(|_| message::Error::SignError),
            )
            .expect("pack echo");
            // Propagated messages are echoed opportunistically: the peer has
            // no outbound propagation node of its own.
            let reply_method = match delivered.method {
                DeliveryMethod::Propagated => DeliveryMethod::Opportunistic,
                method => method,
            };
            let mut msg = OutboundMessage::new(
                delivered.source_hash,
                delivery_hash,
                echo.packed,
                echo.message_hash,
                reply_method,
            );
            let title = String::from_utf8_lossy(&delivered.title).to_string();
            msg.delivery_callback = Some(Box::new(move |m: &OutboundMessage| {
                emit(serde_json::json!({
                    "event": "echo_delivered",
                    "title": title,
                    "method": format!("{:?}", m.method),
                }));
            }));
            msg.failed_callback = Some(Box::new(move |m: &OutboundMessage| {
                emit(serde_json::json!({
                    "event": "echo_failed",
                    "method": format!("{:?}", m.method),
                }));
            }));
            let _ = router.lock().unwrap().handle_outbound(msg);
        }

        {
            let mut r = router.lock().unwrap();
            r.jobs();
            let stored = r.propagation_store.message_count();
            if stored != stored_reported {
                stored_reported = stored;
                emit(serde_json::json!({
                    "event": "propagation_stored",
                    "count": stored,
                    "client_received": r.propagation_store.client_propagation_messages_received,
                }));
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
