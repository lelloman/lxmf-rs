//! Test-facing LXMF node with a small HTTP control API.
//!
//! This is intended for Docker E2E tests. It runs one LXMF endpoint connected
//! to an RNS TCP transport node and exposes enough local HTTP API to announce,
//! send messages, and inspect received messages.
//!
//! Usage:
//!   cargo run --example test_node -- <rns_host:port> [http_bind] [storage_dir] [display_name]
//!
//! Endpoints:
//!   GET  /health
//!   GET  /api/node
//!   POST /api/announce
//!   POST /api/send       {"dest_hash":"32hex","title":"hello","content":"world","method":"opportunistic"}
//!   GET  /api/messages   optional ?clear=true
//!   GET  /api/announces  optional ?clear=true
//!   GET  /api/outbound
//!   GET  /api/state
//!   GET  /api/stamp_costs
//!   GET  /api/peers
//!   GET  /api/storage
//!   GET  /api/propagation
//!   GET  /api/links
//!   POST /api/jobs
//!   POST /api/runtime/clear
//!   POST /api/request_path {"dest_hash":"32hex"}
//!   POST /api/direct_link  {"dest_hash":"32hex"}
//!   POST /api/propagation/enable
//!   POST /api/propagation/disable
//!   POST /api/propagation/announce
//!   POST /api/propagation/destination {"dest_hash":"32hex"}
//!   POST /api/sync   {"dest_hash":"32hex"}
//!   POST /api/unpeer {"dest_hash":"32hex"}

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lxmf_core::constants::{
    DeliveryMethod, MessageState, Representation, APP_NAME, DESTINATION_LENGTH,
};
use lxmf_core::message;
use lxmf_rs::router::{LxmDelivery, LxmRouter, LxmfCallbacks, OutboundMessage, RouterConfig};
use rns_core::msgpack;
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_net::destination::AnnouncedIdentity;
use rns_net::driver::Callbacks;
use rns_net::interface::tcp::TcpClientConfig;
use rns_net::node::{InterfaceConfig, NodeConfig, RnsNode};
use rns_net::InterfaceId;
use serde_json::{json, Value};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_hex_16(s: &str) -> Result<[u8; 16], String> {
    if s.len() != 32 {
        return Err(format!("expected 32 hex characters, got {}", s.len()));
    }

    let mut out = [0u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&s[start..start + 2], 16)
            .map_err(|_| format!("invalid hex at byte {}", idx))?;
    }
    Ok(out)
}

fn now_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn method_name(method: DeliveryMethod) -> &'static str {
    match method {
        DeliveryMethod::Opportunistic => "opportunistic",
        DeliveryMethod::Direct => "direct",
        DeliveryMethod::Propagated => "propagated",
        DeliveryMethod::Paper => "paper",
    }
}

fn file_count_and_bytes(path: &Path) -> (u64, u64) {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return (0, 0),
    };

    let mut count = 0u64;
    let mut bytes = 0u64;
    for entry in entries.flatten() {
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_file() {
            count += 1;
            bytes = bytes.saturating_add(metadata.len());
        }
    }
    (count, bytes)
}

fn load_or_create_identity(path: &Path) -> Identity {
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == 64 {
            let mut key = [0u8; 64];
            key.copy_from_slice(&bytes);
            return Identity::from_private_key(&key);
        }
    }

    let identity = Identity::new(&mut rns_crypto::OsRng);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, identity.get_private_key().unwrap()).expect("save identity");
    identity
}

fn parse_addr(addr: &str) -> Result<(String, u16), String> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| "address must be host:port".to_string())?;
    let port = port
        .parse()
        .map_err(|_| format!("invalid port in address {addr}"))?;
    Ok((host.to_string(), port))
}

fn parse_method(value: Option<&str>) -> Result<DeliveryMethod, String> {
    match value
        .unwrap_or("opportunistic")
        .to_ascii_lowercase()
        .as_str()
    {
        "opportunistic" => Ok(DeliveryMethod::Opportunistic),
        "direct" => Ok(DeliveryMethod::Direct),
        "propagated" => Ok(DeliveryMethod::Propagated),
        other => Err(format!("unsupported method {other}")),
    }
}

#[derive(Clone)]
struct ReceivedMessage {
    source_hash: [u8; DESTINATION_LENGTH],
    title: Vec<u8>,
    content: Vec<u8>,
    method: DeliveryMethod,
    message_hash: [u8; 32],
    received_at: f64,
}

#[derive(Clone)]
struct AnnounceRecord {
    dest_hash: [u8; DESTINATION_LENGTH],
    identity_hash: [u8; DESTINATION_LENGTH],
    hops: u8,
    app_data: Option<Vec<u8>>,
    received_at: f64,
}

#[derive(Clone)]
struct PropagationRecord {
    transport: String,
    size: usize,
    message_count: usize,
    payload_hex: String,
    received_at: f64,
}

#[derive(Default)]
struct TestState {
    messages: Vec<ReceivedMessage>,
    announces: Vec<AnnounceRecord>,
    propagation_payloads: Vec<PropagationRecord>,
}

struct AppCallbacks {
    inner: LxmfCallbacks,
    state: Arc<Mutex<TestState>>,
}

impl Callbacks for AppCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        if let Ok(mut state) = self.state.lock() {
            state.announces.push(AnnounceRecord {
                dest_hash: announced.dest_hash.0,
                identity_hash: announced.identity_hash.0,
                hops: announced.hops,
                app_data: announced.app_data.clone(),
                received_at: announced.received_at,
            });
        }
        self.inner.on_announce(announced);
    }

    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        self.inner.on_path_updated(dest_hash, hops);
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, packet_hash: PacketHash) {
        self.inner.on_local_delivery(dest_hash, raw, packet_hash);
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        dest_hash: DestHash,
        rtt: f64,
        is_initiator: bool,
    ) {
        self.inner
            .on_link_established(link_id, dest_hash, rtt, is_initiator);
    }

    fn on_link_closed(&mut self, link_id: LinkId, reason: Option<rns_core::link::TeardownReason>) {
        self.inner.on_link_closed(link_id, reason);
    }

    fn on_remote_identified(
        &mut self,
        link_id: LinkId,
        identity_hash: IdentityHash,
        public_key: [u8; 64],
    ) {
        self.inner
            .on_remote_identified(link_id, identity_hash, public_key);
    }

    fn on_resource_received(&mut self, link_id: LinkId, data: Vec<u8>, metadata: Option<Vec<u8>>) {
        let _ = record_propagation_payload(&self.state, "resource", &data);
        self.inner.on_resource_received(link_id, data, metadata);
    }

    fn on_resource_completed(&mut self, link_id: LinkId) {
        self.inner.on_resource_completed(link_id);
    }

    fn on_resource_failed(&mut self, link_id: LinkId, error: String) {
        self.inner.on_resource_failed(link_id, error);
    }

    fn on_response(&mut self, link_id: LinkId, request_id: [u8; 16], data: Vec<u8>) {
        self.inner.on_response(link_id, request_id, data);
    }

    fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
        self.inner.on_proof(dest_hash, packet_hash, rtt);
    }

    fn on_proof_requested(&mut self, dest_hash: DestHash, packet_hash: PacketHash) -> bool {
        self.inner.on_proof_requested(dest_hash, packet_hash)
    }

    fn on_link_data(&mut self, link_id: LinkId, context: u8, data: Vec<u8>) {
        let _ = record_propagation_payload(&self.state, "link", &data);
        self.inner.on_link_data(link_id, context, data);
    }
}

struct AppContext {
    router: Arc<Mutex<LxmRouter>>,
    _node: Arc<RnsNode>,
    state: Arc<Mutex<TestState>>,
    identity: Identity,
    source_hash: [u8; DESTINATION_LENGTH],
    display_name: String,
    storage_dir: PathBuf,
    started_at: f64,
}

fn message_to_json(message: &ReceivedMessage) -> Value {
    json!({
        "source_hash": hex(&message.source_hash),
        "title": String::from_utf8_lossy(&message.title),
        "content": String::from_utf8_lossy(&message.content),
        "title_hex": hex(&message.title),
        "content_hex": hex(&message.content),
        "method": format!("{:?}", message.method),
        "message_hash": hex(&message.message_hash),
        "received_at": message.received_at,
    })
}

fn announce_to_json(announce: &AnnounceRecord) -> Value {
    json!({
        "dest_hash": hex(&announce.dest_hash),
        "identity_hash": hex(&announce.identity_hash),
        "hops": announce.hops,
        "app_data_hex": announce.app_data.as_ref().map(|data| hex(data)),
        "app_data": announce
            .app_data
            .as_ref()
            .map(|data| String::from_utf8_lossy(data).to_string()),
        "received_at": announce.received_at,
    })
}

fn propagation_to_json(record: &PropagationRecord) -> Value {
    json!({
        "transport": record.transport,
        "size": record.size,
        "message_count": record.message_count,
        "payload_hex": record.payload_hex,
        "received_at": record.received_at,
    })
}

fn outbound_to_json(message: &OutboundMessage) -> Value {
    json!({
        "destination_hash": hex(&message.destination_hash),
        "source_hash": hex(&message.source_hash),
        "message_hash": hex(&message.message_hash),
        "method": method_name(message.method),
        "state": format!("{:?}", message.state),
        "representation": format!("{:?}", message.representation),
        "attempts": message.attempts,
        "last_attempt": message.last_attempt,
        "link_id": message.link_id.map(|id| hex(&id)),
        "packet_hash": message.packet_hash.map(|hash| hex(&hash)),
        "transient_id": message.transient_id.map(|id| hex(&id)),
        "has_propagation_packed": message.propagation_packed.is_some(),
    })
}

fn peer_to_json(peer: &lxmf_rs::peer::LxmPeer) -> Value {
    json!({
        "destination_hash": hex(&peer.destination_hash),
        "state": format!("{:?}", peer.state),
        "alive": peer.alive,
        "last_heard": peer.last_heard,
        "next_sync_attempt": peer.next_sync_attempt,
        "last_sync_attempt": peer.last_sync_attempt,
        "sync_backoff": peer.sync_backoff,
        "peering_cost": peer.peering_cost,
        "peering_key_value": peer.peering_key_value(),
        "propagation_transfer_limit": peer.propagation_transfer_limit,
        "propagation_sync_limit": peer.propagation_sync_limit,
        "propagation_stamp_cost": peer.propagation_stamp_cost,
        "propagation_stamp_cost_flexibility": peer.propagation_stamp_cost_flexibility,
        "link_id": peer.link_id.map(|id| hex(&id)),
        "handled_ids": peer.handled_ids.len(),
        "unhandled_ids": peer.unhandled_ids.len(),
        "offered": peer.offered,
        "outgoing": peer.outgoing,
        "incoming": peer.incoming,
        "rx_bytes": peer.rx_bytes,
        "tx_bytes": peer.tx_bytes,
    })
}

fn propagation_payload_message_count(data: &[u8]) -> Option<usize> {
    let value = msgpack::unpack_exact(data).ok()?;
    let outer = value.as_array()?;
    if outer.len() != 2 {
        return None;
    }
    let messages = outer[1].as_array()?;
    Some(messages.len())
}

fn record_propagation_payload(state: &Arc<Mutex<TestState>>, transport: &str, data: &[u8]) -> bool {
    let message_count = match propagation_payload_message_count(data) {
        Some(count) => count,
        None => return false,
    };

    if let Ok(mut state) = state.lock() {
        state.propagation_payloads.push(PropagationRecord {
            transport: transport.to_string(),
            size: data.len(),
            message_count,
            payload_hex: hex(data),
            received_at: now_timestamp(),
        });
    }
    true
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str, content_type: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn write_json(stream: &mut TcpStream, status: u16, body: Value) {
    write_response(stream, status, &body.to_string(), "application/json");
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let mut buffer = Vec::new();
    let mut temp = [0u8; 1024];
    let headers_end = loop {
        let n = stream.read(&mut temp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before headers".to_string());
        }
        buffer.extend_from_slice(&temp[..n]);
        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buffer.len() > 64 * 1024 {
            return Err("request headers too large".to_string());
        }
    };

    let header_text =
        std::str::from_utf8(&buffer[..headers_end]).map_err(|_| "invalid headers".to_string())?;
    let mut lines = header_text.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| "missing path".to_string())?
        .to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse()
                    .map_err(|_| "invalid content-length".to_string())?;
            }
        }
    }

    let mut body = buffer[headers_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut temp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before request body".to_string());
        }
        body.extend_from_slice(&temp[..n]);
    }
    body.truncate(content_length);

    Ok(HttpRequest { method, path, body })
}

fn request_json(request: &HttpRequest) -> Result<Value, String> {
    if request.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&request.body).map_err(|e| format!("invalid json: {e}"))
}

fn split_path_query(path: &str) -> (&str, Option<&str>) {
    match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    }
}

fn query_has(query: Option<&str>, key: &str, value: &str) -> bool {
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|part| part.split_once('='))
        .any(|(k, v)| k == key && v == value)
}

fn storage_to_json(ctx: &AppContext) -> Value {
    let (messagestore, local_deliveries, locally_processed, peers, outbound_stamp_costs) = {
        let router = ctx.router.lock().unwrap();
        (
            router.paths.messagestore.clone(),
            router.paths.local_deliveries.clone(),
            router.paths.locally_processed.clone(),
            router.paths.peers.clone(),
            router.paths.outbound_stamp_costs.clone(),
        )
    };
    let (messagestore_count, messagestore_bytes) = file_count_and_bytes(&messagestore);
    let (local_delivery_count, local_delivery_bytes) = file_count_and_bytes(&local_deliveries);
    let (processed_count, processed_bytes) = file_count_and_bytes(&locally_processed);

    json!({
        "storage_dir": ctx.storage_dir.display().to_string(),
        "messagestore": {
            "path": messagestore.display().to_string(),
            "files": messagestore_count,
            "bytes": messagestore_bytes,
        },
        "local_deliveries": {
            "path": local_deliveries.display().to_string(),
            "files": local_delivery_count,
            "bytes": local_delivery_bytes,
        },
        "locally_processed": {
            "path": locally_processed.display().to_string(),
            "files": processed_count,
            "bytes": processed_bytes,
        },
        "peers_path": peers.display().to_string(),
        "stamp_costs_path": outbound_stamp_costs.display().to_string(),
    })
}

fn state_to_json(ctx: &AppContext) -> Value {
    let state = ctx.state.lock().unwrap();
    let router = ctx.router.lock().unwrap();
    json!({
        "status": "ready",
        "display_name": ctx.display_name,
        "uptime": now_timestamp() - ctx.started_at,
        "identity_hash": hex(ctx.identity.hash()),
        "delivery_dest_hash": hex(&ctx.source_hash),
        "propagation_dest_hash": hex(&router.propagation_dest_hash),
        "control_dest_hash": router.control_dest_hash.map(|hash| hex(&hash)),
        "propagation_enabled": router.propagation_node,
        "messages": state.messages.len(),
        "announces": state.announces.len(),
        "propagation_payloads": state.propagation_payloads.len(),
        "outbound": router.outbound.len(),
        "peers": router.peers.len(),
        "stamp_costs": router.outbound_stamp_costs.len(),
        "identity_cache": router.identity_cache.len(),
        "direct_links": router.direct_links.len(),
        "pending_direct_links": router.pending_direct_links.len(),
        "active_propagation_links": router.active_propagation_links.len(),
        "propagation_link": router.propagation_link.map(|id| hex(&id)),
        "propagation_transfer_state": format!("{:?}", router.propagation_transfer_state),
        "propagation_transfer_progress": router.propagation_transfer_progress,
    })
}

fn handle_get(path: &str, query: Option<&str>, ctx: &AppContext, stream: &mut TcpStream) {
    match path {
        "/health" => {
            write_json(
                stream,
                200,
                json!({
                    "status": "healthy",
                    "dest_hash": hex(&ctx.source_hash),
                }),
            );
        }
        "/api/node" => {
            let state = ctx.state.lock().unwrap();
            let router = ctx.router.lock().unwrap();
            write_json(
                stream,
                200,
                json!({
                    "identity_hash": hex(ctx.identity.hash()),
                    "dest_hash": hex(&ctx.source_hash),
                    "display_name": ctx.display_name,
                    "announces": state.announces.len(),
                    "messages": state.messages.len(),
                    "propagation_payloads": state.propagation_payloads.len(),
                    "outbound": router.outbound.len(),
                    "propagation_dest_hash": hex(&router.propagation_dest_hash),
                    "propagation_enabled": router.propagation_node,
                }),
            );
        }
        "/api/state" => write_json(stream, 200, state_to_json(ctx)),
        "/api/messages" => {
            let clear = query_has(query, "clear", "true");
            let mut state = ctx.state.lock().unwrap();
            let messages: Vec<Value> = state.messages.iter().map(message_to_json).collect();
            if clear {
                state.messages.clear();
            }
            write_json(stream, 200, json!({ "messages": messages }));
        }
        "/api/announces" => {
            let clear = query_has(query, "clear", "true");
            let mut state = ctx.state.lock().unwrap();
            let announces: Vec<Value> = state.announces.iter().map(announce_to_json).collect();
            if clear {
                state.announces.clear();
            }
            write_json(stream, 200, json!({ "announces": announces }));
        }
        "/api/propagation" => {
            let clear = query_has(query, "clear", "true");
            let mut state = ctx.state.lock().unwrap();
            let payloads: Vec<Value> = state
                .propagation_payloads
                .iter()
                .map(propagation_to_json)
                .collect();
            if clear {
                state.propagation_payloads.clear();
            }
            let router = ctx.router.lock().unwrap();
            write_json(
                stream,
                200,
                json!({
                    "enabled": router.propagation_node,
                    "propagation_dest_hash": hex(&router.propagation_dest_hash),
                    "control_dest_hash": router.control_dest_hash.map(|hash| hex(&hash)),
                    "propagation_link": router.propagation_link.map(|id| hex(&id)),
                    "active_propagation_links": router.active_propagation_links.iter().map(|id| hex(id)).collect::<Vec<_>>(),
                    "payloads": payloads,
                }),
            );
        }
        "/api/outbound" => {
            let router = ctx.router.lock().unwrap();
            let outbound: Vec<Value> = router.outbound.iter().map(outbound_to_json).collect();
            write_json(stream, 200, json!({ "outbound": outbound }));
        }
        "/api/stamp_costs" => {
            let router = ctx.router.lock().unwrap();
            let costs: Vec<Value> = router
                .outbound_stamp_costs
                .iter()
                .map(|(dest, (timestamp, cost))| {
                    json!({
                        "dest_hash": hex(dest),
                        "timestamp": timestamp,
                        "cost": cost,
                    })
                })
                .collect();
            write_json(stream, 200, json!({ "stamp_costs": costs }));
        }
        "/api/peers" => {
            let router = ctx.router.lock().unwrap();
            let peers: Vec<Value> = router.peers.values().map(peer_to_json).collect();
            write_json(stream, 200, json!({ "peers": peers }));
        }
        "/api/links" => {
            let router = ctx.router.lock().unwrap();
            let direct_links: Vec<Value> = router
                .direct_links
                .iter()
                .map(|(dest, link)| json!({ "dest_hash": hex(dest), "link_id": hex(link) }))
                .collect();
            let pending_direct_links: Vec<Value> = router
                .pending_direct_links
                .iter()
                .map(|(dest, link)| json!({ "dest_hash": hex(dest), "link_id": hex(link) }))
                .collect();
            write_json(
                stream,
                200,
                json!({
                    "direct_links": direct_links,
                    "pending_direct_links": pending_direct_links,
                    "propagation_link": router.propagation_link.map(|id| hex(&id)),
                    "active_propagation_links": router.active_propagation_links.iter().map(|id| hex(id)).collect::<Vec<_>>(),
                }),
            );
        }
        "/api/storage" => write_json(stream, 200, storage_to_json(ctx)),
        _ => write_json(stream, 404, json!({ "error": "not found" })),
    }
}

fn handle_post(
    path: &str,
    request: &HttpRequest,
    ctx: &AppContext,
    stream: &mut TcpStream,
) -> Result<(), String> {
    match path {
        "/api/announce" => {
            let router = ctx.router.lock().unwrap();
            router.announce_delivery(&ctx.identity);
            write_json(
                stream,
                200,
                json!({
                    "announced": true,
                    "dest_hash": hex(&ctx.source_hash),
                }),
            );
            Ok(())
        }
        "/api/jobs" => {
            let mut router = ctx.router.lock().unwrap();
            router.jobs();
            write_json(stream, 200, json!({ "ran": true }));
            Ok(())
        }
        "/api/runtime/clear" => {
            let value = request_json(request)?;
            let clear_messages = value
                .get("messages")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let clear_announces = value
                .get("announces")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let clear_propagation = value
                .get("propagation")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let clear_outbound = value
                .get("outbound")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let clear_caches = value
                .get("caches")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            {
                let mut state = ctx.state.lock().unwrap();
                if clear_messages {
                    state.messages.clear();
                }
                if clear_announces {
                    state.announces.clear();
                }
                if clear_propagation {
                    state.propagation_payloads.clear();
                }
            }
            {
                let mut router = ctx.router.lock().unwrap();
                if clear_outbound {
                    router.outbound.clear();
                }
                if clear_caches {
                    router.locally_delivered_transient_ids.clear();
                    router.locally_processed_transient_ids.clear();
                }
            }

            write_json(stream, 200, json!({ "cleared": true }));
            Ok(())
        }
        "/api/request_path" => {
            let value = request_json(request)?;
            let dest_hash = value
                .get("dest_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "dest_hash is required".to_string())
                .and_then(parse_hex_16)?;
            let requested = {
                let router = ctx.router.lock().unwrap();
                router
                    .node()
                    .map(|node| node.request_path(&DestHash(dest_hash)).is_ok())
                    .unwrap_or(false)
            };
            write_json(
                stream,
                200,
                json!({ "requested": requested, "dest_hash": hex(&dest_hash) }),
            );
            Ok(())
        }
        "/api/direct_link" => {
            let value = request_json(request)?;
            let dest_hash = value
                .get("dest_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "dest_hash is required".to_string())
                .and_then(parse_hex_16)?;
            let created_or_pending = {
                let mut router = ctx.router.lock().unwrap();
                router.ensure_direct_link(dest_hash)
            };
            write_json(
                stream,
                200,
                json!({ "created_or_pending": created_or_pending, "dest_hash": hex(&dest_hash) }),
            );
            Ok(())
        }
        "/api/propagation/enable" => {
            let mut router = ctx.router.lock().unwrap();
            router.enable_propagation();
            write_json(
                stream,
                200,
                json!({
                    "enabled": true,
                    "propagation_dest_hash": hex(&router.propagation_dest_hash),
                    "control_dest_hash": router.control_dest_hash.map(|hash| hex(&hash)),
                }),
            );
            Ok(())
        }
        "/api/propagation/disable" => {
            let mut router = ctx.router.lock().unwrap();
            router.disable_propagation();
            write_json(stream, 200, json!({ "enabled": false }));
            Ok(())
        }
        "/api/propagation/announce" => {
            let router = ctx.router.lock().unwrap();
            router.announce_propagation_node();
            write_json(
                stream,
                200,
                json!({
                    "announced": true,
                    "propagation_dest_hash": hex(&router.propagation_dest_hash),
                }),
            );
            Ok(())
        }
        "/api/propagation/destination" => {
            let value = request_json(request)?;
            let dest_hash = value
                .get("dest_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "dest_hash is required".to_string())
                .and_then(parse_hex_16)?;
            let mut router = ctx.router.lock().unwrap();
            router.set_propagation_dest_hash(dest_hash);
            write_json(
                stream,
                200,
                json!({
                    "propagation_dest_hash": hex(&dest_hash),
                    "outbound_propagation_node": hex(&dest_hash),
                }),
            );
            Ok(())
        }
        "/api/sync" => {
            let value = request_json(request)?;
            let dest_hash = value
                .get("dest_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "dest_hash is required".to_string())
                .and_then(parse_hex_16)?;
            let result = ctx.router.lock().unwrap().sync_peer(&dest_hash);
            write_json(
                stream,
                200,
                json!({
                    "ok": result.is_ok(),
                    "error": result.err().map(|e| format!("{:?}", e)),
                }),
            );
            Ok(())
        }
        "/api/unpeer" => {
            let value = request_json(request)?;
            let dest_hash = value
                .get("dest_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "dest_hash is required".to_string())
                .and_then(parse_hex_16)?;
            let result = ctx.router.lock().unwrap().unpeer(&dest_hash);
            write_json(
                stream,
                200,
                json!({
                    "ok": result.is_ok(),
                    "error": result.err().map(|e| format!("{:?}", e)),
                }),
            );
            Ok(())
        }
        "/api/send" => {
            let value = request_json(request)?;
            let dest_hash = value
                .get("dest_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "dest_hash is required".to_string())
                .and_then(parse_hex_16)?;
            let title = value
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            let content = value
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| "content is required".to_string())?
                .as_bytes()
                .to_vec();
            let method = parse_method(value.get("method").and_then(Value::as_str))?;

            let sign_identity =
                Identity::from_private_key(&ctx.identity.get_private_key().unwrap());
            let packed = message::pack(
                &dest_hash,
                &ctx.source_hash,
                now_timestamp(),
                &title,
                &content,
                vec![],
                None,
                |data| {
                    sign_identity
                        .sign(data)
                        .map_err(|_| message::Error::SignError)
                },
            )
            .map_err(|e| format!("pack failed: {e:?}"))?;

            let message_hash = packed.message_hash;
            let (propagation_packed, transient_id) = if method == DeliveryMethod::Propagated {
                let recipient_public_key = {
                    let router = ctx.router.lock().unwrap();
                    router.identity_cache.get(&dest_hash).copied()
                }
                .ok_or_else(|| {
                    "recipient identity is not cached; announce the recipient before propagated send"
                        .to_string()
                })?;
                let recipient = Identity::from_public_key(&recipient_public_key);
                let mut rng = rns_crypto::OsRng;
                let (propagation_packed, transient_id) =
                    message::propagation_pack(&packed.packed, now_timestamp(), None, |data| {
                        recipient
                            .encrypt(data, &mut rng)
                            .map_err(|_| message::Error::EncryptError)
                    })
                    .map_err(|e| format!("propagation_pack failed: {e:?}"))?;
                (Some(propagation_packed), Some(transient_id))
            } else {
                (None, None)
            };

            let mut router = ctx.router.lock().unwrap();
            router
                .handle_outbound(OutboundMessage {
                    destination_hash: dest_hash,
                    source_hash: ctx.source_hash,
                    packed: packed.packed,
                    message_hash,
                    method,
                    state: MessageState::Outbound,
                    representation: Representation::Unknown,
                    attempts: 0,
                    last_attempt: 0.0,
                    stamp: None,
                    stamp_cost: None,
                    propagation_packed,
                    propagation_stamp: None,
                    transient_id,
                    delivery_callback: None,
                    failed_callback: None,
                    progress_callback: None,
                    link_id: None,
                    packet_hash: None,
                })
                .map_err(|e| e.to_string())?;
            router.jobs();

            write_json(
                stream,
                200,
                json!({
                    "queued": true,
                    "message_hash": hex(&message_hash),
                    "dest_hash": hex(&dest_hash),
                    "method": method_name(method),
                    "transient_id": transient_id.map(|id| hex(&id)),
                }),
            );
            Ok(())
        }
        _ => {
            write_json(stream, 404, json!({ "error": "not found" }));
            Ok(())
        }
    }
}

fn handle_connection(mut stream: TcpStream, ctx: Arc<AppContext>) {
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(e) => {
            write_json(&mut stream, 400, json!({ "error": e }));
            return;
        }
    };
    let (path, query) = split_path_query(&request.path);

    let result = match request.method.as_str() {
        "GET" => {
            handle_get(path, query, &ctx, &mut stream);
            Ok(())
        }
        "POST" => handle_post(path, &request, &ctx, &mut stream),
        _ => {
            write_json(&mut stream, 405, json!({ "error": "method not allowed" }));
            Ok(())
        }
    };

    if let Err(e) = result {
        write_json(&mut stream, 400, json!({ "error": e }));
    }
}

fn print_usage(program: &str) {
    eprintln!(
        "Usage: {program} <rns_host:port> [http_bind] [storage_dir] [display_name]\n\
         Example: {program} node-a:4965 0.0.0.0:8080 /data/lxmf lxmf-a"
    );
}

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let rns_addr = &args[1];
    let http_bind = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());
    let storage_dir = args
        .get(3)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("lxmf-test-node"));
    let display_name = args
        .get(4)
        .cloned()
        .unwrap_or_else(|| "lxmf-test-node".to_string());

    let (rns_host, rns_port) = parse_addr(rns_addr).unwrap_or_else(|e| {
        eprintln!("{e}");
        print_usage(&args[0]);
        std::process::exit(1);
    });

    std::fs::create_dir_all(&storage_dir).expect("create storage directory");
    let identity = load_or_create_identity(&storage_dir.join("identity"));
    let source_hash =
        rns_core::destination::destination_hash(APP_NAME, &["delivery"], Some(identity.hash()));

    let state = Arc::new(Mutex::new(TestState::default()));
    let mut router = LxmRouter::new(
        Identity::from_private_key(&identity.get_private_key().unwrap()),
        RouterConfig {
            storagepath: storage_dir.clone(),
            ..RouterConfig::default()
        },
    );

    let delivery_state = state.clone();
    router.set_delivery_callback(Box::new(move |delivery: &LxmDelivery| {
        if let Ok(mut state) = delivery_state.lock() {
            state.messages.push(ReceivedMessage {
                source_hash: delivery.source_hash,
                title: delivery.title.clone(),
                content: delivery.content.clone(),
                method: delivery.method,
                message_hash: delivery.message_hash,
                received_at: now_timestamp(),
            });
        }
    }));

    let router = Arc::new(Mutex::new(router));
    let callbacks = AppCallbacks {
        inner: LxmfCallbacks::new(router.clone()),
        state: state.clone(),
    };

    let node = Arc::new(
        RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: Some(Identity::new(&mut rns_crypto::OsRng)),
                interfaces: vec![InterfaceConfig {
                    name: String::new(),
                    type_name: "TCPClientInterface".to_string(),
                    config_data: Box::new(TcpClientConfig {
                        name: "lxmf-test-node".into(),
                        target_host: rns_host,
                        target_port: rns_port,
                        interface_id: InterfaceId(1),
                        ..TcpClientConfig::default()
                    }),
                    mode: rns_core::constants::MODE_FULL,
                    ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
                    ifac: None,
                    discovery: None,
                }],
                cache_dir: Some(storage_dir.clone()),
                ..NodeConfig::default()
            },
            Box::new(callbacks),
        )
        .expect("start RNS node"),
    );

    {
        let mut router = router.lock().unwrap();
        router.set_node(node.clone());
        router.register_delivery_identity(&identity, None, Some(display_name.clone()));
        router.announce_delivery(&identity);
    }

    let ctx = Arc::new(AppContext {
        router: router.clone(),
        _node: node,
        state,
        identity,
        source_hash,
        display_name,
        storage_dir: storage_dir.clone(),
        started_at: now_timestamp(),
    });

    {
        let router = router.clone();
        thread::spawn(move || loop {
            if let Ok(mut router) = router.lock() {
                router.jobs();
            }
            thread::sleep(Duration::from_millis(200));
        });
    }

    let listener = TcpListener::bind(&http_bind).expect("bind HTTP control listener");
    println!("lxmf test node ready");
    println!("  rns:       {}", rns_addr);
    println!("  http:      {}", http_bind);
    println!("  storage:   {}", storage_dir.display());
    println!("  dest_hash: {}", hex(&ctx.source_hash));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let ctx = ctx.clone();
                thread::spawn(move || handle_connection(stream, ctx));
            }
            Err(e) => eprintln!("HTTP accept failed: {e}"),
        }
    }
}
