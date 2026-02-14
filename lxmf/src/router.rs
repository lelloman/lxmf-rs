use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lxmf_core::constants::*;
use lxmf_core::message;
use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;

use rns_net::destination::{AnnouncedIdentity, Destination};
use rns_net::driver::Callbacks;
use rns_net::node::RnsNode;

use crate::peer::LxmPeer;
use crate::storage::{self, StoragePaths};

/// Callback function types for the router.
pub type DeliveryCallback = Box<dyn Fn(&LxmDelivery) + Send>;
pub type ProgressCallback = Box<dyn Fn(&[u8; 32], f64) + Send>;

/// Information about a delivered message passed to the delivery callback.
pub struct LxmDelivery {
    pub destination_hash: [u8; DESTINATION_LENGTH],
    pub source_hash: [u8; DESTINATION_LENGTH],
    pub timestamp: f64,
    pub title: Vec<u8>,
    pub content: Vec<u8>,
    pub fields: Vec<(Value, Value)>,
    pub message_hash: [u8; 32],
    pub signature_valid: Option<bool>,
    pub stamp: Option<Vec<u8>>,
    pub transport_encrypted: bool,
    pub transport_encryption: String,
    pub method: DeliveryMethod,
}

/// An outbound message queued for delivery.
pub struct OutboundMessage {
    pub destination_hash: [u8; DESTINATION_LENGTH],
    pub source_hash: [u8; DESTINATION_LENGTH],
    pub packed: Vec<u8>,
    pub message_hash: [u8; 32],
    pub method: DeliveryMethod,
    pub state: MessageState,
    pub representation: Representation,
    pub attempts: u32,
    pub last_attempt: f64,
    pub stamp: Option<Vec<u8>>,
    pub stamp_cost: Option<u8>,
    pub propagation_packed: Option<Vec<u8>>,
    pub propagation_stamp: Option<Vec<u8>>,
    pub transient_id: Option<[u8; 32]>,
    pub delivery_callback: Option<Box<dyn Fn(&OutboundMessage) + Send>>,
    pub failed_callback: Option<Box<dyn Fn(&OutboundMessage) + Send>>,
    pub progress_callback: Option<Box<dyn Fn(&OutboundMessage, f64) + Send>>,
    /// Tracking link_id for direct delivery
    pub link_id: Option<[u8; 16]>,
    /// Tracking packet_hash for opportunistic delivery
    pub packet_hash: Option<[u8; 32]>,
}

/// Configuration for the LXM Router.
pub struct RouterConfig {
    pub storagepath: PathBuf,
    pub autopeer: bool,
    pub autopeer_maxdepth: u8,
    pub propagation_limit: u32,
    pub delivery_limit: u32,
    pub sync_limit: u32,
    pub enforce_ratchets: bool,
    pub enforce_stamps: bool,
    pub static_peers: Vec<[u8; 16]>,
    pub max_peers: usize,
    pub from_static_only: bool,
    pub sync_strategy: SyncStrategy,
    pub propagation_cost: u8,
    pub propagation_cost_flexibility: u8,
    pub peering_cost: u8,
    pub max_peering_cost: u8,
    pub name: Option<String>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            storagepath: PathBuf::from("."),
            autopeer: AUTOPEER,
            autopeer_maxdepth: AUTOPEER_MAXDEPTH,
            propagation_limit: PROPAGATION_LIMIT,
            delivery_limit: DELIVERY_LIMIT,
            sync_limit: SYNC_LIMIT,
            enforce_ratchets: false,
            enforce_stamps: false,
            static_peers: Vec::new(),
            max_peers: MAX_PEERS,
            from_static_only: false,
            sync_strategy: DEFAULT_SYNC_STRATEGY,
            propagation_cost: PROPAGATION_COST,
            propagation_cost_flexibility: PROPAGATION_COST_FLEX,
            peering_cost: PEERING_COST,
            max_peering_cost: MAX_PEERING_COST,
            name: None,
        }
    }
}

/// The core LXMF router engine.
///
/// Manages delivery queue, inbound processing, propagation node functionality,
/// peer management, and announce handling.
pub struct LxmRouter {
    pub identity: Identity,
    pub config: RouterConfig,
    pub paths: StoragePaths,

    // Destinations
    pub propagation_dest_hash: [u8; 16],
    pub delivery_dest_hash: Option<[u8; 16]>,
    pub control_dest_hash: Option<[u8; 16]>,

    // Message queues
    pub outbound: Vec<OutboundMessage>,
    pub pending_inbound: VecDeque<Vec<u8>>,

    // Link tracking
    pub direct_links: HashMap<[u8; 16], [u8; 16]>,       // dest_hash -> link_id
    pub backchannel_links: HashMap<[u8; 16], [u8; 16]>,   // dest_hash -> link_id
    pub link_destinations: HashMap<[u8; 16], [u8; 16]>,   // link_id -> dest_hash
    pub active_propagation_links: Vec<[u8; 16]>,
    pub propagation_link: Option<[u8; 16]>,

    // Caches
    pub locally_delivered_transient_ids: HashMap<[u8; 32], f64>,
    pub locally_processed_transient_ids: HashMap<[u8; 32], f64>,
    pub outbound_stamp_costs: HashMap<[u8; 16], (f64, u8)>,

    // State
    pub propagation_node: bool,
    pub processing_count: u32,
    pub exit_handler_running: bool,

    // Delivery callback
    pub delivery_callback: Option<DeliveryCallback>,

    // Access control
    pub auth_required: bool,
    pub allowed_list: Vec<[u8; 16]>,
    pub ignored_list: Vec<[u8; 16]>,
    pub prioritised_list: Vec<[u8; 16]>,
    pub control_allowed_list: Vec<[u8; 16]>,

    // Peers
    pub peers: HashMap<[u8; 16], LxmPeer>,

    // Propagation transfer state (client-side)
    pub propagation_transfer_state: PropagationTransferState,
    pub propagation_transfer_progress: f64,
    pub propagation_transfer_max_messages: Option<u32>,

    // Identity cache (dest_hash → public_key) populated from announces.
    // Used for signature verification in lxmf_delivery to avoid synchronous
    // RPC calls to the driver thread (which would deadlock when called from
    // a driver callback like on_local_delivery).
    pub identity_cache: HashMap<[u8; 16], [u8; 64]>,

    // Node reference (set after start)
    node: Option<Arc<RnsNode>>,

    // Display name for delivery announces
    pub display_name: Option<String>,
    pub delivery_stamp_cost: Option<u8>,
}

impl LxmRouter {
    /// Create a new LXM Router.
    pub fn new(identity: Identity, config: RouterConfig) -> Self {
        let paths = StoragePaths::new(&config.storagepath);
        let _ = paths.ensure_dirs();

        // Compute propagation destination hash
        let propagation_dest_hash =
            compute_dest_hash(APP_NAME, &["propagation"], identity.hash());

        // Load persisted state
        let locally_delivered_transient_ids =
            storage::load_transient_ids(&paths.local_deliveries);
        let locally_processed_transient_ids =
            storage::load_transient_ids(&paths.locally_processed);
        let outbound_stamp_costs = storage::load_stamp_costs(&paths.outbound_stamp_costs);

        // Load peers from storage
        let mut peers = HashMap::new();
        for peer_val in storage::load_peers(&paths.peers) {
            let peer_bytes = msgpack::pack(&peer_val);
            if let Some(peer) = LxmPeer::from_bytes(&peer_bytes) {
                peers.insert(peer.destination_hash, peer);
            }
        }

        Self {
            identity,
            propagation_dest_hash,
            delivery_dest_hash: None,
            control_dest_hash: None,
            outbound: Vec::new(),
            pending_inbound: VecDeque::new(),
            direct_links: HashMap::new(),
            backchannel_links: HashMap::new(),
            link_destinations: HashMap::new(),
            active_propagation_links: Vec::new(),
            propagation_link: None,
            locally_delivered_transient_ids,
            locally_processed_transient_ids,
            outbound_stamp_costs,
            propagation_node: false,
            processing_count: 0,
            exit_handler_running: false,
            delivery_callback: None,
            auth_required: false,
            allowed_list: Vec::new(),
            ignored_list: Vec::new(),
            prioritised_list: Vec::new(),
            control_allowed_list: Vec::new(),
            peers,
            propagation_transfer_state: PropagationTransferState::Idle,
            propagation_transfer_progress: 0.0,
            propagation_transfer_max_messages: None,
            identity_cache: HashMap::new(),
            node: None,
            display_name: None,
            delivery_stamp_cost: None,
            config,
            paths,
        }
    }

    /// Set the RNS node reference. Called after starting the node.
    pub fn set_node(&mut self, node: Arc<RnsNode>) {
        self.node = Some(node);
    }

    /// Get a reference to the RNS node.
    pub fn node(&self) -> Option<&RnsNode> {
        self.node.as_deref()
    }

    /// Register a delivery identity for receiving direct messages.
    pub fn register_delivery_identity(
        &mut self,
        delivery_identity: &Identity,
        stamp_cost: Option<u8>,
        display_name: Option<String>,
    ) {
        let dest_hash =
            compute_dest_hash(APP_NAME, &["delivery"], delivery_identity.hash());
        self.delivery_dest_hash = Some(dest_hash);
        self.delivery_stamp_cost = stamp_cost;
        self.display_name = display_name;

        if let Some(node) = &self.node {
            // Register as link destination so we can accept incoming LINKREQUEST.
            // Also register as SINGLE destination for opportunistic delivery.
            // When both are registered, rns-net routes link packets through
            // link_manager and falls back to on_local_delivery for non-link DATA.
            let sig_prv = delivery_identity.get_private_key().unwrap();
            let sig_pub = delivery_identity.get_public_key().unwrap();
            let _ = node.register_link_destination(
                dest_hash,
                sig_prv[32..].try_into().unwrap(),
                sig_pub[32..].try_into().unwrap(),
            );
            let _ = node.register_destination(dest_hash, 1); // SINGLE type
        }
    }

    /// Set the delivery callback for incoming messages.
    pub fn set_delivery_callback(&mut self, callback: DeliveryCallback) {
        self.delivery_callback = Some(callback);
    }

    /// Enable propagation node functionality.
    pub fn enable_propagation(&mut self) {
        self.propagation_node = true;

        if let Some(node) = &self.node {
            let sig_prv = self.identity.get_private_key().unwrap();
            let sig_pub = self.identity.get_public_key().unwrap();

            // Register propagation destination for incoming links
            let _ = node.register_link_destination(
                self.propagation_dest_hash,
                sig_prv[32..].try_into().unwrap(),
                sig_pub[32..].try_into().unwrap(),
            );
            let _ = node.register_destination(self.propagation_dest_hash, 1);

            // Register control destination
            let control_hash = compute_dest_hash(
                APP_NAME,
                &["propagation", "control"],
                self.identity.hash(),
            );
            self.control_dest_hash = Some(control_hash);
            let _ = node.register_destination(control_hash, 1);
        }
    }

    /// Disable propagation node functionality at runtime.
    pub fn disable_propagation(&mut self) {
        if !self.propagation_node {
            return;
        }
        self.propagation_node = false;

        if let Some(node) = &self.node {
            // Tear down active propagation links
            for &link_id in &self.active_propagation_links {
                let _ = node.teardown_link(link_id);
            }
            self.active_propagation_links.clear();

            // Deregister propagation destination (link + regular)
            let _ = node.deregister_link_destination(self.propagation_dest_hash);
            let _ = node.deregister_destination(self.propagation_dest_hash);

            // Deregister control destination
            if let Some(control_hash) = self.control_dest_hash.take() {
                let _ = node.deregister_destination(control_hash);
            }

            // Re-announce with propagation_enabled=false
            self.announce_propagation_node();
        }

        // Clear peers and save empty state
        let peer_hashes: Vec<[u8; 16]> = self.peers.keys().copied().collect();
        for hash in &peer_hashes {
            let _ = self.unpeer(hash);
        }
        self.save_peers();
    }

    /// Announce the delivery destination.
    pub fn announce_delivery(&self, delivery_identity: &Identity) {
        if let (Some(node), Some(_dest_hash)) = (&self.node, self.delivery_dest_hash) {
            let app_data = self.build_delivery_announce_data();
            let dest = Destination::single_in(
                APP_NAME,
                &["delivery"],
                IdentityHash(*delivery_identity.hash()),
            );
            let _ = node.announce(&dest, delivery_identity, Some(&app_data));
        }
    }

    /// Announce the propagation node.
    pub fn announce_propagation_node(&self) {
        if let Some(node) = &self.node {
            let app_data = self.build_pn_announce_data();
            let dest = Destination::single_in(
                APP_NAME,
                &["propagation"],
                IdentityHash(*self.identity.hash()),
            );
            let _ = node.announce(&dest, &self.identity, Some(&app_data));
        }
    }

    /// Build delivery announce app_data (v0.5.0+ format).
    fn build_delivery_announce_data(&self) -> Vec<u8> {
        let display_name_val = match &self.display_name {
            Some(name) => Value::Bin(name.as_bytes().to_vec()),
            None => Value::Nil,
        };
        let stamp_cost_val = match self.delivery_stamp_cost {
            Some(cost) => Value::UInt(cost as u64),
            None => Value::Nil,
        };
        msgpack::pack(&Value::Array(vec![display_name_val, stamp_cost_val]))
    }

    /// Build propagation node announce data.
    fn build_pn_announce_data(&self) -> Vec<u8> {
        let now = now_timestamp();
        let state = self.propagation_node && !self.config.from_static_only;
        let metadata = Value::Map(vec![]);

        let announce_data = Value::Array(vec![
            Value::Bool(false), // Legacy flag
            Value::UInt(now as u64),
            Value::Bool(state),
            Value::UInt(self.config.propagation_limit as u64),
            Value::UInt(self.config.sync_limit as u64),
            Value::Array(vec![
                Value::UInt(self.config.propagation_cost as u64),
                Value::UInt(self.config.propagation_cost_flexibility as u64),
                Value::UInt(self.config.peering_cost as u64),
            ]),
            metadata,
        ]);
        msgpack::pack(&announce_data)
    }

    /// Handle an outbound message for delivery.
    pub fn handle_outbound(&mut self, msg: OutboundMessage) {
        self.outbound.push(msg);
    }

    /// Run periodic jobs. Called every PROCESSING_INTERVAL seconds.
    pub fn jobs(&mut self) {
        if self.exit_handler_running {
            return;
        }

        self.processing_count = self.processing_count.wrapping_add(1);

        // Outbound processing (every cycle)
        if self.processing_count % JOB_OUTBOUND_INTERVAL == 0 {
            self.process_outbound();
        }

        // Link cleanup (every cycle)
        if self.processing_count % JOB_LINKS_INTERVAL == 0 {
            self.clean_links();
        }

        // Transient ID cleanup (every 60 cycles = 4 min)
        if self.processing_count % JOB_TRANSIENT_INTERVAL == 0 {
            self.clean_transient_id_caches();
        }

        // Message store cleanup and peer save (every 120 cycles = 8 min)
        if self.processing_count % JOB_STORE_INTERVAL == 0 {
            self.save_peers();
        }
    }

    /// Process outbound message queue.
    ///
    /// Uses field-level borrows to avoid borrow checker issues:
    /// we iterate `self.outbound` mutably while reading other fields.
    fn process_outbound(&mut self) {
        let now = now_timestamp();
        let node = match &self.node {
            Some(n) => n.clone(),
            None => return,
        };

        let mut failed_indices = Vec::new();
        let completed_indices: Vec<usize> = Vec::new();

        for (idx, msg) in self.outbound.iter_mut().enumerate() {
            if msg.state != MessageState::Outbound {
                continue;
            }

            // Check retry timing
            if now - msg.last_attempt < DELIVERY_RETRY_WAIT as f64 {
                continue;
            }

            // Check max attempts
            if msg.attempts >= MAX_DELIVERY_ATTEMPTS {
                msg.state = MessageState::Failed;
                failed_indices.push(idx);
                continue;
            }

            msg.attempts += 1;
            msg.last_attempt = now;

            match msg.method {
                DeliveryMethod::Opportunistic => {
                    if node.has_path(&DestHash(msg.destination_hash)).unwrap_or(false) {
                        if let Ok(Some(announced)) =
                            node.recall_identity(&DestHash(msg.destination_hash))
                        {
                            let dest =
                                Destination::single_out(APP_NAME, &["delivery"], &announced);
                            let data = &msg.packed[DESTINATION_LENGTH..];
                            match node.send_packet(&dest, data) {
                                Ok(packet_hash) => {
                                    msg.packet_hash = Some(packet_hash.0);
                                    msg.state = MessageState::Sent;
                                }
                                Err(_) => {
                                    log::warn!("Failed to send opportunistic packet");
                                }
                            }
                        }
                    } else if msg.attempts <= MAX_PATHLESS_TRIES + 1 {
                        let _ = node.request_path(&DestHash(msg.destination_hash));
                    }
                }
                DeliveryMethod::Direct => {
                    if let Some(&link_id) = self.direct_links.get(&msg.destination_hash) {
                        send_on_link(&node, msg, link_id);
                    } else if let Ok(Some(announced)) =
                        node.recall_identity(&DestHash(msg.destination_hash))
                    {
                        let sig_pub: [u8; 32] = announced.public_key[32..].try_into().unwrap();
                        match node.create_link(msg.destination_hash, sig_pub) {
                            Ok(link_id) => {
                                msg.link_id = Some(link_id);
                                msg.state = MessageState::Sending;
                            }
                            Err(_) => {
                                log::warn!("Failed to create direct link");
                            }
                        }
                    } else if msg.attempts <= MAX_PATHLESS_TRIES + 1 {
                        let _ = node.request_path(&DestHash(msg.destination_hash));
                    }
                }
                DeliveryMethod::Propagated => {
                    if let Some(link_id) = self.propagation_link {
                        if let Some(ref prop_packed) = msg.propagation_packed {
                            if prop_packed.len() <= LINK_PACKET_MDU {
                                msg.representation = Representation::Packet;
                                let _ = node.send_on_link(link_id, prop_packed.clone(), 0);
                            } else {
                                msg.representation = Representation::Resource;
                                let _ =
                                    node.send_resource(link_id, prop_packed.clone(), None);
                            }
                            msg.state = MessageState::Sending;
                        }
                    } else {
                        let _ =
                            node.request_path(&DestHash(self.propagation_dest_hash));
                    }
                }
                DeliveryMethod::Paper => {
                    // Paper messages don't need outbound processing
                }
            }
        }

        // Fire callbacks for failed messages
        for &idx in failed_indices.iter().rev() {
            let msg = &self.outbound[idx];
            if let Some(cb) = &msg.failed_callback {
                cb(msg);
            }
        }

        // Remove completed messages (reverse order to preserve indices)
        for &idx in completed_indices.iter().rev() {
            self.outbound.remove(idx);
        }
    }

    /// Clean up inactive links.
    fn clean_links(&mut self) {
        // Link cleanup is handled via on_link_closed callbacks
    }

    /// Clean expired transient ID caches.
    fn clean_transient_id_caches(&mut self) {
        let now = now_timestamp();
        let expiry = MESSAGE_EXPIRY as f64;

        self.locally_delivered_transient_ids
            .retain(|_, ts| now - *ts < expiry);
        self.locally_processed_transient_ids
            .retain(|_, ts| now - *ts < expiry);

        // Persist
        let _ = storage::save_transient_ids(
            &self.paths.local_deliveries,
            &self.locally_delivered_transient_ids,
        );
        let _ = storage::save_transient_ids(
            &self.paths.locally_processed,
            &self.locally_processed_transient_ids,
        );
    }

    /// Process an inbound LXMF delivery (from packet, link, or resource).
    pub fn lxmf_delivery(
        &mut self,
        lxmf_bytes: &[u8],
        transport_encrypted: bool,
        transport_encryption: &str,
        method: DeliveryMethod,
    ) {
        // Use local identity cache for signature verification. We must NOT
        // call node.recall_identity() here because lxmf_delivery can be called
        // from a driver callback (on_local_delivery), and recall_identity does
        // a synchronous RPC to the driver thread — causing a self-deadlock.
        let cache = self.identity_cache.clone();
        let verify_fn = |src_hash: &[u8; 16], sig: &[u8; 64], data: &[u8]| -> bool {
            if let Some(public_key) = cache.get(src_hash) {
                let id = Identity::from_public_key(public_key);
                return id.verify(sig, data);
            }
            false
        };

        let result = match message::unpack(lxmf_bytes, Some(&verify_fn)) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Failed to unpack inbound message: {:?}", e);
                return;
            }
        };

        // Check if source is ignored
        if self.ignored_list.contains(&result.source_hash) {
            return;
        }

        // Check for duplicates
        let now = now_timestamp();
        if self
            .locally_delivered_transient_ids
            .contains_key(&result.message_hash)
        {
            return;
        }

        // Check stamp validity if enforcement is on
        if self.config.enforce_stamps {
            if let Some(dest_hash) = self.delivery_dest_hash {
                if dest_hash == result.destination_hash {
                    if let Some(stamp_cost) = self.delivery_stamp_cost {
                        if stamp_cost > 0 {
                            let valid_stamp = if let Some(ref stamp) = result.stamp {
                                let workblock = lxmf_core::stamp::stamp_workblock(
                                    &result.message_hash,
                                    WORKBLOCK_EXPAND_ROUNDS,
                                );
                                lxmf_core::stamp::stamp_valid(stamp, stamp_cost, &workblock)
                            } else {
                                false
                            };
                            if !valid_stamp {
                                log::debug!("Dropping message with invalid stamp");
                                return;
                            }
                        }
                    }
                }
            }
        }

        // Record delivery
        self.locally_delivered_transient_ids
            .insert(result.message_hash, now);

        // Fire delivery callback
        if let Some(callback) = &self.delivery_callback {
            let delivery = LxmDelivery {
                destination_hash: result.destination_hash,
                source_hash: result.source_hash,
                timestamp: result.timestamp,
                title: result.title,
                content: result.content,
                fields: result.fields,
                message_hash: result.message_hash,
                signature_valid: result.signature_valid,
                stamp: result.stamp,
                transport_encrypted,
                transport_encryption: transport_encryption.to_string(),
                method,
            };
            callback(&delivery);
        }
    }

    /// Update outbound stamp cost for a destination.
    pub fn update_stamp_cost(&mut self, dest_hash: [u8; 16], cost: u8) {
        let now = now_timestamp();
        self.outbound_stamp_costs.insert(dest_hash, (now, cost));
        let _ = storage::save_stamp_costs(
            &self.paths.outbound_stamp_costs,
            &self.outbound_stamp_costs,
        );
    }

    /// Get the known stamp cost for a destination.
    pub fn get_stamp_cost(&self, dest_hash: &[u8; 16]) -> Option<u8> {
        let now = now_timestamp();
        if let Some(&(ts, cost)) = self.outbound_stamp_costs.get(dest_hash) {
            if now - ts < STAMP_COST_EXPIRY as f64 {
                return Some(cost);
            }
        }
        None
    }

    /// Trigger sync with a specific peer by resetting its next sync attempt to now.
    pub fn sync_peer(&mut self, dest_hash: &[u8; 16]) -> Result<(), PeerError> {
        let peer = self.peers.get_mut(dest_hash).ok_or(PeerError::NotFound)?;
        peer.next_sync_attempt = 0.0;
        Ok(())
    }

    /// Remove a peer from the peer list.
    pub fn unpeer(&mut self, dest_hash: &[u8; 16]) -> Result<(), PeerError> {
        self.peers.remove(dest_hash).ok_or(PeerError::NotFound)?;
        Ok(())
    }

    /// Persist peers to storage.
    fn save_peers(&self) {
        let peer_values: Vec<Value> = self
            .peers
            .values()
            .filter_map(|peer| {
                let bytes = peer.to_bytes();
                msgpack::unpack_exact(&bytes).ok()
            })
            .collect();
        let _ = storage::save_peers(&self.paths.peers, &peer_values);
    }

    /// Exit handler: save state and tear down connections.
    pub fn exit_handler(&mut self) {
        self.exit_handler_running = true;

        // Tear down links
        if let Some(node) = &self.node {
            for &link_id in self.direct_links.values() {
                let _ = node.teardown_link(link_id);
            }
            for &link_id in self.backchannel_links.values() {
                let _ = node.teardown_link(link_id);
            }
            for &link_id in &self.active_propagation_links {
                let _ = node.teardown_link(link_id);
            }
        }

        // Save state
        let _ = storage::save_transient_ids(
            &self.paths.local_deliveries,
            &self.locally_delivered_transient_ids,
        );
        let _ = storage::save_transient_ids(
            &self.paths.locally_processed,
            &self.locally_processed_transient_ids,
        );
        let _ = storage::save_stamp_costs(
            &self.paths.outbound_stamp_costs,
            &self.outbound_stamp_costs,
        );

        // Save peers
        self.save_peers();

        // Drop node reference so the daemon can reclaim ownership for full shutdown.
        self.node = None;
    }
}

/// Send a message on an established link (as packet or resource).
fn send_on_link(node: &RnsNode, msg: &mut OutboundMessage, link_id: [u8; 16]) {
    if msg.packed.len() <= LINK_PACKET_MDU {
        msg.representation = Representation::Packet;
        match node.send_on_link(link_id, msg.packed.clone(), 0) {
            Ok(()) => {
                msg.state = MessageState::Sending;
            }
            Err(_) => {
                log::warn!("Failed to send on direct link");
            }
        }
    } else {
        msg.representation = Representation::Resource;
        match node.send_resource(link_id, msg.packed.clone(), None) {
            Ok(()) => {
                msg.state = MessageState::Sending;
            }
            Err(_) => {
                log::warn!("Failed to send resource on direct link");
            }
        }
    }
}

/// Callbacks implementation for the LXMF router.
///
/// This is the bridge between rns-net events and the LXMF router.
/// The router is wrapped in Arc<Mutex<>> for thread-safe access.
pub struct LxmfCallbacks {
    router: Arc<Mutex<LxmRouter>>,
}

impl LxmfCallbacks {
    pub fn new(router: Arc<Mutex<LxmRouter>>) -> Self {
        Self { router }
    }
}

impl Callbacks for LxmfCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let mut router = self.router.lock().unwrap();

        // Check if this is our own delivery announce
        if let Some(delivery_hash) = router.delivery_dest_hash {
            if announced.dest_hash.0 == delivery_hash {
                return;
            }
        }

        // Cache the public key for signature verification in lxmf_delivery
        router.identity_cache.insert(announced.dest_hash.0, announced.public_key);

        // Extract stamp cost from delivery announces
        if let Some(ref app_data) = announced.app_data {
            if !app_data.is_empty() {
                let first = app_data[0];
                // Check for msgpack array header (v0.5.0+ format)
                if (0x90..=0x9F).contains(&first) || first == 0xDC {
                    if let Ok(val) = msgpack::unpack_exact(app_data) {
                        if let Some(arr) = val.as_array() {
                            if arr.len() >= 2 {
                                if let Some(cost) = arr[1].as_uint() {
                                    router.update_stamp_cost(
                                        announced.dest_hash.0,
                                        cost as u8,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Propagation announce handling is done in handlers module
    }

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {
        // Could trigger outbound processing for waiting messages
    }

    fn on_local_delivery(
        &mut self,
        dest_hash: DestHash,
        raw: Vec<u8>,
        _packet_hash: PacketHash,
    ) {
        let mut router = self.router.lock().unwrap();

        // Check if this is for our delivery destination
        if let Some(delivery_hash) = router.delivery_dest_hash {
            if dest_hash.0 == delivery_hash {
                // Extract data payload from raw wire packet
                let packet = match rns_core::packet::RawPacket::unpack(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("on_local_delivery: unpack failed: {}", e);
                        return;
                    }
                };
                // Decrypt the data payload (encrypted with our public key by sender)
                let plaintext = match router.identity.decrypt(&packet.data) {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("on_local_delivery: decrypt failed: {:?}", e);
                        return;
                    }
                };
                // Opportunistic delivery: prepend destination hash to decrypted payload
                let mut lxmf_bytes =
                    Vec::with_capacity(DESTINATION_LENGTH + plaintext.len());
                lxmf_bytes.extend_from_slice(&dest_hash.0);
                lxmf_bytes.extend_from_slice(&plaintext);
                router.lxmf_delivery(
                    &lxmf_bytes,
                    true,
                    ENCRYPTION_DESCRIPTION_EC,
                    DeliveryMethod::Opportunistic,
                );
            }
        }
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        dest_hash: DestHash,
        _rtt: f64,
        is_initiator: bool,
    ) {
        let mut router = self.router.lock().unwrap();

        if is_initiator {
            // We initiated this link - check if it's for a direct delivery
            let node = match &router.node {
                Some(n) => n.clone(),
                None => return,
            };
            for msg in &mut router.outbound {
                if msg.link_id == Some(link_id.0) {
                    send_on_link(&node, msg, link_id.0);
                    break;
                }
            }
        } else {
            // Incoming link — map link_id to its destination for delivery routing
            router.link_destinations.insert(link_id.0, dest_hash.0);

            if let Some(node) = &router.node {
                // Accept resources on this link
                let _ = node.set_resource_strategy(link_id.0, 1); // AcceptAll
            }

            // Track if it's a propagation link
            if router.propagation_node {
                router.active_propagation_links.push(link_id.0);
            }
        }
    }

    fn on_link_closed(
        &mut self,
        link_id: LinkId,
        _reason: Option<rns_core::link::TeardownReason>,
    ) {
        let mut router = self.router.lock().unwrap();

        // Remove from link tracking
        router.direct_links.retain(|_, v| *v != link_id.0);
        router.backchannel_links.retain(|_, v| *v != link_id.0);
        router.link_destinations.remove(&link_id.0);
        router
            .active_propagation_links
            .retain(|&id| id != link_id.0);

        if router.propagation_link == Some(link_id.0) {
            router.propagation_link = None;
        }

        // Reset any outbound messages waiting on this link
        for msg in &mut router.outbound {
            if msg.link_id == Some(link_id.0) && msg.state == MessageState::Sending {
                msg.state = MessageState::Outbound;
                msg.link_id = None;
            }
        }
    }

    fn on_remote_identified(
        &mut self,
        link_id: LinkId,
        identity_hash: IdentityHash,
        _public_key: [u8; 64],
    ) {
        let mut router = self.router.lock().unwrap();
        router.backchannel_links.insert(identity_hash.0, link_id.0);
    }

    fn on_resource_received(
        &mut self,
        link_id: LinkId,
        data: Vec<u8>,
        _metadata: Option<Vec<u8>>,
    ) {
        let mut router = self.router.lock().unwrap();

        // Check if this link is for delivery
        let is_delivery_link = router
            .link_destinations
            .get(&link_id.0)
            .map_or(false, |dh| router.delivery_dest_hash == Some(*dh));

        if is_delivery_link {
            router.lxmf_delivery(
                &data,
                true,
                ENCRYPTION_DESCRIPTION_EC,
                DeliveryMethod::Direct,
            );
        }
    }

    fn on_resource_completed(&mut self, link_id: LinkId) {
        let mut router = self.router.lock().unwrap();

        // Mark outbound messages as delivered
        for msg in &mut router.outbound {
            if msg.link_id == Some(link_id.0) && msg.state == MessageState::Sending {
                if msg.method == DeliveryMethod::Propagated {
                    msg.state = MessageState::Sent;
                } else {
                    msg.state = MessageState::Delivered;
                }
                if let Some(cb) = &msg.delivery_callback {
                    cb(msg);
                }
                break;
            }
        }
    }

    fn on_resource_failed(&mut self, link_id: LinkId, _error: String) {
        let mut router = self.router.lock().unwrap();

        for msg in &mut router.outbound {
            if msg.link_id == Some(link_id.0) && msg.state == MessageState::Sending {
                msg.state = MessageState::Outbound;
                msg.link_id = None;
                break;
            }
        }
    }

    fn on_response(
        &mut self,
        _link_id: LinkId,
        _request_id: [u8; 16],
        _data: Vec<u8>,
    ) {
        // Response handling for propagation requests is done in peer module
    }

    fn on_proof(
        &mut self,
        _dest_hash: DestHash,
        packet_hash: PacketHash,
        _rtt: f64,
    ) {
        let mut router = self.router.lock().unwrap();

        // Check if this proof matches an outbound message
        for msg in &mut router.outbound {
            if msg.packet_hash == Some(packet_hash.0) {
                msg.state = MessageState::Delivered;
                if let Some(cb) = &msg.delivery_callback {
                    cb(msg);
                }
                break;
            }
        }
    }

    fn on_proof_requested(
        &mut self,
        dest_hash: DestHash,
        _packet_hash: PacketHash,
    ) -> bool {
        let router = self.router.lock().unwrap();
        // Auto-prove delivery packets
        router.delivery_dest_hash == Some(dest_hash.0)
    }

    fn on_link_data(
        &mut self,
        link_id: LinkId,
        _context: u8,
        data: Vec<u8>,
    ) {
        let mut router = self.router.lock().unwrap();

        // Direct delivery via link packet
        let is_delivery_link = router
            .link_destinations
            .get(&link_id.0)
            .map_or(false, |dh| router.delivery_dest_hash == Some(*dh));

        if is_delivery_link {
            router.lxmf_delivery(
                &data,
                true,
                ENCRYPTION_DESCRIPTION_EC,
                DeliveryMethod::Direct,
            );
        }
    }
}

// ============================================================
// Helper functions
// ============================================================

/// Compute a destination hash from app_name, aspects, and identity hash.
/// Delegates to rns_core to ensure consistency with the network protocol.
fn compute_dest_hash(app_name: &str, aspects: &[&str], identity_hash: &[u8; 16]) -> [u8; 16] {
    rns_core::destination::destination_hash(app_name, aspects, Some(identity_hash))
}

/// Get current UNIX timestamp as f64.
pub fn now_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
