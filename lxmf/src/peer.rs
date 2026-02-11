use std::collections::VecDeque;

use lxmf_core::constants::*;
use rns_core::msgpack::{self, Value};

use crate::router::now_timestamp;

/// An LXMF propagation peer.
///
/// Tracks synchronization state, message handling queues, peering key,
/// and statistics for a remote propagation node.
pub struct LxmPeer {
    pub destination_hash: [u8; 16],

    // State
    pub state: PeerState,
    pub alive: bool,
    pub last_heard: f64,

    // Sync config
    pub sync_strategy: SyncStrategy,
    pub peering_timebase: f64,
    pub next_sync_attempt: f64,
    pub last_sync_attempt: f64,
    pub sync_backoff: f64,

    // Peering key: [key_bytes, value]
    pub peering_key: Option<(Vec<u8>, u32)>,
    pub peering_cost: Option<u8>,
    pub metadata: Option<Vec<(Value, Value)>>,

    // Transfer rates
    pub link_establishment_rate: f64,
    pub sync_transfer_rate: f64,

    // Propagation node limits
    pub propagation_transfer_limit: Option<f64>,
    pub propagation_sync_limit: Option<u64>,
    pub propagation_stamp_cost: Option<u8>,
    pub propagation_stamp_cost_flexibility: Option<u8>,

    // Transfer tracking
    pub currently_transferring_messages: Option<Vec<[u8; 32]>>,
    pub current_sync_transfer_started: f64,
    pub link_id: Option<[u8; 16]>,
    pub last_offer: Vec<[u8; 32]>,

    // Message queues
    pub handled_ids: Vec<[u8; 32]>,
    pub unhandled_ids: Vec<[u8; 32]>,
    pub handled_messages_queue: VecDeque<[u8; 32]>,
    pub unhandled_messages_queue: VecDeque<[u8; 32]>,

    // Statistics
    pub offered: u64,
    pub outgoing: u64,
    pub incoming: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl LxmPeer {
    pub fn new(destination_hash: [u8; 16]) -> Self {
        Self {
            destination_hash,
            state: PeerState::Idle,
            alive: false,
            last_heard: 0.0,
            sync_strategy: DEFAULT_SYNC_STRATEGY,
            peering_timebase: 0.0,
            next_sync_attempt: 0.0,
            last_sync_attempt: 0.0,
            sync_backoff: 0.0,
            peering_key: None,
            peering_cost: None,
            metadata: None,
            link_establishment_rate: 0.0,
            sync_transfer_rate: 0.0,
            propagation_transfer_limit: None,
            propagation_sync_limit: None,
            propagation_stamp_cost: None,
            propagation_stamp_cost_flexibility: None,
            currently_transferring_messages: None,
            current_sync_transfer_started: 0.0,
            link_id: None,
            last_offer: Vec::new(),
            handled_ids: Vec::new(),
            unhandled_ids: Vec::new(),
            handled_messages_queue: VecDeque::new(),
            unhandled_messages_queue: VecDeque::new(),
            offered: 0,
            outgoing: 0,
            incoming: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    /// Check if the peering key is ready (sufficient value for peering cost).
    pub fn peering_key_ready(&self) -> bool {
        let cost = match self.peering_cost {
            Some(c) => c,
            None => return false,
        };
        match &self.peering_key {
            Some((_, value)) => {
                if *value >= cost as u32 {
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    /// Get the peering key value, if available.
    pub fn peering_key_value(&self) -> Option<u32> {
        self.peering_key.as_ref().map(|(_, v)| *v)
    }

    /// Check if sync prerequisites are met.
    pub fn sync_checks(&self) -> (bool, SyncPostponeReason) {
        let now = now_timestamp();
        let sync_time_reached = now > self.next_sync_attempt;
        let stamp_costs_known = self.propagation_stamp_cost.is_some()
            && self.propagation_stamp_cost_flexibility.is_some()
            && self.peering_cost.is_some();
        let peering_key_ready = self.peering_key_ready();

        if !sync_time_reached {
            return (false, SyncPostponeReason::BackoffActive);
        }
        if !stamp_costs_known {
            return (false, SyncPostponeReason::StampCostsUnknown);
        }
        if !peering_key_ready {
            return (false, SyncPostponeReason::PeeringKeyNotReady);
        }

        (true, SyncPostponeReason::None)
    }

    /// Apply sync backoff after a failed attempt.
    pub fn apply_backoff(&mut self) {
        let now = now_timestamp();
        self.sync_backoff += SYNC_BACKOFF_STEP as f64;
        self.next_sync_attempt = now + self.sync_backoff;
    }

    /// Reset backoff on successful sync.
    pub fn reset_backoff(&mut self) {
        self.sync_backoff = 0.0;
    }

    /// Called when link is established.
    pub fn handle_link_established(&mut self, link_id: [u8; 16], rtt: f64) {
        self.link_id = Some(link_id);
        if rtt > 0.0 {
            self.link_establishment_rate = rtt;
        }
        self.state = PeerState::LinkReady;
        self.next_sync_attempt = 0.0;
        self.alive = true;
        let now = now_timestamp();
        self.last_heard = now;
        self.reset_backoff();
    }

    /// Called when link is closed.
    pub fn handle_link_closed(&mut self) {
        self.link_id = None;
        self.state = PeerState::Idle;
    }

    /// Build the offer data to send to the peer.
    ///
    /// Returns the msgpack-packed offer and the list of offered transient IDs.
    /// The caller should filter `unhandled_ids` against propagation entries
    /// and stamp costs before calling this.
    pub fn build_offer(
        &mut self,
        available_messages: &[OfferEntry],
    ) -> Option<Vec<u8>> {
        let peering_key = match &self.peering_key {
            Some((key, _)) => key.clone(),
            None => return None,
        };

        let min_accepted_cost = self
            .propagation_stamp_cost
            .unwrap_or(0)
            .saturating_sub(self.propagation_stamp_cost_flexibility.unwrap_or(0));

        let transfer_limit_bytes = self
            .propagation_transfer_limit
            .map(|l| (l * 1000.0) as usize)
            .unwrap_or(usize::MAX);
        let sync_limit_bytes = self
            .propagation_sync_limit
            .map(|l| (l * 1000) as usize)
            .unwrap_or(usize::MAX);

        // Filter and sort by weight (ascending = lowest weight first)
        let mut entries: Vec<&OfferEntry> = available_messages
            .iter()
            .filter(|e| e.stamp_value >= min_accepted_cost as u32)
            .filter(|e| e.size <= transfer_limit_bytes)
            .collect();
        entries.sort_by(|a, b| a.weight.partial_cmp(&b.weight).unwrap_or(std::cmp::Ordering::Equal));

        // Accumulate up to sync limit
        let per_message_overhead = 16usize;
        let structure_overhead = 24usize;
        let mut cumulative_size = structure_overhead;
        let mut offer_ids = Vec::new();

        for entry in entries {
            let next_size = cumulative_size + entry.size + per_message_overhead;
            if next_size >= sync_limit_bytes {
                break;
            }
            cumulative_size = next_size;
            offer_ids.push(entry.transient_id);
        }

        self.last_offer = offer_ids.clone();

        let offer_id_values: Vec<Value> = offer_ids
            .iter()
            .map(|id| Value::Bin(id.to_vec()))
            .collect();

        let offer = Value::Array(vec![
            Value::Bin(peering_key),
            Value::Array(offer_id_values),
        ]);

        self.state = PeerState::RequestSent;
        Some(msgpack::pack(&offer))
    }

    /// Process the response from an offer request.
    ///
    /// Returns a `SyncAction` indicating what the caller should do next.
    pub fn handle_offer_response(&mut self, response_data: &[u8]) -> SyncAction {
        self.state = PeerState::ResponseReceived;

        let response = match msgpack::unpack_exact(response_data) {
            Ok(v) => v,
            Err(_) => {
                // Try to parse as error code
                if response_data.len() == 1 {
                    return self.handle_error_response(response_data[0]);
                }
                self.state = PeerState::Idle;
                return SyncAction::TeardownLink;
            }
        };

        // Check for error codes (uint)
        if let Some(code) = response.as_uint() {
            return self.handle_error_response(code as u8);
        }

        // False = peer has all messages
        if let Some(false) = response.as_bool() {
            // Mark all offered messages as handled
            let offer = self.last_offer.clone();
            for id in &offer {
                self.mark_handled(*id);
            }
            self.state = PeerState::Idle;
            return SyncAction::TeardownLink;
        }

        // True = peer wants all messages
        if let Some(true) = response.as_bool() {
            let wanted: Vec<[u8; 32]> = self.last_offer.clone();
            self.currently_transferring_messages = Some(wanted.clone());
            self.current_sync_transfer_started = now_timestamp();
            self.state = PeerState::ResourceTransferring;
            return SyncAction::TransferMessages(wanted);
        }

        // List = peer wants specific messages
        if let Some(arr) = response.as_array() {
            let mut wanted = Vec::new();
            for item in arr {
                if let Some(id_bytes) = item.as_bin() {
                    if id_bytes.len() == 32 {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(id_bytes);
                        wanted.push(id);
                    }
                }
            }

            // Mark unwanted messages as handled
            let offer = self.last_offer.clone();
            for id in &offer {
                if !wanted.contains(id) {
                    self.mark_handled(*id);
                }
            }

            if wanted.is_empty() {
                self.state = PeerState::Idle;
                return SyncAction::TeardownLink;
            }

            self.currently_transferring_messages = Some(wanted.clone());
            self.current_sync_transfer_started = now_timestamp();
            self.state = PeerState::ResourceTransferring;
            return SyncAction::TransferMessages(wanted);
        }

        self.state = PeerState::Idle;
        SyncAction::TeardownLink
    }

    fn handle_error_response(&mut self, code: u8) -> SyncAction {
        self.state = PeerState::Idle;
        match PeerError::from_u8(code) {
            Some(PeerError::NoIdentity) => SyncAction::IdentifyAndRetry,
            Some(PeerError::NoAccess) => SyncAction::Unpeer,
            Some(PeerError::Throttled) => {
                self.next_sync_attempt = now_timestamp() + PN_STAMP_THROTTLE as f64;
                SyncAction::TeardownLink
            }
            _ => SyncAction::TeardownLink,
        }
    }

    /// Called when resource transfer completes successfully.
    pub fn handle_resource_completed(&mut self, transfer_size_bytes: usize) {
        let now = now_timestamp();
        let duration = now - self.current_sync_transfer_started;

        if let Some(ref transferred) = self.currently_transferring_messages {
            let count = transferred.len() as u64;
            for id in transferred.clone() {
                self.mark_handled(id);
            }
            self.offered += count;
            self.outgoing += count;
            self.tx_bytes += transfer_size_bytes as u64;
        }

        if duration > 0.0 {
            self.sync_transfer_rate = (transfer_size_bytes as f64 * 8.0) / duration;
        }

        self.currently_transferring_messages = None;
        self.alive = true;
        self.last_heard = now;
        self.state = PeerState::Idle;
    }

    /// Called when resource transfer fails.
    pub fn handle_resource_failed(&mut self) {
        self.currently_transferring_messages = None;
        self.state = PeerState::Idle;
    }

    /// Check if this peer should continue syncing (PERSISTENT strategy with remaining messages).
    pub fn should_continue_sync(&self) -> bool {
        self.sync_strategy == SyncStrategy::Persistent && !self.unhandled_ids.is_empty()
    }

    /// Whether the peer has queued items to process.
    pub fn has_queued_items(&self) -> bool {
        !self.handled_messages_queue.is_empty() || !self.unhandled_messages_queue.is_empty()
    }

    /// Process message queues: move items from queues to handled/unhandled lists.
    pub fn process_queues(&mut self) {
        // Process handled queue
        while let Some(tid) = self.handled_messages_queue.pop_back() {
            self.mark_handled(tid);
        }

        // Process unhandled queue
        while let Some(tid) = self.unhandled_messages_queue.pop_back() {
            if !self.handled_ids.contains(&tid) && !self.unhandled_ids.contains(&tid) {
                self.unhandled_ids.push(tid);
            }
        }
    }

    /// Queue a message as unhandled for this peer.
    pub fn queue_unhandled_message(&mut self, transient_id: [u8; 32]) {
        self.unhandled_messages_queue.push_back(transient_id);
    }

    /// Queue a message as handled for this peer.
    pub fn queue_handled_message(&mut self, transient_id: [u8; 32]) {
        self.handled_messages_queue.push_back(transient_id);
    }

    /// Mark a message as handled (move from unhandled to handled).
    fn mark_handled(&mut self, transient_id: [u8; 32]) {
        if !self.handled_ids.contains(&transient_id) {
            self.handled_ids.push(transient_id);
        }
        self.unhandled_ids.retain(|id| *id != transient_id);
    }

    /// Remove a transient ID from both lists (e.g., when message is purged).
    pub fn purge_message(&mut self, transient_id: &[u8; 32]) {
        self.handled_ids.retain(|id| id != transient_id);
        self.unhandled_ids.retain(|id| id != transient_id);
    }

    /// Check if this peer is unreachable (not heard from in MAX_UNREACHABLE).
    pub fn is_unreachable(&self) -> bool {
        let now = now_timestamp();
        self.last_heard > 0.0 && (now - self.last_heard) > MAX_UNREACHABLE as f64
    }

    /// Acceptance rate: proportion of offered messages that were accepted.
    pub fn acceptance_rate(&self) -> f64 {
        if self.offered == 0 {
            return 1.0; // Assume good for new peers
        }
        self.outgoing as f64 / self.offered as f64
    }

    // ================================================================
    // Serialization (matching Python msgpack format for interop)
    // ================================================================

    /// Serialize to bytes (msgpack dict matching Python's field names).
    pub fn to_bytes(&self) -> Vec<u8> {
        let peering_key_val = match &self.peering_key {
            Some((key, value)) => {
                Value::Array(vec![Value::Bin(key.clone()), Value::UInt(*value as u64)])
            }
            None => Value::Nil,
        };

        let metadata_val = match &self.metadata {
            Some(m) => Value::Map(m.clone()),
            None => Value::Nil,
        };

        let handled_id_vals: Vec<Value> = self
            .handled_ids
            .iter()
            .map(|id| Value::Bin(id.to_vec()))
            .collect();
        let unhandled_id_vals: Vec<Value> = self
            .unhandled_ids
            .iter()
            .map(|id| Value::Bin(id.to_vec()))
            .collect();

        let dict = Value::Map(vec![
            (
                Value::Str("peering_timebase".to_string()),
                Value::Float(self.peering_timebase),
            ),
            (
                Value::Str("alive".to_string()),
                Value::Bool(self.alive),
            ),
            (
                Value::Str("metadata".to_string()),
                metadata_val,
            ),
            (
                Value::Str("last_heard".to_string()),
                Value::Float(self.last_heard),
            ),
            (
                Value::Str("sync_strategy".to_string()),
                Value::UInt(self.sync_strategy as u64),
            ),
            (
                Value::Str("peering_key".to_string()),
                peering_key_val,
            ),
            (
                Value::Str("destination_hash".to_string()),
                Value::Bin(self.destination_hash.to_vec()),
            ),
            (
                Value::Str("link_establishment_rate".to_string()),
                Value::Float(self.link_establishment_rate),
            ),
            (
                Value::Str("sync_transfer_rate".to_string()),
                Value::Float(self.sync_transfer_rate),
            ),
            (
                Value::Str("propagation_transfer_limit".to_string()),
                opt_float_val(self.propagation_transfer_limit),
            ),
            (
                Value::Str("propagation_sync_limit".to_string()),
                opt_uint_val(self.propagation_sync_limit),
            ),
            (
                Value::Str("propagation_stamp_cost".to_string()),
                opt_u8_val(self.propagation_stamp_cost),
            ),
            (
                Value::Str("propagation_stamp_cost_flexibility".to_string()),
                opt_u8_val(self.propagation_stamp_cost_flexibility),
            ),
            (
                Value::Str("peering_cost".to_string()),
                opt_u8_val(self.peering_cost),
            ),
            (
                Value::Str("last_sync_attempt".to_string()),
                Value::Float(self.last_sync_attempt),
            ),
            (
                Value::Str("offered".to_string()),
                Value::UInt(self.offered),
            ),
            (
                Value::Str("outgoing".to_string()),
                Value::UInt(self.outgoing),
            ),
            (
                Value::Str("incoming".to_string()),
                Value::UInt(self.incoming),
            ),
            (
                Value::Str("rx_bytes".to_string()),
                Value::UInt(self.rx_bytes),
            ),
            (
                Value::Str("tx_bytes".to_string()),
                Value::UInt(self.tx_bytes),
            ),
            (
                Value::Str("handled_ids".to_string()),
                Value::Array(handled_id_vals),
            ),
            (
                Value::Str("unhandled_ids".to_string()),
                Value::Array(unhandled_id_vals),
            ),
        ]);

        msgpack::pack(&dict)
    }

    /// Deserialize from bytes (msgpack dict matching Python's format).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let val = msgpack::unpack_exact(data).ok()?;
        let map = val.as_map()?;

        let dest_hash_bytes = map_get_bin(map, "destination_hash")?;
        if dest_hash_bytes.len() != 16 {
            return None;
        }
        let mut destination_hash = [0u8; 16];
        destination_hash.copy_from_slice(dest_hash_bytes);

        let mut peer = Self::new(destination_hash);

        peer.peering_timebase = map_get_float(map, "peering_timebase").unwrap_or(0.0);
        peer.alive = map_get_bool(map, "alive").unwrap_or(false);
        peer.last_heard = map_get_float(map, "last_heard").unwrap_or(0.0);

        // Metadata
        if let Some(meta_val) = map_get(map, "metadata") {
            if let Some(m) = meta_val.as_map() {
                peer.metadata = Some(m.to_vec());
            }
        }

        // Sync strategy
        if let Some(s) = map_get_uint(map, "sync_strategy") {
            peer.sync_strategy =
                SyncStrategy::from_u8(s as u8).unwrap_or(DEFAULT_SYNC_STRATEGY);
        }

        // Peering key: [key_bytes, value]
        if let Some(pk_val) = map_get(map, "peering_key") {
            if let Some(arr) = pk_val.as_array() {
                if arr.len() >= 2 {
                    if let (Some(key_bytes), Some(value)) = (arr[0].as_bin(), arr[1].as_uint())
                    {
                        peer.peering_key = Some((key_bytes.to_vec(), value as u32));
                    }
                }
            }
        }

        // Rates
        peer.link_establishment_rate =
            map_get_float(map, "link_establishment_rate").unwrap_or(0.0);
        peer.sync_transfer_rate = map_get_float(map, "sync_transfer_rate").unwrap_or(0.0);

        // Limits
        peer.propagation_transfer_limit = map_get_float(map, "propagation_transfer_limit");
        peer.propagation_sync_limit = map_get_uint(map, "propagation_sync_limit");
        peer.propagation_stamp_cost =
            map_get_uint(map, "propagation_stamp_cost").map(|v| v as u8);
        peer.propagation_stamp_cost_flexibility =
            map_get_uint(map, "propagation_stamp_cost_flexibility").map(|v| v as u8);
        peer.peering_cost = map_get_uint(map, "peering_cost").map(|v| v as u8);

        // Last sync
        peer.last_sync_attempt = map_get_float(map, "last_sync_attempt").unwrap_or(0.0);

        // Stats
        peer.offered = map_get_uint(map, "offered").unwrap_or(0);
        peer.outgoing = map_get_uint(map, "outgoing").unwrap_or(0);
        peer.incoming = map_get_uint(map, "incoming").unwrap_or(0);
        peer.rx_bytes = map_get_uint(map, "rx_bytes").unwrap_or(0);
        peer.tx_bytes = map_get_uint(map, "tx_bytes").unwrap_or(0);

        // Message IDs
        peer.handled_ids = load_id_list(map, "handled_ids");
        peer.unhandled_ids = load_id_list(map, "unhandled_ids");

        Some(peer)
    }
}

/// Entry for building an offer.
pub struct OfferEntry {
    pub transient_id: [u8; 32],
    pub weight: f64,
    pub size: usize,
    pub stamp_value: u32,
}

/// Reason why sync was postponed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPostponeReason {
    None,
    BackoffActive,
    StampCostsUnknown,
    PeeringKeyNotReady,
}

/// Action the router should take after handling an offer response.
#[derive(Debug)]
pub enum SyncAction {
    /// Send the given messages to the peer.
    TransferMessages(Vec<[u8; 32]>),
    /// Re-identify on the link and retry sync.
    IdentifyAndRetry,
    /// Remove this peer (access denied).
    Unpeer,
    /// Close the link and return to idle.
    TeardownLink,
}

/// Select peers for sync.
///
/// Returns indices of peers to sync, prioritizing fastest peers
/// with a random pool for discovery.
pub fn select_peers_for_sync(
    peers: &[LxmPeer],
    fastest_n: usize,
) -> Vec<usize> {
    let candidates: Vec<(usize, &LxmPeer)> = peers
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            p.state == PeerState::Idle
                && !p.unhandled_ids.is_empty()
                && !p.is_unreachable()
        })
        .collect();

    if candidates.is_empty() {
        return Vec::new();
    }

    // Partition into known-speed and unknown-speed
    let mut known: Vec<(usize, &LxmPeer)> = Vec::new();
    let mut unknown: Vec<(usize, &LxmPeer)> = Vec::new();

    for (idx, peer) in &candidates {
        if peer.sync_transfer_rate > 0.0 {
            known.push((*idx, *peer));
        } else {
            unknown.push((*idx, *peer));
        }
    }

    // Sort known by transfer rate (highest first)
    known.sort_by(|a, b| {
        b.1.sync_transfer_rate
            .partial_cmp(&a.1.sync_transfer_rate)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut selected = Vec::new();

    // Take fastest N from known
    for (idx, _) in known.iter().take(fastest_n) {
        selected.push(*idx);
    }

    // Add one from unknown pool if available
    if let Some((idx, _)) = unknown.first() {
        selected.push(*idx);
    }

    selected
}

/// Calculate peer rotation: identify peers to drop.
///
/// Returns indices of peers that should be removed.
pub fn peers_to_drop(
    peers: &[LxmPeer],
    max_peers: usize,
) -> Vec<usize> {
    if peers.len() <= max_peers {
        return Vec::new();
    }

    let headroom = (max_peers * ROTATION_HEADROOM_PCT) / 100;
    let target = max_peers.saturating_sub(headroom);

    if peers.len() <= target {
        return Vec::new();
    }

    let to_drop = peers.len() - target;

    // Build drop candidates: unreachable + low acceptance rate
    let mut candidates: Vec<(usize, f64)> = peers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.is_unreachable() || p.acceptance_rate() < ROTATION_AR_MAX)
        .map(|(idx, p)| {
            // Score: lower is worse (more droppable)
            let score = if p.is_unreachable() {
                0.0
            } else {
                p.acceptance_rate()
            };
            (idx, score)
        })
        .collect();

    // Sort by score ascending (worst first)
    candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    candidates
        .iter()
        .take(to_drop)
        .map(|(idx, _)| *idx)
        .collect()
}

// ============================================================
// Msgpack helper functions for map access
// ============================================================

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

fn map_get_float(map: &[(Value, Value)], key: &str) -> Option<f64> {
    map_get(map, key).and_then(|v| v.as_number())
}

fn map_get_uint(map: &[(Value, Value)], key: &str) -> Option<u64> {
    map_get(map, key).and_then(|v| v.as_uint())
}

fn map_get_bool(map: &[(Value, Value)], key: &str) -> Option<bool> {
    map_get(map, key).and_then(|v| v.as_bool())
}

fn map_get_bin<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a [u8]> {
    map_get(map, key).and_then(|v| v.as_bin())
}

fn load_id_list(map: &[(Value, Value)], key: &str) -> Vec<[u8; 32]> {
    let mut ids = Vec::new();
    if let Some(val) = map_get(map, key) {
        if let Some(arr) = val.as_array() {
            for item in arr {
                if let Some(bytes) = item.as_bin() {
                    if bytes.len() == 32 {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(bytes);
                        ids.push(id);
                    }
                }
            }
        }
    }
    ids
}

fn opt_float_val(v: Option<f64>) -> Value {
    match v {
        Some(f) => Value::Float(f),
        None => Value::Nil,
    }
}

fn opt_uint_val(v: Option<u64>) -> Value {
    match v {
        Some(n) => Value::UInt(n),
        None => Value::Nil,
    }
}

fn opt_u8_val(v: Option<u8>) -> Value {
    match v {
        Some(n) => Value::UInt(n as u64),
        None => Value::Nil,
    }
}
