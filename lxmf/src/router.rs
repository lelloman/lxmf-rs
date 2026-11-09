use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use lxmf_core::constants::*;
use lxmf_core::stamp::{min_accepted_cost, StampCost};
use lxmf_core::{announce, message};
use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash, ProofStrategy};
use rns_crypto::identity::Identity;

use rns_net::destination::{AnnouncedIdentity, Destination};
use rns_net::driver::Callbacks;
use rns_net::event::{QueryRequest, QueryResponse};
use rns_net::node::RnsNode;

use crate::handlers::{
    decide_propagation_action, parse_propagation_announce, PropagationAnnounceResult,
};
use crate::outbound::{
    destination_round_trip, retry_jitter, schedule_attempt, DeliveryTracking, LinkCreation,
    MediumInfo, OutboundNetwork,
};
use crate::peer::{LxmPeer, OfferEntry, SyncAction, SyncPostponeReason};
use crate::propagation::{PropagationEntry, PropagationStore};
use crate::storage::{self, StoragePaths};

/// A background peering key generation result: the peer and its key, if
/// generation succeeded.
type PeeringKeyResult = ([u8; 16], Option<(Vec<u8>, lxmf_core::stamp::StampValue)>);

/// The outcome of a background stamp job for an outbound message.
type StampJobResult = (
    [u8; 32],
    Result<crate::stamper::StampedMessage, crate::stamper::StampJobError>,
);

/// Callback function types for the router.
pub type DeliveryCallback = Box<dyn Fn(&LxmDelivery) + Send>;
pub type ProgressCallback = Box<dyn Fn(&[u8; 32], f64) + Send>;
/// Per-message callback types stored on an [`OutboundMessage`].
pub type OutboundCallback = Box<dyn Fn(&OutboundMessage) + Send>;
pub type OutboundProgressCallback = Box<dyn Fn(&OutboundMessage, f64) + Send>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSyncTransportError {
    SendFailed,
}

pub trait PeerSyncTransport {
    fn send_peer_offer(
        &self,
        link_id: [u8; 16],
        offer: &[u8],
    ) -> Result<(), PeerSyncTransportError>;
    fn identify_peer_link(
        &self,
        link_id: [u8; 16],
        identity_prv_key: [u8; 64],
    ) -> Result<(), PeerSyncTransportError>;
    fn send_peer_resource(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
    ) -> Result<(), PeerSyncTransportError>;
    fn teardown_peer_link(&self, link_id: [u8; 16]) -> Result<(), PeerSyncTransportError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundResourceControlError {
    CancelFailed,
}

pub trait InboundResourceControl {
    fn cancel_inbound_resource(
        &self,
        link_id: [u8; 16],
        resource_hash: &[u8],
    ) -> Result<(), InboundResourceControlError>;
}

impl InboundResourceControl for RnsNode {
    fn cancel_inbound_resource(
        &self,
        link_id: [u8; 16],
        resource_hash: &[u8],
    ) -> Result<(), InboundResourceControlError> {
        // Rejecting by hash also cancels a resource that has already been
        // accepted, while leaving the containing link and other transfers up.
        self.accept_resource(link_id, resource_hash.to_vec(), false)
            .map_err(|_| InboundResourceControlError::CancelFailed)
    }
}

impl PeerSyncTransport for RnsNode {
    fn send_peer_offer(
        &self,
        link_id: [u8; 16],
        offer: &[u8],
    ) -> Result<(), PeerSyncTransportError> {
        self.send_request(link_id, OFFER_REQUEST_PATH, offer)
            .map_err(|_| PeerSyncTransportError::SendFailed)
    }

    fn identify_peer_link(
        &self,
        link_id: [u8; 16],
        identity_prv_key: [u8; 64],
    ) -> Result<(), PeerSyncTransportError> {
        self.identify_on_link(link_id, identity_prv_key)
            .map_err(|_| PeerSyncTransportError::SendFailed)
    }

    fn send_peer_resource(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
    ) -> Result<(), PeerSyncTransportError> {
        self.send_resource(link_id, data, None)
            .map_err(|_| PeerSyncTransportError::SendFailed)
    }

    fn teardown_peer_link(&self, link_id: [u8; 16]) -> Result<(), PeerSyncTransportError> {
        self.teardown_link(link_id)
            .map_err(|_| PeerSyncTransportError::SendFailed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOfferResponseResult {
    OfferSent,
    TransferStarted(usize),
    RetriedAfterIdentify,
    Unpeered,
    Teardown,
    MissingPeer,
    MissingLink,
    EmptyOffer,
    TransportError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundOfferState {
    Accepted,
    Transferring,
    Validating,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundResource {
    pub resource_hash: Vec<u8>,
    pub link_id: [u8; 16],
    pub received: u64,
    pub total: u64,
}

impl InboundResource {
    pub fn progress(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.received.min(self.total) as f64 / self.total as f64
        }
    }
}

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
    pub stamp_cost: Option<StampCost>,
    pub propagation_packed: Option<Vec<u8>>,
    pub propagation_stamp: Option<Vec<u8>>,
    pub transient_id: Option<[u8; 32]>,
    pub delivery_callback: Option<OutboundCallback>,
    pub failed_callback: Option<OutboundCallback>,
    pub progress_callback: Option<OutboundProgressCallback>,
    /// Tracking link_id for direct delivery
    pub link_id: Option<[u8; 16]>,
    /// Tracking packet_hash for opportunistic delivery
    pub packet_hash: Option<[u8; 32]>,
    /// Retry timing and slow-path bookkeeping used by outbound processing.
    pub tracking: DeliveryTracking,
}

impl OutboundMessage {
    /// A message queued for delivery with no callbacks or tracking state.
    pub fn new(
        destination_hash: [u8; DESTINATION_LENGTH],
        source_hash: [u8; DESTINATION_LENGTH],
        packed: Vec<u8>,
        message_hash: [u8; 32],
        method: DeliveryMethod,
    ) -> Self {
        Self {
            destination_hash,
            source_hash,
            packed,
            message_hash,
            method,
            state: MessageState::Outbound,
            representation: Representation::Unknown,
            attempts: 0,
            last_attempt: 0.0,
            stamp: None,
            stamp_cost: None,
            propagation_packed: None,
            propagation_stamp: None,
            transient_id: None,
            delivery_callback: None,
            failed_callback: None,
            progress_callback: None,
            link_id: None,
            packet_hash: None,
            tracking: DeliveryTracking::default(),
        }
    }

    /// Attempt limit for this message (`attempt_limit`).
    pub fn attempt_limit(&self) -> u32 {
        self.tracking
            .max_delivery_attempts
            .unwrap_or(MAX_DELIVERY_ATTEMPTS)
    }

    fn is_concluded(&self) -> bool {
        matches!(
            self.state,
            MessageState::Delivered
                | MessageState::Failed
                | MessageState::Cancelled
                | MessageState::Rejected
        ) || (self.method == DeliveryMethod::Propagated && self.state == MessageState::Sent)
    }

    /// Whether this message is on a slow path and still awaiting conclusion
    /// (`slow_path_in_flight`).
    fn slow_path_in_flight(&self) -> bool {
        if !self.tracking.sent_on_slow_path {
            return false;
        }
        if self.method == DeliveryMethod::Opportunistic {
            self.state == MessageState::Sent
        } else {
            self.state == MessageState::Sending
        }
    }
}

/// Errors returned while accepting an outbound message into the router queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundError {
    MissingOutboundPropagationNode,
}

impl core::fmt::Display for OutboundError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingOutboundPropagationNode => f.write_str(
                "attempt to send propagated message with no outbound propagation node configured",
            ),
        }
    }
}

impl std::error::Error for OutboundError {}

/// Configuration for the LXM Router.
pub struct RouterConfig {
    pub storagepath: PathBuf,
    pub autopeer: bool,
    pub autopeer_maxdepth: u8,
    pub propagation_limit: u32,
    pub delivery_limit: f64,
    pub sync_limit: u32,
    pub enforce_ratchets: bool,
    pub enforce_stamps: bool,
    pub static_peers: Vec<[u8; 16]>,
    pub max_peers: usize,
    pub from_static_only: bool,
    pub sync_strategy: SyncStrategy,
    pub propagation_cost: StampCost,
    pub propagation_cost_flexibility: StampCost,
    pub peering_cost: StampCost,
    pub max_peering_cost: StampCost,
    pub max_inbound_syncs: usize,
    pub sequential_validation: bool,
    pub static_sequential: bool,
    pub name: Option<String>,
    /// How long a peer delivering messages with invalid stamps is throttled,
    /// in seconds (`pn_stamp_throttle`).
    pub pn_stamp_throttle: f64,
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
            max_inbound_syncs: MAX_INBOUND_SYNCS,
            sequential_validation: SEQUENTIAL_VALIDATION,
            static_sequential: STATIC_SEQUENTIAL,
            name: None,
            pn_stamp_throttle: PN_STAMP_THROTTLE as f64,
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
    pub outbound_propagation_node: Option<[u8; 16]>,
    pub delivery_dest_hash: Option<[u8; 16]>,
    pub control_dest_hash: Option<[u8; 16]>,

    // Message queues
    pub outbound: Vec<OutboundMessage>,
    pub pending_inbound: VecDeque<Vec<u8>>,

    // Link tracking
    pub direct_links: HashMap<[u8; 16], [u8; 16]>, // dest_hash -> link_id
    pub pending_direct_links: HashMap<[u8; 16], [u8; 16]>, // dest_hash -> link_id (being established)
    pending_direct_link_creations: HashMap<[u8; 16], f64>, // dest_hash -> requested_at
    direct_link_tx: mpsc::Sender<LinkCreation>,
    direct_link_rx: mpsc::Receiver<LinkCreation>,
    pub backchannel_links: HashMap<[u8; 16], [u8; 16]>, // dest_hash -> link_id
    pub link_destinations: HashMap<[u8; 16], [u8; 16]>, // link_id -> dest_hash
    /// Identity hashes remotes identified as on inbound links.
    pub link_remote_identities: HashMap<[u8; 16], [u8; 16]>, // link_id -> identity_hash
    pub active_propagation_links: Vec<[u8; 16]>,
    pub propagation_link: Option<[u8; 16]>,

    // Caches
    pub locally_delivered_transient_ids: HashMap<[u8; 32], f64>,
    pub locally_processed_transient_ids: HashMap<[u8; 32], f64>,
    pub outbound_stamp_costs: HashMap<[u8; 16], (f64, StampCost)>,
    stamp_costs_dirty: bool,
    path_request_times: HashMap<[u8; 16], f64>,
    slow_path_cache: HashMap<[u8; 16], (bool, f64)>,
    peer_path_requests: HashMap<[u8; 16], f64>,
    peering_keys_generating: HashSet<[u8; 16]>,
    /// Latest valid propagation node announces (info, hops), used to
    /// auto-peer with nodes that sync to us before we peered with them.
    pn_announces: HashMap<[u8; 16], (crate::handlers::PropagationPeerInfo, u8)>,
    /// Propagation stamp costs announced by propagation nodes.
    pn_costs: HashMap<[u8; 16], StampCost>,
    stamp_job_tx: mpsc::Sender<StampJobResult>,
    stamp_job_rx: mpsc::Receiver<StampJobResult>,
    /// The message whose stamps are being generated, and its cancel flag.
    stamp_job: Option<([u8; 32], Arc<std::sync::atomic::AtomicBool>)>,
    peering_key_tx: mpsc::Sender<PeeringKeyResult>,
    peering_key_rx: mpsc::Receiver<PeeringKeyResult>,
    /// Validation outcome of the last client propagation packet, consumed by
    /// the proof request that follows it on the same driver pass.
    propagation_packet_proof: Option<bool>,

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
    pub propagation_store: PropagationStore,
    peer_sync_response_links: HashMap<[u8; 16], [u8; 16]>,
    peer_sync_transfer_sizes: HashMap<[u8; 16], usize>,
    pub accepted_offer_links: HashMap<[u8; 16], InboundOfferState>,
    pub inbound_offer_peers: HashMap<[u8; 16], [u8; 16]>,
    pub validated_peer_links: HashSet<[u8; 16]>,
    pub validating_pn_stamps_from: HashMap<[u8; 16], f64>,
    pub throttled_peers: HashMap<[u8; 16], f64>,

    // Propagation transfer state (client-side)
    pub propagation_transfer_state: PropagationTransferState,
    pub propagation_transfer_progress: f64,
    pub propagation_transfer_size: Option<u64>,
    pub propagation_transfer_max_messages: Option<u32>,

    // Active inbound direct-delivery resources
    pub incoming_delivery_resources: HashMap<Vec<u8>, InboundResource>,

    // Identity cache (dest_hash → public_key) populated from announces.
    // Used for signature verification in lxmf_delivery to avoid synchronous
    // RPC calls to the driver thread (which would deadlock when called from
    // a driver callback like on_local_delivery).
    pub identity_cache: HashMap<[u8; 16], [u8; 64]>,
    pub identity_hash_cache: HashMap<[u8; 16], [u8; 16]>,
    pub compression_cache: HashMap<[u8; 16], bool>,
    pub blackholed_identities: HashSet<[u8; 16]>,

    // Node reference (set after start)
    node: Option<Arc<RnsNode>>,

    // Display name for delivery announces
    pub display_name: Option<String>,
    pub delivery_stamp_cost: Option<StampCost>,
}

impl LxmRouter {
    /// Create a new LXM Router.
    pub fn new(identity: Identity, config: RouterConfig) -> Self {
        let paths = StoragePaths::new(&config.storagepath);
        let _ = paths.ensure_dirs();

        // Compute propagation destination hash
        let propagation_dest_hash = compute_dest_hash(APP_NAME, &["propagation"], identity.hash());

        // Load persisted state
        let locally_delivered_transient_ids = storage::load_transient_ids(&paths.local_deliveries);
        let locally_processed_transient_ids = storage::load_transient_ids(&paths.locally_processed);
        let outbound_stamp_costs = storage::load_stamp_costs(&paths.outbound_stamp_costs);
        let mut propagation_store =
            PropagationStore::new(paths.messagestore.clone(), config.propagation_limit);
        propagation_store.scan_messagestore();

        // Load peers from storage
        let mut peers = HashMap::new();
        for peer_val in storage::load_peers(&paths.peers) {
            let peer_bytes = msgpack::pack(&peer_val);
            if let Some(peer) = LxmPeer::from_bytes(&peer_bytes) {
                peers.insert(peer.destination_hash, peer);
            }
        }

        let (direct_link_tx, direct_link_rx) = mpsc::channel();
        let (peering_key_tx, peering_key_rx) = mpsc::channel();
        let (stamp_job_tx, stamp_job_rx) = mpsc::channel();

        Self {
            identity,
            propagation_dest_hash,
            outbound_propagation_node: None,
            delivery_dest_hash: None,
            control_dest_hash: None,
            outbound: Vec::new(),
            pending_inbound: VecDeque::new(),
            direct_links: HashMap::new(),
            pending_direct_links: HashMap::new(),
            pending_direct_link_creations: HashMap::new(),
            direct_link_tx,
            direct_link_rx,
            backchannel_links: HashMap::new(),
            link_destinations: HashMap::new(),
            link_remote_identities: HashMap::new(),
            active_propagation_links: Vec::new(),
            propagation_link: None,
            locally_delivered_transient_ids,
            locally_processed_transient_ids,
            outbound_stamp_costs,
            stamp_costs_dirty: false,
            path_request_times: HashMap::new(),
            slow_path_cache: HashMap::new(),
            peer_path_requests: HashMap::new(),
            peering_keys_generating: HashSet::new(),
            pn_announces: HashMap::new(),
            pn_costs: HashMap::new(),
            stamp_job_tx,
            stamp_job_rx,
            stamp_job: None,
            peering_key_tx,
            peering_key_rx,
            propagation_packet_proof: None,
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
            propagation_store,
            peer_sync_response_links: HashMap::new(),
            peer_sync_transfer_sizes: HashMap::new(),
            accepted_offer_links: HashMap::new(),
            inbound_offer_peers: HashMap::new(),
            validated_peer_links: HashSet::new(),
            validating_pn_stamps_from: HashMap::new(),
            throttled_peers: HashMap::new(),
            propagation_transfer_state: PropagationTransferState::Idle,
            propagation_transfer_progress: 0.0,
            propagation_transfer_size: None,
            propagation_transfer_max_messages: None,
            incoming_delivery_resources: HashMap::new(),
            identity_cache: HashMap::new(),
            identity_hash_cache: HashMap::new(),
            compression_cache: HashMap::new(),
            blackholed_identities: HashSet::new(),
            node: None,
            display_name: None,
            delivery_stamp_cost: None,
            config,
            paths,
        }
    }

    /// Set the RNS node reference. Called after starting the node.
    ///
    /// Also registers the destination types the router needs announces for
    /// (`REQUIRED_DESTINATION_TYPES`), so a shared instance filtering
    /// announces keeps forwarding them. Registration queries the driver, so it
    /// runs off the caller's thread, which usually holds the router lock.
    pub fn set_node(&mut self, node: Arc<RnsNode>) {
        let filter_node = node.clone();
        thread::spawn(move || {
            for destination_type in [ASPECT_DELIVERY, ASPECT_PROPAGATION] {
                if !filter_node.wants_destination_type(destination_type) {
                    log::debug!("Destination type {} was not registered", destination_type);
                }
            }
        });
        self.node = Some(node);
    }

    /// Register a destination for incoming links and packets, with the
    /// application deciding which packets are proven (`ProveApp`).
    fn register_inbound_destination(
        node: &RnsNode,
        identity: &Identity,
        aspects: &[&str],
        link_cost: Option<f64>,
    ) -> [u8; 16] {
        let dest = Destination::single_in(APP_NAME, aspects, IdentityHash(*identity.hash()))
            .set_proof_strategy(ProofStrategy::ProveApp);
        let dest_hash = dest.hash.0;
        let prv = identity.get_private_key().unwrap();
        let sig_pub = identity.get_public_key().unwrap();
        let _ = node.register_link_destination(
            dest_hash,
            prv[32..].try_into().unwrap(),
            sig_pub[32..].try_into().unwrap(),
            1, // AcceptAll
        );
        if let Some(cost) = link_cost {
            node.set_link_cost(dest_hash, cost);
        }
        let _ = node.register_destination_with_proof(&dest, Some(prv));
        dest_hash
    }

    pub fn register_propagation_request_handlers(
        node: &Arc<RnsNode>,
        router: Arc<Mutex<LxmRouter>>,
    ) -> Result<(), PeerSyncTransportError> {
        node.register_request_handler(OFFER_REQUEST_PATH, None, move |link_id, _, data, remote| {
            let Some((remote_identity_hash, _)) = remote else {
                return Some(vec![PeerError::NoIdentity as u8]);
            };
            let mut router = router.lock().unwrap();
            if !router.propagation_node || !router.active_propagation_links.contains(&link_id) {
                return Some(vec![PeerError::NoAccess as u8]);
            }
            Some(router.handle_inbound_offer(link_id, *remote_identity_hash, data))
        })
        .map_err(|_| PeerSyncTransportError::SendFailed)
    }

    /// Get a reference to the RNS node.
    pub fn node(&self) -> Option<&RnsNode> {
        self.node.as_deref()
    }

    /// Replace the cached transport-level blackhole list.
    pub fn set_blackholed_identities<I>(&mut self, identities: I)
    where
        I: IntoIterator<Item = [u8; 16]>,
    {
        self.blackholed_identities = identities.into_iter().collect();
    }

    /// Refresh the cached transport-level blackhole list from the RNS node.
    pub fn refresh_blackholed_identities(&mut self) -> bool {
        let Some(node) = &self.node else {
            return false;
        };

        match crate::outbound::bounded_query(node, QueryRequest::GetBlackholed) {
            Some(QueryResponse::Blackholed(entries)) => {
                self.blackholed_identities = entries
                    .into_iter()
                    .map(|entry| entry.identity_hash)
                    .collect();
                true
            }
            _ => false,
        }
    }

    fn source_identity_is_blackholed(&self, source_hash: &[u8; 16]) -> bool {
        self.identity_hash_cache
            .get(source_hash)
            .is_some_and(|identity_hash| self.blackholed_identities.contains(identity_hash))
    }

    /// Ensure a direct link exists to the given destination.
    ///
    /// If a link is already active or pending, this is a no-op and returns `true`.
    /// If a new link is successfully created, returns `true`.
    /// Returns `false` only on actual failure (no node, unknown identity, link
    /// creation error).
    pub fn ensure_direct_link(&mut self, dest_hash: [u8; 16]) -> bool {
        // Already active
        if self.direct_links.contains_key(&dest_hash) {
            return true;
        }
        // Already pending
        if self.pending_direct_links.contains_key(&dest_hash) {
            return true;
        }
        // Need a node to create links
        let node = match &self.node {
            Some(n) => n.clone(),
            None => return false,
        };
        // Need identity to get sig_pub
        let announced = match node.recall_identity(&DestHash(dest_hash)) {
            Ok(Some(info)) => info,
            _ => return false,
        };
        let sig_pub: [u8; 32] = announced.public_key[32..].try_into().unwrap();
        match node.create_link(dest_hash, sig_pub) {
            Ok(link_id) => {
                self.pending_direct_links.insert(dest_hash, link_id);
                true
            }
            Err(_) => {
                log::warn!("ensure_direct_link: failed to create link");
                false
            }
        }
    }

    /// Collect results of asynchronous link creations started by outbound
    /// processing. A created link is pending until `on_link_established`; a
    /// failed creation leaves the messages queued for their next attempt.
    fn drain_direct_link_results(&mut self) {
        while let Ok(result) = self.direct_link_rx.try_recv() {
            self.pending_direct_link_creations.remove(&result.dest_hash);
            if result.link_id.is_none() {
                if let Some(peer) = self.peers.get_mut(&result.dest_hash) {
                    if peer.state == PeerState::LinkEstablishing {
                        peer.state = PeerState::Idle;
                    }
                }
            }
            if let Some(link_id) = result.link_id {
                let established = self.direct_links.contains_key(&result.dest_hash)
                    || (self.outbound_propagation_node == Some(result.dest_hash)
                        && self.propagation_link.is_some());
                if !established {
                    self.pending_direct_links.insert(result.dest_hash, link_id);
                }
            }
        }
    }

    /// Register a delivery identity for receiving direct messages.
    ///
    /// `stamp_cost` is the inbound stamp cost; costs below 1 disable stamps
    /// and costs at or above `STAMP_COST_CAP` are ignored
    /// (`set_inbound_stamp_cost`).
    pub fn register_delivery_identity(
        &mut self,
        delivery_identity: &Identity,
        stamp_cost: Option<f64>,
        display_name: Option<String>,
    ) {
        let dest_hash = compute_dest_hash(APP_NAME, &["delivery"], delivery_identity.hash());
        self.delivery_dest_hash = Some(dest_hash);
        self.set_inbound_stamp_cost(stamp_cost);
        self.display_name = display_name;

        if let Some(node) = &self.node {
            // Register as link destination so we can accept incoming LINKREQUEST.
            // Also register as SINGLE destination for opportunistic delivery.
            // When both are registered, rns-net routes link packets through
            // link_manager and falls back to on_local_delivery for non-link DATA.
            Self::register_inbound_destination(
                node,
                delivery_identity,
                &["delivery"],
                Some(DELIVERY_LINK_COST),
            );
        }
    }

    /// Set the inbound stamp cost of the delivery destination. Returns false
    /// (and keeps the current cost) for costs at or above `STAMP_COST_CAP`.
    pub fn set_inbound_stamp_cost(&mut self, stamp_cost: Option<f64>) -> bool {
        match announce::inbound_stamp_cost(stamp_cost) {
            Ok(cost) => {
                self.delivery_stamp_cost = cost;
                true
            }
            Err(_) => false,
        }
    }

    /// Set the delivery callback for incoming messages.
    pub fn set_delivery_callback(&mut self, callback: DeliveryCallback) {
        self.delivery_callback = Some(callback);
    }

    /// Enable propagation node functionality.
    ///
    /// Peers can only sync to this node once
    /// [`register_propagation_request_handlers`](Self::register_propagation_request_handlers)
    /// has also been called with the shared router.
    pub fn enable_propagation(&mut self) {
        self.propagation_node = true;

        if let Some(node) = &self.node {
            // Register propagation destination for incoming links
            Self::register_inbound_destination(
                node,
                &self.identity,
                &["propagation"],
                Some(PROPAGATION_LINK_COST),
            );

            // Register control destination
            let control_hash = Self::register_inbound_destination(
                node,
                &self.identity,
                &["propagation", "control"],
                None,
            );
            self.control_dest_hash = Some(control_hash);
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
                let _ = node.deregister_link_destination(control_hash);
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
            if let Err(err) = node.announce_queued(&dest, delivery_identity, Some(&app_data)) {
                log::warn!("Failed to queue delivery announce: {:?}", err);
            }
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
            if let Err(err) = node.announce_queued(&dest, &self.identity, Some(&app_data)) {
                log::warn!("Failed to queue propagation node announce: {:?}", err);
            }
        }
    }

    /// Announce the propagation control destination.
    pub fn announce_control_destination(&self) {
        if let Some(node) = &self.node {
            let dest = Destination::single_in(
                APP_NAME,
                &["propagation", "control"],
                IdentityHash(*self.identity.hash()),
            );
            if let Err(err) = node.announce_queued(&dest, &self.identity, None) {
                log::warn!("Failed to queue control destination announce: {:?}", err);
            }
        }
    }

    /// Build delivery announce app_data (LXMF 1.3 format).
    pub fn build_delivery_announce_data(&self) -> Vec<u8> {
        announce::build_delivery_announce_data(
            self.display_name.as_deref(),
            self.delivery_stamp_cost,
        )
    }

    /// Build propagation node announce data (LXMF 1.3 format).
    pub fn build_pn_announce_data(&self) -> Vec<u8> {
        let name = self.config.name.as_deref();
        announce::build_pn_announce_data(&announce::PnAnnounceParams {
            node_timebase: now_timestamp() as u64,
            propagation_enabled: self.propagation_node && !self.config.from_static_only,
            propagation_transfer_limit: self.config.propagation_limit as u64,
            propagation_sync_limit: self.config.sync_limit as u64,
            propagation_stamp_cost: self.config.propagation_cost,
            propagation_stamp_cost_flexibility: self.config.propagation_cost_flexibility,
            peering_cost: self.config.peering_cost,
            implementation: Some((IMPLEMENTATION_NAME, env!("CARGO_PKG_VERSION"))),
            name,
        })
    }

    /// Handle an outbound message for delivery.
    ///
    /// As `LXMessage.pack` does, an opportunistic message too large for a
    /// single packet falls back to direct (link) delivery, and the
    /// representation is chosen from the content size. A message without a
    /// stamp cost takes the cost the destination last announced.
    pub fn handle_outbound(&mut self, mut msg: OutboundMessage) -> Result<(), OutboundError> {
        if msg.method == DeliveryMethod::Propagated && self.outbound_propagation_node.is_none() {
            msg.state = MessageState::Failed;
            if let Some(cb) = &msg.failed_callback {
                cb(&msg);
            }
            return Err(OutboundError::MissingOutboundPropagationNode);
        }

        let (method, representation) = message::resolve_delivery(
            msg.method,
            msg.packed.len(),
            msg.propagation_packed.as_ref().map(Vec::len),
        );
        if method != msg.method {
            log::debug!(
                "Opportunistic delivery requested for {:02x?}, but content exceeds the packet \
                 size limit; falling back to link-based delivery",
                &msg.message_hash[..4]
            );
        }
        msg.method = method;
        msg.representation = representation;

        if msg.stamp_cost.is_none() {
            msg.stamp_cost = self.get_stamp_cost(&msg.destination_hash);
        }

        // Stamps are generated in the background, one message at a time
        // (`process_deferred_stamps`); the message waits as Generating.
        let needs_stamp =
            msg.stamp.is_none() && msg.stamp_cost.is_some_and(|c| c > StampCost::ZERO);
        let needs_propagation_stamp =
            msg.method == DeliveryMethod::Propagated && msg.propagation_stamp.is_none();
        if needs_stamp || needs_propagation_stamp {
            msg.state = MessageState::Generating;
            msg.tracking.generation_started = Some(now_timestamp());
        } else {
            msg.state = MessageState::Outbound;
        }
        let dest_hash = msg.destination_hash;
        let opportunistic = msg.method == DeliveryMethod::Opportunistic;
        self.outbound.push(msg);

        // Pre-emptively request an unknown path for opportunistic delivery.
        if opportunistic {
            if let Some(node) = self.node.clone() {
                if !node.has_path(&dest_hash) {
                    let medium = MediumInfo::query(&node);
                    self.request_path_debounced(&dest_hash, &node, &medium);
                    let idx = self.outbound.len() - 1;
                    self.schedule_attempt_for(idx, &dest_hash, true, &node, &medium);
                }
            }
        }
        Ok(())
    }

    /// Cancel a queued outbound message (`cancel_outbound`). Stamp
    /// generation in progress for it is stopped; the failed callback fires
    /// when the message leaves the queue. Returns false when no pending
    /// message has this hash.
    pub fn cancel_outbound(&mut self, message_hash: &[u8; 32]) -> bool {
        if let Some((running, cancel)) = &self.stamp_job {
            if running == message_hash {
                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        match self
            .outbound
            .iter_mut()
            .find(|msg| &msg.message_hash == message_hash && !msg.is_concluded())
        {
            Some(msg) => {
                msg.state = MessageState::Cancelled;
                true
            }
            None => false,
        }
    }

    /// Delivery progress of a queued message (`get_outbound_progress`).
    pub fn outbound_progress(&self, message_hash: &[u8; 32]) -> Option<f64> {
        self.outbound
            .iter()
            .find(|msg| &msg.message_hash == message_hash)
            .map(|msg| msg.tracking.progress)
    }

    /// Install finished stamp jobs and start the next one.
    fn process_stamp_generation<N: OutboundNetwork + ?Sized>(&mut self, network: &N) {
        while let Ok((message_hash, outcome)) = self.stamp_job_rx.try_recv() {
            if self
                .stamp_job
                .as_ref()
                .is_some_and(|(running, _)| *running == message_hash)
            {
                self.stamp_job = None;
            }
            let Some(msg) = self.outbound.iter_mut().find(|msg| {
                msg.message_hash == message_hash && msg.state == MessageState::Generating
            }) else {
                continue;
            };
            match outcome {
                Ok(stamped) => {
                    msg.packed = stamped.packed;
                    if stamped.stamp.is_some() {
                        msg.stamp = stamped.stamp;
                    }
                    if stamped.propagation_packed.is_some() {
                        msg.propagation_packed = stamped.propagation_packed;
                        msg.transient_id = stamped.transient_id;
                        msg.propagation_stamp = stamped.propagation_stamp;
                    }
                    msg.representation = message::resolve_delivery(
                        msg.method,
                        msg.packed.len(),
                        msg.propagation_packed.as_ref().map(Vec::len),
                    )
                    .1;
                    msg.state = MessageState::Outbound;
                    log::debug!("Stamp generation completed for {:02x?}", &message_hash[..4]);
                }
                Err(err) => {
                    log::error!(
                        "Stamp generation for {:02x?} did not succeed ({:?}), failing it",
                        &message_hash[..4],
                        err
                    );
                    msg.state = MessageState::Failed;
                    if let Some(cb) = &msg.failed_callback {
                        cb(msg);
                    }
                }
            }
        }

        if self.stamp_job.is_some() {
            return;
        }
        let now = now_timestamp();
        let Some(idx) = self
            .outbound
            .iter()
            .position(|msg| msg.state == MessageState::Generating)
        else {
            return;
        };

        let msg = &self.outbound[idx];
        let stamp_cost = if msg.stamp.is_none() {
            msg.stamp_cost.filter(|cost| *cost > StampCost::ZERO)
        } else {
            None
        };
        let mut propagation = None;
        if msg.method == DeliveryMethod::Propagated && msg.propagation_stamp.is_none() {
            let dest_hash = msg.destination_hash;
            let started = msg.tracking.generation_started.unwrap_or(now);
            let pn = self.outbound_propagation_node;
            let pn_cost = pn.and_then(|pn| self.pn_costs.get(&pn).copied());
            let public_key = self.destination_public_key(&dest_hash, network);
            match (pn_cost, public_key) {
                (Some(cost), Some(key)) => propagation = Some((key, cost)),
                (pn_cost, public_key) => {
                    if now - started > PR_PATH_TIMEOUT as f64 {
                        log::error!(
                            "Propagation stamp for {:02x?} cannot be generated: {}",
                            &msg.message_hash[..4],
                            if pn_cost.is_none() {
                                "propagation node stamp cost unknown"
                            } else {
                                "recipient identity unknown"
                            }
                        );
                        let msg = &mut self.outbound[idx];
                        msg.state = MessageState::Failed;
                        if let Some(cb) = &msg.failed_callback {
                            cb(msg);
                        }
                        return;
                    }
                    let medium = MediumInfo::query(network);
                    if let (None, Some(pn)) = (pn_cost, pn) {
                        self.request_path_debounced(&pn, network, &medium);
                    }
                    if public_key.is_none() {
                        self.request_path_debounced(&dest_hash, network, &medium);
                    }
                    return;
                }
            }
        }

        let msg = &self.outbound[idx];
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let job = crate::stamper::StampJob {
            message_hash: msg.message_hash,
            packed: msg.packed.clone(),
            stamp_cost,
            ticket_stamp: None,
            propagation,
            cancel: cancel.clone(),
        };
        log::debug!(
            "Starting stamp generation for {:02x?}",
            &msg.message_hash[..4]
        );
        self.stamp_job = Some((msg.message_hash, cancel));
        let results = self.stamp_job_tx.clone();
        thread::spawn(move || {
            let outcome = crate::stamper::run_stamp_job(&job);
            let _ = results.send((job.message_hash, outcome));
        });
    }

    /// Update the outbound propagation node destination hash at runtime.
    ///
    /// Used by the alternative relay fallback to re-target propagated delivery
    /// at a different propagation node.
    pub fn set_propagation_dest_hash(&mut self, dest_hash: [u8; 16]) {
        self.outbound_propagation_node = Some(dest_hash);
    }

    pub fn reset_propagation_transfer_progress(&mut self) {
        self.propagation_transfer_progress = 0.0;
        self.propagation_transfer_size = None;
    }

    pub fn track_inbound_delivery_resource(
        &mut self,
        link_id: [u8; 16],
        resource_hash: Vec<u8>,
        total: u64,
    ) {
        self.incoming_delivery_resources.insert(
            resource_hash.clone(),
            InboundResource {
                resource_hash,
                link_id,
                received: 0,
                total,
            },
        );
    }

    pub fn update_inbound_resource_progress(
        &mut self,
        link_id: [u8; 16],
        received: usize,
        total: usize,
    ) {
        for resource in self.incoming_delivery_resources.values_mut() {
            if resource.link_id == link_id {
                resource.total = resource.total.max(total as u64);
                resource.received = resource.received.max(received as u64).min(resource.total);
            }
        }
    }

    fn finish_inbound_delivery_resources(&mut self, link_id: [u8; 16]) {
        self.incoming_delivery_resources
            .retain(|_, resource| resource.link_id != link_id);
    }

    pub fn inbound_count(&self) -> usize {
        self.incoming_delivery_resources.len()
    }

    pub fn inbound_resources(&self) -> Vec<InboundResource> {
        let mut resources: Vec<_> = self.incoming_delivery_resources.values().cloned().collect();
        resources.sort_by(|left, right| left.resource_hash.cmp(&right.resource_hash));
        resources
    }

    pub fn cancel_inbound_with<T: InboundResourceControl + ?Sized>(
        &mut self,
        resource_hash: &[u8],
        control: &T,
    ) -> bool {
        let Some(resource) = self.incoming_delivery_resources.get(resource_hash).cloned() else {
            return false;
        };
        if control
            .cancel_inbound_resource(resource.link_id, &resource.resource_hash)
            .is_err()
        {
            return false;
        }
        self.incoming_delivery_resources.remove(resource_hash);
        true
    }

    pub fn cancel_all_inbound_with<T: InboundResourceControl + ?Sized>(
        &mut self,
        control: &T,
    ) -> usize {
        let resources = self.inbound_resources();
        resources
            .iter()
            .filter(|resource| self.cancel_inbound_with(&resource.resource_hash, control))
            .count()
    }

    pub fn cancel_inbound(&mut self, resource_hash: &[u8]) -> bool {
        let Some(node) = self.node.clone() else {
            return false;
        };
        self.cancel_inbound_with(resource_hash, node.as_ref())
    }

    pub fn cancel_all_inbound(&mut self) -> usize {
        let Some(node) = self.node.clone() else {
            return 0;
        };
        self.cancel_all_inbound_with(node.as_ref())
    }

    /// Run periodic jobs. Called every PROCESSING_INTERVAL seconds.
    pub fn jobs(&mut self) {
        if self.exit_handler_running {
            return;
        }

        self.processing_count = self.processing_count.wrapping_add(1);

        // Outbound processing and link cleanup run every cycle.
        self.process_outbound();
        self.clean_links();
        self.drain_peering_keys();

        // Transient ID cleanup (every 60 cycles = 4 min)
        if self.processing_count.is_multiple_of(JOB_TRANSIENT_INTERVAL) {
            self.clean_transient_id_caches();
        }

        // Peer propagation sync (every 6 cycles = 24s)
        if self.processing_count.is_multiple_of(JOB_PEERSYNC_INTERVAL) {
            if let Some(node) = self.node.clone() {
                self.ensure_peer_sync_links(&node);
                self.process_peer_syncs_with_transport(node.as_ref());
            }
        }

        // Message store cleanup and peer save (every 120 cycles = 8 min)
        if self.processing_count.is_multiple_of(JOB_STORE_INTERVAL) {
            self.propagation_store
                .clean_messagestore(&self.prioritised_list);
            self.save_peers();
            self.save_stamp_costs_if_dirty();
        }
    }

    /// Process the outbound message queue against the attached RNS node.
    pub fn process_outbound(&mut self) {
        let Some(node) = self.node.clone() else {
            return;
        };
        self.process_outbound_with(&node);
    }

    /// Process the outbound message queue (`process_outbound`).
    ///
    /// Concluded messages are removed from the queue: delivered messages and
    /// propagated messages accepted by the propagation node have their
    /// destination's announce data retained, and failed, cancelled or
    /// rejected messages fire their failed callback.
    pub fn process_outbound_with<N: OutboundNetwork + ?Sized>(&mut self, network: &N) {
        self.drain_direct_link_results();
        self.process_stamp_generation(network);

        let medium = MediumInfo::query(network);
        let now = now_timestamp();
        let mut concluded: Vec<(usize, bool)> = Vec::new(); // (index, fire failed callback)

        for idx in 0..self.outbound.len() {
            let state = self.outbound[idx].state;
            let method = self.outbound[idx].method;
            let dest_hash = self.outbound[idx].destination_hash;

            match state {
                MessageState::Delivered => {
                    network.retain_destination(dest_hash);
                    concluded.push((idx, false));
                    continue;
                }
                MessageState::Sent if method == DeliveryMethod::Propagated => {
                    network.retain_destination(dest_hash);
                    concluded.push((idx, false));
                    continue;
                }
                MessageState::Cancelled | MessageState::Rejected | MessageState::Failed => {
                    // Failed messages had their callback fired when they failed.
                    concluded.push((idx, state != MessageState::Failed));
                    continue;
                }
                // Waiting for stamps; see process_stamp_generation.
                MessageState::Generating => continue,
                _ => {}
            }

            let msg = &mut self.outbound[idx];
            if msg.tracking.progress < 0.01 {
                msg.tracking.progress = 0.01;
            }

            let failed = match method {
                DeliveryMethod::Opportunistic => {
                    self.process_opportunistic(idx, network, &medium, now)
                }
                DeliveryMethod::Direct => self.process_direct(idx, network, &medium, now),
                DeliveryMethod::Propagated => self.process_propagated(idx, network, &medium, now),
                DeliveryMethod::Paper => false,
            };
            if failed {
                self.fail_message_at(idx);
                concluded.push((idx, true));
            }
        }

        // Remove concluded messages (reverse order keeps indices valid), then
        // fire failed callbacks on the removed messages.
        concluded.sort_by_key(|(idx, _)| *idx);
        concluded.dedup_by_key(|(idx, _)| *idx);
        for (idx, fire_failed) in concluded.into_iter().rev() {
            let msg = self.outbound.remove(idx);
            if fire_failed {
                if let Some(cb) = &msg.failed_callback {
                    cb(&msg);
                }
            }
        }
    }

    /// Mark a queued message failed (`fail_message`). The caller removes it
    /// and fires the failed callback.
    fn fail_message_at(&mut self, idx: usize) {
        let msg = &mut self.outbound[idx];
        log::debug!("LXM {:02x?} failed to send", &msg.message_hash[..4]);
        msg.tracking.progress = 0.0;
        if msg.state != MessageState::Rejected {
            msg.state = MessageState::Failed;
        }
    }

    /// `path_request_pending`: a path request for the destination was sent
    /// within the current path request wait.
    fn path_request_pending(&self, dest_hash: &[u8; 16], medium: &MediumInfo) -> bool {
        self.path_request_times
            .get(dest_hash)
            .is_some_and(|requested| now_timestamp() - requested < medium.path_request_wait())
    }

    /// Request a path, debounced per destination (`request_path`): requests
    /// are not repeated within the path request wait, or within
    /// `PATH_REQUEST_DEBOUNCE` while a slow interface is online.
    fn request_path_debounced<N: OutboundNetwork + ?Sized>(
        &mut self,
        dest_hash: &[u8; 16],
        network: &N,
        medium: &MediumInfo,
    ) -> bool {
        let window = medium.path_request_window();
        let now = now_timestamp();
        if self
            .path_request_times
            .get(dest_hash)
            .is_some_and(|requested| now - requested < window)
        {
            log::debug!(
                "Path request for {:02x?} still pending, not repeating",
                &dest_hash[..4]
            );
            return false;
        }
        self.path_request_times
            .retain(|_, requested| now - *requested < window);
        self.path_request_times.insert(*dest_hash, now);
        network.request_path(dest_hash);
        true
    }

    fn round_trip<N: OutboundNetwork + ?Sized>(
        &self,
        dest_hash: &[u8; 16],
        network: &N,
        medium: &MediumInfo,
    ) -> f64 {
        let has_path = network.has_path(dest_hash);
        let first_hop = if has_path {
            network.first_hop_timeout(dest_hash)
        } else {
            0.0
        };
        destination_round_trip(has_path, first_hop, medium)
    }

    /// `slow_path`: whether the round trip to a destination exceeds the
    /// delivery retry wait. Cached per processing interval.
    fn slow_path<N: OutboundNetwork + ?Sized>(
        &mut self,
        dest_hash: &[u8; 16],
        network: &N,
        medium: &MediumInfo,
    ) -> bool {
        let now = now_timestamp();
        if let Some((slow, at)) = self.slow_path_cache.get(dest_hash) {
            if now - at < PROCESSING_INTERVAL as f64 {
                return *slow;
            }
        }
        if self.slow_path_cache.len() > 256 {
            self.slow_path_cache.clear();
        }
        let slow = self.round_trip(dest_hash, network, medium) > DELIVERY_RETRY_WAIT as f64;
        self.slow_path_cache.insert(*dest_hash, (slow, now));
        slow
    }

    /// The target an outbound message is delivered to over the network.
    fn outbound_target(&self, msg: &OutboundMessage) -> Option<[u8; 16]> {
        if msg.method == DeliveryMethod::Propagated {
            self.outbound_propagation_node
        } else {
            Some(msg.destination_hash)
        }
    }

    /// `slow_path_held`: on a slow path, only one message may be in flight,
    /// and messages to the same target go out in queue order.
    fn slow_path_held<N: OutboundNetwork + ?Sized>(
        &mut self,
        idx: usize,
        target: &[u8; 16],
        network: &N,
        medium: &MediumInfo,
    ) -> bool {
        if self.outbound[idx].state != MessageState::Outbound {
            return false;
        }
        if !self.slow_path(target, network, medium) {
            return false;
        }
        let mut ahead = true;
        for (other_idx, other) in self.outbound.iter().enumerate() {
            if other_idx == idx {
                ahead = false;
            } else if other.is_concluded() {
                continue;
            } else if (ahead && self.outbound_target(other).as_ref() == Some(target))
                || other.slow_path_in_flight()
            {
                // A message ahead to the same target, or any message in
                // flight over a slow path, holds this one.
                return true;
            }
        }
        false
    }

    /// `attempt_due`: the retry wait elapsed, or a path the message was
    /// waiting for became known.
    fn attempt_due<N: OutboundNetwork + ?Sized>(
        &self,
        idx: usize,
        target: &[u8; 16],
        network: &N,
        now: f64,
    ) -> bool {
        let tracking = &self.outbound[idx].tracking;
        match tracking.next_delivery_attempt {
            None => true,
            Some(next) if now > next => true,
            Some(_) => tracking.awaiting_path && network.has_path(target),
        }
    }

    fn schedule_attempt_for<N: OutboundNetwork + ?Sized>(
        &mut self,
        idx: usize,
        target: &[u8; 16],
        path_request: bool,
        network: &N,
        medium: &MediumInfo,
    ) {
        let round_trip = if path_request {
            medium.medium_path_timeout
        } else {
            self.round_trip(target, network, medium)
        };
        let schedule = schedule_attempt(now_timestamp(), round_trip, path_request, retry_jitter());
        let tracking = &mut self.outbound[idx].tracking;
        tracking.next_delivery_attempt = Some(schedule.next_delivery_attempt);
        tracking.max_delivery_attempts = Some(schedule.max_delivery_attempts);
        if schedule.awaiting_path {
            tracking.awaiting_path = true;
        }
    }

    /// Public key for a destination, from announces seen by this router or
    /// recalled from the transport's known destinations.
    fn destination_public_key<N: OutboundNetwork + ?Sized>(
        &self,
        dest_hash: &[u8; 16],
        network: &N,
    ) -> Option<[u8; 64]> {
        self.identity_cache
            .get(dest_hash)
            .copied()
            .or_else(|| network.recall_public_key(dest_hash))
    }

    /// Opportunistic outbound handling. Returns true when the message failed.
    fn process_opportunistic<N: OutboundNetwork + ?Sized>(
        &mut self,
        idx: usize,
        network: &N,
        medium: &MediumInfo,
        now: f64,
    ) -> bool {
        let dest_hash = self.outbound[idx].destination_hash;
        let held = self.slow_path_held(idx, &dest_hash, network, medium);
        if held {
            return false;
        }
        let attempts = self.outbound[idx].attempts;
        if attempts > self.outbound[idx].attempt_limit() {
            return self.attempt_due(idx, &dest_hash, network, now);
        }
        if !self.attempt_due(idx, &dest_hash, network, now) {
            return false;
        }

        let public_key = self.destination_public_key(&dest_hash, network);
        let path_known = network.has_path(&dest_hash) && public_key.is_some();
        self.outbound[idx].tracking.awaiting_path = false;

        if attempts >= MAX_PATHLESS_TRIES && !path_known {
            log::debug!(
                "Requesting path to {:02x?} after {} pathless tries",
                &dest_hash[..4],
                attempts
            );
            let msg = &mut self.outbound[idx];
            msg.attempts += 1;
            msg.tracking.sent_on_path = false;
            msg.tracking.progress = 0.01;
            self.request_path_debounced(&dest_hash, network, medium);
            self.schedule_attempt_for(idx, &dest_hash, true, network, medium);
        } else if attempts == MAX_PATHLESS_TRIES + 1
            && path_known
            && self.outbound[idx].tracking.sent_on_path
        {
            // Only rediscover when the previous attempt actually went out
            // over the same, apparently stale, path.
            let pending = self.path_request_pending(&dest_hash, medium);
            let msg = &mut self.outbound[idx];
            msg.attempts += 1;
            msg.tracking.sent_on_path = false;
            msg.tracking.awaiting_path = true;
            msg.tracking.progress = 0.01;
            msg.tracking.next_delivery_attempt = Some(now + medium.path_request_wait());
            if !pending {
                log::debug!(
                    "Opportunistic delivery to {:02x?} still unsuccessful, rediscovering path",
                    &dest_hash[..4]
                );
                self.path_request_times.insert(dest_hash, now);
                network.drop_path(&dest_hash);
                network.request_path(&dest_hash);
            }
        } else {
            let Some(public_key) = public_key else {
                // Path without a recallable identity: wait for an announce.
                self.schedule_attempt_for(idx, &dest_hash, true, network, medium);
                return false;
            };
            let slow = self.slow_path(&dest_hash, network, medium);
            {
                let msg = &mut self.outbound[idx];
                msg.attempts += 1;
                msg.last_attempt = now;
                msg.tracking.sent_on_path = path_known;
                msg.tracking.sent_on_slow_path = slow;
            }
            self.schedule_attempt_for(idx, &dest_hash, false, network, medium);
            let msg = &mut self.outbound[idx];
            log::debug!(
                "Opportunistic delivery attempt {} for {:02x?}",
                msg.attempts,
                &msg.message_hash[..4]
            );
            match network.send_opportunistic(
                &dest_hash,
                &public_key,
                &msg.packed[DESTINATION_LENGTH..],
            ) {
                Ok(packet_hash) => {
                    msg.packet_hash = Some(packet_hash);
                    msg.representation = Representation::Packet;
                    msg.state = MessageState::Sent;
                    msg.tracking.progress = 0.5;
                }
                Err(_) => {
                    log::error!("Error while sending {:02x?}", &msg.message_hash[..4]);
                    return true;
                }
            }
        }
        false
    }

    /// Start establishing a link to `target` for a delivery attempt, or
    /// request a path when none is known. Returns true when the message
    /// failed because its attempts are exhausted.
    fn attempt_link<N: OutboundNetwork + ?Sized>(
        &mut self,
        idx: usize,
        target: [u8; 16],
        network: &N,
        medium: &MediumInfo,
        now: f64,
    ) -> bool {
        if !self.attempt_due(idx, &target, network, now) {
            return false;
        }
        {
            let msg = &mut self.outbound[idx];
            msg.attempts += 1;
            msg.last_attempt = now;
            msg.tracking.awaiting_path = false;
        }
        self.schedule_attempt_for(idx, &target, false, network, medium);

        let msg = &self.outbound[idx];
        if msg.attempts >= msg.attempt_limit() {
            log::debug!(
                "Max delivery attempts reached for {:02x?}",
                &msg.message_hash[..4]
            );
            return true;
        }

        let public_key = self.destination_public_key(&target, network);
        match public_key {
            Some(public_key) if network.has_path(&target) => {
                let sig_pub: [u8; 32] = public_key[32..].try_into().unwrap();
                self.pending_direct_link_creations.insert(target, now);
                network.begin_link(target, sig_pub, self.direct_link_tx.clone());
                self.outbound[idx].tracking.progress = 0.03;
            }
            _ => {
                log::debug!(
                    "No path known for delivery attempt to {:02x?}, requesting path",
                    &target[..4]
                );
                self.request_path_debounced(&target, network, medium);
                self.schedule_attempt_for(idx, &target, true, network, medium);
                self.outbound[idx].tracking.progress = 0.01;
            }
        }
        false
    }

    /// Handle a closed link for a message that was using it.
    fn handle_closed_link<N: OutboundNetwork + ?Sized>(
        &mut self,
        idx: usize,
        target: [u8; 16],
        network: &N,
        medium: &MediumInfo,
    ) {
        let Some(was_established) = self.outbound[idx].tracking.link_closed.take() else {
            return;
        };
        if was_established {
            log::debug!(
                "The link to {:02x?} was closed unexpectedly, retrying path request",
                &target[..4]
            );
            self.request_path_debounced(&target, network, medium);
        } else if !self.outbound[idx].tracking.path_request_retried {
            log::debug!(
                "The link to {:02x?} was never activated, retrying path request",
                &target[..4]
            );
            self.request_path_debounced(&target, network, medium);
            self.outbound[idx].tracking.path_request_retried = true;
        }
        let msg = &self.outbound[idx];
        if msg.attempts + 1 < msg.attempt_limit() {
            self.schedule_attempt_for(idx, &target, false, network, medium);
        }
    }

    /// Direct (link) outbound handling. Returns true when the message failed.
    fn process_direct<N: OutboundNetwork + ?Sized>(
        &mut self,
        idx: usize,
        network: &N,
        medium: &MediumInfo,
        now: f64,
    ) -> bool {
        let dest_hash = self.outbound[idx].destination_hash;
        self.handle_closed_link(idx, dest_hash, network, medium);

        if self.slow_path_held(idx, &dest_hash, network, medium) {
            return false;
        }
        let msg = &self.outbound[idx];
        if msg.attempts > msg.attempt_limit() {
            return self.attempt_due(idx, &dest_hash, network, now);
        }

        let active_link = self
            .direct_links
            .get(&dest_hash)
            .or_else(|| self.backchannel_links.get(&dest_hash))
            .copied();
        if let Some(link_id) = active_link {
            if self.outbound[idx].state == MessageState::Outbound {
                let slow = self.slow_path(&dest_hash, network, medium);
                let auto_compress = self
                    .compression_cache
                    .get(&dest_hash)
                    .copied()
                    .unwrap_or(true);
                let msg = &mut self.outbound[idx];
                msg.tracking.sent_on_slow_path = slow;
                if msg.tracking.progress < 0.05 {
                    msg.tracking.progress = 0.05;
                }
                return send_direct_on_link(network, msg, link_id, auto_compress).is_err();
            }
            // Transfer in progress; wait for it to conclude.
            return false;
        }

        let link_pending = self.pending_direct_links.contains_key(&dest_hash)
            || self.pending_direct_link_creations.contains_key(&dest_hash);
        if link_pending {
            // Wait for the link to become active or close.
            return false;
        }

        self.attempt_link(idx, dest_hash, network, medium, now)
    }

    /// Propagated outbound handling. Returns true when the message failed.
    fn process_propagated<N: OutboundNetwork + ?Sized>(
        &mut self,
        idx: usize,
        network: &N,
        medium: &MediumInfo,
        now: f64,
    ) -> bool {
        let Some(propagation_node) = self.outbound_propagation_node else {
            log::error!("No outbound propagation node specified for propagated message");
            return true;
        };
        self.handle_closed_link(idx, propagation_node, network, medium);

        if self.slow_path_held(idx, &propagation_node, network, medium) {
            return false;
        }
        let msg = &self.outbound[idx];
        if msg.attempts > msg.attempt_limit() {
            return self.attempt_due(idx, &propagation_node, network, now);
        }

        if let Some(link_id) = self.propagation_link {
            if self.outbound[idx].state == MessageState::Outbound {
                let slow = self.slow_path(&propagation_node, network, medium);
                let msg = &mut self.outbound[idx];
                msg.tracking.sent_on_slow_path = slow;
                return send_propagated_on_link(network, msg, link_id).is_err();
            }
            return false;
        }

        let link_pending = self.pending_direct_links.contains_key(&propagation_node)
            || self
                .pending_direct_link_creations
                .contains_key(&propagation_node);
        if link_pending {
            return false;
        }

        self.attempt_link(idx, propagation_node, network, medium, now)
    }

    /// Clean up inactive links.
    fn clean_links(&mut self) {
        // Link cleanup is handled via on_link_closed callbacks
    }

    /// Clean expired transient ID caches.
    fn clean_transient_id_caches(&mut self) {
        let now = now_timestamp();
        // Transient IDs outlive the messages themselves so that copies
        // re-synced from other propagation nodes stay suppressed.
        let expiry = TRANSIENT_ID_EXPIRY as f64;

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
            cache
                .get(src_hash)
                .and_then(|public_key| Identity::from_public_key(public_key).ok())
                .is_some_and(|id| id.verify(sig, data))
        };

        let result = match message::unpack(lxmf_bytes, Some(&verify_fn)) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Failed to unpack inbound message: {:?}", e);
                return;
            }
        };

        // Check if source is blackholed or ignored.
        if self.source_identity_is_blackholed(&result.source_hash) {
            log::debug!(
                "Dropping LXM from blackholed source {:02x?}",
                &result.source_hash[..4]
            );
            return;
        }

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
                        if stamp_cost > StampCost::ZERO {
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

    /// Update the outbound stamp cost for a destination from its latest
    /// announce; `None` clears it. Costs are persisted periodically and on
    /// exit rather than on every announce (upstream d845503).
    pub fn update_stamp_cost(&mut self, dest_hash: [u8; 16], cost: Option<StampCost>) {
        log::trace!(
            "Updating outbound stamp cost for {:02x?} to {:?}",
            &dest_hash[..4],
            cost.map(StampCost::as_f64)
        );
        let changed = match cost {
            Some(cost) => {
                let previous = self
                    .outbound_stamp_costs
                    .insert(dest_hash, (now_timestamp(), cost));
                previous.map(|(_, previous)| previous) != Some(cost)
            }
            None => self.outbound_stamp_costs.remove(&dest_hash).is_some(),
        };
        if changed {
            self.stamp_costs_dirty = true;
        }
    }

    /// Get the known stamp cost for a destination.
    pub fn get_stamp_cost(&self, dest_hash: &[u8; 16]) -> Option<StampCost> {
        let now = now_timestamp();
        self.outbound_stamp_costs
            .get(dest_hash)
            .filter(|(ts, _)| now - ts < STAMP_COST_EXPIRY as f64)
            .map(|(_, cost)| *cost)
    }

    /// Persist outbound stamp costs if they changed since the last save.
    pub fn save_stamp_costs_if_dirty(&mut self) {
        if !self.stamp_costs_dirty {
            return;
        }
        let now = now_timestamp();
        self.outbound_stamp_costs
            .retain(|_, (ts, _)| now - *ts < STAMP_COST_EXPIRY as f64);
        match storage::save_stamp_costs(
            &self.paths.outbound_stamp_costs,
            &self.outbound_stamp_costs,
        ) {
            Ok(()) => self.stamp_costs_dirty = false,
            Err(err) => log::error!("Could not save outbound stamp costs: {}", err),
        }
    }

    fn process_peer_distribution_queue(&mut self) {
        let queued = self.propagation_store.flush_distribution_queue();
        if queued.is_empty() {
            return;
        }

        let peer_hashes: Vec<[u8; 16]> = self.peers.keys().copied().collect();
        for (transient_id, from_peer) in queued {
            for peer_hash in &peer_hashes {
                if Some(*peer_hash) == from_peer {
                    self.propagation_store
                        .add_handled_peer(&transient_id, *peer_hash);
                    continue;
                }

                if let Some(peer) = self.peers.get_mut(peer_hash) {
                    peer.queue_unhandled_message(transient_id);
                    self.propagation_store
                        .add_unhandled_peer(&transient_id, *peer_hash);
                }
            }
        }
    }

    fn peer_sync_offer_entries(&self, transient_ids: &[[u8; 32]]) -> Vec<OfferEntry> {
        let now = now_timestamp();
        transient_ids
            .iter()
            .filter_map(|id| {
                self.propagation_store
                    .entries
                    .get(id)
                    .map(|entry| OfferEntry {
                        transient_id: *id,
                        weight: peer_offer_weight(entry, now, &self.prioritised_list),
                        size: entry.size,
                        stamp_value: entry.stamp_value,
                    })
            })
            .collect()
    }

    fn mark_store_handled_for_peer(&mut self, peer_hash: [u8; 16]) {
        let Some(peer) = self.peers.get(&peer_hash) else {
            return;
        };
        let handled = peer.handled_ids.clone();
        for transient_id in handled {
            self.propagation_store
                .add_handled_peer(&transient_id, peer_hash);
        }
    }

    fn build_peer_sync_resource_payload(&self, wants: &[[u8; 32]]) -> Option<Vec<u8>> {
        let mut messages = Vec::new();
        for transient_id in wants {
            let entry = self.propagation_store.entries.get(transient_id)?;
            let data = std::fs::read(&entry.filepath).ok()?;
            messages.push(Value::Bin(data));
        }

        let payload = Value::Array(vec![Value::Float(now_timestamp()), Value::Array(messages)]);
        Some(msgpack::pack(&payload))
    }

    pub fn check_inbound_offer_admission(&self, remote_hash: [u8; 16]) -> Result<(), PeerError> {
        let bypass_sequential =
            !self.config.static_sequential && self.config.static_peers.contains(&remote_hash);

        if self.config.from_static_only && !self.config.static_peers.contains(&remote_hash) {
            return Err(PeerError::NoAccess);
        }

        if self
            .throttled_peers
            .get(&remote_hash)
            .is_some_and(|until| *until > now_timestamp())
        {
            return Err(PeerError::Throttled);
        }

        if !bypass_sequential
            && self.config.sequential_validation
            && !self.validating_pn_stamps_from.is_empty()
        {
            return Err(PeerError::Throttled);
        }

        let resources_in_progress = self
            .accepted_offer_links
            .values()
            .filter(|state| {
                matches!(
                    state,
                    InboundOfferState::Transferring | InboundOfferState::Validating
                )
            })
            .count();
        if !bypass_sequential
            && self.config.max_inbound_syncs > 0
            && resources_in_progress >= self.config.max_inbound_syncs
        {
            return Err(PeerError::Throttled);
        }

        Ok(())
    }

    pub fn handle_inbound_offer(
        &mut self,
        link_id: [u8; 16],
        remote_identity_hash: [u8; 16],
        data: &[u8],
    ) -> Vec<u8> {
        let remote_hash = compute_dest_hash(APP_NAME, &["propagation"], &remote_identity_hash);
        if let Err(error) = self.check_inbound_offer_admission(remote_hash) {
            return vec![error as u8];
        }

        let value = match msgpack::unpack_exact(data) {
            Ok(value) => value,
            Err(_) => return vec![PeerError::InvalidData as u8],
        };
        let fields = match value.as_array() {
            Some(fields) if fields.len() == 2 => fields,
            _ => return vec![PeerError::InvalidData as u8],
        };
        let peering_key = match fields[0].as_bin() {
            Some(key) if key.len() == STAMP_SIZE => key,
            _ => return vec![PeerError::InvalidData as u8],
        };
        let transient_values = match fields[1].as_array() {
            Some(values) => values,
            None => return vec![PeerError::InvalidData as u8],
        };
        let mut transient_ids = Vec::with_capacity(transient_values.len());
        for value in transient_values {
            let Some(bytes) = value.as_bin() else {
                return vec![PeerError::InvalidData as u8];
            };
            let Ok(transient_id) = <[u8; 32]>::try_from(bytes) else {
                return vec![PeerError::InvalidData as u8];
            };
            transient_ids.push(transient_id);
        }

        let mut peering_id = Vec::with_capacity(32);
        peering_id.extend_from_slice(self.identity.hash());
        peering_id.extend_from_slice(&remote_identity_hash);
        if !lxmf_core::stamp::validate_peering_key(
            &peering_id,
            peering_key,
            self.config.peering_cost,
        ) {
            return vec![PeerError::InvalidKey as u8];
        }
        self.validated_peer_links.insert(link_id);

        let response = self.propagation_store.handle_offer(&transient_ids);
        if response.as_bool() != Some(false) {
            self.accepted_offer_links
                .insert(link_id, InboundOfferState::Accepted);
            self.inbound_offer_peers.insert(link_id, remote_hash);
        }
        msgpack::pack(&response)
    }

    /// Propagation destination hash of a remote identified on a link.
    fn link_remote_pn_hash(&self, link_id: &[u8; 16]) -> Option<[u8; 16]> {
        self.link_remote_identities
            .get(link_id)
            .map(|identity_hash| compute_dest_hash(APP_NAME, &["propagation"], identity_hash))
    }

    /// Decide whether to accept an inbound propagation resource
    /// (`propagation_resource_advertised`).
    ///
    /// Peers transfer messages they offered, and clients upload their own
    /// messages; both arrive as resources on propagation links. When only
    /// static peers are accepted, resources must come from an identified
    /// static peer, unless they carry the application flag clients set.
    pub fn accept_inbound_propagation_resource(
        &mut self,
        link_id: [u8; 16],
        transfer_size: u64,
        app_flag: bool,
    ) -> bool {
        let offered = self.accepted_offer_links.contains_key(&link_id);
        if !offered && !self.active_propagation_links.contains(&link_id) {
            return false;
        }

        if self.config.from_static_only && !app_flag {
            match self.link_remote_pn_hash(&link_id) {
                None => {
                    log::debug!("Rejecting propagation resource from unidentified peer");
                    return false;
                }
                Some(remote_hash) if !self.config.static_peers.contains(&remote_hash) => {
                    log::debug!(
                        "Rejecting propagation resource from {:02x?} not in static peers list",
                        &remote_hash[..4]
                    );
                    return false;
                }
                Some(_) => {}
            }
        }

        let limit = self.config.sync_limit as u64 * 1000;
        if transfer_size > limit {
            log::debug!(
                "Rejecting {} byte propagation resource exceeding the {} byte limit",
                transfer_size,
                limit
            );
            return false;
        }

        if offered {
            self.accepted_offer_links
                .insert(link_id, InboundOfferState::Transferring);
        }
        true
    }

    /// Begin validating a received propagation transfer. Returns the
    /// remote's propagation destination hash when it identified.
    pub fn begin_inbound_validation(&mut self, link_id: [u8; 16]) -> Option<[u8; 16]> {
        let remote_hash = self
            .inbound_offer_peers
            .get(&link_id)
            .copied()
            .or_else(|| self.link_remote_pn_hash(&link_id))?;
        self.accepted_offer_links
            .insert(link_id, InboundOfferState::Validating);
        self.validating_pn_stamps_from
            .insert(remote_hash, now_timestamp());
        Some(remote_hash)
    }

    pub fn finish_inbound_sync(&mut self, link_id: [u8; 16]) {
        let remote_hash = self
            .inbound_offer_peers
            .remove(&link_id)
            .or_else(|| self.link_remote_pn_hash(&link_id));
        if let Some(remote_hash) = remote_hash {
            self.validating_pn_stamps_from.remove(&remote_hash);
        }
        self.accepted_offer_links.remove(&link_id);
    }

    fn cleanup_inbound_link(&mut self, link_id: [u8; 16]) {
        self.finish_inbound_sync(link_id);
        self.validated_peer_links.remove(&link_id);
    }

    /// Minimum stamp cost accepted for propagated messages.
    pub fn min_accepted_propagation_cost(&self) -> StampCost {
        min_accepted_cost(
            self.config.propagation_cost,
            self.config.propagation_cost_flexibility,
        )
    }

    /// Ingest a propagated message (`lxmf_propagation`): deliver it locally
    /// when addressed to this router's delivery destination, otherwise store
    /// it for distribution when running a propagation node. Returns the
    /// transient ID when the message was new.
    pub fn lxmf_propagation(
        &mut self,
        lxmf_data: &[u8],
        stamp_value: lxmf_core::stamp::StampValue,
        stamp_data: Option<&[u8]>,
        from_peer: Option<[u8; 16]>,
    ) -> Option<[u8; 32]> {
        if lxmf_data.len() < LXMF_OVERHEAD {
            return None;
        }
        let transient_id = rns_crypto::sha256::sha256(lxmf_data);
        if self.propagation_store.entries.contains_key(&transient_id)
            || self
                .locally_processed_transient_ids
                .contains_key(&transient_id)
        {
            return None;
        }
        let now = now_timestamp();
        self.locally_processed_transient_ids
            .insert(transient_id, now);

        let mut destination_hash = [0u8; DESTINATION_LENGTH];
        destination_hash.copy_from_slice(&lxmf_data[..DESTINATION_LENGTH]);

        if self.delivery_dest_hash == Some(destination_hash) {
            match self.identity.decrypt(&lxmf_data[DESTINATION_LENGTH..]) {
                Ok(decrypted) => {
                    let mut delivery_data =
                        Vec::with_capacity(DESTINATION_LENGTH + decrypted.len());
                    delivery_data.extend_from_slice(&destination_hash);
                    delivery_data.extend_from_slice(&decrypted);
                    self.lxmf_delivery(
                        &delivery_data,
                        true,
                        ENCRYPTION_DESCRIPTION_EC,
                        DeliveryMethod::Propagated,
                    );
                    self.locally_delivered_transient_ids
                        .insert(transient_id, now_timestamp());
                }
                Err(_) => log::debug!("Could not decrypt propagated message for local delivery"),
            }
            return Some(transient_id);
        }

        if !self.propagation_node {
            log::debug!("Received propagated LXM, but not hosting a propagation node, discarding");
            return Some(transient_id);
        }
        if stamp_value == lxmf_core::stamp::StampValue::ZERO {
            return None;
        }
        self.propagation_store
            .store_message(lxmf_data, stamp_data, stamp_value, from_peer)
    }

    /// Store messages from a validated propagation transfer and update
    /// peer, unpeered and client accounting (`propagation_resource_concluded`).
    fn store_validated_inbound_messages(
        &mut self,
        link_id: [u8; 16],
        remote_hash: Option<[u8; 16]>,
        validated: Vec<lxmf_core::stamp::PnStampResult>,
        invalid_count: usize,
    ) {
        if let Some(remote_hash) = remote_hash {
            self.autopeer_from_incoming_sync(remote_hash);
        }
        for result in validated {
            let message_len = result.lxm_data.len() as u64;
            let peer_hash = remote_hash.filter(|hash| self.peers.contains_key(hash));
            match (peer_hash, remote_hash) {
                (Some(peer_hash), _) => {
                    if let Some(peer) = self.peers.get_mut(&peer_hash) {
                        peer.incoming = peer.incoming.saturating_add(1);
                        peer.rx_bytes = peer.rx_bytes.saturating_add(message_len);
                    }
                }
                (None, Some(_)) => {
                    let store = &mut self.propagation_store;
                    store.unpeered_propagation_incoming =
                        store.unpeered_propagation_incoming.saturating_add(1);
                    store.unpeered_propagation_rx_bytes = store
                        .unpeered_propagation_rx_bytes
                        .saturating_add(message_len);
                }
                (None, None) => {
                    let store = &mut self.propagation_store;
                    store.client_propagation_messages_received =
                        store.client_propagation_messages_received.saturating_add(1);
                }
            }
            self.lxmf_propagation(
                &result.lxm_data,
                result.value,
                Some(&result.stamp),
                peer_hash,
            );
            if let Some(peer) = peer_hash.and_then(|hash| self.peers.get_mut(&hash)) {
                peer.queue_handled_message(result.transient_id);
            }
        }

        if invalid_count > 0 {
            if let Some(node) = &self.node {
                let _ = node.teardown_link(link_id);
            }
            if let Some(remote_hash) = remote_hash {
                self.throttled_peers
                    .insert(remote_hash, now_timestamp() + self.config.pn_stamp_throttle);
                log::warn!(
                    "Propagation transfer from {:02x?} contained {} invalid stamp(s), throttled",
                    &remote_hash[..4],
                    invalid_count
                );
            } else {
                log::warn!(
                    "Propagation transfer from client contained {} invalid stamp(s)",
                    invalid_count
                );
            }
        }
        self.finish_inbound_sync(link_id);
    }

    /// Peer with an identified propagation node that synced to us before we
    /// peered with it, when its last announce shows it enabled within the
    /// auto-peering depth (`propagation_resource_concluded`).
    pub fn autopeer_from_incoming_sync(&mut self, remote_hash: [u8; 16]) -> bool {
        if !self.config.autopeer || self.peers.contains_key(&remote_hash) {
            return false;
        }
        let Some((info, hops)) = self.pn_announces.get(&remote_hash).cloned() else {
            return false;
        };
        if !info.propagation_enabled || hops > self.config.autopeer_maxdepth {
            return false;
        }
        log::debug!(
            "Auto-peering with {:02x?} discovered via incoming sync",
            &remote_hash[..4]
        );
        self.peer(info);
        self.peers.contains_key(&remote_hash)
    }

    /// Handle a client propagation upload sent as a link packet
    /// (`propagation_packet`). Returns whether every message validated, in
    /// which case the packet is proven.
    pub fn handle_propagation_packet(&mut self, link_id: [u8; 16], data: &[u8]) -> bool {
        let Some(messages) = unpack_propagation_batch(data) else {
            return false;
        };
        let validated =
            crate::stamper::validate_pn_stamps(&messages, self.min_accepted_propagation_cost());
        let all_valid = validated.len() == messages.len();
        for result in validated {
            self.propagation_store.client_propagation_messages_received = self
                .propagation_store
                .client_propagation_messages_received
                .saturating_add(1);
            self.lxmf_propagation(&result.lxm_data, result.value, Some(&result.stamp), None);
        }
        if !all_valid {
            log::info!("Propagation transfer from client contained messages with invalid stamps");
            if let Some(node) = &self.node {
                let reject = msgpack::pack(&Value::Array(vec![Value::UInt(
                    PeerError::InvalidStamp as u64,
                )]));
                let _ = node.try_send_on_link(link_id, reject, 0);
                let _ = node.teardown_link(link_id);
            }
        }
        all_valid
    }

    pub fn send_peer_sync_offer_with_transport<T: PeerSyncTransport + ?Sized>(
        &mut self,
        peer_hash: [u8; 16],
        transport: &T,
    ) -> PeerOfferResponseResult {
        let (link_id, unhandled_ids) = match self.peers.get_mut(&peer_hash) {
            Some(peer) => {
                peer.process_queues();
                match peer.link_id {
                    Some(link_id) => (link_id, peer.unhandled_ids.clone()),
                    None => return PeerOfferResponseResult::MissingLink,
                }
            }
            None => return PeerOfferResponseResult::MissingPeer,
        };

        let available_messages = self.peer_sync_offer_entries(&unhandled_ids);
        let offer = match self
            .peers
            .get_mut(&peer_hash)
            .and_then(|peer| peer.build_offer(&available_messages))
        {
            Some(offer) => offer,
            None => return PeerOfferResponseResult::EmptyOffer,
        };

        if transport.send_peer_offer(link_id, &offer).is_err() {
            return PeerOfferResponseResult::TransportError;
        }

        self.peer_sync_response_links.insert(link_id, peer_hash);
        PeerOfferResponseResult::OfferSent
    }

    pub fn handle_peer_offer_response_with_transport<T: PeerSyncTransport + ?Sized>(
        &mut self,
        link_id: [u8; 16],
        response_data: &[u8],
        transport: &T,
    ) -> PeerOfferResponseResult {
        let peer_hash = match self.peer_sync_response_links.remove(&link_id).or_else(|| {
            self.peers
                .iter()
                .find_map(|(hash, peer)| (peer.link_id == Some(link_id)).then_some(*hash))
        }) {
            Some(peer_hash) => peer_hash,
            None => return PeerOfferResponseResult::MissingPeer,
        };

        let action = match self.peers.get_mut(&peer_hash) {
            Some(peer) => peer.handle_offer_response(response_data),
            None => return PeerOfferResponseResult::MissingPeer,
        };

        match action {
            SyncAction::TransferMessages(wants) => {
                let payload = match self.build_peer_sync_resource_payload(&wants) {
                    Some(payload) => payload,
                    None => return PeerOfferResponseResult::TransportError,
                };
                let payload_size = payload.len();
                if transport.send_peer_resource(link_id, payload).is_err() {
                    if let Some(peer) = self.peers.get_mut(&peer_hash) {
                        peer.handle_resource_failed();
                    }
                    return PeerOfferResponseResult::TransportError;
                }
                self.peer_sync_transfer_sizes.insert(link_id, payload_size);
                PeerOfferResponseResult::TransferStarted(wants.len())
            }
            SyncAction::IdentifyAndRetry => {
                let identity_prv_key = match self.identity.get_private_key() {
                    Some(key) => key,
                    None => return PeerOfferResponseResult::TransportError,
                };
                if transport
                    .identify_peer_link(link_id, identity_prv_key)
                    .is_err()
                {
                    return PeerOfferResponseResult::TransportError;
                }
                if let Some(peer) = self.peers.get_mut(&peer_hash) {
                    peer.state = PeerState::LinkReady;
                }
                let retry = self.send_peer_sync_offer_with_transport(peer_hash, transport);
                if retry == PeerOfferResponseResult::TransportError {
                    retry
                } else {
                    PeerOfferResponseResult::RetriedAfterIdentify
                }
            }
            SyncAction::Unpeer => {
                self.peers.remove(&peer_hash);
                self.save_peers();
                let _ = transport.teardown_peer_link(link_id);
                PeerOfferResponseResult::Unpeered
            }
            SyncAction::TeardownLink => {
                self.mark_store_handled_for_peer(peer_hash);
                let _ = transport.teardown_peer_link(link_id);
                PeerOfferResponseResult::Teardown
            }
        }
    }

    /// Prepare peers with unhandled messages for sync (`LXMPeer.sync`):
    /// postpone peers whose costs or peering key are not ready (generating
    /// the key in the background), request paths and back off when none is
    /// found (upstream c939e25), and start link establishment.
    fn ensure_peer_sync_links<N: OutboundNetwork + ?Sized>(&mut self, network: &N) {
        self.ensure_peer_sync_links_at(network, now_timestamp());
    }

    /// [`ensure_peer_sync_links`](Self::ensure_peer_sync_links) at a given
    /// time, against any network implementation.
    pub fn ensure_peer_sync_links_at<N: OutboundNetwork + ?Sized>(
        &mut self,
        network: &N,
        now: f64,
    ) {
        let medium = MediumInfo::query(network);
        let peer_hashes: Vec<[u8; 16]> = self.peers.keys().copied().collect();
        for peer_hash in peer_hashes {
            let Some(peer) = self.peers.get_mut(&peer_hash) else {
                continue;
            };
            peer.process_queues();
            if peer.state != PeerState::Idle || peer.unhandled_ids.is_empty() {
                continue;
            }
            peer.last_sync_attempt = now;
            let (checks_ok, reason) = peer.sync_checks();
            if !checks_ok {
                match reason {
                    SyncPostponeReason::BackoffActive => {
                        if peer.last_sync_attempt > peer.last_heard {
                            peer.alive = false;
                        }
                    }
                    SyncPostponeReason::PeeringKeyNotReady => {
                        self.start_peering_key_generation(peer_hash, network);
                    }
                    _ => {}
                }
                continue;
            }

            if let Some(link_id) = peer.link_id {
                let pending = self.pending_direct_links.values().any(|id| *id == link_id);
                if let Some(peer) = self.peers.get_mut(&peer_hash).filter(|_| !pending) {
                    peer.state = PeerState::LinkReady;
                }
                continue;
            }

            let public_key = self.destination_public_key(&peer_hash, network);
            let path_known = public_key.is_some() && network.has_path(&peer_hash);
            if !path_known {
                match self.peer_path_requests.get(&peer_hash).copied() {
                    Some(requested) if now - requested >= PATH_REQUEST_GRACE => {
                        self.peer_path_requests.remove(&peer_hash);
                        if let Some(peer) = self.peers.get_mut(&peer_hash) {
                            peer.apply_backoff();
                            peer.alive = false;
                        }
                        log::debug!(
                            "Path request was not answered, retrying sync with peer {:02x?} later",
                            &peer_hash[..4]
                        );
                    }
                    Some(_) => {}
                    None => {
                        log::debug!("No path to peer {:02x?}, requesting", &peer_hash[..4]);
                        self.request_path_debounced(&peer_hash, network, &medium);
                        self.peer_path_requests.insert(peer_hash, now);
                    }
                }
                continue;
            }
            self.peer_path_requests.remove(&peer_hash);

            let link_pending = self.pending_direct_links.contains_key(&peer_hash)
                || self.pending_direct_link_creations.contains_key(&peer_hash);
            if link_pending {
                continue;
            }
            let Some(public_key) = public_key else {
                continue;
            };
            log::debug!(
                "Establishing link for sync to peer {:02x?}",
                &peer_hash[..4]
            );
            if let Some(peer) = self.peers.get_mut(&peer_hash) {
                peer.apply_backoff();
                peer.state = PeerState::LinkEstablishing;
            }
            let sig_pub: [u8; 32] = public_key[32..].try_into().unwrap();
            self.pending_direct_link_creations.insert(peer_hash, now);
            network.begin_link(peer_hash, sig_pub, self.direct_link_tx.clone());
        }
    }

    /// Generate a peering key for a peer in the background
    /// (`generate_peering_key`). The key is a stamp over the peer's identity
    /// hash followed by ours, at the peer's peering cost.
    fn start_peering_key_generation<N: OutboundNetwork + ?Sized>(
        &mut self,
        peer_hash: [u8; 16],
        network: &N,
    ) {
        if self.peering_keys_generating.contains(&peer_hash) {
            return;
        }
        let Some(cost) = self
            .peers
            .get(&peer_hash)
            .and_then(|peer| peer.peering_cost)
        else {
            return;
        };
        let identity_hash = self
            .identity_hash_cache
            .get(&peer_hash)
            .copied()
            .or_else(|| {
                self.destination_public_key(&peer_hash, network)
                    .map(|key| crate::outbound::announced_from_public_key(peer_hash, &key))
                    .map(|announced| announced.identity_hash.0)
            });
        let Some(identity_hash) = identity_hash else {
            log::debug!(
                "Could not generate peering key for {:02x?}, identity unknown",
                &peer_hash[..4]
            );
            return;
        };

        let mut key_material = Vec::with_capacity(32);
        key_material.extend_from_slice(&identity_hash);
        key_material.extend_from_slice(self.identity.hash());
        self.peering_keys_generating.insert(peer_hash);
        let results = self.peering_key_tx.clone();
        log::info!("Generating peering key for {:02x?}", &peer_hash[..4]);
        thread::spawn(move || {
            let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let key = crate::stamper::generate_stamp(
                &key_material,
                cost,
                WORKBLOCK_EXPAND_ROUNDS_PEERING,
                cancel,
            )
            .map(|(stamp, value)| (stamp.to_vec(), value));
            let _ = results.send((peer_hash, key));
        });
    }

    /// Install peering keys generated in the background.
    pub fn drain_peering_keys(&mut self) {
        let mut updated = false;
        while let Ok((peer_hash, key)) = self.peering_key_rx.try_recv() {
            self.peering_keys_generating.remove(&peer_hash);
            let Some(peer) = self.peers.get_mut(&peer_hash) else {
                continue;
            };
            match (key, peer.peering_cost) {
                (Some((key, value)), Some(cost)) if value.meets(cost) => {
                    log::info!("Peering key generated for {:02x?}", &peer_hash[..4]);
                    peer.peering_key = Some((key, value));
                    updated = true;
                }
                _ => log::warn!("Peering key generation failed for {:02x?}", &peer_hash[..4]),
            }
        }
        if updated {
            self.save_peers();
        }
    }

    fn process_peer_syncs_with_transport<T: PeerSyncTransport + ?Sized>(&mut self, transport: &T) {
        self.process_peer_distribution_queue();

        let now = now_timestamp();
        let peer_hashes: Vec<[u8; 16]> = self.peers.keys().copied().collect();
        for peer_hash in peer_hashes {
            let should_sync = match self.peers.get(&peer_hash) {
                Some(peer) => {
                    peer.state == PeerState::LinkReady
                        && !peer.unhandled_ids.is_empty()
                        && peer.next_sync_attempt <= now
                }
                None => false,
            };

            if should_sync {
                let _ = self.send_peer_sync_offer_with_transport(peer_hash, transport);
            }
        }
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
        self.stamp_costs_dirty = true;
        self.save_stamp_costs_if_dirty();

        // Save peers
        self.save_peers();

        // Drop node reference so the daemon can reclaim ownership for full shutdown.
        self.node = None;
    }
}

/// Offer weight of a stored message for peer sync ordering.
fn peer_offer_weight(entry: &PropagationEntry, now: f64, prioritised_list: &[[u8; 16]]) -> f64 {
    let age_days = (now - entry.received) / 60.0 / 60.0 / 24.0 / 4.0;
    let age_weight = if age_days > 1.0 { age_days } else { 1.0 };
    let priority_weight = if prioritised_list.contains(&entry.destination_hash) {
        0.1
    } else {
        1.0
    };

    priority_weight * age_weight * entry.size as f64
}

/// Mark a message delivered once (`__mark_delivered`); returns true if the
/// state changed.
fn mark_delivered(msg: &mut OutboundMessage) -> bool {
    if msg.state == MessageState::Delivered {
        return false;
    }
    msg.state = MessageState::Delivered;
    msg.tracking.progress = 1.0;
    if let Some(cb) = &msg.delivery_callback {
        cb(msg);
    }
    true
}

/// Mark a propagated message accepted by the propagation node once
/// (`__mark_propagated`); returns true if the state changed.
fn mark_propagated(msg: &mut OutboundMessage) -> bool {
    if msg.state == MessageState::Sent {
        return false;
    }
    msg.state = MessageState::Sent;
    msg.tracking.progress = 1.0;
    if let Some(cb) = &msg.delivery_callback {
        cb(msg);
    }
    true
}

/// Send a direct message on an established link, as a packet or resource.
///
/// Link packets carry no completion callback here, so a dispatched packet on
/// the encrypted link is treated as delivered.
fn send_direct_on_link<N: OutboundNetwork + ?Sized>(
    network: &N,
    msg: &mut OutboundMessage,
    link_id: [u8; 16],
    auto_compress: bool,
) -> Result<(), crate::outbound::SendFailed> {
    msg.link_id = Some(link_id);
    if msg.representation == Representation::Unknown {
        msg.representation =
            message::resolve_delivery(DeliveryMethod::Direct, msg.packed.len(), None).1;
    }
    if msg.representation == Representation::Packet {
        network.send_link_packet(link_id, msg.packed.clone())?;
        msg.tracking.progress = 0.5;
        mark_delivered(msg);
    } else {
        msg.representation = Representation::Resource;
        network.send_link_resource(link_id, msg.packed.clone(), auto_compress, false)?;
        msg.state = MessageState::Sending;
    }
    Ok(())
}

/// Send a propagated message to the outbound propagation node.
///
/// Propagation resources carry the application flag (LXMF 1.3), which lets
/// a node accepting only static peers still take client deliveries.
fn send_propagated_on_link<N: OutboundNetwork + ?Sized>(
    network: &N,
    msg: &mut OutboundMessage,
    link_id: [u8; 16],
) -> Result<(), crate::outbound::SendFailed> {
    let Some(prop_packed) = msg.propagation_packed.clone() else {
        log::error!("Propagated message has no propagation-packed data");
        return Err(crate::outbound::SendFailed);
    };
    msg.link_id = Some(link_id);
    if msg.representation == Representation::Unknown {
        msg.representation = message::resolve_delivery(
            DeliveryMethod::Propagated,
            msg.packed.len(),
            Some(prop_packed.len()),
        )
        .1;
    }
    if msg.representation == Representation::Packet {
        network.send_link_packet(link_id, prop_packed)?;
        mark_propagated(msg);
    } else {
        msg.representation = Representation::Resource;
        network.send_link_resource(link_id, prop_packed, false, true)?;
        msg.state = MessageState::Sending;
    }
    Ok(())
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

    fn spawn_lxmf_delivery(
        &self,
        lxmf_bytes: Vec<u8>,
        transport_encrypted: bool,
        transport_encryption: &'static str,
        method: DeliveryMethod,
    ) {
        let router = self.router.clone();
        thread::spawn(move || {
            let mut router = router.lock().unwrap();
            router.refresh_blackholed_identities();
            router.lxmf_delivery(
                &lxmf_bytes,
                transport_encrypted,
                transport_encryption,
                method,
            );
        });
    }

    fn is_delivery_link(&self, link_id: LinkId) -> bool {
        let router = self.router.lock().unwrap();
        router.is_delivery_link(&link_id.0)
    }

    /// Run outbound processing off the driver thread (`outbound_trigger`).
    fn kick_outbound(&self) {
        let router = self.router.clone();
        thread::spawn(move || {
            router.lock().unwrap().process_outbound();
        });
    }
}

impl LxmRouter {
    fn is_delivery_link(&self, link_id: &[u8; 16]) -> bool {
        self.link_destinations
            .get(link_id)
            .is_some_and(|dest| self.delivery_dest_hash == Some(*dest))
    }

    fn is_inbound_propagation_link(&self, link_id: &[u8; 16]) -> bool {
        self.active_propagation_links.contains(link_id)
            || self.accepted_offer_links.contains_key(link_id)
    }

    /// Make queued messages waiting for a path to `target` due now. Returns
    /// whether any message was waiting.
    fn wake_messages_awaiting_path(&mut self, target: &[u8; 16]) -> bool {
        let propagation_node = self.outbound_propagation_node;
        let mut woke = false;
        for msg in &mut self.outbound {
            let msg_target = if msg.method == DeliveryMethod::Propagated {
                propagation_node
            } else {
                Some(msg.destination_hash)
            };
            if msg_target.as_ref() == Some(target) && msg.tracking.awaiting_path {
                msg.tracking.next_delivery_attempt = None;
                woke = true;
            }
        }
        woke
    }

    /// Apply a propagation node announce to the peer table.
    fn handle_peer_announce(&mut self, announced: &AnnouncedIdentity, app_data: &[u8]) {
        if !self.propagation_node || announced.dest_hash.0 == self.propagation_dest_hash {
            return;
        }
        let Some(info) = parse_propagation_announce(announced.dest_hash.0, Some(app_data)) else {
            return;
        };
        if self.pn_announces.len() >= 4096
            && !self.pn_announces.contains_key(&info.destination_hash)
        {
            self.pn_announces.clear();
        }
        self.pn_announces
            .insert(info.destination_hash, (info.clone(), announced.hops));
        let is_static_peer = self.config.static_peers.contains(&announced.dest_hash.0);
        let is_existing_peer = self.peers.contains_key(&announced.dest_hash.0);
        let last_heard = self
            .peers
            .get(&announced.dest_hash.0)
            .map(|peer| peer.last_heard)
            .unwrap_or(0.0);

        match decide_propagation_action(
            &info,
            false,
            is_static_peer,
            is_existing_peer,
            last_heard,
            self.config.autopeer,
            Some(announced.hops),
            self.config.autopeer_maxdepth,
        ) {
            PropagationAnnounceResult::Peer(info) => self.peer(info),
            PropagationAnnounceResult::Unpeer {
                destination_hash,
                node_timebase,
            } => {
                if self
                    .peers
                    .get(&destination_hash)
                    .is_some_and(|peer| node_timebase as f64 >= peer.peering_timebase)
                {
                    self.peers.remove(&destination_hash);
                    self.save_peers();
                }
            }
            PropagationAnnounceResult::Ignore => {}
        }
    }

    /// Peer with a propagation node, or refresh an existing peer (`peer`).
    fn peer(&mut self, info: crate::handlers::PropagationPeerInfo) {
        let announced_timebase = info.node_timebase as f64;
        let sync_strategy = self.config.sync_strategy;

        if info.peering_cost > self.config.max_peering_cost {
            if self
                .peers
                .get(&info.destination_hash)
                .is_some_and(|peer| announced_timebase >= peer.peering_timebase)
            {
                self.peers.remove(&info.destination_hash);
                self.save_peers();
            }
            log::info!(
                "Not peering with {:02x?}, its peering cost of {} exceeds the local maximum of {}",
                &info.destination_hash[..4],
                info.peering_cost,
                self.config.max_peering_cost
            );
            return;
        }

        let apply = |peer: &mut LxmPeer| {
            peer.alive = true;
            peer.last_heard = now_timestamp();
            peer.sync_strategy = sync_strategy;
            peer.peering_timebase = announced_timebase;
            peer.propagation_transfer_limit = Some(info.propagation_transfer_limit as f64);
            peer.propagation_sync_limit = Some(info.propagation_sync_limit);
            peer.propagation_stamp_cost = Some(info.propagation_stamp_cost);
            peer.propagation_stamp_cost_flexibility = Some(info.propagation_stamp_cost_flexibility);
            peer.peering_cost = Some(info.peering_cost);
            peer.metadata = Some(info.metadata.clone());
        };

        if let Some(peer) = self.peers.get_mut(&info.destination_hash) {
            if announced_timebase > peer.peering_timebase {
                apply(peer);
                peer.next_sync_attempt = 0.0;
                peer.sync_backoff = 0.0;
                self.save_peers();
            }
        } else if self.peers.len() < self.config.max_peers {
            let mut peer = LxmPeer::new(info.destination_hash);
            apply(&mut peer);
            self.peers.insert(info.destination_hash, peer);
            self.save_peers();
        }
    }
}

impl Callbacks for LxmfCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let mut router = self.router.lock().unwrap();
        let dest_hash = announced.dest_hash.0;

        // Ignore our own delivery announce
        if router.delivery_dest_hash == Some(dest_hash) {
            return;
        }

        // Cache the public key for signature verification in lxmf_delivery
        router
            .identity_cache
            .insert(dest_hash, announced.public_key);
        router
            .identity_hash_cache
            .insert(dest_hash, announced.identity_hash.0);

        let is_pn_announce = announced
            .app_data
            .as_deref()
            .is_some_and(announce::pn_announce_data_is_valid);

        let trigger_outbound = if is_pn_announce {
            let app_data = announced.app_data.as_deref().unwrap_or_default();
            if let Some(cost) = announce::pn_stamp_cost_from_app_data(app_data) {
                router.pn_costs.insert(dest_hash, cost);
            }
            router.handle_peer_announce(&announced, app_data);
            // An announce from our outbound propagation node makes propagated
            // messages waiting for its path actionable.
            router.outbound_propagation_node == Some(dest_hash)
                && router.wake_messages_awaiting_path(&dest_hash)
        } else {
            if let Some(app_data) = announced.app_data.as_deref() {
                if let Some(supports_compression) =
                    announce::compression_support_from_app_data(app_data)
                {
                    router
                        .compression_cache
                        .insert(dest_hash, supports_compression);
                }
                router.update_stamp_cost(dest_hash, announce::stamp_cost_from_app_data(app_data));
            }
            router.wake_messages_awaiting_path(&dest_hash)
        };

        drop(router);
        if trigger_outbound {
            self.kick_outbound();
        }
    }

    fn on_path_updated(&mut self, dest_hash: DestHash, _hops: u8) {
        let woke = self
            .router
            .lock()
            .unwrap()
            .wake_messages_awaiting_path(&dest_hash.0);
        if woke {
            self.kick_outbound();
        }
    }

    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, _packet_hash: PacketHash) {
        let should_deliver = {
            let router = self.router.lock().unwrap();
            router.delivery_dest_hash == Some(dest_hash.0)
        };

        if should_deliver {
            let router = self.router.clone();
            thread::spawn(move || {
                let mut router = router.lock().unwrap();
                // Extract data payload from raw wire packet
                let packet = match rns_core::packet::RawPacket::unpack(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("on_local_delivery: unpack failed: {}", e);
                        return;
                    }
                };
                // Decrypt the data payload (encrypted with our public key by sender)
                let plaintext = match router.identity.decrypt(packet.data()) {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("on_local_delivery: decrypt failed: {:?}", e);
                        return;
                    }
                };
                // Opportunistic delivery: prepend destination hash to decrypted payload
                let mut lxmf_bytes = Vec::with_capacity(DESTINATION_LENGTH + plaintext.len());
                lxmf_bytes.extend_from_slice(&dest_hash.0);
                lxmf_bytes.extend_from_slice(&plaintext);
                router.refresh_blackholed_identities();
                router.lxmf_delivery(
                    &lxmf_bytes,
                    true,
                    ENCRYPTION_DESCRIPTION_EC,
                    DeliveryMethod::Opportunistic,
                );
            });
        }
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        dest_hash: DestHash,
        rtt: f64,
        is_initiator: bool,
    ) {
        let mut router = self.router.lock().unwrap();

        if is_initiator {
            router
                .pending_direct_links
                .retain(|_, lid| *lid != link_id.0);
            router.pending_direct_link_creations.remove(&dest_hash.0);
            let is_propagation_link = router.outbound_propagation_node == Some(dest_hash.0);
            if is_propagation_link {
                router.propagation_link = Some(link_id.0);
            } else if let Some(peer) = router.peers.get_mut(&dest_hash.0) {
                peer.handle_link_established(link_id.0, rtt);
            } else {
                router.direct_links.insert(dest_hash.0, link_id.0);
            }

            // We initiated this link for queued messages; send them now
            // (upstream passes `process_outbound` as the established callback).
            let has_waiting = router.outbound.iter().any(|msg| {
                !msg.is_concluded()
                    && ((msg.method == DeliveryMethod::Propagated && is_propagation_link)
                        || (msg.method == DeliveryMethod::Direct
                            && msg.destination_hash == dest_hash.0))
            });
            drop(router);
            if has_waiting {
                self.kick_outbound();
            }
        } else {
            // Incoming link — map link_id to its destination for delivery routing
            router.link_destinations.insert(link_id.0, dest_hash.0);

            // Track if it's a propagation link
            if router.propagation_node && dest_hash.0 == router.propagation_dest_hash {
                router.active_propagation_links.push(link_id.0);
            }
        }
    }

    fn on_link_closed(&mut self, link_id: LinkId, _reason: Option<rns_core::link::TeardownReason>) {
        let mut router = self.router.lock().unwrap();
        let link = link_id.0;

        // The delivery target this link served, and whether it had been
        // established, so waiting messages can retry (`Link.CLOSED`).
        let closed_target = router
            .direct_links
            .iter()
            .find_map(|(dest, id)| (*id == link).then_some((*dest, true)))
            .or_else(|| {
                router
                    .pending_direct_links
                    .iter()
                    .find_map(|(dest, id)| (*id == link).then_some((*dest, false)))
            })
            .or_else(|| {
                (router.propagation_link == Some(link))
                    .then_some(router.outbound_propagation_node)
                    .flatten()
                    .map(|dest| (dest, true))
            });

        // Remove from link tracking
        router.direct_links.retain(|_, v| *v != link);
        router.pending_direct_links.retain(|_, v| *v != link);
        router.backchannel_links.retain(|_, v| *v != link);
        router.link_destinations.remove(&link);
        router.link_remote_identities.remove(&link);
        router.active_propagation_links.retain(|&id| id != link);

        if router.propagation_link == Some(link) {
            router.propagation_link = None;
        }

        router.peer_sync_response_links.remove(&link);
        router.peer_sync_transfer_sizes.remove(&link);
        router.cleanup_inbound_link(link);
        router.finish_inbound_delivery_resources(link);
        for peer in router.peers.values_mut() {
            if peer.link_id == Some(link) {
                peer.handle_link_closed();
            }
        }

        let propagation_node = router.outbound_propagation_node;
        for msg in &mut router.outbound {
            if msg.is_concluded() {
                continue;
            }
            let on_this_link = msg.link_id == Some(link);
            if on_this_link && msg.state == MessageState::Sending {
                msg.state = MessageState::Outbound;
            }
            if on_this_link {
                msg.link_id = None;
            }
            let msg_target = if msg.method == DeliveryMethod::Propagated {
                propagation_node
            } else if msg.method == DeliveryMethod::Direct {
                Some(msg.destination_hash)
            } else {
                None
            };
            if let Some((target, established)) = closed_target {
                if msg_target == Some(target) {
                    msg.tracking.link_closed = Some(established);
                }
            }
        }
    }

    fn on_remote_identified(
        &mut self,
        link_id: LinkId,
        identity_hash: IdentityHash,
        public_key: [u8; 64],
    ) {
        let mut router = self.router.lock().unwrap();
        router
            .link_remote_identities
            .insert(link_id.0, identity_hash.0);
        if router.is_delivery_link(&link_id.0) {
            // Prepare a backchannel for replies to the identified sender
            // (`delivery_remote_identified`).
            let backchannel_dest = compute_dest_hash(APP_NAME, &["delivery"], &identity_hash.0);
            router.backchannel_links.insert(backchannel_dest, link_id.0);
            router.identity_cache.insert(backchannel_dest, public_key);
            router
                .identity_hash_cache
                .insert(backchannel_dest, identity_hash.0);
        }
    }

    fn on_resource_received(&mut self, link_id: LinkId, data: Vec<u8>, _metadata: Option<Vec<u8>>) {
        if self.is_delivery_link(link_id) {
            self.router
                .lock()
                .unwrap()
                .finish_inbound_delivery_resources(link_id.0);
            self.spawn_lxmf_delivery(
                data,
                true,
                ENCRYPTION_DESCRIPTION_EC,
                DeliveryMethod::Direct,
            );
            return;
        }

        let mut router = self.router.lock().unwrap();
        if !router.is_inbound_propagation_link(&link_id.0) {
            return;
        }
        let Some(messages) = unpack_propagation_batch(&data) else {
            log::debug!("Invalid data structure received at propagation destination, ignoring");
            router.cleanup_inbound_link(link_id.0);
            return;
        };

        let identified = router.link_remote_identities.contains_key(&link_id.0)
            || router.inbound_offer_peers.contains_key(&link_id.0);
        let peering_key_valid = identified && router.validated_peer_links.contains(&link_id.0);
        if !peering_key_valid && messages.len() > 1 {
            log::warn!(
                "Received {} propagation messages without valid peering key presentation, \
                 ignoring; clients can only deliver one message per transfer",
                messages.len()
            );
            if let Some(node) = &router.node {
                let _ = node.teardown_link(link_id.0);
            }
            router.cleanup_inbound_link(link_id.0);
            return;
        }

        let remote_hash = router.begin_inbound_validation(link_id.0);
        let minimum_cost = router.min_accepted_propagation_cost();
        drop(router);

        let router = self.router.clone();
        thread::spawn(move || {
            let offered_count = messages.len();
            let validated = crate::stamper::validate_pn_stamps(&messages, minimum_cost);
            let invalid_count = offered_count.saturating_sub(validated.len());
            router.lock().unwrap().store_validated_inbound_messages(
                link_id.0,
                remote_hash,
                validated,
                invalid_count,
            );
        });
    }

    fn on_resource_accept_query(
        &mut self,
        link_id: LinkId,
        resource_hash: Vec<u8>,
        transfer_size: u64,
        has_metadata: bool,
    ) -> bool {
        self.on_resource_accept_query_with_app_flag(
            link_id,
            resource_hash,
            transfer_size,
            has_metadata,
            false,
        )
    }

    fn on_resource_accept_query_with_app_flag(
        &mut self,
        link_id: LinkId,
        resource_hash: Vec<u8>,
        transfer_size: u64,
        _has_metadata: bool,
        app_flag: bool,
    ) -> bool {
        let mut router = self.router.lock().unwrap();
        if router.is_delivery_link(&link_id.0) {
            let accepted = transfer_size <= (router.config.delivery_limit * 1000.0) as u64;
            log::debug!(
                "{} {} byte inbound LXMF delivery resource on link {:02x?}",
                if accepted { "Accepting" } else { "Rejecting" },
                transfer_size,
                &link_id.0[..4]
            );
            if accepted {
                router.track_inbound_delivery_resource(link_id.0, resource_hash, transfer_size);
            }
            return accepted;
        }
        let accepted =
            router.accept_inbound_propagation_resource(link_id.0, transfer_size, app_flag);
        log::debug!(
            "{} {} byte inbound LXMF propagation resource on link {:02x?}",
            if accepted { "Accepting" } else { "Rejecting" },
            transfer_size,
            &link_id.0[..4]
        );
        accepted
    }

    fn on_resource_progress(&mut self, link_id: LinkId, received: usize, total: usize) {
        let mut router = self.router.lock().unwrap();
        router.update_inbound_resource_progress(link_id.0, received, total);
        let fraction = if total == 0 {
            0.0
        } else {
            received.min(total) as f64 / total as f64
        };
        if router.propagation_link == Some(link_id.0) {
            router.propagation_transfer_size = Some(total as u64);
            router.propagation_transfer_progress = fraction;
        }
        for msg in &mut router.outbound {
            if msg.link_id == Some(link_id.0) && msg.state == MessageState::Sending {
                msg.tracking.progress = 0.10 + fraction * 0.90;
                if let Some(cb) = &msg.progress_callback {
                    cb(msg, msg.tracking.progress);
                }
            }
        }
    }

    fn on_resource_completed(&mut self, link_id: LinkId) {
        let mut router = self.router.lock().unwrap();

        let peer_hash = router
            .peers
            .iter()
            .find_map(|(hash, peer)| (peer.link_id == Some(link_id.0)).then_some(*hash));
        if let Some(peer_hash) = peer_hash {
            let transfer_size = router
                .peer_sync_transfer_sizes
                .remove(&link_id.0)
                .unwrap_or_default();
            let mut should_continue = false;
            if let Some(peer) = router.peers.get_mut(&peer_hash) {
                peer.handle_resource_completed(transfer_size);
                should_continue = peer.should_continue_sync();
                if should_continue {
                    peer.state = PeerState::LinkReady;
                    peer.next_sync_attempt = 0.0;
                }
            }
            router.mark_store_handled_for_peer(peer_hash);
            if let Some(node) = router.node.clone() {
                if should_continue {
                    let _ = router.send_peer_sync_offer_with_transport(peer_hash, node.as_ref());
                } else {
                    let _ = node.teardown_link(link_id.0);
                }
            }
            return;
        }

        // Mark the outbound message transferred on this link concluded.
        let mut slow_path_concluded = false;
        for msg in &mut router.outbound {
            if msg.link_id == Some(link_id.0) && msg.state == MessageState::Sending {
                let changed = if msg.method == DeliveryMethod::Propagated {
                    mark_propagated(msg)
                } else {
                    mark_delivered(msg)
                };
                slow_path_concluded = changed && msg.tracking.sent_on_slow_path;
                break;
            }
        }
        drop(router);
        if slow_path_concluded {
            self.kick_outbound();
        }
    }

    fn on_resource_failed(&mut self, link_id: LinkId, _error: String) {
        let mut router = self.router.lock().unwrap();

        router.cleanup_inbound_link(link_id.0);
        router.finish_inbound_delivery_resources(link_id.0);
        router.peer_sync_transfer_sizes.remove(&link_id.0);
        if let Some(peer) = router
            .peers
            .values_mut()
            .find(|peer| peer.link_id == Some(link_id.0))
        {
            peer.handle_resource_failed();
            return;
        }

        // A failed outbound transfer tears the link down and returns the
        // message to the queue (`__resource_concluded`).
        let mut failed_outbound = false;
        for msg in &mut router.outbound {
            if msg.link_id == Some(link_id.0) && msg.state == MessageState::Sending {
                msg.state = MessageState::Outbound;
                msg.link_id = None;
                failed_outbound = true;
                break;
            }
        }
        if failed_outbound {
            if let Some(node) = &router.node {
                let _ = node.teardown_link(link_id.0);
            }
        }
    }

    fn on_response(&mut self, link_id: LinkId, _request_id: [u8; 16], data: Vec<u8>) {
        let mut router = self.router.lock().unwrap();
        let Some(node) = router.node.clone() else {
            return;
        };
        let _ = router.handle_peer_offer_response_with_transport(link_id.0, &data, node.as_ref());
    }

    fn on_proof(&mut self, _dest_hash: DestHash, packet_hash: PacketHash, _rtt: f64) {
        let mut router = self.router.lock().unwrap();

        // Check if this proof matches an outbound message
        let mut slow_path_concluded = false;
        for msg in &mut router.outbound {
            if msg.packet_hash == Some(packet_hash.0) {
                slow_path_concluded = mark_delivered(msg) && msg.tracking.sent_on_slow_path;
                break;
            }
        }
        drop(router);
        if slow_path_concluded {
            self.kick_outbound();
        }
    }

    fn on_proof_requested(&mut self, dest_hash: DestHash, _packet_hash: PacketHash) -> bool {
        let mut router = self.router.lock().unwrap();
        if router.delivery_dest_hash == Some(dest_hash.0) {
            // Delivery packets are always proven (`delivery_packet`).
            true
        } else if router.propagation_node && router.propagation_dest_hash == dest_hash.0 {
            // Client propagation packets are proven once their stamps
            // validated (`propagation_packet`).
            router.propagation_packet_proof.take().unwrap_or(false)
        } else {
            false
        }
    }

    fn on_link_data(&mut self, link_id: LinkId, _context: u8, data: Vec<u8>) {
        if self.is_delivery_link(link_id) {
            self.spawn_lxmf_delivery(
                data,
                true,
                ENCRYPTION_DESCRIPTION_EC,
                DeliveryMethod::Direct,
            );
            return;
        }
        let mut router = self.router.lock().unwrap();
        if router.propagation_node && router.active_propagation_links.contains(&link_id.0) {
            let valid = router.handle_propagation_packet(link_id.0, &data);
            router.propagation_packet_proof = Some(valid);
        }
    }
}

fn unpack_propagation_batch(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let value = msgpack::unpack_exact(data).ok()?;
    let fields = value.as_array()?;
    if fields.len() != 2 || fields[0].as_number().is_none() {
        return None;
    }
    fields[1]
        .as_array()?
        .iter()
        .map(|value| value.as_bin().map(ToOwned::to_owned))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;

    static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(1);

    fn test_storage_dir(name: &str) -> PathBuf {
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "lxmf_router_unit_{}_{}_{}",
            name,
            std::process::id(),
            id
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn delivery_announce_data_signals_compression_support() {
        let dir = test_storage_dir("delivery_compression_signal");
        let identity = Identity::new(&mut rns_crypto::OsRng);
        let mut router = LxmRouter::new(
            identity,
            RouterConfig {
                storagepath: dir.clone(),
                ..RouterConfig::default()
            },
        );
        router.display_name = Some("Test Node".to_string());
        router.delivery_stamp_cost = Some(StampCost::from_f64(15.5));

        let app_data = router.build_delivery_announce_data();
        let unpacked = msgpack::unpack_exact(&app_data).unwrap();
        let fields = unpacked.as_array().unwrap();

        // LXMF 1.3: [name, ceil(cost), [functionality], exact cost]
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].as_bin(), Some(&b"Test Node"[..]));
        assert_eq!(fields[1].as_uint(), Some(16));
        assert_eq!(fields[3].as_float(), Some(15.5));
        let supported = fields[2].as_array().unwrap();
        assert_eq!(supported.len(), 1);
        assert_eq!(supported[0].as_uint(), Some(SF_COMPRESSION as u64));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn router_mutex_serializes_transient_cache_cleanup_and_delivery_updates() {
        const WRITERS: usize = 6;
        const IDS_PER_WRITER: usize = 80;

        let dir = test_storage_dir("transient_cache_serialization");
        let identity = Identity::new(&mut rns_crypto::OsRng);
        let mut router = LxmRouter::new(
            identity,
            RouterConfig {
                storagepath: dir.clone(),
                ..RouterConfig::default()
            },
        );
        let expired_at = now_timestamp() - TRANSIENT_ID_EXPIRY as f64 - 1.0;
        for index in 0..32u8 {
            router
                .locally_delivered_transient_ids
                .insert([index; 32], expired_at);
            router
                .locally_processed_transient_ids
                .insert([index.wrapping_add(64); 32], expired_at);
        }

        let router = Arc::new(Mutex::new(router));
        let start = Arc::new(Barrier::new(WRITERS + 1));
        let mut handles = Vec::new();

        for writer in 0..WRITERS {
            let router = router.clone();
            let start = start.clone();
            handles.push(thread::spawn(move || {
                start.wait();
                for sequence in 0..IDS_PER_WRITER {
                    let mut id = [0u8; 32];
                    id[..8].copy_from_slice(&(writer as u64).to_be_bytes());
                    id[8..16].copy_from_slice(&(sequence as u64).to_be_bytes());
                    let now = now_timestamp();
                    let mut router = router.lock().unwrap();
                    router.locally_delivered_transient_ids.insert(id, now);
                    id[31] = 1;
                    router.locally_processed_transient_ids.insert(id, now);
                }
            }));
        }

        let cleanup_router = router.clone();
        let cleanup_start = start.clone();
        let cleanup = thread::spawn(move || {
            cleanup_start.wait();
            cleanup_router.lock().unwrap().clean_transient_id_caches();
        });

        for handle in handles {
            handle.join().unwrap();
        }
        cleanup.join().unwrap();

        let mut router = Arc::try_unwrap(router)
            .ok()
            .expect("all worker references should be dropped")
            .into_inner()
            .unwrap();
        router.clean_transient_id_caches();

        assert_eq!(
            router.locally_delivered_transient_ids.len(),
            WRITERS * IDS_PER_WRITER
        );
        assert_eq!(
            router.locally_processed_transient_ids.len(),
            WRITERS * IDS_PER_WRITER
        );
        assert!(router
            .locally_delivered_transient_ids
            .values()
            .all(|timestamp| *timestamp > expired_at));
        assert!(router
            .locally_processed_transient_ids
            .values()
            .all(|timestamp| *timestamp > expired_at));

        router.exit_handler();
        assert_eq!(
            storage::load_transient_ids(&router.paths.local_deliveries),
            router.locally_delivered_transient_ids
        );
        assert_eq!(
            storage::load_transient_ids(&router.paths.locally_processed),
            router.locally_processed_transient_ids
        );

        fs::remove_dir_all(dir).unwrap();
    }
}
