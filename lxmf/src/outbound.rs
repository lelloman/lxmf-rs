//! Outbound delivery support: medium-aware retry timing and the network
//! operations the router's outbound processing needs.
//!
//! Mirrors the medium-aware outbound handling upstream LXMF gained in 1.2/1.3
//! (0889401, fbc821e, acaa9e3, beac6bc, 170e71d, 43a077b, 5745f85): retry
//! waits and attempt limits scale with the round trip of the medium a
//! destination is reached over, path requests are debounced, and messages to
//! slow destinations are held so only one is in flight at a time.

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use lxmf_core::constants::*;
use rns_core::transport::types::InterfaceId;
use rns_core::types::{DestHash, IdentityHash};
use rns_net::destination::{AnnouncedIdentity, Destination};
use rns_net::event::{Event, QueryRequest, QueryResponse};
use rns_net::node::RnsNode;
use rns_net::resource::ResourceSendOptions;

/// `Reticulum.DEFAULT_PER_HOP_TIMEOUT`.
pub const DEFAULT_PER_HOP_TIMEOUT: f64 = rns_core::constants::LINK_ESTABLISHMENT_TIMEOUT_PER_HOP;

/// How long a router query waits for the RNS driver. Router queries are made
/// while holding the router lock; the driver may itself be blocked on that
/// lock inside a callback, so queries must never wait indefinitely.
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);

/// Per-message delivery tracking used by outbound processing.
#[derive(Debug, Clone, Default)]
pub struct DeliveryTracking {
    /// Earliest time of the next delivery attempt (`None`: due now).
    pub next_delivery_attempt: Option<f64>,
    /// Attempt limit scaled to the medium (`None`: `MAX_DELIVERY_ATTEMPTS`).
    pub max_delivery_attempts: Option<u32>,
    /// Waiting for a path; an announce or path response makes the message due.
    pub awaiting_path: bool,
    /// The last opportunistic attempt was sent over a known path.
    pub sent_on_path: bool,
    /// The last attempt went out over a slow path (round trip above the
    /// delivery retry wait), so the message holds others to the same target.
    pub sent_on_slow_path: bool,
    /// A path request was already retried for a link that never activated.
    pub path_request_retried: bool,
    /// The link the message was using closed; `Some(true)` if it had been
    /// established. Handled on the next outbound processing pass.
    pub link_closed: Option<bool>,
    /// Delivery progress, 0.0 to 1.0.
    pub progress: f64,
}

/// A send was not admitted by the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendFailed;

/// Network operations needed by outbound processing.
///
/// Implemented for `Arc<RnsNode>`; tests use a mock.
pub trait OutboundNetwork {
    fn has_path(&self, dest_hash: &[u8; 16]) -> bool;
    fn request_path(&self, dest_hash: &[u8; 16]);
    fn drop_path(&self, dest_hash: &[u8; 16]);
    /// Adaptive path timeout of the slowest medium (0 when unknown).
    fn medium_path_timeout(&self) -> f64;
    /// Slowest positive interface bitrate, if any interface advertises one.
    fn lowest_interface_bitrate(&self) -> Option<u64>;
    /// First-hop timeout towards a destination.
    fn first_hop_timeout(&self, dest_hash: &[u8; 16]) -> f64;
    /// Public key of a destination recalled from known announces.
    fn recall_public_key(&self, dest_hash: &[u8; 16]) -> Option<[u8; 64]>;
    /// Send an opportunistic (single packet) delivery; returns the packet hash.
    fn send_opportunistic(
        &self,
        dest_hash: &[u8; 16],
        public_key: &[u8; 64],
        data: &[u8],
    ) -> Result<[u8; 32], SendFailed>;
    fn send_link_packet(&self, link_id: [u8; 16], data: Vec<u8>) -> Result<(), SendFailed>;
    fn send_link_resource(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        auto_compress: bool,
        app_flag: bool,
    ) -> Result<(), SendFailed>;
    /// Start establishing a link; the result is delivered on `results`.
    fn begin_link(
        &self,
        dest_hash: [u8; 16],
        sig_pub: [u8; 32],
        results: mpsc::Sender<LinkCreation>,
    );
    /// Ask the transport to retain announce data for a destination that was
    /// used for successful delivery (`Reticulum._retain_destination_data`).
    fn retain_destination(&self, dest_hash: [u8; 16]);
}

/// Result of an asynchronous link creation.
pub struct LinkCreation {
    pub dest_hash: [u8; 16],
    pub link_id: Option<[u8; 16]>,
}

pub(crate) fn bounded_query(node: &RnsNode, request: QueryRequest) -> Option<QueryResponse> {
    let (tx, rx) = mpsc::channel();
    node.event_sender().send(Event::query(request, tx)).ok()?;
    match rx.recv_timeout(QUERY_TIMEOUT) {
        Ok(response) => Some(response),
        Err(_) => {
            log::debug!("RNS query timed out while the driver was busy");
            None
        }
    }
}

impl OutboundNetwork for Arc<RnsNode> {
    fn has_path(&self, dest_hash: &[u8; 16]) -> bool {
        matches!(
            bounded_query(
                self,
                QueryRequest::HasPath {
                    dest_hash: *dest_hash
                }
            ),
            Some(QueryResponse::HasPath(true))
        )
    }

    fn request_path(&self, dest_hash: &[u8; 16]) {
        let _ = RnsNode::request_path(self, &DestHash(*dest_hash));
    }

    fn drop_path(&self, dest_hash: &[u8; 16]) {
        let _ = bounded_query(
            self,
            QueryRequest::DropPath {
                dest_hash: *dest_hash,
            },
        );
    }

    fn medium_path_timeout(&self) -> f64 {
        match bounded_query(self, QueryRequest::MediumPathTimeout) {
            Some(QueryResponse::MediumPathTimeout(timeout)) => timeout,
            _ => 0.0,
        }
    }

    fn lowest_interface_bitrate(&self) -> Option<u64> {
        match bounded_query(self, QueryRequest::LowestInterfaceBitrate) {
            Some(QueryResponse::LowestInterfaceBitrate(bitrate)) => bitrate,
            _ => None,
        }
    }

    fn first_hop_timeout(&self, dest_hash: &[u8; 16]) -> f64 {
        match bounded_query(
            self,
            QueryRequest::FirstHopTimeout {
                dest_hash: *dest_hash,
            },
        ) {
            Some(QueryResponse::FirstHopTimeout(timeout)) => timeout,
            _ => DEFAULT_PER_HOP_TIMEOUT,
        }
    }

    fn recall_public_key(&self, dest_hash: &[u8; 16]) -> Option<[u8; 64]> {
        match bounded_query(
            self,
            QueryRequest::RecallIdentity {
                dest_hash: *dest_hash,
            },
        ) {
            Some(QueryResponse::RecallIdentity(Some(announced))) => Some(announced.public_key),
            _ => None,
        }
    }

    fn send_opportunistic(
        &self,
        dest_hash: &[u8; 16],
        public_key: &[u8; 64],
        data: &[u8],
    ) -> Result<[u8; 32], SendFailed> {
        let announced = announced_from_public_key(*dest_hash, public_key);
        let dest = Destination::single_out(APP_NAME, &["delivery"], &announced);
        // The receipt resolves on local transmission; delivery is confirmed
        // by the proof, so the receipt itself is not awaited.
        self.try_send_packet(&dest, data)
            .map(|receipt| receipt.packet_hash().0)
            .map_err(|err| {
                log::debug!("Opportunistic send not admitted: {:?}", err);
                SendFailed
            })
    }

    fn send_link_packet(&self, link_id: [u8; 16], data: Vec<u8>) -> Result<(), SendFailed> {
        self.try_send_on_link(link_id, data, 0)
            .map(|_receipt| ())
            .map_err(|err| {
                log::debug!("Link packet send not admitted: {:?}", err);
                SendFailed
            })
    }

    fn send_link_resource(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        auto_compress: bool,
        app_flag: bool,
    ) -> Result<(), SendFailed> {
        self.send_resource_with_options(
            link_id,
            data,
            None,
            ResourceSendOptions {
                auto_compress,
                app_flag,
            },
        )
        .map_err(|_| SendFailed)
    }

    fn begin_link(
        &self,
        dest_hash: [u8; 16],
        sig_pub: [u8; 32],
        results: mpsc::Sender<LinkCreation>,
    ) {
        let node = self.clone();
        thread::spawn(move || {
            let link_id = node.create_link(dest_hash, sig_pub).ok();
            let _ = results.send(LinkCreation { dest_hash, link_id });
        });
    }

    fn retain_destination(&self, dest_hash: [u8; 16]) {
        let node = self.clone();
        thread::spawn(move || {
            if let Err(err) = node.retain_known_destination(&DestHash(dest_hash)) {
                log::warn!("Failed to retain destination announce data: {:?}", err);
            }
        });
    }
}

/// Build the recalled-identity view of a destination from its public key.
pub fn announced_from_public_key(dest_hash: [u8; 16], public_key: &[u8; 64]) -> AnnouncedIdentity {
    let mut identity_hash = [0u8; 16];
    identity_hash.copy_from_slice(&rns_crypto::sha256::sha256(public_key)[..16]);
    AnnouncedIdentity {
        dest_hash: DestHash(dest_hash),
        identity_hash: IdentityHash(identity_hash),
        public_key: *public_key,
        app_data: None,
        hops: 0,
        received_at: 0.0,
        receiving_interface: InterfaceId(0),
        rssi: None,
        snr: None,
    }
}

/// Snapshot of medium properties for one outbound processing pass.
#[derive(Debug, Clone, Copy)]
pub struct MediumInfo {
    pub medium_path_timeout: f64,
    pub lowest_interface_bitrate: Option<u64>,
}

impl MediumInfo {
    pub fn query<N: OutboundNetwork + ?Sized>(network: &N) -> Self {
        Self {
            medium_path_timeout: network.medium_path_timeout(),
            lowest_interface_bitrate: network.lowest_interface_bitrate(),
        }
    }

    /// `path_request_wait`: how long to wait for a path request answer.
    pub fn path_request_wait(&self) -> f64 {
        (PATH_REQUEST_WAIT as f64).max(self.medium_path_timeout)
    }

    /// Whether any interface is slower than `SLOW_INTERFACE_BITRATE`.
    pub fn slow_interface_online(&self) -> bool {
        self.lowest_interface_bitrate
            .is_some_and(|bitrate| bitrate < SLOW_INTERFACE_BITRATE)
    }

    /// Path request debounce window (`request_path`).
    pub fn path_request_window(&self) -> f64 {
        if self.slow_interface_online() {
            PATH_REQUEST_DEBOUNCE as f64
        } else {
            self.path_request_wait()
        }
    }
}

/// `destination_round_trip`: estimated round trip to a destination.
pub fn destination_round_trip(has_path: bool, first_hop_timeout: f64, medium: &MediumInfo) -> f64 {
    if !has_path {
        return medium.medium_path_timeout;
    }
    let mtu_time = first_hop_timeout - DEFAULT_PER_HOP_TIMEOUT;
    2.0 * mtu_time.max(0.0) + DEFAULT_PER_HOP_TIMEOUT
}

/// Outcome of `schedule_attempt` for a message.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttemptSchedule {
    pub next_delivery_attempt: f64,
    pub max_delivery_attempts: u32,
    pub awaiting_path: bool,
}

/// `schedule_attempt`: when to try again and how many attempts the medium
/// allows. `jitter` in `[0, 1)` spreads retries on slow media.
pub fn schedule_attempt(
    now: f64,
    round_trip: f64,
    path_request: bool,
    jitter: f64,
) -> AttemptSchedule {
    let (wait, awaiting_path) = if path_request {
        (PATH_REQUEST_WAIT as f64, true)
    } else {
        (DELIVERY_RETRY_WAIT as f64, false)
    };
    let mut next_delivery_attempt = now + wait.max(round_trip);

    let max_delivery_attempts = if round_trip > DELIVERY_RETRY_WAIT as f64 {
        let scaled = (MAX_DELIVERY_ATTEMPTS as f64 * DELIVERY_RETRY_WAIT as f64 / round_trip)
            .round_ties_even() as u32;
        scaled.max(3)
    } else {
        MAX_DELIVERY_ATTEMPTS
    };

    let mtu_time = (round_trip - DEFAULT_PER_HOP_TIMEOUT).max(0.0) / 2.0;
    if mtu_time > AIRTIME_AWARE_MTU_TIME {
        next_delivery_attempt += jitter.clamp(0.0, 1.0) * mtu_time;
    }

    AttemptSchedule {
        next_delivery_attempt,
        max_delivery_attempts,
        awaiting_path,
    }
}

/// A cheap jitter source in `[0, 1)` for retry spreading.
pub fn retry_jitter() -> f64 {
    let mut bytes = [0u8; 8];
    rns_crypto::Rng::fill_bytes(&mut rns_crypto::OsRng, &mut bytes);
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn medium(timeout: f64, bitrate: Option<u64>) -> MediumInfo {
        MediumInfo {
            medium_path_timeout: timeout,
            lowest_interface_bitrate: bitrate,
        }
    }

    #[test]
    fn fast_media_use_default_retry_policy() {
        let rt = destination_round_trip(true, DEFAULT_PER_HOP_TIMEOUT, &medium(0.0, None));
        assert_eq!(rt, DEFAULT_PER_HOP_TIMEOUT);
        let schedule = schedule_attempt(100.0, rt, false, 0.5);
        assert_eq!(schedule.next_delivery_attempt, 110.0);
        assert_eq!(schedule.max_delivery_attempts, MAX_DELIVERY_ATTEMPTS);
        assert!(!schedule.awaiting_path);
    }

    #[test]
    fn slow_media_stretch_waits_and_reduce_attempts() {
        // A first hop 20 s above the per-hop allowance: 2*20 + 6 = 46 s.
        let rt = destination_round_trip(true, DEFAULT_PER_HOP_TIMEOUT + 20.0, &medium(0.0, None));
        assert_eq!(rt, 46.0);
        let schedule = schedule_attempt(100.0, rt, false, 0.0);
        assert_eq!(schedule.next_delivery_attempt, 146.0);
        // max(3, round(5*10/46)) = 3
        assert_eq!(schedule.max_delivery_attempts, 3);

        let jittered = schedule_attempt(100.0, rt, false, 0.5);
        assert_eq!(jittered.next_delivery_attempt, 146.0 + 0.5 * 20.0);
    }

    #[test]
    fn path_requests_wait_for_the_medium() {
        let m = medium(30.0, Some(1200));
        let rt = destination_round_trip(false, 0.0, &m);
        assert_eq!(rt, 30.0);
        let schedule = schedule_attempt(0.0, rt, true, 0.0);
        assert_eq!(schedule.next_delivery_attempt, 30.0);
        assert!(schedule.awaiting_path);
        assert!(m.slow_interface_online());
        assert_eq!(m.path_request_window(), PATH_REQUEST_DEBOUNCE as f64);
        assert_eq!(medium(0.0, Some(9600)).path_request_window(), 7.0);
    }

    #[test]
    fn jitter_is_in_unit_interval() {
        for _ in 0..64 {
            let j = retry_jitter();
            assert!((0.0..1.0).contains(&j));
        }
    }
}
