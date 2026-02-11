use lxmf_core::announce;

/// Result of processing a delivery announce.
pub struct DeliveryAnnounceResult {
    pub destination_hash: [u8; 16],
    pub stamp_cost: Option<u8>,
}

/// Process a delivery announce event.
///
/// Extracts the stamp cost from app_data and returns it for the router
/// to update its stamp cost cache and trigger outbound processing.
pub fn handle_delivery_announce(
    destination_hash: [u8; 16],
    app_data: Option<&[u8]>,
) -> DeliveryAnnounceResult {
    let stamp_cost = app_data.and_then(|data| announce::stamp_cost_from_app_data(data));

    DeliveryAnnounceResult {
        destination_hash,
        stamp_cost,
    }
}

/// Result of processing a propagation node announce.
pub enum PropagationAnnounceResult {
    /// Peer the node with the given parameters.
    Peer(PropagationPeerInfo),
    /// Unpeer the node (propagation disabled or out of range).
    Unpeer {
        destination_hash: [u8; 16],
        node_timebase: u64,
    },
    /// Ignore the announce.
    Ignore,
}

/// Information extracted from a propagation node announce.
#[derive(Clone)]
pub struct PropagationPeerInfo {
    pub destination_hash: [u8; 16],
    pub node_timebase: u64,
    pub propagation_enabled: bool,
    pub propagation_transfer_limit: u64,
    pub propagation_sync_limit: u64,
    pub propagation_stamp_cost: u8,
    pub propagation_stamp_cost_flexibility: u8,
    pub peering_cost: u8,
    pub metadata: Vec<(rns_core::msgpack::Value, rns_core::msgpack::Value)>,
}

/// Parse a propagation node announce and extract peer info.
pub fn parse_propagation_announce(
    destination_hash: [u8; 16],
    app_data: Option<&[u8]>,
) -> Option<PropagationPeerInfo> {
    let data = app_data?;
    let parsed = announce::parse_pn_announce_data(data)?;

    Some(PropagationPeerInfo {
        destination_hash,
        node_timebase: parsed.node_timebase,
        propagation_enabled: parsed.propagation_enabled,
        propagation_transfer_limit: parsed.propagation_transfer_limit,
        propagation_sync_limit: parsed.propagation_sync_limit,
        propagation_stamp_cost: parsed.propagation_stamp_cost,
        propagation_stamp_cost_flexibility: parsed.propagation_stamp_cost_flexibility,
        peering_cost: parsed.peering_cost,
        metadata: parsed.metadata,
    })
}

/// Decide what action to take for a propagation announce.
///
/// Arguments:
/// - `info`: Parsed announce data
/// - `is_path_response`: Whether this announce came as a path response
/// - `is_static_peer`: Whether this peer is in the static peer list
/// - `is_existing_peer`: Whether we already have this peer
/// - `last_heard`: Last heard timestamp for static peers (0.0 if never)
/// - `autopeer`: Whether auto-peering is enabled
/// - `hops`: Number of hops to this destination (None if unknown)
/// - `autopeer_maxdepth`: Maximum hop count for auto-peering
pub fn decide_propagation_action(
    info: &PropagationPeerInfo,
    is_path_response: bool,
    is_static_peer: bool,
    is_existing_peer: bool,
    last_heard: f64,
    autopeer: bool,
    hops: Option<u8>,
    autopeer_maxdepth: u8,
) -> PropagationAnnounceResult {
    if is_static_peer {
        if !is_path_response || last_heard == 0.0 {
            PropagationAnnounceResult::Peer(info.clone())
        } else {
            PropagationAnnounceResult::Ignore
        }
    } else if autopeer && !is_path_response {
        if info.propagation_enabled {
            if let Some(h) = hops {
                if h <= autopeer_maxdepth {
                    PropagationAnnounceResult::Peer(info.clone())
                } else if is_existing_peer {
                    PropagationAnnounceResult::Unpeer {
                        destination_hash: info.destination_hash,
                        node_timebase: info.node_timebase,
                    }
                } else {
                    PropagationAnnounceResult::Ignore
                }
            } else {
                PropagationAnnounceResult::Peer(info.clone())
            }
        } else {
            PropagationAnnounceResult::Unpeer {
                destination_hash: info.destination_hash,
                node_timebase: info.node_timebase,
            }
        }
    } else {
        PropagationAnnounceResult::Ignore
    }
}
