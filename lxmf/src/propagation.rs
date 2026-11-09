use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;

use lxmf_core::constants::*;
use lxmf_core::stamp::{format_cost, quantize_value, StampValue};
use rns_core::msgpack::Value;
use rns_crypto::sha256::sha256;

use crate::router::now_timestamp;
use crate::storage::atomic_write;

/// A stored propagation message entry.
pub struct PropagationEntry {
    pub destination_hash: [u8; DESTINATION_LENGTH],
    pub filepath: PathBuf,
    pub received: f64,
    pub size: usize,
    pub handled_peers: Vec<[u8; 16]>,
    pub unhandled_peers: Vec<[u8; 16]>,
    pub has_stamp: bool,
    /// Stamp value, quantized onto the cost grid as upstream stores it.
    pub stamp_value: StampValue,
}

/// Peer distribution queue entry.
struct DistributionEntry {
    transient_id: [u8; 32],
    from_peer: Option<[u8; 16]>,
}

/// The propagation node message store.
pub struct PropagationStore {
    pub entries: HashMap<[u8; 32], PropagationEntry>,
    pub messagepath: PathBuf,
    /// Message store size limit in bytes (`message_storage_limit`); `None`
    /// keeps everything until it expires.
    pub storage_limit: Option<usize>,
    distribution_queue: VecDeque<DistributionEntry>,

    // Statistics
    pub client_propagation_messages_received: u64,
    pub client_propagation_messages_served: u64,
    pub unpeered_propagation_incoming: u64,
    pub unpeered_propagation_rx_bytes: u64,
}

impl PropagationStore {
    pub fn new(messagepath: PathBuf, storage_limit: Option<usize>) -> Self {
        let _ = fs::create_dir_all(&messagepath);
        Self {
            entries: HashMap::new(),
            messagepath,
            storage_limit,
            distribution_queue: VecDeque::new(),
            client_propagation_messages_received: 0,
            client_propagation_messages_served: 0,
            unpeered_propagation_incoming: 0,
            unpeered_propagation_rx_bytes: 0,
        }
    }

    /// Scan the message store directory and rebuild entries from filenames.
    pub fn scan_messagestore(&mut self) {
        self.entries.clear();
        let entries = match fs::read_dir(&self.messagepath) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let filename = match path.file_name().and_then(|f| f.to_str()) {
                Some(f) => f.to_string(),
                None => continue,
            };

            // Parse filename: {hex_transient_id}_{timestamp}_{stamp_value}
            // or: {hex_transient_id}_{timestamp}
            let parts: Vec<&str> = filename.splitn(3, '_').collect();
            if parts.len() < 2 {
                continue;
            }

            let hex_id = parts[0];
            if hex_id.len() != 64 {
                continue;
            }

            let transient_id = match hex_to_bytes32(hex_id) {
                Some(id) => id,
                None => continue,
            };

            let received: f64 = match parts[1].parse() {
                Ok(t) => t,
                Err(_) => continue,
            };

            // Since LXMF 1.3 the value component is a quantized float
            // (`_17.25`); older stores wrote integers (`_17`).
            let stamp_value = if parts.len() >= 3 {
                parse_stored_value(parts[2])
            } else {
                StampValue::ZERO
            };
            let has_stamp = stamp_value > StampValue::ZERO;

            // Read destination hash from first 16 bytes of file
            let file_data = match fs::read(&path) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if file_data.len() < DESTINATION_LENGTH {
                continue;
            }

            let mut destination_hash = [0u8; DESTINATION_LENGTH];
            destination_hash.copy_from_slice(&file_data[..DESTINATION_LENGTH]);

            let size = file_data.len();

            self.entries.insert(
                transient_id,
                PropagationEntry {
                    destination_hash,
                    filepath: path,
                    received,
                    size,
                    handled_peers: Vec::new(),
                    unhandled_peers: Vec::new(),
                    has_stamp,
                    stamp_value,
                },
            );
        }
    }

    /// Store a new propagation message.
    ///
    /// `lxm_data` is the raw LXMF data (without stamp).
    /// `stamp_data` is the optional stamp bytes to append for storage.
    /// Returns the transient_id if stored successfully.
    pub fn store_message(
        &mut self,
        lxm_data: &[u8],
        stamp_data: Option<&[u8]>,
        stamp_value: StampValue,
        from_peer: Option<[u8; 16]>,
    ) -> Option<[u8; 32]> {
        if lxm_data.len() < LXMF_OVERHEAD {
            return None;
        }

        let transient_id = sha256(lxm_data);
        let received = now_timestamp();

        // Check for duplicates
        if self.entries.contains_key(&transient_id) {
            return None;
        }

        // Build stored data (lxm_data + optional stamp)
        let stored_data = match stamp_data {
            Some(stamp) => {
                let mut data = Vec::with_capacity(lxm_data.len() + stamp.len());
                data.extend_from_slice(lxm_data);
                data.extend_from_slice(stamp);
                data
            }
            None => lxm_data.to_vec(),
        };
        let has_stamp = stamp_data.is_some();

        // Build filename
        let hex_id = bytes_to_hex(&transient_id);
        let quantized = quantize_value(stamp_value);
        let stamp_value = StampValue::from_fp(quantized.fp());
        let value_component = if stamp_value > StampValue::ZERO {
            format!("_{}", format_cost(quantized))
        } else {
            String::new()
        };
        let filename = format!("{}_{}{}", hex_id, received, value_component);
        let filepath = self.messagepath.join(&filename);

        // Write to disk
        if atomic_write(&filepath, &stored_data).is_err() {
            return None;
        }

        // Extract destination hash
        let mut destination_hash = [0u8; DESTINATION_LENGTH];
        destination_hash.copy_from_slice(&lxm_data[..DESTINATION_LENGTH]);

        let size = stored_data.len();

        self.entries.insert(
            transient_id,
            PropagationEntry {
                destination_hash,
                filepath,
                received,
                size,
                handled_peers: Vec::new(),
                unhandled_peers: Vec::new(),
                has_stamp,
                stamp_value,
            },
        );

        // Enqueue for peer distribution
        self.distribution_queue.push_back(DistributionEntry {
            transient_id,
            from_peer,
        });

        Some(transient_id)
    }

    /// Get total message store size in bytes.
    pub fn storage_size(&self) -> usize {
        self.entries.values().map(|e| e.size).sum()
    }

    /// Get message count.
    pub fn message_count(&self) -> usize {
        self.entries.len()
    }

    /// Clean the message store: expire old messages and cull by weight.
    pub fn clean_messagestore(&mut self, prioritised_list: &[[u8; 16]]) {
        let now = now_timestamp();

        // Phase 1: Expire old messages
        let expired: Vec<[u8; 32]> = self
            .entries
            .iter()
            .filter(|(_, e)| (now - e.received) > MESSAGE_EXPIRY as f64)
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            if let Some(entry) = self.entries.remove(id) {
                let _ = fs::remove_file(&entry.filepath);
            }
        }

        // Phase 2: Weight-based culling
        if let Some(limit) = self
            .storage_limit
            .filter(|limit| self.storage_size() > *limit)
        {
            let bytes_needed = self.storage_size() - limit;
            let mut weighted: Vec<([u8; 32], f64, usize)> = self
                .entries
                .iter()
                .map(|(id, e)| {
                    let weight = get_weight(e, now, prioritised_list);
                    (*id, weight, e.size)
                })
                .collect();

            // Sort by weight descending (highest weight = remove first)
            weighted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            let mut freed = 0usize;
            for (id, _, size) in &weighted {
                if freed >= bytes_needed {
                    break;
                }
                if let Some(entry) = self.entries.remove(id) {
                    let _ = fs::remove_file(&entry.filepath);
                    freed += size;
                }
            }
        }
    }

    /// Process the offer request from a peer.
    ///
    /// Returns the response data to send back.
    pub fn handle_offer(&self, transient_ids: &[[u8; 32]]) -> Value {
        let mut wanted = Vec::new();
        let mut has_all = true;

        for id in transient_ids {
            if !self.entries.contains_key(id) {
                wanted.push(Value::Bin(id.to_vec()));
                has_all = false;
            }
        }

        if has_all {
            // Already have all messages
            Value::Bool(false)
        } else if wanted.len() == transient_ids.len() {
            // Want all messages
            Value::Bool(true)
        } else {
            // Want specific messages
            Value::Array(wanted)
        }
    }

    /// Process a message get request (client download).
    ///
    /// Returns the list of message data to send (stamps stripped).
    pub fn handle_get_wants(
        &mut self,
        dest_hash: &[u8; 16],
        wants: &[[u8; 32]],
        transfer_limit: Option<usize>,
    ) -> Vec<Vec<u8>> {
        let per_message_overhead = 16usize;
        let structure_overhead = 24usize;
        let mut cumulative_size = structure_overhead;
        let mut messages = Vec::new();

        for id in wants {
            if let Some(entry) = self.entries.get(id) {
                if entry.destination_hash != *dest_hash {
                    continue;
                }

                let file_data = match fs::read(&entry.filepath) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                // Strip stamp only when this entry actually has one.
                let lxm_data = if entry.has_stamp && file_data.len() > STAMP_SIZE {
                    &file_data[..file_data.len() - STAMP_SIZE]
                } else {
                    &file_data
                };

                let next_size = cumulative_size + lxm_data.len() + per_message_overhead;

                if let Some(limit) = transfer_limit {
                    if next_size > limit {
                        continue;
                    }
                }

                cumulative_size = next_size;
                messages.push(lxm_data.to_vec());
            }
        }

        self.client_propagation_messages_served += messages.len() as u64;
        messages
    }

    /// List available messages for a destination (for client list request).
    pub fn list_messages_for_dest(&self, dest_hash: &[u8; 16]) -> Vec<([u8; 32], usize)> {
        let mut available = Vec::new();
        for (id, entry) in &self.entries {
            if entry.destination_hash == *dest_hash {
                available.push((*id, entry.size));
            }
        }
        // Sort by size ascending
        available.sort_by_key(|(_, size)| *size);
        available
    }

    /// Delete messages that a client reports it has.
    pub fn handle_get_haves(&mut self, dest_hash: &[u8; 16], haves: &[[u8; 32]]) {
        for id in haves {
            if let Some(entry) = self.entries.get(id) {
                if entry.destination_hash == *dest_hash {
                    let filepath = entry.filepath.clone();
                    self.entries.remove(id);
                    let _ = fs::remove_file(&filepath);
                }
            }
        }
    }

    /// Flush the peer distribution queue.
    ///
    /// Returns entries that should be queued as unhandled for each peer.
    pub fn flush_distribution_queue(&mut self) -> Vec<([u8; 32], Option<[u8; 16]>)> {
        let mut entries = Vec::new();
        while let Some(entry) = self.distribution_queue.pop_front() {
            entries.push((entry.transient_id, entry.from_peer));
        }
        entries
    }

    /// Add a peer to the handled list for a message.
    pub fn add_handled_peer(&mut self, transient_id: &[u8; 32], peer_hash: [u8; 16]) {
        if let Some(entry) = self.entries.get_mut(transient_id) {
            if !entry.handled_peers.contains(&peer_hash) {
                entry.handled_peers.push(peer_hash);
            }
            entry.unhandled_peers.retain(|p| *p != peer_hash);
        }
    }

    /// Add a peer to the unhandled list for a message.
    pub fn add_unhandled_peer(&mut self, transient_id: &[u8; 32], peer_hash: [u8; 16]) {
        if let Some(entry) = self.entries.get_mut(transient_id) {
            if !entry.unhandled_peers.contains(&peer_hash) {
                entry.unhandled_peers.push(peer_hash);
            }
        }
    }
}

/// Calculate message weight for culling priority.
///
/// Higher weight = more likely to be removed.
/// priority_weight: 0.1 for prioritised destinations, 1.0 otherwise.
/// age_weight: older messages have higher weight (min 1.0, age in 4-day units).
fn get_weight(entry: &PropagationEntry, now: f64, prioritised_list: &[[u8; 16]]) -> f64 {
    let age_days = (now - entry.received) / 60.0 / 60.0 / 24.0 / 4.0;
    let age_weight = if age_days > 1.0 { age_days } else { 1.0 };

    let priority_weight = if prioritised_list.contains(&entry.destination_hash) {
        0.1
    } else {
        1.0
    };

    priority_weight * age_weight * entry.size as f64
}

// ============================================================
// Hex conversion helpers
// ============================================================

/// Parse the value component of a message store filename
/// (`quantize_cost(components[2])` upstream).
fn parse_stored_value(component: &str) -> StampValue {
    match component.parse::<f64>() {
        Ok(value) => StampValue::from_fp(lxmf_core::stamp::StampCost::from_f64(value).fp()),
        Err(_) => StampValue::ZERO,
    }
}

fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(result)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
