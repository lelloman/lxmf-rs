use std::collections::HashMap;

use lxmf_core::constants::*;
use rns_crypto::sha256::sha256;

use crate::router::now_timestamp;

/// Ticket store managing outbound/inbound tickets and delivery tracking.
pub struct TicketStore {
    /// Outbound tickets: dest_hash -> (expiry, ticket_bytes)
    pub outbound: HashMap<[u8; 16], (f64, Vec<u8>)>,
    /// Inbound tickets: dest_hash -> { ticket_bytes -> expiry }
    pub inbound: HashMap<[u8; 16], HashMap<Vec<u8>, f64>>,
    /// Last delivery timestamps: dest_hash -> timestamp
    pub last_deliveries: HashMap<[u8; 16], f64>,
}

impl TicketStore {
    pub fn new() -> Self {
        Self {
            outbound: HashMap::new(),
            inbound: HashMap::new(),
            last_deliveries: HashMap::new(),
        }
    }

    /// Generate a ticket for a destination.
    ///
    /// Returns `Some((expiry, ticket_bytes))` or `None` if throttled.
    pub fn generate_ticket(&mut self, destination_hash: [u8; 16]) -> Option<(f64, Vec<u8>)> {
        let now = now_timestamp();

        // Throttle: don't generate if delivered less than TICKET_INTERVAL ago
        if let Some(&last) = self.last_deliveries.get(&destination_hash) {
            if (now - last) < TICKET_INTERVAL as f64 {
                return None;
            }
        }

        // Try to reuse an existing inbound ticket with enough validity
        if let Some(tickets) = self.inbound.get(&destination_hash) {
            for (ticket, &expiry) in tickets {
                let validity_left = expiry - now;
                if validity_left > TICKET_RENEW as f64 {
                    return Some((expiry, ticket.clone()));
                }
            }
        }

        // Generate new ticket
        let expires = now + TICKET_EXPIRY as f64;
        let ticket = generate_random_ticket();

        self.inbound
            .entry(destination_hash)
            .or_default()
            .insert(ticket.clone(), expires);

        Some((expires, ticket))
    }

    /// Remember a ticket received from a peer (store as outbound).
    pub fn remember_ticket(&mut self, destination_hash: [u8; 16], expiry: f64, ticket: Vec<u8>) {
        self.outbound.insert(destination_hash, (expiry, ticket));
    }

    /// Get the outbound ticket for a destination if available and not expired.
    pub fn get_outbound_ticket(&self, destination_hash: &[u8; 16]) -> Option<&[u8]> {
        if let Some((expiry, ticket)) = self.outbound.get(destination_hash) {
            if *expiry > now_timestamp() {
                return Some(ticket);
            }
        }
        None
    }

    /// Get the expiry time of an outbound ticket.
    pub fn get_outbound_ticket_expiry(&self, destination_hash: &[u8; 16]) -> Option<f64> {
        if let Some((expiry, _)) = self.outbound.get(destination_hash) {
            if *expiry > now_timestamp() {
                return Some(*expiry);
            }
        }
        None
    }

    /// Get all valid inbound tickets for a destination.
    pub fn get_inbound_tickets(&self, destination_hash: &[u8; 16]) -> Option<Vec<&[u8]>> {
        let now = now_timestamp();
        let tickets = self.inbound.get(destination_hash)?;

        let valid: Vec<&[u8]> = tickets
            .iter()
            .filter(|(_, &expiry)| now < expiry)
            .map(|(ticket, _)| ticket.as_slice())
            .collect();

        if valid.is_empty() {
            None
        } else {
            Some(valid)
        }
    }

    /// Record that a ticket was delivered.
    pub fn record_delivery(&mut self, destination_hash: [u8; 16]) {
        self.last_deliveries.insert(destination_hash, now_timestamp());
    }

    /// Clean expired tickets.
    pub fn clean(&mut self) {
        let now = now_timestamp();

        // Clean outbound
        self.outbound.retain(|_, (expiry, _)| *expiry > now);

        // Clean inbound (with grace period)
        let grace_cutoff = now - TICKET_GRACE as f64;
        for tickets in self.inbound.values_mut() {
            tickets.retain(|_, expiry| *expiry > grace_cutoff);
        }
        self.inbound.retain(|_, tickets| !tickets.is_empty());
    }
}

/// Compute a ticket stamp: truncated_hash(ticket + message_id).
///
/// Returns the first 32 bytes of SHA256(ticket || message_id),
/// then truncated to TICKET_LENGTH (16 bytes) by the caller
/// when used as a stamp.
pub fn ticket_stamp(ticket: &[u8], message_id: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(ticket.len() + message_id.len());
    data.extend_from_slice(ticket);
    data.extend_from_slice(message_id);
    let hash = sha256(&data);
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash[..16]);
    result
}

/// Validate a stamp against available tickets.
///
/// Returns `Some(COST_TICKET)` if any ticket produces a matching stamp,
/// or `None` if no ticket matches.
pub fn validate_stamp_with_tickets(
    stamp: &[u8],
    message_id: &[u8],
    tickets: &[&[u8]],
) -> Option<u32> {
    if stamp.len() < TICKET_LENGTH {
        return None;
    }
    let stamp_truncated = &stamp[..TICKET_LENGTH];

    for ticket in tickets {
        let expected = ticket_stamp(ticket, message_id);
        if stamp_truncated == expected {
            return Some(COST_TICKET);
        }
    }
    None
}

/// Generate a stamp from an outbound ticket.
///
/// Returns the truncated hash that should be used as the message stamp.
pub fn generate_stamp_from_ticket(ticket: &[u8], message_id: &[u8]) -> Vec<u8> {
    let stamp = ticket_stamp(ticket, message_id);
    stamp.to_vec()
}

fn generate_random_ticket() -> Vec<u8> {
    use rns_crypto::{OsRng, Rng};
    let mut ticket = vec![0u8; TICKET_LENGTH];
    OsRng.fill_bytes(&mut ticket);
    ticket
}
