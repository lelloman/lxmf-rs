use std::collections::HashMap;

use lxmf_core::constants::*;
use rns_core::msgpack::Value;
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

impl Default for TicketStore {
    fn default() -> Self {
        Self::new()
    }
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
        self.last_deliveries
            .insert(destination_hash, now_timestamp());
    }

    /// Serialize as upstream's `available_tickets` file:
    /// `{"outbound": {dest: [expires, ticket]}, "inbound": {dest: {ticket:
    /// [expires]}}, "last_deliveries": {dest: timestamp}}`.
    pub fn to_value(&self) -> Value {
        let outbound = self
            .outbound
            .iter()
            .map(|(dest, (expires, ticket))| {
                (
                    Value::Bin(dest.to_vec()),
                    Value::Array(vec![Value::Float(*expires), Value::Bin(ticket.clone())]),
                )
            })
            .collect();
        let inbound = self
            .inbound
            .iter()
            .map(|(dest, tickets)| {
                let tickets = tickets
                    .iter()
                    .map(|(ticket, expires)| {
                        (
                            Value::Bin(ticket.clone()),
                            Value::Array(vec![Value::Float(*expires)]),
                        )
                    })
                    .collect();
                (Value::Bin(dest.to_vec()), Value::Map(tickets))
            })
            .collect();
        let last_deliveries = self
            .last_deliveries
            .iter()
            .map(|(dest, at)| (Value::Bin(dest.to_vec()), Value::Float(*at)))
            .collect();
        Value::Map(vec![
            (Value::Str("outbound".into()), Value::Map(outbound)),
            (Value::Str("inbound".into()), Value::Map(inbound)),
            (
                Value::Str("last_deliveries".into()),
                Value::Map(last_deliveries),
            ),
        ])
    }

    /// Load from upstream's `available_tickets` format; malformed entries
    /// are skipped, as upstream recreates missing sections.
    pub fn from_value(value: &Value) -> Self {
        let mut store = Self::new();
        let Some(map) = value.as_map() else {
            return store;
        };
        let section = |name: &str| {
            map.iter()
                .find(|(k, _)| k.as_str() == Some(name))
                .and_then(|(_, v)| v.as_map())
                .unwrap_or(&[])
        };
        let dest = |value: &Value| -> Option<[u8; 16]> { value.as_bin()?.try_into().ok() };
        for (k, v) in section("outbound") {
            let (Some(dest), Some(entry)) = (dest(k), v.as_array()) else {
                continue;
            };
            if let (Some(expires), Some(ticket)) = (
                entry.first().and_then(Value::as_number),
                entry.get(1).and_then(Value::as_bin),
            ) {
                store.outbound.insert(dest, (expires, ticket.to_vec()));
            }
        }
        for (k, v) in section("inbound") {
            let (Some(dest), Some(tickets)) = (dest(k), v.as_map()) else {
                continue;
            };
            for (ticket, entry) in tickets {
                let expires = entry
                    .as_array()
                    .and_then(|e| e.first())
                    .and_then(Value::as_number);
                if let (Some(ticket), Some(expires)) = (ticket.as_bin(), expires) {
                    store
                        .inbound
                        .entry(dest)
                        .or_default()
                        .insert(ticket.to_vec(), expires);
                }
            }
        }
        for (k, v) in section("last_deliveries") {
            if let (Some(dest), Some(at)) = (dest(k), v.as_number()) {
                store.last_deliveries.insert(dest, at);
            }
        }
        store
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
    // The stamp must equal the ticket stamp exactly (`validate_stamp`).
    for ticket in tickets {
        let expected = ticket_stamp(ticket, message_id);
        if stamp == expected {
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

/// The `FIELD_TICKET` value carried in a message: `[expires, ticket]`.
pub fn ticket_field(expires: f64, ticket: &[u8]) -> (Value, Value) {
    (
        Value::UInt(FIELD_TICKET as u64),
        Value::Array(vec![Value::Float(expires), Value::Bin(ticket.to_vec())]),
    )
}

/// Read an unexpired ticket from message fields (`FIELD_TICKET`).
pub fn ticket_from_fields(fields: &[(Value, Value)], now: f64) -> Option<(f64, Vec<u8>)> {
    let (_, entry) = fields
        .iter()
        .find(|(k, _)| k.as_uint() == Some(FIELD_TICKET as u64))?;
    let entry = entry.as_array()?;
    let expires = entry.first()?.as_number()?;
    let ticket = entry.get(1)?.as_bin()?;
    (now < expires && ticket.len() == TICKET_LENGTH).then(|| (expires, ticket.to_vec()))
}
