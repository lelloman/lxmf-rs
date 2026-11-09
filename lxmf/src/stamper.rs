use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lxmf_core::constants::STAMP_SIZE;
use lxmf_core::stamp::{stamp_valid, stamp_value, stamp_workblock, StampCost, StampValue};
use rns_crypto::OsRng;
use rns_crypto::Rng;

/// Generate a stamp with the given cost using rayon parallel iterators.
///
/// Returns Some((stamp, value)) on success, None if cancelled.
/// The `cancel` flag can be set from another thread to abort work.
/// Costs may be fractional; a stamp is valid when its product is at or below
/// the cost's target, and its reported value is then at least the cost.
pub fn generate_stamp(
    message_id: &[u8],
    stamp_cost: StampCost,
    expand_rounds: u32,
    cancel: Arc<AtomicBool>,
) -> Option<([u8; STAMP_SIZE], StampValue)> {
    let workblock = stamp_workblock(message_id, expand_rounds);

    // Use rayon to search in parallel
    let result: Arc<std::sync::Mutex<Option<[u8; STAMP_SIZE]>>> =
        Arc::new(std::sync::Mutex::new(None));

    let num_threads = rayon::current_num_threads();
    // `done` stops the workers once one finds a stamp; the caller's flag is
    // only read, so it can be reused for further work.
    let done = AtomicBool::new(false);
    let done_ref = &done;
    let cancel_ref = &cancel;
    let result_clone = result.clone();
    let workblock_ref = &workblock;

    rayon::scope(|s| {
        for _ in 0..num_threads {
            let result = result_clone.clone();
            s.spawn(move |_| {
                let mut rng = OsRng;
                let mut nonce = [0u8; STAMP_SIZE];
                loop {
                    if cancel_ref.load(Ordering::Relaxed) || done_ref.load(Ordering::Relaxed) {
                        return;
                    }

                    rng.fill_bytes(&mut nonce);
                    if stamp_valid(&nonce, stamp_cost, workblock_ref) {
                        let mut r = result.lock().unwrap();
                        if r.is_none() {
                            *r = Some(nonce);
                        }
                        done_ref.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            });
        }
    });

    let stamp = result.lock().unwrap().take()?;
    let value = stamp_value(&workblock, &stamp);
    Some((stamp, value))
}

/// Cancel stamp generation work by setting the cancel flag.
pub fn cancel_work(cancel: &AtomicBool) {
    cancel.store(true, Ordering::Relaxed);
}

/// Validate multiple PN stamps in parallel using rayon.
pub fn validate_pn_stamps(
    transient_list: &[Vec<u8>],
    target_cost: StampCost,
) -> Vec<lxmf_core::stamp::PnStampResult> {
    use rayon::prelude::*;

    transient_list
        .par_iter()
        .filter_map(|data| lxmf_core::stamp::validate_pn_stamp(data, target_cost))
        .collect()
}

/// Work for one outbound message awaiting stamps
/// (`process_deferred_stamps`).
pub struct StampJob {
    pub message_hash: [u8; 32],
    pub packed: Vec<u8>,
    /// Cost of the message stamp to generate, if one is still needed.
    pub stamp_cost: Option<StampCost>,
    /// A stamp derived from an outbound ticket, used instead of generating.
    pub ticket_stamp: Option<Vec<u8>>,
    /// Recipient public key and propagation node cost, for propagated
    /// messages: the container is (re)built and propagation-stamped.
    pub propagation: Option<([u8; 64], StampCost)>,
    pub cancel: Arc<AtomicBool>,
}

/// Successful output of a [`StampJob`].
#[derive(Debug, Clone)]
pub struct StampedMessage {
    pub packed: Vec<u8>,
    pub stamp: Option<Vec<u8>>,
    pub propagation_packed: Option<Vec<u8>>,
    pub transient_id: Option<[u8; 32]>,
    pub propagation_stamp: Option<Vec<u8>>,
}

/// Why a [`StampJob`] did not produce stamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampJobError {
    Cancelled,
    InvalidMessage,
    EncryptionFailed,
}

/// Generate the message stamp (or apply a ticket stamp), then for
/// propagated messages encrypt the stamped message for the recipient and
/// generate the propagation stamp over its transient ID.
pub fn run_stamp_job(job: &StampJob) -> Result<StampedMessage, StampJobError> {
    let mut packed = job.packed.clone();
    let mut stamp = None;
    if let Some(ticket_stamp) = &job.ticket_stamp {
        stamp = Some(ticket_stamp.clone());
    } else if let Some(cost) = job.stamp_cost {
        let (generated, _value) = generate_stamp(
            &job.message_hash,
            cost,
            lxmf_core::constants::WORKBLOCK_EXPAND_ROUNDS,
            job.cancel.clone(),
        )
        .ok_or(StampJobError::Cancelled)?;
        stamp = Some(generated.to_vec());
    }
    if let Some(stamp) = &stamp {
        packed = lxmf_core::message::attach_stamp(&packed, stamp)
            .map_err(|_| StampJobError::InvalidMessage)?;
    }

    let mut result = StampedMessage {
        packed,
        stamp,
        propagation_packed: None,
        transient_id: None,
        propagation_stamp: None,
    };
    if let Some((public_key, pn_cost)) = &job.propagation {
        let dest_len = lxmf_core::constants::DESTINATION_LENGTH;
        let recipient = rns_crypto::identity::Identity::from_public_key(public_key)
            .map_err(|_| StampJobError::EncryptionFailed)?;
        let encrypted = recipient
            .encrypt(&result.packed[dest_len..], &mut OsRng)
            .map_err(|_| StampJobError::EncryptionFailed)?;
        let mut lxmf_data = Vec::with_capacity(dest_len + encrypted.len() + STAMP_SIZE);
        lxmf_data.extend_from_slice(&result.packed[..dest_len]);
        lxmf_data.extend_from_slice(&encrypted);
        let transient_id = rns_crypto::sha256::sha256(&lxmf_data);
        if job.cancel.load(Ordering::Relaxed) {
            return Err(StampJobError::Cancelled);
        }
        let (propagation_stamp, _value) = generate_stamp(
            &transient_id,
            *pn_cost,
            lxmf_core::constants::WORKBLOCK_EXPAND_ROUNDS_PN,
            job.cancel.clone(),
        )
        .ok_or(StampJobError::Cancelled)?;
        lxmf_data.extend_from_slice(&propagation_stamp);
        result.propagation_packed = Some(lxmf_core::message::propagation_container(
            lxmf_data,
            crate::router::now_timestamp(),
        ));
        result.transient_id = Some(transient_id);
        result.propagation_stamp = Some(propagation_stamp.to_vec());
    }
    Ok(result)
}
