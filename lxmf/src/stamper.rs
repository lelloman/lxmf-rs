use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lxmf_core::stamp::{stamp_valid, stamp_value, stamp_workblock};
use lxmf_core::constants::STAMP_SIZE;
use rns_crypto::OsRng;
use rns_crypto::Rng;

/// Generate a stamp with the given cost using rayon parallel iterators.
///
/// Returns Some((stamp, value)) on success, None if cancelled.
/// The `cancel` flag can be set from another thread to abort work.
pub fn generate_stamp(
    message_id: &[u8],
    stamp_cost: u8,
    expand_rounds: u32,
    cancel: Arc<AtomicBool>,
) -> Option<([u8; STAMP_SIZE], u32)> {
    let workblock = stamp_workblock(message_id, expand_rounds);

    // Use rayon to search in parallel
    let result: Arc<std::sync::Mutex<Option<[u8; STAMP_SIZE]>>> =
        Arc::new(std::sync::Mutex::new(None));

    let num_threads = rayon::current_num_threads();
    let cancel_clone = cancel.clone();
    let result_clone = result.clone();
    let workblock_ref = &workblock;

    rayon::scope(|s| {
        for _ in 0..num_threads {
            let cancel = cancel_clone.clone();
            let result = result_clone.clone();
            s.spawn(move |_| {
                let mut rng = OsRng;
                let mut nonce = [0u8; STAMP_SIZE];
                loop {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    // Check if another thread found a result
                    if result.lock().unwrap().is_some() {
                        return;
                    }

                    rng.fill_bytes(&mut nonce);
                    if stamp_valid(&nonce, stamp_cost, workblock_ref) {
                        let mut r = result.lock().unwrap();
                        if r.is_none() {
                            *r = Some(nonce);
                        }
                        cancel.store(true, Ordering::Relaxed);
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
    target_cost: u8,
) -> Vec<lxmf_core::stamp::PnStampResult> {
    use rayon::prelude::*;

    transient_list
        .par_iter()
        .filter_map(|data| lxmf_core::stamp::validate_pn_stamp(data, target_cost))
        .collect()
}
