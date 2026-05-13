use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lxmf_rs::stamper;

#[test]
fn generate_stamp_respects_pre_cancelled_work() {
    let cancel = Arc::new(AtomicBool::new(true));
    let result = stamper::generate_stamp(b"cancelled-stamp", 8, 1, cancel);

    assert!(result.is_none());
}

#[test]
fn cancel_work_sets_cancellation_flag() {
    let cancel = AtomicBool::new(false);
    stamper::cancel_work(&cancel);

    assert!(cancel.load(Ordering::SeqCst));
}
