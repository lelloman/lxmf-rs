use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lxmf_rs::stamper;

#[test]
fn generate_stamp_respects_pre_cancelled_work() {
    let cancel = Arc::new(AtomicBool::new(true));
    let result = stamper::generate_stamp(
        b"cancelled-stamp",
        lxmf_core::stamp::StampCost::from_whole(8),
        1,
        cancel,
    );

    assert!(result.is_none());
}

#[test]
fn cancel_work_sets_cancellation_flag() {
    let cancel = AtomicBool::new(false);
    stamper::cancel_work(&cancel);

    assert!(cancel.load(Ordering::SeqCst));
}

#[test]
fn stamp_job_builds_a_stamped_propagation_container() {
    use lxmf_core::stamp::{stamp_valid, stamp_workblock, StampCost};
    use lxmf_rs::stamper::{run_stamp_job, StampJob};
    use rns_crypto::identity::Identity;

    let sender = Identity::new(&mut rns_crypto::OsRng);
    let recipient = Identity::new(&mut rns_crypto::OsRng);
    let dest = [0x31; 16];
    let packed = lxmf_core::message::pack(
        &dest,
        &[0x32; 16],
        1_700_000_000.0,
        b"t",
        b"c",
        vec![],
        None,
        |data| {
            sender
                .sign(data)
                .map_err(|_| lxmf_core::message::Error::SignError)
        },
    )
    .unwrap();
    let job = StampJob {
        message_hash: packed.message_hash,
        packed: packed.packed,
        stamp_cost: Some(StampCost::from_f64(3.25)),
        ticket_stamp: None,
        propagation: Some((
            recipient.get_public_key().unwrap(),
            StampCost::from_f64(2.5),
        )),
        cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let stamped = run_stamp_job(&job).unwrap();

    // The container holds dest + encrypted(stamped message) + PN stamp, and
    // the recipient can decrypt it back to the stamped message.
    let container =
        rns_core::msgpack::unpack_exact(stamped.propagation_packed.as_ref().unwrap()).unwrap();
    let lxmf_data = container.as_array().unwrap()[1].as_array().unwrap()[0]
        .as_bin()
        .unwrap()
        .to_vec();
    let (body, pn_stamp) = lxmf_data.split_at(lxmf_data.len() - 32);
    assert_eq!(&body[..16], &dest);
    assert_eq!(
        rns_crypto::sha256::sha256(body),
        stamped.transient_id.unwrap()
    );
    let decrypted = recipient.decrypt(&body[16..]).unwrap();
    assert_eq!(&decrypted[..], &stamped.packed[16..]);
    let pn_workblock = stamp_workblock(
        &stamped.transient_id.unwrap(),
        lxmf_core::constants::WORKBLOCK_EXPAND_ROUNDS_PN,
    );
    assert!(stamp_valid(
        pn_stamp,
        StampCost::from_f64(2.5),
        &pn_workblock
    ));
}
