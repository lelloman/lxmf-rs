//! Inbound delivery details: paper message ingestion, unverified reasons,
//! callbacks outside the router lock, and rejected outbound resources.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lxmf_core::constants::*;
use lxmf_core::message;
use lxmf_rs::router::{
    LxmDelivery, LxmRouter, LxmfCallbacks, OutboundMessage, RouterConfig, UnverifiedReason,
};
use rns_core::types::LinkId;
use rns_crypto::identity::Identity;
use rns_net::driver::Callbacks;

static NEXT_DIR: AtomicUsize = AtomicUsize::new(1);

fn router_for(identity: &Identity, cost: Option<f64>) -> (LxmRouter, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "lxmf_delivery_{}_{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut router = LxmRouter::new(
        Identity::from_private_key(&identity.get_private_key().unwrap()),
        RouterConfig {
            storagepath: dir.clone(),
            enforce_stamps: true,
            ..RouterConfig::default()
        },
    );
    router.delivery_dest_hash = Some(dest(identity));
    router.set_inbound_stamp_cost(cost);
    (router, dir)
}

fn dest(identity: &Identity) -> [u8; 16] {
    rns_core::destination::destination_hash(APP_NAME, &["delivery"], Some(identity.hash()))
}

fn packed(from: &Identity, to: [u8; 16], title: &[u8]) -> message::PackResult {
    message::pack(
        &to,
        &dest(from),
        1_700_000_000.0,
        title,
        b"body",
        vec![],
        None,
        |d| from.sign(d).map_err(|_| message::Error::SignError),
    )
    .unwrap()
}

type Seen = Arc<Mutex<Vec<(Vec<u8>, DeliveryMethod, Option<UnverifiedReason>)>>>;

fn capture(router: &mut LxmRouter) -> Seen {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    router.set_delivery_callback(Box::new(move |d: &LxmDelivery| {
        sink.lock()
            .unwrap()
            .push((d.title.clone(), d.method, d.unverified_reason));
    }));
    seen
}

fn paper_uri(from: &Identity, to: &Identity, title: &[u8]) -> String {
    let message = packed(from, dest(to), title);
    let recipient = Identity::from_public_key(&to.get_public_key().unwrap()).unwrap();
    let paper = message::paper_pack(&message.packed, |data| {
        recipient
            .encrypt(data, &mut rns_crypto::OsRng)
            .map_err(|_| message::Error::EncryptError)
    })
    .unwrap();
    message::as_uri(&paper)
}

#[test]
fn paper_messages_are_ingested_without_stamp_enforcement() {
    let alice = Identity::new(&mut rns_crypto::OsRng);
    let bob = Identity::new(&mut rns_crypto::OsRng);
    let (mut bob_router, _dir) = router_for(&bob, Some(20.0));
    bob_router
        .identity_cache
        .insert(dest(&alice), alice.get_public_key().unwrap());
    let seen = capture(&mut bob_router);

    // Upper-case scheme and line-break slashes are accepted, as upstream.
    let uri = paper_uri(&alice, &bob, b"paper");
    let (scheme, data) = uri.split_at(6);
    let wrapped = format!("{}{}/{}", scheme.to_uppercase(), &data[..10], &data[10..]);
    assert!(bob_router.ingest_lxm_uri(&wrapped, false).is_some());
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(b"paper".to_vec(), DeliveryMethod::Paper, None)],
        "delivered unstamped despite the enforced cost"
    );

    assert!(
        bob_router.ingest_lxm_uri(&uri, false).is_none(),
        "duplicate"
    );
    assert!(
        bob_router.ingest_lxm_uri(&uri, true).is_some(),
        "allowed duplicate"
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert!(bob_router
        .ingest_lxm_uri("http://not-a-message", false)
        .is_none());
}

#[test]
fn unverified_messages_report_why() {
    let alice = Identity::new(&mut rns_crypto::OsRng);
    let mallory = Identity::new(&mut rns_crypto::OsRng);
    let bob = Identity::new(&mut rns_crypto::OsRng);
    let (mut bob_router, _dir) = router_for(&bob, None);
    let seen = capture(&mut bob_router);

    let unknown = packed(&alice, dest(&bob), b"unknown");
    bob_router.lxmf_delivery(&unknown.packed, true, "Curve25519", DeliveryMethod::Direct);

    // Alice's key is known now, but this message was signed by someone else.
    bob_router
        .identity_cache
        .insert(dest(&alice), alice.get_public_key().unwrap());
    let mut forged = packed(&mallory, dest(&bob), b"forged");
    forged.packed[16..32].copy_from_slice(&dest(&alice));
    bob_router.lxmf_delivery(&forged.packed, true, "Curve25519", DeliveryMethod::Direct);

    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].2, Some(UnverifiedReason::SourceUnknown));
    assert_eq!(seen[1].2, Some(UnverifiedReason::SignatureInvalid));
}

#[test]
fn delivery_callbacks_run_without_the_router_lock() {
    let alice = Identity::new(&mut rns_crypto::OsRng);
    let bob = Identity::new(&mut rns_crypto::OsRng);
    let (bob_router, _dir) = router_for(&bob, None);
    let router = Arc::new(Mutex::new(bob_router));
    let link = [0x44; 16];
    router
        .lock()
        .unwrap()
        .link_destinations
        .insert(link, dest(&bob));

    // The callback uses the router, which would deadlock under its lock.
    let delivered = Arc::new(AtomicUsize::new(0));
    let (cb_router, cb_delivered) = (router.clone(), delivered.clone());
    router
        .lock()
        .unwrap()
        .set_delivery_callback(Box::new(move |_d: &LxmDelivery| {
            let _ = cb_router.lock().unwrap().outbound.len();
            cb_delivered.fetch_add(1, Ordering::SeqCst);
        }));

    let mut callbacks = LxmfCallbacks::new(router.clone());
    let message = packed(&alice, dest(&bob), b"over link");
    callbacks.on_link_data(LinkId(link), 0, message.packed);

    let deadline = Instant::now() + Duration::from_secs(5);
    while delivered.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "callback deadlocked or never ran"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn rejected_resources_fail_the_message() {
    let bob = Identity::new(&mut rns_crypto::OsRng);
    let (mut router, _dir) = router_for(&bob, None);
    let link = [0x55; 16];
    let mut msg = OutboundMessage::new(
        [0x66; 16],
        dest(&bob),
        vec![0; 900],
        [0x77; 32],
        DeliveryMethod::Direct,
    );
    let failed = Arc::new(AtomicUsize::new(0));
    let counter = failed.clone();
    msg.failed_callback = Some(Box::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    msg.state = MessageState::Sending;
    msg.link_id = Some(link);
    router.outbound.push(msg);
    let router = Arc::new(Mutex::new(router));
    let mut callbacks = LxmfCallbacks::new(router.clone());

    callbacks.on_resource_failed(LinkId(link), "Resource rejected".into());
    assert_eq!(
        router.lock().unwrap().outbound[0].state,
        MessageState::Rejected
    );
}
