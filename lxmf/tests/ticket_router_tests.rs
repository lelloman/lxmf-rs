//! Tickets wired through the router: learning tickets from inbound
//! messages, stamping outbound messages with them, accepting ticket stamps
//! inbound, and persisting them in upstream's `available_tickets` format.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use lxmf_core::constants::*;
use lxmf_core::message;
use lxmf_core::stamp::StampCost;
use lxmf_rs::router::{LxmDelivery, LxmRouter, OutboundMessage, RouterConfig};
use lxmf_rs::tickets::{generate_stamp_from_ticket, ticket_field};
use rns_crypto::identity::Identity;

static NEXT_DIR: AtomicUsize = AtomicUsize::new(1);

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lxmf_tickets_{}_{}_{}",
        name,
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn delivery_hash(identity: &Identity) -> [u8; 16] {
    rns_core::destination::destination_hash(APP_NAME, &["delivery"], Some(identity.hash()))
}

/// A router receiving for `identity`, with the given inbound stamp cost.
fn receiver(dir: &PathBuf, identity: &Identity, cost: Option<f64>) -> LxmRouter {
    let mut router = LxmRouter::new(
        Identity::from_private_key(&identity.get_private_key().unwrap()),
        RouterConfig {
            storagepath: dir.clone(),
            enforce_stamps: true,
            ..RouterConfig::default()
        },
    );
    router.delivery_dest_hash = Some(delivery_hash(identity));
    router.set_inbound_stamp_cost(cost);
    router
}

fn signed(
    from: &Identity,
    to: [u8; 16],
    fields: Vec<(rns_core::msgpack::Value, rns_core::msgpack::Value)>,
    stamp: Option<&[u8]>,
) -> message::PackResult {
    message::pack(
        &to,
        &delivery_hash(from),
        1_700_000_000.0,
        b"t",
        b"c",
        fields,
        stamp,
        |data| from.sign(data).map_err(|_| message::Error::SignError),
    )
    .unwrap()
}

fn capture(router: &mut LxmRouter) -> Arc<Mutex<Vec<(Option<bool>, Option<f64>)>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    router.set_delivery_callback(Box::new(move |d: &LxmDelivery| {
        sink.lock().unwrap().push((d.stamp_valid, d.stamp_value));
    }));
    seen
}

#[test]
fn tickets_round_trip_through_router_and_persist() {
    let dir = temp_dir("roundtrip");
    let alice = Identity::new(&mut rns_crypto::OsRng);
    let bob = Identity::new(&mut rns_crypto::OsRng);

    // Bob issues a ticket to Alice and sends it in a message.
    let mut bob_router = receiver(&temp_dir("bob"), &bob, None);
    let (expires, ticket) = bob_router.generate_ticket(delivery_hash(&alice)).unwrap();
    assert!(
        bob_router.generate_ticket(delivery_hash(&alice)).unwrap().1 == ticket,
        "a ticket with enough validity is reused"
    );

    // Alice learns it from the signed message.
    let mut alice_router = receiver(&dir, &alice, None);
    alice_router
        .identity_cache
        .insert(delivery_hash(&bob), bob.get_public_key().unwrap());
    let packed = signed(
        &bob,
        delivery_hash(&alice),
        vec![ticket_field(expires, &ticket)],
        None,
    );
    alice_router.lxmf_delivery(&packed.packed, true, "Curve25519", DeliveryMethod::Direct);
    assert_eq!(
        alice_router
            .tickets
            .get_outbound_ticket(&delivery_hash(&bob)),
        Some(&ticket[..])
    );

    // Persisted in upstream's format and reloaded on start.
    let reloaded = receiver(&dir, &alice, None);
    assert_eq!(
        reloaded.tickets.get_outbound_ticket(&delivery_hash(&bob)),
        Some(&ticket[..])
    );

    // Alice's message to Bob is stamped with the ticket instead of
    // proof-of-work, even though Bob announced a stamp cost.
    let to_bob = signed(&alice, delivery_hash(&bob), vec![], None);
    let mut msg = OutboundMessage::new(
        delivery_hash(&bob),
        delivery_hash(&alice),
        to_bob.packed,
        to_bob.message_hash,
        DeliveryMethod::Opportunistic,
    );
    msg.stamp_cost = Some(StampCost::from_whole(24));
    alice_router.handle_outbound(msg).unwrap();
    let queued = &alice_router.outbound[0];
    assert_eq!(
        queued.state,
        MessageState::Outbound,
        "no proof-of-work needed"
    );
    assert_eq!(
        queued.stamp.as_deref(),
        Some(&generate_stamp_from_ticket(&ticket, &to_bob.message_hash)[..])
    );

    // Bob, enforcing a cost of 24, accepts it with the ticket value.
    bob_router.set_inbound_stamp_cost(Some(24.0));
    bob_router
        .identity_cache
        .insert(delivery_hash(&alice), alice.get_public_key().unwrap());
    let seen = capture(&mut bob_router);
    let stamped = alice_router.outbound[0].packed.clone();
    bob_router.lxmf_delivery(&stamped, true, "Curve25519", DeliveryMethod::Opportunistic);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(Some(true), Some(COST_TICKET as f64))]
    );
}

#[test]
fn stamps_are_validated_and_reported_whenever_a_cost_is_set() {
    let alice = Identity::new(&mut rns_crypto::OsRng);
    let bob = Identity::new(&mut rns_crypto::OsRng);
    let mut bob_router = receiver(&temp_dir("validate"), &bob, Some(2.5));
    bob_router.config.enforce_stamps = false;
    let seen = capture(&mut bob_router);

    // Unstamped: accepted when not enforcing, reported invalid.
    let plain = signed(&alice, delivery_hash(&bob), vec![], None);
    bob_router.lxmf_delivery(&plain.packed, true, "Curve25519", DeliveryMethod::Direct);
    assert_eq!(*seen.lock().unwrap(), vec![(Some(false), None)]);

    // The same message stamped at the cost (the stamp is not part of the
    // message hash, so it is checked by a fresh receiver below).
    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (stamp, _) = lxmf_rs::stamper::generate_stamp(
        &plain.message_hash,
        StampCost::from_f64(2.5),
        WORKBLOCK_EXPAND_ROUNDS,
        cancel,
    )
    .unwrap();
    let stamped = message::attach_stamp(&plain.packed, &stamp).unwrap();

    // With enforcement on, an unstamped message is dropped.
    let mut enforcing = receiver(&temp_dir("enforce"), &bob, Some(2.5));
    let seen = capture(&mut enforcing);
    enforcing.lxmf_delivery(&plain.packed, true, "Curve25519", DeliveryMethod::Direct);
    assert!(seen.lock().unwrap().is_empty());
    enforcing.lxmf_delivery(&stamped, true, "Curve25519", DeliveryMethod::Direct);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, Some(true));
    assert!(seen[0].1.unwrap() >= 2.5);
}
