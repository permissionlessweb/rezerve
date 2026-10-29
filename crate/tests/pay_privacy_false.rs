//! Adversarial cases for session access, two-proxy retrieval, and stalled close.
//! A passing run means the check rejected the false claim. A failure names the gap.

use private_inference_rent::access::SessionAccess;
use private_inference_rent::bid_ask_pir::{fetch_row, BidAskDb, ProviderProxy, Row, ROW_LEN};
use private_inference_rent::frost_dkg::dkg_three_party;
use private_inference_rent::zcash_escrow::{
    record_frost_close_stall, ShieldedNote, ZcashEscrowError,
};
use private_inference_rent::{tagged_hash, DerivedAccess, LeaseAccessError, LeaseBook};

fn note_and_key() -> (DerivedAccess, [u8; 32], [u8; 32]) {
    let key = tagged_hash(b"oob", &[b"false-pos"]);
    let note = tagged_hash(b"bid", &[b"false-pos-note"]);
    let lease = DerivedAccess::from_session("ask-fp", &key, &note);
    (lease, key, note)
}

#[test]
fn lease_bearer_still_opens_after_a_session_is_added() {
    let (lease, key, note) = note_and_key();
    let session = lease.open_session(&key, &[1u8; 32]).unwrap();
    let mut book = LeaseBook::new();
    book.accept_bid("L", lease.bearer_hex());
    book.open_session("L", note, session.bearer_hex()).unwrap();
    assert!(book.access("L", &lease.bearer_hex()).is_ok());
    assert!(book.access("L", &session.bearer_hex()).is_ok());
}

#[test]
fn rotated_session_bearer_is_not_still_valid() {
    let (lease, key, note) = note_and_key();
    let first = lease.open_session(&key, &[1u8; 32]).unwrap();
    let second = lease.open_session(&key, &[2u8; 32]).unwrap();
    let mut book = LeaseBook::new();
    book.accept_bid("L", lease.bearer_hex());
    book.open_session("L", note, first.bearer_hex()).unwrap();
    book.rotate_session("L", second.bearer_hex()).unwrap();
    assert_eq!(
        book.access("L", &first.bearer_hex()),
        Err(LeaseAccessError::Unauthorized)
    );
    assert!(book.access("L", &second.bearer_hex()).is_ok());
}

#[test]
fn stopped_session_does_not_remain_open_through_access() {
    let (lease, key, note) = note_and_key();
    let session = lease.open_session(&key, &[3u8; 32]).unwrap();
    let mut book = LeaseBook::new();
    book.accept_bid("L", lease.bearer_hex());
    book.open_session("L", note, session.bearer_hex()).unwrap();
    book.stop_session("L").unwrap();
    assert_eq!(
        book.access("L", &session.bearer_hex()),
        Err(LeaseAccessError::Closed)
    );
    assert!(
        book.access("L", &lease.bearer_hex()).is_ok(),
        "stopping a session must not kill the lease bearer"
    );
}

#[test]
fn session_on_a_different_note_is_rejected() {
    let (lease, key, note) = note_and_key();
    let session = lease.open_session(&key, &[4u8; 32]).unwrap();
    let mut book = LeaseBook::new();
    book.open_session("L", note, session.bearer_hex()).unwrap();
    let other = tagged_hash(b"bid", &[b"other-note"]);
    let err = book.open_session("L", other, session.bearer_hex());
    assert_eq!(err, Err(LeaseAccessError::Unauthorized));
    assert_eq!(book.session_note("L"), Some(note));
}

#[test]
fn close_denies_session_and_lease_bearer() {
    let (lease, key, note) = note_and_key();
    let session = SessionAccess::derive("ask-fp", &key, &note, &[5u8; 32]);
    let mut book = LeaseBook::new();
    book.accept_bid("L", lease.bearer_hex());
    book.open_session("L", note, session.bearer_hex()).unwrap();
    book.close("L").unwrap();
    assert_eq!(
        book.access("L", &session.bearer_hex()),
        Err(LeaseAccessError::Closed)
    );
    assert_eq!(
        book.access("L", &lease.bearer_hex()),
        Err(LeaseAccessError::Closed)
    );
}

#[test]
fn foreign_key_session_does_not_open_the_winner_note() {
    let (lease, key, note) = note_and_key();
    let nonce = [6u8; 32];
    assert!(lease
        .open_session(&tagged_hash(b"oob", &[b"nope"]), &nonce)
        .is_none());
    let foreign = SessionAccess::derive("ask-fp", &tagged_hash(b"oob", &[b"nope"]), &note, &nonce);
    let winner = lease.open_session(&key, &nonce).unwrap();
    let mut book = LeaseBook::new();
    book.open_session("L", note, winner.bearer_hex()).unwrap();
    assert_eq!(
        book.access("L", &foreign.bearer_hex()),
        Err(LeaseAccessError::Unauthorized)
    );
}

fn db() -> BidAskDb {
    BidAskDb::new(vec![
        Row::from_bytes(b"ask-0"),
        Row::from_bytes(b"sealed-bid-1"),
        Row::from_bytes(b"ask-2"),
    ])
}

#[test]
fn one_proxy_answer_is_not_the_requested_row() {
    let mut proxy = ProviderProxy::new(db());
    let mask = vec![1u8, 0, 1];
    let answer = proxy.answer(private_inference_rent::bid_ask_pir::ProxyQuery { bits: mask });
    let row = Row::from_bytes(b"sealed-bid-1");
    assert_ne!(answer.bytes, *row.as_bytes());
}

#[test]
fn fetch_returns_only_the_chosen_row() {
    let want = *Row::from_bytes(b"sealed-bid-1").as_bytes();
    let other = *Row::from_bytes(b"ask-0").as_bytes();
    let mut left = ProviderProxy::new(db());
    let mut right = ProviderProxy::new(db());
    let mask = vec![1u8, 0, 1];
    let got = fetch_row(&mut left, &mut right, 1, &mask).unwrap();
    assert_eq!(got, want);
    assert_ne!(got, other);
    assert!(left.log().hides_index(1, 3));
    assert!(right.log().hides_index(1, 3));
}

#[test]
fn colluding_proxies_can_recover_the_index() {
    let mut left = ProviderProxy::new(db());
    let mut right = ProviderProxy::new(db());
    let mask = vec![1u8, 0, 1];
    fetch_row(&mut left, &mut right, 1, &mask).unwrap();
    let a = &left.log().queries[0].bits;
    let b = &right.log().queries[0].bits;
    let mut xor = vec![0u8; a.len()];
    for i in 0..a.len() {
        xor[i] = a[i] ^ b[i];
    }
    assert_eq!(xor, vec![0, 1, 0], "collusion recovers the index bit");
}

#[test]
fn bad_pir_shapes_fail_closed() {
    let mut left = ProviderProxy::new(db());
    let mut right = ProviderProxy::new(db());
    assert!(fetch_row(&mut left, &mut right, 3, &[0, 0, 0]).is_err());
    assert!(fetch_row(&mut left, &mut right, 0, &[0, 0]).is_err());
    let mut empty_l = ProviderProxy::new(BidAskDb::new(vec![]));
    let mut empty_r = ProviderProxy::new(BidAskDb::new(vec![]));
    assert!(fetch_row(&mut empty_l, &mut empty_r, 0, &[]).is_err());
}

#[test]
fn unit_vector_query_is_not_called_hidden() {
    let mut proxy = ProviderProxy::new(db());
    proxy.answer(private_inference_rent::bid_ask_pir::ProxyQuery {
        bits: vec![0, 1, 0],
    });
    assert!(!proxy.log().hides_index(1, 3));
}

#[test]
fn mismatched_proxy_databases_do_not_return_a_real_row() {
    let mut left = ProviderProxy::new(db());
    let mut right = ProviderProxy::new(BidAskDb::new(vec![
        Row::from_bytes(b"other-0"),
        Row::from_bytes(b"other-1"),
        Row::from_bytes(b"other-2"),
    ]));
    let got = fetch_row(&mut left, &mut right, 1, &[0, 0, 0]).unwrap();
    assert_ne!(&got[..13], b"sealed-bid-1");
    let _ = ROW_LEN;
}

#[test]
fn stall_finish_uses_heights_and_rejects_a_short_deposit() {
    let group = dkg_three_party().expect("dkg");
    let note = ShieldedNote {
        group_id: group.verifying_key,
        commitment: tagged_hash(b"close-challenge", &[b"fp-note"]),
        amount_zat: 100,
        tip: "lab".into(),
        z_addr: String::new(),
        txid: String::new(),
        ironwood_note: Vec::new(),
    };
    let seats = group.seats();
    let stalled = record_frost_close_stall(&group, &seats[..1], &note, 10, 50, 1).unwrap();
    assert_eq!(stalled.finish_amounts(100).unwrap(), (40, 60));
    assert!(stalled.finish_amounts(39).is_err());
    assert_eq!(
        stalled.try_pay_provider(40).unwrap_err(),
        ZcashEscrowError::FrostCloseStalled { have: 1, need: 2 }
    );
    assert!(record_frost_close_stall(&group, &seats[..2], &note, 10, 50, 1).is_err());
    let mut over = note.clone();
    over.amount_zat = 10;
    assert!(record_frost_close_stall(&group, &seats[..1], &over, 10, 50, 1).is_err());
}

#[test]
fn dealer_group_cannot_record_a_stall() {
    use private_inference_rent::frost::FrostGroup;
    let dealer = FrostGroup::dealer(3, 2).expect("dealer group");
    assert!(dealer.is_dealer());
    let note = ShieldedNote {
        group_id: dealer.verifying_key,
        commitment: [7u8; 32],
        amount_zat: 100,
        tip: "lab".into(),
        z_addr: String::new(),
        txid: String::new(),
        ironwood_note: Vec::new(),
    };
    assert!(record_frost_close_stall(&dealer, &[], &note, 1, 2, 1).is_err());
}
