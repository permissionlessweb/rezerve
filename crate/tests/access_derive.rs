//! Access secret from OOB session key + bid commitment. Not Akash ES256K JWT.

use private_inference_rent::access::SessionAccess;
use private_inference_rent::bid::{EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::{tagged_hash, DerivedAccess, LeaseAccessError, LeaseBook};

fn envelope() -> (EncryptedBidEnvelope, [u8; 32]) {
    let key = tagged_hash(b"oob", &[b"access-session"]);
    let env = EncryptedBidEnvelope::seal(
        &PlaintextBid {
            ask_id: "ask-acc".into(),
            bidder_identity: "prov".into(),
            price_uakt: 1,
            provider_endpoint: "oob://p".into(),
        },
        &key,
    )
    .unwrap();
    (env, key)
}

#[test]
fn winner_session_derives_stable_bearer() {
    let (env, key) = envelope();
    let c = env.commitment().commitment;
    let a = DerivedAccess::from_session("ask-acc", &key, &c);
    let b = DerivedAccess::from_session("ask-acc", &key, &c);
    assert_eq!(a.secret, b.secret);
    assert!(a.verify_bearer_hex(&b.bearer_hex()));
}

#[test]
fn lease_winner_access_loser_denied_then_close() {
    let (env, win) = envelope();
    let lose = tagged_hash(b"oob", &[b"loser-session"]);
    let c = env.commitment().commitment;
    let w = DerivedAccess::from_session("ask-acc", &win, &c);
    let l = DerivedAccess::from_session("ask-acc", &lose, &c);
    let mut book = LeaseBook::new();
    book.accept_bid("lease-1", w.bearer_hex());
    let nonce = [9u8; 32];
    let session = SessionAccess::derive("ask-acc", &win, &c, &nonce);
    book.open_session("lease-1", c, session.bearer_hex()).unwrap();
    assert!(book.access("lease-1", &session.bearer_hex()).is_ok());
    assert!(book.access("lease-1", &w.bearer_hex()).is_ok());
    assert_eq!(
        book.access("lease-1", &l.bearer_hex()),
        Err(LeaseAccessError::Unauthorized)
    );
    book.close("lease-1").unwrap();
    assert_eq!(
        book.access("lease-1", &session.bearer_hex()),
        Err(LeaseAccessError::Closed)
    );
}

#[test]
fn rust_go_interop_vector_ask1_session1_bid2() {
    let session = [1u8; 32];
    let bid = [2u8; 32];
    let a = DerivedAccess::from_session("ask-1", &session, &bid);
    let hex = a.bearer_hex();
    assert_eq!(hex.len(), 64);
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../akash-provider-pir/.pir-bearer-vector"),
        &hex,
    )
    .ok();
}

#[test]
fn loser_session_cannot_derive_winner_bearer() {
    let (env, win) = envelope();
    let lose = tagged_hash(b"oob", &[b"loser-session"]);
    let c = env.commitment().commitment;
    let w = DerivedAccess::from_session("ask-acc", &win, &c);
    let l = DerivedAccess::from_session("ask-acc", &lose, &c);
    assert_ne!(w.secret, l.secret);
    assert!(!l.verify_bearer_hex(&w.bearer_hex()));
}

fn winner_lease(nonce_tag: &[u8]) -> (DerivedAccess, [u8; 32], [u8; 32], [u8; 32]) {
    let (env, key) = envelope();
    let note = env.commitment().commitment;
    let nonce = tagged_hash(b"session-nonce", &[nonce_tag]);
    let lease = DerivedAccess::from_session("ask-acc", &key, &note);
    (lease, key, note, nonce)
}

#[test]
fn winner_session_opens() {
    let (lease, key, note, nonce) = winner_lease(b"winner");
    let session = lease.open_session(&key, &nonce).expect("winner session");
    assert_eq!(session.note, note);
    assert_eq!(lease.bid_commitment, note);
    assert_ne!(session.bearer_hex(), lease.bearer_hex());
    assert!(session.verify_bearer_hex(&session.bearer_hex()));
    let mut book = LeaseBook::new();
    book.open_session("lease-1", note, session.bearer_hex())
        .unwrap();
    assert!(book.access_session("lease-1", &session.bearer_hex()).is_ok());
    assert_eq!(
        book.access_session("lease-1", &lease.bearer_hex()),
        Err(LeaseAccessError::Unauthorized)
    );
}

#[test]
fn second_session_differs() {
    let (lease, key, note, n1) = winner_lease(b"one");
    let n2 = tagged_hash(b"session-nonce", &[b"two"]);
    let s1 = lease.open_session(&key, &n1).unwrap();
    let s2 = lease.open_session(&key, &n2).unwrap();
    assert_ne!(n1, n2);
    assert_ne!(s1.secret, s2.secret);
    assert_ne!(s1.bearer_hex(), s2.bearer_hex());
    assert_eq!(s1.note, s2.note);
    assert_eq!(s2.note, note);
    let mut book = LeaseBook::new();
    book.open_session("lease-1", note, s1.bearer_hex()).unwrap();
    let kept = book.rotate_session("lease-1", s2.bearer_hex()).unwrap();
    assert_eq!(kept, note);
    assert_eq!(book.session_note("lease-1"), Some(note));
    assert_eq!(
        book.access_session("lease-1", &s1.bearer_hex()),
        Err(LeaseAccessError::Unauthorized)
    );
    assert!(book.access_session("lease-1", &s2.bearer_hex()).is_ok());
}

#[test]
fn foreign_session_bearer_denied() {
    let (lease, key, note, nonce) = winner_lease(b"shared");
    let foreign_key = tagged_hash(b"oob", &[b"loser-session"]);
    assert!(lease.open_session(&foreign_key, &nonce).is_none());
    let winner = lease.open_session(&key, &nonce).unwrap();
    let foreign = SessionAccess::derive("ask-acc", &foreign_key, &note, &nonce);
    assert_eq!(foreign.note, note);
    assert_ne!(foreign.bearer_hex(), winner.bearer_hex());
    assert!(!winner.verify_bearer_hex(&foreign.bearer_hex()));
    let mut book = LeaseBook::new();
    book.open_session("lease-1", note, winner.bearer_hex())
        .unwrap();
    assert_eq!(
        book.access_session("lease-1", &foreign.bearer_hex()),
        Err(LeaseAccessError::Unauthorized)
    );
}

#[test]
fn stopped_session_denied() {
    let (lease, key, note, nonce) = winner_lease(b"stop");
    let session = lease.open_session(&key, &nonce).unwrap();
    let mut book = LeaseBook::new();
    book.open_session("lease-1", note, session.bearer_hex())
        .unwrap();
    assert!(book.access_session("lease-1", &session.bearer_hex()).is_ok());
    let kept = book.stop_session("lease-1").unwrap();
    assert_eq!(kept, note);
    assert_eq!(book.session_note("lease-1"), Some(note));
    assert_eq!(
        book.access_session("lease-1", &session.bearer_hex()),
        Err(LeaseAccessError::Closed)
    );
}
