//! Access secret from OOB session key + bid commitment. Not Akash ES256K JWT.

use private_inference_rent::bid::{EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::{tagged_hash, DerivedAccess};

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
    use private_inference_rent::LeaseBook;
    let (env, win) = envelope();
    let lose = tagged_hash(b"oob", &[b"loser-session"]);
    let c = env.commitment().commitment;
    let w = DerivedAccess::from_session("ask-acc", &win, &c);
    let l = DerivedAccess::from_session("ask-acc", &lose, &c);
    let mut book = LeaseBook::new();
    book.accept_bid("lease-1", w.bearer_hex());
    assert!(book.access("lease-1", &w.bearer_hex()).is_ok());
    assert_eq!(
        book.access("lease-1", &l.bearer_hex()),
        Err(private_inference_rent::LeaseAccessError::Unauthorized)
    );
    book.close("lease-1").unwrap();
    assert_eq!(
        book.access("lease-1", &w.bearer_hex()),
        Err(private_inference_rent::LeaseAccessError::Closed)
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
