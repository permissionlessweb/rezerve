//! NS6: two parties; loser cannot open winner's envelope.
//! `tenant_hold_key` / `provider_hold_key` are in-process functions, not OS processes.

use private_inference_rent::ask::{PublicAsk, ResourceAsk};
use private_inference_rent::bid::{BidError, EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::onchain::OnChainView;
use private_inference_rent::tagged_hash;
use std::thread;

fn ask() -> PublicAsk {
    PublicAsk::new(
        "ask-ns6",
        "tenant-ns6",
        "version: \"2.0\"\nservices:\n  infer:\n    image: private/infer:1\n",
        ResourceAsk {
            cpu_milli: 1000,
            memory_mib: 2048,
            storage_mib: 4096,
            gpu_units: 0,
        },
        "cpu-infer",
    )
}

fn bid(price: u64, who: &str) -> PlaintextBid {
    PlaintextBid {
        ask_id: "ask-ns6".into(),
        bidder_identity: who.into(),
        price_uakt: price,
        provider_endpoint: format!("oob://{who}"),
    }
}

/// Tenant-side session material. Never returned to provider_hold_key.
fn tenant_hold_key() -> [u8; 32] {
    tagged_hash(b"ns6-tenant-key", &[b"winner"])
}

/// Provider-side (loser) session material. Distinct from tenant_hold_key.
fn provider_hold_key() -> [u8; 32] {
    tagged_hash(b"ns6-provider-key", &[b"loser"])
}

#[test]
fn os_processes_loser_cannot_open_winner() {
    use private_inference_rent::{process_open, process_seal};
    let winner = tagged_hash(b"ns6-os", &[b"win"]);
    let loser = tagged_hash(b"ns6-os", &[b"lose"]);
    let bid = PlaintextBid {
        ask_id: "ask-os".into(),
        bidder_identity: "prov-os".into(),
        price_uakt: 3,
        provider_endpoint: "oob://os".into(),
    };
    let env = process_seal(&bid, &winner).expect("tenant process seal");
    let opened = process_open(&env, &winner).expect("provider process open");
    assert_eq!(opened.price_uakt, 3);
    assert!(process_open(&env, &loser).is_err());
}

#[test]
fn winner_opens_envelope_loser_key_fails_aead() {
    let winner_key = tenant_hold_key();
    let loser_key = provider_hold_key();
    assert_ne!(winner_key, loser_key);

    let winner_env = EncryptedBidEnvelope::seal(&bid(9_000, "winner"), &winner_key).unwrap();
    let loser_env = EncryptedBidEnvelope::seal(&bid(11_000, "loser"), &loser_key).unwrap();

    let opened = winner_env.open(&winner_key).expect("winner key opens winner envelope");
    assert_eq!(opened.price_uakt, 9_000);
    assert_eq!(winner_env.open(&loser_key), Err(BidError::Auth));
    assert_eq!(loser_env.open(&winner_key), Err(BidError::Auth));
}

#[test]
fn tenant_and_provider_hold_keys_are_not_shared() {
    // Two threads stand in for two processes. Not OS processes until later.
    let tenant = thread::spawn(|| tenant_hold_key());
    let provider = thread::spawn(|| provider_hold_key());
    let t = tenant.join().unwrap();
    let p = provider.join().unwrap();
    assert_ne!(t, p, "winner key must not be the provider-held key");
}

#[test]
fn chain_payload_has_no_price_after_two_bid_commitments() {
    let mut view = OnChainView::new(ask());
    let winner_env = EncryptedBidEnvelope::seal(&bid(9_000, "winner"), &tenant_hold_key()).unwrap();
    let loser_env = EncryptedBidEnvelope::seal(&bid(11_000, "loser"), &provider_hold_key()).unwrap();
    view.post_commitment(&winner_env.commitment(), [1u8; 32]).unwrap();
    view.post_commitment(&loser_env.commitment(), [2u8; 32]).unwrap();
    assert_eq!(view.records.len(), 2);

    let payload = view.chain_payload().to_string();
    assert!(
        !payload.contains("price_uakt"),
        "OnChainView::chain_payload must not carry price_uakt: {payload}"
    );
    assert!(!view.payload_contains_plaintext_bid());
}
