//! TDD: public ask + encrypted OOB bids + on-chain commitment-only view.

use private_inference_rent::ask::{PublicAsk, ResourceAsk};
use private_inference_rent::bid::{EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::dregg::FrostSignerInstance;
use private_inference_rent::frost_pool::FrostThresholdPool;
use private_inference_rent::onchain::OnChainView;
use private_inference_rent::steoffle::SteoffleMpc;
use private_inference_rent::tagged_hash;
use private_inference_rent::workflow::{PrivateComputeWorkflow, WorkflowError};
use private_inference_rent::bid::BidError;

fn demo_ask() -> PublicAsk {
    PublicAsk::new(
        "ask-1",
        "tenant-a",
        include_str!("fixtures/manifest.sdl.yml"),
        ResourceAsk {
            cpu_milli: 1000,
            memory_mib: 4096,
            storage_mib: 10240,
            gpu_units: 1,
        },
        "private-inference",
    )
}

#[test]
fn public_ask_is_posted_with_manifest_and_resources() {
    let ask = demo_ask();
    ask.validate().expect("valid ask");
    assert!(ask.manifest_sdl.contains("services:"));
    assert_ne!(ask.ask_commitment(), [0u8; 32]);
}

#[test]
fn empty_ask_rejected() {
    let mut ask = demo_ask();
    ask.manifest_sdl.clear();
    assert!(ask.validate().is_err());
}

#[test]
fn encrypted_oob_bid_roundtrip_and_commitment() {
    let key = tagged_hash(b"oob", &[b"session"]);
    let bid = PlaintextBid {
        ask_id: "ask-1".into(),
        bidder_identity: "provider-x".into(),
        price_uakt: 99_000,
        provider_endpoint: "direct://provider-x".into(),
    };
    let env = EncryptedBidEnvelope::seal_with_nonce(&bid, &key, [1u8; 16]).unwrap();
    assert!(!env.ciphertext.is_empty());
    assert!(!env.ciphertext.windows(3).any(|w| w == b"99_"));
    let opened = env.open(&key).unwrap();
    assert_eq!(opened, bid);
    env.commitment().verify_against(&env).unwrap();
}

#[test]
fn tenant_label_is_in_ask_commitment() {
    let a = demo_ask();
    let mut b = demo_ask();
    b.tenant_label = "other-tenant".into();
    assert_ne!(a.ask_commitment(), b.ask_commitment());
}

#[test]
fn tampered_ciphertext_fails_mac() {
    let key = tagged_hash(b"oob", &[b"session"]);
    let bid = PlaintextBid {
        ask_id: "ask-1".into(),
        bidder_identity: "provider-x".into(),
        price_uakt: 99_000,
        provider_endpoint: "direct://provider-x".into(),
    };
    let mut env = EncryptedBidEnvelope::seal_with_nonce(&bid, &key, [1u8; 16]).unwrap();
    env.ciphertext[0] ^= 0x01;
    assert_eq!(env.open(&key), Err(BidError::Auth));
}

#[test]
fn on_chain_view_has_only_commitments_and_attestations() {
    let ask = demo_ask();
    let mut view = OnChainView::new(ask);
    let key = tagged_hash(b"oob", &[b"session"]);
    let bid = PlaintextBid {
        ask_id: "ask-1".into(),
        bidder_identity: "secret-provider".into(),
        price_uakt: 123_456,
        provider_endpoint: "oob".into(),
    };
    let env = EncryptedBidEnvelope::seal_with_nonce(&bid, &key, [2u8; 16]).unwrap();
    view.post_commitment(&env.commitment(), [9u8; 32]).unwrap();

    let payload = view.chain_payload().to_string();
    assert!(!payload.contains("secret-provider"));
    assert!(!payload.contains("123456"));
    assert!(!payload.contains("price_uakt"));
    assert!(!payload.contains("bidder_identity"));
    assert!(payload.contains("bid_commitment"));
    assert!(payload.contains("steoffle_attestation"));
    assert!(!view.payload_contains_plaintext_bid());
}

#[test]
fn workflow_ingests_oob_then_posts_commitment_only() {
    let group = tagged_hash(b"frost-group", &[b"g"]);
    let mut wf = PrivateComputeWorkflow::open(
        demo_ask(),
        FrostThresholdPool::new(group, 2, 3).unwrap(),
    )
    .unwrap();
    let signer = FrostSignerInstance::new(
        tagged_hash(b"s", &[b"1"]),
        tagged_hash(b"i", &[b"1"]),
        vec![tagged_hash(b"c", &[b"1"])],
    )
    .unwrap();
    let att = SteoffleMpc::attest(&signer).unwrap();
    wf.enroll_signer(signer).unwrap();
    let key = tagged_hash(b"oob", &[b"k"]);
    let env = EncryptedBidEnvelope::seal_with_nonce(
        &PlaintextBid {
            ask_id: "ask-1".into(),
            bidder_identity: "hid".into(),
            price_uakt: 7,
            provider_endpoint: "oob".into(),
        },
        &key,
        [3u8; 16],
    )
    .unwrap();
    wf.ingest_oob_bid(env, &att).unwrap();
    assert_eq!(wf.view.records.len(), 1);
    assert!(!wf.view.payload_contains_plaintext_bid());
    let opened = wf.open_oob_bid(0, &key).unwrap();
    assert_eq!(opened.price_uakt, 7);
    assert_eq!(wf.open_oob_bid(9, &key), Err(WorkflowError::BidIndex));
    assert!(wf.receipt().steoffle_ok);
}

#[test]
fn ingest_rejects_ask_mismatch_and_unknown_signer() {
    let group = tagged_hash(b"frost-group", &[b"g2"]);
    let mut wf = PrivateComputeWorkflow::open(
        demo_ask(),
        FrostThresholdPool::new(group, 2, 3).unwrap(),
    )
    .unwrap();
    let signer = FrostSignerInstance::new(
        tagged_hash(b"s", &[b"2"]),
        tagged_hash(b"i", &[b"2"]),
        vec![tagged_hash(b"c", &[b"2"])],
    )
    .unwrap();
    let att = SteoffleMpc::attest(&signer).unwrap();
    let key = tagged_hash(b"oob", &[b"k"]);
    let env = EncryptedBidEnvelope::seal_with_nonce(
        &PlaintextBid {
            ask_id: "wrong-ask".into(),
            bidder_identity: "hid".into(),
            price_uakt: 7,
            provider_endpoint: "oob".into(),
        },
        &key,
        [3u8; 16],
    )
    .unwrap();
    assert_eq!(wf.ingest_oob_bid(env, &att), Err(WorkflowError::AskMismatch));

    let env = EncryptedBidEnvelope::seal_with_nonce(
        &PlaintextBid {
            ask_id: "ask-1".into(),
            bidder_identity: "hid".into(),
            price_uakt: 7,
            provider_endpoint: "oob".into(),
        },
        &key,
        [4u8; 16],
    )
    .unwrap();
    assert!(matches!(
        wf.ingest_oob_bid(env, &att),
        Err(WorkflowError::Steoffle(_))
    ));
}
