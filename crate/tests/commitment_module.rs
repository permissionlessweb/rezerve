//! Bid commitment module: query matches OOB hex; no price_uakt.

use private_inference_rent::ask::{PublicAsk, ResourceAsk};
use private_inference_rent::bid::{EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::hex32;
use private_inference_rent::onchain::CommitmentModule;
use private_inference_rent::zap1::IbcV2PacketAttest;
use private_inference_rent::tagged_hash;

fn ask() -> PublicAsk {
    PublicAsk::new(
        "ask-mod",
        "tenant",
        "version: \"2.0\"\n",
        ResourceAsk {
            cpu_milli: 100,
            memory_mib: 256,
            storage_mib: 512,
            gpu_units: 0,
        },
        "private-llm",
    )
}

#[test]
fn query_bid_matches_oob_commitment_hex() {
    let public = ask();
    let key = tagged_hash(b"session", &[b"mod"]);
    let bid = PlaintextBid {
        ask_id: public.ask_id.clone(),
        bidder_identity: "prov".into(),
        price_uakt: 9_000,
        provider_endpoint: "oob://p".into(),
    };
    let env = EncryptedBidEnvelope::seal(&bid, &key).unwrap();
    let commit = env.commitment();
    let mut m = CommitmentModule::new(public.clone());
    m.post_commitment(&commit, [7u8; 32]).unwrap();
    let rec = m
        .query_bid(&hex32(&public.ask_commitment()), &hex32(&commit.commitment))
        .expect("record");
    assert_eq!(rec.bid_commitment, hex32(&commit.commitment));
    assert_eq!(rec.ask_commitment, hex32(&public.ask_commitment()));
}

#[test]
fn chain_payload_has_no_price_uakt() {
    let public = ask();
    let key = tagged_hash(b"session", &[b"price"]);
    let bid = PlaintextBid {
        ask_id: public.ask_id.clone(),
        bidder_identity: "prov".into(),
        price_uakt: 77_000,
        provider_endpoint: "oob://p".into(),
    };
    let env = EncryptedBidEnvelope::seal(&bid, &key).unwrap();
    let mut m = CommitmentModule::new(public);
    m.post_commitment(&env.commitment(), [1u8; 32]).unwrap();
    let payload = m.view.chain_payload().to_string();
    assert!(!payload.contains("price_uakt"), "{payload}");
    assert!(!m.view.payload_contains_plaintext_bid());
}

#[test]
fn publish_records_packet_and_bid() {
    let public = ask();
    let key = tagged_hash(b"session", &[b"pub"]);
    let bid = PlaintextBid {
        ask_id: public.ask_id.clone(),
        bidder_identity: "prov".into(),
        price_uakt: 3,
        provider_endpoint: "oob://p".into(),
    };
    let env = EncryptedBidEnvelope::seal(&bid, &key).unwrap();
    let pkt = IbcV2PacketAttest::bind(
        "07-tendermint-0",
        "07-tendermint-1",
        1,
        1,
        &[9u8; 32],
        1,
        &[8u8; 32],
        &[7u8; 32],
    );
    let mut m = CommitmentModule::new(public);
    m.publish(&pkt, &env.commitment(), [2u8; 32]).unwrap();
    m.ibc.verify_packet(&pkt).unwrap();
}
