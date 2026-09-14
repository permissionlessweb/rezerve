//! Predictive product-path cases from `docs/PRODUCT_PATH.md`.
//! Imports shipped crate names only. Missing contract symbols are an intended compile fail.

use private_inference_rent::ask::{PublicAsk, ResourceAsk};
use private_inference_rent::bid::{BidError, EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::committee::demo_layered_committees;
use private_inference_rent::frost_pool::FrostThresholdPool;
use private_inference_rent::hashmerchant::DepositAttestation;
use private_inference_rent::workflow::PrivateComputeWorkflow;
use private_inference_rent::{tagged_hash, SpendAuth};

fn public_ask(id: &str) -> PublicAsk {
    PublicAsk::new(
        id,
        format!("tenant-{id}"),
        "version: \"2.0\"\nservices:\n  inference:\n    image: private/infer:1\n",
        ResourceAsk {
            cpu_milli: 2000,
            memory_mib: 8192,
            storage_mib: 20480,
            gpu_units: 1,
        },
        "private-llm",
    )
}

fn plaintext_bid(ask_id: &str, price_uakt: u64) -> PlaintextBid {
    PlaintextBid {
        ask_id: ask_id.into(),
        bidder_identity: "prov-west".into(),
        price_uakt,
        provider_endpoint: "oob://prov-west".into(),
    }
}

fn session_key() -> [u8; 32] {
    tagged_hash(b"product-path-session", &[b"key"])
}

fn layered_pool(group: [u8; 32]) -> FrostThresholdPool {
    FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .allow_sim_transcript()
        .with_layered(demo_layered_committees().unwrap())
}

fn matching_parts() -> [(&'static str, &'static [&'static str]); 2] {
    [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ]
}

fn product_attestation(
    group: [u8; 32],
    note: [u8; 32],
    amount_zat: u64,
) -> DepositAttestation {
    DepositAttestation::prove_for_test(
        tagged_hash(b"zcash-root", &[b"product-path"]),
        note,
        amount_zat,
        group,
    )
}

fn spend_auth(
    pool: &FrostThresholdPool,
    group: [u8; 32],
    note: [u8; 32],
    amount_zat: u64,
    bid: Option<[u8; 32]>,
) -> SpendAuth {
    let outer = pool.layered.as_ref().expect("layered product pool");
    let parts = matching_parts();
    SpendAuth::from_quorum(outer, &parts, group, note, amount_zat, bid).expect("from_quorum")
}

#[test]
fn sealed_bid_roundtrip_opens_plaintext() {
    let key = session_key();
    let bid = plaintext_bid("ask-product", 42_000);
    let env = EncryptedBidEnvelope::seal(&bid, &key).expect("seal generates nonce");
    assert_ne!(env.nonce, [0u8; 16]);
    let opened = env.open(&key).expect("open");
    assert_eq!(opened, bid);
}

#[test]
fn aead_tamper_of_ciphertext_is_auth_error() {
    let key = session_key();
    let mut env = EncryptedBidEnvelope::seal(&plaintext_bid("ask-product", 9), &key).unwrap();
    env.ciphertext[0] ^= 0x01;
    assert_eq!(env.open(&key), Err(BidError::Auth));
}

#[test]
fn chain_payload_has_no_price_uakt() {
    let group = tagged_hash(b"frost-group", &[b"payload"]);
    let mut wf = PrivateComputeWorkflow::open(public_ask("ask-payload"), layered_pool(group)).unwrap();
    let env = EncryptedBidEnvelope::seal(&plaintext_bid("ask-payload", 77_000), &session_key()).unwrap();
    let att = wf.pool.layered.as_ref().unwrap().inners[0].seats[0]
        .attestation
        .clone();
    wf.ingest_oob_bid(env, &att).unwrap();

    let payload = wf.view.chain_payload().to_string();
    assert!(
        !payload.contains("price_uakt"),
        "on-chain payload must not include price_uakt: {payload}"
    );
    assert!(!wf.view.payload_contains_plaintext_bid());
}

#[test]
fn on_chain_record_does_not_treat_stoffel_confirm_as_private_attest() {
    let group = tagged_hash(b"frost-group", &[b"no-stoffel-claim"]);
    let mut wf = PrivateComputeWorkflow::open(public_ask("ask-ns"), layered_pool(group)).unwrap();
    let env = EncryptedBidEnvelope::seal(&plaintext_bid("ask-ns", 11), &session_key()).unwrap();
    let att = wf.pool.layered.as_ref().unwrap().inners[0].seats[0]
        .attestation
        .clone();
    let rec = wf.ingest_oob_bid(env, &att).unwrap();
    assert!(
        rec.stoffel_confirm.is_empty(),
        "product ingest must not bind a stoffel_confirm private-MPC claim"
    );
}

#[test]
fn spend_auth_from_quorum_binds_group_note_amount_and_optional_bid() {
    let group = tagged_hash(b"frost-group", &[b"bind"]);
    let note = tagged_hash(b"note", &[b"bind"]);
    let bid = tagged_hash(b"bid-commit-v1", &[b"bind"]);
    let pool = layered_pool(group);
    let auth = spend_auth(&pool, group, note, 1_000, Some(bid));
    assert_eq!(auth.group_id, group);
    assert_eq!(auth.note, note);
    assert_eq!(auth.amount_zat, 1_000);
    assert_eq!(auth.bid_commitment, Some(bid));
}

#[test]
fn from_quorum_rejects_labels_that_do_not_bind_note_and_amount() {
    let group = tagged_hash(b"frost-group", &[b"unbound-fields"]);
    let pool = layered_pool(group);
    let outer = pool.layered.as_ref().unwrap();
    let parts = matching_parts();
    let err = SpendAuth::from_quorum(outer, &parts, group, [0u8; 32], 0, None);
    assert!(err.is_err(), "zero amount / zero note must not mint SpendAuth");
}

#[test]
fn authorize_spend_rejects_auth_for_wrong_group() {
    let group = tagged_hash(b"frost-group", &[b"auth-group"]);
    let other = tagged_hash(b"frost-group", &[b"other-group"]);
    let note = tagged_hash(b"note", &[b"auth-group"]);
    let pool = layered_pool(group);
    let other_pool = layered_pool(other);
    let auth = spend_auth(&other_pool, other, note, 500, None);
    assert!(pool.authorize_spend(&auth).is_err());
}

#[test]
fn product_credit_rejects_prove_for_test_without_sim_flag() {
    let group = tagged_hash(b"frost-group", &[b"ns1"]);
    let note = tagged_hash(b"note", &[b"ns1"]);
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap());
    let att = product_attestation(group, note, 1_000);
    let auth = spend_auth(&pool, group, note, 1_000, None);
    let err = pool.credit_deposit(&att, &auth);
    assert!(err.is_err(), "product path must reject sim transcript");
    assert_eq!(pool.balance_zat, 0);
    let bundle = private_inference_rent::local_hosting_bundle(group, note, 1_000, "NS1", "sib");
    private_inference_rent::accept_on_zap1_client(&bundle).expect("lc");
    pool.credit_deposit_zap1(&bundle, &auth).expect("zap1 product ingest");
    assert_eq!(pool.balance_zat, 1_000);
}

#[test]
fn credit_deposit_rejects_auth_with_wrong_note() {
    let group = tagged_hash(b"frost-group", &[b"wrong-note"]);
    let note = tagged_hash(b"note", &[b"a"]);
    let other_note = tagged_hash(b"note", &[b"b"]);
    let mut pool = layered_pool(group);
    let att = product_attestation(group, note, 2_000);
    let auth = spend_auth(&pool, group, other_note, 2_000, None);
    assert!(pool.credit_deposit(&att, &auth).is_err());
    assert_eq!(pool.balance_zat, 0);
}

#[test]
fn credit_deposit_rejects_auth_with_wrong_amount() {
    let group = tagged_hash(b"frost-group", &[b"wrong-amt"]);
    let note = tagged_hash(b"note", &[b"amt"]);
    let mut pool = layered_pool(group);
    let att = product_attestation(group, note, 2_000);
    let auth = spend_auth(&pool, group, note, 9_999, None);
    assert!(pool.credit_deposit(&att, &auth).is_err());
    assert_eq!(pool.balance_zat, 0);
}

#[test]
fn unlayered_product_credit_without_matching_spend_auth_is_rejected() {
    let group = tagged_hash(b"frost-group", &[b"unlayered"]);
    let note = tagged_hash(b"note", &[b"unlayered"]);
    let mut pool = FrostThresholdPool::new(group, 2, 3).unwrap();
    let att = product_attestation(group, note, 1_000);
    let layered = layered_pool(group);
    let auth = spend_auth(&layered, group, note, 1_000, None);
    assert!(
        pool.credit_deposit(&att, &auth).is_err(),
        "unlayered product ingest must not accept a SpendAuth from another committee"
    );
    assert_eq!(pool.balance_zat, 0);
}

#[test]
fn layered_pool_credits_only_with_matching_spend_auth() {
    let group = tagged_hash(b"frost-group", &[b"ok-credit"]);
    let note = tagged_hash(b"note", &[b"ok-credit"]);
    let mut pool = layered_pool(group);
    let att = product_attestation(group, note, 2_000_000);
    let auth = spend_auth(&pool, group, note, 2_000_000, None);
    pool.authorize_spend(&auth).expect("authorize_spend");
    let credit = pool.credit_deposit(&att, &auth).expect("credit_deposit");
    assert_eq!(credit.amount_zat, 2_000_000);
    assert_eq!(credit.note_commitment, note);
    assert_eq!(pool.balance_zat, 2_000_000);
}

#[test]
fn workflow_credit_deposit_sets_receipt_from_last_credit_outcome() {
    let group = tagged_hash(b"frost-group", &[b"receipt"]);
    let note = tagged_hash(b"note", &[b"receipt"]);
    let mut wf = PrivateComputeWorkflow::open(public_ask("ask-rc"), layered_pool(group)).unwrap();
    let att = product_attestation(group, note, 3_000);
    let auth = spend_auth(&wf.pool, group, note, 3_000, None);
    wf.credit_deposit(&att, &auth).unwrap();
    assert!(wf.receipt().deposit_accepted);
    assert_eq!(wf.receipt().pool_balance_zat, 3_000);
}

#[test]
fn failed_replay_does_not_invent_a_new_credit() {
    let group = tagged_hash(b"frost-group", &[b"replay"]);
    let note = tagged_hash(b"note", &[b"replay"]);
    let mut wf = PrivateComputeWorkflow::open(public_ask("ask-rp"), layered_pool(group)).unwrap();
    let att = product_attestation(group, note, 4_000);
    let auth = spend_auth(&wf.pool, group, note, 4_000, None);
    wf.credit_deposit(&att, &auth).unwrap();
    assert!(wf.credit_deposit(&att, &auth).is_err());
    assert_eq!(wf.pool.balance_zat, 4_000);
    assert_eq!(wf.pool.credits.len(), 1);
    // Last credit outcome failed; do not treat a sticky prior success as a new accept.
    assert!(
        !wf.receipt().deposit_accepted,
        "deposit_accepted is the last credit outcome, not a sticky true"
    );
}

#[test]
fn stoffel_confirm_smoke_skips_when_cli_missing() {
    if !private_inference_rent::stoffel::available() {
        return;
    }
    let digest = tagged_hash(b"product-stoffel-smoke", &[b"same"]);
    private_inference_rent::confirm_digest(&digest, &digest)
        .expect("CLI present: matching digest confirms");
}

// live-ict: Cargo feature. When off, this file makes no daemon-interop claim.
// When on, tests must fail closed if OLineTestEnv/Docker cannot spawn.
// Default `cargo test` must not enable live-ict.