//! cw-orch / ict-shaped e2e suite: every protocol edge as a named case.
//!
//! Live `OLineTestEnv::daemon()` needs Docker + the `interface` feature on
//! o-line. This file drives the **shipped** crate on those same edges so the
//! cw-orch wrapper can attach later without reimplementing them.

use private_inference_rent::ask::{PublicAsk, ResourceAsk};
use private_inference_rent::bid::{BidError, EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::committee::{demo_layered_committees, CommitteeError};
use private_inference_rent::dregg::FrostSignerInstance;
use private_inference_rent::frost_pool::{FrostThresholdPool, SpendAuth};
use private_inference_rent::hashmerchant::{DepositAttestation, DepositError};
use private_inference_rent::interop::{IctCwOrchScenario, ICT_HARNESS_MODULES};
use private_inference_rent::onchain::{OnChainError, OnChainView};
use private_inference_rent::steoffle::{SteoffleError, SteoffleMpc};
use private_inference_rent::tagged_hash;
use private_inference_rent::workflow::{PrivateComputeWorkflow, WorkflowError};

const EDGES: &[&str] = &[
    "ask_invalid",
    "bid_mac_tamper",
    "bid_ask_mismatch",
    "bid_unknown_signer",
    "steoffle_signer_id_bind",
    "onchain_foreign_ask",
    "deposit_zero",
    "deposit_replay",
    "deposit_layered_needs_quorum",
    "deposit_under_quorum",
    "deposit_happy_layered",
    "committee_duplicate_signer",
    "committee_unbound_quorum",
    "receipt_survives_failed_replay",
    "stoffel_local_mpc_match",
    "stoffel_local_mpc_mismatch",
];

fn ask(id: &str) -> PublicAsk {
    PublicAsk::new(
        id,
        "tenant",
        "version: \"2.0\"\nservices:\n  inf:\n    image: x\n",
        ResourceAsk {
            cpu_milli: 1000,
            memory_mib: 2048,
            storage_mib: 4096,
            gpu_units: 0,
        },
        "cpu",
    )
}

fn signer(tag: &str) -> FrostSignerInstance {
    FrostSignerInstance::new(
        tagged_hash(b"s", &[tag.as_bytes()]),
        tagged_hash(b"i", &[tag.as_bytes()]),
        vec![tagged_hash(b"c", &[tag.as_bytes()])],
    )
    .unwrap()
}

fn key() -> [u8; 32] {
    tagged_hash(b"oob", &[b"e2e"])
}

fn bid(ask_id: &str, price: u64) -> PlaintextBid {
    PlaintextBid {
        ask_id: ask_id.into(),
        bidder_identity: "prov".into(),
        price_uakt: price,
        provider_endpoint: "oob".into(),
    }
}

#[test]
fn catalog_lists_every_budget_and_protocol_edge() {
    assert_eq!(EDGES.len(), 16);
    assert!(ICT_HARNESS_MODULES.iter().any(|m| m.contains("interface")));
}

#[test]
fn edge_ask_invalid() {
    let mut a = ask("a");
    a.manifest_sdl.clear();
    assert!(a.validate().is_err());
}

#[test]
fn edge_bid_mac_tamper() {
    let mut env = EncryptedBidEnvelope::seal(&bid("a", 10), &key()).unwrap();
    env.ciphertext[0] ^= 1;
    assert_eq!(env.open(&key()), Err(BidError::Auth));
}

#[test]
fn edge_bid_ask_mismatch() {
    let group = tagged_hash(b"g", &[b"e2e"]);
    let mut wf =
        PrivateComputeWorkflow::open(ask("ask-a"), FrostThresholdPool::new(group, 2, 3).unwrap())
            .unwrap();
    let s = signer("x");
    let att = SteoffleMpc::attest(&s).unwrap();
    wf.enroll_signer(s).unwrap();
    let env = EncryptedBidEnvelope::seal(&bid("other", 10), &key()).unwrap();
    assert_eq!(wf.ingest_oob_bid(env, &att), Err(WorkflowError::AskMismatch));
}

#[test]
fn edge_bid_unknown_signer() {
    let group = tagged_hash(b"g", &[b"e2e2"]);
    let mut wf =
        PrivateComputeWorkflow::open(ask("ask-a"), FrostThresholdPool::new(group, 2, 3).unwrap())
            .unwrap();
    let s = signer("y");
    let att = SteoffleMpc::attest(&s).unwrap();
    let env = EncryptedBidEnvelope::seal(&bid("ask-a", 10), &key()).unwrap();
    assert!(matches!(
        wf.ingest_oob_bid(env, &att),
        Err(WorkflowError::Steoffle(SteoffleError::UnknownSigner))
    ));
}

#[test]
fn edge_steoffle_signer_id_bind() {
    let s = signer("z");
    let mut att = SteoffleMpc::attest(&s).unwrap();
    att.signer_id = tagged_hash(b"s", &[b"not-z"]);
    assert_eq!(SteoffleMpc::verify(&s, &att), Err(SteoffleError::UnknownSigner));
}

#[test]
fn edge_onchain_foreign_ask() {
    let mut view = OnChainView::new(ask("ask-a"));
    let env = EncryptedBidEnvelope::seal(&bid("other", 3), &key()).unwrap();
    assert_eq!(
        view.post_commitment(&env.commitment(), [1u8; 32]),
        Err(OnChainError::AskMismatch)
    );
}

#[test]
fn edge_deposit_zero_and_replay() {
    let group = tagged_hash(b"g", &[b"dep"]);
    let mut pool = FrostThresholdPool::new(group, 2, 3).unwrap();
    let zero = DepositAttestation::prove([1u8; 32], [2u8; 32], 0, group);
    assert_eq!(pool.credit_transcript(&zero), Err(DepositError::ZeroAmount));
    let att = DepositAttestation::prove([1u8; 32], [3u8; 32], 50, group);
    pool.credit_transcript(&att).unwrap();
    assert_eq!(pool.credit_transcript(&att), Err(DepositError::Replay));
}

#[test]
fn edge_deposit_layered_needs_quorum() {
    let group = tagged_hash(b"g", &[b"lq"]);
    let pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap());
    let att = DepositAttestation::prove([4u8; 32], [5u8; 32], 9, group);
    let err = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &[("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..])],
        group,
        att.deposit_note_commitment,
        att.amount_zat,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CommitteeError::BelowThreshold { have: 1, need: 2 });
}

#[test]
fn edge_deposit_under_quorum() {
    let group = tagged_hash(b"g", &[b"uq"]);
    let pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap());
    let err = pool
        .layered
        .as_ref()
        .unwrap()
        .quorum(&[("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..])])
        .unwrap_err();
    assert_eq!(err, CommitteeError::BelowThreshold { have: 1, need: 2 });
}

#[test]
fn edge_deposit_happy_layered_and_receipt() {
    let group = tagged_hash(b"g", &[b"ok"]);
    let mut wf = PrivateComputeWorkflow::open(
        ask("ask-e2e"),
        FrostThresholdPool::new(group, 2, 3)
            .unwrap()
            .allow_sim_transcript()
            .with_layered(demo_layered_committees().unwrap()),
    )
    .unwrap();
    let steoffle = &wf.pool.layered.as_ref().unwrap().inners[0].seats[0].attestation.clone();
    let env = EncryptedBidEnvelope::seal(&bid("ask-e2e", 42), &key()).unwrap();
    wf.ingest_oob_bid(env, steoffle).unwrap();
    let q = wf
        .pool
        .layered
        .as_ref()
        .unwrap()
        .quorum(&[
            ("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..]),
            ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
        ])
        .unwrap();
    let att = DepositAttestation::prove([6u8; 32], [7u8; 32], 1000, group);
    let auth = SpendAuth::from_quorum(
        wf.pool.layered.as_ref().unwrap(),
        &[
            ("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..]),
            ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
        ],
        group,
        att.deposit_note_commitment,
        att.amount_zat,
        None,
    )
    .unwrap();
    assert_eq!(auth.quorum.digest, q.digest);
    wf.credit_deposit(&att, &auth).unwrap();
    assert!(wf.credit_deposit(&att, &auth).is_err());
    let rc = wf.receipt();
    assert!(!rc.deposit_accepted);
    assert!(!rc.last_credit_ok);
    assert_eq!(wf.pool.credits.len(), 1);
    assert!(rc.steoffle_ok);
    assert_eq!(rc.inner_seats, 15);
    assert_eq!(rc.outer_n, 3);
    let sc = IctCwOrchScenario::from_workflow("e2e-happy", &wf);
    assert!(sc.wraps_shipped_receipt());
}

#[test]
fn edge_committee_duplicate_signer() {
    use private_inference_rent::{InnerCommittee, SignerSeat};
    let s = signer("dup");
    let a = SignerSeat::enroll("a", s.clone()).unwrap();
    let b = SignerSeat::enroll("b", s).unwrap();
    assert!(matches!(
        InnerCommittee::form("x", 2, vec![a, b]),
        Err(CommitteeError::Duplicate(_))
    ));
}

#[test]
fn edge_committee_unbound_quorum() {
    let unbound = demo_layered_committees().unwrap();
    let err = unbound
        .quorum(&[
            ("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..]),
            ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
        ])
        .unwrap_err();
    assert_eq!(err, CommitteeError::UnboundGroup);
}

#[test]
fn edge_stoffel_local_mpc_match_and_mismatch() {
    if !private_inference_rent::stoffel::available() {
        eprintln!("skip: stoffel CLI not installed");
        return;
    }
    let digest = tagged_hash(b"stoffel-e2e", &[b"ok"]);
    let tag = private_inference_rent::confirm_digest(&digest, &digest).expect("match");
    assert_ne!(tag, [0u8; 32]);
    let mut bad = digest;
    bad[0] ^= 1;
    assert_eq!(
        private_inference_rent::confirm_digest(&digest, &bad),
        Err(private_inference_rent::StoffelError::DigestMismatch)
    );

    let group = tagged_hash(b"g", &[b"stoffel-wf"]);
    let mut wf =
        PrivateComputeWorkflow::open(ask("ask-st"), FrostThresholdPool::new(group, 2, 3).unwrap())
            .unwrap();
    wf.require_stoffel_confirm().unwrap();
    let s = signer("st");
    let att = SteoffleMpc::attest(&s).unwrap();
    wf.enroll_signer(s).unwrap();
    let env = EncryptedBidEnvelope::seal(&bid("ask-st", 7), &key()).unwrap();
    let rec = wf.ingest_oob_bid(env, &att).expect("ingest");
    assert!(!rec.steoffle_attestation.is_empty());
    assert!(wf.receipt().stoffel_ok);
}

#[cfg(feature = "live-ict")]
#[test]
fn live_cw_orch_daemon_spawns_or_fail_closed() {
    let hint = private_inference_rent::cw_orch::try_live_attach()
        .expect("live-ict must attach; DaemonUnavailable is not a pass");
    assert!(!hint.chain_id.is_empty());
    assert!(hint.deploy_on_daemon && hint.escrow_grant_recorded && hint.ics08_deployed);
    assert!(hint.zap1_stored && hint.zap1_matches && hint.zap1_tamper_rejected);
    assert!(
        hint.ics08_accepted && hint.ics08_tamper_rejected,
        "live-ict ics08 must execute/query, not store-only instantiate: {hint:?}"
    );
}
