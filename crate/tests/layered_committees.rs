//! Multi-entity, two-layer FROST committees (inner signers + outer guardians).

use private_inference_rent::ask::{PublicAsk, ResourceAsk};
use private_inference_rent::bid::{EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::committee::{demo_layered_committees, CommitteeError};
use private_inference_rent::frost_pool::{FrostThresholdPool, SpendAuth};
use private_inference_rent::hashmerchant::DepositAttestation;
use private_inference_rent::tagged_hash;
use private_inference_rent::workflow::PrivateComputeWorkflow;

fn ask(id: &str) -> PublicAsk {
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

#[test]
fn two_layers_multiple_entities_form() {
    let outer = demo_layered_committees().expect("form");
    assert_eq!(outer.threshold, 2);
    assert_eq!(outer.n(), 3);
    for inner in &outer.inners {
        assert_eq!(inner.threshold, 3);
        assert_eq!(inner.n(), 5);
        assert_eq!(inner.seats.len(), 5);
    }
    let entities: usize = outer.inners.iter().map(|i| i.seats.len()).sum();
    assert_eq!(entities, 15, "3 inner committees × 5 signers");
}

#[test]
fn inner_quorum_requires_threshold_distinct_signers() {
    let outer = demo_layered_committees().unwrap();
    let alpha = &outer.inners[0];
    let ok = alpha.quorum(&["alpha-s0", "alpha-s1", "alpha-s2"]).unwrap();
    assert_eq!(ok.participants.len(), 3);

    let err = alpha.quorum(&["alpha-s0", "alpha-s1"]).unwrap_err();
    assert_eq!(
        err,
        CommitteeError::BelowThreshold { have: 2, need: 3 }
    );
}

#[test]
fn outer_quorum_needs_two_inner_committees() {
    let group = tagged_hash(b"g", &[b"outer-q"]);
    let outer = demo_layered_committees().unwrap().bind_pool(group);
    let err = outer
        .quorum(&[("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..])])
        .unwrap_err();
    assert_eq!(
        err,
        CommitteeError::BelowThreshold { have: 1, need: 2 }
    );

    let q = outer
        .quorum(&[
            ("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..]),
            ("gamma", &["gamma-s1", "gamma-s3", "gamma-s4"][..]),
        ])
        .unwrap();
    assert_eq!(q.inner_quorums.len(), 2);
    assert_ne!(q.digest, [0u8; 32]);
}

#[test]
fn form_rejects_duplicate_signer_identity() {
    use private_inference_rent::{FrostSignerInstance, InnerCommittee, SignerSeat};
    let signer = FrostSignerInstance::new(
        tagged_hash(b"same", &[b"id"]),
        tagged_hash(b"same", &[b"inst"]),
        vec![tagged_hash(b"c", &[b"0"])],
    )
    .unwrap();
    let a = SignerSeat::enroll("alpha-s0", signer.clone()).unwrap();
    let b = SignerSeat::enroll("alpha-s1", signer).unwrap();
    assert!(matches!(
        InnerCommittee::form("alpha", 2, vec![a, b]),
        Err(CommitteeError::Duplicate(_))
    ));
}

#[test]
fn unknown_or_duplicate_participants_fail() {
    let outer = demo_layered_committees().unwrap();
    assert!(matches!(
        outer.inners[0].quorum(&["nope"]).unwrap_err(),
        CommitteeError::UnknownMember(_)
    ));
    assert!(matches!(
        outer.inners[0]
            .quorum(&["alpha-s0", "alpha-s0", "alpha-s1"])
            .unwrap_err(),
        CommitteeError::Duplicate(_)
    ));
}

#[test]
fn multi_tenant_multi_bidder_with_layered_pool() {
    let group = tagged_hash(b"frost-group", &[b"layered-demo"]);
    let outer = demo_layered_committees().unwrap();
    let pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .allow_sim_transcript()
        .with_layered(outer.clone());

    let mut wf_a = PrivateComputeWorkflow::open(ask("ask-a"), pool.clone()).unwrap();
    let mut wf_b = PrivateComputeWorkflow::open(ask("ask-b"), pool).unwrap();

    let bidders = [
        ("prov-west", 11_000u64),
        ("prov-east", 12_000),
        ("prov-eu", 9_500),
        ("prov-apac", 13_200),
    ];
    let session = tagged_hash(b"oob-session", &[b"multi"]);
    let steoffle = &outer.inners[0].seats[0].attestation;

    for (i, (who, price)) in bidders.iter().enumerate() {
        let env = EncryptedBidEnvelope::seal_with_nonce(
            &PlaintextBid {
                ask_id: "ask-a".into(),
                bidder_identity: (*who).into(),
                price_uakt: *price,
                provider_endpoint: format!("oob://{who}"),
            },
            &session,
            [i as u8; 16],
        )
        .unwrap();
        wf_a.ingest_oob_bid(env, steoffle).unwrap();
    }
    // Second tenant sees two other providers.
    for (i, (who, price)) in [("prov-lab", 8_000u64), ("prov-core", 8_100)].iter().enumerate() {
        let env = EncryptedBidEnvelope::seal_with_nonce(
            &PlaintextBid {
                ask_id: "ask-b".into(),
                bidder_identity: (*who).into(),
                price_uakt: *price,
                provider_endpoint: format!("oob://{who}"),
            },
            &session,
            [20 + i as u8; 16],
        )
        .unwrap();
        wf_b.ingest_oob_bid(env, steoffle).unwrap();
    }

    assert_eq!(wf_a.oob_envelopes.len(), 4);
    assert_eq!(wf_b.oob_envelopes.len(), 2);
    assert!(!wf_a.view.payload_contains_plaintext_bid());
    assert!(!wf_b.view.payload_contains_plaintext_bid());

    let dep = DepositAttestation::prove(
        tagged_hash(b"zcash-root", &[b"layered"]),
        tagged_hash(b"note", &[b"layered"]),
        2_000_000,
        group,
    );
    let parts: &[(&str, &[&str])] = &[
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ];
    let auth = SpendAuth::from_quorum(
        wf_a.pool.layered.as_ref().unwrap(),
        parts,
        group,
        dep.deposit_note_commitment,
        dep.amount_zat,
        None,
    )
    .unwrap();
    wf_a.pool.authorize_spend(&auth).unwrap();
    wf_a.credit_deposit(&dep, &auth).unwrap();

    let rc = wf_a.receipt();
    assert_eq!(rc.oob_bid_count, 4);
    assert_eq!(rc.outer_n, 3);
    assert_eq!(rc.inner_seats, 15);
    assert!(rc.deposit_accepted);
    assert!(rc.last_credit_ok);

    // Replay fails; last outcome is not accepted. Pool still holds the one credit.
    assert!(wf_a.credit_deposit(&dep, &auth).is_err());
    assert!(!wf_a.receipt().last_credit_ok);
    assert!(!wf_a.receipt().deposit_accepted);
    assert_eq!(wf_a.pool.credits.len(), 1);
    assert_eq!(wf_a.pool.balance_zat, 2_000_000);
}

#[test]
fn quorum_from_wrong_outer_rejected() {
    let group = tagged_hash(b"frost-group", &[b"p"]);
    let outer = demo_layered_committees().unwrap();
    let other_group = tagged_hash(b"frost-group", &[b"other-pool"]);
    let pool = FrostThresholdPool::new(other_group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap());
    let bound = outer.bind_pool(group);
    let q = bound
        .quorum(&[
            ("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..]),
            ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
        ])
        .unwrap();
    assert!(pool.authorize_with_quorum(&q).is_err());
}

#[test]
fn committee_id_binds_members() {
    let a = demo_layered_committees().unwrap();
    let mut b = demo_layered_committees().unwrap();
    b.inners[0].seats.swap(0, 1);
    // re-form so id is recomputed
    let seats = b.inners[0].seats.clone();
    let reformed = private_inference_rent::InnerCommittee::form("alpha", 3, seats).unwrap();
    assert_eq!(reformed.committee_id, a.inners[0].committee_id); // same member set
    let mut seats2 = a.inners[0].seats.clone();
    seats2.pop();
    let smaller = private_inference_rent::InnerCommittee::form("alpha", 3, seats2).unwrap();
    assert_ne!(smaller.committee_id, a.inners[0].committee_id);
}
