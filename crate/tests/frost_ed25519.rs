//! Real frost-ed25519 dealer keygen + spend signature (offline, no Docker).

use private_inference_rent::committee::demo_layered_committees;
use private_inference_rent::frost::FrostGroup;
use private_inference_rent::frost_pool::FrostThresholdPool;
use private_inference_rent::hashmerchant::DepositAttestation;
use private_inference_rent::{tagged_hash, SpendAuth};

fn parts() -> [(&'static str, &'static [&'static str]); 2] {
    [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ]
}

#[test]
fn frost_dealer_sign_and_verify_spend_message() {
    let g = FrostGroup::dealer(3, 2).expect("dealer");
    let group_id = tagged_hash(b"g", &[b"frost"]);
    let note = tagged_hash(b"n", &[b"1"]);
    let msg = FrostGroup::spend_message(&group_id, &note, 100);
    let sig = g.sign(&msg).expect("sign");
    g.verify(&msg, &sig).expect("verify");
    let mut bad = msg;
    bad[0] ^= 1;
    assert!(g.verify(&bad, &sig).is_err());
}

#[test]
fn pool_with_frost_rejects_unsigned_spend_auth() {
    let group = tagged_hash(b"g", &[b"frost-pool"]);
    let frost = FrostGroup::dealer(3, 2).unwrap();
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost);
    let note = tagged_hash(b"n", &[b"2"]);
    let att = DepositAttestation::prove_for_test([3u8; 32], note, 50, group);
    let auth = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &parts(),
        group,
        note,
        50,
        None,
    )
    .unwrap();
    assert!(pool.credit_deposit(&att, &auth).is_err());
}

#[test]
fn pool_with_frost_accepts_signed_spend() {
    let group = tagged_hash(b"g", &[b"frost-ok"]);
    let mut frost = FrostGroup::dealer(3, 2).unwrap();
    let seats = frost.issue_seats();
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .allow_sim_transcript()
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost.clone());
    let note = tagged_hash(b"n", &[b"3"]);
    let att = DepositAttestation::prove_for_test([4u8; 32], note, 77, group);
    let msg = FrostGroup::spend_message(&group, &note, 77);
    let sig = frost.sign_with_seats(&msg, &seats[..2]).unwrap();
    let auth = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &parts(),
        group,
        note,
        77,
        None,
    )
    .unwrap()
    .with_frost_sig(sig);
    pool.credit_deposit(&att, &auth).expect("signed credit");
    assert_eq!(pool.balance_zat, 77);
}
