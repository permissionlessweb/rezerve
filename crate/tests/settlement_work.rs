//! NS7: local settlement predicate. SDL/work receipt; pay once; replay fails.
//! Not an Akash lease. No live ict.

use private_inference_rent::{SettlementBook, SettlementError, WorkReceipt, tagged_hash};

fn receipt(amount: u64) -> WorkReceipt {
    WorkReceipt::bind("ask-ns7", tagged_hash(b"ns7-prov", &[b"c"]), amount)
}

#[test]
fn pay_from_pool_debits_and_replay_fails() {
    use private_inference_rent::committee::demo_layered_committees;
    use private_inference_rent::frost::FrostGroup;
    use private_inference_rent::frost_pool::FrostThresholdPool;
    use private_inference_rent::local_hosting_bundle;
    use private_inference_rent::SpendAuth;

    let (frost, seats) = private_inference_rent::frost_dkg::dkg_escrow_seats()
        .expect("dkg among tenant, provider, resolver");
    assert!(
        !frost.is_dealer(),
        "settlement pool is DKG among tenant, provider, resolver, not dealer"
    );
    let group = frost.verifying_key;
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost.clone());
    let note = tagged_hash(b"ns7-pool", &[b"n"]);
    let bundle = local_hosting_bundle(group, note, 4_000, "NS7", "sib");
    let msg = FrostGroup::spend_message(&group, &note, 4_000);
    let sig = frost.sign_with_seats(&msg, &seats[..2]).unwrap();
    let parts = [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ];
    let auth = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &parts,
        group,
        note,
        4_000,
        None,
    )
    .unwrap()
    .with_frost_sig(sig);
    private_inference_rent::accept_on_zap1_client(&bundle).unwrap();
    pool.credit_deposit_zap1(&bundle, &auth).unwrap();
    assert_eq!(pool.balance_zat, 4_000);
    let r = WorkReceipt::bind("ask-ns7", tagged_hash(b"ns7-prov", &[b"c"]), 4_000);
    let mut book = SettlementBook::new();
    assert_eq!(book.pay_from_pool(&mut pool, &r, &auth).unwrap(), 4_000);
    assert_eq!(pool.balance_zat, 0);
    assert_eq!(
        book.pay_from_pool(&mut pool, &r, &auth),
        Err(SettlementError::Replay)
    );
}

#[test]
fn pay_once_then_replay_same_work_digest_fails() {
    let r = receipt(4_000);
    let mut book = SettlementBook::new();
    assert_eq!(book.pay(&r).unwrap(), 4_000);
    assert_eq!(book.pay(&r), Err(SettlementError::Replay));
}

#[test]
fn require_work_before_pay_rejects_unbound_or_empty() {
    let mut bad = receipt(1);
    bad.work_digest = tagged_hash(b"forged", &[b"x"]);
    assert_eq!(
        SettlementBook::require_work_before_pay(&bad),
        Err(SettlementError::UnboundDigest)
    );
    let empty = WorkReceipt::bind("", tagged_hash(b"ns7-prov", &[b"c"]), 0);
    assert_eq!(
        SettlementBook::require_work_before_pay(&empty),
        Err(SettlementError::MissingReceipt)
    );
}

#[cfg(feature = "live-ict")]
#[test]
fn live_ict_lease_attempts_spawn() {
    let hint = private_inference_rent::cw_orch::try_live_attach()
        .expect("live-ict must spawn pir-live-attach and return Ok");
    assert!(!hint.chain_id.is_empty());
}

#[test]
fn settlement_book_replay_is_the_nullifier_standin() {
    // Honest name: this is SettlementBook replay, not a seam-dex nullifier set.
    let r = receipt(99);
    let mut book = SettlementBook::new();
    book.pay(&r).unwrap();
    assert_eq!(book.pay(&r), Err(SettlementError::Replay));
}

#[cfg(feature = "seam-dex")]
#[test]
fn seam_nullifier_reuse_after_ibc_deposit_then_swap_fails() {
    use private_inference_rent::frost::FrostGroup;
    use private_inference_rent::seam_swap::{
        demo_zec_hub_pool, frost_backed_pool, ibc_deposit_then_swap,
    };
    use terp_seams::dex::SeamState;

    let (frost, seats) = private_inference_rent::frost_dkg::dkg_escrow_seats()
        .expect("dkg among tenant, provider, resolver");
    assert!(
        !frost.is_dealer(),
        "settlement pool is DKG among tenant, provider, resolver, not dealer"
    );
    let group = frost.verifying_key;
    let mut fp = frost_backed_pool(group, frost.clone());
    let mut pool = demo_zec_hub_pool();
    let mut state = SeamState::default();
    ibc_deposit_then_swap(&mut fp, &frost, &seats, &mut pool, &mut state, 5_000, 7).unwrap();
    let again = ibc_deposit_then_swap(&mut fp, &frost, &seats, &mut pool, &mut state, 5_000, 7);
    assert!(again.is_err(), "reused seam nullifier must fail: {again:?}");
}
