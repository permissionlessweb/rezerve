//! Product escrow: ZAP1 credit + two FROST zat spends. Not uter p bank.

use private_inference_rent::access::LeaseBook;
use private_inference_rent::accrual::{commit_accrual, AccrualRate, HeightWindow};
use private_inference_rent::committee::demo_layered_committees;
use private_inference_rent::custody::EscrowHolders;
use private_inference_rent::escrow::{
    settle_close, EscrowCell, EscrowMemberIds, EscrowParty, ResolverShareError,
};
use private_inference_rent::frost::FrostGroup;
use private_inference_rent::frost_pool::FrostThresholdPool;
use private_inference_rent::settlement::SettlementBook;
use private_inference_rent::zap1::local_hosting_bundle;
use private_inference_rent::{tagged_hash, SpendAuth};

fn members() -> EscrowMemberIds {
    EscrowMemberIds {
        tenant: "t".into(),
        provider: "p".into(),
        resolver: "r".into(),
    }
}

fn parts() -> [(&'static str, &'static [&'static str]); 2] {
    [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ]
}

fn signed(
    pool: &FrostThresholdPool,
    frost: &FrostGroup,
    holders: &EscrowHolders,
    note: [u8; 32],
    amount: u64,
    bid: [u8; 32],
) -> SpendAuth {
    let msg = FrostGroup::spend_message(&pool.group_id, &note, amount);
    let sig = holders.happy_sign(frost, &msg).unwrap();
    SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &parts(),
        pool.group_id,
        note,
        amount,
        Some(bid),
    )
    .unwrap()
    .with_frost_sig(sig)
}

#[test]
fn settle_close_uses_frost_zat_not_uterp() {
    let src = include_str!("../src/escrow.rs");
    assert!(!src.contains("uterp") && !src.contains("BankMsg"));
    assert!(src.contains("credit_deposit_zap1"));
    assert!(src.contains("fund_with_zap1"));
}

#[test]
fn fund_with_zap1_not_sim_transcript() {
    let src = include_str!("../src/escrow.rs");
    let start = src.find("fn fund_with_zap1").expect("fund_with_zap1");
    let body = &src[start..];
    assert!(body.contains("credit_deposit_zap1"));
    assert!(!body.contains("prove_for_test"));
    assert!(!body.contains("credit_transcript"));
}

#[test]
fn zap1_credit_then_two_frost_spends() {
    let bid = tagged_hash(b"bid", &[b"sh"]);
    let (frost, holders) = EscrowHolders::from_dkg(&members()).expect("dkg seats");
    assert!(!frost.is_dealer(), "product escrow is DKG part1/2/3, not dealer");
    let group = frost.verifying_key;
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .bind_bid(bid)
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost.clone());
    let dep = tagged_hash(b"n", &[b"dep"]);
    let mut bundle = local_hosting_bundle(group, dep, 100, "PIR-ESCROW-ZAP1", "sib");
    if std::env::var("PIR_ZAKURA_LAB").ok().as_deref() == Some("1") {
        let n = private_inference_rent::zakura::lab_spawn()
            .expect("PIR_ZAKURA_LAB=1 fail-closed");
        bundle
            .stamp_zakura_tip(&n.as_regtest())
            .expect("stamp tip (not memo open)");
        assert!(bundle.orchard_anchor_txid.is_some());
    }
    let auth = signed(&pool, &frost, &holders, dep, 100, bid);
    let cell = EscrowCell::open(100, bid, members()).unwrap();
    cell.fund_with_zap1(&mut pool, &bundle, &auth).unwrap();
    assert_eq!(pool.balance_zat, 100);

    let mut cell = cell;
    let (wit, pubv) = commit_accrual(
        HeightWindow {
            open_height: 10,
            close_height: 50,
        },
        AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[b"shielded"]),
        tagged_hash(b"hdr", &[b"open-sh"]),
        tagged_hash(b"hdr", &[b"close-sh"]),
    )
    .unwrap();
    assert_eq!(wit.earned_zat, 40);
    cell.accrue_from_witness(wit, pubv).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("l", "b".into());
    cell.close(EscrowParty::Tenant, &mut leases, "l", None)
        .unwrap();

    let pay = signed(
        &pool,
        &frost,
        &holders,
        cell.provider_receipt("a").work_digest,
        40,
        bid,
    );
    let refund = signed(
        &pool,
        &frost,
        &holders,
        cell.refund_receipt("a").work_digest,
        60,
        bid,
    );
    let mut book = SettlementBook::new();
    settle_close(&cell, &mut book, &mut pool, Some(&pay), Some(&refund), "a").unwrap();
    assert_eq!(pool.balance_zat, 0);
}

#[test]
fn resolver_share_without_grant_fails() {
    let bid = tagged_hash(b"bid", &[b"pol"]);
    let cell = EscrowCell::open(10, bid, members()).unwrap();
    assert_eq!(
        cell.resolver_may_sign("r"),
        Err(ResolverShareError::CellOpen)
    );
}
