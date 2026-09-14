//! Cites `docs/AUDIT_FREEZE.md`. In-process custody/earned stay here.
//! Compose arbiter: `run_composed_arbiter` (`deploy_on` + `fund_with_zap1` + two spends + bearer deny).

use private_inference_rent::access::{DerivedAccess, LeaseBook};
use private_inference_rent::accrual::{commit_accrual, AccrualRate, HeightWindow};
use private_inference_rent::committee::demo_layered_committees;
use private_inference_rent::custody::EscrowHolders;
use private_inference_rent::escrow::{
    settle_close, EscrowCell, EscrowError, EscrowMemberIds, EscrowParty,
};
use private_inference_rent::frost::FrostGroup;
use private_inference_rent::frost_pool::FrostThresholdPool;
use private_inference_rent::settlement::SettlementBook;
use private_inference_rent::zap1::local_hosting_bundle;
use private_inference_rent::{tagged_hash, SpendAuth, PIR_FROST_SEAT_ENV};

const AUDIT: &str = include_str!("../docs/AUDIT_FREEZE.md");

fn members() -> EscrowMemberIds {
    EscrowMemberIds {
        tenant: "tenant-a".into(),
        provider: "provider-b".into(),
        resolver: "resolver-c".into(),
    }
}

fn parts() -> [(&'static str, &'static [&'static str]); 2] {
    [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ]
}

#[test]
fn honesty_header_matches_audit_freeze_md() {
    assert!(AUDIT.contains("## Honesty (do not contradict)"));
    assert!(AUDIT.contains("Product money is **zat / FROST / ZAP1**"));
    assert!(AUDIT.contains("Dealer `FrostSeat` is **not** a tenant/provider/resolver role label"));
    assert!(AUDIT.contains("Vote extensions are **not** on the escrow path"));
    assert!(AUDIT.contains("Orchard memo is **not** opened"));
    assert!(AUDIT.contains("1. **Custody**"));
    assert!(AUDIT.contains("2. **Earned**"));
    assert!(AUDIT.contains("3. **One arbiter e2e**"));
    assert!(AUDIT.contains("4. **This header**"));
    assert!(AUDIT.contains("status:"));
}

#[test]
fn freeze_custody_earned_arbiter_in_process() {
    assert!(
        !AUDIT.contains("deploy_on is uterp grant-only")
            || AUDIT.contains("cw-orch `deploy_on`")
    );
    // compose note: pir-cw-orch deploy_on remains grant-only; this test is in-process.

    let bid = tagged_hash(b"bid", &[b"audit-freeze"]);
    let group = tagged_hash(b"g", &[b"audit-freeze"]);
    let mut frost = FrostGroup::dealer(3, 2).unwrap();
    let issued = frost.issue_seats();
    let holders = EscrowHolders::from_issued(&members(), issued).unwrap();
    let env_line = EscrowHolders::encode_seat_env(holders.seat("tenant-a").unwrap()).unwrap();
    assert!(!env_line.is_empty());
    std::env::set_var(PIR_FROST_SEAT_ENV, &env_line);
    let from_env = EscrowHolders::load_seat_from_env().unwrap();
    assert_eq!(
        from_env.identifier_bytes(),
        holders.seat("tenant-a").unwrap().identifier_bytes()
    );

    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .bind_bid(bid)
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost.clone());
    let dep = tagged_hash(b"n", &[b"audit-dep"]);
    let bundle = local_hosting_bundle(group, dep, 100, "PIR-AUDIT-ZAP1", "sib");
    let msg = FrostGroup::spend_message(&group, &dep, 100);
    let sig = holders.happy_sign(&frost, &msg).unwrap();
    let auth = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &parts(),
        group,
        dep,
        100,
        Some(bid),
    )
    .unwrap()
    .with_frost_sig(sig);

    let mut cell = EscrowCell::open(100, bid, members()).unwrap();
    cell.fund_with_zap1(&mut pool, &bundle, &auth).unwrap();

    cell.earned_zat = 40;
    let mut leases = LeaseBook::new();
    leases.accept_bid("lease-audit", "x".into());
    assert_eq!(
        cell.close(EscrowParty::Tenant, &mut leases, "lease-audit", None)
            .unwrap_err(),
        EscrowError::NoWorkReceipts
    );
    cell.earned_zat = 0;

    let (wit, pubv) = commit_accrual(
        HeightWindow {
            open_height: 10,
            close_height: 50,
        },
        AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[b"audit"]),
        tagged_hash(b"hdr", &[b"open-audit"]),
        tagged_hash(b"hdr", &[b"close-audit"]),
    )
    .unwrap();
    assert_eq!(wit.earned_zat, 40);
    cell.accrue_from_witness(wit, pubv).unwrap();

    let key = tagged_hash(b"sess", &[b"audit"]);
    let winner = DerivedAccess::from_session("ask-audit", &key, &bid);
    leases.accept_bid("lease-audit", winner.bearer_hex());
    leases
        .access("lease-audit", &winner.bearer_hex())
        .unwrap();
    cell.close(EscrowParty::Tenant, &mut leases, "lease-audit", None)
        .unwrap();
    assert_eq!(
        leases.access("lease-audit", &winner.bearer_hex()),
        Err(private_inference_rent::LeaseAccessError::Closed)
    );

    assert!(holders
        .sign_after_grant(&cell, &frost, &msg, "tenant-a")
        .is_ok());

    let pay_note = cell.provider_receipt("ask-audit").work_digest;
    let ref_note = cell.refund_receipt("ask-audit").work_digest;
    let pay_msg = FrostGroup::spend_message(&group, &pay_note, 40);
    let pay_sig = holders.happy_sign(&frost, &pay_msg).unwrap();
    let pay = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &parts(),
        group,
        pay_note,
        40,
        Some(bid),
    )
    .unwrap()
    .with_frost_sig(pay_sig);
    let ref_msg = FrostGroup::spend_message(&group, &ref_note, 60);
    let ref_sig = holders.happy_sign(&frost, &ref_msg).unwrap();
    let refund = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &parts(),
        group,
        ref_note,
        60,
        Some(bid),
    )
    .unwrap()
    .with_frost_sig(ref_sig);

    let mut book = SettlementBook::new();
    settle_close(
        &cell,
        &mut book,
        &mut pool,
        Some(&pay),
        Some(&refund),
        "ask-audit",
    )
    .unwrap();
    assert_eq!(pool.balance_zat, 0);
}
