//! Slice 1: bid-bound escrow close. LeaseBook is access-only.

use private_inference_rent::access::{DerivedAccess, LeaseBook};
use private_inference_rent::committee::demo_layered_committees;
use private_inference_rent::accrual::{commit_accrual, AccrualRate, HeightWindow};
use private_inference_rent::escrow::{
    settle_close, EscrowCell, EscrowError, EscrowMemberIds, EscrowParty, ResolverShareError,
    SettlementIntent,
};
use private_inference_rent::custody::EscrowHolders;
use private_inference_rent::frost::FrostGroup;
use private_inference_rent::frost_pool::FrostThresholdPool;
use private_inference_rent::hashmerchant::DepositAttestation;
use private_inference_rent::settlement::SettlementBook;
use private_inference_rent::{tagged_hash, SpendAuth};

fn members() -> EscrowMemberIds {
    EscrowMemberIds {
        tenant: "tenant-a".into(),
        provider: "provider-b".into(),
        resolver: "resolver-c".into(),
    }
}

fn bid() -> [u8; 32] {
    tagged_hash(b"bid", &[b"escrow-1"])
}

fn parts() -> [(&'static str, &'static [&'static str]); 2] {
    [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ]
}

fn signed_auth(
    pool: &FrostThresholdPool,
    frost: &FrostGroup,
    holders: &EscrowHolders,
    note: [u8; 32],
    amount: u64,
    bid_c: [u8; 32],
) -> SpendAuth {
    let group = pool.group_id;
    let msg = FrostGroup::spend_message(&group, &note, amount);
    let sig = holders.happy_sign(frost, &msg).unwrap();
    SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &parts(),
        group,
        note,
        amount,
        Some(bid_c),
    )
    .unwrap()
    .with_frost_sig(sig)
}

/// Production pool: DKG among tenant, provider, resolver (not trusted-dealer keygen).
fn funded_pool(deposit: u64, bid_c: [u8; 32]) -> (FrostThresholdPool, FrostGroup, EscrowHolders) {
    let (frost, holders) = EscrowHolders::from_dkg(&members()).expect("dkg seats");
    assert!(!frost.is_dealer(), "production pool is DKG, not trusted-dealer keygen");
    let group = frost.verifying_key;
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .allow_sim_transcript()
        .bind_bid(bid_c)
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost.clone());
    let note = tagged_hash(b"n", &[b"deposit"]);
    let att = DepositAttestation::prove_for_test([9u8; 32], note, deposit, group);
    let auth = signed_auth(&pool, &frost, &holders, note, deposit, bid_c);
    pool.credit_deposit(&att, &auth).unwrap();
    (pool, frost, holders)
}

#[test]
fn escrow_cell_open_binds_deposit_bid_and_three_member_ids() {
    let cell = EscrowCell::open(100, bid(), members()).unwrap();
    assert_eq!(cell.deposit_zat, 100);
    assert_eq!(cell.bid_commitment, bid());
    assert_eq!(cell.members.resolver, "resolver-c");
    assert_ne!(cell.cell_id, [0u8; 32]);
}

#[test]
fn escrow_accrue_rejects_earned_above_deposit() {
    let mut cell = EscrowCell::open(100, bid(), members()).unwrap();
    let b = bid();
    assert!(cell
        .accrue(&[private_inference_rent::WorkReceipt::bind("x", b, 101)])
        .is_err());
    cell.accrue(&[private_inference_rent::WorkReceipt::bind("x", b, 40)])
        .unwrap();
    assert!(cell
        .accrue(&[private_inference_rent::WorkReceipt::bind("x", b, 70)])
        .is_err());
}

fn height_accrue(cell: &mut EscrowCell, earned: u64, tag: &[u8]) {
    let (wit, pubv) = commit_accrual(
        HeightWindow {
            open_height: 10,
            close_height: 10 + earned,
        },
        AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[tag]),
        tagged_hash(b"hdr-o", &[tag]),
        tagged_hash(b"hdr-c", &[tag]),
    )
    .unwrap();
    assert_eq!(wit.earned_zat, earned);
    cell.accrue_from_witness(wit, pubv).unwrap();
}

#[test]
fn escrow_close_by_tenant_or_provider_kills_lease_access() {
    let mut cell = EscrowCell::open(100, bid(), members()).unwrap();
    height_accrue(&mut cell, 25, b"ask-1");
    let mut leases = LeaseBook::new();
    let acc = DerivedAccess::from_session("ask-1", &[7u8; 32], &bid());
    leases.accept_bid("lease-1", acc.bearer_hex());
    cell.close(EscrowParty::Tenant, &mut leases, "lease-1", None)
        .unwrap();
    assert!(leases.access("lease-1", &acc.bearer_hex()).is_err());
}

#[test]
fn escrow_close_two_intents_earned_plus_remainder_eq_deposit() {
    let mut cell = EscrowCell::open(100, bid(), members()).unwrap();
    let (wit, pubv) = commit_accrual(
        HeightWindow {
            open_height: 10,
            close_height: 45,
        },
        AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[b"two-intents"]),
        tagged_hash(b"hdr", &[b"open-35"]),
        tagged_hash(b"hdr", &[b"close-35"]),
    )
    .unwrap();
    assert_eq!(wit.earned_zat, 35);
    cell.accrue_from_witness(wit, pubv.clone()).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("l", "b".into());
    let grant = cell
        .close(EscrowParty::Provider, &mut leases, "l", None)
        .unwrap();
    let [a, b] = cell.intents().unwrap();
    assert_eq!(a, SettlementIntent::PayProvider(35));
    assert_eq!(b, SettlementIntent::RefundTenant(65));
    assert_eq!(a.amount() + b.amount(), 100);
    let view = grant.view();
    assert_eq!(view.earned_zat, 0);
    assert_eq!(view.remainder_zat, 100);
    assert_eq!(view.accrual_commitment, hex::encode(pubv.commitment));
}

#[test]
fn escrow_close_cannot_override_accrued_earned() {
    let mut cell = EscrowCell::open(100, bid(), members()).unwrap();
    height_accrue(&mut cell, 10, b"override");
    let mut leases = LeaseBook::new();
    leases.accept_bid("l", "b".into());
    let e = cell
        .close(EscrowParty::Tenant, &mut leases, "l", Some(99))
        .unwrap_err();
    assert_eq!(e, EscrowError::EarnedOverride);
    assert!(cell.closed.is_none());
}

#[test]
fn escrow_resolver_share_rejected_without_close_grant() {
    let cell = EscrowCell::open(100, bid(), members()).unwrap();
    assert_eq!(
        cell.resolver_may_sign("resolver-c"),
        Err(ResolverShareError::CellOpen)
    );
}

#[test]
fn escrow_resolver_share_allowed_after_recorded_grant() {
    let mut cell = EscrowCell::open(100, bid(), members()).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("l", "b".into());
    cell.close(EscrowParty::Tenant, &mut leases, "l", None)
        .unwrap();
    cell.resolver_may_sign("resolver-c").unwrap();
    assert!(cell.resolver_may_sign("tenant-a").is_err());
}

#[test]
fn escrow_dealer_seats_are_not_tenant_provider_resolver_roles() {
    let (frost, holders) = EscrowHolders::from_dkg(&members()).expect("dkg seats");
    assert!(
        !frost.is_dealer(),
        "escrow close constructs FrostGroup via DKG part1/2/3, not dealer"
    );
    let tenant = holders.seat("tenant-a").expect("tenant");
    let dbg = format!("{tenant:?}");
    assert!(!dbg.contains("tenant"));
    assert!(!dbg.contains("provider"));
    assert!(!dbg.contains("resolver"));
}

#[test]
fn escrow_settle_is_atomic_both_intents_or_neither() {
    let bid_c = bid();
    let (mut pool, frost, holders) = funded_pool(100, bid_c);
    let mut cell = EscrowCell::open(100, bid_c, members()).unwrap();
    height_accrue(&mut cell, 40, b"atomic");
    let mut leases = LeaseBook::new();
    leases.accept_bid("l", "b".into());
    cell.close(EscrowParty::Tenant, &mut leases, "l", None)
        .unwrap();

    let mut book = SettlementBook::new();
    let earned_note = cell.provider_receipt("ask").work_digest;
    let refund_note = cell.refund_receipt("ask").work_digest;
    assert_ne!(earned_note, refund_note);

    let pay = signed_auth(
        &pool,
        &frost,
        &holders,
        cell.provider_receipt("ask").work_digest,
        40,
        bid_c,
    );
    let refund = signed_auth(
        &pool,
        &frost,
        &holders,
        cell.refund_receipt("ask").work_digest,
        60,
        bid_c,
    );
    settle_close(&cell, &mut book, &mut pool, Some(&pay), Some(&refund), "ask").unwrap();
    assert_eq!(pool.balance_zat, 0);
}

#[test]
fn escrow_replay_deny_on_both_payout_spends() {
    let bid_c = bid();
    let (mut pool, frost, holders) = funded_pool(100, bid_c);
    let mut cell = EscrowCell::open(100, bid_c, members()).unwrap();
    height_accrue(&mut cell, 40, b"replay");
    let mut leases = LeaseBook::new();
    leases.accept_bid("l", "b".into());
    cell.close(EscrowParty::Provider, &mut leases, "l", None)
        .unwrap();
    let mut book = SettlementBook::new();
    let pay = signed_auth(
        &pool,
        &frost,
        &holders,
        cell.provider_receipt("ask").work_digest,
        40,
        bid_c,
    );
    let refund = signed_auth(
        &pool,
        &frost,
        &holders,
        cell.refund_receipt("ask").work_digest,
        60,
        bid_c,
    );
    settle_close(&cell, &mut book, &mut pool, Some(&pay), Some(&refund), "ask").unwrap();
    let err = settle_close(&cell, &mut book, &mut pool, Some(&pay), Some(&refund), "ask");
    assert!(err.is_err());
}
