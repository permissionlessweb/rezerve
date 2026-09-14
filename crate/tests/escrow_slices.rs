//! Slices 2–4: grant JSON, provider honor via partial close, LC event notice (not VE).

use private_inference_rent::access::LeaseBook;
use private_inference_rent::escrow::{
    EscrowCell, EscrowMemberIds, EscrowParty, GrantView,
};
use private_inference_rent::escrow_notice::{
    resolver_may_sign_from_notice, CloseAction, CloseEventAttest, CloseEventAttrs, ResolverNotice,
    ResolverNoticeError,
};
use private_inference_rent::run_escrow_partial_close;
use private_inference_rent::tagged_hash;

fn members() -> EscrowMemberIds {
    EscrowMemberIds {
        tenant: "tenant1".into(),
        provider: "provider1".into(),
        resolver: "resolver1".into(),
    }
}

#[test]
fn grant_view_json_keys_match_cw_grant_resp() {
    use private_inference_rent::accrual::{commit_accrual, AccrualRate, HeightWindow};
    let bid = tagged_hash(b"bid", &[b"json"]);
    let mut cell = EscrowCell::open(100, bid, members()).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("l", "b".into());
    let (wit, pubv) = commit_accrual(
        HeightWindow {
            open_height: 10,
            close_height: 50,
        },
        AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[b"grant-view"]),
        tagged_hash(b"hdr", &[b"open"]),
        tagged_hash(b"hdr", &[b"close"]),
    )
    .unwrap();
    cell.accrue_from_witness(wit, pubv.clone()).unwrap();
    let grant = cell
        .close(EscrowParty::Tenant, &mut leases, "l", None)
        .unwrap();
    assert_eq!(grant.earned_zat, 40, "private split stays on the grant");
    let view = grant.view();
    let v = serde_json::to_value(&view).unwrap();
    assert_eq!(v["cell_id"], hex::encode(grant.cell_id));
    assert_eq!(v["closer"], "tenant");
    assert_eq!(v["earned_zat"], 0, "public earned is never the closer bill");
    assert_eq!(v["remainder_zat"], 100, "public remainder is deposit accounting");
    assert_eq!(v["recorded"], true);
    assert_eq!(v["accrual_commitment"], hex::encode(pubv.commitment));
    assert_eq!(v["open_header_hash"], hex::encode(pubv.open_header_hash));
    assert_eq!(v["close_header_hash"], hex::encode(pubv.close_header_hash));
    let obj = v.as_object().expect("object");
    assert!(obj.contains_key("accrual_commitment"));
    assert!(obj.contains_key("open_header_hash"));
    assert!(obj.contains_key("close_header_hash"));
    let back: GrantView = serde_json::from_value(v).unwrap();
    assert_eq!(back, view);
}

#[test]
fn escrow_cell_id_matches_contract_tag() {
    let bid = [7u8; 32];
    let cell = EscrowCell::open(100, bid, members()).unwrap();
    let expect = tagged_hash(
        b"escrow-cell-v1",
        &[
            &100u64.to_le_bytes(),
            &bid,
            b"tenant1",
            b"provider1",
            b"resolver1",
        ],
    );
    assert_eq!(cell.cell_id, expect);
}

#[test]
fn escrow_partial_earned_close_denies_bearer_and_splits_pool() {
    let r = run_escrow_partial_close().expect("partial escrow close");
    assert!(r.winner_accessed);
    assert!(r.closed_denied);
    assert_eq!(r.earned_zat + r.remainder_zat, r.deposit_zat);
    assert_eq!(r.pool_after, 0);
    assert_ne!(r.earned_zat, r.deposit_zat, "must be partial, not full-pay rent");
}

#[test]
fn resolver_ws_without_attest_cannot_sign() {
    let bid = tagged_hash(b"bid", &[b"ws"]);
    let mut cell = EscrowCell::open(50, bid, members()).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("l", "b".into());
    cell.close(EscrowParty::Provider, &mut leases, "l", None)
        .unwrap();
    let attrs = CloseEventAttrs {
        action: CloseAction::Close,
        cell_id: cell.cell_id,
        closer: EscrowParty::Provider,
        earned_zat: 0,
        remainder_zat: 50,
    };
    let notice = ResolverNotice {
        delivered_over_ws: true,
        attest: None,
    };
    let err = resolver_may_sign_from_notice(
        &cell,
        "resolver1",
        &notice,
        [1u8; 32],
        [2u8; 32],
        &attrs,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::WsOnlyUnverified);
}

#[test]
fn resolver_sign_requires_verified_event_and_grant() {
    let bid = tagged_hash(b"bid", &[b"lc"]);
    let mut cell = EscrowCell::open(50, bid, members()).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("l", "b".into());
    cell.close(EscrowParty::Tenant, &mut leases, "l", None)
        .unwrap();
    let attrs = CloseEventAttrs {
        action: CloseAction::Close,
        cell_id: cell.cell_id,
        closer: EscrowParty::Tenant,
        earned_zat: 0,
        remainder_zat: 50,
    };
    let header = tagged_hash(b"hdr", &[b"1"]);
    let tx = tagged_hash(b"tx", &[b"1"]);
    let attest = CloseEventAttest::bind(header, tx, &attrs);
    let notice = ResolverNotice {
        delivered_over_ws: true,
        attest: Some(attest),
    };
    resolver_may_sign_from_notice(&cell, "resolver1", &notice, header, tx, &attrs).unwrap();

    let mut bad = attrs.clone();
    bad.earned_zat = 50;
    let err = resolver_may_sign_from_notice(&cell, "resolver1", &notice, header, tx, &bad)
        .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
}

#[test]
fn vote_extensions_are_not_on_the_escrow_notice_path() {
    let src = include_str!("../src/escrow_notice.rs");
    assert!(!src.contains("vote_extension") && !src.contains("VoteExtension") && !src.contains("ExtendVote"));
    let plan = include_str!("../docs/ESCROW_CLOSE_PLAN.md");
    assert!(plan.contains("Vote extensions are out"));
}
