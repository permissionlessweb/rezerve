//! Slice 3: after grant exists, LeaseBook access kill is honored (not a second escrow).

use private_inference_rent::access::{DerivedAccess, LeaseAccessError, LeaseBook};
use private_inference_rent::accrual::{commit_accrual, AccrualRate, HeightWindow};
use private_inference_rent::escrow::{EscrowCell, EscrowMemberIds, EscrowParty};
use private_inference_rent::tagged_hash;

#[test]
fn accrue_partial_then_leasebook_close_after_grant_denies_bearer() {
    let deposit = 100u64;
    let earned = 40u64;
    let bid = tagged_hash(b"bid", &[b"provider-honor"]);
    let mut cell = EscrowCell::open(
        deposit,
        bid,
        EscrowMemberIds {
            tenant: "tenant1".into(),
            provider: "provider1".into(),
            resolver: "resolver1".into(),
        },
    )
    .unwrap();
    let (wit, pubv) = commit_accrual(
        HeightWindow {
            open_height: 10,
            close_height: 50,
        },
        AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[b"honor"]),
        tagged_hash(b"hdr", &[b"open-honor"]),
        tagged_hash(b"hdr", &[b"close-honor"]),
    )
    .unwrap();
    assert_eq!(wit.earned_zat, earned);
    cell.accrue_from_witness(wit, pubv).unwrap();
    assert_eq!(cell.earned_zat, earned);
    assert_ne!(earned, deposit);

    let key = tagged_hash(b"sess", &[b"honor"]);
    let winner = DerivedAccess::from_session("ask-honor", &key, &bid);
    let bearer = winner.bearer_hex();
    let mut leases = LeaseBook::new();
    leases.accept_bid("lease-honor", bearer.clone());
    leases.access("lease-honor", &bearer).unwrap();

    let grant = cell
        .close(EscrowParty::Provider, &mut leases, "lease-honor", None)
        .unwrap();
    assert!(grant.recorded);
    assert_eq!(grant.earned_zat, earned);
    assert_eq!(grant.remainder_zat, deposit - earned);
    assert!(cell.grant.is_some());

    // Honor is a second LeaseBook::close after the grant exists (access kill, not escrow).
    leases.close("lease-honor").unwrap();
    assert!(!leases.is_open("lease-honor"));
    assert_eq!(
        leases.access("lease-honor", &bearer),
        Err(LeaseAccessError::Closed)
    );
}
