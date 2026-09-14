//! Several rent + pay rounds. Each loop: winner access, loser denied, close then deny.
//! `cargo test --features e2e --test rent_rounds`

use private_inference_rent::run_rent_rounds;

fn assert_lease_contract(r: &private_inference_rent::RentRound) {
    assert!(r.winner_accessed, "round {}: winner must access after accept", r.n);
    assert!(r.loser_denied, "round {}: loser must not access", r.n);
    assert!(r.closed_denied, "round {}: winner must not access after close", r.n);
    assert_eq!(r.paid_zat, 2_000);
    assert_eq!(r.pool_after, 0);
}

#[test]
fn three_rent_rounds_pay_once_each() {
    let rounds = run_rent_rounds(3).expect("three rent rounds");
    assert_eq!(rounds.len(), 3);
    for (i, r) in rounds.iter().enumerate() {
        assert_eq!(r.n, (i + 1) as u32);
        assert_lease_contract(r);
        assert!(!r.bid_commitment_hex.is_empty());
    }
}

#[test]
fn hundred_rent_rounds_lease_access_close() {
    let rounds = run_rent_rounds(100).expect("100 rent rounds");
    assert_eq!(rounds.len(), 100);
    for r in &rounds {
        assert_lease_contract(r);
    }
}

#[test]
fn hundred_rent_rounds_pay_once_each() {
    let rounds = run_rent_rounds(100).expect("100 rent rounds pay once");
    assert_eq!(rounds.len(), 100);
    let mut seen = std::collections::BTreeSet::new();
    for r in &rounds {
        assert_lease_contract(r);
        assert!(seen.insert(r.n), "round {} paid twice", r.n);
        assert_eq!(r.paid_zat, 2_000);
        assert_eq!(r.pool_after, 0);
    }
}

#[test]
fn access_is_optional_unless_pir_require_access() {
    let rounds = run_rent_rounds(2).unwrap();
    assert_eq!(rounds.len(), 2);
    for r in &rounds {
        assert_lease_contract(r);
    }
    if std::env::var("PIR_REQUIRE_ACCESS").ok().as_deref() == Some("1") {
        assert!(rounds.iter().all(|r| r.accessed), "{rounds:?}");
    }
}
