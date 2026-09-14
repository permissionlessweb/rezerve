//! FROST seats: threshold + wrong-group. Seats cloned across fns, not OS processes.

use private_inference_rent::frost::{FrostError, FrostGroup, FrostSeat};
use private_inference_rent::tagged_hash;

fn holder_a(seat: FrostSeat, msg: &[u8], group: &FrostGroup) -> Result<Vec<u8>, FrostError> {
    // Separate stack frame only — not an OS process (NS6 owns that story).
    group.sign_with_seats(msg, &[seat])
}

fn holder_pair(s0: FrostSeat, s1: FrostSeat, msg: &[u8], group: &FrostGroup) -> Result<Vec<u8>, FrostError> {
    group.sign_with_seats(msg, &[s0, s1])
}

#[test]
fn one_seat_below_threshold_fails() {
    let g = FrostGroup::dealer(3, 2).unwrap();
    let msg = tagged_hash(b"frost-seat", &[b"msg"]);
    let mut g = g;
    let seat = g.take_seat(0).unwrap();
    assert_eq!(
        holder_a(seat, &msg, &g),
        Err(FrostError::BelowThreshold { have: 1, need: 2 })
    );
}

#[test]
fn two_seats_sign_and_verify() {
    let g = FrostGroup::dealer(3, 2).unwrap();
    let msg = tagged_hash(b"frost-seat", &[b"ok"]);
    let seats = g.seats();
    let sig = holder_pair(seats[0].clone(), seats[1].clone(), &msg, &g).expect("sign");
    g.verify(&msg, &sig).expect("verify");
}

#[test]
fn wrong_group_seat_does_not_verify_here() {
    let here = FrostGroup::dealer(3, 2).unwrap();
    let other = FrostGroup::dealer(3, 2).unwrap();
    let msg = tagged_hash(b"frost-seat", &[b"xgroup"]);
    let foreign = other.seats();
    assert!(
        here.sign_with_seats(&msg, &foreign[..2]).is_err(),
        "foreign seats must not produce a signature on this group"
    );
}

#[test]
fn os_holders_sign_and_verify() {
    let mut g = FrostGroup::dealer(3, 2).unwrap();
    let msg = tagged_hash(b"frost-seat", &[b"os"]);
    let seats = g.issue_seats();
    assert_eq!(g.remaining_shares(), 0);
    let sig = private_inference_rent::sign_with_os_holders(&g, &msg, &seats[..2])
        .expect("os holders");
    g.verify(&msg, &sig).unwrap();
}

#[test]
fn sign_fails_after_issue_seats() {
    let mut g = FrostGroup::dealer(3, 2).unwrap();
    let msg = tagged_hash(b"frost-seat", &[b"issued"]);
    let seats = g.issue_seats();
    assert_eq!(g.remaining_shares(), 0);
    assert_eq!(g.sign(&msg), Err(FrostError::SeatsIssued));
    let sig = g.sign_with_seats(&msg, &seats[..2]).expect("held seats");
    g.verify(&msg, &sig).unwrap();
}

fn ns5_parts() -> [(&'static str, &'static [&'static str]); 2] {
    [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ]
}

/// Credited ZAP1+IBC value cannot move without a FROST sig from OS holder processes.
#[test]
fn os_holders_unsigned_cannot_spend_zap1_credit() {
    use private_inference_rent::committee::demo_layered_committees;
    use private_inference_rent::frost_pool::FrostThresholdPool;
    use private_inference_rent::local_hosting_bundle;
    use private_inference_rent::{SettlementBook, SpendAuth, WorkReceipt};

    let group = tagged_hash(b"ns5-pool", &[b"g"]);
    let note = tagged_hash(b"ns5-pool", &[b"n"]);
    let bid = tagged_hash(b"ns5-bid", &[b"oob"]);
    let mut frost = FrostGroup::dealer(3, 2).unwrap();
    let seats = frost.issue_seats();
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost.clone())
        .bind_bid(bid);
    let msg = FrostGroup::spend_message(&group, &note, 9_000);
    let sig = private_inference_rent::sign_with_os_holders(&frost, &msg, &seats[..2])
        .expect("os holders sign spend");
    let signed = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &ns5_parts(),
        group,
        note,
        9_000,
        Some(bid),
    )
    .unwrap()
    .with_frost_sig(sig);
    let bundle = local_hosting_bundle(group, note, 9_000, "NS5", "sib");
    private_inference_rent::accept_on_zap1_client(&bundle).unwrap();
    pool.credit_deposit_zap1(&bundle, &signed).unwrap();
    assert_eq!(pool.balance_zat, 9_000);

    let unsigned = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &ns5_parts(),
        group,
        note,
        9_000,
        Some(bid),
    )
    .unwrap();
    let r = WorkReceipt::bind("ask-ns5", bid, 9_000);
    let mut book = SettlementBook::new();
    let err = book.pay_from_pool(&mut pool, &r, &unsigned).unwrap_err();
    assert!(
        format!("{err:?}").contains("Unauthorized") || format!("{err}").contains("frost"),
        "{err:?}"
    );
    assert_eq!(pool.balance_zat, 9_000, "unsigned must not move credited value");
}

#[test]
fn os_holders_wrong_group_cannot_spend_zap1_credit() {
    use private_inference_rent::committee::demo_layered_committees;
    use private_inference_rent::frost_pool::FrostThresholdPool;
    use private_inference_rent::local_hosting_bundle;
    use private_inference_rent::{SettlementBook, SpendAuth, WorkReceipt};

    let group = tagged_hash(b"ns5-pool", &[b"g2"]);
    let note = tagged_hash(b"ns5-pool", &[b"n2"]);
    let bid = tagged_hash(b"ns5-bid", &[b"oob2"]);
    let mut frost = FrostGroup::dealer(3, 2).unwrap();
    let seats = frost.issue_seats();
    let mut other = FrostGroup::dealer(3, 2).unwrap();
    let foreign = other.issue_seats();
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost.clone())
        .bind_bid(bid);
    let msg = FrostGroup::spend_message(&group, &note, 3_000);
    let good = private_inference_rent::sign_with_os_holders(&frost, &msg, &seats[..2]).unwrap();
    let signed = SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &ns5_parts(),
        group,
        note,
        3_000,
        Some(bid),
    )
    .unwrap()
    .with_frost_sig(good);
    let b2 = local_hosting_bundle(group, note, 3_000, "NS5b", "sib");
    private_inference_rent::accept_on_zap1_client(&b2).unwrap();
    pool.credit_deposit_zap1(&b2, &signed)
        .unwrap();

    let foreign_sig =
        private_inference_rent::sign_with_os_holders(&other, &msg, &foreign[..2]).unwrap();
    let forged = signed.clone().with_frost_sig(foreign_sig);
    let r = WorkReceipt::bind("ask-ns5b", bid, 3_000);
    let mut book = SettlementBook::new();
    assert!(
        book.pay_from_pool(&mut pool, &r, &forged).is_err(),
        "wrong-group OS holders must not debit"
    );
    assert_eq!(pool.balance_zat, 3_000);

    book.pay_from_pool(&mut pool, &r, &signed).unwrap();
    assert_eq!(pool.balance_zat, 0);
}

#[test]
fn debug_redacts_key_package() {
    let g = FrostGroup::dealer(3, 2).unwrap();
    let mut g = g;
    let s = format!("{:?}", g.take_seat(0).unwrap());
    assert!(s.contains("<redacted>"));
}
