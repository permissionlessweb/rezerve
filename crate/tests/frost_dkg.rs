//! Real frost-ed25519 DKG part1/part2/part3 (3 parties, min_signers=2).

use frost_ed25519::Identifier;
use private_inference_rent::access::LeaseBook;
use private_inference_rent::accrual::{commit_accrual, AccrualRate, HeightWindow};
use private_inference_rent::custody::{CustodyError, EscrowHolders};
use private_inference_rent::escrow::{EscrowCell, EscrowMemberIds, EscrowParty};
use private_inference_rent::frost::{FrostError, FrostGroup};
use private_inference_rent::frost_dkg::{
    dkg_escrow_seats, dkg_three_party, sign_tenant_provider, DkgParty, DKG_MAX_SIGNERS,
    DKG_MIN_SIGNERS,
};
use private_inference_rent::tagged_hash;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::fs;

fn members() -> EscrowMemberIds {
    EscrowMemberIds {
        tenant: "tenant-a".into(),
        provider: "provider-b".into(),
        resolver: "resolver-c".into(),
    }
}

fn exclusive_src(name: &str) -> String {
    let p = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), name);
    fs::read_to_string(&p).unwrap_or_else(|_| panic!("{p}"))
}

#[test]
fn three_round_dkg_group_verifies_spend() {
    let group = dkg_three_party().expect("dkg");
    assert_eq!(group.min_signers, DKG_MIN_SIGNERS);
    assert_eq!(group.max_signers, DKG_MAX_SIGNERS);
    assert_eq!(DKG_MIN_SIGNERS, 2);
    assert_eq!(DKG_MAX_SIGNERS, 3);
    let gid = tagged_hash(b"frost-group", &[b"dkg"]);
    let note = tagged_hash(b"note", &[b"dkg-spend"]);
    let msg = FrostGroup::spend_message(&gid, &note, 1_000);
    let sig = sign_tenant_provider(&group, &msg).expect("tenant+provider sign");
    group.verify(&msg, &sig).expect("group verifies spend");
}

#[test]
fn frost_dkg_source_has_no_dealer() {
    let src = exclusive_src("src/frost_dkg.rs");
    assert!(
        !src.contains("generate_with_dealer"),
        "dealer generate_with_dealer must not appear in frost_dkg.rs"
    );
    assert!(!src.contains("FrostGroup::dealer"));
    assert!(!src.contains("DummyStwo"));
    assert!(!src.contains("std::env::args"));
    assert!(
        src.contains("part1(") && src.contains("part2(") && src.contains("part3("),
        "expected DKG part1/part2/part3 calls"
    );
    assert!(src.contains("dkg_escrow_seats"));
    assert!(src.contains("DKG_MAX_SIGNERS: u16 = 3"));
    assert!(src.contains("DKG_MIN_SIGNERS: u16 = 2"));
    assert!(src.contains("dummy verifying key"));
    assert!(src.contains("Vec::new()"));
    assert!(src.contains("verifying_share"));
    assert!(src.contains("part3 verifying share"));
    assert!(src.contains("seat group verifying key"));
    assert!(src.contains("group.is_dealer()"));
    assert!(src.contains("dealer leftover"));
}

#[test]
fn dkg_parties_run_part1_part2_part3() {
    let mut rng = OsRng;
    let mut parties = [
        DkgParty::from_index(1).unwrap(),
        DkgParty::from_index(2).unwrap(),
        DkgParty::from_index(3).unwrap(),
    ];
    let mut r1 = BTreeMap::new();
    for p in &mut parties {
        let pkg = p.round1(&mut rng).expect("part1");
        r1.insert(p.identifier(), pkg);
    }
    assert_eq!(r1.len(), 3);

    let mut r2_inbox: BTreeMap<Identifier, BTreeMap<Identifier, _>> = BTreeMap::new();
    for p in &mut parties {
        let mut others = r1.clone();
        others.remove(&p.identifier());
        let pkgs = p.round2(&others).expect("part2");
        assert!(p.key_package().is_none());
        for (recv, pkg) in pkgs {
            r2_inbox.entry(recv).or_default().insert(p.identifier(), pkg);
        }
    }

    let mut vks = Vec::new();
    for p in &mut parties {
        let mut others = r1.clone();
        others.remove(&p.identifier());
        let inbox = r2_inbox.get(&p.identifier()).expect("inbox");
        let (kp, pk) = p.round3(&others, inbox).expect("part3");
        assert_eq!(kp.identifier(), &p.identifier());
        assert_eq!(kp.min_signers().clone(), DKG_MIN_SIGNERS);
        assert!(p.key_package().is_some());
        let seat = p.seat().expect("part3 seat");
        assert_eq!(seat.identifier_bytes(), p.identifier().serialize());
        assert_eq!(pk.verifying_shares().len(), DKG_MAX_SIGNERS as usize);
        vks.push(pk.verifying_key().serialize().expect("vk"));
        assert!(p.round3(&others, inbox).is_err(), "part3 must not rerun");
    }
    assert_eq!(vks.len(), 3);
    assert_eq!(vks[0], vks[1]);
    assert_eq!(vks[1], vks[2]);
}

#[test]
fn custody_source_dkg_not_dealer_or_argv() {
    let src = exclusive_src("src/custody.rs");
    assert!(!src.contains("generate_with_dealer"));
    assert!(!src.contains("FrostGroup::dealer"));
    assert!(!src.contains("std::env::args"));
    assert!(!src.contains("DummyStwo"));
    assert!(src.contains("from_dkg"));
    assert!(src.contains("dkg_escrow_seats"));
    assert!(src.contains("PIR_FROST_SEAT"));
    assert!(src.contains("ArgvForbidden"));
    assert!(src.contains("DuplicateMember"));
    assert!(src.contains("decode_product_seat"));
    assert!(src.contains("dkg_identifier_bytes"));
    assert!(src.contains("require_dkg_seat_roles"));
    assert!(src.contains("require_dkg_group"));
    assert!(src.contains("require_seat_in_group"));
    assert!(src.contains("require_same_dkg_group"));
    assert!(src.contains("seat_group_vk"));
    assert!(src.contains("dummy verifying key"));
    assert!(src.contains("group.is_dealer()"));
    assert!(src.contains("dealer leftover"));
    assert!(src.contains("let [tenant, provider, resolver] = seats"));
    assert!(src.contains("decode_product_seat(&tenant.encode()?"));
    assert!(
        src.contains("line.contains(\"--key-package\")"),
        "stdin/env must reject argv --key-package, not parse it"
    );
}

#[test]
fn frost_dealer_is_named_negative_control_not_product_constructor() {
    let src = exclusive_src("src/frost.rs");
    assert!(src.contains("generate_with_dealer"));
    assert!(src.contains("from_key_packages"));
    assert!(src.contains("Negative-control only"));
    assert!(src.contains("dkg_escrow_seats"));
    assert!(src.contains("EscrowHolders::from_dkg"));
    assert!(src.contains("dealer_issued: true"));
    assert!(src.contains("dealer_issued: false"));
    assert!(src.contains("pub fn is_dealer"));
    assert!(
        src.contains("not product custody"),
        "FrostGroup::dealer must not be the product constructor"
    );
}

#[test]
fn exclusive_product_tests_construct_frost_via_dkg() {
    let close = exclusive_src("tests/escrow_close.rs");
    let funded = close
        .split("fn funded_pool")
        .nth(1)
        .expect("funded_pool")
        .split("#[test]")
        .next()
        .expect("funded_pool body");
    assert!(
        funded.contains("EscrowHolders::from_dkg"),
        "escrow close must construct FrostGroup via DKG among tenant, provider, resolver"
    );
    assert!(
        !funded.contains("FrostGroup::dealer"),
        "funded_pool must not call FrostGroup::dealer"
    );
    assert!(
        !close.contains("FrostGroup::dealer"),
        "product escrow close must not call FrostGroup::dealer"
    );
    assert!(!close.contains("generate_with_dealer"));
    assert!(close.contains("EscrowHolders::from_dkg"));

    let shielded = exclusive_src("tests/escrow_shielded.rs");
    assert!(shielded.contains("EscrowHolders::from_dkg"));
    assert!(
        !shielded.contains("FrostGroup::dealer"),
        "escrow_shielded must not call FrostGroup::dealer"
    );
    assert!(
        !shielded.contains("generate_with_dealer"),
        "escrow_shielded must not call generate_with_dealer"
    );

    let settle = exclusive_src("tests/settlement_work.rs");
    assert!(settle.contains("dkg_escrow_seats"));
    assert!(
        !settle.contains("FrostGroup::dealer"),
        "settlement_work must not call FrostGroup::dealer"
    );
    assert!(!settle.contains("generate_with_dealer"));
    assert!(settle.contains("frost.is_dealer()"));
    assert!(close.contains("frost.is_dealer()"));
    assert!(shielded.contains("frost.is_dealer()"));
}

#[test]
fn escrow_holders_seats_from_dkg_not_dealer() {
    let members = members();
    let (group, holders) = EscrowHolders::from_dkg(&members).expect("dkg holders");
    assert_eq!(group.min_signers, 2);
    assert_eq!(group.max_signers, 3);
    assert_eq!(group.remaining_shares(), 0);
    assert_eq!(group.sign(b"must-use-seats").unwrap_err(), FrostError::SeatsIssued);
    assert!(
        sign_tenant_provider(&group, b"must-use-holders").is_err(),
        "product DKG group must not retain part3 KeyPackages"
    );
    let msg = b"dkg-custody-sign";
    let sig = holders.happy_sign(&group, msg).expect("tenant+provider");
    group.verify(msg, &sig).expect("verify");
    let env = EscrowHolders::encode_seat_env(holders.seat("tenant-a").unwrap()).unwrap();
    assert!(!env.contains("--key-package"));
    assert!(!env.starts_with('-'));
    let decoded = EscrowHolders::load_seat_from_stdin(&env).unwrap();
    assert_eq!(
        decoded.identifier_bytes(),
        holders.seat("tenant-a").unwrap().identifier_bytes()
    );
}

#[test]
fn dkg_holders_resolver_denied_until_grant() {
    let members = members();
    let (group, holders) = EscrowHolders::from_dkg(&members).expect("dkg holders");
    let bid = tagged_hash(b"bid", &[b"dkg-grant"]);
    let mut cell = EscrowCell::open(100, bid, members.clone()).unwrap();
    let msg = b"resolver-try";
    assert_eq!(
        holders
            .sign_after_grant(&cell, &group, msg, "tenant-a")
            .unwrap_err(),
        CustodyError::ResolverDenied
    );
    let (wit, pubv) = commit_accrual(
        HeightWindow {
            open_height: 10,
            close_height: 50,
        },
        AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[b"dkg-grant"]),
        tagged_hash(b"hdr", &[b"open-dkg"]),
        tagged_hash(b"hdr", &[b"close-dkg"]),
    )
    .unwrap();
    assert_eq!(wit.earned_zat, 40);
    cell.accrue_from_witness(wit, pubv).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("lease-dkg", "x".into());
    cell.close(EscrowParty::Tenant, &mut leases, "lease-dkg", None)
        .unwrap();
    let sig = holders
        .sign_after_grant(&cell, &group, msg, "tenant-a")
        .expect("granted");
    group.verify(msg, &sig).expect("verify");
}

#[test]
fn dkg_party_rejects_out_of_range_identifier() {
    assert!(DkgParty::from_index(0).is_err());
    assert!(DkgParty::from_index(4).is_err());
    assert!(DkgParty::from_index(1).is_ok());
}

#[test]
fn load_seat_from_stdin_rejects_empty_and_unknown_member() {
    let members = members();
    let (_group, holders) = EscrowHolders::from_dkg(&members).expect("dkg holders");
    assert_eq!(
        EscrowHolders::load_seat_from_stdin("").unwrap_err(),
        CustodyError::SeatSource
    );
    assert!(matches!(
        holders.seat("not-a-member"),
        Err(CustodyError::UnknownMember(_))
    ));
}

#[test]
fn key_package_not_on_argv() {
    let err = EscrowHolders::load_seat_from_argv(["pir-frost-holder", "--key-package", "00"])
        .unwrap_err();
    assert_eq!(err, CustodyError::ArgvForbidden);
}

#[test]
fn from_dkg_rejects_empty_member_ids() {
    let empty_tenant = EscrowMemberIds {
        tenant: String::new(),
        provider: "provider-b".into(),
        resolver: "resolver-c".into(),
    };
    assert_eq!(
        EscrowHolders::from_dkg(&empty_tenant).unwrap_err(),
        CustodyError::EmptyMember
    );
    let empty_provider = EscrowMemberIds {
        tenant: "tenant-a".into(),
        provider: String::new(),
        resolver: "resolver-c".into(),
    };
    assert_eq!(
        EscrowHolders::from_dkg(&empty_provider).unwrap_err(),
        CustodyError::EmptyMember
    );
    let empty_resolver = EscrowMemberIds {
        tenant: "tenant-a".into(),
        provider: "provider-b".into(),
        resolver: String::new(),
    };
    assert_eq!(
        EscrowHolders::from_dkg(&empty_resolver).unwrap_err(),
        CustodyError::EmptyMember
    );
}

#[test]
fn from_issued_needs_three_dkg_seats_and_binds_dkg_not_dealer() {
    let (group, seats) = dkg_escrow_seats().expect("dkg seats");
    assert_eq!(group.remaining_shares(), 0);
    assert_eq!(seats.len(), 3);
    assert_eq!(
        EscrowHolders::from_issued(&members(), seats[..2].to_vec()).unwrap_err(),
        CustodyError::NeedThreeSeats
    );
    let holders = EscrowHolders::from_issued(&members(), seats.to_vec()).expect("bind dkg");
    let sig = holders.happy_sign(&group, b"issued-dkg").expect("sign");
    group.verify(b"issued-dkg", &sig).expect("verify");
    let shuffled = vec![seats[1].clone(), seats[0].clone(), seats[2].clone()];
    assert!(
        EscrowHolders::from_issued(&members(), shuffled).is_err(),
        "EscrowHolders must bind DKG identifiers 1,2,3 as tenant,provider,resolver"
    );
}

#[test]
fn provider_is_threshold_member_unsigned_cannot_spend() {
    let (group, holders) = EscrowHolders::from_dkg(&members()).expect("dkg holders");
    assert!(!group.is_dealer(), "product DKG must not be dealer-issued");
    let provider = holders.seat("provider-b").expect("provider seat");
    let tenant = holders.seat("tenant-a").expect("tenant seat");
    let resolver = holders.seat("resolver-c").expect("resolver seat");
    assert_eq!(
        provider.identifier_bytes(),
        frost_ed25519::Identifier::try_from(2u16)
            .unwrap()
            .serialize(),
        "provider must be DKG identifier 2"
    );
    assert_eq!(
        tenant.identifier_bytes(),
        frost_ed25519::Identifier::try_from(1u16)
            .unwrap()
            .serialize()
    );
    assert_eq!(
        resolver.identifier_bytes(),
        frost_ed25519::Identifier::try_from(3u16)
            .unwrap()
            .serialize()
    );
    let msg = b"side-market-spend";
    let happy = holders.happy_sign(&group, msg).expect("tenant+provider");
    group.verify(msg, &happy).expect("happy path verifies");
    assert_eq!(
        group
            .sign_with_seats(msg, &[provider.clone()])
            .unwrap_err(),
        FrostError::BelowThreshold { have: 1, need: 2 },
        "provider seat alone cannot happy-path spend"
    );
    let dealer = FrostGroup::dealer(3, 2).expect("negative-control dealer");
    assert!(dealer.is_dealer());
    assert_eq!(
        EscrowHolders::from_dkg(&members())
            .expect("fresh dkg")
            .0
            .is_dealer(),
        false
    );
}

#[test]
fn dkg_runs_are_not_a_fixed_verifying_key() {
    let a = dkg_three_party().expect("dkg a");
    let b = dkg_three_party().expect("dkg b");
    assert_ne!(
        a.verifying_key, b.verifying_key,
        "OsRng part1 must not emit a dummy constant group key"
    );
}

#[test]
fn dkg_escrow_seats_reject_below_threshold() {
    let (group, seats) = dkg_escrow_seats().expect("dkg seats");
    assert_eq!(group.remaining_shares(), 0);
    assert_eq!(
        group.sign_with_seats(b"one-seat", &seats[..1]).unwrap_err(),
        FrostError::BelowThreshold { have: 1, need: 2 }
    );
    let sig = group
        .sign_with_seats(b"two-seats", &seats[..2])
        .expect("min=2");
    group.verify(b"two-seats", &sig).expect("verify");
}

#[test]
fn dkg_party_key_package_absent_until_part3() {
    let mut rng = OsRng;
    let mut p = DkgParty::from_index(1).unwrap();
    assert!(p.key_package().is_none());
    assert!(p.seat().is_err());
    let _ = p.round1(&mut rng).expect("part1");
    assert!(p.key_package().is_none());
    assert!(p.seat().is_err());
    assert!(p.round1(&mut rng).is_err(), "part1 must not rerun");
}

#[test]
fn dkg_round2_without_round1_and_round3_without_round2_fail() {
    let mut p = DkgParty::from_index(1).unwrap();
    let empty_r1: BTreeMap<Identifier, frost_ed25519::keys::dkg::round1::Package> =
        BTreeMap::new();
    let empty_r2: BTreeMap<Identifier, frost_ed25519::keys::dkg::round2::Package> =
        BTreeMap::new();
    assert!(p.round2(&empty_r1).is_err());
    assert!(p.round3(&empty_r1, &empty_r2).is_err());
}

#[test]
fn dkg_party_seat_is_stdin_env_not_argv() {
    let (group, seats) = dkg_escrow_seats().expect("dkg seats");
    assert_eq!(group.remaining_shares(), 0);
    let encoded = seats[0].encode().expect("encode");
    assert!(!encoded.contains("--key-package"));
    assert!(!encoded.starts_with('-'));
    assert!(encoded.contains(':'));
    let from_stdin = EscrowHolders::load_seat_from_stdin(&encoded).expect("stdin");
    assert_eq!(from_stdin.identifier_bytes(), seats[0].identifier_bytes());
    let argv = EscrowHolders::load_seat_from_argv([encoded.as_str()]).unwrap_err();
    assert_eq!(argv, CustodyError::ArgvForbidden);
}

#[test]
fn from_dkg_rejects_duplicate_member_ids() {
    let dup = EscrowMemberIds {
        tenant: "same".into(),
        provider: "same".into(),
        resolver: "resolver-c".into(),
    };
    assert_eq!(
        EscrowHolders::from_dkg(&dup).unwrap_err(),
        CustodyError::DuplicateMember
    );
}

#[test]
fn from_dkg_binds_identifiers_1_2_3_as_tenant_provider_resolver() {
    let members = members();
    let (group, holders) = EscrowHolders::from_dkg(&members).expect("dkg holders");
    assert_eq!(group.remaining_shares(), 0);
    let id = |i: u16| Identifier::try_from(i).unwrap().serialize();
    assert_eq!(
        holders.seat("tenant-a").unwrap().identifier_bytes(),
        id(1)
    );
    assert_eq!(
        holders.seat("provider-b").unwrap().identifier_bytes(),
        id(2)
    );
    assert_eq!(
        holders.seat("resolver-c").unwrap().identifier_bytes(),
        id(3)
    );
}

#[test]
fn load_seat_from_stdin_rejects_argv_shaped_and_mismatched_identity() {
    assert_eq!(
        EscrowHolders::load_seat_from_stdin("--key-package 00").unwrap_err(),
        CustodyError::ArgvForbidden
    );
    assert_eq!(
        EscrowHolders::load_seat_from_stdin("--key-package:00").unwrap_err(),
        CustodyError::ArgvForbidden
    );
    let (_group, seats) = dkg_escrow_seats().expect("dkg seats");
    let a = seats[0].encode().expect("a");
    let b = seats[1].encode().expect("b");
    let a_id = a.split_once(':').expect("a fmt").0;
    let b_pkg = b.split_once(':').expect("b fmt").1;
    let mixed = format!("{a_id}:{b_pkg}");
    assert!(EscrowHolders::load_seat_from_stdin(&mixed).is_err());
}

#[test]
fn dkg_round2_rejects_self_round1_package() {
    let mut rng = OsRng;
    let mut p = DkgParty::from_index(1).unwrap();
    let pkg = p.round1(&mut rng).expect("part1");
    let mut r1 = BTreeMap::new();
    r1.insert(p.identifier(), pkg);
    assert!(p.round2(&r1).is_err());
}

#[test]
fn dkg_round2_rejects_wrong_other_count() {
    let mut rng = OsRng;
    let mut a = DkgParty::from_index(1).unwrap();
    let mut b = DkgParty::from_index(2).unwrap();
    let _ = a.round1(&mut rng).expect("part1 a");
    let pkg_b = b.round1(&mut rng).expect("part1 b");
    let mut others = BTreeMap::new();
    others.insert(b.identifier(), pkg_b);
    assert!(a.round2(&others).is_err(), "part2 needs two other round1 packages");
}

#[test]
fn dkg_verifying_key_is_not_dummy_zero() {
    let group = dkg_three_party().expect("dkg");
    assert_ne!(group.verifying_key, [0u8; 32]);
    let (escrow, seats) = dkg_escrow_seats().expect("seats");
    assert_ne!(escrow.verifying_key, [0u8; 32]);
    assert_eq!(escrow.remaining_shares(), 0);
    assert_eq!(seats.len(), 3);
}

#[test]
fn sign_after_grant_pairs_resolver_with_provider_not_resolver() {
    let members = members();
    let (group, holders) = EscrowHolders::from_dkg(&members).expect("dkg holders");
    let bid = tagged_hash(b"bid", &[b"dkg-pair"]);
    let mut cell = EscrowCell::open(100, bid, members.clone()).unwrap();
    let (wit, pubv) = commit_accrual(
        HeightWindow {
            open_height: 10,
            close_height: 50,
        },
        AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[b"dkg-pair"]),
        tagged_hash(b"hdr", &[b"open-pair"]),
        tagged_hash(b"hdr", &[b"close-pair"]),
    )
    .unwrap();
    assert_eq!(wit.earned_zat, 40);
    cell.accrue_from_witness(wit, pubv).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("lease-pair", "x".into());
    cell.close(EscrowParty::Provider, &mut leases, "lease-pair", None)
        .unwrap();
    let msg = b"resolver-pair";
    assert_eq!(
        holders
            .sign_after_grant(&cell, &group, msg, "resolver-c")
            .unwrap_err(),
        CustodyError::ResolverDenied
    );
    assert!(matches!(
        holders.sign_after_grant(&cell, &group, msg, "stranger"),
        Err(CustodyError::UnknownMember(_))
    ));
    let sig = holders
        .sign_after_grant(&cell, &group, msg, "provider-b")
        .expect("resolver+provider");
    group.verify(msg, &sig).expect("verify");
}

#[test]
fn from_dkg_rejects_all_duplicate_member_pairs() {
    let tenant_resolver = EscrowMemberIds {
        tenant: "same".into(),
        provider: "provider-b".into(),
        resolver: "same".into(),
    };
    assert_eq!(
        EscrowHolders::from_dkg(&tenant_resolver).unwrap_err(),
        CustodyError::DuplicateMember
    );
    let provider_resolver = EscrowMemberIds {
        tenant: "tenant-a".into(),
        provider: "same".into(),
        resolver: "same".into(),
    };
    assert_eq!(
        EscrowHolders::from_dkg(&provider_resolver).unwrap_err(),
        CustodyError::DuplicateMember
    );
}

#[test]
fn happy_sign_rejects_group_that_retained_part3_packages() {
    let retained = dkg_three_party().expect("retained");
    assert_ne!(retained.remaining_shares(), 0);
    let (_group, holders) = EscrowHolders::from_dkg(&members()).expect("dkg holders");
    assert!(
        holders.happy_sign(&retained, b"no-retain").is_err(),
        "product sign must not use a group that still holds part3 KeyPackages"
    );
}

#[test]
fn happy_sign_rejects_foreign_dkg_group() {
    let (group_a, holders) = EscrowHolders::from_dkg(&members()).expect("a");
    let (group_b, _) = EscrowHolders::from_dkg(&members()).expect("b");
    assert_ne!(group_a.verifying_key, group_b.verifying_key);
    assert!(
        holders.happy_sign(&group_b, b"foreign-vk").is_err(),
        "DKG seats must match the group verifying key"
    );
    let sig = holders.happy_sign(&group_a, b"same-vk").expect("same run");
    group_a.verify(b"same-vk", &sig).expect("verify");
}

#[test]
fn dkg_round2_must_not_rerun() {
    let mut rng = OsRng;
    let mut parties = [
        DkgParty::from_index(1).unwrap(),
        DkgParty::from_index(2).unwrap(),
        DkgParty::from_index(3).unwrap(),
    ];
    let mut r1 = BTreeMap::new();
    for p in &mut parties {
        let pkg = p.round1(&mut rng).expect("part1");
        r1.insert(p.identifier(), pkg);
    }
    let mut others = r1.clone();
    others.remove(&parties[0].identifier());
    let _ = parties[0].round2(&others).expect("part2");
    assert!(parties[0].round2(&others).is_err(), "part2 must not rerun");
}

#[test]
fn dkg_round3_rejects_self_in_round1_or_inbox() {
    let mut rng = OsRng;
    let mut parties = [
        DkgParty::from_index(1).unwrap(),
        DkgParty::from_index(2).unwrap(),
        DkgParty::from_index(3).unwrap(),
    ];
    let mut r1 = BTreeMap::new();
    for p in &mut parties {
        let pkg = p.round1(&mut rng).expect("part1");
        r1.insert(p.identifier(), pkg);
    }
    let mut r2_inbox: BTreeMap<Identifier, BTreeMap<Identifier, _>> = BTreeMap::new();
    for p in &mut parties {
        let mut others = r1.clone();
        others.remove(&p.identifier());
        let pkgs = p.round2(&others).expect("part2");
        for (recv, pkg) in pkgs {
            r2_inbox.entry(recv).or_default().insert(p.identifier(), pkg);
        }
    }
    let id0 = parties[0].identifier();
    let inbox = r2_inbox.get(&id0).expect("inbox").clone();
    assert!(parties[0].round3(&r1, &inbox).is_err(), "round1 must omit self");
}

#[test]
fn load_seat_from_stdin_rejects_non_hex_and_missing_colon() {
    assert!(EscrowHolders::load_seat_from_stdin("not-a-seat").is_err());
    assert!(EscrowHolders::load_seat_from_stdin("zz:00").is_err());
    assert!(EscrowHolders::load_seat_from_stdin("00").is_err());
}

#[test]
fn dkg_party_debug_does_not_print_key_package() {
    let p = DkgParty::from_index(1).unwrap();
    let dbg = format!("{p:?}");
    assert!(dbg.contains("DkgParty"));
    assert!(dbg.contains("has_share"));
    assert!(!dbg.contains("key_package"));
    assert!(!dbg.contains("SecretPackage"));
}

#[test]
fn happy_sign_rejects_wrong_threshold_group() {
    let mut other = FrostGroup::dealer(5, 3).expect("dealer only as negative control");
    let _ = other.issue_seats();
    assert_eq!(other.remaining_shares(), 0);
    assert!(other.is_dealer());
    let (_group, holders) = EscrowHolders::from_dkg(&members()).expect("dkg holders");
    assert!(
        holders.happy_sign(&other, b"wrong-t").is_err(),
        "product custody is 3 parties min=2 DKG, not a dealer 5-of-3"
    );
}

#[test]
fn happy_sign_rejects_matching_threshold_dealer_group() {
    let mut other = FrostGroup::dealer(3, 2).expect("dealer only as negative control");
    let _ = other.issue_seats();
    assert!(other.is_dealer());
    assert_eq!(other.min_signers, 2);
    assert_eq!(other.max_signers, 3);
    assert_eq!(other.remaining_shares(), 0);
    let (_group, holders) = EscrowHolders::from_dkg(&members()).expect("dkg holders");
    assert_eq!(
        holders.happy_sign(&other, b"dealer-3-2").unwrap_err(),
        CustodyError::Frost(FrostError::Protocol("dealer leftover".into()))
    );
}

#[test]
fn from_dkg_group_is_not_dealer_issued() {
    let (group, _) = EscrowHolders::from_dkg(&members()).expect("dkg");
    assert!(!group.is_dealer());
    let (escrow, _) = dkg_escrow_seats().expect("seats");
    assert!(!escrow.is_dealer());
    let three = dkg_three_party().expect("three");
    assert!(!three.is_dealer());
    let dealer = FrostGroup::dealer(3, 2).expect("dealer only as negative control");
    assert!(dealer.is_dealer());
}

#[test]
fn from_issued_rejects_mixed_dkg_runs() {
    let (group_a, seats_a) = dkg_escrow_seats().expect("dkg a");
    let (group_b, seats_b) = dkg_escrow_seats().expect("dkg b");
    assert_ne!(group_a.verifying_key, group_b.verifying_key);
    let mixed = vec![
        seats_a[0].clone(),
        seats_a[1].clone(),
        seats_b[2].clone(),
    ];
    assert!(
        EscrowHolders::from_issued(&members(), mixed).is_err(),
        "EscrowHolders must not mix tenant/provider/resolver seats from two DKG runs"
    );
    let swapped_provider = vec![
        seats_a[0].clone(),
        seats_b[1].clone(),
        seats_a[2].clone(),
    ];
    assert!(
        EscrowHolders::from_issued(&members(), swapped_provider).is_err(),
        "provider seat from a second DKG run must not bind"
    );
}

#[test]
fn bind_rejects_seats_from_two_dkg_groups() {
    let (_ga, sa) = dkg_escrow_seats().expect("a");
    let (_gb, sb) = dkg_escrow_seats().expect("b");
    assert!(
        EscrowHolders::bind(&members(), sa[0].clone(), sa[1].clone(), sb[2].clone()).is_err(),
        "bind must require one DKG group verifying key"
    );
}

#[test]
fn dkg_escrow_seats_match_group_verifying_key() {
    let (group, seats) = dkg_escrow_seats().expect("dkg seats");
    assert_eq!(group.min_signers, 2);
    assert_eq!(group.max_signers, 3);
    let holders = EscrowHolders::from_issued(&members(), seats.to_vec()).expect("same run");
    let sig = holders.happy_sign(&group, b"same-run-vk").expect("sign");
    group.verify(b"same-run-vk", &sig).expect("verify");
}

#[test]
fn load_seat_from_env_is_not_argv() {
    let (_group, seats) = dkg_escrow_seats().expect("dkg seats");
    let encoded = EscrowHolders::encode_seat_env(&seats[0]).expect("encode");
    assert!(!encoded.contains("--key-package"));
    std::env::set_var(
        private_inference_rent::custody::PIR_FROST_SEAT_ENV,
        &encoded,
    );
    let loaded = EscrowHolders::load_seat_from_env().expect("PIR_FROST_SEAT");
    std::env::remove_var(private_inference_rent::custody::PIR_FROST_SEAT_ENV);
    assert_eq!(loaded.identifier_bytes(), seats[0].identifier_bytes());
    assert_eq!(
        EscrowHolders::load_seat_from_argv(["--key-package", encoded.as_str()]).unwrap_err(),
        CustodyError::ArgvForbidden
    );
}
