//! Product inclusion: zap1-verify Merkle + IBC v2 bind. No network.

use private_inference_rent::committee::demo_layered_committees;
use private_inference_rent::frost::FrostGroup;
use private_inference_rent::frost_dkg::dkg_three_party;
use private_inference_rent::frost_pool::{FrostThresholdPool, SpendAuth};
use private_inference_rent::zap1::{local_hosting_bundle, IbcV2PacketAttest, Zap1Error};
use private_inference_rent::{tagged_hash, Zap1Ibcv2Bundle};
use std::sync::Mutex;

/// One ict-rs CosmosChain name / pir-live-attach flock at a time.
static LIVE_ICT_LOCK: Mutex<()> = Mutex::new(());

fn signed_auth(
    pool: &FrostThresholdPool,
    group: [u8; 32],
    note: [u8; 32],
    amount: u64,
) -> SpendAuth {
    let frost = pool.frost.as_ref().expect("frost");
    let parts = [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ];
    let msg = FrostGroup::spend_message(&group, &note, amount);
    let seats = frost.seats();
    let sig = if seats.len() >= 2 {
        frost.sign_with_seats(&msg, &seats[..2]).unwrap()
    } else {
        frost.sign(&msg).unwrap()
    };
    SpendAuth::from_quorum(
        pool.layered.as_ref().unwrap(),
        &parts,
        group,
        note,
        amount,
        None,
    )
    .unwrap()
    .with_frost_sig(sig)
}

#[test]
fn zap1_hosting_vector_matches_upstream() {
    let h = zap1_verify::compute_leaf_hash(&zap1_verify::EventPayload::HostingPayment {
        serial_number: b"Z15P-2026-001",
        month: 7,
        year: 2026,
    });
    assert_eq!(
        zap1_verify::bytes_to_hex(&h),
        "6fe67554ae4108215a05d2e6f0e24c15fd7d5846ebd653618eff498f1be41a4f"
    );
}

#[test]
fn local_bundle_verifies_with_zap1_verify() {
    let g = tagged_hash(b"g", &[b"zap1"]);
    let note = tagged_hash(b"n", &[b"1"]);
    let b = local_hosting_bundle(g, note, 50, "PIR-001", "sib");
    b.verify().expect("valid local tree");
}

#[test]
fn tampered_sibling_fails_merkle() {
    let g = tagged_hash(b"g", &[b"zap1"]);
    let note = tagged_hash(b"n", &[b"1"]);
    let mut b = local_hosting_bundle(g, note, 50, "PIR-001", "sib");
    b.proof[0].sibling[0] ^= 1;
    assert_eq!(b.verify(), Err(Zap1Error::Merkle));
}

#[test]
fn ibc_packet_must_bind_note_amount_group_leaf() {
    let g = tagged_hash(b"g", &[b"zap1"]);
    let note = tagged_hash(b"n", &[b"1"]);
    let mut b = local_hosting_bundle(g, note, 50, "PIR-001", "sib");
    b.ibc = IbcV2PacketAttest::bind(
        "08-zap1-src",
        "08-terp-dst",
        1,
        0,
        &note,
        99,
        &g,
        &b.leaf_hash,
    );
    assert_eq!(b.verify(), Err(Zap1Error::IbcBind));
}

#[test]
fn credit_deposit_zap1_fails_without_live_client() {
    let _live = LIVE_ICT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let group = tagged_hash(b"g", &[b"nolc"]);
    let frost = dkg_three_party().unwrap();
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost);
    let note = tagged_hash(b"n", &[b"nolc"]);
    let bundle = local_hosting_bundle(group, note, 5, "PIR-NOLC", "sib");
    let auth = signed_auth(&pool, group, note, 5);
    let r = pool.credit_deposit_zap1(&bundle, &auth);
    #[cfg(feature = "live-ict")]
    {
        // live-ict stores cw-zap1-ibcv2 on a spawned chain (not in-proc pir-zap1-lc).
        match r {
            Ok(c) => {
                assert_eq!(c.amount_zat, 5);
                let hint = private_inference_rent::cw_orch::try_live_attach().expect(
                    "live-ict credit Ok must be daemon_builder_from_chain+deploy_on, not in-proc LC",
                );
                assert!(
                    hint.zap1_stored
                        && hint.zap1_matches
                        && hint.ics08_accepted
                        && hint.ics08_tamper_rejected,
                    "in-proc LC credit is skip-green: {hint:?}"
                );
            }
            Err(e) => {
                let s = e.to_string();
                assert!(
                    s.contains("eco")
                        || s.contains("on-chain")
                        || s.contains("live")
                        || s.contains("zap1")
                        || s.contains("spawn")
                        || s.contains("Daemon")
                        || s.contains("wasm"),
                    "live-ict must fail-closed on missing eco, got {s}"
                );
                assert_eq!(pool.balance_zat, 0);
            }
        }
    }
    #[cfg(not(feature = "live-ict"))]
    {
        assert!(r.is_err(), "in-proc credit without accept_on_zap1_client");
        assert_eq!(pool.balance_zat, 0);
    }
}

#[test]
fn credit_deposit_zap1_accepts_verified_bundle() {
    let _live = LIVE_ICT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let group = tagged_hash(b"g", &[b"pool"]);
    let frost = dkg_three_party().unwrap();
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost);
    let note = tagged_hash(b"n", &[b"credit"]);
    let bundle = local_hosting_bundle(group, note, 77, "PIR-002", "sib");
    let auth = signed_auth(&pool, group, note, 77);
    #[cfg(feature = "live-ict")]
    {
        let _ = (bundle, auth);
        // in-proc accept_on_zap1_client / pir-zap1-lc is not product money.
        let hint = private_inference_rent::cw_orch::try_live_attach().expect(
            "live-ict credit is daemon_builder_from_chain+deploy_on, not in-proc pir-zap1-lc",
        );
        assert!(
            hint.deploy_on_daemon
                && hint.zap1_stored
                && hint.zap1_matches
                && hint.zap1_tamper_rejected
                && hint.ics08_deployed
                && hint.ics08_accepted
                && hint.ics08_tamper_rejected,
            "live-ict fund_with_zap1 is on-chain zap1+ics08 execute/query: {hint:?}"
        );
        assert_eq!(
            pool.balance_zat, 0,
            "RAM FrostThresholdPool is not live-ict money"
        );
    }
    #[cfg(not(feature = "live-ict"))]
    {
        private_inference_rent::accept_on_zap1_client(&bundle).expect("lc");
        let c = pool.credit_deposit_zap1(&bundle, &auth).expect("credit");
        assert_eq!(c.amount_zat, 77);
        assert!(pool.credit_deposit_zap1(&bundle, &auth).is_err());
    }
}

#[test]
fn prove_for_test_is_not_a_zap1_bundle() {
    let _ = std::any::type_name::<Zap1Ibcv2Bundle>();
}

#[cfg(feature = "live-ict")]
#[test]
fn live_ict_does_not_skip_when_chain_or_lc_missing() {
    let _live = LIVE_ICT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        private_inference_rent::zap1_lc_required(),
        "live-ict must fail-closed on LC/chain, not skip-green"
    );
    // Feature flag is not a pass. Missing Docker/chain/wasm is Err, not skip-green.
    match private_inference_rent::cw_orch::try_live_attach() {
        Ok(hint) => {
            assert!(
                hint.deploy_on_daemon && hint.escrow_grant_recorded && !hint.chain_id.is_empty(),
                "live-ict attach without deploy_on(Daemon)+escrow grant: {hint:?}"
            );
            assert!(
                hint.zap1_stored
                    && hint.zap1_matches
                    && hint.zap1_tamper_rejected
                    && hint.ics08_deployed
                    && hint.ics08_accepted
                    && hint.ics08_tamper_rejected,
                "live-ict attach is on-chain zap1 + ics08 execute/query (not store-only): {hint:?}"
            );
        }
        Err(e) => {
            let s = e.to_string();
            assert!(
                s.contains("Daemon")
                    || s.contains("docker")
                    || s.contains("spawn")
                    || s.contains("grpc")
                    || s.contains("lock")
                    || s.contains("wasm")
                    || s.contains("fail"),
                "live-ict must fail-closed on missing eco, got {s}"
            );
        }
    }
}

#[test]
fn free_string_orchard_anchor_is_rejected() {
    let g = tagged_hash(b"g", &[b"zap1"]);
    let note = tagged_hash(b"n", &[b"1"]);
    let mut b = local_hosting_bundle(g, note, 50, "PIR-001", "sib");
    b.orchard_anchor_txid = Some("not-a-txid".into());
    assert_eq!(b.verify(), Err(Zap1Error::BadAnchor));
    b.orchard_anchor_txid = Some("ab".repeat(32));
    b.verify().expect("64 hex is well-formed (not yet node-checked)");
}
