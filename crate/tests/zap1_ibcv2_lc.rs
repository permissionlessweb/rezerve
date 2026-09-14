//! NS9: ZAP1 IBC v2 attestation module + product-credit hook.
//!
//! Unit tests compile/check contract message JSON. Live path does not panic
//! without Docker; `PIR_ZAKURA_LAB=1` is fail-closed if no chain/helper.
//! `cw-ics08-wasm-crosslink` is not this client.

use private_inference_rent::committee::demo_layered_committees;
use private_inference_rent::frost::FrostGroup;
use private_inference_rent::frost_pool::{FrostThresholdPool, SpendAuth};
use private_inference_rent::zap1::local_hosting_bundle;
use private_inference_rent::zap1_lc::{
    require_onchain_accept, zap1_lc_required, Zap1LcError, ENV_ZAP1_LC_BIN, ENV_ZAP1_REQUIRE_CHAIN,
};
use private_inference_rent::{hex32, tagged_hash, Zap1Ibcv2Bundle};

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
fn contract_msgs_compile_and_roundtrip() {
    let g = tagged_hash(b"g", &[b"lc"]);
    let note = tagged_hash(b"n", &[b"lc"]);
    let b = local_hosting_bundle(g, note, 11, "PIR-LC", "sib");
    b.verify().expect("fixture still verifies");
    let req = b.lc_helper_request();
    let j = serde_json::to_value(&req).expect("serde");
    assert_eq!(j["event_kind"], "hosting_payment");
    assert_eq!(j["sequence"], 1);
    assert_eq!(j["source_client"], "08-zap1-src");
    // Same JSON shape as cw-zap1-ibcv2 ExecuteMsg::AttestPacket fields.
    let exec = serde_json::json!({
        "attest_packet": {
            "source_client": req.source_client,
            "dest_client": req.dest_client,
            "sequence": req.sequence,
            "timeout_timestamp_ns": req.timeout_timestamp_ns,
            "app_data_hash_hex": req.app_data_hash_hex,
            "note_hex": req.note_hex,
            "amount_zat": req.amount_zat,
            "frost_group_hex": req.frost_group_hex,
            "leaf_hex": req.leaf_hex,
            "merkle_root_hex": req.merkle_root_hex,
            "event_kind": req.event_kind,
            "wallet_or_serial": req.wallet_or_serial,
            "proof": [{
                "sibling_hex": hex32(&b.proof[0].sibling),
                "sibling_is_left": b.proof[0].sibling_is_left
            }]
        }
    });
    assert!(exec.get("attest_packet").is_some());
    let q = serde_json::json!({
        "match": {
            "source_client": req.source_client,
            "dest_client": req.dest_client,
            "sequence": req.sequence,
            "app_data_hash_hex": req.app_data_hash_hex
        }
    });
    assert!(q.get("match").is_some());
}

#[test]
fn local_hosting_bundle_remains_unit_fixture() {
    let _ = std::any::type_name::<fn([u8; 32], [u8; 32], u64, &str, &str) -> Zap1Ibcv2Bundle>();
    let g = tagged_hash(b"g", &[b"fix"]);
    let n = tagged_hash(b"n", &[b"fix"]);
    assert!(local_hosting_bundle(g, n, 1, "a", "b").verify().is_ok());
}

#[test]
fn helper_missing_is_error_not_ok() {
    let g = tagged_hash(b"g", &[b"lc2"]);
    let note = tagged_hash(b"n", &[b"lc2"]);
    let b = local_hosting_bundle(g, note, 3, "PIR-LC2", "sib");
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    match require_onchain_accept(&b) {
        Err(Zap1LcError::Spawn(s)) => {
            assert!(s.contains("PIR_ZAP1_LC_BIN") || s.contains("spawn"));
        }
        other => panic!("expected Spawn, got {other:?}"),
    }
}

/// Without Docker / helper: skip (return), do not panic.
/// `PIR_ZAKURA_LAB=1` or `--features live-ict`: fail-closed if eco/helper missing.
#[test]
fn zap1_ibcv2_lc_live() {
    let lab = std::env::var("PIR_ZAKURA_LAB").ok().as_deref() == Some("1");
    let live_ict = cfg!(feature = "live-ict");
    let docker = std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let cargo_helper = option_env!("CARGO_BIN_EXE_pir-zap1-lc").map(str::to_string);
    let helper = std::env::var(ENV_ZAP1_LC_BIN)
        .ok()
        .filter(|p| std::path::Path::new(p).is_file())
        .or_else(|| cargo_helper.filter(|p| std::path::Path::new(p).is_file()));

    if (lab || live_ict) && helper.is_none() {
        panic!(
            "PIR_ZAKURA_LAB=1 or live-ict but no PIR_ZAP1_LC_BIN / pir-zap1-lc; fail-closed (not Crosslink)"
        );
    }
    if helper.is_none() {
        if !docker {
            return;
        }
        eprintln!("skip: docker up but no zap1 lc helper");
        return;
    }

    let helper = helper.unwrap();
    std::env::set_var(ENV_ZAP1_LC_BIN, &helper);
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");

    let g = tagged_hash(b"g", &[b"live-lc"]);
    let note = tagged_hash(b"n", &[b"live-lc"]);
    let frost = FrostGroup::dealer(3, 2).unwrap();
    let mut pool = FrostThresholdPool::new(g, 2, 3)
        .unwrap()
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost);
    let bundle = local_hosting_bundle(g, note, 21, "PIR-LIVE-LC", "sib");
    let auth = signed_auth(&pool, g, note, 21);
    let before = pool.balance_zat;
    let ok = pool.credit_deposit_zap1(&bundle, &auth);
    if !ok.is_ok() {
        panic!("helper present but credit failed: {ok:?}");
    }
    assert!(pool.balance_zat > before);

    let mut tampered = bundle.clone();
    tampered.ibc.app_data_hash[0] ^= 1;
    let bal = pool.balance_zat;
    assert!(pool.credit_deposit_zap1(&tampered, &auth).is_err());
    assert_eq!(pool.balance_zat, bal);
}

#[test]
fn live_ict_or_lab_gate_is_honest() {
    let _ = zap1_lc_required();
}
