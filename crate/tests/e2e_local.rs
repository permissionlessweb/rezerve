//! Full successful **local** e2e: shipped `run_local_e2e` (cw-orch-style modules).
//! Product compose: `run_production_sequence` (ask → OOB bid/commitment match →
//! ZAP1+Halo2 DKG credit → allocate → pir serve HTTP 200 → close grant →
//! two Ironwood spends → bearer deny).
//! `cargo test --features e2e --test e2e_local`

use private_inference_rent::e2e::{
    run_local_e2e, ModuleStatus, LOCAL_E2E_MODULES, PRODUCTION_SEQUENCE,
};

#[test]
fn full_local_e2e_required_modules_pass() {
    let report = run_local_e2e().expect("local e2e");
    assert!(report.required_ok());
    assert_eq!(report.ask_id, "ask-e2e-local");
    assert_eq!(report.deposit_zat, 10_000);
    #[cfg(not(feature = "live-ict"))]
    {
        assert!(report.swap_out.is_some(), "e2e feature includes seam-dex");
    }
    #[cfg(feature = "live-ict")]
    {
        assert!(
            report.swap_out.is_none(),
            "live-ict must not treat RAM seam-dex as money: {:?}",
            report.swap_out
        );
    }
    let names: Vec<_> = report.modules.iter().map(|m| m.name.as_str()).collect();
    for expected in LOCAL_E2E_MODULES {
        assert!(names.contains(expected), "missing module {expected}");
    }
    for m in &report.modules {
        if m.required {
            assert_eq!(m.status, ModuleStatus::Passed, "{}", m.detail);
        }
    }
    #[cfg(feature = "live-ict")]
    {
        let ict = report
            .modules
            .iter()
            .find(|m| m.name == "ict_attach")
            .expect("ict_attach");
        assert!(ict.required, "live-ict ict_attach is fail-closed, not skip");
        assert_eq!(ict.status, private_inference_rent::e2e::ModuleStatus::Passed);
        assert!(
            ict.detail.contains("deploy_on")
                && ict.detail.contains("escrow_grant_recorded")
                && ict.detail.contains("zap1_stored")
                && ict.detail.contains("ics08_accepted"),
            "live-ict must run daemon_builder_from_chain + deploy_on + escrow grant + on-chain zap1 + ics08 execute/query: {}",
            ict.detail
        );
        let frost = report
            .modules
            .iter()
            .find(|m| m.name == "frost_spend")
            .expect("frost_spend");
        assert!(
            frost.detail.contains("RAM pool not credited")
                && frost.detail.contains("ics08"),
            "live-ict frost_spend must not credit RAM FrostThresholdPool: {}",
            frost.detail
        );
        let zap1 = report
            .modules
            .iter()
            .find(|m| m.name == "zap1_ibcv2")
            .expect("zap1_ibcv2");
        assert!(
            zap1.detail.contains("on-chain zap1")
                && zap1.detail.contains("ics08")
                && zap1.detail.contains("deploy_on"),
            "live-ict zap1_ibcv2 must reuse attach ics08 execute/query, not a second CosmosChain: {}",
            zap1.detail
        );
    }
}

#[test]
fn modular_suite_catalog_matches_existing_tests() {
    let root = env!("CARGO_MANIFEST_DIR");
    let tests = std::path::Path::new(root).join("tests");
    assert!(tests.join("product_path.rs").is_file());
    assert!(tests.join("frost_ed25519.rs").is_file());
    assert!(tests.join("seam_swap_joint.rs").is_file());
    assert!(tests.join("zakura_live.rs").is_file());
    assert!(tests.join("zap1_ibcv2.rs").is_file());
    assert!(tests.join("cw_orch_e2e.rs").is_file());
    assert!(tests.join("two_process_oob.rs").is_file());
    assert!(tests.join("settlement_work.rs").is_file());
    assert!(tests.join("cw_orch_daemon.rs").is_file());
}

/// One compose: public SDL ask, ChaCha OOB bid / 32-byte commitment match,
/// ZAP1+Halo2 credit into a FROST DKG pool, provider allocate after match,
/// pir serve HTTP 200, LC-class close grant, two Ironwood spends, winner bearer denied.
#[cfg(feature = "live-ict")]
#[test]
fn production_sequence_ask_oob_bid_zap1_halo2_dkg_allocate_serve_close_grant_two_ironwood_bearer_deny()
{
    let r = private_inference_rent::run_production_sequence()
        .expect("production sequence: no piece may be skipped");
    assert_eq!(r.steps_hit.len(), PRODUCTION_SEQUENCE.len());
    assert_eq!(
        r.steps_hit,
        PRODUCTION_SEQUENCE
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
    );
    assert!(!r.dummy_used, "DummyStwo / dealer / RAM pool / zcashd forbidden");
    assert_eq!(r.serve_http, 200, "pir serve HTTP 200, not inspect Running");
    assert!(!r.ask_commitment.is_empty() && r.ask_commitment.len() == 64);
    assert!(!r.bid_commitment.is_empty() && r.bid_commitment.len() == 64);
    assert_ne!(r.ask_commitment, r.bid_commitment);
    assert!(!r.chain_id.is_empty());
    assert!(!r.earned_txid.is_empty());
    assert!(!r.remainder_txid.is_empty());
    assert_ne!(r.earned_txid, r.remainder_txid);
    assert!(r.close_height > r.open_height, "f() needs a height window");
    assert!(r.earned_zat > 0, "earned is f(open,close,rate), not a closer 0");
    assert_eq!(
        r.earned_zat,
        private_inference_rent::accrual::f(
            r.open_height,
            r.close_height,
            private_inference_rent::accrual::AccrualRate {
                zat_per_height: 1
            },
        )
        .expect("f(open,close,rate)"),
        "Ironwood earned must be f(open_height, close_height, rate), not close_notes(..., 40)"
    );
    let e2e_src = include_str!("../src/e2e.rs");
    assert!(
        e2e_src.contains("accrue_from_zakura_halo2")
            && e2e_src.contains("verify_product_accrual")
            && e2e_src.contains("accept_on_zap1_client")
            && e2e_src.contains("open_note")
            && e2e_src.contains("PIR_KEEP_CHAIN")
            && e2e_src.contains("query_live_commit_match")
            && e2e_src.contains("LIVE_CW_PIR_COMMIT_MATCH_OK")
            && !e2e_src.contains("let mut view = crate::OnChainView::new(ask.clone())")
            && !e2e_src.contains("match-serve")
            && !e2e_src.contains("close_notes(&frost, &frost_seats[..2], &opened, 40)")
            && !e2e_src.contains("close_notes(&fg, &seats[..2], &note, 40)"),
        "production sequence must use live cw-pir-commit + credit_deposit_zap1 + Halo2 of f(); no RAM OnChainView/match-serve"
    );
    for step in PRODUCTION_SEQUENCE {
        assert!(
            r.steps_hit.iter().any(|h| h == step),
            "production sequence skipped {step}"
        );
    }
}

#[cfg(not(feature = "live-ict"))]
#[test]
fn production_sequence_ask_oob_bid_zap1_halo2_dkg_allocate_serve_close_grant_two_ironwood_bearer_deny()
{
    if std::env::var("PIR_ZAKURA_LAB").ok().as_deref() == Some("1") {
        panic!(
            "PIR_ZAKURA_LAB=1 production sequence needs --features live-ict (fail-closed; no skip-green)"
        );
    }
    let err = private_inference_rent::run_production_sequence().expect_err("live-ict required");
    assert!(
        err.contains("live-ict"),
        "production sequence without live-ict must fail closed: {err}"
    );
}
