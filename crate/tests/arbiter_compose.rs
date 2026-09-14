//! One arbiter path: `deploy_on` + `fund_with_zap1` + two FROST spends + bearer deny.
//! `cargo test --features cw-orch-suite --test arbiter_compose`
//! With `--features live-ict,cw-orch-suite` attach is fail-closed (no skip-green).
//! live-ict money is on-chain zap1 + Zakura two spends, not a RAM pool.

use private_inference_rent::run_composed_arbiter;

#[test]
fn one_arbiter_deploy_on_fund_with_zap1_two_spends_bearer_deny() {
    let r = run_composed_arbiter().expect("composed arbiter: no piece may be skipped");
    assert!(r.deploy_on, "PrivateInference::deploy_on");
    assert!(r.fund_with_zap1, "EscrowCell::fund_with_zap1");
    assert!(r.two_frost_spends, "two Zcash/FROST settle spends");
    assert!(r.bearer_deny, "winner close / bearer deny");
    #[cfg(feature = "live-ict")]
    {
        assert!(
            r.live_ict.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
            "ict-rs Daemon via daemon_builder_from_chain + deploy_on"
        );
        assert!(
            r.one_ict_process,
            "live-ict arbiter must be one pir-live-attach process + Zakura spends"
        );
    }
    #[cfg(not(feature = "live-ict"))]
    {
        assert!(r.live_ict.is_none());
        assert!(
            !r.one_ict_process,
            "Mock deploy_on is not ict-rs Daemon; do not claim one_ict_process"
        );
    }
}
