//! Arbiter entry from the PIR crate: cw-orch `deploy_on` (same contracts as wasm).
//! `cargo test --features cw-orch-suite --test escrow_cw_orch`
//!
//! Live ict-rs Daemon is fail-closed via `try_live_attach` when `live-ict` is on.

use cw_orch::prelude::*;
use pir_cw_orch::{
    EscrowPartyMsg, Ics08AcceptedResp, Ics08ExecuteMsg, Ics08ProofStepMsg, Ics08QueryMsg,
    PrivateInference, PrivateInferenceDeployData,
};
use private_inference_rent::hex32;
use private_inference_rent::run_escrow_partial_close;
use private_inference_rent::tagged_hash;
use private_inference_rent::zap1::local_hosting_bundle;

#[test]
fn cw_orch_deploy_on_is_escrow_arbiter() {
    let mock = Mock::new("owner");
    let suite = PrivateInference::deploy_on(mock, PrivateInferenceDeployData)
        .expect("deploy_on");
    let (_id, grant) = suite
        .escrow_open_accrue_close(
            "bb".repeat(32),
            "tenant1".into(),
            "provider1".into(),
            "resolver1".into(),
            100,
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(32),
            EscrowPartyMsg::Tenant,
        )
        .expect("escrow round on suite");
    assert_eq!(grant.accrual_commitment.len(), 64);
    assert!(grant.recorded);
    assert_eq!(grant.earned_zat, 0, "on-chain grant is not a uter p bill");
    assert_eq!(grant.remainder_zat, 100);
}

#[test]
fn deploy_on_ics08_execute_query_is_not_store_only() {
    let mock = Mock::new("owner");
    let suite = PrivateInference::deploy_on(mock, PrivateInferenceDeployData).expect("deploy_on");
    let g = tagged_hash(b"g", &[b"ics08-mock"]);
    let n = tagged_hash(b"n", &[b"ics08-mock"]);
    let bundle = local_hosting_bundle(g, n, 11, "PIR-LC-LIVE", "sib");
    bundle.verify().expect("fixture merkle");

    suite
        .ics08_zap1
        .execute(
            &Ics08ExecuteMsg::CreateClient {
                source_client: bundle.ibc.source_client.clone(),
                dest_client: bundle.ibc.dest_client.clone(),
            },
            Some(&[]),
        )
        .expect("ics08 create_client");

    let proof: Vec<Ics08ProofStepMsg> = bundle
        .proof
        .iter()
        .map(|s| Ics08ProofStepMsg {
            sibling_hex: hex32(&s.sibling),
            sibling_is_left: s.sibling_is_left,
        })
        .collect();
    suite
        .ics08_zap1
        .execute(
            &Ics08ExecuteMsg::AttestPacket {
                source_client: bundle.ibc.source_client.clone(),
                dest_client: bundle.ibc.dest_client.clone(),
                sequence: bundle.ibc.sequence,
                timeout_timestamp_ns: bundle.ibc.timeout_timestamp_ns,
                app_data_hash_hex: hex32(&bundle.ibc.app_data_hash),
                note_hex: hex32(&bundle.deposit_note_commitment),
                amount_zat: bundle.amount_zat,
                frost_group_hex: hex32(&bundle.frost_group_id),
                leaf_hex: hex32(&bundle.leaf_hash),
                merkle_root_hex: hex32(&bundle.merkle_root),
                event_kind: "hosting_payment".into(),
                wallet_or_serial: bundle.wallet_or_serial.clone(),
                proof: proof.clone(),
            },
            Some(&[]),
        )
        .expect("ics08 attest_packet");

    let ok: Ics08AcceptedResp = suite
        .ics08_zap1
        .query(&Ics08QueryMsg::Accepted {
            source_client: bundle.ibc.source_client.clone(),
            dest_client: bundle.ibc.dest_client.clone(),
            sequence: bundle.ibc.sequence,
            app_data_hash_hex: hex32(&bundle.ibc.app_data_hash),
        })
        .expect("ics08 accepted query");
    assert!(ok.accepted, "ics08 execute/query must accept the good packet");

    let mut bad = hex32(&bundle.ibc.app_data_hash);
    let last = bad.pop().expect("hex");
    bad.push(if last == '0' { '1' } else { '0' });
    let tamper = suite.ics08_zap1.execute(
        &Ics08ExecuteMsg::AttestPacket {
            source_client: bundle.ibc.source_client.clone(),
            dest_client: bundle.ibc.dest_client.clone(),
            sequence: bundle.ibc.sequence,
            timeout_timestamp_ns: bundle.ibc.timeout_timestamp_ns,
            app_data_hash_hex: bad.clone(),
            note_hex: hex32(&bundle.deposit_note_commitment),
            amount_zat: bundle.amount_zat,
            frost_group_hex: hex32(&bundle.frost_group_id),
            leaf_hex: hex32(&bundle.leaf_hash),
            merkle_root_hex: hex32(&bundle.merkle_root),
            event_kind: "hosting_payment".into(),
            wallet_or_serial: bundle.wallet_or_serial.clone(),
            proof,
        },
        Some(&[]),
    );
    assert!(tamper.is_err(), "tampered app_data_hash must fail ics08 execute");
    let no: Ics08AcceptedResp = suite
        .ics08_zap1
        .query(&Ics08QueryMsg::Accepted {
            source_client: bundle.ibc.source_client,
            dest_client: bundle.ibc.dest_client,
            sequence: bundle.ibc.sequence,
            app_data_hash_hex: bad,
        })
        .expect("ics08 tamper query");
    assert!(!no.accepted, "ics08 must not accept tampered app_data_hash");
}

#[test]
fn in_process_partial_close_still_matches_suite_amounts() {
    let r = run_escrow_partial_close().unwrap();
    assert_eq!(r.earned_zat, 40);
    assert_eq!(r.remainder_zat, 60);
    assert!(r.closed_denied);
}

#[test]
fn one_path_deploy_on_fund_with_zap1_two_spends_bearer_deny() {
    let r = private_inference_rent::run_composed_arbiter().expect("no piece skipped");
    assert!(r.deploy_on && r.fund_with_zap1 && r.two_frost_spends && r.bearer_deny);
    #[cfg(feature = "live-ict")]
    {
        assert!(
            r.one_ict_process,
            "live-ict must not report Mock/RAM as the arbiter"
        );
    }
    #[cfg(not(feature = "live-ict"))]
    {
        assert!(!r.one_ict_process);
    }
}

#[cfg(feature = "live-ict")]
#[test]
fn live_ict_attach_fail_closed() {
    let hint = private_inference_rent::cw_orch::try_live_attach()
        .expect("live-ict must attach via daemon_builder_from_chain + deploy_on(Daemon)");
    assert!(hint.deploy_on_daemon);
    assert!(
        hint.escrow_grant_recorded,
        "live-ict deploy_on must record grant-only escrow (no BankMsg/uterp)"
    );
    assert!(
        hint.zap1_stored && hint.zap1_matches && hint.zap1_tamper_rejected,
        "live-ict fund_with_zap1 is on-chain zap1 from the same attach process"
    );
    assert!(
        hint.ics08_deployed,
        "PrivateInference::deploy_on must instantiate ics08 on Daemon"
    );
    assert!(
        hint.ics08_accepted && hint.ics08_tamper_rejected,
        "live-ict ics08 must CreateClient+AttestPacket+Accepted query, not store-only: {hint:?}"
    );
    assert!(!hint.chain_id.is_empty());
}
