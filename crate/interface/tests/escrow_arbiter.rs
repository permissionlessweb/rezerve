//! Arbiter: `PrivateInference::deploy_on` + escrow close/grant.
//! Same contract code as wasm (`ContractWrapper`). Live path is
//! `pir-live-attach`: `daemon_builder_from_chain` then the same four-contract
//! `deploy_on` sequence on Daemon (fail-closed if Docker/chain/wasm missing).
//! Full compose (`deploy_on` + `fund_with_zap1` + two FROST spends + bearer deny)
//! is `private-inference-rent` `run_composed_arbiter` (this crate has no PIR dep).
//! live-ict: one `pir-live-attach` process (`daemon_builder_from_chain` +
//! `deploy_on` on Daemon); this Mock suite is not that process.

use cosmwasm_std::{coin, Addr, Uint128};
use cw_orch::prelude::*;
use cw_pir_commit::ExecuteMsg as CommitExecute;
use pir_cw_orch::{
    EscrowPartyMsg, Ics08AcceptedResp, Ics08ExecuteMsg, Ics08QueryMsg, PrivateInference,
    PrivateInferenceDeployData,
};

#[test]
fn deploy_on_then_escrow_close_grant_and_commit() {
    let mock = Mock::new("owner");

    let suite = PrivateInference::deploy_on(mock.clone(), PrivateInferenceDeployData)
        .expect("deploy_on Mock");

    let ask = "aa".repeat(32);
    let bid = "bb".repeat(32);
    suite
        .commit
        .execute(
            &CommitExecute::PostCommitments {
                ask_commitment: ask.clone(),
                bid_commitment: bid.clone(),
            },
            Some(&[]),
        )
        .expect("commit");

    let (cell_id, grant) = suite
        .escrow_open_accrue_close(
            bid.clone(),
            "tenant1".into(),
            "provider1".into(),
            "resolver1".into(),
            100,
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(32),
            EscrowPartyMsg::Tenant,
        )
        .expect("escrow round");

    assert!(!cell_id.is_empty());
    assert!(grant.recorded);
    assert_eq!(grant.earned_zat, 0);
    assert_eq!(grant.remainder_zat, 100);
    assert_eq!(grant.accrual_commitment, "aa".repeat(32));
    assert_eq!(grant.cell_id, cell_id);

    let tenant = Addr::unchecked("tenant1");
    let provider = Addr::unchecked("provider1");
    let t = mock
        .query_balance(&tenant, "uterp")
        .unwrap_or(Uint128::zero());
    let p = mock
        .query_balance(&provider, "uterp")
        .unwrap_or(Uint128::zero());
    assert_eq!(p.u128(), 0, "close is grant-only; no uterp to provider");
    assert_eq!(t.u128(), 0, "close is grant-only; no uterp to tenant");

    let no_grant = suite
        .escrow
        .query::<pir_cw_orch::GrantResp>(&pir_cw_orch::EscrowQueryMsg::Grant {
            cell_id: "00".repeat(32),
        });
    assert!(no_grant.is_err(), "unknown cell has no grant");

    suite
        .ics08_zap1
        .execute(
            &Ics08ExecuteMsg::CreateClient {
                source_client: "08-zap1-src".into(),
                dest_client: "08-terp-dst".into(),
            },
            Some(&[]),
        )
        .expect("ics08 create_client (store-only instantiate is not packet accept)");
    let none: Ics08AcceptedResp = suite
        .ics08_zap1
        .query(&Ics08QueryMsg::Accepted {
            source_client: "08-zap1-src".into(),
            dest_client: "08-terp-dst".into(),
            sequence: 1,
            app_data_hash_hex: "00".repeat(32),
        })
        .expect("ics08 accepted query");
    assert!(
        !none.accepted,
        "ics08 CreateClient without AttestPacket is not packet accept"
    );
}

#[test]
fn grant_query_before_close_fails() {
    let mock = Mock::new("owner");
    let suite = PrivateInference::deploy_on(mock, PrivateInferenceDeployData).unwrap();
    let res = suite
        .escrow
        .execute(
            &pir_cw_orch::EscrowExecuteMsg::OpenCell {
                bid_commitment: "bb".repeat(32),
                tenant: "t".into(),
                provider: "p".into(),
                resolver: "r".into(),
                deposit_zat: 50,
            },
            Some(&[]),
        )
        .unwrap();
    let cell_id = res
        .event_attr_value("wasm", "cell_id")
        .or_else(|_| res.event_attr_value("wasm-open_cell", "cell_id"))
        .expect("cell_id");
    assert!(suite
        .escrow
        .query::<pir_cw_orch::GrantResp>(&pir_cw_orch::EscrowQueryMsg::Grant { cell_id })
        .is_err());
}

#[test]
fn open_cell_rejects_bank_funds() {
    let mock = Mock::new("owner");
    mock.set_balance(&mock.sender.clone(), vec![coin(1_000_000, "uterp")])
        .unwrap();
    let suite = PrivateInference::deploy_on(mock, PrivateInferenceDeployData).unwrap();
    let err = suite
        .escrow
        .execute(
            &pir_cw_orch::EscrowExecuteMsg::OpenCell {
                bid_commitment: "bb".repeat(32),
                tenant: "t".into(),
                provider: "p".into(),
                resolver: "r".into(),
                deposit_zat: 50,
            },
            Some(&[coin(50, "uterp")]),
        )
        .expect_err("OpenCell must reject uter p bank funds");
    let s = err.to_string();
    assert!(
        s.contains("bank funds") || s.contains("deposit_zat") || s.contains("Zcash"),
        "{s}"
    );
}
