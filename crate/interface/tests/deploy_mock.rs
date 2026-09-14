//! Mock `deploy_on` — cw-orch native state, no Docker.

use cw_orch::prelude::*;
use cw_pir_commit::ExecuteMsg as CommitExecute;
use cw_pir_commit::QueryMsg as CommitQuery;
use pir_cw_orch::{PrivateInference, PrivateInferenceDeployData};

#[test]
fn deploy_on_mock_then_commit_match() {
    let mock = Mock::new("owner");
    let suite = PrivateInference::deploy_on(mock, PrivateInferenceDeployData)
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
        .expect("post commitments");

    let raw = suite
        .commit
        .query(&CommitQuery::Match {
            ask_commitment: ask,
            bid_commitment: bid,
        })
        .expect("match query");
    let v: serde_json::Value = raw;
    assert_eq!(v["matches"], true);
}

#[test]
fn load_from_same_chain_type() {
    let mock = Mock::new("owner");
    let _ = PrivateInference::deploy_on(mock.clone(), PrivateInferenceDeployData).unwrap();
    let loaded = PrivateInference::load_from(mock).unwrap();
    assert!(loaded.commit.addr_str().is_ok() || loaded.commit.code_id().is_ok());
}
