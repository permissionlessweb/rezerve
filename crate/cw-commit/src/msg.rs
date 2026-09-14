use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Generic kv (packet hash). Values must be 64-char hex — no price/identity.
    Commit { key: String, value: String },
    /// Ask + bid commitments only.
    PostCommitments {
        ask_commitment: String,
        bid_commitment: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Get { key: String },
    GetCommitments {},
    Match {
        ask_commitment: String,
        bid_commitment: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Commitments {
    pub ask_commitment: String,
    pub bid_commitment: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MatchResp {
    pub matches: bool,
}
