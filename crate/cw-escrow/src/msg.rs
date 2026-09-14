use cosmwasm_std::Binary;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Party {
    Tenant,
    Provider,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecuteMsg {
    OpenCell {
        bid_commitment: String,
        tenant: String,
        provider: String,
        resolver: String,
        /// Zcash-note accounting. Bank `info.funds` is rejected.
        deposit_zat: u64,
    },
    /// Public surface is a height-bound commitment + header hashes (Halo2
    /// instances of `f(open, close, rate)`). Not a closer-supplied earned.
    Accrue {
        cell_id: String,
        commitment: String,
        open_header_hash: String,
        close_header_hash: String,
    },
    /// Host `proof_instance_verify` of `f` against stored 96-byte instances.
    /// Empty proof is invalid. Accrue still records the public waist.
    VerifyAccrualHalo2 {
        cell_id: String,
        /// `pir-accrual.f.v1` (2). HOSTING_PAYMENT zkid 1 is rejected.
        zkid: u64,
        proof: Binary,
    },
    /// Does not take earned. Records current accrued + remainder.
    Close {
        cell_id: String,
        party: Party,
    },
    Dispute {
        cell_id: String,
        party: Party,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Grant { cell_id: String },
    Cell { cell_id: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GrantResp {
    pub cell_id: String,
    pub closer: Party,
    /// Not a closer-supplied bill. Always 0 on-chain; split is private witness.
    pub earned_zat: u64,
    pub remainder_zat: u64,
    pub recorded: bool,
    pub accrual_commitment: String,
    pub open_header_hash: String,
    pub close_header_hash: String,
    /// Packed 96-byte Halo2 instances of `f` (192 hex). Not earned.
    #[serde(default)]
    pub halo2_instances: String,
    /// True after `VerifyAccrualHalo2` accepted a proof of `f`.
    #[serde(default)]
    pub halo2_verified: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CellResp {
    pub cell_id: String,
    pub deposit_zat: u64,
    pub bid_commitment: String,
    pub tenant: String,
    pub provider: String,
    pub resolver: String,
    pub earned_zat: u64,
    pub closed: bool,
    pub denom: String,
    pub accrual_commitment: String,
    pub open_header_hash: String,
    pub close_header_hash: String,
    /// Packed 96-byte Halo2 instances of `f` (192 hex). Not earned.
    #[serde(default)]
    pub halo2_instances: String,
    /// True after `VerifyAccrualHalo2` accepted a proof of `f`.
    #[serde(default)]
    pub halo2_verified: bool,
}
