//! Hook from PIR product credit to a ZAP1 IBC v2 LC-class helper.
//!
//! `PIR_ZAP1_LC_BIN` must print JSON `{ "accepted": true, "matches": true }`.
//! Close path (`--attest-close`) re-binds Close attrs. Packet path is in-proc
//! `cw-ics08-wasm-zap1` verify unless the helper itself talks to a chain.
//! Missing spawn / binary is fail-closed when required.
//!
//! This module does **not** store ICS-08 08-wasm. Groot store of
//! `cw-zap1-ibcv2.wasm` is `pir-live-attach` + `PIR_ZAP1_WASM`. Crosslink
//! `cw_ics08_wasm_crosslink.wasm` is a different client. Full ICS-08 nine
//! entrypoints are the next increment.

use crate::escrow::EscrowParty;
use crate::escrow_notice::{CloseAction, CloseEventAttest, CloseEventAttrs};
use crate::zap1::{Zap1Error, Zap1EventKind, Zap1Ibcv2Bundle};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ENV_ZAP1_LC_BIN: &str = "PIR_ZAP1_LC_BIN";
pub const ENV_ZAP1_REQUIRE_CHAIN: &str = "PIR_ZAP1_REQUIRE_CHAIN";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Zap1LcError {
    #[error("zap1 lc spawn missing or helper failed: {0}")]
    Spawn(String),
    #[error("on-chain module rejected packet or tampered app_data_hash")]
    Rejected,
    #[error(transparent)]
    Zap1(#[from] Zap1Error),
}

impl From<Zap1LcError> for Zap1Error {
    fn from(e: Zap1LcError) -> Self {
        match e {
            Zap1LcError::Zap1(z) => z,
            Zap1LcError::Rejected => Zap1Error::IbcBind,
            Zap1LcError::Spawn(_) => Zap1Error::ChainAcceptRequired,
        }
    }
}

/// NS9: live-ict fail-closed, or an explicit helper/env.
/// `PIR_ZAP1_REQUIRE_CHAIN=0` is the fixture override. Not 08-wasm store.
pub fn zap1_lc_required() -> bool {
    if std::env::var(ENV_ZAP1_REQUIRE_CHAIN).ok().as_deref() == Some("0") {
        return false;
    }
    if std::env::var(ENV_ZAP1_LC_BIN).is_ok() {
        return true;
    }
    if std::env::var(ENV_ZAP1_REQUIRE_CHAIN).ok().as_deref() == Some("1") {
        return true;
    }
    cfg!(feature = "live-ict")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zap1LcHelperRequest {
    pub source_client: String,
    pub dest_client: String,
    pub sequence: u64,
    pub app_data_hash_hex: String,
    pub leaf_hex: String,
    pub merkle_root_hex: String,
    pub event_kind: String,
    pub wallet_or_serial: String,
    pub note_hex: String,
    pub amount_zat: u64,
    pub frost_group_hex: String,
    pub timeout_timestamp_ns: u64,
    pub proof: Vec<crate::zap1::Zap1ProofStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zap1LcHelperReport {
    pub accepted: bool,
    pub matches: bool,
}

impl Zap1Ibcv2Bundle {
    pub fn lc_helper_request(&self) -> Zap1LcHelperRequest {
        Zap1LcHelperRequest {
            source_client: self.ibc.source_client.clone(),
            dest_client: self.ibc.dest_client.clone(),
            sequence: self.ibc.sequence,
            app_data_hash_hex: hex::encode(self.ibc.app_data_hash),
            leaf_hex: hex::encode(self.leaf_hash),
            merkle_root_hex: hex::encode(self.merkle_root),
            event_kind: match self.event_kind {
                Zap1EventKind::HostingPayment => "hosting_payment".into(),
                Zap1EventKind::ProgramEntry => "program_entry".into(),
                Zap1EventKind::OwnershipAttest => "ownership_attest".into(),
            },
            wallet_or_serial: self.wallet_or_serial.clone(),
            note_hex: hex::encode(self.deposit_note_commitment),
            amount_zat: self.amount_zat,
            frost_group_hex: hex::encode(self.frost_group_id),
            timeout_timestamp_ns: self.ibc.timeout_timestamp_ns,
            proof: self.proof.clone(),
        }
    }
}

/// Close-event LC request. Not ICS-08 08-wasm store; helper must accept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseEventLcRequest {
    pub header_hash_hex: String,
    pub tx_hash_hex: String,
    pub app_data_hash_hex: String,
    pub action: String,
    pub cell_id_hex: String,
    pub closer: String,
    pub earned_zat: u64,
    pub remainder_zat: u64,
    /// Public Close surface is grant-only. Bank/uterp settle never authorizes.
    #[serde(default)]
    pub settle: String,
    /// cw-pir-escrow Close grant hashes. Empty on WorkReceipt sim path.
    #[serde(default)]
    pub accrual_commitment: String,
    #[serde(default)]
    pub open_header_hash: String,
    #[serde(default)]
    pub close_header_hash: String,
}

impl CloseEventLcRequest {
    /// Bind Close attrs for `--attest-close`. Local hash until the helper runs.
    /// Does not store `cw-zap1-ibcv2.wasm`. Public `earned_zat` is GrantView 0.
    pub fn bind(
        header_hash: [u8; 32],
        tx_hash: [u8; 32],
        app_data_hash: [u8; 32],
        action: &str,
        cell_id: [u8; 32],
        closer: &str,
        earned_zat: u64,
        remainder_zat: u64,
    ) -> Self {
        Self {
            header_hash_hex: hex::encode(header_hash),
            tx_hash_hex: hex::encode(tx_hash),
            app_data_hash_hex: hex::encode(app_data_hash),
            action: action.into(),
            cell_id_hex: hex::encode(cell_id),
            closer: closer.into(),
            earned_zat,
            remainder_zat,
            settle: "grant_only".into(),
            accrual_commitment: String::new(),
            open_header_hash: String::new(),
            close_header_hash: String::new(),
        }
    }

    /// Bind GrantView public hashes into LC-verified Close attrs.
    pub fn with_grant_public(
        mut self,
        accrual_commitment: impl Into<String>,
        open_header_hash: impl Into<String>,
        close_header_hash: impl Into<String>,
    ) -> Self {
        self.accrual_commitment = accrual_commitment.into();
        self.open_header_hash = open_header_hash.into();
        self.close_header_hash = close_header_hash.into();
        self
    }
}

fn spawn_helper(bin: &str, flag: &str, env_key: &str, body: &str) -> Result<(), Zap1LcError> {
    let path = std::path::PathBuf::from(bin);
    if !path.is_file() {
        return Err(Zap1LcError::Spawn(format!("{bin} is not a file")));
    }
    let out = std::process::Command::new(&path)
        .arg(flag)
        .env(env_key, body)
        .output()
        .map_err(|e| Zap1LcError::Spawn(format!("spawn {bin}: {e}")))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().last().unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(line).unwrap_or(serde_json::json!({}));
    let accepted = v.get("accepted").and_then(|x| x.as_bool()) == Some(true);
    let matches = v.get("matches").and_then(|x| x.as_bool()) == Some(true);
    if out.status.success() && accepted && matches {
        return Ok(());
    }
    if v.get("rejected").and_then(|x| x.as_bool()) == Some(true) {
        return Err(Zap1LcError::Rejected);
    }
    Err(Zap1LcError::Spawn(format!(
        "lc helper exit={} stdout={} stderr={}",
        out.status,
        stdout.trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

fn hex32_bytes(s: &str) -> Option<[u8; 32]> {
    let t = s.trim().trim_start_matches("0x");
    let raw = hex::decode(t).ok()?;
    raw.try_into().ok()
}

/// Re-bind Close attrs the same way `pir-zap1-lc --attest-close` does.
/// In-process hash; helper is LC-class. Does not store `cw-zap1-ibcv2.wasm`.
pub fn close_event_lc_rebind(req: &CloseEventLcRequest) -> Result<CloseEventAttest, Zap1LcError> {
    let header = hex32_bytes(&req.header_hash_hex).ok_or(Zap1LcError::Rejected)?;
    let tx = hex32_bytes(&req.tx_hash_hex).ok_or(Zap1LcError::Rejected)?;
    if header == tx {
        return Err(Zap1LcError::Rejected);
    }
    let cell_id = hex32_bytes(&req.cell_id_hex).ok_or(Zap1LcError::Rejected)?;
    let app = hex32_bytes(&req.app_data_hash_hex).ok_or(Zap1LcError::Rejected)?;
    let action = match req.action.as_str() {
        "close" => CloseAction::Close,
        "dispute" => CloseAction::Dispute,
        _ => return Err(Zap1LcError::Rejected),
    };
    let closer = match req.closer.as_str() {
        "tenant" => EscrowParty::Tenant,
        "provider" => EscrowParty::Provider,
        _ => return Err(Zap1LcError::Rejected),
    };
    // Grant-only public surface: earned stays private (0 on the wire).
    if req.settle != "grant_only" || req.earned_zat != 0 || req.remainder_zat == 0 {
        return Err(Zap1LcError::Rejected);
    }
    let hashed = !req.accrual_commitment.is_empty()
        || !req.open_header_hash.is_empty()
        || !req.close_header_hash.is_empty();
    if hashed {
        let acc = hex32_bytes(&req.accrual_commitment).ok_or(Zap1LcError::Rejected)?;
        let open = hex32_bytes(&req.open_header_hash).ok_or(Zap1LcError::Rejected)?;
        let close = hex32_bytes(&req.close_header_hash).ok_or(Zap1LcError::Rejected)?;
        if acc == [0u8; 32] || open == close {
            return Err(Zap1LcError::Rejected);
        }
    }
    let attrs = CloseEventAttrs {
        action,
        cell_id,
        closer,
        earned_zat: req.earned_zat,
        remainder_zat: req.remainder_zat,
    };
    let attest = CloseEventAttest::bind(header, tx, &attrs);
    if attest.app_data_hash != app || !attest.verify(header, tx, &attrs) {
        return Err(Zap1LcError::Rejected);
    }
    Ok(attest)
}

/// Close attrs always re-bind (in-proc hash). When `zap1_lc_required()`, they
/// must also be accepted by `PIR_ZAP1_LC_BIN`. Missing helper is fail-closed.
/// Does not store `cw-zap1-ibcv2.wasm`. Public earned is GrantView 0;
/// remainder is deposit; settle is `grant_only`. Vote-extension actions never
/// authorize. live-ict is fail-closed (NS9).
pub fn require_close_event_lc(req: &CloseEventLcRequest) -> Result<(), Zap1LcError> {
    let _attest = close_event_lc_rebind(req)?;
    if !zap1_lc_required() {
        return Ok(());
    }
    let bin = std::env::var(ENV_ZAP1_LC_BIN).map_err(|_| {
        Zap1LcError::Spawn(format!(
            "{ENV_ZAP1_LC_BIN} unset; close attrs need LC helper (not 08-wasm store)"
        ))
    })?;
    let body = serde_json::to_string(req).map_err(|e| Zap1LcError::Spawn(e.to_string()))?;
    spawn_helper(&bin, "--attest-close", "PIR_ZAP1_CLOSE_JSON", &body)
}

/// Query / spawn helper. Fail-closed: no skip-green.
/// In-proc helper verify is not ICS-08 08-wasm store.
pub fn require_onchain_accept(bundle: &Zap1Ibcv2Bundle) -> Result<(), Zap1LcError> {
    bundle.verify()?;
    let bin = std::env::var(ENV_ZAP1_LC_BIN).map_err(|_| {
        Zap1LcError::Spawn(format!(
            "{ENV_ZAP1_LC_BIN} unset; packet accept needs LC helper (not ICS-08 08-wasm store)"
        ))
    })?;
    let req = bundle.lc_helper_request();
    let body = serde_json::to_string(&req).map_err(|e| Zap1LcError::Spawn(e.to_string()))?;
    spawn_helper(&bin, "--attest", "PIR_ZAP1_ATTEST_JSON", &body)
}
