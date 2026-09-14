//! CosmWasm-shaped publish/query over the in-process [`CommitmentModule`].
//!
//! The RAM module is **not** a live chain. Live attach is `pir-live-attach`:
//! `ict-rs-cw-orch::daemon_builder_from_chain` → `DaemonBuilder.build` →
//! `PrivateInference::deploy_on` sequence on that Daemon. This crate does not
//! path-dep `ict-rs`; the bin in `live-chain/` does.

use crate::bid::BidCommitment;
use crate::hex32;
use crate::ibc_module::{IbcModuleError, IbcV2Packet};
use crate::onchain::{CommitmentModule, PublishError};
use thiserror::Error;

/// Handle after a CosmWasm-shaped publish (in-process or, later, Daemon).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CwOrchAttach {
    pub ask_id: String,
    pub packet_commitment_hex: String,
    pub bid_commitment_hex: String,
    /// Always `false` for [`publish_commitments`]. Live attach is opt-in.
    pub live: bool,
}

/// Returned only after `daemon_builder_from_chain` + Daemon `deploy_on`.
/// `escrow_grant_recorded` is the same grant-only open/accrue/close as Mock
/// `PrivateInference::escrow_open_accrue_close` (no BankMsg / uterp).
/// `zap1_*` is the on-chain store/match/tamper from that same `pir-live-attach`
/// process — not a second CosmosChain and not in-proc `pir-zap1-lc`.
/// `ics08_*` is CreateClient + AttestPacket + Accepted query on the stored
/// `cw-ics08-wasm-zap1` (store-only instantiate is not packet accept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDaemonHint {
    pub chain_id: String,
    pub deploy_on_daemon: bool,
    pub escrow_grant_recorded: bool,
    pub zap1_stored: bool,
    pub zap1_matches: bool,
    pub zap1_tamper_rejected: bool,
    pub ics08_deployed: bool,
    pub ics08_accepted: bool,
    pub ics08_tamper_rejected: bool,
    /// LCD of the still-running ict chain when `PIR_KEEP_CHAIN=1`.
    pub rest_url: String,
    /// `cw-pir-commit` address posted during attach (live Match, not RAM store).
    pub commit_contract: String,
    pub zap1_halo2_accepted: bool,
    pub keep_chain: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CwOrchError {
    #[error("live-ict feature is off; RAM CommitmentModule is not a live chain")]
    LiveDisabled,
    #[error("Daemon unavailable: {0}")]
    DaemonUnavailable(String),
    #[error(transparent)]
    Publish(#[from] PublishError),
    #[error(transparent)]
    Ibc(#[from] IbcModuleError),
}

/// In-process publish via [`CommitmentModule::publish`]. Sets `live: false`.
pub fn publish_commitments(
    module: &mut CommitmentModule,
    packet: &IbcV2Packet,
    bid: &BidCommitment,
) -> Result<CwOrchAttach, CwOrchError> {
    let att = crate::tagged_hash(b"cw-orch-publish", &[&packet.packet_commitment(), &bid.commitment]);
    module.publish(packet, bid, att)?;
    Ok(CwOrchAttach {
        ask_id: bid.ask_id.clone(),
        packet_commitment_hex: hex32(&packet.packet_commitment()),
        bid_commitment_hex: hex32(&bid.commitment),
        live: false,
    })
}

/// Re-query the stored packet; tampered packets fail.
pub fn query_published_packet(
    module: &CommitmentModule,
    packet: &IbcV2Packet,
) -> Result<(), CwOrchError> {
    module.ibc.verify_packet(packet)?;
    Ok(())
}

/// Live attach is opt-in. Without `live-ict` this always fails closed.
#[cfg(not(feature = "live-ict"))]
pub fn try_live_attach() -> Result<LiveDaemonHint, CwOrchError> {
    Err(CwOrchError::LiveDisabled)
}

/// Fail closed unless `pir-live-attach` returns live JSON from `daemon_builder_from_chain`.
#[cfg(feature = "live-ict")]
pub fn try_live_attach() -> Result<LiveDaemonHint, CwOrchError> {
    match run_live_attach_bin() {
        Ok(hint) => Ok(hint),
        Err(e) => Err(CwOrchError::DaemonUnavailable(format!(
            "{}; {}",
            probe_daemon_builder_from_chain(),
            e
        ))),
    }
}

/// Seal an OOB bid and exec `pir-live-attach` with ask/bid commitment hex only.
pub fn run_live_attach_bin() -> Result<LiveDaemonHint, String> {
    let (ask_hex, bid_hex) = oob_commitment_hexes()?;
    run_live_attach_with_commits(&ask_hex, &bid_hex)
}

/// Same `pir-live-attach` path with caller-supplied 32-byte ask/bid hex (one compose).
pub fn run_live_attach_with_commits(ask_hex: &str, bid_hex: &str) -> Result<LiveDaemonHint, String> {
    if ask_hex.len() != 64 || bid_hex.len() != 64 {
        return Err("live attach commits must be 32-byte hex".into());
    }
    let bin = live_attach_bin().ok_or_else(|| "pir-live-attach binary not found".to_string())?;
    // One CosmosChain name at a time (ict-pir-live-attach-pir-live-1-val-0).
    let lock_path = std::env::temp_dir().join("pir-live-attach.lock");
    let lockf = std::fs::File::create(&lock_path)
        .map_err(|e| format!("live-attach lock: {e}"))?;
    lockf
        .lock()
        .map_err(|e| format!("live-attach flock: {e}"))?;
    let mut cmd = std::process::Command::new(&bin);
    cmd.env("PIR_ASK_COMMIT", ask_hex)
        .env("PIR_BID_COMMIT", bid_hex);
    if std::env::var("PIR_KEEP_CHAIN").ok().as_deref() == Some("1") {
        cmd.env("PIR_KEEP_CHAIN", "1");
    }
    if let Ok(w) = std::env::var("PIR_COMMIT_WASM") {
        if std::path::Path::new(&w).is_file() {
            cmd.env("PIR_COMMIT_WASM", &w);
        }
    }
    if let Some(w) = zap1_wasm_file() {
        cmd.env("PIR_ZAP1_WASM", w);
    } else {
        return Err(format!(
            "cw-zap1-ibcv2.wasm missing (store on spawned chain required); {}",
            crate::zap1::eco_probe_public()
        ));
    }
    if let Some(w) = escrow_wasm_file() {
        cmd.env("PIR_ESCROW_WASM", w);
    }
    if let Some(w) = ics08_wasm_file() {
        cmd.env("PIR_ICS08_WASM", w);
    } else {
        return Err(format!(
            "cw_ics08_wasm_zap1.wasm missing (PrivateInference::deploy_on needs all four contracts); {}",
            crate::zap1::eco_probe_public()
        ));
    }
    if let Ok(j) = std::env::var("PIR_ZAP1_ATTEST_JSON") {
        if !j.is_empty() {
            cmd.env("PIR_ZAP1_ATTEST_JSON", j);
        }
    } else {
        let g = crate::tagged_hash(b"g", &[b"zap1-live"]);
        let n = crate::tagged_hash(b"n", &[b"zap1-live"]);
        let bundle = crate::zap1::local_hosting_bundle(g, n, 11, "PIR-LC-LIVE", "sib");
        if let Ok(js) = serde_json::to_string(&bundle.lc_helper_request()) {
            cmd.env("PIR_ZAP1_ATTEST_JSON", js);
        }
    }
    let out = cmd
        .output()
        .map_err(|e| format!("spawn {bin:?}: {e}"))?;
    drop(lockf);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json_line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or("");
    let v: serde_json::Value =
        serde_json::from_str(json_line).unwrap_or(serde_json::json!({}));
    let oob_ok = v.get("oob_bid_matches").and_then(|x| x.as_bool()) == Some(true);
    let mismatch = v.get("mismatch_rejected").and_then(|x| x.as_bool()) == Some(true);
    let no_price = v.get("no_price_on_chain").and_then(|x| x.as_bool()) == Some(true);
    let deploy_on_daemon = v.get("deploy_on_daemon").and_then(|x| x.as_bool()) == Some(true)
        && v.get("daemon_built").and_then(|x| x.as_bool()) == Some(true)
        && v.get("private_inference_deploy_on").and_then(|x| x.as_bool()) == Some(true);
    let escrow_grant_recorded = v.get("escrow_grant_recorded").and_then(|x| x.as_bool())
        == Some(true)
        && v.get("escrow_open_accrue_close").and_then(|x| x.as_bool()) == Some(true)
        && v.get("escrow_earned_zat").and_then(|x| x.as_u64()) == Some(0);
    let ics08_ok = ics08_onchain_ok(&v);
    let zap1_ok = zap1_onchain_ok(&v);
    if v.get("live").and_then(|x| x.as_bool()) == Some(true)
        && v.get("called_daemon_builder_from_chain")
            .and_then(|x| x.as_bool())
            == Some(true)
        && deploy_on_daemon
        && escrow_grant_recorded
        && ics08_ok
        && v.get("tamper_rejected").and_then(|x| x.as_bool()) == Some(true)
        && oob_ok
        && mismatch
        && no_price
        && zap1_ok
    {
        return Ok(LiveDaemonHint {
            chain_id: v
                .get("chain_id")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string(),
            deploy_on_daemon: true,
            escrow_grant_recorded: true,
            zap1_stored: v.get("zap1_stored").and_then(|x| x.as_bool()) == Some(true),
            zap1_matches: v.get("zap1_matches").and_then(|x| x.as_bool()) == Some(true)
                || v.get("zap1_accepted").and_then(|x| x.as_bool()) == Some(true),
            zap1_tamper_rejected: v.get("zap1_tamper_rejected").and_then(|x| x.as_bool())
                == Some(true),
            ics08_deployed: true,
            ics08_accepted: true,
            ics08_tamper_rejected: true,
            rest_url: v
                .get("rest_url")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            commit_contract: v
                .get("contract")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            zap1_halo2_accepted: v.get("zap1_halo2_accepted").and_then(|x| x.as_bool())
                == Some(true),
            keep_chain: v.get("keep_chain").and_then(|x| x.as_bool()) == Some(true),
        });
    }
    Err(format!(
        "pir-live-attach exit={} stdout={} stderr={}",
        out.status,
        stdout.trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

fn wasm_from_env_or_rel(var: &str, rel: &[&str]) -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var(var) {
        let pb = std::path::PathBuf::from(p);
        return pb.is_file().then_some(pb);
    }
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for r in rel {
        let p = root.join(r);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn zap1_wasm_file() -> Option<std::path::PathBuf> {
    wasm_from_env_or_rel(
        "PIR_ZAP1_WASM",
        &[
            "cw-zap1-ibcv2/target/wasm32-unknown-unknown/release/cw_zap1_ibcv2.wasm",
            "cw-zap1-ibcv2/artifacts/cw_zap1_ibcv2.wasm",
        ],
    )
}

fn escrow_wasm_file() -> Option<std::path::PathBuf> {
    wasm_from_env_or_rel(
        "PIR_ESCROW_WASM",
        &[
            "cw-escrow/target/wasm32-unknown-unknown/release/cw_pir_escrow.wasm",
            "cw-escrow/artifacts/cw_pir_escrow.wasm",
        ],
    )
}

fn ics08_wasm_file() -> Option<std::path::PathBuf> {
    wasm_from_env_or_rel(
        "PIR_ICS08_WASM",
        &[
            "../terp-rs/crates/cw-ics08-wasm-zap1/target/wasm32-unknown-unknown/release/cw_ics08_wasm_zap1.wasm",
            "../terp-rs/crates/cw-ics08-wasm-zap1/artifacts/cw_ics08_wasm_zap1.wasm",
            "cw-ics08-wasm-zap1/target/wasm32-unknown-unknown/release/cw_ics08_wasm_zap1.wasm",
        ],
    )
}

fn halo2_artifacts_present() -> bool {
    matches!(std::env::var("PIR_HALO2_PARAMS"), Ok(p) if std::path::Path::new(&p).is_file())
        && matches!(std::env::var("PIR_HALO2_VK_BODY"), Ok(p) if std::path::Path::new(&p).is_file())
        && matches!(std::env::var("PIR_HALO2_PROOF"), Ok(p) if std::path::Path::new(&p).is_file())
        && matches!(std::env::var("PIR_HALO2_INSTANCES"), Ok(p) if std::path::Path::new(&p).is_file())
}

/// Fail-closed: on-chain zap1 store+match+tamper. Missing fields is not Ok.
/// When Halo2 store-full-circuit artifacts are present, credit is the host
/// `proof_instance_verify` accept (no Merkle siblings on execute).
fn zap1_onchain_ok(v: &serde_json::Value) -> bool {
    let merkle = v.get("zap1_stored").and_then(|x| x.as_bool()) == Some(true)
        && (v.get("zap1_accepted").and_then(|x| x.as_bool()) == Some(true)
            || v.get("zap1_matches").and_then(|x| x.as_bool()) == Some(true))
        && v.get("zap1_tamper_rejected").and_then(|x| x.as_bool()) == Some(true);
    if !merkle {
        return false;
    }
    if halo2_artifacts_present() {
        v.get("zap1_halo2_stored").and_then(|x| x.as_bool()) == Some(true)
            && v.get("zap1_halo2_accepted").and_then(|x| x.as_bool()) == Some(true)
            && v.get("zap1_halo2_tamper_rejected").and_then(|x| x.as_bool()) == Some(true)
    } else {
        true
    }
}

/// Fail-closed: ics08 CreateClient + AttestPacket + Accepted query + tamper.
/// A non-empty `ics08_contract` after instantiate is store-only, not accept.
fn ics08_onchain_ok(v: &serde_json::Value) -> bool {
    v.get("ics08_contract")
        .and_then(|x| x.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
        && v.get("ics08_executed").and_then(|x| x.as_bool()) == Some(true)
        && v.get("ics08_accepted").and_then(|x| x.as_bool()) == Some(true)
        && v.get("ics08_tamper_rejected").and_then(|x| x.as_bool()) == Some(true)
}

/// Store `cw-zap1-ibcv2.wasm` on a spawned Terp chain and attest this bundle.
pub fn attest_zap1_on_live_chain(bundle: &crate::zap1::Zap1Ibcv2Bundle) -> Result<LiveDaemonHint, String> {
    let body = serde_json::to_string(&bundle.lc_helper_request())
        .map_err(|e| format!("zap1 attest json: {e}"))?;
    std::env::set_var("PIR_ZAP1_ATTEST_JSON", &body);
    if let Some(w) = zap1_wasm_file() {
        std::env::set_var("PIR_ZAP1_WASM", w);
    }
    run_live_attach_bin()
}

fn oob_commitment_hexes() -> Result<(String, String), String> {
    use crate::ask::{PublicAsk, ResourceAsk};
    use crate::bid::{EncryptedBidEnvelope, PlaintextBid};
    let public = PublicAsk::new(
        "ask-live-ns4",
        "tenant",
        "version: \"2.0\"\nservices:\n  app:\n    image: alpine\n",
        ResourceAsk {
            cpu_milli: 100,
            memory_mib: 256,
            storage_mib: 512,
            gpu_units: 0,
        },
        "private-llm",
    );
    let key = crate::tagged_hash(b"session", &[b"live-ns4"]);
    let bid = PlaintextBid {
        ask_id: public.ask_id.clone(),
        bidder_identity: "prov-oob".into(),
        price_uakt: 4_000,
        provider_endpoint: "oob://p".into(),
    };
    let env = EncryptedBidEnvelope::seal(&bid, &key).map_err(|e| e.to_string())?;
    let ask_hex = crate::hex32(&public.ask_commitment());
    let bid_hex = crate::hex32(&env.commitment().commitment);
    env.commitment()
        .verify_against(&env)
        .map_err(|e| e.to_string())?;
    Ok((ask_hex, bid_hex))
}

fn live_attach_bin() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("PIR_LIVE_ATTACH_BIN") {
        let pb = std::path::PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in [
        "live-chain/target/debug/pir-live-attach",
        "../ict-rs/target/debug/pir-live-attach",
        "../ict-rs/target/release/pir-live-attach",
    ] {
        let p = root.join(rel);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Attempts Docker + ict-rs crate + names `daemon_builder_from_chain`. Not an Ok stub.
pub fn probe_daemon_builder_from_chain() -> String {
    let mut parts = vec!["probe daemon_builder_from_chain".to_string()];
    let docker = std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match docker {
        Ok(s) if s.success() => parts.push("docker=ok".into()),
        Ok(s) => parts.push(format!("docker_exit={s}")),
        Err(e) => parts.push(format!("docker_spawn={e}")),
    }
    let ict = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ict-rs/ict-rs/src/lib.rs");
    if ict.is_file() {
        parts.push("ict-rs_crate=present".into());
    } else {
        parts.push("ict-rs_crate=missing".into());
    }
    parts.push(
        "ict_rs_cw_orch::daemon_builder_from_chain not invoked: no running CosmosChain in this process"
            .into(),
    );
    parts.join("; ")
}
