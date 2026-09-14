//! Same four-contract sequence as `pir_cw_orch::PrivateInference::deploy_on`.
//!
//! `pir-cw-orch` is cw-orch 0.24 / cosmwasm-std 1.5 (Mock + wasm wrappers).
//! ict-rs `daemon_builder_from_chain` yields cw-orch 0.30 Daemon (cosmwasm-std 3).
//! Those Daemon types cannot be the same generic, so this bin runs the Deploy
//! steps on the ict-rs Daemon itself. Missing wasm / gRPC / funds fail closed.

use cw_orch::contract::Contract;
use cw_orch::daemon::Daemon;
use cw_orch::prelude::{ChainInfoOwned, IndexResponse, Uploadable, WasmPath};
use serde_json::json;
use std::path::PathBuf;

pub const COMMIT_ID: &str = "cw-pir-commit";
pub const ESCROW_ID: &str = "cw-pir-escrow";
pub const ZAP1_ID: &str = "cw-zap1-ibcv2";
pub const ICS08_ID: &str = "cw-ics08-wasm-zap1";

/// Well-known mnemonic recovered as genesis faucet so Daemon can pay gas.
pub const DEPLOYER_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub struct WasmFiles {
    pub commit: PathBuf,
    pub escrow: PathBuf,
    pub zap1: PathBuf,
    pub ics08: PathBuf,
}

impl WasmFiles {
    pub fn discover() -> Result<Self, String> {
        Ok(Self {
            commit: require_wasm(
                "PIR_COMMIT_WASM",
                &[
                    "../cw-commit/artifacts/cw_pir_commit.wasm",
                    "../cw-commit/target/wasm32-unknown-unknown/release/cw_pir_commit.wasm",
                ],
            )?,
            escrow: require_wasm(
                "PIR_ESCROW_WASM",
                &[
                    "../cw-escrow/artifacts/cw_pir_escrow.wasm",
                    "../cw-escrow/target/wasm32-unknown-unknown/release/cw_pir_escrow.wasm",
                ],
            )?,
            zap1: require_wasm(
                "PIR_ZAP1_WASM",
                &[
                    "../cw-zap1-ibcv2/artifacts/cw_zap1_ibcv2.wasm",
                    "../cw-zap1-ibcv2/target/wasm32-unknown-unknown/release/cw_zap1_ibcv2.wasm",
                ],
            )?,
            ics08: require_wasm(
                "PIR_ICS08_WASM",
                &[
                    "../../terp-rs/crates/cw-ics08-wasm-zap1/artifacts/cw_ics08_wasm_zap1.wasm",
                    "../../terp-rs/crates/cw-ics08-wasm-zap1/target/wasm32-unknown-unknown/release/cw_ics08_wasm_zap1.wasm",
                    "../cw-ics08-wasm-zap1/target/wasm32-unknown-unknown/release/cw_ics08_wasm_zap1.wasm",
                ],
            )?,
        })
    }

    pub fn export_env(&self) {
        std::env::set_var("PIR_COMMIT_WASM", &self.commit);
        std::env::set_var("PIR_ESCROW_WASM", &self.escrow);
        std::env::set_var("PIR_ZAP1_WASM", &self.zap1);
        std::env::set_var("PIR_ICS08_WASM", &self.ics08);
    }
}

fn require_wasm(var: &str, rel: &[&str]) -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var(var) {
        let pb = PathBuf::from(&p);
        if pb.is_file() {
            return Ok(pb);
        }
        return Err(format!("{var} not a file: {p}"));
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for r in rel {
        let p = root.join(r);
        if p.is_file() {
            return Ok(p);
        }
    }
    Err(format!(
        "missing {var} wasm (PrivateInference::deploy_on needs all four contracts)"
    ))
}

struct CommitUpload;
struct EscrowUpload;
struct Zap1Upload;
struct Ics08Upload;

impl Uploadable for CommitUpload {
    fn wasm(_chain: &ChainInfoOwned) -> WasmPath {
        WasmPath::new(std::env::var("PIR_COMMIT_WASM").expect("PIR_COMMIT_WASM")).expect("commit wasm")
    }
}
impl Uploadable for EscrowUpload {
    fn wasm(_chain: &ChainInfoOwned) -> WasmPath {
        WasmPath::new(std::env::var("PIR_ESCROW_WASM").expect("PIR_ESCROW_WASM")).expect("escrow wasm")
    }
}
impl Uploadable for Zap1Upload {
    fn wasm(_chain: &ChainInfoOwned) -> WasmPath {
        WasmPath::new(std::env::var("PIR_ZAP1_WASM").expect("PIR_ZAP1_WASM")).expect("zap1 wasm")
    }
}
impl Uploadable for Ics08Upload {
    fn wasm(_chain: &ChainInfoOwned) -> WasmPath {
        WasmPath::new(std::env::var("PIR_ICS08_WASM").expect("PIR_ICS08_WASM")).expect("ics08 wasm")
    }
}

pub struct Deployed {
    pub commit: Contract<Daemon>,
    pub escrow: Contract<Daemon>,
    pub zap1: Contract<Daemon>,
    pub ics08: Contract<Daemon>,
}

/// `PrivateInference::deploy_on(Daemon)`: store + instantiate commit, escrow, zap1, ics08.
pub fn deploy_on_daemon(daemon: Daemon) -> Result<Deployed, String> {
    let commit = Contract::new(COMMIT_ID, daemon.clone());
    commit
        .upload(&CommitUpload)
        .map_err(|e| format!("after daemon_builder: deploy_on upload {COMMIT_ID}: {e}"))?;
    commit
        .instantiate(&json!({}), None, &[])
        .map_err(|e| format!("after daemon_builder: deploy_on instantiate {COMMIT_ID}: {e}"))?;

    let escrow = Contract::new(ESCROW_ID, daemon.clone());
    escrow
        .upload(&EscrowUpload)
        .map_err(|e| format!("after daemon_builder: deploy_on upload {ESCROW_ID}: {e}"))?;
    escrow
        .instantiate(&json!({}), None, &[])
        .map_err(|e| format!("after daemon_builder: deploy_on instantiate {ESCROW_ID}: {e}"))?;

    let zap1 = Contract::new(ZAP1_ID, daemon.clone());
    zap1
        .upload(&Zap1Upload)
        .map_err(|e| format!("after daemon_builder: deploy_on upload {ZAP1_ID}: {e}"))?;
    zap1
        .instantiate(&json!({}), None, &[])
        .map_err(|e| format!("after daemon_builder: deploy_on instantiate {ZAP1_ID}: {e}"))?;

    let ics08 = Contract::new(ICS08_ID, daemon);
    ics08
        .upload(&Ics08Upload)
        .map_err(|e| format!("after daemon_builder: deploy_on upload {ICS08_ID}: {e}"))?;
    ics08
        .instantiate(&json!({}), None, &[])
        .map_err(|e| format!("after daemon_builder: deploy_on instantiate {ICS08_ID}: {e}"))?;

    Ok(Deployed {
        commit,
        escrow,
        zap1,
        ics08,
    })
}

pub struct CommitExercise {
    pub oob_bid_matches: bool,
    pub mismatch_rejected: bool,
    pub no_price_on_chain: bool,
    pub addr: String,
}

pub fn exercise_commit(
    suite: &Deployed,
    ask_hex: &str,
    bid_hex: &str,
) -> Result<CommitExercise, String> {
    suite
        .commit
        .execute(
            &json!({
                "post_commitments": {
                    "ask_commitment": ask_hex,
                    "bid_commitment": bid_hex
                }
            }),
            &[],
        )
        .map_err(|e| format!("after daemon_builder: post_commitments: {e}"))?;

    let stored: serde_json::Value = suite
        .commit
        .query(&json!({"get_commitments":{}}))
        .map_err(|e| format!("after daemon_builder: get_commitments: {e}"))?;
    let stored_s = stored.to_string();
    let stored_low = stored_s.to_ascii_lowercase();
    let no_price_on_chain = !stored_low.contains("price")
        && !stored_low.contains("identity")
        && !stored_s.contains("uakt");

    let match_ok: serde_json::Value = suite
        .commit
        .query(&json!({
            "match": {"ask_commitment": ask_hex, "bid_commitment": bid_hex}
        }))
        .map_err(|e| format!("after daemon_builder: match: {e}"))?;
    let mut bad_bid = bid_hex.to_string();
    let last = bad_bid.pop().unwrap();
    bad_bid.push(if last == '0' { '1' } else { '0' });
    let match_bad: serde_json::Value = suite
        .commit
        .query(&json!({
            "match": {"ask_commitment": ask_hex, "bid_commitment": bad_bid}
        }))
        .map_err(|e| format!("after daemon_builder: match tamper: {e}"))?;

    let good = query_matches_true(&match_ok)
        && stored_s.contains(bid_hex)
        && stored_s.contains(ask_hex);
    let mismatch_rejected = !query_matches_true(&match_bad);
    Ok(CommitExercise {
        oob_bid_matches: good,
        mismatch_rejected,
        no_price_on_chain,
        addr: suite
            .commit
            .address()
            .map(|a| a.to_string())
            .map_err(|e| format!("after daemon_builder: commit addr: {e}"))?,
    })
}

pub struct Zap1Exercise {
    pub stored: bool,
    pub accepted: bool,
    pub matches: bool,
    pub tamper_rejected: bool,
    pub addr: String,
    pub halo2_stored: bool,
    pub halo2_accepted: bool,
    pub halo2_tamper_rejected: bool,
    pub halo2_zkid: u64,
}

/// Off-chain Halo2 proof + pinned zkid. Merkle siblings never go on execute.
pub struct Halo2Attest {
    pub zkid: u64,
    pub proof: Vec<u8>,
    pub instances: Vec<u8>,
}

pub fn exercise_zap1(
    suite: &Deployed,
    raw: &str,
    halo2: Option<&Halo2Attest>,
) -> Result<Zap1Exercise, String> {
    let addr = suite
        .zap1
        .address()
        .map(|a| a.to_string())
        .map_err(|e| format!("after daemon_builder: zap1 addr: {e}"))?;
    if raw.is_empty() && halo2.is_none() {
        return Err(
            "after daemon_builder: PIR_ZAP1_ATTEST_JSON missing and Halo2 attest missing (fail-closed, not stored:true)"
                .into(),
        );
    }
    let v: serde_json::Value = serde_json::from_str(raw).unwrap_or(json!({}));
    let src = v
        .get("source_client")
        .and_then(|x| x.as_str())
        .unwrap_or("08-zap1-src");
    let dst = v
        .get("dest_client")
        .and_then(|x| x.as_str())
        .unwrap_or("08-terp-dst");
    suite
        .zap1
        .execute(
            &json!({
                "create_client": { "source_client": src, "dest_client": dst }
            }),
            &[],
        )
        .map_err(|e| format!("after daemon_builder: zap1 create_client: {e}"))?;
    let app_hex = v
        .get("app_data_hash_hex")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let seq = v.get("sequence").and_then(|x| x.as_u64()).unwrap_or(1);
    let timeout = v
        .get("timeout_timestamp_ns")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);

    if let Some(h) = halo2 {
        return exercise_zap1_halo2(suite, src, dst, seq, timeout, app_hex, addr, h);
    }

    let attest = attest_execute_from_json(&v)?;
    suite
        .zap1
        .execute(&attest, &[])
        .map_err(|e| format!("after daemon_builder: zap1 attest: {e}"))?;
    let q: serde_json::Value = suite
        .zap1
        .query(&json!({
            "match": {
                "source_client": src,
                "dest_client": dst,
                "sequence": seq,
                "app_data_hash_hex": app_hex
            }
        }))
        .map_err(|e| format!("after daemon_builder: zap1 match: {e}"))?;
    let matches = query_matches_true(&q);
    let mut bad = app_hex.to_string();
    if let Some(c) = bad.pop() {
        bad.push(if c == '0' { '1' } else { '0' });
    }
    let mut tampered = v.clone();
    tampered["app_data_hash_hex"] = json!(bad);
    let tamper_exec = suite
        .zap1
        .execute(&attest_execute_from_json(&tampered)?, &[]);
    let match_bad: serde_json::Value = suite
        .zap1
        .query(&json!({
            "match": {
                "source_client": src,
                "dest_client": dst,
                "sequence": seq,
                "app_data_hash_hex": bad
            }
        }))
        .unwrap_or(json!({}));
    let tamper_rejected = tamper_exec.is_err() && !query_matches_true(&match_bad);
    Ok(Zap1Exercise {
        stored: true,
        accepted: matches,
        matches,
        tamper_rejected,
        addr,
        halo2_stored: false,
        halo2_accepted: false,
        halo2_tamper_rejected: false,
        halo2_zkid: 0,
    })
}

fn exercise_zap1_halo2(
    suite: &Deployed,
    src: &str,
    dst: &str,
    seq: u64,
    timeout: u64,
    app_hex: &str,
    addr: String,
    h: &Halo2Attest,
) -> Result<Zap1Exercise, String> {
    let proof_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &h.proof);
    let inst_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &h.instances);
    let attest = json!({
        "attest_halo2": {
            "source_client": src,
            "dest_client": dst,
            "sequence": seq,
            "timeout_timestamp_ns": timeout,
            "app_data_hash_hex": app_hex,
            "zkid": h.zkid,
            "proof": proof_b64,
            "instances": inst_b64
        }
    });
    suite
        .zap1
        .execute(&attest, &[])
        .map_err(|e| format!("after daemon_builder: zap1 attest_halo2: {e}"))?;
    let q: serde_json::Value = suite
        .zap1
        .query(&json!({
            "match": {
                "source_client": src,
                "dest_client": dst,
                "sequence": seq,
                "app_data_hash_hex": app_hex
            }
        }))
        .map_err(|e| format!("after daemon_builder: zap1 halo2 match: {e}"))?;
    let matches = query_matches_true(&q);
    let mut bad = app_hex.to_string();
    if let Some(c) = bad.pop() {
        bad.push(if c == '0' { '1' } else { '0' });
    }
    let mut tamper_msg = attest.clone();
    tamper_msg["attest_halo2"]["app_data_hash_hex"] = json!(bad);
    let tamper_exec = suite.zap1.execute(&tamper_msg, &[]);
    let match_bad: serde_json::Value = suite
        .zap1
        .query(&json!({
            "match": {
                "source_client": src,
                "dest_client": dst,
                "sequence": seq,
                "app_data_hash_hex": bad
            }
        }))
        .unwrap_or(json!({}));
    let tamper_rejected = tamper_exec.is_err() && !query_matches_true(&match_bad);
    Ok(Zap1Exercise {
        stored: true,
        accepted: matches,
        matches,
        tamper_rejected,
        addr,
        halo2_stored: true,
        halo2_accepted: matches,
        halo2_tamper_rejected: tamper_rejected,
        halo2_zkid: h.zkid,
    })
}

fn query_matches_true(q: &serde_json::Value) -> bool {
    q.get("matches").and_then(|x| x.as_bool()) == Some(true)
        || q.to_string().contains("\"matches\":true")
        || q.to_string().contains("\"matches\": true")
}

fn query_accepted_true(q: &serde_json::Value) -> bool {
    q.get("accepted").and_then(|x| x.as_bool()) == Some(true)
        || q.to_string().contains("\"accepted\":true")
        || q.to_string().contains("\"accepted\": true")
}

pub struct Ics08Exercise {
    pub executed: bool,
    pub accepted: bool,
    pub tamper_rejected: bool,
    pub addr: String,
}

/// Packet accept on the stored `cw-ics08-wasm-zap1`: CreateClient + AttestPacket
/// + Accepted query + tamper reject. Instantiate-only is not this.
pub fn exercise_ics08(suite: &Deployed, raw: &str) -> Result<Ics08Exercise, String> {
    let addr = suite
        .ics08
        .address()
        .map(|a| a.to_string())
        .map_err(|e| format!("after daemon_builder: ics08 addr: {e}"))?;
    if raw.is_empty() {
        return Err(
            "after daemon_builder: ics08 execute skipped (empty attest json; store-only instantiate is not packet accept)"
                .into(),
        );
    }
    let v: serde_json::Value = serde_json::from_str(raw).unwrap_or(json!({}));
    let src = v
        .get("source_client")
        .and_then(|x| x.as_str())
        .unwrap_or("08-zap1-src");
    let dst = v
        .get("dest_client")
        .and_then(|x| x.as_str())
        .unwrap_or("08-terp-dst");
    let app_hex = v
        .get("app_data_hash_hex")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let seq = v.get("sequence").and_then(|x| x.as_u64()).unwrap_or(1);
    suite
        .ics08
        .execute(
            &json!({
                "create_client": { "source_client": src, "dest_client": dst }
            }),
            &[],
        )
        .map_err(|e| format!("after daemon_builder: ics08 create_client: {e}"))?;
    let attest = attest_execute_from_json(&v)?;
    suite
        .ics08
        .execute(&attest, &[])
        .map_err(|e| format!("after daemon_builder: ics08 attest_packet: {e}"))?;
    let q: serde_json::Value = suite
        .ics08
        .query(&json!({
            "accepted": {
                "source_client": src,
                "dest_client": dst,
                "sequence": seq,
                "app_data_hash_hex": app_hex
            }
        }))
        .map_err(|e| format!("after daemon_builder: ics08 accepted query: {e}"))?;
    let accepted = query_accepted_true(&q);
    if !accepted {
        return Err(format!(
            "after daemon_builder: ics08 Accepted query did not accept good packet q={q}"
        ));
    }
    let mut bad = app_hex.to_string();
    if let Some(c) = bad.pop() {
        bad.push(if c == '0' { '1' } else { '0' });
    }
    let mut tampered = v.clone();
    tampered["app_data_hash_hex"] = json!(bad);
    let tamper_exec = suite
        .ics08
        .execute(&attest_execute_from_json(&tampered)?, &[]);
    let match_bad: serde_json::Value = suite
        .ics08
        .query(&json!({
            "accepted": {
                "source_client": src,
                "dest_client": dst,
                "sequence": seq,
                "app_data_hash_hex": bad
            }
        }))
        .unwrap_or(json!({}));
    let tamper_rejected = tamper_exec.is_err() && !query_accepted_true(&match_bad);
    if !tamper_rejected {
        return Err(
            "after daemon_builder: ics08 tampered app_data_hash was not rejected on execute/query"
                .into(),
        );
    }
    Ok(Ics08Exercise {
        executed: true,
        accepted: true,
        tamper_rejected: true,
        addr,
    })
}

fn attest_execute_from_json(v: &serde_json::Value) -> Result<serde_json::Value, String> {
    let proof = v
        .get("proof")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    let mut steps = Vec::new();
    for p in proof {
        let hex_s = p
            .get("sibling_hex")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                p.get("sibling").and_then(|a| a.as_array()).and_then(|arr| {
                    if arr.len() == 32 {
                        let mut b = Vec::with_capacity(32);
                        for el in arr {
                            b.push(el.as_u64().unwrap_or(0) as u8);
                        }
                        Some(hex::encode(b))
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default();
        steps.push(json!({
            "sibling_hex": hex_s,
            "sibling_is_left": p.get("sibling_is_left").and_then(|x| x.as_bool()).unwrap_or(false)
        }));
    }
    Ok(json!({
        "attest_packet": {
            "source_client": v.get("source_client").and_then(|x| x.as_str()).unwrap_or(""),
            "dest_client": v.get("dest_client").and_then(|x| x.as_str()).unwrap_or(""),
            "sequence": v.get("sequence").and_then(|x| x.as_u64()).unwrap_or(0),
            "timeout_timestamp_ns": v.get("timeout_timestamp_ns").and_then(|x| x.as_u64()).unwrap_or(0),
            "app_data_hash_hex": v.get("app_data_hash_hex").and_then(|x| x.as_str()).unwrap_or(""),
            "note_hex": v.get("note_hex").and_then(|x| x.as_str()).unwrap_or(""),
            "amount_zat": v.get("amount_zat").and_then(|x| x.as_u64()).unwrap_or(0),
            "frost_group_hex": v.get("frost_group_hex").and_then(|x| x.as_str()).unwrap_or(""),
            "leaf_hex": v.get("leaf_hex").and_then(|x| x.as_str()).unwrap_or(""),
            "merkle_root_hex": v.get("merkle_root_hex").and_then(|x| x.as_str()).unwrap_or(""),
            "event_kind": v.get("event_kind").and_then(|x| x.as_str()).unwrap_or("hosting_payment"),
            "wallet_or_serial": v.get("wallet_or_serial").and_then(|x| x.as_str()).unwrap_or(""),
            "proof": steps
        }
    }))
}

/// Same domain as `cw-pir-escrow` `sha_like` / in-process `escrow-cell-v1`.
fn escrow_cell_id(deposit: u64, bid: &str, tenant: &str, provider: &str, resolver: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let tag = b"escrow-cell-v1";
    h.update(tag);
    h.update(&[tag.len() as u8]);
    for p in [
        deposit.to_le_bytes().as_slice(),
        hex::decode(bid).unwrap_or_default().as_slice(),
        tenant.as_bytes(),
        provider.as_bytes(),
        resolver.as_bytes(),
    ] {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    hex::encode(h.finalize())
}

fn first_event_attr(res: &impl IndexResponse, key: &str) -> Option<String> {
    for ty in ["wasm", "wasm-open_cell", "wasm-close"] {
        if let Ok(v) = res.event_attr_value(ty, key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    for ev in res.events() {
        for a in ev.attributes {
            if a.key == key && !a.value.is_empty() {
                return Some(a.value);
            }
        }
    }
    None
}

pub struct EscrowExercise {
    pub grant_recorded: bool,
    pub earned_zat: u64,
    pub remainder_zat: u64,
    pub cell_id: String,
    pub open_accrue_close: bool,
}

/// `PrivateInference::escrow_open_accrue_close` on the ict-rs Daemon.
/// Grant + events only (empty funds). Value is not BankMsg / uterp.
pub fn exercise_escrow(suite: &Deployed) -> Result<EscrowExercise, String> {
    let bid = "bb".repeat(32);
    let tenant = "tenant1";
    let provider = "provider1";
    let resolver = "resolver1";
    let deposit = 100u64;
    let commitment = "aa".repeat(32);
    let open_h = "bb".repeat(32);
    let close_h = "cc".repeat(32);
    let cell_id = escrow_cell_id(deposit, &bid, tenant, provider, resolver);

    let open = suite
        .escrow
        .execute(
            &json!({
                "open_cell": {
                    "bid_commitment": bid,
                    "tenant": tenant,
                    "provider": provider,
                    "resolver": resolver,
                    "deposit_zat": deposit
                }
            }),
            &[],
        )
        .map_err(|e| format!("after daemon_builder: escrow open_cell: {e}"))?;
    if let Some(ev) = first_event_attr(&open, "cell_id") {
        if ev != cell_id {
            return Err(format!(
                "after daemon_builder: escrow cell_id mismatch event={ev} computed={cell_id}"
            ));
        }
    }

    suite
        .escrow
        .execute(
            &json!({
                "accrue": {
                    "cell_id": cell_id,
                    "commitment": commitment,
                    "open_header_hash": open_h,
                    "close_header_hash": close_h
                }
            }),
            &[],
        )
        .map_err(|e| format!("after daemon_builder: escrow accrue: {e}"))?;

    suite
        .escrow
        .execute(
            &json!({
                "close": {
                    "cell_id": cell_id,
                    "party": "tenant"
                }
            }),
            &[],
        )
        .map_err(|e| format!("after daemon_builder: escrow close: {e}"))?;

    let grant: serde_json::Value = suite
        .escrow
        .query(&json!({ "grant": { "cell_id": cell_id } }))
        .map_err(|e| format!("after daemon_builder: escrow grant query: {e}"))?;
    let recorded = grant.get("recorded").and_then(|x| x.as_bool()) == Some(true);
    let earned_zat = grant.get("earned_zat").and_then(|x| x.as_u64()).unwrap_or(0);
    let remainder_zat = grant
        .get("remainder_zat")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let acc = grant
        .get("accrual_commitment")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if !recorded || acc.len() != 64 || earned_zat != 0 || remainder_zat != deposit {
        return Err(format!(
            "after daemon_builder: escrow grant piece skipped grant={grant}"
        ));
    }
    let unknown = suite
        .escrow
        .query::<serde_json::Value, serde_json::Value>(&json!({ "grant": { "cell_id": "00".repeat(32) } }));
    if unknown.is_ok() {
        return Err("after daemon_builder: unknown cell must have no grant".into());
    }
    Ok(EscrowExercise {
        grant_recorded: true,
        earned_zat,
        remainder_zat,
        cell_id,
        open_accrue_close: true,
    })
}
