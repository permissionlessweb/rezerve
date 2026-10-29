//! One JSON line per successful production sequence.
//!
//! Times are host wall clock. `inclusion_prove_us` includes the first k=17
//! `Params::new` and `keygen_pk` in this process. Chain gas is the sum of
//! successful txs on the kept ict LCD. Fee amounts are the uterp the txs
//! declared, and `fee_at_min_price_uterp` is `gas_used` at `0.025uterp`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxGas {
    pub hash: String,
    pub gas_wanted: u64,
    pub gas_used: u64,
    pub fee_uterp: u64,
    pub msg: String,
    pub store_circuit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eBench {
    pub recorded_unix_ms: u64,
    pub image: String,
    pub inclusion_prove_includes_keygen: bool,
    pub inclusion_prove_us: u64,
    pub inclusion_prove_ms: u64,
    pub inclusion_verify_us: u64,
    pub inclusion_verify_ms: u64,
    pub stored_vk_verify_us: u64,
    pub stored_vk_verify_ms: u64,
    pub accrual_prove_us: u64,
    pub accrual_prove_ms: u64,
    pub accrual_verify_us: u64,
    pub accrual_verify_ms: u64,
    pub chain_tx_count: u64,
    pub chain_gas_used: u64,
    pub chain_gas_wanted: u64,
    pub chain_fee_uterp: u64,
    pub fee_at_min_price_uterp: String,
    pub store_circuit_gas_used: u64,
    pub txs: Vec<TxGas>,
}

#[derive(Debug, Clone, Copy)]
pub struct AccrualTimes {
    pub prove_us: u64,
    pub verify_us: u64,
}

impl E2eBench {
    pub fn blank() -> Self {
        Self {
            recorded_unix_ms: 0,
            image: std::env::var("PIR_BENCH_LABEL")
                .ok()
                .filter(|label| !label.is_empty())
                .or_else(|| std::env::var("PIR_TERP_IMAGE").ok())
                .unwrap_or_else(|| "unset".into()),
            inclusion_prove_includes_keygen: true,
            inclusion_prove_us: 0,
            inclusion_prove_ms: 0,
            inclusion_verify_us: 0,
            inclusion_verify_ms: 0,
            stored_vk_verify_us: 0,
            stored_vk_verify_ms: 0,
            accrual_prove_us: 0,
            accrual_prove_ms: 0,
            accrual_verify_us: 0,
            accrual_verify_ms: 0,
            chain_tx_count: 0,
            chain_gas_used: 0,
            chain_gas_wanted: 0,
            chain_fee_uterp: 0,
            fee_at_min_price_uterp: "0.000".into(),
            store_circuit_gas_used: 0,
            txs: Vec::new(),
        }
    }

    pub fn set_inclusion_prove_us(&mut self, us: u64) {
        self.inclusion_prove_us = us;
        self.inclusion_prove_ms = us / 1000;
    }

    pub fn set_inclusion_verify_us(&mut self, us: u64) {
        self.inclusion_verify_us = us;
        self.inclusion_verify_ms = us / 1000;
    }

    pub fn set_stored_vk_verify_us(&mut self, us: u64) {
        self.stored_vk_verify_us = us;
        self.stored_vk_verify_ms = us / 1000;
    }

    pub fn set_accrual(&mut self, times: AccrualTimes) {
        self.accrual_prove_us = times.prove_us;
        self.accrual_prove_ms = times.prove_us / 1000;
        self.accrual_verify_us = times.verify_us;
        self.accrual_verify_ms = times.verify_us / 1000;
    }

    pub fn apply_chain(&mut self, txs: Vec<TxGas>) {
        self.chain_tx_count = txs.len() as u64;
        self.chain_gas_used = txs.iter().map(|t| t.gas_used).sum();
        self.chain_gas_wanted = txs.iter().map(|t| t.gas_wanted).sum();
        self.chain_fee_uterp = txs.iter().map(|t| t.fee_uterp).sum();
        self.store_circuit_gas_used = txs
            .iter()
            .filter(|t| t.store_circuit)
            .map(|t| t.gas_used)
            .sum();
        self.fee_at_min_price_uterp = fee_at_min_price(self.chain_gas_used);
        self.txs = txs;
    }

    pub fn line(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("e2e bench json: {e}"))
    }
}

pub fn elapsed_us(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// `0.025uterp` per gas, the price `pir-live-attach` configures.
pub fn fee_at_min_price(gas_used: u64) -> String {
    let milli = gas_used.saturating_mul(25);
    format!("{}.{:03}", milli / 1000, milli % 1000)
}

pub fn history_path() -> PathBuf {
    if let Ok(p) = std::env::var("PIR_E2E_BENCH_PATH") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts/bench/e2e-history.jsonl")
}

pub fn record(bench: &mut E2eBench) -> Result<PathBuf, String> {
    bench.recorded_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let line = bench.line()?;
    println!("E2E_BENCH {line}");
    let path = history_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("bench dir: {e}"))?;
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("bench history: {e}"))?;
    writeln!(f, "{line}").map_err(|e| format!("bench append: {e}"))?;
    if let Some(latest) = latest_path(&path) {
        std::fs::write(&latest, format!("{line}\n")).map_err(|e| format!("bench latest: {e}"))?;
    }
    Ok(path)
}

fn latest_path(history: &Path) -> Option<PathBuf> {
    Some(history.with_file_name("e2e-latest.json"))
}

pub fn parse_tx_search(body: &str) -> Result<Vec<TxGas>, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("tx search json: {e}"))?;
    let responses = array_field(&v, "tx_responses", "txResponses")
        .ok_or_else(|| "tx search missing tx_responses".to_string())?;
    let txs = array_field(&v, "txs", "txs");
    let mut out = Vec::with_capacity(responses.len());
    for (i, tx) in responses.iter().enumerate() {
        let code = json_u64(tx.get("code")).unwrap_or(0);
        if code != 0 {
            continue;
        }
        let hash = tx
            .get("txhash")
            .or_else(|| tx.get("tx_hash"))
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string();
        if hash.is_empty() {
            return Err("tx response missing txhash".into());
        }
        let gas_wanted = json_u64(tx.get("gas_wanted").or_else(|| tx.get("gasWanted")))
            .ok_or_else(|| format!("tx {hash} missing gas_wanted"))?;
        let gas_used = json_u64(tx.get("gas_used").or_else(|| tx.get("gasUsed")))
            .ok_or_else(|| format!("tx {hash} missing gas_used"))?;
        let body_tx = txs.and_then(|all| all.get(i));
        let fee_uterp = fee_uterp_of(body_tx);
        let msg = msg_of(body_tx);
        let store_circuit = events_store_circuit(tx);
        out.push(TxGas {
            hash,
            gas_wanted,
            gas_used,
            fee_uterp,
            msg,
            store_circuit,
        });
    }
    if out.is_empty() {
        return Err("tx search returned no successful txs".into());
    }
    Ok(out)
}

pub fn fetch_chain_gas(rpc: &str) -> Result<Vec<TxGas>, String> {
    if rpc.is_empty() {
        return Err("chain rpc_url is empty".into());
    }
    let py = r#"
import json, sys, urllib.request
rpc = sys.argv[1].rstrip("/")
page = 1
txs = []
total = None
while page <= 20:
    url = f'{rpc}/tx_search?query=%22tx.height%3E0%22&prove=false&page={page}&per_page=100'
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    result = data.get("result") or {}
    batch = result.get("txs") or []
    txs.extend(batch)
    total = int(result.get("total_count") or 0)
    if not batch or len(txs) >= total:
        break
    page += 1
json.dump({"result": {"txs": txs, "total_count": str(total or len(txs))}}, sys.stdout)
"#;
    let out = std::process::Command::new("python3")
        .args(["-c", py, rpc])
        .output()
        .map_err(|e| format!("tx search: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tx search failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_comet_tx_search(&String::from_utf8_lossy(&out.stdout))
}

pub fn parse_comet_tx_search(body: &str) -> Result<Vec<TxGas>, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("comet tx_search json: {e}"))?;
    let txs = v
        .pointer("/result/txs")
        .and_then(|t| t.as_array())
        .ok_or_else(|| "comet tx_search missing result.txs".to_string())?;
    let mut out = Vec::new();
    for tx in txs {
        let result = tx.get("tx_result").unwrap_or(tx);
        let code = json_u64(result.get("code")).unwrap_or(0);
        if code != 0 {
            continue;
        }
        let hash = tx
            .get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string();
        if hash.is_empty() {
            return Err("comet tx missing hash".into());
        }
        let gas_wanted = json_u64(result.get("gas_wanted").or_else(|| result.get("gasWanted")))
            .ok_or_else(|| format!("tx {hash} missing gas_wanted"))?;
        let gas_used = json_u64(result.get("gas_used").or_else(|| result.get("gasUsed")))
            .ok_or_else(|| format!("tx {hash} missing gas_used"))?;
        let events = result.get("events").cloned().unwrap_or(serde_json::json!([]));
        let store_circuit = events_store_circuit(&serde_json::json!({"logs": [{"events": events}]}));
        out.push(TxGas {
            hash,
            gas_wanted,
            gas_used,
            fee_uterp: 0,
            msg: String::new(),
            store_circuit,
        });
    }
    if out.is_empty() {
        return Err("comet tx_search returned no successful txs".into());
    }
    Ok(out)
}

fn array_field<'a>(
    v: &'a serde_json::Value,
    snake: &str,
    camel: &str,
) -> Option<&'a Vec<serde_json::Value>> {
    v.get(snake)
        .or_else(|| v.get(camel))
        .and_then(|x| x.as_array())
}

fn json_u64(v: Option<&serde_json::Value>) -> Option<u64> {
    let v = v?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str()?.parse().ok()
}

fn fee_uterp_of(tx: Option<&serde_json::Value>) -> u64 {
    let Some(tx) = tx else {
        return 0;
    };
    let amounts = tx
        .pointer("/auth_info/fee/amount")
        .or_else(|| tx.pointer("/authInfo/fee/amount"))
        .and_then(|a| a.as_array());
    let Some(amounts) = amounts else {
        return 0;
    };
    amounts
        .iter()
        .filter(|coin| {
            coin.get("denom")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .ends_with("uterp")
        })
        .filter_map(|coin| json_u64(coin.get("amount")))
        .sum()
}

fn msg_of(tx: Option<&serde_json::Value>) -> String {
    let Some(tx) = tx else {
        return String::new();
    };
    let ty = tx
        .pointer("/body/messages/0/@type")
        .and_then(|t| t.as_str())
        .unwrap_or("");
    ty.rsplit(['/', '.']).next().unwrap_or(ty).to_string()
}

fn events_store_circuit(tx: &serde_json::Value) -> bool {
    let logs = tx.get("logs").and_then(|l| l.as_array());
    let Some(logs) = logs else {
        return false;
    };
    for log in logs {
        let Some(events) = log.get("events").and_then(|e| e.as_array()) else {
            continue;
        };
        for ev in events {
            let ty = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if ty.contains("store_full_circuit") || ty.contains("store_circuit") {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_search_sums_successful_uterp_and_store_circuit() {
        let body = r#"{
          "txs": [
            {"body":{"messages":[{"@type":"/cosmwasm.wasm.v1.MsgStoreCode"}]},
             "auth_info":{"fee":{"amount":[{"denom":"uterp","amount":"5000"}]}}},
            {"body":{"messages":[{"@type":"/cosmwasm.wasm.v1.MsgExecuteContract"}]},
             "auth_info":{"fee":{"amount":[{"denom":"uterp","amount":"2500"}]}}}
          ],
          "tx_responses": [
            {"code":0,"txhash":"AA","gas_wanted":"200000","gas_used":"100000",
             "logs":[{"events":[{"type":"store_full_circuit","attributes":[{"key":"zk_id","value":"1"}]}]}]},
            {"code":1,"txhash":"BB","gas_wanted":"10","gas_used":"9","logs":[]},
            {"code":0,"txhash":"CC","gasWanted":"80000","gasUsed":"40000","logs":[]}
          ]
        }"#;
        let txs = parse_tx_search(body).expect("parse");
        assert_eq!(txs.len(), 2);
        assert!(txs[0].store_circuit);
        assert_eq!(txs[0].gas_used, 100_000);
        assert_eq!(txs[0].fee_uterp, 5_000);
        assert_eq!(txs[0].msg, "MsgStoreCode");
        assert_eq!(txs[1].hash, "CC");
        assert_eq!(txs[1].gas_used, 40_000);
        assert_eq!(txs[1].fee_uterp, 0);
        let mut bench = E2eBench::blank();
        bench.apply_chain(txs);
        assert_eq!(bench.chain_tx_count, 2);
        assert_eq!(bench.chain_gas_used, 140_000);
        assert_eq!(bench.chain_gas_wanted, 280_000);
        assert_eq!(bench.chain_fee_uterp, 5_000);
        assert_eq!(bench.store_circuit_gas_used, 100_000);
        assert_eq!(bench.fee_at_min_price_uterp, "3500.000");
    }

    #[test]
    fn comet_tx_search_reads_gas_and_skips_failures() {
        let body = r#"{
          "result": {
            "total_count": "2",
            "txs": [
              {"hash":"AA","tx_result":{"code":0,"gas_wanted":"200000","gas_used":"100000",
                "events":[{"type":"store_full_circuit","attributes":[]}]}},
              {"hash":"BB","tx_result":{"code":1,"gas_wanted":"10","gas_used":"9","events":[]}}
            ]
          }
        }"#;
        let txs = parse_comet_tx_search(body).expect("comet");
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].gas_used, 100_000);
        assert!(txs[0].store_circuit);
    }

    #[test]
    fn min_price_fee_uses_configured_uterp_rate() {
        assert_eq!(fee_at_min_price(1000), "25.000");
        assert_eq!(fee_at_min_price(1), "0.025");
    }
}
