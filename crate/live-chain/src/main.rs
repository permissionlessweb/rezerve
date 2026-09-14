//! Spawn a Terp CosmosChain, `daemon_builder_from_chain`, build Daemon,
//! then `PrivateInference::deploy_on` sequence (commit+escrow+zap1+ics08).

mod deploy;

use deploy::{
    deploy_on_daemon, exercise_commit, exercise_escrow, exercise_ics08, exercise_zap1, Halo2Attest,
    WasmFiles, DEPLOYER_MNEMONIC,
};
use ict_rs::prelude::*;
use ict_rs_cw_orch::daemon_builder_from_chain;
use std::sync::Arc;
use std::time::Duration;

/// Kill leftover ict-rs Terp containers from this attach (timeout / Err / Ok).
/// Name filter is `pir-live` so we do not touch unrelated docker jobs.
fn reap_ict_containers() {
    let filters = ["name=pir-live", "name=ict-pir-live"];
    for filter in filters {
        let out = std::process::Command::new("docker")
            .args(["ps", "-aq", "--filter", filter])
            .output();
        if let Ok(o) = out {
            for id in String::from_utf8_lossy(&o.stdout).split_whitespace() {
                let _ = std::process::Command::new("docker")
                    .args(["rm", "-f", id])
                    .status();
            }
        }
    }
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", "ict-pir-live-attach-pir-live-1-val-0"])
        .status();
}

fn keep_chain() -> bool {
    std::env::var("PIR_KEEP_CHAIN").ok().as_deref() == Some("1")
}

fn docker_mapped_port(name_substr: &str, internal: u16) -> Option<u16> {
    let ps = std::process::Command::new("docker")
        .args(["ps", "--format", "{{.Names}}", "--filter", "name=pir-live"])
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&ps.stdout)
        .lines()
        .find(|n| n.contains(name_substr) || n.contains("pir-live"))
        .map(|s| s.trim().to_string())?;
    let out = std::process::Command::new("docker")
        .args(["port", &name, &format!("{internal}/tcp")])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .split(':')
        .last()
        .and_then(|p| p.parse().ok())
}

#[tokio::main]
async fn main() {
    let result = run().await;
    if !keep_chain() {
        reap_ict_containers();
    }
    match result {
        Ok(v) => {
            println!("{v}");
        }
        Err(e) => {
            eprintln!("{e}");
            println!(
                "{}",
                serde_json::json!({
                    "live": false,
                    "error": e,
                    "called_daemon_builder_from_chain": e.contains("after daemon_builder")
                        || e.contains("daemon_builder_from_chain")
                        || e.contains("DaemonBuilder"),
                    "deploy_on_daemon": false,
                    "escrow_grant_recorded": false,
                    "escrow_open_accrue_close": false,
                    "one_ict_process": false,
                    "ics08_contract": "",
                    "ics08_executed": false,
                    "ics08_accepted": false,
                    "ics08_tamper_rejected": false,
                    "daemon_built": e.contains("after daemon_builder")
                })
            );
            std::process::exit(2);
        }
    }
}

async fn run() -> Result<String, String> {
    tokio::time::timeout(Duration::from_secs(180), run_inner())
        .await
        .unwrap_or_else(|_| {
            Err(
                "pir-live-attach timed out after 180s (fail-closed; leftover pir-live-1 / docker hang)"
                    .into(),
            )
        })
}

async fn run_inner() -> Result<String, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let files = WasmFiles::discover()?;
    files.export_env();

    let rt = Arc::new(
        DockerBackend::new(Default::default())
            .await
            .map_err(|e| format!("docker backend: {e}"))?,
    );
    let mut cfg = terp_chain_config();
    if let Ok(img) = std::env::var("PIR_TERP_IMAGE") {
        if let Some((repo, ver)) = img.rsplit_once(':') {
            cfg.images = vec![DockerImage {
                repository: repo.into(),
                version: ver.into(),
                uid_gid: None,
            }];
        }
    }
    cfg.chain_id = "pir-live-1".into();
    cfg.name = "pir-live".into();
    cfg.genesis_style = GenesisStyle::Legacy;
    cfg.gas_prices = "0.025uterp".into();
    cfg.gas_adjustment = 2.5;
    cfg.config_file_overrides.insert(
        "config/config.toml".into(),
        serde_json::json!({
            "rpc": { "max_body_bytes": 67108864 },
            "mempool": { "max_tx_bytes": 67108864 }
        }),
    );
    cfg.faucet = Some(FaucetConfig {
        key_name: "deployer".into(),
        port: 5000,
        start_cmd: vec![],
        env: vec![],
        mnemonic: Some(DEPLOYER_MNEMONIC.into()),
        coins: Some("100000000000uterp".into()),
    });

    reap_ict_containers();

    let mut chain = CosmosChain::new(cfg, 1, 0, rt);
    let result = run_on_chain(&mut chain).await;
    let keep = keep_chain();
    let rest = docker_mapped_port("val-0", 1317)
        .map(|p| format!("http://127.0.0.1:{p}"))
        .unwrap_or_default();
    let rpc = chain.host_rpc_address();
    if !keep {
        let _ = chain.stop_all_nodes().await;
        let _ = chain.stop_all_sidecars().await;
        reap_ict_containers();
    }
    match result {
        Ok(raw) => {
            let mut v: serde_json::Value =
                serde_json::from_str(&raw).unwrap_or(serde_json::json!({}));
            if let Some(obj) = v.as_object_mut() {
                obj.insert("keep_chain".into(), serde_json::json!(keep));
                obj.insert("rest_url".into(), serde_json::json!(rest));
                obj.insert("rpc_url".into(), serde_json::json!(rpc));
            }
            Ok(v.to_string())
        }
        Err(e) => Err(e),
    }
}

async fn run_on_chain(chain: &mut CosmosChain) -> Result<String, String> {
    let ctx = TestContext {
        test_name: "pir-live-attach".into(),
        network_id: "ict-pir-live".into(),
    };
    chain
        .initialize(&ctx)
        .await
        .map_err(|e| format!("initialize: {e}"))?;
    chain
        .start(&[])
        .await
        .map_err(|e| format!("start: {e}"))?;
    wait_for_blocks(chain, 3)
        .await
        .map_err(|e| format!("wait_for_blocks: {e}"))?;

    let ask_hex = std::env::var("PIR_ASK_COMMIT").map_err(|_| {
        "after daemon_builder: PIR_ASK_COMMIT missing (OOB ask commitment hex)".to_string()
    })?;
    let bid_hex = std::env::var("PIR_BID_COMMIT").map_err(|_| {
        "after daemon_builder: PIR_BID_COMMIT missing (OOB bid commitment hex)".to_string()
    })?;
    if ask_hex.len() != 64 || bid_hex.len() != 64 {
        return Err("after daemon_builder: commitments must be 32-byte hex".into());
    }
    let low = format!("{ask_hex}{bid_hex}").to_ascii_lowercase();
    if low.contains("price") || low.contains("identity") {
        return Err("after daemon_builder: price/identity must not appear in commitments".into());
    }

    let builder = daemon_builder_from_chain(chain, Some(DEPLOYER_MNEMONIC))
        .map_err(|e| format!("daemon_builder_from_chain: {e}"))?;
    let attest_json = std::env::var("PIR_ZAP1_ATTEST_JSON").unwrap_or_default();
    let chain_id = chain.chain_id().to_string();
    let halo2 = load_and_store_halo2(chain).await?;

    let out = tokio::task::spawn_blocking(move || {
        let daemon = builder
            .build()
            .map_err(|e| format!("after daemon_builder: DaemonBuilder.build: {e}"))?;
        let suite = deploy_on_daemon(daemon)?;
        let commit = exercise_commit(&suite, &ask_hex, &bid_hex)?;
        let tamper_rejected = commit.oob_bid_matches && commit.mismatch_rejected;
        let mut v = serde_json::json!({
            "live": true,
            "chain_id": chain_id,
            "called_daemon_builder_from_chain": true,
            "daemon_built": true,
            "deploy_on_daemon": true,
            "private_inference_deploy_on": true,
            "one_ict_process": true,
            "contract": commit.addr,
            "ics08_contract": suite.ics08.address().map(|a| a.to_string()).unwrap_or_default(),
            "escrow_contract": suite.escrow.address().map(|a| a.to_string()).unwrap_or_default(),
            "stored_matches_good": commit.oob_bid_matches,
            "tamper_rejected": tamper_rejected,
            "oob_bid_matches": commit.oob_bid_matches,
            "mismatch_rejected": commit.mismatch_rejected,
            "no_price_on_chain": commit.no_price_on_chain
        });
        let z = exercise_zap1(&suite, &attest_json, halo2.as_ref())?;
        let ics = exercise_ics08(&suite, &attest_json)?;
        let escrow = exercise_escrow(&suite)?;
        if let Some(obj) = v.as_object_mut() {
            obj.insert("zap1_stored".into(), serde_json::json!(z.stored));
            obj.insert("zap1_accepted".into(), serde_json::json!(z.accepted));
            obj.insert("zap1_matches".into(), serde_json::json!(z.matches));
            obj.insert(
                "zap1_tamper_rejected".into(),
                serde_json::json!(z.tamper_rejected),
            );
            obj.insert("zap1_contract".into(), serde_json::json!(z.addr));
            obj.insert("zap1_halo2_stored".into(), serde_json::json!(z.halo2_stored));
            obj.insert(
                "zap1_halo2_accepted".into(),
                serde_json::json!(z.halo2_accepted),
            );
            obj.insert(
                "zap1_halo2_tamper_rejected".into(),
                serde_json::json!(z.halo2_tamper_rejected),
            );
            obj.insert("zap1_halo2_zkid".into(), serde_json::json!(z.halo2_zkid));
            obj.insert("ics08_executed".into(), serde_json::json!(ics.executed));
            obj.insert("ics08_accepted".into(), serde_json::json!(ics.accepted));
            obj.insert(
                "ics08_tamper_rejected".into(),
                serde_json::json!(ics.tamper_rejected),
            );
            obj.insert("ics08_addr".into(), serde_json::json!(ics.addr));
            obj.insert(
                "escrow_grant_recorded".into(),
                serde_json::json!(escrow.grant_recorded),
            );
            obj.insert(
                "escrow_open_accrue_close".into(),
                serde_json::json!(escrow.open_accrue_close),
            );
            obj.insert(
                "escrow_earned_zat".into(),
                serde_json::json!(escrow.earned_zat),
            );
            obj.insert(
                "escrow_remainder_zat".into(),
                serde_json::json!(escrow.remainder_zat),
            );
            obj.insert("escrow_cell_id".into(), serde_json::json!(escrow.cell_id));
        }
        Ok::<_, String>(v.to_string())
    })
    .await
    .map_err(|e| format!("after daemon_builder: join Daemon deploy_on: {e}"))??;
    Ok(out)
}

async fn load_and_store_halo2(chain: &CosmosChain) -> Result<Option<Halo2Attest>, String> {
    let params = match std::env::var("PIR_HALO2_PARAMS") {
        Ok(p) if std::path::Path::new(&p).is_file() => p,
        _ => {
            if std::env::var("PIR_HALO2_REQUIRE").ok().as_deref() == Some("1") {
                return Err(
                    "PIR_HALO2_REQUIRE=1 but PIR_HALO2_PARAMS missing (host fail-closed)".into(),
                );
            }
            return Ok(None);
        }
    };
    let vk = std::env::var("PIR_HALO2_VK_BODY").unwrap_or_default();
    let proof_path = std::env::var("PIR_HALO2_PROOF").unwrap_or_default();
    let inst_path = std::env::var("PIR_HALO2_INSTANCES").unwrap_or_default();
    if !std::path::Path::new(&vk).is_file() {
        return Err("PIR_HALO2_PARAMS set but PIR_HALO2_VK_BODY is not a file".into());
    }
    if !std::path::Path::new(&proof_path).is_file() {
        return Err("PIR_HALO2_PARAMS set but PIR_HALO2_PROOF is not a file".into());
    }
    if !std::path::Path::new(&inst_path).is_file() {
        return Err("PIR_HALO2_PARAMS set but PIR_HALO2_INSTANCES is not a file".into());
    }
    let proof = std::fs::read(&proof_path).map_err(|e| format!("read halo2 proof: {e}"))?;
    let instances = std::fs::read(&inst_path).map_err(|e| format!("read halo2 instances: {e}"))?;
    if proof.is_empty() {
        return Err("empty halo2 proof".into());
    }
    if instances.len() != 128 {
        return Err(format!(
            "halo2 instances must be 128 bytes, got {}",
            instances.len()
        ));
    }
    let node = chain.primary_node().map_err(|e| e.to_string())?;
    node.copy_file_from_host(std::path::Path::new(&params), "/tmp/pir-params.bin")
        .await
        .map_err(|e| format!("copy halo2 params: {e}"))?;
    node.copy_file_from_host(std::path::Path::new(&vk), "/tmp/pir-vk_body.bin")
        .await
        .map_err(|e| format!("copy halo2 vk: {e}"))?;
    let j = broadcast_tx(
        chain,
        &[
            "tx",
            "wasm",
            "store-full-circuit",
            "/tmp/pir-params.bin",
            "/tmp/pir-vk_body.bin",
            "--k",
            "17",
            "--circuit-type",
            "0",
            "--curve-type",
            "0",
            "--from",
            "deployer",
        ],
    )
    .await
    .map_err(|e| format!("store-full-circuit: {e}"))?;
    let zkid = extract_zkid(&j).unwrap_or(1);
    Ok(Some(Halo2Attest {
        zkid,
        proof,
        instances,
    }))
}

async fn broadcast_tx(chain: &CosmosChain, args: &[&str]) -> Result<serde_json::Value, String> {
    let out = chain.chain_exec_tx(args).await.map_err(|e| e.to_string())?;
    if out.exit_code != 0 {
        return Err(format!(
            "exit {} {}",
            out.exit_code,
            out.stderr_str()
        ));
    }
    let j: serde_json::Value =
        serde_json::from_str(out.stdout_str().trim()).unwrap_or(serde_json::Value::Null);
    let hash = j["txhash"].as_str().unwrap_or("").to_string();
    if hash.is_empty() {
        return Err(format!("no txhash {}", out.stdout_str()));
    }
    wait_tx(chain, &hash).await
}

async fn wait_tx(chain: &CosmosChain, hash: &str) -> Result<serde_json::Value, String> {
    for _ in 0..40 {
        let _ = wait_for_blocks(chain, 1).await;
        let q = chain
            .chain_exec(&["query", "tx", hash, "--output", "json"])
            .await
            .map_err(|e| e.to_string())?;
        let s = q.stdout_str().trim().to_string();
        if s.is_empty() || s.contains("not found") {
            tokio::time::sleep(Duration::from_millis(400)).await;
            continue;
        }
        let j: serde_json::Value = serde_json::from_str(&s).map_err(|e| format!("{e}: {s}"))?;
        let code = j["code"].as_u64().unwrap_or(999);
        if code != 0 {
            return Err(format!(
                "code={code} {}",
                j["raw_log"].as_str().unwrap_or("")
            ));
        }
        return Ok(j);
    }
    Err(format!("timeout {hash}"))
}

fn extract_zkid(j: &serde_json::Value) -> Option<u64> {
    let logs = j.get("logs")?.as_array()?;
    for log in logs {
        let evs = log.get("events")?.as_array()?;
        for ev in evs {
            let ty = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if ty == "store_full_circuit" || ty == "store_circuit" {
                if let Some(attrs) = ev.get("attributes").and_then(|a| a.as_array()) {
                    for a in attrs {
                        let k = a.get("key").and_then(|x| x.as_str()).unwrap_or("");
                        if k == "zk_id" || k == "zkid" {
                            return a.get("value").and_then(|v| v.as_str())?.parse().ok();
                        }
                    }
                }
            }
        }
    }
    None
}
