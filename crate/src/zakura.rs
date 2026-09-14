//! Native local Zakura node — same contract as ict-rs `chain::zakura`
//! (`feature = "zakura"` on the lab host: `spawn_zakura_local`, `ZAKURAD_BIN`,
//! `ZAKURA_RPC`, debian:trixie-slim bind-mount of a Linux `zakurad`).
//!
//! This crate does not depend on the full ict-rs library (local checkout
//! is only `ict-rs-cw-orch`). The spawn path here is that dedicated support
//! so experiments do not need compose-only attach.
//!
//! Order: reuse `ZAKURA_RPC` if ready → `ZAKURAD_BIN` + Docker spawn →
//! opt-in compose (`PIR_ZAKURA_SPAWN=1`). Skip, do not panic, if Docker/bin
//! missing. macOS Mach-O `zakurad` cannot run in Debian; use a Linux binary.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Default JSON-RPC port (ict-rs `ZAKURA_RPC_PORT`).
pub const ZAKURA_RPC_PORT: u16 = 18232;
pub const ZAKURA_P2P_PORT: u16 = 18233;
pub const ZAKURA_METRICS_PORT: u16 = 19901;

pub const DEST_BINDING_DOMAIN: &str = "terp-dest-binding-v0";
/// Same deterministic miner as zakurad tests (secp256k1 sk=1). No zcashd.
pub const REGTEST_MINER_DEST: &str = "tmLPctKo9j49rtCSKpwEBpLBeykiTGomGQs";
pub const REGTEST_MINER_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
pub const REGTEST_MINER_OWNER_BINDING_HEX: &str =
    "8385e7048941893ade27cf16f1d4cd9095c5f709b4b42a6a21ce076cbee0dc27";

/// Host-built Linux `zakurad` (ict-rs `ENV_ZAKURAD_BIN`).
pub const ENV_ZAKURAD_BIN: &str = "ZAKURAD_BIN";
/// RPC base URL override (ict-rs `ENV_ZAKURA_RPC`).
pub const ENV_ZAKURA_RPC: &str = "ZAKURA_RPC";

pub const ZAKURA_BASE_IMAGE: &str = "debian:trixie-slim";
pub const CONTAINER_ZAKURAD_PATH: &str = "/usr/local/bin/zakurad";
pub const CONTAINER_CONFIG_PATH: &str = "/etc/zakura/node-corridor.toml";
pub const NATIVE_CONTAINER_NAME: &str = "pir-zakura-local";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ZakuraError {
    #[error("zakura rpc not configured")]
    Missing,
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("spawn: {0}")]
    Spawn(String),
}

#[derive(Debug, Clone)]
pub struct ZakuraNodeConfig {
    pub zakurad_bin: PathBuf,
    pub rpc_host_port: u16,
    pub test_name: String,
    pub dest_display: String,
    pub ready_timeout_secs: u64,
    pub reuse_if_ready: bool,
}

impl Default for ZakuraNodeConfig {
    fn default() -> Self {
        Self {
            zakurad_bin: resolve_zakurad_bin().unwrap_or_else(|_| PathBuf::from("/nonexistent/zakurad")),
            rpc_host_port: ZAKURA_RPC_PORT,
            test_name: "zakura-local".into(),
            dest_display: REGTEST_MINER_DEST.into(),
            ready_timeout_secs: 60,
            reuse_if_ready: true,
        }
    }
}

impl ZakuraNodeConfig {
    pub fn corridor(zakurad_bin: impl Into<PathBuf>) -> Self {
        Self {
            zakurad_bin: zakurad_bin.into(),
            ..Self::default()
        }
    }

    pub fn from_env() -> Result<Self, ZakuraError> {
        Ok(Self::corridor(resolve_zakurad_bin()?))
    }

    pub fn rpc_url(&self) -> String {
        std::env::var(ENV_ZAKURA_RPC).unwrap_or_else(|_| {
            format!("http://127.0.0.1:{}", self.rpc_host_port)
        })
    }
}

/// Handle after attach or native Docker spawn (ict-rs `ZakuraNode`).
#[derive(Debug, Clone)]
pub struct ZakuraNode {
    pub rpc_url: String,
    pub dest_display: String,
    pub owner_binding_hex: String,
    pub reused_existing: bool,
    pub container_name: Option<String>,
}

impl ZakuraNode {
    pub fn as_regtest(&self) -> ZakuraRegtest {
        ZakuraRegtest {
            rpc: self.rpc_url.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZakuraRegtest {
    pub rpc: String,
}

impl ZakuraRegtest {
    pub fn discover() -> Option<Self> {
        std::env::var(ENV_ZAKURA_RPC)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|rpc| Self { rpc })
    }

    pub fn sibling_repo() -> Option<PathBuf> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../zakura");
        p.is_dir().then_some(p.canonicalize().unwrap_or(p))
    }

    pub fn compose_file() -> Option<PathBuf> {
        let root = Self::sibling_repo()?;
        let f = root.join("docker/docker-compose.zakura-regtest-e2e.yml");
        f.is_file().then_some(f)
    }

    /// Attach if RPC ready; else ict-rs-style spawn; else compose if `PIR_ZAKURA_SPAWN=1`.
    pub fn attach_or_spawn() -> Result<Self, ZakuraError> {
        spawn_zakura_local(ZakuraNodeConfig::from_env().unwrap_or_default())
            .map(|n| n.as_regtest())
            .or_else(|_| Self::spawn())
    }

    /// Opt-in docker compose up. Prefer [`spawn_zakura_local`] when `ZAKURAD_BIN` is set.
    pub fn spawn() -> Result<Self, ZakuraError> {
        if let Some(d) = Self::discover() {
            if d.getblockchaininfo().is_ok() {
                return Ok(d);
            }
        }
        if std::env::var("PIR_ZAKURA_SPAWN").ok().as_deref() != Some("1") {
            return Err(ZakuraError::Missing);
        }
        let compose = Self::compose_file().ok_or(ZakuraError::Missing)?;
        let status = Command::new("docker")
            .args(["compose", "-f"])
            .arg(&compose)
            .args(["up", "-d"])
            .status()
            .map_err(|e| ZakuraError::Spawn(e.to_string()))?;
        if !status.success() {
            return Err(ZakuraError::Spawn(format!("compose exit {status}")));
        }
        Ok(Self {
            rpc: format!("http://127.0.0.1:{ZAKURA_RPC_PORT}"),
        })
    }

    pub fn getblockchaininfo(&self) -> Result<Value, ZakuraError> {
        rpc_getblockchaininfo(&self.rpc)
    }

    pub fn commitment_tree_root(&self) -> Result<Option<String>, ZakuraError> {
        let v = self.getblockchaininfo()?;
        let r = v.get("result").cloned().unwrap_or(v);
        for key in [
            "ironwoodTreeRoot",
            "finalIronwoodRoot",
            "saplingTreeRoot",
            "finalSaplingRoot",
            "orchardTreeRoot",
        ] {
            if let Some(s) = r.get(key).and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    return Ok(Some(s.to_string()));
                }
            }
        }
        if let Some(s) = r.get("bestblockhash").and_then(|x| x.as_str()) {
            return Ok(Some(s.to_string()));
        }
        Ok(None)
    }
}

pub fn resolve_zakurad_bin() -> Result<PathBuf, ZakuraError> {
    if let Ok(p) = std::env::var(ENV_ZAKURAD_BIN) {
        let pb = PathBuf::from(p.trim());
        if pb.is_file() {
            return Ok(pb);
        }
        return Err(ZakuraError::Spawn(format!(
            "{ENV_ZAKURAD_BIN}={pb:?} is not a file (need Linux zakurad for Docker)"
        )));
    }
    for rel in [
        "../zakura/target/zakura-regtest-e2e-linux/zakurad",
        "../zakura/target/debug/zakurad",
        "../zakura/target/release/zakurad",
        "../../zakura/target/debug/zakurad",
    ] {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        if p.is_file() {
            return Ok(p);
        }
    }
    Err(ZakuraError::Missing)
}

/// Native ict-rs-style lab: reuse RPC, else spawn `zakurad` in debian:trixie-slim.
///
/// Default: skip-friendly (`Missing` if no bin/Docker).
/// `PIR_ZAKURA_LAB=1` is fail-closed (do not silently skip).
pub fn lab_spawn() -> Result<ZakuraNode, ZakuraError> {
    let cfg = match ZakuraNodeConfig::from_env() {
        Ok(c) => c,
        Err(_) => ZakuraNodeConfig::default(),
    };
    spawn_zakura_local(cfg)
}

pub fn owner_binding_from_dest_display(dest_display: &str) -> String {
    let preimage = format!("{DEST_BINDING_DOMAIN}|{}", dest_display.trim());
    hex::encode(Sha256::digest(preimage.as_bytes()))
}

/// ict-rs corridor TOML (regtest only). NU6.3 at height 2 so Ironwood v6
/// notes are the native shielded pool (not Canopy/Sapling, not Orchard).
pub fn corridor_node_toml() -> String {
    format!(
        r#"# Generated by private-inference-rent native zakura (ict-rs feature=zakura).
[network]
network = "Regtest"
listen_addr = "0.0.0.0:{ZAKURA_P2P_PORT}"
p2p_stack = "legacy"
cache_dir = false
initial_testnet_peers = []
max_connections_per_ip = 4

[network.testnet_parameters.activation_heights]
NU5 = 1
NU6 = 1
"NU6.1" = 2
"NU6.2" = 2
"NU6.3" = 2

# Height 1 (NU6) funds the lockbox; height 2 (NU6.1 + Ironwood) disburses it.
[[network.testnet_parameters.funding_streams]]
height_range = {{ start = 1, end = 2 }}
recipients = [{{ receiver = "Deferred", numerator = 1 }}]

[[network.testnet_parameters.lockbox_disbursements]]
address = "t2RnBRiqrN1nW4ecZs1Fj3WWjNdnSs4kiX8"
amount = 6250000

[state]
ephemeral = true

[rpc]
listen_addr = "0.0.0.0:{ZAKURA_RPC_PORT}"
enable_cookie_auth = false

[metrics]
endpoint_addr = "0.0.0.0:{ZAKURA_METRICS_PORT}"

[mining]
internal_miner = false
miner_address = "{REGTEST_MINER_DEST}"

[tracing]
filter = "info"
"#
    )
}

/// True when `getblockchaininfo.upgrades` lists NU6.3 (Ironwood).
pub fn nu6_3_configured(rpc: &str) -> bool {
    let Ok(v) = rpc_getblockchaininfo(rpc) else {
        return false;
    };
    let r = v.get("result").cloned().unwrap_or(v);
    let Some(up) = r.get("upgrades").and_then(|u| u.as_object()) else {
        return false;
    };
    up.values().any(|val| {
        val.get("name")
            .and_then(|n| n.as_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("NU6.3") || n.eq_ignore_ascii_case("Nu6_3"))
    })
}

fn docker_ok() -> bool {
    Command::new("docker")
        .args(["info"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn rpc_getblockchaininfo(rpc: &str) -> Result<Value, ZakuraError> {
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "pir",
        "method": "getblockchaininfo",
        "params": []
    });
    let out = Command::new("curl")
        .args(["-sS", "-X", "POST", "-H", "content-type: text/plain", "--data"])
        .arg(body.to_string())
        .arg(rpc)
        .output()
        .map_err(|e| ZakuraError::Rpc(e.to_string()))?;
    if !out.status.success() {
        return Err(ZakuraError::Rpc(String::from_utf8_lossy(&out.stderr).into()));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| ZakuraError::Rpc(e.to_string()))
}

fn rpc_ready(rpc: &str) -> bool {
    rpc_getblockchaininfo(rpc).is_ok()
}

/// ict-rs `spawn_zakura_local`: reuse ready RPC or bind-mount `zakurad` into debian:trixie-slim.
pub fn spawn_zakura_local(config: ZakuraNodeConfig) -> Result<ZakuraNode, ZakuraError> {
    let rpc_url = config.rpc_url();
    let dest = config.dest_display.clone();
    let binding = owner_binding_from_dest_display(&dest);

    if config.reuse_if_ready && rpc_ready(&rpc_url) {
        let tip = rpc_getblockchaininfo(&rpc_url)
            .ok()
            .and_then(|v| {
                let r = v.get("result").cloned().unwrap_or(v);
                r.get("blocks")
                    .and_then(|b| b.as_u64())
                    .or_else(|| r.get("blocks").and_then(|b| b.as_i64()).map(|i| i as u64))
            })
            .unwrap_or(0);
        // Need 100 mature coinbases and an Ironwood-capable tip.
        if nu6_3_configured(&rpc_url) && tip >= 101 {
            return Ok(ZakuraNode {
                rpc_url,
                dest_display: dest,
                owner_binding_hex: binding,
                reused_existing: true,
                container_name: None,
            });
        }
        // Stale Canopy/Sapling lab, or genesis-only node missing lockbox config.
        let _ = Command::new("docker")
            .args(["rm", "-f", NATIVE_CONTAINER_NAME])
            .status();
    }

    if !config.zakurad_bin.is_file() {
        return Err(ZakuraError::Missing);
    }
    if !docker_ok() {
        return Err(ZakuraError::Spawn("docker not available".into()));
    }

    let cfg_dir = std::env::temp_dir().join("pir-zakura");
    std::fs::create_dir_all(&cfg_dir).map_err(|e| ZakuraError::Spawn(e.to_string()))?;
    let cfg_host = cfg_dir.join("node-corridor.toml");
    std::fs::write(&cfg_host, corridor_node_toml()).map_err(|e| ZakuraError::Spawn(e.to_string()))?;

    let bin = config
        .zakurad_bin
        .canonicalize()
        .unwrap_or(config.zakurad_bin.clone());
    let cfg_abs = cfg_host.canonicalize().unwrap_or(cfg_host);

    let _ = Command::new("docker")
        .args(["rm", "-f", NATIVE_CONTAINER_NAME])
        .status();

    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            NATIVE_CONTAINER_NAME,
            "-p",
            &format!("{}:{}", config.rpc_host_port, ZAKURA_RPC_PORT),
            "-p",
            &format!("{ZAKURA_P2P_PORT}:{ZAKURA_P2P_PORT}"),
            "-v",
            &format!("{}:{CONTAINER_ZAKURAD_PATH}:ro", bin.display()),
            "-v",
            &format!("{}:{CONTAINER_CONFIG_PATH}:ro", cfg_abs.display()),
            "--label",
            "ict.feature=zakura",
            "--label",
            "ict.sidecar=zakura",
            "--label",
            &format!("ict.test={}", config.test_name),
            ZAKURA_BASE_IMAGE,
            CONTAINER_ZAKURAD_PATH,
            "--config",
            CONTAINER_CONFIG_PATH,
            "start",
        ])
        .status()
        .map_err(|e| ZakuraError::Spawn(e.to_string()))?;
    if !status.success() {
        return Err(ZakuraError::Spawn(format!("docker run exit {status}")));
    }

    let deadline = Instant::now() + Duration::from_secs(config.ready_timeout_secs.max(1));
    while Instant::now() < deadline {
        if rpc_ready(&rpc_url) {
            return Ok(ZakuraNode {
                rpc_url,
                dest_display: dest,
                owner_binding_hex: binding,
                reused_existing: false,
                container_name: Some(NATIVE_CONTAINER_NAME.into()),
            });
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(ZakuraError::Spawn(format!("timeout waiting for {rpc_url}")))
}

/// Unified L0 seams crate (`terp-seams`), not Juno Astroport and not the retired shim dir.
pub fn seam_private_dex_dir() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../terp-rs/crates/terp-seams");
    Path::new(&p).is_dir().then_some(p)
}

#[deprecated(note = "use seam_private_dex_dir — not crates/dex Astroport")]
pub fn dex_integration_dir() -> Option<PathBuf> {
    seam_private_dex_dir()
}
