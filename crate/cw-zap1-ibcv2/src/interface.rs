//! cw-orch interface for the ZAP1 IBC v2 attestation module.

use cw_orch::{interface, prelude::*};

use crate::{ExecuteMsg, InstantiateMsg, QueryMsg};

pub const CONTRACT_ID: &str = "cw-zap1-ibcv2";

#[interface(InstantiateMsg, ExecuteMsg, QueryMsg, Empty, id = CONTRACT_ID)]
pub struct CwZap1Ibcv2Contract;

impl<Chain> Uploadable for CwZap1Ibcv2Contract<Chain> {
    fn wasm(_chain: &ChainInfoOwned) -> WasmPath {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for rel in [
            "artifacts/cw_zap1_ibcv2.wasm",
            "target/wasm32-unknown-unknown/release/cw_zap1_ibcv2.wasm",
        ] {
            let p = root.join(rel);
            if p.is_file() {
                return WasmPath::new(p).expect("cw-zap1-ibcv2 wasm");
            }
        }
        artifacts_dir_from_workspace!()
            .find_wasm_path("cw_zap1_ibcv2")
            .unwrap_or_else(|_| {
                WasmPath::new(root.join("Cargo.toml")).expect("crate root")
            })
    }

    fn wrapper() -> Box<dyn MockContract<Empty>> {
        Box::new(ContractWrapper::new_with_empty(
            crate::execute,
            crate::instantiate,
            crate::query,
        ))
    }
}
