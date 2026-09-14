//! cw-orch interface for `cw-pir-commit`. Not compiled into the wasm.

use cw_orch::{interface, prelude::*};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

pub const CONTRACT_ID: &str = "cw-pir-commit";

#[interface(InstantiateMsg, ExecuteMsg, QueryMsg, Empty, id = CONTRACT_ID)]
pub struct CwPirCommitContract;

impl<Chain> Uploadable for CwPirCommitContract<Chain> {
    fn wasm(_chain: &ChainInfoOwned) -> WasmPath {
        wasm_path("cw_pir_commit")
    }

    fn wrapper() -> Box<dyn MockContract<Empty>> {
        Box::new(ContractWrapper::new_with_empty(
            crate::execute,
            crate::instantiate,
            crate::query,
        ))
    }
}

fn wasm_path(stem: &str) -> WasmPath {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in [
        format!("artifacts/{stem}.wasm"),
        format!("target/wasm32-unknown-unknown/release/{stem}.wasm"),
    ] {
        let p = root.join(&rel);
        if p.is_file() {
            return WasmPath::new(p).expect("cw-pir-commit wasm");
        }
    }
    artifacts_dir_from_workspace!()
        .find_wasm_path(stem)
        .unwrap_or_else(|_| {
            WasmPath::new(root.join(format!("artifacts/{stem}.wasm")))
                .unwrap_or_else(|_| {
                    WasmPath::new(root.join("Cargo.toml")).expect("crate root")
                })
        })
}
