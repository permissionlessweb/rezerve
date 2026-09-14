//! cw-orch suite for private-inference-rent on-chain contracts.
//!
//! `PrivateInference::deploy_on(chain, data)` uploads and instantiates:
//! - `cw-pir-commit` (ask/bid commitments)
//! - `cw-pir-escrow` (cell, accrue, close/dispute **grant + events only**; no BankMsg)
//! - `cw-zap1-ibcv2` (ZAP1 + IBC v2 packet attestation)
//! - `cw-ics08-wasm-zap1` (IBC v2 08-wasm client surface; not Crosslink)
//!
//! Addresses and code ids live in cw-orch native state (`load_from`), not a
//! side-car JSON helper.
//!
//! Live ict-rs: `daemon_builder_from_chain` + this `deploy_on` sequence on
//! Daemon is `pir-live-attach` (cw-orch 0.30 Daemon vs this crate's 0.24 Mock).

pub use cw_ics08_wasm_zap1::{
    AcceptedResp as Ics08AcceptedResp, CwIcs08WasmZap1Contract, ExecuteMsg as Ics08ExecuteMsg,
    InstantiateMsg as Ics08InstantiateMsg, QueryMsg as Ics08QueryMsg,
    Zap1ProofStepMsg as Ics08ProofStepMsg,
};
pub use cw_pir_commit::{
    CwPirCommitContract, ExecuteMsg as CommitExecuteMsg, InstantiateMsg as CommitInstantiateMsg,
    QueryMsg as CommitQueryMsg,
};
pub use cw_pir_escrow::{
    CwPirEscrowContract, ExecuteMsg as EscrowExecuteMsg, GrantResp, InstantiateMsg as EscrowInstantiateMsg,
    Party as EscrowPartyMsg, QueryMsg as EscrowQueryMsg,
};
pub use cw_zap1_ibcv2::{
    CwZap1Ibcv2Contract, ExecuteMsg as Zap1ExecuteMsg, InstantiateMsg as Zap1InstantiateMsg,
    QueryMsg as Zap1QueryMsg,
};

use cw_orch::contract::Deploy;
use cw_orch::contract::interface_traits::ContractInstance;
use cw_orch::environment::CwEnv;
use cw_orch::prelude::{
    CwOrchError, CwOrchExecute, CwOrchInstantiate, CwOrchQuery, CwOrchUpload, IndexResponse,
};

/// Extra instantiate inputs. Empty — all three contracts take `{}`.
#[derive(Clone, Debug, Default)]
pub struct PrivateInferenceDeployData;

/// On-chain PIR suite. Same type on Mock and Daemon.
pub struct PrivateInference<Chain: CwEnv> {
    pub commit: CwPirCommitContract<Chain>,
    pub escrow: CwPirEscrowContract<Chain>,
    pub zap1_ibcv2: CwZap1Ibcv2Contract<Chain>,
    pub ics08_zap1: CwIcs08WasmZap1Contract<Chain>,
}

impl<Chain: CwEnv> PrivateInference<Chain> {
    pub fn new(chain: Chain) -> Self {
        Self {
            commit: CwPirCommitContract::new(chain.clone()),
            escrow: CwPirEscrowContract::new(chain.clone()),
            zap1_ibcv2: CwZap1Ibcv2Contract::new(chain.clone()),
            ics08_zap1: CwIcs08WasmZap1Contract::new(chain),
        }
    }

    /// Open + accrue + close on the escrow contract. Close records a grant
    /// (no BankMsg). `deposit_zat` is Zcash-note accounting; OpenCell rejects
    /// bank funds. Grant must exist before a resolver may sign.
    pub fn escrow_open_accrue_close(
        &self,
        bid_commitment: String,
        tenant: String,
        provider: String,
        resolver: String,
        deposit_zat: u64,
        accrual_commitment: String,
        open_header_hash: String,
        close_header_hash: String,
        closer: EscrowPartyMsg,
    ) -> Result<(String, GrantResp), CwOrchError> {
        let res = self.escrow.execute(
            &EscrowExecuteMsg::OpenCell {
                bid_commitment,
                tenant,
                provider,
                resolver,
                deposit_zat,
            },
            Some(&[]),
        )?;
        let cell_id = res
            .event_attr_value("wasm", "cell_id")
            .or_else(|_| res.event_attr_value("wasm-open_cell", "cell_id"))
            .map_err(|e| CwOrchError::StdErr(e.to_string()))?;
        self.escrow.execute(
            &EscrowExecuteMsg::Accrue {
                cell_id: cell_id.clone(),
                commitment: accrual_commitment,
                open_header_hash,
                close_header_hash,
            },
            Some(&[]),
        )?;
        self.escrow.execute(
            &EscrowExecuteMsg::Close {
                cell_id: cell_id.clone(),
                party: closer,
            },
            Some(&[]),
        )?;
        let grant: GrantResp = self.escrow.query(&EscrowQueryMsg::Grant {
            cell_id: cell_id.clone(),
        })?;
        Ok((cell_id, grant))
    }
}

impl<Chain: CwEnv> Deploy<Chain> for PrivateInference<Chain> {
    type Error = CwOrchError;
    type DeployData = PrivateInferenceDeployData;

    fn store_on(chain: Chain) -> Result<Self, Self::Error> {
        let suite = Self::new(chain);
        suite.commit.upload()?;
        suite.escrow.upload()?;
        suite.zap1_ibcv2.upload()?;
        suite.ics08_zap1.upload()?;
        Ok(suite)
    }

    fn deploy_on(chain: Chain, _data: Self::DeployData) -> Result<Self, Self::Error> {
        let suite = Self::store_on(chain)?;
        suite
            .commit
            .instantiate(&CommitInstantiateMsg {}, None, Some(&[]))?;
        suite
            .escrow
            .instantiate(&EscrowInstantiateMsg {}, None, Some(&[]))?;
        suite
            .zap1_ibcv2
            .instantiate(&Zap1InstantiateMsg {}, None, Some(&[]))?;
        suite
            .ics08_zap1
            .instantiate(&Ics08InstantiateMsg {}, None, Some(&[]))?;
        Ok(suite)
    }

    fn deployed_state_file_path() -> Option<String> {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("state.json");
        Some(p.display().to_string())
    }

    fn get_contracts_mut(&mut self) -> Vec<Box<&mut dyn ContractInstance<Chain>>> {
        vec![
            Box::new(&mut self.commit),
            Box::new(&mut self.escrow),
            Box::new(&mut self.zap1_ibcv2),
            Box::new(&mut self.ics08_zap1),
        ]
    }

    fn load_from(chain: Chain) -> Result<Self, Self::Error> {
        Ok(Self::new(chain))
    }
}
