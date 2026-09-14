//! Offline scenario wrapper around the shipped workflow.
//!
//! This is not a live ict-rs or cw-orchestrator run. It records harness *names*
//! o-line uses so a later feature-gated spawn can attach. RAM publish is
//! [`crate::cw_orch::publish_commitments`]; live attach is fail-closed.

use crate::cw_orch::CwOrchError;
use crate::workflow::{PrivateComputeWorkflow, WorkflowReceipt};
use serde::{Deserialize, Serialize};

pub const ICT_HARNESS_MODULES: &[&str] = &[
    "o_line_sdl::testing::ict_network",
    "o_line_sdl::testing::ict_terp",
    "o_line_sdl::interface::env::OLineTestEnv",
    "ict_rs_cw_orch::daemon_builder_from_chain",
    "pir_cw_orch::PrivateInference::deploy_on",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IctCwOrchScenario {
    pub name: String,
    pub harness: Vec<String>,
    pub receipt: WorkflowReceipt,
    /// Live Daemon attach. `from_workflow` always leaves this `false`.
    #[serde(default)]
    pub live: bool,
}

impl IctCwOrchScenario {
    /// Offline scenario only (`live: false`).
    pub fn from_workflow(name: impl Into<String>, wf: &PrivateComputeWorkflow) -> Self {
        Self {
            name: name.into(),
            harness: ICT_HARNESS_MODULES.iter().map(|s| (*s).to_string()).collect(),
            receipt: wf.receipt(),
            live: false,
        }
    }

    pub fn wraps_shipped_receipt(&self) -> bool {
        !self.receipt.ask_id.is_empty() && self.harness.len() == ICT_HARNESS_MODULES.len()
    }

    /// Always attempts live attach. Offline `from_workflow` is not an attach success.
    pub fn attach_or_fail_live(&self) -> Result<(), CwOrchError> {
        let _ = crate::cw_orch::try_live_attach()?;
        Ok(())
    }
}
