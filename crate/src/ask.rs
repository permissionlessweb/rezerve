//! Public manifest / resource ask (the only plaintext market surface).

use crate::tagged_hash;
use serde::{Deserialize, Serialize};

/// Compute resources requested on the public Akash-shaped ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceAsk {
    pub cpu_milli: u32,
    pub memory_mib: u32,
    pub storage_mib: u32,
    pub gpu_units: u32,
}

/// Tenant-posted public ask: SDL/manifest + resources. No bid prices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAsk {
    pub ask_id: String,
    pub tenant_label: String,
    pub manifest_sdl: String,
    pub resources: ResourceAsk,
    pub inference_profile: String,
}

impl PublicAsk {
    pub fn new(
        ask_id: impl Into<String>,
        tenant_label: impl Into<String>,
        manifest_sdl: impl Into<String>,
        resources: ResourceAsk,
        inference_profile: impl Into<String>,
    ) -> Self {
        Self {
            ask_id: ask_id.into(),
            tenant_label: tenant_label.into(),
            manifest_sdl: manifest_sdl.into(),
            resources,
            inference_profile: inference_profile.into(),
        }
    }

    /// Commitment to the public ask (posted on-chain as the ask id binding).
    pub fn ask_commitment(&self) -> [u8; 32] {
        tagged_hash(
            b"private-rent-ask-v1",
            &[
                self.ask_id.as_bytes(),
                self.tenant_label.as_bytes(),
                self.manifest_sdl.as_bytes(),
                &self.resources.cpu_milli.to_le_bytes(),
                &self.resources.memory_mib.to_le_bytes(),
                &self.resources.storage_mib.to_le_bytes(),
                &self.resources.gpu_units.to_le_bytes(),
                self.inference_profile.as_bytes(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), crate::workflow::WorkflowError> {
        if self.ask_id.is_empty() || self.manifest_sdl.is_empty() {
            return Err(crate::workflow::WorkflowError::InvalidAsk);
        }
        if self.resources.cpu_milli == 0 || self.resources.memory_mib == 0 {
            return Err(crate::workflow::WorkflowError::InvalidAsk);
        }
        Ok(())
    }
}
