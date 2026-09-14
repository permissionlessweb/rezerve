//! Local signer identity + SHA-256 runtime-proof hash.
//! Not a dregg kernel, not a TEE, not an MPC runtime.

use crate::tagged_hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SignerInstanceError {
    #[error("missing runtime proof")]
    MissingRuntimeProof,
    #[error("runtime proof invalid")]
    InvalidRuntimeProof,
    #[error("empty seat commitments")]
    EmptyCommitments,
}

/// Local hash over signer + instance ids. Not a dregg / TEE attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRuntimeProof {
    pub signer_id: [u8; 32],
    pub instance_id: [u8; 32],
    pub proof: [u8; 32],
}

impl LocalRuntimeProof {
    pub fn prove(signer_id: [u8; 32], instance_id: [u8; 32]) -> Self {
        let proof = tagged_hash(b"seat-runtime-v1", &[&signer_id, &instance_id]);
        Self {
            signer_id,
            instance_id,
            proof,
        }
    }

    pub fn verify(&self) -> Result<(), SignerInstanceError> {
        if self.proof == [0u8; 32] {
            return Err(SignerInstanceError::MissingRuntimeProof);
        }
        let expected = tagged_hash(b"seat-runtime-v1", &[&self.signer_id, &self.instance_id]);
        if expected != self.proof {
            return Err(SignerInstanceError::InvalidRuntimeProof);
        }
        Ok(())
    }
}

/// One in-process FROST signer label + local commitment hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSignerInstance {
    pub signer_id: [u8; 32],
    pub instance_id: [u8; 32],
    pub seat_commitments: Vec<[u8; 32]>,
    pub runtime: LocalRuntimeProof,
}

impl FrostSignerInstance {
    pub fn new(
        signer_id: [u8; 32],
        instance_id: [u8; 32],
        seat_commitments: Vec<[u8; 32]>,
    ) -> Result<Self, SignerInstanceError> {
        if seat_commitments.is_empty() {
            return Err(SignerInstanceError::EmptyCommitments);
        }
        let runtime = LocalRuntimeProof::prove(signer_id, instance_id);
        Ok(Self {
            signer_id,
            instance_id,
            seat_commitments,
            runtime,
        })
    }

    pub fn commitment_digest(&self) -> [u8; 32] {
        let mut parts: Vec<&[u8]> = vec![&self.signer_id];
        for c in &self.seat_commitments {
            parts.push(c.as_slice());
        }
        tagged_hash(b"seat-commitments-v1", &parts)
    }
}
