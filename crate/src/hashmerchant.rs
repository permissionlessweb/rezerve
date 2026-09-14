//! Local deposit transcript (domain-separated hash). Not a Zcash inclusion proof.

use crate::tagged_hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DepositError {
    #[error("empty state root")]
    EmptyRoot,
    #[error("empty deposit proof")]
    EmptyProof,
    #[error("state root / proof mismatch")]
    Mismatch,
    #[error("frost group binding mismatch")]
    FrostBinding,
    #[error("zero amount")]
    ZeroAmount,
    #[error("note already credited")]
    Replay,
    #[error("layered pool requires a verified quorum")]
    QuorumRequired,
    #[error("sim transcript (prove_for_test) rejected on product ingest")]
    SimTranscript,
}

/// Local transcript binding root, note, amount, and pool group id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositAttestation {
    /// Local transcript root. Not an Orchard/Sapling/Zcash tree root.
    pub transcript_root: [u8; 32],
    pub deposit_note_commitment: [u8; 32],
    pub amount_zat: u64,
    pub frost_group_id: [u8; 32],
    pub inclusion_proof: Vec<u8>,
}

impl DepositAttestation {
    /// Local transcript mint. Not inclusion; not on the product ingest path.
    #[cfg(feature = "sim")]
    pub fn prove_for_test(
        transcript_root: [u8; 32],
        deposit_note_commitment: [u8; 32],
        amount_zat: u64,
        frost_group_id: [u8; 32],
    ) -> Self {
        let inclusion_proof = tagged_hash(
            b"hashmerchant-deposit-v1",
            &[
                &transcript_root,
                &deposit_note_commitment,
                &amount_zat.to_le_bytes(),
                &frost_group_id,
            ],
        )
        .to_vec();
        Self {
            transcript_root,
            deposit_note_commitment,
            amount_zat,
            frost_group_id,
            inclusion_proof,
        }
    }

    /// Sim alias for `prove_for_test`. Feature `sim` (default).
    #[cfg(feature = "sim")]
    pub fn prove(
        transcript_root: [u8; 32],
        deposit_note_commitment: [u8; 32],
        amount_zat: u64,
        frost_group_id: [u8; 32],
    ) -> Self {
        Self::prove_for_test(
            transcript_root,
            deposit_note_commitment,
            amount_zat,
            frost_group_id,
        )
    }

    pub fn verify(&self, expected_frost_group: &[u8; 32]) -> Result<(), DepositError> {
        if self.amount_zat == 0 {
            return Err(DepositError::ZeroAmount);
        }
        if self.transcript_root == [0u8; 32] {
            return Err(DepositError::EmptyRoot);
        }
        if self.inclusion_proof.is_empty() {
            return Err(DepositError::EmptyProof);
        }
        if &self.frost_group_id != expected_frost_group {
            return Err(DepositError::FrostBinding);
        }
        let expected = tagged_hash(
            b"hashmerchant-deposit-v1",
            &[
                &self.transcript_root,
                &self.deposit_note_commitment,
                &self.amount_zat.to_le_bytes(),
                &self.frost_group_id,
            ],
        );
        if self.inclusion_proof.as_slice() != expected.as_slice() {
            return Err(DepositError::Mismatch);
        }
        Ok(())
    }
}

/// Accepts a well-formed local transcript for this pool group.
pub struct HashmerchantIngress {
    pub frost_group_id: [u8; 32],
}

impl HashmerchantIngress {
    pub fn new(frost_group_id: [u8; 32]) -> Self {
        Self { frost_group_id }
    }

    pub fn accept(&self, att: &DepositAttestation) -> Result<(), DepositError> {
        att.verify(&self.frost_group_id)
    }
}
