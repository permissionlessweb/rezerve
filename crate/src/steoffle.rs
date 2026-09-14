//! Local SHA-256 seat transcript. Not private MPC. Stoffel CLI is [`crate::stoffel`].

use crate::dregg::{FrostSignerInstance, SignerInstanceError};
use crate::tagged_hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SteoffleError {
    #[error("signer instance: {0}")]
    Signer(#[from] SignerInstanceError),
    #[error("attestation mismatch")]
    AttestationMismatch,
    #[error("tampered commitments")]
    TamperedCommitments,
    #[error("unknown signer")]
    UnknownSigner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteoffleAttestation {
    pub signer_id: [u8; 32],
    pub commitment_digest: [u8; 32],
    pub runtime_proof: [u8; 32],
    /// SHA-256 seat transcript. Not an MPC attestation.
    pub seat_transcript: [u8; 32],
}

pub struct SteoffleMpc;

impl SteoffleMpc {
    pub fn attest(signer: &FrostSignerInstance) -> Result<SteoffleAttestation, SteoffleError> {
        signer.runtime.verify()?;
        let commitment_digest = signer.commitment_digest();
        let seat_transcript = tagged_hash(
            b"steoffle-seat-v1",
            &[
                &signer.signer_id,
                &commitment_digest,
                &signer.runtime.proof,
            ],
        );
        Ok(SteoffleAttestation {
            signer_id: signer.signer_id,
            commitment_digest,
            runtime_proof: signer.runtime.proof,
            seat_transcript,
        })
    }

    pub fn verify(
        signer: &FrostSignerInstance,
        att: &SteoffleAttestation,
    ) -> Result<(), SteoffleError> {
        if att.signer_id != signer.signer_id || signer.runtime.signer_id != signer.signer_id {
            return Err(SteoffleError::UnknownSigner);
        }
        signer.runtime.verify()?;
        let digest = signer.commitment_digest();
        if digest != att.commitment_digest {
            return Err(SteoffleError::TamperedCommitments);
        }
        let expected = Self::attest(signer)?;
        if expected.seat_transcript != att.seat_transcript
            || expected.runtime_proof != att.runtime_proof
        {
            return Err(SteoffleError::AttestationMismatch);
        }
        Ok(())
    }
}
