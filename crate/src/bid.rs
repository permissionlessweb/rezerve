//! OOB bids: ChaCha20-Poly1305. Ciphertext stays off-chain.

use crate::tagged_hash;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BidError {
    #[error("empty bid payload")]
    Empty,
    #[error("serialize failed")]
    Serialize,
    #[error("decryption failed")]
    Decrypt,
    #[error("authentication failed")]
    Auth,
    #[error("commitment mismatch")]
    CommitmentMismatch,
    #[error("rng failed")]
    Rng,
}

/// Off-chain bid contents. Never serialized on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextBid {
    pub ask_id: String,
    pub bidder_identity: String,
    pub price_uakt: u64,
    pub provider_endpoint: String,
}

/// Sealed envelope: AEAD ciphertext + tag (tag also mirrored in `mac`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBidEnvelope {
    pub ask_id: String,
    pub nonce: [u8; 16],
    pub ciphertext: Vec<u8>,
    pub mac: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BidCommitment {
    pub ask_id: String,
    pub commitment: [u8; 32],
}

impl EncryptedBidEnvelope {
    pub fn seal(bid: &PlaintextBid, session_key: &[u8; 32]) -> Result<Self, BidError> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| BidError::Rng)?;
        Self::seal_with_nonce(bid, session_key, nonce)
    }

    pub fn seal_with_nonce(
        bid: &PlaintextBid,
        session_key: &[u8; 32],
        nonce: [u8; 16],
    ) -> Result<Self, BidError> {
        if bid.bidder_identity.is_empty() || bid.price_uakt == 0 {
            return Err(BidError::Empty);
        }
        let json = serde_json::to_vec(bid).map_err(|_| BidError::Serialize)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(session_key).map_err(|_| BidError::Auth)?;
        let n = Nonce::from_slice(&nonce[..12]);
        let aad = aead_aad(bid.ask_id.as_bytes(), &nonce);
        let sealed = cipher
            .encrypt(n, Payload { msg: &json, aad: &aad })
            .map_err(|_| BidError::Auth)?;
        if sealed.len() < 16 {
            return Err(BidError::Auth);
        }
        let (ct, tag) = sealed.split_at(sealed.len() - 16);
        let mut mac = [0u8; 32];
        mac[..16].copy_from_slice(tag);
        Ok(Self {
            ask_id: bid.ask_id.clone(),
            nonce,
            ciphertext: ct.to_vec(),
            mac,
        })
    }

    pub fn open(&self, session_key: &[u8; 32]) -> Result<PlaintextBid, BidError> {
        if self.ciphertext.is_empty() {
            return Err(BidError::Decrypt);
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(session_key).map_err(|_| BidError::Auth)?;
        let n = Nonce::from_slice(&self.nonce[..12]);
        let aad = aead_aad(self.ask_id.as_bytes(), &self.nonce);
        let mut sealed = self.ciphertext.clone();
        sealed.extend_from_slice(&self.mac[..16]);
        let plain = cipher
            .decrypt(n, Payload { msg: &sealed, aad: &aad })
            .map_err(|_| BidError::Auth)?;
        serde_json::from_slice(&plain).map_err(|_| BidError::Decrypt)
    }

    pub fn commitment(&self) -> BidCommitment {
        BidCommitment {
            ask_id: self.ask_id.clone(),
            commitment: tagged_hash(
                b"bid-commit-v1",
                &[
                    self.ask_id.as_bytes(),
                    &self.nonce,
                    &self.ciphertext,
                    &self.mac,
                ],
            ),
        }
    }
}

impl BidCommitment {
    pub fn verify_against(&self, envelope: &EncryptedBidEnvelope) -> Result<(), BidError> {
        let expected = envelope.commitment();
        if expected.commitment != self.commitment || expected.ask_id != self.ask_id {
            return Err(BidError::CommitmentMismatch);
        }
        Ok(())
    }
}

fn aead_aad(ask_id: &[u8], nonce: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + ask_id.len() + nonce.len());
    aad.extend_from_slice(&(ask_id.len() as u64).to_le_bytes());
    aad.extend_from_slice(ask_id);
    aad.extend_from_slice(nonce);
    aad
}
