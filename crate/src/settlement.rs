//! Local settlement predicate: pay once per bound work digest. Not an Akash/ict lease.

use crate::tagged_hash;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkReceipt {
    pub ask_id: String,
    pub provider_commitment: [u8; 32],
    pub amount_zat: u64,
    pub work_digest: [u8; 32],
}

impl WorkReceipt {
    pub fn bind(ask_id: impl Into<String>, provider_commitment: [u8; 32], amount_zat: u64) -> Self {
        let ask_id = ask_id.into();
        let work_digest = digest_of(&ask_id, &provider_commitment, amount_zat);
        Self {
            ask_id,
            provider_commitment,
            amount_zat,
            work_digest,
        }
    }

    pub fn digest_matches(&self) -> bool {
        self.work_digest == digest_of(&self.ask_id, &self.provider_commitment, self.amount_zat)
    }
}

fn digest_of(ask_id: &str, provider: &[u8; 32], amount_zat: u64) -> [u8; 32] {
    tagged_hash(
        b"work-receipt-v1",
        &[ask_id.as_bytes(), provider, &amount_zat.to_le_bytes()],
    )
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SettlementError {
    #[error("work digest already paid")]
    Replay,
    #[error("work receipt required before pay")]
    MissingReceipt,
    #[error("work digest does not bind ask/provider/amount")]
    UnboundDigest,
    #[error("pool balance {have} below pay {need}")]
    Insufficient { have: u64, need: u64 },
    #[error("pool refused authorized debit: {0}")]
    Unauthorized(String),
}

/// In-process book. Same bound digest cannot be paid twice.
#[derive(Debug, Default, Clone)]
pub struct SettlementBook {
    paid_digests: HashSet<[u8; 32]>,
}

impl SettlementBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn require_work_before_pay(receipt: &WorkReceipt) -> Result<(), SettlementError> {
        if receipt.ask_id.is_empty() || receipt.amount_zat == 0 {
            return Err(SettlementError::MissingReceipt);
        }
        if !receipt.digest_matches() {
            return Err(SettlementError::UnboundDigest);
        }
        Ok(())
    }

    pub fn pay(&mut self, receipt: &WorkReceipt) -> Result<u64, SettlementError> {
        Self::require_work_before_pay(receipt)?;
        if !self.paid_digests.insert(receipt.work_digest) {
            return Err(SettlementError::Replay);
        }
        Ok(receipt.amount_zat)
    }

    /// Debit a credited FROST pool. Same digest cannot pay twice.
    /// When the pool has `.with_frost`, `auth` must carry a verifying FROST sig
    /// (OS holders or seats). Unsigned / wrong-group cannot move value.
    pub fn pay_from_pool(
        &mut self,
        pool: &mut crate::frost_pool::FrostThresholdPool,
        receipt: &WorkReceipt,
        auth: &crate::frost_pool::SpendAuth,
    ) -> Result<u64, SettlementError> {
        Self::require_work_before_pay(receipt)?;
        if self.paid_digests.contains(&receipt.work_digest) {
            return Err(SettlementError::Replay);
        }
        if pool.balance_zat < receipt.amount_zat {
            return Err(SettlementError::Insufficient {
                have: pool.balance_zat,
                need: receipt.amount_zat,
            });
        }
        pool.debit_authorized(auth, receipt.amount_zat)
            .map_err(|e| SettlementError::Unauthorized(e.to_string()))?;
        self.paid_digests.insert(receipt.work_digest);
        Ok(receipt.amount_zat)
    }
}
