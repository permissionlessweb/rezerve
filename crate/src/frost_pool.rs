//! In-memory pool credited from local deposit transcripts.

use crate::committee::{CommitteeError, LayeredQuorum, OuterCommittee};
use crate::frost::FrostGroup;
use crate::hashmerchant::{DepositAttestation, DepositError, HashmerchantIngress};
use crate::zap1::{Zap1Error, Zap1Ibcv2Bundle};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PoolError {
    #[error("deposit: {0}")]
    Deposit(#[from] DepositError),
    #[error("committee: {0}")]
    Committee(#[from] CommitteeError),
    #[error("zap1/ibc: {0}")]
    Zap1(#[from] Zap1Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolCredit {
    pub note_commitment: [u8; 32],
    pub amount_zat: u64,
}

/// Quorum plus bound spend fields. Product credit requires this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendAuth {
    pub group_id: [u8; 32],
    pub note: [u8; 32],
    pub amount_zat: u64,
    pub bid_commitment: Option<[u8; 32]>,
    pub quorum: LayeredQuorum,
    pub frost_sig: Option<Vec<u8>>,
}

impl SpendAuth {
    pub fn from_quorum(
        outer: &OuterCommittee,
        parts: &[(&str, &[&str])],
        group_id: [u8; 32],
        note: [u8; 32],
        amount_zat: u64,
        bid_commitment: Option<[u8; 32]>,
    ) -> Result<Self, CommitteeError> {
        if note == [0u8; 32] || amount_zat == 0 {
            return Err(CommitteeError::UnboundSpend);
        }
        if outer.group_id != Some(group_id) || group_id == [0u8; 32] {
            return Err(CommitteeError::UnboundGroup);
        }
        let quorum = outer.quorum(parts)?;
        if quorum.group_id != group_id {
            return Err(CommitteeError::UnboundGroup);
        }
        Ok(Self {
            group_id,
            note,
            amount_zat,
            bid_commitment,
            quorum,
            frost_sig: None,
        })
    }

    pub fn with_frost_sig(mut self, sig: Vec<u8>) -> Self {
        self.frost_sig = Some(sig);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostThresholdPool {
    pub group_id: [u8; 32],
    pub threshold: u16,
    pub n_signers: u16,
    pub balance_zat: u64,
    pub credits: Vec<PoolCredit>,
    pub spent_notes: BTreeSet<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layered: Option<OuterCommittee>,
    #[serde(skip)]
    pub frost: Option<FrostGroup>,
    /// When false (default), `credit_deposit` rejects `prove_for_test` transcripts.
    #[serde(default)]
    pub allow_sim_transcript: bool,
    /// If set, spend/debit `SpendAuth` must carry this bid commitment.
    #[serde(default)]
    pub bound_bid: Option<[u8; 32]>,
}

impl FrostThresholdPool {
    pub fn new(group_id: [u8; 32], threshold: u16, n_signers: u16) -> Result<Self, CommitteeError> {
        if n_signers == 0 || threshold == 0 || threshold > n_signers {
            return Err(CommitteeError::BadParams {
                threshold,
                n: n_signers,
            });
        }
        Ok(Self {
            group_id,
            threshold,
            n_signers,
            balance_zat: 0,
            credits: Vec::new(),
            spent_notes: BTreeSet::new(),
            layered: None,
            frost: None,
            allow_sim_transcript: false,
            bound_bid: None,
        })
    }

    pub fn bind_bid(mut self, bid: [u8; 32]) -> Self {
        self.bound_bid = Some(bid);
        self
    }

    pub fn allow_sim_transcript(mut self) -> Self {
        self.allow_sim_transcript = true;
        self
    }

    pub fn with_frost(mut self, frost: FrostGroup) -> Self {
        self.frost = Some(frost);
        self
    }

    pub fn with_layered(mut self, outer: OuterCommittee) -> Self {
        let bound = outer.bind_pool(self.group_id);
        self.threshold = bound.threshold;
        self.n_signers = bound.n();
        self.layered = Some(bound);
        self
    }

    pub fn authorize_with_quorum(&self, q: &LayeredQuorum) -> Result<(), CommitteeError> {
        let outer = self.layered.as_ref().ok_or(CommitteeError::Empty)?;
        if outer.group_id != Some(self.group_id) || self.group_id == [0u8; 32] {
            return Err(CommitteeError::UnboundGroup);
        }
        if q.outer_id != outer.committee_id || q.group_id != self.group_id {
            return Err(CommitteeError::UnboundGroup);
        }
        let parts: Vec<(String, Vec<String>)> = q
            .inner_quorums
            .iter()
            .map(|iq| (iq.label.clone(), iq.participants.clone()))
            .collect();
        let refs: Vec<(&str, Vec<&str>)> = parts
            .iter()
            .map(|(l, p)| (l.as_str(), p.iter().map(|s| s.as_str()).collect()))
            .collect();
        let pairs: Vec<(&str, &[&str])> = refs
            .iter()
            .map(|(l, p)| (*l, p.as_slice()))
            .collect();
        let recomputed = outer.quorum(&pairs)?;
        if recomputed.digest != q.digest {
            return Err(CommitteeError::DigestMismatch);
        }
        Ok(())
    }

    pub fn authorize_spend(&self, auth: &SpendAuth) -> Result<(), CommitteeError> {
        if auth.group_id != self.group_id {
            return Err(CommitteeError::SpendGroup);
        }
        if auth.note == [0u8; 32] || auth.amount_zat == 0 {
            return Err(CommitteeError::UnboundSpend);
        }
        self.authorize_with_quorum(&auth.quorum)?;
        if auth.quorum.group_id != self.group_id {
            return Err(CommitteeError::SpendGroup);
        }
        if let Some(want) = self.bound_bid {
            match auth.bid_commitment {
                Some(got) if got == want => {}
                _ => return Err(CommitteeError::SpendNote),
            }
        }
        if let Some(fg) = &self.frost {
            let sig = auth
                .frost_sig
                .as_ref()
                .ok_or(CommitteeError::FrostRequired)?;
            let msg = FrostGroup::spend_message(&auth.group_id, &auth.note, auth.amount_zat);
            fg.verify(&msg, sig)
                .map_err(|_| CommitteeError::FrostVerify)?;
        }
        Ok(())
    }

    /// Move credited value. Requires the same `SpendAuth` checks as product credit
    /// (FROST verify when `.with_frost`). Unsigned / wrong-group cannot debit.
    pub fn debit_authorized(&mut self, auth: &SpendAuth, amount: u64) -> Result<(), PoolError> {
        self.authorize_spend(auth)?;
        if auth.amount_zat != amount {
            return Err(CommitteeError::SpendAmount.into());
        }
        if self.balance_zat < amount {
            return Err(DepositError::Replay.into());
        }
        self.balance_zat = self.balance_zat.saturating_sub(amount);
        Ok(())
    }

    /// Product credit: attestation + matching `SpendAuth`. No unlayered bypass.
    pub fn credit_deposit(
        &mut self,
        att: &DepositAttestation,
        auth: &SpendAuth,
    ) -> Result<PoolCredit, PoolError> {
        self.authorize_spend(auth)?;
        if att.frost_group_id != auth.group_id {
            return Err(CommitteeError::SpendGroup.into());
        }
        if att.deposit_note_commitment != auth.note {
            return Err(CommitteeError::SpendNote.into());
        }
        if att.amount_zat != auth.amount_zat {
            return Err(CommitteeError::SpendAmount.into());
        }
        if !self.allow_sim_transcript {
            return Err(DepositError::SimTranscript.into());
        }
        Ok(self.apply_credit(att)?)
    }

    /// Product credit from ZAP1 + IBC v2 packet bind (not `prove_for_test`).
    /// Live-ict on-chain accept is Halo2 `AttestHalo2` when circuit artifacts
    /// are present (siblings stay off execute). Fail-closed if the helper is
    /// missing.
    pub fn credit_deposit_zap1(
        &mut self,
        bundle: &Zap1Ibcv2Bundle,
        auth: &SpendAuth,
    ) -> Result<PoolCredit, PoolError> {
        bundle.verify()?;
        crate::zap1::require_live_client_accept(bundle)?;
        self.authorize_spend(auth)?;
        if bundle.frost_group_id != auth.group_id || bundle.frost_group_id != self.group_id {
            return Err(CommitteeError::SpendGroup.into());
        }
        if bundle.deposit_note_commitment != auth.note {
            return Err(CommitteeError::SpendNote.into());
        }
        if bundle.amount_zat != auth.amount_zat {
            return Err(CommitteeError::SpendAmount.into());
        }
        if !self.spent_notes.insert(bundle.deposit_note_commitment) {
            return Err(DepositError::Replay.into());
        }
        let credit = PoolCredit {
            note_commitment: bundle.deposit_note_commitment,
            amount_zat: bundle.amount_zat,
        };
        self.balance_zat = self.balance_zat.saturating_add(bundle.amount_zat);
        self.credits.push(credit.clone());
        Ok(credit)
    }

    /// Sim-only credit without `SpendAuth`. Feature `sim` (default).
    #[cfg(feature = "sim")]
    pub fn credit_transcript(&mut self, att: &DepositAttestation) -> Result<PoolCredit, DepositError> {
        self.apply_credit(att)
    }

    fn apply_credit(&mut self, att: &DepositAttestation) -> Result<PoolCredit, DepositError> {
        let ingress = HashmerchantIngress::new(self.group_id);
        ingress.accept(att)?;
        if !self.spent_notes.insert(att.deposit_note_commitment) {
            return Err(DepositError::Replay);
        }
        let credit = PoolCredit {
            note_commitment: att.deposit_note_commitment,
            amount_zat: att.amount_zat,
        };
        self.balance_zat = self.balance_zat.saturating_add(att.amount_zat);
        self.credits.push(credit.clone());
        Ok(credit)
    }
}
