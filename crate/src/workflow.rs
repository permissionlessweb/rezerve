//! Orchestration of the offline compute-rent demo.

use crate::ask::PublicAsk;
use crate::bid::{BidCommitment, EncryptedBidEnvelope, PlaintextBid};
use crate::dregg::FrostSignerInstance;
use crate::frost_pool::{FrostThresholdPool, PoolCredit, SpendAuth};
use crate::hashmerchant::DepositAttestation;
use crate::zap1::Zap1Ibcv2Bundle;
use crate::onchain::{OnChainBidRecord, OnChainView};
use crate::steoffle::{SteoffleAttestation, SteoffleError, SteoffleMpc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkflowError {
    #[error("invalid public ask")]
    InvalidAsk,
    #[error("ask id mismatch")]
    AskMismatch,
    #[error("bid index out of range")]
    BidIndex,
    #[error("bid: {0}")]
    Bid(#[from] crate::bid::BidError),
    #[error("deposit: {0}")]
    Deposit(#[from] crate::hashmerchant::DepositError),
    #[error("pool: {0}")]
    Pool(#[from] crate::frost_pool::PoolError),
    #[error("on-chain: {0}")]
    OnChain(#[from] crate::onchain::OnChainError),
    #[error("steoffle: {0}")]
    Steoffle(#[from] crate::steoffle::SteoffleError),
    #[error("stoffel: {0}")]
    Stoffel(#[from] crate::stoffel::StoffelError),
    #[error("committee: {0}")]
    Committee(#[from] crate::committee::CommitteeError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowReceipt {
    pub ask_id: String,
    pub on_chain: OnChainView,
    pub deposit_accepted: bool,
    /// Outcome of the most recent `credit_deposit` call only.
    pub last_credit_ok: bool,
    pub pool_balance_zat: u64,
    pub steoffle_ok: bool,
    pub stoffel_ok: bool,
    pub oob_bid_count: usize,
    pub outer_n: u16,
    pub inner_seats: u16,
}

pub struct PrivateComputeWorkflow {
    pub view: OnChainView,
    pub pool: FrostThresholdPool,
    pub oob_envelopes: Vec<EncryptedBidEnvelope>,
    signers: BTreeMap<[u8; 32], FrostSignerInstance>,
    verified_bids: usize,
    last_credit_ok: bool,
    stoffel_confirm: bool,
}

impl PrivateComputeWorkflow {
    pub fn open(ask: PublicAsk, pool: FrostThresholdPool) -> Result<Self, WorkflowError> {
        ask.validate()?;
        let mut wf = Self {
            view: OnChainView::new(ask),
            pool,
            oob_envelopes: Vec::new(),
            signers: BTreeMap::new(),
            verified_bids: 0,
            last_credit_ok: false,
            stoffel_confirm: false,
        };
        if let Some(outer) = wf.pool.layered.as_ref() {
            let to_enroll: Vec<_> = outer
                .inners
                .iter()
                .flat_map(|inner| inner.seats.iter().map(|s| s.signer.clone()))
                .collect();
            for signer in to_enroll {
                wf.enroll_signer(signer)?;
            }
        }
        Ok(wf)
    }

    /// Checks Stoffel CLI presence. Does not bind a private-MPC field on-chain.
    pub fn require_stoffel_confirm(&mut self) -> Result<(), WorkflowError> {
        if !crate::stoffel::available() {
            return Err(crate::stoffel::StoffelError::CliMissing.into());
        }
        self.stoffel_confirm = true;
        Ok(())
    }

    pub fn enroll_signer(&mut self, signer: FrostSignerInstance) -> Result<(), WorkflowError> {
        signer.runtime.verify().map_err(SteoffleError::from)?;
        self.signers.insert(signer.signer_id, signer);
        Ok(())
    }

    pub fn ingest_oob_bid(
        &mut self,
        envelope: EncryptedBidEnvelope,
        steoffle: &SteoffleAttestation,
    ) -> Result<OnChainBidRecord, WorkflowError> {
        if envelope.ask_id != self.view.public_ask.ask_id {
            return Err(WorkflowError::AskMismatch);
        }
        let signer = self
            .signers
            .get(&steoffle.signer_id)
            .ok_or(SteoffleError::UnknownSigner)?;
        SteoffleMpc::verify(signer, steoffle)?;
        let commit: BidCommitment = envelope.commitment();
        let rec = self.view.post_commitment(&commit, steoffle.seat_transcript)?;
        self.oob_envelopes.push(envelope);
        self.verified_bids += 1;
        Ok(rec)
    }

    pub fn open_oob_bid(
        &self,
        index: usize,
        session_key: &[u8; 32],
    ) -> Result<PlaintextBid, WorkflowError> {
        let env = self.oob_envelopes.get(index).ok_or(WorkflowError::BidIndex)?;
        Ok(env.open(session_key)?)
    }

    pub fn credit_deposit(
        &mut self,
        att: &DepositAttestation,
        auth: &SpendAuth,
    ) -> Result<PoolCredit, WorkflowError> {
        match self.pool.credit_deposit(att, auth) {
            Ok(credit) => {
                self.last_credit_ok = true;
                Ok(credit)
            }
            Err(e) => {
                self.last_credit_ok = false;
                Err(e.into())
            }
        }
    }

    pub fn credit_deposit_zap1(
        &mut self,
        bundle: &Zap1Ibcv2Bundle,
        auth: &SpendAuth,
    ) -> Result<PoolCredit, WorkflowError> {
        match self.pool.credit_deposit_zap1(bundle, auth) {
            Ok(credit) => {
                self.last_credit_ok = true;
                Ok(credit)
            }
            Err(e) => {
                self.last_credit_ok = false;
                Err(e.into())
            }
        }
    }

    pub fn attest_signer(
        signer: &FrostSignerInstance,
    ) -> Result<SteoffleAttestation, WorkflowError> {
        Ok(SteoffleMpc::attest(signer)?)
    }

    pub fn receipt(&self) -> WorkflowReceipt {
        let steoffle_ok = !self.oob_envelopes.is_empty()
            && self.verified_bids == self.oob_envelopes.len();
        WorkflowReceipt {
            ask_id: self.view.public_ask.ask_id.clone(),
            on_chain: self.view.clone(),
            deposit_accepted: self.last_credit_ok,
            last_credit_ok: self.last_credit_ok,
            pool_balance_zat: self.pool.balance_zat,
            steoffle_ok,
            stoffel_ok: !self.stoffel_confirm || crate::stoffel::available(),
            oob_bid_count: self.oob_envelopes.len(),
            outer_n: self
                .pool
                .layered
                .as_ref()
                .map(|o| o.n())
                .unwrap_or(self.pool.n_signers),
            inner_seats: self
                .pool
                .layered
                .as_ref()
                .map(|o| o.inners.iter().map(|i| i.n()).sum())
                .unwrap_or(self.pool.n_signers),
        }
    }
}
