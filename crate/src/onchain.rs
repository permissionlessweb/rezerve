//! On-chain bid-phase view: commitments and attestations only.
//! CosmWasm-shaped store — not a live chain.

use crate::ask::PublicAsk;
use crate::bid::BidCommitment;
use crate::hex32;
use crate::ibc_module::{IbcModuleError, IbcV2Module, IbcV2Packet};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OnChainError {
    #[error("ask id mismatch")]
    AskMismatch,
}

/// Chain-visible bid record. Must not carry price, bidder identity, or Stoffel MPC claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainBidRecord {
    pub ask_commitment: String,
    pub bid_commitment: String,
    pub steoffle_attestation: String,
    /// Unused. Not a private-MPC attestation (secret CMP does not exist).
    pub stoffel_confirm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainView {
    pub public_ask: PublicAsk,
    pub records: Vec<OnChainBidRecord>,
}

impl OnChainView {
    pub fn new(public_ask: PublicAsk) -> Self {
        Self {
            public_ask,
            records: Vec::new(),
        }
    }

    pub fn post_commitment(
        &mut self,
        bid: &BidCommitment,
        steoffle_attestation: [u8; 32],
    ) -> Result<OnChainBidRecord, OnChainError> {
        if bid.ask_id != self.public_ask.ask_id {
            return Err(OnChainError::AskMismatch);
        }
        let rec = OnChainBidRecord {
            ask_commitment: hex32(&self.public_ask.ask_commitment()),
            bid_commitment: hex32(&bid.commitment),
            steoffle_attestation: hex32(&steoffle_attestation),
            stoffel_confirm: String::new(),
        };
        self.records.push(rec.clone());
        Ok(rec)
    }

    pub fn query_bid(
        &self,
        ask_commitment: &str,
        bid_commitment: &str,
    ) -> Option<&OnChainBidRecord> {
        self.records.iter().find(|r| {
            r.ask_commitment == ask_commitment && r.bid_commitment == bid_commitment
        })
    }

    /// Fixture / serialization used as the chain-message payload.
    pub fn chain_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": "private-inference-rent/bid-phase",
            "ask_id": self.public_ask.ask_id,
            "ask_commitment": hex32(&self.public_ask.ask_commitment()),
            "manifest": self.public_ask.manifest_sdl,
            "resources": self.public_ask.resources,
            "records": self.records,
        })
    }

    pub fn payload_contains_plaintext_bid(&self) -> bool {
        let s = self.chain_payload().to_string();
        let lower = s.to_ascii_lowercase();
        lower.contains("price_uakt")
            || lower.contains("bidder_identity")
            || lower.contains("\"price\"")
    }
}

/// Bid store + IBC packet store. Later ict-rs-cw-orch Daemon can call these methods.
#[derive(Debug, Clone)]
pub struct CommitmentModule {
    pub view: OnChainView,
    pub ibc: IbcV2Module,
}

impl CommitmentModule {
    pub fn new(public_ask: PublicAsk) -> Self {
        Self {
            view: OnChainView::new(public_ask),
            ibc: IbcV2Module::new(),
        }
    }

    pub fn post_commitment(
        &mut self,
        bid: &BidCommitment,
        steoffle_attestation: [u8; 32],
    ) -> Result<OnChainBidRecord, OnChainError> {
        self.view.post_commitment(bid, steoffle_attestation)
    }

    pub fn query_bid(
        &self,
        ask_commitment: &str,
        bid_commitment: &str,
    ) -> Option<&OnChainBidRecord> {
        self.view.query_bid(ask_commitment, bid_commitment)
    }

    /// Record packet commitment and bid record together (module "publish").
    pub fn publish(
        &mut self,
        packet: &IbcV2Packet,
        bid: &BidCommitment,
        steoffle_attestation: [u8; 32],
    ) -> Result<OnChainBidRecord, PublishError> {
        self.ibc.commit_packet(packet)?;
        Ok(self.view.post_commitment(bid, steoffle_attestation)?)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PublishError {
    #[error(transparent)]
    Ibc(#[from] IbcModuleError),
    #[error(transparent)]
    OnChain(#[from] OnChainError),
}
