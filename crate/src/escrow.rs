//! Bid-bound escrow cell. Access kill stays on [`LeaseBook`].
//! Product money is zat via [`FrostThresholdPool`] + FROST `SpendAuth`.
//! Native-denom CosmWasm sends are a public-rail rehearsal in `cw-pir-escrow`, not this module.
//!
//! Product accrue is [`EscrowCell::accrue_from_witness_halo2`]: Halo2 of
//! `f(open_height, close_height, rate)`, earned stays on the private witness,
//! grant JSON matches `cw-pir-escrow` (`earned_zat` = 0 plus commitment /
//! header hashes). [`EscrowCell::accrue_from_witness`] binds the witness only
//! (no proof). [`EscrowCell::accrue`] (work receipts) is sim-only.

use crate::access::{LeaseAccessError, LeaseBook};
use crate::accrual::{
    accrue_from_zakura_halo2, verify_product_accrual, verify_witness, AccrualError, AccrualPublic,
    AccrualRate, AccrualWitness,
};
use crate::zakura::ZakuraRegtest;
use crate::frost_pool::{FrostThresholdPool, PoolCredit, SpendAuth};
use crate::settlement::{SettlementBook, SettlementError, WorkReceipt};
use crate::zap1::{Zap1Error, Zap1Ibcv2Bundle};
use crate::tagged_hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowParty {
    Tenant,
    Provider,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowMemberIds {
    pub tenant: String,
    pub provider: String,
    pub resolver: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseRecord {
    pub closer: EscrowParty,
    pub earned_zat: u64,
    pub remainder_zat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseGrant {
    pub cell_id: [u8; 32],
    pub closer: EscrowParty,
    /// Private split (FROST spends). Not posted by [`GrantView`].
    pub earned_zat: u64,
    pub remainder_zat: u64,
    pub recorded: bool,
    pub accrual_commitment: String,
    pub open_header_hash: String,
    pub close_header_hash: String,
}

/// JSON the CosmWasm `Grant` query must round-trip (hex cell_id).
/// Public earned is always 0; the split is the private witness. Remainder on
/// the wire is the deposit (same as `cw-pir-escrow` `GrantResp`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantView {
    pub cell_id: String,
    pub closer: EscrowParty,
    pub earned_zat: u64,
    pub remainder_zat: u64,
    pub recorded: bool,
    pub accrual_commitment: String,
    pub open_header_hash: String,
    pub close_header_hash: String,
}

impl CloseGrant {
    pub fn view(&self) -> GrantView {
        GrantView {
            cell_id: hex::encode(self.cell_id),
            closer: self.closer,
            earned_zat: 0,
            remainder_zat: self.earned_zat.saturating_add(self.remainder_zat),
            recorded: self.recorded,
            accrual_commitment: self.accrual_commitment.clone(),
            open_header_hash: self.open_header_hash.clone(),
            close_header_hash: self.close_header_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementIntent {
    PayProvider(u64),
    RefundTenant(u64),
}

impl SettlementIntent {
    pub fn amount(self) -> u64 {
        match self {
            Self::PayProvider(a) | Self::RefundTenant(a) => a,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EscrowError {
    #[error("zero deposit")]
    ZeroDeposit,
    #[error("zero bid commitment")]
    ZeroBid,
    #[error("empty member id")]
    EmptyMember,
    #[error("earned exceeds deposit")]
    EarnedExceedsDeposit,
    #[error("cell already closed")]
    AlreadyClosed,
    #[error("cell still open")]
    CellOpen,
    #[error("close does not take an earned override")]
    EarnedOverride,
    #[error("intents only after close")]
    NotClosed,
    #[error("grant missing")]
    NoGrant,
    #[error("grant does not match close")]
    GrantMismatch,
    #[error("resolver share not granted")]
    ResolverDenied,
    #[error("lease: {0:?}")]
    Lease(LeaseAccessError),
    #[error("settle: {0}")]
    Settle(#[from] SettlementError),
    #[error("zap1: {0}")]
    Zap1(#[from] Zap1Error),
    #[error("pool: {0}")]
    Pool(String),
    #[error("deposit amount does not match cell")]
    DepositMismatch,
    #[error("earned requires bound work receipts")]
    NoWorkReceipts,
    #[error("work receipt does not bind this cell")]
    ReceiptMismatch,
    #[error("accrual: {0}")]
    Accrual(#[from] AccrualError),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResolverShareError {
    #[error("no close grant")]
    NoGrant,
    #[error("grant mismatch")]
    GrantMismatch,
    #[error("cell still open")]
    CellOpen,
}

#[derive(Debug, Clone)]
pub struct EscrowCell {
    pub cell_id: [u8; 32],
    pub deposit_zat: u64,
    pub bid_commitment: [u8; 32],
    pub members: EscrowMemberIds,
    pub earned_zat: u64,
    pub work_receipts: Vec<WorkReceipt>,
    pub accrual: Option<AccrualPublic>,
    pub closed: Option<CloseRecord>,
    pub grant: Option<CloseGrant>,
}

impl EscrowCell {
    pub fn open(
        deposit_zat: u64,
        bid_commitment: [u8; 32],
        members: EscrowMemberIds,
    ) -> Result<Self, EscrowError> {
        if deposit_zat == 0 {
            return Err(EscrowError::ZeroDeposit);
        }
        if bid_commitment == [0u8; 32] {
            return Err(EscrowError::ZeroBid);
        }
        if members.tenant.is_empty() || members.provider.is_empty() || members.resolver.is_empty() {
            return Err(EscrowError::EmptyMember);
        }
        let cell_id = tagged_hash(
            b"escrow-cell-v1",
            &[
                &deposit_zat.to_le_bytes(),
                &bid_commitment,
                members.tenant.as_bytes(),
                members.provider.as_bytes(),
                members.resolver.as_bytes(),
            ],
        );
        Ok(Self {
            cell_id,
            deposit_zat,
            bid_commitment,
            members,
            earned_zat: 0,
            work_receipts: Vec::new(),
            accrual: None,
            closed: None,
            grant: None,
        })
    }

    /// Witness bind of `earned = f(open_height, close_height, rate)` without a
    /// Halo2 proof. Product path is [`accrue_from_witness_halo2`].
    pub fn accrue_from_witness(
        &mut self,
        witness: AccrualWitness,
        public: AccrualPublic,
    ) -> Result<(), EscrowError> {
        if self.closed.is_some() {
            return Err(EscrowError::AlreadyClosed);
        }
        verify_witness(&witness, &public)?;
        if witness.earned_zat > self.deposit_zat {
            return Err(EscrowError::EarnedExceedsDeposit);
        }
        self.earned_zat = witness.earned_zat;
        self.accrual = Some(public);
        Ok(())
    }

    /// Product accrue: Halo2 of `f(open_height, close_height, rate)`. Empty
    /// proof is invalid — plaintext earned is not a substitute.
    pub fn accrue_from_witness_halo2(
        &mut self,
        witness: AccrualWitness,
        public: AccrualPublic,
        proof: &[u8],
    ) -> Result<(), EscrowError> {
        verify_product_accrual(&witness, &public, proof)?;
        self.accrue_from_witness(witness, public)
    }

    /// Product accrue from live Zakura `getblockheader` heights with Halo2 of `f`.
    pub fn accrue_from_zakura(
        &mut self,
        z: &ZakuraRegtest,
        open_height: u64,
        close_height: u64,
        rate: AccrualRate,
        blinding: [u8; 32],
    ) -> Result<(), EscrowError> {
        let (wit, pubv, proof) =
            accrue_from_zakura_halo2(z, open_height, close_height, rate, blinding)?;
        self.accrue_from_witness_halo2(wit, pubv, &proof)
    }

    /// Sim accrue from bound [`WorkReceipt`]s. Raw `u64` is not accepted.
    /// Product path is [`accrue_from_witness_halo2`].
    pub fn accrue(&mut self, receipts: &[WorkReceipt]) -> Result<(), EscrowError> {
        if self.closed.is_some() {
            return Err(EscrowError::AlreadyClosed);
        }
        if receipts.is_empty() {
            return Err(EscrowError::NoWorkReceipts);
        }
        let mut add = 0u64;
        for r in receipts {
            if !r.digest_matches() || r.amount_zat == 0 {
                return Err(EscrowError::ReceiptMismatch);
            }
            if r.provider_commitment != self.bid_commitment {
                return Err(EscrowError::ReceiptMismatch);
            }
            add = add
                .checked_add(r.amount_zat)
                .ok_or(EscrowError::EarnedExceedsDeposit)?;
        }
        let earned = self
            .earned_zat
            .checked_add(add)
            .ok_or(EscrowError::EarnedExceedsDeposit)?;
        if earned > self.deposit_zat {
            return Err(EscrowError::EarnedExceedsDeposit);
        }
        self.work_receipts.extend(receipts.iter().cloned());
        self.earned_zat = earned;
        Ok(())
    }

    /// `earned_override` must be `None`. Accrued earned is the only amount.
    pub fn close(
        &mut self,
        party: EscrowParty,
        lease: &mut LeaseBook,
        lease_id: &str,
        earned_override: Option<u64>,
    ) -> Result<CloseGrant, EscrowError> {
        if earned_override.is_some() {
            return Err(EscrowError::EarnedOverride);
        }
        if self.closed.is_some() {
            return Err(EscrowError::AlreadyClosed);
        }
        if self.earned_zat > 0 && self.work_receipts.is_empty() && self.accrual.is_none() {
            return Err(EscrowError::NoWorkReceipts);
        }
        let remainder = self.deposit_zat - self.earned_zat;
        let rec = CloseRecord {
            closer: party,
            earned_zat: self.earned_zat,
            remainder_zat: remainder,
        };
        lease.close(lease_id).map_err(EscrowError::Lease)?;
        let (accrual_commitment, open_header_hash, close_header_hash) = match &self.accrual {
            Some(p) => (
                hex::encode(p.commitment),
                hex::encode(p.open_header_hash),
                hex::encode(p.close_header_hash),
            ),
            None => (String::new(), String::new(), String::new()),
        };
        let grant = CloseGrant {
            cell_id: self.cell_id,
            closer: party,
            earned_zat: rec.earned_zat,
            remainder_zat: rec.remainder_zat,
            recorded: true,
            accrual_commitment,
            open_header_hash,
            close_header_hash,
        };
        self.closed = Some(rec);
        self.grant = Some(grant.clone());
        Ok(grant)
    }

    pub fn intents(&self) -> Result<[SettlementIntent; 2], EscrowError> {
        let c = self.closed.as_ref().ok_or(EscrowError::NotClosed)?;
        Ok([
            SettlementIntent::PayProvider(c.earned_zat),
            SettlementIntent::RefundTenant(c.remainder_zat),
        ])
    }

    pub fn resolver_may_sign(&self, member_id: &str) -> Result<(), ResolverShareError> {
        if self.closed.is_none() {
            return Err(ResolverShareError::CellOpen);
        }
        let g = self.grant.as_ref().ok_or(ResolverShareError::NoGrant)?;
        if !g.recorded || g.cell_id != self.cell_id {
            return Err(ResolverShareError::GrantMismatch);
        }
        let c = self.closed.as_ref().unwrap();
        if g.earned_zat != c.earned_zat || g.remainder_zat != c.remainder_zat {
            return Err(ResolverShareError::GrantMismatch);
        }
        if member_id != self.members.resolver {
            return Err(ResolverShareError::GrantMismatch);
        }
        Ok(())
    }

    /// Product ingest only: ZAP1 + IBC v2 + FROST `SpendAuth`. Not `prove_for_test`.
    pub fn fund_with_zap1(
        &self,
        pool: &mut FrostThresholdPool,
        bundle: &Zap1Ibcv2Bundle,
        auth: &SpendAuth,
    ) -> Result<PoolCredit, EscrowError> {
        if bundle.amount_zat != self.deposit_zat {
            return Err(EscrowError::DepositMismatch);
        }
        if auth.bid_commitment != Some(self.bid_commitment) {
            return Err(EscrowError::DepositMismatch);
        }
        crate::zap1::accept_on_zap1_client(bundle)?;
        pool.credit_deposit_zap1(bundle, auth)
            .map_err(|e| EscrowError::Pool(e.to_string()))
    }

    pub fn provider_receipt(&self, ask_id: &str) -> WorkReceipt {
        WorkReceipt::bind(ask_id, self.bid_commitment, self.earned_zat)
    }

    pub fn refund_receipt(&self, ask_id: &str) -> WorkReceipt {
        let tag = tagged_hash(b"refund-v1", &[&self.cell_id]);
        WorkReceipt::bind(ask_id, tag, self.remainder_zat())
    }

    fn remainder_zat(&self) -> u64 {
        self.closed
            .as_ref()
            .map(|c| c.remainder_zat)
            .unwrap_or(self.deposit_zat - self.earned_zat)
    }
}

/// Both payouts or neither. Zero-amount intents are skipped (SpendAuth rejects 0).
pub fn settle_close(
    cell: &EscrowCell,
    book: &mut SettlementBook,
    pool: &mut FrostThresholdPool,
    pay_provider: Option<&SpendAuth>,
    refund_tenant: Option<&SpendAuth>,
    ask_id: &str,
) -> Result<(), EscrowError> {
    let [p, r] = cell.intents()?;
    let mut book2 = book.clone();
    let mut pool2 = pool.clone();
    if p.amount() > 0 {
        let auth = pay_provider.ok_or(EscrowError::NoGrant)?;
        book2.pay_from_pool(&mut pool2, &cell.provider_receipt(ask_id), auth)?;
    }
    if r.amount() > 0 {
        let auth = refund_tenant.ok_or(EscrowError::NoGrant)?;
        book2.pay_from_pool(&mut pool2, &cell.refund_receipt(ask_id), auth)?;
    }
    *book = book2;
    *pool = pool2;
    Ok(())
}
