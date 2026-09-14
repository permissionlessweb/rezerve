//! Compute-rent workflow: public ask, AEAD OOB bids, SpendAuth, FROST-ed25519
//! spend signatures, optional Zakura attach. Stoffel secret CMP is still blocked.

pub mod access;
pub mod accrual;
pub mod ask;
pub mod bid;
pub mod committee;
pub mod custody;
pub mod cw_orch;
pub mod e2e;
pub mod escrow;
pub mod escrow_notice;
pub mod dregg;
pub mod frost;
pub mod frost_dkg;
pub mod frost_process;
pub mod frost_pool;
pub mod hashmerchant;
pub mod ibc_module;
pub mod interop;
pub mod onchain;
pub mod party_process;
pub mod settlement;
pub mod steoffle;
pub mod stoffel;
pub mod zakura;
pub mod zcash_escrow;
pub mod zap1;
pub mod zap1_lc;
pub mod workflow;
#[cfg(feature = "seam-dex")]
pub mod seam_swap;
#[cfg(feature = "cw-orch-suite")]
pub use pir_cw_orch::{PrivateInference, PrivateInferenceDeployData};

pub use access::{DerivedAccess, LeaseAccessError, LeaseBook};
pub use ask::{PublicAsk, ResourceAsk};
pub use bid::{BidCommitment, EncryptedBidEnvelope, PlaintextBid};
pub use committee::{
    demo_layered_committees, CommitteeError, InnerCommittee, InnerQuorum, LayeredQuorum,
    OuterCommittee, SignerSeat,
};
pub use dregg::{FrostSignerInstance, LocalRuntimeProof, SignerInstanceError};
pub use e2e::{
    run_composed_arbiter, run_escrow_partial_close, run_local_e2e, run_production_sequence,
    run_rent_rounds, ComposedArbiterReport, EscrowPartialReport, LocalE2eReport,
    ProductionSequenceReport, RentRound, LOCAL_E2E_MODULES, PRODUCTION_SEQUENCE,
};
pub use custody::{CustodyError, EscrowHolders, PIR_FROST_SEAT_ENV};
pub use escrow::{
    settle_close, CloseGrant, CloseRecord, EscrowCell, EscrowError, EscrowMemberIds, EscrowParty,
    GrantView, ResolverShareError, SettlementIntent,
};
pub use escrow_notice::{
    resolver_dkg_share_from_notice, resolver_may_sign_from_notice, CloseAction, CloseEventAttest,
    CloseEventAttrs, ResolverDkgShare, ResolverNotice, ResolverNoticeError,
};
pub use frost::{FrostError, FrostGroup, FrostSeat};
pub use frost_dkg::{
    dkg_three_party, sign_tenant_provider, tenant_provider_seats, FrostParams,
};
pub use frost_process::sign_with_os_holders;
pub use frost_pool::{FrostThresholdPool, PoolCredit, PoolError, SpendAuth};
pub use zakura::{
    lab_spawn, spawn_zakura_local, ZakuraError, ZakuraNode, ZakuraNodeConfig, ZakuraRegtest,
    ENV_ZAKURAD_BIN, ENV_ZAKURA_RPC, ZAKURA_RPC_PORT,
};
pub use zcash_escrow::{
    attach_zakura, lab_required, ShieldedNote, SpendResult, ZcashEscrow, ZcashEscrowError,
};
pub use zap1::{
    accept_on_zap1_client, local_hosting_bundle, require_live_client_accept, IbcV2PacketAttest,
    Zap1Error, Zap1EventKind, Zap1Ibcv2Bundle,
    Zap1ProofStep,
};
pub use zap1_lc::{require_onchain_accept, zap1_lc_required, Zap1LcError};
pub use hashmerchant::{DepositAttestation, HashmerchantIngress};
pub use ibc_module::{IbcModuleError, IbcV2Module, IbcV2Packet};
pub use onchain::{
    CommitmentModule, OnChainBidRecord, OnChainError, OnChainView, PublishError,
};
pub use party_process::{process_open, process_seal};
pub use settlement::{SettlementBook, SettlementError, WorkReceipt};
pub use steoffle::{SteoffleAttestation, SteoffleMpc};
pub use stoffel::{confirm_digest, StoffelError};
pub use workflow::{PrivateComputeWorkflow, WorkflowReceipt};

/// Domain-separated SHA-256.
pub fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(tag);
    h.update(&[tag.len() as u8]);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}
