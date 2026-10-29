//! AKT stake inclusion public instances.
//!
//! Private relation: `stake_uakt >= min_stake_uakt`. The bonding account is a
//! witness. It is not a public instance, and neither is a renter id.
//! Pasta Halo2 for that relation is not live. Prove and verify fail closed.
//! `PIR_*` is the allocate gate, not this check.
//! The inclusion root is caller-supplied. This is not an Akash mainnet snapshot.

use thiserror::Error;

pub const CIRCUIT_ID: &str = "akt-stake-inclusion.v0";
pub const AMOUNT_CLASS_LABEL: &str = "AKT_STAKE_GE_MIN";
pub const INSTANCE_LEN: usize = 96;
/// No proving key. `verify_akt_stake_inclusion` never accepts.
pub const PROOF_LIVE: bool = false;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AktStakeError {
    #[error("AKT stake inclusion proof is not live")]
    ProofNotLive,
    #[error("min_stake_uakt must be nonzero")]
    ZeroMin,
    #[error("bonding account must be nonempty")]
    EmptyAccount,
    #[error("private stake is below min_stake_uakt")]
    StakeBelowMin,
    #[error("bonding account appears in public instances")]
    AccountInPublicInputs,
}

/// Witness. Never serialized onto the public instance list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AktStakeWitness {
    pub bonding_account: Vec<u8>,
    pub stake_uakt: u64,
}

/// Three public rows: packed root, minimum stake, amount class.
///
/// 96 bytes, little-endian Pallas elements. Not a 128-byte HOSTING_PAYMENT
/// list. `amount_class` is the domain `AKT_STAKE_GE_MIN`, not a balance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AktStakePublic {
    pub inclusion_root: [u8; 32],
    pub min_stake_uakt: u64,
    pub amount_class: [u8; 32],
}

fn pack32(bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = *bytes;
    out[31] &= 0x3f;
    let _ = hosting_payment::pack_hash32(&out);
    out
}

fn amount_class_bytes() -> [u8; 32] {
    let mut raw = [0u8; 32];
    let label = AMOUNT_CLASS_LABEL.as_bytes();
    raw[..label.len()].copy_from_slice(label);
    pack32(&raw)
}

fn le_u64_field(x: u64) -> [u8; 32] {
    let mut raw = [0u8; 32];
    raw[..8].copy_from_slice(&x.to_le_bytes());
    raw
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

impl AktStakePublic {
    /// Packed root and the market minimum. No account parameter and no renter id.
    pub fn new(inclusion_root: [u8; 32], min_stake_uakt: u64) -> Result<Self, AktStakeError> {
        if min_stake_uakt == 0 {
            return Err(AktStakeError::ZeroMin);
        }
        Ok(Self {
            inclusion_root: pack32(&inclusion_root),
            min_stake_uakt,
            amount_class: amount_class_bytes(),
        })
    }

    /// Row 0 root, row 1 `min_stake_uakt`, row 2 amount class.
    pub fn instance_bytes(&self) -> [u8; INSTANCE_LEN] {
        let mut out = [0u8; INSTANCE_LEN];
        out[0..32].copy_from_slice(&self.inclusion_root);
        out[32..64].copy_from_slice(&le_u64_field(self.min_stake_uakt));
        out[64..96].copy_from_slice(&self.amount_class);
        out
    }

    /// Public JSON. Stake, bonding account, and renter id are not keys.
    pub fn chain_json(&self) -> String {
        serde_json::json!({
            "circuit_id": CIRCUIT_ID,
            "proof_live": PROOF_LIVE,
            "inclusion_root": hex::encode(self.inclusion_root),
            "min_stake_uakt": self.min_stake_uakt,
            "amount_class": hex::encode(self.amount_class),
        })
        .to_string()
    }
}

/// Cleartext check of the intended relation. Not a zero-knowledge proof.
pub fn statement_holds(
    witness: &AktStakeWitness,
    public: &AktStakePublic,
) -> Result<(), AktStakeError> {
    if witness.bonding_account.is_empty() {
        return Err(AktStakeError::EmptyAccount);
    }
    if witness.stake_uakt < public.min_stake_uakt {
        return Err(AktStakeError::StakeBelowMin);
    }
    if bytes_contain(&public.instance_bytes(), &witness.bonding_account) {
        return Err(AktStakeError::AccountInPublicInputs);
    }
    Ok(())
}

/// Does not produce proof bytes. A held statement still returns [`AktStakeError::ProofNotLive`].
pub fn prove_akt_stake_inclusion(
    witness: &AktStakeWitness,
    public: &AktStakePublic,
) -> Result<Vec<u8>, AktStakeError> {
    statement_holds(witness, public)?;
    Err(AktStakeError::ProofNotLive)
}

/// Rejects every proof, including empty bytes. The circuit is not live.
pub fn verify_akt_stake_inclusion(
    _public: &AktStakePublic,
    _proof: &[u8],
) -> Result<(), AktStakeError> {
    Err(AktStakeError::ProofNotLive)
}
