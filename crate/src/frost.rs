//! frost-ed25519 threshold sign. Product groups: DKG part3 [`FrostGroup::from_key_packages`].
//! [`FrostGroup::dealer`] is a named negative-control helper, not product custody.

use crate::tagged_hash;
use frost_ed25519 as frost;
use frost_ed25519::keys::{IdentifierList, KeyPackage, PublicKeyPackage};
use frost_ed25519::{round1, round2, Identifier, SigningPackage};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FrostError {
    #[error("frost: {0}")]
    Protocol(String),
    #[error("not enough signers: have {have}, need {need}")]
    BelowThreshold { have: u16, need: u16 },
    #[error("verify failed")]
    Verify,
    #[error("dealer shares already issued; sign only with seats")]
    SeatsIssued,
}

/// One threshold share. Secret is redacted in Debug.
/// Not OS-process isolated; clone two seats to simulate split holders (NS6 owns processes).
#[derive(Clone)]
pub struct FrostSeat {
    identifier: Identifier,
    package: KeyPackage,
}

impl std::fmt::Debug for FrostSeat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostSeat")
            .field("identifier", &self.identifier)
            .field("package", &"<redacted>")
            .finish()
    }
}

impl FrostSeat {
    pub fn identifier_bytes(&self) -> Vec<u8> {
        self.identifier.serialize()
    }

    pub fn encode(&self) -> Result<String, FrostError> {
        let pkg = self
            .package
            .serialize()
            .map_err(|e| FrostError::Protocol(e.to_string()))?;
        Ok(format!(
            "{}:{}",
            hex::encode(self.identifier.serialize()),
            hex::encode(pkg)
        ))
    }

    pub fn decode(s: &str) -> Result<Self, FrostError> {
        let (id_hex, pkg_hex) = s.split_once(':').ok_or_else(|| FrostError::Protocol("seat".into()))?;
        let id_b = hex::decode(id_hex).map_err(|e| FrostError::Protocol(e.to_string()))?;
        let pkg_b = hex::decode(pkg_hex).map_err(|e| FrostError::Protocol(e.to_string()))?;
        let identifier = Identifier::deserialize(&id_b).map_err(|e| FrostError::Protocol(e.to_string()))?;
        let package = KeyPackage::deserialize(&pkg_b).map_err(|e| FrostError::Protocol(e.to_string()))?;
        Ok(Self { identifier, package })
    }
}

/// Threshold verifying group. Product construction is DKG `from_key_packages`.
#[derive(Clone)]
pub struct FrostGroup {
    pub min_signers: u16,
    pub max_signers: u16,
    pub verifying_key: [u8; 32],
    packages: Vec<(Identifier, KeyPackage)>,
    pubkeys: PublicKeyPackage,
    /// True iff constructed by [`Self::dealer`]. Product custody rejects this.
    dealer_issued: bool,
}

impl std::fmt::Debug for FrostGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrostGroup")
            .field("min_signers", &self.min_signers)
            .field("max_signers", &self.max_signers)
            .field("dealer_issued", &self.dealer_issued)
            .finish()
    }
}

impl FrostGroup {
    /// Trusted-dealer keygen (`generate_with_dealer`). Negative-control only.
    /// Product pools: `frost_dkg::dkg_escrow_seats` / `EscrowHolders::from_dkg`.
    pub fn dealer(max_signers: u16, min_signers: u16) -> Result<Self, FrostError> {
        let mut rng = OsRng;
        let (shares, pubkeys) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            IdentifierList::Default,
            &mut rng,
        )
        .map_err(|e| FrostError::Protocol(e.to_string()))?;
        let vk = pubkeys
            .verifying_key()
            .serialize()
            .map_err(|e| FrostError::Protocol(e.to_string()))?;
        let mut verifying_key = [0u8; 32];
        verifying_key.copy_from_slice(&vk);
        let packages: Vec<_> = shares
            .into_iter()
            .map(|(id, secret)| {
                (
                    id,
                    KeyPackage::try_from(secret).expect("dealer share to key package"),
                )
            })
            .collect();
        Ok(Self {
            min_signers,
            max_signers,
            verifying_key,
            packages,
            pubkeys,
            dealer_issued: true,
        })
    }

    /// Named negative-control origin. Product pools are [`Self::from_key_packages`].
    pub fn is_dealer(&self) -> bool {
        self.dealer_issued
    }

    /// Assemble a group from DKG `part3` outputs (no trusted dealer).
    pub fn from_key_packages(
        min_signers: u16,
        max_signers: u16,
        packages: Vec<(Identifier, KeyPackage)>,
        pubkeys: PublicKeyPackage,
    ) -> Result<Self, FrostError> {
        let vk = pubkeys
            .verifying_key()
            .serialize()
            .map_err(|e| FrostError::Protocol(e.to_string()))?;
        let mut verifying_key = [0u8; 32];
        verifying_key.copy_from_slice(&vk);
        Ok(Self {
            min_signers,
            max_signers,
            verifying_key,
            packages,
            pubkeys,
            dealer_issued: false,
        })
    }

    pub fn spend_message(group_id: &[u8; 32], note: &[u8; 32], amount_zat: u64) -> [u8; 32] {
        tagged_hash(
            b"frost-spend-v1",
            &[group_id, note, &amount_zat.to_le_bytes()],
        )
    }

    pub fn public_keys(&self) -> &PublicKeyPackage {
        &self.pubkeys
    }

    pub fn remaining_shares(&self) -> usize {
        self.packages.len()
    }

    /// Clone retained KeyPackages as seats. Product `dkg_escrow_seats` groups hold none.
    pub fn seats(&self) -> Vec<FrostSeat> {
        self.packages
            .iter()
            .map(|(id, kp)| FrostSeat {
                identifier: *id,
                package: kp.clone(),
            })
            .collect()
    }

    /// Move retained KeyPackages out. After this, `sign()` fails; use `sign_with_seats`.
    pub fn issue_seats(&mut self) -> Vec<FrostSeat> {
        self.packages
            .drain(..)
            .map(|(id, package)| FrostSeat { identifier: id, package })
            .collect()
    }

    pub fn take_seat(&mut self, i: usize) -> Option<FrostSeat> {
        if i >= self.packages.len() {
            return None;
        }
        let (id, package) = self.packages.remove(i);
        Some(FrostSeat { identifier: id, package })
    }

    /// Sign using only `seats`. Threshold still applies. Uses this group's `pubkeys`.
    pub fn sign_with_seats(&self, msg: &[u8], seats: &[FrostSeat]) -> Result<Vec<u8>, FrostError> {
        if (seats.len() as u16) < self.min_signers {
            return Err(FrostError::BelowThreshold {
                have: seats.len() as u16,
                need: self.min_signers,
            });
        }
        let mut rng = OsRng;
        let mut commitments = BTreeMap::new();
        let mut nonces = BTreeMap::new();
        for seat in seats {
            let (n, c) = round1::commit(seat.package.signing_share(), &mut rng);
            commitments.insert(seat.identifier, c);
            nonces.insert(seat.identifier, n);
        }
        let pkg = SigningPackage::new(commitments, msg);
        let mut shares = BTreeMap::new();
        for seat in seats {
            let n = nonces
                .get(&seat.identifier)
                .ok_or_else(|| FrostError::Protocol("nonce".into()))?;
            let sh = round2::sign(&pkg, n, &seat.package)
                .map_err(|e| FrostError::Protocol(e.to_string()))?;
            shares.insert(seat.identifier, sh);
        }
        let sig = frost::aggregate(&pkg, &shares, &self.pubkeys)
            .map_err(|e| FrostError::Protocol(e.to_string()))?;
        sig.serialize()
            .map_err(|e| FrostError::Protocol(e.to_string()))
    }

    /// Sign from retained KeyPackages. Product DKG groups return [`FrostError::SeatsIssued`].
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, FrostError> {
        if self.packages.is_empty() {
            return Err(FrostError::SeatsIssued);
        }
        let seats = self.seats();
        let n = self.min_signers as usize;
        if seats.len() < n {
            return Err(FrostError::BelowThreshold {
                have: seats.len() as u16,
                need: self.min_signers,
            });
        }
        self.sign_with_seats(msg, &seats[..n])
    }

    pub fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> Result<(), FrostError> {
        let sig = frost::Signature::deserialize(sig_bytes)
            .map_err(|_| FrostError::Verify)?;
        self.pubkeys
            .verifying_key()
            .verify(msg, &sig)
            .map_err(|_| FrostError::Verify)
    }
}
