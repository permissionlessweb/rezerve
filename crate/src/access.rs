//! Access material for a rented resource, derived from the OOB AEAD key.
//!
//! Public Akash uses an **ES256K** (secp256k1) JWT and historically **mTLS
//! certs** (`ergors` jwt-verify + certificate workflow; `o-line` lease WSS + JWT).
//! This crate does **not** mint those. This module derives a 32-byte access secret
//! from the same key the bid was sealed with + the bid commitment, so a forked
//! provider can later issue JWT/mTLS from that secret instead of the public
//! account key.

use crate::tagged_hash;
use serde::{Deserialize, Serialize};

/// Domain tags — do not reuse bid-seal or frost-spend tags.
const TAG_ACCESS: &[u8] = b"pir-access-v1";
const TAG_BEARER: &[u8] = b"pir-access-bearer-v1";

/// Derived access for one winning bid / lease binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedAccess {
    pub ask_id: String,
    pub bid_commitment: [u8; 32],
    /// 32-byte secret. Not a JWT. Not an mTLS cert.
    pub secret: [u8; 32],
}

impl DerivedAccess {
    /// `session_key` is the out-of-band ChaCha20-Poly1305 key. Loser keys must not reproduce this.
    pub fn from_session(
        ask_id: impl Into<String>,
        session_key: &[u8; 32],
        bid_commitment: &[u8; 32],
    ) -> Self {
        let ask_id = ask_id.into();
        let secret = tagged_hash(
            TAG_ACCESS,
            &[session_key, bid_commitment, ask_id.as_bytes()],
        );
        Self {
            ask_id,
            bid_commitment: *bid_commitment,
            secret,
        }
    }

    /// Hex bearer for HTTP `Authorization: Bearer`. Not ES256K.
    pub fn bearer_hex(&self) -> String {
        hex::encode(tagged_hash(TAG_BEARER, &[&self.secret]))
    }

    pub fn verify_bearer_hex(&self, presented: &str) -> bool {
        presented == self.bearer_hex()
    }
}

/// In-process provider lease engine (same rules as `akash-provider-pir` PIR bearer).
#[derive(Debug, Default)]
pub struct LeaseBook {
    /// lease_id → (winner bearer, open)
    leases: std::collections::BTreeMap<String, (String, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseAccessError {
    UnknownLease,
    Closed,
    Unauthorized,
}

impl LeaseBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a winning bid: open a deployment for this bearer only.
    pub fn accept_bid(&mut self, lease_id: impl Into<String>, winner_bearer: String) {
        self.leases.insert(lease_id.into(), (winner_bearer, true));
    }

    pub fn access(&self, lease_id: &str, bearer: &str) -> Result<(), LeaseAccessError> {
        match self.leases.get(lease_id) {
            None => Err(LeaseAccessError::UnknownLease),
            Some((_, false)) => Err(LeaseAccessError::Closed),
            Some((want, true)) if want == bearer => Ok(()),
            Some(_) => Err(LeaseAccessError::Unauthorized),
        }
    }

    /// Close the bid/lease. Further access fails even with the winner key.
    pub fn close(&mut self, lease_id: &str) -> Result<(), LeaseAccessError> {
        match self.leases.get_mut(lease_id) {
            None => Err(LeaseAccessError::UnknownLease),
            Some((_, open)) => {
                *open = false;
                Ok(())
            }
        }
    }

    pub fn is_open(&self, lease_id: &str) -> bool {
        self.leases.get(lease_id).map(|(_, o)| *o).unwrap_or(false)
    }
}
