//! Access material for a rented resource, derived from the OOB AEAD key.
//!
//! Public Akash uses an **ES256K** (secp256k1) JWT and historically **mTLS
//! certs** (`ergors` jwt-verify + certificate workflow; `o-line` lease WSS + JWT).
//! This crate does **not** mint those. This module derives a 32-byte access secret
//! from the same key the bid was sealed with + the bid commitment, so a forked
//! provider can later issue JWT/mTLS from that secret instead of the public
//! account key.
//!
//! [`DerivedAccess::bearer_hex`] is stable for the lease and re-links sessions.
//! Session auth uses [`SessionAccess`]: the same out-of-band key plus a session
//! nonce. Rotating or stopping the session drops the old bearer. The note
//! (`bid_commitment`) stays put. The nonce is not a renter id.

use crate::tagged_hash;
use serde::{Deserialize, Serialize};

/// Domain tags — do not reuse bid-seal or frost-spend tags.
const TAG_ACCESS: &[u8] = b"pir-access-v1";
const TAG_BEARER: &[u8] = b"pir-access-bearer-v1";
const TAG_SESSION: &[u8] = b"pir-access-session-v1";
const TAG_SESSION_BEARER: &[u8] = b"pir-access-session-bearer-v1";

/// Derived access for one winning bid / lease binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedAccess {
    pub ask_id: String,
    pub bid_commitment: [u8; 32],
    /// 32-byte secret. Not a JWT. Not an mTLS cert. Not a session bearer.
    pub secret: [u8; 32],
}

/// One workload session. The payment note is not this bearer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAccess {
    pub ask_id: String,
    /// Bid commitment. Unchanged when `session_nonce` rotates.
    pub note: [u8; 32],
    pub session_nonce: [u8; 32],
    /// 32-byte session secret. Not [`DerivedAccess::secret`].
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

    /// Lease-long hex. Stable for this note, so it re-links sessions.
    /// Session HTTP auth uses [`SessionAccess::bearer_hex`] instead.
    pub fn bearer_hex(&self) -> String {
        hex::encode(tagged_hash(TAG_BEARER, &[&self.secret]))
    }

    pub fn verify_bearer_hex(&self, presented: &str) -> bool {
        presented == self.bearer_hex()
    }

    /// Session capability from this note and the same OOB key, plus `session_nonce`.
    /// Wrong key returns `None`. Does not change `bid_commitment`.
    pub fn open_session(
        &self,
        oob_key: &[u8; 32],
        session_nonce: &[u8; 32],
    ) -> Option<SessionAccess> {
        let bound = Self::from_session(&self.ask_id, oob_key, &self.bid_commitment);
        if bound.secret != self.secret {
            return None;
        }
        Some(SessionAccess::derive(
            &self.ask_id,
            oob_key,
            &self.bid_commitment,
            session_nonce,
        ))
    }
}

impl SessionAccess {
    /// `oob_key` is the out-of-band ChaCha20-Poly1305 key. `note` is the bid
    /// commitment and is not rewritten by a new nonce. Nonce is not a renter id.
    pub fn derive(
        ask_id: impl Into<String>,
        oob_key: &[u8; 32],
        note: &[u8; 32],
        session_nonce: &[u8; 32],
    ) -> Self {
        let ask_id = ask_id.into();
        let secret = tagged_hash(
            TAG_SESSION,
            &[oob_key, note, ask_id.as_bytes(), session_nonce],
        );
        Self {
            ask_id,
            note: *note,
            session_nonce: *session_nonce,
            secret,
        }
    }

    /// Hex for `Authorization: Bearer` on this session only. Not ES256K.
    pub fn bearer_hex(&self) -> String {
        hex::encode(tagged_hash(TAG_SESSION_BEARER, &[&self.secret]))
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
    /// lease_id → current session. Note is stable; bearer is not.
    sessions: std::collections::BTreeMap<String, SessionSlot>,
}

#[derive(Debug, Clone)]
struct SessionSlot {
    note: [u8; 32],
    /// `None` after stop. The previous bearer is dropped.
    bearer: Option<String>,
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

    /// Record the winning lease. The lease-long bearer is not an HTTP credential.
    /// Workload open uses [`Self::open_session`] and [`Self::access`].
    pub fn accept_bid(&mut self, lease_id: impl Into<String>, winner_bearer: String) {
        self.leases.insert(lease_id.into(), (winner_bearer, true));
    }

    /// Admit the lease bearer (existing path) or the current session bearer.
    /// Session rotation drops only the previous session bearer.
    pub fn access(&self, lease_id: &str, bearer: &str) -> Result<(), LeaseAccessError> {
        match self.leases.get(lease_id) {
            Some((_, false)) => Err(LeaseAccessError::Closed),
            Some((want, true)) if want == bearer => Ok(()),
            Some(_) | None => self.access_session(lease_id, bearer),
        }
    }

    /// Close the bid/lease and drop the session bearer.
    pub fn close(&mut self, lease_id: &str) -> Result<(), LeaseAccessError> {
        match self.leases.get_mut(lease_id) {
            None => Err(LeaseAccessError::UnknownLease),
            Some((_, open)) => {
                *open = false;
                if let Some(slot) = self.sessions.get_mut(lease_id) {
                    slot.bearer = None;
                }
                Ok(())
            }
        }
    }

    pub fn is_open(&self, lease_id: &str) -> bool {
        self.leases.get(lease_id).map(|(_, o)| *o).unwrap_or(false)
    }

    /// Open a session on `note`. A second open with the same note replaces the
    /// bearer. A different note is rejected so the payment note cannot be swapped.
    pub fn open_session(
        &mut self,
        lease_id: impl Into<String>,
        note: [u8; 32],
        bearer: String,
    ) -> Result<(), LeaseAccessError> {
        let lease_id = lease_id.into();
        if let Some(slot) = self.sessions.get_mut(&lease_id) {
            if slot.note != note {
                return Err(LeaseAccessError::Unauthorized);
            }
            slot.bearer = Some(bearer);
            return Ok(());
        }
        self.sessions.insert(
            lease_id,
            SessionSlot {
                note,
                bearer: Some(bearer),
            },
        );
        Ok(())
    }

    pub fn access_session(&self, lease_id: &str, bearer: &str) -> Result<(), LeaseAccessError> {
        match self.sessions.get(lease_id) {
            None => Err(LeaseAccessError::UnknownLease),
            Some(slot) => match slot.bearer.as_deref() {
                None => Err(LeaseAccessError::Closed),
                Some(want) if want == bearer => Ok(()),
                Some(_) => Err(LeaseAccessError::Unauthorized),
            },
        }
    }

    /// New session bearer. The stored note is returned unchanged. Old bearer fails `access_session`.
    pub fn rotate_session(
        &mut self,
        lease_id: &str,
        bearer: String,
    ) -> Result<[u8; 32], LeaseAccessError> {
        match self.sessions.get_mut(lease_id) {
            None => Err(LeaseAccessError::UnknownLease),
            Some(slot) => {
                slot.bearer = Some(bearer);
                Ok(slot.note)
            }
        }
    }

    /// Stop the session. The note stays. The current bearer is denied.
    pub fn stop_session(&mut self, lease_id: &str) -> Result<[u8; 32], LeaseAccessError> {
        match self.sessions.get_mut(lease_id) {
            None => Err(LeaseAccessError::UnknownLease),
            Some(slot) => {
                slot.bearer = None;
                Ok(slot.note)
            }
        }
    }

    pub fn session_note(&self, lease_id: &str) -> Option<[u8; 32]> {
        self.sessions.get(lease_id).map(|slot| slot.note)
    }
}
