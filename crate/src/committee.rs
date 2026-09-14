//! Two-layer t-of-n committees (in-memory). Inner seats are hashed into
//! `committee_id`; outer ids bind inner ids plus the pool `group_id`.

use crate::dregg::FrostSignerInstance;
use crate::steoffle::{SteoffleAttestation, SteoffleError, SteoffleMpc};
use crate::tagged_hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitteeError {
    #[error("threshold {threshold} exceeds n={n}")]
    BadParams { threshold: u16, n: u16 },
    #[error("empty committee")]
    Empty,
    #[error("unknown member {0}")]
    UnknownMember(String),
    #[error("below threshold: have {have}, need {need}")]
    BelowThreshold { have: u16, need: u16 },
    #[error("duplicate participant {0}")]
    Duplicate(String),
    #[error("steoffle: {0}")]
    Steoffle(#[from] SteoffleError),
    #[error("inner committee failed: {0}")]
    Inner(String),
    #[error("quorum digest mismatch")]
    DigestMismatch,
    #[error("committee not bound to a pool group")]
    UnboundGroup,
    #[error("signer instance: {0}")]
    Signer(#[from] crate::dregg::SignerInstanceError),
    #[error("spend auth must bind note and amount")]
    UnboundSpend,
    #[error("spend auth group mismatch")]
    SpendGroup,
    #[error("spend auth note mismatch")]
    SpendNote,
    #[error("spend auth amount mismatch")]
    SpendAmount,
    #[error("frost signature required")]
    FrostRequired,
    #[error("frost signature verify failed")]
    FrostVerify,
}

/// One inner-layer FROST signer plus its Steoffle attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerSeat {
    pub label: String,
    pub signer: FrostSignerInstance,
    pub attestation: SteoffleAttestation,
}

impl SignerSeat {
    pub fn enroll(label: impl Into<String>, signer: FrostSignerInstance) -> Result<Self, CommitteeError> {
        let attestation = SteoffleMpc::attest(&signer)?;
        Ok(Self {
            label: label.into(),
            signer,
            attestation,
        })
    }
}

/// Inner FROST committee: t-of-n in-process signer labels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerCommittee {
    pub committee_id: [u8; 32],
    pub label: String,
    pub threshold: u16,
    pub seats: Vec<SignerSeat>,
}

impl InnerCommittee {
    pub fn form(
        label: impl Into<String>,
        threshold: u16,
        seats: Vec<SignerSeat>,
    ) -> Result<Self, CommitteeError> {
        let label = label.into();
        let n = seats.len() as u16;
        if n == 0 {
            return Err(CommitteeError::Empty);
        }
        if threshold == 0 || threshold > n {
            return Err(CommitteeError::BadParams { threshold, n });
        }
        let mut labels = std::collections::BTreeSet::new();
        let mut signer_ids = std::collections::BTreeSet::new();
        let mut instance_ids = std::collections::BTreeSet::new();
        for s in &seats {
            if !labels.insert(s.label.as_str()) {
                return Err(CommitteeError::Duplicate(s.label.clone()));
            }
            if !signer_ids.insert(s.signer.signer_id) {
                return Err(CommitteeError::Duplicate(hex::encode(s.signer.signer_id)));
            }
            if !instance_ids.insert(s.signer.instance_id) {
                return Err(CommitteeError::Duplicate(hex::encode(s.signer.instance_id)));
            }
            SteoffleMpc::verify(&s.signer, &s.attestation)?;
        }
        let committee_id = inner_committee_id(&label, threshold, n, &seats);
        Ok(Self {
            committee_id,
            label,
            threshold,
            seats,
        })
    }

    pub fn n(&self) -> u16 {
        self.seats.len() as u16
    }

    /// Collect a quorum of named inner signers. Each must still verify Steoffle.
    pub fn quorum(&self, participants: &[&str]) -> Result<InnerQuorum, CommitteeError> {
        let mut unique = Vec::new();
        let mut seen_labels = std::collections::BTreeSet::new();
        let mut seen_signers = std::collections::BTreeSet::new();
        for p in participants {
            if !seen_labels.insert(*p) {
                return Err(CommitteeError::Duplicate((*p).into()));
            }
            let seat = self
                .seats
                .iter()
                .find(|s| s.label == *p)
                .ok_or_else(|| CommitteeError::UnknownMember((*p).into()))?;
            if !seen_signers.insert(seat.signer.signer_id) {
                return Err(CommitteeError::Duplicate(hex::encode(seat.signer.signer_id)));
            }
            SteoffleMpc::verify(&seat.signer, &seat.attestation)?;
            unique.push(seat.label.clone());
        }
        let have = unique.len() as u16;
        if have < self.threshold {
            return Err(CommitteeError::BelowThreshold {
                have,
                need: self.threshold,
            });
        }
        let digest = tagged_hash(
            b"frost-inner-quorum-v1",
            &{
                let mut parts: Vec<&[u8]> = vec![&self.committee_id];
                for u in &unique {
                    parts.push(u.as_bytes());
                }
                parts
            },
        );
        Ok(InnerQuorum {
            committee_id: self.committee_id,
            label: self.label.clone(),
            participants: unique,
            digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerQuorum {
    pub committee_id: [u8; 32],
    pub label: String,
    pub participants: Vec<String>,
    pub digest: [u8; 32],
}

/// Outer committee: t-of-n inner committees (threshold of thresholds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterCommittee {
    pub committee_id: [u8; 32],
    pub label: String,
    pub threshold: u16,
    pub group_id: Option<[u8; 32]>,
    pub inners: Vec<InnerCommittee>,
}

impl OuterCommittee {
    pub fn form(
        label: impl Into<String>,
        threshold: u16,
        inners: Vec<InnerCommittee>,
    ) -> Result<Self, CommitteeError> {
        let label = label.into();
        let n = inners.len() as u16;
        if n == 0 {
            return Err(CommitteeError::Empty);
        }
        if threshold == 0 || threshold > n {
            return Err(CommitteeError::BadParams { threshold, n });
        }
        let mut seen = std::collections::BTreeSet::new();
        for inner in &inners {
            if !seen.insert(inner.label.as_str()) {
                return Err(CommitteeError::Duplicate(inner.label.clone()));
            }
        }
        let committee_id = outer_committee_id(&label, threshold, n, None, &inners);
        Ok(Self {
            committee_id,
            label,
            threshold,
            group_id: None,
            inners,
        })
    }

    /// Bind this outer committee to a pool `group_id` (recomputes `committee_id`).
    pub fn bind_pool(mut self, group_id: [u8; 32]) -> Self {
        self.group_id = Some(group_id);
        self.committee_id = outer_committee_id(
            &self.label,
            self.threshold,
            self.n(),
            self.group_id.as_ref(),
            &self.inners,
        );
        self
    }

    pub fn n(&self) -> u16 {
        self.inners.len() as u16
    }

    /// Each outer seat is an inner committee. `parts` maps inner label → participant labels.
    pub fn quorum(
        &self,
        parts: &[(&str, &[&str])],
    ) -> Result<LayeredQuorum, CommitteeError> {
        let mut inner_quorums = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for (inner_label, members) in parts {
            if !seen.insert(*inner_label) {
                return Err(CommitteeError::Duplicate((*inner_label).into()));
            }
            let inner = self
                .inners
                .iter()
                .find(|i| i.label == *inner_label)
                .ok_or_else(|| CommitteeError::UnknownMember((*inner_label).into()))?;
            let q = inner
                .quorum(members)
                .map_err(|e| CommitteeError::Inner(format!("{}: {e}", inner.label)))?;
            inner_quorums.push(q);
        }
        let have = inner_quorums.len() as u16;
        if have < self.threshold {
            return Err(CommitteeError::BelowThreshold {
                have,
                need: self.threshold,
            });
        }
        let digest = tagged_hash(
            b"frost-layered-quorum-v1",
            &{
                let mut acc: Vec<&[u8]> = vec![&self.committee_id];
                for q in &inner_quorums {
                    acc.push(&q.digest);
                }
                acc
            },
        );
        let group_id = match self.group_id {
            Some(g) if g != [0u8; 32] => g,
            _ => return Err(CommitteeError::UnboundGroup),
        };
        Ok(LayeredQuorum {
            outer_id: self.committee_id,
            group_id,
            inner_quorums,
            digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayeredQuorum {
    pub outer_id: [u8; 32],
    pub group_id: [u8; 32],
    pub inner_quorums: Vec<InnerQuorum>,
    pub digest: [u8; 32],
}

fn inner_committee_id(label: &str, threshold: u16, n: u16, seats: &[SignerSeat]) -> [u8; 32] {
    let mut ids: Vec<[u8; 32]> = seats.iter().map(|s| s.signer.signer_id).collect();
    ids.sort_unstable();
    let t = threshold.to_le_bytes();
    let nn = n.to_le_bytes();
    let mut parts: Vec<&[u8]> = vec![label.as_bytes(), &t, &nn];
    for id in &ids {
        parts.push(id.as_slice());
    }
    tagged_hash(b"frost-inner-committee-v1", &parts)
}

fn outer_committee_id(
    label: &str,
    threshold: u16,
    n: u16,
    group_id: Option<&[u8; 32]>,
    inners: &[InnerCommittee],
) -> [u8; 32] {
    let mut ids: Vec<[u8; 32]> = inners.iter().map(|i| i.committee_id).collect();
    ids.sort_unstable();
    let t = threshold.to_le_bytes();
    let nn = n.to_le_bytes();
    let g = group_id.copied().unwrap_or([0u8; 32]);
    let mut parts: Vec<&[u8]> = vec![label.as_bytes(), &t, &nn, g.as_slice()];
    for id in &ids {
        parts.push(id.as_slice());
    }
    tagged_hash(b"frost-outer-committee-v1", &parts)
}

/// Demo factory: three inner 3-of-5 committees under an outer 2-of-3.
pub fn demo_layered_committees() -> Result<OuterCommittee, CommitteeError> {
    fn seat(committee: &str, idx: u8) -> Result<SignerSeat, CommitteeError> {
        let signer = FrostSignerInstance::new(
            tagged_hash(b"frost-signer", &[committee.as_bytes(), &[idx]]),
            tagged_hash(b"seat-instance", &[committee.as_bytes(), &[idx]]),
            vec![tagged_hash(b"dkg-commit", &[committee.as_bytes(), &[idx]])],
        )?;
        SignerSeat::enroll(format!("{committee}-s{idx}"), signer)
    }

    let mut inners = Vec::new();
    for (label, n) in [("alpha", 5u8), ("beta", 5u8), ("gamma", 5u8)] {
        let seats: Result<Vec<_>, _> = (0..n).map(|i| seat(label, i)).collect();
        inners.push(InnerCommittee::form(label, 3, seats?)?);
    }
    OuterCommittee::form("pool-guardians", 2, inners)
}
