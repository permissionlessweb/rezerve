//! CosmWasm-shaped IBC v2 packet store. Not a live chain or ICS-04 light client.

use crate::zap1::IbcV2PacketAttest;
use std::collections::BTreeMap;
use thiserror::Error;

/// Packet type stored by the module (same fields as the ZAP1 attest).
pub type IbcV2Packet = IbcV2PacketAttest;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IbcModuleError {
    #[error("unknown packet")]
    Unknown,
    #[error("tampered packet")]
    Tampered,
    #[error("duplicate sequence")]
    Duplicate,
}

/// In-memory module: commitments keyed by (source_client, dest_client, sequence).
#[derive(Debug, Clone, Default)]
pub struct IbcV2Module {
    commitments: BTreeMap<(String, String, u64), [u8; 32]>,
}

impl IbcV2Module {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn commit_packet(&mut self, packet: &IbcV2Packet) -> Result<[u8; 32], IbcModuleError> {
        let key = (
            packet.source_client.clone(),
            packet.dest_client.clone(),
            packet.sequence,
        );
        if self.commitments.contains_key(&key) {
            return Err(IbcModuleError::Duplicate);
        }
        let c = packet.packet_commitment();
        self.commitments.insert(key, c);
        Ok(c)
    }

    pub fn query_packet(
        &self,
        source_client: &str,
        dest_client: &str,
        sequence: u64,
    ) -> Option<[u8; 32]> {
        self.commitments
            .get(&(
                source_client.to_string(),
                dest_client.to_string(),
                sequence,
            ))
            .copied()
    }

    pub fn verify_packet(&self, packet: &IbcV2Packet) -> Result<(), IbcModuleError> {
        match self.query_packet(&packet.source_client, &packet.dest_client, packet.sequence)
        {
            None => Err(IbcModuleError::Unknown),
            Some(stored) if stored != packet.packet_commitment() => Err(IbcModuleError::Tampered),
            Some(_) => Ok(()),
        }
    }
}
