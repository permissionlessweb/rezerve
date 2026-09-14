//! Tenant/provider as OS processes holding a session key.

use crate::bid::{BidError, EncryptedBidEnvelope, PlaintextBid};
use std::io::Write;
use std::process::{Command, Stdio};

fn party_bin() -> Result<std::path::PathBuf, BidError> {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_pir-party") {
        return Ok(p.into());
    }
    let exe = std::env::current_exe().map_err(|_| BidError::Rng)?;
    let sib = exe.with_file_name("pir-party");
    if sib.is_file() {
        return Ok(sib);
    }
    Err(BidError::Rng)
}

pub fn process_seal(bid: &PlaintextBid, session_key: &[u8; 32]) -> Result<EncryptedBidEnvelope, BidError> {
    let bin = party_bin()?;
    let mut child = Command::new(bin)
        .arg("seal")
        .arg(hex::encode(session_key))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| BidError::Rng)?;
    {
        let mut stdin = child.stdin.take().ok_or(BidError::Rng)?;
        stdin
            .write_all(&serde_json::to_vec(bid).map_err(|_| BidError::Serialize)?)
            .map_err(|_| BidError::Rng)?;
    }
    let out = child.wait_with_output().map_err(|_| BidError::Rng)?;
    if !out.status.success() {
        return Err(BidError::Auth);
    }
    serde_json::from_slice(&out.stdout).map_err(|_| BidError::Serialize)
}

pub fn process_open(env: &EncryptedBidEnvelope, session_key: &[u8; 32]) -> Result<PlaintextBid, BidError> {
    let bin = party_bin()?;
    let mut child = Command::new(bin)
        .arg("open")
        .arg(hex::encode(session_key))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| BidError::Rng)?;
    {
        let mut stdin = child.stdin.take().ok_or(BidError::Rng)?;
        stdin
            .write_all(&serde_json::to_vec(env).map_err(|_| BidError::Serialize)?)
            .map_err(|_| BidError::Rng)?;
    }
    let out = child.wait_with_output().map_err(|_| BidError::Rng)?;
    if !out.status.success() {
        return Err(BidError::Auth);
    }
    serde_json::from_slice(&out.stdout).map_err(|_| BidError::Decrypt)
}
