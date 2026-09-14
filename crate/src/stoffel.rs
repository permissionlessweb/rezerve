//! Stoffel CLI local-MPC confirm. HoneyBadger 0.1 has no secret CMP, so limbs are opened.

use crate::tagged_hash;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoffelError {
    #[error("stoffel CLI not found (https://docs.stoffelmpc.com/getting-started/installation)")]
    CliMissing,
    #[error("stoffel project missing at {0}")]
    ProjectMissing(String),
    #[error("stoffel run failed: {0}")]
    Run(String),
    #[error("digest mismatch under Stoffel local MPC")]
    DigestMismatch,
}

pub fn stoffel_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("STOFFEL_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if Command::new("stoffel").arg("--version").output().ok()?.status.success() {
        return Some(PathBuf::from("stoffel"));
    }
    let home = std::env::var("HOME").ok()?;
    let fallback = PathBuf::from(home).join(".local/bin/stoffel");
    fallback.is_file().then_some(fallback)
}

pub fn attest_project_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("stoffel/attest")
}

pub fn digest_limbs(digest: &[u8; 32]) -> [i64; 4] {
    let mut out = [0i64; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let start = i * 8;
        let mut b = [0u8; 8];
        b.copy_from_slice(&digest[start..start + 8]);
        *slot = i64::from_le_bytes(b);
    }
    out
}

fn fmt_limbs(l: &[i64; 4]) -> String {
    format!("{},{},{},{}", l[0], l[1], l[2], l[3])
}

/// Local MPC confirm. Returns a tag to bind on-chain on match.
pub fn confirm_digest(expected: &[u8; 32], got: &[u8; 32]) -> Result<[u8; 32], StoffelError> {
    let bin = stoffel_bin().ok_or(StoffelError::CliMissing)?;
    let project = attest_project_dir();
    if !project.join("src/main.stfl").is_file() {
        return Err(StoffelError::ProjectMissing(project.display().to_string()));
    }
    let e = fmt_limbs(&digest_limbs(expected));
    let g = fmt_limbs(&digest_limbs(got));
    let output = Command::new(&bin)
        .current_dir(&project)
        .args([
            "run",
            "--client-input",
            &format!("0={e}"),
            "--client-input",
            &format!("1={g}"),
            "--parties",
            "5",
            "--threshold",
            "1",
        ])
        .output()
        .map_err(|err| StoffelError::Run(err.to_string()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(StoffelError::Run(format!(
            "status={} stderr={} stdout={}",
            output.status,
            stderr.chars().take(400).collect::<String>(),
            stdout.chars().take(200).collect::<String>()
        )));
    }
    let last = stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    match last {
        "1" => Ok(tagged_hash(b"stoffel-confirm-v1", &[expected, got])),
        "0" => Err(StoffelError::DigestMismatch),
        other => Err(StoffelError::Run(format!("unexpected output last line: {other}"))),
    }
}

pub fn available() -> bool {
    stoffel_bin().is_some() && Path::new(&attest_project_dir()).join("src/main.stfl").is_file()
}
