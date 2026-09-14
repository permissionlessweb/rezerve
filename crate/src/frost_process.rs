//! FROST signing via one OS process per seat. Parent never loads KeyPackages
//! after spawn (only identifiers + commitments + shares).

use crate::frost::{FrostError, FrostGroup, FrostSeat};
use frost_ed25519 as frost;
use frost_ed25519::{round1, Identifier, SigningPackage};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn holder_bin() -> Result<std::path::PathBuf, FrostError> {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_pir-frost-holder") {
        return Ok(p.into());
    }
    let exe = std::env::current_exe().map_err(|e| FrostError::Protocol(e.to_string()))?;
    let sib = exe.with_file_name("pir-frost-holder");
    if sib.is_file() {
        return Ok(sib);
    }
    Err(FrostError::Protocol("pir-frost-holder binary not found".into()))
}

/// Sign by spawning one `pir-frost-holder` process per seat.
pub fn sign_with_os_holders(
    group: &FrostGroup,
    msg: &[u8],
    seats: &[FrostSeat],
) -> Result<Vec<u8>, FrostError> {
    if (seats.len() as u16) < group.min_signers {
        return Err(FrostError::BelowThreshold {
            have: seats.len() as u16,
            need: group.min_signers,
        });
    }
    let bin = holder_bin()?;
    let need = group.min_signers as usize;
    let encoded: Vec<String> = seats
        .iter()
        .take(need)
        .map(|s| s.encode())
        .collect::<Result<_, _>>()?;
    let ids: Vec<Identifier> = encoded
        .iter()
        .map(|e| {
            let idh = e.split(':').next().unwrap();
            let b = hex::decode(idh).map_err(|e| FrostError::Protocol(e.to_string()))?;
            Identifier::deserialize(&b).map_err(|e| FrostError::Protocol(e.to_string()))
        })
        .collect::<Result<_, _>>()?;

    let mut kids = Vec::new();
    for enc in &encoded {
        let child = Command::new(&bin)
            .arg(enc)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| FrostError::Protocol(e.to_string()))?;
        kids.push(child);
    }

    let mut commits = BTreeMap::new();
    let mut stdins = Vec::new();
    let mut stdouts = Vec::new();
    for kid in &mut kids {
        stdins.push(kid.stdin.take().ok_or_else(|| FrostError::Protocol("stdin".into()))?);
        stdouts.push(BufReader::new(
            kid.stdout.take().ok_or_else(|| FrostError::Protocol("stdout".into()))?,
        ));
    }
    for (i, stdin) in stdins.iter_mut().enumerate() {
        stdin
            .write_all(b"COMMIT\n")
            .map_err(|e| FrostError::Protocol(e.to_string()))?;
        stdin.flush().map_err(|e| FrostError::Protocol(e.to_string()))?;
        let mut line = String::new();
        stdouts[i]
            .read_line(&mut line)
            .map_err(|e| FrostError::Protocol(e.to_string()))?;
        let hex_c = line
            .trim()
            .strip_prefix("C ")
            .ok_or_else(|| FrostError::Protocol(format!("commit: {line}")))?;
        let c = round1::SigningCommitments::deserialize(
            &hex::decode(hex_c).map_err(|e| FrostError::Protocol(e.to_string()))?,
        )
        .map_err(|e| FrostError::Protocol(e.to_string()))?;
        commits.insert(ids[i], c);
    }

    let mut commit_parts = Vec::new();
    for (id, c) in &commits {
        let cb = c.serialize().map_err(|e| FrostError::Protocol(e.to_string()))?;
        commit_parts.push(format!("{}:{}", hex::encode(id.serialize()), hex::encode(cb)));
    }
    let sign_line = format!("SIGN {} {}\n", hex::encode(msg), commit_parts.join(","));
    let mut shares = BTreeMap::new();
    for (i, stdin) in stdins.iter_mut().enumerate() {
        stdin
            .write_all(sign_line.as_bytes())
            .map_err(|e| FrostError::Protocol(e.to_string()))?;
        stdin.flush().map_err(|e| FrostError::Protocol(e.to_string()))?;
        let mut line = String::new();
        stdouts[i]
            .read_line(&mut line)
            .map_err(|e| FrostError::Protocol(e.to_string()))?;
        let hex_s = line
            .trim()
            .strip_prefix("S ")
            .ok_or_else(|| FrostError::Protocol(format!("share: {line}")))?;
        let sh = frost::round2::SignatureShare::deserialize(
            &hex::decode(hex_s).map_err(|e| FrostError::Protocol(e.to_string()))?,
        )
        .map_err(|e| FrostError::Protocol(e.to_string()))?;
        shares.insert(ids[i], sh);
    }
    for stdin in &mut stdins {
        let _ = stdin.write_all(b"QUIT\n");
    }
    drop(stdins);
    drop(stdouts);
    for mut kid in kids {
        let _ = kid.wait();
    }

    let pkg = SigningPackage::new(commits, msg);
    let sig = frost::aggregate(&pkg, &shares, group.public_keys())
        .map_err(|e| FrostError::Protocol(e.to_string()))?;
    let raw = sig
        .serialize()
        .map_err(|e| FrostError::Protocol(e.to_string()))?;
    group.verify(msg, &raw)?;
    Ok(raw)
}
