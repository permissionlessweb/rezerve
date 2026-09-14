//! Write Pasta store-full-circuit files + a HOSTING_PAYMENT proof.
//!
//! Defaults match `pir-live-attach` live bundle: serial PIR-LC-LIVE, sibling
//! "sib", amount 11, frost = SHA-256(tag "g" || "zap1-live") via PIR
//! `tagged_hash`. Pass frost as 64-hex if you need a different group.
//!
//! Usage (lab only): `cargo run --bin export-halo2 -- /path/to/dir [frost_hex]`

use std::env;
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(env::args().nth(1).unwrap_or_else(|| "/tmp/pir-halo2".into()));
    let frost = env::args()
        .nth(2)
        .and_then(|s| {
            let t = s.trim().trim_start_matches("0x");
            if t.len() != 64 {
                return None;
            }
            let mut out = [0u8; 32];
            hex::decode_to_slice(t, &mut out).ok()?;
            Some(out)
        })
        .unwrap_or_else(hosting_payment::live_frost_group);
    if let Err(e) = run(&dir, &frost) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run(dir: &std::path::Path, frost: &[u8; 32]) -> Result<(), String> {
    hosting_payment::write_store_full_circuit_files(dir)?;
    let serial = hosting_payment::LIVE_SERIAL;
    let sibling = hosting_payment::LIVE_SIBLING;
    let amount = hosting_payment::LIVE_AMOUNT_ZAT;
    let proof = hosting_payment::prove_inclusion(serial, sibling, frost, amount)?;
    let inst = hosting_payment::encode_instances(serial, sibling, frost, amount);
    std::fs::write(dir.join("proof.bin"), &proof).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("instances.bin"), &inst).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("frost.hex"), hex::encode(frost)).map_err(|e| e.to_string())?;
    println!(
        "wrote {} params={} vk_body={} proof={} instances={}",
        dir.display(),
        dir.join("params.bin").metadata().map(|m| m.len()).unwrap_or(0),
        dir.join("vk_body.bin").metadata().map(|m| m.len()).unwrap_or(0),
        proof.len(),
        inst.len()
    );
    Ok(())
}
