//! Write Pasta store-full-circuit files + HOSTING_PAYMENT proof for live attach.
//! Frost matches `run_live_attach_bin` (`tagged_hash(b"g", &[b"zap1-live"])`).

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/pir-halo2".into());
    let frost = private_inference_rent::tagged_hash(b"g", &[b"zap1-live"]);
    if let Err(e) = run(&dir, &frost) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run(dir: &str, frost: &[u8; 32]) -> Result<(), String> {
    let p = std::path::Path::new(dir);
    hosting_payment::write_store_full_circuit_files(p)?;
    let proof = hosting_payment::prove_inclusion("PIR-LC-LIVE", "sib", frost, 11)?;
    let inst = hosting_payment::encode_instances("PIR-LC-LIVE", "sib", frost, 11);
    std::fs::write(p.join("proof.bin"), &proof).map_err(|e| e.to_string())?;
    std::fs::write(p.join("instances.bin"), &inst).map_err(|e| e.to_string())?;
    std::fs::write(p.join("frost.hex"), hex::encode(frost)).map_err(|e| e.to_string())?;
    println!(
        "wrote {dir} proof={} instances={}",
        proof.len(),
        inst.len()
    );
    Ok(())
}
