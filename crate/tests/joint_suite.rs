//! Joint PIR + DEX + Zakura catalog. Both suites can share one Zcash attach.

use private_inference_rent::zakura::{seam_private_dex_dir, ZakuraRegtest};

#[test]
fn joint_catalog_names_both_suites() {
    let pir = env!("CARGO_MANIFEST_DIR");
    assert!(std::path::Path::new(pir).join("tests/product_path.rs").is_file());
    assert!(std::path::Path::new(pir).join("tests/frost_ed25519.rs").is_file());
    if let Some(dex) = seam_private_dex_dir() {
        assert!(dex.join("Cargo.toml").is_file());
    }
}

#[test]
fn joint_zcash_attach_is_optional_shared_handle() {
    let rpc = ZakuraRegtest::discover();
    let compose = ZakuraRegtest::compose_file();
    // Shared env: ZAKURA_RPC. DEX and PIR both read it.
    if rpc.is_none() && compose.is_none() {
        eprintln!("joint suite: no Zakura sibling or ZAKURA_RPC; PIR-only catalog still valid");
    }
}
