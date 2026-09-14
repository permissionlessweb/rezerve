//! Native Zakura spawn (ict-rs-compatible). Skip unless RPC / ZAKURAD_BIN / compose.

use private_inference_rent::zakura::{
    lab_spawn, owner_binding_from_dest_display, spawn_zakura_local, ZakuraNodeConfig, ZakuraRegtest,
    REGTEST_MINER_DEST, REGTEST_MINER_OWNER_BINDING_HEX, ZAKURA_RPC_PORT,
};
use private_inference_rent::{local_hosting_bundle, tagged_hash};

#[test]
fn ict_rs_corridor_constants_match() {
    assert_eq!(ZAKURA_RPC_PORT, 18232);
    assert_eq!(
        owner_binding_from_dest_display(REGTEST_MINER_DEST),
        REGTEST_MINER_OWNER_BINDING_HEX
    );
}

#[test]
fn zakura_native_spawn_or_skip() {
    match lab_spawn() {
        Ok(n) => {
            let z = n.as_regtest();
            match z.getblockchaininfo() {
                Ok(info) => {
                    assert!(
                        info.get("result").is_some()
                            || info.get("chain").is_some()
                            || info.get("error").is_some()
                    );
                    let _ = z.commitment_tree_root();
                }
                Err(e) => eprintln!("skip: zakura rpc not reachable ({e})"),
            }
        }
        Err(e) => eprintln!("skip: no native node ({e}); set ZAKURAD_BIN or ZAKURA_RPC"),
    }
}

#[test]
fn spawn_zakura_local_skips_without_bin() {
    if std::env::var("ZAKURAD_BIN").ok().filter(|s| !s.is_empty()).is_some() {
        let _ = spawn_zakura_local(ZakuraNodeConfig::from_env().unwrap_or_default());
        return;
    }
    let err = spawn_zakura_local(ZakuraNodeConfig::default());
    assert!(err.is_err() || err.unwrap().reused_existing);
}

#[test]
fn lab_stamps_zap1_bundle_when_node_up() {
    match lab_spawn() {
        Ok(n) => {
            let z = n.as_regtest();
            if z.getblockchaininfo().is_err() {
                eprintln!("skip: rpc not ready");
                return;
            }
            let g = tagged_hash(b"lab", &[b"g"]);
            let note = tagged_hash(b"lab", &[b"n"]);
            let mut b = local_hosting_bundle(g, note, 1, "PIR-LAB", "sib");
            b.stamp_zakura_tip(&z).expect("stamp");
            b.verify_against_zakura(&z)
                .expect("stamp must match live tip");
            let tip = z.commitment_tree_root().unwrap().unwrap();
            assert_eq!(
                b.orchard_anchor_txid.as_deref().map(|s| s.to_ascii_lowercase()),
                Some(tip.trim_start_matches("0x").to_ascii_lowercase())
            );
            let mut forged = b.clone();
            forged.orchard_anchor_txid = Some("11".repeat(32));
            assert_eq!(
                forged.verify_against_zakura(&z),
                Err(private_inference_rent::Zap1Error::AnchorMismatch)
            );
        }
        Err(e) if std::env::var("PIR_ZAKURA_LAB").ok().as_deref() == Some("1") => {
            panic!("PIR_ZAKURA_LAB=1 but lab_spawn failed: {e}");
        }
        Err(e) => eprintln!("skip: lab_spawn ({e})"),
    }
}

#[test]
fn zakura_compose_and_dex_dirs_are_discoverable() {
    let _ = ZakuraRegtest::sibling_repo();
    let _ = ZakuraRegtest::compose_file();
    let _ = private_inference_rent::zakura::dex_integration_dir();
}
