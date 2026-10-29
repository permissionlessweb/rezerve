//! Public instances for AKT stake. The Halo2 proof is not live.

use private_inference_rent::akt_stake::{
    prove_akt_stake_inclusion, statement_holds, verify_akt_stake_inclusion, AktStakeError,
    AktStakePublic, AktStakeWitness, AMOUNT_CLASS_LABEL, CIRCUIT_ID, INSTANCE_LEN, PROOF_LIVE,
};

fn public_at(min: u64) -> AktStakePublic {
    AktStakePublic::new([0x11; 32], min).expect("nonzero min")
}

#[test]
fn stake_at_least_min_keeps_bonding_account_off_public_instances() {
    let min = 1_000_001_u64;
    let public = public_at(min);
    let alpha = AktStakeWitness {
        bonding_account: b"akash1bond-ALPHA-account-not-public".to_vec(),
        stake_uakt: 2_000_003,
    };
    let beta = AktStakeWitness {
        bonding_account: b"akash1bond-BETA-account-not-public".to_vec(),
        stake_uakt: 9_000_007,
    };
    assert!(statement_holds(&alpha, &public).is_ok());
    assert!(statement_holds(&beta, &public).is_ok());
    assert_eq!(
        statement_holds(
            &AktStakeWitness {
                bonding_account: alpha.bonding_account.clone(),
                stake_uakt: min,
            },
            &public,
        )
        .ok(),
        Some(())
    );

    let bytes = public.instance_bytes();
    assert_eq!(bytes.len(), INSTANCE_LEN);
    assert_eq!(&bytes[0..32], &public.inclusion_root);
    assert_eq!(&bytes[32..40], &min.to_le_bytes());
    assert_eq!(&bytes[40..64], &[0u8; 24]);
    assert_eq!(&bytes[64..96], &public.amount_class);
    for account in [&alpha.bonding_account, &beta.bonding_account] {
        assert!(
            !bytes
                .windows(account.len())
                .any(|window| window == account.as_slice()),
            "bonding account leaked into public instances"
        );
    }
    let renter = b"renter-7f3a-not-an-instance";
    assert!(!bytes.windows(renter.len()).any(|window| window == renter));

    let json = public.chain_json();
    let value: serde_json::Value = serde_json::from_str(&json).expect("json");
    assert_eq!(value["circuit_id"], CIRCUIT_ID);
    assert_eq!(value["proof_live"], false);
    assert_eq!(value["min_stake_uakt"], min);
    assert!(value.get("bonding_account").is_none());
    assert!(value.get("stake_uakt").is_none());
    assert!(value.get("renter_id").is_none());
    assert!(!json.contains("akash1bond-ALPHA"));
    assert!(!json.contains("akash1bond-BETA"));
    assert!(!json.contains("2000003"));
    assert!(!json.contains("9000007"));
    assert!(!json.contains("renter-7f3a"));
    let class = hex::decode(value["amount_class"].as_str().expect("class")).expect("hex");
    assert!(class
        .windows(AMOUNT_CLASS_LABEL.len())
        .any(|window| window == AMOUNT_CLASS_LABEL.as_bytes()));

    let mut leaked = [0u8; 32];
    let needle = b"bond-acct-leak-test!";
    leaked[..needle.len()].copy_from_slice(needle);
    let tainted = AktStakePublic::new(leaked, min).expect("root");
    let leak_witness = AktStakeWitness {
        bonding_account: needle.to_vec(),
        stake_uakt: min,
    };
    assert_eq!(
        statement_holds(&leak_witness, &tainted).expect_err("account in root"),
        AktStakeError::AccountInPublicInputs
    );
}

#[test]
fn verify_fails_closed_because_proof_is_not_live() {
    assert!(!PROOF_LIVE);
    assert_eq!(
        AktStakePublic::new([0xff; 32], 0).expect_err("zero"),
        AktStakeError::ZeroMin
    );
    let mut high = [0xff; 32];
    let public = AktStakePublic::new(high, 50).expect("min");
    high[31] = 0x3f;
    assert_eq!(public.inclusion_root, high);

    let enough = AktStakeWitness {
        bonding_account: b"akash1bond-ENOUGH-account".to_vec(),
        stake_uakt: 50,
    };
    let low = AktStakeWitness {
        bonding_account: enough.bonding_account.clone(),
        stake_uakt: 49,
    };
    let empty = AktStakeWitness {
        bonding_account: Vec::new(),
        stake_uakt: 50,
    };
    assert_eq!(
        prove_akt_stake_inclusion(&enough, &public).expect_err("no proof bytes"),
        AktStakeError::ProofNotLive
    );
    assert_eq!(
        prove_akt_stake_inclusion(&low, &public).expect_err("below"),
        AktStakeError::StakeBelowMin
    );
    assert_eq!(
        prove_akt_stake_inclusion(&empty, &public).expect_err("empty account"),
        AktStakeError::EmptyAccount
    );
    assert_eq!(
        verify_akt_stake_inclusion(&public, &[]).expect_err("empty proof"),
        AktStakeError::ProofNotLive
    );
    assert_eq!(
        verify_akt_stake_inclusion(&public, b"not-a-halo2-proof").expect_err("fake"),
        AktStakeError::ProofNotLive
    );
    assert_eq!(
        verify_akt_stake_inclusion(&public, &public.instance_bytes()).expect_err("instances"),
        AktStakeError::ProofNotLive
    );

    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/akt_stake.rs"))
        .expect("source");
    assert!(src.contains("ProofNotLive"));
    assert!(src.contains("not live"));
    assert!(src.contains("not an Akash mainnet snapshot"));
    assert!(src.contains("statement_holds"));
    assert!(src.contains("PIR_*"));
    assert!(!src.contains("verify_proof"));
    assert!(!src.contains("mainnet AKT"));
    assert!(!src.contains("Ok(vec!"));
    assert!(!src.contains("renter_id:"));
}
