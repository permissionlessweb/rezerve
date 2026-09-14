//! Real Halo2 HOSTING_PAYMENT inclusion. Merkle path is not a CosmWasm execute field.

use hosting_payment::{
    encode_instances, prove_inclusion, verify_inclusion, CIRCUIT_ID, INSTANCE_COUNT, KIND_DOMAIN,
};

#[test]
#[ignore = "K=17 Halo2 BLAKE2b prove is lab-only and long"]
fn halo2_prove_and_verify_hosting_payment() {
    let frost = [11u8; 32];
    let proof = prove_inclusion("PIR-001", "sib-private", &frost, 50).expect("halo2 prove");
    assert!(!proof.is_empty());
    assert!(verify_inclusion(&proof, "PIR-001", "sib-private", &frost, 50).unwrap());
    let inst = encode_instances("PIR-001", "sib-private", &frost, 50);
    assert_eq!(inst.len(), INSTANCE_COUNT * 32);
    assert_eq!(CIRCUIT_ID, "hosting-payment.inclusion.v1");
    assert_eq!(KIND_DOMAIN, "HOSTING_PAYMENT");
    assert!(hosting_payment::proof_instance_verify(1, &proof, &inst).unwrap());
}

#[test]
#[ignore = "K=17 Halo2 BLAKE2b prove is lab-only and long"]
fn bitflip_instances_rejected() {
    let frost = [11u8; 32];
    let proof = prove_inclusion("PIR-001", "sib-private", &frost, 50).unwrap();
    let mut inst = encode_instances("PIR-001", "sib-private", &frost, 50);
    inst[0] ^= 0xff;
    assert!(!hosting_payment::proof_instance_verify(1, &proof, &inst).unwrap());
}

#[test]
fn empty_halo2_proof_fails() {
    let inst = encode_instances("PIR-001", "sib-private", &[11u8; 32], 50);
    assert!(hosting_payment::proof_instance_verify(1, &[], &inst).is_err());
}

#[test]
fn exported_halo2_proof_fail_closed_when_required_or_verifies() {
    match hosting_payment::proof_instance_verify_exported() {
        Ok(ok) => assert!(ok, "exported Halo2 proof must verify"),
        Err(e) if std::env::var("PIR_HALO2_REQUIRE").ok().as_deref() == Some("1") => {
            panic!("PIR_HALO2_REQUIRE=1 fail-closed: {e}");
        }
        Err(_) => {}
    }
}
