//! Local SHA-256 seat transcript (not MPC, not a dregg kernel).

use private_inference_rent::dregg::{FrostSignerInstance, LocalRuntimeProof, SignerInstanceError};
use private_inference_rent::steoffle::{SteoffleError, SteoffleMpc};
use private_inference_rent::tagged_hash;

fn signer() -> FrostSignerInstance {
    FrostSignerInstance::new(
        tagged_hash(b"frost-signer", &[b"0"]),
        tagged_hash(b"seat-instance", &[b"rt"]),
        vec![
            tagged_hash(b"dkg-commit", &[b"0"]),
            tagged_hash(b"dkg-commit", &[b"1"]),
        ],
    )
    .unwrap()
}

#[test]
fn well_formed_attestation_and_runtime_pass() {
    let s = signer();
    s.runtime.verify().unwrap();
    let att = SteoffleMpc::attest(&s).unwrap();
    SteoffleMpc::verify(&s, &att).unwrap();
}

#[test]
fn missing_runtime_proof_fails() {
    let mut rt = LocalRuntimeProof::prove([1u8; 32], [2u8; 32]);
    rt.proof = [0u8; 32];
    assert_eq!(rt.verify(), Err(SignerInstanceError::MissingRuntimeProof));
}

#[test]
fn mutated_commitments_fail() {
    let s = signer();
    let att = SteoffleMpc::attest(&s).unwrap();
    let mut tampered = s.clone();
    tampered.seat_commitments[0][0] ^= 0x01;
    match SteoffleMpc::verify(&tampered, &att) {
        Err(SteoffleError::TamperedCommitments) => {}
        other => panic!("expected tampered, got {other:?}"),
    }
}

#[test]
fn mutated_runtime_proof_fails() {
    let mut s = signer();
    s.runtime.proof[3] ^= 0xaa;
    assert!(s.runtime.verify().is_err());
    assert!(SteoffleMpc::attest(&s).is_err());
}

#[test]
fn empty_commitments_rejected() {
    let err = FrostSignerInstance::new([1u8; 32], [2u8; 32], vec![]).unwrap_err();
    assert_eq!(err, SignerInstanceError::EmptyCommitments);
}
