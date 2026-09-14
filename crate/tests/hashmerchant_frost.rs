//! Hashmerchant Zcash root → FROST threshold pool deposit accept/reject.

use private_inference_rent::frost_pool::FrostThresholdPool;
use private_inference_rent::hashmerchant::{DepositAttestation, DepositError, HashmerchantIngress};
use private_inference_rent::tagged_hash;

fn group() -> [u8; 32] {
    tagged_hash(b"frost-group", &[b"pool-a"])
}

fn valid_att(amount: u64) -> DepositAttestation {
    DepositAttestation::prove(
        tagged_hash(b"zcash-state-root", &[b"height-100"]),
        tagged_hash(b"note-cm", &[b"n1"]),
        amount,
        group(),
    )
}

#[test]
fn valid_root_and_proof_credits_frost_pool() {
    let mut pool = FrostThresholdPool::new(group(), 2, 3).unwrap();
    let att = valid_att(50_000);
    let credit = pool.credit_transcript(&att).expect("accept");
    assert_eq!(credit.amount_zat, 50_000);
    assert_eq!(pool.balance_zat, 50_000);
    assert_eq!(pool.credits.len(), 1);
}

#[test]
fn empty_root_rejected() {
    let ingress = HashmerchantIngress::new(group());
    let mut att = valid_att(1);
    att.transcript_root = [0u8; 32];
    assert_eq!(ingress.accept(&att), Err(DepositError::EmptyRoot));
}

#[test]
fn empty_proof_rejected() {
    let ingress = HashmerchantIngress::new(group());
    let mut att = valid_att(1);
    att.inclusion_proof.clear();
    assert_eq!(ingress.accept(&att), Err(DepositError::EmptyProof));
}

#[test]
fn mismatched_proof_rejected() {
    let mut pool = FrostThresholdPool::new(group(), 2, 3).unwrap();
    let mut att = valid_att(9);
    att.inclusion_proof[0] ^= 0xff;
    assert_eq!(pool.credit_transcript(&att), Err(DepositError::Mismatch));
    assert_eq!(pool.balance_zat, 0);
}

#[test]
fn wrong_frost_group_rejected() {
    let other = tagged_hash(b"frost-group", &[b"other"]);
    let mut pool = FrostThresholdPool::new(other, 2, 3).unwrap();
    let att = valid_att(1);
    assert_eq!(pool.credit_transcript(&att), Err(DepositError::FrostBinding));
}

#[test]
fn replay_and_zero_amount_rejected() {
    let mut pool = FrostThresholdPool::new(group(), 2, 3).unwrap();
    let att = valid_att(50_000);
    pool.credit_transcript(&att).unwrap();
    assert_eq!(pool.credit_transcript(&att), Err(DepositError::Replay));
    assert_eq!(pool.balance_zat, 50_000);
    let zero = valid_att(0);
    assert_eq!(pool.credit_transcript(&zero), Err(DepositError::ZeroAmount));
}

#[test]
fn bad_pool_threshold_rejected() {
    assert!(FrostThresholdPool::new(group(), 0, 3).is_err());
    assert!(FrostThresholdPool::new(group(), 4, 3).is_err());
}
