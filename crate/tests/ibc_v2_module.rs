//! IBC v2 module store: commit + verify; tamper rejects. No live chain.

use private_inference_rent::ibc_module::{IbcModuleError, IbcV2Module};
use private_inference_rent::zap1::IbcV2PacketAttest;

fn sample_packet() -> IbcV2PacketAttest {
    IbcV2PacketAttest::bind(
        "07-tendermint-0",
        "07-tendermint-1",
        1,
        1_000_000,
        &[1u8; 32],
        42,
        &[2u8; 32],
        &[3u8; 32],
    )
}

#[test]
fn commit_then_verify_ok() {
    let pkt = sample_packet();
    let mut m = IbcV2Module::new();
    let stored = m.commit_packet(&pkt).expect("commit");
    assert_eq!(stored, pkt.packet_commitment());
    assert_eq!(
        m.query_packet(&pkt.source_client, &pkt.dest_client, pkt.sequence),
        Some(stored)
    );
    m.verify_packet(&pkt).expect("verify");
}

#[test]
fn tampered_app_data_hash_is_rejected() {
    let pkt = sample_packet();
    let mut m = IbcV2Module::new();
    m.commit_packet(&pkt).unwrap();
    let mut bad = pkt;
    bad.app_data_hash[0] ^= 0x01;
    assert_eq!(m.verify_packet(&bad), Err(IbcModuleError::Tampered));
}

#[test]
fn tampered_sequence_is_unknown() {
    let pkt = sample_packet();
    let mut m = IbcV2Module::new();
    m.commit_packet(&pkt).unwrap();
    let mut bad = pkt;
    bad.sequence = 99;
    assert_eq!(m.verify_packet(&bad), Err(IbcModuleError::Unknown));
}

#[test]
fn duplicate_commit_is_rejected() {
    let pkt = sample_packet();
    let mut m = IbcV2Module::new();
    m.commit_packet(&pkt).unwrap();
    assert_eq!(m.commit_packet(&pkt), Err(IbcModuleError::Duplicate));
}

#[test]
fn verify_unknown_without_commit() {
    let m = IbcV2Module::new();
    assert_eq!(
        m.verify_packet(&sample_packet()),
        Err(IbcModuleError::Unknown)
    );
}
