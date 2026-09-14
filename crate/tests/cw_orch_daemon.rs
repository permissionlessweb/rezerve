//! Fail-closed CosmWasm / ict-rs-cw-orch attach.
//!
//! In-process `publish_commitments` is a RAM CommitmentModule, not a Daemon.
//! `live-ict` must fail closed here: the ict-rs crate is not in this tree.
//!
//! `cargo test --features e2e --offline --test cw_orch_daemon`

use private_inference_rent::ask::{PublicAsk, ResourceAsk};
use private_inference_rent::bid::{EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::cw_orch::{
    publish_commitments, query_published_packet, try_live_attach, CwOrchError,
};
use private_inference_rent::frost_pool::FrostThresholdPool;
use private_inference_rent::interop::IctCwOrchScenario;
use private_inference_rent::onchain::CommitmentModule;
use private_inference_rent::workflow::PrivateComputeWorkflow;
use private_inference_rent::zap1::IbcV2PacketAttest;
use private_inference_rent::tagged_hash;

fn ask() -> PublicAsk {
    PublicAsk::new(
        "ask-cw-orch",
        "tenant",
        "version: \"2.0\"\n",
        ResourceAsk {
            cpu_milli: 100,
            memory_mib: 256,
            storage_mib: 512,
            gpu_units: 0,
        },
        "private-llm",
    )
}

fn sealed_bid(public: &PublicAsk) -> EncryptedBidEnvelope {
    let key = tagged_hash(b"session", &[b"cw-orch"]);
    let bid = PlaintextBid {
        ask_id: public.ask_id.clone(),
        bidder_identity: "prov".into(),
        price_uakt: 4_000,
        provider_endpoint: "oob://p".into(),
    };
    EncryptedBidEnvelope::seal(&bid, &key).unwrap()
}

fn packet() -> IbcV2PacketAttest {
    IbcV2PacketAttest::bind(
        "07-tendermint-0",
        "07-tendermint-1",
        1,
        1,
        &[9u8; 32],
        1,
        &[8u8; 32],
        &[7u8; 32],
    )
}

#[test]
fn publish_then_query_ok() {
    let public = ask();
    let env = sealed_bid(&public);
    let pkt = packet();
    let mut module = CommitmentModule::new(public);
    let attach = publish_commitments(&mut module, &pkt, &env.commitment()).unwrap();
    assert!(!attach.live, "RAM publish is not a live Daemon");
    query_published_packet(&module, &pkt).expect("packet still matches store");
}

#[test]
fn query_rejects_tampered_packet() {
    let public = ask();
    let env = sealed_bid(&public);
    let pkt = packet();
    let mut module = CommitmentModule::new(public);
    publish_commitments(&mut module, &pkt, &env.commitment()).unwrap();
    let mut tampered = pkt;
    tampered.app_data_hash[0] ^= 0xff;
    query_published_packet(&module, &tampered).expect_err("tampered app_data_hash");
}

#[test]
#[cfg(not(feature = "live-ict"))]
fn live_bin_ok_only_from_daemon_builder() {
    match private_inference_rent::cw_orch::run_live_attach_bin() {
        Ok(h) => {
            assert!(!h.chain_id.is_empty());
        }
        Err(e) => {
            assert!(
                e.contains("not found")
                    || e.contains("daemon_builder_from_chain")
                    || e.contains("pir-live-attach"),
                "{e}"
            );
        }
    }
}

#[test]
fn probe_names_daemon_builder_from_chain() {
    let p = private_inference_rent::cw_orch::probe_daemon_builder_from_chain();
    assert!(
        p.contains("daemon_builder_from_chain"),
        "{p}"
    );
}

#[test]
#[cfg(not(feature = "live-ict"))]
fn try_live_attach_disabled_without_feature() {
    match try_live_attach() {
        Err(CwOrchError::LiveDisabled) => {}
        other => panic!("expected LiveDisabled, got {other:?}"),
    }
}

#[test]
#[cfg(feature = "live-ict")]
fn try_live_attach_succeeds_only_when_chain_query_rejects_tamper() {
    let hint = try_live_attach().unwrap_or_else(|e| {
        panic!(
            "live-ict must Ok only after daemon_builder_from_chain + DaemonBuilder.build + deploy_on + chain match/mismatch query; got {e:?}"
        )
    });
    assert!(!hint.chain_id.is_empty(), "live attach must report a chain id");
    assert!(
        hint.deploy_on_daemon,
        "live-ict must PrivateInference::deploy_on on Daemon"
    );
    assert!(
        hint.escrow_grant_recorded,
        "live-ict deploy_on must record grant-only escrow (no BankMsg/uterp)"
    );
    assert!(
        hint.zap1_stored && hint.zap1_matches && hint.zap1_tamper_rejected,
        "live-ict must store/match zap1 on the same Daemon deploy_on"
    );
    assert!(hint.ics08_deployed, "live-ict deploy_on must include ics08");
    assert!(
        hint.ics08_accepted && hint.ics08_tamper_rejected,
        "live-ict ics08 must CreateClient+AttestPacket+Accepted query, not store-only: {hint:?}"
    );
}

#[test]
fn interop_attach_or_fail_live() {
    let public = ask();
    let group = tagged_hash(b"frost-group", &[b"cw-orch"]);
    let wf = PrivateComputeWorkflow::open(
        public,
        FrostThresholdPool::new(group, 2, 3)
            .unwrap()
            .allow_sim_transcript(),
    )
    .unwrap();
    let sc = IctCwOrchScenario::from_workflow("cw-orch-daemon", &wf);
    #[cfg(not(feature = "live-ict"))]
    {
        match sc.attach_or_fail_live() {
            Err(CwOrchError::LiveDisabled) => {}
            other => panic!("expected LiveDisabled, got {other:?}"),
        }
    }
    #[cfg(feature = "live-ict")]
    {
        sc.attach_or_fail_live()
            .expect("live-ict attach_or_fail_live must call try_live_attach Ok");
    }
}
