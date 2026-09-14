//! Interop with ict-rs + cw-orchestrator harness names used by o-line.
//!
//! Imports the *shipped* `private_inference_rent` crate (not a test-only clone)
//! and binds a scenario object to the documented o-line ict / cw-orch modules.

use private_inference_rent::ask::{PublicAsk, ResourceAsk};
use private_inference_rent::bid::{EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::committee::demo_layered_committees;
use private_inference_rent::frost_pool::{FrostThresholdPool, SpendAuth};
use private_inference_rent::hashmerchant::DepositAttestation;
use private_inference_rent::interop::{IctCwOrchScenario, ICT_HARNESS_MODULES};
use private_inference_rent::tagged_hash;
use private_inference_rent::workflow::PrivateComputeWorkflow;

fn shipped_workflow() -> PrivateComputeWorkflow {
    let group = tagged_hash(b"frost-group", &[b"interop"]);
    let ask = PublicAsk::new(
        "ask-interop",
        "t",
        "version: \"2.0\"\nservices:\n  inf:\n    image: x\n",
        ResourceAsk {
            cpu_milli: 500,
            memory_mib: 1024,
            storage_mib: 2048,
            gpu_units: 0,
        },
        "cpu-infer",
    );
    let mut wf = PrivateComputeWorkflow::open(
        ask,
        FrostThresholdPool::new(group, 2, 3)
            .unwrap()
            .allow_sim_transcript()
            .with_layered(demo_layered_committees().unwrap()),
    )
    .unwrap();
    let att = wf.pool.layered.as_ref().unwrap().inners[0].seats[0]
        .attestation
        .clone();
    let env = EncryptedBidEnvelope::seal_with_nonce(
        &PlaintextBid {
            ask_id: "ask-interop".into(),
            bidder_identity: "oob".into(),
            price_uakt: 11,
            provider_endpoint: "oob".into(),
        },
        &tagged_hash(b"k", &[b"s"]),
        [4u8; 16],
    )
    .unwrap();
    wf.ingest_oob_bid(env, &att).unwrap();
    let note = tagged_hash(b"note", &[b"i"]);
    let dep = DepositAttestation::prove(
        tagged_hash(b"root", &[b"i"]),
        note,
        100,
        group,
    );
    let auth = SpendAuth::from_quorum(
        wf.pool.layered.as_ref().unwrap(),
        &[
            ("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..]),
            ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
        ],
        group,
        note,
        100,
        None,
    )
    .unwrap();
    wf.credit_deposit(&dep, &auth).unwrap();
    wf
}

#[test]
fn interop_scenario_imports_shipped_crate_and_named_harnesses() {
    let wf = shipped_workflow();
    let sc = IctCwOrchScenario::from_workflow("private-inference-rent", &wf);
    assert!(sc.wraps_shipped_receipt());
    assert!(ICT_HARNESS_MODULES.iter().any(|m| m.contains("ict_")));
    assert!(ICT_HARNESS_MODULES.iter().any(|m| m.contains("interface")));
    assert!(sc.receipt.deposit_accepted);
    assert!(sc.receipt.steoffle_ok);
    assert!(!sc.receipt.on_chain.payload_contains_plaintext_bid());
}

#[test]
fn ict_cw_orch_stoffel_confirm_on_shipped_workflow() {
    if !private_inference_rent::stoffel::available() {
        eprintln!("skip: stoffel CLI not installed");
        return;
    }
    let digest = private_inference_rent::tagged_hash(b"ict-stoffel", &[b"1"]);
    let tag = private_inference_rent::confirm_digest(&digest, &digest).unwrap();
    assert_ne!(tag, [0u8; 32]);
}

#[cfg(feature = "live-ict")]
#[test]
fn live_ict_attach_is_daemon_builder_from_chain_plus_deploy_on() {
    let group = tagged_hash(b"frost-group", &[b"interop-live"]);
    let ask = PublicAsk::new(
        "ask-interop-live",
        "t",
        "version: \"2.0\"\nservices:\n  inf:\n    image: x\n",
        ResourceAsk {
            cpu_milli: 500,
            memory_mib: 1024,
            storage_mib: 2048,
            gpu_units: 0,
        },
        "cpu-infer",
    );
    let wf = PrivateComputeWorkflow::open(
        ask,
        FrostThresholdPool::new(group, 2, 3)
            .unwrap()
            .with_layered(demo_layered_committees().unwrap()),
    )
    .unwrap();
    IctCwOrchScenario::from_workflow("live-ict-attach", &wf)
        .attach_or_fail_live()
        .expect(
            "live-ict must try_live_attach: daemon_builder_from_chain + PrivateInference::deploy_on",
        );
}

#[test]
fn harness_module_paths_match_oline_layout() {
    // Structural check: o-line still publishes these modules (source on disk).
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../o-line/src");
    let ict = std::path::Path::new(root).join("testing/ict_terp.rs");
    let iface = std::path::Path::new(root).join("interface/mod.rs");
    assert!(ict.exists(), "missing {ict:?}");
    assert!(iface.exists(), "missing {iface:?}");
    let ict_src = std::fs::read_to_string(&ict).unwrap();
    assert!(ict_src.contains("ict_rs"));
    let iface_src = std::fs::read_to_string(&iface).unwrap();
    assert!(iface_src.contains("cw-orchestrator") || iface_src.contains("cw-orch"));
}
