//! Fixture launch of the private inference rent workflow (offline).

use private_inference_rent::ask::{PublicAsk, ResourceAsk};
use private_inference_rent::bid::{EncryptedBidEnvelope, PlaintextBid};
use private_inference_rent::committee::demo_layered_committees;
use private_inference_rent::frost_pool::{FrostThresholdPool, SpendAuth};
use private_inference_rent::workflow::PrivateComputeWorkflow;
use private_inference_rent::tagged_hash;

fn main() {
    let rc = run_fixture();
    println!(
        "commitment={} attestation={} deposit-accept={} pool_zat={}",
        rc.on_chain.records[0].bid_commitment,
        rc.on_chain.records[0].steoffle_attestation,
        rc.deposit_accepted,
        rc.pool_balance_zat
    );
}

fn run_fixture() -> private_inference_rent::WorkflowReceipt {
    let group = tagged_hash(b"frost-group", &[b"demo-pool"]);
    let ask = PublicAsk::new(
        "ask-demo-1",
        "tenant",
        "version: \"2.0\"\nservices:\n  inference:\n    image: private/infer:1\n",
        ResourceAsk {
            cpu_milli: 2000,
            memory_mib: 8192,
            storage_mib: 20480,
            gpu_units: 1,
        },
        "private-llm",
    );
    let pool = FrostThresholdPool::new(group, 2, 3)
        .expect("pool")
        .with_layered(demo_layered_committees().expect("committees"));
    let mut wf = PrivateComputeWorkflow::open(ask, pool).expect("ask");

    let steoffle = wf.pool.layered.as_ref().unwrap().inners[0].seats[0]
        .attestation
        .clone();

    let key = tagged_hash(b"oob-session", &[b"direct"]);
    let bid = PlaintextBid {
        ask_id: "ask-demo-1".into(),
        bidder_identity: "provider-oob".into(),
        price_uakt: 42_000,
        provider_endpoint: "oob://direct".into(),
    };
    let env = EncryptedBidEnvelope::seal(&bid, &key).expect("seal");
    wf.ingest_oob_bid(env, &steoffle).expect("ingest");

    let note = tagged_hash(b"note", &[b"deposit"]);
    let dep = private_inference_rent::local_hosting_bundle(group, note, 1_000_000, "PIR-DEMO", "sib");
    let auth = SpendAuth::from_quorum(
        wf.pool.layered.as_ref().unwrap(),
        &[
            ("alpha", &["alpha-s0", "alpha-s1", "alpha-s2"][..]),
            ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
        ],
        group,
        note,
        1_000_000,
        None,
    )
    .expect("spend auth");
    private_inference_rent::accept_on_zap1_client(&dep).expect("lc accept");
    wf.credit_deposit_zap1(&dep, &auth).expect("deposit");

    wf.receipt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_names_commitment_attestation_deposit() {
        let rc = run_fixture();
        assert!(!rc.on_chain.records[0].bid_commitment.is_empty());
        assert!(rc.deposit_accepted);
    }
}
