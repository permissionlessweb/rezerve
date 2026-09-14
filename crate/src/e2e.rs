//! Modular local e2e (cw-orch suite style): named modules, one full workflow.
//!
//! Required in-proc modules pass without Docker. `live-ict` makes `ict_attach`
//! required and fail-closed (Docker + `daemon_builder_from_chain` +
//! `PrivateInference::deploy_on` on Daemon). `PIR_ZAKURA_LAB=1` makes
//! `zakura_attach` required and fail-closed. No skip-green.
//!
//! Product compose is [`run_production_sequence`]: ask → ChaCha OOB bid /
//! chain commitments → ZAP1+Halo2 DKG credit → allocate after match →
//! pir serve HTTP 200 → LC-class close grant → two Ironwood spends →
//! winner bearer denied. Fail-closed if any step is skipped.

use crate::ask::{PublicAsk, ResourceAsk};
use crate::bid::{EncryptedBidEnvelope, PlaintextBid};
use crate::committee::demo_layered_committees;
use crate::frost::{FrostGroup, FrostSeat};
use crate::frost_dkg::dkg_escrow_seats;
use crate::frost_pool::FrostThresholdPool;
use crate::steoffle::SteoffleMpc;
use crate::workflow::PrivateComputeWorkflow;
use crate::{tagged_hash, SpendAuth};

/// Product custody: DKG group id is the verifying key, not a dealer seat map.
fn product_dkg() -> Result<(FrostGroup, Vec<FrostSeat>, [u8; 32]), String> {
    let (frost, seats) = dkg_escrow_seats().map_err(|e| e.to_string())?;
    let group = frost.verifying_key;
    Ok((frost, seats.to_vec(), group))
}
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleStatus {
    Passed,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleReport {
    pub name: String,
    pub required: bool,
    pub status: ModuleStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalE2eReport {
    pub modules: Vec<ModuleReport>,
    pub ask_id: String,
    pub deposit_zat: u64,
    pub swap_out: Option<u128>,
    pub zakura_rpc: Option<String>,
}

impl LocalE2eReport {
    pub fn required_ok(&self) -> bool {
        self.modules
            .iter()
            .filter(|m| m.required)
            .all(|m| m.status == ModuleStatus::Passed)
    }
}

pub const LOCAL_E2E_MODULES: &[&str] = &[
    "ask_bid",
    "frost_spend",
    "seam_swap",
    "zakura_attach",
    "ict_attach",
    "zap1_ibcv2",
];

/// Full local happy path: ask → OOB bid → FROST credit → optional seam swap.
pub fn run_local_e2e() -> Result<LocalE2eReport, String> {
    let mut modules = Vec::new();
    let (frost, frost_seats, group) = product_dkg()?;
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .map_err(|e| e.to_string())?
        .with_layered(demo_layered_committees().map_err(|e| e.to_string())?)
        .with_frost(frost.clone());

    let ask = PublicAsk::new(
        "ask-e2e-local",
        "tenant-e2e",
        "version: \"2.0\"\nservices:\n  infer:\n    image: private/infer:1\n",
        ResourceAsk {
            cpu_milli: 1000,
            memory_mib: 4096,
            storage_mib: 8192,
            gpu_units: 0,
        },
        "cpu-infer",
    );
    let mut wf = PrivateComputeWorkflow::open(ask, pool.clone()).map_err(|e| e.to_string())?;
    let seat = pool
        .layered
        .as_ref()
        .and_then(|o| o.inners.first())
        .and_then(|i| i.seats.first())
        .ok_or_else(|| "no committee seat".to_string())?;
    let att = SteoffleMpc::attest(&seat.signer).map_err(|e| e.to_string())?;
    let key = tagged_hash(b"e2e-oob", &[b"k"]);
    let env = EncryptedBidEnvelope::seal(
        &PlaintextBid {
            ask_id: "ask-e2e-local".into(),
            bidder_identity: "prov-e2e".into(),
            price_uakt: 12_000,
            provider_endpoint: "oob://e2e".into(),
        },
        &key,
    )
    .map_err(|e| e.to_string())?;
    let rec = wf.ingest_oob_bid(env, &att).map_err(|e| e.to_string())?;
    if wf.view.payload_contains_plaintext_bid() {
        return Err("on-chain payload leaked bid plaintext".into());
    }
    modules.push(ModuleReport {
        name: "ask_bid".into(),
        required: true,
        status: ModuleStatus::Passed,
        detail: format!("bid_commitment={}", rec.bid_commitment),
    });

    // live-ict / Zakura attach before any ZAP1 eco accept (no skip-green).
    #[cfg(feature = "live-ict")]
    let mut live_hint: Option<crate::cw_orch::LiveDaemonHint> = None;
    let lab_required = std::env::var("PIR_ZAKURA_LAB").ok().as_deref() == Some("1");
    let zakura_node = match crate::zakura::lab_spawn() {
        Ok(n) => {
            let z = n.as_regtest();
            match z.getblockchaininfo() {
                Ok(_) => {
                    modules.push(ModuleReport {
                        name: "zakura_attach".into(),
                        required: lab_required,
                        status: ModuleStatus::Passed,
                        detail: format!(
                            "ict-rs native spawn rpc={} reused={}",
                            n.rpc_url, n.reused_existing
                        ),
                    });
                    Some(z)
                }
                Err(e) if lab_required => {
                    modules.push(ModuleReport {
                        name: "zakura_attach".into(),
                        required: true,
                        status: ModuleStatus::Failed,
                        detail: e.to_string(),
                    });
                    return Err("PIR_ZAKURA_LAB=1 but node RPC failed".into());
                }
                Err(e) => {
                    modules.push(ModuleReport {
                        name: "zakura_attach".into(),
                        required: false,
                        status: ModuleStatus::Skipped,
                        detail: e.to_string(),
                    });
                    None
                }
            }
        }
        Err(e) if lab_required => {
            modules.push(ModuleReport {
                name: "zakura_attach".into(),
                required: true,
                status: ModuleStatus::Failed,
                detail: e.to_string(),
            });
            return Err("PIR_ZAKURA_LAB=1 requires ZAKURAD_BIN + Docker".into());
        }
        Err(e) => {
            modules.push(ModuleReport {
                name: "zakura_attach".into(),
                required: false,
                status: ModuleStatus::Skipped,
                detail: format!("no native node ({e}); export ZAKURAD_BIN or PIR_ZAKURA_LAB=1"),
            });
            None
        }
    };

    #[cfg(feature = "live-ict")]
    {
        match crate::cw_orch::try_live_attach() {
            Ok(hint)
                if hint.deploy_on_daemon
                    && hint.escrow_grant_recorded
                    && hint.zap1_stored
                    && hint.zap1_matches
                    && hint.zap1_tamper_rejected
                    && hint.ics08_deployed
                    && hint.ics08_accepted
                    && hint.ics08_tamper_rejected
                    && !hint.chain_id.is_empty() =>
            {
                modules.push(ModuleReport {
                    name: "ict_attach".into(),
                    required: true,
                    status: ModuleStatus::Passed,
                    detail: format!(
                        "daemon_builder_from_chain+deploy_on chain_id={} deploy_on_daemon={} escrow_grant_recorded={} zap1_stored={} ics08_deployed={} ics08_accepted={} ics08_tamper_rejected={}",
                        hint.chain_id, hint.deploy_on_daemon, hint.escrow_grant_recorded, hint.zap1_stored, hint.ics08_deployed, hint.ics08_accepted, hint.ics08_tamper_rejected
                    ),
                });
                live_hint = Some(hint);
            }
            Ok(hint) => {
                modules.push(ModuleReport {
                    name: "ict_attach".into(),
                    required: true,
                    status: ModuleStatus::Failed,
                    detail: format!(
                        "attach without deploy_on(Daemon)+escrow grant+zap1+ics08 execute/query chain_id={} deploy_on_daemon={} escrow_grant_recorded={} zap1_stored={} ics08_deployed={} ics08_accepted={} ics08_tamper_rejected={}",
                        hint.chain_id, hint.deploy_on_daemon, hint.escrow_grant_recorded, hint.zap1_stored, hint.ics08_deployed, hint.ics08_accepted, hint.ics08_tamper_rejected
                    ),
                });
                return Err(
                    "ict_attach fail-closed: deploy_on(Daemon) or escrow grant or ics08 execute/query missing".into(),
                );
            }
            Err(e) => {
                modules.push(ModuleReport {
                    name: "ict_attach".into(),
                    required: true,
                    status: ModuleStatus::Failed,
                    detail: e.to_string(),
                });
                return Err(format!("ict_attach fail-closed: {e}"));
            }
        }
    }
    #[cfg(not(feature = "live-ict"))]
    {
        modules.push(ModuleReport {
            name: "ict_attach".into(),
            required: false,
            status: ModuleStatus::Skipped,
            detail: "cw-orch attach via ict-rs-cw-orch when --features live-ict".into(),
        });
    }

    let zat = 10_000u64;
    let parts = [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ];
    #[cfg(feature = "live-ict")]
    {
        // RAM FrostThresholdPool + local_hosting_bundle is not money.
        // Product fund is on-chain zap1 + ics08 AttestPacket from pir-live-attach.
        match live_hint.as_ref() {
            Some(h)
                if h.zap1_stored
                    && h.zap1_matches
                    && h.ics08_deployed
                    && h.ics08_accepted
                    && h.ics08_tamper_rejected =>
            {
                modules.push(ModuleReport {
                    name: "frost_spend".into(),
                    required: true,
                    status: ModuleStatus::Passed,
                    detail: format!(
                        "on-chain zap1+ics08 from daemon_builder_from_chain+deploy_on chain_id={}; RAM pool not credited",
                        h.chain_id
                    ),
                });
            }
            _ => {
                modules.push(ModuleReport {
                    name: "frost_spend".into(),
                    required: true,
                    status: ModuleStatus::Failed,
                    detail: "live-ict frost_spend fail-closed: RAM local_hosting_bundle is not money"
                        .into(),
                });
                return Err(
                    "frost_spend fail-closed: live-ict does not credit RAM FrostThresholdPool"
                        .into(),
                );
            }
        }
    }
    #[cfg(not(feature = "live-ict"))]
    {
        let note = tagged_hash(b"e2e-note", &[&zat.to_le_bytes()]);
        let bundle0 = crate::zap1::local_hosting_bundle(group, note, zat, "PIR-E2E-FROST", "sib0");
        let msg = FrostGroup::spend_message(&group, &note, zat);
        let sig = frost
            .sign_with_seats(&msg, &frost_seats[..2])
            .map_err(|e| e.to_string())?;
        let auth = SpendAuth::from_quorum(
            pool.layered.as_ref().ok_or("no outer")?,
            &parts,
            group,
            note,
            zat,
            None,
        )
        .map_err(|e| e.to_string())?
        .with_frost_sig(sig);
        crate::zap1::accept_on_zap1_client(&bundle0).map_err(|e| e.to_string())?;
        wf.credit_deposit_zap1(&bundle0, &auth)
            .map_err(|e| e.to_string())?;
        modules.push(ModuleReport {
            name: "frost_spend".into(),
            required: true,
            status: ModuleStatus::Passed,
            detail: format!("balance_zat={}", wf.pool.balance_zat),
        });
        pool = wf.pool.clone();
    }

    let swap_out;
    #[cfg(feature = "live-ict")]
    {
        let _ = (&frost, &frost_seats, &parts, &mut pool, &wf);
    }
    #[cfg(all(feature = "seam-dex", feature = "live-ict"))]
    {
        swap_out = None;
        modules.push(ModuleReport {
            name: "seam_swap".into(),
            required: false,
            status: ModuleStatus::Failed,
            detail: "RAM seam-dex / FrostThresholdPool is not live-ict money".into(),
        });
    }
    #[cfg(all(feature = "seam-dex", not(feature = "live-ict")))]
    {
        use crate::seam_swap::{demo_zec_hub_pool, ibc_deposit_then_swap};
        use terp_seams::dex::SeamState;
        let mut dex = demo_zec_hub_pool();
        let mut st = SeamState::default();
        match ibc_deposit_then_swap(&mut pool, &frost, &frost_seats, &mut dex, &mut st, 8_000, 7) {
            Ok(out) => {
                swap_out = Some(out);
                modules.push(ModuleReport {
                    name: "seam_swap".into(),
                    required: true,
                    status: ModuleStatus::Passed,
                    detail: format!("delta_out={out}"),
                });
            }
            Err(e) => {
                modules.push(ModuleReport {
                    name: "seam_swap".into(),
                    required: true,
                    status: ModuleStatus::Failed,
                    detail: e.clone(),
                });
                return Err(format!("seam_swap module failed: {e}"));
            }
        }
    }
    #[cfg(not(feature = "seam-dex"))]
    {
        swap_out = None;
        modules.push(ModuleReport {
            name: "seam_swap".into(),
            required: false,
            status: ModuleStatus::Skipped,
            detail: "enable --features seam-dex (terp_seams::dex)".into(),
        });
    }

    {
        #[cfg(feature = "live-ict")]
        {
            // Same pir-live-attach process as ict_attach: do not spawn a second
            // CosmosChain. In-proc pir-zap1-lc is not this accept.
            match live_hint.as_ref() {
                Some(hint)
                    if hint.zap1_stored
                        && hint.zap1_matches
                        && hint.zap1_tamper_rejected
                        && hint.ics08_accepted
                        && hint.ics08_tamper_rejected =>
                {
                    modules.push(ModuleReport {
                        name: "zap1_ibcv2".into(),
                        required: true,
                        status: ModuleStatus::Passed,
                        detail: format!(
                            "on-chain zap1+ics08 execute/query from daemon_builder_from_chain+deploy_on chain_id={}",
                            hint.chain_id
                        ),
                    });
                }
                Some(hint) => {
                    modules.push(ModuleReport {
                        name: "zap1_ibcv2".into(),
                        required: true,
                        status: ModuleStatus::Failed,
                        detail: format!(
                            "live-ict attach missing on-chain zap1 stored={} matches={} tamper={}",
                            hint.zap1_stored, hint.zap1_matches, hint.zap1_tamper_rejected
                        ),
                    });
                    return Err(
                        "zap1_ibcv2 fail-closed: live-ict deploy_on did not store/match zap1"
                            .into(),
                    );
                }
                None => {
                    modules.push(ModuleReport {
                        name: "zap1_ibcv2".into(),
                        required: true,
                        status: ModuleStatus::Failed,
                        detail: "live-ict ict_attach missing".into(),
                    });
                    return Err("zap1_ibcv2 fail-closed: live-ict ict_attach missing".into());
                }
            }
        }
        #[cfg(not(feature = "live-ict"))]
        {
            let zat2 = 2_000u64;
            let note2 = tagged_hash(b"e2e-zap1-note", &[&zat2.to_le_bytes()]);
            let mut bundle =
                crate::zap1::local_hosting_bundle(group, note2, zat2, "PIR-E2E-001", "sib");
            if let Some(ref z) = zakura_node {
                let _ = bundle.stamp_zakura_tip(z);
            }
            let zap1_ok = if let Some(ref z) = zakura_node {
                bundle.verify_against_zakura(z)
            } else {
                bundle.verify()
            };
            match zap1_ok {
                Ok(()) => {
                    let msg2 = FrostGroup::spend_message(&group, &note2, zat2);
                    let sig2 = frost
                        .sign_with_seats(&msg2, &frost_seats[..2])
                        .map_err(|e| e.to_string())?;
                    let auth2 = SpendAuth::from_quorum(
                        pool.layered.as_ref().ok_or("no outer")?,
                        &parts,
                        group,
                        note2,
                        zat2,
                        None,
                    )
                    .map_err(|e| e.to_string())?
                    .with_frost_sig(sig2);
                    crate::zap1::accept_on_zap1_client(&bundle).map_err(|e| e.to_string())?;
                    match wf.credit_deposit_zap1(&bundle, &auth2) {
                        Ok(_) => modules.push(ModuleReport {
                            name: "zap1_ibcv2".into(),
                            required: true,
                            status: ModuleStatus::Passed,
                            detail: format!(
                                "root={} zakura_tip={}",
                                hex::encode(bundle.merkle_root),
                                bundle.orchard_anchor_txid.as_deref().unwrap_or("none")
                            ),
                        }),
                        Err(e) => {
                            modules.push(ModuleReport {
                                name: "zap1_ibcv2".into(),
                                required: true,
                                status: ModuleStatus::Failed,
                                detail: e.to_string(),
                            });
                            return Err("zap1_ibcv2 credit failed".into());
                        }
                    }
                }
                Err(e) => {
                    modules.push(ModuleReport {
                        name: "zap1_ibcv2".into(),
                        required: true,
                        status: ModuleStatus::Failed,
                        detail: e.to_string(),
                    });
                    return Err("zap1_ibcv2 verify failed".into());
                }
            }
        }
    }

    let report = LocalE2eReport {
        modules,
        ask_id: "ask-e2e-local".into(),
        deposit_zat: zat,
        swap_out,
        zakura_rpc: zakura_node.map(|z| z.rpc),
    };
    if !report.required_ok() {
        return Err("required e2e module failed".into());
    }
    Ok(report)
}

/// One closed rent + optional access of the rented mock resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RentRound {
    pub n: u32,
    pub ask_id: String,
    pub bid_commitment_hex: String,
    pub paid_zat: u64,
    pub pool_after: u64,
    /// HTTP access of ergors mock-inference `/health` (or `PIR_INFER_URL`).
    pub accessed: bool,
    pub access_detail: String,
    /// Winner bearer reached the open lease.
    pub winner_accessed: bool,
    /// Loser key was rejected on the open lease.
    pub loser_denied: bool,
    /// After close, winner could not access.
    pub closed_denied: bool,
}

/// Several full rounds: ask → private bid → ZAP1 credit → work receipt → pay.
/// Access uses the **public** compute-market mock (`ergors` inference provider),
/// not a forked Akash `provider-services`.
///
/// `live-ict` fails closed: RAM `FrostThresholdPool` + `local_hosting_bundle`
/// is not money. Product fund is `pir-live-attach` (`daemon_builder_from_chain`
/// + `deploy_on` + ics08 execute/query).
#[cfg(feature = "live-ict")]
pub fn run_rent_rounds(_rounds: u32) -> Result<Vec<RentRound>, String> {
    Err(
        "run_rent_rounds: RAM FrostThresholdPool + local_hosting_bundle is not live-ict money; use pir-live-attach daemon_builder_from_chain+deploy_on"
            .into(),
    )
}

#[cfg(not(feature = "live-ict"))]
pub fn run_rent_rounds(rounds: u32) -> Result<Vec<RentRound>, String> {
    if rounds == 0 {
        return Err("need at least one rent round".into());
    }
    let (frost, seats, group) = product_dkg()?;
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .map_err(|e| e.to_string())?
        .with_layered(demo_layered_committees().map_err(|e| e.to_string())?)
        .with_frost(frost.clone());
    let parts = [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ];
    let mut book = crate::SettlementBook::new();
    let mut leases = crate::LeaseBook::new();
    let mut out = Vec::new();
    for n in 1..=rounds {
        let ask_id = format!("ask-rent-{n}");
        let ask = PublicAsk::new(
            &ask_id,
            "tenant-rent",
            "version: \"2.0\"\nservices:\n  infer:\n    image: permissionlessweb/mock-inference-provider:latest\n",
            ResourceAsk {
                cpu_milli: 500,
                memory_mib: 512,
                storage_mib: 512,
                gpu_units: 0,
            },
            "mock-infer",
        );
        let mut wf = PrivateComputeWorkflow::open(ask, pool.clone()).map_err(|e| e.to_string())?;
        let seat = pool
            .layered
            .as_ref()
            .and_then(|o| o.inners.first())
            .and_then(|i| i.seats.first())
            .ok_or("no seat")?;
        let att = SteoffleMpc::attest(&seat.signer).map_err(|e| e.to_string())?;
        let key = tagged_hash(b"e2e-rent-oob", &[&n.to_le_bytes()]);
        let env = EncryptedBidEnvelope::seal(
            &PlaintextBid {
                ask_id: ask_id.clone(),
                bidder_identity: format!("prov-rent-{n}"),
                price_uakt: 1_000 * u64::from(n),
                provider_endpoint: "oob://rent".into(),
            },
            &key,
        )
        .map_err(|e| e.to_string())?;
        let bid_c = env.commitment().commitment;
        let rec = wf.ingest_oob_bid(env, &att).map_err(|e| e.to_string())?;
        if wf.view.payload_contains_plaintext_bid() {
            return Err("plaintext bid leaked".into());
        }
        let zat = 2_000u64;
        let note = tagged_hash(b"e2e-rent-note", &[&n.to_le_bytes()]);
        let bundle = crate::zap1::local_hosting_bundle(
            group,
            note,
            zat,
            &format!("PIR-RENT-{n}"),
            "sib",
        );
        let msg = FrostGroup::spend_message(&group, &note, zat);
        let sig = frost
            .sign_with_seats(&msg, &seats[..2])
            .map_err(|e| e.to_string())?;
        let auth = SpendAuth::from_quorum(
            pool.layered.as_ref().ok_or("no outer")?,
            &parts,
            group,
            note,
            zat,
            Some(tagged_hash(b"rent-bid", &[rec.bid_commitment.as_bytes()])),
        )
        .map_err(|e| e.to_string())?
        .with_frost_sig(sig);
        crate::zap1::accept_on_zap1_client(&bundle).map_err(|e| e.to_string())?;
        wf.credit_deposit_zap1(&bundle, &auth)
            .map_err(|e| e.to_string())?;
        let receipt = crate::WorkReceipt::bind(
            &ask_id,
            tagged_hash(b"e2e-rent-prov", &[&n.to_le_bytes()]),
            zat,
        );
        book.pay_from_pool(&mut wf.pool, &receipt, &auth)
            .map_err(|e| e.to_string())?;

        let winner = crate::DerivedAccess::from_session(&ask_id, &key, &bid_c);
        let loser_key = tagged_hash(b"e2e-rent-oob", &[b"loser", &n.to_le_bytes()]);
        let loser = crate::DerivedAccess::from_session(&ask_id, &loser_key, &bid_c);
        let lease_id = format!("lease-{n}");
        leases.accept_bid(&lease_id, winner.bearer_hex());
        let winner_accessed = leases.access(&lease_id, &winner.bearer_hex()).is_ok();
        let loser_denied = leases.access(&lease_id, &loser.bearer_hex())
            == Err(crate::LeaseAccessError::Unauthorized);
        leases.close(&lease_id).map_err(|e| format!("{e:?}"))?;
        let closed_denied = leases.access(&lease_id, &winner.bearer_hex())
            == Err(crate::LeaseAccessError::Closed);
        if !winner_accessed || !loser_denied || !closed_denied {
            return Err(format!(
                "round {n}: lease access contract failed winner={winner_accessed} loser_denied={loser_denied} closed_denied={closed_denied}"
            ));
        }

        let (accessed, access_detail) = access_rented_mock();
        if std::env::var("PIR_REQUIRE_ACCESS").ok().as_deref() == Some("1") && !accessed {
            return Err(format!("round {n}: access required: {access_detail}"));
        }
        out.push(RentRound {
            n,
            ask_id,
            bid_commitment_hex: rec.bid_commitment,
            paid_zat: zat,
            pool_after: wf.pool.balance_zat,
            accessed,
            access_detail,
            winner_accessed,
            loser_denied,
            closed_denied,
        });
        pool = wf.pool.clone();
    }
    Ok(out)
}

fn access_rented_mock() -> (bool, String) {
    let url = std::env::var("PIR_INFER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:11434/health".into());
    match std::process::Command::new("curl")
        .args(["-sf", "--max-time", "2", &url])
        .output()
    {
        Ok(o) if o.status.success() => (true, format!("GET {url} ok")),
        Ok(o) => (
            false,
            format!(
                "GET {url} exit={} (ergors mock-inference; not Akash provider-services)",
                o.status
            ),
        ),
        Err(e) => (false, format!("curl {url}: {e}")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowPartialReport {
    pub deposit_zat: u64,
    pub earned_zat: u64,
    pub remainder_zat: u64,
    pub pool_after: u64,
    pub winner_accessed: bool,
    pub closed_denied: bool,
}

/// Partial accrue, escrow close (tenant), atomic two-intent settle, bearer denied.
/// Not the full-pay `run_rent_rounds` path.
pub fn run_escrow_partial_close() -> Result<EscrowPartialReport, String> {
    use crate::access::{DerivedAccess, LeaseBook};
    use crate::escrow::{settle_close, EscrowCell, EscrowMemberIds, EscrowParty};
    use crate::settlement::SettlementBook;
    use crate::zap1::local_hosting_bundle;

    let deposit = 100u64;
    let earned = 40u64;
    let bid_c = tagged_hash(b"bid", &[b"escrow-partial"]);
    let (frost, seats, group) = product_dkg()?;
    let mut pool = FrostThresholdPool::new(group, 2, 3)
        .map_err(|e| e.to_string())?
        .bind_bid(bid_c)
        .with_layered(demo_layered_committees().map_err(|e| e.to_string())?)
        .with_frost(frost.clone());
    let parts = [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ];
    let dep_note = tagged_hash(b"n", &[b"escrow-partial-dep"]);
    let bundle = local_hosting_bundle(group, dep_note, deposit, "PIR-PARTIAL", "sib");
    let msg = FrostGroup::spend_message(&group, &dep_note, deposit);
    let sig = frost
        .sign_with_seats(&msg, &seats[..2])
        .map_err(|e| e.to_string())?;
    let auth = SpendAuth::from_quorum(
        pool.layered.as_ref().ok_or("outer")?,
        &parts,
        group,
        dep_note,
        deposit,
        Some(bid_c),
    )
    .map_err(|e| e.to_string())?
    .with_frost_sig(sig);

    let mut cell = EscrowCell::open(
        deposit,
        bid_c,
        EscrowMemberIds {
            tenant: "tenant-a".into(),
            provider: "provider-b".into(),
            resolver: "resolver-c".into(),
        },
    )
    .map_err(|e| e.to_string())?;
    cell.fund_with_zap1(&mut pool, &bundle, &auth)
        .map_err(|e| e.to_string())?;
    let hp_proof = hosting_payment::prove_inclusion("PIR-PARTIAL", "sib", &group, deposit)
        .map_err(|e| format!("halo2 prove: {e}"))?;
    let hp_inst = hosting_payment::encode_instances("PIR-PARTIAL", "sib", &group, deposit);
    match hosting_payment::proof_instance_verify(1, &hp_proof, &hp_inst) {
        Ok(true) => {}
        Ok(false) => return Err("halo2 proof_instance_verify rejected inclusion".into()),
        Err(e) => return Err(format!("halo2 verify: {e}")),
    }
    // Earned is Halo2 of f(open_height, close_height, rate), not a closer bill.
    let (wit, pubv, proof) = crate::accrual::commit_and_prove_accrual(
        crate::accrual::HeightWindow {
            open_height: 10,
            close_height: 50,
        },
        crate::accrual::AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[b"partial"]),
        tagged_hash(b"hdr", &[b"open-partial"]),
        tagged_hash(b"hdr", &[b"close-partial"]),
    )
    .map_err(|e| e.to_string())?;
    if wit.earned_zat != earned
        || wit.earned_zat
            != crate::accrual::f(
                10,
                50,
                crate::accrual::AccrualRate {
                    zat_per_height: 1,
                },
            )
            .map_err(|e| e.to_string())?
    {
        return Err("composed arbiter: height accrual did not bind f()".into());
    }
    cell.accrue_from_witness_halo2(wit, pubv, &proof)
        .map_err(|e| e.to_string())?;
    let key = tagged_hash(b"sess", &[b"partial"]);
    let winner = DerivedAccess::from_session("ask-partial", &key, &bid_c);
    let mut leases = LeaseBook::new();
    leases.accept_bid("lease-partial", winner.bearer_hex());
    let winner_accessed = leases
        .access("lease-partial", &winner.bearer_hex())
        .is_ok();
    cell.close(EscrowParty::Tenant, &mut leases, "lease-partial", None)
        .map_err(|e| e.to_string())?;
    let closed_denied = leases.access("lease-partial", &winner.bearer_hex())
        == Err(crate::LeaseAccessError::Closed);

    let mut book = SettlementBook::new();
    let pay_note = cell.provider_receipt("ask-partial").work_digest;
    let ref_note = cell.refund_receipt("ask-partial").work_digest;
    let pay_msg = FrostGroup::spend_message(&group, &pay_note, earned);
    let pay_sig = frost
        .sign_with_seats(&pay_msg, &seats[..2])
        .map_err(|e| e.to_string())?;
    let pay = SpendAuth::from_quorum(
        pool.layered.as_ref().ok_or("outer")?,
        &parts,
        group,
        pay_note,
        earned,
        Some(bid_c),
    )
    .map_err(|e| e.to_string())?
    .with_frost_sig(pay_sig);
    let rem = deposit - earned;
    let ref_msg = FrostGroup::spend_message(&group, &ref_note, rem);
    let ref_sig = frost
        .sign_with_seats(&ref_msg, &seats[..2])
        .map_err(|e| e.to_string())?;
    let refund = SpendAuth::from_quorum(
        pool.layered.as_ref().ok_or("outer")?,
        &parts,
        group,
        ref_note,
        rem,
        Some(bid_c),
    )
    .map_err(|e| e.to_string())?
    .with_frost_sig(ref_sig);
    settle_close(
        &cell,
        &mut book,
        &mut pool,
        Some(&pay),
        Some(&refund),
        "ask-partial",
    )
    .map_err(|e| e.to_string())?;

    Ok(EscrowPartialReport {
        deposit_zat: deposit,
        earned_zat: earned,
        remainder_zat: rem,
        pool_after: pool.balance_zat,
        winner_accessed,
        closed_denied,
    })
}

/// One arbiter: `deploy_on` + `fund_with_zap1` + two FROST spends + bearer deny.
/// Fail-closed if any piece is skipped. `live-ict` is **one** `pir-live-attach`
/// process (`daemon_builder_from_chain` + `deploy_on` + on-chain zap1 + grant).
/// Two spends on that path are Zakura Ironwood notes (`PIR_ZAKURA_LAB=1`);
/// a RAM `FrostThresholdPool` is not money.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposedArbiterReport {
    pub deploy_on: bool,
    pub fund_with_zap1: bool,
    pub two_frost_spends: bool,
    pub bearer_deny: bool,
    pub live_ict: Option<String>,
    /// True only when live-ict attach supplied deploy+zap1 and Zakura supplied spends.
    pub one_ict_process: bool,
}

pub fn run_composed_arbiter() -> Result<ComposedArbiterReport, String> {
    composed_arbiter_inner()
}

#[cfg(all(feature = "cw-orch-suite", feature = "live-ict"))]
fn lease_winner_close_denied() -> Result<(bool, bool), String> {
    use crate::access::{DerivedAccess, LeaseBook};
    let bid_c = tagged_hash(b"bid", &[b"ict-arbiter"]);
    let key = tagged_hash(b"sess", &[b"ict-arbiter"]);
    let winner = DerivedAccess::from_session("ask-ict-arbiter", &key, &bid_c);
    let mut leases = LeaseBook::new();
    leases.accept_bid("lease-ict-arbiter", winner.bearer_hex());
    let winner_accessed = leases
        .access("lease-ict-arbiter", &winner.bearer_hex())
        .is_ok();
    leases
        .close("lease-ict-arbiter")
        .map_err(|e| format!("{e:?}"))?;
    let closed_denied = leases.access("lease-ict-arbiter", &winner.bearer_hex())
        == Err(crate::LeaseAccessError::Closed);
    Ok((winner_accessed, closed_denied))
}

#[cfg(feature = "cw-orch-suite")]
fn zcash_two_spends() -> Result<(), String> {
    let z = crate::zcash_escrow::ZcashEscrow::connect()
        .map_err(|e| format!("composed arbiter: zakura lab fail-closed: {e}"))?;
    let (fg, seats, _) = product_dkg()?;
    let note = z
        .open_note(&fg, &seats[..2], 100, "arbiter")
        .map_err(|e| format!("composed arbiter: zcash open: {e}"))?;
    let open_h = snapshot_open_height(&z)?;
    let acc = ironwood_accrual_from_zakura(&z, open_h, 100, b"arbiter-zcash")?;
    let (pay, refund) = z
        .close_notes(&fg, &seats[..2], &note, acc.earned_zat)
        .map_err(|e| format!("composed arbiter: z_frostspend: {e}"))?;
    if pay.txid.is_empty() || refund.txid.is_empty() {
        return Err("composed arbiter: zcash two spends missing txid".into());
    }
    Ok(())
}

#[cfg(not(feature = "cw-orch-suite"))]
fn composed_arbiter_inner() -> Result<ComposedArbiterReport, String> {
    Err(
        "composed arbiter: PrivateInference::deploy_on skipped (need --features cw-orch-suite)"
            .into(),
    )
}

#[cfg(feature = "cw-orch-suite")]
fn composed_arbiter_inner() -> Result<ComposedArbiterReport, String> {
    let report = ComposedArbiterReport {
        deploy_on: false,
        fund_with_zap1: false,
        two_frost_spends: false,
        bearer_deny: false,
        live_ict: None,
        one_ict_process: false,
    };

    #[cfg(feature = "live-ict")]
    {
        return composed_arbiter_live_ict(report);
    }

    #[cfg(not(feature = "live-ict"))]
    {
        composed_arbiter_mock(report)
    }
}

/// One ict process: `pir-live-attach` (daemon_builder_from_chain + deploy_on +
/// zap1 store/match + grant). RAM pool is not the money path.
#[cfg(all(feature = "cw-orch-suite", feature = "live-ict"))]
fn composed_arbiter_live_ict(
    mut report: ComposedArbiterReport,
) -> Result<ComposedArbiterReport, String> {
    let hint = crate::cw_orch::try_live_attach().map_err(|e| {
        format!(
            "composed arbiter: live-ict fail-closed (daemon_builder_from_chain + deploy_on): {e}"
        )
    })?;
    if hint.chain_id.is_empty()
        || !hint.deploy_on_daemon
        || !hint.escrow_grant_recorded
        || !hint.ics08_deployed
        || !hint.ics08_accepted
        || !hint.ics08_tamper_rejected
    {
        return Err(
            "composed arbiter: live-ict requires daemon_builder_from_chain + deploy_on(Daemon) + escrow grant + ics08 execute/query (no BankMsg/uterp)"
                .into(),
        );
    }
    report.live_ict = Some(hint.chain_id.clone());
    report.deploy_on = true;
    if !hint.zap1_stored || !hint.zap1_matches || !hint.zap1_tamper_rejected {
        return Err(
            "composed arbiter: live-ict fund_with_zap1 missing on-chain zap1 (RAM pool is not money)"
                .into(),
        );
    }
    report.fund_with_zap1 = true;

    if !crate::zcash_escrow::lab_required() {
        return Err(
            "composed arbiter: live-ict two Zcash spends require PIR_ZAKURA_LAB=1; RAM FrostThresholdPool is not money"
                .into(),
        );
    }
    zcash_two_spends()?;
    report.two_frost_spends = true;

    let (winner_accessed, closed_denied) = lease_winner_close_denied()?;
    if !winner_accessed || !closed_denied {
        return Err("composed arbiter: bearer deny skipped".into());
    }
    report.bearer_deny = true;
    report.one_ict_process = true;

    if !report.deploy_on
        || !report.fund_with_zap1
        || !report.two_frost_spends
        || !report.bearer_deny
        || !report.one_ict_process
    {
        return Err("composed arbiter: a required piece was skipped".into());
    }
    Ok(report)
}

/// Mock `PrivateInference::deploy_on` + in-process FROST settle. Not ict-rs Daemon.
#[cfg(all(feature = "cw-orch-suite", not(feature = "live-ict")))]
fn composed_arbiter_mock(
    mut report: ComposedArbiterReport,
) -> Result<ComposedArbiterReport, String> {
    use crate::{hex32, PrivateInference, PrivateInferenceDeployData};
    use cw_orch::prelude::*;
    use pir_cw_orch::{
        EscrowPartyMsg, Ics08AcceptedResp, Ics08ExecuteMsg, Ics08ProofStepMsg, Ics08QueryMsg,
    };
    let mock = Mock::new("owner");
    let suite = PrivateInference::deploy_on(mock, PrivateInferenceDeployData)
        .map_err(|e| format!("deploy_on failed: {e}"))?;
    let (_id, grant) = suite
        .escrow_open_accrue_close(
            "bb".repeat(32),
            "tenant1".into(),
            "provider1".into(),
            "resolver1".into(),
            100,
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(32),
            EscrowPartyMsg::Tenant,
        )
        .map_err(|e| format!("deploy_on escrow: {e}"))?;
    if !grant.recorded
        || grant.accrual_commitment.len() != 64
        || grant.earned_zat != 0
        || grant.remainder_zat != 100
    {
        return Err("composed arbiter: deploy_on grant piece skipped".into());
    }
    let g = tagged_hash(b"g", &[b"ics08-mock-arbiter"]);
    let n = tagged_hash(b"n", &[b"ics08-mock-arbiter"]);
    let bundle = crate::zap1::local_hosting_bundle(g, n, 11, "PIR-LC-LIVE", "sib");
    suite
        .ics08_zap1
        .execute(
            &Ics08ExecuteMsg::CreateClient {
                source_client: bundle.ibc.source_client.clone(),
                dest_client: bundle.ibc.dest_client.clone(),
            },
            Some(&[]),
        )
        .map_err(|e| format!("composed arbiter: ics08 create_client: {e}"))?;
    let proof: Vec<Ics08ProofStepMsg> = bundle
        .proof
        .iter()
        .map(|s| Ics08ProofStepMsg {
            sibling_hex: hex32(&s.sibling),
            sibling_is_left: s.sibling_is_left,
        })
        .collect();
    suite
        .ics08_zap1
        .execute(
            &Ics08ExecuteMsg::AttestPacket {
                source_client: bundle.ibc.source_client.clone(),
                dest_client: bundle.ibc.dest_client.clone(),
                sequence: bundle.ibc.sequence,
                timeout_timestamp_ns: bundle.ibc.timeout_timestamp_ns,
                app_data_hash_hex: hex32(&bundle.ibc.app_data_hash),
                note_hex: hex32(&bundle.deposit_note_commitment),
                amount_zat: bundle.amount_zat,
                frost_group_hex: hex32(&bundle.frost_group_id),
                leaf_hex: hex32(&bundle.leaf_hash),
                merkle_root_hex: hex32(&bundle.merkle_root),
                event_kind: "hosting_payment".into(),
                wallet_or_serial: bundle.wallet_or_serial.clone(),
                proof,
            },
            Some(&[]),
        )
        .map_err(|e| format!("composed arbiter: ics08 attest_packet: {e}"))?;
    let acc: Ics08AcceptedResp = suite
        .ics08_zap1
        .query(&Ics08QueryMsg::Accepted {
            source_client: bundle.ibc.source_client,
            dest_client: bundle.ibc.dest_client,
            sequence: bundle.ibc.sequence,
            app_data_hash_hex: hex32(&bundle.ibc.app_data_hash),
        })
        .map_err(|e| format!("composed arbiter: ics08 accepted query: {e}"))?;
    if !acc.accepted {
        return Err(
            "composed arbiter: ics08 store-only instantiate is not packet accept".into(),
        );
    }
    report.deploy_on = true;

    let partial = run_escrow_partial_close()?;
    if partial.deposit_zat != 100 || partial.earned_zat != 40 {
        return Err("composed arbiter: fund_with_zap1 amounts skipped".into());
    }
    report.fund_with_zap1 = true;
    if partial.pool_after != 0 || partial.remainder_zat != 60 {
        return Err("composed arbiter: two FROST spends skipped".into());
    }
    report.two_frost_spends = true;
    if !partial.winner_accessed || !partial.closed_denied {
        return Err("composed arbiter: bearer deny skipped".into());
    }
    report.bearer_deny = true;
    report.one_ict_process = false;

    if crate::zcash_escrow::lab_required() {
        zcash_two_spends()?;
    }

    if !report.deploy_on
        || !report.fund_with_zap1
        || !report.two_frost_spends
        || !report.bearer_deny
    {
        return Err("composed arbiter: a required piece was skipped".into());
    }
    Ok(report)
}

#[derive(Debug, Clone)]
struct ProvenAccrual {
    earned_zat: u64,
    open_height: u64,
    close_height: u64,
    public: crate::accrual::AccrualPublic,
    proof: Vec<u8>,
}

/// Close earned from live Zakura heights: Halo2 of `f(open, close, rate)`.
/// Generates at least one tip block so close height exceeds the post-open tip.
/// Hardcoded `close_notes(..., 40)` is not `f`.
fn snapshot_open_height(z: &crate::zcash_escrow::ZcashEscrow) -> Result<u64, String> {
    crate::accrual::open_at_tip(&z.regtest())
        .map_err(|e| format!("open_at_tip after DKG open: {e}"))
}

fn ironwood_accrual_from_zakura(
    z: &crate::zcash_escrow::ZcashEscrow,
    open_height: u64,
    deposit: u64,
    blind_tag: &[u8],
) -> Result<ProvenAccrual, String> {
    let rt = z.regtest();
    z.generate(1)
        .map_err(|e| format!("generate close-height block: {e}"))?;
    let mut close_height = crate::accrual::open_at_tip(&rt)
        .map_err(|e| format!("open_at_tip close: {e}"))?;
    if close_height <= open_height {
        let need = open_height.saturating_sub(close_height).saturating_add(1);
        z.generate(need)
            .map_err(|e| format!("generate to exceed open_height: {e}"))?;
        close_height = crate::accrual::open_at_tip(&rt)
            .map_err(|e| format!("open_at_tip close retry: {e}"))?;
    }
    if close_height <= open_height {
        return Err(format!(
            "close_height {close_height} must exceed open_height {open_height}"
        ));
    }
    let rate = crate::accrual::AccrualRate {
        zat_per_height: 1,
    };
    let expect = crate::accrual::f(open_height, close_height, rate).map_err(|e| e.to_string())?;
    if expect == 0 || expect > deposit {
        return Err(format!(
            "f({open_height},{close_height},1)={expect} not in (0, deposit={deposit}]"
        ));
    }
    let blinding = tagged_hash(b"pir-accrual-blind", &[blind_tag]);
    let (wit, pubv, proof) = crate::accrual::accrue_from_zakura_halo2(
        &rt,
        open_height,
        close_height,
        rate,
        blinding,
    )
    .map_err(|e| format!("accrue_from_zakura_halo2: {e}"))?;
    crate::accrual::verify_product_accrual(&wit, &pubv, &proof)
        .map_err(|e| format!("verify_product_accrual: {e}"))?;
    if wit.earned_zat != expect {
        return Err(format!(
            "witness earned {} != f({open_height},{close_height},1)={expect}",
            wit.earned_zat
        ));
    }
    if proof.is_empty() {
        return Err("empty Halo2 proof of f()".into());
    }
    println!(
        "halo2_accrual_ok earned_zat={} open_height={} close_height={} rate=1",
        wit.earned_zat, open_height, close_height
    );
    Ok(ProvenAccrual {
        earned_zat: wit.earned_zat,
        open_height,
        close_height,
        public: pubv,
        proof,
    })
}

/// Production marketplace sequence. Fail-closed if any step is skipped.
/// `live-ict` + `PIR_ZAKURA_LAB=1` required. RAM `FrostThresholdPool` is not money.
pub const PRODUCTION_SEQUENCE: &[&str] = &[
    "public_sdl_ask",
    "chacha_oob_bid_commit_match",
    "zap1_halo2_dkg_credit",
    "provider_allocate_after_commit_match",
    "pir_serve_http_200",
    "close_grant_lc_attrs",
    "two_ironwood_spends",
    "winner_bearer_denied",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionSequenceReport {
    pub steps_hit: Vec<String>,
    pub ask_id: String,
    pub ask_commitment: String,
    pub bid_commitment: String,
    pub chain_id: String,
    pub serve_http: u16,
    pub earned_txid: String,
    pub remainder_txid: String,
    pub dummy_used: bool,
    pub earned_zat: u64,
    pub open_height: u64,
    pub close_height: u64,
}

pub fn run_production_sequence() -> Result<ProductionSequenceReport, String> {
    #[cfg(not(feature = "live-ict"))]
    {
        Err(
            "production sequence: live-ict required (fail-closed; no skip-green)".into(),
        )
    }
    #[cfg(feature = "live-ict")]
    {
        production_sequence_live()
    }
}

#[cfg(feature = "live-ict")]
fn production_hit(steps: &mut Vec<String>, name: &str) -> Result<(), String> {
    let expect = PRODUCTION_SEQUENCE
        .get(steps.len())
        .copied()
        .unwrap_or("<end>");
    if expect != name {
        return Err(format!(
            "production sequence skipped or reordered: expected {expect}, got {name} after {:?}",
            steps
        ));
    }
    println!("STEP {name}");
    steps.push(name.into());
    Ok(())
}

#[cfg(feature = "live-ict")]
fn require_halo2_artifacts() -> Result<(), String> {
    for var in [
        "PIR_HALO2_PARAMS",
        "PIR_HALO2_VK_BODY",
        "PIR_HALO2_PROOF",
        "PIR_HALO2_INSTANCES",
    ] {
        match std::env::var(var) {
            Ok(p) if std::path::Path::new(&p).is_file() => {}
            Ok(p) => {
                return Err(format!(
                    "production sequence: {var}={p} is not a file (Halo2 required)"
                ))
            }
            Err(_) => {
                return Err(format!(
                    "production sequence: {var} unset (Halo2 Path A required; no DummyStwo)"
                ))
            }
        }
    }
    Ok(())
}

#[cfg(feature = "live-ict")]
fn production_sequence_live() -> Result<ProductionSequenceReport, String> {
    if std::env::var("PIR_ZAKURA_LAB").ok().as_deref() != Some("1") {
        return Err(
            "production sequence: PIR_ZAKURA_LAB=1 required (fail-closed; no skip-green)"
                .into(),
        );
    }
    require_halo2_artifacts()?;
    if !crate::zcash_escrow::lab_required() {
        return Err("production sequence: Zakura lab required".into());
    }

    std::env::set_var("PIR_KEEP_CHAIN", "1");
    let _keep_chain = KeepLiveChain;
    let mut steps = Vec::new();
    let ask_id = "ask-prod-seq";
    let sdl = "version: \"2.0\"\nservices:\n  infer:\n    image: python:3.12-alpine\n";
    let ask = PublicAsk::new(
        ask_id,
        "tenant-prod-seq",
        sdl,
        ResourceAsk {
            cpu_milli: 1000,
            memory_mib: 4096,
            storage_mib: 8192,
            gpu_units: 0,
        },
        "cpu-infer",
    );
    ask.validate().map_err(|e| e.to_string())?;
    production_hit(&mut steps, "public_sdl_ask")?;

    let session = tagged_hash(b"prod-seq-oob", &[b"k"]);
    let envelope = EncryptedBidEnvelope::seal(
        &PlaintextBid {
            ask_id: ask_id.into(),
            bidder_identity: "prov-prod-seq".into(),
            price_uakt: 12_000,
            provider_endpoint: "oob://prod-seq".into(),
        },
        &session,
    )
    .map_err(|e| e.to_string())?;
    let ask_hex = crate::hex32(&ask.ask_commitment());
    let bid_hex = crate::hex32(&envelope.commitment().commitment);
    envelope
        .commitment()
        .verify_against(&envelope)
        .map_err(|e| e.to_string())?;

    let (frost, frost_seats, group) = product_dkg()?;
    if frost.is_dealer() {
        return Err(
            "production sequence: FrostGroup::dealer is not product custody (need dkg_escrow_seats)"
                .into(),
        );
    }
    let deposit = 100u64;
    let dep_note = tagged_hash(b"prod-seq-zap1-note", &[&group, &deposit.to_le_bytes()]);
    let bundle = crate::zap1::local_hosting_bundle(group, dep_note, deposit, "PIR-PROD-SEQ", "sib");
    let attest = serde_json::to_string(&bundle.lc_helper_request())
        .map_err(|e| format!("zap1 attest json: {e}"))?;
    std::env::set_var("PIR_ZAP1_ATTEST_JSON", &attest);
    let hint = crate::cw_orch::run_live_attach_with_commits(&ask_hex, &bid_hex)
        .map_err(|e| format!("production sequence: live-ict commit/zap1 attach: {e}"))?;
    if hint.chain_id.is_empty()
        || !hint.deploy_on_daemon
        || !hint.zap1_stored
        || !hint.zap1_matches
        || !hint.zap1_tamper_rejected
        || !hint.ics08_accepted
        || !hint.escrow_grant_recorded
    {
        return Err(format!(
            "production sequence: chain did not store 32-byte commits + ZAP1+Halo2: chain_id={} zap1_stored={} zap1_matches={}",
            hint.chain_id, hint.zap1_stored, hint.zap1_matches
        ));
    }
    if hint.rest_url.is_empty() || hint.commit_contract.is_empty() || !hint.keep_chain {
        return Err(
            "production sequence: PIR_KEEP_CHAIN=1 must leave LCD + cw-pir-commit addr (not RAM OnChainView)"
                .into(),
        );
    }
    query_live_commit_match(&hint.rest_url, &hint.commit_contract, &ask_hex, &bid_hex)?;
    production_hit(&mut steps, "chacha_oob_bid_commit_match")?;

    crate::zap1::accept_on_zap1_client(&bundle).map_err(|e| {
        format!("production sequence: ZAP1 live-client accept (not in-proc skip): {e}")
    })?;

    let z = crate::zcash_escrow::ZcashEscrow::connect()
        .map_err(|e| format!("production sequence: zakura fail-closed: {e}"))?;
    let opened = z
        .open_note(&frost, &frost_seats[..2], deposit, "prod-seq")
        .map_err(|e| format!("production sequence: DKG Ironwood open: {e}"))?;
    if opened.amount_zat != deposit {
        return Err("production sequence: Ironwood open did not credit DKG pool".into());
    }
    if !hint.zap1_matches || !hint.zap1_stored {
        return Err("production sequence: on-chain ZAP1+Halo2 did not accept DKG credit".into());
    }
    println!("ZAP1_DKG_CREDIT_OK amount_zat={deposit} ironwood_open=true zap1_onchain=true");
    let open_height = snapshot_open_height(&z)?;
    production_hit(&mut steps, "zap1_halo2_dkg_credit")?;

    let bearer = crate::DerivedAccess::from_session(ask_id, &session, &envelope.commitment().commitment)
        .bearer_hex();
    let work = prod_sidecar_serve(
        &ask_hex,
        &bid_hex,
        &envelope,
        &session,
        &bearer,
        &hint,
    )?;
    production_hit(&mut steps, "provider_allocate_after_commit_match")?;
    if work.serve_http != 200 {
        return Err(format!(
            "production sequence: pir serve HTTP {} (inspect Running is not HTTP 200)",
            work.serve_http
        ));
    }
    production_hit(&mut steps, "pir_serve_http_200")?;

    use crate::escrow::EscrowParty;
    use crate::escrow_notice::{CloseAction, CloseEventAttest, CloseEventAttrs};
    use crate::zap1_lc::{close_event_lc_rebind, CloseEventLcRequest};
    let acc = ironwood_accrual_from_zakura(&z, open_height, deposit, ask_hex.as_bytes())?;
    if acc.proof.is_empty() {
        return Err("production sequence: Halo2 of f() missing".into());
    }
    let cell = tagged_hash(b"prod-seq-cell", &[ask_hex.as_bytes()]);
    let header = tagged_hash(b"prod-seq-hdr", &[b"open"]);
    let txh = tagged_hash(b"prod-seq-tx", &[b"close"]);
    let attrs = CloseEventAttrs {
        action: CloseAction::Close,
        cell_id: cell,
        closer: EscrowParty::Tenant,
        earned_zat: 0,
        remainder_zat: deposit,
    };
    let attest = CloseEventAttest::bind(header, txh, &attrs);
    let req = CloseEventLcRequest::bind(
        header,
        txh,
        attest.app_data_hash,
        "close",
        cell,
        "tenant",
        0,
        deposit,
    )
    .with_grant_public(
        hex::encode(acc.public.commitment),
        hex::encode(acc.public.open_header_hash),
        hex::encode(acc.public.close_header_hash),
    );
    if !hint.ics08_accepted {
        return Err(
            "production sequence: close needs live ics08 packet accept (pir-zap1-lc helper is not the LC)"
                .into(),
        );
    }
    close_event_lc_rebind(&req)
        .map_err(|e| format!("production sequence: close grant attrs rebind: {e}"))?;
    if !hint.escrow_grant_recorded {
        return Err("production sequence: on-chain escrow grant missing".into());
    }
    production_hit(&mut steps, "close_grant_lc_attrs")?;

    let (pay, refund) = z
        .close_notes(&frost, &frost_seats[..2], &opened, acc.earned_zat)
        .map_err(|e| format!("production sequence: two Ironwood spends: {e}"))?;
    if pay.txid.is_empty() || refund.txid.is_empty() || pay.txid == refund.txid {
        return Err("production sequence: two Ironwood spends missing distinct txids".into());
    }
    production_hit(&mut steps, "two_ironwood_spends")?;

    work.deny_winner()
        .map_err(|e| format!("production sequence: winner bearer deny: {e}"))?;
    production_hit(&mut steps, "winner_bearer_denied")?;

    if steps.len() != PRODUCTION_SEQUENCE.len() {
        return Err(format!(
            "production sequence: a required step was skipped: {:?}",
            steps
        ));
    }
    let report = ProductionSequenceReport {
        steps_hit: steps,
        ask_id: ask_id.into(),
        ask_commitment: ask_hex,
        bid_commitment: bid_hex,
        chain_id: hint.chain_id,
        serve_http: 200,
        earned_txid: pay.txid,
        remainder_txid: refund.txid,
        dummy_used: frost.is_dealer()
            || !hint.ics08_accepted
            || !hint.zap1_stored
            || hint.rest_url.is_empty()
            || hint.commit_contract.is_empty(),
        earned_zat: acc.earned_zat,
        open_height: acc.open_height,
        close_height: acc.close_height,
    };
    if report.dummy_used {
        return Err("production sequence: dummy_used derived true (live LCD/commit/ics08/zap1 credit missing)".into());
    }
    println!(
        "PRODUCTION_SEQUENCE_OK dummy_used={} serve_http=200 earned_zat={} open_height={} close_height={} steps_hit={:?}",
        report.dummy_used, report.earned_zat, report.open_height, report.close_height, report.steps_hit
    );
    Ok(report)
}

#[cfg(feature = "live-ict")]
struct KeepLiveChain;

#[cfg(feature = "live-ict")]
impl Drop for KeepLiveChain {
    fn drop(&mut self) {
        let filters = ["name=pir-live", "name=ict-pir-live"];
        for filter in filters {
            if let Ok(o) = std::process::Command::new("docker")
                .args(["ps", "-aq", "--filter", filter])
                .output()
            {
                for id in String::from_utf8_lossy(&o.stdout).split_whitespace() {
                    let _ = std::process::Command::new("docker")
                        .args(["rm", "-f", id])
                        .status();
                }
            }
        }
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", "ict-pir-live-attach-pir-live-1-val-0"])
            .status();
    }
}

#[cfg(feature = "live-ict")]
fn query_live_commit_match(rest: &str, contract: &str, ask: &str, bid: &str) -> Result<(), String> {
    let py = format!(
        r#"import json,base64,urllib.parse,urllib.request
q=json.dumps({{"match":{{"ask_commitment":"{ask}","bid_commitment":"{bid}"}}}}).encode()
u="{rest}/cosmwasm/wasm/v1/contract/{contract}/smart/"+urllib.parse.quote(base64.b64encode(q).decode(), safe="")
print(urllib.request.urlopen(u, timeout=8).read().decode())
"#
    );
    let mut last = String::new();
    for _ in 0..20 {
        let o = std::process::Command::new("python3")
            .args(["-c", &py])
            .output()
            .map_err(|e| format!("live cw-pir-commit query: {e}"))?;
        let stdout = String::from_utf8_lossy(&o.stdout).to_string();
        let stderr = String::from_utf8_lossy(&o.stderr).to_string();
        if o.status.success()
            && (stdout.contains("\"matches\":true") || stdout.contains("\"matches\": true"))
        {
            println!("LIVE_CW_PIR_COMMIT_MATCH_OK contract={contract}");
            return Ok(());
        }
        last = format!("stdout={stdout} stderr={stderr}");
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err(format!("live cw-pir-commit match not true: {last}"))
}

#[cfg(feature = "live-ict")]
fn lcd_smart_base(rest: &str, contract: &str) -> String {
    format!(
        "{}/cosmwasm/wasm/v1/contract/{}/smart",
        rest.trim_end_matches('/'),
        contract
    )
}

#[cfg(feature = "live-ict")]
struct ProdSidecar {
    sidecar: String,
    lease_container: String,
    net: String,
    lease: String,
    bearer: String,
}

#[cfg(feature = "live-ict")]
impl Drop for ProdSidecar {
    fn drop(&mut self) {
        let _ = docker_out(&[
            "exec",
            &self.sidecar,
            "provider-services",
            "pir",
            "stop",
            "--lease",
            &self.lease,
        ]);
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.sidecar, &self.lease_container])
            .status();
        let _ = std::process::Command::new("docker")
            .args(["network", "rm", &self.net])
            .status();
    }
}

#[cfg(feature = "live-ict")]
impl ProdSidecar {
    fn deny_winner(&self) -> Result<(), String> {
        let close = docker_out(&[
            "exec",
            &self.sidecar,
            "provider-services",
            "pir",
            "close",
            "--lease",
            &self.lease,
        ])?;
        let _ = close;
        let access = std::process::Command::new("docker")
            .args([
                "exec",
                &self.sidecar,
                "provider-services",
                "pir",
                "access",
                "--lease",
                &self.lease,
                "--bearer",
                &self.bearer,
            ])
            .output()
            .map_err(|e| format!("pir access: {e}"))?;
        if access.status.success() {
            return Err("winner bearer still accepted after close".into());
        }
        Ok(())
    }
}

#[cfg(feature = "live-ict")]
fn docker_out(args: &[&str]) -> Result<String, String> {
    let o = std::process::Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| format!("docker {args:?}: {e}"))?;
    let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
    if !o.status.success() {
        return Err(format!(
            "docker {args:?} exit={} stdout={stdout} stderr={stderr}",
            o.status
        ));
    }
    Ok(stdout)
}

#[cfg(feature = "live-ict")]
fn wait_url(url: &str) -> Result<String, String> {
    for _ in 0..40 {
        let o = std::process::Command::new("curl")
            .args(["-fsS", "--max-time", "2", url])
            .output();
        if let Ok(o) = o {
            if o.status.success() {
                return Ok(String::from_utf8_lossy(&o.stdout).trim().to_string());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err(format!("timed out waiting for {url}"))
}

#[cfg(feature = "live-ict")]
struct ProdServe {
    _guard: ProdSidecar,
    serve_http: u16,
}

#[cfg(feature = "live-ict")]
impl ProdServe {
    fn deny_winner(&self) -> Result<(), String> {
        self._guard.deny_winner()
    }
}

#[cfg(feature = "live-ict")]
fn prod_sidecar_serve(
    ask_hex: &str,
    bid_hex: &str,
    envelope: &EncryptedBidEnvelope,
    session: &[u8; 32],
    bearer: &str,
    hint: &crate::cw_orch::LiveDaemonHint,
) -> Result<ProdServe, String> {
    let info = std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("docker required for pir serve: {e}"))?;
    if !info.success() {
        return Err("production sequence: docker required for pir serve (fail-closed)".into());
    }
    let img = std::env::var("PIR_PROVIDER_IMAGE")
        .unwrap_or_else(|_| "akash-provider-pir:local".into());
    docker_out(&["image", "inspect", &img]).map_err(|e| {
        format!("production sequence: provider image {img} missing (build Dockerfile.pir): {e}")
    })?;

    let dir = std::env::temp_dir().join("pir-prod-seq");
    std::fs::create_dir_all(&dir).map_err(|e| format!("prod-seq dir: {e}"))?;
    let env_path = dir.join("envelope.json");
    std::fs::write(
        &env_path,
        serde_json::to_vec(envelope).map_err(|e| format!("envelope json: {e}"))?,
    )
    .map_err(|e| format!("write envelope: {e}"))?;
    let zap1_path = dir.join("zap1-accept.json");
    let zap1_body = serde_json::json!({
        "accepted": hint.zap1_matches,
        "matches": hint.zap1_matches,
        "zap1_matches": hint.zap1_matches,
        "zap1_halo2_accepted": hint.zap1_stored && hint.zap1_matches,
        "zap1_halo2_stored": hint.zap1_stored,
    });
    std::fs::write(
        &zap1_path,
        serde_json::to_vec(&zap1_body).map_err(|e| format!("zap1 json: {e}"))?,
    )
    .map_err(|e| format!("write zap1 accept: {e}"))?;

    if hint.rest_url.is_empty() || hint.commit_contract.is_empty() {
        return Err(
            "production sequence: sidecar needs live LCD + cw-pir-commit addr (not a RAM commit store)"
                .into(),
        );
    }
    let match_url_host = lcd_smart_base(&hint.rest_url, &hint.commit_contract);
    let match_url_docker = match_url_host.replace("127.0.0.1", "host.docker.internal");

    let net = "pir-prod-seq";
    let sidecar = "pir-ict-sidecar-prod";
    let lease = "lease-prod-seq";
    let lease_container = format!("pir-lease-{lease}");
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", &sidecar, &lease_container])
        .status();
    let _ = std::process::Command::new("docker")
        .args(["network", "rm", net])
        .status();
    let _ = docker_out(&["network", "create", net]);

    let env_host = env_path.to_string_lossy().into_owned();
    let zap1_host = zap1_path.to_string_lossy().into_owned();
    let session_hex = hex::encode(session);
    docker_out(&[
        "run",
        "-d",
        "--name",
        sidecar,
        "--network",
        net,
        "--add-host",
        "host.docker.internal:host-gateway",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        &format!("{env_host}:/tmp/pir/envelope.json:ro"),
        "-v",
        &format!("{zap1_host}:/tmp/pir/zap1-accept.json:ro"),
        "-e",
        "PIR_REQUIRE_COMMIT=1",
        "-e",
        "PIR_REQUIRE_ENVELOPE=1",
        "-e",
        "PIR_ZAP1_REQUIRE=1",
        "-e",
        &format!("PIR_ASK_COMMIT={ask_hex}"),
        "-e",
        &format!("PIR_BID_COMMIT={bid_hex}"),
        "-e",
        "PIR_BID_ENVELOPE_FILE=/tmp/pir/envelope.json",
        "-e",
        &format!("PIR_SESSION_KEY={session_hex}"),
        "-e",
        &format!("PIR_COMMIT_MATCH_URL={match_url_docker}"),
        "-e",
        "PIR_ZAP1_ACCEPT_FILE=/tmp/pir/zap1-accept.json",
        "-e",
        "PIR_LEASE_BOOK_FILE=/tmp/pir/leases.json",
        "-e",
        "PIR_SERVE_IMAGE=python:3.12-alpine",
        "-p",
        "127.0.0.1:8445:8444",
        &img,
        "pir",
        "sidecar",
    ])?;

    let health = wait_url("http://127.0.0.1:8445/health")
        .map_err(|e| format!("sidecar health: {e}"))?;
    if !health.contains("\"allocate\":true") && !health.contains("\"allocate\": true") {
        return Err(format!("allocate denied after commit match: {health}"));
    }
    if !health.contains("\"match_url\":true") && !health.contains("\"match_url\": true") {
        return Err(format!("PIR_COMMIT_MATCH_URL not set on sidecar: {health}"));
    }

    let check = docker_out(&["exec", sidecar, "provider-services", "pir", "check"])?;
    if !check.contains("\"allocate\":true") && !check.contains("\"allocate\": true") {
        return Err(format!("pir check allocate false: {check}"));
    }
    if !check.contains("\"envelope\":true") && !check.contains("\"envelope\": true") {
        return Err(format!("pir check missing envelope: {check}"));
    }
    if !check.contains("\"match_url\":true") && !check.contains("\"match_url\": true") {
        return Err(format!("pir check missing match_url: {check}"));
    }

    let serve = docker_out(&[
        "exec",
        sidecar,
        "provider-services",
        "pir",
        "serve",
        "--lease",
        lease,
        "--bearer",
        bearer,
        "--port",
        "18777",
    ])?;
    if !serve.contains("\"served\":true") && !serve.contains("\"served\": true") {
        return Err(format!("pir serve did not spawn: {serve}"));
    }
    let inspect = docker_out(&[
        "inspect",
        "-f",
        "running={{.State.Running}} image={{.Config.Image}}",
        &lease_container,
    ])?;
    if !inspect.contains("running=true") {
        return Err(format!("lease container not running: {inspect}"));
    }
    let http = docker_out(&[
        "exec",
        &lease_container,
        "python",
        "-c",
        "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8080/'); print(r.status)",
    ])?;
    if !http.contains("200") {
        return Err(format!(
            "pir serve HTTP not 200 (inspect Running is not enough): {http}"
        ));
    }

    Ok(ProdServe {
        _guard: ProdSidecar {
            sidecar: sidecar.into(),
            lease_container,
            net: net.into(),
            lease: lease.into(),
            bearer: bearer.into(),
        },
        serve_http: 200,
    })
}
