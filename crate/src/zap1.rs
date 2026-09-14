//! Product Zcash inclusion: ZAP1 Merkle verify + IBC v2 packet attestation.
//!
//! ZAP1 (`zap1-verify` 0.2.1, Frontier-Compute, Mar–May 2026) proves a
//! lifecycle event is in a BLAKE2b tree whose root is intended to be
//! anchored in an Orchard memo. That is **not** Orchard note-commitment
//! inclusion and **not** a viewing-key open of the memo.
//!
//! IBC v2 attestation here is the app packet the CosmWasm module
//! (`cw-zap1-ibcv2`) commits: clients + sequence + app-data hash binding
//! note, amount, FROST group, and the ZAP1 leaf. Local `packet_commitment`
//! is not a light client. On-chain accept is `zap1_lc::require_onchain_accept`.

use crate::tagged_hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zap1_verify::{
    compute_leaf_hash, verify_proof, EventPayload, ProofStep, SiblingPosition,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Zap1Error {
    #[error("zap1 merkle proof failed")]
    Merkle,
    #[error("leaf does not match event payload")]
    LeafMismatch,
    #[error("ibc v2 packet does not bind deposit")]
    IbcBind,
    #[error("empty ibc client id")]
    EmptyClient,
    #[error("zero sequence")]
    ZeroSequence,
    #[error("orchard anchor is not a 32-byte hex root/txid")]
    BadAnchor,
    #[error("orchard anchor is not the live zakura tip")]
    AnchorMismatch,
    #[error("orchard anchor required against a live node")]
    AnchorRequired,
    #[error("on-chain zap1 ibc v2 accept required (helper/spawn missing)")]
    ChainAcceptRequired,
    #[error("live zap1 ibc v2 client did not accept packet")]
    LiveClient,
    #[error("eco cannot spawn zap1 ibc v2 client ({0})")]
    EcoUnavailable(String),
}

/// IBC v2 packet fields (clients, not v1 channel-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IbcV2PacketAttest {
    pub source_client: String,
    pub dest_client: String,
    pub sequence: u64,
    pub timeout_timestamp_ns: u64,
    /// SHA-256 of note || amount_le || frost_group || zap1_leaf.
    pub app_data_hash: [u8; 32],
}

impl IbcV2PacketAttest {
    pub fn bind(
        source_client: impl Into<String>,
        dest_client: impl Into<String>,
        sequence: u64,
        timeout_timestamp_ns: u64,
        note: &[u8; 32],
        amount_zat: u64,
        frost_group: &[u8; 32],
        zap1_leaf: &[u8; 32],
    ) -> Self {
        Self {
            source_client: source_client.into(),
            dest_client: dest_client.into(),
            sequence,
            timeout_timestamp_ns,
            app_data_hash: app_data_hash(note, amount_zat, frost_group, zap1_leaf),
        }
    }

    pub fn verify_binds(
        &self,
        note: &[u8; 32],
        amount_zat: u64,
        frost_group: &[u8; 32],
        zap1_leaf: &[u8; 32],
    ) -> Result<(), Zap1Error> {
        if self.source_client.is_empty() || self.dest_client.is_empty() {
            return Err(Zap1Error::EmptyClient);
        }
        if self.sequence == 0 {
            return Err(Zap1Error::ZeroSequence);
        }
        let expect = app_data_hash(note, amount_zat, frost_group, zap1_leaf);
        if self.app_data_hash != expect {
            return Err(Zap1Error::IbcBind);
        }
        Ok(())
    }

    /// Local packet commitment (what a module would store). Not a light-client check.
    pub fn packet_commitment(&self) -> [u8; 32] {
        tagged_hash(
            b"ibc-v2-packet-v1",
            &[
                self.source_client.as_bytes(),
                self.dest_client.as_bytes(),
                &self.sequence.to_be_bytes(),
                &self.timeout_timestamp_ns.to_be_bytes(),
                &self.app_data_hash,
            ],
        )
    }
}

pub fn app_data_hash(
    note: &[u8; 32],
    amount_zat: u64,
    frost_group: &[u8; 32],
    zap1_leaf: &[u8; 32],
) -> [u8; 32] {
    tagged_hash(
        b"ibc-v2-zap1-app-v1",
        &[note, &amount_zat.to_le_bytes(), frost_group, zap1_leaf],
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Zap1EventKind {
    HostingPayment,
    ProgramEntry,
    OwnershipAttest,
}

/// One sibling in a ZAP1 Merkle path (serde-friendly).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zap1ProofStep {
    pub sibling: [u8; 32],
    /// True if the sibling is on the left (IBC/ZAP1 `SiblingPosition::Left`).
    pub sibling_is_left: bool,
}

/// Product inclusion bundle: ZAP1 path + IBC v2 bind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zap1Ibcv2Bundle {
    pub frost_group_id: [u8; 32],
    pub deposit_note_commitment: [u8; 32],
    pub amount_zat: u64,
    pub event_kind: Zap1EventKind,
    pub wallet_or_serial: String,
    pub leaf_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub proof: Vec<Zap1ProofStep>,
    /// Optional Orchard anchor txid (hex). Recorded, not opened.
    pub orchard_anchor_txid: Option<String>,
    pub ibc: IbcV2PacketAttest,
}

impl Zap1Ibcv2Bundle {
    pub fn verify(&self) -> Result<(), Zap1Error> {
        let payload = match self.event_kind {
            Zap1EventKind::HostingPayment => EventPayload::HostingPayment {
                serial_number: self.wallet_or_serial.as_bytes(),
                month: 8,
                year: 2026,
            },
            Zap1EventKind::ProgramEntry => EventPayload::ProgramEntry {
                wallet_hash: self.wallet_or_serial.as_bytes(),
            },
            Zap1EventKind::OwnershipAttest => EventPayload::OwnershipAttest {
                wallet_hash: self.wallet_or_serial.as_bytes(),
                serial_number: b"pir-seat",
            },
        };
        let leaf = compute_leaf_hash(&payload);
        if leaf != self.leaf_hash {
            return Err(Zap1Error::LeafMismatch);
        }
        let path: Vec<ProofStep> = self
            .proof
            .iter()
            .map(|s| ProofStep {
                hash: s.sibling,
                position: if s.sibling_is_left {
                    SiblingPosition::Left
                } else {
                    SiblingPosition::Right
                },
            })
            .collect();
        if !verify_proof(&self.leaf_hash, &path, &self.merkle_root) {
            return Err(Zap1Error::Merkle);
        }
        self.ibc.verify_binds(
            &self.deposit_note_commitment,
            self.amount_zat,
            &self.frost_group_id,
            &self.leaf_hash,
        )?;
        if let Some(ref a) = self.orchard_anchor_txid {
            if !is_hex32(a) {
                return Err(Zap1Error::BadAnchor);
            }
        }
        Ok(())
    }

    /// NS2: stamped tip must equal the node's reported root / bestblockhash.
    pub fn verify_against_zakura(
        &self,
        node: &crate::zakura::ZakuraRegtest,
    ) -> Result<(), Zap1Error> {
        self.verify()?;
        let tip = node
            .commitment_tree_root()
            .map_err(|_| Zap1Error::AnchorRequired)?
            .ok_or(Zap1Error::AnchorRequired)?;
        match &self.orchard_anchor_txid {
            None => Err(Zap1Error::AnchorRequired),
            Some(a) if a.eq_ignore_ascii_case(tip.trim_start_matches("0x")) || a.eq_ignore_ascii_case(&tip) => {
                Ok(())
            }
            Some(_) => Err(Zap1Error::AnchorMismatch),
        }
    }
}

fn is_hex32(s: &str) -> bool {
    let t = s.trim().trim_start_matches("0x");
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Two-leaf tree used by local tests (same construction as zap1-verify e2e vectors).
pub fn local_hosting_bundle(
    frost_group_id: [u8; 32],
    note: [u8; 32],
    amount_zat: u64,
    serial: &str,
    sibling_wallet: &str,
) -> Zap1Ibcv2Bundle {
    let leaf = compute_leaf_hash(&EventPayload::HostingPayment {
        serial_number: serial.as_bytes(),
        month: 8,
        year: 2026,
    });
    let sibling = compute_leaf_hash(&EventPayload::ProgramEntry {
        wallet_hash: sibling_wallet.as_bytes(),
    });
    let root = zap1_verify::node_hash(&leaf, &sibling);
    let ibc = IbcV2PacketAttest::bind(
        "08-zap1-src",
        "08-terp-dst",
        1,
        0,
        &note,
        amount_zat,
        &frost_group_id,
        &leaf,
    );
    Zap1Ibcv2Bundle {
        frost_group_id,
        deposit_note_commitment: note,
        amount_zat,
        event_kind: Zap1EventKind::HostingPayment,
        wallet_or_serial: serial.into(),
        leaf_hash: leaf,
        merkle_root: root,
        proof: vec![Zap1ProofStep {
            sibling,
            sibling_is_left: false,
        }],
        orchard_anchor_txid: None,
        ibc,
    }
}

/// In-process store of packets the **same** wasm client accepted.
/// Product credit queries this (or HTTP). Empty unless `accept_on_zap1_client`.
use std::collections::BTreeSet;
use std::sync::Mutex;

static ACCEPTED: Mutex<BTreeSet<(String, String, u64, [u8; 32])>> = Mutex::new(BTreeSet::new());

fn lab_or_live_ict() -> bool {
    std::env::var("PIR_ZAP1_REQUIRE_CHAIN").ok().as_deref() == Some("1")
        || cfg!(feature = "live-ict")
}

/// Run ZAP1 + IBC v2 verify (same as `cw-ics08-wasm-zap1`) and record accept.
///
/// With `live-ict` / `PIR_ZAP1_REQUIRE_CHAIN=1`: must hit HTTP eco or
/// `PIR_ZAP1_LC_BIN` (lab helper / ict-rs spawn). Missing eco is
/// [`Zap1Error::EcoUnavailable`] — never in-proc skip-green.
pub fn accept_on_zap1_client(bundle: &Zap1Ibcv2Bundle) -> Result<(), Zap1Error> {
    if lab_or_live_ict() {
        return accept_via_eco(bundle);
    }
    let kind = match bundle.event_kind {
        Zap1EventKind::HostingPayment => "hosting_payment",
        Zap1EventKind::ProgramEntry => "program_entry",
        Zap1EventKind::OwnershipAttest => "ownership_attest",
    };
    let ibc = cw_ics08_wasm_zap1::IbcV2Fields {
        source_client: bundle.ibc.source_client.clone(),
        dest_client: bundle.ibc.dest_client.clone(),
        sequence: bundle.ibc.sequence,
        timeout_timestamp_ns: bundle.ibc.timeout_timestamp_ns,
        app_data_hash_hex: hex::encode(bundle.ibc.app_data_hash),
    };
    let steps: Vec<([u8; 32], bool)> = bundle
        .proof
        .iter()
        .map(|s| (s.sibling, s.sibling_is_left))
        .collect();
    cw_ics08_wasm_zap1::verify_zap1_ibcv2(
        &ibc,
        kind,
        &bundle.wallet_or_serial,
        &bundle.deposit_note_commitment,
        bundle.amount_zat,
        &bundle.frost_group_id,
        &bundle.leaf_hash,
        &bundle.merkle_root,
        &steps,
    )
    .map_err(|_| Zap1Error::LiveClient)?;
    ACCEPTED
        .lock()
        .expect("accepted lock")
        .insert((
            bundle.ibc.source_client.clone(),
            bundle.ibc.dest_client.clone(),
            bundle.ibc.sequence,
            bundle.ibc.app_data_hash,
        ));
    Ok(())
}

/// Docker / wasm / helper probe. Never returns Ok as a stand-in for a client.
pub(crate) fn eco_probe_public() -> String {
    eco_probe()
}

fn eco_probe() -> String {
    let mut parts = Vec::new();
    let docker = std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match docker {
        Ok(s) if s.success() => parts.push("docker=ok".into()),
        Ok(s) => parts.push(format!("docker_exit={s}")),
        Err(e) => parts.push(format!("docker_spawn={e}")),
    }
    match std::env::var("PIR_ZAP1_LC_HTTP") {
        Ok(u) if !u.is_empty() => parts.push("PIR_ZAP1_LC_HTTP=set".into()),
        _ => parts.push("PIR_ZAP1_LC_HTTP=unset".into()),
    }
    match std::env::var(crate::zap1_lc::ENV_ZAP1_LC_BIN) {
        Ok(p) if std::path::Path::new(&p).is_file() => parts.push("PIR_ZAP1_LC_BIN=file".into()),
        Ok(_) => parts.push("PIR_ZAP1_LC_BIN=missing_file".into()),
        Err(_) => parts.push("PIR_ZAP1_LC_BIN=unset".into()),
    }
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm = root.join("cw-zap1-ibcv2/target/wasm32-unknown-unknown/release/cw_zap1_ibcv2.wasm");
    if wasm.is_file() {
        parts.push("cw-zap1-ibcv2.wasm=present".into());
    } else {
        parts.push("cw-zap1-ibcv2.wasm=missing".into());
    }
    let attach = root.join("live-chain/target/debug/pir-live-attach");
    if attach.is_file() {
        parts.push("pir-live-attach=present".into());
    } else {
        parts.push("pir-live-attach=missing".into());
    }
    parts.join("; ")
}

fn query_http_accept(url: &str, bundle: &Zap1Ibcv2Bundle) -> Result<(), Zap1Error> {
    let q = format!(
        "{}/accepted?src={}&dst={}&seq={}&hash={}",
        url.trim_end_matches('/'),
        bundle.ibc.source_client,
        bundle.ibc.dest_client,
        bundle.ibc.sequence,
        hex::encode(bundle.ibc.app_data_hash)
    );
    let body = std::process::Command::new("curl")
        .args(["-fsS", "--max-time", "8", &q])
        .output()
        .map_err(|e| Zap1Error::EcoUnavailable(format!("curl {e}; {}", eco_probe())))?;
    if !body.status.success() {
        return Err(Zap1Error::EcoUnavailable(format!(
            "http {} exit={}; {}",
            url,
            body.status,
            eco_probe()
        )));
    }
    let s = String::from_utf8_lossy(&body.stdout);
    if s.contains("\"accepted\":true") || s.contains("\"accepted\": true") {
        record_accepted(bundle);
        Ok(())
    } else {
        Err(Zap1Error::LiveClient)
    }
}

fn accept_via_eco(bundle: &Zap1Ibcv2Bundle) -> Result<(), Zap1Error> {
    if let Ok(url) = std::env::var("PIR_ZAP1_LC_HTTP") {
        if !url.is_empty() {
            return query_http_accept(&url, bundle);
        }
    }
    if already_accepted(bundle) {
        return Ok(());
    }
    if std::env::var(crate::zap1_lc::ENV_ZAP1_LC_BIN).is_ok() {
        let r = crate::zap1_lc::require_onchain_accept(bundle).map_err(|e| match e {
            crate::zap1_lc::Zap1LcError::Rejected => Zap1Error::LiveClient,
            crate::zap1_lc::Zap1LcError::Zap1(z) => z,
            crate::zap1_lc::Zap1LcError::Spawn(s) => {
                Zap1Error::EcoUnavailable(format!("{s}; {}", eco_probe()))
            }
        });
        if r.is_ok() {
            record_accepted(bundle);
        }
        return r;
    }
    match crate::cw_orch::attest_zap1_on_live_chain(bundle) {
        Ok(_) => {
            record_accepted(bundle);
            Ok(())
        }
        Err(e) => Err(Zap1Error::EcoUnavailable(format!("{e}; {}", eco_probe()))),
    }
}

fn record_accepted(bundle: &Zap1Ibcv2Bundle) {
    ACCEPTED.lock().expect("accepted lock").insert((
        bundle.ibc.source_client.clone(),
        bundle.ibc.dest_client.clone(),
        bundle.ibc.sequence,
        bundle.ibc.app_data_hash,
    ));
}

fn already_accepted(bundle: &Zap1Ibcv2Bundle) -> bool {
    ACCEPTED.lock().expect("accepted lock").contains(&(
        bundle.ibc.source_client.clone(),
        bundle.ibc.dest_client.clone(),
        bundle.ibc.sequence,
        bundle.ibc.app_data_hash,
    ))
}

/// Product path: a live (or in-proc wasm-equivalent) query must have accepted.
pub fn require_live_client_accept(bundle: &Zap1Ibcv2Bundle) -> Result<(), Zap1Error> {
    if already_accepted(bundle) {
        return Ok(());
    }
    if lab_or_live_ict() {
        return accept_via_eco(bundle);
    }
    Err(Zap1Error::LiveClient)
}

impl Zap1Ibcv2Bundle {
    /// Record a live Zakura chain tip as the Orchard-anchor *reference*.
    /// Does not open a memo; `bestblockhash` is not a ZAP1 `MERKLE_ROOT` memo txid.
    pub fn stamp_zakura_tip(&mut self, node: &crate::zakura::ZakuraRegtest) -> Result<(), crate::zakura::ZakuraError> {
        if let Some(tip) = node.commitment_tree_root()? {
            self.orchard_anchor_txid = Some(tip);
        } else {
            let v = node.getblockchaininfo()?;
            let r = v.get("result").cloned().unwrap_or(v);
            if let Some(h) = r.get("bestblockhash").and_then(|x| x.as_str()) {
                self.orchard_anchor_txid = Some(h.to_string());
            }
        }
        Ok(())
    }
}
