//! Shielded escrow on **Zakura only** (node `generate` + `sendrawtransaction`).
//!
//! Notes are **Ironwood** (NU6.3, V3 plaintext, v6 tx). Open funds a V3 note to
//! the DKG group's Ironwood receiver (miner coinbase is the shield *source*,
//! not spend authority). Spend is DKG FROST (`frost-spend-v1` in the dest memo)
//! then `add_ironwood_spend` of **that** opened note, proven by its nullifier.
//! Prefer a shielded-only DKG Ironwood spend (ZIP-317 from the note). Miner
//! coinbase pays ZIP-317 only when the note cannot cover the fee — never a
//! wallet sidecar send (send-many / shield-coinbase RPCs) and never a fresh
//! coinbase re-shield as if FROST-owned. Not Sapling/Orchard. Not a RAM u64
//! pool as money.
//!
//! Spend authority is the DKG group: Lagrange-`reconstruct` the FROST-ed25519
//! group secret from any threshold of `KeyPackage`s, then domain-separate into
//! an Ironwood `SpendingKey`. Any valid t-of-n subset owns the same note. The
//! public verifying key is not sufficient. FROST-ed25519 cannot be orchard
//! `SpendAuthorizingKey` (wrong curve); the reconstructed secret still requires
//! the shares.

use crate::frost::{FrostError, FrostGroup, FrostSeat};
use crate::zakura::{lab_spawn, ZakuraError, ZakuraNode, ZakuraRegtest};
use crate::tagged_hash;
use incrementalmerkletree::{Hashable, Level};
use orchard::keys::{DiversifierIndex, FullViewingKey, Scope, SpendingKey};
use orchard::note::{Note as IronwoodNote, NoteVersion, RandomSeed, Rho};
use orchard::tree::MerkleHashOrchard;
use orchard::value::NoteValue;
use serde_json::Value;
use std::process::Command;
use thiserror::Error;

pub const ENV_PIR_ZAKURA_LAB: &str = "PIR_ZAKURA_LAB";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ZcashEscrowError {
    #[error("zakura: {0}")]
    Zakura(#[from] ZakuraError),
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("frost: {0}")]
    Frost(#[from] FrostError),
    #[error("zakura RPC missing (set ZAKURA_RPC or lab_spawn; PIR_ZAKURA_LAB=1 is fail-closed)")]
    RpcMissing,
    #[error("node refused note open/spend: {0}")]
    NoteOp(String),
}

pub fn lab_required() -> bool {
    std::env::var(ENV_PIR_ZAKURA_LAB).ok().as_deref() == Some("1")
}

pub fn attach_zakura() -> Result<ZakuraNode, ZcashEscrowError> {
    let n = lab_spawn().map_err(|e| {
        if lab_required() {
            ZcashEscrowError::Zakura(e)
        } else {
            e.into()
        }
    })?;
    n.as_regtest().getblockchaininfo().map_err(|e| {
        if lab_required() {
            ZcashEscrowError::Rpc(format!("PIR_ZAKURA_LAB=1 getblockchaininfo: {e}"))
        } else {
            ZcashEscrowError::RpcMissing
        }
    })?;
    Ok(n)
}

/// Ironwood receiver owned by the DKG group reconstructed from `seats`.
/// Any valid threshold subset of the same DKG run returns the same address.
pub fn dkg_ironwood_receiver(seats: &[FrostSeat], tag: &[u8]) -> Result<String, ZcashEscrowError> {
    Ok(addr_hex(ironwood_receiver(seats, tag)?))
}

#[derive(Debug, Clone)]
pub struct ShieldedNote {
    pub group_id: [u8; 32],
    pub commitment: [u8; 32],
    pub amount_zat: u64,
    pub tip: String,
    pub z_addr: String,
    pub txid: String,
    /// Serialized Ironwood V3 note (recipient, value, rho, rseed, version).
    pub ironwood_note: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SpendResult {
    pub txid: String,
    pub frost_sig: Vec<u8>,
    pub dest_z_addr: String,
    /// Remainder note still owned by the DKG group after a partial spend.
    pub change: Option<Box<ShieldedNote>>,
    /// Nullifier of the opened DKG Ironwood note this spend consumed.
    pub nullifier: [u8; 32],
}

pub struct ZcashEscrow {
    node: ZakuraNode,
}

impl ZcashEscrow {
    pub fn connect() -> Result<Self, ZcashEscrowError> {
        Ok(Self {
            node: attach_zakura()?,
        })
    }

    pub fn from_node(node: ZakuraNode) -> Self {
        Self { node }
    }

    pub fn regtest(&self) -> ZakuraRegtest {
        self.node.as_regtest()
    }

    fn rpc_result(&self, method: &str, params: Value) -> Result<Value, ZcashEscrowError> {
        let resp = json_rpc(&self.node.rpc_url, method, params)?;
        if let Some(err) = resp.get("error") {
            if !err.is_null() {
                return Err(ZcashEscrowError::NoteOp(format!("{method}: {err}")));
            }
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| ZcashEscrowError::NoteOp(format!("{method}: no result")))
    }

    fn generate_blocks(&self, n: u64) -> Result<Vec<String>, ZcashEscrowError> {
        let v = self.rpc_result("generate", serde_json::json!([n]))?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn send_raw(&self, hex_tx: &str) -> Result<String, ZcashEscrowError> {
        let v = self.rpc_result("sendrawtransaction", serde_json::json!([hex_tx]))?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ZcashEscrowError::NoteOp(format!("sendrawtransaction: {v}")))
    }

    fn wait_tx(&self, txid: &str) -> Result<(), ZcashEscrowError> {
        for _ in 0..40 {
            match self.rpc_result("getrawtransaction", serde_json::json!([txid, 1])) {
                Ok(v) if v.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0) >= 1 => {
                    return Ok(());
                }
                _ => {}
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        Err(ZcashEscrowError::NoteOp(format!(
            "txid {txid} not confirmed on zakura after generate"
        )))
    }

    fn ensure_mature_coinbase(&self) -> Result<(), ZcashEscrowError> {
        let tip = self
            .rpc_result("getblockcount", Value::Array(vec![]))?
            .as_u64()
            .unwrap_or(0);
        if tip < 101 {
            self.generate_blocks(101 - tip)?;
        }
        Ok(())
    }

    /// Open: mine coinbase, submit an Ironwood V3 output of `amount_zat` to the
    /// DKG group receiver via sendrawtransaction, confirm. The note is stored
    /// so spend can `add_ironwood_spend` it. `seats` must be the same threshold
    /// set used at spend (Ironwood SK is seat-bound, not VK-bound).
    pub fn open_note(
        &self,
        group: &FrostGroup,
        seats: &[FrostSeat],
        amount_zat: u64,
        _serial: &str,
    ) -> Result<ShieldedNote, ZcashEscrowError> {
        let _ = self.rpc_result("getblockchaininfo", Value::Array(vec![]))?;
        if dkg_group_id_from_seats(seats)? != group.verifying_key {
            return Err(ZcashEscrowError::NoteOp(
                "DKG seats are not this group's Ironwood spend authority".into(),
            ));
        }
        if !crate::zakura::nu6_3_configured(&self.node.rpc_url) {
            return Err(ZcashEscrowError::NoteOp(
                "Zakura lab is not NU6.3; Ironwood pool notes required (not Orchard, not Sapling)"
                    .into(),
            ));
        }
        self.ensure_mature_coinbase()?;
        let (txid, note) = open_group_ironwood_note(self, group, seats, amount_zat)?;
        self.generate_blocks(1)?;
        self.wait_tx(&txid)?;
        let tip = self
            .regtest()
            .commitment_tree_root()?
            .unwrap_or_else(|| txid.clone());
        let commitment = extracted_cmx(&note);
        Ok(ShieldedNote {
            group_id: group.verifying_key,
            commitment,
            amount_zat: note.value().inner(),
            tip,
            z_addr: addr_hex(note.recipient()),
            txid,
            ironwood_note: encode_ironwood_note(&note),
        })
    }

    pub fn spend_note(
        &self,
        group: &FrostGroup,
        seats: &[FrostSeat],
        note: &ShieldedNote,
        dest_tag: &[u8],
        amount_zat: u64,
    ) -> Result<SpendResult, ZcashEscrowError> {
        if amount_zat > note.amount_zat {
            return Err(ZcashEscrowError::NoteOp("amount exceeds note".into()));
        }
        if note.group_id != group.verifying_key {
            return Err(ZcashEscrowError::NoteOp(
                "note spend authority is a different DKG group".into(),
            ));
        }
        if dkg_group_id_from_seats(seats)? != group.verifying_key {
            return Err(ZcashEscrowError::NoteOp(
                "DKG seats are not this group's Ironwood spend authority".into(),
            ));
        }
        if note.ironwood_note.is_empty() {
            return Err(ZcashEscrowError::NoteOp(
                "DKG spend: opened Ironwood note missing (cannot re-shield coinbase)".into(),
            ));
        }
        let opened = decode_ironwood_note(&note.ironwood_note)?;
        if opened.version() != NoteVersion::V3 {
            return Err(ZcashEscrowError::NoteOp(
                "DKG spend: Ironwood V3 note required".into(),
            ));
        }
        let msg = FrostGroup::spend_message(&note.group_id, &note.commitment, amount_zat);
        let frost_sig = group.sign_with_seats(&msg, seats)?;
        group.verify(&msg, &frost_sig)?;
        let dest_addr = ironwood_receiver(seats, dest_tag)?;
        let (txid, change_note, nullifier) =
            spend_opened_ironwood(self, seats, &opened, dest_addr, amount_zat, &frost_sig)?;
        self.generate_blocks(1)?;
        self.wait_tx(&txid)?;
        let change = change_note.map(|n| {
            Box::new(ShieldedNote {
                group_id: group.verifying_key,
                commitment: extracted_cmx(&n),
                amount_zat: n.value().inner(),
                tip: txid.clone(),
                z_addr: addr_hex(n.recipient()),
                txid: txid.clone(),
                ironwood_note: encode_ironwood_note(&n),
            })
        });
        Ok(SpendResult {
            txid,
            frost_sig,
            dest_z_addr: addr_hex(dest_addr),
            change,
            nullifier,
        })
    }

    pub fn close_notes(
        &self,
        group: &FrostGroup,
        seats: &[FrostSeat],
        note: &ShieldedNote,
        earned_zat: u64,
    ) -> Result<(SpendResult, SpendResult), ZcashEscrowError> {
        let _rem = note
            .amount_zat
            .checked_sub(earned_zat)
            .ok_or_else(|| ZcashEscrowError::NoteOp("earned > deposit".into()))?;
        let pay = self.spend_note(group, seats, note, b"provider", earned_zat)?;
        // Remainder is the DKG-owned change after the earned spend (ZIP-317 may
        // have come from the note). Drain that note to the tenant. Do not
        // re-shield a miner coinbase as if it were FROST-owned.
        match pay.change.as_deref() {
            None => Ok((pay.clone(), pay)),
            Some(change) => {
                let refund =
                    self.spend_note(group, seats, change, b"tenant", change.amount_zat)?;
                Ok((pay, refund))
            }
        }
    }
}

fn json_rpc(rpc: &str, method: &str, params: Value) -> Result<Value, ZcashEscrowError> {
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "pir-zcash-escrow",
        "method": method,
        "params": params,
    });
    let out = Command::new("curl")
        .args(["-sS", "-X", "POST", "-H", "content-type: text/plain", "--data"])
        .arg(body.to_string())
        .arg(rpc)
        .output()
        .map_err(|e| ZcashEscrowError::Rpc(e.to_string()))?;
    if !out.status.success() {
        return Err(ZcashEscrowError::Rpc(
            String::from_utf8_lossy(&out.stderr).into(),
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| ZcashEscrowError::Rpc(e.to_string()))
}

fn key_packages_from_seats(
    seats: &[FrostSeat],
) -> Result<Vec<frost_ed25519::keys::KeyPackage>, ZcashEscrowError> {
    if seats.is_empty() {
        return Err(ZcashEscrowError::NoteOp(
            "DKG Ironwood SK needs threshold seats (not a public verifying key)".into(),
        ));
    }
    let mut pkgs = Vec::with_capacity(seats.len());
    let mut group_vk: Option<Vec<u8>> = None;
    for s in seats {
        let enc = s.encode()?;
        let pkg_hex = enc.split_once(':').map(|(_, p)| p).ok_or_else(|| {
            ZcashEscrowError::NoteOp("DKG seat encoding".into())
        })?;
        let raw = hex::decode(pkg_hex).map_err(|e| ZcashEscrowError::NoteOp(e.to_string()))?;
        let kp = frost_ed25519::keys::KeyPackage::deserialize(&raw).map_err(|e| {
            ZcashEscrowError::NoteOp(format!("DKG KeyPackage: {e}"))
        })?;
        let vk = kp
            .verifying_key()
            .serialize()
            .map_err(|e| ZcashEscrowError::NoteOp(format!("DKG vk: {e}")))?;
        match &group_vk {
            None => group_vk = Some(vk),
            Some(prev) if prev != &vk => {
                return Err(ZcashEscrowError::NoteOp(
                    "DKG seats from different groups cannot own one Ironwood note".into(),
                ));
            }
            Some(_) => {}
        }
        pkgs.push(kp);
    }
    Ok(pkgs)
}

fn dkg_group_id_from_seats(seats: &[FrostSeat]) -> Result<[u8; 32], ZcashEscrowError> {
    let pkgs = key_packages_from_seats(seats)?;
    let vk = pkgs[0]
        .verifying_key()
        .serialize()
        .map_err(|e| ZcashEscrowError::NoteOp(format!("DKG vk: {e}")))?;
    if vk.len() != 32 {
        return Err(ZcashEscrowError::NoteOp("DKG verifying key length".into()));
    }
    let mut gid = [0u8; 32];
    gid.copy_from_slice(&vk);
    Ok(gid)
}

/// Lab custody: Ironwood SK from Lagrange-reconstructed FROST group secret.
/// Any valid threshold subset of the same DKG run yields the same SK. Never
/// derived from the public verifying key. Spend still requires frost-spend-v1.
fn ironwood_sk_from_seats(seats: &[FrostSeat]) -> Result<SpendingKey, ZcashEscrowError> {
    let pkgs = key_packages_from_seats(seats)?;
    let min = *pkgs[0].min_signers();
    if (seats.len() as u16) < min {
        return Err(ZcashEscrowError::NoteOp(
            "DKG Ironwood SK needs threshold seats (not a public verifying key)".into(),
        ));
    }
    let signing = frost_ed25519::keys::reconstruct(&pkgs).map_err(|e| {
        ZcashEscrowError::NoteOp(format!(
            "DKG reconstruct: need threshold shares to own the Ironwood SK ({e})"
        ))
    })?;
    let secret = signing.serialize();
    let mut raw = tagged_hash(b"pir-dkg-ironwood-sk-reconstruct", &[&secret]);
    for s in 0u8..=255 {
        raw[0] ^= s;
        if let Some(sk) = Option::from(SpendingKey::from_bytes(raw)) {
            return Ok(sk);
        }
        raw[0] ^= s;
    }
    Err(ZcashEscrowError::NoteOp(
        "could not derive Ironwood SpendingKey from reconstructed DKG group secret".into(),
    ))
}

fn dest_diversifier(tag: &[u8]) -> DiversifierIndex {
    let n = match tag {
        b"open" | b"" => 0u32,
        b"provider" => 1,
        b"tenant" => 2,
        other => {
            let h = tagged_hash(b"pir-ironwood-div", &[other]);
            u32::from_le_bytes(h[..4].try_into().unwrap())
        }
    };
    DiversifierIndex::from(n)
}

fn ironwood_receiver(seats: &[FrostSeat], tag: &[u8]) -> Result<orchard::Address, ZcashEscrowError> {
    let sk = ironwood_sk_from_seats(seats)?;
    let fvk = FullViewingKey::from(&sk);
    Ok(fvk.address_at(dest_diversifier(tag), Scope::External))
}

fn addr_hex(addr: orchard::Address) -> String {
    hex::encode(addr.to_raw_address_bytes())
}

fn extracted_cmx(note: &IronwoodNote) -> [u8; 32] {
    orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes()
}

fn encode_ironwood_note(n: &IronwoodNote) -> Vec<u8> {
    let mut v = Vec::with_capacity(116);
    v.extend_from_slice(&n.recipient().to_raw_address_bytes());
    v.extend_from_slice(&n.value().inner().to_le_bytes());
    v.extend_from_slice(&n.rho().to_bytes());
    v.extend_from_slice(n.rseed().as_bytes());
    v.push(match n.version() {
        NoteVersion::V3 => 3,
        NoteVersion::V2 => 2,
    });
    v
}

fn decode_ironwood_note(bytes: &[u8]) -> Result<IronwoodNote, ZcashEscrowError> {
    if bytes.len() != 116 {
        return Err(ZcashEscrowError::NoteOp(
            "DKG spend: Ironwood note encoding length".into(),
        ));
    }
    let mut raw_addr = [0u8; 43];
    raw_addr.copy_from_slice(&bytes[..43]);
    let addr = Option::from(orchard::Address::from_raw_address_bytes(&raw_addr)).ok_or_else(
        || ZcashEscrowError::NoteOp("DKG spend: Ironwood recipient".into()),
    )?;
    let mut valb = [0u8; 8];
    valb.copy_from_slice(&bytes[43..51]);
    let value = NoteValue::from_raw(u64::from_le_bytes(valb));
    let mut rhob = [0u8; 32];
    rhob.copy_from_slice(&bytes[51..83]);
    let rho = Option::from(Rho::from_bytes(&rhob))
        .ok_or_else(|| ZcashEscrowError::NoteOp("DKG spend: Ironwood rho".into()))?;
    let mut rseedb = [0u8; 32];
    rseedb.copy_from_slice(&bytes[83..115]);
    let rseed = Option::from(RandomSeed::from_bytes(rseedb, &rho))
        .ok_or_else(|| ZcashEscrowError::NoteOp("DKG spend: Ironwood rseed".into()))?;
    let version = match bytes[115] {
        3 => NoteVersion::V3,
        _ => {
            return Err(ZcashEscrowError::NoteOp(
                "DKG spend: Ironwood V3 note required".into(),
            ))
        }
    };
    Option::from(IronwoodNote::from_parts(addr, value, rho, rseed, version)).ok_or_else(|| {
        ZcashEscrowError::NoteOp("DKG spend: could not reconstruct Ironwood note".into())
    })
}

fn open_group_ironwood_note(
    esc: &ZcashEscrow,
    _group: &FrostGroup,
    seats: &[FrostSeat],
    amount_zat: u64,
) -> Result<(String, IronwoodNote), ZcashEscrowError> {
    let sk = ironwood_sk_from_seats(seats)?;
    let fvk = FullViewingKey::from(&sk);
    let addr = fvk.address_at(dest_diversifier(b"open"), Scope::External);
    let ovk = fvk.to_ovk(Scope::External);
    let (raw, built) = build_open_tx(esc, addr, amount_zat, Some(ovk))?;
    let note = decrypt_output_value(built.ironwood_bundle(), &fvk, amount_zat).ok_or_else(|| {
        ZcashEscrowError::NoteOp("DKG open: Ironwood V3 note not decryptable after build".into())
    })?;
    let txid = esc.send_raw(&hex::encode(&raw))?;
    Ok((txid, note))
}

fn spend_opened_ironwood(
    esc: &ZcashEscrow,
    seats: &[FrostSeat],
    opened: &IronwoodNote,
    dest: orchard::Address,
    amount_zat: u64,
    frost_sig: &[u8],
) -> Result<(String, Option<IronwoodNote>, [u8; 32]), ZcashEscrowError> {
    let sk = ironwood_sk_from_seats(seats)?;
    let fvk = FullViewingKey::from(&sk);
    let change_addr = fvk.address_at(dest_diversifier(b"open"), Scope::External);
    let opened_v = opened.value().inner();
    if amount_zat > opened_v {
        return Err(ZcashEscrowError::NoteOp("amount exceeds note".into()));
    }
    let drain = amount_zat == opened_v;
    let (merkle_path, anchor) = merkle_path_for_opened(esc, opened)?;
    // Spend authority is the reconstructed DKG Ironwood SK (`add_ironwood_spend`
    // of the opened note). Prefer a shielded-only DKG Ironwood spend. Miner
    // coinbase pays ZIP-317 only when the note cannot cover the fee — not
    // wallet send-many, not a coinbase re-shield as if FROST-owned.
    let (raw, built) = match build_spend_tx(
        esc,
        &fvk,
        &sk,
        opened,
        merkle_path.clone(),
        anchor,
        dest,
        amount_zat,
        drain,
        SpendFee::FromNote,
        frost_sig,
    ) {
        Ok(v) => v,
        Err(e) if zip317_from_note_too_small(&e) => build_spend_tx(
            esc,
            &fvk,
            &sk,
            opened,
            merkle_path,
            anchor,
            dest,
            amount_zat,
            drain,
            SpendFee::MinerCoinbase,
            frost_sig,
        )?,
        Err(e) => return Err(e),
    };
    let nullifier = require_opened_nullifier(&built, &fvk, opened)?;
    let change = if drain {
        None
    } else {
        decrypt_output_to(built.ironwood_bundle(), &fvk, change_addr)
    };
    let txid = esc.send_raw(&hex::encode(&raw))?;
    Ok((txid, change, nullifier))
}

fn zip317_from_note_too_small(e: &ZcashEscrowError) -> bool {
    match e {
        ZcashEscrowError::NoteOp(msg) => {
            msg.contains("ZIP-317")
                || msg.contains("too small for shielded-only")
                || msg.contains("miner fee fallback")
                || msg.contains("cannot cover dest")
        }
        _ => false,
    }
}

fn decrypt_output_value(
    bundle: Option<&orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>>,
    fvk: &FullViewingKey,
    amount_zat: u64,
) -> Option<IronwoodNote> {
    decrypt_outputs(bundle, fvk)
        .into_iter()
        .find(|n| n.value().inner() == amount_zat)
}

fn decrypt_output_to(
    bundle: Option<&orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>>,
    fvk: &FullViewingKey,
    addr: orchard::Address,
) -> Option<IronwoodNote> {
    decrypt_outputs(bundle, fvk)
        .into_iter()
        .find(|n| n.recipient() == addr)
}

fn decrypt_outputs(
    bundle: Option<&orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>>,
    fvk: &FullViewingKey,
) -> Vec<IronwoodNote> {
    let Some(bundle) = bundle else {
        return Vec::new();
    };
    let ivk = fvk.to_ivk(Scope::External);
    bundle
        .decrypt_outputs_with_keys(&[ivk])
        .into_iter()
        .map(|(_, _, n, _, _)| n)
        .collect()
}

fn frost_spend_memo(frost_sig: &[u8]) -> zcash_protocol::memo::MemoBytes {
    let mut b = b"pir-dkg-frost-spend-v1:".to_vec();
    b.extend_from_slice(frost_sig);
    zcash_protocol::memo::MemoBytes::from_bytes(&b)
        .unwrap_or_else(|_| zcash_protocol::memo::MemoBytes::empty())
}

fn require_opened_nullifier(
    tx: &zcash_primitives::transaction::Transaction,
    fvk: &FullViewingKey,
    opened: &IronwoodNote,
) -> Result<[u8; 32], ZcashEscrowError> {
    require_ironwood_only(tx)?;
    let want = opened.nullifier(fvk).to_bytes();
    let bundle = tx.ironwood_bundle().ok_or_else(|| {
        ZcashEscrowError::NoteOp("built tx missing Ironwood bundle".into())
    })?;
    let found = bundle
        .actions()
        .iter()
        .any(|a| a.nullifier().to_bytes() == want);
    if !found {
        return Err(ZcashEscrowError::NoteOp(
            "DKG spend: opened Ironwood nullifier missing (cannot re-shield coinbase as if FROST-owned)"
                .into(),
        ));
    }
    Ok(want)
}

fn merkle_path_for_opened(
    esc: &ZcashEscrow,
    opened: &IronwoodNote,
) -> Result<(orchard::tree::MerklePath, orchard::Anchor), ZcashEscrowError> {
    let want = extracted_cmx(opened);
    let leaves = ironwood_cmx_leaves(esc)?;
    let pos = leaves
        .iter()
        .position(|c| c == &want)
        .ok_or_else(|| {
            ZcashEscrowError::NoteOp(
                "DKG spend: opened Ironwood note not in Zakura tree (cannot re-shield coinbase)"
                    .into(),
            )
        })?;
    merkle_path_at(&leaves, pos)
}

fn merkle_path_at(
    leaves: &[[u8; 32]],
    pos: usize,
) -> Result<(orchard::tree::MerklePath, orchard::Anchor), ZcashEscrowError> {
    if pos >= leaves.len() {
        return Err(ZcashEscrowError::NoteOp(
            "DKG spend: Ironwood merkle position".into(),
        ));
    }
    let parsed: Vec<MerkleHashOrchard> = leaves
        .iter()
        .map(|b| {
            Option::from(MerkleHashOrchard::from_bytes(b)).ok_or_else(|| {
                ZcashEscrowError::NoteOp("DKG spend: Ironwood cmx".into())
            })
        })
        .collect::<Result<_, _>>()?;
    const DEPTH: usize = 32;
    let mut levels: Vec<Vec<MerkleHashOrchard>> = Vec::with_capacity(DEPTH + 1);
    levels.push(parsed);
    for l in 0..DEPTH {
        let level = Level::from(l as u8);
        let cur = &levels[l];
        let mut next = Vec::with_capacity(cur.len().div_ceil(2));
        let mut p = 0;
        while p < cur.len() {
            let left = cur[p];
            let right = cur
                .get(p + 1)
                .copied()
                .unwrap_or_else(|| MerkleHashOrchard::empty_root(level));
            next.push(MerkleHashOrchard::combine(level, &left, &right));
            p += 2;
        }
        levels.push(next);
    }
    let auth_path = core::array::from_fn(|l| {
        let level = Level::from(l as u8);
        let sibling = (pos >> l) ^ 1;
        levels[l]
            .get(sibling)
            .copied()
            .unwrap_or_else(|| MerkleHashOrchard::empty_root(level))
    });
    let path = orchard::tree::MerklePath::from_parts(pos as u32, auth_path);
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&leaves[pos]))
        .ok_or_else(|| ZcashEscrowError::NoteOp("DKG spend: Ironwood cmx".into()))?;
    let anchor = path.root(cmx);
    Ok((path, anchor))
}

fn ironwood_cmx_leaves(esc: &ZcashEscrow) -> Result<Vec<[u8; 32]>, ZcashEscrowError> {
    let tip = esc
        .rpc_result("getblockcount", Value::Array(vec![]))?
        .as_u64()
        .unwrap_or(0);
    let mut leaves = Vec::new();
    for h in 1..=tip {
        let hash = esc
            .rpc_result("getblockhash", serde_json::json!([h]))?
            .as_str()
            .ok_or_else(|| ZcashEscrowError::NoteOp("getblockhash".into()))?
            .to_string();
        let block = esc.rpc_result("getblock", serde_json::json!([hash, 1]))?;
        let txs = block.get("tx").and_then(|t| t.as_array()).cloned().unwrap_or_default();
        for txv in txs {
            let txid = match txv {
                Value::String(s) => s,
                Value::Object(o) => o
                    .get("txid")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                _ => continue,
            };
            if txid.is_empty() {
                continue;
            }
            let hex_tx = match esc.rpc_result("getrawtransaction", serde_json::json!([txid, 0])) {
                Ok(Value::String(s)) => s,
                Ok(v) => v
                    .get("hex")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                Err(_) => continue,
            };
            if hex_tx.is_empty() {
                continue;
            }
            if let Ok(tx) = parse_v6_tx(&hex_tx) {
                if let Some(bundle) = tx.ironwood_bundle() {
                    for action in bundle.actions() {
                        leaves.push(action.cmx().to_bytes());
                    }
                }
            }
        }
    }
    Ok(leaves)
}

fn parse_v6_tx(hex_tx: &str) -> Result<zcash_primitives::transaction::Transaction, ZcashEscrowError> {
    use zcash_protocol::consensus::BranchId;
    let raw = hex::decode(hex_tx).map_err(|e| ZcashEscrowError::NoteOp(e.to_string()))?;
    zcash_primitives::transaction::Transaction::read(&raw[..], BranchId::Nu6_3)
        .map_err(|e| ZcashEscrowError::NoteOp(format!("tx read: {e}")))
}

fn build_open_tx(
    esc: &ZcashEscrow,
    addr: orchard::Address,
    amount_zat: u64,
    ovk: Option<orchard::keys::OutgoingViewingKey>,
) -> Result<(Vec<u8>, zcash_primitives::transaction::Transaction), ZcashEscrowError> {
    use orchard::keys::SpendAuthorizingKey;
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder as TxBuilder, BundlePadding},
        fees::zip317::FeeRule,
    };
    use zcash_protocol::{
        consensus::BlockHeight,
        memo::MemoBytes,
        value::Zatoshis,
    };
    use zcash_transparent::address::TransparentAddress;
    use zcash_transparent::builder::TransparentSigningSet;

    let height = esc
        .rpc_result("getblockcount", Value::Array(vec![]))?
        .as_u64()
        .unwrap_or(1);
    let (outpoint, coin) = unused_mature_coinbase(esc, height)?;
    let cfg = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: None,
        ironwood_anchor: Some(orchard::Anchor::empty_tree()),
        orchard_padding: BundlePadding::DEFAULT,
        ironwood_padding: BundlePadding::DEFAULT,
    };
    let mut txb = TxBuilder::new(ZakuraParams, BlockHeight::from(height as u32), cfg);
    let miner_sk = miner_secret()?;
    let mut tss = TransparentSigningSet::new();
    let pk = tss.add_key(miner_sk);
    txb.add_transparent_p2pkh_input(pk, outpoint, coin.clone())
        .map_err(|e| ZcashEscrowError::NoteOp(format!("p2pkh input: {e:?}")))?;
    let coin_zat: u64 = coin.value().into();
    let value = Zatoshis::from_u64(amount_zat)
        .map_err(|_| ZcashEscrowError::NoteOp("amount".into()))?;
    txb.add_ironwood_output::<()>(ovk, addr, value, MemoBytes::empty())
        .map_err(|e| ZcashEscrowError::NoteOp(format!("ironwood out: {e:?}")))?;
    // ZIP-317: logical = max(t-in, t-out) + ironwood actions. A P2PKH change
    // output does not raise the fee above a single t-in + padded Ironwood bundle.
    let fee = u64::from(
        txb.get_fee(&FeeRule::standard())
            .map_err(|e| ZcashEscrowError::NoteOp(format!("fee: {e:?}")))?,
    );
    if coin_zat < amount_zat.saturating_add(fee) {
        return Err(ZcashEscrowError::NoteOp(
            "coinbase too small for DKG Ironwood open".into(),
        ));
    }
    let t_change = coin_zat - amount_zat - fee;
    if t_change > 0 {
        let t_addr = TransparentAddress::from_pubkey(&pk);
        let cv = Zatoshis::from_u64(t_change)
            .map_err(|_| ZcashEscrowError::NoteOp("t-change".into()))?;
        txb.add_transparent_output(&t_addr, cv)
            .map_err(|e| ZcashEscrowError::NoteOp(format!("t-out: {e:?}")))?;
    }
    let prover = zcash_proofs::prover::LocalTxProver::bundled();
    let built = txb
        .build(
            &tss,
            &[],
            &[] as &[SpendAuthorizingKey],
            rand::rngs::OsRng,
            &prover,
            &prover,
            &FeeRule::standard(),
        )
        .map_err(|e| ZcashEscrowError::NoteOp(format!("ironwood tx build: {e:?}")))?;
    require_ironwood_only(built.transaction())?;
    let mut out = Vec::new();
    built
        .transaction()
        .write(&mut out)
        .map_err(|e| ZcashEscrowError::NoteOp(format!("tx write: {e}")))?;
    Ok((out, built.transaction().clone()))
}

enum SpendFee {
    /// ZIP-317 paid from the opened DKG Ironwood note (no transparent inputs).
    FromNote,
    /// Miner coinbase pays ZIP-317 only. Spend authority remains the opened note.
    MinerCoinbase,
}

fn build_spend_tx(
    esc: &ZcashEscrow,
    fvk: &FullViewingKey,
    ironwood_sk: &SpendingKey,
    opened: &IronwoodNote,
    merkle_path: orchard::tree::MerklePath,
    anchor: orchard::Anchor,
    dest: orchard::Address,
    amount_zat: u64,
    drain: bool,
    fee_src: SpendFee,
    frost_sig: &[u8],
) -> Result<(Vec<u8>, zcash_primitives::transaction::Transaction), ZcashEscrowError> {
    use orchard::keys::SpendAuthorizingKey;
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder as TxBuilder, BundlePadding},
        fees::zip317::FeeRule,
    };
    use zcash_protocol::{
        consensus::BlockHeight,
        value::Zatoshis,
    };
    use zcash_transparent::address::TransparentAddress;
    use zcash_transparent::builder::TransparentSigningSet;

    let height = esc
        .rpc_result("getblockcount", Value::Array(vec![]))?
        .as_u64()
        .unwrap_or(1);
    let cfg = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: None,
        ironwood_anchor: Some(anchor),
        orchard_padding: BundlePadding::DEFAULT,
        ironwood_padding: BundlePadding::DEFAULT,
    };
    let ovk = fvk.to_ovk(Scope::External);
    let memo = frost_spend_memo(frost_sig);
    let opened_v = opened.value().inner();
    let change_addr = fvk.address_at(dest_diversifier(b"open"), Scope::External);
    let mut tss = TransparentSigningSet::new();
    let mut txb = TxBuilder::new(ZakuraParams, BlockHeight::from(height as u32), cfg.clone());
    txb.add_ironwood_spend::<()>(fvk.clone(), *opened, merkle_path.clone())
        .map_err(|e| ZcashEscrowError::NoteOp(format!("add_ironwood_spend: {e:?}")))?;

    match fee_src {
        SpendFee::FromNote => {
            // shielded-only DKG Ironwood spend
            let dest_amount = if drain {
                let mut probe =
                    TxBuilder::new(ZakuraParams, BlockHeight::from(height as u32), cfg);
                probe
                    .add_ironwood_spend::<()>(fvk.clone(), *opened, merkle_path)
                    .map_err(|e| ZcashEscrowError::NoteOp(format!("add_ironwood_spend: {e:?}")))?;
                let probe_v = Zatoshis::from_u64(1)
                    .map_err(|_| ZcashEscrowError::NoteOp("amount".into()))?;
                probe
                    .add_ironwood_output::<()>(Some(ovk.clone()), dest, probe_v, memo.clone())
                    .map_err(|e| ZcashEscrowError::NoteOp(format!("ironwood dest: {e:?}")))?;
                let fee = u64::from(
                    probe
                        .get_fee(&FeeRule::standard())
                        .map_err(|e| ZcashEscrowError::NoteOp(format!("fee: {e:?}")))?,
                );
                if opened_v <= fee {
                    return Err(ZcashEscrowError::NoteOp(
                        "DKG note too small for shielded-only ZIP-317".into(),
                    ));
                }
                opened_v - fee
            } else {
                amount_zat
            };
            let dest_v = Zatoshis::from_u64(dest_amount)
                .map_err(|_| ZcashEscrowError::NoteOp("amount".into()))?;
            txb.add_ironwood_output::<()>(Some(ovk.clone()), dest, dest_v, memo.clone())
                .map_err(|e| ZcashEscrowError::NoteOp(format!("ironwood dest: {e:?}")))?;
            if !drain {
                let fee0 = u64::from(
                    txb.get_fee(&FeeRule::standard())
                        .map_err(|e| ZcashEscrowError::NoteOp(format!("fee: {e:?}")))?,
                );
                let leftover = opened_v.saturating_sub(amount_zat);
                if leftover < fee0 {
                    return Err(ZcashEscrowError::NoteOp(
                        "DKG note cannot cover dest + ZIP-317; miner fee fallback".into(),
                    ));
                }
                if leftover > fee0 {
                    let cv = Zatoshis::from_u64(leftover - fee0)
                        .map_err(|_| ZcashEscrowError::NoteOp("change".into()))?;
                    txb.add_ironwood_output::<()>(Some(ovk), change_addr, cv, memo)
                        .map_err(|e| ZcashEscrowError::NoteOp(format!("ironwood change: {e:?}")))?;
                    let fee1 = u64::from(
                        txb.get_fee(&FeeRule::standard())
                            .map_err(|e| ZcashEscrowError::NoteOp(format!("fee: {e:?}")))?,
                    );
                    if fee1 != fee0 {
                        return Err(ZcashEscrowError::NoteOp(
                            "ZIP-317 changed with DKG change output".into(),
                        ));
                    }
                }
            }
        }
        SpendFee::MinerCoinbase => {
            let (outpoint, coin) = unused_mature_coinbase(esc, height)?;
            let miner_sk = miner_secret()?;
            let pk = tss.add_key(miner_sk);
            txb.add_transparent_p2pkh_input(pk, outpoint, coin.clone())
                .map_err(|e| ZcashEscrowError::NoteOp(format!("p2pkh input: {e:?}")))?;
            let dest_v = Zatoshis::from_u64(amount_zat)
                .map_err(|_| ZcashEscrowError::NoteOp("amount".into()))?;
            txb.add_ironwood_output::<()>(Some(ovk.clone()), dest, dest_v, memo.clone())
                .map_err(|e| ZcashEscrowError::NoteOp(format!("ironwood dest: {e:?}")))?;
            let leftover = opened_v.saturating_sub(amount_zat);
            if leftover > 0 {
                let cv = Zatoshis::from_u64(leftover)
                    .map_err(|_| ZcashEscrowError::NoteOp("change".into()))?;
                txb.add_ironwood_output::<()>(Some(ovk), change_addr, cv, memo)
                    .map_err(|e| ZcashEscrowError::NoteOp(format!("ironwood change: {e:?}")))?;
            }
            let coin_zat: u64 = coin.value().into();
            let fee = u64::from(
                txb.get_fee(&FeeRule::standard())
                    .map_err(|e| ZcashEscrowError::NoteOp(format!("fee: {e:?}")))?,
            );
            if coin_zat < fee {
                return Err(ZcashEscrowError::NoteOp(
                    "coinbase too small to pay ZIP-317 fee for DKG Ironwood spend".into(),
                ));
            }
            let t_change = coin_zat - fee;
            if t_change > 0 {
                let t_addr = TransparentAddress::from_pubkey(&pk);
                let cv = Zatoshis::from_u64(t_change)
                    .map_err(|_| ZcashEscrowError::NoteOp("t-change".into()))?;
                txb.add_transparent_output(&t_addr, cv)
                    .map_err(|e| ZcashEscrowError::NoteOp(format!("t-out: {e:?}")))?;
            }
        }
    }

    let prover = zcash_proofs::prover::LocalTxProver::bundled();
    let sak = SpendAuthorizingKey::from(ironwood_sk);
    let built = txb
        .build(
            &tss,
            &[],
            &[sak],
            rand::rngs::OsRng,
            &prover,
            &prover,
            &FeeRule::standard(),
        )
        .map_err(|e| ZcashEscrowError::NoteOp(format!("ironwood spend tx build: {e:?}")))?;
    require_ironwood_only(built.transaction())?;
    if matches!(fee_src, SpendFee::FromNote) {
        if let Some(tb) = built.transaction().transparent_bundle() {
            if !tb.vin.is_empty() || !tb.vout.is_empty() {
                return Err(ZcashEscrowError::NoteOp(
                    "shielded-only DKG spend must not include transparent inputs".into(),
                ));
            }
        }
    }
    if matches!(fee_src, SpendFee::MinerCoinbase) {
        let vb = i64::from(
            built
                .transaction()
                .ironwood_bundle()
                .ok_or_else(|| {
                    ZcashEscrowError::NoteOp("built tx missing Ironwood bundle".into())
                })?
                .value_balance(),
        );
        if vb != 0 {
            return Err(ZcashEscrowError::NoteOp(
                "DKG spend: miner transparent must not enter Ironwood (cannot shield miner transparent as if FROST-owned)".into(),
            ));
        }
    }
    require_opened_nullifier(built.transaction(), fvk, opened)?;
    let mut out = Vec::new();
    built
        .transaction()
        .write(&mut out)
        .map_err(|e| ZcashEscrowError::NoteOp(format!("tx write: {e}")))?;
    Ok((out, built.transaction().clone()))
}

fn require_ironwood_only(
    tx: &zcash_primitives::transaction::Transaction,
) -> Result<(), ZcashEscrowError> {
    if tx.sapling_bundle().is_some() {
        return Err(ZcashEscrowError::NoteOp(
            "Sapling bundle forbidden on the Ironwood product path".into(),
        ));
    }
    if tx.orchard_bundle().is_some() {
        return Err(ZcashEscrowError::NoteOp(
            "Orchard bundle forbidden on the Ironwood product path".into(),
        ));
    }
    if tx.ironwood_bundle().is_none() {
        return Err(ZcashEscrowError::NoteOp(
            "built tx missing Ironwood bundle".into(),
        ));
    }
    Ok(())
}

/// Coinbase spend key for shielding into the DKG Ironwood note.
/// Default is secp256k1 `sk=1`, the same key as `zakura::REGTEST_MINER_DEST`
/// (`tmLPctKo…` / WIF `cMahea7z…`). That is the lab miner, not dummy money.
/// Override with `PIR_MINER_SK` (32-byte hex) if the node uses another address.
fn miner_secret() -> Result<secp256k1::SecretKey, ZcashEscrowError> {
    if let Ok(hex) = std::env::var("PIR_MINER_SK") {
        let raw = hex::decode(hex.trim().trim_start_matches("0x"))
            .map_err(|e| ZcashEscrowError::NoteOp(format!("PIR_MINER_SK: {e}")))?;
        if raw.len() != 32 {
            return Err(ZcashEscrowError::NoteOp(
                "PIR_MINER_SK must be 32-byte hex".into(),
            ));
        }
        return secp256k1::SecretKey::from_slice(&raw)
            .map_err(|e| ZcashEscrowError::NoteOp(format!("PIR_MINER_SK: {e}")));
    }
    secp256k1::SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .map_err(|e| ZcashEscrowError::NoteOp(format!("miner sk: {e}")))
}

#[derive(Clone)]
struct ZakuraParams;
impl zcash_protocol::consensus::Parameters for ZakuraParams {
    fn network_type(&self) -> zcash_protocol::consensus::NetworkType {
        zcash_protocol::consensus::NetworkType::Regtest
    }
    fn activation_height(
        &self,
        nu: zcash_protocol::consensus::NetworkUpgrade,
    ) -> Option<zcash_protocol::consensus::BlockHeight> {
        use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade};
        match nu {
            NetworkUpgrade::Overwinter
            | NetworkUpgrade::Sapling
            | NetworkUpgrade::Blossom
            | NetworkUpgrade::Heartwood
            | NetworkUpgrade::Canopy
            | NetworkUpgrade::Nu5
            | NetworkUpgrade::Nu6
            | NetworkUpgrade::Nu6_1
            | NetworkUpgrade::Nu6_2
            | NetworkUpgrade::Nu6_3 => Some(BlockHeight::from(1u32)),
        }
    }
}

fn unused_mature_coinbase(
    esc: &ZcashEscrow,
    tip: u64,
) -> Result<(zcash_transparent::bundle::OutPoint, zcash_transparent::bundle::TxOut), ZcashEscrowError>
{
    if tip < 101 {
        return Err(ZcashEscrowError::NoteOp("need 101 generated blocks".into()));
    }
    let mut last_err = ZcashEscrowError::NoteOp("no unspent mature coinbase".into());
    for h in (1..=tip - 100).rev() {
        match coinbase_at(esc, h) {
            Ok((op, coin, txid_hex)) => {
                match esc.rpc_result("gettxout", serde_json::json!([txid_hex, 0])) {
                    Ok(v) if v.is_null() => continue,
                    Ok(_) => return Ok((op, coin)),
                    Err(_) => return Ok((op, coin)),
                }
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn coinbase_at(
    esc: &ZcashEscrow,
    h: u64,
) -> Result<
    (
        zcash_transparent::bundle::OutPoint,
        zcash_transparent::bundle::TxOut,
        String,
    ),
    ZcashEscrowError,
> {
    use zcash_protocol::value::Zatoshis;
    use zcash_script::script::Code;
    use zcash_transparent::address::Script;
    use zcash_transparent::bundle::{OutPoint, TxOut};
    let hash = esc
        .rpc_result("getblockhash", serde_json::json!([h]))?
        .as_str()
        .ok_or_else(|| ZcashEscrowError::NoteOp("getblockhash".into()))?
        .to_string();
    let block = esc.rpc_result("getblock", serde_json::json!([hash, 2]))?;
    let tx0 = block
        .get("tx")
        .and_then(|t| t.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| ZcashEscrowError::NoteOp("no coinbase".into()))?;
    let txid_hex = tx0
        .get("txid")
        .and_then(|t| t.as_str())
        .ok_or_else(|| ZcashEscrowError::NoteOp("coinbase txid".into()))?
        .to_string();
    let mut txid = hex::decode(&txid_hex).map_err(|e| ZcashEscrowError::NoteOp(e.to_string()))?;
    if txid.len() != 32 {
        return Err(ZcashEscrowError::NoteOp("txid len".into()));
    }
    txid.reverse();
    let mut id = [0u8; 32];
    id.copy_from_slice(&txid);
    let vout = tx0
        .get("vout")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| ZcashEscrowError::NoteOp("no vout".into()))?;
    let zat = vout
        .get("valueZat")
        .and_then(|v| v.as_u64())
        .or_else(|| vout.get("value").and_then(|v| v.as_f64()).map(|f| (f * 1e8) as u64))
        .unwrap_or(0);
    let spk = vout
        .pointer("/scriptPubKey/hex")
        .and_then(|h| h.as_str())
        .ok_or_else(|| ZcashEscrowError::NoteOp("scriptPubKey".into()))?;
    let bytes = hex::decode(spk).map_err(|e| ZcashEscrowError::NoteOp(e.to_string()))?;
    let script = Script(Code(bytes));
    let value = Zatoshis::from_u64(zat).map_err(|_| ZcashEscrowError::NoteOp("zat".into()))?;
    Ok((OutPoint::new(id, 0), TxOut::new(value, script), txid_hex))
}
