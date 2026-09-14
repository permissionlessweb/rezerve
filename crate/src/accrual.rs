//! Private rent accrual from Zcash heights, not wall-clock.
//!
//! `earned = f(open_height, close_height, rate) = (close - open) * rate`.
//! The public surface is a BLAKE2b commitment plus Halo2 instances (header
//! hashes). Duration, earned, rate, and heights stay off the public JSON.
//! Header `time` is unused. HOSTING_PAYMENT inclusion is not `f`.

use crate::zakura::{ZakuraError, ZakuraRegtest};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde_json::Value;
use thiserror::Error;

/// Zatoshis credited per inclusive-open exclusive-close height step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccrualRate {
    pub zat_per_height: u64,
}

/// Bid-accept (open) through close, as Zcash heights on the deposit chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeightWindow {
    pub open_height: u64,
    pub close_height: u64,
}

/// `getblockheader` fields used as height evidence. Wall-clock is not a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainHeader {
    pub height: u64,
    pub hash: [u8; 32],
}

/// Private witness: earned and duration never leave this type onto the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccrualWitness {
    pub window: HeightWindow,
    pub rate: AccrualRate,
    pub earned_zat: u64,
    pub duration_heights: u64,
    pub blinding: [u8; 32],
}

/// On-chain / circuit public inputs. No plaintext hours, earned, rate, or heights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccrualPublic {
    /// BLAKE2b-256 (`pir-accrual-v1`) of window, rate, blinding, and headers.
    pub commitment: [u8; 32],
    /// `getblockheader` hash at open height.
    pub open_header_hash: [u8; 32],
    /// `getblockheader` hash at close height.
    pub close_header_hash: [u8; 32],
}

/// Pasta/Pallas-sized packing: clear the top two bits of a 32-byte digest.
///
/// Same waist as `hosting_payment::pack_hash32` (canonical Pallas element).
fn pack_fe32(bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = *bytes;
    out[31] &= 0x3f;
    let _ = hosting_payment::pack_hash32(&out);
    out
}

impl AccrualPublic {
    /// Halo2 waist: packed commitment / open header / close header.
    ///
    /// Duration, earned, rate, and heights are not instances. Same 96-byte
    /// encoding as `hosting_payment::encode_accrual_instances` (`f`, not
    /// 128-byte HOSTING_PAYMENT).
    pub fn zk_public_inputs(&self) -> [[u8; 32]; 3] {
        let b = self.zk_instance_bytes();
        let mut out = [[0u8; 32]; 3];
        out[0].copy_from_slice(&b[0..32]);
        out[1].copy_from_slice(&b[32..64]);
        out[2].copy_from_slice(&b[64..96]);
        out
    }

    /// Concatenated Halo2 instance bytes (96 LE bytes, three packed field elements).
    pub fn zk_instance_bytes(&self) -> [u8; 96] {
        hosting_payment::encode_accrual_instances(
            &self.commitment,
            &self.open_header_hash,
            &self.close_header_hash,
        )
    }

    /// Hex-only public JSON. Duration, earned, rate, and heights are not fields.
    pub fn chain_surface(&self) -> Value {
        serde_json::json!({
            "commitment": hex::encode(self.commitment),
            "open_header_hash": hex::encode(self.open_header_hash),
            "close_header_hash": hex::encode(self.close_header_hash),
        })
    }

    /// 192-char hex of the 96-byte Halo2 instances (packed C || open || close).
    pub fn halo2_instances_hex(&self) -> String {
        hex::encode(self.zk_instance_bytes())
    }
}

/// Product grant JSON. `earned_zat` is always 0; split stays on the witness.
///
/// Public waist is the commitment plus packed Halo2 instances of `f`, not a
/// closer-supplied bill.
pub fn product_grant_json(public: &AccrualPublic) -> Value {
    serde_json::json!({
        "earned_zat": 0u64,
        "commitment": hex::encode(public.commitment),
        "open_header_hash": hex::encode(public.open_header_hash),
        "close_header_hash": hex::encode(public.close_header_hash),
        "halo2_instances": public.halo2_instances_hex(),
    })
}

/// Hex-only public JSON. Duration, earned, rate, and heights are not fields.
impl Serialize for AccrualPublic {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("AccrualPublic", 3)?;
        s.serialize_field("commitment", &hex::encode(self.commitment))?;
        s.serialize_field("open_header_hash", &hex::encode(self.open_header_hash))?;
        s.serialize_field("close_header_hash", &hex::encode(self.close_header_hash))?;
        s.end()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AccrualError {
    #[error("close_height {close} must be greater than open_height {open}")]
    InvertedWindow { open: u64, close: u64 },
    #[error("rate must be nonzero")]
    ZeroRate,
    #[error("height window * rate overflows u64")]
    Overflow,
    #[error("zakura: {0}")]
    Zakura(String),
    #[error("header missing for height {0}")]
    MissingHeader(u64),
    #[error("getblockheader object missing height or hash")]
    MalformedHeader,
    #[error("getblockheader height {header} != requested {requested}")]
    HeaderHeightMismatch { requested: u64, header: u64 },
    #[error("open and close headers must differ")]
    HeaderCollision,
    #[error("earned commitment does not bind witness")]
    UnboundCommitment,
    #[error("empty Halo2 proof is never valid")]
    EmptyHalo2Proof,
    #[error("HOSTING_PAYMENT inclusion does not prove height_window * rate")]
    WrongCircuit,
    #[error("Halo2 proof does not satisfy f(open_height, close_height, rate)")]
    InvalidHalo2Proof,
    #[error("halo2: {0}")]
    Halo2(String),
}

impl From<ZakuraError> for AccrualError {
    fn from(e: ZakuraError) -> Self {
        AccrualError::Zakura(e.to_string())
    }
}

/// Height span used as the private duration (not posted).
pub fn duration_heights(window: HeightWindow) -> Result<u64, AccrualError> {
    if window.close_height <= window.open_height {
        return Err(AccrualError::InvertedWindow {
            open: window.open_height,
            close: window.close_height,
        });
    }
    Ok(window.close_height - window.open_height)
}

fn le_fe_u64(x: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&x.to_le_bytes());
    b
}

/// Pallas `duration * rate = earned` (same field as Halo2 instances).
/// Integer overflow is already rejected by `checked_mul`.
fn constrain_product_pallas(duration: u64, rate: u64, earned: u64) -> Result<(), AccrualError> {
    let df = hosting_payment::pack_hash32(&le_fe_u64(duration));
    let rf = hosting_payment::pack_hash32(&le_fe_u64(rate));
    let ef = hosting_payment::pack_hash32(&le_fe_u64(earned));
    if std::ops::Mul::mul(df, rf) != ef {
        return Err(AccrualError::UnboundCommitment);
    }
    Ok(())
}

/// Product `f(open_height, close_height, rate) = height_window * rate`.
///
/// Height window is inclusive-open exclusive-close (`close - open`). Header
/// Unix `time` is not an argument. Integer `checked_mul` then the same product
/// in Pallas. The public surface is [`AccrualPublic`] (commitment + packed
/// header hashes), not the product.
pub fn f(open_height: u64, close_height: u64, rate: AccrualRate) -> Result<u64, AccrualError> {
    if rate.zat_per_height == 0 {
        return Err(AccrualError::ZeroRate);
    }
    let d = duration_heights(HeightWindow {
        open_height,
        close_height,
    })?;
    let earned = d
        .checked_mul(rate.zat_per_height)
        .ok_or(AccrualError::Overflow)?;
    constrain_product_pallas(d, rate.zat_per_height, earned)?;
    Ok(earned)
}

/// `earned = (close_height - open_height) * rate`.
pub fn earned_zat(window: HeightWindow, rate: AccrualRate) -> Result<u64, AccrualError> {
    f(window.open_height, window.close_height, rate)
}

fn bind_commitment(
    witness: &AccrualWitness,
    open_header_hash: &[u8; 32],
    close_header_hash: &[u8; 32],
) -> [u8; 32] {
    // Same preimage the AccrualCircuit hashes with WordChip BLAKE2b-256.
    hosting_payment::accrual_commit_bytes(
        witness.window.open_height,
        witness.window.close_height,
        witness.rate.zat_per_height,
        &witness.blinding,
        open_header_hash,
        close_header_hash,
    )
}

pub fn commit_accrual(
    window: HeightWindow,
    rate: AccrualRate,
    blinding: [u8; 32],
    open_header_hash: [u8; 32],
    close_header_hash: [u8; 32],
) -> Result<(AccrualWitness, AccrualPublic), AccrualError> {
    if open_header_hash == close_header_hash {
        return Err(AccrualError::HeaderCollision);
    }
    let duration = duration_heights(window)?;
    let earned = f(window.open_height, window.close_height, rate)?;
    if duration.checked_mul(rate.zat_per_height) != Some(earned) {
        return Err(AccrualError::UnboundCommitment);
    }
    let witness = AccrualWitness {
        window,
        rate,
        earned_zat: earned,
        duration_heights: duration,
        blinding,
    };
    let commitment = bind_commitment(&witness, &open_header_hash, &close_header_hash);
    Ok((
        witness,
        AccrualPublic {
            commitment,
            open_header_hash,
            close_header_hash,
        },
    ))
}

pub fn verify_witness(witness: &AccrualWitness, public: &AccrualPublic) -> Result<(), AccrualError> {
    let expected = f(
        witness.window.open_height,
        witness.window.close_height,
        witness.rate,
    )?;
    if expected != witness.earned_zat
        || duration_heights(witness.window)? != witness.duration_heights
        || witness
            .duration_heights
            .checked_mul(witness.rate.zat_per_height)
            != Some(witness.earned_zat)
    {
        return Err(AccrualError::UnboundCommitment);
    }
    if public.open_header_hash == public.close_header_hash {
        return Err(AccrualError::HeaderCollision);
    }
    if bind_commitment(witness, &public.open_header_hash, &public.close_header_hash)
        != public.commitment
    {
        return Err(AccrualError::UnboundCommitment);
    }
    let ins = public.zk_public_inputs();
    let expect = hosting_payment::encode_accrual_instances(
        &public.commitment,
        &public.open_header_hash,
        &public.close_header_hash,
    );
    if ins[0] != pack_fe32(&public.commitment)
        || ins[1] != pack_fe32(&public.open_header_hash)
        || ins[2] != pack_fe32(&public.close_header_hash)
        || public.zk_instance_bytes() != expect
        || expect.len() != 96
        || (ins[1][31] & 0xc0) != 0
        || (ins[2][31] & 0xc0) != 0
    {
        return Err(AccrualError::UnboundCommitment);
    }
    constrain_product_pallas(
        witness.duration_heights,
        witness.rate.zat_per_height,
        witness.earned_zat,
    )
}

/// Fail-closed Halo2 gate for `f(open_height, close_height, rate)`.
///
/// Empty proofs are invalid. Host waist is `proof_instance_verify` with
/// 96-byte instances and `ACCRUAL_ZKID`. HOSTING_PAYMENT (zkid 1 / 128-byte
/// instances) is a different relation and is `WrongCircuit`.
pub fn verify_accrual_halo2(proof: &[u8], public: &AccrualPublic) -> Result<(), AccrualError> {
    if proof.is_empty() {
        return Err(AccrualError::EmptyHalo2Proof);
    }
    if proof.starts_with(b"DSTW") {
        return Err(AccrualError::InvalidHalo2Proof);
    }
    // Pasta Halo2 proofs are kilobytes; refuse tiny blobs without keygen.
    if proof.len() < 64 {
        return Err(AccrualError::InvalidHalo2Proof);
    }
    let inst = public.zk_instance_bytes();
    if inst.len() != 96 {
        return Err(AccrualError::WrongCircuit);
    }
    if hosting_payment::decode_instances(&inst).is_ok() {
        return Err(AccrualError::WrongCircuit);
    }
    match hosting_payment::proof_instance_verify(1, proof, &inst) {
        Ok(_) => return Err(AccrualError::WrongCircuit),
        Err(_) => {}
    }
    match hosting_payment::proof_instance_verify(hosting_payment::ACCRUAL_ZKID, proof, &inst) {
        Ok(true) => Ok(()),
        Ok(false) => Err(AccrualError::InvalidHalo2Proof),
        Err(e) if e.contains("HOSTING_PAYMENT") => Err(AccrualError::WrongCircuit),
        Err(e) if e.contains("empty proof") => Err(AccrualError::EmptyHalo2Proof),
        Err(_) => Err(AccrualError::InvalidHalo2Proof),
    }
}

/// Off-chain Halo2 prove of `f`. Public instances are [`AccrualPublic`].
pub fn prove_accrual_halo2(
    witness: &AccrualWitness,
    public: &AccrualPublic,
) -> Result<Vec<u8>, AccrualError> {
    verify_witness(witness, public)?;
    let proof = hosting_payment::prove_accrual(
        witness.window.open_height,
        witness.window.close_height,
        witness.rate.zat_per_height,
        witness.earned_zat,
        &witness.blinding,
        &public.open_header_hash,
        &public.close_header_hash,
    )
    .map_err(AccrualError::Halo2)?;
    if proof.is_empty() {
        return Err(AccrualError::EmptyHalo2Proof);
    }
    Ok(proof)
}

/// Product accrue: witness binds `f` **and** a Halo2 proof of that relation.
/// Missing/empty proof is invalid — plaintext earned is not a substitute.
pub fn verify_product_accrual(
    witness: &AccrualWitness,
    public: &AccrualPublic,
    proof: &[u8],
) -> Result<(), AccrualError> {
    verify_witness(witness, public)?;
    verify_accrual_halo2(proof, public)
}

/// Commit `f`, prove Halo2, verify. Empty proof is never returned.
pub fn commit_and_prove_accrual(
    window: HeightWindow,
    rate: AccrualRate,
    blinding: [u8; 32],
    open_header_hash: [u8; 32],
    close_header_hash: [u8; 32],
) -> Result<(AccrualWitness, AccrualPublic, Vec<u8>), AccrualError> {
    let (witness, public) = commit_accrual(
        window,
        rate,
        blinding,
        open_header_hash,
        close_header_hash,
    )?;
    let proof = prove_accrual_halo2(&witness, &public)?;
    verify_product_accrual(&witness, &public, &proof)?;
    Ok((witness, public, proof))
}

/// Accrue from two `getblockheader` anchors and prove Halo2 of `f`.
pub fn accrue_from_headers_halo2(
    open: ChainHeader,
    close: ChainHeader,
    rate: AccrualRate,
    blinding: [u8; 32],
) -> Result<(AccrualWitness, AccrualPublic, Vec<u8>), AccrualError> {
    let (witness, public) = accrue_from_headers(open, close, rate, blinding)?;
    let proof = prove_accrual_halo2(&witness, &public)?;
    verify_product_accrual(&witness, &public, &proof)?;
    Ok((witness, public, proof))
}

/// Accrue from two verbose `getblockheader` objects and prove Halo2 of `f`.
pub fn accrue_from_getblockheader_json_halo2(
    open_header: &Value,
    open_requested: u64,
    close_header: &Value,
    close_requested: u64,
    rate: AccrualRate,
    blinding: [u8; 32],
) -> Result<(AccrualWitness, AccrualPublic, Vec<u8>), AccrualError> {
    let (witness, public) = accrue_from_getblockheader_json(
        open_header,
        open_requested,
        close_header,
        close_requested,
        rate,
        blinding,
    )?;
    let proof = prove_accrual_halo2(&witness, &public)?;
    verify_product_accrual(&witness, &public, &proof)?;
    Ok((witness, public, proof))
}

/// JSON-RPC envelope or the verbose header object itself.
fn as_header_object(header: &Value) -> &Value {
    match header.get("result") {
        Some(r) if r.is_object() => r,
        _ => header,
    }
}

/// Verbose Zakura `getblockheader` object → height + hash only.
///
/// Unix `time` / `mediantime` and `previousblockhash` are not the window and
/// are never read. Height is the object's `height` field.
pub fn chain_header_from_verbose(header: &Value) -> Result<ChainHeader, AccrualError> {
    let header = as_header_object(header);
    let hash = parse_header_hash(header).ok_or(AccrualError::MalformedHeader)?;
    let reported = header_reported_height(header).ok_or(AccrualError::MalformedHeader)?;
    Ok(ChainHeader {
        height: reported,
        hash,
    })
}

/// Verbose Zakura `getblockheader` object → height + hash only.
///
/// Height is taken from the header object and must equal `requested`.
pub fn chain_header_from_getblockheader(
    header: &Value,
    requested: u64,
) -> Result<ChainHeader, AccrualError> {
    let parsed = chain_header_from_verbose(header)
        .map_err(|_| AccrualError::MissingHeader(requested))?;
    if parsed.height != requested {
        return Err(AccrualError::HeaderHeightMismatch {
            requested,
            header: parsed.height,
        });
    }
    Ok(parsed)
}

/// Accrue from two verbose `getblockheader` JSON objects.
pub fn accrue_from_getblockheader_json(
    open_header: &Value,
    open_requested: u64,
    close_header: &Value,
    close_requested: u64,
    rate: AccrualRate,
    blinding: [u8; 32],
) -> Result<(AccrualWitness, AccrualPublic), AccrualError> {
    let open = chain_header_from_getblockheader(open_header, open_requested)?;
    let close = chain_header_from_getblockheader(close_header, close_requested)?;
    accrue_from_headers(open, close, rate, blinding)
}

/// Accrue from two `getblockheader` anchors. Earned is the height delta × rate.
pub fn accrue_from_headers(
    open: ChainHeader,
    close: ChainHeader,
    rate: AccrualRate,
    blinding: [u8; 32],
) -> Result<(AccrualWitness, AccrualPublic), AccrualError> {
    let window = HeightWindow {
        open_height: open.height,
        close_height: close.height,
    };
    commit_accrual(window, rate, blinding, open.hash, close.hash)
}

fn rpc_call(rpc: &str, method: &str, params: Value) -> Result<Value, AccrualError> {
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "pir-accrual",
        "method": method,
        "params": params,
    });
    let out = std::process::Command::new("curl")
        .args(["-sS", "-X", "POST", "-H", "content-type: text/plain", "--data"])
        .arg(body.to_string())
        .arg(rpc)
        .output()
        .map_err(|e| AccrualError::Zakura(e.to_string()))?;
    if !out.status.success() {
        return Err(AccrualError::Zakura(String::from_utf8_lossy(&out.stderr).into()));
    }
    let v: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| AccrualError::Zakura(e.to_string()))?;
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        return Err(AccrualError::Zakura(err.to_string()));
    }
    Ok(v.get("result").cloned().unwrap_or(v))
}

/// Tip height from Zakura `getblockcount` (preflight only; the window is header `height`).
pub fn getblockcount(z: &ZakuraRegtest) -> Result<u64, AccrualError> {
    let r = rpc_call(&z.rpc, "getblockcount", serde_json::json!([]))?;
    parse_height_value(&r).ok_or_else(|| AccrualError::Zakura("getblockcount not a height".into()))
}

/// Tip hash from Zakura `getbestblockhash` (then `getblockheader` for height).
pub fn getbestblockhash(z: &ZakuraRegtest) -> Result<String, AccrualError> {
    let r = rpc_call(&z.rpc, "getbestblockhash", serde_json::json!([]))?;
    r.as_str()
        .map(|s| s.trim_start_matches("0x").to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AccrualError::Zakura("getbestblockhash not a hash".into()))
}

fn parse_height_value(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn parse_header_hash(v: &Value) -> Option<[u8; 32]> {
    let s = v.get("hash").and_then(|h| h.as_str())?;
    let s = s.trim_start_matches("0x");
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn header_reported_height(v: &Value) -> Option<u64> {
    // Verbose getblockheader also has Unix `time` / `mediantime`; neither is
    // the window. `blocks` and `previousblockhash` are not height evidence.
    v.get("height").and_then(parse_height_value)
}

fn header_object_usable(v: &Value) -> bool {
    let v = as_header_object(v);
    parse_header_hash(v).is_some() && header_reported_height(v).is_some()
}

fn fetch_header_json(z: &ZakuraRegtest, height: u64) -> Result<Value, AccrualError> {
    // Zakura `getblockheader` takes hash-or-height; verbose object is required
    // so `height` (not Unix `time`) is the window evidence.
    if let Ok(v) = rpc_call(
        &z.rpc,
        "getblockheader",
        serde_json::json!([height.to_string(), true]),
    ) {
        if header_object_usable(&v) {
            return Ok(v);
        }
    }
    let hash_v = rpc_call(&z.rpc, "getblockhash", serde_json::json!([height]))?;
    let hash = hash_v
        .as_str()
        .ok_or(AccrualError::MissingHeader(height))?;
    let header = rpc_call(&z.rpc, "getblockheader", serde_json::json!([hash, true]))?;
    if !header_object_usable(&header) {
        return Err(AccrualError::MissingHeader(height));
    }
    Ok(header)
}

/// Verbose Zakura `getblockheader` JSON at `height` (may include unused `time`).
pub fn getblockheader_json(z: &ZakuraRegtest, height: u64) -> Result<Value, AccrualError> {
    fetch_header_json(z, height)
}

/// Verbose `getblockheader` at `height`. Height is taken from the header object.
pub fn header_at(z: &ZakuraRegtest, height: u64) -> Result<ChainHeader, AccrualError> {
    let header = fetch_header_json(z, height)?;
    chain_header_from_getblockheader(&header, height)
}

/// Header hash at `height` via Zakura `getblockheader` (hash-or-height).
pub fn getblockheader_at(z: &ZakuraRegtest, height: u64) -> Result<[u8; 32], AccrualError> {
    Ok(header_at(z, height)?.hash)
}

/// Accrue from live Zakura heights (open = bid-accept, close supplied).
///
/// The window is the two `getblockheader` `height` fields, not `getblockcount`
/// and not Unix `time`. Product spend path is [`accrue_from_zakura_halo2`].
pub fn accrue_from_zakura(
    z: &ZakuraRegtest,
    open_height: u64,
    close_height: u64,
    rate: AccrualRate,
    blinding: [u8; 32],
) -> Result<(AccrualWitness, AccrualPublic), AccrualError> {
    if let Ok(tip) = getblockcount(z) {
        if close_height > tip {
            return Err(AccrualError::Zakura(format!(
                "close_height {close_height} above tip {tip}"
            )));
        }
        if open_height > tip {
            return Err(AccrualError::Zakura(format!(
                "open_height {open_height} above tip {tip}"
            )));
        }
    }
    let open_h = header_at(z, open_height)?;
    let close_h = header_at(z, close_height)?;
    accrue_from_headers(open_h, close_h, rate, blinding)
}

/// Product path: Zakura heights → `f` → Halo2 proof. Missing proof is not returned.
pub fn accrue_from_zakura_halo2(
    z: &ZakuraRegtest,
    open_height: u64,
    close_height: u64,
    rate: AccrualRate,
    blinding: [u8; 32],
) -> Result<(AccrualWitness, AccrualPublic, Vec<u8>), AccrualError> {
    let (witness, public) = accrue_from_zakura(z, open_height, close_height, rate, blinding)?;
    let proof = prove_accrual_halo2(&witness, &public)?;
    verify_product_accrual(&witness, &public, &proof)?;
    Ok((witness, public, proof))
}

/// Open height from verbose `getblockheader` of the tip (bid-accept).
///
/// Prefers `getbestblockhash` then `getblockheader`; falls back to
/// `getblockcount` + `getblockheader`. The returned value is the header
/// `height` field.
pub fn open_at_tip(z: &ZakuraRegtest) -> Result<u64, AccrualError> {
    if let Ok(hash) = getbestblockhash(z) {
        let header = rpc_call(
            &z.rpc,
            "getblockheader",
            serde_json::json!([hash, true]),
        );
        if let Ok(header) = header {
            if let Ok(hdr) = chain_header_from_verbose(&header) {
                return Ok(hdr.height);
            }
        }
    }
    let tip = getblockcount(z)?;
    let hdr = header_at(z, tip)?;
    Ok(hdr.height)
}
