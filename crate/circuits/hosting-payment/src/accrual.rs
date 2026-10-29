//! Halo2 of `f(open_height, close_height, rate) = (close - open) * rate`,
//! bound to an Ironwood note id the way zkAPI binds a balance to `note_id`.
//!
//! Public instances (one column, 3 rows) — 96 bytes LE, not HOSTING_PAYMENT:
//!   [0] packed BLAKE2b-256 commitment (`pir-accrual-v1`)
//!   [1] packed open header hash
//!   [2] packed close header hash
//!
//! The note id is not a public instance, and neither is a renter id or an
//! account. It is 32 witness bytes inside the BLAKE2b preimage (after the
//! headers), so a different note does not open the same commitment. Earned
//! is `f` and is not a public instance. The closer cannot set it.
//! HOSTING_PAYMENT inclusion (128-byte instances) is a different relation.
//! `PIR_*` on the provider is the allocate gate, not this binding.

use crate::blake2b::{blake2b_256, BLOCK_LEN};
use crate::chip::WordChip;
use crate::{pack_bytes_circuit, pack_hash32, personal_words, reject_forbidden_proof_bytes};
use ff::PrimeField;
use group::ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{self, Circuit, ConstraintSystem, Error, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};
use rand::rng;
use std::sync::OnceLock;

use crate::chip::WordConfig;

/// Two BLAKE2b-256 compresses (note id spills one block) plus `f`.
/// k=16 cannot hold both compresses. k=17 is HOSTING_PAYMENT.
pub const ACCRUAL_K: u32 = 18;
pub const ACCRUAL_INSTANCE_COUNT: usize = 3;
pub const ACCRUAL_CIRCUIT_ID: &str = "pir-accrual.f.v1";
pub const ACCRUAL_PERSONAL: &[u8] = b"pir-accrual-v1";
/// Opened Ironwood note id (nullifier), appended after the two headers.
pub const ACCRUAL_NOTE_OFF: usize = 120;
pub const ACCRUAL_NOTE_LEN: usize = 32;
pub const ACCRUAL_PREIMAGE_LEN: usize = ACCRUAL_NOTE_OFF + ACCRUAL_NOTE_LEN;
/// Path A zkid for `f`. HOSTING_PAYMENT inclusion stays zkid 1 / 128 bytes.
pub const ACCRUAL_ZKID: u64 = 2;

pub fn accrual_preimage_note(
    open_height: u64,
    close_height: u64,
    rate: u64,
    blinding: &[u8; 32],
    open_header: &[u8; 32],
    close_header: &[u8; 32],
    note_id: &[u8; 32],
) -> [u8; ACCRUAL_PREIMAGE_LEN] {
    let mut b = [0u8; ACCRUAL_PREIMAGE_LEN];
    b[0..8].copy_from_slice(&open_height.to_le_bytes());
    b[8..16].copy_from_slice(&close_height.to_le_bytes());
    b[16..24].copy_from_slice(&rate.to_le_bytes());
    b[24..56].copy_from_slice(blinding);
    b[56..88].copy_from_slice(open_header);
    b[88..120].copy_from_slice(close_header);
    b[ACCRUAL_NOTE_OFF..ACCRUAL_PREIMAGE_LEN].copy_from_slice(note_id);
    b
}

/// Same preimage with a zero note id (not an Ironwood note).
pub fn accrual_preimage(
    open_height: u64,
    close_height: u64,
    rate: u64,
    blinding: &[u8; 32],
    open_header: &[u8; 32],
    close_header: &[u8; 32],
) -> [u8; ACCRUAL_PREIMAGE_LEN] {
    accrual_preimage_note(
        open_height,
        close_height,
        rate,
        blinding,
        open_header,
        close_header,
        &[0u8; 32],
    )
}

/// BLAKE2b-256 of the private window / rate / blinding, headers, and note id.
pub fn accrual_commit_note_bytes(
    open_height: u64,
    close_height: u64,
    rate: u64,
    blinding: &[u8; 32],
    open_header: &[u8; 32],
    close_header: &[u8; 32],
    note_id: &[u8; 32],
) -> [u8; 32] {
    blake2b_256(
        &accrual_preimage_note(
            open_height,
            close_height,
            rate,
            blinding,
            open_header,
            close_header,
            note_id,
        ),
        ACCRUAL_PERSONAL,
    )
}

/// BLAKE2b-256 bound to the all-zero note id.
pub fn accrual_commit_bytes(
    open_height: u64,
    close_height: u64,
    rate: u64,
    blinding: &[u8; 32],
    open_header: &[u8; 32],
    close_header: &[u8; 32],
) -> [u8; 32] {
    accrual_commit_note_bytes(
        open_height,
        close_height,
        rate,
        blinding,
        open_header,
        close_header,
        &[0u8; 32],
    )
}

pub fn accrual_public_scalars(
    commitment: &[u8; 32],
    open_header: &[u8; 32],
    close_header: &[u8; 32],
) -> [pallas::Base; ACCRUAL_INSTANCE_COUNT] {
    [
        pack_hash32(commitment),
        pack_hash32(open_header),
        pack_hash32(close_header),
    ]
}

pub fn encode_accrual_instances(
    commitment: &[u8; 32],
    open_header: &[u8; 32],
    close_header: &[u8; 32],
) -> [u8; 96] {
    let pubs = accrual_public_scalars(commitment, open_header, close_header);
    let mut out = [0u8; 96];
    for (i, f) in pubs.iter().enumerate() {
        out[i * 32..(i + 1) * 32].copy_from_slice(f.to_repr().as_ref());
    }
    out
}

pub fn decode_accrual_instances(
    bytes: &[u8],
) -> Result<[pallas::Base; ACCRUAL_INSTANCE_COUNT], String> {
    if bytes.len() == 128 {
        return Err("instances are 128-byte HOSTING_PAYMENT, not 96-byte f()".into());
    }
    if bytes.len() != 96 {
        return Err("accrual instances must be 96 bytes (not HOSTING_PAYMENT 128)".into());
    }
    let mut out = [pallas::Base::ZERO; ACCRUAL_INSTANCE_COUNT];
    for i in 0..ACCRUAL_INSTANCE_COUNT {
        let chunk: [u8; 32] = bytes[i * 32..(i + 1) * 32]
            .try_into()
            .map_err(|_| "chunk")?;
        out[i] = Option::<pallas::Base>::from(pallas::Base::from_repr(chunk))
            .ok_or_else(|| "invalid field encoding".to_string())?;
    }
    Ok(out)
}

struct AccrualCircuit {
    block0: [Value<u8>; BLOCK_LEN],
    block1: [Value<u8>; BLOCK_LEN],
    note: [Value<u8>; ACCRUAL_NOTE_LEN],
    open_height: Value<u64>,
    close_height: Value<u64>,
    rate: Value<u64>,
    earned: Value<u64>,
}

impl Default for AccrualCircuit {
    fn default() -> Self {
        Self {
            block0: [Value::unknown(); BLOCK_LEN],
            block1: [Value::unknown(); BLOCK_LEN],
            note: [Value::unknown(); ACCRUAL_NOTE_LEN],
            open_height: Value::unknown(),
            close_height: Value::unknown(),
            rate: Value::unknown(),
            earned: Value::unknown(),
        }
    }
}

impl Circuit<pallas::Base> for AccrualCircuit {
    type Config = WordConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let constant = meta.fixed_column();
        WordChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let f = WordChip::construct(config);
        f.load_tables(layouter.namespace(|| "tables"))?;
        let zero = f.load_constant_field(layouter.namespace(|| "0"), pallas::Base::ZERO)?;

        let tail = ACCRUAL_PREIMAGE_LEN - BLOCK_LEN;
        let mut block0_vals = [Value::known(0u8); BLOCK_LEN];
        let mut block1_vals = [Value::known(0u8); BLOCK_LEN];
        let mut block0_cells: Vec<AssignedCell<pallas::Base, pallas::Base>> =
            Vec::with_capacity(BLOCK_LEN);
        let mut block1_cells: Vec<AssignedCell<pallas::Base, pallas::Base>> =
            Vec::with_capacity(BLOCK_LEN);
        for p in 0..BLOCK_LEN {
            block0_vals[p] = self.block0[p];
            block0_cells.push(f.assign_u8(
                layouter.namespace(|| format!("b0-{p}")),
                self.block0[p],
            )?);
        }
        for p in 0..BLOCK_LEN {
            let cell = if p >= tail {
                block1_vals[p] = Value::known(0u8);
                zero.clone()
            } else {
                block1_vals[p] = self.block1[p];
                f.assign_u8(layouter.namespace(|| format!("b1-{p}")), self.block1[p])?
            };
            block1_cells.push(cell);
        }

        // Note id is witness bytes at preimage[120..152], not a public instance.
        // block0[120..128] || block1[0..24].
        for i in 0..8 {
            let n = f.assign_u8(layouter.namespace(|| format!("note{i}")), self.note[i])?;
            f.constrain_equal(
                layouter.namespace(|| format!("note-b0-{i}")),
                &n,
                &block0_cells[ACCRUAL_NOTE_OFF + i],
            )?;
        }
        for i in 0..24 {
            let n = f.assign_u8(
                layouter.namespace(|| format!("note{}", 8 + i)),
                self.note[8 + i],
            )?;
            f.constrain_equal(
                layouter.namespace(|| format!("note-b1-{i}")),
                &n,
                &block1_cells[i],
            )?;
        }

        let words0 = f.bytes_to_words(
            layouter.namespace(|| "block0 words"),
            &block0_cells,
            &block0_vals,
        )?;
        let words1 = f.bytes_to_words(
            layouter.namespace(|| "block1 words"),
            &block1_cells,
            &block1_vals,
        )?;
        let t0 = f.constant_u64(layouter.namespace(|| "t0"), BLOCK_LEN as u64)?;
        let t1 = f.constant_u64(
            layouter.namespace(|| "t1"),
            ACCRUAL_PREIMAGE_LEN as u64,
        )?;
        let (plo, phi) = personal_words(ACCRUAL_PERSONAL);
        let digest = f.blake2b_two_blocks(
            layouter.namespace(|| "accrual blake2b"),
            &words0,
            &words1,
            &t0,
            &t1,
            plo,
            phi,
        )?;
        let digest_bytes = f.digest_bytes(layouter.namespace(|| "digest"), &digest)?;
        let packed_c = pack_bytes_circuit(&f, layouter.namespace(|| "pack C"), &digest_bytes)?;

        let pub_c = f.load_public(layouter.namespace(|| "pub C"), 0)?;
        let pub_open_h = f.load_public(layouter.namespace(|| "pub open h"), 1)?;
        let pub_close_h = f.load_public(layouter.namespace(|| "pub close h"), 2)?;
        f.constrain_equal(layouter.namespace(|| "C"), &packed_c, &pub_c)?;

        let open_hdr: [AssignedCell<pallas::Base, pallas::Base>; 32] = block0_cells[56..88]
            .to_vec()
            .try_into()
            .expect("open header bytes");
        let close_hdr: [AssignedCell<pallas::Base, pallas::Base>; 32] = block0_cells[88..120]
            .to_vec()
            .try_into()
            .expect("close header bytes");
        let packed_oh = pack_bytes_circuit(&f, layouter.namespace(|| "pack oh"), &open_hdr)?;
        let packed_ch = pack_bytes_circuit(&f, layouter.namespace(|| "pack ch"), &close_hdr)?;
        f.constrain_equal(layouter.namespace(|| "OH"), &packed_oh, &pub_open_h)?;
        f.constrain_equal(layouter.namespace(|| "CH"), &packed_ch, &pub_close_h)?;

        // f(): duration = close - open (field add, not wrapping 64-bit); earned = duration * rate.
        // Public instances stay the three packed hashes (96 bytes). Earned and note id are private.
        let open_w = f.assign_word(layouter.namespace(|| "open"), self.open_height)?;
        let close_w = f.assign_word(layouter.namespace(|| "close"), self.close_height)?;
        f.constrain_equal(layouter.namespace(|| "open b"), &open_w.value, &words0[0].value)?;
        f.constrain_equal(layouter.namespace(|| "close b"), &close_w.value, &words0[1].value)?;
        let duration_v = self
            .close_height
            .zip(self.open_height)
            .map(|(c, o)| c.wrapping_sub(o));
        let duration = f.assign_word(layouter.namespace(|| "duration"), duration_v)?;
        let sum = f.fadd(
            layouter.namespace(|| "open+dur"),
            &open_w.value,
            &duration.value,
        )?;
        f.constrain_equal(layouter.namespace(|| "close"), &sum, &close_w.value)?;
        let rate_w = f.assign_word(layouter.namespace(|| "rate"), self.rate)?;
        f.constrain_equal(layouter.namespace(|| "rate w"), &rate_w.value, &words0[2].value)?;
        let one = f.load_constant_field(layouter.namespace(|| "1"), pallas::Base::ONE)?;
        let dur_inv = f.assign_field(
            layouter.namespace(|| "dur inv"),
            duration.value.value().copied().map(|d| {
                Option::<pallas::Base>::from(d.invert()).unwrap_or(pallas::Base::ZERO)
            }),
        )?;
        let dur_one = f.mul(layouter.namespace(|| "dur*inv"), &duration.value, &dur_inv)?;
        f.constrain_equal(layouter.namespace(|| "dur nz"), &dur_one, &one)?;
        let rate_inv = f.assign_field(
            layouter.namespace(|| "rate inv"),
            rate_w.value.value().copied().map(|r| {
                Option::<pallas::Base>::from(r.invert()).unwrap_or(pallas::Base::ZERO)
            }),
        )?;
        let rate_one = f.mul(layouter.namespace(|| "rate*inv"), &rate_w.value, &rate_inv)?;
        f.constrain_equal(layouter.namespace(|| "rate nz"), &rate_one, &one)?;
        let prod = f.mul(
            layouter.namespace(|| "dur*rate"),
            &duration.value,
            &rate_w.value,
        )?;
        let earned = f.assign_word(layouter.namespace(|| "earned"), self.earned)?;
        f.constrain_equal(layouter.namespace(|| "earned"), &prod, &earned.value)?;
        let _ = zero;
        Ok(())
    }
}

fn circuit_from(
    open_height: u64,
    close_height: u64,
    rate: u64,
    earned: u64,
    blinding: &[u8; 32],
    open_header: &[u8; 32],
    close_header: &[u8; 32],
    note_id: &[u8; 32],
) -> AccrualCircuit {
    let pre = accrual_preimage_note(
        open_height,
        close_height,
        rate,
        blinding,
        open_header,
        close_header,
        note_id,
    );
    let mut block0 = [Value::known(0u8); BLOCK_LEN];
    let mut block1 = [Value::known(0u8); BLOCK_LEN];
    for (i, b) in pre.iter().enumerate() {
        if i < BLOCK_LEN {
            block0[i] = Value::known(*b);
        } else {
            block1[i - BLOCK_LEN] = Value::known(*b);
        }
    }
    AccrualCircuit {
        block0,
        block1,
        note: note_id.map(Value::known),
        open_height: Value::known(open_height),
        close_height: Value::known(close_height),
        rate: Value::known(rate),
        earned: Value::known(earned),
    }
}

fn to_instance(pubs: &[pallas::Base; ACCRUAL_INSTANCE_COUNT]) -> [[vesta::Scalar; 3]; 1] {
    let mut row = [vesta::Scalar::zero(); 3];
    for (i, p) in pubs.iter().enumerate() {
        row[i] = *p;
    }
    [row]
}

fn setup_keys() -> Result<
    &'static (
        halo2_proofs::poly::commitment::Params<vesta::Affine>,
        plonk::ProvingKey<vesta::Affine>,
    ),
    String,
> {
    static KEYS: OnceLock<(
        halo2_proofs::poly::commitment::Params<vesta::Affine>,
        plonk::ProvingKey<vesta::Affine>,
    )> = OnceLock::new();
    Ok(KEYS.get_or_init(|| {
        let params = halo2_proofs::poly::commitment::Params::new(ACCRUAL_K);
        let empty = AccrualCircuit::default();
        let vk = plonk::keygen_vk(&params, &empty).expect("accrual keygen_vk");
        let pk = plonk::keygen_pk(&params, vk, &empty).expect("accrual keygen_pk");
        (params, pk)
    }))
}

/// Off-chain Halo2 prove of `earned = (close - open) * rate` bound to the
/// all-zero note id. Empty proof is never produced.
pub fn prove_accrual(
    open_height: u64,
    close_height: u64,
    rate: u64,
    earned: u64,
    blinding: &[u8; 32],
    open_header: &[u8; 32],
    close_header: &[u8; 32],
) -> Result<Vec<u8>, String> {
    prove_accrual_note(
        open_height,
        close_height,
        rate,
        earned,
        blinding,
        open_header,
        close_header,
        &[0u8; 32],
    )
}

/// Same relation, bound to a 32-byte Ironwood note id. The note is witness
/// only. Public instances stay commitment || open header || close header.
/// Earned must be `(close - open) * rate`; the caller cannot set another bill.
pub fn prove_accrual_note(
    open_height: u64,
    close_height: u64,
    rate: u64,
    earned: u64,
    blinding: &[u8; 32],
    open_header: &[u8; 32],
    close_header: &[u8; 32],
    note_id: &[u8; 32],
) -> Result<Vec<u8>, String> {
    if close_height <= open_height {
        return Err("inverted window".into());
    }
    if rate == 0 {
        return Err("zero rate".into());
    }
    let duration = close_height - open_height;
    if duration.checked_mul(rate) != Some(earned) {
        return Err("earned != (close - open) * rate".into());
    }
    if open_header == close_header {
        return Err("header collision".into());
    }
    let circuit = circuit_from(
        open_height,
        close_height,
        rate,
        earned,
        blinding,
        open_header,
        close_header,
        note_id,
    );
    let commitment = accrual_commit_note_bytes(
        open_height,
        close_height,
        rate,
        blinding,
        open_header,
        close_header,
        note_id,
    );
    let pubs = accrual_public_scalars(&commitment, open_header, close_header);
    let (params, pk) = setup_keys()?;
    let instance = to_instance(&pubs);
    let refs: Vec<&[vesta::Scalar]> = instance.iter().map(|r| &r[..]).collect();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
    plonk::create_proof(params, pk, &[circuit], &[&refs], rng(), &mut transcript)
        .map_err(|e| format!("create_proof: {e}"))?;
    Ok(transcript.finalize())
}

fn halo2_verify(
    params: &halo2_proofs::poly::commitment::Params<vesta::Affine>,
    vk: &plonk::VerifyingKey<vesta::Affine>,
    proof: &[u8],
    pubs: &[pallas::Base; ACCRUAL_INSTANCE_COUNT],
) -> Result<bool, String> {
    reject_forbidden_proof_bytes(proof)?;
    let instance = to_instance(pubs);
    let refs: Vec<&[vesta::Scalar]> = instance.iter().map(|r| &r[..]).collect();
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof);
    match plonk::verify_proof(params, vk, strategy, &[&refs], &mut transcript) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Real Halo2 verify of `f`. 128-byte HOSTING_PAYMENT instances are rejected.
pub fn verify_accrual(proof: &[u8], instances: &[u8]) -> Result<bool, String> {
    reject_forbidden_proof_bytes(proof)?;
    let pubs = decode_accrual_instances(instances)?;
    let (params, pk) = setup_keys()?;
    halo2_verify(params, pk.get_vk(), proof, &pubs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preimage_binds_note_id() {
        assert_eq!(ACCRUAL_PREIMAGE_LEN, 152);
        assert!(ACCRUAL_PREIMAGE_LEN > BLOCK_LEN);
        assert_eq!(ACCRUAL_NOTE_OFF, 120);
        assert_eq!(ACCRUAL_NOTE_LEN, 32);
        assert_ne!(ACCRUAL_K, crate::K);
        assert_eq!(ACCRUAL_INSTANCE_COUNT, 3);
        assert_eq!(ACCRUAL_ZKID, 2);
        assert_ne!(ACCRUAL_CIRCUIT_ID, crate::CIRCUIT_ID);
        let note_a = [0xabu8; 32];
        let note_b = [0xcdu8; 32];
        let open_h = [0x0au8; 32];
        let close_h = [0x0cu8; 32];
        let blinding = [7u8; 32];
        let pre = accrual_preimage_note(10, 15, 100, &blinding, &open_h, &close_h, &note_a);
        assert_eq!(&pre[ACCRUAL_NOTE_OFF..], &note_a);
        let c0 = accrual_commit_bytes(10, 15, 100, &blinding, &open_h, &close_h);
        let c_zero = accrual_commit_note_bytes(
            10, 15, 100, &blinding, &open_h, &close_h, &[0u8; 32],
        );
        assert_eq!(c0, c_zero);
        let c_a = accrual_commit_note_bytes(10, 15, 100, &blinding, &open_h, &close_h, &note_a);
        let c_b = accrual_commit_note_bytes(10, 15, 100, &blinding, &open_h, &close_h, &note_b);
        assert_ne!(c_a, c_b);
        assert_ne!(c_a, c0);
        let inst = encode_accrual_instances(&c_a, &open_h, &close_h);
        assert_eq!(inst.len(), 96);
        assert!(!inst.chunks(32).any(|w| w == note_a || w == note_b));
        assert!(decode_accrual_instances(&inst).is_ok());
        assert!(decode_accrual_instances(&[0u8; 128])
            .unwrap_err()
            .contains("HOSTING_PAYMENT"));
        assert!(verify_accrual(&[], &inst).unwrap_err().contains("empty proof"));
        assert!(crate::proof_instance_verify(1, &[1u8; 80], &inst)
            .unwrap_err()
            .contains("HOSTING_PAYMENT zkid"));
        assert!(crate::proof_instance_verify(ACCRUAL_ZKID, &[], &inst)
            .unwrap_err()
            .contains("empty proof"));
        assert!(crate::proof_instance_verify(ACCRUAL_ZKID, &[1u8; 80], &[0u8; 128])
            .unwrap_err()
            .contains("96-byte"));
        assert!(prove_accrual_note(10, 15, 100, 1, &blinding, &open_h, &close_h, &note_a).is_err());
    }

    #[test]
    fn mock_prover_accepts_f() {
        use halo2_proofs::dev::MockProver;
        let open_h = [0x0au8; 32];
        let close_h = [0x0cu8; 32];
        let blinding = [7u8; 32];
        let note = [0xabu8; 32];
        let circuit = circuit_from(10, 15, 100, 500, &blinding, &open_h, &close_h, &note);
        let c = accrual_commit_note_bytes(10, 15, 100, &blinding, &open_h, &close_h, &note);
        let pubs = accrual_public_scalars(&c, &open_h, &close_h);
        let prover = MockProver::run(ACCRUAL_K, &circuit, vec![pubs.to_vec()]).expect("mock");
        prover.assert_satisfied();
        let bad = circuit_from(10, 15, 100, 1, &blinding, &open_h, &close_h, &note);
        let bad_prover = MockProver::run(ACCRUAL_K, &bad, vec![pubs.to_vec()]).expect("mock bad");
        assert!(bad_prover.verify().is_err(), "wrong earned must not satisfy f()");
    }
}
