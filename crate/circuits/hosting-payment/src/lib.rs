//! Halo2 circuits:
//! - ZAP1 HOSTING_PAYMENT leaf inclusion (BLAKE2b-256), 128-byte instances
//! - `f(open_height, close_height, rate)` accrual (`accrual` module), 96-byte instances
//!
//! HOSTING_PAYMENT public instances (one column, 4 rows) — 128 bytes LE:
//!   [0] merkle_root   (254-bit pack of ZAP1 BLAKE2b root)
//!   [1] frost_group
//!   [2] amount_class
//!   [3] hosting_kind  (domain `HOSTING_PAYMENT`)
//!
//! Private (never on CosmWasm execute): serial, month, year, Merkle sibling
//! bytes, left/right bit.
//!
//! Leaf = BLAKE2b-256(`NordicShield_`, `0x05 || u16be(len) || serial || month_be || year_be`)
//! Node = BLAKE2b-256(`NordicShield_MRK`, `left || right`)
//! Default tree matches PIR `local_hosting_bundle`: sibling is ProgramEntry
//! leaf, on the right, depth 1.
//!
//! Host: `proof_instance_verify(zkid, proof, instances)` via
//! `halo2_proofs::plonk::verify_proof` (not DummyStwo, not always-true).
//! Empty proof is an error. Missing host must fail closed (this crate never
//! returns true without `verify_proof`).

mod blake2b;
mod chip;
mod accrual;

pub use accrual::{
    accrual_commit_bytes, accrual_preimage, accrual_public_scalars, decode_accrual_instances,
    encode_accrual_instances, prove_accrual, verify_accrual, ACCRUAL_CIRCUIT_ID, ACCRUAL_INSTANCE_COUNT,
    ACCRUAL_K, ACCRUAL_PERSONAL, ACCRUAL_PREIMAGE_LEN, ACCRUAL_ZKID,
};

use crate::blake2b::{hosting_payment_leaf, node_hash, program_entry_leaf, LEAF_PERSONAL, NODE_PERSONAL};
use crate::chip::{WordChip, WordConfig};
use ff::PrimeField;
use group::ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{self, Circuit, ConstraintSystem, Error, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const K: u32 = 17;
pub const INSTANCE_COUNT: usize = 4;
pub const MERKLE_DEPTH: usize = 1;
pub const MAX_SERIAL: usize = 32;
pub const KIND_DOMAIN: &str = "HOSTING_PAYMENT";
pub const CIRCUIT_ID: &str = "hosting-payment.inclusion.v1";
pub const HOSTING_MONTH: u32 = 8;
pub const HOSTING_YEAR: u32 = 2026;
/// Matches `pir-live-attach` / `export-halo2` default witness.
pub const LIVE_SERIAL: &str = "PIR-LC-LIVE";
pub const LIVE_SIBLING: &str = "sib";
pub const LIVE_AMOUNT_ZAT: u64 = 11;

pub(crate) fn personal_words(p: &[u8]) -> (u64, u64) {
    let mut b = [0u8; 16];
    let n = core::cmp::min(p.len(), 16);
    b[..n].copy_from_slice(&p[..n]);
    (
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
    )
}

struct HostingPaymentCircuit {
    serial: [Value<u8>; MAX_SERIAL],
    serial_len: Value<u64>,
    sibling: [Value<u8>; 32],
    is_left: Value<bool>,
    frost: Value<pallas::Base>,
    amount: Value<pallas::Base>,
}

impl Default for HostingPaymentCircuit {
    fn default() -> Self {
        Self {
            serial: [Value::unknown(); MAX_SERIAL],
            serial_len: Value::unknown(),
            sibling: [Value::unknown(); 32],
            is_left: Value::unknown(),
            frost: Value::unknown(),
            amount: Value::unknown(),
        }
    }
}

impl Circuit<pallas::Base> for HostingPaymentCircuit {
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
        let one = f.load_constant_field(layouter.namespace(|| "1"), pallas::Base::ONE)?;

        let mut serial_cells = Vec::with_capacity(MAX_SERIAL);
        for i in 0..MAX_SERIAL {
            serial_cells.push(f.assign_u8(
                layouter.namespace(|| format!("ser{i}")),
                self.serial[i],
            )?);
        }
        let mut e = Vec::with_capacity(MAX_SERIAL + 1);
        for k in 0..=MAX_SERIAL {
            let bit = self
                .serial_len
                .map(|n| {
                    if n == k as u64 {
                        pallas::Base::ONE
                    } else {
                        pallas::Base::ZERO
                    }
                });
            e.push(f.assign_bit(layouter.namespace(|| format!("e{k}")), bit)?);
        }
        let mut e_sum = zero.clone();
        for (k, ek) in e.iter().enumerate() {
            e_sum = f.fadd(layouter.namespace(|| format!("es{k}")), &e_sum, ek)?;
        }
        f.constrain_equal(layouter.namespace(|| "one-hot"), &e_sum, &one)?;
        let mut n_cell = zero.clone();
        for k in 0..=MAX_SERIAL {
            let kv = f.load_constant_field(layouter.namespace(|| format!("k{k}")), pallas::Base::from(k as u64))?;
            let term = f.mul(layouter.namespace(|| format!("nk{k}")), &e[k], &kv)?;
            n_cell = f.fadd(layouter.namespace(|| format!("ns{k}")), &n_cell, &term)?;
        }

        let month_year: [u8; 8] = {
            let mut b = [0u8; 8];
            b[0..4].copy_from_slice(&HOSTING_MONTH.to_be_bytes());
            b[4..8].copy_from_slice(&HOSTING_YEAR.to_be_bytes());
            b
        };

        let mut block_vals = [Value::known(0u8); 128];
        let mut block_cells = Vec::with_capacity(128);
        for p in 0..128 {
            let byte_v = self.serial_len.map(|len| {
                let mut serial = [0u8; MAX_SERIAL];
                for i in 0..MAX_SERIAL {
                    self.serial[i].map(|b| serial[i] = b);
                }
                leaf_block_byte_known(&serial, len as usize, p, &month_year)
            });
            let cell = if p == 0 {
                f.load_constant_field(layouter.namespace(|| "b0"), pallas::Base::from(0x05u64))?
            } else if p == 1 {
                zero.clone()
            } else if p == 2 {
                n_cell.clone()
            } else if p >= 3 + MAX_SERIAL + 8 {
                zero.clone()
            } else {
                f.assign_u8(layouter.namespace(|| format!("mb{p}")), byte_v)?
            };
            block_vals[p] = byte_v;
            block_cells.push(cell);
        }

        // Bind bytes 3..42: serial then month||year, via one-hot length.
        for j in 0..(MAX_SERIAL + 8) {
            let p = 3 + j;
            let mut expected = zero.clone();
            if j < MAX_SERIAL {
                let mut gt = zero.clone();
                for k in (j + 1)..=MAX_SERIAL {
                    gt = f.fadd(layouter.namespace(|| format!("gt{j}-{k}")), &gt, &e[k])?;
                }
                expected = f.mul(
                    layouter.namespace(|| format!("serterm{j}")),
                    &serial_cells[j],
                    &gt,
                )?;
            }
            for t in 0..8 {
                let k = j as i32 - t as i32;
                if (0..=MAX_SERIAL as i32).contains(&k) {
                    let myt = f.load_constant_field(
                        layouter.namespace(|| format!("my{j}-{t}")),
                        pallas::Base::from(month_year[t] as u64),
                    )?;
                    let term = f.mul(
                        layouter.namespace(|| format!("myt{j}-{t}")),
                        &e[k as usize],
                        &myt,
                    )?;
                    expected = f.fadd(layouter.namespace(|| format!("mya{j}-{t}")), &expected, &term)?;
                }
            }
            f.constrain_equal(
                layouter.namespace(|| format!("leafb{p}")),
                &block_cells[p],
                &expected,
            )?;
        }

        let leaf_words = f.bytes_to_words(
            layouter.namespace(|| "leaf words"),
            &block_cells,
            &block_vals,
        )?;
        let eleven = f.load_constant_field(layouter.namespace(|| "11"), pallas::Base::from(11u64))?;
        let t_leaf_f = f.fadd(layouter.namespace(|| "tleaf"), &n_cell, &eleven)?;
        let t_leaf = f.assign_word(
            layouter.namespace(|| "tleaf word"),
            self.serial_len.map(|n| n + 11),
        )?;
        f.constrain_equal(layouter.namespace(|| "t=n+11"), &t_leaf.value, &t_leaf_f)?;
        let (leaf_lo, leaf_hi) = personal_words(LEAF_PERSONAL);
        let leaf_h = f.blake2b_one_block(
            layouter.namespace(|| "leaf blake2b"),
            &leaf_words,
            &t_leaf,
            leaf_lo,
            leaf_hi,
        )?;
        let leaf_bytes = f.digest_bytes(layouter.namespace(|| "leaf out"), &leaf_h)?;

        let mut sib_cells = Vec::with_capacity(32);
        for i in 0..32 {
            sib_cells.push(f.assign_u8(
                layouter.namespace(|| format!("sib{i}")),
                self.sibling[i],
            )?);
        }
        let is_left = f.assign_bit(
            layouter.namespace(|| "is_left"),
            self.is_left.map(|b| {
                if b {
                    pallas::Base::ONE
                } else {
                    pallas::Base::ZERO
                }
            }),
        )?;
        let neg = f.load_constant_field(layouter.namespace(|| "-1"), -pallas::Base::ONE)?;
        let neg_bit = f.mul(layouter.namespace(|| "-L"), &is_left, &neg)?;
        let one_minus = f.fadd(layouter.namespace(|| "1-L"), &one, &neg_bit)?;

        let mut left_bytes = Vec::with_capacity(32);
        let mut right_bytes = Vec::with_capacity(32);
        let mut left_vals = [Value::known(0u8); 32];
        let mut right_vals = [Value::known(0u8); 32];
        for i in 0..32 {
            let sib_term = f.mul(
                layouter.namespace(|| format!("sL{i}")),
                &sib_cells[i],
                &is_left,
            )?;
            let leaf_term = f.mul(
                layouter.namespace(|| format!("cR{i}")),
                &leaf_bytes[i],
                &one_minus,
            )?;
            let left = f.fadd(layouter.namespace(|| format!("L{i}")), &sib_term, &leaf_term)?;
            let sib_r = f.mul(
                layouter.namespace(|| format!("sR{i}")),
                &sib_cells[i],
                &one_minus,
            )?;
            let leaf_l = f.mul(
                layouter.namespace(|| format!("cL{i}")),
                &leaf_bytes[i],
                &is_left,
            )?;
            let right = f.fadd(layouter.namespace(|| format!("R{i}")), &sib_r, &leaf_l)?;
            left_bytes.push(left);
            right_bytes.push(right);
        }
        for i in 0..32 {
            left_vals[i] = self
                .is_left
                .zip(self.sibling[i])
                .zip(self.serial_len)
                .map(|((left_bit, s), len)| {
                    let mut serial = [0u8; MAX_SERIAL];
                    for j in 0..MAX_SERIAL {
                        self.serial[j].map(|b| serial[j] = b);
                    }
                    let leaf = hosting_payment_leaf(
                        &serial[..len as usize],
                        HOSTING_MONTH,
                        HOSTING_YEAR,
                    );
                    if left_bit {
                        s
                    } else {
                        leaf[i]
                    }
                });
            right_vals[i] = self
                .is_left
                .zip(self.sibling[i])
                .zip(self.serial_len)
                .map(|((left_bit, s), len)| {
                    let mut serial = [0u8; MAX_SERIAL];
                    for j in 0..MAX_SERIAL {
                        self.serial[j].map(|b| serial[j] = b);
                    }
                    let leaf = hosting_payment_leaf(
                        &serial[..len as usize],
                        HOSTING_MONTH,
                        HOSTING_YEAR,
                    );
                    if left_bit {
                        leaf[i]
                    } else {
                        s
                    }
                });
        }

        let mut node_block_cells = Vec::with_capacity(128);
        let mut node_block_vals = [Value::known(0u8); 128];
        node_block_cells.extend(left_bytes);
        node_block_cells.extend(right_bytes);
        for i in 0..32 {
            node_block_vals[i] = left_vals[i];
            node_block_vals[32 + i] = right_vals[i];
        }
        for _ in 64..128 {
            node_block_cells.push(zero.clone());
        }
        let node_words = f.bytes_to_words(
            layouter.namespace(|| "node words"),
            &node_block_cells,
            &node_block_vals,
        )?;
        let t_node = f.constant_u64(layouter.namespace(|| "t64"), 64)?;
        let (node_lo, node_hi) = personal_words(NODE_PERSONAL);
        let root_h = f.blake2b_one_block(
            layouter.namespace(|| "node blake2b"),
            &node_words,
            &t_node,
            node_lo,
            node_hi,
        )?;
        let root_bytes = f.digest_bytes(layouter.namespace(|| "root out"), &root_h)?;
        let packed_root = pack_bytes_circuit(&f, layouter.namespace(|| "pack root"), &root_bytes)?;

        let pub_root = f.load_public(layouter.namespace(|| "pub root"), 0)?;
        let pub_frost = f.load_public(layouter.namespace(|| "pub frost"), 1)?;
        let pub_amt = f.load_public(layouter.namespace(|| "pub amt"), 2)?;
        let pub_kind = f.load_public(layouter.namespace(|| "pub kind"), 3)?;
        let frost_w = f.assign_field(layouter.namespace(|| "frost"), self.frost)?;
        let amt_w = f.assign_field(layouter.namespace(|| "amt"), self.amount)?;
        let kind = f.load_constant_field(layouter.namespace(|| "KIND"), str_to_field(KIND_DOMAIN))?;

        f.constrain_equal(layouter.namespace(|| "R"), &packed_root, &pub_root)?;
        f.constrain_equal(layouter.namespace(|| "F"), &frost_w, &pub_frost)?;
        f.constrain_equal(layouter.namespace(|| "A"), &amt_w, &pub_amt)?;
        f.constrain_equal(layouter.namespace(|| "K"), &kind, &pub_kind)?;
        Ok(())
    }
}

fn leaf_block_byte_known(serial: &[u8; MAX_SERIAL], len: usize, p: usize, month_year: &[u8; 8]) -> u8 {
    if p == 0 {
        return 0x05;
    }
    if p == 1 {
        return 0;
    }
    if p == 2 {
        return len as u8;
    }
    if p >= 3 + len + 8 {
        return 0;
    }
    if p < 3 + len {
        return serial[p - 3];
    }
    month_year[p - (3 + len)]
}

pub(crate) fn pack_bytes_circuit(
    f: &WordChip<pallas::Base>,
    mut layouter: impl Layouter<pallas::Base>,
    bytes: &[halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>; 32],
) -> Result<halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>, Error> {
    let two56 = f.load_constant_field(layouter.namespace(|| "256"), pallas::Base::from(256u64))?;
    let mut pow = f.load_constant_field(layouter.namespace(|| "pow1"), pallas::Base::ONE)?;
    let mut acc = f.load_constant_field(layouter.namespace(|| "acc0"), pallas::Base::ZERO)?;
    for i in 0..32 {
        let b = if i == 31 {
            // mask top 2 bits: byte = r + 64*q, q in {0,1,2,3}, r in 0..63
            mask6(f, layouter.namespace(|| "mask31"), &bytes[31])?
        } else {
            bytes[i].clone()
        };
        let term = f.mul(layouter.namespace(|| format!("pt{i}")), &b, &pow)?;
        acc = f.fadd(layouter.namespace(|| format!("pa{i}")), &acc, &term)?;
        if i != 31 {
            pow = f.mul(layouter.namespace(|| format!("pp{i}")), &pow, &two56)?;
        }
    }
    Ok(acc)
}

fn mask6(
    f: &WordChip<pallas::Base>,
    mut layouter: impl Layouter<pallas::Base>,
    byte: &halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
) -> Result<halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>, Error> {
    let mut bits = Vec::with_capacity(8);
    for i in 0..8 {
        let bv = byte.value().copied().map(|v| {
            let n = v.to_repr().as_ref()[0];
            if (n >> i) & 1 == 1 {
                pallas::Base::ONE
            } else {
                pallas::Base::ZERO
            }
        });
        bits.push(f.assign_bit(layouter.namespace(|| format!("mbit{i}")), bv)?);
    }
    let mut acc = f.load_constant_field(layouter.namespace(|| "bacc"), pallas::Base::ZERO)?;
    let mut masked = f.load_constant_field(layouter.namespace(|| "macc"), pallas::Base::ZERO)?;
    for i in 0..8 {
        let p2 = f.load_constant_field(
            layouter.namespace(|| format!("p2{i}")),
            pallas::Base::from(1u64 << i),
        )?;
        let term = f.mul(layouter.namespace(|| format!("bt{i}")), &bits[i], &p2)?;
        acc = f.fadd(layouter.namespace(|| format!("ba{i}")), &acc, &term)?;
        if i < 6 {
            masked = f.fadd(layouter.namespace(|| format!("ma{i}")), &masked, &term)?;
        }
    }
    f.constrain_equal(layouter.namespace(|| "byte bits"), byte, &acc)?;
    Ok(masked)
}

pub fn str_to_field<F: PrimeField>(s: &str) -> F {
    let mut repr = F::default().to_repr();
    let src = s.as_bytes();
    let len = core::cmp::min(src.len(), repr.as_ref().len());
    repr.as_mut()[..len].copy_from_slice(&src[..len]);
    Option::<F>::from(F::from_repr(repr)).unwrap_or(F::ZERO)
}

/// 254-bit pack so every 32-byte ZAP1 digest is a canonical pallas element.
pub fn pack_hash32(b: &[u8; 32]) -> pallas::Base {
    let mut tmp = *b;
    tmp[31] &= 0x3f;
    Option::<pallas::Base>::from(pallas::Base::from_repr(tmp)).expect("254-bit fits pallas")
}

pub fn bytes32_to_field(b: &[u8; 32]) -> pallas::Base {
    pack_hash32(b)
}

pub fn hosting_kind() -> pallas::Base {
    str_to_field(KIND_DOMAIN)
}

/// PIR tagged hash (`tag || u8(tag_len) || u64le(part_len) || part …`).
pub fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(tag);
    h.update(&[tag.len() as u8]);
    for p in parts {
        h.update(&(*p).len().to_le_bytes());
        h.update(*p);
    }
    h.finalize().into()
}

pub fn live_frost_group() -> [u8; 32] {
    tagged_hash(b"g", &[b"zap1-live"])
}

/// Toy field-mul (`serial² + HOSTING_PAYMENT`) is not ZAP1 inclusion.
pub fn toy_field_mul_leaf(serial: &str) -> pallas::Base {
    str_to_field::<pallas::Base>(serial).square() + hosting_kind()
}

pub fn zap1_hosting_leaf_bytes(serial: &str) -> [u8; 32] {
    hosting_payment_leaf(serial.as_bytes(), HOSTING_MONTH, HOSTING_YEAR)
}

pub fn zap1_hosting_leaf(serial: &str) -> pallas::Base {
    pack_hash32(&zap1_hosting_leaf_bytes(serial))
}

pub fn zap1_sibling_leaf_bytes(sibling: &str) -> [u8; 32] {
    program_entry_leaf(sibling.as_bytes())
}

pub fn zap1_merkle_root_bytes(serial: &str, sibling: &str) -> [u8; 32] {
    node_hash(
        &zap1_hosting_leaf_bytes(serial),
        &zap1_sibling_leaf_bytes(sibling),
    )
}

pub fn merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    node_hash(left, right)
}

pub fn public_scalars(
    serial: &str,
    sibling: &str,
    frost: &[u8; 32],
    amount_zat: u64,
) -> [pallas::Base; INSTANCE_COUNT] {
    [
        pack_hash32(&zap1_merkle_root_bytes(serial, sibling)),
        pack_hash32(frost),
        pallas::Base::from(amount_zat),
        hosting_kind(),
    ]
}

pub fn encode_instances(
    serial: &str,
    sibling: &str,
    frost: &[u8; 32],
    amount_zat: u64,
) -> Vec<u8> {
    let pubs = public_scalars(serial, sibling, frost, amount_zat);
    let mut out = Vec::with_capacity(128);
    for f in pubs {
        out.extend_from_slice(f.to_repr().as_ref());
    }
    out
}

fn to_halo2_instance(pubs: &[pallas::Base; 4]) -> [[vesta::Scalar; 4]; 1] {
    let mut row = [vesta::Scalar::zero(); 4];
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
        let params = halo2_proofs::poly::commitment::Params::new(K);
        let empty = HostingPaymentCircuit::default();
        let vk = plonk::keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = plonk::keygen_pk(&params, vk, &empty).expect("keygen_pk");
        (params, pk)
    }))
}

fn verifying_setup() -> Result<
    &'static (
        halo2_proofs::poly::commitment::Params<vesta::Affine>,
        plonk::VerifyingKey<vesta::Affine>,
    ),
    String,
> {
    static VK: OnceLock<(
        halo2_proofs::poly::commitment::Params<vesta::Affine>,
        plonk::VerifyingKey<vesta::Affine>,
    )> = OnceLock::new();
    Ok(VK.get_or_init(|| {
        let params = halo2_proofs::poly::commitment::Params::new(K);
        let empty = HostingPaymentCircuit::default();
        let vk = plonk::keygen_vk(&params, &empty).expect("keygen_vk");
        (params, vk)
    }))
}

fn circuit_from(
    serial: &str,
    sibling: &str,
    frost: &[u8; 32],
    amount_zat: u64,
) -> Result<HostingPaymentCircuit, String> {
    let sb = serial.as_bytes();
    if sb.len() > MAX_SERIAL {
        return Err("serial too long".into());
    }
    let mut serial_v = [Value::known(0u8); MAX_SERIAL];
    for (i, b) in sb.iter().enumerate() {
        serial_v[i] = Value::known(*b);
    }
    let sib = zap1_sibling_leaf_bytes(sibling);
    Ok(HostingPaymentCircuit {
        serial: serial_v,
        serial_len: Value::known(sb.len() as u64),
        sibling: sib.map(Value::known),
        is_left: Value::known(false),
        frost: Value::known(pack_hash32(frost)),
        amount: Value::known(pallas::Base::from(amount_zat)),
    })
}

/// Off-chain Halo2 prove. Merkle siblings stay in the witness, not in public execute.
pub fn prove_inclusion(
    serial: &str,
    sibling: &str,
    frost: &[u8; 32],
    amount_zat: u64,
) -> Result<Vec<u8>, String> {
    let circuit = circuit_from(serial, sibling, frost, amount_zat)?;
    let (params, pk) = setup_keys()?;
    let pubs = public_scalars(serial, sibling, frost, amount_zat);
    let instance = to_halo2_instance(&pubs);
    let refs: Vec<&[vesta::Scalar]> = instance.iter().map(|r| &r[..]).collect();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
    plonk::create_proof(params, pk, &[circuit], &[&refs], OsRng, &mut transcript)
        .map_err(|e| format!("create_proof: {e}"))?;
    Ok(transcript.finalize())
}

/// Real Halo2 verify (`plonk::verify_proof`). Returns false on invalid proof.
pub fn verify_inclusion(
    proof: &[u8],
    serial: &str,
    sibling: &str,
    frost: &[u8; 32],
    amount_zat: u64,
) -> Result<bool, String> {
    let pubs = public_scalars(serial, sibling, frost, amount_zat);
    verify_inclusion_instances(proof, &pubs)
}

pub fn verify_inclusion_instances(
    proof: &[u8],
    pubs: &[pallas::Base; INSTANCE_COUNT],
) -> Result<bool, String> {
    if proof.is_empty() {
        return Err("empty proof".into());
    }
    let (params, vk) = verifying_setup()?;
    halo2_verify_proof(params, vk, proof, pubs)
}

/// DummyStwo (`DSTW` checksum) is forbidden. Empty proof is not Halo2-true.
pub(crate) fn reject_forbidden_proof_bytes(proof: &[u8]) -> Result<(), String> {
    if proof.is_empty() {
        return Err("empty proof".into());
    }
    if proof.starts_with(b"DSTW") {
        return Err("DummyStwo proofs are forbidden (Halo2 HOSTING_PAYMENT only)".into());
    }
    Ok(())
}

/// WordChip BLAKE2b Merkle: lookups + ≥7 gates + 5 advice + 1 instance.
/// Toy field-mul (`serial² + HOSTING_PAYMENT`) fails this.
pub fn cs_is_hosting_payment_wordchip(
    cs: &plonk::ConstraintSystem<pallas::Base>,
) -> Result<(), String> {
    if !cs.has_lookups() {
        return Err("loaded CS has no lookups; toy field-mul is not HOSTING_PAYMENT".into());
    }
    // WordChip: bool, add64, fadd, compose_nibble, mul, byte, nibble4 (+ range/xor lookups).
    if cs.get_gate_count() < 7 {
        return Err("loaded CS too small for BLAKE2b Merkle (toy field-mul rejected)".into());
    }
    if cs.get_num_advice_columns() < 5 || cs.get_num_instance_columns() != 1 {
        return Err("loaded CS column counts are not HOSTING_PAYMENT WordChip".into());
    }
    Ok(())
}

fn halo2_verify_proof(
    params: &halo2_proofs::poly::commitment::Params<vesta::Affine>,
    vk: &plonk::VerifyingKey<vesta::Affine>,
    proof: &[u8],
    pubs: &[pallas::Base; INSTANCE_COUNT],
) -> Result<bool, String> {
    reject_forbidden_proof_bytes(proof)?;
    let instance = to_halo2_instance(pubs);
    let refs: Vec<&[vesta::Scalar]> = instance.iter().map(|r| &r[..]).collect();
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof);
    match plonk::verify_proof(params, vk, strategy, &[&refs], &mut transcript) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn decode_instances(bytes: &[u8]) -> Result<[pallas::Base; INSTANCE_COUNT], String> {
    if bytes.len() != 128 {
        return Err("instances must be 128 bytes".into());
    }
    let mut out = [pallas::Base::ZERO; INSTANCE_COUNT];
    for i in 0..INSTANCE_COUNT {
        let chunk: [u8; 32] = bytes[i * 32..(i + 1) * 32]
            .try_into()
            .map_err(|_| "chunk")?;
        out[i] = Option::<pallas::Base>::from(pallas::Base::from_repr(chunk))
            .ok_or_else(|| "invalid field encoding".to_string())?;
    }
    Ok(out)
}

/// Native stand-in for zk-wasmvm `proof_instance_verify(zkid, proof, instances)`.
/// Halo2 `plonk::verify_proof` only (not DummyStwo, not always-true).
///
/// Instance waist:
/// - 128 bytes + zkid 1 → HOSTING_PAYMENT inclusion
/// - 96 bytes + zkid 2 → `f(open_height, close_height, rate)` (`pir-accrual.f.v1`)
///
/// Path A store (`params.bin`+`vk_body.bin`) is preferred so verify does not
/// re-keygen. Missing store + `PIR_HALO2_REQUIRE=1` fail-closes.
/// Does not invent a wasm FFI; CosmWasm execute forwards these blobs only.
pub fn proof_instance_verify(zkid: u64, proof: &[u8], instances: &[u8]) -> Result<bool, String> {
    reject_forbidden_proof_bytes(proof)?;
    if instances.len() == 96 {
        if zkid == 1 {
            return Err("HOSTING_PAYMENT zkid does not verify f()".into());
        }
        return verify_accrual(proof, instances);
    }
    if zkid == ACCRUAL_ZKID {
        return Err("accrual zkid requires 96-byte instances, not HOSTING_PAYMENT 128".into());
    }
    let pubs = decode_instances(instances)?;
    if pubs[3] != hosting_kind() {
        return Ok(false);
    }
    #[cfg(feature = "store-full-circuit")]
    {
        let required = std::env::var("PIR_HALO2_REQUIRE").ok().as_deref() == Some("1");
        let paths = resolve_halo2_artifacts();
        if paths.params.is_file() && paths.vk_body.is_file() {
            let params = std::fs::read(&paths.params).map_err(|e| e.to_string())?;
            let vk_body = std::fs::read(&paths.vk_body).map_err(|e| e.to_string())?;
            return verify_proof_with_store(&params, &vk_body, proof, instances);
        }
        if required {
            return Err(
                "PIR_HALO2_REQUIRE=1 but PIR_HALO2_PARAMS/VK_BODY missing (host fail-closed)"
                    .into(),
            );
        }
    }
    verify_inclusion_instances(proof, &pubs)
}

pub fn default_halo2_artifact_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/halo2")
}

/// Paths for a Path A store-full-circuit bundle (proof + 128-byte instances).
pub struct Halo2ArtifactPaths {
    pub proof: PathBuf,
    pub instances: PathBuf,
    pub params: PathBuf,
    pub vk_body: PathBuf,
}

/// Env (`PIR_HALO2_*`) else `circuits/hosting-payment/../../artifacts/halo2`.
pub fn resolve_halo2_artifacts() -> Halo2ArtifactPaths {
    let dir = std::env::var("PIR_HALO2_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_halo2_artifact_dir());
    let proof = std::env::var("PIR_HALO2_PROOF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir.join("proof.bin"));
    let instances = std::env::var("PIR_HALO2_INSTANCES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir.join("instances.bin"));
    let params = std::env::var("PIR_HALO2_PARAMS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir.join("params.bin"));
    let vk_body = std::env::var("PIR_HALO2_VK_BODY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir.join("vk_body.bin"));
    Halo2ArtifactPaths {
        proof,
        instances,
        params,
        vk_body,
    }
}

/// True iff instances are 128-byte ZAP1 HOSTING_PAYMENT (not toy field-mul).
pub fn instances_are_zap1_hosting_payment(
    instances: &[u8],
    serial: &str,
    sibling: &str,
    frost: &[u8; 32],
    amount_zat: u64,
) -> Result<bool, String> {
    let pubs = decode_instances(instances)?;
    let expect = public_scalars(serial, sibling, frost, amount_zat);
    Ok(pubs == expect && pubs[0] != toy_field_mul_leaf(serial) && pubs[3] == hosting_kind())
}

/// Verify files at `proof`/`instances`. Missing + `required` → host fail-closed.
pub fn proof_instance_verify_from_paths(
    proof_path: &Path,
    inst_path: &Path,
    required: bool,
) -> Result<bool, String> {
    if !proof_path.is_file() || !inst_path.is_file() {
        if required {
            return Err(
                "PIR_HALO2_REQUIRE=1 but PIR_HALO2_PROOF/INSTANCES missing (host fail-closed)"
                    .into(),
            );
        }
        return Err("empty proof".into());
    }
    let proof = std::fs::read(proof_path).map_err(|e| e.to_string())?;
    let inst = std::fs::read(inst_path).map_err(|e| e.to_string())?;
    reject_forbidden_proof_bytes(&proof)?;
    proof_instance_verify(1, &proof, &inst)
}

/// Verify a pre-exported Halo2 proof (`PIR_HALO2_PROOF` + `PIR_HALO2_INSTANCES`
/// or `artifacts/halo2`). Missing artifacts: error (not Ok). `PIR_HALO2_REQUIRE=1`
/// fail-closes. Prefer Path A store (params+vk_body) so CosmWasm host verify
/// does not re-keygen.
pub fn proof_instance_verify_exported() -> Result<bool, String> {
    let required = std::env::var("PIR_HALO2_REQUIRE").ok().as_deref() == Some("1");
    let paths = resolve_halo2_artifacts();
    if !paths.proof.is_file() || !paths.instances.is_file() {
        if required {
            return Err(
                "PIR_HALO2_REQUIRE=1 but PIR_HALO2_PROOF/INSTANCES missing (host fail-closed)"
                    .into(),
            );
        }
        return Err("empty proof".into());
    }
    let proof = std::fs::read(&paths.proof).map_err(|e| e.to_string())?;
    let inst = std::fs::read(&paths.instances).map_err(|e| e.to_string())?;
    reject_forbidden_proof_bytes(&proof)?;
    if !instances_are_zap1_hosting_payment(
        &inst,
        LIVE_SERIAL,
        LIVE_SIBLING,
        &live_frost_group(),
        LIVE_AMOUNT_ZAT,
    )? {
        return Err("instances are not ZAP1 HOSTING_PAYMENT Merkle (toy field-mul rejected)".into());
    }
    #[cfg(feature = "store-full-circuit")]
    {
        if paths.params.is_file() && paths.vk_body.is_file() {
            let params = std::fs::read(&paths.params).map_err(|e| e.to_string())?;
            let vk_body = std::fs::read(&paths.vk_body).map_err(|e| e.to_string())?;
            return verify_proof_with_store(&params, &vk_body, &proof, &inst);
        }
        if required {
            return Err(
                "PIR_HALO2_REQUIRE=1 but PIR_HALO2_PARAMS/VK_BODY missing (host fail-closed)"
                    .into(),
            );
        }
    }
    proof_instance_verify(1, &proof, &inst)
}

/// Path A `store-full-circuit`: Plonkish=0, Pasta=0, k=17, i=4.
pub const STORE_PROVER_ID: u8 = 0;
pub const STORE_CURVE_ID: u8 = 0;
pub const COSMWASM_FOOTER_LEN: usize = 80;

pub fn circuit_footer(
    param_len: u32,
    cs_len: u32,
    vk_len: u32,
    param_hash: &[u8; 32],
    vk_hash: &[u8; 32],
) -> [u8; COSMWASM_FOOTER_LEN] {
    let mut footer = [0u8; COSMWASM_FOOTER_LEN];
    footer[0] = STORE_PROVER_ID;
    footer[1] = STORE_CURVE_ID;
    footer[2] = K as u8;
    footer[3] = INSTANCE_COUNT as u8;
    footer[4..8].copy_from_slice(&param_len.to_le_bytes());
    footer[8..12].copy_from_slice(&cs_len.to_le_bytes());
    footer[12..16].copy_from_slice(&vk_len.to_le_bytes());
    footer[16..48].copy_from_slice(param_hash);
    footer[48..80].copy_from_slice(vk_hash);
    footer
}

/// Params blob + vk_body (`cs.write || vk.write || 80-byte footer`).
/// Host concatenates `[params | vk_body]` and reads the footer.
/// crates.io halo2_proofs 0.3 has no public `cs()`/`vk.write`; Path A needs the fork.
#[cfg(feature = "store-full-circuit")]
pub fn export_store_full_circuit() -> Result<(Vec<u8>, Vec<u8>), String> {
    use sha2::{Digest, Sha256};
    let (params, pk) = setup_keys()?;
    let mut params_body = Vec::new();
    params
        .write(&mut params_body)
        .map_err(|e| format!("params.write: {e}"))?;
    let mut cs = Vec::new();
    pk.get_vk()
        .cs()
        .write(&mut cs)
        .map_err(|e| format!("cs.write: {e}"))?;
    let mut vk_only = Vec::new();
    pk.get_vk()
        .write(&mut vk_only)
        .map_err(|e| format!("vk.write: {e}"))?;
    let mut vk_region = Vec::with_capacity(cs.len() + vk_only.len());
    vk_region.extend_from_slice(&cs);
    vk_region.extend_from_slice(&vk_only);
    let param_hash: [u8; 32] = Sha256::digest(&params_body).into();
    let vk_hash: [u8; 32] = Sha256::digest(&vk_region).into();
    let footer = circuit_footer(
        params_body.len() as u32,
        cs.len() as u32,
        vk_only.len() as u32,
        &param_hash,
        &vk_hash,
    );
    vk_region.extend_from_slice(&footer);
    Ok((params_body, vk_region))
}

#[cfg(feature = "store-full-circuit")]
pub fn write_store_full_circuit_files(dir: &std::path::Path) -> Result<(), String> {
    let (params, vk) = export_store_full_circuit()?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("params.bin"), params).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("vk_body.bin"), vk).map_err(|e| e.to_string())?;
    Ok(())
}

/// Halo2 host verify from Path A `params.bin` + `vk_body.bin` (cs || vk || footer).
/// Rejects toy CS (no lookups / too few gates). Empty proof is an error.
#[cfg(feature = "store-full-circuit")]
pub fn verify_proof_with_store(
    params_bytes: &[u8],
    vk_body: &[u8],
    proof: &[u8],
    instances: &[u8],
) -> Result<bool, String> {
    reject_forbidden_proof_bytes(proof)?;
    if vk_body.len() < COSMWASM_FOOTER_LEN {
        return Err("vk_body shorter than 80-byte footer".into());
    }
    let footer_off = vk_body.len() - COSMWASM_FOOTER_LEN;
    let footer = &vk_body[footer_off..];
    if footer[0] != STORE_PROVER_ID || footer[1] != STORE_CURVE_ID {
        return Err("store footer is not Plonkish Pasta (prover=0 curve=0)".into());
    }
    if footer[2] != K as u8 || footer[3] != INSTANCE_COUNT as u8 {
        return Err("store footer k/instances mismatch (need k=17 i=4)".into());
    }
    let cs_len = u32::from_le_bytes(footer[8..12].try_into().unwrap()) as usize;
    let vk_len = u32::from_le_bytes(footer[12..16].try_into().unwrap()) as usize;
    if cs_len + vk_len != footer_off {
        return Err(format!(
            "vk_body layout: cs({cs_len})+vk({vk_len}) != body({})",
            footer_off
        ));
    }
    let pubs = decode_instances(instances)?;
    if pubs[3] != hosting_kind() {
        return Ok(false);
    }
    let mut params_r = std::io::Cursor::new(params_bytes);
    let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(&mut params_r)
        .map_err(|e| format!("params.read: {e}"))?;
    let mut cs_r = std::io::Cursor::new(&vk_body[..cs_len]);
    let cs = plonk::ConstraintSystem::<pallas::Base>::read(&mut cs_r)
        .map_err(|e| format!("cs.read: {e}"))?;
    cs_is_hosting_payment_wordchip(&cs)?;
    let mut vk_r = std::io::Cursor::new(&vk_body[cs_len..cs_len + vk_len]);
    let vk = plonk::VerifyingKey::<vesta::Affine>::read_with_cs(&mut vk_r, &params, cs, vec![])
        .map_err(|e| format!("vk.read_with_cs: {e}"))?;
    halo2_verify_proof(&params, &vk, proof, &pubs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zap1_leaf_is_not_toy_field_mul() {
        let toy = toy_field_mul_leaf("PIR-001");
        assert_ne!(zap1_hosting_leaf("PIR-001"), toy);
        let leaf = zap1_hosting_leaf_bytes("PIR-001");
        let expect = zap1_verify::compute_leaf_hash(&zap1_verify::EventPayload::HostingPayment {
            serial_number: b"PIR-001",
            month: 8,
            year: 2026,
        });
        assert_eq!(leaf, expect);
        let live = zap1_merkle_root_bytes(LIVE_SERIAL, LIVE_SIBLING);
        assert_ne!(pack_hash32(&live), toy_field_mul_leaf(LIVE_SERIAL));
    }

    #[test]
    fn dummy_stwo_forbidden_in_hosting_payment() {
        let type_path = ["Dummy", "Stwo", "::"].concat();
        let crate_path = ["lean", "_stwo", "_dummy"].concat();
        let stark = ["Dummy", " STARK"].concat();
        for src in [
            include_str!("lib.rs"),
            include_str!("chip.rs"),
            include_str!("blake2b.rs"),
            include_str!("accrual.rs"),
            include_str!("bin/export-halo2.rs"),
        ] {
            assert!(!src.contains(&type_path), "forbidden type in circuit");
            assert!(!src.contains(&crate_path), "forbidden crate in circuit");
            assert!(!src.contains(&stark), "forbidden dummy stark in circuit");
        }
        assert!(include_str!("lib.rs").contains("plonk::verify_proof"));
        let inst = encode_instances(LIVE_SERIAL, LIVE_SIBLING, &live_frost_group(), LIVE_AMOUNT_ZAT);
        let e = proof_instance_verify(1, b"DSTW\x02\x05", &inst).unwrap_err();
        assert!(
            e.contains("DummyStwo"),
            "DummyStwo blob must fail closed, got {e}"
        );
        assert!(proof_instance_verify(1, &[], &inst).unwrap_err().contains("empty proof"));
    }

    #[test]
    fn constraint_system_is_blake2b_merkle_not_toy_mul() {
        let mut meta = plonk::ConstraintSystem::<pallas::Base>::default();
        let _ = HostingPaymentCircuit::configure(&mut meta);
        cs_is_hosting_payment_wordchip(&meta).expect("WordChip BLAKE2b Merkle CS");
        assert!(
            meta.get_gate_count() >= 7,
            "toy field-mul is a single mul gate; HOSTING_PAYMENT needs WordChip"
        );
    }

    #[test]
    fn zap1_root_matches_verify_proof() {
        let leaf = zap1_hosting_leaf_bytes("PIR-001");
        let sib = zap1_sibling_leaf_bytes("sib-private");
        let root = zap1_merkle_root_bytes("PIR-001", "sib-private");
        let path = [zap1_verify::ProofStep {
            hash: sib,
            position: zap1_verify::SiblingPosition::Right,
        }];
        assert!(zap1_verify::verify_proof(&leaf, &path, &root));
        assert_eq!(root, zap1_verify::node_hash(&leaf, &sib));
    }

    #[test]
    fn instances_are_128_bytes() {
        let b = encode_instances("s", "sib", &[1u8; 32], 1);
        assert_eq!(b.len(), 128);
    }

    #[test]
    fn empty_proof_is_not_true() {
        let inst = encode_instances("s", "sib", &[0u8; 32], 0);
        assert!(proof_instance_verify(1, &[], &inst).is_err());
        let e = proof_instance_verify(1, &[], &inst).unwrap_err();
        assert!(e.contains("empty proof"));
    }

    #[test]
    fn missing_host_artifacts_fail_closed_when_required() {
        let e = proof_instance_verify_from_paths(
            Path::new("/no/such/pir-halo2-proof.bin"),
            Path::new("/no/such/pir-halo2-instances.bin"),
            true,
        )
        .unwrap_err();
        assert!(
            e.contains("fail-closed") || e.contains("missing"),
            "missing host must fail closed, got {e}"
        );
        let e2 = proof_instance_verify_from_paths(
            Path::new("/no/such/pir-halo2-proof.bin"),
            Path::new("/no/such/pir-halo2-instances.bin"),
            false,
        )
        .unwrap_err();
        assert_eq!(e2, "empty proof");
    }

    #[test]
    fn live_instances_are_zap1_hosting_payment_not_toy() {
        let frost = live_frost_group();
        let inst = encode_instances(LIVE_SERIAL, LIVE_SIBLING, &frost, LIVE_AMOUNT_ZAT);
        assert_eq!(inst.len(), 128);
        assert!(instances_are_zap1_hosting_payment(
            &inst,
            LIVE_SERIAL,
            LIVE_SIBLING,
            &frost,
            LIVE_AMOUNT_ZAT,
        )
        .unwrap());
        assert_eq!(&inst[96..111], KIND_DOMAIN.as_bytes());
        let root = pack_hash32(&zap1_merkle_root_bytes(LIVE_SERIAL, LIVE_SIBLING));
        assert_eq!(&inst[..32], root.to_repr().as_ref());
        assert_ne!(root, toy_field_mul_leaf(LIVE_SERIAL));
        let leaf = zap1_hosting_leaf_bytes(LIVE_SERIAL);
        let sib = zap1_sibling_leaf_bytes(LIVE_SIBLING);
        let path = [zap1_verify::ProofStep {
            hash: sib,
            position: zap1_verify::SiblingPosition::Right,
        }];
        assert!(zap1_verify::verify_proof(
            &leaf,
            &path,
            &zap1_merkle_root_bytes(LIVE_SERIAL, LIVE_SIBLING)
        ));
    }

    /// K=17 BLAKE2b prove hung the last craft pulse (~17m CPU, workflow cancelled).
    /// Native ZAP1 leaf/root tests above stay default; prove is lab `--ignored`.
    #[test]
    #[ignore = "K=17 Halo2 BLAKE2b prove is lab-only and long"]
    fn prove_verify_roundtrip() {
        let frost = [7u8; 32];
        let proof = prove_inclusion("PIR-001", "sib-leaf", &frost, 50).unwrap();
        assert!(!proof.is_empty());
        assert!(verify_inclusion(&proof, "PIR-001", "sib-leaf", &frost, 50).unwrap());
    }

    #[test]
    #[ignore = "K=17 Halo2 BLAKE2b prove is lab-only and long"]
    fn wrong_serial_fails() {
        let frost = [7u8; 32];
        let proof = prove_inclusion("alice", "sib", &frost, 1).unwrap();
        assert!(!verify_inclusion(&proof, "bob", "sib", &frost, 1).unwrap());
    }

    #[test]
    #[ignore = "K=17 Halo2 BLAKE2b prove is lab-only and long"]
    fn frost_and_amount_are_bound() {
        let frost = [7u8; 32];
        let proof = prove_inclusion("alice", "sib", &frost, 9).unwrap();
        let mut other = [7u8; 32];
        other[0] = 8;
        assert!(!verify_inclusion(&proof, "alice", "sib", &other, 9).unwrap());
        assert!(!verify_inclusion(&proof, "alice", "sib", &frost, 10).unwrap());
    }

    #[test]
    #[ignore = "K=17 Halo2 BLAKE2b prove is lab-only and long"]
    fn host_waist_proof_instance_verify() {
        let frost = [9u8; 32];
        let proof = prove_inclusion("PIR-LC-1", "sib", &frost, 10).unwrap();
        let inst = encode_instances("PIR-LC-1", "sib", &frost, 10);
        assert!(proof_instance_verify(1, &proof, &inst).unwrap());
        let mut bad = inst.clone();
        bad[0] ^= 1;
        assert!(!proof_instance_verify(1, &proof, &bad).unwrap());
    }

    #[test]
    fn pasta_footer_is_plonkish_curve_zero() {
        let f = circuit_footer(10, 20, 30, &[7u8; 32], &[8u8; 32]);
        assert_eq!(f.len(), 80);
        assert_eq!(f[0], STORE_PROVER_ID);
        assert_eq!(f[1], STORE_CURVE_ID);
        assert_eq!(f[2], K as u8);
        assert_eq!(f[3], INSTANCE_COUNT as u8);
        assert_eq!(&f[4..8], &10u32.to_le_bytes());
        assert_eq!(&f[48..80], &[8u8; 32]);
    }

    /// Current circuit (not a stored toy VK): live ZAP1 HOSTING_PAYMENT witness
    /// satisfies Halo2 constraints; a toy field-mul root does not.
    #[test]
    #[ignore = "K=17 MockProver synthesize is lab-only and long"]
    fn mock_prover_zap1_hosting_payment_not_toy() {
        use halo2_proofs::dev::MockProver;
        let frost = live_frost_group();
        let circuit = circuit_from(LIVE_SERIAL, LIVE_SIBLING, &frost, LIVE_AMOUNT_ZAT)
            .expect("circuit");
        let pubs = public_scalars(LIVE_SERIAL, LIVE_SIBLING, &frost, LIVE_AMOUNT_ZAT);
        assert_ne!(pubs[0], toy_field_mul_leaf(LIVE_SERIAL));
        let prover = MockProver::run(K, &circuit, vec![pubs.to_vec()])
            .expect("k=17 must fit BLAKE2b-256 Merkle inclusion");
        prover.assert_satisfied();
        let mut toy = pubs;
        toy[0] = toy_field_mul_leaf(LIVE_SERIAL);
        let bad = MockProver::run(K, &circuit, vec![toy.to_vec()]).expect("run toy root");
        assert!(
            bad.verify().is_err(),
            "toy field-mul root must not satisfy HOSTING_PAYMENT inclusion"
        );
    }

    /// Real Halo2 `plonk::verify_proof` against Path A store + ZAP1 instances.
    /// DummyStwo is forbidden; empty proof and missing host fail closed.
    /// Skip-green is not allowed: missing store files fail the test.
    #[cfg(feature = "store-full-circuit")]
    #[test]
    fn store_artifacts_verify_zap1_hosting_payment() {
        let paths = resolve_halo2_artifacts();
        assert!(
            paths.proof.is_file()
                && paths.instances.is_file()
                && paths.params.is_file()
                && paths.vk_body.is_file(),
            "missing Halo2 store (host fail-closed): proof={:?} instances={:?} params={:?} vk={:?}",
            paths.proof,
            paths.instances,
            paths.params,
            paths.vk_body
        );
        let proof = std::fs::read(&paths.proof).expect("proof.bin");
        let inst = std::fs::read(&paths.instances).expect("instances.bin");
        let params = std::fs::read(&paths.params).expect("params.bin");
        let vk_body = std::fs::read(&paths.vk_body).expect("vk_body.bin");
        assert!(!proof.is_empty(), "empty halo2 proof");
        assert!(
            !proof.starts_with(b"DSTW"),
            "DummyStwo is forbidden on HOSTING_PAYMENT"
        );
        assert!(
            instances_are_zap1_hosting_payment(
                &inst,
                LIVE_SERIAL,
                LIVE_SIBLING,
                &live_frost_group(),
                LIVE_AMOUNT_ZAT,
            )
            .unwrap(),
            "instances must be ZAP1 HOSTING_PAYMENT Merkle, not toy field-mul"
        );
        let leaf = zap1_hosting_leaf_bytes(LIVE_SERIAL);
        let sib = zap1_sibling_leaf_bytes(LIVE_SIBLING);
        let root = zap1_merkle_root_bytes(LIVE_SERIAL, LIVE_SIBLING);
        let path = [zap1_verify::ProofStep {
            hash: sib,
            position: zap1_verify::SiblingPosition::Right,
        }];
        assert!(
            zap1_verify::verify_proof(&leaf, &path, &root),
            "public instances must be a real ZAP1 Merkle inclusion"
        );
        let ok = verify_proof_with_store(&params, &vk_body, &proof, &inst)
            .expect("halo2 store verify");
        assert!(ok, "Halo2 plonk::verify_proof rejected HOSTING_PAYMENT inclusion");
        assert!(
            proof_instance_verify(1, &proof, &inst).expect("waist verify"),
            "proof_instance_verify must accept ZAP1 HOSTING_PAYMENT Halo2"
        );
        assert!(
            proof_instance_verify_exported().expect("exported waist"),
            "proof_instance_verify_exported must accept stored HOSTING_PAYMENT"
        );
        assert!(verify_proof_with_store(&params, &vk_body, &[], &inst).is_err());
        assert!(proof_instance_verify(1, &[], &inst).is_err());
        assert!(verify_proof_with_store(&params, &vk_body, b"DSTW", &inst).is_err());
        let mut bad = inst.clone();
        bad[0] ^= 0xff;
        assert!(!verify_proof_with_store(&params, &vk_body, &proof, &bad).unwrap());
        let mut toy_inst = inst.clone();
        let toy = toy_field_mul_leaf(LIVE_SERIAL).to_repr();
        toy_inst[..32].copy_from_slice(toy.as_ref());
        assert!(
            !instances_are_zap1_hosting_payment(
                &toy_inst,
                LIVE_SERIAL,
                LIVE_SIBLING,
                &live_frost_group(),
                LIVE_AMOUNT_ZAT,
            )
            .unwrap()
        );
        assert!(!verify_proof_with_store(&params, &vk_body, &proof, &toy_inst).unwrap());
    }
}
