//! 64-bit ALU + one-block BLAKE2b-256 for pasta / halo2_proofs 0.3.
//!
//! Words are 16 range-checked nibbles. XOR is a 4-bit lookup. ROTR 32/24/16
//! permute nibbles; ROTR 63 splits to bits.

use crate::blake2b::{BLOCK_LEN, G_IDX, IV, SIGMA};
use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector, TableColumn,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

const NIBBLES: usize = 16;

#[derive(Clone, Debug)]
pub struct WordConfig {
    pub advice: [Column<Advice>; 5],
    pub instance: Column<Instance>,
    pub constant: Column<Fixed>,
    pub s_bool: Selector,
    pub s_add: Selector,
    pub s_fadd: Selector,
    pub s_compose: Selector,
    pub s_range: Selector,
    pub s_xor: Selector,
    pub s_mul: Selector,
    pub s_byte: Selector,
    pub s_nibble4: Selector,
    pub range_table: TableColumn,
    pub xor_a: TableColumn,
    pub xor_b: TableColumn,
    pub xor_c: TableColumn,
}

#[derive(Clone)]
pub struct Word64<F: PrimeField> {
    pub value: AssignedCell<F, F>,
    pub nibbles: [AssignedCell<F, F>; NIBBLES],
    pub raw: Value<u64>,
}

pub struct WordChip<F: PrimeField> {
    config: WordConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Chip<F> for WordChip<F> {
    type Config = WordConfig;
    type Loaded = ();
    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: PrimeField> WordChip<F> {
    pub fn construct(config: WordConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 5],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> WordConfig {
        meta.enable_equality(instance);
        meta.enable_constant(constant);
        for c in &advice {
            meta.enable_equality(*c);
        }
        let s_bool = meta.selector();
        meta.create_gate("bool", |meta| {
            let b = meta.query_advice(advice[0], Rotation::cur());
            let s = meta.query_selector(s_bool);
            vec![s * b.clone() * (b - Expression::Constant(F::ONE))]
        });
        let s_add = meta.selector();
        meta.create_gate("add64", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let carry = meta.query_advice(advice[3], Rotation::cur());
            let s = meta.query_selector(s_add);
            let two64 = Expression::Constant(two_pow_64::<F>());
            vec![s * (a + b - out - carry * two64)]
        });
        let s_fadd = meta.selector();
        meta.create_gate("fadd", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let s = meta.query_selector(s_fadd);
            vec![s * (a + b - out)]
        });
        let s_compose = meta.selector();
        meta.create_gate("compose_nibble", |meta| {
            let prev = meta.query_advice(advice[1], Rotation::cur());
            let nib = meta.query_advice(advice[0], Rotation::cur());
            let acc = meta.query_advice(advice[1], Rotation::next());
            let pow = meta.query_advice(advice[4], Rotation::cur());
            let s = meta.query_selector(s_compose);
            vec![s * (prev + nib * pow - acc)]
        });
        let s_mul = meta.selector();
        meta.create_gate("mul", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let s = meta.query_selector(s_mul);
            vec![s * (lhs * rhs - out)]
        });
        let s_byte = meta.selector();
        meta.create_gate("byte", |meta| {
            let lo = meta.query_advice(advice[0], Rotation::cur());
            let hi = meta.query_advice(advice[1], Rotation::cur());
            let byte = meta.query_advice(advice[2], Rotation::cur());
            let s = meta.query_selector(s_byte);
            vec![s * (byte - lo - hi * Expression::Constant(F::from(16u64)))]
        });
        let s_nibble4 = meta.selector();
        meta.create_gate("nibble4", |meta| {
            let b0 = meta.query_advice(advice[0], Rotation::cur());
            let b1 = meta.query_advice(advice[1], Rotation::cur());
            let nib = meta.query_advice(advice[2], Rotation::cur());
            let b2 = meta.query_advice(advice[3], Rotation::cur());
            let b3 = meta.query_advice(advice[4], Rotation::cur());
            let s = meta.query_selector(s_nibble4);
            vec![s * (nib
                - b0
                - b1 * Expression::Constant(F::from(2u64))
                - b2 * Expression::Constant(F::from(4u64))
                - b3 * Expression::Constant(F::from(8u64)))]
        });
        let s_range = meta.complex_selector();
        let range_table = meta.lookup_table_column();
        meta.lookup(|meta| {
            let s = meta.query_selector(s_range);
            let n = meta.query_advice(advice[0], Rotation::cur());
            vec![(s * n, range_table)]
        });
        let s_xor = meta.complex_selector();
        let xor_a = meta.lookup_table_column();
        let xor_b = meta.lookup_table_column();
        let xor_c = meta.lookup_table_column();
        meta.lookup(|meta| {
            let s = meta.query_selector(s_xor);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![
                (s.clone() * a, xor_a),
                (s.clone() * b, xor_b),
                (s * c, xor_c),
            ]
        });
        WordConfig {
            advice,
            instance,
            constant,
            s_bool,
            s_add,
            s_fadd,
            s_compose,
            s_range,
            s_xor,
            s_mul,
            s_byte,
            s_nibble4,
            range_table,
            xor_a,
            xor_b,
            xor_c,
        }
    }

    pub fn load_tables(&self, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "range 0..15",
            |mut table| {
                for i in 0..16u64 {
                    table.assign_cell(
                        || "r",
                        self.config.range_table,
                        i as usize,
                        || Value::known(F::from(i)),
                    )?;
                }
                Ok(())
            },
        )?;
        layouter.assign_table(
            || "xor nibbles",
            |mut table| {
                let mut off = 0;
                for a in 0..16u64 {
                    for b in 0..16u64 {
                        table.assign_cell(
                            || "a",
                            self.config.xor_a,
                            off,
                            || Value::known(F::from(a)),
                        )?;
                        table.assign_cell(
                            || "b",
                            self.config.xor_b,
                            off,
                            || Value::known(F::from(b)),
                        )?;
                        table.assign_cell(
                            || "c",
                            self.config.xor_c,
                            off,
                            || Value::known(F::from(a ^ b)),
                        )?;
                        off += 1;
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn assign_word(
        &self,
        mut layouter: impl Layouter<F>,
        raw: Value<u64>,
    ) -> Result<Word64<F>, Error> {
        layouter.assign_region(
            || "word",
            |mut region| {
                let mut nibbles: Vec<AssignedCell<F, F>> = Vec::with_capacity(NIBBLES);
                region.assign_advice_from_constant(
                    || "acc0",
                    self.config.advice[1],
                    0,
                    F::ZERO,
                )?;
                let mut acc_val = Value::known(F::ZERO);
                let mut last_acc = None;
                for i in 0..NIBBLES {
                    self.config.s_range.enable(&mut region, i)?;
                    self.config.s_compose.enable(&mut region, i)?;
                    let nib_v = raw.map(|w| F::from((w >> (4 * i)) & 0xf));
                    let nib = region.assign_advice(|| "nib", self.config.advice[0], i, || nib_v)?;
                    let pow = F::from(1u64 << (4 * i));
                    region.assign_advice_from_constant(|| "pow", self.config.advice[4], i, pow)?;
                    acc_val = acc_val.zip(nib_v).map(|(p, n)| p + n * pow);
                    last_acc = Some(region.assign_advice(
                        || "acc",
                        self.config.advice[1],
                        i + 1,
                        || acc_val,
                    )?);
                    nibbles.push(nib);
                }
                let value = region.assign_advice(|| "val", self.config.advice[2], 0, || raw.map(F::from))?;
                region.constrain_equal(value.cell(), last_acc.unwrap().cell())?;
                Ok(Word64 {
                    value,
                    nibbles: nibbles.try_into().ok().unwrap(),
                    raw,
                })
            },
        )
    }

    pub fn constant_u64(&self, layouter: impl Layouter<F>, c: u64) -> Result<Word64<F>, Error> {
        self.assign_word(layouter, Value::known(c))
    }

    pub fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: &Word64<F>,
        b: &Word64<F>,
    ) -> Result<Word64<F>, Error> {
        let raw = a.raw.zip(b.raw).map(|(x, y)| x.wrapping_add(y));
        let out = self.assign_word(layouter.namespace(|| "sum word"), raw)?;
        layouter.assign_region(
            || "add64",
            |mut region| {
                self.config.s_add.enable(&mut region, 0)?;
                a.value
                    .copy_advice(|| "a", &mut region, self.config.advice[0], 0)?;
                b.value
                    .copy_advice(|| "b", &mut region, self.config.advice[1], 0)?;
                out.value
                    .copy_advice(|| "out", &mut region, self.config.advice[2], 0)?;
                let carry_bit = a.raw.zip(b.raw).map(|(x, y)| {
                    if x.overflowing_add(y).1 {
                        F::ONE
                    } else {
                        F::ZERO
                    }
                });
                let carry =
                    region.assign_advice(|| "carry", self.config.advice[3], 0, || carry_bit)?;
                self.config.s_bool.enable(&mut region, 1)?;
                carry.copy_advice(|| "cbit", &mut region, self.config.advice[0], 1)?;
                Ok(())
            },
        )?;
        Ok(out)
    }

    pub fn xor(
        &self,
        mut layouter: impl Layouter<F>,
        a: &Word64<F>,
        b: &Word64<F>,
    ) -> Result<Word64<F>, Error> {
        let raw = a.raw.zip(b.raw).map(|(x, y)| x ^ y);
        let out = self.assign_word(layouter.namespace(|| "xor word"), raw)?;
        layouter.assign_region(
            || "xor nibbles",
            |mut region| {
                for i in 0..NIBBLES {
                    self.config.s_xor.enable(&mut region, i)?;
                    a.nibbles[i].copy_advice(|| "a", &mut region, self.config.advice[0], i)?;
                    b.nibbles[i].copy_advice(|| "b", &mut region, self.config.advice[1], i)?;
                    out.nibbles[i].copy_advice(|| "c", &mut region, self.config.advice[2], i)?;
                }
                Ok(())
            },
        )?;
        Ok(out)
    }

    pub fn rotr(
        &self,
        mut layouter: impl Layouter<F>,
        a: &Word64<F>,
        n: u32,
    ) -> Result<Word64<F>, Error> {
        let raw = a.raw.map(|w| w.rotate_right(n));
        if n % 4 == 0 {
            let shift = (n / 4) as usize;
            let out = self.assign_word(layouter.namespace(|| "rotr nibble"), raw)?;
            layouter.assign_region(
                || "rotr eq",
                |mut region| {
                    for i in 0..NIBBLES {
                        let src = (i + shift) % NIBBLES;
                        region.constrain_equal(out.nibbles[i].cell(), a.nibbles[src].cell())?;
                    }
                    Ok(())
                },
            )?;
            return Ok(out);
        }
        debug_assert_eq!(n, 63);
        let bits = self.split_bits(layouter.namespace(|| "bits"), a)?;
        // LSB-first: new[i] = old[(i+n) % 64] matches u64::rotate_right.
        let rotated: Vec<_> = (0..64)
            .map(|i| bits[(i + n as usize) % 64].clone())
            .collect();
        self.pack_bits(layouter.namespace(|| "rotr63"), &rotated, raw)
    }

    fn split_bits(
        &self,
        mut layouter: impl Layouter<F>,
        a: &Word64<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        layouter.assign_region(
            || "split bits",
            |mut region| {
                let mut bits = Vec::with_capacity(64);
                for i in 0..64 {
                    self.config.s_bool.enable(&mut region, i)?;
                    let bv = a.raw.map(|w| F::from((w >> i) & 1));
                    bits.push(region.assign_advice(|| "bit", self.config.advice[0], i, || bv)?);
                }
                for ni in 0..NIBBLES {
                    let row = 64 + ni;
                    self.config.s_nibble4.enable(&mut region, row)?;
                    bits[ni * 4].copy_advice(|| "b0", &mut region, self.config.advice[0], row)?;
                    bits[ni * 4 + 1].copy_advice(|| "b1", &mut region, self.config.advice[1], row)?;
                    a.nibbles[ni].copy_advice(|| "n", &mut region, self.config.advice[2], row)?;
                    bits[ni * 4 + 2].copy_advice(|| "b2", &mut region, self.config.advice[3], row)?;
                    bits[ni * 4 + 3].copy_advice(|| "b3", &mut region, self.config.advice[4], row)?;
                }
                Ok(bits)
            },
        )
    }

    fn pack_bits(
        &self,
        mut layouter: impl Layouter<F>,
        bits: &[AssignedCell<F, F>],
        raw: Value<u64>,
    ) -> Result<Word64<F>, Error> {
        let out = self.assign_word(layouter.namespace(|| "pack"), raw)?;
        layouter.assign_region(
            || "pack bits",
            |mut region| {
                for ni in 0..NIBBLES {
                    self.config.s_nibble4.enable(&mut region, ni)?;
                    bits[ni * 4].copy_advice(|| "b0", &mut region, self.config.advice[0], ni)?;
                    bits[ni * 4 + 1].copy_advice(|| "b1", &mut region, self.config.advice[1], ni)?;
                    out.nibbles[ni].copy_advice(|| "n", &mut region, self.config.advice[2], ni)?;
                    bits[ni * 4 + 2].copy_advice(|| "b2", &mut region, self.config.advice[3], ni)?;
                    bits[ni * 4 + 3].copy_advice(|| "b3", &mut region, self.config.advice[4], ni)?;
                }
                Ok(())
            },
        )?;
        Ok(out)
    }

    pub fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "mul",
            |mut region| {
                self.config.s_mul.enable(&mut region, 0)?;
                a.copy_advice(|| "l", &mut region, self.config.advice[0], 0)?;
                b.copy_advice(|| "r", &mut region, self.config.advice[1], 0)?;
                let v = a.value().copied() * b.value();
                region.assign_advice(|| "p", self.config.advice[2], 0, || v)
            },
        )
    }

    pub fn fadd(
        &self,
        mut layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "fadd",
            |mut region| {
                self.config.s_fadd.enable(&mut region, 0)?;
                a.copy_advice(|| "a", &mut region, self.config.advice[0], 0)?;
                b.copy_advice(|| "b", &mut region, self.config.advice[1], 0)?;
                let sum = a.value().copied() + b.value();
                region.assign_advice(|| "s", self.config.advice[2], 0, || sum)
            },
        )
    }

    pub fn assign_field(
        &self,
        mut layouter: impl Layouter<F>,
        v: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "f",
            |mut region| region.assign_advice(|| "v", self.config.advice[0], 0, || v),
        )
    }

    /// Range-checked byte (two nibbles + byte gate).
    pub fn assign_u8(
        &self,
        mut layouter: impl Layouter<F>,
        v: Value<u8>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "u8",
            |mut region| {
                self.config.s_byte.enable(&mut region, 0)?;
                self.config.s_range.enable(&mut region, 0)?;
                self.config.s_range.enable(&mut region, 1)?;
                let lo = v.map(|x| F::from((x & 0xf) as u64));
                let hi = v.map(|x| F::from(((x >> 4) & 0xf) as u64));
                let byte_v = v.map(|x| F::from(x as u64));
                region.assign_advice(|| "lo", self.config.advice[0], 0, || lo)?;
                let hi_cell =
                    region.assign_advice(|| "hi", self.config.advice[1], 0, || hi)?;
                let byte =
                    region.assign_advice(|| "byte", self.config.advice[2], 0, || byte_v)?;
                hi_cell.copy_advice(|| "hi-range", &mut region, self.config.advice[0], 1)?;
                Ok(byte)
            },
        )
    }

    pub fn assign_bit(
        &self,
        mut layouter: impl Layouter<F>,
        v: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "bit",
            |mut region| {
                self.config.s_bool.enable(&mut region, 0)?;
                region.assign_advice(|| "b", self.config.advice[0], 0, || v)
            },
        )
    }

    pub fn constrain_equal(
        &self,
        mut layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        layouter.assign_region(|| "eq", |mut region| region.constrain_equal(a.cell(), b.cell()))
    }

    pub fn load_public(
        &self,
        mut layouter: impl Layouter<F>,
        row: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "pub",
            |mut region| {
                region.assign_advice_from_instance(
                    || "p",
                    self.config.instance,
                    row,
                    self.config.advice[0],
                    0,
                )
            },
        )
    }

    pub fn load_constant_field(
        &self,
        mut layouter: impl Layouter<F>,
        c: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "const f",
            |mut region| region.assign_advice_from_constant(|| "c", self.config.advice[0], 0, c),
        )
    }

    pub fn bytes_to_words(
        &self,
        mut layouter: impl Layouter<F>,
        bytes: &[AssignedCell<F, F>],
        block: &[Value<u8>; BLOCK_LEN],
    ) -> Result<[Word64<F>; 16], Error> {
        assert_eq!(bytes.len(), BLOCK_LEN);
        let mut out = Vec::with_capacity(16);
        for i in 0..16 {
            let mut raw = Value::known(0u64);
            for b in 0..8 {
                raw = raw
                    .zip(block[i * 8 + b])
                    .map(|(w, byte)| w | ((byte as u64) << (8 * b)));
            }
            let w = self.assign_word(layouter.namespace(|| format!("m{i}")), raw)?;
            layouter.assign_region(
                || format!("m{i} bytes"),
                |mut region| {
                    for b in 0..8 {
                        self.config.s_byte.enable(&mut region, b)?;
                        w.nibbles[b * 2].copy_advice(
                            || "lo",
                            &mut region,
                            self.config.advice[0],
                            b,
                        )?;
                        w.nibbles[b * 2 + 1].copy_advice(
                            || "hi",
                            &mut region,
                            self.config.advice[1],
                            b,
                        )?;
                        bytes[i * 8 + b].copy_advice(
                            || "byte",
                            &mut region,
                            self.config.advice[2],
                            b,
                        )?;
                    }
                    Ok(())
                },
            )?;
            out.push(w);
        }
        Ok(out.try_into().ok().unwrap())
    }

    pub fn digest_bytes(
        &self,
        mut layouter: impl Layouter<F>,
        h: &[Word64<F>; 4],
    ) -> Result<[AssignedCell<F, F>; 32], Error> {
        let mut bytes = Vec::with_capacity(32);
        for i in 0..4 {
            let part = layouter.assign_region(
                || format!("digest{i}"),
                |mut region| {
                    let mut local = Vec::with_capacity(8);
                    for b in 0..8 {
                        self.config.s_byte.enable(&mut region, b)?;
                        h[i].nibbles[b * 2].copy_advice(
                            || "lo",
                            &mut region,
                            self.config.advice[0],
                            b,
                        )?;
                        h[i].nibbles[b * 2 + 1].copy_advice(
                            || "hi",
                            &mut region,
                            self.config.advice[1],
                            b,
                        )?;
                        let v = h[i].raw.map(|w| F::from(w.to_le_bytes()[b] as u64));
                        local.push(region.assign_advice(
                            || "byte",
                            self.config.advice[2],
                            b,
                            || v,
                        )?);
                    }
                    Ok(local)
                },
            )?;
            bytes.extend(part);
        }
        Ok(bytes.try_into().ok().unwrap())
    }

    fn g(
        &self,
        mut layouter: impl Layouter<F>,
        v: &mut [Word64<F>; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        x: &Word64<F>,
        y: &Word64<F>,
    ) -> Result<(), Error> {
        let t = self.add(layouter.namespace(|| "a+b"), &v[a], &v[b])?;
        v[a] = self.add(layouter.namespace(|| "a+x"), &t, x)?;
        let dx = self.xor(layouter.namespace(|| "d^a"), &v[d], &v[a])?;
        v[d] = self.rotr(layouter.namespace(|| "rotr32"), &dx, 32)?;
        v[c] = self.add(layouter.namespace(|| "c+d"), &v[c], &v[d])?;
        let bx = self.xor(layouter.namespace(|| "b^c"), &v[b], &v[c])?;
        v[b] = self.rotr(layouter.namespace(|| "rotr24"), &bx, 24)?;
        let t = self.add(layouter.namespace(|| "a+b2"), &v[a], &v[b])?;
        v[a] = self.add(layouter.namespace(|| "a+y"), &t, y)?;
        let dx = self.xor(layouter.namespace(|| "d^a2"), &v[d], &v[a])?;
        v[d] = self.rotr(layouter.namespace(|| "rotr16"), &dx, 16)?;
        v[c] = self.add(layouter.namespace(|| "c+d2"), &v[c], &v[d])?;
        let bx = self.xor(layouter.namespace(|| "b^c2"), &v[b], &v[c])?;
        v[b] = self.rotr(layouter.namespace(|| "rotr63"), &bx, 63)?;
        Ok(())
    }

    pub fn compress(
        &self,
        mut layouter: impl Layouter<F>,
        h: &mut [Word64<F>; 8],
        m: &[Word64<F>; 16],
        t: &Word64<F>,
        last: bool,
    ) -> Result<(), Error> {
        let mut v: [Word64<F>; 16] = core::array::from_fn(|_| h[0].clone());
        for i in 0..8 {
            v[i] = h[i].clone();
            v[i + 8] = self.constant_u64(layouter.namespace(|| format!("iv{i}")), IV[i])?;
        }
        v[12] = self.xor(layouter.namespace(|| "v12^t"), &v[12], t)?;
        if last {
            let f = self.constant_u64(layouter.namespace(|| "f"), u64::MAX)?;
            v[14] = self.xor(layouter.namespace(|| "v14^f"), &v[14], &f)?;
        }
        for r in 0..12 {
            let s = &SIGMA[r];
            for (g_i, idx) in G_IDX.iter().enumerate() {
                self.g(
                    layouter.namespace(|| format!("r{r}g{g_i}")),
                    &mut v,
                    idx[0],
                    idx[1],
                    idx[2],
                    idx[3],
                    &m[s[g_i * 2]],
                    &m[s[g_i * 2 + 1]],
                )?;
            }
        }
        for i in 0..8 {
            let t = self.xor(layouter.namespace(|| format!("h^v{i}")), &h[i], &v[i])?;
            h[i] = self.xor(layouter.namespace(|| format!("h^v8{i}")), &t, &v[i + 8])?;
        }
        Ok(())
    }

    pub fn blake2b_one_block(
        &self,
        mut layouter: impl Layouter<F>,
        block_words: &[Word64<F>; 16],
        t: &Word64<F>,
        personal_lo: u64,
        personal_hi: u64,
    ) -> Result<[Word64<F>; 4], Error> {
        let mut init = IV;
        init[0] ^= 0x0101_0020;
        init[6] ^= personal_lo;
        init[7] ^= personal_hi;
        let mut h: [Word64<F>; 8] = core::array::from_fn(|_| block_words[0].clone());
        for i in 0..8 {
            h[i] = self.constant_u64(layouter.namespace(|| format!("h{i}")), init[i])?;
        }
        self.compress(
            layouter.namespace(|| "compress"),
            &mut h,
            block_words,
            t,
            true,
        )?;
        Ok([h[0].clone(), h[1].clone(), h[2].clone(), h[3].clone()])
    }
}

fn two_pow_64<F: PrimeField>() -> F {
    F::from(1u64 << 32) * F::from(1u64 << 32)
}
