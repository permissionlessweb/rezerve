//! RFC 7693 BLAKE2b-256 matching zap1-verify personalization.
//!
//! Leaf:  `NordicShield_` (13 bytes, zero-padded to 16)
//! Node:  `NordicShield_MRK` (16 bytes) over `left || right`

pub const HASH_LEN: usize = 32;
pub const BLOCK_LEN: usize = 128;
pub const LEAF_PERSONAL: &[u8; 13] = b"NordicShield_";
pub const NODE_PERSONAL: &[u8; 16] = b"NordicShield_MRK";
pub const EVENT_HOSTING_PAYMENT: u8 = 0x05;
pub const EVENT_PROGRAM_ENTRY: u8 = 0x01;

pub const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// BLAKE2b message permutation (RFC 7693). Round 10–11 repeat 0–1.
pub const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

pub const G_IDX: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

#[inline]
pub fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

pub fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_LEN], t: u64, last: bool) {
    let mut m = [0u64; 16];
    for i in 0..16 {
        m[i] = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t;
    if last {
        v[14] ^= u64::MAX;
    }
    for r in 0..12 {
        let s = &SIGMA[r];
        for (g_i, idx) in G_IDX.iter().enumerate() {
            g(
                &mut v,
                idx[0],
                idx[1],
                idx[2],
                idx[3],
                m[s[g_i * 2]],
                m[s[g_i * 2 + 1]],
            );
        }
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Sequential BLAKE2b-256 with a personalization string (zero-padded to 16).
pub fn blake2b_256(data: &[u8], personal: &[u8]) -> [u8; HASH_LEN] {
    let mut h = IV;
    // param block word 0: digest_len | key_len<<8 | fanout<<16 | depth<<24
    h[0] ^= 0x0101_0020;
    let mut pers = [0u8; 16];
    let n = core::cmp::min(personal.len(), 16);
    pers[..n].copy_from_slice(&personal[..n]);
    h[6] ^= u64::from_le_bytes(pers[0..8].try_into().unwrap());
    h[7] ^= u64::from_le_bytes(pers[8..16].try_into().unwrap());

    let mut t = 0u64;
    let mut off = 0;
    while off + BLOCK_LEN <= data.len() {
        t += BLOCK_LEN as u64;
        let mut block = [0u8; BLOCK_LEN];
        block.copy_from_slice(&data[off..off + BLOCK_LEN]);
        compress(&mut h, &block, t, false);
        off += BLOCK_LEN;
    }
    let mut block = [0u8; BLOCK_LEN];
    let rest = data.len() - off;
    block[..rest].copy_from_slice(&data[off..]);
    t += rest as u64;
    compress(&mut h, &block, t, true);

    let mut out = [0u8; HASH_LEN];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

pub fn leaf_hash(preimage: &[u8]) -> [u8; HASH_LEN] {
    blake2b_256(preimage, LEAF_PERSONAL)
}

pub fn node_hash(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left);
    data[32..].copy_from_slice(right);
    blake2b_256(&data, NODE_PERSONAL)
}

/// `0x05 || u16_be(len) || serial || month_be || year_be`
pub fn hosting_payment_preimage(serial: &[u8], month: u32, year: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 2 + serial.len() + 8);
    buf.push(EVENT_HOSTING_PAYMENT);
    buf.extend_from_slice(&(serial.len() as u16).to_be_bytes());
    buf.extend_from_slice(serial);
    buf.extend_from_slice(&month.to_be_bytes());
    buf.extend_from_slice(&year.to_be_bytes());
    buf
}

pub fn hosting_payment_leaf(serial: &[u8], month: u32, year: u32) -> [u8; HASH_LEN] {
    leaf_hash(&hosting_payment_preimage(serial, month, year))
}

/// `0x01 || wallet` (no length prefix), same as zap1-verify ProgramEntry.
pub fn program_entry_leaf(wallet: &[u8]) -> [u8; HASH_LEN] {
    let mut buf = Vec::with_capacity(1 + wallet.len());
    buf.push(EVENT_PROGRAM_ENTRY);
    buf.extend_from_slice(wallet);
    leaf_hash(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_01_program_entry() {
        let h = program_entry_leaf(b"wallet_abc");
        assert_eq!(
            hex(&h),
            "344a05bf81faf6e2d54a0e52ea0267aff0244998eb1ee27adf5627413e92f089"
        );
    }

    #[test]
    fn vec_05_hosting_payment() {
        let h = hosting_payment_leaf(b"Z15P-2026-001", 7, 2026);
        assert_eq!(
            hex(&h),
            "6fe67554ae4108215a05d2e6f0e24c15fd7d5846ebd653618eff498f1be41a4f"
        );
    }

    #[test]
    fn matches_zap1_verify_hosting_and_node() {
        let serial = b"PIR-001";
        let leaf = hosting_payment_leaf(serial, 8, 2026);
        let expect = zap1_verify::compute_leaf_hash(&zap1_verify::EventPayload::HostingPayment {
            serial_number: serial,
            month: 8,
            year: 2026,
        });
        assert_eq!(leaf, expect);
        let sib = program_entry_leaf(b"sib-private");
        let sib_expect = zap1_verify::compute_leaf_hash(&zap1_verify::EventPayload::ProgramEntry {
            wallet_hash: b"sib-private",
        });
        assert_eq!(sib, sib_expect);
        let root = node_hash(&leaf, &sib);
        assert_eq!(root, zap1_verify::node_hash(&leaf, &sib));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
