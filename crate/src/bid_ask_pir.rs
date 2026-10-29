//! Two-proxy retrieval of sealed bid and ask rows.
//!
//! Each proxy sees a random bit-vector, not a row index. The client XORs the
//! two answers and obtains one row. This is information-theoretic if the two
//! proxies do not combine their queries. It is not YPIR. Single-server YPIR
//! (`valar-ypir`) is the later swap; the row width and fetch API stay.

pub const ROW_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row([u8; ROW_LEN]);

impl Row {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut row = [0u8; ROW_LEN];
        let n = bytes.len().min(ROW_LEN);
        row[..n].copy_from_slice(&bytes[..n]);
        Self(row)
    }

    pub fn as_bytes(&self) -> &[u8; ROW_LEN] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct BidAskDb {
    rows: Vec<Row>,
}

impl BidAskDb {
    pub fn new(rows: Vec<Row>) -> Self {
        Self { rows }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// What one proxy is allowed to see. No `index` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyQuery {
    pub bits: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyAnswer {
    pub bytes: [u8; ROW_LEN],
}

#[derive(Clone, Debug, Default)]
pub struct ProxyLog {
    pub queries: Vec<ProxyQuery>,
}

impl ProxyLog {
    /// True when no stored query is exactly the unit vector of `index`.
    pub fn hides_index(&self, index: usize, n: usize) -> bool {
        let unit = unit_bits(n, index);
        self.queries.iter().all(|q| q.bits != unit)
    }
}

fn unit_bits(n: usize, index: usize) -> Vec<u8> {
    let mut bits = vec![0u8; n];
    if index < n {
        bits[index] = 1;
    }
    bits
}

fn xor_row(acc: &mut [u8; ROW_LEN], row: &Row) {
    for (a, b) in acc.iter_mut().zip(row.0.iter()) {
        *a ^= b;
    }
}

fn answer(db: &BidAskDb, bits: &[u8]) -> ProxyAnswer {
    let mut bytes = [0u8; ROW_LEN];
    for (i, row) in db.rows.iter().enumerate() {
        if bits.get(i).copied().unwrap_or(0) == 1 {
            xor_row(&mut bytes, row);
        }
    }
    ProxyAnswer { bytes }
}

/// One untrusted proxy. It stores the database and a log of query vectors.
#[derive(Clone, Debug)]
pub struct ProviderProxy {
    db: BidAskDb,
    log: ProxyLog,
}

impl ProviderProxy {
    pub fn new(db: BidAskDb) -> Self {
        Self {
            db,
            log: ProxyLog::default(),
        }
    }

    pub fn answer(&mut self, query: ProxyQuery) -> ProxyAnswer {
        let out = answer(&self.db, &query.bits);
        self.log.queries.push(query);
        out
    }

    pub fn log(&self) -> &ProxyLog {
        &self.log
    }
}

fn xor_bits(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter()
        .zip(right.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

fn xor_answers(left: &ProxyAnswer, right: &ProxyAnswer) -> [u8; ROW_LEN] {
    let mut out = left.bytes;
    for (a, b) in out.iter_mut().zip(right.bytes.iter()) {
        *a ^= b;
    }
    out
}

/// Fetch `index` from two non-colluding copies of the same database.
pub fn fetch_row(
    left: &mut ProviderProxy,
    right: &mut ProviderProxy,
    index: usize,
    mask: &[u8],
) -> Result<[u8; ROW_LEN], &'static str> {
    let n = left.db.len();
    if n == 0 || n != right.db.len() || mask.len() != n || index >= n {
        return Err("pir shape");
    }
    let mut bits_right = mask.to_vec();
    bits_right[index] ^= 1;
    let a = left.answer(ProxyQuery {
        bits: mask.to_vec(),
    });
    let b = right.answer(ProxyQuery { bits: bits_right });
    Ok(xor_answers(&a, &b))
}

/// Mask and masked-plus-index differ by exactly one bit. Neither vector is stored as the index.
pub fn query_pair(n: usize, index: usize, mask: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    if mask.len() != n || index >= n {
        return Err("pir shape");
    }
    let mut other = mask.to_vec();
    other[index] ^= 1;
    if other == unit_bits(n, index) && mask == unit_bits(n, index) {
        return Err("pir mask");
    }
    let _ = xor_bits(mask, &other);
    Ok((mask.to_vec(), other))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_proxies_return_the_row_and_hide_the_index() {
        let rows = vec![
            Row::from_bytes(b"ask-row-0"),
            Row::from_bytes(b"sealed-bid-1"),
            Row::from_bytes(b"ask-row-2"),
        ];
        let mut left = ProviderProxy::new(BidAskDb::new(rows.clone()));
        let mut right = ProviderProxy::new(BidAskDb::new(rows.clone()));
        let mask = vec![1u8, 0, 1];
        let got = fetch_row(&mut left, &mut right, 1, &mask).unwrap();
        assert_eq!(got, *rows[1].as_bytes());
        assert!(left.log().hides_index(1, 3));
        assert!(right.log().hides_index(1, 3));
        let (q_left, q_right) = query_pair(3, 1, &mask).unwrap();
        assert_ne!(q_left, unit_bits(3, 1));
        assert_ne!(q_right, unit_bits(3, 1));
        let mut solo = ProviderProxy::new(BidAskDb::new(rows.clone()));
        let alone = solo.answer(ProxyQuery { bits: q_left });
        assert_ne!(
            alone.bytes, *rows[1].as_bytes(),
            "one proxy answer is not the row; two-proxy XOR is not YPIR"
        );
    }
}
