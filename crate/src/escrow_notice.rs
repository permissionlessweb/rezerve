//! Resolver notice: websocket is delivery; event attest is the bind; grant authorizes.
//! This is **not** vote extensions and **not** a running 08-wasm client.

use crate::escrow::{CloseGrant, EscrowCell, EscrowParty, GrantView, ResolverShareError};
use crate::tagged_hash;
use crate::zap1_lc::{require_close_event_lc, CloseEventLcRequest, Zap1LcError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseEventAttrs {
    pub action: CloseAction,
    pub cell_id: [u8; 32],
    pub closer: EscrowParty,
    pub earned_zat: u64,
    pub remainder_zat: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseAction {
    Close,
    Dispute,
}

impl CloseEventAttrs {
    /// CosmWasm `Close` / `Dispute` attributes delivered over WS or TxSearch.
    /// Parsing is delivery; LC + grant still authorize the share.
    pub fn from_wasm_attributes<'a, I>(attrs: I) -> Result<Self, ResolverNoticeError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut action = None;
        let mut cell_hex = None;
        let mut closer = None;
        let mut earned = None;
        let mut remainder = None;
        let mut settle = None;
        let mut accrual = None;
        let mut open_h = None;
        let mut close_h = None;
        for (k, v) in attrs {
            match k {
                "action" => action = Some(v),
                "cell_id" => cell_hex = Some(v),
                "closer" => closer = Some(v),
                "earned_zat" => earned = Some(v),
                "remainder_zat" => remainder = Some(v),
                "settle" => settle = Some(v),
                "accrual_commitment" => {
                    accrual = Some(parse_hex32(v).ok_or(ResolverNoticeError::AttestFailed)?);
                }
                "open_header_hash" => {
                    open_h = Some(parse_hex32(v).ok_or(ResolverNoticeError::AttestFailed)?);
                }
                "close_header_hash" => {
                    close_h = Some(parse_hex32(v).ok_or(ResolverNoticeError::AttestFailed)?);
                }
                _ => {}
            }
        }
        // cw-pir-escrow emits grant hashes on Close. If any are present, all
        // must be 32-byte hex and the headers must differ. Not stored on attrs
        // (LC bind stays header/tx/action/cell/closer/split).
        if accrual.is_some() || open_h.is_some() || close_h.is_some() {
            let acc = accrual.ok_or(ResolverNoticeError::AttestFailed)?;
            let open = open_h.ok_or(ResolverNoticeError::AttestFailed)?;
            let close = close_h.ok_or(ResolverNoticeError::AttestFailed)?;
            if acc == [0u8; 32] || open == close {
                return Err(ResolverNoticeError::AttestFailed);
            }
        }
        // cw-pir-escrow Close/Dispute is grant-only. Public earned is 0 (GrantView).
        if settle != Some("grant_only") {
            return Err(ResolverNoticeError::AttestFailed);
        }
        let action = match action.unwrap_or("") {
            "close" => CloseAction::Close,
            "dispute" => CloseAction::Dispute,
            _ => return Err(ResolverNoticeError::AttestFailed),
        };
        let closer = match closer.unwrap_or("") {
            "tenant" => EscrowParty::Tenant,
            "provider" => EscrowParty::Provider,
            _ => return Err(ResolverNoticeError::AttestFailed),
        };
        let cell_id = parse_hex32(cell_hex.unwrap_or("")).ok_or(ResolverNoticeError::AttestFailed)?;
        let earned_zat = match earned {
            None | Some("") => 0,
            Some(s) => s
                .parse()
                .map_err(|_| ResolverNoticeError::AttestFailed)?,
        };
        if earned_zat != 0 {
            return Err(ResolverNoticeError::AttestFailed);
        }
        let remainder_zat = remainder
            .ok_or(ResolverNoticeError::AttestFailed)?
            .parse()
            .map_err(|_| ResolverNoticeError::AttestFailed)?;
        if remainder_zat == 0 {
            return Err(ResolverNoticeError::AttestFailed);
        }
        Ok(Self {
            action,
            cell_id,
            closer,
            earned_zat,
            remainder_zat,
        })
    }

    /// CometBFT WS / TxSearch / `query tx` JSON. Delivery only — not LC proof.
    pub fn from_comet_json(json: &str) -> Result<Self, ResolverNoticeError> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|_| ResolverNoticeError::AttestFailed)?;
        let mut groups = Vec::new();
        collect_wasm_attr_groups(&v, &mut groups);
        collect_flattened_wasm_groups(&v, &mut groups);
        let mut last_err = ResolverNoticeError::AttestFailed;
        for g in groups {
            match Self::from_wasm_attributes(g.iter().map(|(k, val)| (k.as_str(), val.as_str()))) {
                Ok(attrs) => return Ok(attrs),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    /// Header + tx hashes in WS / `query tx` JSON. Both must be present and
    /// differ. Tx-only CometBFT WS uses [`ResolverNotice::from_ws_json`].
    pub fn hashes_from_comet_json(json: &str) -> Result<([u8; 32], [u8; 32]), ResolverNoticeError> {
        let (header, tx) = delivery_hashes_from_comet_json(json)?;
        match (header, tx) {
            (Some(h), Some(t)) if h != t => Ok((h, t)),
            _ => Err(ResolverNoticeError::AttestFailed),
        }
    }
}

fn collect_wasm_attr_groups(v: &serde_json::Value, out: &mut Vec<Vec<(String, String)>>) {
    match v {
        serde_json::Value::Array(a) => {
            for x in a {
                collect_wasm_attr_groups(x, out);
            }
        }
        serde_json::Value::Object(m) => {
            let ty = m.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if ty == "wasm" || ty.starts_with("wasm-") {
                if let Some(attrs) = m.get("attributes").and_then(|a| a.as_array()) {
                    let mut g = Vec::new();
                    for a in attrs {
                        let k = a.get("key").and_then(|x| x.as_str()).unwrap_or("");
                        let val = a.get("value").and_then(|x| x.as_str()).unwrap_or("");
                        if k.is_empty() {
                            continue;
                        }
                        let (k, val) = normalize_wasm_attr(k, val);
                        if !k.is_empty() {
                            g.push((k, val));
                        }
                    }
                    if !g.is_empty() {
                        out.push(g);
                    }
                }
            }
            for val in m.values() {
                collect_wasm_attr_groups(val, out);
            }
        }
        _ => {}
    }
}

fn wasm_flat_key(k: &str) -> Option<&str> {
    if let Some(rest) = k.strip_prefix("wasm.") {
        return Some(rest);
    }
    if let Some(rest) = k.strip_prefix("wasm-") {
        if let Some((_, attr)) = rest.split_once('.') {
            return Some(attr);
        }
    }
    None
}

fn value_strings(v: &serde_json::Value) -> Vec<&str> {
    match v {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect(),
        _ => Vec::new(),
    }
}

/// CometBFT WS flattened `events` (`wasm.action` / `wasm-close.action` arrays).
fn collect_flattened_wasm_groups(v: &serde_json::Value, out: &mut Vec<Vec<(String, String)>>) {
    match v {
        serde_json::Value::Array(a) => {
            for x in a {
                collect_flattened_wasm_groups(x, out);
            }
        }
        serde_json::Value::Object(m) => {
            let mut g = Vec::new();
            for (k, val) in m {
                if let Some(attr) = wasm_flat_key(k) {
                    for s in value_strings(val) {
                        g.push((attr.to_string(), s.to_string()));
                    }
                }
            }
            if !g.is_empty() {
                out.push(g);
            }
            for val in m.values() {
                collect_flattened_wasm_groups(val, out);
            }
        }
        _ => {}
    }
}

#[derive(Clone, Copy)]
enum DeliveryHashKind {
    Header,
    Tx,
}

fn classify_delivery_hash(parent: Option<&str>, key: &str) -> Option<DeliveryHashKind> {
    match key {
        "header_hash" | "header.hash" => Some(DeliveryHashKind::Header),
        "txhash" | "tx_hash" | "tx.hash" => Some(DeliveryHashKind::Tx),
        "hash" => match parent {
            Some("header") | Some("block_id") => Some(DeliveryHashKind::Header),
            Some("attributes") | Some("last_block_id") => None,
            _ => Some(DeliveryHashKind::Tx),
        },
        _ => None,
    }
}

fn delivery_hashes_from_comet_json(
    json: &str,
) -> Result<(Option<[u8; 32]>, Option<[u8; 32]>), ResolverNoticeError> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|_| ResolverNoticeError::AttestFailed)?;
    let mut header = None;
    let mut tx = None;
    collect_delivery_hashes(&v, &mut header, &mut tx, None);
    Ok((header, tx))
}

fn take_hash_value(kind: DeliveryHashKind, key: &str, s: &str, header: &mut Option<[u8; 32]>, tx: &mut Option<[u8; 32]>) {
    let Some(h) = parse_hex32(s) else {
        return;
    };
    match kind {
        DeliveryHashKind::Header => *header = Some(h),
        DeliveryHashKind::Tx => {
            if key == "txhash" || key == "tx_hash" || key == "tx.hash" || tx.is_none() {
                *tx = Some(h);
            }
        }
    }
}

fn collect_delivery_hashes(
    v: &serde_json::Value,
    header: &mut Option<[u8; 32]>,
    tx: &mut Option<[u8; 32]>,
    parent: Option<&str>,
) {
    match v {
        serde_json::Value::Array(a) => {
            for x in a {
                collect_delivery_hashes(x, header, tx, parent);
            }
        }
        serde_json::Value::Object(m) => {
            if let (Some(k), Some(val)) = (
                m.get("key").and_then(|x| x.as_str()),
                m.get("value"),
            ) {
                if let Some(kind) = classify_delivery_hash(parent, k) {
                    for s in value_strings(val) {
                        take_hash_value(kind, k, s, header, tx);
                    }
                }
            }
            for (k, val) in m {
                if let Some(kind) = classify_delivery_hash(parent, k.as_str()) {
                    for s in value_strings(val) {
                        take_hash_value(kind, k.as_str(), s, header, tx);
                    }
                }
                collect_delivery_hashes(val, header, tx, Some(k.as_str()));
            }
        }
        _ => {}
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let t = s.trim().trim_start_matches("0x");
    let raw = hex::decode(t).ok()?;
    raw.try_into().ok()
}

const WASM_CLOSE_KEYS: &[&str] = &[
    "action",
    "cell_id",
    "closer",
    "earned_zat",
    "remainder_zat",
    "settle",
    "accrual_commitment",
    "open_header_hash",
    "close_header_hash",
    "_contract_address",
];

/// CometBFT ABCI often base64-encodes wasm attribute keys/values. Decode only
/// when the key is a known Close attr after decode (hex cell ids are not keys).
fn normalize_wasm_attr(k: &str, v: &str) -> (String, String) {
    if WASM_CLOSE_KEYS.contains(&k) {
        return (k.to_string(), v.to_string());
    }
    if let Some(dk) = b64_ascii(k) {
        if WASM_CLOSE_KEYS.iter().any(|n| *n == dk) {
            let dv = b64_ascii(v).unwrap_or_else(|| v.to_string());
            return (dk, dv);
        }
    }
    (k.to_string(), v.to_string())
}

fn b64_ascii(s: &str) -> Option<String> {
    let raw = std_base64_decode(s)?;
    let t = std::str::from_utf8(&raw).ok()?;
    if t.is_empty() || !t.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    Some(t.to_string())
}

fn std_base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut s = s.trim().to_string();
    if s.is_empty() {
        return None;
    }
    while s.len() % 4 != 0 {
        s.push('=');
    }
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut i = 0;
    while i < b.len() {
        let pad2 = b[i + 2] == b'=';
        let pad3 = b[i + 3] == b'=';
        if pad2 && !pad3 {
            return None;
        }
        let a = val(b[i])?;
        let c = val(b[i + 1])?;
        let d = if pad2 { 0 } else { val(b[i + 2])? };
        let e = if pad3 { 0 } else { val(b[i + 3])? };
        out.push((a << 2) | (c >> 4));
        if !pad2 {
            out.push((c << 4) | (d >> 2));
        }
        if !pad3 {
            out.push((d << 6) | e);
        }
        i += 4;
    }
    Some(out)
}

fn action_str(action: CloseAction) -> &'static str {
    match action {
        CloseAction::Close => "close",
        CloseAction::Dispute => "dispute",
    }
}

fn closer_str(closer: EscrowParty) -> &'static str {
    match closer {
        EscrowParty::Tenant => "tenant",
        EscrowParty::Provider => "provider",
    }
}

/// Local bind of header + tx + close attributes. Same honesty class as
/// `IbcV2PacketAttest` until `require_close_event_lc` (live-ict fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseEventAttest {
    pub header_hash: [u8; 32],
    pub tx_hash: [u8; 32],
    pub app_data_hash: [u8; 32],
}

impl CloseEventAttest {
    pub fn bind(header_hash: [u8; 32], tx_hash: [u8; 32], attrs: &CloseEventAttrs) -> Self {
        Self {
            header_hash,
            tx_hash,
            app_data_hash: event_app_hash(header_hash, tx_hash, attrs),
        }
    }

    pub fn verify(&self, header_hash: [u8; 32], tx_hash: [u8; 32], attrs: &CloseEventAttrs) -> bool {
        *self == Self::bind(header_hash, tx_hash, attrs)
    }
}

fn event_app_hash(header: [u8; 32], tx: [u8; 32], attrs: &CloseEventAttrs) -> [u8; 32] {
    tagged_hash(
        b"escrow-close-event-v1",
        &[
            &header,
            &tx,
            action_str(attrs.action).as_bytes(),
            &attrs.cell_id,
            closer_str(attrs.closer).as_bytes(),
            &attrs.earned_zat.to_le_bytes(),
            &attrs.remainder_zat.to_le_bytes(),
            b"grant_only",
        ],
    )
}

/// How the resolver heard about close. `delivered_over_ws` is **not** proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverNotice {
    pub delivered_over_ws: bool,
    pub attest: Option<CloseEventAttest>,
}

impl ResolverNotice {
    /// Websocket delivery of a close event. Delivery is ignored as proof.
    pub fn from_ws(attest: CloseEventAttest) -> Self {
        Self {
            delivered_over_ws: true,
            attest: Some(attest),
        }
    }

    pub fn ws_only() -> Self {
        Self {
            delivered_over_ws: true,
            attest: None,
        }
    }

    /// CometBFT WS / TxSearch JSON is delivery. Tx hash must be in the payload
    /// and match. Real `tm.event='Tx'` WS has `tx.hash`, not `header.hash`; the
    /// caller header is LC input. Missing tx hash is not LC. Attest bind is
    /// still not LC; `require_close_event_lc` authorizes Close attrs.
    pub fn from_ws_json(
        json: &str,
        header_hash: [u8; 32],
        tx_hash: [u8; 32],
    ) -> Result<(Self, CloseEventAttrs), ResolverNoticeError> {
        let attrs = CloseEventAttrs::from_comet_json(json)?;
        let (h, t) = delivery_hashes_from_comet_json(json)?;
        match (h, t) {
            (Some(h), Some(t)) => {
                if h != header_hash || t != tx_hash {
                    return Err(ResolverNoticeError::AttestFailed);
                }
            }
            (None, Some(t)) => {
                if t != tx_hash || header_hash == tx_hash {
                    return Err(ResolverNoticeError::AttestFailed);
                }
            }
            _ => return Err(ResolverNoticeError::AttestFailed),
        }
        Ok((
            Self::from_ws(CloseEventAttest::bind(header_hash, tx_hash, &attrs)),
            attrs,
        ))
    }
}

/// CosmWasm `QueryMsg::Grant` JSON. Same public surface as [`GrantView`].
/// LCD `{ "data": "<base64 JSON>" }` and `{ "data": { ... } }` both parse.
pub fn grant_view_from_query_json(json: &str) -> Result<GrantView, ResolverNoticeError> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|_| ResolverNoticeError::AttestFailed)?;
    let node = grant_query_node(v)?;
    let view: GrantView =
        serde_json::from_value(node).map_err(|_| ResolverNoticeError::AttestFailed)?;
    if !view.recorded || view.earned_zat != 0 || view.remainder_zat == 0 {
        return Err(ResolverNoticeError::AttestFailed);
    }
    parse_hex32(&view.cell_id).ok_or(ResolverNoticeError::AttestFailed)?;
    let hashed = !view.accrual_commitment.is_empty()
        || !view.open_header_hash.is_empty()
        || !view.close_header_hash.is_empty();
    if hashed {
        let acc = parse_hex32(&view.accrual_commitment).ok_or(ResolverNoticeError::AttestFailed)?;
        let open = parse_hex32(&view.open_header_hash).ok_or(ResolverNoticeError::AttestFailed)?;
        let close = parse_hex32(&view.close_header_hash).ok_or(ResolverNoticeError::AttestFailed)?;
        if acc == [0u8; 32] || open == close {
            return Err(ResolverNoticeError::AttestFailed);
        }
    }
    Ok(view)
}

fn grant_query_node(v: serde_json::Value) -> Result<serde_json::Value, ResolverNoticeError> {
    if v.get("recorded").is_some() && v.get("cell_id").is_some() {
        return Ok(v);
    }
    let Some(data) = v.get("data") else {
        return Ok(v);
    };
    if let Some(s) = data.as_str() {
        let parsed = json_from_maybe_encoded(s).ok_or(ResolverNoticeError::AttestFailed)?;
        return grant_query_node(parsed);
    }
    grant_query_node(data.clone())
}

fn json_from_maybe_encoded(s: &str) -> Option<serde_json::Value> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
        return Some(v);
    }
    let raw = std_base64_decode(t)?;
    serde_json::from_slice(&raw).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverNoticeError {
    WsOnlyUnverified,
    AttestFailed,
    Grant(ResolverShareError),
    Lc(Zap1LcError),
}

/// Resolver may use their share only after a verifying attest **and** a grant.
/// A websocket delivery without attest is rejected.
pub fn resolver_may_sign_from_notice(
    cell: &EscrowCell,
    member_id: &str,
    notice: &ResolverNotice,
    header_hash: [u8; 32],
    tx_hash: [u8; 32],
    attrs: &CloseEventAttrs,
) -> Result<(), ResolverNoticeError> {
    let Some(attest) = notice.attest.as_ref() else {
        return Err(ResolverNoticeError::WsOnlyUnverified);
    };
    if !attest.verify(header_hash, tx_hash, attrs) {
        return Err(ResolverNoticeError::AttestFailed);
    }
    if attrs.cell_id != cell.cell_id {
        return Err(ResolverNoticeError::AttestFailed);
    }
    let grant: &CloseGrant = cell.grant.as_ref().ok_or(ResolverNoticeError::Grant(
        ResolverShareError::NoGrant,
    ))?;
    let view = grant.view();
    // Event carries GrantView (earned=0, remainder=deposit), not the private split.
    if attrs.earned_zat != view.earned_zat || attrs.remainder_zat != view.remainder_zat {
        return Err(ResolverNoticeError::AttestFailed);
    }
    if attrs.closer != grant.closer {
        return Err(ResolverNoticeError::Grant(ResolverShareError::GrantMismatch));
    }
    require_close_event_lc(
        &CloseEventLcRequest::bind(
            header_hash,
            tx_hash,
            attest.app_data_hash,
            action_str(attrs.action),
            attrs.cell_id,
            closer_str(attrs.closer),
            attrs.earned_zat,
            attrs.remainder_zat,
        )
        .with_grant_public(
            &view.accrual_commitment,
            &view.open_header_hash,
            &view.close_header_hash,
        ),
    )
    .map_err(ResolverNoticeError::Lc)?;
    cell.resolver_may_sign(member_id)
        .map_err(ResolverNoticeError::Grant)
}

/// Resolver DKG share identity. Not a dealer `KeyPackage`; the DKG track owns rounds.
/// This crate only records which share may be used after grant + event attest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverDkgShare {
    pub member_id: String,
    /// Commitment to the party's DKG share (`part3` output identity), not dealer secret bytes.
    pub share_commitment: [u8; 32],
}

impl ResolverDkgShare {
    /// Bind to DKG `part3` seat encoding (`identifier_hex:package_hex`).
    /// Same shape as `PIR_FROST_SEAT` / stdin — not argv, not dealer `KeyPackage`.
    pub fn from_part3_identity(
        member_id: impl Into<String>,
        part3_bytes: &[u8],
    ) -> Result<Self, ResolverNoticeError> {
        let member_id = member_id.into();
        if member_id.is_empty() || part3_bytes.is_empty() {
            return Err(ResolverNoticeError::AttestFailed);
        }
        let s = std::str::from_utf8(part3_bytes).map_err(|_| ResolverNoticeError::AttestFailed)?;
        let (id_hex, pkg_hex) = s
            .split_once(':')
            .ok_or(ResolverNoticeError::AttestFailed)?;
        let id = hex::decode(id_hex.trim()).map_err(|_| ResolverNoticeError::AttestFailed)?;
        let pkg = hex::decode(pkg_hex.trim()).map_err(|_| ResolverNoticeError::AttestFailed)?;
        if id.is_empty() || pkg.is_empty() || pkg.iter().all(|b| *b == 0) {
            return Err(ResolverNoticeError::AttestFailed);
        }
        Ok(Self {
            member_id,
            share_commitment: tagged_hash(b"escrow-resolver-dkg-part3-v1", &[&id, &pkg]),
        })
    }
}

/// Grant-gated authorization to contribute the resolver DKG share.
/// WS delivery is ignored; attest + recorded grant are required. No vote extensions.
pub fn resolver_dkg_share_from_notice(
    cell: &EscrowCell,
    share: &ResolverDkgShare,
    notice: &ResolverNotice,
    header_hash: [u8; 32],
    tx_hash: [u8; 32],
    attrs: &CloseEventAttrs,
) -> Result<[u8; 32], ResolverNoticeError> {
    if share.member_id.is_empty() || share.share_commitment == [0u8; 32] {
        return Err(ResolverNoticeError::AttestFailed);
    }
    resolver_may_sign_from_notice(cell, &share.member_id, notice, header_hash, tx_hash, attrs)?;
    let grant = cell.grant.as_ref().ok_or(ResolverNoticeError::Grant(
        ResolverShareError::NoGrant,
    ))?;
    let attest = notice.attest.as_ref().ok_or(ResolverNoticeError::WsOnlyUnverified)?;
    Ok(tagged_hash(
        b"escrow-resolver-dkg-share-v1",
        &[
            &cell.cell_id,
            share.member_id.as_bytes(),
            &share.share_commitment,
            &header_hash,
            &tx_hash,
            &attest.app_data_hash,
            closer_str(grant.closer).as_bytes(),
            &grant.earned_zat.to_le_bytes(),
            &grant.remainder_zat.to_le_bytes(),
            grant.accrual_commitment.as_bytes(),
            grant.open_header_hash.as_bytes(),
            grant.close_header_hash.as_bytes(),
        ],
    ))
}

/// WS / TxSearch JSON is how the resolver notices Close. LC + grant authorize the DKG share.
/// Vote extensions are not a notice path.
pub fn resolver_dkg_share_from_ws_delivery(
    cell: &EscrowCell,
    share: &ResolverDkgShare,
    ws_json: &str,
    header_hash: [u8; 32],
    tx_hash: [u8; 32],
) -> Result<[u8; 32], ResolverNoticeError> {
    let (notice, attrs) = ResolverNotice::from_ws_json(ws_json, header_hash, tx_hash)?;
    if !notice.delivered_over_ws {
        return Err(ResolverNoticeError::WsOnlyUnverified);
    }
    ws_close_matches_cell_grant(cell, ws_json)?;
    resolver_dkg_share_from_notice(cell, share, &notice, header_hash, tx_hash, &attrs)
}

fn grant_query_matches_cell(
    cell: &EscrowCell,
    grant_json: &str,
) -> Result<(), ResolverNoticeError> {
    let view = grant_view_from_query_json(grant_json)?;
    let grant = cell.grant.as_ref().ok_or(ResolverNoticeError::Grant(
        ResolverShareError::NoGrant,
    ))?;
    if view != grant.view() {
        return Err(ResolverNoticeError::Grant(ResolverShareError::GrantMismatch));
    }
    Ok(())
}

fn grant_hashes_from_ws_json(
    json: &str,
) -> Result<(Option<[u8; 32]>, Option<[u8; 32]>, Option<[u8; 32]>), ResolverNoticeError> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|_| ResolverNoticeError::AttestFailed)?;
    let mut groups = Vec::new();
    collect_wasm_attr_groups(&v, &mut groups);
    collect_flattened_wasm_groups(&v, &mut groups);
    let mut acc = None;
    let mut open = None;
    let mut close = None;
    for g in &groups {
        for (k, val) in g {
            match k.as_str() {
                "accrual_commitment" => acc = parse_hex32(val),
                "open_header_hash" => open = parse_hex32(val),
                "close_header_hash" => close = parse_hex32(val),
                _ => {}
            }
        }
    }
    Ok((acc, open, close))
}

fn ws_close_matches_cell_grant(
    cell: &EscrowCell,
    ws_json: &str,
) -> Result<(), ResolverNoticeError> {
    let view = cell
        .grant
        .as_ref()
        .ok_or(ResolverNoticeError::Grant(ResolverShareError::NoGrant))?
        .view();
    if view.accrual_commitment.is_empty()
        && view.open_header_hash.is_empty()
        && view.close_header_hash.is_empty()
    {
        return Ok(());
    }
    let (acc, open, close) = grant_hashes_from_ws_json(ws_json)?;
    let acc_ok = acc == parse_hex32(&view.accrual_commitment);
    let open_ok = open == parse_hex32(&view.open_header_hash);
    let close_ok = close == parse_hex32(&view.close_header_hash);
    if acc_ok && open_ok && close_ok && open != close {
        Ok(())
    } else {
        Err(ResolverNoticeError::AttestFailed)
    }
}

fn grant_query_matches_ws_close(
    cell: &EscrowCell,
    grant_json: &str,
    ws_json: &str,
) -> Result<(), ResolverNoticeError> {
    grant_query_matches_cell(cell, grant_json)?;
    ws_close_matches_cell_grant(cell, ws_json)
}

/// Slice 4 product path: WS/TxSearch delivery + `QueryMsg::Grant` + LC-verified Close attrs.
/// Grant query bytes are authorization; WS is not proof. No vote extensions.
pub fn resolver_dkg_share_from_ws_delivery_with_grant_query(
    cell: &EscrowCell,
    share: &ResolverDkgShare,
    ws_json: &str,
    grant_json: &str,
    header_hash: [u8; 32],
    tx_hash: [u8; 32],
) -> Result<[u8; 32], ResolverNoticeError> {
    grant_query_matches_ws_close(cell, grant_json, ws_json)?;
    resolver_dkg_share_from_ws_delivery(cell, share, ws_json, header_hash, tx_hash)
}
