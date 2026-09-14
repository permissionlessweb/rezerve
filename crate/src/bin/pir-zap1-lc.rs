//! Helper: ZAP1 Merkle + IBC v2 via `cw-ics08-wasm-zap1`, and LC-class Close bind.
//! Not Crosslink 08-wasm store. Prints one JSON line `{ "accepted": true, "matches": true }`
//! or `{ "accepted": false, "matches": false, "rejected": true }`.

use private_inference_rent::escrow::EscrowParty;
use private_inference_rent::escrow_notice::{CloseAction, CloseEventAttest, CloseEventAttrs};

fn parse32_hex(s: &str) -> Option<[u8; 32]> {
    let t = s.trim().trim_start_matches("0x");
    let raw = hex::decode(t).ok()?;
    raw.try_into().ok()
}

fn reject(error: &str) -> ! {
    println!(
        r#"{{"accepted":false,"matches":false,"rejected":true,"error":{}}}"#,
        serde_json::to_string(error).unwrap_or_else(|_| "\"err\"".into())
    );
    std::process::exit(1);
}

fn accept() {
    println!(r#"{{"accepted":true,"matches":true}}"#);
}

/// Re-bind Close attrs (same as `CloseEventAttest`). Missing/wrong fields reject.
fn attest_close() {
    let body = std::env::var("PIR_ZAP1_CLOSE_JSON").unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let Some(header) = v
        .get("header_hash_hex")
        .and_then(|x| x.as_str())
        .and_then(parse32_hex)
    else {
        reject("bad header_hash_hex");
    };
    let Some(tx) = v
        .get("tx_hash_hex")
        .and_then(|x| x.as_str())
        .and_then(parse32_hex)
    else {
        reject("bad tx_hash_hex");
    };
    let Some(app) = v
        .get("app_data_hash_hex")
        .and_then(|x| x.as_str())
        .and_then(parse32_hex)
    else {
        reject("bad app_data_hash_hex");
    };
    let Some(cell_id) = v
        .get("cell_id_hex")
        .and_then(|x| x.as_str())
        .and_then(parse32_hex)
    else {
        reject("bad cell_id_hex");
    };
    let action = match v.get("action").and_then(|x| x.as_str()).unwrap_or("") {
        "close" => CloseAction::Close,
        "dispute" => CloseAction::Dispute,
        other => reject(&format!("unknown close action {other}")),
    };
    let closer = match v.get("closer").and_then(|x| x.as_str()).unwrap_or("") {
        "tenant" => EscrowParty::Tenant,
        "provider" => EscrowParty::Provider,
        other => reject(&format!("unknown closer {other}")),
    };
    let earned_zat = v.get("earned_zat").and_then(|x| x.as_u64()).unwrap_or(0);
    let remainder_zat = v.get("remainder_zat").and_then(|x| x.as_u64()).unwrap_or(0);
    if earned_zat == 0 && remainder_zat == 0 {
        reject("close earned+remainder both zero");
    }
    let attrs = CloseEventAttrs {
        action,
        cell_id,
        closer,
        earned_zat,
        remainder_zat,
    };
    let attest = CloseEventAttest::bind(header, tx, &attrs);
    if attest.app_data_hash == app && attest.verify(header, tx, &attrs) {
        accept();
    } else {
        reject("close app_data_hash does not bind header/tx/attrs");
    }
}

fn attest_packet() {
    let body = std::env::var("PIR_ZAP1_ATTEST_JSON").unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let source = v.get("source_client").and_then(|x| x.as_str()).unwrap_or("");
    let dest = v.get("dest_client").and_then(|x| x.as_str()).unwrap_or("");
    let sequence = v.get("sequence").and_then(|x| x.as_u64()).unwrap_or(0);
    let timeout = v
        .get("timeout_timestamp_ns")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let app_hex = v
        .get("app_data_hash_hex")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let ibc = cw_ics08_wasm_zap1::IbcV2Fields {
        source_client: source.into(),
        dest_client: dest.into(),
        sequence,
        timeout_timestamp_ns: timeout,
        app_data_hash_hex: app_hex.into(),
    };
    let kind = v.get("event_kind").and_then(|x| x.as_str()).unwrap_or("");
    let wallet = v
        .get("wallet_or_serial")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let parse32 = |k: &str| -> Option<[u8; 32]> {
        v.get(k).and_then(|x| x.as_str()).and_then(parse32_hex)
    };
    let note = parse32("note_hex").unwrap_or([0u8; 32]);
    let frost = parse32("frost_group_hex").unwrap_or([0u8; 32]);
    let leaf = parse32("leaf_hex").unwrap_or([0u8; 32]);
    let root = parse32("merkle_root_hex").unwrap_or([0u8; 32]);
    let amount = v.get("amount_zat").and_then(|x| x.as_u64()).unwrap_or(0);
    let mut steps = Vec::new();
    if let Some(arr) = v.get("proof").and_then(|x| x.as_array()) {
        for p in arr {
            let sib = if let Some(s) = p.get("sibling_hex").and_then(|x| x.as_str()) {
                parse32_hex(s)
            } else if let Some(arr) = p.get("sibling").and_then(|x| x.as_array()) {
                let mut out = [0u8; 32];
                if arr.len() == 32 {
                    for (i, el) in arr.iter().enumerate() {
                        out[i] = el.as_u64().unwrap_or(0) as u8;
                    }
                    Some(out)
                } else {
                    None
                }
            } else {
                None
            };
            let left = p
                .get("sibling_is_left")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            if let Some(s) = sib {
                steps.push((s, left));
            }
        }
    }
    match cw_ics08_wasm_zap1::verify_zap1_ibcv2(
        &ibc, kind, wallet, &note, amount, &frost, &leaf, &root, &steps,
    ) {
        Ok(_) => accept(),
        Err(e) => reject(&e),
    }
}

fn main() {
    let close = std::env::args().any(|a| a == "--attest-close");
    if close {
        attest_close();
    } else {
        attest_packet();
    }
}
