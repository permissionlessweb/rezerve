//! Open/spend Ironwood notes via zcash_escrow (add_ironwood_output / add_ironwood_spend)
//! then submitrawtransaction to ZAKURA_RPC. No wallet getnewaddress.

use private_inference_rent::frost::{FrostGroup, FrostSeat};
use private_inference_rent::frost_dkg::dkg_three_party;
use private_inference_rent::zcash_escrow::{ShieldedNote, ZcashEscrow};
use serde_json::json;
use std::path::PathBuf;

fn state_path() -> PathBuf {
    std::env::var("SVG_MINT_IRONWOOD_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/svg-mint-ironwood-state.json"))
}

fn load_or_dkg() -> Result<(FrostGroup, Vec<FrostSeat>, Option<ShieldedNote>), String> {
    let p = state_path();
    if p.is_file() {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let seats: Vec<FrostSeat> = v["seats"]
            .as_array()
            .ok_or("seats")?
            .iter()
            .map(|s| FrostSeat::decode(s.as_str().unwrap_or("")))
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        let pk_hex = v["pubkeys_hex"].as_str().ok_or("pubkeys")?;
        let pk_b = hex::decode(pk_hex).map_err(|e| e.to_string())?;
        let pubkeys = frost_ed25519::keys::PublicKeyPackage::deserialize(&pk_b)
            .map_err(|e| e.to_string())?;
        let min = v["min_signers"].as_u64().unwrap_or(2) as u16;
        let max = v["max_signers"].as_u64().unwrap_or(3) as u16;
        let pkgs: Vec<_> = seats
            .iter()
            .map(|s| {
                let enc = s.encode().expect("seat");
                let (id_hex, pkg_hex) = enc.split_once(':').unwrap();
                let id_b = hex::decode(id_hex).unwrap();
                let pkg_b = hex::decode(pkg_hex).unwrap();
                (
                    frost_ed25519::Identifier::deserialize(&id_b).unwrap(),
                    frost_ed25519::keys::KeyPackage::deserialize(&pkg_b).unwrap(),
                )
            })
            .collect();
        let g = FrostGroup::from_key_packages(min, max, pkgs, pubkeys).map_err(|e| e.to_string())?;
        let note = v.get("note").and_then(|n| {
            if n.is_null() {
                None
            } else {
                Some(ShieldedNote {
                    group_id: serde_json::from_value(n["group_id"].clone()).ok()?,
                    commitment: serde_json::from_value(n["commitment"].clone()).ok()?,
                    amount_zat: n["amount_zat"].as_u64()?,
                    tip: n["tip"].as_str()?.into(),
                    z_addr: n["z_addr"].as_str()?.into(),
                    txid: n["txid"].as_str()?.into(),
                    ironwood_note: serde_json::from_value(n["ironwood_note"].clone()).ok()?,
                })
            }
        });
        return Ok((g.clone(), g.seats(), note));
    }
    let g = dkg_three_party().map_err(|e| e.to_string())?;
    Ok((g.clone(), g.seats(), None))
}

fn save(g: &FrostGroup, seats: &[FrostSeat], note: Option<&ShieldedNote>) -> Result<(), String> {
    let seats_enc: Vec<String> = seats
        .iter()
        .map(|s| s.encode().map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let pk = g
        .public_keys()
        .serialize()
        .map_err(|e| e.to_string())?;
    let note_v = note.map(|n| {
        json!({
            "group_id": n.group_id,
            "commitment": n.commitment,
            "amount_zat": n.amount_zat,
            "tip": n.tip,
            "z_addr": n.z_addr,
            "txid": n.txid,
            "ironwood_note": n.ironwood_note,
        })
    });
    let v = json!({
        "min_signers": g.min_signers,
        "max_signers": g.max_signers,
        "seats": seats_enc,
        "pubkeys_hex": hex::encode(pk),
        "note": note_v,
    });
    std::fs::write(state_path(), v.to_string()).map_err(|e| e.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("open");
    if let Err(e) = run(cmd) {
        println!("{}", json!({"ok": false, "error": e}));
        std::process::exit(2);
    }
}

fn run(cmd: &str) -> Result<(), String> {
    let esc = ZcashEscrow::connect().map_err(|e| e.to_string())?;
    let (g, seats, note) = load_or_dkg()?;
    let open_seats = vec![seats[0].clone(), seats[1].clone()];
    match cmd {
        "ua" | "ivk" => {
            let (ua, ivk) =
                private_inference_rent::zcash_escrow::dkg_shared_ua_ivk(&open_seats, b"open")
                    .map_err(|e| e.to_string())?;
            save(&g, &seats, note.as_ref())?;
            println!(
                "{}",
                json!({"ok": true, "ua": ua, "ivk": ivk, "tag": "open"})
            );
        }
        "scan" => {
            let from: u64 = std::env::var("SVG_MINT_SCAN_FROM")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let hits = esc
                .scan_incoming(&open_seats, b"open", from)
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({
                    "ok": true,
                    "notes": hits.iter().map(|(t,a)| json!({"txid": t, "amount_zat": a})).collect::<Vec<_>>(),
                    "identified_by": "ivk",
                })
            );
        }
        "open" => {
            let amt: u64 = std::env::var("SVG_MINT_IRONWOOD_ZAT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50_000);
            let n = esc
                .open_note(&g, &open_seats, amt, "SVG-MINT")
                .map_err(|e| e.to_string())?;
            save(&g, &seats, Some(&n))?;
            println!(
                "{}",
                json!({"ok": true, "txid": n.txid, "z_addr": n.z_addr, "amount_zat": n.amount_zat})
            );
        }
        "spend" | "refund" => {
            let n = note.ok_or("no opened note")?;
            let spend_seats = vec![seats[0].clone(), seats[2].clone()];
            let amt = n.amount_zat / 2;
            let r = esc
                .spend_note(&g, &spend_seats, &n, b"svg-mint-refund", amt)
                .map_err(|e| e.to_string())?;
            save(&g, &seats, r.change.as_deref())?;
            println!(
                "{}",
                json!({"ok": true, "txid": r.txid, "shielded_only": r.shielded_only})
            );
        }
        _ => return Err(format!("unknown {cmd}")),
    }
    Ok(())
}
