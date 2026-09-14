//! Zakura Ironwood notes for a DKG FROST group. No zcashd. No Orchard/Sapling.
//! No dummy Ok balance. Spend authority is the DKG group (ZIP-32 Ironwood SK
//! from the reconstructed group seed + frost-spend-v1 over the nullifier).
//! Honest production stand-in: ZIP-312 RedPallas FROST is not this module.

use private_inference_rent::frost_dkg::dkg_three_party;
use private_inference_rent::zcash_escrow::{
    attach_zakura, dkg_ironwood_receiver, dkg_opened_nullifier, lab_required, ShieldedNote,
    ZcashEscrow, ZcashEscrowError, IRONWOOD_SPEND_STAND_IN,
};
use private_inference_rent::ZakuraNode;

fn frost_fixture() -> private_inference_rent::frost::FrostGroup {
    dkg_three_party().expect("DKG part1–3 group owns the note")
}

#[test]
fn product_open_spend_uses_zakura_sendraw_not_zcashd() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/zcash_escrow.rs"
    ));
    assert!(
        !src.contains("local_hosting_bundle"),
        "zcash_escrow must not open notes via local_hosting_bundle"
    );
    assert!(
        !src.contains("z_sendmany")
            && !src.contains("z_shieldcoinbase")
            && !src.contains("spawn_zcashd"),
        "discontinued wallet sidecar RPCs must not appear"
    );
    assert!(
        src.contains("sendrawtransaction")
            && src.contains("add_ironwood_output")
            && src.contains("add_ironwood_spend"),
        "open is Ironwood output; spend is add_ironwood_spend of the opened note"
    );
    assert!(
        !src.contains("add_sapling_output") && !src.contains("add_orchard_output"),
        "Sapling/Orchard must not be the product shielded path"
    );
    assert!(
        src.contains("require_ironwood_only") && src.contains("ironwood_bundle"),
        "built txs must be Ironwood-only"
    );
    assert!(
        src.contains("REGTEST_MINER_DEST") || src.contains("tmLPctKo") || src.contains("miner sk"),
        "coinbase SK is the Zakura lab miner (sk=1 → tmLPctKo), optional PIR_MINER_SK override"
    );
    assert!(
        !src.contains("pub orchard_note") && src.contains("pub ironwood_note"),
        "stored note is Ironwood V3, not an Orchard field"
    );
    assert!(
        src.contains("frost-spend-v1") || src.contains("spend_message"),
        "spend authority is DKG FROST"
    );
    assert!(
        !src.contains("uterp") && !src.contains("uter p") && !src.contains("FrostThresholdPool"),
        "Zcash escrow must not treat RAM u64 / uter p as money"
    );
    assert!(
        !src.contains("DummyStwo") && !src.contains("Dummy STARK"),
        "Zcash escrow must not use DummyStwo"
    );
    assert!(
        !src.contains("let _ = note") && src.contains("spend_opened_ironwood"),
        "spend must consume the opened DKG note, not ignore it and re-shield coinbase"
    );
    assert!(
        src.contains("ironwood_sk_from_seats")
            && src.contains("from_zip32_seed")
            && src.contains("keys::reconstruct")
            && src.contains("secret.len() != 32")
            && src.contains("32-byte group scalar")
            && !src.contains("ironwood_sk_for_group")
            && !src.contains("pir-dkg-ironwood-sk-seats")
            && !src.contains("pir-dkg-ironwood-sk-reconstruct"),
        "Ironwood SK is ZIP-32 from the reconstructed 32-byte DKG group scalar, not a hash of a seat subset, the public VK, or ed25519 bytes as SAK"
    );
    assert!(
        src.contains("require_dkg_owns_opened")
            && src.contains("opened.nullifier")
            && src.contains("coin type 133"),
        "spend must prove the opened note is DKG-owned and FROST-sign its Ironwood nullifier"
    );
    assert!(
        src.contains("require_opened_nullifier")
            && src.contains("SpendFee::FromNote")
            && src.contains("frost_spend_memo"),
        "spend must prove the opened DKG nullifier and prefer shielded-only ZIP-317 from the note"
    );
    assert!(
        src.contains("zip317_from_note_too_small")
            && src.contains("cannot shield miner transparent as if FROST-owned"),
        "miner coinbase is ZIP-317 fallback only; it must not add Ironwood value"
    );
    assert!(
        src.contains("zip317_shielded_fee")
            && src.contains("extra_change")
            && !src.contains("ZIP-317 changed with DKG change output"),
        "partial DKG spend must price dest+change ZIP-317 up front, not bounce to miner"
    );
    assert!(
        src.contains("frost-spend-v1 signature missing")
            && src.contains("dest memo missing frost-spend-v1")
            && !src.contains("unwrap_or_else(|_| zcash_protocol::memo::MemoBytes::empty())"),
        "frost-spend-v1 must be fail-closed in the dest memo, not dropped"
    );
    assert!(
        src.contains("remainder note missing after earned spend"),
        "close must not clone the provider spend as a fake tenant refund"
    );
    assert!(
        src.contains("confirm_mined_dkg_open")
            && src.contains("confirm_mined_dkg_spend")
            && src.contains("recover_outputs_with_ovks")
            && src.contains("pub shielded_only"),
        "open/spend must confirm the mined Zakura tx (not the builder copy) and dest memo via OVK"
    );
    assert!(
        src.contains("mined tx missing DKG Ironwood V3 note")
            && src.contains("mined shielded-only tx has transparent inputs"),
        "chain confirmation must fail closed if the mined tx is not the DKG Ironwood spend"
    );
    assert!(
        src.contains("Honest production stand-in")
            && src.contains("ZIP-312 RedPallas FROST is not this module")
            && src.contains("Do not fake it")
            && src.contains("IRONWOOD_SPEND_STAND_IN")
            && src.contains("Spend authority is [`IRONWOOD_SPEND_STAND_IN`]")
            && src.contains("spend_stand_in: IRONWOOD_SPEND_STAND_IN")
            && src.contains("pay.spend_stand_in != IRONWOOD_SPEND_STAND_IN")
            && !src.contains("fn zip312")
            && !src.contains("RedPallasFrost"),
        "ZIP-312 RedPallas FROST is not in this Zakura; do not fake it — keep frost-spend-v1 + ZIP-32 reconstructed seed on open/close_notes"
    );
    assert!(
        src.contains("two `add_ironwood_spend` of **that** opened")
            && src.contains("First add_ironwood_spend")
            && src.contains("Second add_ironwood_spend")
            && src.contains("dkg_opened_nullifier")
            && src.contains("first add_ironwood_spend must consume THAT opened DKG note")
            && src.contains("note.spend_stand_in() != IRONWOOD_SPEND_STAND_IN"),
        "close must be two add_ironwood_spend of the opened DKG note (earned + remainder)"
    );
    assert_eq!(
        IRONWOOD_SPEND_STAND_IN,
        "frost-spend-v1+zip32-reconstructed-dkg-seed; ZIP-312 RedPallas FROST is not this module"
    );
}

#[test]
fn any_threshold_subset_owns_the_same_ironwood_receiver() {
    let g = frost_fixture();
    let seats = g.seats();
    assert_eq!(seats.len(), 3, "product DKG is 2-of-3");
    let a = dkg_ironwood_receiver(&seats[0..2], b"open").expect("seats 0,1");
    let b = dkg_ironwood_receiver(&[seats[0].clone(), seats[2].clone()], b"open")
        .expect("seats 0,2");
    let c = dkg_ironwood_receiver(&seats[1..3], b"open").expect("seats 1,2");
    assert_eq!(a, b, "any 2-of-3 subset must own the same Ironwood receiver");
    assert_eq!(b, c, "any 2-of-3 subset must own the same Ironwood receiver");
    let provider = dkg_ironwood_receiver(&seats[0..2], b"provider").unwrap();
    let tenant = dkg_ironwood_receiver(&[seats[1].clone(), seats[2].clone()], b"tenant").unwrap();
    assert_ne!(provider, tenant);
    assert_eq!(
        dkg_ironwood_receiver(&[seats[0].clone(), seats[2].clone()], b"provider").unwrap(),
        provider,
        "provider diversifier is still group-owned across subsets"
    );
    let one = dkg_ironwood_receiver(&seats[0..1], b"open");
    assert!(
        one.is_err(),
        "one seat is not threshold spend authority, got {one:?}"
    );
    let other = dkg_three_party().expect("second DKG group");
    let mixed = dkg_ironwood_receiver(&[seats[0].clone(), other.seats()[0].clone()], b"open");
    assert!(
        mixed.is_err(),
        "seats from different DKG groups cannot share an Ironwood receiver, got {mixed:?}"
    );
}

#[test]
fn skip_without_lab() {
    match attach_zakura() {
        Ok(n) => {
            let esc = ZcashEscrow::from_node(n);
            let g = frost_fixture();
            let seats = g.seats();
            let open_seats = vec![seats[0].clone(), seats[1].clone()];
            // Different 2-of-3 subset spends: the group owns the note, not a seat pair.
            let spend_seats = vec![seats[0].clone(), seats[2].clone()];
            match esc.open_note(&g, &open_seats, 200_000, "PIR-ZCASH") {
                Ok(note) => {
                    assert_eq!(note.group_id, g.verifying_key);
                    assert_eq!(
                        note.spend_stand_in(),
                        IRONWOOD_SPEND_STAND_IN,
                        "open is frost-spend-v1 + ZIP-32 reconstructed DKG seed, not ZIP-312"
                    );
                    assert!(
                        !note.ironwood_note.is_empty(),
                        "open must store the Ironwood V3 note the DKG group can spend"
                    );
                    match esc.close_notes(&g, &spend_seats, &note, 40_000) {
                        Ok((pay, refund)) => {
                            assert!(!pay.txid.is_empty());
                            assert!(!refund.txid.is_empty());
                            assert_ne!(pay.txid, refund.txid);
                            assert!(!pay.frost_sig.is_empty());
                            assert!(!refund.frost_sig.is_empty());
                            assert_eq!(pay.spend_stand_in, IRONWOOD_SPEND_STAND_IN);
                            assert_eq!(refund.spend_stand_in, IRONWOOD_SPEND_STAND_IN);
                            let opened_nf = dkg_opened_nullifier(&spend_seats, &note)
                                .expect("opened DKG note nullifier");
                            assert_eq!(
                                pay.nullifier, opened_nf,
                                "first add_ironwood_spend must consume THAT opened DKG note"
                            );
                            assert_ne!(
                                pay.nullifier, [0u8; 32],
                                "close must spend the opened DKG Ironwood note"
                            );
                            assert_ne!(pay.nullifier, refund.nullifier);
                            assert_ne!(
                                pay.dest_z_addr, refund.dest_z_addr,
                                "earned and remainder dests are distinct DKG diversifiers"
                            );
                            assert!(
                                pay.shielded_only && refund.shielded_only,
                                "close must be shielded-only DKG Ironwood spends (ZIP-317 from the notes), not miner transparent as if FROST-owned"
                            );
                            assert!(
                                pay.change.is_some(),
                                "earned spend must leave a DKG remainder note for the second add_ironwood_spend"
                            );
                            assert!(
                                refund.change.is_none(),
                                "remainder spend drains THAT leftover note to the tenant"
                            );
                        }
                        Err(e) if lab_required() => {
                            panic!(
                                "PIR_ZAKURA_LAB=1: Ironwood close (earned + remainder) must succeed with a different DKG subset, got {e}"
                            );
                        }
                        Err(ZcashEscrowError::NoteOp(msg)) => {
                            assert!(
                                msg.contains("DKG")
                                    || msg.contains("ironwood")
                                    || msg.contains("sendrawtransaction")
                                    || msg.contains("spend")
                                    || msg.contains("add_ironwood_spend")
                                    || msg.contains("reconstruct"),
                                "open funded a group note; close must spend it or fail closed, got {msg}"
                            );
                        }
                        Err(e) => panic!("unexpected close error: {e}"),
                    }
                }
                Err(e) if lab_required() => {
                    panic!("PIR_ZAKURA_LAB=1 but open_note failed (Zakura ironwood sendraw): {e}");
                }
                Err(ZcashEscrowError::NoteOp(msg)) => {
                    assert!(
                        msg.contains("sendrawtransaction")
                            || msg.contains("ironwood")
                            || msg.contains("generate")
                            || msg.contains("DKG"),
                        "fail closed on missing Zakura note path, got {msg}"
                    );
                }
                Err(e) => panic!("RPC attached but unexpected error: {e}"),
            }
        }
        Err(e) if lab_required() => {
            panic!("PIR_ZAKURA_LAB=1 but node RPC failed: {e}");
        }
        Err(_) => {}
    }
}

#[test]
fn spend_rejects_empty_note_and_foreign_group_without_rpc() {
    let esc = ZcashEscrow::from_node(ZakuraNode {
        rpc_url: "http://127.0.0.1:1".into(),
        dest_display: String::new(),
        owner_binding_hex: String::new(),
        reused_existing: false,
        container_name: None,
    });
    let g = frost_fixture();
    let seats = g.seats();
    let pair = vec![seats[0].clone(), seats[1].clone()];
    let empty = ShieldedNote {
        group_id: g.verifying_key,
        commitment: [9u8; 32],
        amount_zat: 50_000,
        tip: String::new(),
        z_addr: String::new(),
        txid: String::new(),
        ironwood_note: vec![],
    };
    assert_eq!(
        empty.spend_stand_in(),
        IRONWOOD_SPEND_STAND_IN,
        "stand-in is frost-spend-v1 + ZIP-32 reconstructed DKG seed even before a live spend"
    );
    let err = esc
        .spend_note(&g, &pair, &empty, b"provider", 1)
        .expect_err("empty Ironwood note is not a DKG spend");
    let msg = err.to_string();
    assert!(
        msg.contains("missing") || msg.contains("Ironwood note"),
        "must fail closed, not re-shield coinbase, got {msg}"
    );
    let err = dkg_opened_nullifier(&pair, &empty)
        .expect_err("empty note has no DKG Ironwood nullifier");
    assert!(
        err.to_string().contains("missing") || err.to_string().contains("Ironwood note"),
        "nullifier of an empty note must fail closed, got {err}"
    );

    let other = dkg_three_party().expect("foreign DKG");
    let foreign = ShieldedNote {
        group_id: other.verifying_key,
        commitment: [1u8; 32],
        amount_zat: 50_000,
        tip: String::new(),
        z_addr: String::new(),
        txid: String::new(),
        ironwood_note: vec![3u8; 116],
    };
    let err = esc
        .spend_note(&g, &pair, &foreign, b"provider", 1)
        .expect_err("foreign group must not spend this note");
    assert!(
        err.to_string().contains("different DKG"),
        "got {err}"
    );

    let over = ShieldedNote {
        group_id: g.verifying_key,
        commitment: [2u8; 32],
        amount_zat: 10,
        tip: String::new(),
        z_addr: String::new(),
        txid: String::new(),
        ironwood_note: vec![3u8; 116],
    };
    let err = esc
        .spend_note(&g, &pair, &over, b"provider", 11)
        .expect_err("cannot spend more than the DKG note");
    assert!(
        err.to_string().contains("exceeds"),
        "got {err}"
    );

    let foreign_seats = vec![other.seats()[0].clone(), other.seats()[1].clone()];
    let ours = ShieldedNote {
        group_id: g.verifying_key,
        commitment: [3u8; 32],
        amount_zat: 50_000,
        tip: String::new(),
        z_addr: String::new(),
        txid: String::new(),
        ironwood_note: vec![3u8; 116],
    };
    let err = esc
        .spend_note(&g, &foreign_seats, &ours, b"provider", 1)
        .expect_err("foreign DKG seats are not this note's spend authority");
    assert!(
        err.to_string().contains("spend authority") || err.to_string().contains("DKG"),
        "got {err}"
    );

    let err = esc
        .close_notes(&g, &pair, &ours, 50_001)
        .expect_err("earned cannot exceed the opened DKG note");
    assert!(
        err.to_string().contains("earned > deposit"),
        "got {err}"
    );
}
