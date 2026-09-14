//! Accrual is f(open_height, close_height, rate). Public output is a commitment.

use private_inference_rent::accrual::{
    accrue_from_getblockheader_json, accrue_from_headers, accrue_from_headers_halo2,
    accrue_from_zakura, accrue_from_zakura_halo2, chain_header_from_getblockheader,
    chain_header_from_verbose, commit_accrual, commit_and_prove_accrual, duration_heights,
    earned_zat, f, getbestblockhash, getblockcount, getblockheader_at, getblockheader_json,
    header_at, open_at_tip, product_grant_json, prove_accrual_halo2, verify_accrual_halo2,
    verify_product_accrual, verify_witness, AccrualError, AccrualRate, ChainHeader, HeightWindow,
};
use private_inference_rent::tagged_hash;
use private_inference_rent::zakura::lab_spawn;
use serde_json::json;

fn pack_fe32(bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = *bytes;
    out[31] &= 0x3f;
    out
}

fn verbose_header(height: u64, hash: [u8; 32], unix_time: i64) -> serde_json::Value {
    json!({
        "hash": hex::encode(hash),
        "confirmations": 3,
        "height": height,
        "version": 4,
        "merkleroot": "00".repeat(32),
        "blockcommitments": "00".repeat(32),
        "finalsaplingroot": "00".repeat(32),
        "time": unix_time,
        "mediantime": unix_time,
        "nonce": "00".repeat(32),
        "bits": "1f07ffff",
        "previousblockhash": "ff".repeat(32),
    })
}

#[test]
fn src_has_no_wall_clock() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/src/accrual.rs");
    let s = std::fs::read_to_string(p).expect("accrual.rs");
    assert!(
        !s.contains("std::time") && !s.contains("Instant") && !s.contains("SystemTime"),
        "std::time Instant/SystemTime is forbidden as block time"
    );
    assert!(
        !s.contains("get(\"time\")") && !s.contains("get(\"mediantime\")"),
        "Unix time fields must not be read as the height window"
    );
    assert!(
        !s.contains("get(\"previousblockhash\")") && !s.contains("get(\"blocks\")"),
        "previousblockhash/blocks are not height evidence"
    );
    assert!(
        s.contains("getblockheader"),
        "heights must come from Zakura getblockheader"
    );
    assert!(!s.contains("DummyStwo") && !s.to_ascii_lowercase().contains("dummy_stwo"));
    assert!(!s.contains("BankMsg") && !s.contains("prove_for_test"));
    assert!(!s.contains("toy_field_mul"));
    assert!(!s.contains("later Halo2"), "Halo2 waist is current, not deferred");
    assert!(
        s.contains("checked_mul"),
        "earned is height window * rate, not a closer integer"
    );
    assert!(
        s.contains("Mul::mul"),
        "height window * rate is also constrained in Pallas"
    );
    assert!(
        s.contains("getbestblockhash") && s.contains("getblockheader"),
        "tip height is getbestblockhash then getblockheader"
    );
    assert!(s.contains("pack_hash32"), "zk inputs must be Pallas-packed");
    assert!(
        s.contains("EmptyHalo2Proof")
            && s.contains("proof_instance_verify")
            && s.contains("ACCRUAL_ZKID"),
        "empty Halo2 proofs fail closed; f() is proof_instance_verify(ACCRUAL_ZKID), not HOSTING_PAYMENT"
    );
    assert!(
        s.contains("prove_accrual") && s.contains("verify_accrual"),
        "f() must be a Halo2 prove/verify, not HOSTING_PAYMENT inclusion"
    );
    assert!(
        s.contains("accrual_commit_bytes"),
        "commitment must be the AccrualCircuit BLAKE2b preimage"
    );
    assert!(
        s.contains("verify_product_accrual") && s.contains("commit_and_prove_accrual"),
        "product accrue requires a Halo2 proof of f(); missing proof is fail-closed"
    );
    assert!(
        s.contains("product_grant_json"),
        "grant JSON is commitment/instances with earned_zat = 0"
    );
    assert!(
        s.contains("accrue_from_zakura_halo2") && s.contains("accrue_from_headers_halo2"),
        "Zakura headers must prove f() before a product grant"
    );
}

fn lab_required() -> bool {
    std::env::var("PIR_ZAKURA_LAB").ok().as_deref() == Some("1")
}

#[test]
fn earned_is_height_delta_times_rate() {
    src_has_no_wall_clock();
    let w = HeightWindow {
        open_height: 10,
        close_height: 15,
    };
    let rate = AccrualRate {
        zat_per_height: 100,
    };
    assert_eq!(duration_heights(w).unwrap(), 5);
    assert_eq!(earned_zat(w, rate).unwrap(), 500);
    assert_eq!(f(10, 15, rate).unwrap(), 500);
    assert_eq!(f(10, 15, rate).unwrap(), earned_zat(w, rate).unwrap());
    assert_eq!(
        earned_zat(
            HeightWindow {
                open_height: 8,
                close_height: 8
            },
            rate
        ),
        Err(AccrualError::InvertedWindow {
            open: 8,
            close: 8
        })
    );
    assert_eq!(
        f(8, 7, rate),
        Err(AccrualError::InvertedWindow {
            open: 8,
            close: 7
        })
    );
    assert_eq!(
        earned_zat(w, AccrualRate { zat_per_height: 0 }),
        Err(AccrualError::ZeroRate)
    );
    assert_eq!(
        earned_zat(
            HeightWindow {
                open_height: 0,
                close_height: 2
            },
            AccrualRate {
                zat_per_height: u64::MAX
            }
        ),
        Err(AccrualError::Overflow)
    );
    for (open, close, zat_per_height, want) in [
        (0u64, 1u64, 1u64, 1u64),
        (10, 11, 7, 7),
        (100, 140, 7, 280),
        (8, 18, 50, 500),
    ] {
        let rate = AccrualRate { zat_per_height };
        assert_eq!(f(open, close, rate).unwrap(), want);
        assert_eq!(want, (close - open) * zat_per_height);
    }
}

#[test]
fn public_surface_is_commitment_not_duration() {
    let w = HeightWindow {
        open_height: 100,
        close_height: 140,
    };
    let rate = AccrualRate {
        zat_per_height: 7,
    };
    let blinding = tagged_hash(b"test-blind", &[b"accrual"]);
    let mut open_h = [0xff; 32];
    open_h[0] = 0x0a;
    let mut close_h = [0xee; 32];
    close_h[0] = 0x0c;
    let (wit, pubv) = commit_accrual(w, rate, blinding, open_h, close_h).unwrap();
    assert_eq!(wit.earned_zat, 40 * 7);
    assert_eq!(wit.duration_heights, 40);
    verify_witness(&wit, &pubv).unwrap();

    let encoded = pubv.chain_surface();
    let s = encoded.to_string();
    assert!(!s.contains("zat_per_height"));
    assert!(!s.contains("duration"));
    assert!(!s.contains("earned"));
    let obj = encoded.as_object().expect("object");
    assert_eq!(obj.len(), 3);
    assert!(obj.contains_key("commitment"));
    assert!(obj.contains_key("open_header_hash"));
    assert!(obj.contains_key("close_header_hash"));
    for (k, v) in obj {
        let hex_s = v.as_str().expect("public surface is hex strings only");
        assert_eq!(hex_s.len(), 64, "{k} must be 32-byte hex");
        assert!(v.as_u64().is_none(), "{k} must not be a numeric height/earned");
        assert!(v.as_i64().is_none());
    }
    let open_hex = hex::encode(open_h);
    let close_hex = hex::encode(close_h);
    let commit_hex = hex::encode(pubv.commitment);
    assert_eq!(
        obj.get("open_header_hash").and_then(|v| v.as_str()),
        Some(open_hex.as_str())
    );
    assert_eq!(
        obj.get("close_header_hash").and_then(|v| v.as_str()),
        Some(close_hex.as_str())
    );
    assert_eq!(
        obj.get("commitment").and_then(|v| v.as_str()),
        Some(commit_hex.as_str())
    );

    let ser = serde_json::to_value(&pubv).unwrap();
    let ser_obj = ser.as_object().expect("serialize object");
    assert_eq!(ser_obj.len(), 3);
    assert!(ser_obj.get("earned_zat").is_none());
    assert!(ser_obj.get("duration_heights").is_none());
    assert!(ser_obj.get("open_height").is_none());
    assert!(ser_obj.get("close_height").is_none());
    assert!(ser_obj.get("zat_per_height").is_none());

    let ins = pubv.zk_public_inputs();
    assert_eq!(ins.len(), 3);
    assert_eq!(ins[0], pack_fe32(&pubv.commitment));
    assert_eq!(ins[1], pack_fe32(&open_h));
    assert_eq!(ins[2], pack_fe32(&close_h));
    assert_ne!(ins[1], open_h, "Halo2 instances must be 254-bit packed");
    assert_eq!(ins[1][31], 0x3f);
    let bytes = pubv.zk_instance_bytes();
    assert_eq!(bytes.len(), 96);
    assert_eq!(&bytes[0..32], &ins[0]);
    assert_eq!(&bytes[32..64], &ins[1]);
    assert_eq!(&bytes[64..96], &ins[2]);
    assert_eq!(
        bytes,
        hosting_payment::encode_accrual_instances(&pubv.commitment, &open_h, &close_h)
    );
    let grant = product_grant_json(&pubv);
    assert_eq!(grant.get("earned_zat").and_then(|v| v.as_u64()), Some(0));
    let inst_hex = pubv.halo2_instances_hex();
    assert_eq!(inst_hex.len(), 192);
    assert_eq!(
        grant.get("halo2_instances").and_then(|v| v.as_str()),
        Some(inst_hex.as_str())
    );
    assert!(grant.get("duration_heights").is_none());
    assert!(grant.get("open_height").is_none());
    assert!(grant.get("zat_per_height").is_none());
    let grant_s = grant.to_string();
    assert!(!grant_s.contains("duration"));
    assert_eq!(
        verify_product_accrual(&wit, &pubv, &[]),
        Err(AccrualError::EmptyHalo2Proof)
    );
    assert_eq!(
        pubv.commitment,
        hosting_payment::accrual_commit_bytes(
            w.open_height,
            w.close_height,
            rate.zat_per_height,
            &blinding,
            &open_h,
            &close_h
        )
    );
    assert!(hosting_payment::decode_accrual_instances(&bytes).is_ok());
    assert!(hosting_payment::decode_instances(&bytes).is_err());
    assert_eq!(hosting_payment::INSTANCE_COUNT, 4);
    assert_eq!(hosting_payment::ACCRUAL_INSTANCE_COUNT, 3);
    assert_eq!(hosting_payment::ACCRUAL_ZKID, 2);
    assert_ne!(hosting_payment::K, hosting_payment::ACCRUAL_K);
    assert_eq!(hosting_payment::ACCRUAL_CIRCUIT_ID, "pir-accrual.f.v1");

    let mut bad = wit.clone();
    bad.earned_zat = 1;
    assert_eq!(
        verify_witness(&bad, &pubv),
        Err(AccrualError::UnboundCommitment)
    );

    let mut dur = wit.clone();
    dur.duration_heights = 1;
    assert_eq!(
        verify_witness(&dur, &pubv),
        Err(AccrualError::UnboundCommitment)
    );

    let mut swapped = pubv.clone();
    swapped.open_header_hash = close_h;
    swapped.close_header_hash = open_h;
    assert_eq!(
        verify_witness(&wit, &swapped),
        Err(AccrualError::UnboundCommitment)
    );

    assert_eq!(
        commit_accrual(w, rate, blinding, open_h, open_h),
        Err(AccrualError::HeaderCollision)
    );

    let mut rate_tamper = wit.clone();
    rate_tamper.rate.zat_per_height = 1;
    assert_eq!(
        verify_witness(&rate_tamper, &pubv),
        Err(AccrualError::UnboundCommitment)
    );

    for x in ins {
        let _ = hosting_payment::pack_hash32(&x);
        assert_eq!(x[31] & 0xc0, 0, "Pallas instance must clear top two bits");
    }

    let mut height_le = [0u8; 32];
    height_le[..8].copy_from_slice(&w.open_height.to_le_bytes());
    assert_ne!(ins[0], height_le, "instances must not be plaintext heights");
    height_le[..8].copy_from_slice(&wit.earned_zat.to_le_bytes());
    assert_ne!(ins[0], height_le, "instances must not be plaintext earned");
    height_le[..8].copy_from_slice(&rate.zat_per_height.to_le_bytes());
    assert_ne!(ins[0], height_le, "instances must not be plaintext rate");

    assert_eq!(
        verify_accrual_halo2(&[], &pubv),
        Err(AccrualError::EmptyHalo2Proof)
    );
    assert_eq!(
        verify_accrual_halo2(&[0x01, 0x02, 0x03], &pubv),
        Err(AccrualError::InvalidHalo2Proof)
    );
    assert_eq!(
        verify_accrual_halo2(b"DSTW\x01\x02", &pubv),
        Err(AccrualError::InvalidHalo2Proof)
    );
    let hp = hosting_payment::encode_instances("PIR-001", "sib", &[1u8; 32], 1);
    assert_eq!(hp.len(), 128);
    assert!(hosting_payment::decode_accrual_instances(&hp)
        .unwrap_err()
        .contains("HOSTING_PAYMENT"));
}

#[test]
fn halo2_proves_f_height_window_times_rate() {
    src_has_no_wall_clock();
    let w = HeightWindow {
        open_height: 10,
        close_height: 15,
    };
    let rate = AccrualRate {
        zat_per_height: 100,
    };
    let blinding = tagged_hash(b"test-blind", &[b"halo2-f"]);
    let mut open_h = [0x11u8; 32];
    open_h[31] = 0x3a;
    let mut close_h = [0x22u8; 32];
    close_h[31] = 0x3b;
    let (wit, pubv, proof) =
        commit_and_prove_accrual(w, rate, blinding, open_h, close_h).expect("Halo2 prove of f()");
    assert_eq!(wit.earned_zat, f(10, 15, rate).unwrap());
    assert_eq!(wit.earned_zat, 500);
    verify_witness(&wit, &pubv).unwrap();
    assert!(!proof.is_empty());
    assert!(!proof.starts_with(b"DSTW"));
    verify_accrual_halo2(&proof, &pubv).expect("Halo2 verify of f()");
    verify_product_accrual(&wit, &pubv, &proof).expect("product accrue requires Halo2 of f()");
    assert_eq!(
        verify_product_accrual(&wit, &pubv, &[]),
        Err(AccrualError::EmptyHalo2Proof)
    );
    let grant = product_grant_json(&pubv);
    assert_eq!(grant["earned_zat"], 0);
    assert_eq!(grant["halo2_instances"].as_str().unwrap().len(), 192);
    assert!(hosting_payment::verify_accrual(&proof, &pubv.zk_instance_bytes()).unwrap());
    assert!(
        hosting_payment::proof_instance_verify(
            hosting_payment::ACCRUAL_ZKID,
            &proof,
            &pubv.zk_instance_bytes()
        )
        .unwrap(),
        "proof_instance_verify(ACCRUAL_ZKID) must accept f()"
    );
    assert!(
        hosting_payment::proof_instance_verify(1, &proof, &pubv.zk_instance_bytes()).is_err(),
        "HOSTING_PAYMENT zkid 1 must not verify 96-byte f()"
    );
    let (wit_h, pubv_h, proof_h) =
        accrue_from_headers_halo2(
            ChainHeader {
                height: 10,
                hash: open_h,
            },
            ChainHeader {
                height: 15,
                hash: close_h,
            },
            rate,
            blinding,
        )
        .expect("headers Halo2 of f()");
    assert_eq!(wit_h.earned_zat, 500);
    assert_eq!(pubv_h.commitment, pubv.commitment);
    verify_product_accrual(&wit_h, &pubv_h, &proof_h).unwrap();

    let mut bad_inst = pubv.zk_instance_bytes();
    bad_inst[0] ^= 0x01;
    assert!(
        !hosting_payment::verify_accrual(&proof, &bad_inst).unwrap(),
        "bitflipped instances must not satisfy f()"
    );

    let mut bad_wit = wit.clone();
    bad_wit.earned_zat = 1;
    assert_eq!(
        prove_accrual_halo2(&bad_wit, &pubv),
        Err(AccrualError::UnboundCommitment)
    );
    assert!(hosting_payment::prove_accrual(
        10,
        15,
        100,
        1,
        &blinding,
        &open_h,
        &close_h
    )
    .is_err());

    let hp_inst = hosting_payment::encode_instances("PIR-001", "sib", &[1u8; 32], 1);
    assert!(
        hosting_payment::verify_accrual(&proof, &hp_inst).is_err(),
        "HOSTING_PAYMENT 128-byte instances are not f()"
    );
}

#[test]
fn getblockheader_json_uses_height_not_unix_time() {
    let open_hash = [0x11; 32];
    let close_hash = [0x22; 32];
    let open = verbose_header(10, open_hash, 1_700_000_000);
    let close = verbose_header(15, close_hash, 1_700_000_500);
    let rate = AccrualRate {
        zat_per_height: 100,
    };
    let blinding = tagged_hash(b"test-blind", &[b"json"]);
    let (wit, pubv) = accrue_from_getblockheader_json(
        &open, 10, &close, 15, rate, blinding,
    )
    .unwrap();
    assert_eq!(wit.earned_zat, 5 * 100);
    assert_eq!(wit.duration_heights, 5);
    assert_ne!(
        wit.earned_zat,
        500 * 100,
        "Unix time delta must not be the window"
    );
    assert_eq!(pubv.open_header_hash, open_hash);
    assert_eq!(pubv.close_header_hash, close_hash);
    verify_witness(&wit, &pubv).unwrap();
    assert_eq!(
        verify_product_accrual(&wit, &pubv, &[]),
        Err(AccrualError::EmptyHalo2Proof)
    );
    let grant = product_grant_json(&pubv);
    assert_eq!(grant.get("earned_zat").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(
        grant.get("halo2_instances").and_then(|v| v.as_str()).map(str::len),
        Some(192)
    );
    let surface = pubv.chain_surface();
    let s = surface.to_string();
    assert!(!s.contains("duration"));
    assert!(!s.contains("earned"));
    assert!(surface.get("open_height").is_none());
    assert!(surface.get("time").is_none());

    let wrapped_open = json!({ "jsonrpc": "1.0", "id": "pir-accrual", "result": open });
    let wrapped_close = json!({ "jsonrpc": "1.0", "id": "pir-accrual", "result": close });
    let hdr = chain_header_from_getblockheader(&wrapped_open, 10).unwrap();
    assert_eq!(hdr.height, 10);
    assert_eq!(hdr.hash, open_hash);
    let (wit2, _) = accrue_from_getblockheader_json(
        &wrapped_open,
        10,
        &wrapped_close,
        15,
        rate,
        blinding,
    )
    .unwrap();
    assert_eq!(wit2.earned_zat, wit.earned_zat);

    assert_eq!(
        chain_header_from_getblockheader(&open, 11),
        Err(AccrualError::HeaderHeightMismatch {
            requested: 11,
            header: 10
        })
    );

    let time_only = json!({
        "hash": hex::encode(open_hash),
        "time": 10,
        "mediantime": 10,
    });
    assert_eq!(
        chain_header_from_getblockheader(&time_only, 10),
        Err(AccrualError::MissingHeader(10))
    );
    assert_eq!(
        chain_header_from_verbose(&time_only),
        Err(AccrualError::MalformedHeader)
    );

    let mediantime_as_height = json!({
        "hash": hex::encode(open_hash),
        "mediantime": 10,
        "time": 10,
    });
    assert_eq!(
        chain_header_from_getblockheader(&mediantime_as_height, 10),
        Err(AccrualError::MissingHeader(10))
    );

    let prev_is_not_hash = json!({
        "hash": hex::encode(open_hash),
        "previousblockhash": hex::encode(close_hash),
        "height": 10,
        "time": 10,
    });
    let sneaky = chain_header_from_getblockheader(&prev_is_not_hash, 10).unwrap();
    assert_eq!(sneaky.hash, open_hash);
    assert_ne!(sneaky.hash, close_hash);
    assert_eq!(sneaky.height, 10);

    let (wit3, pubv3) = accrue_from_headers(
        ChainHeader {
            height: 10,
            hash: open_hash,
        },
        ChainHeader {
            height: 15,
            hash: close_hash,
        },
        rate,
        blinding,
    )
    .unwrap();
    assert_eq!(wit3.earned_zat, 500);
    verify_witness(&wit3, &pubv3).unwrap();

    // Zakura BlockHeaderObject shape (hash + height; Unix time is a sibling field).
    let open_snap = json!({
        "hash": hex::encode(open_hash),
        "confirmations": 10,
        "height": 1,
        "version": 4,
        "merkleroot": "f37e9f691fffb635de0999491d906ee85ba40cd36dae9f6e5911a8277d7c5f75",
        "blockcommitments": "00".repeat(32),
        "finalsaplingroot": "00".repeat(32),
        "time": 1_477_674_473,
        "mediantime": 1_477_674_473,
        "nonce": "00".repeat(32),
        "solution": "00",
        "bits": "2007ffff",
        "difficulty": 1.0,
        "previousblockhash": "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38",
        "nextblockhash": "00f1a49e54553ac3ef735f2eb1d8247c9a87c22a47dbd7823ae70adcd6c21a18",
    });
    let close_snap = json!({
        "hash": hex::encode(close_hash),
        "confirmations": 4,
        "height": 6,
        "version": 4,
        "merkleroot": "00".repeat(32),
        "blockcommitments": "00".repeat(32),
        "finalsaplingroot": "00".repeat(32),
        "time": 1_477_674_973,
        "mediantime": 1_477_674_800,
        "nonce": "00".repeat(32),
        "bits": "2007ffff",
        "difficulty": 1.0,
        "previousblockhash": hex::encode(open_hash),
    });
    let hdr = chain_header_from_verbose(&open_snap).unwrap();
    assert_eq!(hdr.height, 1);
    assert_eq!(hdr.hash, open_hash);
    let (wit_snap, pub_snap) = accrue_from_getblockheader_json(
        &open_snap, 1, &close_snap, 6, rate, blinding,
    )
    .unwrap();
    assert_eq!(wit_snap.earned_zat, 5 * 100);
    assert_ne!(
        wit_snap.earned_zat,
        500 * 100,
        "Zakura Unix time delta must not be the window"
    );
    verify_witness(&wit_snap, &pub_snap).unwrap();

    let hex_only = json!("00".repeat(160));
    assert_eq!(
        chain_header_from_verbose(&hex_only),
        Err(AccrualError::MalformedHeader)
    );
    let prefixed = json!({
        "hash": format!("0x{}", hex::encode(open_hash)),
        "height": 10,
        "time": 99,
    });
    let pref = chain_header_from_getblockheader(&prefixed, 10).unwrap();
    assert_eq!(pref.hash, open_hash);
    assert_eq!(pref.height, 10);

    let height_as_string = json!({
        "hash": hex::encode(open_hash),
        "height": "10",
        "time": 1_700_000_000,
    });
    let hs = chain_header_from_getblockheader(&height_as_string, 10).unwrap();
    assert_eq!(hs.height, 10);
    assert_eq!(hs.hash, open_hash);
}

#[test]
fn heights_from_zakura_getblockheader() {
    match lab_spawn() {
        Ok(n) => {
            let z = n.as_regtest();
            match getblockcount(&z) {
                Ok(tip) => {
                    if tip < 2 {
                        if lab_required() {
                            panic!("PIR_ZAKURA_LAB=1 but chain has no height window (tip {tip})");
                        }
                        eprintln!("skip: tip {tip}");
                        return;
                    }
                    let open = tip - 1;
                    let close = tip;
                    let open_hdr = header_at(&z, open).expect("open getblockheader");
                    let close_hdr = header_at(&z, close).expect("close getblockheader");
                    assert_eq!(open_hdr.height, open);
                    assert_eq!(close_hdr.height, close);
                    assert_ne!(open_hdr.hash, close_hdr.hash);
                    assert_eq!(getblockheader_at(&z, open).unwrap(), open_hdr.hash);
                    let tip_from_header = open_at_tip(&z).unwrap();
                    let tip_now = getblockcount(&z).expect("tip after header");
                    assert_eq!(tip_from_header, tip_now);
                    assert!(tip_from_header >= close);
                    let best = getbestblockhash(&z).expect("getbestblockhash");
                    assert_eq!(best.len(), 64);
                    let open_json = getblockheader_json(&z, open).expect("open json");
                    let close_json = getblockheader_json(&z, close).expect("close json");
                    assert!(open_json.get("height").is_some() || open_json.get("result").is_some());
                    let rate = AccrualRate {
                        zat_per_height: 3,
                    };
                    let (wit, pubv) = accrue_from_zakura(
                        &z,
                        open,
                        close,
                        rate,
                        tagged_hash(b"blind", &[b"live"]),
                    )
                    .unwrap();
                    assert_eq!(wit.earned_zat, (close - open) * 3);
                    assert_eq!(wit.duration_heights, close - open);
                    assert_eq!(pubv.open_header_hash, open_hdr.hash);
                    assert_eq!(pubv.close_header_hash, close_hdr.hash);
                    verify_witness(&wit, &pubv).unwrap();
                    assert_eq!(
                        verify_product_accrual(&wit, &pubv, &[]),
                        Err(AccrualError::EmptyHalo2Proof)
                    );
                    let (wit_h, pubv_h, proof) = accrue_from_zakura_halo2(
                        &z,
                        open,
                        close,
                        rate,
                        tagged_hash(b"blind", &[b"live"]),
                    )
                    .expect("Halo2 of f() from Zakura getblockheader");
                    assert_eq!(wit_h.earned_zat, wit.earned_zat);
                    assert_eq!(pubv_h.commitment, pubv.commitment);
                    assert!(!proof.is_empty());
                    verify_product_accrual(&wit_h, &pubv_h, &proof).unwrap();
                    assert!(hosting_payment::proof_instance_verify(
                        hosting_payment::ACCRUAL_ZKID,
                        &proof,
                        &pubv_h.zk_instance_bytes()
                    )
                    .unwrap());
                    let grant = product_grant_json(&pubv_h);
                    assert_eq!(grant.get("earned_zat").and_then(|v| v.as_u64()), Some(0));
                    let (wit_json, pubv_json) = accrue_from_getblockheader_json(
                        &open_json,
                        open,
                        &close_json,
                        close,
                        rate,
                        tagged_hash(b"blind", &[b"live"]),
                    )
                    .unwrap();
                    assert_eq!(wit_json.earned_zat, wit.earned_zat);
                    assert_eq!(pubv_json.commitment, pubv.commitment);
                    let surface = pubv.chain_surface();
                    let obj = surface.as_object().expect("object");
                    assert_eq!(obj.len(), 3);
                    assert!(obj.get("earned_zat").is_none());
                    assert!(obj.get("duration_heights").is_none());
                    assert!(obj.get("open_height").is_none());
                    assert!(!surface.to_string().contains("duration"));
                }
                Err(e) => {
                    if lab_required() {
                        panic!("PIR_ZAKURA_LAB=1 but getblockcount failed: {e}");
                    }
                    eprintln!("skip: getblockcount ({e})");
                }
            }
        }
        Err(e) if lab_required() => {
            panic!("PIR_ZAKURA_LAB=1 but lab_spawn failed: {e}");
        }
        Err(e) => eprintln!("skip: lab_spawn ({e})"),
    }
}
