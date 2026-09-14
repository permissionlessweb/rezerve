//! Slice 4: resolver notice is WS delivery + attest bind + grant. Not vote extensions.

use private_inference_rent::access::LeaseBook;
use private_inference_rent::accrual::{commit_accrual, AccrualRate, HeightWindow};
use private_inference_rent::escrow::{EscrowCell, EscrowMemberIds, EscrowParty, GrantView};
use private_inference_rent::escrow_notice::{
    grant_view_from_query_json, resolver_dkg_share_from_notice, resolver_dkg_share_from_ws_delivery,
    resolver_dkg_share_from_ws_delivery_with_grant_query, resolver_may_sign_from_notice, CloseAction,
    CloseEventAttest, CloseEventAttrs, ResolverDkgShare, ResolverNotice, ResolverNoticeError,
};
use private_inference_rent::escrow::ResolverShareError;
use private_inference_rent::tagged_hash;
use private_inference_rent::zap1_lc::{
    require_close_event_lc, CloseEventLcRequest, Zap1LcError, ENV_ZAP1_LC_BIN, ENV_ZAP1_REQUIRE_CHAIN,
};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn members() -> EscrowMemberIds {
    EscrowMemberIds {
        tenant: "tenant1".into(),
        provider: "provider1".into(),
        resolver: "resolver1".into(),
    }
}

fn fixture_lc_off() {
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "0");
    std::env::remove_var(ENV_ZAP1_LC_BIN);
}

fn closed_cell() -> (EscrowCell, CloseEventAttrs) {
    let bid = tagged_hash(b"bid", &[b"resolver-notice"]);
    let mut cell = EscrowCell::open(80, bid, members()).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("lease-r", "bearer".into());
    cell.accrue(&[private_inference_rent::WorkReceipt::bind(
        "ask-r",
        bid,
        30,
    )])
    .unwrap();
    cell.close(EscrowParty::Tenant, &mut leases, "lease-r", None)
        .unwrap();
    let view = cell.grant.as_ref().unwrap().view();
    let attrs = CloseEventAttrs {
        action: CloseAction::Close,
        cell_id: cell.cell_id,
        closer: EscrowParty::Tenant,
        earned_zat: view.earned_zat,
        remainder_zat: view.remainder_zat,
    };
    assert_eq!(attrs.earned_zat, 0);
    assert_eq!(attrs.remainder_zat, 80);
    (cell, attrs)
}

fn part3_identity_bytes() -> Vec<u8> {
    format!("{}:{}", hex::encode([1u8; 32]), hex::encode([7u8; 32])).into_bytes()
}

fn resolver_share() -> ResolverDkgShare {
    ResolverDkgShare::from_part3_identity("resolver1", &part3_identity_bytes()).unwrap()
}

fn grant_query_json(cell: &EscrowCell) -> String {
    serde_json::to_string(&cell.grant.as_ref().expect("grant").view()).unwrap()
}

fn closer_str(p: EscrowParty) -> &'static str {
    match p {
        EscrowParty::Tenant => "tenant",
        EscrowParty::Provider => "provider",
    }
}

fn action_str(a: CloseAction) -> &'static str {
    match a {
        CloseAction::Close => "close",
        CloseAction::Dispute => "dispute",
    }
}

fn wasm_close_attributes(attrs: &CloseEventAttrs, grant: Option<&GrantView>) -> Vec<serde_json::Value> {
    let mut a = vec![
        serde_json::json!({"key": "action", "value": action_str(attrs.action)}),
        serde_json::json!({"key": "cell_id", "value": hex::encode(attrs.cell_id)}),
        serde_json::json!({"key": "closer", "value": closer_str(attrs.closer)}),
        serde_json::json!({"key": "remainder_zat", "value": attrs.remainder_zat.to_string()}),
        serde_json::json!({"key": "settle", "value": "grant_only"}),
    ];
    if let Some(g) = grant {
        if !g.accrual_commitment.is_empty() {
            a.push(serde_json::json!({"key": "accrual_commitment", "value": g.accrual_commitment}));
            a.push(serde_json::json!({"key": "open_header_hash", "value": g.open_header_hash}));
            a.push(serde_json::json!({"key": "close_header_hash", "value": g.close_header_hash}));
        }
    }
    a
}

/// CometBFT WS / TxSearch payload. Delivery only — LC + grant still authorize.
fn comet_close_json(attrs: &CloseEventAttrs, header: [u8; 32], tx: [u8; 32]) -> String {
    comet_close_json_with_grant(attrs, None, header, tx)
}

fn comet_close_json_grant(
    attrs: &CloseEventAttrs,
    header: [u8; 32],
    tx: [u8; 32],
    grant: Option<&GrantView>,
) -> String {
    comet_close_json_with_grant(attrs, grant, header, tx)
}

fn comet_close_json_with_grant(
    attrs: &CloseEventAttrs,
    grant: Option<&GrantView>,
    header: [u8; 32],
    tx: [u8; 32],
) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": "pir-resolver",
        "result": {
            "query": "tm.event='Tx'",
            "data": {
                "value": {
                    "TxResult": {
                        "height": "1",
                        "txhash": hex::encode(tx),
                        "header": { "hash": hex::encode(header) },
                        "result": {
                            "events": [{
                                "type": "wasm",
                                "attributes": wasm_close_attributes(attrs, grant)
                            }]
                        }
                    }
                }
            }
        }
    })
    .to_string()
}

/// Real CometBFT WS Tx delivery: hashes live in `events` string arrays, not `txhash`.
fn comet_ws_array_json(
    attrs: &CloseEventAttrs,
    grant: Option<&GrantView>,
    header: [u8; 32],
    tx: [u8; 32],
) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": {
            "query": "tm.event='Tx'",
            "data": {
                "type": "tendermint/event/Tx",
                "value": {
                    "TxResult": {
                        "height": "1",
                        "index": 0,
                        "tx": "AQ==",
                        "result": {
                            "events": [{
                                "type": "wasm",
                                "attributes": wasm_close_attributes(attrs, grant)
                            }]
                        }
                    }
                }
            },
            "events": {
                "tm.event": ["Tx"],
                "tx.hash": [hex::encode(tx)],
                "header.hash": [hex::encode(header)],
                "tx.height": ["1"]
            }
        }
    })
    .to_string()
}

fn closed_cell_with_accrual() -> (EscrowCell, CloseEventAttrs, GrantView) {
    let bid = tagged_hash(b"bid", &[b"resolver-accrual"]);
    let mut cell = EscrowCell::open(80, bid, members()).unwrap();
    let mut leases = LeaseBook::new();
    leases.accept_bid("lease-r", "bearer".into());
    let (wit, pubv) = commit_accrual(
        HeightWindow {
            open_height: 10,
            close_height: 40,
        },
        AccrualRate {
            zat_per_height: 1,
        },
        tagged_hash(b"blind", &[b"resolver-accrual"]),
        tagged_hash(b"hdr", &[b"open-cell"]),
        tagged_hash(b"hdr", &[b"close-cell"]),
    )
    .unwrap();
    cell.accrue_from_witness(wit, pubv).unwrap();
    cell.close(EscrowParty::Tenant, &mut leases, "lease-r", None)
        .unwrap();
    let view = cell.grant.as_ref().unwrap().view();
    assert_eq!(view.earned_zat, 0);
    assert_eq!(view.remainder_zat, 80);
    assert_eq!(view.accrual_commitment.len(), 64);
    let attrs = CloseEventAttrs {
        action: CloseAction::Close,
        cell_id: cell.cell_id,
        closer: EscrowParty::Tenant,
        earned_zat: view.earned_zat,
        remainder_zat: view.remainder_zat,
    };
    (cell, attrs, view)
}

fn pir_zap1_lc_bin() -> Option<String> {
    option_env!("CARGO_BIN_EXE_pir-zap1-lc")
        .map(str::to_string)
        .filter(|p| std::path::Path::new(p).is_file())
}

#[test]
fn resolver_ws_only_notice_fails() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let notice = ResolverNotice::ws_only();
    let err = resolver_may_sign_from_notice(
        &cell,
        "resolver1",
        &notice,
        [3u8; 32],
        [4u8; 32],
        &attrs,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::WsOnlyUnverified);
}

#[test]
fn resolver_attest_and_grant_succeeds() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"resolver"]);
    let tx = tagged_hash(b"tx", &[b"resolver"]);
    let attest = CloseEventAttest::bind(header, tx, &attrs);
    let notice = ResolverNotice {
        delivered_over_ws: false,
        attest: Some(attest),
    };
    resolver_may_sign_from_notice(&cell, "resolver1", &notice, header, tx, &attrs).unwrap();
    assert!(cell.grant.as_ref().is_some_and(|g| g.recorded));
}

#[test]
fn resolver_ws_delivery_parses_close_attrs() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let cell_hex = hex::encode(attrs.cell_id);
    let parsed = CloseEventAttrs::from_wasm_attributes([
        ("action", "close"),
        ("cell_id", cell_hex.as_str()),
        ("closer", "tenant"),
        ("remainder_zat", "80"),
        ("settle", "grant_only"),
    ])
    .unwrap();
    assert_eq!(parsed, attrs);
    assert_eq!(parsed.earned_zat, 0);
    let header = tagged_hash(b"hdr", &[b"ws-attrs"]);
    let tx = tagged_hash(b"tx", &[b"ws-attrs"]);
    let notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &parsed));
    assert!(notice.delivered_over_ws);
    let token = resolver_dkg_share_from_notice(
        &cell,
        &resolver_share(),
        &notice,
        header,
        tx,
        &parsed,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_ws_delivery_rejects_bad_close_attrs() {
    let err = CloseEventAttrs::from_wasm_attributes([
        ("action", "extend_vote"),
        ("cell_id", "aa"),
        ("closer", "resolver"),
        ("earned_zat", "1"),
        ("remainder_zat", "1"),
    ])
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
}

#[test]
fn resolver_dkg_share_rejected_without_grant() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let bid = tagged_hash(b"bid", &[b"open-cell"]);
    let cell = EscrowCell::open(80, bid, members()).unwrap();
    let attrs = CloseEventAttrs {
        action: CloseAction::Close,
        cell_id: cell.cell_id,
        closer: EscrowParty::Tenant,
        earned_zat: 0,
        remainder_zat: 80,
    };
    // Open cell has no grant; public remainder is the deposit but share stays denied.
    let header = tagged_hash(b"hdr", &[b"open"]);
    let tx = tagged_hash(b"tx", &[b"open"]);
    let notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &attrs));
    let err = resolver_dkg_share_from_notice(
        &cell,
        &resolver_share(),
        &notice,
        header,
        tx,
        &attrs,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::Grant(ResolverShareError::NoGrant));
}

#[test]
fn resolver_dkg_share_rejected_on_ws_only() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let notice = ResolverNotice::ws_only();
    let err = resolver_dkg_share_from_notice(
        &cell,
        &resolver_share(),
        &notice,
        [3u8; 32],
        [4u8; 32],
        &attrs,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::WsOnlyUnverified);
}

#[test]
fn resolver_dkg_share_rejected_for_tenant_member() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"tenant-share"]);
    let tx = tagged_hash(b"tx", &[b"tenant-share"]);
    let notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &attrs));
    let share = ResolverDkgShare {
        member_id: "tenant1".into(),
        share_commitment: tagged_hash(b"dkg-share", &[b"tenant1"]),
    };
    let err = resolver_dkg_share_from_notice(&cell, &share, &notice, header, tx, &attrs)
        .unwrap_err();
    assert_eq!(
        err,
        ResolverNoticeError::Grant(ResolverShareError::GrantMismatch)
    );
}

#[test]
fn resolver_dkg_share_rejected_on_zero_commitment() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"zero"]);
    let tx = tagged_hash(b"tx", &[b"zero"]);
    let notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &attrs));
    let share = ResolverDkgShare {
        member_id: "resolver1".into(),
        share_commitment: [0u8; 32],
    };
    let err = resolver_dkg_share_from_notice(&cell, &share, &notice, header, tx, &attrs)
        .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
}

#[test]
fn resolver_dkg_share_rejected_on_closer_mismatch() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let mut bad = attrs.clone();
    bad.closer = EscrowParty::Provider;
    let header = tagged_hash(b"hdr", &[b"closer"]);
    let tx = tagged_hash(b"tx", &[b"closer"]);
    let notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &bad));
    let err = resolver_dkg_share_from_notice(&cell, &resolver_share(), &notice, header, tx, &bad)
        .unwrap_err();
    assert_eq!(
        err,
        ResolverNoticeError::Grant(ResolverShareError::GrantMismatch)
    );
}

#[test]
fn resolver_dkg_share_allowed_after_attest_and_grant() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"dkg"]);
    let tx = tagged_hash(b"tx", &[b"dkg"]);
    let notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &attrs));
    let token = resolver_dkg_share_from_notice(
        &cell,
        &resolver_share(),
        &notice,
        header,
        tx,
        &attrs,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_dkg_share_fail_closed_when_lc_required_without_helper() {
    let _g = ENV_LOCK.lock().unwrap();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"lc-miss"]);
    let tx = tagged_hash(b"tx", &[b"lc-miss"]);
    let notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &attrs));
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    let err = resolver_dkg_share_from_notice(
        &cell,
        &resolver_share(),
        &notice,
        header,
        tx,
        &attrs,
    );
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
    match err {
        Err(ResolverNoticeError::Lc(Zap1LcError::Spawn(s))) => {
            assert!(s.contains("PIR_ZAP1_LC_BIN"));
            assert!(s.contains("not 08-wasm store"));
        }
        other => panic!("expected Lc fail-closed, got {other:?}"),
    }
}

#[test]
fn live_ict_close_lc_fail_closed_without_helper() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    if cfg!(feature = "live-ict") {
        std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
        assert!(
            private_inference_rent::zap1_lc_required(),
            "NS9 live-ict must require Close LC"
        );
    } else {
        std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
        assert!(private_inference_rent::zap1_lc_required());
    }
    let header = [1u8; 32];
    let tx = [2u8; 32];
    let attrs = CloseEventAttrs {
        action: CloseAction::Close,
        cell_id: [4u8; 32],
        closer: EscrowParty::Tenant,
        earned_zat: 0,
        remainder_zat: 1,
    };
    let attest = CloseEventAttest::bind(header, tx, &attrs);
    let req = CloseEventLcRequest::bind(
        header,
        tx,
        attest.app_data_hash,
        "close",
        attrs.cell_id,
        "tenant",
        0,
        1,
    );
    match require_close_event_lc(&req) {
        Err(Zap1LcError::Spawn(s)) => {
            assert!(!s.contains("store cw-zap1-ibcv2"));
            assert!(s.contains("not 08-wasm store"));
        }
        other => panic!("expected Spawn fail-closed, got {other:?}"),
    }
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
}

#[test]
fn resolver_dkg_share_lc_helper_rebinds_close_attrs() {
    let _g = ENV_LOCK.lock().unwrap();
    let bin = pir_zap1_lc_bin().expect("pir-zap1-lc bin (LC-class Close rebind, not 08-wasm store)");
    std::env::set_var(ENV_ZAP1_LC_BIN, &bin);
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"lc-ok"]);
    let tx = tagged_hash(b"tx", &[b"lc-ok"]);
    let notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &attrs));
    let token = resolver_dkg_share_from_notice(
        &cell,
        &resolver_share(),
        &notice,
        header,
        tx,
        &attrs,
    )
    .expect("LC helper must re-bind Close attrs");
    assert_ne!(token, [0u8; 32]);

    let mut bad = attrs.clone();
    bad.earned_zat = 99;
    let bad_notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &bad));
    let err = resolver_dkg_share_from_notice(
        &cell,
        &resolver_share(),
        &bad_notice,
        header,
        tx,
        &bad,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);

    let mut leaked = attrs.clone();
    leaked.earned_zat = 30;
    leaked.remainder_zat = 50;
    let leaked_notice = ResolverNotice::from_ws(CloseEventAttest::bind(header, tx, &leaked));
    let err = resolver_dkg_share_from_notice(
        &cell,
        &resolver_share(),
        &leaked_notice,
        header,
        tx,
        &leaked,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);

    std::env::remove_var(ENV_ZAP1_LC_BIN);
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
}

#[test]
fn require_close_event_lc_rejects_malformed_attrs_when_required() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    let req = CloseEventLcRequest {
        header_hash_hex: "zz".into(),
        tx_hash_hex: hex::encode([2u8; 32]),
        app_data_hash_hex: hex::encode([3u8; 32]),
        action: "close".into(),
        cell_id_hex: hex::encode([4u8; 32]),
        closer: "tenant".into(),
        earned_zat: 0,
        remainder_zat: 1,
        settle: "grant_only".into(),
        accrual_commitment: String::new(),
        open_header_hash: String::new(),
        close_header_hash: String::new(),
    };
    assert_eq!(require_close_event_lc(&req), Err(Zap1LcError::Rejected));
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
}

#[test]
fn resolver_dkg_share_from_part3_identity_not_dealer() {
    let share = ResolverDkgShare::from_part3_identity("resolver1", &part3_identity_bytes()).unwrap();
    assert_eq!(share.member_id, "resolver1");
    assert_ne!(share.share_commitment, [0u8; 32]);
    assert_eq!(
        ResolverDkgShare::from_part3_identity("resolver1", b"").unwrap_err(),
        ResolverNoticeError::AttestFailed
    );
    assert_eq!(
        ResolverDkgShare::from_part3_identity("", &part3_identity_bytes()).unwrap_err(),
        ResolverNoticeError::AttestFailed
    );
    assert_eq!(
        ResolverDkgShare::from_part3_identity("resolver1", b"part3-pkg-not-dealer").unwrap_err(),
        ResolverNoticeError::AttestFailed
    );
    let zero_pkg = format!("{}:{}", hex::encode([1u8; 32]), hex::encode([0u8; 32])).into_bytes();
    assert_eq!(
        ResolverDkgShare::from_part3_identity("resolver1", &zero_pkg).unwrap_err(),
        ResolverNoticeError::AttestFailed
    );
    let src = include_str!("../src/escrow_notice.rs");
    assert!(src.contains("from_part3_identity"));
    assert!(src.contains("identifier_hex:package_hex"));
    assert!(!src.contains("generate_with_dealer"));
}

#[test]
fn resolver_comet_ws_json_parses_close_attrs_and_hashes() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"comet-ws"]);
    let tx = tagged_hash(b"tx", &[b"comet-ws"]);
    let json = comet_close_json(&attrs, header, tx);
    let parsed = CloseEventAttrs::from_comet_json(&json).unwrap();
    assert_eq!(parsed, attrs);
    let (h, t) = CloseEventAttrs::hashes_from_comet_json(&json).unwrap();
    assert_eq!(h, header);
    assert_eq!(t, tx);
    let (notice, from_ws) = ResolverNotice::from_ws_json(&json, header, tx).unwrap();
    assert!(notice.delivered_over_ws);
    assert_eq!(from_ws, attrs);
    let token = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &json,
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_ws_delivery_rejects_hash_mismatch() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"ws-mm"]);
    let tx = tagged_hash(b"tx", &[b"ws-mm"]);
    let json = comet_close_json(&attrs, header, tx);
    let err = ResolverNotice::from_ws_json(&json, header, tagged_hash(b"tx", &[b"other"]))
        .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
    let err = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &json,
        tagged_hash(b"hdr", &[b"other"]),
        tx,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
}

#[test]
fn resolver_ws_vote_extension_json_cannot_authorize_share() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"ve"]);
    let tx = tagged_hash(b"tx", &[b"ve"]);
    let json = serde_json::json!({
        "result": {
            "events": [{
                "type": "vote_extension",
                "attributes": [
                    {"key": "action", "value": "close"},
                    {"key": "cell_id", "value": hex::encode(attrs.cell_id)},
                    {"key": "closer", "value": "tenant"},
                    {"key": "earned_zat", "value": "30"},
                    {"key": "remainder_zat", "value": "50"},
                    {"key": "settle", "value": "grant_only"}
                ]
            }]
        }
    })
    .to_string();
    assert_eq!(
        CloseEventAttrs::from_comet_json(&json).unwrap_err(),
        ResolverNoticeError::AttestFailed
    );
    let err = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &json,
        header,
        tx,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
}

#[test]
fn resolver_ws_wasm_close_event_type_grant_gates_dkg_share() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"wasm-close"]);
    let tx = tagged_hash(b"tx", &[b"wasm-close"]);
    let json = serde_json::json!({
        "txhash": hex::encode(tx),
        "header_hash": hex::encode(header),
        "events": [{
            "type": "wasm-close",
            "attributes": [
                {"key": "action", "value": "close"},
                {"key": "cell_id", "value": hex::encode(attrs.cell_id)},
                {"key": "closer", "value": "tenant"},
                {"key": "remainder_zat", "value": attrs.remainder_zat.to_string()},
                {"key": "settle", "value": "grant_only"}
            ]
        }]
    })
    .to_string();
    let token = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &json,
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_dispute_ws_delivery_grant_gates_dkg_share() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, mut attrs) = closed_cell();
    attrs.action = CloseAction::Dispute;
    let header = tagged_hash(b"hdr", &[b"dispute"]);
    let tx = tagged_hash(b"tx", &[b"dispute"]);
    let json = comet_close_json(&attrs, header, tx);
    let token = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &json,
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_ws_delivery_fail_closed_when_lc_required_without_helper() {
    let _g = ENV_LOCK.lock().unwrap();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"ws-lc"]);
    let tx = tagged_hash(b"tx", &[b"ws-lc"]);
    let json = comet_close_json(&attrs, header, tx);
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    let err = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &json,
        header,
        tx,
    );
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
    match err {
        Err(ResolverNoticeError::Lc(Zap1LcError::Spawn(s))) => {
            assert!(s.contains("PIR_ZAP1_LC_BIN"));
            assert!(s.contains("not 08-wasm store"));
        }
        other => panic!("expected Lc fail-closed, got {other:?}"),
    }
}

#[test]
fn require_close_event_lc_rejects_zero_split_and_vote_extension_action() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    let zero = CloseEventLcRequest::bind(
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        "close",
        [4u8; 32],
        "tenant",
        0,
        0,
    );
    assert_eq!(require_close_event_lc(&zero), Err(Zap1LcError::Rejected));
    let ve = CloseEventLcRequest::bind(
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        "extend_vote",
        [4u8; 32],
        "tenant",
        1,
        1,
    );
    assert_eq!(require_close_event_lc(&ve), Err(Zap1LcError::Rejected));
    let leaked = CloseEventLcRequest::bind(
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        "close",
        [4u8; 32],
        "tenant",
        30,
        50,
    );
    assert_eq!(require_close_event_lc(&leaked), Err(Zap1LcError::Rejected));
    let same_hash = CloseEventLcRequest::bind(
        [1u8; 32],
        [1u8; 32],
        [3u8; 32],
        "close",
        [4u8; 32],
        "tenant",
        0,
        80,
    );
    assert_eq!(require_close_event_lc(&same_hash), Err(Zap1LcError::Rejected));
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
}

#[test]
fn vote_extension_strings_absent_from_notice_path() {
    let src = include_str!("../src/escrow_notice.rs");
    assert!(!src.contains("vote_extension"));
    assert!(!src.contains("VoteExtension"));
    assert!(!src.contains("ExtendVote"));
    assert!(!src.contains("VerifyVoteExtension"));
    assert!(!src.contains("generate_with_dealer"));
    assert!(!src.contains("FrostGroup::dealer"));
    assert!(src.contains("resolver_dkg_share_from_ws_delivery"));
    assert!(src.contains("resolver_dkg_share_from_ws_delivery_with_grant_query"));
    assert!(src.contains("from_part3_identity"));
    assert!(src.contains("grant_view_from_query_json"));
    assert!(src.contains("collect_flattened_wasm_groups"));
    assert!(src.contains("tx.hash"));
    assert!(src.contains("grant_query_matches_ws_close"));
    let lc = include_str!("../src/zap1_lc.rs");
    assert!(!lc.contains("store+query on a spawned Terp"));
    assert!(lc.contains("Does not store `cw-zap1-ibcv2.wasm`"));
    assert!(lc.contains("not 08-wasm store"));
    assert!(lc.contains("Vote-extension actions never authorize"));
    let helper = include_str!("../src/bin/pir-zap1-lc.rs");
    assert!(
        helper.contains("--attest-close") && helper.contains("CloseEventAttest"),
        "pir-zap1-lc must re-bind Close attrs (not ignore --attest-close)"
    );
    let plan = include_str!("../docs/ESCROW_CLOSE_PLAN.md");
    assert!(plan.contains("Vote extensions are out"));
}

#[test]
fn resolver_ws_public_earned_leak_cannot_parse() {
    let (cell, attrs) = closed_cell();
    let cell_hex = hex::encode(attrs.cell_id);
    let err = CloseEventAttrs::from_wasm_attributes([
        ("action", "close"),
        ("cell_id", cell_hex.as_str()),
        ("closer", "tenant"),
        ("earned_zat", "30"),
        ("remainder_zat", "50"),
        ("settle", "grant_only"),
    ])
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
    let err = CloseEventAttrs::from_wasm_attributes([
        ("action", "close"),
        ("cell_id", cell_hex.as_str()),
        ("closer", "tenant"),
        ("remainder_zat", "80"),
    ])
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
    let _ = cell;
}

#[test]
fn resolver_dkg_share_requires_grant_query_matching_view() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"grant-q"]);
    let tx = tagged_hash(b"tx", &[b"grant-q"]);
    let json = comet_close_json(&attrs, header, tx);
    let grant_json = grant_query_json(&cell);
    let view = grant_view_from_query_json(&grant_json).unwrap();
    assert_eq!(view.earned_zat, 0);
    assert_eq!(view.remainder_zat, 80);
    assert!(view.recorded);
    let token = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &json,
        &grant_json,
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);

    let mut leaked = view.clone();
    leaked.earned_zat = 30;
    leaked.remainder_zat = 50;
    let bad = serde_json::to_string(&leaked).unwrap();
    assert_eq!(
        grant_view_from_query_json(&bad).unwrap_err(),
        ResolverNoticeError::AttestFailed
    );
    let err = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &json,
        &bad,
        header,
        tx,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);

    let mut other = view;
    other.closer = EscrowParty::Provider;
    let mismatch = serde_json::to_string(&other).unwrap();
    let err = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &json,
        &mismatch,
        header,
        tx,
    )
    .unwrap_err();
    assert_eq!(
        err,
        ResolverNoticeError::Grant(ResolverShareError::GrantMismatch)
    );
}

#[test]
fn resolver_ws_json_without_hashes_cannot_authorize() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"no-hash"]);
    let tx = tagged_hash(b"tx", &[b"no-hash"]);
    let json = serde_json::json!({
        "events": [{
            "type": "wasm",
            "attributes": [
                {"key": "action", "value": "close"},
                {"key": "cell_id", "value": hex::encode(attrs.cell_id)},
                {"key": "closer", "value": "tenant"},
                {"key": "remainder_zat", "value": attrs.remainder_zat.to_string()},
                {"key": "settle", "value": "grant_only"}
            ]
        }]
    })
    .to_string();
    assert_eq!(
        ResolverNotice::from_ws_json(&json, header, tx).unwrap_err(),
        ResolverNoticeError::AttestFailed
    );
    let err = resolver_dkg_share_from_ws_delivery(&cell, &resolver_share(), &json, header, tx)
        .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
}

#[test]
fn require_close_event_lc_rejects_tampered_app_data_hash() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    let header = tagged_hash(b"hdr", &[b"tamper-app"]);
    let tx = tagged_hash(b"tx", &[b"tamper-app"]);
    let attrs = CloseEventAttrs {
        action: CloseAction::Close,
        cell_id: [4u8; 32],
        closer: EscrowParty::Tenant,
        earned_zat: 0,
        remainder_zat: 80,
    };
    let attest = CloseEventAttest::bind(header, tx, &attrs);
    let mut req = CloseEventLcRequest::bind(
        header,
        tx,
        attest.app_data_hash,
        "close",
        attrs.cell_id,
        "tenant",
        0,
        80,
    );
    req.app_data_hash_hex = hex::encode([9u8; 32]);
    assert_eq!(require_close_event_lc(&req), Err(Zap1LcError::Rejected));
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
}

#[test]
fn resolver_ws_delivery_lc_helper_rebinds_close_attrs() {
    let _g = ENV_LOCK.lock().unwrap();
    let bin = pir_zap1_lc_bin().expect("pir-zap1-lc bin (LC-class Close rebind, not 08-wasm store)");
    std::env::set_var(ENV_ZAP1_LC_BIN, &bin);
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"ws-lc-ok"]);
    let tx = tagged_hash(b"tx", &[b"ws-lc-ok"]);
    let json = comet_close_json(&attrs, header, tx);
    let token = resolver_dkg_share_from_ws_delivery(&cell, &resolver_share(), &json, header, tx)
        .expect("WS delivery + LC helper must re-bind Close attrs");
    assert_ne!(token, [0u8; 32]);
    let grant_json = grant_query_json(&cell);
    let wrapped = serde_json::json!({ "data": serde_json::from_str::<serde_json::Value>(&grant_json).unwrap() })
        .to_string();
    let token2 = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &json,
        &wrapped,
        header,
        tx,
    )
    .expect("Grant query + WS + LC helper");
    assert_eq!(token, token2);
    let other_header = tagged_hash(b"hdr", &[b"ws-lc-other"]);
    let other_tx = tagged_hash(b"tx", &[b"ws-lc-other"]);
    let other_json = comet_close_json(&attrs, other_header, other_tx);
    let other = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &other_json,
        other_header,
        other_tx,
    )
    .unwrap();
    assert_ne!(token, other);
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
}

fn b64(s: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let n = (b.len() - i).min(3);
        let x = (b[i] as u32) << 16
            | if n > 1 { (b[i + 1] as u32) << 8 } else { 0 }
            | if n > 2 { b[i + 2] as u32 } else { 0 };
        out.push(T[((x >> 18) & 63) as usize] as char);
        out.push(T[((x >> 12) & 63) as usize] as char);
        if n > 1 {
            out.push(T[((x >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if n > 2 {
            out.push(T[(x & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

#[test]
fn resolver_ws_grant_hashes_gate_dkg_share() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs, pubv) = closed_cell_with_accrual();
    let header = tagged_hash(b"hdr", &[b"acc-ws"]);
    let tx = tagged_hash(b"tx", &[b"acc-ws"]);
    let missing = comet_close_json(&attrs, header, tx);
    let err = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &missing,
        header,
        tx,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);

    let json = comet_close_json_grant(&attrs, header, tx, Some(&pubv));
    let token = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &json,
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);

    let grant_json = grant_query_json(&cell);
    let token2 = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &json,
        &grant_json,
        header,
        tx,
    )
    .unwrap();
    assert_eq!(token, token2);

    let mut tampered = pubv.clone();
    tampered.close_header_hash = hex::encode(tagged_hash(b"hdr", &[b"tamper-close"]));
    let bad = comet_close_json_grant(&attrs, header, tx, Some(&tampered));
    let err = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &bad,
        &grant_json,
        header,
        tx,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
}

#[test]
fn resolver_ws_flattened_comet_events_grant_gate() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs, pubv) = closed_cell_with_accrual();
    let header = tagged_hash(b"hdr", &[b"flat-ws"]);
    let tx = tagged_hash(b"tx", &[b"flat-ws"]);
    let json = serde_json::json!({
        "result": {
            "data": {
                "TxResult": {
                    "tx.hash": hex::encode(tx),
                    "header.hash": hex::encode(header),
                    "events": {
                        "tm.event": ["Tx"],
                        "wasm.action": ["close"],
                        "wasm.cell_id": [hex::encode(attrs.cell_id)],
                        "wasm.closer": ["tenant"],
                        "wasm.remainder_zat": [attrs.remainder_zat.to_string()],
                        "wasm.settle": ["grant_only"],
                        "wasm.accrual_commitment": [pubv.accrual_commitment],
                        "wasm.open_header_hash": [pubv.open_header_hash],
                        "wasm.close_header_hash": [pubv.close_header_hash]
                    }
                }
            }
        }
    })
    .to_string();
    let token = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &json,
        &grant_query_json(&cell),
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_ws_base64_abci_attrs_grant_gate() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs, pubv) = closed_cell_with_accrual();
    let header = tagged_hash(b"hdr", &[b"b64-ws"]);
    let tx = tagged_hash(b"tx", &[b"b64-ws"]);
    let json = serde_json::json!({
        "txhash": hex::encode(tx),
        "header_hash": hex::encode(header),
        "events": [{
            "type": "wasm",
            "attributes": [
                {"key": b64("action"), "value": b64("close")},
                {"key": b64("cell_id"), "value": b64(&hex::encode(attrs.cell_id))},
                {"key": b64("closer"), "value": b64("tenant")},
                {"key": b64("remainder_zat"), "value": b64(&attrs.remainder_zat.to_string())},
                {"key": b64("settle"), "value": b64("grant_only")},
                {"key": b64("accrual_commitment"), "value": b64(&pubv.accrual_commitment)},
                {"key": b64("open_header_hash"), "value": b64(&pubv.open_header_hash)},
                {"key": b64("close_header_hash"), "value": b64(&pubv.close_header_hash)}
            ]
        }]
    })
    .to_string();
    let token = resolver_dkg_share_from_ws_delivery(
        &cell,
        &resolver_share(),
        &json,
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn require_close_event_lc_rejects_bad_grant_public_hashes() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    let header = tagged_hash(b"hdr", &[b"lc-gp"]);
    let tx = tagged_hash(b"tx", &[b"lc-gp"]);
    let attrs = CloseEventAttrs {
        action: CloseAction::Close,
        cell_id: [4u8; 32],
        closer: EscrowParty::Tenant,
        earned_zat: 0,
        remainder_zat: 80,
    };
    let attest = CloseEventAttest::bind(header, tx, &attrs);
    let collide = CloseEventLcRequest::bind(
        header,
        tx,
        attest.app_data_hash,
        "close",
        attrs.cell_id,
        "tenant",
        0,
        80,
    )
    .with_grant_public(hex::encode([7u8; 32]), hex::encode([8u8; 32]), hex::encode([8u8; 32]));
    assert_eq!(require_close_event_lc(&collide), Err(Zap1LcError::Rejected));
    let partial = CloseEventLcRequest::bind(
        header,
        tx,
        attest.app_data_hash,
        "close",
        attrs.cell_id,
        "tenant",
        0,
        80,
    )
    .with_grant_public(hex::encode([7u8; 32]), String::new(), hex::encode([9u8; 32]));
    assert_eq!(require_close_event_lc(&partial), Err(Zap1LcError::Rejected));
    let ok = CloseEventLcRequest::bind(
        header,
        tx,
        attest.app_data_hash,
        "close",
        attrs.cell_id,
        "tenant",
        0,
        80,
    )
    .with_grant_public(hex::encode([7u8; 32]), hex::encode([8u8; 32]), hex::encode([9u8; 32]));
    match require_close_event_lc(&ok) {
        Err(Zap1LcError::Spawn(s)) => {
            assert!(s.contains("PIR_ZAP1_LC_BIN"));
            assert!(s.contains("not 08-wasm store"));
        }
        other => panic!("expected Spawn after grant-public rebind, got {other:?}"),
    }
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
}

#[test]
fn resolver_dkg_share_lc_verifies_grant_public_close_attrs() {
    let _g = ENV_LOCK.lock().unwrap();
    let bin = pir_zap1_lc_bin().expect("pir-zap1-lc bin (LC-class Close rebind, not 08-wasm store)");
    std::env::set_var(ENV_ZAP1_LC_BIN, &bin);
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    let (cell, attrs, pubv) = closed_cell_with_accrual();
    let header = tagged_hash(b"hdr", &[b"lc-acc"]);
    let tx = tagged_hash(b"tx", &[b"lc-acc"]);
    let json = comet_close_json_grant(&attrs, header, tx, Some(&pubv));
    let token = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &json,
        &grant_query_json(&cell),
        header,
        tx,
    )
    .expect("WS + grant query + LC helper rebind Close attrs including grant hashes");
    assert_ne!(token, [0u8; 32]);
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
}

#[test]
fn from_wasm_attributes_rejects_partial_grant_hashes() {
    let cell_hex = hex::encode([4u8; 32]);
    let acc = hex::encode([7u8; 32]);
    let err = CloseEventAttrs::from_wasm_attributes([
        ("action", "close"),
        ("cell_id", cell_hex.as_str()),
        ("closer", "tenant"),
        ("remainder_zat", "80"),
        ("settle", "grant_only"),
        ("accrual_commitment", acc.as_str()),
    ])
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
}

#[test]
fn grant_view_query_rejects_colliding_header_hashes() {
    let (cell, _, _) = closed_cell_with_accrual();
    let mut view = cell.grant.as_ref().unwrap().view();
    view.close_header_hash = view.open_header_hash.clone();
    let bad = serde_json::to_string(&view).unwrap();
    assert_eq!(
        grant_view_from_query_json(&bad).unwrap_err(),
        ResolverNoticeError::AttestFailed
    );
}

#[test]
fn resolver_comet_ws_array_hashes_grant_gate_dkg_share() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs, view) = closed_cell_with_accrual();
    let header = tagged_hash(b"hdr", &[b"comet-arr"]);
    let tx = tagged_hash(b"tx", &[b"comet-arr"]);
    let json = comet_ws_array_json(&attrs, Some(&view), header, tx);
    let (h, t) = CloseEventAttrs::hashes_from_comet_json(&json).unwrap();
    assert_eq!(h, header);
    assert_eq!(t, tx);
    let token = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &json,
        &grant_query_json(&cell),
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_flattened_wasm_events_grant_gate_dkg_share() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs, view) = closed_cell_with_accrual();
    let header = tagged_hash(b"hdr", &[b"flat-wasm"]);
    let tx = tagged_hash(b"tx", &[b"flat-wasm"]);
    let json = serde_json::json!({
        "result": {
            "events": {
                "tm.event": ["Tx"],
                "tx.hash": [hex::encode(tx)],
                "header.hash": [hex::encode(header)],
                "wasm.action": [action_str(attrs.action)],
                "wasm.cell_id": [hex::encode(attrs.cell_id)],
                "wasm.closer": [closer_str(attrs.closer)],
                "wasm.remainder_zat": [attrs.remainder_zat.to_string()],
                "wasm.settle": ["grant_only"],
                "wasm.accrual_commitment": [view.accrual_commitment],
                "wasm.open_header_hash": [view.open_header_hash],
                "wasm.close_header_hash": [view.close_header_hash]
            }
        }
    })
    .to_string();
    let token = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &json,
        &grant_query_json(&cell),
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_grant_query_rejects_ws_missing_or_mismatched_accrual_hashes() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs, view) = closed_cell_with_accrual();
    let header = tagged_hash(b"hdr", &[b"grant-h"]);
    let tx = tagged_hash(b"tx", &[b"grant-h"]);
    let missing = comet_close_json(&attrs, header, tx);
    let err = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &missing,
        &grant_query_json(&cell),
        header,
        tx,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);

    let mut bad = view.clone();
    bad.open_header_hash = hex::encode(tagged_hash(b"hdr", &[b"other-open"]));
    let mismatched = comet_close_json_with_grant(&attrs, Some(&bad), header, tx);
    let err = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &mismatched,
        &grant_query_json(&cell),
        header,
        tx,
    )
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);

    let ok = comet_close_json_with_grant(&attrs, Some(&view), header, tx);
    let token = resolver_dkg_share_from_ws_delivery_with_grant_query(
        &cell,
        &resolver_share(),
        &ok,
        &grant_query_json(&cell),
        header,
        tx,
    )
    .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_ws_last_block_id_hash_is_not_close_header_or_tx() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"this-block"]);
    let tx = tagged_hash(b"tx", &[b"this-tx"]);
    let prev = tagged_hash(b"hdr", &[b"prev-block"]);
    let json = serde_json::json!({
        "result": {
            "data": {
                "value": {
                    "header": {
                        "hash": hex::encode(header),
                        "last_block_id": { "hash": hex::encode(prev) }
                    },
                    "TxResult": {
                        "result": {
                            "events": [{
                                "type": "wasm",
                                "attributes": wasm_close_attributes(&attrs, None)
                            }]
                        }
                    }
                }
            },
            "events": { "tx.hash": [hex::encode(tx)] }
        }
    })
    .to_string();
    let (h, t) = CloseEventAttrs::hashes_from_comet_json(&json).unwrap();
    assert_eq!(h, header);
    assert_eq!(t, tx);
    assert_ne!(h, prev);
    let token = resolver_dkg_share_from_ws_delivery(&cell, &resolver_share(), &json, header, tx)
        .unwrap();
    assert_ne!(token, [0u8; 32]);
}

#[test]
fn resolver_flattened_vote_extension_cannot_authorize_share() {
    let _g = ENV_LOCK.lock().unwrap();
    fixture_lc_off();
    let (cell, attrs) = closed_cell();
    let header = tagged_hash(b"hdr", &[b"flat-ve"]);
    let tx = tagged_hash(b"tx", &[b"flat-ve"]);
    let json = serde_json::json!({
        "result": {
            "events": {
                "vote_extension.action": ["close"],
                "vote_extension.cell_id": [hex::encode(attrs.cell_id)],
                "vote_extension.closer": ["tenant"],
                "vote_extension.remainder_zat": [attrs.remainder_zat.to_string()],
                "vote_extension.settle": ["grant_only"],
                "tx.hash": [hex::encode(tx)],
                "header.hash": [hex::encode(header)]
            }
        }
    })
    .to_string();
    assert_eq!(
        CloseEventAttrs::from_comet_json(&json).unwrap_err(),
        ResolverNoticeError::AttestFailed
    );
    let err = resolver_dkg_share_from_ws_delivery(&cell, &resolver_share(), &json, header, tx)
        .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
}

#[test]
fn require_close_event_lc_rejects_non_grant_only_settle() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var(ENV_ZAP1_REQUIRE_CHAIN, "1");
    std::env::remove_var(ENV_ZAP1_LC_BIN);
    let mut req = CloseEventLcRequest::bind(
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        "close",
        [4u8; 32],
        "tenant",
        0,
        80,
    );
    req.settle = "bank_send".into();
    assert_eq!(require_close_event_lc(&req), Err(Zap1LcError::Rejected));
    req.settle = String::new();
    assert_eq!(require_close_event_lc(&req), Err(Zap1LcError::Rejected));
    std::env::remove_var(ENV_ZAP1_REQUIRE_CHAIN);
}

#[test]
fn resolver_ws_partial_grant_hashes_cannot_parse() {
    let (cell, attrs, view) = closed_cell_with_accrual();
    let cell_hex = hex::encode(attrs.cell_id);
    let err = CloseEventAttrs::from_wasm_attributes([
        ("action", "close"),
        ("cell_id", cell_hex.as_str()),
        ("closer", "tenant"),
        ("remainder_zat", "80"),
        ("settle", "grant_only"),
        ("accrual_commitment", view.accrual_commitment.as_str()),
    ])
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
    let same = hex::encode([9u8; 32]);
    let err = CloseEventAttrs::from_wasm_attributes([
        ("action", "close"),
        ("cell_id", cell_hex.as_str()),
        ("closer", "tenant"),
        ("remainder_zat", "80"),
        ("settle", "grant_only"),
        ("accrual_commitment", view.accrual_commitment.as_str()),
        ("open_header_hash", same.as_str()),
        ("close_header_hash", same.as_str()),
    ])
    .unwrap_err();
    assert_eq!(err, ResolverNoticeError::AttestFailed);
    let _ = cell;
}
