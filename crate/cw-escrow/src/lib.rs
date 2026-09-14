use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult,
};
use cw_storage_plus::Map;
use serde::{Deserialize, Serialize};

pub mod msg;
pub use msg::{CellResp, ExecuteMsg, GrantResp, InstantiateMsg, Party, QueryMsg};

#[cfg(target_arch = "wasm32")]
mod zk_host;

#[cfg(not(target_arch = "wasm32"))]
mod interface;
#[cfg(not(target_arch = "wasm32"))]
pub use interface::CwPirEscrowContract;

/// Path A zkid for `pir-accrual.f.v1`. HOSTING_PAYMENT inclusion is 1.
const ACCRUAL_ZKID: u64 = 2;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Cell {
    deposit_zat: u64,
    bid_commitment: String,
    tenant: String,
    provider: String,
    resolver: String,
    earned_zat: u64,
    closed: bool,
    closer: Option<Party>,
    remainder_zat: Option<u64>,
    denom: String,
    accrual_commitment: Option<String>,
    open_header_hash: Option<String>,
    close_header_hash: Option<String>,
    #[serde(default)]
    halo2_instances: Option<String>,
    #[serde(default)]
    halo2_verified: bool,
}

const CELLS: Map<&str, Cell> = Map::new("cells");

fn require_hex32(s: &str) -> StdResult<()> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StdError::generic_err("must be 32-byte hex"));
    }
    Ok(())
}

/// Same Pallas waist as `AccrualPublic::zk_instance_bytes` (clear top two bits).
fn pack_fe32(bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = *bytes;
    out[31] &= 0x3f;
    out
}

fn decode_hex32(s: &str) -> StdResult<[u8; 32]> {
    require_hex32(s)?;
    let b = hex::decode(s).map_err(|_| StdError::generic_err("must be 32-byte hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

/// 96-byte Halo2 instances of `f`: packed commitment || open header || close header.
fn encode_halo2_instances(commitment: &str, open_h: &str, close_h: &str) -> StdResult<String> {
    let mut out = [0u8; 96];
    out[0..32].copy_from_slice(&pack_fe32(&decode_hex32(commitment)?));
    out[32..64].copy_from_slice(&pack_fe32(&decode_hex32(open_h)?));
    out[64..96].copy_from_slice(&pack_fe32(&decode_hex32(close_h)?));
    Ok(hex::encode(out))
}

fn party_str(p: Party) -> &'static str {
    match p {
        Party::Tenant => "tenant",
        Party::Provider => "provider",
    }
}

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    Ok(Response::new())
}

#[entry_point]
pub fn execute(deps: DepsMut, _env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::OpenCell {
            bid_commitment,
            tenant,
            provider,
            resolver,
            deposit_zat,
        } => open(
            deps,
            info,
            bid_commitment,
            tenant,
            provider,
            resolver,
            deposit_zat,
        ),
        ExecuteMsg::Accrue {
            cell_id,
            commitment,
            open_header_hash,
            close_header_hash,
        } => accrue(deps, cell_id, commitment, open_header_hash, close_header_hash),
        ExecuteMsg::VerifyAccrualHalo2 {
            cell_id,
            zkid,
            proof,
        } => verify_accrual_halo2(deps, cell_id, zkid, proof),
        ExecuteMsg::Close { cell_id, party } => close(deps, info, cell_id, party, "close"),
        ExecuteMsg::Dispute { cell_id, party } => close(deps, info, cell_id, party, "dispute"),
    }
}

fn open(
    deps: DepsMut,
    info: MessageInfo,
    bid_commitment: String,
    tenant: String,
    provider: String,
    resolver: String,
    deposit_zat: u64,
) -> StdResult<Response> {
    require_hex32(&bid_commitment)?;
    if tenant.is_empty() || provider.is_empty() || resolver.is_empty() {
        return Err(StdError::generic_err("empty member"));
    }
    if info.funds.iter().any(|c| !c.amount.is_zero()) {
        return Err(StdError::generic_err(
            "OpenCell rejects bank funds; deposit is Zcash notes (deposit_zat accounting only)",
        ));
    }
    if deposit_zat == 0 {
        return Err(StdError::generic_err("zero deposit"));
    }
    let cell_id = hex::encode(sha_like(
        deposit_zat,
        &bid_commitment,
        &tenant,
        &provider,
        &resolver,
    ));
    if CELLS.may_load(deps.storage, &cell_id)?.is_some() {
        return Err(StdError::generic_err("cell exists"));
    }
    CELLS.save(
        deps.storage,
        &cell_id,
        &Cell {
            deposit_zat,
            bid_commitment,
            tenant,
            provider,
            resolver,
            earned_zat: 0,
            closed: false,
            closer: None,
            remainder_zat: None,
            denom: "zat".into(),
            accrual_commitment: None,
            open_header_hash: None,
            close_header_hash: None,
            halo2_instances: None,
            halo2_verified: false,
        },
    )?;
    Ok(Response::new()
        .add_attribute("action", "open_cell")
        .add_attribute("cell_id", cell_id)
        .add_attribute("deposit_zat", deposit_zat.to_string())
        .add_attribute("denom", "zat"))
}

/// Same domain as in-process `escrow-cell-v1` is SHA-256; contract uses the same tag.
fn sha_like(deposit: u64, bid: &str, tenant: &str, provider: &str, resolver: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let tag = b"escrow-cell-v1";
    h.update(tag);
    h.update(&[tag.len() as u8]);
    for p in [
        deposit.to_le_bytes().as_slice(),
        &hex::decode(bid).unwrap_or_default(),
        tenant.as_bytes(),
        provider.as_bytes(),
        resolver.as_bytes(),
    ] {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

fn accrue(
    deps: DepsMut,
    cell_id: String,
    commitment: String,
    open_header_hash: String,
    close_header_hash: String,
) -> StdResult<Response> {
    let mut c = CELLS
        .may_load(deps.storage, &cell_id)?
        .ok_or_else(|| StdError::generic_err("unknown cell"))?;
    if c.closed {
        return Err(StdError::generic_err("already closed"));
    }
    require_hex32(&commitment)?;
    require_hex32(&open_header_hash)?;
    require_hex32(&close_header_hash)?;
    if open_header_hash == close_header_hash {
        return Err(StdError::generic_err("open and close headers must differ"));
    }
    let halo2_instances = encode_halo2_instances(&commitment, &open_header_hash, &close_header_hash)?;
    c.accrual_commitment = Some(commitment.clone());
    c.open_header_hash = Some(open_header_hash.clone());
    c.close_header_hash = Some(close_header_hash.clone());
    c.halo2_instances = Some(halo2_instances.clone());
    c.halo2_verified = false;
    CELLS.save(deps.storage, &cell_id, &c)?;
    Ok(Response::new()
        .add_attribute("action", "accrue")
        .add_attribute("accrual_commitment", commitment)
        .add_attribute("open_header_hash", open_header_hash)
        .add_attribute("close_header_hash", close_header_hash)
        .add_attribute("halo2_instances", halo2_instances)
        .add_attribute("halo2_verified", "false")
        .add_attribute("earned_zat", "0"))
}

fn verify_accrual_halo2(
    deps: DepsMut,
    cell_id: String,
    zkid: u64,
    proof: Binary,
) -> StdResult<Response> {
    let mut c = CELLS
        .may_load(deps.storage, &cell_id)?
        .ok_or_else(|| StdError::generic_err("unknown cell"))?;
    if c.closed {
        return Err(StdError::generic_err("already closed"));
    }
    let inst_hex = c
        .halo2_instances
        .clone()
        .ok_or_else(|| StdError::generic_err("accrue commitment required before halo2 verify"))?;
    if inst_hex.len() != 192 {
        return Err(StdError::generic_err(
            "Halo2 instances of f() required before proof_instance_verify",
        ));
    }
    if proof.is_empty() {
        return Err(StdError::generic_err("empty halo2 proof"));
    }
    if proof.as_slice().starts_with(b"DSTW") {
        return Err(StdError::generic_err("DummyStwo proofs are forbidden"));
    }
    if proof.len() < 64 {
        return Err(StdError::generic_err("invalid halo2 proof"));
    }
    if zkid != ACCRUAL_ZKID {
        return Err(StdError::generic_err(
            "HOSTING_PAYMENT zkid is not f(); use pir-accrual.f.v1",
        ));
    }
    let inst = hex::decode(&inst_hex).map_err(|_| StdError::generic_err("halo2 instances hex"))?;
    if inst.len() != 96 {
        return Err(StdError::generic_err("accrual instances must be 96 bytes"));
    }
    let ok = {
        #[cfg(not(target_arch = "wasm32"))]
        {
            hosting_payment::proof_instance_verify(zkid, proof.as_slice(), inst.as_slice())
                .map_err(StdError::generic_err)?
        }
        #[cfg(target_arch = "wasm32")]
        {
            zk_host::verify(zkid, proof.as_slice(), inst.as_slice())?
        }
    };
    if !ok {
        return Err(StdError::generic_err("halo2 proof_instance_verify rejected"));
    }
    c.halo2_verified = true;
    CELLS.save(deps.storage, &cell_id, &c)?;
    Ok(Response::new()
        .add_attribute("action", "verify_accrual_halo2")
        .add_attribute("halo2_instances", inst_hex)
        .add_attribute("halo2_verified", "true")
        .add_attribute("zkid", zkid.to_string())
        .add_attribute("earned_zat", "0"))
}

fn close(
    deps: DepsMut,
    _info: MessageInfo,
    cell_id: String,
    party: Party,
    action: &str,
) -> StdResult<Response> {
    let mut c = CELLS
        .may_load(deps.storage, &cell_id)?
        .ok_or_else(|| StdError::generic_err("unknown cell"))?;
    if c.closed {
        return Err(StdError::generic_err("already closed"));
    }
    let commitment = c
        .accrual_commitment
        .clone()
        .ok_or_else(|| StdError::generic_err("accrue commitment required before close"))?;
    let open_h = c.open_header_hash.clone().unwrap_or_default();
    let close_h = c.close_header_hash.clone().unwrap_or_default();
    let halo2 = c.halo2_instances.clone().unwrap_or_default();
    if halo2.len() != 192 {
        return Err(StdError::generic_err(
            "Halo2 instances of f() required before close (fail-closed missing proof waist)",
        ));
    }
    let verified = if c.halo2_verified { "true" } else { "false" };
    // Split is private; on-chain remainder is the full deposit accounting.
    let remainder = c.deposit_zat;
    c.closed = true;
    c.closer = Some(party);
    c.remainder_zat = Some(remainder);
    CELLS.save(deps.storage, &cell_id, &c)?;

    // Grant + events only. Value lives in DKG-owned Zcash notes, not BankMsg / uterp.
    Ok(Response::new()
        .add_attribute("action", action)
        .add_attribute("cell_id", cell_id)
        .add_attribute("closer", party_str(party))
        .add_attribute("accrual_commitment", commitment)
        .add_attribute("open_header_hash", open_h)
        .add_attribute("close_header_hash", close_h)
        .add_attribute("halo2_instances", halo2)
        .add_attribute("halo2_verified", verified)
        .add_attribute("earned_zat", "0")
        .add_attribute("remainder_zat", remainder.to_string())
        .add_attribute("settle", "grant_only"))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Grant { cell_id } => {
            let c = CELLS
                .may_load(deps.storage, &cell_id)?
                .ok_or_else(|| StdError::generic_err("unknown cell"))?;
            if !c.closed {
                return Err(StdError::generic_err("no grant"));
            }
            to_json_binary(&GrantResp {
                cell_id,
                closer: c.closer.unwrap(),
                earned_zat: 0,
                remainder_zat: c.remainder_zat.unwrap_or(c.deposit_zat),
                recorded: true,
                accrual_commitment: c.accrual_commitment.unwrap_or_default(),
                open_header_hash: c.open_header_hash.unwrap_or_default(),
                close_header_hash: c.close_header_hash.unwrap_or_default(),
                halo2_instances: c.halo2_instances.unwrap_or_default(),
                halo2_verified: c.halo2_verified,
            })
        }
        QueryMsg::Cell { cell_id } => {
            let c = CELLS
                .may_load(deps.storage, &cell_id)?
                .ok_or_else(|| StdError::generic_err("unknown cell"))?;
            to_json_binary(&CellResp {
                cell_id,
                deposit_zat: c.deposit_zat,
                bid_commitment: c.bid_commitment,
                tenant: c.tenant,
                provider: c.provider,
                resolver: c.resolver,
                earned_zat: 0,
                closed: c.closed,
                denom: c.denom,
                accrual_commitment: c.accrual_commitment.unwrap_or_default(),
                open_header_hash: c.open_header_hash.unwrap_or_default(),
                close_header_hash: c.close_header_hash.unwrap_or_default(),
                halo2_instances: c.halo2_instances.unwrap_or_default(),
                halo2_verified: c.halo2_verified,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_json, Binary, Coin, Uint128};

    fn bid_hex() -> String {
        hex::encode([7u8; 32])
    }

    fn open_ok(deps: DepsMut) -> String {
        let res = execute(
            deps,
            mock_env(),
            mock_info("funder", &[]),
            ExecuteMsg::OpenCell {
                bid_commitment: bid_hex(),
                tenant: "tenant1".into(),
                provider: "provider1".into(),
                resolver: "resolver1".into(),
                deposit_zat: 100,
            },
        )
        .unwrap();
        attr(&res, "cell_id")
    }

    fn attr(res: &Response, key: &str) -> String {
        res.attributes
            .iter()
            .find(|a| a.key == key)
            .map(|a| a.value.clone())
            .unwrap()
    }

    #[test]
    fn close_emits_grant_events_not_bank() {
        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("a", &[]), InstantiateMsg {}).unwrap();
        let cell_id = open_ok(deps.as_mut());
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::Accrue {
                cell_id: cell_id.clone(),
                commitment: "aa".repeat(32),
                open_header_hash: "bb".repeat(32),
                close_header_hash: "cc".repeat(32),
            },
        )
        .unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("tenant1", &[]),
            ExecuteMsg::Close {
                cell_id: cell_id.clone(),
                party: Party::Tenant,
            },
        )
        .unwrap();
        assert_eq!(attr(&res, "action"), "close");
        assert_eq!(attr(&res, "accrual_commitment"), "aa".repeat(32));
        assert_eq!(attr(&res, "earned_zat"), "0");
        assert_eq!(attr(&res, "halo2_instances").len(), 192);
        assert_eq!(attr(&res, "halo2_verified"), "false");
        assert_eq!(attr(&res, "settle"), "grant_only");
        assert!(
            res.messages.is_empty(),
            "close must not BankMsg; Zcash notes move value"
        );
        let grant: GrantResp = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Grant {
                    cell_id: cell_id.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(grant.recorded);
        assert_eq!(grant.earned_zat, 0);
        assert_eq!(grant.remainder_zat, 100);
        assert_eq!(grant.accrual_commitment, "aa".repeat(32));
        assert_eq!(grant.halo2_instances.len(), 192);
        assert!(!grant.halo2_verified, "Accrue without proof is not verified");
        assert_eq!(grant.closer, Party::Tenant);
        let cell: CellResp = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Cell { cell_id },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(cell.earned_zat, 0);
        assert_eq!(cell.halo2_instances, grant.halo2_instances);
    }

    #[test]
    fn accrue_emits_halo2_instances_not_earned() {
        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("a", &[]), InstantiateMsg {}).unwrap();
        let cell_id = open_ok(deps.as_mut());
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::Accrue {
                cell_id: cell_id.clone(),
                commitment: "aa".repeat(32),
                open_header_hash: "bb".repeat(32),
                close_header_hash: "cc".repeat(32),
            },
        )
        .unwrap();
        assert_eq!(attr(&res, "earned_zat"), "0");
        let inst = attr(&res, "halo2_instances");
        assert_eq!(inst.len(), 192);
        let want = encode_halo2_instances(
            &"aa".repeat(32),
            &"bb".repeat(32),
            &"cc".repeat(32),
        )
        .unwrap();
        assert_eq!(inst, want);
        assert_eq!(&inst[126..128], "3b", "open header must be Pallas-packed");
        assert_eq!(&inst[190..192], "0c", "close header must be Pallas-packed");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("tenant1", &[]),
            ExecuteMsg::Close {
                cell_id: "missing".into(),
                party: Party::Tenant,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown cell"));
    }

    #[test]
    fn halo2_instances_match_circuit_waist() {
        let c = [0xaau8; 32];
        let o = [0xbbu8; 32];
        let cl = [0xccu8; 32];
        let want = hosting_payment::encode_accrual_instances(&c, &o, &cl);
        let got = hex::decode(
            encode_halo2_instances(&hex::encode(c), &hex::encode(o), &hex::encode(cl)).unwrap(),
        )
        .unwrap();
        assert_eq!(got.as_slice(), want.as_slice());
        assert_eq!(got.len(), 96);
        assert_eq!(hosting_payment::ACCRUAL_INSTANCE_COUNT, 3);
        assert_eq!(hosting_payment::ACCRUAL_ZKID, ACCRUAL_ZKID);
        assert!(hosting_payment::decode_accrual_instances(&got).is_ok());
        assert!(hosting_payment::decode_instances(&got).is_err());
    }

    #[test]
    fn verify_accrual_halo2_fail_closed_missing_or_wrong_circuit() {
        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("a", &[]), InstantiateMsg {}).unwrap();
        let cell_id = open_ok(deps.as_mut());
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::VerifyAccrualHalo2 {
                cell_id: cell_id.clone(),
                zkid: ACCRUAL_ZKID,
                proof: Binary::from(vec![1u8; 8]),
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("accrue commitment required"),
            "{err}"
        );
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::Accrue {
                cell_id: cell_id.clone(),
                commitment: "aa".repeat(32),
                open_header_hash: "bb".repeat(32),
                close_header_hash: "cc".repeat(32),
            },
        )
        .unwrap();
        let empty = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::VerifyAccrualHalo2 {
                cell_id: cell_id.clone(),
                zkid: ACCRUAL_ZKID,
                proof: Binary::default(),
            },
        )
        .unwrap_err();
        assert!(empty.to_string().contains("empty halo2 proof"), "{empty}");
        let dstw = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::VerifyAccrualHalo2 {
                cell_id: cell_id.clone(),
                zkid: ACCRUAL_ZKID,
                proof: Binary::from(b"DSTW\x01\x02".to_vec()),
            },
        )
        .unwrap_err();
        assert!(dstw.to_string().contains("DummyStwo"), "{dstw}");
        let hp = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::VerifyAccrualHalo2 {
                cell_id: cell_id.clone(),
                zkid: 1,
                proof: Binary::from(vec![1u8; 80]),
            },
        )
        .unwrap_err();
        assert!(
            hp.to_string().contains("HOSTING_PAYMENT"),
            "zkid 1 must not verify f(): {hp}"
        );
        let bogus = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::VerifyAccrualHalo2 {
                cell_id,
                zkid: ACCRUAL_ZKID,
                proof: Binary::from(vec![1u8; 8]),
            },
        )
        .unwrap_err();
        assert!(
            bogus.to_string().contains("invalid halo2 proof"),
            "{bogus}"
        );
    }

    #[test]
    fn close_without_accrue_is_fail_closed() {
        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("a", &[]), InstantiateMsg {}).unwrap();
        let cell_id = open_ok(deps.as_mut());
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("tenant1", &[]),
            ExecuteMsg::Close {
                cell_id,
                party: Party::Tenant,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("accrue commitment required"));
    }

    #[test]
    fn accrue_rejects_earned_zat_field() {
        let raw = r#"{"accrue":{"cell_id":"ab","earned_zat":40}}"#;
        let parsed: Result<ExecuteMsg, _> = from_json(raw.as_bytes());
        assert!(parsed.is_err(), "accrue must not accept closer-supplied earned_zat");
        let with_rate = r#"{"accrue":{"cell_id":"ab","commitment":"aa","open_header_hash":"bb","close_header_hash":"cc","zat_per_height":7}}"#;
        assert!(
            from_json::<ExecuteMsg>(with_rate.as_bytes()).is_err(),
            "rate is private; not an Accrue field"
        );
        let with_dur = r#"{"accrue":{"cell_id":"ab","commitment":"aa","open_header_hash":"bb","close_header_hash":"cc","duration_heights":5}}"#;
        assert!(
            from_json::<ExecuteMsg>(with_dur.as_bytes()).is_err(),
            "duration is private; not an Accrue field"
        );
    }

    #[test]
    fn close_rejects_earned_in_msg_by_not_having_field() {
        let raw = r#"{"close":{"cell_id":"ab","party":"tenant","earned_zat":99}}"#;
        let parsed: Result<ExecuteMsg, _> = from_json(raw.as_bytes());
        assert!(parsed.is_err(), "close must not accept earned_zat");
    }

    #[test]
    fn grant_query_fails_while_open() {
        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("a", &[]), InstantiateMsg {}).unwrap();
        let cell_id = open_ok(deps.as_mut());
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::Grant { cell_id },
        )
        .unwrap_err();
        assert!(err.to_string().contains("no grant"));
    }

    #[test]
    fn dispute_also_writes_grant() {
        let mut deps = mock_dependencies();
        instantiate(deps.as_mut(), mock_env(), mock_info("a", &[]), InstantiateMsg {}).unwrap();
        let cell_id = open_ok(deps.as_mut());
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::Accrue {
                cell_id: cell_id.clone(),
                commitment: "aa".repeat(32),
                open_header_hash: "bb".repeat(32),
                close_header_hash: "cc".repeat(32),
            },
        )
        .unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("x", &[]),
            ExecuteMsg::Dispute {
                cell_id: cell_id.clone(),
                party: Party::Provider,
            },
        )
        .unwrap();
        let grant: GrantResp = from_json(
            query(deps.as_ref(), mock_env(), QueryMsg::Grant { cell_id }).unwrap(),
        )
        .unwrap();
        assert!(grant.recorded);
        assert_eq!(grant.closer, Party::Provider);
    }
}
