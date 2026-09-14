//! ZAP1 IBC v2 *attestation module* for PIR pay inclusion.
//!
//! Stores (source_client, dest_client, sequence) → packet commitment +
//! app_data_hash and verifies a zap1-verify Merkle path for HOSTING_PAYMENT
//! (or sibling event kinds) before accept.
//!
//! This is **not** Crosslink 08-wasm (no header/Ed25519 verify). It is **not**
//! a complete ICS-08 08-wasm host (the nine create/update/misbehaviour/…
//! entrypoints are the next increment). A RAM SHA-256 bind is not this module.

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult,
};
use cw_storage_plus::{Item, Map};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zap1_verify::{compute_leaf_hash, verify_proof, EventPayload, ProofStep, SiblingPosition};

#[cfg(target_arch = "wasm32")]
mod zk_host;

#[cfg(not(target_arch = "wasm32"))]
mod interface;
#[cfg(not(target_arch = "wasm32"))]
pub use interface::CwZap1Ibcv2Contract;

const CLIENTS: Item<ClientPair> = Item::new("clients");
const PACKETS: Map<(&str, &str, u64), StoredPacket> = Map::new("pkts");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClientPair {
    pub source_client: String,
    pub dest_client: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProofStepMsg {
    pub sibling_hex: String,
    pub sibling_is_left: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Record the IBC v2 client pair this module attests for.
    CreateClient {
        source_client: String,
        dest_client: String,
    },
    /// Accept a packet only after zap1-verify + app_data_hash bind.
    AttestPacket {
        source_client: String,
        dest_client: String,
        sequence: u64,
        timeout_timestamp_ns: u64,
        app_data_hash_hex: String,
        note_hex: String,
        amount_zat: u64,
        frost_group_hex: String,
        leaf_hex: String,
        merkle_root_hex: String,
        /// hosting_payment | program_entry | ownership_attest
        event_kind: String,
        wallet_or_serial: String,
        proof: Vec<ProofStepMsg>,
    },
    /// HOSTING_PAYMENT inclusion via Halo2 (zk-wasmvm waist).
    /// Merkle siblings are **not** in this message — only proof + 128-byte instances.
    AttestHalo2 {
        source_client: String,
        dest_client: String,
        sequence: u64,
        timeout_timestamp_ns: u64,
        app_data_hash_hex: String,
        zkid: u64,
        proof: Binary,
        /// 4 × 32 LE field: root, frost, amount_class, HOSTING_PAYMENT kind.
        instances: Binary,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Clients {},
    Packet {
        source_client: String,
        dest_client: String,
        sequence: u64,
    },
    /// True iff stored commitment matches the submitted packet (tamper → false).
    Match {
        source_client: String,
        dest_client: String,
        sequence: u64,
        app_data_hash_hex: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StoredPacket {
    pub sequence: u64,
    pub app_data_hash_hex: String,
    pub packet_commitment_hex: String,
    pub leaf_hex: String,
    pub merkle_root_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MatchResp {
    pub matches: bool,
}

fn hex32(s: &str) -> StdResult<[u8; 32]> {
    let t = s.trim().trim_start_matches("0x");
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(StdError::generic_err("need 32-byte hex"));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(t, &mut out).map_err(|e| StdError::generic_err(e.to_string()))?;
    Ok(out)
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(&[tag.len() as u8]);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(*p);
    }
    h.finalize().into()
}

fn app_data_hash(note: &[u8; 32], amount_zat: u64, frost: &[u8; 32], leaf: &[u8; 32]) -> [u8; 32] {
    tagged_hash(
        b"ibc-v2-zap1-app-v1",
        &[note, &amount_zat.to_le_bytes(), frost, leaf],
    )
}

fn packet_commitment(
    source: &str,
    dest: &str,
    sequence: u64,
    timeout_ns: u64,
    app: &[u8; 32],
) -> [u8; 32] {
    tagged_hash(
        b"ibc-v2-packet-v1",
        &[
            source.as_bytes(),
            dest.as_bytes(),
            &sequence.to_be_bytes(),
            &timeout_ns.to_be_bytes(),
            app,
        ],
    )
}

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    Ok(Response::new().add_attribute("module", "cw-zap1-ibcv2-attest"))
}

#[entry_point]
pub fn execute(deps: DepsMut, _env: Env, _info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::CreateClient {
            source_client,
            dest_client,
        } => {
            if source_client.is_empty() || dest_client.is_empty() {
                return Err(StdError::generic_err("empty client id"));
            }
            CLIENTS.save(
                deps.storage,
                &ClientPair {
                    source_client,
                    dest_client,
                },
            )?;
            Ok(Response::new().add_attribute("action", "create_client"))
        }
        ExecuteMsg::AttestPacket {
            source_client,
            dest_client,
            sequence,
            timeout_timestamp_ns,
            app_data_hash_hex,
            note_hex,
            amount_zat,
            frost_group_hex,
            leaf_hex,
            merkle_root_hex,
            event_kind,
            wallet_or_serial,
            proof,
        } => {
            if sequence == 0 {
                return Err(StdError::generic_err("zero sequence"));
            }
            if let Some(c) = CLIENTS.may_load(deps.storage)? {
                if c.source_client != source_client || c.dest_client != dest_client {
                    return Err(StdError::generic_err("client id mismatch"));
                }
            }
            let note = hex32(&note_hex)?;
            let frost = hex32(&frost_group_hex)?;
            let leaf = hex32(&leaf_hex)?;
            let root = hex32(&merkle_root_hex)?;
            let submitted = hex32(&app_data_hash_hex)?;
            let expect = app_data_hash(&note, amount_zat, &frost, &leaf);
            if submitted != expect {
                return Err(StdError::generic_err("tampered app_data_hash"));
            }
            let payload = match event_kind.as_str() {
                "hosting_payment" => EventPayload::HostingPayment {
                    serial_number: wallet_or_serial.as_bytes(),
                    month: 8,
                    year: 2026,
                },
                "program_entry" => EventPayload::ProgramEntry {
                    wallet_hash: wallet_or_serial.as_bytes(),
                },
                "ownership_attest" => EventPayload::OwnershipAttest {
                    wallet_hash: wallet_or_serial.as_bytes(),
                    serial_number: b"pir-seat",
                },
                _ => return Err(StdError::generic_err("unknown event_kind")),
            };
            let computed = compute_leaf_hash(&payload);
            if computed != leaf {
                return Err(StdError::generic_err("leaf does not match event"));
            }
            let path: StdResult<Vec<ProofStep>> = proof
                .iter()
                .map(|s| {
                    Ok(ProofStep {
                        hash: hex32(&s.sibling_hex)?,
                        position: if s.sibling_is_left {
                            SiblingPosition::Left
                        } else {
                            SiblingPosition::Right
                        },
                    })
                })
                .collect();
            if !verify_proof(&leaf, &path?, &root) {
                return Err(StdError::generic_err("zap1 merkle proof failed"));
            }
            let cmt = packet_commitment(
                &source_client,
                &dest_client,
                sequence,
                timeout_timestamp_ns,
                &submitted,
            );
            if PACKETS
                .may_load(deps.storage, (&source_client, &dest_client, sequence))?
                .is_some()
            {
                return Err(StdError::generic_err("duplicate sequence"));
            }
            PACKETS.save(
                deps.storage,
                (&source_client, &dest_client, sequence),
                &StoredPacket {
                    sequence,
                    app_data_hash_hex: hex::encode(submitted),
                    packet_commitment_hex: hex::encode(cmt),
                    leaf_hex: hex::encode(leaf),
                    merkle_root_hex: hex::encode(root),
                },
            )?;
            Ok(Response::new().add_attribute("action", "attest_packet"))
        }
        ExecuteMsg::AttestHalo2 {
            source_client,
            dest_client,
            sequence,
            timeout_timestamp_ns,
            app_data_hash_hex,
            zkid,
            proof,
            instances,
        } => {
            if sequence == 0 {
                return Err(StdError::generic_err("zero sequence"));
            }
            if let Some(c) = CLIENTS.may_load(deps.storage)? {
                if c.source_client != source_client || c.dest_client != dest_client {
                    return Err(StdError::generic_err("client id mismatch"));
                }
            }
            let submitted = hex32(&app_data_hash_hex)?;
            if instances.len() != 128 {
                return Err(StdError::generic_err("instances must be 128 bytes"));
            }
            if proof.is_empty() {
                return Err(StdError::generic_err("empty halo2 proof"));
            }
            let ok = {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    hosting_payment::proof_instance_verify(
                        zkid,
                        proof.as_slice(),
                        instances.as_slice(),
                    )
                    .map_err(StdError::generic_err)?
                }
                #[cfg(target_arch = "wasm32")]
                {
                    zk_host::verify(zkid, proof.as_slice(), instances.as_slice())?
                }
            };
            if !ok {
                return Err(StdError::generic_err("halo2 proof_instance_verify rejected"));
            }
            let root_hex = hex::encode(&instances.as_slice()[..32]);
            let cmt = packet_commitment(
                &source_client,
                &dest_client,
                sequence,
                timeout_timestamp_ns,
                &submitted,
            );
            if PACKETS
                .may_load(deps.storage, (&source_client, &dest_client, sequence))?
                .is_some()
            {
                return Err(StdError::generic_err("duplicate sequence"));
            }
            PACKETS.save(
                deps.storage,
                (&source_client, &dest_client, sequence),
                &StoredPacket {
                    sequence,
                    app_data_hash_hex: hex::encode(submitted),
                    packet_commitment_hex: hex::encode(cmt),
                    leaf_hex: String::new(),
                    merkle_root_hex: root_hex,
                },
            )?;
            Ok(Response::new()
                .add_attribute("action", "attest_halo2")
                .add_attribute("zkid", zkid.to_string()))
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Clients {} => to_json_binary(&CLIENTS.may_load(deps.storage)?),
        QueryMsg::Packet {
            source_client,
            dest_client,
            sequence,
        } => to_json_binary(
            &PACKETS.may_load(deps.storage, (&source_client, &dest_client, sequence))?,
        ),
        QueryMsg::Match {
            source_client,
            dest_client,
            sequence,
            app_data_hash_hex,
        } => {
            let stored = PACKETS.may_load(deps.storage, (&source_client, &dest_client, sequence))?;
            let want = hex32(&app_data_hash_hex).ok();
            let matches = match (stored, want) {
                (Some(s), Some(w)) => s.app_data_hash_hex == hex::encode(w),
                _ => false,
            };
            to_json_binary(&MatchResp { matches })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_json, Addr};
    use zap1_verify::node_hash;

    #[test]
    fn attest_and_match_rejects_tamper() {
        let mut deps = mock_dependencies();
        let info = mock_info("owner", &[]);
        instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::CreateClient {
                source_client: "08-zap1-src".into(),
                dest_client: "08-terp-dst".into(),
            },
        )
        .unwrap();

        let serial = "PIR-LC-1";
        let leaf = compute_leaf_hash(&EventPayload::HostingPayment {
            serial_number: serial.as_bytes(),
            month: 8,
            year: 2026,
        });
        let sib = compute_leaf_hash(&EventPayload::ProgramEntry {
            wallet_hash: b"sib",
        });
        let root = node_hash(&leaf, &sib);
        let note = [2u8; 32];
        let frost = [3u8; 32];
        let app = app_data_hash(&note, 10, &frost, &leaf);

        execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::AttestPacket {
                source_client: "08-zap1-src".into(),
                dest_client: "08-terp-dst".into(),
                sequence: 1,
                timeout_timestamp_ns: 0,
                app_data_hash_hex: hex::encode(app),
                note_hex: hex::encode(note),
                amount_zat: 10,
                frost_group_hex: hex::encode(frost),
                leaf_hex: hex::encode(leaf),
                merkle_root_hex: hex::encode(root),
                event_kind: "hosting_payment".into(),
                wallet_or_serial: serial.into(),
                proof: vec![ProofStepMsg {
                    sibling_hex: hex::encode(sib),
                    sibling_is_left: false,
                }],
            },
        )
        .unwrap();

        let good: MatchResp = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Match {
                    source_client: "08-zap1-src".into(),
                    dest_client: "08-terp-dst".into(),
                    sequence: 1,
                    app_data_hash_hex: hex::encode(app),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(good.matches);

        let mut bad = app;
        bad[0] ^= 1;
        let tamper: MatchResp = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Match {
                    source_client: "08-zap1-src".into(),
                    dest_client: "08-terp-dst".into(),
                    sequence: 1,
                    app_data_hash_hex: hex::encode(bad),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!tamper.matches);
        let _ = Addr::unchecked("x");
    }

    #[test]
    fn attest_halo2_no_merkle_path_on_execute() {
        let mut deps = mock_dependencies();
        let info = mock_info("owner", &[]);
        instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::CreateClient {
                source_client: "08-zap1-src".into(),
                dest_client: "08-terp-dst".into(),
            },
        )
        .unwrap();

        let frost = [3u8; 32];
        let proof = hosting_payment::prove_inclusion("PIR-001", "sib", &frost, 10).unwrap();
        let instances = hosting_payment::encode_instances("PIR-001", "sib", &frost, 10);
        let msg = ExecuteMsg::AttestHalo2 {
            source_client: "08-zap1-src".into(),
            dest_client: "08-terp-dst".into(),
            sequence: 1,
            timeout_timestamp_ns: 0,
            app_data_hash_hex: hex::encode([2u8; 32]),
            zkid: 1,
            proof: Binary::from(proof),
            instances: Binary::from(instances),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();
    }
}
