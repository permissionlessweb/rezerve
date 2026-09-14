use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult,
};
use cw_storage_plus::Item;

pub mod msg;
pub use msg::{Commitments, ExecuteMsg, InstantiateMsg, MatchResp, QueryMsg};

#[cfg(not(target_arch = "wasm32"))]
mod interface;
#[cfg(not(target_arch = "wasm32"))]
pub use interface::CwPirCommitContract;

const ASK: Item<String> = Item::new("ask_c");
const BID: Item<String> = Item::new("bid_c");

fn require_hex32(s: &str) -> StdResult<()> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StdError::generic_err("commitment must be 32-byte hex"));
    }
    let low = s.to_ascii_lowercase();
    if low.contains("price") || low.contains("identity") {
        return Err(StdError::generic_err("price/identity not allowed"));
    }
    Ok(())
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
pub fn execute(deps: DepsMut, _env: Env, _info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Commit { key, value } => {
            require_hex32(&value)?;
            if key == "ask" {
                ASK.save(deps.storage, &value)?;
            } else if key == "bid" {
                BID.save(deps.storage, &value)?;
            } else {
                return Err(StdError::generic_err("only ask|bid keys"));
            }
            Ok(Response::new())
        }
        ExecuteMsg::PostCommitments {
            ask_commitment,
            bid_commitment,
        } => {
            require_hex32(&ask_commitment)?;
            require_hex32(&bid_commitment)?;
            ASK.save(deps.storage, &ask_commitment)?;
            BID.save(deps.storage, &bid_commitment)?;
            Ok(Response::new())
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Get { key } => {
            let v = if key == "ask" {
                ASK.may_load(deps.storage)?
            } else if key == "bid" {
                BID.may_load(deps.storage)?
            } else {
                None
            };
            to_json_binary(&v)
        }
        QueryMsg::GetCommitments {} => {
            let c = Commitments {
                ask_commitment: ASK.may_load(deps.storage)?.unwrap_or_default(),
                bid_commitment: BID.may_load(deps.storage)?.unwrap_or_default(),
            };
            to_json_binary(&c)
        }
        QueryMsg::Match {
            ask_commitment,
            bid_commitment,
        } => {
            let stored_ask = ASK.may_load(deps.storage)?.unwrap_or_default();
            let stored_bid = BID.may_load(deps.storage)?.unwrap_or_default();
            to_json_binary(&MatchResp {
                matches: stored_ask == ask_commitment && stored_bid == bid_commitment,
            })
        }
    }
}
