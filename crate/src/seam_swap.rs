//! Private **seam** swaps (not Juno Astroport): constant-product DEX math from
//! `terp_seams::dex`, IBC-shaped ZEC deposit notes, FROST spend auth.

use crate::committee::demo_layered_committees;
use crate::frost::{FrostGroup, FrostSeat};
use crate::frost_pool::FrostThresholdPool;
use crate::{tagged_hash, SpendAuth};
use terp_seams::dex::{
    apply_swap, quote_exact_in, AssetId, NoteIn, Pool, PoolStatus, SeamState, SwapPublic,
};

/// Hub/ZEC-shaped demo pool (seam AssetId::Hub vs AssetB).
pub fn demo_zec_hub_pool() -> Pool {
    Pool {
        pool_id: 1,
        asset_a: AssetId::Hub,
        asset_b: AssetId::AssetB,
        r_a: 2_000_000,
        r_b: 1_000_000,
        gamma: 997,
        gamma_den: 1000,
        status: PoolStatus::Active,
    }
}

/// IBC deposit: ZEC note value becomes a seam `NoteIn` after FROST-authorized credit.
pub fn ibc_deposit_then_swap(
    frost_pool: &mut FrostThresholdPool,
    frost: &FrostGroup,
    seats: &[FrostSeat],
    dex_pool: &mut Pool,
    state: &mut SeamState,
    zat: u64,
    nullifier: u64,
) -> Result<u128, String> {
    let group = frost_pool.group_id;
    let note = tagged_hash(b"ibc-zec-note", &[&zat.to_le_bytes()]);
    let att = crate::zap1::local_hosting_bundle(group, note, zat, "PIR-SEAM", "sib");
    let outer = frost_pool
        .layered
        .as_ref()
        .ok_or_else(|| "layered pool required".to_string())?;
    let parts = [
        ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
        ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
    ];
    let msg = FrostGroup::spend_message(&group, &note, zat);
    let need = frost.min_signers as usize;
    let sig = if seats.len() >= need {
        frost.sign_with_seats(&msg, &seats[..need])
    } else {
        frost.sign(&msg)
    }
    .map_err(|e| e.to_string())?;
    let auth = SpendAuth::from_quorum(outer, &parts, group, note, zat, None)
        .map_err(|e| e.to_string())?
        .with_frost_sig(sig);
    crate::zap1::accept_on_zap1_client(&att).map_err(|e| e.to_string())?;
    frost_pool
        .credit_deposit_zap1(&att, &auth)
        .map_err(|e| e.to_string())?;

    let notes = [NoteIn {
        asset_id: AssetId::Hub,
        value: zat as u128,
        nullifier,
    }];
    let public = SwapPublic {
        asset_in: AssetId::Hub,
        asset_out: AssetId::AssetB,
        delta_in: zat as u128,
        min_out: 1,
        nullifiers: vec![nullifier],
        oracle_mid: None,
        oracle_params: None,
        now_height: 1,
    };
    apply_swap(dex_pool, state, &notes, &public).map_err(|e| format!("{e:?}"))
}

pub fn quote_hub_to_b(pool: &Pool, delta_in: u128) -> Result<u128, String> {
    quote_exact_in(pool.r_a, pool.r_b, delta_in, pool.gamma, pool.gamma_den)
        .map_err(|e| format!("{e:?}"))
}

pub fn frost_backed_pool(group: [u8; 32], frost: FrostGroup) -> FrostThresholdPool {
    FrostThresholdPool::new(group, 2, 3)
        .expect("pool")
        .with_layered(demo_layered_committees().unwrap())
        .with_frost(frost)
}
