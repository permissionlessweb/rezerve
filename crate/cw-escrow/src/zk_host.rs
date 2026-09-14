//! wasm32 FFI to zk-wasmvm `proof_instance_verify` for `f` (96-byte instances).
//!
//! Guest stays on cosmwasm-std 1.5 (no `Api::proof_instance_verify`). Missing
//! import → wasm instantiate fails (fail closed). Crypto-false → 1.

#![cfg(target_arch = "wasm32")]

use cosmwasm_std::StdError;

#[repr(C)]
struct Region {
    offset: u32,
    capacity: u32,
    length: u32,
}

fn build_region(data: &[u8]) -> Box<Region> {
    Box::new(Region {
        offset: data.as_ptr() as u32,
        capacity: data.len() as u32,
        length: data.len() as u32,
    })
}

extern "C" {
    fn proof_instance_verify(
        zkid: u32,
        proof_ptr: u32,
        proof_len: u32,
        i_ptr: u32,
        i_len: u32,
    ) -> u32;
}

/// Host verify. `0` accept, `1` crypto-false, `>1` host error.
pub fn verify(zkid: u64, proof: &[u8], instances: &[u8]) -> Result<bool, StdError> {
    let proof_send = build_region(proof);
    let proof_ptr = &*proof_send as *const Region as u32;
    let inst_send = build_region(instances);
    let inst_ptr = &*inst_send as *const Region as u32;
    let result = unsafe {
        proof_instance_verify(
            zkid as u32,
            proof_ptr,
            proof.len() as u32,
            inst_ptr,
            instances.len() as u32,
        )
    };
    match result {
        0 => Ok(true),
        1 => Ok(false),
        code => Err(StdError::generic_err(format!(
            "zk-wasmvm proof_instance_verify host error {code}"
        ))),
    }
}
