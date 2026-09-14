# `cw-zap1-ibcv2` — PIR packet attestation module

This CosmWasm module **attests IBC v2 packets** (client pair + sequence → commitment) using `zap1-verify`. It is **not** the ICS-08 08-wasm light client and does **not** implement all nine ICS-08 entrypoints.

| Need | Crate |
|------|--------|
| 08-wasm LC on Terp | `cw-ics08-wasm-zap1` at `terp-rs/contracts/light-clients/cw-ics08-wasm-zap1` |
| This PIR attestation module | **this crate** |
| Merkle verify (no contract) | `zap1-verify` 0.2.1 on crates.io |

Do not merge this crate into the 08-wasm LC or vice versa.
