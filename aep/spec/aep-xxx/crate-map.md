# Crate map

This repository’s product crate is **`private-inference-rent`** (`crate/`). Documentation for behavior is this AEP, not a second docs tree.

Env prefix `PIR_*` is the **side-market allocate gate**. The lab sequence also runs a two-proxy XOR fetch (`crate/src/bid_ask_pir.rs`). That is not Valar YPIR. Colluding proxies recover the index. Single-server YPIR is still the funded retrieval.

## Package

| Item | Value |
|---|---|
| Cargo name | `private-inference-rent` |
| Path | `crate/` |
| Circuit | `hosting-payment` at `crate/circuits/hosting-payment` |
| Halo2 artifacts | `crate/artifacts/halo2/` |

## Modules (Rust)

| Path | Role |
|---|---|
| `crate/src/ask.rs` | `PublicAsk`, ask commitment |
| `crate/src/bid.rs` | `EncryptedBidEnvelope`, bid commitment, ChaCha20-Poly1305 |
| `crate/src/access.rs` | `DerivedAccess` bearer. Lease bearer and session bearer. |
| `crate/src/bid_ask_pir.rs` | Two-proxy XOR row fetch. Not YPIR. |
| `crate/src/frost_dkg.rs` | `FrostParams`, DKG seats |
| `crate/src/frost.rs` | RFC 9591 sign/verify |
| `crate/src/zap1.rs` | ZAP1 Merkle + Halo2 credit |
| `crate/src/accrual.rs` | `f(open, close, rate)` |
| `crate/src/akt_stake.rs` | `AktStakePublic` (96-byte instances). Verify fails closed. Proof not live. |
| `crate/src/zcash_escrow.rs` | Ironwood open, two spends, `finish_amounts` stall |
| `crate/src/e2e.rs` | Production sequence |
| `crate/src/e2e_bench.rs` | Prove, verify, and chain-gas record |

## CosmWasm

| Package | Path | Execute / query |
|---|---|---|
| `cw-pir-commit` | `crate/cw-commit/` | `PostCommitments`, `Match` |
| `cw-pir-escrow` | `crate/cw-escrow/` | open / accrue / close grant |
| `cw-zap1-ibcv2` | `crate/cw-zap1-ibcv2/` | attest packet, Halo2 accept |

## Halo2

| Item | Path / crate |
|---|---|
| Circuit | `zakura-halo2-proofs` 5.0.0, feature `batch` only, Pasta IPA, k=17 |
| HOSTING_PAYMENT | `crate/circuits/hosting-payment/src/lib.rs` |
| Accrual | `crate/circuits/hosting-payment/src/accrual.rs` |
| Host verify | `proof_instance_verify` → `halo2_proofs::plonk::verify_proof` |
| VK / params | `crate/artifacts/halo2/vk_body.bin`, `params.bin` |
| Export bin | `crate/src/bin/pir-export-halo2.rs` |
| AKT inclusion | Not a circuit. `crate/src/akt_stake.rs` public instances only. No vk. Verify fails closed. |

Public instances for HOSTING_PAYMENT (one column, four rows, 128 bytes LE): merkle root, FROST group, amount class, `HOSTING_PAYMENT`. Witness (siblings, serial, month, year) stays off execute.

AKT stake inclusion is not that circuit. Its 96-byte public instances (root, min, amount class) are specified in [`data-structures.md`](data-structures.md#aktstakeinclusion-proposed). The proof is not live.

## Provider

| Path | Role |
|---|---|
| `provider/pirgate/` | Allocate gate (envelope, match URL) |
| `provider/gateway/pir/` | Derived bearer |
| `provider/cmd/pir-sidecar/` | Sidecar process |
| `provider/Dockerfile.pir` | Lab image `akash-provider-pir:local` |

## Retrieval

| Item | Today | Still to build |
|---|---|---|
| Two-proxy XOR | Lab sequence. Honest only if proxies do not collude. | — |
| Valar YPIR / SimplePIR | Not in the crate | [valar-ypir](https://crates.io/crates/valar-ypir), [vote-nullifier-pir](https://github.com/valargroup/vote-nullifier-pir) |
| Provider proxy | Logs bit-vectors for the XOR path | Untrusted host for a YPIR database |

## Other registered provers

The payment circuit is `prover_id` 0. The same VM also has Stwo (`prover_id` 2, M31) and Flock Ligerito (`prover_id` 3). Those hosts are not this statement. The recommendation is in the AEP under Proof systems.

## Tests (normative list)

| Path | Checks |
|---|---|
| `crate/tests/ask_bid.rs` | Ask + envelope + commitments |
| `crate/tests/akt_stake.rs` | Private stake ≥ min. Bonding account not in instances. Verify fails closed. |
| `crate/tests/access_derive.rs` | Winner bearer; loser denied; close denies |
| `crate/tests/frost_dkg.rs` | `FrostParams`; threshold |
| `crate/tests/e2e_local.rs` | Lab sequence, including two-proxy XOR, AKT gate, stall close |
| `provider/pirgate/gate_test.go` | Public default; fail-closed PIR |
| `provider/gateway/pir/access_test.go` | Bearer accept / deny |
