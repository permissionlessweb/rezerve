# PIR crate map

This repository’s product crate is **`private-inference-rent`** (`crate/`). Documentation for behavior is this AEP, not a second docs tree.

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
| `crate/src/access.rs` | `DerivedAccess` bearer |
| `crate/src/frost_dkg.rs` | `FrostParams`, DKG seats |
| `crate/src/frost.rs` | RFC 9591 sign/verify |
| `crate/src/zap1.rs` | ZAP1 Merkle + Halo2 credit |
| `crate/src/accrual.rs` | `f(open, close, rate)` |
| `crate/src/zcash_escrow.rs` | Ironwood open / two spends |
| `crate/src/e2e.rs` | Production sequence |

## CosmWasm

| Package | Path | Execute / query |
|---|---|---|
| `cw-pir-commit` | `crate/cw-commit/` | `PostCommitments`, `Match` |
| `cw-pir-escrow` | `crate/cw-escrow/` | open / accrue / close grant |
| `cw-zap1-ibcv2` | `crate/cw-zap1-ibcv2/` | attest packet, Halo2 accept |

## Halo2

| Item | Path / crate |
|---|---|
| Circuit | `halo2_proofs` PLONK, Pasta, k=17 |
| HOSTING_PAYMENT | `crate/circuits/hosting-payment/src/lib.rs` |
| Accrual | `crate/circuits/hosting-payment/src/accrual.rs` |
| Host verify | `proof_instance_verify` → `halo2_proofs::plonk::verify_proof` |
| VK / params | `crate/artifacts/halo2/vk_body.bin`, `params.bin` |
| Export bin | `crate/src/bin/pir-export-halo2.rs` |

Public instances for HOSTING_PAYMENT (one column, four rows, 128 bytes LE): merkle root, FROST group, amount class, `HOSTING_PAYMENT`. Witness (siblings, serial, month, year) stays off execute.

## Provider

| Path | Role |
|---|---|
| `provider/pirgate/` | Allocate gate (envelope, match URL) |
| `provider/gateway/pir/` | Derived bearer |
| `provider/cmd/pir-sidecar/` | Sidecar process |
| `provider/Dockerfile.pir` | Lab image `akash-provider-pir:local` |

## Tests (normative list)

| Path | Checks |
|---|---|
| `crate/tests/ask_bid.rs` | Ask + envelope + commitments |
| `crate/tests/access_derive.rs` | Winner bearer; loser denied; close denies |
| `crate/tests/frost_dkg.rs` | `FrostParams`; threshold |
| `crate/tests/e2e_local.rs` | Local sequence |
| `provider/pirgate/gate_test.go` | Public default; fail-closed PIR |
| `provider/gateway/pir/access_test.go` | Bearer accept / deny |
