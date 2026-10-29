# re-zerve overnight loop

Decisions locked 2026-10-29 before the sleep run.

- Product tree stays `~/abstract/re-zerve` on the lab host. Keep its git history. Local commits only. Do not push. Do not rewrite history.
- Internal crates reference the refreshed terp-core workspace dependency set (`crates/terp-rs` workspace dependencies and patches, local CosmWasm and zakura-halo2). No second Halo2 checkout and no `5364d3d` git pin.
- `crates/private-inference-rent` is not a second source of logic. Once `re-zerve` itself builds, stop syncing into it and leave a pointer.
- Soundness stays on the current zakura-halo2 hosting-payment circuit. The chain image for this build is terpd `v6.5.0`.
- A cycle is not successful until the same green sequence includes bid PIR, AKT min-stake inclusion, and a stalled FROST close that does not let the closer set earned. The lease bearer still works.
- Every action gets a start time, end time, and duration in the journal below. E2E numbers append to `e2e-history.jsonl`.

## Remaining gaps

1. Product crate resolve. Closed earlier. `private-inference-rent` is a workspace member. `cw-orch-core` default features are empty. Commit `cd980c2` on lab `main`, not pushed. Halo2 stays `zakura-halo2-proofs` 5.0.0, feature `batch` only. `multicore` is off.
2. terpd `v6.5.0` image. Still absent. `docker pull registry.terp.network/terp-core:v6.5.0` returned `not found`. The image was not retagged. This cycle ran on `terp-core:local-arm64` after `terpd version` printed `6.4.0`. The bench label is `terpd 6.4.0`, not v6.5.0. `TERP_IMAGE_VERSION=local-arm64` is the real tag. It is not the retired tag `local` or `local-zk`.
3. Instantiate decode limit. Not hit. The 4MB cosmrs limit did not fire. A first store of the August 20 Halo2 artifacts failed in the VM with `ZkError` `invalid point encoding in proof` and gas_used 389145465. Those artifacts were older than the circuit sources. They were not retried. One fresh `pir-export-halo2` then one green sequence. Store-full-circuit gas_used on that sequence was 638984649.
4. Bid PIR. Closed in the green sequence. Retrieval was two-proxy XOR. It is not YPIR. The log line is `bid_pir_retrieval=two-proxy-xor not_ypir=true`. One proxy answer is not the row.
5. AKT min-stake inclusion. Included, not a live proof. `PROOF_LIVE` stayed false. The cleartext statement held for a stake at or above the minimum, and `verify_akt_stake_inclusion` rejected a fake proof. The bonding account was not a public instance. This is not an Akash mainnet snapshot. A Pasta Halo2 proof of the relation is still absent.
6. Stalled FROST close. Closed in the green sequence. `finish_amounts` returned earned 1 and remainder 99 from open height 102 and close height 103, rate 1. That is `f`, not a closer integer. `try_pay_provider` on an invented amount returned `CloserSetEarned`. A one-seat `close_notes_from_challenge` returned `FrostCloseStalled` and did not spend. The threshold close used `close_notes_from_challenge`, so the caller did not pass earned.
7. Lease bearer. Still present. `winner_bearer_denied` ran after the two Ironwood spends. It was not removed.
8. wasm stack limiter. parity-wasm 0.45 was not rechecked. v6.5.0 is not on the host. rustc 1.86.0 cannot resolve this workspace (`serde_with` and `darling_macro` want 1.88). Wasm was built with rustc 1.88.0, `RUSTFLAGS=-C target-cpu=mvp`, then `wasm-opt -O1` once from that rustc output. The optimizer left the bytes unchanged (commit 362459, zap1 439663, escrow 421528). ics08, built inside terp-rs, is 424975. terpd 6.4.0 stored those contracts. They are not the old ~214KB figure.
9. Circuit cost. New bench on terpd 6.4.0, same prover. `zakura-halo2-proofs` 5.0.0, `batch` only. Inclusion prove 125.0 s (includes keygen), inclusion verify 1.4 s, stored-vk verify 88.4 s, accrual prove 259.4 s, accrual verify 3.0 s, 17 txs, gas_used 651629464, store-full-circuit gas 638984649. v6.2.1 was 152.2 s, 1.7 s, 107.8 s, 318.2 s, 3.5 s, 17 txs, gas_used 645690935, store-full-circuit 638984649. No prover swap. The product crate still links crates.io `halo2_proofs` 0.3.5 through orchard. That is the Zcash stack.
10. ZIP-312 RedPallas is not in Zakura. The spend stand-in is `frost-spend-v1+zip32-reconstructed-dkg-seed`: FROST-ed25519 reconstructs the group seed, ZIP-32 coin type 133 derives the Ironwood spending key. No BankMsg. No uterp as product money. The stall record has no viewing key. No public-mainnet claim. The closer cannot set earned.
11. `Deploy::deployed_state_file_path` is still gone on cw-orch 0.30. Unchanged.
12. Duplicate tree `~/abstract/terp-core/crates/private-inference-rent` was not deleted. Its README remains a pointer. Logic was not synced back.

## Journal

### 2026-10-29 seed

- Start: session handoff after the sleep-run questions.
- End: loop armed at 30 minutes.
- Result: decisions recorded. No new e2e in this seed.
- Next slice: point re-zerve hosting-payment at the refreshed workspace Halo2, confirm `v6.5.0`, then one soundness sequence that records benches.

### 2026-10-29 dependency slice

- Start: 2026-10-29T06:35:25Z
- End: 2026-10-29T07:02:58Z
- Duration: 27m33s (1653s)
- What: Added `~/abstract/re-zerve/Cargo.toml` workspace. Patches point at the existing terp-core checkouts (local CosmWasm 4.1, local zakura-halo2, local tendermint-rs, cosmrs). No second Halo2 checkout. No git rev `5364d3d`. `hosting-payment` no longer path-depends on `../../../zcash/halo2`. Circuit API moved to zakura-halo2-proofs 5 (`rng()`, `gate_count`, `read_with_cs` without the extra vec). Contract crates use workspace CosmWasm. `StdError::generic_err` became `StdError::msg`. cw-orch 0.30 `execute`/`instantiate` take `&[Coin]`, not `Option`. Tests build `MessageInfo` locally because `mock_info` is gone. Commit `fc4df4c` on lab `main`. Not pushed.
- Result: `cargo check -p hosting-payment` finished dev profile in 8.18s against `zakura-halo2-proofs` 5.0.0 and `zakura-pasta-curves` 5.0.0. `cargo test -p cw-pir-commit -p cw-pir-escrow -p cw-zap1-ibcv2 -p pir-cw-orch` exited 0: escrow 9 tests, zap1 2 tests (226.85s, includes `prove_inclusion`), deploy_mock 2, escrow_arbiter 3. Not a production sequence. No `e2e-history.jsonl` row. `private-inference-rent` does not resolve in this workspace (gap 1). docker was not on PATH, so the v6.5.0 image was not confirmed.
- Next slice: unblock `crate/` (sha2), then confirm the terpd `v6.5.0` image tag before any sequence.

### 2026-10-29 crate resolve

- Start: 2026-10-29T07:05:27Z
- End: 2026-10-29T07:21:05Z
- Duration: 15m38s (938s)
- What: Admitted `crate/` as workspace member `private-inference-rent`. Tried a `vendor/bip32` patch that moved `sha2` to 0.11, `hmac` to 0.13, and `ripemd` to 0.2. That resolve failed: stable `sha2` 0.11 pulls `crypto-common ^0.2`, and `zcash_primitives` 0.30 pins `crypto-common =0.2.0-rc.1`. Removed the vendor patch. Turned `cw-orch-core` default feature `zk` off and linked `cw-orch-daemon` feature `zk` to `cw-orch-core/zk`. `cargo tree` then selected `sha2` 0.11.0-pre.4 and did not select `wasmer-types`. `cargo check -p private-inference-rent -p cw-pir-commit -p cw-pir-escrow -p cw-zap1-ibcv2 -p pir-cw-orch -p hosting-payment` exited 0 in 1m06s. `--features cw-orch-suite` first failed in already-dirty `crate/src/e2e.rs` (`execute` got `Some(&[])`, cw-orch 0.30 wants `&[Coin]`). Those two call sites now pass `&[]`. The feature check then exited 0 in 3.68s. `e2e.rs` was not committed; the file already had other uncommitted work. Docker: `registry.terp.network/terp-core:v6.5.0` is absent. Local tag `terp-core:local-arm64` is terpd 6.4.0. No production sequence. No `e2e-history.jsonl` row.
- Result: Resolve and dev check are green. Not a production sequence. Commits, not pushed: re-zerve `cd980c2`, cw-orchestrator `6bf04cdc`. Pointer README written at `~/abstract/terp-core/crates/private-inference-rent/README.md` (gitignored by `crates/*`).
- Next slice: obtain terpd image `registry.terp.network/terp-core:v6.5.0` (do not relabel 6.4.0 or v6.2.1), then one sequence that runs bid PIR, AKT min-stake inclusion, and a stalled FROST close through `finish_amounts`.

### 2026-10-29 production sequence on terpd 6.4.0

- Start: 2026-10-29T07:35:42Z
- End: 2026-10-29T09:49:35Z
- Duration: 2h13m53s (8033s)
- What: Pulled `registry.terp.network/terp-core:v6.5.0` once. The registry returned `not found`. Did not retag. `docker run --entrypoint terpd terp-core:local-arm64 version` printed `6.4.0`. Wired the existing bid PIR, AKT stake, and stalled-close code into `run_production_sequence` without removing the lease bearer. Built a Linux `zakurad` 1.2.0 (ELF aarch64) because none was on disk. Pointed the compose script at `~/abstract/re-zerve` and at `terp-core:local-arm64` with bench label `terpd 6.4.0`. Re-exported Halo2 once after the August artifacts failed point encoding. One production sequence then passed.
- Result: Green. `PRODUCTION_SEQUENCE_COMPOSE_OK`. Retrieval was two-proxy XOR, not YPIR. AKT `proof_live=false`, statement held, verify rejected. Stall `finish_amounts` earned 1 remainder 99, below-threshold spend false, closer-set earned false, provider paid 0. Winner bearer denied. Bench file `artifacts/bench/e2e-history.jsonl` image `terpd 6.4.0`: inclusion prove 125.0 s, verify 1.4 s, stored-vk verify 88.4 s, accrual prove 259.4 s, verify 3.0 s, 17 txs, gas_used 651629464, store-full-circuit 638984649. Not pushed.
- Next slice: terpd image `v6.5.0` is still missing. AKT still has no live Halo2 proof. ZIP-312 RedPallas is still not this module.

