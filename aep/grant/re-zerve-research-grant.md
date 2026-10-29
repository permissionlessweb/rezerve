# Research grant: re-zerve private bid market

Status: proposal. Draft AEP: [`../spec/aep-xxx/README.md`](../spec/aep-xxx/README.md). This file asks for the work the lab sequence does not yet do. It is not a claim that the public Akash network runs this path.

## Summary

Akash is a public compute marketplace. re-zerve keeps that marketplace and adds a private bid path in the same `provider-services` binary: sealed bids, a commitment match, a derived lease bearer, and settlement as two Ironwood shielded spends signed by a FROST group. CosmWasm records the grant. It does not move the notes.

A lab sequence on **terpd 6.4.0** (image `terp-core:local-arm64`) now runs that market, a two-proxy bid fetch, an AKT minimum-stake gate, and a stalled FROST close. The proof system on that path is Halo2 Pasta, k=17 (`zakura-halo2-proofs` 5.0.0). terpd `v6.5.0` was requested from `registry.terp.network` on 29 October 2026 and was not found.

This grant funds three builds on top of that baseline:

1. Single-server private information retrieval of bids and asks, so an untrusted provider proxy cannot learn the row.
2. A live zero-knowledge proof of minimum AKT stake, with a root that can come from Cosmos staking today and from a Solana stake account after Akash’s planned SPL migration.
3. The same payment statement on Stwo, measured against Flock Ligerito, without retiring Halo2 until the new proof verifies in the Terp zk-cosmwasm VM.

## What the lab already runs

Commit `a887c86` on the lab repository, not published from this proposal. `terpd version` printed 6.4.0. An August Halo2 artifact failed in the VM (`ZkError`, invalid point encoding) and was not reused. One fresh export, then one sequence that exited 0.

| Behavior | Result |
|---|---|
| Order, sealed bid, `Match`, allocate, serve, lease bearer denied after close | Ran |
| Two Ironwood spends. Earned is `f(102, 103, 1) = 1`. Closer cannot set earned. | Ran |
| Bid fetch | Two-proxy XOR. Not YPIR. Colluding proxies recover the index. |
| AKT stake | Cleartext check that stake is at least the minimum. `PROOF_LIVE` is false. A fake proof is rejected. No Halo2 stake proof. No mainnet staking root. |
| FROST stall | `finish_amounts` quotes earned 1 and remainder 99. One seat does not spend. Invented earned is refused. Provider paid 0 while stalled. |
| Spend authority | `frost-spend-v1+zip32-reconstructed-dkg-seed`. ZIP-312 RedPallas is not in Zakura. |

Host times include the first keygen in the process.

| Measure | terpd 6.4.0 | Earlier terpd 6.2.1 |
|---|---:|---:|
| Inclusion prove | 125.0 s | 152.2 s |
| Inclusion verify | 1.4 s | 1.7 s |
| Stored VK verify | 88.4 s | 107.8 s |
| Accrual prove | 259.4 s | 318.2 s |
| Accrual verify | 3.0 s | 3.5 s |
| Transactions | 17 | 17 |
| `gas_used` | 651,629,464 | 645,690,935 |
| `store-full-circuit` gas | 638,984,649 | 638,984,649 |

`store-full-circuit` is the Halo2 params and verifying key. It is almost the entire gas bill.

## Why the next proof is a STARK

The zk-cosmwasm VM already verifies three prover families. Only the first is this market’s statement.

| `prover_id` | System | Field | Today |
|---|---|---|---|
| 0 | Halo2 IPA | Pasta / Vesta, k=17 | Payment and accrual |
| 2 | Stwo (Circle STARK) | M31 | Registered host. Different statement (SSLE demo). |
| 3 | Flock Ligerito | curve id 7 | Registered host. Different statement. |

The Halo2 path is the right soundness baseline because it verifies on the VM that terpd 6.4.0 already runs. It is the wrong place to stop. Stored-VK verify is 88 seconds, and the params transaction dominates gas. Stwo and Ligerito do not need that universal params file, and both verifiers are already in the VM. The grant’s circuit milestone is the **same four public instances** (merkle root, FROST group, amount class, `HOSTING_PAYMENT`) on `prover_id` 2, with `prover_id` 3 timed on the same bench. Halo2 stays the shipped proof until that STARK verifies in the VM. The existing SSLE and Flock demos are not this payment circuit.

## Akash on Solana

[Proposal 346](https://akash.network/), “Migrate the Akash Protocol to Solana,” opened on 26 October 2026 and closes on 2 November 2026. Published tallies during the vote were about 98% yes, above the 33.4% quorum. A yes authorizes AKT as a 1:1 SPL token and a one-way portal after audits. It does not move the marketplace. A later vote sets the cutover. Leases on akashnet-2 continue until then.

re-zerve still extends Akash market access: same provider binary, public path when the private gate is off, sealed bid when it is on. After a cutover, the public order may be a Solana program instead of `MsgCreateBid`. Pay does not follow that move. Ironwood notes stay on Zakura. The Terp VM still verifies the proof.

The AKT gate has to grow a second root source. The statement remains `stake ≥ min`. The root may be a Cosmos staking tree now and a Solana stake account, or the SPL supply, after the portal exists. The lab gate binds neither root. A live proof that hard-codes only `x/staking` would be obsolete on the day of the cutover.

## Work packages

### 1. YPIR retrieval and a provider proxy

Replace the two-proxy XOR fetch with single-server PIR in the style of Valar Group (YPIR / SimplePIR, as in vote-nullifier and spendability retrieval). An untrusted proxy stores fixed-size rows and answers queries. The proxy must not learn the index even if it is one party. The lab sequence must show that one proxy’s answer is not the row, and that the production serve step uses this fetch.

Exit: the same green sequence names the scheme, and the test that colluding XOR proxies recover the index is no longer the product path.

### 2. Live AKT inclusion, two root sources

A Halo2 or Stwo proof of `stake ≥ min_stake` whose public inputs are the root, the minimum, and the amount class. The bonding account stays a witness. `PROOF_LIVE` becomes true only when `verify` accepts that proof and rejects a proof for a stake under the minimum. Document two root extractors: Cosmos staking, and Solana stake / SPL. Ship the extractor that has a tree. Stub the other with an explicit unsupported error, not a fake root.

Exit: the lab sequence runs the live proof. A cleartext `statement_holds` check is no longer the gate.

### 3. Payment statement on Stwo, compared with Ligerito

Same public instances as HOSTING_PAYMENT. Prove and verify under `prover_id` 2. Repeat under `prover_id` 3. Record prove time, verify time, proof bytes, and `gas_used` beside the Halo2 row in `artifacts/bench/e2e-history.jsonl`. Keep Halo2 as the sequence’s proof until the Stwo proof verifies inside terpd on a stated image tag.

Exit: a bench row for Stwo, a bench row for Ligerito, and a written choice of which one replaces Halo2. No prover swap in the green sequence before that verify.

### 4. Image and client limits

Repeat the production sequence on `registry.terp.network/terp-core:v6.5.0` when that tag exists. Do not retag another image. If instantiate again fails because a client refuses a decoded message over 4 MB, fix the client limit or stop returning the Halo2 params inside that response, and record the byte sizes.

Exit: one green sequence whose bench `image` field is the tag that `terpd version` printed, and whose `store-full-circuit` path is the fresh proof.

### 5. Review

Independent review of the sealed-bid gate, the lease bearer, sidecar isolation, the PIR query, the AKT witness (account not public), and the stall rule that the closer cannot set earned.

## Out of scope

- A public Akash mainnet deployment.
- Moving Ironwood notes or the Terp verifier onto Solana.
- Treating two-proxy XOR as YPIR.
- Claiming ZIP-312 RedPallas.
- Replacing the lease bearer.
- Using the Stwo SSLE demo or the Flock demo as the payment proof.
- Bank transfers or uterp as the product’s money.

## Environment

Operators reproduce the lab sequence with the repository `mise.toml` (`mise run setup`, then `mise run demo` on a host that has the chain image and `zakurad`). The script does not download terpd `v6.5.0`. It refuses to relabel another image as that tag.
