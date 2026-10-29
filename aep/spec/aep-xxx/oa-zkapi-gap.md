# re-zerve and zkAPI (Open Anonymity × Ethereum Foundation)

Decision note for iteration under **Zcash payments** and **Akash providers**.
Sources: [EF post](https://blog.ethereum.org/2026/10/01/introducing-zkapi), [OA site](https://openanonymity.ai/), [unlinkable inference](https://openanonymity.ai/blog/unlinkable-inference/), local tree `crates/zkapi` (ethereum/zkapi). Circuit id in that tree: `zkapi-v2-note-bound-v1`.

zkAPI is live on Ethereum mainnet. re-zerve is a local Akash-shaped market with Ironwood settlement. The human problem they share: **do not let a long-lived account stitch a person’s payments to their usage.**

## What people are actually buying

Ken Liu (OA): unlinkable inference plus payments, so “privacy and sovereignty is foundational and people are in control.” Davide Crapis (EF dAI): more of that for the age of AI. The EF post: every API key today points at an account, the account at a payment method, and years of prompts become one profile.

zkAPI’s answer, in their words: deposit once, then authorize with a proof. The **provider sees the requests**. The **payment layer sees the spend**. **Neither learns the link.**

What they explicitly do **not** hide: prompt text, IP, timing. They point at Tor for network anonymity. OA Chat adds extra layers (TEE verification that logs are off, GPU-enclave query rewrite, local memory, Refraction proxy). Those are the chat product, not the zkAPI vault.

re-zerve’s human job is the same split, on a **marketplace**:

| Person | Should not have to |
|---|---|
| Deployer (renter) | Publish a clearing price, or let a courier see which bid they fetched |
| Provider | Leave public Akash, or learn which other renter is shopping |
| Payer | Have the Ironwood note glued to the workload the provider sees |

## Feature comparison

| Feature | zkAPI (OA × EF) | re-zerve today | Gap under our constraints |
|---|---|---|---|
| Payment asset | ETH / USDC into an Ethereum vault. Balance is a private note after deposit. | Ironwood notes (NU6.3). CosmWasm records a grant, not bank coins. | Keep Zcash. Do not port the vault. |
| Who can see the deposit | One ordinary L1 transaction, then the note is what you spend. | Open is a shielded note whose spend key is the FROST group. | We already hide the deposit better at open. Their strength is **later spends** that do not reveal which note. |
| Unlink payment from use | Groth16 BN254 membership: prove a funded note without saying which. Note-bound BabyJubJub commitment. Server charges an anonymous commitment. | Commitment match + derived bearer. The bearer is stable for the lease. Pay path is Halo2 `HOSTING_PAYMENT` (Pasta, k=17) with public instances (root, FROST group, amount class, kind). | **Largest privacy gap.** A stable bearer and a public FROST group on the proof can re-link the lease. Borrow their *pattern* (membership + note-bound state), not their curve. |
| Metering | Short-lived key, cap, charge **actual** use, withdraw the rest. Challenge service if the operator stalls. | Accrual `f(open_height, close_height, rate)` from Zcash heights. Two spends at close. Closer cannot set earned. A lab sequence records `finish_amounts` when fewer than `t` seats will sign and does not spend. | Heights are the right clock. The stall does not pay the quote. A later threshold close still has to spend `f` without a closer-set integer. |
| Marketplace | One issuer (zkAPI server) and one inference upstream (OpenRouter). “Uber for prompts” is OA’s older essay: users, proxy stations, destinations. | Many Akash providers. Public order. Sealed bid. Allocate after `Match`. Custom `provider-services`. | Do not collapse to one OA-platform. Their station is our **provider proxy**, not our provider. |
| Bid / ask privacy | Not a bid book. Price is a prepaid balance. | Price off the Akash order book. Hash on chain. | Keep. They do not have this. |
| Association graph on fetch | Client talks to server for proofs; prompts go **direct** to the model host in the preferred mode (proxy mode lets the server see traffic — they treat that as worse). | Lab sequence runs two-proxy XOR. That hides the index from one proxy. Colluding proxies recover it. Valar YPIR is specified, not built. | **Replace XOR with YPIR.** Their “direct, not through the payment server” is the same instinct: the courier must not see both payment and content. |
| Identity at the gate | No account after deposit. Blind tickets in the older OA design; zkAPI replaces tickets with note proofs. | Public ask is readable. Bidder identity is inside the envelope only. AKT stake inclusion has public instances; the Halo2 proof is not live. | Stake proof must stay ZK (like their note proof): threshold yes, bonding account no. |
| Threshold custody | Single user note. Operator Schnorr on the balance. Single-party Groth16 setup (they document the trust). | FROST `t`-of-`n`. Penumbra-style sidecars welcome. Dealer forbidden. | Keep FROST. Do not copy single-party setup as the spend authority. |
| Workload host | Any OpenAI-compatible API. TEE is optional OA Chat, not the protocol. | Akash cluster via custom provider. Public path when the side-market gate is off. | Stay on Akash. TEE is not this protocol (same split they made). |
| Client | Browser SDK, WASM prover, local `zkapi-clientd` speaking OpenAI HTTP. | No renter UI. `provider-services` CLI. | Front end is a grant item. Their lesson: the human meets a chat box, not a circuit. |
| What is live | Mainnet vault, OA Chat, Sepolia. | Lab sequence on terpd 6.4.0 (image `terp-core:local-arm64`). Halo2 Pasta, k=17. Not the public Akash default. terpd `v6.5.0` was not in the registry on 2026-10-29. | Do not pretend parity. Copy the **unlink** property first. |

## What to take, what to leave

**Take (privacy, fits Zcash + Akash)**

1. **Unlink the payer from the workload.** Their sentence to steal: provider sees the request, payment layer sees the spend, neither sees both. For us: Ironwood close sees the note; the Akash provider sees the manifest; the derived credential must not be a stable join key across sessions.
2. **Note-bound state.** `zkapi` binds balance to `note_id` inside the proof (`docs/note-bound-commitments.md`) and lets the server subtract a charge without opening the note. Map that onto an Ironwood note and `f(open, close, rate)`, still Halo2, still no `BankMsg`.
3. **Ephemeral capability.** Their short-lived API key dies with the session. Our bearer lives for the lease. Prefer a per-session bearer derived from the same OOB key so a provider log cannot stitch sessions.
4. **Provider proxy = their non-content path.** Fund the Valar-style PIR index so the proxy stores rows and learns no index. Do not relay prompts through that proxy (they warn proxy mode sees traffic).
5. **Pin artifacts.** They pin `circuit_id`, key hashes, vault address. We already pin Halo2 `vk_body.bin` / `params.bin`. Keep that discipline when the PIR DB root and AKT inclusion vk appear.
6. **Say what we do not hide.** They say IP and prompt text. We should say: SDL is public; prompt/content in the container is the renter’s and the provider’s; network anonymity is out of scope unless a proxy like Refraction is chosen later.

**Leave (wrong asset or wrong market)**

| Their piece | Why we skip it |
|---|---|
| ETH / USDC vault | Payments are Zcash. |
| Groth16 BN254 + BabyJubJub | We verify Halo2 on Pasta. A second curve is a new trusted setup. |
| Single-party Groth16 setup as spend authority | FROST DKG is the custody we already chose. |
| OpenRouter / one inference upstream | Providers are Akash operators. |
| Stripe and account signup | OA Chat’s other door. Not this market. |
| TEE query rewrite as protocol | OA uses it so prompts are less identifying. Useful later for renters. Not required to close the payment-link gap. |

## Priority while we tune

Ordered for **privacy gained per unit of work**, given we will not leave Zcash or Akash.

| Order | Work | Why first |
|---|---|---|
| 1 | Cryptographic PIR for sealed bids/asks, Valar YPIR shape, untrusted provider proxy | Closes the association graph on the path we still do in the clear (OOB). Specified, not built. |
| 2 | Unlink bearer from lease-long identity | zkAPI’s actual product. Stable `DerivedAccess` re-links sessions the payment proof tried to separate. |
| 3 | Note-bound accrual proof | Keep Halo2. Public instances must not include a renter id. Charge via heights, not a closer integer. Challenge path if FROST close stalls. |
| 4 | AKT stake inclusion, ZK only | Their “funded note” is “allowed to spend.” Ours adds buy-and-hold without a public bonding account. Public instances are specified. The Pasta Halo2 proof is not live. |
| 5 | Renter-facing client | OA Chat is why the EF post is legible. A local client that fetches via PIR and opens a bearer. Not a second docs site. |
| 6 | Circuit size (k=17, vk, prove time) | After the unlink property exists. Faster proofs do not fix a linkable bearer. |
| 7 | Light-client interop, portable CosmWasm | Makes pay inclusion real on a chain. Does not, by itself, hide who paid. |

## One-paragraph decision

zkAPI hides **which deposit paid for this API session**. re-zerve must hide **which note paid for this Akash lease** and **which bid a renter pulled from a proxy**, while many providers still compete on a public order. Copy their split (content path ≠ payment path ≠ courier). Do not copy their chain, their curve, or their single upstream. Next build is PIR retrieval plus a session bearer; Halo2 and Ironwood stay the payment proof.