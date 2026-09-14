# Data structures

Normative field tables for [AEP-xxx](README.md). Byte encodings are little-endian unless noted. Hashes are 32-byte BLAKE2b tagged hashes (`tagged_hash(label, …)`).

## `PublicAsk`

Public resource request. Corresponds to an Akash **deployment** / **order**. Anyone may read it. Bid prices are not on this object.

| Field | Type | Constraint |
|---|---|---|
| `ask_id` | string | nonempty, opaque |
| `tenant_label` | string | bound into `ask_commitment` |
| `manifest_sdl` | string | nonempty SDL / manifest |
| `cpu_milli` | u64 | nonzero |
| `memory_mib` | u64 | nonzero |
| `storage_mib` | u64 | |
| `gpu_units` | u64 | |
| `inference_profile` | string | capacity profile |

```
ask_commitment = tagged_hash("private-rent-ask-v1",
  ask_id, tenant_label, manifest_sdl,
  cpu_milli, memory_mib, storage_mib, gpu_units,
  inference_profile)
```

| Derived | Type | On chain |
|---|---|---|
| `ask_commitment` | 32 bytes, 64-char hex | yes |

## `EncryptedBidEnvelope`

Sealed bid. Price is off the public order book. Delivered out of band. JSON matches crate `EncryptedBidEnvelope` and provider `pirgate.Envelope` (byte arrays as JSON number arrays).

| Field | Type | Notes |
|---|---|---|
| `ask_id` | string | binds envelope to the ask |
| `nonce` | 16 bytes | AEAD nonce is `nonce[0..12]` |
| `ciphertext` | bytes | ChaCha20-Poly1305 |
| `mac` | 32 bytes | Poly1305 tag is `mac[0..16]` |

Plaintext (never posted):

| Field | Type | Constraint |
|---|---|---|
| `ask_id` | string | |
| `bidder_identity` | string | |
| `price_uakt` | u64 | nonzero |
| `provider_endpoint` | string | |

AAD: length-prefixed `ask_id` (u64 LE) ‖ 16-byte nonce. Fresh nonce per seal. Open with the wrong key fails closed.

```
bid_commitment = tagged_hash("bid-commit-v1",
  ask_id, nonce, ciphertext, mac)
```

## `CommitmentStore`

On-chain record. No price, identity, endpoint, or envelope.

| Execute | Fields | Rule |
|---|---|---|
| `PostCommitments` | `ask_commitment`, `bid_commitment` | each 64-char hex |
| `Commit` | `key`, `value` | generic 64-char hex slots |

| Query | Input | Output |
|---|---|---|
| `GetCommitments` | — | stored hex pair |
| `Match` | `ask_commitment`, `bid_commitment` | `{ matches: bool }` |

`Match` is true only when both stored strings equal the query.

## `DerivedAccess`

Private-path lease credential. Not the public ES256K JWT.

```
secret     = tagged_hash("pir-access-v1", oob_aead_key, bid_commitment, ask_id)
bearer_hex = hex(tagged_hash("pir-access-bearer-v1", secret))
```

| Field | Type | Use |
|---|---|---|
| `bearer_hex` | 64-char hex | `Authorization: Bearer` |
| `lease_id` | string | lease book |

Winner opens. Foreign bearer denied. After `pir stop` / close, winner denied.

## `BidAskPir` (proposed)

Private information retrieval of sealed bids and public asks. The courier is an untrusted **provider proxy**. It MUST NOT learn which row was queried. Design mirrors Valar Group PIR (YPIR / SimplePIR).

| Field | Type | Notes |
|---|---|---|
| `row_id` | u64 | Index in the PIR database (not sent in the clear) |
| `row` | bytes | Fixed-size: envelope *or* ask commitment blob |
| `kind` | enum | `sealed_bid` \| `public_ask` |
| `query` | PIR query | Client hides `row_id` |
| `answer` | PIR answer | Only the client recovers `row` |
| `db_root` / hint | per scheme | YPIR silent preprocessing as in `valar-ypir` |

Direct OOB without this object is the crate today. This object is a required upcoming dependency.

## `ProviderProxy` (proposed)

| Field | Type | Notes |
|---|---|---|
| `endpoint` | URL | Serves PIR queries |
| `operator` | string | MAY be a third party, not the bidding provider |
| `index` | PIR database | Rows of `BidAskPir.row` |
| `trust` | — | Untrusted for query identity. Trusted only to return *some* answer; authenticity is the AEAD / commitment, not the proxy. |

## `FrostParams`

RFC 9591 FROST-ed25519. `t` of `n` is configuration, not a new market.

| Parameter | Type | Meaning |
|---|---|---|
| `n` (`max_signers`) | u16 | sidecars that hold a share |
| `t` (`min_signers`) | u16 | signatures that verify as the group |
| `ciphersuite` | const | FROST-ed25519 in this draft |
| `identifiers` | `1..=n` | seat ids |
| `placement[i]` | enum | `akash_lease` \| `wasmer` \| other |

First-demo profile: `t=2`, `n=3`. Placement is a **cross-chain collaboration** (one Akash lease, two local Wasmer). Penumbra-style validator sidecars are a welcome home for shares.

Lease profile (crate today): same `(t, n)` with seats labeled deployer, provider, resolver for close grants.

Dealer packages (`generate_with_dealer`) are not product custody.

## `IronwoodClose`

Product money is Ironwood notes (NU6.3, V3 plaintext, v6 tx). CosmWasm records a grant; it does not `BankMsg`.

| Step | What |
|---|---|
| Open | Shield into a note whose spend authority is the FROST group |
| Spend 1 | Consume opened note: earned → provider; remainder → group |
| Spend 2 | Consume remainder → deployer |
| Earned | `f(open_height, close_height, rate) = (close − open) × rate` from Zcash heights |
| Grant | `frost-spend-v1` over the opened Ironwood nullifier |
| SK | ZIP-32 (coin type 133) of the reconstructed DKG group seed |

ZIP-312 RedPallas is not in Zakura. Do not claim it.

## `AktStakeInclusion` (proposed)

ZK inclusion proof that a **market bidder** holds at least `min_stake_uakt` bonded or delegated AKT. Purpose: **buy-and-hold pressure on AKT** as a condition of private-market access, without publishing the bidder’s full staking identity on the bid.

| Field | Type | Notes |
|---|---|---|
| `min_stake_uakt` | u64 | threshold set by the market |
| `inclusion_root` | 32 bytes | staking / vesting tree root at a proven height |
| `proof` | Halo2 (or later) | bidder is in that tree with `stake ≥ min` |
| `public_instances` | list | root, min, amount class — not the account |

This object is **not** implemented in the crate today. It is a stated bias of this AEP: private bids should still **extend demand for AKT**.

## `PirGate`

`provider-services` allocate check.

| Env | Effect |
|---|---|
| PIR unset | `PirAllocationAllowed = true` (public Akash) |
| `PIR_REQUIRE_COMMIT=1` or `PIR_MODE=1` | fail closed without 32-byte hex commitments |
| `PIR_REQUIRE_ENVELOPE=1` | envelope **and** match URL required |
| `PIR_COMMIT_MATCH_URL` | CosmWasm `Match` must return true |
| `PIR_ZAP1_REQUIRE=1` | Halo2 / ZAP1 accept required |
