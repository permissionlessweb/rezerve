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

Private-path lease credential. Not the public ES256K JWT. The lease-long bearer is stable for the note and re-links sessions. Session auth is a separate bearer from the same out-of-band key plus a session nonce. `PIR_*` env names are the allocate gate, not this derivation.

```
secret         = tagged_hash("pir-access-v1", oob_aead_key, bid_commitment, ask_id)
bearer_hex     = hex(tagged_hash("pir-access-bearer-v1", secret))
session_secret = tagged_hash("pir-access-session-v1",
                   oob_aead_key, bid_commitment, ask_id, session_nonce)
session_bearer = hex(tagged_hash("pir-access-session-bearer-v1", session_secret))
```

| Field | Type | Use |
|---|---|---|
| `note` (`bid_commitment`) | 32 bytes | payment-note binding; unchanged when the session nonce rotates |
| `session_nonce` | 32 bytes | fresh per session; not a renter id |
| `session_bearer` | 64-char hex | `Authorization: Bearer` for this session only |
| `bearer_hex` | 64-char hex | lease binding; not a session credential |
| `lease_id` | string | lease book |

Winner session opens. A second session bearer differs. A foreign bearer is denied. After rotate or `pir stop` / close, the previous session bearer is denied. The note stays the same.

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
| Earned | `f(open_height, close_height, rate) = (close − open) × rate` from Zcash heights. The closer cannot set earned. |
| Note binding | Halo2 accrual (`pir-accrual.f.v1`, Pasta) binds that `f` to the opened Ironwood note id (32-byte nullifier) inside the BLAKE2b witness, the way zkAPI binds balance to `note_id`. The note id is not a public instance. A different note does not open the same commitment. |
| Public instances | Accrual, 96 bytes: packed commitment, open header hash, close header hash. `HOSTING_PAYMENT`, 128 bytes: merkle root, FROST group, amount class, kind. Neither list carries a renter id or an account. |
| Grant | `frost-spend-v1` over the opened Ironwood nullifier |
| SK | ZIP-32 (coin type 133) of the reconstructed DKG group seed |

`PIR_*` on the provider is the allocate gate. It is not this note binding and not cryptographic private information retrieval.

ZIP-312 RedPallas is not in Zakura. Do not claim it. Stay on Ironwood notes and Halo2 on Pasta. Do not port an ETH vault, Groth16, or BN254.

## `AktStakeInclusion` (proposed)

ZK inclusion statement that a **market bidder** holds at least `min_stake_uakt` bonded or delegated AKT. Purpose: **buy-and-hold pressure on AKT** as a condition of private-market access, without publishing the bidder's bonding account or a renter id.

**Status:** the public-instance struct is in `crate/src/akt_stake.rs`. The Halo2 proof is **not live**. `verify_akt_stake_inclusion` fails closed (`ProofNotLive`) for empty and nonempty bytes. `statement_holds` is a cleartext check that `stake_uakt ≥ min_stake_uakt` and that the bonding account is absent from the instance bytes. That check is not a proof. The crate does not query Akash, does not ship a mainnet staking snapshot, and does not claim mainnet AKT.

### Public instances

96 bytes, three little-endian Pallas elements (same 254-bit pack as other Pasta instances in this crate). Not the 128-byte `HOSTING_PAYMENT` list. No bonding account. No renter id. No exact stake.

| Row | Field | Type | Constraint |
|---|---|---|---|
| 0 | `inclusion_root` | 32 bytes | Market-chosen staking or vesting tree root, packed. Not an account. Not fetched from Akash mainnet. |
| 1 | `min_stake_uakt` | u64 | Nonzero threshold, little-endian in the field. Public. |
| 2 | `amount_class` | 32 bytes | Domain `AKT_STAKE_GE_MIN`. Circuit kind. Not the bidder's balance and not a balance bucket. |

### Witness (not an instance)

| Field | Type | Constraint |
|---|---|---|
| `bonding_account` | bytes | Nonempty. Must not occur in the 96 instance bytes. |
| `stake_uakt` | u64 | Private. Relation is `stake_uakt ≥ min_stake_uakt`. |

### Intended Halo2 relation (not live)

Pasta PLONK, same curve family as accrual and `HOSTING_PAYMENT`. Not Groth16. Not BN254. No verifying key is shipped.

| Step | Constraint |
|---|---|
| Leaf | BLAKE2b-256, personal `akt-stake-v0`, over `bonding_account` and `stake_uakt` (u64 LE) |
| Inclusion | Merkle opening of that leaf to `inclusion_root` (personal `akt-stake-mrk` on nodes) |
| Range | `stake_uakt ≥ min_stake_uakt` |
| Public | The three rows above only |

The crate does not evaluate this relation. A full circuit is larger than this pass (accrual and `HOSTING_PAYMENT` already sit at k=17 / k=18). Until a real `verify_proof` exists, callers must treat every proof as rejected.

| API | Behavior |
|---|---|
| `AktStakePublic::new` | Builds the three public rows. Rejects `min_stake_uakt = 0`. Takes no account and no renter id. |
| `statement_holds` | Cleartext relation and account-absence check. Not a proof. |
| `prove_akt_stake_inclusion` | If the statement fails, returns that error. If it holds, returns `ProofNotLive` and no bytes. |
| `verify_akt_stake_inclusion` | Always `ProofNotLive`. |

`PIR_*` on the provider is the allocate gate. It is not this inclusion check and not cryptographic private information retrieval.

Ironwood notes stay the payment asset. This object does not add an ETH vault or a second curve.

## `PirGate`

`provider-services` allocate check.

| Env | Effect |
|---|---|
| PIR unset | `PirAllocationAllowed = true` (public Akash) |
| `PIR_REQUIRE_COMMIT=1` or `PIR_MODE=1` | fail closed without 32-byte hex commitments |
| `PIR_REQUIRE_ENVELOPE=1` | envelope **and** match URL required |
| `PIR_COMMIT_MATCH_URL` | CosmWasm `Match` must return true |
| `PIR_ZAP1_REQUIRE=1` | Halo2 / ZAP1 accept required |
