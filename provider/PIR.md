# re-zerve (PIR) native market path

Upstream: `e70d473` (shallow). This tree is **`crates/akash-provider-pir`**.

This binary is how a provider **allocates inference/compute** against the private market. Stock `ghcr.io/akash-network/provider` does not implement this path.

## Workflow (native)

1. **Commit** — `PIR_REQUIRE_COMMIT=1` (or `PIR_MODE=1`). Allocate only when ask + bid commitments are 32-byte hex. Bid hex may be derived from a ChaCha20-Poly1305 OOB envelope (`PIR_BID_ENVELOPE_FILE`). When `PIR_COMMIT_MATCH_URL` is set, allocate only after that query returns `{"matches":true}` (cw-pir-commit `Match`). Optional `PIR_ZAP1_REQUIRE=1` waits for Halo2/ZAP1 accept JSON.
2. **Accept** — `provider-services pir accept --lease L --bearer <64-hex>` writes `PIR_LEASE_BOOK_FILE`. Gateway `AuthProcess` treats that bearer as full lease access (**DerivedAccess**, not ES256K).
3. **Access** — `Authorization: Bearer <64-hex>`. Foreign bearer denied.
4. **Serve** — `provider-services pir serve --lease L --bearer <hex>` `docker run`s a lightweight HTTP container (`python:3.12-alpine` by default). Confirmed running + HTTP 200 (in-container GET, not only `State.Running`).
5. **Sidecar** — `provider-services pir sidecar` keep-alive `/health` on `:8444` for ict-rs. `akash_provider_config` / `pir_provider_sidecar_config` mount `/var/run/docker.sock`. Image `akash-provider-pir:local`.
6. **Close** — `provider-services pir stop --lease L` removes the container and denies the bearer without restart.

Public market default (env unset) still bids.

## Env

| Var | Role |
|---|---|
| `PIR_REQUIRE_COMMIT=1` / `PIR_MODE=1` | Private-market gate |
| `PIR_ASK_COMMIT` / `PIR_ASK_COMMIT_FILE` | 64-hex ask commitment |
| `PIR_BID_COMMIT` / `PIR_BID_COMMIT_FILE` | 64-hex bid commitment (file must be hex, not merely nonempty) |
| `PIR_BID_ENVELOPE` / `PIR_BID_ENVELOPE_FILE` | ChaCha20-Poly1305 OOB envelope JSON; bid hex is `bid-commit-v1` |
| `PIR_REQUIRE_ENVELOPE=1` | Fail closed unless a ChaCha envelope is present |
| `PIR_SESSION_KEY` | 64-hex OOB key; when set with an envelope, Open must succeed |
| `PIR_COMMIT_MATCH_URL` | POST `{ask_commitment,bid_commitment}` → `{matches}` (cw-pir-commit) |
| `PIR_ZAP1_REQUIRE=1` | Also require Halo2/ZAP1 accept |
| `PIR_ZAP1_ACCEPT_FILE` / `PIR_ZAP1_ACCEPT_URL` | JSON with `zap1_halo2_accepted` or `matches` |
| `PIR_LEASE_BOOK_FILE` | JSON lease book (accept/close persist) |
| `PIR_ACCESS_BEARERS` / `PIR_ACCESS_BEARERS_FILE` | Extra allow-list; **file is reread every request** |
| `PIR_PROVIDER_IMAGE` | ict-rs sidecar image (`repo:tag`) for this fork (default `akash-provider-pir:local`) |
| `PIR_SERVE_IMAGE` | Lease container image (default `python:3.12-alpine`) |

## Tests

```bash
go test ./gateway/pir ./bidengine -count=1
```

```bash
go build -o provider-services ./cmd/provider-services
PIR_REQUIRE_COMMIT=1 ./provider-services pir check
```

Image (linux binary + docker client, `pir sidecar` by default):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o provider-services ./cmd/pir-sidecar
docker build -f Dockerfile.pir -t akash-provider-pir:local .
```

Sidecar + spawn/serve on the lab host: `scripts/lab-provider-sidecar.sh`.

jwt-verify replace should point here: `crates/akash-provider-pir`.
