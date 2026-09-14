#!/bin/sh
# One production-shaped compose on the lab host. Fail if any step is skipped:
# ask, OOB bid/commitment match, ZAP1+Halo2 DKG credit, provider serve HTTP 200,
# close grant, two Ironwood spends, bearer deny.
# Never run on the laptop.
set -eu
set -o pipefail
export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/go/bin:/usr/local/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH}"
ROOT="${HOME}/abstract/terp-core/crates/private-inference-rent"
AKASH="${HOME}/abstract/terp-core/crates/akash-provider-pir"
cd "$ROOT"

echo "host=$(hostname) cwd=$ROOT"

echo "reaping leftover ict-pir-live-attach / pir-live-1 / pir-prod-seq containers"
for filter in name=pir-live name=ict-pir-live name=pir-lease name=pir-ict-sidecar name=pir-cw-commit name=pir-prod-seq; do
  ids="$(docker ps -aq --filter "$filter" 2>/dev/null || true)"
  if [ -n "$ids" ]; then
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null 2>&1 || true
  fi
done
docker rm -f \
  ict-pir-live-attach-pir-live-1-val-0 \
  pir-live-1 \
  pir-ict-sidecar-prod \
  pir-cw-commit-match-prod \
  pir-lease-lease-prod-seq \
  pir-zcashd-wallet \
  >/dev/null 2>&1 || true
unset ZCASHD_RPC || true

echo "building pir-zap1-lc + pir-export-halo2"
cargo build --bin pir-zap1-lc --bin pir-export-halo2 --features export-halo2
BIN="${ROOT}/target/debug/pir-zap1-lc"
if [ ! -x "$BIN" ]; then
  echo "pir-zap1-lc missing after build" >&2
  exit 1
fi
export PIR_ZAP1_LC_BIN="$BIN"

echo "building cw_pir_commit.wasm with rustc 1.86 (no bulk-memory)"
rustup target add wasm32-unknown-unknown --toolchain 1.86 >/dev/null
(
  cd "${ROOT}/cw-commit"
  rustup run 1.86 cargo build --release --target wasm32-unknown-unknown
)
WASM="${ROOT}/cw-commit/target/wasm32-unknown-unknown/release/cw_pir_commit.wasm"
if [ ! -f "$WASM" ]; then
  echo "cw_pir_commit.wasm missing after 1.86 build" >&2
  exit 1
fi
export PIR_COMMIT_WASM="$WASM"
echo "PIR_COMMIT_WASM=$PIR_COMMIT_WASM"

echo "building cw_zap1_ibcv2.wasm with rustc 1.86 (no bulk-memory)"
(
  cd "${ROOT}/cw-zap1-ibcv2"
  rustup run 1.86 cargo build --release --target wasm32-unknown-unknown
)
ZAP1_WASM="${ROOT}/cw-zap1-ibcv2/target/wasm32-unknown-unknown/release/cw_zap1_ibcv2.wasm"
if [ ! -f "$ZAP1_WASM" ]; then
  echo "cw_zap1_ibcv2.wasm missing after 1.86 build" >&2
  exit 1
fi
export PIR_ZAP1_WASM="$ZAP1_WASM"
echo "PIR_ZAP1_WASM=$PIR_ZAP1_WASM"

echo "building cw_pir_escrow.wasm with rustc 1.86 (no bulk-memory)"
(
  cd "${ROOT}/cw-escrow"
  rustup run 1.86 cargo build --release --target wasm32-unknown-unknown
)
ESCROW_WASM="${ROOT}/cw-escrow/target/wasm32-unknown-unknown/release/cw_pir_escrow.wasm"
if [ ! -f "$ESCROW_WASM" ]; then
  echo "cw_pir_escrow.wasm missing after 1.86 build" >&2
  exit 1
fi
export PIR_ESCROW_WASM="$ESCROW_WASM"
echo "PIR_ESCROW_WASM=$PIR_ESCROW_WASM"

echo "building cw_ics08_wasm_zap1.wasm with rustc 1.86 (no bulk-memory)"
TERP_RS="${HOME}/abstract/terp-core/crates/terp-rs"
ICS08_SRC="${TERP_RS}/crates/cw-ics08-wasm-zap1"
ICS08_BUILD="${TMPDIR:-/tmp}/pir-ics08-wasm"
rm -rf "${ICS08_BUILD}"
mkdir -p "${ICS08_BUILD}"
cp -a "${ICS08_SRC}/." "${ICS08_BUILD}/"
python3 - "$ICS08_BUILD/Cargo.toml" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
t = p.read_text()
cut = t.split("[target.")[0].rstrip() + "\n"
p.write_text(cut)
PY
(
  cd "${ICS08_BUILD}"
  export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
  rustup run 1.86 cargo build --release --target wasm32-unknown-unknown
)
ICS08_WASM="${ICS08_BUILD}/target/wasm32-unknown-unknown/release/cw_ics08_wasm_zap1.wasm"
if [ ! -f "$ICS08_WASM" ]; then
  echo "cw_ics08_wasm_zap1.wasm missing after 1.86 build" >&2
  exit 1
fi
export PIR_ICS08_WASM="$ICS08_WASM"
echo "PIR_ICS08_WASM=$PIR_ICS08_WASM"

echo "exporting Pasta Halo2 store-full-circuit (params + vk_body + proof)"
HALO2_DIR="${ROOT}/artifacts/halo2"
mkdir -p "${HALO2_DIR}"
if [ ! -s "${HALO2_DIR}/proof.bin" ] || [ ! -s "${HALO2_DIR}/params.bin" ] || [ ! -s "${HALO2_DIR}/vk_body.bin" ]; then
  "${ROOT}/target/debug/pir-export-halo2" "${HALO2_DIR}"
fi
if [ ! -s "${HALO2_DIR}/proof.bin" ] || [ ! -s "${HALO2_DIR}/params.bin" ]; then
  echo "halo2 artifacts missing after pir-export-halo2" >&2
  exit 1
fi
export PIR_HALO2_PARAMS="${HALO2_DIR}/params.bin"
export PIR_HALO2_VK_BODY="${HALO2_DIR}/vk_body.bin"
export PIR_HALO2_PROOF="${HALO2_DIR}/proof.bin"
export PIR_HALO2_INSTANCES="${HALO2_DIR}/instances.bin"
echo "PIR_HALO2_PARAMS=$PIR_HALO2_PARAMS"

echo "building pir-live-attach (daemon_builder_from_chain + deploy_on Daemon)"
(
  cd "${ROOT}/live-chain"
  cargo build --bin pir-live-attach
)
ATTACH="${ROOT}/live-chain/target/debug/pir-live-attach"
if [ ! -x "$ATTACH" ]; then
  echo "pir-live-attach missing after build" >&2
  exit 1
fi
export PIR_LIVE_ATTACH_BIN="$ATTACH"
echo "PIR_LIVE_ATTACH_BIN=$PIR_LIVE_ATTACH_BIN"

export PIR_ZAKURA_LAB=1
export ZAKURAD_BIN="${ZAKURAD_BIN:-$HOME/abstract/terp-core/crates/zakura/target/zakura-regtest-e2e-linux/zakurad}"
export PIR_REQUIRE_COMMIT=1
export PIR_REQUIRE_ENVELOPE=1
export PIR_PROVIDER_IMAGE="${PIR_PROVIDER_IMAGE:-akash-provider-pir:local}"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "docker required for production sequence pir serve" >&2
  exit 1
fi

echo "ensuring provider sidecar image ${PIR_PROVIDER_IMAGE}"
if ! docker image inspect "$PIR_PROVIDER_IMAGE" >/dev/null 2>&1; then
  echo "building linux provider-services for sidecar image"
  (
    cd "$AKASH"
    arch="$(uname -m)"
    case "$arch" in
      arm64|aarch64) GOARCH=arm64 ;;
      x86_64|amd64) GOARCH=amd64 ;;
      *) echo "unsupported arch $arch" >&2; exit 1 ;;
    esac
    CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -o provider-services ./cmd/pir-sidecar
    docker build -f Dockerfile.pir -t "$PIR_PROVIDER_IMAGE" .
  )
fi
docker image inspect -f '{{.Os}}/{{.Architecture}} {{.RepoTags}}' "$PIR_PROVIDER_IMAGE"
echo "pull lightweight serve image"
docker pull python:3.12-alpine >/tmp/pir-python-pull.txt

LOG="${TMPDIR:-/tmp}/pir-production-sequence.log"
rm -f "$LOG"
echo "ONE compose: production sequence (fail if any step skipped)"
cargo test --features live-ict,e2e,cw-orch-suite --test e2e_local \
  production_sequence_ask_oob_bid_zap1_halo2_dkg_allocate_serve_close_grant_two_ironwood_bearer_deny \
  -- --nocapture --exact 2>&1 | tee "$LOG"

grep -q "STEP public_sdl_ask" "$LOG" || { echo "skipped public_sdl_ask" >&2; exit 1; }
grep -q "STEP chacha_oob_bid_commit_match" "$LOG" || { echo "skipped chacha_oob_bid_commit_match" >&2; exit 1; }
grep -q "STEP zap1_halo2_dkg_credit" "$LOG" || { echo "skipped zap1_halo2_dkg_credit" >&2; exit 1; }
grep -q "STEP provider_allocate_after_commit_match" "$LOG" || { echo "skipped provider_allocate_after_commit_match" >&2; exit 1; }
grep -q "STEP pir_serve_http_200" "$LOG" || { echo "skipped pir_serve_http_200" >&2; exit 1; }
grep -q "STEP close_grant_lc_attrs" "$LOG" || { echo "skipped close_grant_lc_attrs" >&2; exit 1; }
grep -q "STEP two_ironwood_spends" "$LOG" || { echo "skipped two_ironwood_spends" >&2; exit 1; }
grep -q "STEP winner_bearer_denied" "$LOG" || { echo "skipped winner_bearer_denied" >&2; exit 1; }
grep -q "PRODUCTION_SEQUENCE_OK" "$LOG" || { echo "missing PRODUCTION_SEQUENCE_OK" >&2; exit 1; }
grep -q "dummy_used=false" "$LOG" || { echo "dummy_used not false" >&2; exit 1; }
grep -q "serve_http=200" "$LOG" || { echo "pir serve HTTP 200 missing" >&2; exit 1; }
grep -q "halo2_accrual_ok" "$LOG" || { echo "skipped halo2 of f(open,close,rate)" >&2; exit 1; }
grep -q "LIVE_CW_PIR_COMMIT_MATCH_OK" "$LOG" || { echo "skipped live cw-pir-commit match" >&2; exit 1; }
grep -q "ZAP1_DKG_CREDIT_OK" "$LOG" || { echo "skipped credit_deposit_zap1" >&2; exit 1; }
echo "PRODUCTION_SEQUENCE_COMPOSE_OK"
