#!/bin/sh
# One production-shaped compose on the lab host. Fail if any step is skipped:
# ask, OOB bid/commitment match, ZAP1+Halo2 DKG credit, provider serve HTTP 200,
# close grant, two Ironwood spends, bearer deny.
# Never run on the laptop.
set -eu
set -o pipefail
export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/go/bin:/usr/local/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH}"
ROOT="${HOME}/abstract/re-zerve/crate"
AKASH="${HOME}/abstract/terp-core/crates/akash-provider-pir"
cd "$ROOT"

echo "host=$(hostname) cwd=$ROOT"

# v6.2.1's stack limiter is parity-wasm 0.45. rustc 1.86 call_indirect
# encodings fail it with "Invalid table reference (128)". wasm-opt -O1
# rewrites those into the form that parser accepts.
WASM_OPT="${WASM_OPT:-/opt/homebrew/bin/wasm-opt}"
rewrite_wasm() {
  src="$1"
  raw="${src}.unopt"
  stamp="${src}.opt-stamp"
  # Cargo leaves the previous optimized wasm in place when sources are unchanged.
  # Optimizing that file again is not the rustc output.
  if [ ! -f "$stamp" ] || [ "$src" -nt "$stamp" ]; then
    cp "$src" "$raw"
    "$WASM_OPT" -o "${src}.opt" -O1 "$raw"
    mv "${src}.opt" "$src"
    touch "$stamp"
  fi
}

STATUS="/tmp/rezerve-e2e-status"
LOG="${TMPDIR:-/tmp}/pir-production-sequence.log"
rm -f "$LOG"
: > "$STATUS"
E2E_REPORTED=0
report_fail() {
  E2E_REPORTED=1
  printf 'E2E_FAIL: %s\n' "$1" | tee -a "$STATUS"
  exit 1
}
trap 'ec=$?; if [ "$ec" -ne 0 ] && [ "$E2E_REPORTED" -eq 0 ]; then printf "E2E_FAIL: script_exit=%s\n" "$ec" | tee -a "$STATUS"; fi' EXIT

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
# Workspace members write into the re-zerve target, not crate/target.
WS="${HOME}/abstract/re-zerve"
TARGET="${CARGO_TARGET_DIR:-${WS}/target}"
BIN="${TARGET}/debug/pir-zap1-lc"
if [ ! -x "$BIN" ]; then
  echo "pir-zap1-lc missing after build" >&2
  exit 1
fi
export PIR_ZAP1_LC_BIN="$BIN"

echo "building cw_pir_commit.wasm with rustc 1.86 (no bulk-memory)"
rustup target add wasm32-unknown-unknown --toolchain 1.88.0 >/dev/null
(
  cd "${ROOT}/cw-commit"
  # v6.2.1 wasmvm rejects rustc 1.86 GC/function-references type sections.
  export RUSTFLAGS="-C target-cpu=mvp"
  rustup run 1.88.0 cargo build --release --lib --target wasm32-unknown-unknown
)
WASM="${TARGET}/wasm32-unknown-unknown/release/cw_pir_commit.wasm"
if [ ! -f "$WASM" ]; then
  echo "cw_pir_commit.wasm missing after 1.86 build" >&2
  exit 1
fi
rewrite_wasm "$WASM"
export PIR_COMMIT_WASM="$WASM"
echo "PIR_COMMIT_WASM=$PIR_COMMIT_WASM"

echo "building cw_zap1_ibcv2.wasm with rustc 1.86 (no bulk-memory)"
(
  cd "${ROOT}/cw-zap1-ibcv2"
  export RUSTFLAGS="-C target-cpu=mvp"
  rustup run 1.88.0 cargo build --release --lib --target wasm32-unknown-unknown
)
ZAP1_WASM="${TARGET}/wasm32-unknown-unknown/release/cw_zap1_ibcv2.wasm"
if [ ! -f "$ZAP1_WASM" ]; then
  echo "cw_zap1_ibcv2.wasm missing after 1.86 build" >&2
  exit 1
fi
rewrite_wasm "$ZAP1_WASM"
export PIR_ZAP1_WASM="$ZAP1_WASM"
echo "PIR_ZAP1_WASM=$PIR_ZAP1_WASM"

echo "building cw_pir_escrow.wasm with rustc 1.86 (no bulk-memory)"
(
  cd "${ROOT}/cw-escrow"
  export RUSTFLAGS="-C target-cpu=mvp"
  rustup run 1.88.0 cargo build --release --lib --target wasm32-unknown-unknown
)
ESCROW_WASM="${TARGET}/wasm32-unknown-unknown/release/cw_pir_escrow.wasm"
if [ ! -f "$ESCROW_WASM" ]; then
  echo "cw_pir_escrow.wasm missing after 1.86 build" >&2
  exit 1
fi
rewrite_wasm "$ESCROW_WASM"
export PIR_ESCROW_WASM="$ESCROW_WASM"
echo "PIR_ESCROW_WASM=$PIR_ESCROW_WASM"

echo "building cw_ics08_wasm_zap1.wasm inside terp-rs (workspace deps)"
TERP_RS="${HOME}/abstract/terp-core/crates/terp-rs"
(
  cd "${TERP_RS}"
  export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
  export RUSTFLAGS="-C target-cpu=mvp"
  rustup run 1.88.0 cargo build --release --lib --target wasm32-unknown-unknown -p cw-ics08-wasm-zap1
)
ICS08_WASM="${TERP_RS}/target/wasm32-unknown-unknown/release/cw_ics08_wasm_zap1.wasm"
if [ ! -f "$ICS08_WASM" ]; then
  echo "cw_ics08_wasm_zap1.wasm missing after build" >&2
  exit 1
fi
rewrite_wasm "$ICS08_WASM"
export PIR_ICS08_WASM="$ICS08_WASM"
echo "PIR_ICS08_WASM=$PIR_ICS08_WASM"

echo "exporting Pasta Halo2 store-full-circuit (params + vk_body + proof)"
HALO2_DIR="${ROOT}/artifacts/halo2"
mkdir -p "${HALO2_DIR}"
# August artifacts do not match the circuit sources. Re-export once from
# the current pir-export-halo2 when a source is newer than proof.bin.
stale=""
if [ -f "${HALO2_DIR}/proof.bin" ]; then
  stale=$(find "${ROOT}/circuits/hosting-payment/src" -name "*.rs" -newer "${HALO2_DIR}/proof.bin" -print -quit || true)
fi
if [ ! -s "${HALO2_DIR}/proof.bin" ] || [ ! -s "${HALO2_DIR}/params.bin" ] || [ ! -s "${HALO2_DIR}/vk_body.bin" ] || [ -n "$stale" ]; then
  rm -f "${HALO2_DIR}/proof.bin" "${HALO2_DIR}/params.bin" "${HALO2_DIR}/vk_body.bin" "${HALO2_DIR}/instances.bin"
  "${TARGET}/debug/pir-export-halo2" "${HALO2_DIR}"
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

# registry.terp.network/terp-core:v6.5.0 is not in the registry. Do not retag
# another image as v6.5.0. The chain image on this host is terp-core:local-arm64.
# local-arm64 is the tag on this host. It is not the retired tag "local"
# and it is not v6.5.0. Do not retag the image.
export TERP_IMAGE_REPO="${TERP_IMAGE_REPO:-terp-core}"
export TERP_IMAGE_VERSION="${TERP_IMAGE_VERSION:-local-arm64}"
export PIR_TERP_IMAGE="${PIR_TERP_IMAGE:-${TERP_IMAGE_REPO}:${TERP_IMAGE_VERSION}}"
echo "terpd version inside ${PIR_TERP_IMAGE}:"
terpd_ver="$(docker run --rm --entrypoint terpd "${PIR_TERP_IMAGE}" version 2>&1 | tr -d $'\r' | tail -n 1)"
printf '%s\n' "${terpd_ver}"
case "${terpd_ver}" in
  6.4.0)
    export PIR_BENCH_LABEL="terpd 6.4.0"
    ;;
  *)
    echo "refusing to label ${PIR_TERP_IMAGE} as v6.5.0; terpd version is: ${terpd_ver}" >&2
    exit 1
    ;;
esac
echo "bench_label=${PIR_BENCH_LABEL} image=${PIR_TERP_IMAGE}"
export PIR_E2E_BENCH_PATH="${HOME}/abstract/re-zerve/artifacts/bench/e2e-history.jsonl"
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

echo "waiting for Linux zakurad ${ZAKURAD_BIN}"
i=0
while [ ! -x "${ZAKURAD_BIN}" ]; do
  build_running=0
  if pgrep -f ubuntu-package.Dockerfile >/dev/null 2>&1; then
    build_running=1
  fi
  if docker ps --format "{{.Names}}" | grep -qx zakurad-build; then
    build_running=1
  fi
  if [ "$build_running" -eq 0 ]; then
    echo "zakurad build is not running and ${ZAKURAD_BIN} is missing" >&2
    exit 1
  fi
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then
    echo "zakurad build still running after 60 minutes" >&2
    exit 1
  fi
  sleep 30
done
docker run --rm -v "${ZAKURAD_BIN}:/usr/local/bin/zakurad:ro" debian:trixie-slim /usr/local/bin/zakurad --version
echo "ONE compose: production sequence (fail if any step skipped)"
set +e
cargo test --features live-ict,e2e,cw-orch-suite --test e2e_local \
  production_sequence_ask_oob_bid_zap1_halo2_dkg_allocate_serve_close_grant_two_ironwood_bearer_deny \
  -- --nocapture --exact >"$LOG" 2>&1
test_ec=$?
set -e
if [ "$test_ec" -ne 0 ]; then
  reason="$(python3 - "$LOG" <<'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
bits = []
m = re.search(r"panicked at ([^:\n]+):(\d+)", text)
if m:
    bits.append(f"panic={m.group(1)}:{m.group(2)}")
for pat in (
    r"ZkError error: [^\n\\]{0,180}",
    r"image tag is gone",
    r"can't compile schema generator[^\n]{0,80}",
    r"could not compile \S+",
    r"No such file or directory",
):
    hit = re.search(pat, text)
    if hit:
        bits.append(re.sub(r"\s+", " ", hit.group(0))[:180])
        break
print(" | ".join(bits) if bits else "cargo test failed")
PY
)"
  if grep -E -q "DecodeError|decode limit|4194304|exceeds max size|message length" "$LOG"; then
    echo "INSTANTIATE_DECODE_STOP" | tee -a "$STATUS"
    echo "wasm_commit_bytes=$(wc -c < "$WASM" | tr -d " ")" | tee -a "$STATUS"
    echo "wasm_zap1_bytes=$(wc -c < "$ZAP1_WASM" | tr -d " ")" | tee -a "$STATUS"
    echo "wasm_escrow_bytes=$(wc -c < "$ESCROW_WASM" | tr -d " ")" | tee -a "$STATUS"
    echo "wasm_ics08_bytes=$(wc -c < "$ICS08_WASM" | tr -d " ")" | tee -a "$STATUS"
    python3 - "$LOG" <<'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
for line in text.splitlines():
    if re.search(r"cosmrs|Decode|4194304|too large|instantiate", line, re.I):
        print("DECODE_CTX:", line[:400])
PY
    echo "stopping; not retrying the same instantiate decode failure" | tee -a "$STATUS"
  fi
  report_fail "cargo_test_exit=${test_ec} ${reason}"
fi

require() {
  grep -q "$1" "$LOG" || report_fail "missing $2"
}
require "STEP public_sdl_ask" "public_sdl_ask"
require "STEP chacha_oob_bid_commit_match" "chacha_oob_bid_commit_match"
require "STEP zap1_halo2_dkg_credit" "zap1_halo2_dkg_credit"
require "STEP provider_allocate_after_commit_match" "provider_allocate_after_commit_match"
require "STEP pir_serve_http_200" "pir_serve_http_200"
require "STEP close_grant_lc_attrs" "close_grant_lc_attrs"
require "STEP two_ironwood_spends" "two_ironwood_spends"
require "STEP bid_ask_pir_two_proxy_xor" "bid_ask_pir_two_proxy_xor"
require "bid_pir_retrieval=two-proxy-xor not_ypir=true" "two-proxy XOR retrieval"
require "STEP akt_min_stake_inclusion" "akt_min_stake_inclusion"
require "akt_min_stake proof_live=false statement=held verify=rejected" "akt proof not live"
require "STEP frost_close_stall_finish_amounts" "frost_close_stall_finish_amounts"
require "below_threshold_spend=false" "below-threshold spend"
require "closer_set_earned=false" "closer set earned"
require "ironwood_spend_stand_in=frost-spend-v1+zip32-reconstructed-dkg-seed" "ZIP-32 stand-in"
require "STEP winner_bearer_denied" "winner_bearer_denied"
require "PRODUCTION_SEQUENCE_OK" "PRODUCTION_SEQUENCE_OK"
require "dummy_used=false" "dummy_used=false"
require "serve_http=200" "serve_http=200"
require "halo2_accrual_ok" "halo2_accrual_ok"
require "LIVE_CW_PIR_COMMIT_MATCH_OK" "LIVE_CW_PIR_COMMIT_MATCH_OK"
require "ZAP1_DKG_CREDIT_OK" "ZAP1_DKG_CREDIT_OK"
require "E2E_BENCH " "E2E_BENCH"
bench_line="$(grep '^E2E_BENCH ' "$LOG" | tail -1)"
printf '%s\n' "$bench_line" | tee -a "$STATUS"
printf 'PRODUCTION_SEQUENCE_COMPOSE_OK\n' | tee -a "$STATUS"
