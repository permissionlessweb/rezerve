#!/bin/sh
# Toolchain for the re-zerve lab sequence.
# Run from the repository root, on a host that is allowed to compile.
# `mise run setup` calls this. `mise run check -- <package>` typechecks one crate.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing $1" >&2
    exit 1
  fi
}

setup() {
  need rustup
  need cargo
  rustup toolchain install 1.88.0
  rustup target add wasm32-unknown-unknown --toolchain 1.88.0
  need go
  need python3
  need docker
  if ! command -v wasm-opt >/dev/null 2>&1; then
    echo "wasm-opt is not on PATH. Install binaryen. The v6.2.1 stack limiter needs one wasm-opt -O1 from rustc output, not a second pass." >&2
    exit 1
  fi
  echo "demo env ready at $ROOT"
  echo "rust $(rustup run 1.88.0 rustc --version)"
  echo "go $(go version)"
  echo "wasm-opt $(wasm-opt --version | head -1)"
}

check_pkg() {
  need cargo
  if [ "$#" -eq 0 ]; then
    cargo check --workspace --offline --manifest-path "$ROOT/Cargo.toml"
    return
  fi
  cargo check --offline --manifest-path "$ROOT/Cargo.toml" -p "$1"
}

test_contracts() {
  need cargo
  cargo test --offline --manifest-path "$ROOT/Cargo.toml" \
    -p cw-pir-commit -p cw-pir-escrow -p cw-zap1-ibcv2 -p pir-cw-orch
}

demo() {
  need docker
  # shellcheck disable=SC1091
  image="${PIR_TERP_IMAGE:-terp-core:local-arm64}"
  if [ "$image" = "registry.terp.network/terp-core:v6.5.0" ] || [ "$image" = "v6.5.0" ]; then
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      echo "refusing to run: $image is not local. Do not retag another image as v6.5.0." >&2
      exit 1
    fi
  fi
  exec sh "$ROOT/crate/scripts/lab-production-loop.sh"
}

usage() {
  echo "usage: scripts/demo-env.sh setup | check [package] | test-contracts | demo" >&2
  exit 2
}

cmd=${1:-}
shift || true
case "$cmd" in
  setup) setup ;;
  check) check_pkg "$@" ;;
  test-contracts) test_contracts ;;
  demo) demo ;;
  *) usage ;;
esac
