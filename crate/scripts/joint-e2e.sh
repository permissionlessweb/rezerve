#!/usr/bin/env bash
# Run PIR tests, optionally attach Zakura, optionally run DEX integration-tests.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
cd "$ROOT"

if [[ -z "${ZAKURAD_BIN:-}" ]]; then
  for cand in ../zakura/target/zakura-regtest-e2e-linux/zakurad ../zakura/target/debug/zakurad ../zakura/target/release/zakurad; do
    if [[ -f "$cand" ]]; then
      export ZAKURAD_BIN="$(cd "$(dirname "$cand")" && pwd)/$(basename "$cand")"
      break
    fi
  done
fi

if [[ -n "${ZAKURAD_BIN:-}" ]]; then
  echo "native ict-rs-style lab: ZAKURAD_BIN=${ZAKURAD_BIN}"
  export ZAKURA_RPC="${ZAKURA_RPC:-http://127.0.0.1:18232}"
  export PIR_ZAKURA_LAB="${PIR_ZAKURA_LAB:-1}"
elif [[ "${PIR_ZAKURA_SPAWN:-}" == "1" ]] && [[ -f ../zakura/docker/docker-compose.zakura-regtest-e2e.yml ]]; then
  echo "spawning zakura-regtest-e2e (needs Linux zakurad; prefer ZAKURAD_BIN)"
  docker compose -f ../zakura/docker/docker-compose.zakura-regtest-e2e.yml up -d || true
  export ZAKURA_RPC="${ZAKURA_RPC:-http://127.0.0.1:18232}"
fi

# Modular local e2e (required modules, no Docker) then existing suite files.
cargo test --features e2e --test e2e_local
cargo test --test product_path --test frost_ed25519 --test zakura_live --test joint_suite

if [[ -d ../terp-rs/crates/seam_private_dex ]]; then
  echo "private seam DEX (IBC ZEC + FROST committees) — same ZAKURA_RPC"
  cargo test --features seam-dex --test seam_swap_joint
  (cd ../terp-rs/crates/seam_private_dex && cargo test) || \
    echo "seam_private_dex crate tests skipped/failed; PIR seam-dex tests still ran"
fi
