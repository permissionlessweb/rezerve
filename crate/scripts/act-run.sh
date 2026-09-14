#!/usr/bin/env bash
# Run the crate workflow under nektos/act and always reap leftover containers.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cleanup() {
  set +e
  echo "[act-run] reaping leftover act containers/networks..."
  if command -v docker >/dev/null 2>&1; then
    reap_ids() {
      local ids
      ids="$(cat || true)"
      if [ -n "$ids" ]; then
        # shellcheck disable=SC2086
        docker rm -f $ids >/dev/null 2>&1
      fi
    }
    docker ps -aq --filter "name=act-" 2>/dev/null | reap_ids
    docker ps -aq --filter "label=act" 2>/dev/null | reap_ids
    while IFS= read -r net; do
      [ -n "$net" ] && docker network rm "$net" >/dev/null 2>&1
    done < <(docker network ls --format '{{.Name}}' 2>/dev/null | grep -E '^act-' || true)
  fi
  return 0
}

trap cleanup EXIT INT TERM

if ! command -v act >/dev/null 2>&1; then
  echo "act is not installed (https://github.com/nektos/act)" >&2
  exit 127
fi

# Prefer workflow inside this crate; fall back to monorepo path.
WF="$ROOT/.github/workflows/private-inference-rent.yml"
if [[ ! -f "$WF" ]]; then
  echo "missing $WF" >&2
  exit 1
fi

# ACT=true is also set by act itself; we set it so cleanup steps fire.
export ACT=true

# --rm: delete job container when the job ends (act often skips this).
# Do not pass --reuse — that is the usual source of hung containers.
act --rm --workflows "$WF" "$@"
