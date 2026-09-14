#!/bin/sh
# Native re-zerve provider workflow. Run ON the lab host (go + optional docker).
set -eu
export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/go/bin:/usr/local/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH}"
ROOT="${HOME}/abstract/terp-core/crates/akash-provider-pir"
PIR="${HOME}/abstract/terp-core/crates/private-inference-rent"
cd "$ROOT"
echo "host=$(hostname) cwd=$ROOT"

go test ./gateway/pir ./pirgate ./bidengine -count=1 -timeout 180s \
  -run 'PirAllocation|MarketWorkflow|BearerFileReload|BearerMatches|ClosedLease|AcceptBearer|ServeSpawns'

echo "building provider-services (pir check/accept/close)"
go build -o /tmp/provider-services-pir ./cmd/provider-services
PIR_REQUIRE_COMMIT=1 /tmp/provider-services-pir pir check | tee /tmp/pir-check.json
grep -q '"allocate":false' /tmp/pir-check.json

ASK="$(python3 -c 'print("aa"+"0"*62)')"
BID="$(python3 -c 'print("bb"+"0"*62)')"
export PIR_REQUIRE_COMMIT=1
export PIR_ASK_COMMIT="$ASK"
export PIR_BID_COMMIT="$BID"
/tmp/provider-services-pir pir check | tee /tmp/pir-check2.json
grep -q '"allocate":true' /tmp/pir-check2.json

BOOK="/tmp/pir-leases.json"
rm -f "$BOOK"
export PIR_LEASE_BOOK_FILE="$BOOK"
# bearer from known vector (session=1s, bid=2s, ask-1)
BEARER="ed105aa1fbea7d092b317a6fc11c315c68e756153a2aa5e8ba47381ee9ac88b0"
/tmp/provider-services-pir pir accept --lease lease-1 --bearer "$BEARER"
/tmp/provider-services-pir pir access --lease lease-1 --bearer "$BEARER"
/tmp/provider-services-pir pir close --lease lease-1
if /tmp/provider-services-pir pir access --lease lease-1 --bearer "$BEARER"; then
  echo "close did not deny" >&2
  exit 1
fi
echo "provider-services pir workflow ok"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "serve lightweight container"
  export PIR_REQUIRE_COMMIT=1
  export PIR_ASK_COMMIT="$ASK"
  export PIR_BID_COMMIT="$BID"
  export PIR_LEASE_BOOK_FILE="$BOOK"
  /tmp/provider-services-pir pir stop --lease lease-serve >/dev/null 2>&1 || true
  /tmp/provider-services-pir pir serve --lease lease-serve --bearer "$BEARER" --port 18765
  docker inspect -f '{{.State.Running}} {{.Name}} {{.Config.Image}}' pir-lease-lease-serve
  docker exec pir-lease-lease-serve python -c 'import urllib.request; r=urllib.request.urlopen("http://127.0.0.1:8080/"); raise SystemExit(0 if r.status==200 else r.status)'
  echo "lease_http=200"
  host_ok=0
  n=0
  while [ "$n" -lt 20 ]; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18765/ || true)"
    if [ "$code" = "200" ]; then
      host_ok=1
      break
    fi
    n=$((n + 1))
    sleep 0.25
  done
  echo "host_http=$host_ok"
  /tmp/provider-services-pir pir stop --lease lease-serve
  if docker inspect pir-lease-lease-serve >/dev/null 2>&1; then
    echo "container still present after stop" >&2
    exit 1
  fi
  echo "host-binary serve ok"
else
  echo "docker not running; skip container spawn"
fi

cd "$PIR"
export PIR_REQUIRE_PROVIDER_ENGINE=1
cargo test --test provider_workflow --test provider_engine --test access_derive -- --nocapture

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  sh "$PIR/scripts/lab-provider-sidecar.sh"
else
  echo "PIR_PROVIDER_IMAGE=akash-provider-pir:local  # ict-rs sidecar when docker is up"
fi
