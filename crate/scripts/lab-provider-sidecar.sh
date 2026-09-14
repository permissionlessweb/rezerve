#!/bin/sh
# Wire akash-provider-pir into an ict-style sidecar and confirm a lightweight
# lease container is spawned and serving HTTP. Run ON the lab host.
#
# Allocate only after 32-byte ask+bid hex from a ChaCha envelope and a live
# cw-pir-commit Match JSON {matches:true} at PIR_COMMIT_MATCH_URL.
set -eu
export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/go/bin:/usr/local/bin:/Applications/Docker.app/Contents/Resources/bin:${PATH}"
ROOT="${HOME}/abstract/terp-core/crates/akash-provider-pir"
ICT="${HOME}/abstract/terp-core/crates/ict-rs/ict-rs"
cd "$ROOT"
echo "host=$(hostname) cwd=$ROOT"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "docker required for sidecar e2e" >&2
  exit 1
fi

echo "building linux provider-services for sidecar image"
arch="$(uname -m)"
case "$arch" in
  arm64|aarch64) GOARCH=arm64 ;;
  x86_64|amd64) GOARCH=amd64 ;;
  *) echo "unsupported arch $arch" >&2; exit 1 ;;
esac
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -o provider-services ./cmd/pir-sidecar
file provider-services | tee /tmp/pir-provider-elf.txt
grep -qi 'ELF' /tmp/pir-provider-elf.txt

echo "building akash-provider-pir:local"
docker build -f Dockerfile.pir -t akash-provider-pir:local .
docker image inspect -f '{{.Os}}/{{.Architecture}} {{.RepoTags}}' akash-provider-pir:local

echo "pull lightweight serve image"
docker pull python:3.12-alpine >/tmp/pir-python-pull.txt

ASK="$(python3 -c 'print("aa"+"0"*62)')"
SESSION="$(python3 -c 'print("11"*32)')"
LEASE=lease-ict
CNAME=pir-lease-${LEASE}
NET=pir-sidecar-e2e
MATCH=pir-cw-commit-match
mkdir -p /tmp/pir-e2e

docker rm -f pir-ict-sidecar "$CNAME" "$MATCH" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null 2>&1 || true

echo "seal ChaCha20-Poly1305 OOB envelope"
docker run --rm -v /tmp/pir-e2e:/out \
  akash-provider-pir:local \
  pir seal --ask-id ask-1 --bidder prov --price 9000 --endpoint oob://p \
  --session-key "$SESSION" --envelope-out /out/envelope.json \
  | tee /tmp/pir-e2e-seal.json
test -s /tmp/pir-e2e/envelope.json
BID="$(python3 -c 'import json; print(json.load(open("/tmp/pir-e2e-seal.json"))["bid_commitment"])')"
BEARER="$(python3 -c 'import json; print(json.load(open("/tmp/pir-e2e-seal.json"))["bearer"])')"
echo "bid_commitment=$BID"

echo "start local cw-pir-commit match query"
docker run -d --name "$MATCH" --network "$NET" \
  -e PIR_ASK_COMMIT="$ASK" \
  -e PIR_BID_COMMIT="$BID" \
  -p 127.0.0.1:18770:8080 \
  akash-provider-pir:local \
  pir match-serve --addr :8080

ok_match=0
i=0
while [ "$i" -lt 40 ]; do
  if curl -fsS http://127.0.0.1:18770/health >/tmp/pir-commit-health.json 2>/dev/null; then
    ok_match=1
    break
  fi
  i=$((i + 1))
  sleep 0.25
done
if [ "$ok_match" -ne 1 ]; then
  echo "cw-pir-commit match health failed" >&2
  docker logs "$MATCH" >&2 || true
  exit 1
fi

python3 - <<PY
import json, urllib.request
ask = "$ASK"
bid = "$BID"
def post(url, obj):
    body = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())
got = post("http://127.0.0.1:18770/match", {"ask_commitment": ask, "bid_commitment": bid})
open("/tmp/pir-commit-match.json", "w").write(json.dumps(got))
assert got.get("matches") is True, got
# live cw-pir-commit QueryMsg wrap (what pir check POSTs)
wrap = post("http://127.0.0.1:18770/match", {"match": {"ask_commitment": ask, "bid_commitment": bid}})
assert wrap.get("matches") is True, wrap
got2 = post("http://127.0.0.1:18770/match", {"ask_commitment": ask, "bid_commitment": "cc"+"0"*62})
open("/tmp/pir-commit-mismatch.json", "w").write(json.dumps(got2))
assert got2.get("matches") is False, got2
print("cw-pir-commit matches:true (QueryMsg wrap; tamper matches:false)")
PY
grep -q '"matches": true' /tmp/pir-commit-match.json || grep -q '"matches":true' /tmp/pir-commit-match.json

echo "start pir sidecar with docker.sock + envelope + match URL"
docker run -d --name pir-ict-sidecar --network "$NET" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /tmp/pir-e2e/envelope.json:/tmp/pir/envelope.json:ro \
  -e PIR_REQUIRE_COMMIT=1 \
  -e PIR_REQUIRE_ENVELOPE=1 \
  -e PIR_ASK_COMMIT="$ASK" \
  -e PIR_BID_COMMIT="$BID" \
  -e PIR_BID_ENVELOPE_FILE=/tmp/pir/envelope.json \
  -e PIR_SESSION_KEY="$SESSION" \
  -e PIR_COMMIT_MATCH_URL=http://${MATCH}:8080/match \
  -e PIR_LEASE_BOOK_FILE=/tmp/pir/leases.json \
  -e PIR_SERVE_IMAGE=python:3.12-alpine \
  -p 127.0.0.1:8444:8444 \
  akash-provider-pir:local \
  pir sidecar

cleanup() {
  docker exec pir-ict-sidecar provider-services pir stop --lease "$LEASE" >/dev/null 2>&1 || true
  docker rm -f pir-ict-sidecar "$CNAME" "$MATCH" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ok_health=0
i=0
while [ "$i" -lt 40 ]; do
  if curl -fsS http://127.0.0.1:8444/health >/tmp/pir-sidecar-health.json 2>/dev/null \
     && grep -q '"allocate":true' /tmp/pir-sidecar-health.json; then
    ok_health=1
    break
  fi
  i=$((i + 1))
  sleep 0.25
done
if [ "$ok_health" -ne 1 ]; then
  echo "sidecar health failed (need allocate:true after live cw-pir-commit)" >&2
  cat /tmp/pir-sidecar-health.json >&2 || true
  docker logs pir-ict-sidecar >&2 || true
  exit 1
fi
echo "health $(cat /tmp/pir-sidecar-health.json)"
grep -q '"ok":true' /tmp/pir-sidecar-health.json
grep -q '"allocate":true' /tmp/pir-sidecar-health.json
grep -q '"match_url":true' /tmp/pir-sidecar-health.json
grep -q '"matches":true' /tmp/pir-sidecar-health.json
grep -q '"envelope":true' /tmp/pir-sidecar-health.json

echo "exec pir check inside sidecar"
docker exec pir-ict-sidecar provider-services pir check | tee /tmp/pir-sidecar-check.json
grep -q '"allocate":true' /tmp/pir-sidecar-check.json
grep -q '"envelope":true' /tmp/pir-sidecar-check.json
grep -q '"match_url":true' /tmp/pir-sidecar-check.json
grep -q '"matches":true' /tmp/pir-sidecar-check.json

echo "exec pir serve inside sidecar (spawn lightweight container)"
docker exec pir-ict-sidecar provider-services pir serve \
  --lease "$LEASE" --bearer "$BEARER" --port 18766 | tee /tmp/pir-sidecar-serve.json
grep -q '"served":true' /tmp/pir-sidecar-serve.json
grep -q '"running":true' /tmp/pir-sidecar-serve.json

echo "confirm sibling container spawned"
docker inspect -f 'running={{.State.Running}} name={{.Name}} image={{.Config.Image}} labels={{.Config.Labels}}' \
  "$CNAME" | tee /tmp/pir-sidecar-inspect.txt
grep -q 'running=true' /tmp/pir-sidecar-inspect.txt
grep -q 'python:3.12-alpine' /tmp/pir-sidecar-inspect.txt
grep -q "name=/${CNAME}" /tmp/pir-sidecar-inspect.txt

echo "confirm served (HTTP 200 inside lease container)"
docker exec "$CNAME" python -c 'import urllib.request; r=urllib.request.urlopen("http://127.0.0.1:8080/"); raise SystemExit(0 if r.status==200 else r.status)'
echo "lease_http=200"

echo "confirm served (HTTP from sidecar via docker exec)"
docker exec pir-ict-sidecar docker exec "$CNAME" python -c \
  'import urllib.request; r=urllib.request.urlopen("http://127.0.0.1:8080/"); print(r.status)' \
  | tee /tmp/pir-sidecar-http.txt
grep -q 200 /tmp/pir-sidecar-http.txt

ok_host=0
j=0
while [ "$j" -lt 20 ]; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18766/ || true)"
  if [ "$code" = "200" ]; then
    ok_host=1
    break
  fi
  j=$((j + 1))
  sleep 0.25
done
echo "host_http=${ok_host} (1=200 on 127.0.0.1:18766; in-container 200 is the spawn proof)"

echo "exec pir stop inside sidecar"
docker exec pir-ict-sidecar provider-services pir stop --lease "$LEASE"
if docker inspect "$CNAME" >/dev/null 2>&1; then
  echo "lease container still present after stop" >&2
  exit 1
fi
echo "container_gone"

echo "ict-rs sidecar config + live spawn test (points at local cw-pir-commit match query)"
cd "$ICT"
export PIR_PROVIDER_IMAGE=akash-provider-pir:local
export PIR_SIDECAR_E2E=1
export PIR_REQUIRE_COMMIT=1
# Cargo test starts its own match-serve on the ict docker network and sets
# PIR_COMMIT_MATCH_URL=http://pir-cw-commit-match-e2e:8080/match. Unset host
# leftovers so pir_provider_sidecar_config does not inject the shell-script
# network hostname (pir-cw-commit-match) which that sidecar cannot resolve.
unset PIR_COMMIT_MATCH_URL PIR_BID_ENVELOPE_FILE PIR_REQUIRE_ENVELOPE PIR_SESSION_KEY || true
cargo test --offline --features akash,docker --test pir_provider_sidecar_test -- --nocapture

echo "SIDECAR_SPAWN_SERVE_OK"
