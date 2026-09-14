#!/bin/sh
# Refresh git-SoT from the cargo/go working trees (after a lab test pass).
set -eu
ROOT="${HOME}/abstract/re-zerve"
PIR="${HOME}/abstract/terp-core/crates/private-inference-rent"
PROV="${HOME}/abstract/terp-core/crates/akash-provider-pir"
rsync -a --delete \
  --exclude target --exclude node_modules --exclude book-out --exclude www \
  --exclude .git --exclude .DS_Store --exclude .tmp-ict-e2e.log \
  "$PIR/" "$ROOT/crate/"
rsync -a --delete \
  --exclude .git --exclude vendor --exclude .cache --exclude dist \
  --exclude provider-services --exclude target --exclude node_modules \
  "$PROV/" "$ROOT/provider/"
echo "pulled working trees -> $ROOT"
