#!/bin/sh
# Copy git-SoT sources into cargo/go working trees on the lab host.
# Does not delete target/ or Go caches.
set -eu
ROOT="${HOME}/abstract/re-zerve"
PIR="${HOME}/abstract/terp-core/crates/private-inference-rent"
PROV="${HOME}/abstract/terp-core/crates/akash-provider-pir"
test -d "$ROOT/crate" && test -d "$ROOT/provider"
test -d "$PIR" && test -d "$PROV"
rsync -a \
  --exclude target --exclude node_modules --exclude book-out --exclude www \
  --exclude .git --exclude .DS_Store --exclude .tmp-ict-e2e.log \
  "$ROOT/crate/" "$PIR/"
rsync -a \
  --exclude .git --exclude vendor --exclude .cache --exclude dist \
  --exclude provider-services --exclude target --exclude node_modules \
  "$ROOT/provider/" "$PROV/"
echo "synced crate -> $PIR"
echo "synced provider -> $PROV"
