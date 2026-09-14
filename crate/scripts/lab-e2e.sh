#!/bin/sh
# Canonical re-zerve compile/test. One production-shaped compose.
# Run ON the lab host only. Never on the laptop.
set -eu
exec "$(dirname "$0")/lab-production-loop.sh"
