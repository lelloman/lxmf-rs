#!/usr/bin/env bash
# Live interop between upstream Python LXMF and lxmf-rs.
#
# Needs checkouts of upstream LXMF and Reticulum (RNS) at the reviewed
# commits recorded in UPSTREAM.md, and their Python dependencies
# (cryptography, pyserial). Point at them with:
#
#   LXMF_SRC=../LXMF RNS_SRC=../Reticulum tests/interop/run_live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${LXMF_SRC:?LXMF_SRC must point at an upstream LXMF checkout}"
: "${RNS_SRC:?RNS_SRC must point at an upstream Reticulum checkout}"

PROFILE=debug
if [[ -n "${INTEROP_RELEASE:-}" ]]; then PROFILE=release; fi
cargo build --manifest-path "$ROOT/Cargo.toml" --example interop_peer ${INTEROP_RELEASE:+--release}
LXMF_SRC="$LXMF_SRC" RNS_SRC="$RNS_SRC" \
  python3 -I "$ROOT/tests/interop/lxmf13_live.py" "$ROOT/target/$PROFILE/examples/interop_peer"
