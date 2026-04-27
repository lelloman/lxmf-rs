#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="01_health"
echo "Suite 01: health and control-plane readiness"

for port in ${RNS_CONTROL_PORTS}; do
  if ctl_get "$port" "/health" >/dev/null; then
    pass_test "RNS control API healthy on ${port}"
  else
    fail_test "RNS control API unhealthy on ${port}"
  fi
done

for port in ${LXMF_CLIENT_PORTS}; do
  status="$(ctl_get "$port" "/health" | jq -r '.status')"
  assert_eq "$status" "healthy" "LXMF client healthy on ${port}"

  dest="$(node_dest_hash "$port")"
  if [[ "$dest" =~ ^[0-9a-f]{32}$ ]]; then
    pass_test "LXMF client ${port} exposes delivery destination"
  else
    fail_test "LXMF client ${port} destination malformed" "$dest"
  fi
done

suite_result "$_CURRENT_SUITE"
