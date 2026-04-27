#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="02_discovery"
echo "Suite 02: announce discovery and convergence"

require_clients 2
clear_all_lxmf

PORT_A="$(client_port_by_index 0)"
PORT_B="$(client_port_by_index 1)"
DEST_A="$(node_dest_hash "$PORT_A")"

announce_delivery "$PORT_A"
if wait_for_announce "$PORT_B" "$DEST_A" 45; then
  pass_test "Adjacent client receives delivery announce"
else
  fail_test "Adjacent client did not receive delivery announce"
fi

if (( LXMF_CLIENT_COUNT >= 3 )); then
  PORT_LAST="$(last_client_port)"
  if wait_for_announce "$PORT_LAST" "$DEST_A" 60; then
    pass_test "Remote client receives delivery announce"
  else
    fail_test "Remote client did not receive delivery announce"
  fi
fi

for port in ${LXMF_CLIENT_PORTS}; do
  announce_delivery "$port"
done

settle_topology_runtime 3
PORT_A_ANNOUNCES="$(ctl_get "$PORT_A" "/api/announces" | jq -r '.announces | length')"
assert_ge "$PORT_A_ANNOUNCES" 1 "Announce convergence records peers"

suite_result "$_CURRENT_SUITE"
