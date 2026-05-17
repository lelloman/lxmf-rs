#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="10_scale"
echo "Suite 10: many-client announce and delivery subset"

if [[ "${TOPO_TYPE}" != "star" ]]; then
  skip_suite "Scale test requires star topology"
fi
require_clients 8

clear_all_lxmf

for port in ${LXMF_CLIENT_PORTS}; do
  announce_delivery "$port"
done

settle_topology_runtime 5

PORT_A="$(client_port_by_index 0)"
if poll_count "$PORT_A" "/api/announces" ".announces" 4 90; then
  pass_test "Hub-adjacent client observes multiple peer announces"
else
  ANNOUNCE_COUNT="$(ctl_get "$PORT_A" "/api/announces" | jq -r '.announces | length')"
  fail_test "Hub-adjacent client observes multiple peer announces" "expected >= 4, got ${ANNOUNCE_COUNT}"
fi

DEST_A="$(node_dest_hash "$PORT_A")"

for idx in 1 2 3 4; do
  port="$(client_port_by_index "$idx")"
  dest="$(node_dest_hash "$port")"
  content="scale-${TOPOLOGY}-${idx}"
  send_lxmf "$PORT_A" "$dest" "scale" "$content" "opportunistic" >/dev/null
  if wait_for_message_content "$port" "$content" 60; then
    pass_test "Scale subset delivery to client ${idx}"
  else
    fail_test "Scale subset delivery failed to client ${idx}"
  fi
done

CONTENT_BACK="scale-back-${TOPOLOGY}"
PORT_LAST="$(last_client_port)"
send_lxmf "$PORT_LAST" "$DEST_A" "scale-back" "$CONTENT_BACK" "opportunistic" >/dev/null
if wait_for_message_content "$PORT_A" "$CONTENT_BACK" 60; then
  pass_test "Scale subset reverse delivery"
else
  fail_test "Scale subset reverse delivery failed"
fi

suite_result "$_CURRENT_SUITE"
