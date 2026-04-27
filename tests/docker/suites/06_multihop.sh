#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="06_multihop"
echo "Suite 06: multihop endpoint delivery"

if [[ "${TOPO_TYPE}" != "chain" ]]; then
  skip_suite "Multihop endpoint test requires chain topology"
fi
require_clients 3

clear_all_lxmf

PORT_A="$(client_port_by_index 0)"
PORT_LAST="$(last_client_port)"
DEST_A="$(node_dest_hash "$PORT_A")"
DEST_LAST="$(node_dest_hash "$PORT_LAST")"

announce_delivery "$PORT_A"
announce_delivery "$PORT_LAST"
wait_for_announce "$PORT_LAST" "$DEST_A" 60 || fail_test "Last node did not learn first node"
wait_for_announce "$PORT_A" "$DEST_LAST" 60 || fail_test "First node did not learn last node"

CONTENT="multihop-${TOPOLOGY}"
send_lxmf "$PORT_A" "$DEST_LAST" "multihop" "$CONTENT" "opportunistic" >/dev/null

if wait_for_message_content "$PORT_LAST" "$CONTENT" 60; then
  pass_test "Multihop opportunistic message delivered"
else
  fail_test "Multihop opportunistic message not delivered"
fi

suite_result "$_CURRENT_SUITE"
