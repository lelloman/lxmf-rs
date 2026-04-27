#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="05_bidirectional"
echo "Suite 05: bidirectional messaging"

require_clients 2
clear_all_lxmf

PORT_A="$(client_port_by_index 0)"
PORT_B="$(client_port_by_index 1)"
DEST_A="$(node_dest_hash "$PORT_A")"
DEST_B="$(node_dest_hash "$PORT_B")"

announce_delivery "$PORT_A"
announce_delivery "$PORT_B"
wait_for_announce "$PORT_A" "$DEST_B" 45 || fail_test "Alice did not learn Bob"
wait_for_announce "$PORT_B" "$DEST_A" 45 || fail_test "Bob did not learn Alice"

CONTENT_AB="a-to-b-${TOPOLOGY}"
CONTENT_BA="b-to-a-${TOPOLOGY}"
send_lxmf "$PORT_A" "$DEST_B" "ab" "$CONTENT_AB" "opportunistic" >/dev/null
send_lxmf "$PORT_B" "$DEST_A" "ba" "$CONTENT_BA" "opportunistic" >/dev/null

if wait_for_message_content "$PORT_B" "$CONTENT_AB" 45; then
  pass_test "A to B delivered"
else
  fail_test "A to B not delivered"
fi

if wait_for_message_content "$PORT_A" "$CONTENT_BA" 45; then
  pass_test "B to A delivered"
else
  fail_test "B to A not delivered"
fi

suite_result "$_CURRENT_SUITE"
