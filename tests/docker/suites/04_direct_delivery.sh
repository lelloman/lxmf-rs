#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="04_direct_delivery"
echo "Suite 04: direct link LXMF delivery"

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

CONTENT="direct-${TOPOLOGY}"
SEND_RESULT="$(send_lxmf "$PORT_A" "$DEST_B" "direct" "$CONTENT" "direct")"
MESSAGE_HASH="$(echo "$SEND_RESULT" | jq -r '.message_hash')"

if wait_for_message_content "$PORT_B" "$CONTENT" 60; then
  pass_test "Direct message delivered"
else
  fail_test "Direct message not delivered" "$MESSAGE_HASH"
fi

if poll_count "$PORT_A" "/api/links" ".direct_links" 1 10; then
  pass_test "Sender tracks direct link"
else
  fail_test "Sender did not track direct link"
fi

suite_result "$_CURRENT_SUITE"
