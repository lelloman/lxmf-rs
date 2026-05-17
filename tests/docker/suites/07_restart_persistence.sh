#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="07_restart_persistence"
echo "Suite 07: client restart and persistent identity"

require_clients 2

PORT_B="$(client_port_by_index 1)"
DEST_BEFORE="$(node_dest_hash "$PORT_B")"

docker compose -f "${COMPOSE_FILE:?COMPOSE_FILE required}" restart lxmf-b >/dev/null

if wait_for_http_health "$PORT_B" 45; then
  pass_test "Restarted client becomes healthy"
else
  fail_test "Restarted client did not become healthy"
fi

DEST_AFTER="$(node_dest_hash "$PORT_B")"
assert_eq "$DEST_AFTER" "$DEST_BEFORE" "Restarted client preserves delivery destination"

PORT_A="$(client_port_by_index 0)"
DEST_A="$(node_dest_hash "$PORT_A")"
clear_all_lxmf
announce_delivery "$PORT_A"
announce_delivery "$PORT_B"
wait_for_announce "$PORT_A" "$DEST_AFTER" 45 || fail_test "Alice did not relearn restarted Bob"
if ! wait_for_announce "$PORT_B" "$DEST_A" 10; then
  echo "  NOTE: restarted Bob did not observe a fresh Alice announce; retained RNS routing may suppress duplicate announce callbacks"
fi

CONTENT="after-restart-${TOPOLOGY}"
send_lxmf "$PORT_A" "$DEST_AFTER" "restart" "$CONTENT" "opportunistic" >/dev/null
if wait_for_message_content "$PORT_B" "$CONTENT" 45; then
  pass_test "Message delivered after client restart"
else
  fail_test "Message not delivered after client restart"
fi

suite_result "$_CURRENT_SUITE"
