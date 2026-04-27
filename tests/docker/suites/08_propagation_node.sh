#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="08_propagation_node"
echo "Suite 08: propagation node announce and state"

require_clients 2
clear_all_lxmf

PORT_PROP="$(client_port_by_index 0)"
PORT_CLIENT="$(client_port_by_index 1)"

ENABLE_RESULT="$(ctl_post "$PORT_PROP" "/api/propagation/enable" '{}')"
PROP_DEST="$(echo "$ENABLE_RESULT" | jq -r '.propagation_dest_hash')"
ctl_post "$PORT_PROP" "/api/propagation/announce" '{}' >/dev/null

enabled="$(ctl_get "$PORT_PROP" "/api/propagation" | jq -r '.enabled')"
assert_eq "$enabled" "true" "Propagation node reports enabled"

if wait_for_announce "$PORT_CLIENT" "$PROP_DEST" 45; then
  pass_test "Client receives propagation node announce"
else
  fail_test "Client did not receive propagation node announce" "$PROP_DEST"
fi

suite_result "$_CURRENT_SUITE"
