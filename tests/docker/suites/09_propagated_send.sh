#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="09_propagated_send"
echo "Suite 09: propagated send path"

require_clients 3
clear_all_lxmf

PORT_PROP="$(client_port_by_index 0)"
PORT_SENDER="$(client_port_by_index 1)"
PORT_RECIP="$(client_port_by_index 2)"
DEST_RECIP="$(node_dest_hash "$PORT_RECIP")"

ENABLE_RESULT="$(ctl_post "$PORT_PROP" "/api/propagation/enable" '{}')"
PROP_DEST="$(echo "$ENABLE_RESULT" | jq -r '.propagation_dest_hash')"
ctl_post "$PORT_PROP" "/api/propagation/announce" '{}' >/dev/null
announce_delivery "$PORT_RECIP"

wait_for_announce "$PORT_SENDER" "$PROP_DEST" 60 || fail_test "Sender did not learn propagation node"
wait_for_announce "$PORT_SENDER" "$DEST_RECIP" 60 || fail_test "Sender did not learn recipient"

ctl_post "$PORT_SENDER" "/api/propagation/destination" "$(jq -n --arg dh "$PROP_DEST" '{dest_hash:$dh}')" >/dev/null

CONTENT="propagated-${TOPOLOGY}"
SEND_RESULT="$(send_lxmf "$PORT_SENDER" "$DEST_RECIP" "propagated" "$CONTENT" "propagated")"
MESSAGE_HASH="$(echo "$SEND_RESULT" | jq -r '.message_hash')"
TRANSIENT_ID="$(echo "$SEND_RESULT" | jq -r '.transient_id')"

if [[ "$TRANSIENT_ID" =~ ^[0-9a-f]{64}$ ]]; then
  pass_test "Propagated send creates transient id"
else
  fail_test "Propagated send did not create transient id" "$SEND_RESULT"
fi

if poll_count "$PORT_PROP" "/api/propagation" ".payloads" 1 90; then
  pass_test "Propagation node observes propagated payload"
else
  fail_test "Propagation node did not observe propagated payload" "$MESSAGE_HASH"
fi

suite_result "$_CURRENT_SUITE"
