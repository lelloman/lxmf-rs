#!/usr/bin/env bash
set -euo pipefail

PASSES=0
FAILURES=0
_CURRENT_SUITE=""

record_result() {
  local status="$1" msg="$2" detail="${3:-}"
  if [[ -n "${TEST_RESULTS_FILE:-}" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$status" "${TOPOLOGY:-unknown}" "${_CURRENT_SUITE:-unknown}" "$msg" "$detail" \
      >> "$TEST_RESULTS_FILE"
  fi
}

pass_test() {
  local msg="$1"
  echo "  PASS: ${msg}"
  (( PASSES++ )) || true
  record_result "PASS" "$msg"
}

fail_test() {
  local msg="$1" detail="${2:-}"
  if [[ -n "$detail" ]]; then
    echo "  FAIL: ${msg} -- ${detail}"
  else
    echo "  FAIL: ${msg}"
  fi
  (( FAILURES++ )) || true
  record_result "FAIL" "$msg" "$detail"
}

skip_suite() {
  local reason="$1"
  echo "  SKIP: ${reason}"
  record_result "SKIP" "$reason"
  exit 0
}

ctl_get() {
  local port="$1" path="$2"
  curl -sf "http://localhost:${port}${path}"
}

ctl_post() {
  local port="$1" path="$2" body="${3:-}"
  if [[ -z "$body" ]]; then
    body='{}'
  fi
  curl -sf -X POST -H "Content-Type: application/json" \
    -d "$body" "http://localhost:${port}${path}"
}

wait_for_http_health() {
  local port="$1" timeout="${2:-30}"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if curl -sf "http://localhost:${port}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT: health check failed on port ${port}" >&2
  return 1
}

settle_topology_runtime() {
  local seconds="${1:-3}"
  sleep "$seconds"
  run_jobs_all 2>/dev/null || true
}

poll_until() {
  local port="$1" path="$2" jq_filter="$3" expected="$4" timeout="${5:-30}"
  local deadline=$((SECONDS + timeout))
  local result=""
  while (( SECONDS < deadline )); do
    result="$(ctl_get "$port" "$path" 2>/dev/null | jq -r "$jq_filter" 2>/dev/null || true)"
    if [[ "$result" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT: ${port}${path} | jq '${jq_filter}' expected '${expected}', last got '${result:-<empty>}'" >&2
  return 1
}

poll_count() {
  local port="$1" path="$2" jq_filter="$3" minimum="$4" timeout="${5:-30}"
  local deadline=$((SECONDS + timeout))
  local count=0
  while (( SECONDS < deadline )); do
    count="$(ctl_get "$port" "$path" 2>/dev/null | jq -r "${jq_filter} | length" 2>/dev/null || true)"
    if [[ -n "$count" ]] && (( count >= minimum )); then
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT: ${port}${path} | jq '${jq_filter} | length' expected >= ${minimum}, last got ${count:-0}" >&2
  return 1
}

assert_eq() {
  local actual="$1" expected="$2" msg="$3"
  if [[ "$actual" == "$expected" ]]; then
    pass_test "$msg"
  else
    fail_test "$msg" "expected '${expected}', got '${actual}'"
  fi
}

assert_ge() {
  local actual="$1" minimum="$2" msg="$3"
  if (( actual >= minimum )); then
    pass_test "$msg"
  else
    fail_test "$msg" "expected >= ${minimum}, got ${actual}"
  fi
}

suite_result() {
  local name="$1"
  echo ""
  echo "=== ${name}: ${PASSES} passed, ${FAILURES} failed ==="
  if (( FAILURES > 0 )); then
    return 1
  fi
  return 0
}

require_clients() {
  local minimum="$1"
  local count="${LXMF_CLIENT_COUNT:-0}"
  if (( count < minimum )); then
    skip_suite "Need at least ${minimum} LXMF clients, got ${count}"
  fi
}

client_port_by_index() {
  local idx="$1"
  local letter
  letter="$(printf "\\$(printf '%03o' "$(( idx + 97 ))")")"
  local varname="LXMF_$(echo "$letter" | tr '[:lower:]' '[:upper:]')_PORT"
  echo "${!varname}"
}

last_client_port() {
  client_port_by_index "$(( LXMF_CLIENT_COUNT - 1 ))"
}

clear_all_lxmf() {
  local port
  for port in ${LXMF_CLIENT_PORTS}; do
    ctl_post "$port" "/api/runtime/clear" '{"caches":true}' >/dev/null
  done
}

run_jobs_all() {
  local port
  for port in ${LXMF_CLIENT_PORTS}; do
    ctl_post "$port" "/api/jobs" '{}' >/dev/null || true
  done
}

node_dest_hash() {
  local port="$1"
  ctl_get "$port" "/api/node" | jq -r '.dest_hash'
}

propagation_dest_hash() {
  local port="$1"
  ctl_get "$port" "/api/node" | jq -r '.propagation_dest_hash'
}

announce_delivery() {
  local port="$1"
  ctl_post "$port" "/api/announce" '{}' >/dev/null
}

wait_for_announce() {
  local port="$1" dest_hash="$2" timeout="${3:-30}"
  poll_until "$port" "/api/announces" \
    "[.announces[] | select(.dest_hash == \"${dest_hash}\")] | length | . > 0" \
    "true" "$timeout"
}

send_lxmf() {
  local port="$1" dest_hash="$2" title="$3" content="$4" method="$5"
  local body
  body="$(jq -n \
    --arg dh "$dest_hash" \
    --arg title "$title" \
    --arg content "$content" \
    --arg method "$method" \
    '{dest_hash: $dh, title: $title, content: $content, method: $method}')"
  ctl_post "$port" "/api/send" "$body"
}

wait_for_message_content() {
  local port="$1" content="$2" timeout="${3:-30}"
  poll_until "$port" "/api/messages" \
    "[.messages[] | select(.content == \"${content}\")] | length | . > 0" \
    "true" "$timeout"
}

wait_for_outbound_state() {
  local port="$1" message_hash="$2" state="$3" timeout="${4:-30}"
  poll_until "$port" "/api/outbound" \
    ".outbound[] | select(.message_hash == \"${message_hash}\") | .state" \
    "$state" "$timeout"
}
