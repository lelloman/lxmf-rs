#!/usr/bin/env bash
set -euo pipefail

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

wait_for_topology_ready() {
  local timeout="${1:-45}"
  local port

  for port in ${RNS_CONTROL_PORTS:-}; do
    wait_for_http_health "$port" "$timeout"
  done

  for port in ${LXMF_CLIENT_PORTS:-}; do
    wait_for_http_health "$port" "$timeout"
  done
}

settle_topology_runtime() {
  local seconds="${1:-3}"
  sleep "$seconds"
  run_jobs_all 2>/dev/null || true
}
