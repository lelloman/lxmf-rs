#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${DOCKER_DIR}/../.." && pwd)"
RNS_ROOT="$(cd "${REPO_ROOT}/../rns-rs" 2>/dev/null && pwd || true)"
IMAGE="lxmf-e2e"
CONTAINER="lxmf-server-e2e-$RANDOM-$$"

for cmd in docker curl jq tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: '$cmd' is required." >&2
    exit 1
  fi
done

source "${DOCKER_DIR}/lib/build.sh"

if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
  echo "=== Building ${IMAGE} Docker image ==="
  build_lxmf_e2e_image "$DOCKER_DIR" "$REPO_ROOT" "$RNS_ROOT" "$IMAGE"
fi

cleanup() {
  docker logs "$CONTAINER" 2>/dev/null || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== Starting lxmf-server E2E container ==="
docker run -d --name "$CONTAINER" "$IMAGE" sh -lc '
set -eu
mkdir -p /tmp/rns /tmp/lxmf-server

cat > /tmp/rns/config <<EOF
[reticulum]
share_instance = Yes
shared_instance_port = 37428
instance_control_port = 37429
enable_transport = No
EOF

cat > /tmp/lxmf-server/lxmf-server.json <<EOF
{
  "lxmd_bin": "/usr/local/bin/lxmd",
  "rns": {
    "shared_instance_port": 37428
  },
  "http": {
    "host": "127.0.0.1",
    "port": 37529,
    "disable_auth": true
  }
}
EOF

rns-server start --config /tmp/rns --no-http > /tmp/rns-server.log 2>&1 &
sleep 3
exec lxmf-server start --config /tmp/lxmf-server --disable-auth
' >/dev/null

wait_for_http() {
  local path="$1"
  local attempts="${2:-60}"
  for _ in $(seq 1 "$attempts"); do
    if docker exec "$CONTAINER" curl -sf "http://127.0.0.1:37529${path}" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: timed out waiting for ${path}" >&2
  return 1
}

echo "=== Waiting for lxmf-server health ==="
wait_for_http "/healthz" 30
wait_for_http "/readyz" 60

echo "=== Verifying managed processes ==="
processes="$(docker exec "$CONTAINER" curl -sf http://127.0.0.1:37529/api/processes)"
echo "$processes" | jq -e '.processes[] | select(.name == "lxmd" and .status == "running" and .ready == true)' >/dev/null

echo "=== Verifying lxmd log tail endpoint ==="
docker exec "$CONTAINER" curl -sf "http://127.0.0.1:37529/api/processes/lxmd/logs?tail=20" | jq -e '.name == "lxmd" and (.logs | type == "array")' >/dev/null

echo "=== Restarting lxmd through the control API ==="
docker exec "$CONTAINER" curl -sf -X POST http://127.0.0.1:37529/api/processes/lxmd/restart | jq -e '.queued == true' >/dev/null
wait_for_http "/readyz" 60

processes="$(docker exec "$CONTAINER" curl -sf http://127.0.0.1:37529/api/processes)"
echo "$processes" | jq -e '.processes[] | select(.name == "lxmd" and .status == "running" and .ready == true)' >/dev/null

echo "=== lxmf-server E2E passed ==="
