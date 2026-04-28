#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${DOCKER_DIR}/../.." && pwd)"
RNS_ROOT="$(cd "${REPO_ROOT}/../rns-rs" 2>/dev/null && pwd || true)"
IMAGE="lxmf-e2e"
RUN_ID="${RANDOM}-$$"
CONTAINERS=()
STARTED_CONTAINER=""

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
  for container in "${CONTAINERS[@]}"; do
    echo "--- ${container} logs ---" >&2
    docker logs "$container" 2>/dev/null || true
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

start_container() {
  local suffix="$1"
  local disable_auth="${2:-true}"
  local token="${3:-}"
  local name="lxmf-server-e2e-${suffix}-${RUN_ID}"

  CONTAINERS+=("$name")
  echo "=== Starting ${name} ===" >&2
  docker run -d --name "$name" "$IMAGE" sh -lc "
set -eu
mkdir -p /tmp/rns /tmp/lxmf-server /tmp/sidecars /tmp/fake-bin

cat > /tmp/rns/config <<EOF
[reticulum]
share_instance = Yes
shared_instance_port = 37428
instance_control_port = 37429
enable_transport = No
EOF

cat > /tmp/lxmf-server/lxmf-server.json <<EOF
{
  \"lxmd_bin\": \"/usr/local/bin/lxmd\",
  \"rns\": {
    \"shared_instance_port\": 37428
  },
  \"http\": {
    \"host\": \"127.0.0.1\",
    \"port\": 37529,
    \"disable_auth\": ${disable_auth},
    \"auth_token\": \"${token}\"
  }
}
EOF

cat > /tmp/sidecars/stable.sh <<'EOF'
#!/usr/bin/env sh
set -eu
ready=\"\${1:?ready file required}\"
mkdir -p \"\$(dirname \"\$ready\")\"
echo stable-start
touch \"\$ready\"
while true; do
  sleep 60
done
EOF
chmod +x /tmp/sidecars/stable.sh

cat > /tmp/sidecars/fail.sh <<'EOF'
#!/usr/bin/env sh
echo fail-start
exit 7
EOF
chmod +x /tmp/sidecars/fail.sh

cat > /tmp/sidecars/flappy.sh <<'EOF'
#!/usr/bin/env sh
set -eu
ready=\"\${1:?ready file required}\"
count_file=\"/tmp/sidecars/flappy-count\"
count=0
if [ -f \"\$count_file\" ]; then
  count=\"\$(cat \"\$count_file\")\"
fi
count=\$((count + 1))
echo \"\$count\" > \"\$count_file\"
mkdir -p \"\$(dirname \"\$ready\")\"
echo \"flappy-start-\$count\"
touch \"\$ready\"
sleep 1
exit 9
EOF
chmod +x /tmp/sidecars/flappy.sh

rns-server start --config /tmp/rns --no-http > /tmp/rns-server.log 2>&1 &
sleep 3
exec lxmf-server start --config /tmp/lxmf-server
" >/dev/null

  STARTED_CONTAINER="$name"
}

wait_for_http() {
  local container="$1"
  local path="$2"
  local attempts="${3:-60}"
  local header="${4:-}"
  for _ in $(seq 1 "$attempts"); do
    if [[ -n "$header" ]]; then
      if docker exec "$container" curl -sf -H "$header" "http://127.0.0.1:37529${path}" >/dev/null; then
        return 0
      fi
    else
      if docker exec "$container" curl -sf "http://127.0.0.1:37529${path}" >/dev/null; then
        return 0
      fi
    fi
    sleep 1
  done
  echo "ERROR: timed out waiting for ${container} ${path}" >&2
  return 1
}

api_get() {
  local container="$1"
  local path="$2"
  local header="${3:-}"
  if [[ -n "$header" ]]; then
    docker exec "$container" curl -sf -H "$header" "http://127.0.0.1:37529${path}"
  else
    docker exec "$container" curl -sf "http://127.0.0.1:37529${path}"
  fi
}

api_post() {
  local container="$1"
  local path="$2"
  local body="${3:-}"
  local header="${4:-}"
  if [[ -n "$header" ]]; then
    docker exec -i "$container" curl -sf -X POST -H "$header" -H "Content-Type: application/json" --data-binary @- "http://127.0.0.1:37529${path}" <<< "$body"
  else
    docker exec -i "$container" curl -sf -X POST -H "Content-Type: application/json" --data-binary @- "http://127.0.0.1:37529${path}" <<< "$body"
  fi
}

http_status() {
  local container="$1"
  local path="$2"
  local header="${3:-}"
  if [[ -n "$header" ]]; then
    docker exec "$container" curl -s -o /dev/null -w "%{http_code}" -H "$header" "http://127.0.0.1:37529${path}"
  else
    docker exec "$container" curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:37529${path}"
  fi
}

wait_for_process() {
  local container="$1"
  local name="$2"
  local jq_expr="$3"
  local attempts="${4:-60}"
  for _ in $(seq 1 "$attempts"); do
    if api_get "$container" "/api/processes" | jq -e ".processes[] | select(.name == \"${name}\") | ${jq_expr}" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: timed out waiting for process ${name} in ${container}" >&2
  api_get "$container" "/api/processes" >&2 || true
  return 1
}

ensure_process_running() {
  local container="$1"
  local name="$2"
  local attempts="${3:-60}"
  for _ in $(seq 1 "$attempts"); do
    local process
    process="$(api_get "$container" "/api/processes" | jq -c ".processes[] | select(.name == \"${name}\")" || true)"
    if [[ -z "$process" ]]; then
      sleep 1
      continue
    fi
    if echo "$process" | jq -e '.status == "running" and .ready == true' >/dev/null; then
      return 0
    fi
    if echo "$process" | jq -e '.status == "stopped"' >/dev/null; then
      api_post "$container" "/api/processes/${name}/start" '{}' | jq -e '.queued == true' >/dev/null
    fi
    sleep 1
  done
  echo "ERROR: process ${name} did not become running/ready in ${container}" >&2
  api_get "$container" "/api/processes" >&2 || true
  return 1
}

scenario_smoke_and_generated_config() {
  local container
  start_container smoke true
  container="$STARTED_CONTAINER"

  wait_for_http "$container" "/healthz" 30
  wait_for_http "$container" "/readyz" 60

  api_get "$container" "/api/processes" |
    jq -e '.processes[] | select(.name == "lxmd" and .status == "running" and .ready == true)' >/dev/null

  api_get "$container" "/api/processes/lxmd/logs?tail=20" |
    jq -e '.name == "lxmd" and (.logs | type == "array")' >/dev/null

  docker exec "$container" test -f /tmp/lxmf-server/rns-client/config
  docker exec "$container" grep -q "LocalClientInterface" /tmp/lxmf-server/rns-client/config
  docker exec "$container" grep -q "port = 37428" /tmp/lxmf-server/rns-client/config

  api_post "$container" "/api/processes/lxmd/restart" '{}' | jq -e '.queued == true' >/dev/null
  wait_for_http "$container" "/readyz" 60
  wait_for_process "$container" "lxmd" '.status == "running" and .ready == true' 60
}

scenario_auth() {
  local container
  start_container auth false secret-token
  container="$STARTED_CONTAINER"

  wait_for_http "$container" "/healthz" 30
  [[ "$(http_status "$container" "/api/info")" == "401" ]]
  [[ "$(http_status "$container" "/api/info" "Authorization: Bearer wrong")" == "401" ]]
  [[ "$(http_status "$container" "/api/info" "Authorization: Bearer secret-token")" == "200" ]]

  api_get "$container" "/api/info" "Authorization: Bearer secret-token" |
    jq -e '.name == "lxmf-server" and (.config.launch_plan | length >= 1)' >/dev/null
}

scenario_config_apply_and_sidecars() {
  local container
  start_container sidecars true
  container="$STARTED_CONTAINER"
  wait_for_http "$container" "/readyz" 60

  local config
  config='{
    "lxmd_bin": "/usr/local/bin/lxmd",
    "rns": {"shared_instance_port": 37428},
    "http": {"host": "127.0.0.1", "port": 37529, "disable_auth": true},
    "sidecars": [
      {
        "name": "stable-sidecar",
        "bin": "/tmp/sidecars/stable.sh",
        "args": ["/tmp/lxmf-server/run/stable-sidecar.ready"],
        "restart": true,
        "ready_file": "/tmp/lxmf-server/run/stable-sidecar.ready"
      }
    ]
  }'

  api_post "$container" "/api/config/validate" "$config" |
    jq -e '.valid == true and (.config.launch_plan[] | select(.name == "stable-sidecar"))' >/dev/null

  api_post "$container" "/api/config/save" "$config" |
    jq -e '.action == "save" and (.processes_to_restart | index("stable-sidecar"))' >/dev/null
  docker exec "$container" grep -q '"name": "stable-sidecar"' /tmp/lxmf-server/lxmf-server.json

  api_post "$container" "/api/config/apply" "$config" |
    jq -e '.action == "apply" and (.processes_to_restart | index("stable-sidecar"))' >/dev/null

  ensure_process_running "$container" "stable-sidecar" 60
  wait_for_http "$container" "/readyz" 60

  api_get "$container" "/api/processes/stable-sidecar/logs?tail=20" |
    jq -e '.logs[] | select(.line | contains("stable-start"))' >/dev/null

  api_post "$container" "/api/processes/stable-sidecar/stop" '{}' | jq -e '.queued == true' >/dev/null
  wait_for_process "$container" "stable-sidecar" '.status == "stopped"' 30
  [[ "$(http_status "$container" "/readyz")" == "503" ]]

  ensure_process_running "$container" "stable-sidecar" 60

  local pid_before
  pid_before="$(api_get "$container" "/api/processes" | jq -r '.processes[] | select(.name == "stable-sidecar") | .pid')"
  api_post "$container" "/api/processes/stable-sidecar/restart" '{}' | jq -e '.queued == true' >/dev/null
  for _ in $(seq 1 30); do
    local pid_after
    pid_after="$(api_get "$container" "/api/processes" | jq -r '.processes[] | select(.name == "stable-sidecar") | .pid')"
    if [[ "$pid_after" != "$pid_before" && "$pid_after" != "null" ]]; then
      ensure_process_running "$container" "stable-sidecar" 30
      return 0
    fi
    sleep 1
  done
  echo "ERROR: stable-sidecar pid did not change after restart" >&2
  return 1
}

scenario_process_failure_modes() {
  local container
  start_container failures true
  container="$STARTED_CONTAINER"
  wait_for_http "$container" "/readyz" 60

  local config
  config='{
    "lxmd_bin": "/usr/local/bin/lxmd",
    "rns": {"shared_instance_port": 37428},
    "http": {"host": "127.0.0.1", "port": 37529, "disable_auth": true},
    "sidecars": [
      {
        "name": "failing-sidecar",
        "bin": "/tmp/sidecars/fail.sh",
        "restart": false
      },
      {
        "name": "flappy-sidecar",
        "bin": "/tmp/sidecars/flappy.sh",
        "args": ["/tmp/lxmf-server/run/flappy-sidecar.ready"],
        "restart": true,
        "ready_file": "/tmp/lxmf-server/run/flappy-sidecar.ready"
      }
    ]
  }'

  api_post "$container" "/api/config/apply" "$config" |
    jq -e '.action == "apply" and (.processes_to_restart | index("failing-sidecar")) and (.processes_to_restart | index("flappy-sidecar"))' >/dev/null

  wait_for_process "$container" "failing-sidecar" 'true' 30
  wait_for_process "$container" "flappy-sidecar" 'true' 30
  wait_for_process "$container" "failing-sidecar" '.status == "stopped"' 30
  api_post "$container" "/api/processes/failing-sidecar/start" '{}' | jq -e '.queued == true' >/dev/null
  ensure_process_running "$container" "flappy-sidecar" 60

  wait_for_process "$container" "failing-sidecar" '.status == "stopped" and .exit_code == 7' 30

  for _ in $(seq 1 60); do
    if api_get "$container" "/api/processes" |
      jq -e '.processes[] | select(.name == "flappy-sidecar" and .restart_count >= 1)' >/dev/null; then
      break
    fi
    sleep 1
  done
  api_get "$container" "/api/processes" |
    jq -e '.processes[] | select(.name == "flappy-sidecar" and .restart_count >= 1)' >/dev/null
  docker exec "$container" sh -lc 'test "$(cat /tmp/sidecars/flappy-count)" -ge 2'
  [[ "$(http_status "$container" "/readyz")" == "503" ]]
}

scenario_bad_config_and_missing_process() {
  local container
  start_container validation true
  container="$STARTED_CONTAINER"
  wait_for_http "$container" "/readyz" 60

  [[ "$(http_status "$container" "/api/processes/does-not-exist/logs")" == "404" ]]
  api_post "$container" "/api/processes/does-not-exist/restart" '{}' | jq -e '.queued == true' >/dev/null

  local invalid_status
  invalid_status="$(docker exec -i "$container" curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" --data-binary @- http://127.0.0.1:37529/api/config/validate <<< '{"unexpected":true}')"
  [[ "$invalid_status" == "400" ]]

  local bad_config
  bad_config='{
    "lxmd_bin": "/tmp/fake-bin/does-not-exist",
    "http": {"host": "127.0.0.1", "port": 37529, "disable_auth": true}
  }'
  api_post "$container" "/api/config/validate" "$bad_config" |
    jq -e '.valid == true and .config.lxmd_bin == "/tmp/fake-bin/does-not-exist"' >/dev/null
}

run_scenario() {
  local name="$1"
  echo ""
  echo "============================================"
  echo "  lxmf-server E2E: ${name}"
  echo "============================================"
  "scenario_${name}"
}

run_scenario smoke_and_generated_config
run_scenario auth
run_scenario config_apply_and_sidecars
run_scenario process_failure_modes
run_scenario bad_config_and_missing_process

echo ""
echo "=== lxmf-server comprehensive E2E passed ==="
