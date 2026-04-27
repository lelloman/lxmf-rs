#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RNS_ROOT="$(cd "${REPO_ROOT}/../rns-rs" 2>/dev/null && pwd || true)"

TOPOLOGY="chain-3"
SUITE_FILTER=""
CLEAN_ONLY=false
NO_TEARDOWN=false
IMAGE="lxmf-e2e"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --topology) TOPOLOGY="$2"; shift 2 ;;
    --suite) SUITE_FILTER="$2"; shift 2 ;;
    --clean) CLEAN_ONLY=true; shift ;;
    --no-teardown) NO_TEARDOWN=true; shift ;;
    *)
      echo "Usage: $0 [--topology TOPOLOGY] [--suite FILTER] [--clean] [--no-teardown]" >&2
      exit 1
      ;;
  esac
done

if $CLEAN_ONLY; then
  for file in "${SCRIPT_DIR}"/configs/*/docker-compose.yml; do
    [[ -f "$file" ]] || continue
    docker compose -f "$file" down -v 2>/dev/null || true
  done
  docker rmi "$IMAGE" 2>/dev/null || true
  rm -rf "${SCRIPT_DIR}/configs"
  exit 0
fi

for cmd in docker curl jq tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: '$cmd' is required." >&2
    exit 1
  fi
done

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose v2 is required." >&2
  exit 1
fi

source "${SCRIPT_DIR}/lib/build.sh"
source "${SCRIPT_DIR}/lib/readiness.sh"
source "${SCRIPT_DIR}/lib/summary.sh"

if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
  echo "=== Building ${IMAGE} Docker image ==="
  build_lxmf_e2e_image "$SCRIPT_DIR" "$REPO_ROOT" "$RNS_ROOT" "$IMAGE"
fi

TOPO_TYPE="${TOPOLOGY%%-*}"
TOPO_N="${TOPOLOGY#*-}"
TOPO_SCRIPT="${SCRIPT_DIR}/topologies/${TOPO_TYPE}.sh"

if [[ ! -f "$TOPO_SCRIPT" ]]; then
  echo "ERROR: unknown topology type '${TOPO_TYPE}'" >&2
  exit 1
fi

echo "=== Generating topology ${TOPOLOGY} ==="
bash "$TOPO_SCRIPT" "$TOPO_N"

COMPOSE_FILE="${SCRIPT_DIR}/configs/${TOPOLOGY}/docker-compose.yml"
PORTS_FILE="${SCRIPT_DIR}/configs/${TOPOLOGY}/ports.env"
export COMPOSE_FILE PORTS_FILE

echo "=== Starting containers ==="
docker compose -f "$COMPOSE_FILE" up -d --wait

set -a
source "$PORTS_FILE"
set +a

source "${SCRIPT_DIR}/lib/helpers.sh"

echo "=== Waiting for topology readiness ==="
wait_for_topology_ready 45
settle_topology_runtime 3

if [[ -z "${TEST_RESULTS_FILE:-}" ]]; then
  export TEST_RESULTS_FILE
  TEST_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/lxmf-e2e-results.XXXXXX")"
  trap 'rm -f "$TEST_RESULTS_FILE"' EXIT
fi

SUITES_RUN=0
SUITES_FAILED=0

run_suite() {
  local suite="$1"
  local suite_name
  suite_name="$(basename "$suite" .sh)"

  echo ""
  echo "=== Running suite: ${suite_name} ==="
  settle_topology_runtime 2
  if bash "$suite"; then
    (( SUITES_RUN++ )) || true
  else
    (( SUITES_RUN++ )) || true
    (( SUITES_FAILED++ )) || true
    echo "--- Container logs (last 80 lines) ---"
    docker compose -f "$COMPOSE_FILE" logs --tail=80 || true
    echo "--- End logs ---"
  fi
}

if [[ -n "$SUITE_FILTER" ]]; then
  matched=false
  for suite in "${SCRIPT_DIR}"/suites/*.sh; do
    [[ -f "$suite" ]] || continue
    if [[ "$(basename "$suite")" == "${SUITE_FILTER}"* ]]; then
      run_suite "$suite"
      matched=true
    fi
  done
  if ! $matched; then
    echo "ERROR: no suite matching '${SUITE_FILTER}'" >&2
    SUITES_FAILED=1
  fi
else
  for suite in "${SCRIPT_DIR}"/suites/*.sh; do
    [[ -f "$suite" ]] || continue
    run_suite "$suite"
  done
fi

if ! $NO_TEARDOWN; then
  echo ""
  echo "=== Tearing down containers ==="
  docker compose -f "$COMPOSE_FILE" down -v
fi

print_test_summary "$TEST_RESULTS_FILE"

echo ""
echo "  Topology: ${TOPOLOGY}"
echo "  Suites run: ${SUITES_RUN}"
echo "  Suites failed: ${SUITES_FAILED}"

if (( SUITES_FAILED > 0 )); then
  exit 1
fi
