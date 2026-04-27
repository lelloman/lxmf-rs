#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RNS_ROOT="$(cd "${REPO_ROOT}/../rns-rs" 2>/dev/null && pwd || true)"

SKIP_SCALE=false
NO_TEARDOWN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-scale) SKIP_SCALE=true; shift ;;
    --no-teardown) NO_TEARDOWN=true; shift ;;
    *)
      echo "Usage: $0 [--no-scale] [--no-teardown]" >&2
      exit 1
      ;;
  esac
done

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
source "${SCRIPT_DIR}/lib/summary.sh"

echo "============================================"
echo "  Building lxmf-e2e Docker image"
echo "============================================"
build_lxmf_e2e_image "$SCRIPT_DIR" "$REPO_ROOT" "$RNS_ROOT" "lxmf-e2e"

MATRIX=(
  "chain-3  all  Core LXMF behavior on 3-node chain"
  "chain-5  all  Multi-hop LXMF behavior on 5-node chain"
  "mesh-4   all  Mesh LXMF convergence and delivery"
  "star-8   all  Star fan-out with many LXMF clients"
)

if ! $SKIP_SCALE; then
  MATRIX+=("star-12  10  Scale subset on 12-client star")
fi

export TEST_RESULTS_FILE
TEST_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/lxmf-e2e-results.XXXXXX")"
trap 'rm -f "$TEST_RESULTS_FILE"' EXIT

TOTAL_RUNS=0
TOTAL_FAILED=0
RESULTS=()
START_TIME=$SECONDS

for entry in "${MATRIX[@]}"; do
  read -r topology suite_filter description <<< "$entry"
  description="${entry#*  *  }"
  (( TOTAL_RUNS++ )) || true

  echo ""
  echo "============================================"
  echo "  [${TOTAL_RUNS}] ${description}"
  echo "  topology=${topology} suite=${suite_filter}"
  echo "============================================"

  args=("--topology" "$topology")
  if [[ "$suite_filter" != "all" ]]; then
    args+=("--suite" "$suite_filter")
  fi
  if $NO_TEARDOWN; then
    args+=("--no-teardown")
  fi

  if SKIP_BUILD=true TEST_RESULTS_FILE="$TEST_RESULTS_FILE" bash "${SCRIPT_DIR}/run.sh" "${args[@]}"; then
    RESULTS+=("PASS  ${description}")
  else
    RESULTS+=("FAIL  ${description}")
    (( TOTAL_FAILED++ )) || true
  fi
done

ELAPSED=$((SECONDS - START_TIME))

print_test_summary "$TEST_RESULTS_FILE"

echo ""
echo "============================================"
echo "  FULL DOCKER E2E MATRIX RESULTS"
echo "============================================"
for result in "${RESULTS[@]}"; do
  echo "  ${result}"
done
echo "--------------------------------------------"
echo "  Runs: ${TOTAL_RUNS}  Failed: ${TOTAL_FAILED}  Time: ${ELAPSED}s"
echo "============================================"

if (( TOTAL_FAILED > 0 )); then
  exit 1
fi
