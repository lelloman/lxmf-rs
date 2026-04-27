#!/usr/bin/env bash
set -euo pipefail

print_test_summary() {
  local results_file="${1:?Usage: print_test_summary RESULTS_FILE}"

  if [[ ! -f "$results_file" ]] || [[ ! -s "$results_file" ]]; then
    echo ""
    echo "  (no test results recorded)"
    return
  fi

  local total_pass=0 total_fail=0 total_skip=0
  local current_header=""
  local -a failures=()

  echo ""
  echo "============================================"
  echo "  TEST RESULTS SUMMARY"
  echo "============================================"

  while IFS=$'\t' read -r status topology suite msg detail; do
    local header="${suite} [${topology}]"
    if [[ "$header" != "$current_header" ]]; then
      current_header="$header"
      echo ""
      echo "  ${header}"
    fi

    case "$status" in
      PASS)
        echo "    [PASS] ${msg}"
        (( total_pass++ )) || true
        ;;
      FAIL)
        if [[ -n "$detail" ]]; then
          echo "    [FAIL] ${msg} -- ${detail}"
          failures+=("${suite} [${topology}]: ${msg} -- ${detail}")
        else
          echo "    [FAIL] ${msg}"
          failures+=("${suite} [${topology}]: ${msg}")
        fi
        (( total_fail++ )) || true
        ;;
      SKIP)
        echo "    [SKIP] ${msg}"
        (( total_skip++ )) || true
        ;;
    esac
  done < "$results_file"

  echo ""
  echo "--------------------------------------------"
  printf "  Total: %d passed, %d failed, %d skipped\n" "$total_pass" "$total_fail" "$total_skip"

  if (( total_fail > 0 )); then
    echo ""
    echo "  FAILURES:"
    for failure in "${failures[@]}"; do
      echo "    - ${failure}"
    done
  fi
  echo "============================================"
}
