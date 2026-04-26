#!/usr/bin/env bash
set -euo pipefail

cargo clippy \
  --workspace \
  --all-targets
