#!/usr/bin/env bash
set -euo pipefail

build_lxmf_e2e_image() {
  local script_dir="${1:?script_dir required}"
  local repo_root="${2:?repo_root required}"
  local rns_root="${3:?rns_root required}"
  local image="${4:-lxmf-e2e}"

  if [[ ! -d "$rns_root" ]]; then
    echo "ERROR: sibling rns-rs checkout not found at ${rns_root}" >&2
    exit 1
  fi

  local context
  context="$(mktemp -d "${TMPDIR:-/tmp}/lxmf-docker-context.XXXXXX")"
  trap 'rm -rf "$context"; trap - RETURN' RETURN

  mkdir -p "${context}/lxmf-rs" "${context}/rns-rs"

  tar -C "$repo_root" \
    --exclude='./.git' \
    --exclude='./target' \
    --exclude='./tests/docker/configs' \
    -cf - . | tar -C "${context}/lxmf-rs" -xf -

  tar -C "$rns_root" \
    --exclude='./.git' \
    --exclude='./target' \
    --exclude='./dist' \
    --exclude='./data' \
    --exclude='./rns-esp32' \
    -cf - . | tar -C "${context}/rns-rs" -xf -

  docker build -t "$image" -f "${script_dir}/Dockerfile" "$context"
}
