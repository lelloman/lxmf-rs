#!/usr/bin/env bash
set -euo pipefail

node_letter() {
  local idx="$1"
  printf "\\$(printf '%03o' "$(( idx + 97 ))")"
}

uppercase() {
  tr '[:lower:]' '[:upper:]'
}

gen_rns_config() {
  local node_dir="$1"
  shift

  mkdir -p "$node_dir"

  {
    echo "[reticulum]"
    echo "enable_transport = True"
    echo "share_instance = Yes"
    echo "provider_bridge = Yes"
    echo "provider_socket_path = /data/rns/provider.sock"
    echo ""
    echo "[interfaces]"
  } > "${node_dir}/config"

  local iface_num=0
  local spec
  for spec in "$@"; do
    local iface_type="${spec%%:*}"
    local remainder="${spec#*:}"

    {
      echo ""
      echo "  [[Interface ${iface_num}]]"
      echo "    type = ${iface_type}"
    } >> "${node_dir}/config"
    (( iface_num++ )) || true

    while [[ -n "$remainder" && "$remainder" != "$spec" ]]; do
      local pair
      if [[ "$remainder" == *:* ]]; then
        pair="${remainder%%:*}"
        remainder="${remainder#*:}"
      else
        pair="$remainder"
        remainder=""
      fi
      echo "    ${pair%%=*} = ${pair#*=}" >> "${node_dir}/config"
    done
  done
}

gen_compose_header() {
  local file="$1"
  cat > "$file" <<'EOF'
networks:
  lxmf-e2e:
    driver: bridge

services:
EOF
}

gen_rns_service() {
  local file="$1" name="$2" host_port="$3" config_dir="$4"
  shift 4
  local depends=("$@")

  cat >> "$file" <<EOF
  ${name}:
    image: lxmf-e2e
    container_name: ${name}
    command: >
      sh -c "mkdir -p /data/rns &&
             cp /etc/rns/config /data/rns/config &&
             exec rns-ctl http --config /data/rns --disable-auth --host 0.0.0.0 --port 8080"
    volumes:
      - ${config_dir}:/etc/rns:ro
      - ${name}-data:/data/rns
    ports:
      - "${host_port}:8080"
    networks:
      - lxmf-e2e
EOF

  if (( ${#depends[@]} > 0 )); then
    echo "    depends_on:" >> "$file"
    local dep
    for dep in "${depends[@]}"; do
      cat >> "$file" <<EOF
      ${dep}:
        condition: service_healthy
EOF
    done
  fi

  echo "" >> "$file"
}

gen_lxmf_service() {
  local file="$1" name="$2" host_port="$3" rns_service="$4"

  cat >> "$file" <<EOF
  ${name}:
    image: lxmf-e2e
    container_name: ${name}
    command: ["lxmf-test-node", "${rns_service}:4965", "0.0.0.0:8080", "/data/lxmf", "${name}"]
    volumes:
      - ${name}-data:/data/lxmf
    ports:
      - "${host_port}:8080"
    networks:
      - lxmf-e2e
    depends_on:
      ${rns_service}:
        condition: service_healthy

EOF
}

write_ports_env() {
  local file="$1"
  shift
  > "$file"
  local line
  for line in "$@"; do
    echo "$line" >> "$file"
  done
}
