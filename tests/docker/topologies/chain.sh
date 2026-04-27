#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/topology.sh"

N="${1:?Usage: chain.sh N}"
TOPOLOGY="chain-${N}"
OUT_DIR="${SCRIPT_DIR}/configs/${TOPOLOGY}"
RNS_PORT_BASE="${RNS_PORT_BASE:-8081}"
LXMF_PORT_BASE="${LXMF_PORT_BASE:-8181}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

COMPOSE_FILE="${OUT_DIR}/docker-compose.yml"
gen_compose_header "$COMPOSE_FILE"

ports=()
rns_ports=()
lxmf_ports=()
client_services=()
volumes=()

for (( i=0; i<N; i++ )); do
  letter="$(node_letter "$i")"
  upper="$(echo "$letter" | uppercase)"
  rns_service="rns-${letter}"
  lxmf_service="lxmf-${letter}"
  rns_port=$((RNS_PORT_BASE + i))
  lxmf_port=$((LXMF_PORT_BASE + i))
  config_dir="${OUT_DIR}/${rns_service}"

  ifaces=("TCPServerInterface:listen_ip=0.0.0.0:listen_port=4965")
  depends=()
  if (( i > 0 )); then
    prev="rns-$(node_letter $((i - 1)))"
    ifaces+=("TCPClientInterface:target_host=${prev}:target_port=4965")
    depends+=("$prev")
  fi

  gen_rns_config "$config_dir" "${ifaces[@]}"
  gen_rns_service "$COMPOSE_FILE" "$rns_service" "$rns_port" "$config_dir" "${depends[@]}"
  gen_lxmf_service "$COMPOSE_FILE" "$lxmf_service" "$lxmf_port" "$rns_service"

  ports+=("RNS_${upper}_PORT=${rns_port}")
  ports+=("LXMF_${upper}_PORT=${lxmf_port}")
  rns_ports+=("$rns_port")
  lxmf_ports+=("$lxmf_port")
  client_services+=("$lxmf_service")
  volumes+=("${rns_service}-data" "${lxmf_service}-data")
done

{
  echo "volumes:"
  for volume in "${volumes[@]}"; do
    echo "  ${volume}:"
  done
} >> "$COMPOSE_FILE"

ports+=("TOPOLOGY=${TOPOLOGY}")
ports+=("TOPO_TYPE=chain")
ports+=("TOPO_N=${N}")
ports+=("LXMF_CLIENT_COUNT=${N}")
ports+=("RNS_CONTROL_PORTS=\"${rns_ports[*]}\"")
ports+=("LXMF_CLIENT_PORTS=\"${lxmf_ports[*]}\"")
ports+=("LXMF_CLIENT_SERVICES=\"${client_services[*]}\"")

write_ports_env "${OUT_DIR}/ports.env" "${ports[@]}"
echo "Generated ${TOPOLOGY}"
