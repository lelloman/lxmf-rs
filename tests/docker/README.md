# Docker E2E

This suite runs real `rns-ctl` nodes and LXMF test clients in Docker Compose
topologies. It is intended to exercise inter-node behavior that unit tests do
not cover: discovery, opportunistic delivery, direct links, restarts,
propagation-node announce handling, propagated sends, and multi-client scale.

## Run

```sh
tests/docker/run-all.sh
```

Useful narrower runs:

```sh
tests/docker/run.sh --topology chain-3
tests/docker/run.sh --topology mesh-4
tests/docker/run.sh --topology star-8 --suite 10
```

`run-all.sh` builds the Docker image once, then reuses it across the topology
matrix. Individual runs can skip the image build:

```sh
SKIP_BUILD=true tests/docker/run.sh --topology chain-3
```

If local host ports are occupied, move the generated port ranges:

```sh
RNS_PORT_BASE=18080 LXMF_PORT_BASE=18181 \
  SKIP_BUILD=true tests/docker/run.sh --topology star-12 --suite 10
```

The default ports are stable for CI:

- RNS control APIs: `8080+` for star topologies, `8081+` for chain/mesh
- LXMF control APIs: `8181+`

## Requirements

- Docker with Compose v2
- `curl`
- `jq`
- `tar`
- sibling checkout at `../rns-rs`
