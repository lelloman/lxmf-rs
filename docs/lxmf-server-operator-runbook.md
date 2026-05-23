# lxmf-server Operator Runbook

## Scope

`lxmf-server` is the supervisor and local control server for LXMF application
services. It owns:

- process lifecycle for `lxmd`
- persisted `lxmf-server.json` config
- generated RNS client config for `lxmd`
- embedded LXMF HTTP control API
- process readiness and recent process logs

`lxmf-server` does not replace `rns-server`. On the VPS experiment hosts,
`rns-server` remains the Reticulum transport node and `lxmf-server` runs beside
it as an LXMF overlay service. `lxmd` connects to the local shared RNS instance
through `LocalClientInterface` on port `37428`.

## Build

For a direct local build:

```bash
cargo build --release -p lxmf-server -p lxmd
```

The two runtime binaries are:

- `target/release/lxmf-server`
- `target/release/lxmd`

## Files And Paths

On the VPS hosts, keep RNS and LXMF runtime state separate:

- `/var/lib/rns-node`
  Existing `rns-server` config root.
- `/var/lib/lxmf-server`
  `lxmf-server` config root.
- `/var/lib/lxmf-server/lxmf-server.json`
  Product config managed by `lxmf-server`.
- `/var/lib/lxmf-server/lxmd`
  Default `lxmd` config directory.
- `/var/lib/lxmf-server/rns-client/config`
  Generated RNS client config for `lxmd`.
- `/var/lib/lxmf-server/logs/lxmd.log`
  Durable stdout/stderr log for `lxmd`.
- `/var/lib/lxmf-server/run/lxmd.ready`
  Readiness marker written by `lxmd`.

Install binaries under:

- `/usr/local/bin/lxmf-server`
- `/usr/local/bin/lxmd`

## RNS Dependency

Each VPS must already run `rns-server` with shared instance support enabled on
port `37428`. The RNS node config should include:

```ini
[reticulum]
share_instance = Yes
shared_instance_port = 37428
```

Keep the public Reticulum listener, transport behavior, and RNS control plane in
the existing `rns-server` deployment. `lxmf-server` should only bind its own
control API to localhost unless there is a specific reason to expose it.

## VPS Experiment Targets

The LXMF overlay should run on both current VPS experiment targets:

| Target | SSH alias | Role |
| --- | --- | --- |
| `vps-eu` | `vps-eu` | EU Reticulum node plus LXMF propagation node |
| `vps-us` | `vps-us` | US Reticulum node plus LXMF propagation node |

Use the same LXMF runtime layout on both machines unless a test case explicitly
requires a regional difference:

- LXMF config root: `/var/lib/lxmf-server`
- LXMF control plane: `127.0.0.1:37529`
- RNS shared instance: `127.0.0.1:37428`
- installed binaries: `/usr/local/bin/lxmf-server`, `/usr/local/bin/lxmd`

## Install Or Update

From a local release build, copy the binaries to each host:

```bash
cargo build --release -p lxmf-server -p lxmd

for host in vps-eu vps-us; do
  scp target/release/lxmf-server target/release/lxmd "root@$host:/usr/local/bin/"
  ssh "root@$host" 'chmod 0755 /usr/local/bin/lxmf-server /usr/local/bin/lxmd'
done
```

Create the LXMF config root and baseline config:

```bash
for host in vps-eu vps-us; do
  ssh "root@$host" 'mkdir -p /var/lib/lxmf-server'
  ssh "root@$host" 'cat > /var/lib/lxmf-server/lxmf-server.json <<EOF
{
  "lxmd_bin": "/usr/local/bin/lxmd",
  "lxmd": {
    "propagation_node": true
  },
  "rns": {
    "shared_instance_port": 37428
  },
  "http": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 37529,
    "auth_token": "replace-with-host-local-token"
  }
}
EOF'
done
```

Use a unique token per host. Do not set `disable_auth` on shared VPS
infrastructure unless the API is strictly reachable only through a trusted local
channel.

## systemd Service

Install this service on both VPSes:

```ini
[Unit]
Description=LXMF server
After=rns-server.service
Requires=rns-server.service

[Service]
Type=simple
ExecStart=/usr/local/bin/lxmf-server start --config /var/lib/lxmf-server
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Example remote install:

```bash
for host in vps-eu vps-us; do
  ssh "root@$host" 'cat > /etc/systemd/system/lxmf-server.service <<EOF
[Unit]
Description=LXMF server
After=rns-server.service
Requires=rns-server.service

[Service]
Type=simple
ExecStart=/usr/local/bin/lxmf-server start --config /var/lib/lxmf-server
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now lxmf-server'
done
```

## Startup

Development startup from the workspace:

```bash
cargo run -p lxmf-server -- start --config /tmp/lxmf-server
```

Release-style startup on a VPS:

```bash
/usr/local/bin/lxmf-server start --config /var/lib/lxmf-server
```

Useful flags:

- `--config PATH`
  Config directory containing `lxmf-server.json`.
- `--lxmd-bin PATH`
  Advanced override for the `lxmd` executable.
- `--http-host HOST`
  Embedded control-plane bind host.
- `--http-port PORT`
  Embedded control-plane port.
- `--http-token TOKEN`
  Fixed bearer token for the control plane.
- `--disable-auth`
  Disable control-plane auth.
- `--no-http`
  Disable the embedded control plane.
- `--dry-run`
  Print the launch plan and exit.

## Verification

Check service state and versions on both machines:

```bash
for host in vps-eu vps-us; do
  echo "== $host =="
  ssh "root@$host" 'systemctl status rns-server --no-pager'
  ssh "root@$host" 'systemctl status lxmf-server --no-pager'
  ssh "root@$host" '/usr/local/bin/lxmf-server --version; /usr/local/bin/lxmd --version'
done
```

Check local health and readiness:

```bash
for host in vps-eu vps-us; do
  echo "== $host =="
  ssh "root@$host" 'curl -sf http://127.0.0.1:37529/healthz'
  ssh "root@$host" 'curl -sf http://127.0.0.1:37529/readyz'
  ssh "root@$host" 'test -f /var/lib/lxmf-server/rns-client/config'
  ssh "root@$host" 'grep -q "LocalClientInterface" /var/lib/lxmf-server/rns-client/config'
  ssh "root@$host" 'grep -q "port = 37428" /var/lib/lxmf-server/rns-client/config'
done
```

Health endpoints are unauthenticated. API calls under `/api/` require the bearer
token configured in `lxmf-server.json`:

```bash
curl -sf -H "Authorization: Bearer $LXMF_SERVER_TOKEN" \
  http://127.0.0.1:37529/api/info
```

For remote access, prefer SSH forwarding:

```bash
ssh -L 37529:127.0.0.1:37529 root@vps-eu
```

## Control Plane

Key endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /api/info`
- `GET /api/processes`
- `GET /api/processes/:name/logs`
- `GET /api/diagnostics`
- `GET /api/config`
- `GET /api/config/schema`
- `POST /api/config/validate`
- `POST /api/config/save`
- `POST /api/config/apply`
- `POST /api/processes/:name/start`
- `POST /api/processes/:name/stop`
- `POST /api/processes/:name/restart`

The only default managed process is `lxmd`. Additional sidecars can be declared
in `lxmf-server.json`.

## Config

Minimal VPS config:

```json
{
  "lxmd_bin": "/usr/local/bin/lxmd",
  "lxmd": {
    "propagation_node": true
  },
  "rns": {
    "shared_instance_port": 37428
  },
  "http": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 37529,
    "auth_token": "replace-with-host-local-token"
  }
}
```

Common fields:

- `lxmd_bin`
  Path to the `lxmd` executable.
- `lxmd.config_dir`
  Explicit `lxmd` config directory. Defaults under the server config root.
- `lxmd.rns_config_dir`
  Explicit RNS client config directory. Defaults under the server config root.
- `lxmd.propagation_node`
  Starts `lxmd` as an LXMF propagation node.
- `lxmd.on_inbound`
  External executable to run when a message is received.
- `rns.shared_instance_port`
  Local RNS shared instance port. Default is `37428`.
- `http.enabled`
  Enables or disables the LXMF control API.
- `http.host`
  HTTP bind host. Use `127.0.0.1` on VPSes.
- `http.port`
  HTTP bind port. Default is `37529`.
- `http.auth_token`
  Bearer token for `/api/` endpoints.
- `sidecars`
  Optional supervised helper processes.

## Propagation Peering

Start both VPSes with LXMF propagation enabled and autopeering left at the
`lxmd` default. After both nodes are stable, capture their propagation node
destination hashes from `lxmd` logs and decide whether the experiment needs
deterministic static peering.

If static peering is needed, write explicit `lxmd` propagation config in the
`lxmd.config_dir` and include each remote node in `static_peers`.

## Observability

Use the LXMF control API first:

- `/readyz`
  Returns `200` only when all managed processes are running and ready. This is
  process readiness only; it is not delivery proof.
- `/api/processes`
  Shows managed process status, readiness, PID, restart count, and recent logs.
- `/api/processes/lxmd/logs?tail=100`
  Shows recent buffered `lxmd` logs.
- `/api/diagnostics`
  Shows an operator summary with process readiness, LXMF storage counters,
  recent `lxmd` log-derived signals, and explicit pass/fail checks for the
  local overlay. Treat `degraded` as actionable until the failing checks are
  understood.

Health endpoints are unauthenticated. Calls under `/api/` require the bearer
token from `lxmf-server.json` unless auth is explicitly disabled. A local check
on a VPS looks like this:

```bash
token=$(jq -r '.http.auth_token' /var/lib/lxmf-server/lxmf-server.json)
curl -sf -H "Authorization: Bearer $token" \
  http://127.0.0.1:37529/api/diagnostics | jq
```

From the workspace, collect both VPSes with the LXMF report script:

```bash
scripts/lxmf_vps_report.py
scripts/lxmf_vps_report.py --json > /tmp/lxmf-vps-report.json
```

The script SSHes to each host, reads the local API token, queries `/healthz`,
`/readyz`, `/api/processes`, and `/api/diagnostics`, then falls back to
shell-level probes. It also runs `lxmd --status` and `lxmd --peers` against the
local RNS shared instance so propagation control reachability is visible even
when the HTTP supervisor endpoint is older than this runbook.

Shell-level checks remain useful when the HTTP API is unavailable:

```bash
journalctl -u lxmf-server --since '1 hour ago' --no-pager
tail -n 200 /var/lib/lxmf-server/logs/lxmd.log
find /var/lib/lxmf-server/lxmd/storage/lxmf -maxdepth 2 -type f -ls
ss -xap | grep '@rns/default'
```

### Delivery Evidence

Do not use RNS transport health alone as LXMF delivery evidence. The RNS daily
report proves the Reticulum node is healthy; it does not prove LXMF delivery or
propagation peering.

For "we are delivering messages" to be true on the VPS experiment, collect all
of these signals or explain why a missing signal is expected for the test:

1. `/readyz` returns `200` on both hosts.
2. `/api/diagnostics` is `healthy`, or every failing check is explained.
3. `lxmd --status` returns successfully on each host and shows the propagation
   message store and client counters.
4. `lxmd --peers` returns successfully and shows the expected remote
   propagation peer(s), or the experiment explicitly does not require peering.
5. The sender observes an outbound state transition for the test message, and
   the receiver observes the message content or an inbound callback/log entry.
6. If propagation delivery is being tested, the propagation node message store
   count or client propagation counters change during the test window.

Negative signals that mean delivery is not demonstrated:

- `lxmd --status` or `lxmd --peers` times out.
- The `peers` storage file is empty or only contains an empty msgpack object.
- The message store is empty after a test that should have used propagation.
- Recent logs contain shared-instance connection failures.
- `ss -xap` shows no live `lxmd` connection to `@rns/default` while the service
  is expected to be online.

### RNS Daily VPS Report DB Handoff

Keep the daily report SQLite database on `vps-eu` as the canonical handoff copy
so the report can be run from more than one workstation. This is the report
database used by `scripts/vps_daily_report.py` in `rns-rs`; do not replace the
live RNS node runtime database at `/var/lib/rns-node/stats.db`.

Before running the daily report, download the latest handoff copy:

```bash
cd ../rns-rs
scp root@vps-eu:/root/vps_daily_reports.db data/vps_daily_reports.db
```

Then collect the daily snapshots locally:

```bash
python3 scripts/vps_daily_report.py --host vps-eu --ssh-target root@vps-eu --stdout-summary
python3 scripts/vps_daily_report.py --host vps-us --ssh-target root@vps-us --stdout-summary
```

After both captures complete, upload the updated database back to `vps-eu`:

```bash
scp data/vps_daily_reports.db root@vps-eu:/root/vps_daily_reports.db
```

If the handoff database is missing on `vps-eu`, start from the local
`data/vps_daily_reports.db`, run both captures, and upload it immediately after
the report. Only one workstation should run the handoff procedure at a time.

## Troubleshooting

If `lxmf-server` starts but `lxmd` is not ready:

1. Check `systemctl status rns-server`.
2. Confirm the RNS shared instance port is enabled and listening on `37428`.
3. Inspect `/var/lib/lxmf-server/rns-client/config`.
4. Inspect `/api/processes` and `/api/processes/lxmd/logs?tail=200`.
5. Inspect `journalctl -u lxmf-server`.

Common cases:

- `lxmd` cannot connect to RNS
  Verify `rns-server` is active and `share_instance = Yes` is set on the RNS
  node config. Check `ss -xap | grep '@rns/default'`; a healthy LXMF process
  should have a live connection to the shared instance. If `lxmd` started before
  the shared instance was available and did not reconnect, restart
  `lxmf-server`.
- `/readyz` returns `503`
  Inspect `/api/processes`; `lxmd` may still be starting or restarting.
- `/api/diagnostics` returns `degraded`
  Read the failing checks first. Common causes are empty peer state, missing
  message-store directories, or recent shared-instance connection errors.
- `lxmd --status` or `lxmd --peers` times out
  The propagation control destination is not reachable. Confirm `lxmd` is
  connected to RNS, wait for path discovery, and inspect recent announce logs.
- API returns `401`
  Provide `Authorization: Bearer <token>` or verify `http.auth_token`.
- Port conflict on `37529`
  Change `http.port` in `lxmf-server.json` and restart `lxmf-server`.

## Release Smoke Checklist

Before deploying a new LXMF build to the VPSes:

1. `cargo test -p lxmf-server`
2. `cargo test -p lxmd`
3. `cargo test -p lxmf-rs`
4. `bash tests/docker/lxmf-server/run.sh`
5. `bash tests/docker/run-all.sh`
