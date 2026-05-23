#!/usr/bin/env python3
"""Collect LXMF VPS overlay diagnostics over SSH."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

DEFAULT_TARGETS = ["vps-eu=root@vps-eu", "vps-us=root@vps-us"]
DEFAULT_CONFIG_DIR = "/var/lib/lxmf-server"
DEFAULT_PORT = 37529


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def run(cmd: list[str], timeout: int = 30) -> CommandResult:
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    return CommandResult(
        " ".join(shlex.quote(part) for part in cmd),
        proc.returncode,
        proc.stdout,
        proc.stderr,
    )


def run_ssh(target: str, script: str, timeout: int = 30) -> CommandResult:
    return run(["ssh", target, f"bash -lc {shlex.quote(script)}"], timeout=timeout)


def parse_json_result(result: CommandResult) -> Any:
    if result.returncode != 0 or not result.stdout.strip():
        return {
            "ok": False,
            "error": result.stderr.strip() or result.stdout.strip(),
            "returncode": result.returncode,
        }
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "error": f"invalid JSON: {exc}",
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }


def get_auth_token(target: str, config_dir: str) -> tuple[str | None, CommandResult]:
    path = f"{config_dir}/lxmf-server.json"
    py = (
        "import json; "
        f"cfg=json.load(open({path!r})); "
        "print(cfg.get('http', {}).get('auth_token', ''))"
    )
    result = run_ssh(target, "python3 -c " + shlex.quote(py), timeout=10)
    token = result.stdout.strip() if result.returncode == 0 else ""
    return (token or None), result


def curl_json(
    target: str,
    path: str,
    token: str | None,
    port: int,
    timeout: int = 15,
) -> tuple[Any, CommandResult]:
    headers = ""
    if token:
        headers = "-H " + shlex.quote(f"Authorization: Bearer {token}")
    cmd = f"curl -sf {headers} http://127.0.0.1:{port}{path}"
    result = run_ssh(target, cmd, timeout=timeout)
    return parse_json_result(result), result


def shell_probe(target: str, config_dir: str) -> dict[str, Any]:
    lxmd_config = f"{config_dir}/lxmd"
    rns_config = f"{config_dir}/rns-client"
    script = f"""
set +e
echo --systemd
systemctl is-active rns-server lxmf-server 2>&1
echo --processes
ps -eo pid,lstart,cmd | grep -E '[r]ns-server|[l]xmf-server|[l]xmd'
echo --sockets
ss -xap 2>/dev/null | grep -E '@rns/default|lxmd|rns-server' || true
echo --tcp
ss -tanp 2>/dev/null | grep -E '37529|37428|18080|4242' || true
echo --storage
find {shlex.quote(lxmd_config)}/storage/lxmf -maxdepth 2 -type f -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort || true
echo --messages
find {shlex.quote(lxmd_config)}/messages -type f -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort | tail -50 || true
echo --logs
if test -f {shlex.quote(config_dir)}/logs/lxmd.log; then
  grep -Eai 'shared instance|connect|failed|error|warn|deliver|received|inbound|message|propagation|peer|sync|control' {shlex.quote(config_dir)}/logs/lxmd.log | tail -120
fi
echo --lxmd-status
if command -v timeout >/dev/null 2>&1; then
  timeout 20 /usr/local/bin/lxmd --config {shlex.quote(lxmd_config)} --rnsconfig {shlex.quote(rns_config)} --status --timeout 15
  echo STATUS_RC=$?
  timeout 20 /usr/local/bin/lxmd --config {shlex.quote(lxmd_config)} --rnsconfig {shlex.quote(rns_config)} --peers --timeout 15
  echo PEERS_RC=$?
else
  /usr/local/bin/lxmd --config {shlex.quote(lxmd_config)} --rnsconfig {shlex.quote(rns_config)} --status --timeout 15
  echo STATUS_RC=$?
  /usr/local/bin/lxmd --config {shlex.quote(lxmd_config)} --rnsconfig {shlex.quote(rns_config)} --peers --timeout 15
  echo PEERS_RC=$?
fi
"""
    result = run_ssh(target, script, timeout=90)
    return result.as_dict()


def collect_host(host: str, ssh_target: str, config_dir: str, port: int) -> dict[str, Any]:
    token, token_result = get_auth_token(ssh_target, config_dir)
    health, health_cmd = curl_json(ssh_target, "/healthz", None, port)
    ready, ready_cmd = curl_json(ssh_target, "/readyz", None, port)
    info, info_cmd = curl_json(ssh_target, "/api/info", token, port)
    processes, processes_cmd = curl_json(ssh_target, "/api/processes", token, port)
    diagnostics, diagnostics_cmd = curl_json(ssh_target, "/api/diagnostics", token, port)
    return {
        "host": host,
        "ssh_target": ssh_target,
        "config_dir": config_dir,
        "port": port,
        "auth_token_present": token is not None,
        "auth_token_command": {
            **token_result.as_dict(),
            "stdout": "<redacted>" if token else token_result.stdout,
        },
        "healthz": health,
        "readyz": ready,
        "api_info": info,
        "api_processes": processes,
        "api_diagnostics": diagnostics,
        "commands": {
            "healthz": health_cmd.as_dict(),
            "readyz": ready_cmd.as_dict(),
            "api_info": info_cmd.as_dict(),
            "api_processes": processes_cmd.as_dict(),
            "api_diagnostics": diagnostics_cmd.as_dict(),
        },
        "shell_probe": shell_probe(ssh_target, config_dir),
    }


def summarize(host: dict[str, Any]) -> str:
    lines = [f"== {host['host']} =="]
    ready = host.get("readyz")
    if isinstance(ready, dict) and "ready" in ready:
        lines.append(f"readyz: {ready['ready']}")
    else:
        lines.append(f"readyz: unavailable ({ready})")
    diagnostics = host.get("api_diagnostics")
    if isinstance(diagnostics, dict) and "status" in diagnostics:
        lines.append(f"diagnostics: {diagnostics['status']}")
        for check in diagnostics.get("checks", []):
            status = "ok" if check.get("ok") else "FAIL"
            lines.append(f"  {status} {check.get('name')}: {check.get('detail')}")
        storage = diagnostics.get("lxmd", {}).get("storage", {})
        msg = storage.get("messagestore", {})
        peers = storage.get("peers", {})
        if msg:
            lines.append(
                f"  messagestore: {msg.get('file_count')} files / {msg.get('total_bytes')} bytes"
            )
        if peers:
            lines.append(f"  peers file: {peers.get('bytes')} bytes")
    else:
        lines.append("diagnostics: unavailable on deployed lxmf-server")
    shell = host.get("shell_probe", {})
    if shell.get("returncode") != 0:
        lines.append(f"shell probe failed: {shell.get('stderr', '').strip()}")
    else:
        text = shell.get("stdout", "")
        for needle in ["STATUS_RC=", "PEERS_RC="]:
            for line in text.splitlines():
                if line.startswith(needle):
                    lines.append(line)
        for line in text.splitlines():
            low = line.lower()
            is_lxmd_log = line.startswith("[stderr]") or line.startswith("[stdout]")
            if (
                is_lxmd_log
                and "shared instance" in low
                and ("failed" in low or "refused" in low)
            ):
                lines.append(f"shared-instance error: {line[:220]}")
                break
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        action="append",
        help="Host key or host=ssh-target. Defaults to root@vps-eu and root@vps-us.",
    )
    parser.add_argument("--config-dir", default=DEFAULT_CONFIG_DIR)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--json", action="store_true", help="Print full JSON report")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_targets = args.target or DEFAULT_TARGETS
    targets = []
    for target in raw_targets:
        if "=" in target:
            host, ssh_target = target.split("=", 1)
        else:
            host = ssh_target = target
        targets.append((host, ssh_target))

    report = [collect_host(host, ssh_target, args.config_dir, args.port) for host, ssh_target in targets]
    if args.json:
        json.dump({"hosts": report}, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        print("\n\n".join(summarize(host) for host in report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
