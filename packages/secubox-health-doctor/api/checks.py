# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: health-doctor checks (issue #212)

Each check function returns a (ok: bool, details: dict) tuple. Details is
serialized into the per-check JSON, journal events, and CLI output.
Checks must be defensive: any exception -> ok=False, details={"error": str(e)}.
"""
from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, Tuple

CheckFn = Callable[[], Tuple[bool, dict]]


def _run(cmd: list, timeout: int = 5) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _systemd_active(unit: str) -> bool:
    try:
        r = _run(["systemctl", "is-active", "--quiet", unit])
        return r.returncode == 0
    except Exception:
        return False


def _lxc_running(name: str, lxc_path: str = "/data/lxc") -> bool:
    try:
        r = _run(["lxc-info", "-n", name, "-P", lxc_path, "-s"])
        return "RUNNING" in r.stdout
    except Exception:
        return False


def _tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _uds_alive(path: str) -> bool:
    if not Path(path).exists():
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(path)
            return True
    except OSError:
        return False


def _file_mtime_age(p: str) -> float | None:
    try:
        return time.time() - Path(p).stat().st_mtime
    except OSError:
        return None


# ── Vital service checks ──────────────────────────────────────────────────

def check_haproxy() -> tuple[bool, dict]:
    ok = _systemd_active("haproxy")
    stats_socket = "/run/haproxy/admin.sock"
    sock_ok = _uds_alive(stats_socket)
    return (ok and sock_ok, {
        "systemd_active": ok,
        "stats_socket": stats_socket,
        "stats_socket_alive": sock_ok,
    })


def check_nginx() -> tuple[bool, dict]:
    ok = _systemd_active("nginx")
    http = _tcp_open("127.0.0.1", 9080) or _tcp_open("127.0.0.1", 80)
    return (ok and http, {
        "systemd_active": ok,
        "tcp_9080_open": http,
    })


def check_secubox_metrics() -> tuple[bool, dict]:
    unit_ok = _systemd_active("secubox-metrics")
    socket_ok = _uds_alive("/run/secubox/metrics.sock")
    return (unit_ok and socket_ok, {
        "systemd_active": unit_ok,
        "uds_alive": socket_ok,
    })


def check_secubox_hub() -> tuple[bool, dict]:
    unit_ok = _systemd_active("secubox-hub")
    return (unit_ok, {"systemd_active": unit_ok})


def check_mitmproxy_lxc() -> tuple[bool, dict]:
    running = _lxc_running("mitmproxy")
    return (running, {"lxc_state": "RUNNING" if running else "STOPPED"})


def check_gitea_lxc() -> tuple[bool, dict]:
    running = _lxc_running("gitea")
    http_ok = False
    if running:
        http_ok = _tcp_open("10.100.0.40", 3000, timeout=2.0)
    return (running and http_ok, {
        "lxc_state": "RUNNING" if running else "STOPPED",
        "http_3000_open": http_ok,
    })


def check_mail_lxc() -> tuple[bool, dict]:
    running = _lxc_running("mail")
    if not running:
        return False, {"lxc_state": "STOPPED"}
    ports = {p: _tcp_open("10.100.0.10", p, timeout=2.0)
             for p in (25, 465, 587, 993)}
    ok = running and all(ports.values())
    return ok, {"lxc_state": "RUNNING", "ports": ports}


def check_cookie_audit_ledger() -> tuple[bool, dict]:
    """Ledger should have been touched in the last 2h if traffic exists."""
    path = "/data/lxc/mitmproxy/rootfs/var/log/secubox/cookie-audit/server.jsonl"
    age = _file_mtime_age(path)
    if age is None:
        return False, {"ledger": path, "exists": False}
    fresh = age < 7200
    return fresh, {"ledger": path, "age_seconds": int(age), "fresh": fresh}


def check_filesystems() -> tuple[bool, dict]:
    """Critical paths must be mounted read-write."""
    paths = ["/var/log", "/var/cache", "/var/lib/secubox", "/data"]
    detail = {}
    ok_all = True
    for p in paths:
        try:
            stat = Path(p).stat()
            writable = (stat.st_mode & 0o200) != 0
            detail[p] = {"exists": True, "writable_bit": bool(writable)}
        except OSError as e:
            detail[p] = {"exists": False, "error": str(e)}
            ok_all = False
    return ok_all, detail


def check_act_runner_arm64() -> tuple[bool, dict]:
    """Optional — only flag if the LXC exists but isn't running."""
    name = "act-runner-ci-arm64"
    exists = Path(f"/data/lxc/{name}/rootfs").is_dir()
    if not exists:
        return True, {"present": False, "skipped": True}
    running = _lxc_running(name)
    return running, {"present": True, "lxc_state": "RUNNING" if running else "STOPPED"}


# ── Registry ──────────────────────────────────────────────────────────────

# Vital — every entry here counts toward the "failing" tally in the doctor
# summary. Keep this list strict: only services whose absence makes the
# board itself unusable. CI runners, optional capacity probes, etc. should
# go in REGISTRY_INFORMATIONAL once that tier is forged (#214 followup).
REGISTRY: Dict[str, CheckFn] = {
    "haproxy":             check_haproxy,
    "nginx":               check_nginx,
    "secubox-metrics":     check_secubox_metrics,
    "secubox-hub":         check_secubox_hub,
    "mitmproxy-lxc":       check_mitmproxy_lxc,
    "gitea-lxc":           check_gitea_lxc,
    "mail-lxc":            check_mail_lxc,
    "cookie-audit-ledger": check_cookie_audit_ledger,
    "filesystems":         check_filesystems,
}
# check_act_runner_arm64 kept as a module-level function (cheap) so a
# future REGISTRY_INFORMATIONAL tier can reuse it without duplication.
# Not vital — a stopped CI runner doesn't break the board (#214).
