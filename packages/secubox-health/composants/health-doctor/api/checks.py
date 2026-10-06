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
    # Chemin HOTE (#1362). Il pointait dans le rootfs du LXC mitmproxy,
    # supprime : la sonde rapportait exists=False en permanence. Les sept
    # autres references du depot utilisent ce chemin-ci, ecrit par sbxmitm.
    path = "/var/log/secubox/cookie-audit/server.jsonl"
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


def check_waf_selftest() -> tuple[bool, dict]:
    """sbxwaf ecoute, laisse passer un temoin sain et refuse les charges canari."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "health_doctor_waf_selftest", Path(__file__).with_name("waf_selftest.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.verifier()


def check_clamav() -> tuple[bool, dict]:
    """Antivirus à la demande (#1912) : le LXC `clamav` peut DORMIR (c'est son état normal) ; ce qui
    compte est la base de signatures. Sans le paquet, rien à surveiller."""
    import json
    if not Path("/usr/sbin/clamavctl").exists():
        return True, {"present": False, "skipped": True}
    try:
        r = _run(["/usr/sbin/clamavctl", "status", "--json"], timeout=8)
        d = json.loads(r.stdout)
    except Exception as e:                                   # noqa: BLE001
        return False, {"error": f"{type(e).__name__}: {e}"}
    ok = bool(d.get("base_a_jour"))
    return ok, {"lxc": d.get("lxc"), "clamd": d.get("clamd"), "veille_normale": d.get("lxc") == "STOPPED",
                "base_age_jours": d.get("base_age_jours"), "base_a_jour": ok,
                "dernier_demarrage_s": d.get("dernier_demarrage_s")}


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
    # "mitmproxy-lxc" RETIRE (#1362) : le conteneur mitmproxy a ete supprime
    # avec le decommissionnement du WAF mitmproxy. La sonde rapportait donc
    # un echec PERMANENT — un voyant rouge qui ne designe rien n'apprend
    # plus rien et finit par masquer les vrais. L'inspection vit maintenant
    # dans sbxwaf (moteur Go, :8085), deja couvert par ses propres sondes.
    "gitea-lxc":           check_gitea_lxc,
    "mail-lxc":            check_mail_lxc,
    "cookie-audit-ledger": check_cookie_audit_ledger,
    "filesystems":         check_filesystems,
    # Preuve dynamique que sbxwaf BLOQUE (et ne bloque pas le trafic sain), pas
    # seulement que l'unite tourne : charges canari + temoin, toutes les 5 min.
    "waf-selftest":        check_waf_selftest,
    # Base de signatures de l'antivirus à la demande ; le LXC endormi est NORMAL, une base périmée non.
    "clamav":              check_clamav,
}
# check_act_runner_arm64 kept as a module-level function (cheap) so a
# future REGISTRY_INFORMATIONAL tier can reuse it without duplication.
# Not vital — a stopped CI runner doesn't break the board (#214).
