# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: health-doctor checks (issue #212)

Each check function returns a (ok: bool, details: dict) tuple. Details is
serialized into the per-check JSON, journal events, and CLI output.
Checks must be defensive: any exception -> ok=False, details={"error": str(e)}.
"""
from __future__ import annotations

import http.client
import socket
import subprocess
import time
import tomllib
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


CGROUP = Path("/sys/fs/cgroup")
MODULES_D = Path("/etc/secubox/modules.d")
MAIL_TOML = Path("/etc/secubox/mail.toml")


def _lxc_running(name: str) -> bool:
    """Par le cgroup, lisible de tous (#3967) : la sonde tourne sous `secubox` et `lxc-info` y échoue toujours (verrou
    root), ce qui donnait « arrêté » pour un conteneur en service. `-1`, `-2`… : reliquat d'un démarrage précédent."""
    for d in [CGROUP / f"lxc.payload.{name}", *CGROUP.glob(f"lxc.payload.{name}-[0-9]*")]:
        try:
            if "populated 1" in (d / "cgroup.events").read_text():
                return True
        except OSError:
            continue
    return False


def _toml(chemin: Path) -> dict:
    try:
        return tomllib.loads(chemin.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _a_la_demande(module: str) -> bool:
    """Le module dort quand il ne sert pas : arrêté est alors son état normal."""
    return _toml(MODULES_D / f"{module}.toml").get("lifecycle") == "on-demand"


def _http_200(socket_unix: str, chemin: str, delai: float = 3.0) -> bool:
    conn = http.client.HTTPConnection("localhost", timeout=delai)
    conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.sock.settimeout(delai)
    try:
        conn.sock.connect(socket_unix)
        conn.request("GET", chemin)
        return conn.getresponse().status == 200
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()


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
    """Servi par son unité, ou par l'agrégateur (unité propre alors inactive, c'est voulu)."""
    unit_ok = _systemd_active("secubox-hub")
    agg_ok = not unit_ok and _http_200("/run/secubox/aggregator.sock", "/api/v1/hub/health")
    return (unit_ok or agg_ok, {"systemd_active": unit_ok, "par_agregateur": agg_ok})


def check_gitea_lxc() -> tuple[bool, dict]:
    running = _lxc_running("gitea")
    if not running and _a_la_demande("gitea"):
        return True, {"lxc_state": "STOPPED", "veille_normale": True}
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
        # Fenêtres planifiées (#3925) : entre deux, le conteneur dort. Normal seulement si la minuterie vit.
        fenetre = _toml(MAIL_TOML).get("fenetre")
        planifie = (isinstance(fenetre, dict) and fenetre.get("actif") is True
                    and _systemd_active("secubox-mail-fenetre.timer"))
        veille = planifie or _a_la_demande("mail")
        return veille, {"lxc_state": "STOPPED", "veille_normale": veille}
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


def _comptes_admin():
    """Règle partagée (secubox_core.comptes_admin) chargée par son chemin : le paquet tire FastAPI, la sonde tourne
    chaque minute."""
    import importlib.util
    paquet = importlib.util.find_spec("secubox_core")
    spec = importlib.util.spec_from_file_location(
        "health_doctor_comptes_admin", Path(list(paquet.submodule_search_locations)[0]) / "comptes_admin.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_comptes_admin(users: Path | None = None) -> tuple[bool, dict]:
    """Administrateur actif sans mot de passe (#3708). Un NOMBRE, jamais un nom : le relevé est lisible du LAN sans
    session (mode tableau de bord) et son cache est public."""
    try:
        r = _comptes_admin().resume(users)
    except (OSError, ImportError, AttributeError, TypeError) as e:
        return True, {"skipped": True, "error": type(e).__name__}      # secubox-core antérieur : rien à dire
    if not r["lisible"]:
        return True, {"skipped": True, "lisible": False}
    n = r["sans_mot_de_passe"]
    return n == 0, {"sans_mot_de_passe": n, **({"message": (
        f"{n} administrateur(s) actif(s) sans mot de passe : à configurer ou à désactiver "
        "(page Utilisateurs).")} if n else {})}


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

# Avertissements : montrés (page Santé, healthctl), jamais comptés parmi les services vitaux en échec.
REGISTRY_AVERTISSEMENTS: Dict[str, CheckFn] = {
    "comptes-admin":       check_comptes_admin,
}
