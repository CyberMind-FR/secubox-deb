# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
secubox_core.health — Standardized Health Response for SecuBox Modules
======================================================================
Navbar-compliant health responses with status, version, dev_stage.

Also hosts systemd_batch()/parse_units() — the shared "one systemctl
list-units call → per-module {status,msg}" helper ported verbatim from
secubox-hub's _refresh_health_batch() (ref #1175), so every module can
build its sidebar/health-batch snapshot the same way instead of
reimplementing the systemctl parsing loop.
"""
import glob
import os
import subprocess
from enum import Enum
from typing import Callable, FrozenSet, Optional, Dict, Any
from pydantic import BaseModel


class WorkingStatus(str, Enum):
    """Working status for health checks."""
    ok = "ok"
    degraded = "degraded"
    error = "error"


class EnabledStatus(str, Enum):
    """Enabled/disabled status."""
    enabled = "enabled"
    disabled = "disabled"


class DevStage(str, Enum):
    """Development stage for module maturity."""
    alpha = "alpha"
    beta = "beta"
    production = "production"


class HealthResponse(BaseModel):
    """
    Standard health response for all SecuBox modules.

    This format is consumed by the navbar/sidebar to display:
    - Status LED (green/yellow/red)
    - Version badge
    - Development stage indicator (α/β)
    """
    status: WorkingStatus
    module: str
    version: str
    enabled: EnabledStatus = EnabledStatus.enabled
    dev_stage: DevStage = DevStage.production
    message: Optional[str] = None
    checks: Optional[Dict[str, Any]] = None

    class Config:
        use_enum_values = True


def make_health_response(
    module: str,
    version: str,
    status: WorkingStatus = WorkingStatus.ok,
    enabled: EnabledStatus = EnabledStatus.enabled,
    dev_stage: DevStage = DevStage.production,
    message: Optional[str] = None,
    checks: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    Quick helper to create a standard health response.

    Usage:
        @app.get("/health")
        async def health():
            return make_health_response(
                module="waf",
                version="1.2.0",
                dev_stage=DevStage.production
            )
    """
    return HealthResponse(
        status=status,
        module=module,
        version=version,
        enabled=enabled,
        dev_stage=dev_stage,
        message=message,
        checks=checks,
    ).model_dump(exclude_none=True)


def health_from_checks(
    module: str,
    version: str,
    checks: Dict[str, bool],
    critical_checks: Optional[list] = None,
    dev_stage: DevStage = DevStage.production,
) -> dict:
    """
    Create health response from a dict of check results.

    Args:
        module: Module name
        version: Module version
        checks: Dict of check_name -> bool (True = pass)
        critical_checks: List of check names that cause 'error' if failed
        dev_stage: Development stage

    Returns:
        Standard health response with computed status

    Usage:
        @app.get("/health")
        async def health():
            checks = {
                "engine_running": pgrep("sbxwaf"),
                "lapi_ok": lapi_reachable(),
                "config_valid": validate_config(),
            }
            return health_from_checks(
                module="waf",
                version="2.0.0",
                checks=checks,
                critical_checks=["engine_running"]
            )
    """
    critical_checks = critical_checks or []

    # Determine status based on check results
    all_pass = all(checks.values())
    critical_fail = any(
        not checks.get(c, True) for c in critical_checks
    )

    if critical_fail:
        status = WorkingStatus.error
    elif all_pass:
        status = WorkingStatus.ok
    else:
        status = WorkingStatus.degraded

    # Generate message
    failed = [k for k, v in checks.items() if not v]
    message = None
    if failed:
        message = f"Failed: {', '.join(failed)}"

    return make_health_response(
        module=module,
        version=version,
        status=status,
        dev_stage=dev_stage,
        message=message,
        checks=checks,
    )


# Module metadata registry (can be extended at runtime)
MODULE_METADATA: Dict[str, Dict[str, Any]] = {
    # Core modules
    "hub": {"version": "1.7.0", "dev_stage": "production"},
    "waf": {"version": "1.2.0", "dev_stage": "production"},
    "haproxy": {"version": "1.1.0", "dev_stage": "production"},
    "wireguard": {"version": "2.0.0", "dev_stage": "production"},
    "vhost": {"version": "1.1.0", "dev_stage": "production"},
    "dns": {"version": "2.0.0", "dev_stage": "production"},
    "system": {"version": "1.2.0", "dev_stage": "production"},
    "metrics": {"version": "1.0.0", "dev_stage": "beta"},
    "ai-gateway": {"version": "1.0.0", "dev_stage": "beta"},
    "ai-insights": {"version": "1.0.0", "dev_stage": "beta"},
    "mcp-server": {"version": "1.0.0", "dev_stage": "alpha"},
    # Add more as needed
}


def get_module_metadata(module: str) -> Dict[str, Any]:
    """Get metadata for a module, with defaults."""
    return MODULE_METADATA.get(module, {
        "version": "1.0.0",
        "dev_stage": "production"
    })


# ══════════════════════════════════════════════════════════════════
# systemd_batch() — shared "one systemctl call → {id: {status,msg}}"
# helper. Ported verbatim from secubox-hub's _refresh_health_batch()
# (ref #1175); only the sleepable-modules read and any module-specific
# aliasing (e.g. the Hub's waf→waf-ng overlay) stay in the caller.
# ══════════════════════════════════════════════════════════════════

def parse_units(text: str, sleepable: FrozenSet[str] = frozenset(),
                au_repos: FrozenSet[str] = frozenset(),
                absents: FrozenSet[str] = frozenset()) -> Dict[str, dict]:
    """Parse `systemctl list-units --type=service ... --no-legend --plain
    secubox-*` plain-text output into `{mod_id: {"status", "msg"}}`.

    Only lines for `secubox-<id>.service` units with at least 4
    whitespace-separated fields (unit load active sub ...) are
    considered. Classification (identical to the former secubox-hub
    inline logic):
      - active=="active" and sub=="running" -> ok / "Running"
      - active=="active"                    -> warn / "Active (<sub>)"
      - active=="failed"                    -> error / "Failed"
        (a crash is a real alarm even for a sleepable module — intentional
        sleep goes through disable+stop i.e. inactive/dead, never failed)
      - mod_id in sleepable                 -> ok / "Asleep (on-demand)" + veille
      - mod_id in au_repos                  -> ok / "Au repos (tâche planifiée)" + veille
      - else                                -> warn / "<active>/<sub>"

    `veille: True` marque un état attendu, ni sain ni dégradé : la page Santé le
    compte à part et le score le pondère (#1893).
    """
    modules: Dict[str, dict] = {}
    for line in text.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        unit, _load, active, sub = parts[0], parts[1], parts[2], parts[3]
        if not (unit.startswith("secubox-") and unit.endswith(".service")):
            continue
        mod_id = unit[8:-8]
        if mod_id in absents and active != "active":
            continue                      # unité inexistante ou masquée : rien à surveiller
        if active == "active" and sub == "running":
            modules[mod_id] = {"status": "ok", "msg": "Running"}
        elif active == "active":
            modules[mod_id] = {"status": "warn", "msg": f"Active ({sub})"}
        elif active == "failed":
            modules[mod_id] = {"status": "error", "msg": "Failed"}
        elif mod_id in sleepable:
            modules[mod_id] = {"status": "ok", "msg": "Asleep (on-demand)", "veille": True}
        elif mod_id in au_repos:
            modules[mod_id] = {"status": "ok", "msg": "Au repos (tâche planifiée)", "veille": True}
        else:
            modules[mod_id] = {"status": "warn", "msg": f"{active}/{sub}"}
    return modules


def _blocs_show(show_text: str):
    for bloc in show_text.strip().split("\n\n"):
        props = dict(l.split("=", 1) for l in bloc.splitlines() if "=" in l)
        unite = props.get("Id", "")
        if unite.startswith("secubox-") and unite.endswith(".service"):
            yield unite[8:-8], props


def parse_au_repos(show_text: str) -> FrozenSet[str]:
    """Ids des unités « au repos » : arrêtées par conception, dernier passage réussi.

    `show_text` : `systemctl show <unités> -p Id,Type,Result,ActiveState,LoadState,TriggeredBy`
    (blocs séparés par une ligne vide). Une tâche planifiée — oneshot, ou déclenchée par un
    timer/path (TriggeredBy) — qui n'est pas en cours est NORMALEMENT inactive/dead ; seul un
    Result différent de « success » est une alerte.
    """
    repos = set()
    for mod, p in _blocs_show(show_text):
        if p.get("LoadState") != "loaded":
            continue
        if p.get("ActiveState") != "inactive" or p.get("Result", "success") != "success":
            continue
        if p.get("Type") == "oneshot" or p.get("TriggeredBy"):
            repos.add(mod)
    return frozenset(repos)


def parse_absents(show_text: str) -> FrozenSet[str]:
    """Ids des unités qui n'existent pas (not-found) ou sont masquées : rien à surveiller.

    systemd les garde dans `list-units --all` tant qu'une dépendance les cite ; elles
    s'affichaient « inactive/dead », donc dégradées, alors qu'aucun service n'est censé tourner.
    """
    return frozenset(mod for mod, p in _blocs_show(show_text)
                     if p.get("LoadState") in ("not-found", "masked"))


def unites_au_repos(noms=None) -> tuple:
    """Relevé réel : (au_repos, absents), un seul `systemctl show` sur des unités nommées.

    `noms` : ids de modules à interroger (par défaut, ceux de `list-units secubox-* --all`).
    Nommer les unités est nécessaire : un motif `secubox-*` n'atteint pas les unités arrêtées
    et déchargées de la mémoire. Jamais d'exception.
    """
    def _sortie(args):
        try:
            return subprocess.run(args, capture_output=True, text=True, timeout=10).stdout
        except Exception:
            return ""
    if noms is None:
        brut = _sortie(["systemctl", "list-units", "secubox-*", "--all", "--full",
                        "--no-legend", "--plain", "--no-pager"])
        noms = [l.split()[0][8:-8] for l in brut.splitlines()
                if l.split() and l.split()[0].startswith("secubox-") and l.split()[0].endswith(".service")]
    if not noms:
        return frozenset(), frozenset()
    show = _sortie(["systemctl", "show", "--no-pager", "-p", "Id,Type,Result,ActiveState,LoadState,TriggeredBy",
                    *[f"secubox-{n}.service" for n in noms]])
    return parse_au_repos(show), parse_absents(show)


def systemd_batch(
    sock_dir: str = "/run/secubox",
    sleepable: FrozenSet[str] = frozenset(),
    _run: Optional[Callable[[], str]] = None,
    au_repos: FrozenSet[str] = frozenset(),
    absents: FrozenSet[str] = frozenset(),
) -> Dict[str, dict]:
    """Build the `{mod_id: {"status", "msg"}}` health-batch snapshot in one
    systemctl call plus a socket-directory scan.

    `_run` is an injection point for tests (and any caller with its own
    subprocess wrapper) — when given, it is called with no arguments and
    must return the raw `systemctl list-units` stdout text. Otherwise the
    exact secubox-hub systemctl invocation is run (5s timeout); any
    failure (missing systemctl, timeout, ...) degrades to an empty text
    rather than raising, matching the former hub behaviour.

    Module ids found only via a `/run/secubox/<id>.sock` socket (no
    matching unit in the systemctl output) are added as
    `{"status": "ok", "msg": "Socket active"}` — but never override a
    module id already known from systemctl.
    """
    if _run is not None:
        text = _run()
    else:
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service",
                 "--state=running,failed,inactive", "--no-legend", "--plain",
                 "secubox-*"],
                capture_output=True, text=True, timeout=5,
            )
            text = result.stdout
        except Exception:
            text = ""

    modules = parse_units(text, sleepable, au_repos, absents)

    for sock in glob.glob(os.path.join(sock_dir, "*.sock")):
        mod_id = os.path.basename(sock)[:-len(".sock")]
        if mod_id not in modules:
            modules[mod_id] = {"status": "ok", "msg": "Socket active"}

    return modules
