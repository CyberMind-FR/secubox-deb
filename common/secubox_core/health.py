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
                module="crowdsec",
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
                "engine_running": pgrep("crowdsec"),
                "lapi_ok": lapi_reachable(),
                "config_valid": validate_config(),
            }
            return health_from_checks(
                module="crowdsec",
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
    "crowdsec": {"version": "2.0.0", "dev_stage": "production"},
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

def parse_units(text: str, sleepable: FrozenSet[str] = frozenset()) -> Dict[str, dict]:
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
      - mod_id in sleepable                 -> ok / "Asleep (on-demand)"
      - else                                -> warn / "<active>/<sub>"
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
        if active == "active" and sub == "running":
            modules[mod_id] = {"status": "ok", "msg": "Running"}
        elif active == "active":
            modules[mod_id] = {"status": "warn", "msg": f"Active ({sub})"}
        elif active == "failed":
            modules[mod_id] = {"status": "error", "msg": "Failed"}
        elif mod_id in sleepable:
            modules[mod_id] = {"status": "ok", "msg": "Asleep (on-demand)"}
        else:
            modules[mod_id] = {"status": "warn", "msg": f"{active}/{sub}"}
    return modules


def systemd_batch(
    sock_dir: str = "/run/secubox",
    sleepable: FrozenSet[str] = frozenset(),
    _run: Optional[Callable[[], str]] = None,
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

    modules = parse_units(text, sleepable)

    for sock in glob.glob(os.path.join(sock_dir, "*.sock")):
        mod_id = os.path.basename(sock)[:-len(".sock")]
        if mod_id not in modules:
            modules[mod_id] = {"status": "ok", "msg": "Socket active"}

    return modules
