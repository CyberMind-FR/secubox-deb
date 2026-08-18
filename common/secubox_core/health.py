# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
secubox_core.health — Standardized Health Response for SecuBox Modules
======================================================================
Navbar-compliant health responses with status, version, dev_stage.
"""
from enum import Enum
from typing import Optional, Dict, Any
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
