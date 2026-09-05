# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""WAF router — Rule category management."""
import json
from pathlib import Path
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("mitmproxy.waf")

RULES_FILE = Path("/data/mitmproxy-waf/data/waf-rules.json")
DEFAULT_RULES = Path("/usr/share/secubox/mitmproxy/data/waf-rules.json")


class RuleCategory(BaseModel):
    name: str
    enabled: bool
    severity: str
    pattern_count: int
    hits: int = 0


class RulesResponse(BaseModel):
    categories: List[RuleCategory]


class RuleStatsResponse(BaseModel):
    stats: Dict[str, int]


class ToggleRequest(BaseModel):
    category: str
    enabled: bool


class ActionResponse(BaseModel):
    success: bool
    message: str


def _load_rules() -> dict:
    """Load WAF rules from file."""
    if RULES_FILE.exists():
        return json.loads(RULES_FILE.read_text())
    elif DEFAULT_RULES.exists():
        return json.loads(DEFAULT_RULES.read_text())
    return {}


def _save_rules(rules: dict) -> None:
    """Save WAF rules to file."""
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(json.dumps(rules, indent=2))


def _load_stats() -> dict:
    """Load detection stats."""
    stats_file = RULES_FILE.parent / "stats.json"
    if stats_file.exists():
        try:
            return json.loads(stats_file.read_text())
        except Exception:
            pass
    return {}


@router.get("/rules", response_model=RulesResponse)
async def get_rules(user=Depends(require_jwt)):
    """Get all WAF rule categories."""
    rules = _load_rules()
    stats = _load_stats()

    categories = []
    for name, config in rules.items():
        categories.append(RuleCategory(
            name=name,
            enabled=config.get("enabled", True),
            severity=config.get("severity", "medium"),
            pattern_count=len(config.get("patterns", [])),
            hits=stats.get(name, 0)
        ))

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    categories.sort(key=lambda x: severity_order.get(x.severity, 99))

    return RulesResponse(categories=categories)


@router.post("/rules/toggle", response_model=ActionResponse)
async def toggle_rule(req: ToggleRequest, user=Depends(require_jwt)):
    """Enable or disable a rule category."""
    rules = _load_rules()

    if req.category not in rules:
        raise HTTPException(404, f"Category not found: {req.category}")

    rules[req.category]["enabled"] = req.enabled
    _save_rules(rules)

    action = "enabled" if req.enabled else "disabled"
    log.info(f"WAF category {req.category} {action}")

    return ActionResponse(success=True, message=f"Category {req.category} {action}")


@router.get("/rules/stats", response_model=RuleStatsResponse)
async def get_rule_stats(user=Depends(require_jwt)):
    """Get per-category detection statistics."""
    return RuleStatsResponse(stats=_load_stats())


# ── Phase 7.A/B (#498) : enforcement & threats dashboard ──────────────


class EnforcementResponse(BaseModel):
    """Phase 7.A : bridge / drop counters + recent bans / recent honeypot hits."""
    bridge_enabled: bool
    bans_pushed: int
    bans_failed: int
    requests: int
    blocked: int
    warnings: int
    rate_limit_offenders: int = 0
    honeypot_hits_last_hour: int = 0
    recent_bans: list = []
    recent_threats: list = []


def _read_lines_tail(path: Path, n: int) -> list:
    """Read last N lines from a log file (cheap, no need for tac/tail)."""
    if not path.exists():
        return []
    try:
        with path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, 64 * 1024)
            f.seek(max(0, size - chunk))
            return f.read().decode("utf-8", errors="ignore").splitlines()[-n:]
    except Exception:
        return []


@router.get("/enforcement", response_model=EnforcementResponse)
async def get_enforcement(user=Depends(require_jwt)):
    """Phase 7.A/B (#498) — surface bridge + honeypot + rate-limit state.

    Reads :
      - /data/mitmproxy-waf/logs/waf-stats.json   (WAF counters incl. bans_pushed)
      - /data/mitmproxy/data/threats.log           (recent threats)
      - /var/log/nginx/honeypot.log                (honeypot hits last hour)
      - nft set ip secubox_waf_ratelimit.offenders_v4 (live offender count)

    Designed for the admin webui Threats tab. Auto-refresh client-side.
    """
    import subprocess
    import time

    stats_file = Path("/data/mitmproxy-waf/logs/waf-stats.json")
    stats = {}
    if stats_file.exists():
        try:
            stats = json.loads(stats_file.read_text())
        except Exception:
            pass

    # No external ban bridge is configured.
    bridge_enabled = False

    # Recent threats (last 20)
    threats_log = Path("/data/mitmproxy/data/threats.log")
    recent_threats = []
    for line in _read_lines_tail(threats_log, 20):
        try:
            recent_threats.append(json.loads(line))
        except Exception:
            pass

    # No external ban backend is configured.
    recent_bans = []

    # Live rate-limit offender count
    rate_limit_offenders = 0
    try:
        out = subprocess.run(
            ["nft", "-j", "list", "set", "inet", "secubox_waf_ratelimit", "offenders_v4"],
            capture_output=True, text=True, timeout=2,
        ).stdout
        data = json.loads(out or "{}")
        for item in data.get("nftables", []):
            elem = item.get("set", {}).get("elem", [])
            rate_limit_offenders = len(elem) if isinstance(elem, list) else 0
            break
    except Exception:
        pass

    # Honeypot hits last hour (count lines whose timestamp is within last 3600s)
    honeypot_hits = 0
    hp_log = Path("/var/log/nginx/honeypot.log")
    if hp_log.exists():
        try:
            cutoff = time.time() - 3600
            for line in _read_lines_tail(hp_log, 5000):
                # log_format starts with $time_iso8601 — first 25 chars
                ts_str = line[:25]
                try:
                    from datetime import datetime as _dt
                    ts = _dt.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
                    if ts > cutoff:
                        honeypot_hits += 1
                except Exception:
                    pass
        except Exception:
            pass

    return EnforcementResponse(
        bridge_enabled=bridge_enabled,
        bans_pushed=stats.get("bans_pushed", 0),
        bans_failed=stats.get("bans_failed", 0),
        requests=stats.get("requests", 0),
        blocked=stats.get("blocked", 0),
        warnings=stats.get("warnings", 0),
        rate_limit_offenders=rate_limit_offenders,
        honeypot_hits_last_hour=honeypot_hits,
        recent_bans=recent_bans,
        recent_threats=recent_threats,
    )
