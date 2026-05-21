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
