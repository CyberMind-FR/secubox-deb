# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""ToolBoX rule engine (#492) : generative whitelist + dynamic filtering sensitivity.

Replaces the static whitelist.py with a 3-layer system :

  1. STATIC rules   : operator-edited YAML patterns (whitelist-baseline.yaml
                      + /etc/secubox/toolbox/whitelist.yaml)
  2. GENERATIVE     : auto-learned rules at runtime :
                      - persistent cert-pinning failures -> auto-whitelist
                      - HSTS preload list match -> trust
                      - high-reputation ASN + valid CT log -> soft trust
  3. SENSITIVITY    : filtering profile that gates active blocking decisions :
                      low / medium / high / paranoid

Stored in :
  /etc/secubox/toolbox/rule-engine.yaml          : sensitivity profile + custom rules
  /var/lib/secubox/toolbox/learned-rules.json    : runtime-learned trust list

The engine exposes :
  evaluate(host, context) -> {action, reason, source}
    action  = "trust" | "trust-warn" | "inspect" | "block"
    source  = "static" | "generative" | "default"

Used by :
  - mitmproxy addons before deciding to MITM
  - local_store.py to tag analysis_status
  - aggregator to produce the inspection breakdown
"""
from __future__ import annotations

import fnmatch
import json
import logging
import re
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("secubox.rule_engine")

# Configurable paths
BASELINE_PATH = Path("/usr/share/secubox/toolbox/whitelist-baseline.yaml")
OVERRIDE_PATH = Path("/etc/secubox/toolbox/whitelist.yaml")
RULES_PATH = Path("/etc/secubox/toolbox/rule-engine.yaml")
LEARNED_PATH = Path("/var/lib/secubox/toolbox/learned-rules.json")

# Cache
_CACHE: dict | None = None
_CACHE_MTIME: float = 0.0
_LEARNED_CACHE: dict | None = None
_LEARNED_CACHE_MTIME: float = 0.0


# ────────── Sensitivity profiles ──────────

SENSITIVITY_PROFILES = {
    "low": {
        "label": "🟢 Permissif",
        "description": "Bloque seulement le malware confirmé. Aucun faux positif.",
        "threat_intel_action": "block",     # block iff match in feeds
        "dga_score_min": 90,                # block iff DGA confidence ≥ 90
        "beaconing_score_min": 100,         # never block on beacon alone
        "block_unknown": False,
    },
    "medium": {
        "label": "🟡 Équilibré (défaut)",
        "description": "Bloque malware + DGA fort + beaconing évident.",
        "threat_intel_action": "block",
        "dga_score_min": 70,
        "beaconing_score_min": 75,
        "block_unknown": False,
    },
    "high": {
        "label": "🟠 Strict",
        "description": "Bloque malware + DGA + beaconing + ASN faible réputation.",
        "threat_intel_action": "block",
        "dga_score_min": 50,
        "beaconing_score_min": 50,
        "block_unknown": False,
        "block_low_reputation_asn": True,
    },
    "paranoid": {
        "label": "🔴 Paranoïaque",
        "description": "Bloque TOUT sauf si whitelisté (static OU généré).",
        "threat_intel_action": "block",
        "dga_score_min": 30,
        "beaconing_score_min": 30,
        "block_unknown": True,                # default-deny
    },
}


# ────────── Generative rules ──────────

# Predicate functions for generative rules. Each takes (host, context) and
# returns True if the rule matches.

def _is_french_gov(host: str, ctx: dict) -> bool:
    """*.gouv.fr or *.service-public.fr : French gov, never MITM."""
    return host.endswith(".gouv.fr") or host == "service-public.fr"


def _is_french_health(host: str, ctx: dict) -> bool:
    """*.fr health domains (CNAM/CPAM/ANS)."""
    return any(host.endswith(s) for s in (
        ".ameli.fr", ".cnam.fr", ".cpam.fr", ".ars.sante.fr",
        ".dossier-medical.fr", ".sesam-vitale.fr",
    ))


def _is_persistent_pinning(host: str, ctx: dict) -> bool:
    """Auto-learn : if we observed ≥3 cert-pinning failures, assume legit."""
    pinning_count = ctx.get("pinning_history", {}).get(host, 0)
    return pinning_count >= 3


def _is_high_reputation_asn(host: str, ctx: dict) -> bool:
    """ASN is in our high-reputation set (Cloudflare, Akamai, Google, etc.)."""
    high_rep_asns = {
        13335,  # Cloudflare
        16509,  # Amazon
        15169,  # Google
        20940,  # Akamai
        32934,  # Facebook
        2906,   # Netflix
        46489,  # Twitch
        13414,  # Twitter
        714,    # Apple
        16276,  # OVH
    }
    asn = ctx.get("asn")
    return asn in high_rep_asns if asn else False


GENERATIVE_RULES = [
    {
        "name": "gov-fr",
        "predicate": _is_french_gov,
        "action": "trust",
        "reason": "French gov ccTLD (*.gouv.fr / service-public.fr)",
        "category": "government-auto",
    },
    {
        "name": "health-fr",
        "predicate": _is_french_health,
        "action": "trust",
        "reason": "French healthcare infrastructure",
        "category": "health-auto",
    },
    {
        "name": "persistent-pinning",
        "predicate": _is_persistent_pinning,
        "action": "trust-warn",
        "reason": "Cert-pinning observed ≥3 times — auto-learned trust",
        "category": "learned-cert-pinned",
    },
    {
        "name": "high-rep-asn",
        "predicate": _is_high_reputation_asn,
        "action": "trust-warn",
        "reason": "Hosted by high-reputation infrastructure provider",
        "category": "infrastructure-auto",
    },
]


# ────────── Static rules (YAML) ──────────

def _load_yaml(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        import yaml as _yaml
    except ImportError:
        log.warning("PyYAML unavailable")
        return []
    try:
        data = _yaml.safe_load(path.read_text()) or {}
        return data.get("whitelist", []) or []
    except Exception as e:
        log.warning("yaml load failed (%s): %s", path, e)
        return []


def _load_engine_config() -> dict:
    """Load /etc/secubox/toolbox/rule-engine.yaml — sensitivity + custom rules."""
    if not RULES_PATH.exists():
        return {"sensitivity": "medium"}
    try:
        import yaml as _yaml
        return _yaml.safe_load(RULES_PATH.read_text()) or {"sensitivity": "medium"}
    except Exception as e:
        log.warning("rule-engine config load failed: %s", e)
        return {"sensitivity": "medium"}


def _load_learned() -> dict:
    """Load runtime-learned rules from disk."""
    global _LEARNED_CACHE, _LEARNED_CACHE_MTIME
    if not LEARNED_PATH.exists():
        return {"hosts": {}, "pinning_history": {}}
    try:
        m = LEARNED_PATH.stat().st_mtime
        if _LEARNED_CACHE is not None and m <= _LEARNED_CACHE_MTIME:
            return _LEARNED_CACHE
        _LEARNED_CACHE = json.loads(LEARNED_PATH.read_text())
        _LEARNED_CACHE_MTIME = m
        return _LEARNED_CACHE
    except Exception as e:
        log.warning("learned rules load failed: %s", e)
        return {"hosts": {}, "pinning_history": {}}


def record_pinning_failure(host: str) -> int:
    """Auto-learn : called by mitm addons when a cert-pinning failure is detected.

    Increments the host's pinning counter. Once ≥3, the host gets generatively
    whitelisted on the next evaluate() call.
    Returns the new count.
    """
    learned = _load_learned()
    learned.setdefault("pinning_history", {})
    learned["pinning_history"][host] = learned["pinning_history"].get(host, 0) + 1
    learned.setdefault("hosts", {})[host] = {
        "last_seen": int(time.time()),
        "source": "auto-pinning-detected",
    }
    try:
        LEARNED_PATH.parent.mkdir(parents=True, exist_ok=True)
        LEARNED_PATH.write_text(json.dumps(learned, indent=2)[:200000])
        # Bust the cache
        global _LEARNED_CACHE_MTIME
        _LEARNED_CACHE_MTIME = 0.0
    except Exception as e:
        log.warning("learned rules persist failed: %s", e)
    return learned["pinning_history"][host]


def _refresh_static_cache() -> dict:
    """Reload static whitelist YAML if mtime changed."""
    global _CACHE, _CACHE_MTIME
    mtime = 0.0
    for p in (BASELINE_PATH, OVERRIDE_PATH, RULES_PATH):
        if p.exists():
            mtime = max(mtime, p.stat().st_mtime)
    if _CACHE is not None and mtime <= _CACHE_MTIME:
        return _CACHE
    entries = _load_yaml(BASELINE_PATH) + _load_yaml(OVERRIDE_PATH)
    # Also load custom rules from engine config
    cfg = _load_engine_config()
    for e in cfg.get("static_rules") or []:
        entries.append(e)
    compiled: dict[str, dict] = {}
    for e in entries:
        p = e.get("pattern", "").lower().strip()
        if p:
            compiled[p] = e
    _CACHE = {
        "entries": compiled,
        "count": len(compiled),
        "sensitivity": (cfg.get("sensitivity") or "medium").lower(),
    }
    _CACHE_MTIME = mtime
    log.info("rule-engine reloaded : %d static rules, sensitivity=%s",
             len(compiled), _CACHE["sensitivity"])
    return _CACHE


# ────────── Public API ──────────

def evaluate(host: str, context: Optional[dict] = None) -> dict:
    """Decide what to do with a host. Order :
      1. Static whitelist match -> trust
      2. Generative rule match -> trust / trust-warn
      3. Default -> inspect

    Returns {action, reason, source, category}.
    """
    if not host:
        return {"action": "inspect", "reason": "no host", "source": "default", "category": None}
    h = host.lower().strip()
    ctx = context or {}

    # 1. Static rules
    cache = _refresh_static_cache()
    for pattern, entry in cache["entries"].items():
        if fnmatch.fnmatch(h, pattern):
            return {
                "action": "trust",
                "reason": entry.get("reason", "whitelisted"),
                "source": "static",
                "category": entry.get("category"),
                "quality_expected": entry.get("quality_expected", "?"),
            }

    # 2. Generative rules — inject pinning history from learned store
    learned = _load_learned()
    enriched_ctx = {**ctx, "pinning_history": learned.get("pinning_history", {})}
    for rule in GENERATIVE_RULES:
        try:
            if rule["predicate"](h, enriched_ctx):
                return {
                    "action": rule["action"],
                    "reason": rule["reason"],
                    "source": "generative",
                    "category": rule["category"],
                    "rule_name": rule["name"],
                }
        except Exception as e:
            log.debug("generative rule %s eval failed: %s", rule["name"], e)

    # 3. Default : inspect
    return {"action": "inspect", "reason": "no rule matched", "source": "default", "category": None}


def get_sensitivity() -> dict:
    """Returns the active sensitivity profile dict (label/description/thresholds)."""
    cache = _refresh_static_cache()
    profile_name = cache.get("sensitivity", "medium")
    return {
        "name": profile_name,
        **SENSITIVITY_PROFILES.get(profile_name, SENSITIVITY_PROFILES["medium"]),
    }


def should_block(*, threat_intel_matches: int = 0, dga_score: int = 0,
                 beaconing_score: int = 0, asn_reputation: str | None = None,
                 is_whitelisted: bool = False) -> tuple[bool, str]:
    """Given signal values + active sensitivity, decide whether to block.

    Returns (block_decision, reason).
    """
    profile = get_sensitivity()
    if is_whitelisted:
        return False, "whitelisted (rule_engine)"
    if profile.get("threat_intel_action") == "block" and threat_intel_matches > 0:
        return True, f"threat-intel match (sensitivity={profile['name']})"
    if dga_score >= profile.get("dga_score_min", 999):
        return True, f"DGA score {dga_score} ≥ threshold {profile['dga_score_min']}"
    if beaconing_score >= profile.get("beaconing_score_min", 999):
        return True, f"beaconing score {beaconing_score} ≥ threshold {profile['beaconing_score_min']}"
    if profile.get("block_low_reputation_asn") and asn_reputation in ("D", "F"):
        return True, f"low-reputation ASN ({asn_reputation})"
    if profile.get("block_unknown"):
        return True, "paranoid mode : default-deny"
    return False, "no rule matched"


def stats() -> dict:
    """Returns engine stats : static rule count + sensitivity + learned count."""
    cache = _refresh_static_cache()
    learned = _load_learned()
    return {
        "static_rules": cache["count"],
        "sensitivity": cache.get("sensitivity", "medium"),
        "sensitivity_profile": get_sensitivity(),
        "generative_rules": len(GENERATIVE_RULES),
        "learned_hosts": len(learned.get("hosts", {})),
        "learned_pinning_count": sum(learned.get("pinning_history", {}).values()),
        "baseline_loaded": BASELINE_PATH.exists(),
        "override_loaded": OVERRIDE_PATH.exists(),
        "engine_config_loaded": RULES_PATH.exists(),
    }


# Backward-compatibility shim for callers still using whitelist.match/is_whitelisted
def match(host: str) -> dict | None:
    """Returns the matching rule dict for compat with whitelist.py. None if no
    trust decision."""
    result = evaluate(host)
    if result["action"] in ("trust", "trust-warn"):
        return {
            "pattern": host,
            "reason": result["reason"],
            "category": result.get("category"),
            "quality_expected": result.get("quality_expected", "?"),
            "source": result["source"],
        }
    return None


def is_whitelisted(host: str) -> bool:
    return match(host) is not None
