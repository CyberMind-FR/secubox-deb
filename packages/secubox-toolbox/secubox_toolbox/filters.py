# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox-Deb :: toolbox :: modular filter config (#566)
#
# Single source of truth for which mitm filters are active, toggled from
# the toolbox WebUI (GET/POST /admin/filters). The mitm addons
# (inject_banner, protective_mode, ad_ghost) read this at flow time with a
# short cache so toggles take effect within seconds — no restart.
from __future__ import annotations

import json
import os
import time
from typing import Dict

FILTERS_PATH = "/etc/secubox/toolbox/filters.json"

DEFAULTS: Dict = {
    "banner": True,                 # inject the R2/R3 transparency banner
    "protective": "spoof",          # off | alert | spoof  (tracker spoofer)
    "ad_ghost": True,               # R3+/R4 silent ad/banner/widget ghosting
    "ad_ghost_block": True,         # 204 known ad/tracker hosts (save bandwidth)
    "media_cache": False,           # #577 shared media proxy-cache (opt-in)
    "stream_inject": False,         # #620 stream loader inject (TTFB) — opt-in, phase 2
    "autolearn": True,              # #589 also block auto-learned bad hosts
    "ad_ghost_categories": {        # cosmetic ghost groups
        "ads": True,
        "consent_nag": True,
        "newsletter": True,
        "social_widgets": True,
    },
}

_VALID_PROTECTIVE = ("off", "alert", "spoof")

_cache: Dict = {}
_cache_ts: float = 0.0


def get_filters(force: bool = False) -> Dict:
    """Merged filter config (defaults + on-disk overrides), 5 s cached."""
    global _cache, _cache_ts
    now = time.time()
    if not force and _cache and (now - _cache_ts) < 5:
        return _cache
    out = json.loads(json.dumps(DEFAULTS))  # deep copy
    try:
        with open(FILTERS_PATH, "r", encoding="utf-8") as f:
            disk = json.load(f)
        if isinstance(disk, dict):
            for k, v in disk.items():
                if k == "ad_ghost_categories" and isinstance(v, dict):
                    out["ad_ghost_categories"].update(v)
                elif k in out:
                    out[k] = v
    except Exception:
        pass
    if out.get("protective") not in _VALID_PROTECTIVE:
        out["protective"] = DEFAULTS["protective"]
    _cache = out
    _cache_ts = now
    return out


def set_filters(patch: Dict) -> Dict:
    """Merge a partial patch into the on-disk config and return the result.
    Only known keys are accepted (defensive)."""
    global _cache_ts
    cur = get_filters(force=True)
    for k, v in (patch or {}).items():
        if k == "ad_ghost_categories" and isinstance(v, dict):
            cur["ad_ghost_categories"].update(
                {ck: bool(cv) for ck, cv in v.items()
                 if ck in DEFAULTS["ad_ghost_categories"]})
        elif k == "protective" and v in _VALID_PROTECTIVE:
            cur["protective"] = v
        elif k in ("banner", "ad_ghost", "ad_ghost_block", "media_cache", "autolearn"):
            cur[k] = bool(v)
    try:
        os.makedirs(os.path.dirname(FILTERS_PATH), exist_ok=True)
        tmp = FILTERS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cur, f, indent=1)
        os.replace(tmp, FILTERS_PATH)
    except Exception:
        pass
    _cache_ts = 0.0  # invalidate
    return cur
