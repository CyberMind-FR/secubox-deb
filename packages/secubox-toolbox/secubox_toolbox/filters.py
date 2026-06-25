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

FILTERS_PATH = os.environ.get(
    "SECUBOX_FILTERS_PATH", "/etc/secubox/toolbox/filters.json")

DEFAULTS: Dict = {
    "banner": True,                 # inject the R2/R3 transparency banner
    "ad_guard": True,               # #740 MASTER ad-block switch (orthogonal to R0-R4):
                                    # gates the R3 cosmetic + 204 host-block at once
    "protective": "spoof",          # off | alert | spoof  (tracker spoofer)
    "ad_ghost": True,               # R3+/R4 silent ad/banner/widget ghosting
    "ad_ghost_block": True,         # 204 known ad/tracker hosts (save bandwidth)
    "media_cache": False,           # #577 shared media proxy-cache (opt-in)
    "stream_inject": True,          # #620/#630 stream loader inject (TTFB) — default on
    "autolearn": True,              # #589 also block auto-learned bad hosts
    "ad_learn": True,               # #656 aggressive ad-URL learning toggle
    "tls_splice": "observe",        # #649 off | observe | on  (asset SNI-splice)
    # ── kbin Tor egress (#683) — ships dark; arm via reconciler after soak ──
    "tor_mode": False,              # route MITM upstream egress through Tor (global kbin Tor mode)
    "tor_preset": "anonymous",      # anonymous | stealth | minimal (secubox-tor preset)
    # ── Anti-Track v2 (#633) — ships dark; arm after observe-only soak ──
    "privacy_enforce": False,       # master switch; off = observe-only
    "privacy_poison": True,         # forge stable fake id for loadbearing trackers
    "privacy_anonymize": True,      # always-on header hygiene (DNT/GPC, strip op-hdrs)
    "privacy_ip_drop": False,       # nft-drop exclusive-tracker IPs (plan 2)
    "privacy_dns_feed": True,       # feed learned blacklist into dns-guard (plan 2)
    "fortknox_sites": [],           # per-site first-party-only opt-in
    "ad_ghost_categories": {        # cosmetic ghost groups
        "ads": True,
        "consent_nag": True,
        "newsletter": True,
        "social_widgets": True,
    },
}

_VALID_PROTECTIVE = ("off", "alert", "spoof")
_VALID_SPLICE = ("off", "observe", "on")
_VALID_TOR_PRESET = ("anonymous", "stealth", "minimal")

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
    if out.get("tls_splice") not in _VALID_SPLICE:
        out["tls_splice"] = DEFAULTS["tls_splice"]
    if out.get("tor_preset") not in _VALID_TOR_PRESET:
        out["tor_preset"] = DEFAULTS["tor_preset"]
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
        elif k == "tls_splice" and v in _VALID_SPLICE:
            cur["tls_splice"] = v
        elif k == "tor_preset" and v in _VALID_TOR_PRESET:
            cur["tor_preset"] = v
        elif k == "fortknox_sites" and isinstance(v, list):
            cur["fortknox_sites"] = [str(s).strip().lower() for s in v if str(s).strip()]
        elif k in ("banner", "ad_guard", "ad_ghost", "ad_ghost_block", "media_cache",
                   "autolearn", "privacy_enforce", "privacy_poison", "privacy_anonymize",
                   "privacy_ip_drop", "privacy_dns_feed", "ad_learn", "tor_mode"):
            cur[k] = bool(v)
    data = json.dumps(cur, indent=1)
    try:
        # Preferred: atomic tmp + rename (needs write on the parent dir).
        tmp = FILTERS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, FILTERS_PATH)
    except OSError:
        # The serving user often can't create a tmp here: the operator UI is
        # served by the aggregator (user `secubox`) and /etc/secubox/toolbox is
        # 0750 → no dir-write. Fall back to an in-place write, which needs only
        # file-write perm (filters.json is group-writable) AND reliably fires
        # the secubox-toolbox-tor.path watcher (in-place modify, not a rename).
        try:
            with open(FILTERS_PATH, "w", encoding="utf-8") as f:
                f.write(data)
        except Exception:
            pass
    except Exception:
        pass
    _cache_ts = 0.0  # invalidate
    return cur
