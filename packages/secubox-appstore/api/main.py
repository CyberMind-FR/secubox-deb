# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: secubox-appstore :: catalog API (Phase A — read-only)

Serves a categorized, tiered, searchable catalog of SecuBox modules by
merging the baked manifest catalog (generated at build from every module's
debian/secubox.yaml) with live runtime state (dpkg installed/version +
systemctl active). Runs unprivileged (user `secubox`): all state queries are
read-only. Install/enable/prefs/profiles are later phases (a root worker).
"""
import os
import json
import time
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException

CATALOG_FILE = Path(os.environ.get(
    "APPSTORE_CATALOG", "/usr/share/secubox/appstore/catalog.json"))
TIER_RANK = {"all": 0, "lite": 1, "standard": 2, "pro": 3}
_STATE_TTL = 30.0
_state_cache = {"ts": 0.0, "data": {}}

app = FastAPI(title="secubox-appstore", version="0.1.0",
              root_path="/api/v1/appstore")


def board_tier() -> str:
    """Best-effort board tier; defaults to 'pro' (unlock all) when unset."""
    t = os.environ.get("SECUBOX_TIER")
    if t:
        return t.strip()
    try:
        for line in open("/etc/secubox/secubox.conf", encoding="utf-8"):
            s = line.strip()
            if s.lower().startswith("tier") and "=" in s:
                return s.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "pro"


def load_catalog() -> list:
    try:
        return json.loads(CATALOG_FILE.read_text(encoding="utf-8")).get("modules", [])
    except Exception:
        return []


def _dpkg_state() -> dict:
    out = {}
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\t${Version}\n", "secubox-*"],
            capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if len(p) >= 3:
                out[p[0]] = {"installed": p[1].strip().startswith("ii"), "version": p[2].strip()}
    except Exception:
        pass
    return out


def _svc_active(names: list) -> dict:
    out = {}
    if not names:
        return out
    try:
        units = [f"{n}.service" for n in names]
        r = subprocess.run(["systemctl", "is-active", *units],
                           capture_output=True, text=True, timeout=10)
        for n, st in zip(names, r.stdout.splitlines()):
            out[n] = (st.strip() == "active")
    except Exception:
        pass
    return out


def compute_state(force: bool = False) -> dict:
    now = time.time()
    if not force and _state_cache["data"] and (now - _state_cache["ts"] < _STATE_TTL):
        return _state_cache["data"]
    catalog = load_catalog()
    dpkg = _dpkg_state()
    installed_names = [m["name"] for m in catalog if dpkg.get(m["name"], {}).get("installed")]
    active = _svc_active(installed_names)
    brank = TIER_RANK.get(board_tier(), 2)
    result = {}
    for m in catalog:
        name = m["name"]
        d = dpkg.get(name, {})
        installed = bool(d.get("installed"))
        running = bool(active.get(name))
        tier = m.get("tier", "lite")
        tier_locked = (tier != "all") and (TIER_RANK.get(tier, 1) > brank)
        if not installed:
            state = "tier-locked" if tier_locked else "available"
        elif running:
            state = "running"
        else:
            state = "installed"
        result[name] = {
            **m,
            "installed": installed,
            "running": running,
            "version": d.get("version"),
            "tier_locked": tier_locked,
            "state": state,
        }
    _state_cache["ts"] = now
    _state_cache["data"] = result
    return result


@app.get("/health")
async def health():
    return {"ok": True, "module": "appstore",
            "catalog_count": len(load_catalog()), "board_tier": board_tier()}


@app.get("/categories")
async def categories():
    st = compute_state()
    cats: dict = {}
    for m in st.values():
        cats[m["category"]] = cats.get(m["category"], 0) + 1
    return {
        "categories": [{"name": k, "count": v} for k, v in sorted(cats.items())],
        "tiers": ["lite", "standard", "pro", "all"],
        "states": ["available", "installed", "running", "tier-locked"],
        "board_tier": board_tier(),
    }


@app.get("/catalog")
async def catalog(category: Optional[str] = None, tier: Optional[str] = None,
                  state: Optional[str] = None, q: Optional[str] = None):
    st = compute_state()
    items = list(st.values())
    if category:
        items = [m for m in items if m["category"] == category]
    if tier:
        items = [m for m in items if m["tier"] == tier]
    if state:
        items = [m for m in items if m["state"] == state]
    if q:
        ql = q.lower()
        items = [m for m in items
                 if ql in m["name"].lower() or ql in (m.get("description") or "").lower()]
    items.sort(key=lambda m: (m["category"], m["name"]))
    return {"modules": items, "count": len(items), "total": len(st), "board_tier": board_tier()}


@app.get("/module/{name}")
async def module(name: str):
    st = compute_state()
    if name not in st:
        alt = f"secubox-{name}"
        if alt in st:
            name = alt
        else:
            raise HTTPException(status_code=404, detail=f"unknown module {name!r}")
    return dict(st[name])
