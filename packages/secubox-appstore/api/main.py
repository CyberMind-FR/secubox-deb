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
from pydantic import BaseModel

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


# ── Mesh catalog — federated view over the annuaire directory (#768, phase 2) ──
# Every node holds the converged gondwana directory. We read it read-only (the
# journal is owned by `secubox`, our own user) and join each ServiceOffer to the
# publishing node's NodeRecord, so the appstore shows a fleet-wide catalog:
# which service is offered/emancipated, by which node, over which channel, and
# how to reach it. Graceful no-op when secubox-annuaire is not installed.

ANNUAIRE_LIB = "/usr/lib/secubox/annuaire"
ANNUAIRE_DB = os.environ.get("ANNUAIRE_DB_PATH", "/var/lib/secubox/annuaire/journal.db")


def _read_directory():
    import sys  # noqa: PLC0415
    if ANNUAIRE_LIB not in sys.path:
        sys.path.insert(0, ANNUAIRE_LIB)
    try:
        from annuaire.log import Journal  # noqa: PLC0415
        from annuaire.verbs import _get_nodes, _get_offers  # noqa: PLC0415
    except Exception:
        return [], {}
    if not os.path.exists(ANNUAIRE_DB):
        return [], {}
    try:
        j = Journal(ANNUAIRE_DB)
        return _get_offers(j), {n["did"]: n for n in _get_nodes(j)}
    except Exception:
        return [], {}


@app.get("/mesh-catalog")
async def mesh_catalog():
    offers, nodes = _read_directory()
    items = []
    for o in offers:
        prov = o.get("provider")
        node = nodes.get(prov, {})
        scope = o.get("scope") or {}
        items.append({
            "name": o.get("name"),
            "kind": o.get("kind"),
            "endpoint": o.get("endpoint"),
            "channel": scope.get("channel"),
            "port": scope.get("port"),
            "approval_mode": o.get("approval_mode"),
            "provider_did": prov,
            "provider_node": node.get("boxname") or "?",
            "provider_mesh_ip": node.get("mesh_ip"),
        })
    items.sort(key=lambda x: (x.get("provider_node") or "", x.get("name") or ""))
    return {
        "catalog": items,
        "nodes": [{"boxname": n.get("boxname"), "mesh_ip": n.get("mesh_ip"),
                   "ddns": n.get("ddns"), "did": n.get("did")} for n in nodes.values()],
        "count": len(items), "node_count": len(nodes),
    }


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


# ── Lifecycle + config (Phase B/C) ──────────────────────────────────────────
# The API runs as the unprivileged `secubox` user; all privileged work goes
# through the validated root helper /usr/sbin/secubox-appstorectl via a narrow
# sudoers rule (start/stop/restart/enable/disable + write-config only).
ACTIONS = {"start", "stop", "restart", "enable", "disable"}
APPSTORECTL = "/usr/sbin/secubox-appstorectl"


class ConfigIn(BaseModel):
    content: str


def _resolve(name: str, st: dict) -> str:
    if name in st:
        return name
    alt = f"secubox-{name}"
    if alt in st:
        return alt
    raise HTTPException(status_code=404, detail=f"unknown module {name!r}")


def _appstorectl(args, input_text=None):
    try:
        r = subprocess.run(["sudo", "-n", APPSTORECTL, *args], input=input_text,
                           capture_output=True, text=True, timeout=90)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def _config_path(name: str) -> Path:
    short = name[len("secubox-"):] if name.startswith("secubox-") else name
    return Path(f"/etc/secubox/{short}.toml")


@app.post("/module/{name}/action/{verb}")
async def module_action(name: str, verb: str):
    name = _resolve(name, compute_state())
    if verb not in ACTIONS:
        raise HTTPException(status_code=400, detail=f"unknown action {verb!r}")
    rc, out, err = _appstorectl([verb, name])
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"{verb} failed: {err or out}")
    new = compute_state(force=True).get(name, {})
    return {"status": "ok", "action": verb, "module": name,
            "state": new.get("state"), "running": new.get("running"), "message": out}


@app.get("/module/{name}/config")
async def get_config(name: str):
    name = _resolve(name, compute_state())
    p = _config_path(name)
    try:
        return {"module": name, "path": str(p), "exists": True,
                "readable": True, "content": p.read_text(encoding="utf-8")}
    except FileNotFoundError:
        return {"module": name, "path": str(p), "exists": False, "readable": True, "content": ""}
    except PermissionError:
        return {"module": name, "path": str(p), "exists": True, "readable": False, "content": ""}


@app.put("/module/{name}/config")
async def put_config(name: str, body: ConfigIn):
    name = _resolve(name, compute_state())
    rc, out, err = _appstorectl(["write-config", name], input_text=body.content)
    if rc != 0:
        raise HTTPException(status_code=400, detail=f"config write failed: {err or out}")
    return {"status": "ok", "module": name, "message": out}
