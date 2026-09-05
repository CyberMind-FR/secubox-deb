<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WebOS P1 — Registre normalisé — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Livrer un module Debian `secubox-webos` (socket propre, indépendant de l'agrégateur) qui sert un registre de services normalisé, composé du catalogue existant (`menu.d`/menu cache du Hub) + santé + latence/reach, sans UI.

**Architecture:** FastAPI sur `/run/secubox/webos.sock` (uvicorn dédié, `User=secubox`), tâche de fond qui recompose un cache normalisé cache-first ; endpoints `GET /public/services` (minimal, sans JWT) et `GET /services` (détail, JWT). La jointure `id↔domaine` vient d'un champ `domain`/`same_origin` ajouté aux `menu.d` (repli gracieux). La santé vient d'un helper partagé `secubox_core.health` (factorisé du Hub, refacto neutre).

**Tech Stack:** Python 3.11, FastAPI, uvicorn, Pydantic, pytest ; packaging debhelper-compat 13 ; nginx unix-socket proxy.

**Spec:** `docs/superpowers/specs/2026-08-24-webos-hall-p1-registre-design.md` (et discovery `docs/superpowers/specs/2026-08-24-webos-hall-phase0-discovery.md`).

## Global Constraints

- **En-tête SPDX** en tête de CHAQUE fichier source (Python/Bash) : bloc `LicenseRef-CMSD-1.0` (voir `.claude/CLAUDE.md`).
- **Aucune UI, aucune cardlet, aucun shell Hall** en P1 (brief §20 réserve ça à P2+).
- **Indépendant de l'agrégateur** : uvicorn dédié sur `/run/secubox/webos.sock`, jamais servi in-process par l'agrégateur.
- **Cache-first strict** : jamais de sonde live ni de composition dans le chemin de requête ; l'endpoint lit un cache mémoire/fichier.
- **Pas de duplication** : la santé passe par `secubox_core.health.systemd_batch()` (un seul mécanisme, deux consommateurs) ; le catalogue vient du cache menu du Hub (`/var/cache/secubox/menu.json`), pas d'un parseur `menu.d` dupliqué.
- **Auth** : `from secubox_core.auth import require_jwt` ; `public_router = APIRouter(prefix="/public")` sans JWT ; `router` avec `Depends(require_jwt)`. Jamais de secret en clair/logs.
- **Public = minimal** (`id,name,category,icon,health.state,installed,active`) — jamais `urls`/`latency_ms`/`reach`/`capabilities` sans auth (anti-fuite d'inventaire).
- **Mapping santé** : `ok→online`, `warn→degraded`, `error→offline`, absent→`unknown`. Latence `null` si non mesurée (jamais inventée).
- **systemd** : `User=secubox` `Group=secubox` (comme les autres modules — PAS d'utilisateur dédié en P1 : évite les 502 de propriété sur `/run/secubox` partagé) ; **pas de `RuntimeDirectory=secubox`** (efface les sockets des ~95 autres unités) ; `ExecStartPre=+/bin/rm -f /run/secubox/webos.sock` (délie la socket périmée qu'on possède) ; `CacheDirectory=secubox` ; `NoNewPrivileges=true` ; `ReadWritePaths=/run/secubox /var/cache/secubox`.
- **Packaging** : `Architecture: all`, `Standards-Version: 4.6.2`, `debhelper-compat (= 13)`, `Depends: secubox-core, python3, python3-fastapi|python3-pip, python3-uvicorn|python3-pip, python3-pydantic|python3-pip` ; `postinst` : `systemctl enable --now secubox-webos` ; `prerm` : `systemctl stop`.
- **Feature flag** `webos.enabled` défaut **false** (registre vide si off).
- **Domaine** : `hall.gk2.net` sert `/api/v1/webos/*` ; `all.gk2.net`→Hub existant.
- **Versioning** : première release `1.0.0-1~bookworm1`.
- **Tests** : pytest par-paquet ; helper `secubox_core` testé dans `common/`. TDD strict.

---

### Task 1: Squelette du paquet `secubox-webos` + `/healthz`

**Files:**
- Create: `packages/secubox-webos/debian/{control,rules,changelog,compat,postinst,prerm,secubox-webos.service}`
- Create: `packages/secubox-webos/api/__init__.py`, `packages/secubox-webos/api/main.py`
- Create: `packages/secubox-webos/nginx/webos.conf`
- Create: `packages/secubox-webos/etc/webos.toml.example`
- Create: `packages/secubox-webos/pytest.ini`, `packages/secubox-webos/tests/__init__.py`, `packages/secubox-webos/tests/test_healthz.py`

**Interfaces:**
- Consumes: rien.
- Produces: FastAPI `app` dans `api.main` (root_path `/api/v1/webos`), route `GET /healthz` → `{"status":"ok"}`. Servie sur `/run/secubox/webos.sock`.

- [ ] **Step 1: Write the failing test**

`packages/secubox-webos/tests/test_healthz.py` :
```python
from fastapi.testclient import TestClient
from api.main import app

def test_healthz_ok():
    c = TestClient(app)
    r = c.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
```
`packages/secubox-webos/pytest.ini` :
```ini
[pytest]
pythonpath = .
testpaths = tests
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_healthz.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.main'`.

- [ ] **Step 3: Write minimal implementation**

`packages/secubox-webos/api/__init__.py` : vide (avec en-tête SPDX en commentaire).
`packages/secubox-webos/api/main.py` :
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — API registre normalisé (P1)."""
from fastapi import FastAPI

app = FastAPI(title="SecuBox WebOS", root_path="/api/v1/webos")

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_healthz.py -v`
Expected: PASS.

- [ ] **Step 5: Write the packaging files**

`debian/compat` : `13`
`debian/control` :
```
Source: secubox-webos
Section: admin
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://secubox.in

Package: secubox-webos
Architecture: all
Depends: ${misc:Depends},
         secubox-core,
         python3,
         python3-fastapi | python3-pip,
         python3-uvicorn | python3-pip,
         python3-pydantic | python3-pip
Description: SecuBox WebOS — normalized service registry (Hall P1)
 Aggregator-independent registry service exposing a normalized view of
 SecuBox services (catalogue + health + reach), served on its own socket.
```
`debian/changelog` :
```
secubox-webos (1.0.0-1~bookworm1) bookworm; urgency=medium

  * P1 : registre normalisé — module dédié secubox-webos (socket propre,
    indépendant de l'agrégateur), endpoints /public/services + /services,
    santé via helper partagé, jointure id↔domaine via menu.d. (ref #1175)

 -- Gerald KERMA <devel@cybermind.fr>  Sun, 24 Aug 2026 12:00:00 +0200
```
`debian/rules` (modèle `secubox-metrics`) :
```make
#!/usr/bin/make -f
%:
	dh $@

override_dh_auto_install:
	install -d $(CURDIR)/debian/secubox-webos/usr/lib/secubox/webos/api
	install -d $(CURDIR)/debian/secubox-webos/etc/nginx/secubox.d
	install -d $(CURDIR)/debian/secubox-webos/etc/secubox
	cp -r api/* $(CURDIR)/debian/secubox-webos/usr/lib/secubox/webos/api/
	install -m 0644 nginx/webos.conf $(CURDIR)/debian/secubox-webos/etc/nginx/secubox.d/webos.conf
	install -m 0644 etc/webos.toml.example $(CURDIR)/debian/secubox-webos/etc/secubox/webos.toml.example
```
`debian/secubox-webos.service` (modèle metrics — noter `User=secubox`, pas de RuntimeDirectory, `ExecStartPre=+rm`) :
```ini
[Unit]
Description=SecuBox WebOS normalized registry API
After=network.target secubox-core.service
Wants=secubox-core.service

[Service]
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/webos
RuntimeDirectoryMode=0755
CacheDirectory=secubox
CacheDirectoryMode=0755
ExecStartPre=+/bin/rm -f /run/secubox/webos.sock
ExecStart=/usr/bin/python3 -m uvicorn api.main:app --uds /run/secubox/webos.sock --log-level warning
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ReadWritePaths=/run/secubox /var/cache/secubox

[Install]
WantedBy=multi-user.target
```
`debian/postinst` :
```bash
#!/bin/bash
set -e
if [ "$1" = "configure" ]; then
    systemctl daemon-reload || true
    systemctl enable --now secubox-webos.service || true
    if [ -x /usr/sbin/nginx ] && nginx -t 2>/dev/null; then systemctl reload nginx || true; fi
fi
#DEBHELPER#
```
`debian/prerm` :
```bash
#!/bin/bash
set -e
if [ "$1" = "remove" ]; then systemctl stop secubox-webos.service || true; fi
#DEBHELPER#
```
`nginx/webos.conf` (routage même-socket, préfixe conservé comme metrics) :
```nginx
# WebOS registre — VITAL, indépendant de l'agrégateur (#1175). Socket dédié.
location /api/v1/webos/ {
    proxy_pass http://unix:/run/secubox/webos.sock:/api/v1/webos/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_intercept_errors on;
}
```
`etc/webos.toml.example` :
```toml
# /etc/secubox/webos.toml
[webos]
enabled = false
registry_enabled = true
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-webos
git commit -m "feat(webos): squelette paquet secubox-webos + /healthz (ref #1175)"
```

---

### Task 2: Modèle Pydantic `Service` (`api/models.py`)

**Files:**
- Create: `packages/secubox-webos/api/models.py`
- Test: `packages/secubox-webos/tests/test_models.py`

**Interfaces:**
- Produces: `Service`, `ServiceUrls`, `ServiceRouting`, `ServiceHealth`, `ServiceAuth` (Pydantic). Champs exacts = spec §4.

- [ ] **Step 1: Write the failing test**
```python
from api.models import Service

def test_service_defaults():
    s = Service(id="waf", name="WAF", category="wall",
                urls={"path": "/waf/"}, routing={}, health={}, auth={})
    assert s.health.state == "unknown"
    assert s.health.latency_ms is None
    assert s.routing.mode == "unknown"
    assert s.cardlet is None
    assert s.capabilities == []
    assert s.urls.path == "/waf/"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_models.py -v`
Expected: FAIL — `No module named 'api.models'`.

- [ ] **Step 3: Write minimal implementation**

`api/models.py` (en-tête SPDX + ) :
```python
from typing import List, Optional, Literal
from pydantic import BaseModel

class ServiceUrls(BaseModel):
    lan: Optional[str] = None
    wan: Optional[str] = None
    path: str

class ServiceRouting(BaseModel):
    mode: Literal["localhost", "lan", "wan", "unknown"] = "unknown"
    available: bool = True

class ServiceHealth(BaseModel):
    state: Literal["online", "degraded", "offline", "unknown"] = "unknown"
    latency_ms: Optional[float] = None
    stale: bool = False
    checked_at: Optional[str] = None

class ServiceAuth(BaseModel):
    mode: Literal["none", "jwt", "cookie", "zkp", "unknown"] = "unknown"

class Service(BaseModel):
    id: str
    name: str
    description: str = ""
    category: str
    icon: str = ""
    urls: ServiceUrls
    routing: ServiceRouting
    health: ServiceHealth
    auth: ServiceAuth
    capabilities: List[str] = []
    cardlet: Optional[dict] = None
    installed: bool = True
    active: bool = True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_models.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add packages/secubox-webos/api/models.py packages/secubox-webos/tests/test_models.py
git commit -m "feat(webos): modèle Service normalisé (ref #1175)"
```

---

### Task 3: Helper santé partagé `secubox_core.health.systemd_batch()` + refacto Hub neutre

**Files:**
- Create: `common/secubox_core/health.py`
- Test: `common/tests/test_health.py` (ou l'emplacement des tests de `secubox_core` — vérifier `common/`)
- Modify: `packages/secubox-hub/api/main.py` (fonction `_refresh_health_batch`, ~lignes 510-566) pour appeler le helper.

**Interfaces:**
- Produces: `secubox_core.health.parse_units(text: str) -> dict[str, dict]` et `secubox_core.health.systemd_batch(sock_dir: str = "/run/secubox", _run=None) -> dict[str, dict]`. Retour = `{"<id>": {"status": "ok"|"warn"|"error", "msg": str}}` où `<id>` est le suffixe après `secubox-`.

- [ ] **Step 1: Write the failing test**
```python
from secubox_core.health import parse_units

SAMPLE = (
    "secubox-waf.service loaded active running SecuBox WAF\n"
    "secubox-dpi.service loaded active reloading SecuBox DPI\n"
    "secubox-auth.service loaded failed failed SecuBox Auth\n"
)

def test_parse_units_maps_states():
    d = parse_units(SAMPLE)
    assert d["waf"]["status"] == "ok"
    assert d["dpi"]["status"] == "warn"
    assert d["auth"]["status"] == "error"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd common && python3 -m pytest tests/test_health.py -v`
Expected: FAIL — `No module named 'secubox_core.health'`.

- [ ] **Step 3: Write minimal implementation**

`common/secubox_core/health.py` (SPDX + ) :
```python
import glob
import os
import subprocess
from typing import Dict, Optional

def parse_units(text: str) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for line in text.splitlines():
        line = line.strip().lstrip("●").strip()
        if not line.startswith("secubox-"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        unit, _load, active, sub = parts[0], parts[1], parts[2], parts[3]
        if not unit.endswith(".service"):
            continue
        mod = unit[len("secubox-"):-len(".service")]
        if active == "active" and sub == "running":
            status, msg = "ok", "Running"
        elif active == "failed" or sub == "failed":
            status, msg = "error", "Failed"
        elif active == "active":
            status, msg = "warn", sub
        else:
            status, msg = "warn", sub or active
        out[mod] = {"status": status, "msg": msg}
    return out

def systemd_batch(sock_dir: str = "/run/secubox", _run: Optional[callable] = None) -> Dict[str, dict]:
    if _run is not None:
        text = _run()
    else:
        try:
            text = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-legend",
                 "--plain", "secubox-*"],
                capture_output=True, text=True, timeout=10).stdout
        except Exception:
            text = ""
    result = parse_units(text)
    # modules présents seulement par leur socket, sans unité listée
    for sock in glob.glob(os.path.join(sock_dir, "*.sock")):
        mod = os.path.basename(sock)[:-len(".sock")]
        result.setdefault(mod, {"status": "ok", "msg": "Socket present"})
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd common && python3 -m pytest tests/test_health.py -v`
Expected: PASS.

- [ ] **Step 5: Refactor Hub to use the helper (neutral)**

Dans `packages/secubox-hub/api/main.py`, `_refresh_health_batch` : remplacer la construction interne du dict `modules` par un appel à `secubox_core.health.systemd_batch()`, en conservant EXACTEMENT le format de sortie `{"modules": <batch>, "count": len(<batch>)}` et la logique « Asleep » (si elle lit `sleepable-modules.json`, la garder autour du helper — le helper ne connaît pas le sommeil). Ajouter `from secubox_core.health import systemd_batch` en tête.

- [ ] **Step 6: Verify Hub tests still pass**

Run: `cd packages/secubox-hub && python3 -m pytest -q 2>&1 | tail -5`
Expected: aucun test cassé (refacto neutre). Si le Hub n'a pas de test sur health-batch, ajouter un test minimal vérifiant que `/public/health-batch` renvoie `{"modules":..., "count":...}` avec un `systemd_batch` injecté/mocké.

- [ ] **Step 7: Commit**
```bash
git add common/secubox_core/health.py common/tests/test_health.py packages/secubox-hub/api/main.py
git commit -m "feat(core): helper santé systemd_batch partagé + Hub l'utilise (ref #1175)"
```

---

### Task 4: `api/idmap.py` (jointure id↔domaine) + passthrough `domain` dans le cache menu du Hub

**Files:**
- Create: `packages/secubox-webos/api/idmap.py`
- Test: `packages/secubox-webos/tests/test_idmap.py`
- Modify: `packages/secubox-hub/api/main.py` (`_compute_menu_sync`, ~lignes 77-150) — faire passer `domain`/`same_origin` du drop-in `menu.d` vers l'item du cache menu.

**Interfaces:**
- Consumes: un item de menu (dict) avec au moins `id`, éventuellement `domain` (str) et `same_origin` (bool).
- Produces: `api.idmap.resolve(item: dict, suffix: str = ".gk2.secubox.in") -> tuple[Optional[str], bool]`. Retour `(domain_or_none, same_origin)` : `same_origin=True` ⇒ `(None, True)` ; sinon `domain` explicite ⇒ `(domain, False)` ; sinon **repli gracieux** convention ⇒ `(f"{id}{suffix}", False)`.

- [ ] **Step 1: Write the failing test**
```python
from api.idmap import resolve

def test_same_origin():
    assert resolve({"id": "radio", "same_origin": True}) == (None, True)

def test_explicit_domain():
    assert resolve({"id": "nc", "domain": "nextcloud.gk2.secubox.in"}) == ("nextcloud.gk2.secubox.in", False)

def test_graceful_fallback_convention():
    assert resolve({"id": "waf"}) == ("waf.gk2.secubox.in", False)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_idmap.py -v`
Expected: FAIL — `No module named 'api.idmap'`.

- [ ] **Step 3: Write minimal implementation**

`api/idmap.py` (SPDX + ) :
```python
from typing import Optional, Tuple

def resolve(item: dict, suffix: str = ".gk2.secubox.in") -> Tuple[Optional[str], bool]:
    if item.get("same_origin"):
        return (None, True)
    dom = item.get("domain")
    if dom:
        return (dom, False)
    return (f"{item['id']}{suffix}", False)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_idmap.py -v`
Expected: PASS.

- [ ] **Step 5: Hub passthrough of `domain`/`same_origin`**

Dans `_compute_menu_sync` (`packages/secubox-hub/api/main.py`), là où chaque item du cache menu est construit à partir du drop-in `menu.d`, ajouter la copie conditionnelle des deux champs :
```python
if "domain" in raw:        item["domain"] = raw["domain"]
if "same_origin" in raw:   item["same_origin"] = raw["same_origin"]
```
(Adapter `raw`/`item` aux noms locaux réels. Champs absents ⇒ non ajoutés — neutre.)

- [ ] **Step 6: Verify + commit**

Run: `cd packages/secubox-hub && python3 -m pytest -q 2>&1 | tail -3` (rien de cassé).
```bash
git add packages/secubox-webos/api/idmap.py packages/secubox-webos/tests/test_idmap.py packages/secubox-hub/api/main.py
git commit -m "feat(webos): idmap id↔domaine + passthrough domain dans le cache menu du Hub (ref #1175)"
```

---

### Task 5: `api/registry.py` — `normalize_services()`

**Files:**
- Create: `packages/secubox-webos/api/registry.py`
- Test: `packages/secubox-webos/tests/test_registry.py`

**Interfaces:**
- Consumes: `api.models.Service`, `api.idmap.resolve`.
- Produces:
  - `api.registry.HEALTH_MAP = {"ok": "online", "warn": "degraded", "error": "offline"}`
  - `api.registry.normalize_services(menu: dict, health: dict, exposure: Optional[dict] = None) -> list[Service]`
  - `api.registry.load_menu_cache(path: str = "/var/cache/secubox/menu.json") -> dict` (repli `{"categories": []}` si absent)
  - `api.registry.load_exposure_cache(path: str = "/var/cache/secubox/webos/exposure-health.json") -> dict` (repli `{}` — best-effort, latence/reach absents ⇒ `null`/`unknown`)

  `menu` a la forme `{"categories":[{"items":[{id,name,category,icon,path,description,installed,active, domain?, same_origin?}]}]}`.
  `health` a la forme `{id: {"status": "...", "msg": "..."}}` (sortie `systemd_batch`).
  `exposure` a la forme `{domain: {"reach": "wan"|"lan"|"localhost", "latency_ms": float}}`.

- [ ] **Step 1: Write the failing test**
```python
from api.registry import normalize_services, HEALTH_MAP

MENU = {"categories": [{"items": [
    {"id": "waf", "name": "WAF", "category": "wall", "icon": "🔥", "path": "/waf/",
     "description": "", "installed": True, "active": True,
     "domain": "waf.gk2.secubox.in"},
    {"id": "radio", "name": "Radio", "category": "mind", "icon": "🎧", "path": "/radio/",
     "installed": True, "active": True, "same_origin": True},
]}]}
HEALTH = {"waf": {"status": "ok", "msg": "Running"},
          "radio": {"status": "error", "msg": "Failed"}}
EXPO = {"waf.gk2.secubox.in": {"reach": "wan", "latency_ms": 12.5}}

def test_health_mapping_and_join():
    svcs = {s.id: s for s in normalize_services(MENU, HEALTH, EXPO)}
    assert svcs["waf"].health.state == "online"
    assert svcs["waf"].urls.lan == "https://waf.gk2.secubox.in"
    assert svcs["waf"].urls.wan == "https://waf.gk2.secubox.in"   # reach=wan
    assert svcs["waf"].routing.mode == "wan"
    assert svcs["waf"].health.latency_ms == 12.5
    # radio: offline, same-origin (pas d'URL), latence absente
    assert svcs["radio"].health.state == "offline"
    assert svcs["radio"].urls.lan is None
    assert svcs["radio"].urls.wan is None
    assert svcs["radio"].health.latency_ms is None
    assert svcs["radio"].routing.available is False   # offline

def test_unknown_when_health_absent():
    svcs = {s.id: s for s in normalize_services(MENU, {}, None)}
    assert svcs["waf"].health.state == "unknown"
    assert svcs["waf"].urls.wan is None               # pas d'expo ⇒ pas de wan
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_registry.py -v`
Expected: FAIL — `No module named 'api.registry'`.

- [ ] **Step 3: Write minimal implementation**

`api/registry.py` (SPDX + ) :
```python
import json
from pathlib import Path
from typing import List, Optional
from api.models import Service, ServiceUrls, ServiceRouting, ServiceHealth, ServiceAuth
from api.idmap import resolve

HEALTH_MAP = {"ok": "online", "warn": "degraded", "error": "offline"}

def load_menu_cache(path: str = "/var/cache/secubox/menu.json") -> dict:
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return {"categories": []}

def load_exposure_cache(path: str = "/var/cache/secubox/webos/exposure-health.json") -> dict:
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return {}

def normalize_services(menu: dict, health: dict, exposure: Optional[dict] = None) -> List[Service]:
    exposure = exposure or {}
    out: List[Service] = []
    for cat in menu.get("categories", []):
        for item in cat.get("items", []):
            state = HEALTH_MAP.get((health.get(item["id"]) or {}).get("status"), "unknown")
            domain, same_origin = resolve(item)
            rec = exposure.get(domain) if domain else None
            latency = rec.get("latency_ms") if rec else None
            reach = rec.get("reach") if rec else "unknown"
            lan = f"https://{domain}" if domain else None
            wan = lan if reach == "wan" else None
            out.append(Service(
                id=item["id"], name=item.get("name", item["id"]),
                description=item.get("description", ""),
                category=item.get("category", "root"), icon=item.get("icon", ""),
                urls=ServiceUrls(lan=lan, wan=wan, path=item.get("path", "/")),
                routing=ServiceRouting(
                    mode=reach if reach in ("localhost", "lan", "wan") else "unknown",
                    available=(state != "offline")),
                health=ServiceHealth(state=state, latency_ms=latency),
                auth=ServiceAuth(),
                installed=bool(item.get("installed", True)),
                active=bool(item.get("active", True)),
            ))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_registry.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add packages/secubox-webos/api/registry.py packages/secubox-webos/tests/test_registry.py
git commit -m "feat(webos): normalize_services — compose menu+santé+reach → Service (ref #1175)"
```

---

### Task 6: `api/flags.py` — lecture `webos.toml`

**Files:**
- Create: `packages/secubox-webos/api/flags.py`
- Test: `packages/secubox-webos/tests/test_flags.py`

**Interfaces:**
- Produces: `api.flags.load_flags(path: str = "/etc/secubox/webos.toml") -> dict` → `{"enabled": bool, "registry_enabled": bool}`. Fichier absent ⇒ `{"enabled": False, "registry_enabled": True}`.

- [ ] **Step 1: Write the failing test**
```python
from api.flags import load_flags

def test_missing_file_defaults(tmp_path):
    f = load_flags(str(tmp_path / "nope.toml"))
    assert f == {"enabled": False, "registry_enabled": True}

def test_reads_enabled(tmp_path):
    p = tmp_path / "webos.toml"
    p.write_text("[webos]\nenabled = true\nregistry_enabled = false\n")
    assert load_flags(str(p)) == {"enabled": True, "registry_enabled": False}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_flags.py -v`
Expected: FAIL — `No module named 'api.flags'`.

- [ ] **Step 3: Write minimal implementation**

`api/flags.py` (SPDX + ; `tomllib` est en stdlib 3.11) :
```python
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:  # 3.10 fallback
    import tomli as tomllib

def load_flags(path: str = "/etc/secubox/webos.toml") -> dict:
    data = {}
    try:
        data = tomllib.loads(Path(path).read_text()).get("webos", {})
    except Exception:
        data = {}
    return {
        "enabled": bool(data.get("enabled", False)),
        "registry_enabled": bool(data.get("registry_enabled", True)),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_flags.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add packages/secubox-webos/api/flags.py packages/secubox-webos/tests/test_flags.py
git commit -m "feat(webos): flags webos.toml (ref #1175)"
```

---

### Task 7: Endpoints + tâche de fond + cache (`api/main.py`)

**Files:**
- Modify: `packages/secubox-webos/api/main.py`
- Test: `packages/secubox-webos/tests/test_endpoints.py`

**Interfaces:**
- Consumes: `registry.normalize_services/load_menu_cache/load_exposure_cache`, `health.systemd_batch`, `flags.load_flags`, `secubox_core.auth.require_jwt`.
- Produces (HTTP) :
  - `GET /public/services` → `{"services": [ {id,name,category,icon,health:{state},installed,active} ], "computed_at": <float|null>}` (minimal, sans JWT).
  - `GET /services` → `{"services": [<Service complet>], "computed_at": <float|null>}` (JWT).
  - Registre vide `{"services": [], ...}` si `flags.enabled` est faux.
  - `_recompute()` (helper testable) : lit menu/health/expo, remplit `_cache`.

- [ ] **Step 1: Write the failing test**
```python
from fastapi.testclient import TestClient
import api.main as m
from api.main import app, require_jwt

def _seed():
    m._cache["services"] = [
        m.Service(id="waf", name="WAF", category="wall", icon="🔥",
                  urls={"path": "/waf/", "lan": "https://waf.gk2.secubox.in", "wan": "https://waf.gk2.secubox.in"},
                  routing={"mode": "wan"}, health={"state": "online", "latency_ms": 5.0},
                  auth={}).model_dump()
    ]
    m._cache["computed_at"] = 123.0

def test_public_is_minimal():
    _seed()
    c = TestClient(app)
    r = c.get("/public/services")
    assert r.status_code == 200
    svc = r.json()["services"][0]
    assert svc["id"] == "waf" and svc["health"]["state"] == "online"
    assert "urls" not in svc and "latency_ms" not in str(svc)   # pas de fuite

def test_detail_requires_jwt_and_is_full():
    _seed()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "gk2"}
    try:
        c = TestClient(app)
        svc = c.get("/services").json()["services"][0]
        assert svc["urls"]["wan"] == "https://waf.gk2.secubox.in"
        assert svc["health"]["latency_ms"] == 5.0
    finally:
        app.dependency_overrides.clear()

def test_flag_off_empty(monkeypatch):
    monkeypatch.setattr(m, "_flags", {"enabled": False, "registry_enabled": True})
    _seed()
    c = TestClient(app)
    assert c.get("/public/services").json()["services"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_endpoints.py -v`
Expected: FAIL (`require_jwt`/`_cache`/routes absents).

- [ ] **Step 3: Write minimal implementation**

Réécrire `api/main.py` (garder `/healthz` de Task 1) :
```python
# SPDX ... (garder l'en-tête)
"""SecuBox-Deb :: WebOS — API registre normalisé (P1)."""
import asyncio
import json
import time
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter, Depends

from secubox_core.auth import require_jwt
from secubox_core.health import systemd_batch
from api.models import Service
from api import registry, flags

_cache: dict = {"services": [], "computed_at": None}
_flags: dict = flags.load_flags()
_CACHE_FILE = Path("/var/cache/secubox/webos/services.json")

def _recompute() -> None:
    menu = registry.load_menu_cache()
    health = systemd_batch()
    expo = registry.load_exposure_cache()
    svcs = registry.normalize_services(menu, health, expo)
    _cache["services"] = [s.model_dump() for s in svcs]
    _cache["computed_at"] = time.time()
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(_cache))
    except Exception:
        pass

async def _refresh_loop():
    while True:
        try:
            _recompute()
        except Exception:
            pass
        await asyncio.sleep(15)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _flags
    _flags = flags.load_flags()
    if _CACHE_FILE.exists():
        try:
            _cache.update(json.loads(_CACHE_FILE.read_text()))
        except Exception:
            pass
    task = asyncio.create_task(_refresh_loop())
    yield
    task.cancel()

app = FastAPI(title="SecuBox WebOS", root_path="/api/v1/webos", lifespan=lifespan)
public_router = APIRouter(prefix="/public")
router = APIRouter()

def _enabled() -> bool:
    return bool(_flags.get("enabled"))

_PUBLIC_FIELDS = ("id", "name", "category", "icon", "installed", "active")

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

@public_router.get("/services")
async def public_services():
    if not _enabled():
        return {"services": [], "computed_at": _cache["computed_at"]}
    out = []
    for s in _cache["services"]:
        row = {k: s[k] for k in _PUBLIC_FIELDS if k in s}
        row["health"] = {"state": (s.get("health") or {}).get("state", "unknown")}
        out.append(row)
    return {"services": out, "computed_at": _cache["computed_at"]}

@router.get("/services")
async def services(user=Depends(require_jwt)):
    if not _enabled():
        return {"services": [], "computed_at": _cache["computed_at"]}
    return {"services": _cache["services"], "computed_at": _cache["computed_at"]}

app.include_router(public_router)
app.include_router(router)
```
Note test : `test_public_is_minimal`/`test_detail...` réamorcent `_flags` à enabled. Ajouter au `_seed()` du test : `m._flags = {"enabled": True, "registry_enabled": True}`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-webos && python3 -m pytest tests/ -v`
Expected: PASS (toute la suite).

- [ ] **Step 5: Commit**
```bash
git add packages/secubox-webos/api/main.py packages/secubox-webos/tests/test_endpoints.py
git commit -m "feat(webos): endpoints public/services (minimal) + services (JWT) + refresh cache-first (ref #1175)"
```

---

### Task 8: Peuplement `domain`/`same_origin` dans les `menu.d` (sweep batché)

**Files:**
- Modify: `packages/*/menu.d/*.json` (les modules exposés sur leur propre domaine)
- Test: `packages/secubox-webos/tests/test_menud_schema.py`

**Interfaces:**
- Consumes: rien (données).
- Produces: chaque drop-in `menu.d` concerné porte `"domain": "<x>.gk2.secubox.in"` ou `"same_origin": true`. Repli gracieux = si absent, `idmap` applique la convention (Task 4) — donc **non bloquant** : peupler d'abord les modules à domaine NON conventionnel (ex. `nc`→`nextcloud`, `lyrion`, `photos`→`photoprism`…), laisser les conventionnels hériter.

- [ ] **Step 1: Écrire le test de schéma**

`packages/secubox-webos/tests/test_menud_schema.py` :
```python
import json, glob, os

def test_menud_domain_fields_are_wellformed():
    root = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages")
    for path in glob.glob(os.path.join(root, "*", "menu.d", "*.json")):
        data = json.loads(open(path).read())
        items = data if isinstance(data, list) else data.get("items", [data])
        for it in items:
            if not isinstance(it, dict):
                continue
            if "domain" in it:
                assert isinstance(it["domain"], str) and it["domain"], path
            if "same_origin" in it:
                assert isinstance(it["same_origin"], bool), path
```

- [ ] **Step 2: Run test to verify it passes (schéma vide encore vrai)**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_menud_schema.py -v`
Expected: PASS (aucun champ encore = trivialement vrai — c'est un garde-fou, pas un TDD rouge).

- [ ] **Step 3: Inventorier les domaines non conventionnels**

Lister les `menu.d/*.json` dont l'`id` ne correspond PAS à `<id>.gk2.secubox.in`. Croiser avec les vhosts réels (`packages/secubox-vhost` / la config nginx). Pour chacun, ajouter le champ. Exemples attendus (à confirmer par inspection) : `nc→nextcloud.gk2.secubox.in`, `lyrion→lyrion.gk2.secubox.in`, `radio→same_origin:true`, etc. Modules même-origine (servis en path relatif sous le Hub) ⇒ `"same_origin": true`.

- [ ] **Step 4: Éditer les drop-ins (une passe)**

Ajouter le champ dans chaque fichier concerné (édition JSON minimale, ne rien casser d'autre).

- [ ] **Step 5: Re-run schema test + commit**

Run: `cd packages/secubox-webos && python3 -m pytest tests/test_menud_schema.py -v` → PASS.
```bash
git add packages/*/menu.d/*.json packages/secubox-webos/tests/test_menud_schema.py
git commit -m "feat(webos): domaines menu.d (jointure id↔domaine, non conventionnels) (ref #1175)"
```

---

### Task 9: Intégration, build, déploiement, alias (étape contrôleur — actions live consignées dans #1175)

**Files:**
- Modify: `packages/secubox-webos/debian/changelog` (si bump nécessaire après itérations)

> **Cette tâche N'EST PAS du TDD-subagent** : ce sont des actions d'intégration/board exécutées par le contrôleur, source-first, chaque action live consignée dans l'issue #1175. Ne pas la déléguer à un implémenteur.

- [ ] **Step 1: Suite complète verte + build**
```bash
cd packages/secubox-webos && python3 -m pytest tests/ -q
cd common && python3 -m pytest tests/test_health.py -q
cd packages/secubox-hub && python3 -m pytest -q
cd packages/secubox-webos && dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b -d
```
Attendu : `secubox-webos_1.0.0-1~bookworm1_all.deb` produit ; toutes suites vertes.

- [ ] **Step 2: Déployer sur gk2 + vérifier la socket**
```bash
scp packages/secubox-webos_1.0.0-1~bookworm1_all.deb root@192.168.1.200:/tmp/
ssh root@192.168.1.200 'dpkg -i /tmp/secubox-webos_1.0.0-1~bookworm1_all.deb; systemctl is-active secubox-webos; ls -l /run/secubox/webos.sock'
ssh root@192.168.1.200 'curl -s --unix-socket /run/secubox/webos.sock http://x/api/v1/webos/healthz'
```
Activer le flag pour tester le registre : poser `/etc/secubox/webos.toml` `enabled=true`, `systemctl restart secubox-webos`, puis `curl … /api/v1/webos/public/services` (attendu : services réels, minimal).

- [ ] **Step 3: Câbler `hall.gk2.net` (source-first + live consigné)**
  - DNS : enregistrement `hall.gk2.net` via l'API Gandi (clé sur board).
  - HAProxy : route déclarative pour `hall.gk2.net` → nginx (chaîne d'inspection par défaut, PAS de `waf_bypass`).
  - nginx : le vhost `hall.gk2.net` doit inclure `etc/nginx/secubox.d/webos.conf` (livré par le paquet). Ajouter le `server` block `server_name hall.gk2.net` s'il n'existe pas.
  - Cert : certbot (DNS-01 Gandi ou HTTP-01 selon la chaîne ACME du board).
  - Vérifier : `curl -k https://hall.gk2.net/api/v1/webos/healthz`.

- [ ] **Step 4: Câbler l'alias `all.gk2.net`→Hub (item WIP ouvert)**
  - Ajouter `all.gk2.secubox.in`/`all.gk2.net` au `server_name` du Hub (`packages/secubox-hub/nginx/webui.conf:55`) + ACL HAProxy + cert. (Source-first : éditer la conf du paquet Hub, rebuild/redeploy Hub.)
  - Vérifier : `all.gk2.net` ne tombe plus sur `wrong-domain.html`.

- [ ] **Step 5: Sync apt + commit changelog + consigner #1175**
```bash
ssh root@192.168.1.200 'cd /data/apt && reprepro includedeb bookworm /tmp/secubox-webos_1.0.0-1~bookworm1_all.deb'
git add -A && git commit -m "release: secubox-webos 1.0.0 — registre P1 déployé (ref #1175)"
```
Commenter #1175 : endpoints live, flag testé, alias câblés, en attente de validation.

---

## Self-Review

**Spec coverage :**
- §3 module dédié/socket/indépendance → Task 1 (unit+service) ✓
- §4 objet Service + mapping santé + public/détail → Tasks 2, 5, 7 ✓
- §5-C helper santé partagé → Task 3 ✓
- §6-B champ domain menu.d + idmap → Tasks 4, 8 ✓
- §7 cache/refresh → Task 7 (_refresh_loop, cache-first) ✓
- §8 feature flags → Task 6 + Task 7 (_enabled) ✓
- §9 auth (require_jwt, public/router) → Task 7 ✓
- §10 alias hall/all → Task 9 ✓
- §11 structure fichiers → Tasks 1-7 ✓
- §12 DoD / §13 tests → Tasks 2-8 (unit) + Task 9 (E2E board) ✓
- §14 risques : R4 cache-first (Task 7), R5 helper partagé (Task 3), R6 split public/détail (Task 7) ✓

**Placeholder scan :** aucun TBD/handle-edge-cases ; tout code est concret. (Task 8 Step 3 « inventorier » est une étape de données guidée, pas un placeholder de code.)

**Type consistency :** `systemd_batch`→`{id:{status,msg}}` consommé par `normalize_services(health)` ✓ ; `resolve(item)->(domain,same_origin)` consommé par `normalize_services` ✓ ; `Service.model_dump()` stocké dans `_cache["services"]` et reprojeté ✓ ; `HEALTH_MAP` clés `ok/warn/error` = sortie `parse_units` ✓.

**Divergences notées (assumées, cf. spec) :** `User=secubox` partagé (pas d'utilisateur dédié — sécurité socket board) ; enrichissement latence/reach best-effort (chemin cache exposure à confirmer sur board en Task 9, repli `{}`).

---

## Execution Handoff

Plan complet et sauvegardé. Deux options d'exécution :
1. **Subagent-Driven (recommandé)** — un subagent frais par tâche, revue entre chaque, itération rapide.
2. **Inline** — exécution en session avec checkpoints.
