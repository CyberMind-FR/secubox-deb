<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## ⚡ Performance Patterns — Double Caching (porté depuis OpenWrt)

Le pattern shell → cron + fichier statique se traduit en Debian par
**background task FastAPI + fichier cache JSON** :

### Pattern Debian (FastAPI + asyncio)
```python
# Dans api/main.py de chaque module stats-heavy
import asyncio, json
from pathlib import Path

CACHE_FILE = Path("/var/cache/secubox/<module>/stats.json")
_cache: dict = {}

async def refresh_cache():
    """Tourne en background, met à jour toutes les 60s."""
    while True:
        try:
            data = await _compute_stats()  # logique métier
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(data))
            _cache.update(data)
        except Exception as e:
            logger.error(f"cache refresh failed: {e}")
        await asyncio.sleep(60)

@app.on_event("startup")
async def startup():
    asyncio.create_task(refresh_cache())

@app.get("/stats")
async def get_stats():
    if _cache:
        return _cache
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text())
    return {"error": "cache not ready"}
```

### Règle d'application (identique OpenWrt)

* **Toujours** pour les dashboards stats (WAF, bandwidth, DPI…)
* **Toujours** quand l'endpoint lit des logs ou calcule des agrégats
* **Toujours** quand la donnée peut être périmée de 60s sans impact utilisateur
* **Jamais** pour les actions temps-réel (start/stop/restart/ban)

---

