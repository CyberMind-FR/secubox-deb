<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Health/Doctor/Repair Pattern

## Architecture Multi-Couche

Chaque module SecuBox implémente 4 niveaux de surveillance et réparation.

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: /health                                           │
│  ├── Status: ok | degraded | error                          │
│  ├── Checks basiques (service up, socket exists)            │
│  └── Public, pas d'auth requis                              │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: /doctor                                           │
│  ├── Diagnostic détaillé                                    │
│  ├── Liste des issues détectées                             │
│  ├── can_repair: true/false                                 │
│  └── Suggère les actions de repair                          │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: /repair                                           │
│  ├── Exécute les réparations automatiques                   │
│  ├── Log chaque action                                      │
│  ├── Vérifie le résultat                                    │
│  └── Retourne success + actions effectuées                  │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: Escalade                                          │
│  ├── Si repair échoue → notifier hub central                │
│  ├── Récursion: repair dépendances d'abord                  │
│  └── Alerte admin si échec critique                         │
└─────────────────────────────────────────────────────────────┘
```

## Endpoints Standard

### GET /health (public)
```json
{
  "status": "ok",           // ok | degraded | error
  "healthy": true,
  "checks": {
    "service_active": true,
    "socket_exists": true,
    "config_valid": true,
    "deps_ok": true
  }
}
```

### GET /doctor (auth required)
```json
{
  "healthy": false,
  "issues": [
    {"type": "socket_missing", "repairable": true},
    {"type": "config_invalid", "repairable": false}
  ],
  "can_repair": true,
  "repair_endpoint": "/repair",
  "suggested_actions": ["create_socket_dir", "restart"]
}
```

### POST /repair (auth required)
```json
{
  "success": true,
  "repairs": [
    {"action": "create_socket_dir", "status": "ok"},
    {"action": "restart", "status": "ok"},
    {"action": "verify", "status": "ok"}
  ],
  "issues_remaining": []
}
```

## Implémentation Type (Python/FastAPI)

```python
# ══════════════════════════════════════════════════════════════
# Health/Doctor/Repair Pattern
# ══════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Layer 1: Basic health check (public)."""
    checks = {
        "service_active": _check_service_active(),
        "socket_exists": Path(SOCKET_PATH).exists(),
        "config_valid": _validate_config(),
    }

    status = "ok" if all(checks.values()) else "degraded"
    if not checks["service_active"]:
        status = "error"

    return {
        "status": status,
        "healthy": status == "ok",
        "checks": checks
    }


@app.get("/doctor", dependencies=[Depends(require_jwt)])
async def doctor_check():
    """Layer 2: Diagnostic détaillé."""
    issues = []

    if not _check_service_active():
        issues.append({"type": "service_dead", "repairable": True})

    if not Path(SOCKET_PATH).exists():
        issues.append({"type": "socket_missing", "repairable": True})

    if not _validate_config():
        issues.append({"type": "config_invalid", "repairable": False})

    # Check dependencies
    for dep in DEPENDENCIES:
        if not _check_dep_healthy(dep):
            issues.append({"type": f"dep_{dep}_unhealthy", "repairable": True})

    can_repair = all(i["repairable"] for i in issues)

    return {
        "healthy": len(issues) == 0,
        "issues": issues,
        "can_repair": can_repair,
        "repair_endpoint": "/repair"
    }


@app.post("/repair", dependencies=[Depends(require_jwt)])
async def repair_module():
    """Layer 3: Auto-repair avec log."""
    repairs = []

    # 1. Repair dependencies first (recursion)
    for dep in DEPENDENCIES:
        if not _check_dep_healthy(dep):
            try:
                # Call dep's repair endpoint
                async with httpx.AsyncClient() as client:
                    r = await client.post(f"http://unix:/run/secubox/{dep}.sock/repair")
                    repairs.append({"action": f"repair_dep_{dep}", "status": "ok"})
            except Exception as e:
                repairs.append({"action": f"repair_dep_{dep}", "status": "error", "message": str(e)})

    # 2. Create socket directory
    socket_dir = Path(SOCKET_PATH).parent
    if not socket_dir.exists():
        socket_dir.mkdir(parents=True, exist_ok=True)
        repairs.append({"action": "create_socket_dir", "status": "ok"})

    # 3. Fix permissions
    try:
        os.chmod(socket_dir, 0o755)
        repairs.append({"action": "fix_perms", "status": "ok"})
    except Exception as e:
        repairs.append({"action": "fix_perms", "status": "error", "message": str(e)})

    # 4. Restart service
    try:
        subprocess.run(["systemctl", "restart", SERVICE_NAME], timeout=30, check=True)
        repairs.append({"action": "restart", "status": "ok"})
    except Exception as e:
        repairs.append({"action": "restart", "status": "error", "message": str(e)})

    # 5. Verify
    time.sleep(2)
    health = await health_check()
    repairs.append({"action": "verify", "status": "ok" if health["healthy"] else "error"})

    # 6. Escalade si échec
    success = all(r["status"] == "ok" for r in repairs)
    if not success:
        _escalate_to_hub(MODULE_NAME, repairs)

    # Log repair
    _log_repair(repairs, success)

    return {
        "success": success,
        "repairs": repairs,
        "issues_remaining": [] if success else await doctor_check()["issues"]
    }


def _escalate_to_hub(module: str, repairs: list):
    """Layer 4: Escalade vers hub central."""
    try:
        httpx.post(
            "http://unix:/run/secubox/hub.sock/alerts",
            json={
                "type": "repair_failed",
                "module": module,
                "repairs": repairs,
                "severity": "warning"
            },
            timeout=5
        )
    except Exception:
        pass  # Hub might be down too
```

## Modules Implémentés

| Module | /health | /doctor | /repair | Notes |
|--------|---------|---------|---------|-------|
| secubox-hub | ✅ | ✅ | ✅ | Central, répare tous les modules |
| secubox-haproxy | ✅ | - | ✅ | + /certificates/repair, /vhosts/repair |
| secubox-waf | ✅ | ✅ | ✅ | Repair rules, logs, routes |
| secubox-crowdsec | ⬜ | ⬜ | ⬜ | TODO: CAPI, hub, bouncer |
| secubox-wireguard | ⬜ | ⬜ | ⬜ | TODO: peers, routes |
| ... | ⬜ | ⬜ | ⬜ | À implémenter |

## Vhost comme Master Controller

Le module vhost orchestre HAProxy, nginx et les certs:

```
vhost add domain.com
  ├── 1. Créer config nginx
  ├── 2. Créer vhost HAProxy
  ├── 3. Demander cert ACME
  ├── 4. Recharger nginx
  └── 5. Recharger HAProxy

vhost repair domain.com
  ├── 1. Check nginx config
  ├── 2. Check HAProxy config
  ├── 3. Check cert validity
  ├── 4. Repair si nécessaire
  └── 5. Sync état distribué
```

## État Distribué

Pour éviter les duplications:
1. Chaque module maintient son état local
2. Hub central agrège les états via `/health` polling
3. Repairs sont idempotents (peuvent être appelés plusieurs fois)
4. Locks distribués via fichiers dans `/run/secubox/locks/`

## Logs Repair

Tous les repairs sont loggés dans `/var/log/secubox/repairs.log`:
```
2026-05-08T14:30:00 | secubox-waf | reload_rules | OK | 150 rules loaded
2026-05-08T14:30:01 | secubox-waf | fix_perms | OK |
2026-05-08T14:30:02 | secubox-haproxy | reload | FAIL | Config error line 42
```
