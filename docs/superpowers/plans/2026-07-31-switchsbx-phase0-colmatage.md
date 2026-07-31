# SwitchSBX Phase 0 — Colmatage du plan d'authentification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fermer quatre failles actives du plan d'authentification et supprimer un défaut de performance sur le chemin chaud, sans introduire SwitchSBX.

**Architecture:** Toutes les corrections vivent dans `common/secubox_core/` (partagé par tous les services) plus trois paquets. Le point central est que `secubox_core.auth` a des défauts **permissifs** qui ne sont corrigés que dans le processus `secubox-auth` ; les 44 modules routés vers leur socket dédiée gardent ces défauts (l'agrégateur, lui, monte 113 modules dont `auth`, donc il est couvert). On rend les défauts *fail-closed* et on fournit un magasin de sessions partagé lisible par tous.

**Tech Stack:** Python 3.11, FastAPI, python-jose (HS256), argon2-cffi, pytest, nginx, systemd.

## Global Constraints

- Cible : Debian 12 bookworm, Python 3.11.2 (pas de `tarfile filter=`, pas de syntaxe 3.12+).
- Tests : `.venv` du dépôt, exécution **par répertoire** (collision de `pytest.ini` entre paquets).
- Aucun secret en clair ; `/etc/secubox/users.json` doit rester `secubox:secubox`.
- Ne jamais élargir les permissions d'un parent partagé (`/run/secubox`, `/var/log/secubox`, `/etc/secubox`).
- Les messages de commit ne portent aucune référence à un assistant IA.
- Chaque tâche se termine par un commit.

---

### Task 1 : rejeter les jetons porteurs d'un `scope`

Un `mfa_token` (émis avant la vérification TOTP) et un `setup_token` (émis contre un mot de passe vide) sont aujourd'hui acceptés comme jetons d'accès complets par tout module dont le validateur de session est resté au défaut permissif.

**Files:**
- Modify: `common/secubox_core/auth.py:128-180`
- Test: `common/secubox_core/tests/test_scope_rejection.py`

**Interfaces:**
- Consumes: rien
- Produces: `require_jwt(request, creds, scope=None)` — quand `scope is None`, seuls les jetons **sans** claim `scope` sont acceptés ; quand `scope="mfa-challenge"`, seul ce scope précis est accepté. `_validate_token(token, expected_scope=None) -> Optional[Dict[str, Any]]`.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# common/secubox_core/tests/test_scope_rejection.py
import pytest
from secubox_core import auth


@pytest.fixture(autouse=True)
def _permissive_session(monkeypatch):
    """Reproduit le défaut des 44 modules à socket dédiée : validateur permissif."""
    auth.set_session_validator(lambda jti: True)
    monkeypatch.setattr(auth.user_store, "is_enabled", lambda u: True)


def test_scoped_token_is_not_a_full_access_token():
    """Un mfa-challenge ne doit JAMAIS ouvrir un endpoint protégé."""
    tok = auth.create_token("alice", scope="mfa-challenge", expires_in=300)
    assert auth._validate_token(tok) is None


def test_setup_token_is_not_a_full_access_token():
    tok = auth.create_token("alice", scope="set-password", expires_in=900)
    assert auth._validate_token(tok) is None


def test_scoped_token_accepted_only_for_its_own_scope():
    tok = auth.create_token("alice", scope="mfa-challenge", expires_in=300)
    assert auth._validate_token(tok, expected_scope="mfa-challenge") is not None
    assert auth._validate_token(tok, expected_scope="totp-enroll") is None


def test_plain_token_still_works():
    tok = auth.create_token("alice")
    payload = auth._validate_token(tok)
    assert payload is not None and payload["sub"] == "alice"


def test_plain_token_rejected_when_a_scope_is_required():
    tok = auth.create_token("alice")
    assert auth._validate_token(tok, expected_scope="mfa-challenge") is None
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd common && ../.venv/bin/pytest secubox_core/tests/test_scope_rejection.py -v`
Expected : FAIL — `test_scoped_token_is_not_a_full_access_token` échoue (le jeton scopé est accepté), et `_validate_token()` ne prend pas encore `expected_scope`.

- [ ] **Step 3 : implémenter**

Dans `common/secubox_core/auth.py`, remplacer `_validate_token` et `require_jwt` :

```python
def _validate_token(token: str, expected_scope: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Decode + session/enabled/scope checks. Returns the payload if fully
    valid, else None — never raises.

    `scope` carries a short-lived INTENT (mfa-challenge, set-password,
    totp-enroll). Such a token is emitted BEFORE the second factor is proven,
    so it must never satisfy a plain `Depends(require_jwt)`. Callers that want
    one pass `expected_scope` explicitly.
    """
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
    except JWTError:
        return None
    if not payload.get("sub"):
        return None
    if payload.get("scope") != expected_scope:
        return None
    jti = payload.get("jti")
    if not jti or not _session_validator(jti):
        return None
    if not user_store.is_enabled(payload["sub"]):
        return None
    return payload


async def require_jwt(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    scope: Optional[str] = None,
) -> Dict[str, Any]:
    candidates = []
    if creds is not None and creds.credentials:
        candidates.append(creds.credentials)
    cookie_tok = request.cookies.get(SESSION_COOKIE)
    if cookie_tok:
        candidates.append(cookie_tok)
    if not candidates:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Bearer ou session manquant",
            headers={"WWW-Authenticate": "Bearer"},
        )
    for token in candidates:
        payload = _validate_token(token, expected_scope=scope)
        if payload is not None:
            return payload
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expiré",
        headers={"WWW-Authenticate": "Bearer"},
    )
```

- [ ] **Step 4 : lancer les tests**

Run : `cd common && ../.venv/bin/pytest secubox_core/tests/ -v`
Expected : PASS, y compris `test_auth_rewire.py` qui existe déjà.

- [ ] **Step 5 : vérifier que `secubox-auth` fonctionne toujours**

`secubox-auth` valide ses jetons scopés via `_check_scope()`, qui appelle `_jwt_decode` — un chemin distinct de `_validate_token`, donc non impacté.

Run : `cd packages/secubox-auth && ../../.venv/bin/pytest tests/ -v`
Expected : PASS.

- [ ] **Step 6 : commit**

```bash
git add common/secubox_core/auth.py common/secubox_core/tests/test_scope_rejection.py
git commit -m "fix(core): un jeton porteur d'un scope n'est plus un jeton d'accès complet

Les jetons d'étape (mfa-challenge, set-password, totp-enroll) sont émis AVANT
que le second facteur soit prouvé. _validate_token() ne lisait jamais le claim
scope : sur tout module dont le validateur de session est resté au défaut
permissif, un mfa-challenge ouvrait 300s d'accès complet avec le seul mot de
passe, et un setup_token 900s sans aucun mot de passe.

require_jwt gagne un paramètre scope explicite ; sans lui, seuls les jetons
sans scope passent."
```

---

### Task 2 : validateur de session fail-closed + magasin partagé

`_session_validator` vaut `lambda jti: True` par défaut et n'est remplacé que par `secubox-auth`. Les 44 modules routés vers leur socket dédiée ne révoquent donc jamais rien.

**Files:**
- Create: `common/secubox_core/session_store.py`
- Modify: `common/secubox_core/auth.py:30-44`
- Modify: `packages/secubox-auth/api/main.py:191-220`
- Test: `common/secubox_core/tests/test_session_store.py`

**Interfaces:**
- Consumes: rien
- Produces: `session_store.is_valid(jti: str) -> bool`, `session_store.reload() -> None`, `session_store.SESSIONS_PATH: Path`. `auth._session_validator` vaut désormais `session_store.is_valid` par défaut.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# common/secubox_core/tests/test_session_store.py
import json
import pytest
from secubox_core import session_store


@pytest.fixture
def store(tmp_path, monkeypatch):
    p = tmp_path / "sessions.json"
    monkeypatch.setattr(session_store, "SESSIONS_PATH", p)
    session_store.reload()
    return p


def test_unknown_jti_is_rejected(store):
    store.write_text(json.dumps([{"id": "abc"}]))
    session_store.reload()
    assert session_store.is_valid("abc") is True
    assert session_store.is_valid("inconnu") is False


def test_missing_file_is_fail_closed(store):
    """Fichier absent = personne n'entre. Jamais l'inverse."""
    assert not store.exists()
    assert session_store.is_valid("abc") is False


def test_corrupt_file_is_fail_closed(store):
    store.write_text("{ ceci n'est pas du json")
    session_store.reload()
    assert session_store.is_valid("abc") is False


def test_reload_picks_up_new_sessions(store):
    store.write_text(json.dumps([{"id": "un"}]))
    session_store.reload()
    assert session_store.is_valid("deux") is False
    store.write_text(json.dumps([{"id": "un"}, {"id": "deux"}]))
    session_store.reload()
    assert session_store.is_valid("deux") is True


def test_parses_once_until_mtime_changes(store, monkeypatch):
    """Le chemin chaud ne doit pas reparser le fichier à chaque appel."""
    store.write_text(json.dumps([{"id": "un"}]))
    session_store.reload()
    calls = []
    real_loads = json.loads
    monkeypatch.setattr(json, "loads", lambda s, **k: (calls.append(1), real_loads(s, **k))[1])
    for _ in range(50):
        session_store.is_valid("un")
    assert calls == []
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd common && ../.venv/bin/pytest secubox_core/tests/test_session_store.py -v`
Expected : FAIL — `ModuleNotFoundError: No module named 'secubox_core.session_store'`.

- [ ] **Step 3 : implémenter le magasin**

```python
# common/secubox_core/session_store.py
"""Shared, read-mostly session view for every SecuBox service.

`secubox-auth` OWNS /var/lib/secubox/auth/sessions.json (it writes it on every
login and revocation). Every other service only READS it, to answer one
question: is this jti still a live session?

Two properties matter and are load-bearing:

- **Fail-closed.** A missing or corrupt file means nobody is let in. The
  previous default (`lambda jti: True`) meant the opposite, so revocation was
  silently a no-op on the 44 modules routed to their own dedicated socket.
- **Parsed once.** The file is re-read only when its mtime moves, so the hot
  path is a set lookup, never a read() + json.loads().
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional, Set

SESSIONS_PATH = Path(
    os.environ.get("SECUBOX_AUTH_SESSIONS", "/var/lib/secubox/auth/sessions.json")
)

_jtis: Set[str] = set()
_mtime: Optional[float] = None
_loaded = False


def reload() -> None:
    """Force a re-read on the next lookup."""
    global _loaded, _mtime
    _loaded = False
    _mtime = None


def _refresh_if_stale() -> None:
    global _jtis, _mtime, _loaded
    try:
        st = SESSIONS_PATH.stat()
    except OSError:
        _jtis = set()
        _loaded = True
        _mtime = None
        return
    if _loaded and _mtime == st.st_mtime:
        return
    try:
        rows = json.loads(SESSIONS_PATH.read_text())
        _jtis = {r.get("id") for r in rows if isinstance(r, dict) and r.get("id")}
    except (OSError, ValueError, TypeError, AttributeError):
        _jtis = set()
    _mtime = st.st_mtime
    _loaded = True


def is_valid(jti: str) -> bool:
    if not jti:
        return False
    _refresh_if_stale()
    return jti in _jtis
```

- [ ] **Step 4 : brancher le défaut fail-closed**

Dans `common/secubox_core/auth.py`, remplacer la ligne 32 :

```python
from . import session_store

_session_validator: Callable[[str], bool] = session_store.is_valid
```

- [ ] **Step 5 : lancer les tests**

Run : `cd common && ../.venv/bin/pytest secubox_core/tests/ -v`
Expected : PASS.

- [ ] **Step 6 : vérifier que `secubox-auth` écrit bien un mtime neuf**

`_write_sessions()` fait `_SESSIONS_FILE.write_text(...)`, ce qui met l'mtime à jour — les lecteurs le verront. Aucune modification nécessaire, mais le test suivant le fige :

```python
# packages/secubox-auth/tests/test_session_visibility.py
import json
from secubox_core import session_store


def test_revocation_is_visible_to_readers(tmp_path, monkeypatch):
    p = tmp_path / "sessions.json"
    monkeypatch.setattr(session_store, "SESSIONS_PATH", p)
    p.write_text(json.dumps([{"id": "vivante"}]))
    session_store.reload()
    assert session_store.is_valid("vivante") is True
    p.write_text(json.dumps([]))          # secubox-auth révoque
    assert session_store.is_valid("vivante") is False
```

Run : `cd packages/secubox-auth && ../../.venv/bin/pytest tests/test_session_visibility.py -v`
Expected : PASS.

- [ ] **Step 7 : commit**

```bash
git add common/secubox_core/session_store.py common/secubox_core/auth.py \
        common/secubox_core/tests/test_session_store.py \
        packages/secubox-auth/tests/test_session_visibility.py
git commit -m "fix(core): validateur de session fail-closed et partagé par tous les services

Le défaut était lambda jti: True, et seul secubox-auth le remplaçait. Les 44
services tournant dans leur propre interpréteur acceptaient donc n'importe quel
jti : logout, revoke_session et la révocation sur changement de mot de passe
n'avaient aucun effet chez eux.

session_store lit sessions.json en le reparsant uniquement quand son mtime
bouge — le chemin chaud reste une recherche en table. Fichier absent ou
corrompu : personne n'entre."
```

---

### Task 3 : authentifier l'API `secubox-certs`

Le module importe `Depends` mais n'appelle `require_jwt` nulle part. `POST /issue` et `DELETE /revoke/{domain}` sont ouverts, et le snippet nginx commun ajoute `Access-Control-Allow-Origin: *`.

**Files:**
- Modify: `packages/secubox-certs/api/main.py` (tous les décorateurs `@router.*` sauf `/health`)
- Test: `packages/secubox-certs/tests/test_auth_required.py`

**Interfaces:**
- Consumes: `secubox_core.auth.require_jwt` (Task 1)
- Produces: rien

- [ ] **Step 1 : écrire le test qui échoue**

```python
# packages/secubox-certs/tests/test_auth_required.py
import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

PROTECTED = [
    ("get",    "/list"),
    ("get",    "/status"),
    ("get",    "/details/example.com"),
    ("post",   "/check"),
    ("post",   "/issue"),
    ("post",   "/renew/example.com"),
    ("post",   "/renew-all"),
    ("delete", "/revoke/example.com"),
    ("get",    "/metrics"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_endpoint_requires_auth(method, path):
    r = getattr(client, method)(path, json={} if method in ("post",) else None)
    assert r.status_code == 401, f"{method.upper()} {path} accessible sans authentification"


def test_health_stays_public():
    assert client.get("/health").status_code == 200
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd packages/secubox-certs && ../../.venv/bin/pytest tests/test_auth_required.py -v`
Expected : FAIL — tous renvoient 200 au lieu de 401.

- [ ] **Step 3 : implémenter**

En tête de `packages/secubox-certs/api/main.py`, ajouter l'import :

```python
from secubox_core.auth import require_jwt
```

Puis ajouter `dependencies=[Depends(require_jwt)]` à chaque décorateur sauf `/health`. Exemple sur les deux endpoints destructifs :

```python
@router.post("/issue", dependencies=[Depends(require_jwt)])
def issue_certificate(req: CertRequest, background_tasks: BackgroundTasks):
    ...


@router.delete("/revoke/{domain}", dependencies=[Depends(require_jwt)])
def revoke_certificate(domain: str):
    ...
```

- [ ] **Step 4 : lancer le test**

Run : `cd packages/secubox-certs && ../../.venv/bin/pytest tests/test_auth_required.py -v`
Expected : PASS.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-certs/api/main.py packages/secubox-certs/tests/test_auth_required.py
git commit -m "fix(certs): authentifier l'API de gestion des certificats

Le module importait Depends sans jamais appeler require_jwt : POST /issue et
DELETE /revoke/{domain} étaient ouverts, et le snippet proxy commun ajoute
Access-Control-Allow-Origin: * — donc atteignables en cross-origin depuis
n'importe quel site visité sur le LAN. /health reste public (sidebar,
watchdog)."
```

---

### Task 4 : neutraliser la pile d'authentification de `secubox-portal`

`secubox-portal` pointe sur `/etc/secubox/users.json` dans un format incompatible : toute écriture écrase le magasin canonique et rétrograde argon2 vers du SHA-256 non salé, en créant au passage un compte `admin` / `secubox`.

**Files:**
- Modify: `packages/secubox-portal/api/main.py:159-182`
- Test: `packages/secubox-portal/tests/test_no_users_write.py`

**Interfaces:**
- Consumes: `secubox_core.user_store`
- Produces: `_load_users()` délègue en lecture seule ; `_save_users()` lève `RuntimeError`.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# packages/secubox-portal/tests/test_no_users_write.py
import json
import pytest
from api import main as portal


def test_save_users_refuses_to_write(tmp_path, monkeypatch):
    """Le format plat du portal écraserait le schéma v2 et rétrograderait argon2."""
    p = tmp_path / "users.json"
    canonical = {"version": 2, "users": [{"username": "gk2", "password_hash": "$argon2id$..."}]}
    p.write_text(json.dumps(canonical))
    monkeypatch.setattr(portal, "USERS_FILE", p)
    with pytest.raises(RuntimeError):
        portal._save_users({"admin": {"password_hash": "deadbeef", "role": "admin"}})
    assert json.loads(p.read_text()) == canonical


def test_load_users_never_provisions_a_default_admin(tmp_path, monkeypatch):
    p = tmp_path / "users.json"          # absent
    monkeypatch.setattr(portal, "USERS_FILE", p)
    assert portal._load_users() == {}
    assert not p.exists(), "un admin/secubox par défaut a été créé"
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd packages/secubox-portal && ../../.venv/bin/pytest tests/test_no_users_write.py -v`
Expected : FAIL — `_save_users` écrit, et `_load_users` crée `admin` / `secubox`.

- [ ] **Step 3 : implémenter**

Remplacer `_load_users` et `_save_users` dans `packages/secubox-portal/api/main.py` :

```python
def _load_users() -> dict:
    """Read-only view of the canonical store, in the flat shape this module expects.

    secubox-portal predates secubox-users and kept its own SHA-256 store at the
    SAME path as the canonical v2 file. Its writes would erase the argon2
    hashes; its default-admin bootstrap would recreate admin/secubox. Both are
    gone: the canonical store is owned by secubox-users / secubox_core, and
    this module now only reads through it.
    """
    from secubox_core import user_store
    out = {}
    for u in user_store.load_with_fallback().get("users", []):
        name = u.get("username")
        if name:
            out[name] = {"email": u.get("email"), "role": u.get("role", "user")}
    return out


def _save_users(users: dict):
    raise RuntimeError(
        "secubox-portal ne gère plus les identités — utiliser secubox-users "
        "(/etc/secubox/users.json est au schéma v2, argon2)"
    )
```

- [ ] **Step 4 : lancer le test**

Run : `cd packages/secubox-portal && ../../.venv/bin/pytest tests/ -v`
Expected : PASS.

- [ ] **Step 5 : vérifier ce qui casse en aval**

Run : `cd packages/secubox-portal && grep -n "_save_users\|_load_users" api/main.py`
Chaque appelant de `_save_users` (création/suppression d'utilisateur) doit désormais renvoyer un 501. Les remplacer par :

```python
    raise HTTPException(status_code=501,
                        detail="Gestion des comptes déplacée vers secubox-users")
```

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-portal/api/main.py packages/secubox-portal/tests/test_no_users_write.py
git commit -m "fix(portal): retirer la pile d'authentification concurrente

secubox-portal écrivait /etc/secubox/users.json dans un format plat
incompatible avec le schéma v2 : toute écriture écrasait les comptes et
rétrogradait argon2 vers du SHA-256 non salé, et un fichier absent
déclenchait la création d'un admin/secubox. Le module lit désormais le
magasin canonique en lecture seule ; la gestion des comptes appartient à
secubox-users."
```

---

### Task 5 : anti-brute-force sur `/login`

Aucun `limit_req` nginx, aucun compteur d'échecs, aucun verrouillage. La mémoire projet indique que « le WAF est la couche brute-force » — sbxwaf bannit sur signatures regex, pas sur volumétrie d'authentification.

**Files:**
- Create: `packages/secubox-auth/nginx/auth-ratelimit.conf`
- Modify: `packages/secubox-auth/api/main.py` (fonction `_login_v2`)
- Modify: `packages/secubox-auth/debian/secubox-auth.install`
- Test: `packages/secubox-auth/tests/test_login_lockout.py`

**Interfaces:**
- Consumes: `_append_audit`, `_client_meta` (existants)
- Produces: `_lockout_check(username: str) -> None` (lève 429), `_lockout_record_failure(username: str) -> None`, `_lockout_clear(username: str) -> None`

- [ ] **Step 1 : écrire le test qui échoue**

```python
# packages/secubox-auth/tests/test_login_lockout.py
import pytest
from fastapi import HTTPException
from api import main as authmod


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(authmod, "_LOCKOUT", {})


def test_lockout_after_threshold():
    for _ in range(authmod._LOCKOUT_MAX):
        authmod._lockout_record_failure("alice")
    with pytest.raises(HTTPException) as e:
        authmod._lockout_check("alice")
    assert e.value.status_code == 429


def test_below_threshold_is_allowed():
    for _ in range(authmod._LOCKOUT_MAX - 1):
        authmod._lockout_record_failure("alice")
    authmod._lockout_check("alice")          # ne doit pas lever


def test_success_clears_the_counter():
    for _ in range(authmod._LOCKOUT_MAX):
        authmod._lockout_record_failure("alice")
    authmod._lockout_clear("alice")
    authmod._lockout_check("alice")


def test_lockout_is_per_account():
    for _ in range(authmod._LOCKOUT_MAX):
        authmod._lockout_record_failure("alice")
    authmod._lockout_check("bob")            # bob n'est pas puni pour alice
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd packages/secubox-auth && ../../.venv/bin/pytest tests/test_login_lockout.py -v`
Expected : FAIL — `AttributeError: module 'api.main' has no attribute '_LOCKOUT'`.

- [ ] **Step 3 : implémenter le verrouillage**

Ajouter dans `packages/secubox-auth/api/main.py`, avant `_login_v2` :

```python
# ── Verrouillage de compte ────────────────────────────────────────────────
# Par compte et non par IP : derrière HAProxy + nginx la vraie IP est en
# X-Forwarded-For, falsifiable si un vhost oublie de la réécrire, alors que
# le nom de compte est celui que l'attaquant doit deviner.
_LOCKOUT: Dict[str, list] = {}
_LOCKOUT_MAX = 5
_LOCKOUT_WINDOW = 300      # secondes observées
_LOCKOUT_COOLDOWN = 900    # durée du blocage


def _lockout_record_failure(username: str) -> None:
    now = time.time()
    hits = [t for t in _LOCKOUT.get(username, []) if now - t < _LOCKOUT_WINDOW]
    hits.append(now)
    _LOCKOUT[username] = hits


def _lockout_clear(username: str) -> None:
    _LOCKOUT.pop(username, None)


def _lockout_check(username: str) -> None:
    now = time.time()
    hits = [t for t in _LOCKOUT.get(username, []) if now - t < _LOCKOUT_COOLDOWN]
    _LOCKOUT[username] = hits
    if len(hits) >= _LOCKOUT_MAX:
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives — réessayez dans quelques minutes",
        )
```

- [ ] **Step 4 : brancher dans `_login_v2`**

Au tout début de `_login_v2`, après `ip, ua = _client_meta(request)` :

```python
    _lockout_check(req.username)
```

Après chaque `_emit_session_event("login_failed", ...)` de cette fonction, ajouter :

```python
        _lockout_record_failure(req.username)
```

Et juste avant le `return {"access_token": tok, ...}` final :

```python
    _lockout_clear(req.username)
```

- [ ] **Step 5 : lancer les tests**

Run : `cd packages/secubox-auth && ../../.venv/bin/pytest tests/ -v`
Expected : PASS.

- [ ] **Step 6 : ajouter la limite nginx**

```nginx
# packages/secubox-auth/nginx/auth-ratelimit.conf
# /etc/nginx/conf.d/ — la zone doit vivre au niveau http.
#
# Deuxième ligne de défense, devant le verrouillage par compte : celui-ci
# protège UN compte, celle-ci protège le service d'un balayage sur beaucoup
# de comptes. burst=10 nodelay absorbe un utilisateur qui se trompe deux fois
# de suite sans lui infliger d'attente.
limit_req_zone $binary_remote_addr zone=sbx_login:10m rate=10r/m;
```

Puis, dans le fichier de route du module, sur la location du login :

```nginx
location = /api/v1/auth/login {
    limit_req zone=sbx_login burst=10 nodelay;
    limit_req_status 429;
    proxy_pass http://unix:/run/secubox/auth.sock:/login;
    include /etc/nginx/snippets/secubox-proxy.conf;
}
```

- [ ] **Step 7 : vérifier la syntaxe nginx**

Run : `ssh root@192.168.1.200 'nginx -t'`
Expected : `syntax is ok` / `test is successful`.

- [ ] **Step 8 : commit**

```bash
git add packages/secubox-auth/api/main.py packages/secubox-auth/nginx/auth-ratelimit.conf \
        packages/secubox-auth/tests/test_login_lockout.py packages/secubox-auth/debian/secubox-auth.install
git commit -m "feat(auth): verrouillage de compte et limite de débit sur /login

Aucune protection anti-brute-force n'existait sur l'authentification : ni
limit_req, ni compteur d'échecs, ni verrouillage. sbxwaf bannit sur signatures
regex, pas sur volumétrie d'authentification.

Verrouillage par compte (5 échecs / 5 min → 15 min), plus une limite nginx par
IP pour couvrir le balayage multi-comptes."
```

---

### Task 6 : cacher `users.json` sur le chemin chaud

`user_store.get_user()` fait `json.loads(USERS_PATH.read_text())` sans cache. Chaque requête authentifiée, dans l'agrégateur comme dans chacun des 44 processus dédiés, relit et reparse le fichier.

**Files:**
- Modify: `common/secubox_core/user_store.py:29-37`
- Test: `common/secubox_core/tests/test_user_store_cache.py`

**Interfaces:**
- Consumes: rien
- Produces: `_load_users_json()` inchangé côté signature ; ajout de `invalidate_cache() -> None`.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# common/secubox_core/tests/test_user_store_cache.py
import json
from secubox_core import user_store


def _doc(name="gk2"):
    return {"version": 2, "users": [{"username": name, "enabled": True}]}


def test_file_is_parsed_once_when_unchanged(tmp_path, monkeypatch):
    p = tmp_path / "users.json"
    p.write_text(json.dumps(_doc()))
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    user_store.invalidate_cache()
    reads = []
    real = user_store.Path.read_text
    monkeypatch.setattr(user_store.Path, "read_text",
                        lambda self, *a, **k: (reads.append(1), real(self, *a, **k))[1])
    for _ in range(50):
        assert user_store.is_enabled("gk2") is True
    assert len(reads) == 1, f"{len(reads)} lectures pour 50 requêtes"


def test_change_is_picked_up(tmp_path, monkeypatch):
    p = tmp_path / "users.json"
    p.write_text(json.dumps(_doc("gk2")))
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    user_store.invalidate_cache()
    assert user_store.get_user("gk2") is not None
    import os, time
    time.sleep(0.01)
    p.write_text(json.dumps(_doc("admin")))
    os.utime(p, None)
    assert user_store.get_user("admin") is not None
    assert user_store.get_user("gk2") is None
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd common && ../.venv/bin/pytest secubox_core/tests/test_user_store_cache.py -v`
Expected : FAIL — 50 lectures au lieu d'une, et `invalidate_cache` n'existe pas.

- [ ] **Step 3 : implémenter**

Remplacer `_load_users_json` dans `common/secubox_core/user_store.py` :

```python
_cache_doc: Optional[Dict[str, Any]] = None
_cache_mtime: Optional[float] = None
_cache_loaded = False


def invalidate_cache() -> None:
    """Force a re-read on the next access (tests, and after a local write)."""
    global _cache_loaded, _cache_mtime, _cache_doc
    _cache_loaded = False
    _cache_mtime = None
    _cache_doc = None


def _load_users_json() -> Optional[Dict[str, Any]]:
    """Return the v2 doc or None, re-reading only when the file's mtime moves.

    This sits on the hot path: every authenticated request reaches it through
    require_jwt → is_enabled → get_user. Without the mtime guard each request
    re-read and re-parsed the whole file, in the aggregator and in each of
    the 44 dedicated service processes.
    """
    global _cache_doc, _cache_mtime, _cache_loaded
    try:
        st = USERS_PATH.stat()
    except OSError:
        _cache_doc, _cache_loaded, _cache_mtime = None, True, None
        return None
    if _cache_loaded and _cache_mtime == st.st_mtime:
        return _cache_doc
    try:
        _cache_doc = json.loads(USERS_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("user_store: users.json unreadable (%s)", exc)
        _cache_doc = None
    _cache_mtime = st.st_mtime
    _cache_loaded = True
    return _cache_doc
```

Et dans `_atomic_write_users`, juste après `os.replace(tmp, USERS_PATH)` :

```python
        invalidate_cache()
```

- [ ] **Step 4 : lancer toute la suite**

Run : `cd common && ../.venv/bin/pytest secubox_core/tests/ -v`
Expected : PASS — y compris les tests existants qui écrivent `users.json`.

- [ ] **Step 5 : mesurer le gain**

```bash
cd common && ../.venv/bin/python -c "
import json, time, tempfile, os
from pathlib import Path
from secubox_core import user_store
d = Path(tempfile.mkdtemp())/'users.json'
d.write_text(json.dumps({'version':2,'users':[{'username':f'u{i}','enabled':True} for i in range(50)]}))
user_store.USERS_PATH = d; user_store.invalidate_cache()
t=time.perf_counter()
for _ in range(10000): user_store.is_enabled('u25')
print(f'{(time.perf_counter()-t)/10000*1e6:.1f} us/appel')
"
```

Consigner la valeur dans le message de commit.

- [ ] **Step 6 : commit**

```bash
git add common/secubox_core/user_store.py common/secubox_core/tests/test_user_store_cache.py
git commit -m "perf(core): ne plus reparser users.json à chaque requête authentifiée

get_user() faisait json.loads(read_text()) sans cache, et il est sur le chemin
chaud : require_jwt → is_enabled → get_user, à chaque requête, sur chacun des
chaque processus de service. Le fichier n'est relu que quand son mtime bouge ;
_atomic_write_users invalide le cache après écriture."
```

---

### Task 7 : test de non-régression de bout en bout

Fige les quatre failles pour qu'elles ne puissent pas revenir.

**Files:**
- Create: `tests/cspn/test_auth_regression.py`

**Interfaces:**
- Consumes: tout ce qui précède
- Produces: rien

- [ ] **Step 1 : écrire le test**

```python
# tests/cspn/test_auth_regression.py
"""Régressions de sécurité figées — phase 0 de SwitchSBX.

Chacun de ces tests échoue sur le code antérieur au 2026-07-31. Ils ne
testent pas une implémentation mais une PROPRIÉTÉ : si l'un casse, une faille
connue est revenue.
"""
import inspect
import pytest
from secubox_core import auth, session_store, user_store


def test_A_scoped_token_is_never_full_access(monkeypatch):
    auth.set_session_validator(lambda jti: True)
    monkeypatch.setattr(auth.user_store, "is_enabled", lambda u: True)
    for scope in ("mfa-challenge", "set-password", "totp-enroll"):
        tok = auth.create_token("victime", scope=scope)
        assert auth._validate_token(tok) is None, f"scope {scope} accepté"


def test_B_default_session_validator_is_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "SESSIONS_PATH", tmp_path / "absent.json")
    session_store.reload()
    assert session_store.is_valid("nimporte") is False


def test_C_certs_api_is_authenticated():
    import importlib
    m = importlib.import_module("api.main")          # depuis packages/secubox-certs
    for route in m.app.routes:
        path = getattr(route, "path", "")
        if path.endswith("/health") or not path.startswith("/"):
            continue
        deps = getattr(route, "dependencies", [])
        assert deps, f"{path} sans dépendance d'authentification"


def test_D_portal_cannot_write_users_json():
    import importlib
    p = importlib.import_module("api.main")          # depuis packages/secubox-portal
    with pytest.raises(RuntimeError):
        p._save_users({"admin": {"password_hash": "x"}})


def test_user_store_has_an_mtime_guard():
    src = inspect.getsource(user_store._load_users_json)
    assert "st_mtime" in src, "le cache mtime a disparu du chemin chaud"
```

- [ ] **Step 2 : lancer**

Run : `cd tests/cspn && ../../.venv/bin/pytest test_auth_regression.py -v`
Expected : PASS pour A, B, E. C et D nécessitent le `sys.path` du paquet concerné — les exécuter depuis leur répertoire, ou les marquer `pytest.importorskip`.

- [ ] **Step 3 : commit**

```bash
git add tests/cspn/test_auth_regression.py
git commit -m "test(cspn): figer les quatre régressions d'authentification de la phase 0"
```

---

## Critères de sortie de la phase 0

- [ ] Un jeton de scope ne satisfait plus `Depends(require_jwt)` sur aucun module.
- [ ] Un `sessions.json` absent ou corrompu refuse tout le monde.
- [ ] Une révocation depuis `secubox-auth` est visible par un module à socket dédiée.
- [ ] `POST /issue` et `DELETE /revoke/{domain}` de `secubox-certs` renvoient 401 sans jeton.
- [ ] `secubox-portal` ne peut plus écrire `users.json`.
- [ ] 6 échecs de connexion sur un compte renvoient 429.
- [ ] `users.json` est lu une fois, pas à chaque requête — gain mesuré et consigné.
- [ ] `tests/cspn/test_auth_regression.py` passe.

## Déploiement

`secubox_core` est partagé : après build, redéployer **tous** les paquets qui l'embarquent, puis redémarrer les services **séquentiellement** — jamais en parallèle (111 daemons redémarrés ensemble provoquent une panne de troupeau). Attendre la socket de chacun avant de passer au suivant.

Synchroniser les `.deb` vers `apt.secubox.in` (`reprepro includedeb` dans `/data/apt` sur gk2) après le build : une installation directe sur la board seule crée une dérive.
