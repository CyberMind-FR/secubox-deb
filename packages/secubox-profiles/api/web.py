# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — API web (Phase 1, LECTURE SEULE + état désiré)
CyberMind — https://cybermind.fr

Expose l'inventaire (status/profiles/pins/diff) et les DEUX seules écritures
autorisées en Phase 1 : ajouter/retirer un module de la liste `on` d'un
profil, poser/lever un pin. Aucune route ne démarre/arrête/active/désactive
quoi que ce soit — `apply` n'existe pas encore (Phase 3, avec snapshot 4R et
audit). Ce service tourne sur son PROPRE socket
(`/run/secubox/profiles.sock`), jamais via l'aggregator : le moteur de
profils ne doit pas dépendre de quelque chose qu'il pourrait plus tard
redémarrer.

Deux règles structurelles, indépendantes de diff.plan_changes :
  * un pin qui éteindrait un module protégé est refusé ICI, à l'écriture
    (HTTP 409), AVANT toute tentative d'écrire pins.toml — sinon un
    utilisateur qui ne consulte jamais /diff après coup se serait déjà
    verrouillé hors de sa propre box ;
  * un état de sonde indéterminé (Actual.enabled/active à None) ne devient
    JAMAIS "off" dans les réponses API — il reste "unknown", distinct de
    "on"/"off". `observe.is_on()` coalesce None -> False, ce qui est correct
    pour une DÉCISION actionnable (diff/plan_changes) mais mentirait ici,
    dans une vue d'inventaire.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

# Miroir du layout runtime (/usr/lib/secubox/profiles) : secubox_core est un
# paquet Debian dist-packages, jamais un venv (voir secubox-users, même
# topologie de service : socket dédié, system python3).
sys.path.insert(0, "/usr/lib/python3/dist-packages")
try:
    from secubox_core.auth import require_jwt
except ImportError:  # pragma: no cover - dev sans secubox_core installé
    async def require_jwt():
        return {"sub": "admin"}

from . import cli as _cli
from .diff import ProtectedViolation, plan_changes
from .lifecycle import effective_lifecycle, is_sleepable, wake_budget
from .manifest import LIFECYCLES, WAKE_CLASSES, ManifestError, load_all
from .observe import Actual, is_on, load_routes
from .scan import _toml_list, _toml_str
from .state import OFF, ON, Profile, StateError, load_pins, load_profile

DEFAULT_ROOT = Path("/etc/secubox")


def _root() -> Path:
    """Racine de config — surchageable en test via SECUBOX_PROFILES_ROOT
    (miroir du `--root` du CLI, lu à chaque requête pour rester testable)."""
    return Path(os.environ.get("SECUBOX_PROFILES_ROOT", str(DEFAULT_ROOT)))


def _tri_state(a: Actual) -> str:
    """"on" | "off" | "unknown" — jamais un booléen qui effacerait le doute.

    `enabled`/`active` à None signifie que la sonde n'a pas pu s'exécuter
    (voir observe._run_cmd) : indéterminé, pas "off". Seul le cas où les DEUX
    ont pu être observés autorise une réponse "on"/"off" définitive."""
    if a.enabled is None or a.active is None:
        return "unknown"
    return ON if (a.enabled and a.active) else OFF


def _atomic_write(path: Path, content: str) -> None:
    """Écriture atomique : fichier temporaire dans le même répertoire (donc
    même filesystem, `os.replace` est atomique) puis swap. Un crash à
    n'importe quel point avant `os.replace` laisse l'original intact — un
    profil/pins.toml corrompu à mi-écriture n'est pas une option ici, il fait
    ensuite autorité pour tout le module."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _write_profile(path: Path, profile: Profile) -> None:
    lines = [
        "# SPDX-License-Identifier: LicenseRef-CMSD-1.0",
        "# Profil réécrit par l'API secubox-profiles — Phase 1 n'applique rien",
        "# automatiquement (apply arrive en Phase 3, avec snapshot 4R + audit).",
        f"name  = {_toml_str(profile.name)}",
        f"label = {_toml_str(profile.label)}",
        f"on    = {_toml_list(sorted(profile.on))}",
    ]
    _atomic_write(path, "\n".join(lines) + "\n")


def _write_pins(path: Path, pins: dict) -> None:
    lines = [
        "# SPDX-License-Identifier: LicenseRef-CMSD-1.0",
        "# Pins réécrits par l'API secubox-profiles. Un pin protégé sur 'off'",
        "# est refusé AVANT d'atteindre ce fichier (voir POST /pins, HTTP 409).",
    ]
    for mid in sorted(pins):
        lines.append(f"{_toml_str(mid)} = {_toml_str(pins[mid])}")
    _atomic_write(path, "\n".join(lines) + "\n")


def _build_status_payload(manifests: dict, actuals: dict) -> dict:
    modules = []
    totals = {"count": 0, "on": 0, "off": 0, "unknown": 0, "rss_kb": 0, "exposed_public": 0}
    by_category: dict = {}
    by_runtime: dict = {}
    by_exposure: dict = {}

    def bump(bucket: dict, key: str, state: str, rss: Optional[int]) -> None:
        b = bucket.setdefault(key, {"count": 0, "on": 0, "off": 0, "unknown": 0, "rss_kb": 0})
        b["count"] += 1
        b[state] += 1
        if rss:
            b["rss_kb"] += rss

    for mid, m in sorted(manifests.items()):
        a = actuals.get(mid, Actual())
        st = _tri_state(a)
        # sleep_state ("up"/"asleep"/"n/a") is a SEPARATE axis from the
        # observation tri-state `st` above: `st` can be "unknown" (probe
        # failed) while sleep_state still has an actionable answer, because
        # it reuses is_on()'s None -> False coalescing (same posture as
        # observe.is_on's own docstring: correct for a DECISION, wrong for an
        # inventory view — which is exactly what this field is for, a
        # manual-action affordance, not a status display of doubt).
        # "waking" (mid-wake-up) is deliberately NOT modeled here: the only
        # candidate signal (waker-active.json, api/waker.py) is a best-effort
        # anti-storm lock, not a reliable "in progress" probe — surfacing it
        # as a third state would be a fragile guess. Deferred.
        eff = effective_lifecycle(m)
        if eff in ("always-on", "manual"):
            sleep_state = "n/a"
            budget = None
        else:
            sleep_state = "up" if is_on(a) else "asleep"
            budget = wake_budget(m)
        modules.append({
            "id": mid, "category": m.category, "runtime": m.runtime,
            "exposure": m.exposure, "priority": m.priority,
            "protected": m.protected, "on": st, "rss_kb": a.rss_kb,
            "lifecycle": eff, "wake_class": m.wake_class,
            "sleep_state": sleep_state, "wake_budget_s": budget,
            "portal_domain": m.portal_domain,
        })
        totals["count"] += 1
        totals[st] += 1
        if a.rss_kb:
            totals["rss_kb"] += a.rss_kb
        if m.exposure == "public":
            totals["exposed_public"] += 1
        bump(by_category, m.category, st, a.rss_kb)
        bump(by_runtime, m.runtime, st, a.rss_kb)
        bump(by_exposure, m.exposure, st, a.rss_kb)

    return {
        "modules": modules,
        "totals": totals,
        "by_category": by_category,
        "by_runtime": by_runtime,
        "by_exposure": by_exposure,
    }


# ---------------------------------------------------------------------------
# /status cache — pattern "double caching" imposé par le CLAUDE.md du projet
# (Performance Patterns) : le calcul (observe_all -> systemctl/lxc-ls) tourne
# hors de la boucle asyncio (asyncio.to_thread), jamais dessus. Ce service
# tourne sur son propre socket, mais la board a déjà vu un appel bloquant sur
# une boucle PARTAGÉE geler ~110 modules (voir aggregator) : même seul,
# `observe_all` reste hors-loop par prudence/cohérence avec le reste du parc.
#
# TTL 60s. Clé = racine de config (str(root)) plutôt qu'une clé globale
# unique : chaque test utilise un tmp_path distinct comme racine, donc chaque
# test obtient naturellement un cache froid et recalcule sur ses propres
# doubles — aucune fuite d'état entre tests, sans changer un seul test
# existant. En production il n'y a qu'une racine (/etc/secubox), donc un seul
# slot de cache actif.
# ---------------------------------------------------------------------------

_STATUS_CACHE_TTL_S = 60.0


class _StatusCacheEntry:
    __slots__ = ("payload", "computed_at")

    def __init__(self, payload: dict, computed_at: float):
        self.payload = payload
        self.computed_at = computed_at


_status_cache: dict[str, _StatusCacheEntry] = {}
_status_locks: dict[str, asyncio.Lock] = {}


def _status_lock(key: str) -> asyncio.Lock:
    lock = _status_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _status_locks[key] = lock
    return lock


def _compute_status_payload(root: Path) -> dict:
    """Bloquant (subprocess via observe_all) — appeler uniquement via
    asyncio.to_thread, jamais directement dans une coroutine d'endpoint."""
    mod_dir, _prof_dir, _pins_file, _active_file = _cli._paths(root)
    manifests = _load_manifests_or_500(mod_dir)
    routes = load_routes()
    actuals = _cli._observe_all(manifests, routes)
    return _build_status_payload(manifests, actuals)


def _with_freshness(entry: _StatusCacheEntry) -> dict:
    age_s = max(0.0, time.time() - entry.computed_at)
    return {
        **entry.payload,
        "cached_at": datetime.fromtimestamp(entry.computed_at, tz=timezone.utc).isoformat(),
        "age_s": round(age_s, 1),
    }


async def _get_status_cached(root: Path) -> dict:
    key = str(root)
    entry = _status_cache.get(key)
    if entry is not None and (time.time() - entry.computed_at) < _STATUS_CACHE_TTL_S:
        return _with_freshness(entry)

    async with _status_lock(key):
        # Un autre appel concurrent a pu rafraîchir pendant l'attente du lock.
        entry = _status_cache.get(key)
        if entry is not None and (time.time() - entry.computed_at) < _STATUS_CACHE_TTL_S:
            return _with_freshness(entry)
        # Cache froid : on calcule une fois plutôt que de renvoyer une
        # erreur — /status doit toujours répondre, même au tout premier appel.
        payload = await asyncio.to_thread(_compute_status_payload, root)
        entry = _StatusCacheEntry(payload=payload, computed_at=time.time())
        _status_cache[key] = entry
        return _with_freshness(entry)


async def _status_cache_refresher() -> None:
    """Rafraîchissement proactif en arrière-plan (motif CLAUDE.md) : une
    requête ne devrait quasiment jamais payer le coût du calcul, seulement le
    tout premier appel après démarrage. Une erreur de rafraîchissement ne
    doit ni planter le service ni effacer un cache encore valide — on
    réessaiera au tour suivant."""
    while True:
        try:
            root = _root()
            payload = await asyncio.to_thread(_compute_status_payload, root)
            _status_cache[str(root)] = _StatusCacheEntry(payload=payload, computed_at=time.time())
        except Exception:
            pass
        await asyncio.sleep(_STATUS_CACHE_TTL_S)


def _load_manifests_or_500(mod_dir: Path) -> dict:
    try:
        return load_all(mod_dir)
    except ManifestError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _load_pins_or_500(pins_file: Path) -> dict:
    try:
        return load_pins(pins_file)
    except StateError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


class MemberUpdate(BaseModel):
    id: str
    on: bool


class PinUpdate(BaseModel):
    id: str
    pin: Optional[str] = None


class ActiveUpdate(BaseModel):
    name: str


class ApplyRequest(BaseModel):
    profile: str


class ModuleAction(BaseModel):
    module: str


class LifecycleUpdate(BaseModel):
    module: str
    lifecycle: str
    wake_class: str = "normal"


# Sérialise TOUTE écriture du fichier `active` partagé + toute actuation
# (apply/rollback) en un seul verrou async, dans ce process. Corrige un TOCTOU
# structurel : entre la préview d'un opérateur (GET /diff) et sa confirmation
# (POST /apply), un second onglet/admin pouvait réécrire `active` avec un
# AUTRE profil — l'apply exécuté ensuite par `secubox-profilectl apply --yes`
# recalculait alors son plan à partir de CE profil différent, silencieusement.
# Le remède : /apply prend désormais le profil à actuer en paramètre, réécrit
# `active` avec CE profil précis puis actue, le tout sous le même verrou que
# /active et /rollback — aucune de ces routes ne peut plus s'entrelacer.
# NB : verrou PROCESS-LOCAL — correct uniquement parce que le service tourne en
# un seul worker uvicorn (ExecStart sans --workers). Ne PAS ajouter --workers>1
# sans passer à un verrou inter-process (flock), sinon la sérialisation saute.
_apply_lock = asyncio.Lock()


def _ctl_run(argv, **kw):
    import subprocess
    return subprocess.run(argv, capture_output=True, text=True, timeout=1800, **kw)


async def _run_ctl_json_argv(argv: list[str]) -> dict:
    """Corps partagé par tout appel webui→ctl synchrone (--wait --pipe) :
    exécute l'argv FIXE (voir /etc/sudoers.d/secubox-profiles) via
    `_ctl_run`, hors-loop (to_thread), et parse le rapport JSON s'il existe.

    IMPORTANT — on lance le CLI via `systemd-run`, PAS un simple `sudo …ctl` :
    ce service tourne en ProtectSystem=strict avec un ReadWritePaths réduit, et
    un enfant `sudo` HÉRITE de ce namespace de montage → le CLI verrait
    /var/lib/secubox/profiles/rollback (snapshot), /var/log/secubox (audit),
    /etc/secubox/waf (routes) et /data/lxc en READ-ONLY (EROFS observé). Une
    unité transitoire `systemd-run` s'exécute dans le contexte de PID 1, HORS
    du sandbox, avec tous les accès nécessaires pour piloter systemd/LXC et
    écrire ces chemins. `--wait` = synchrone, `--pipe` = on récupère le JSON du
    CLI sur stdout, `--collect --quiet` = nettoyage + pas de bruit systemd-run.

    Le rapport est parsé EN PREMIER, avant tout regard sur le rc : apply/
    rollback/wake émettent tous un --json report même quand ils se replient
    (apply rolled_back, wake refused) — le surfacer est bien plus utile à
    l'opérateur/panel qu'une chaîne d'erreur tronquée ; c'est l'appelant HTTP
    qui classe applied/refused/rolled_back, pas cette fonction. Ce n'est
    qu'à défaut de JSON parseable qu'on retombe sur un échec HTTP (409 pour
    le rc=3 conventionnel de refus protégé, 500 sinon)."""
    import asyncio as _a
    import json as _json
    proc = await _a.to_thread(_ctl_run, argv)
    try:
        report = _json.loads(proc.stdout)
    except ValueError:
        report = None
    if isinstance(report, dict) and "status" in report:
        return report
    # No parseable report → a genuine failure. rc=3 is the protected-STOP
    # refusal (no JSON report is emitted on that path).
    if proc.returncode == 3:
        raise HTTPException(status_code=409, detail=(proc.stderr or proc.stdout).strip()[:300])
    raise HTTPException(status_code=500,
                        detail=f"ctl échoué: {(proc.stderr or proc.stdout).strip()[:300]}")


async def _run_ctl_json(verb: str) -> dict:
    argv = ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe",
            "--collect", "--quiet",
            "/usr/sbin/secubox-profilectl", verb, "--yes", "--json"]
    return await _run_ctl_json_argv(argv)


async def _run_wake_ctl(module: str) -> dict:
    """Réveil manuel (panel) — synchrone (--wait --pipe), DIFFÉRENT du réveil
    fire-and-forget du waker (api/waker.py::_fire_wake, pas de --wait/--pipe) :
    le panel attend et affiche le report, le waker rend la main tout de suite
    pour ne jamais bloquer une requête HTTP publique sur l'issue du réveil.
    Deux argv distincts => deux grants sudoers distincts (voir
    sudoers.d/secubox-profiles)."""
    argv = ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe",
            "--collect", "--quiet",
            "/usr/sbin/secubox-wakectl", "wake", module, "--json"]
    return await _run_ctl_json_argv(argv)


async def _run_setlifecycle_ctl(module: str, lifecycle: str, wake_class: str) -> dict:
    """Fixe le niveau d'éveil d'un module — écrit le manifeste root:root, d'où
    la délégation au ctl root (webui→ctl + systemd-run, comme apply/rollback).
    L'appelant a DÉJÀ validé module connu + lifecycle/wake_class ∈ énum (422/404)
    avant d'arriver ici, donc l'argv construit est toujours (module, valeur
    d'énum, valeur d'énum) — le ctl revalide malgré tout (argparse choices=)."""
    argv = ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe",
            "--collect", "--quiet",
            "/usr/sbin/secubox-profilectl", "set-lifecycle", module,
            "--lifecycle", lifecycle, "--wake-class", wake_class, "--json"]
    return await _run_ctl_json_argv(argv)


async def _run_sleep_ctl(module: str) -> dict:
    """Sommeil manuel (panel) — réutilise l'actionneur `apply` du profilectl
    déjà grant-é, restreint à CE module via `--only` : plan_changes calcule
    déjà un STOP pour tout module sleepable actuellement up et non désiré ON
    (absent du profil actif / non épinglé on), donc `--only <module>` isole
    correctement l'effet à ce seul module sans réimplémenter d'actionneur
    dédié. Si le module EST désiré ON (listé dans le profil actif / épinglé
    on), le plan filtré est vide et l'appel est un no-op sûr — le panel/
    l'opérateur voit alors `changed: []` plutôt qu'un module qui se
    rendormirait aussitôt reconverge."""
    argv = ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe",
            "--collect", "--quiet",
            "/usr/sbin/secubox-profilectl", "apply", "--only", module, "--yes", "--json"]
    return await _run_ctl_json_argv(argv)


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecuBox Profiles API",
        description="Inventaire et profils de modules — Phase 1 (lecture seule + état désiré).",
        version="1.0.0",
        docs_url="/docs",
        redoc_url=None,
    )

    @app.on_event("startup")
    async def _start_status_refresher() -> None:
        # Fire-and-forget background task (motif CLAUDE.md « Performance
        # Patterns — Double Caching »). N'est pas nécessaire à la correction
        # de /status (voir _get_status_cached : cache froid = calcul direct,
        # jamais d'erreur) — seulement à garder le cache chaud en continu sur
        # le service réel.
        asyncio.create_task(_status_cache_refresher())

    @app.get("/api/v1/profiles/status")
    async def get_status(_claims=Depends(require_jwt)):
        return await _get_status_cached(_root())

    @app.get("/api/v1/profiles/lifecycles")
    async def get_lifecycles():
        # Agregat NON-SENSIBLE (id + lifecycle + sleep_state), SANS JWT — meme
        # posture que l'API DPI /pub (agrege, lecture seule). Sert de SOURCE DE
        # VERITE UNIQUE au Hall pour piloter le mode de sonde des cardlets : un
        # cardlet dont le module est `on-demand` passe en mode econome (sonde
        # only-when-visible, lit un cache quand `asleep`, ne reveille jamais en
        # fond) ; `always-on` sonde live. N'expose ni rss, ni exposure, ni
        # topologie — rien qui justifie un JWT. Reutilise le cache de /status.
        payload = await _get_status_cached(_root())
        # portal_domain (le vhost, déjà public — c'est l'URL des cartes) est
        # ajouté pour que le Hall mappe une carte à son module et propose un
        # réveil (POST /wake, JWT) piloté par le lifecycle. On n'expose toujours
        # ni rss, ni exposure, ni interne.
        return {"lifecycles": [
            {"id": m["id"], "lifecycle": m["lifecycle"],
             "sleep_state": m["sleep_state"],
             "portal_domain": m.get("portal_domain")}
            for m in payload.get("modules", [])
        ]}

    @app.get("/api/v1/profiles/profiles")
    async def list_profiles(_claims=Depends(require_jwt)):
        root = _root()
        _mod_dir, prof_dir, _pins_file, active_file = _cli._paths(root)
        out = []
        for p in sorted(Path(prof_dir).glob("*.toml")):
            try:
                prof = load_profile(p)
            except StateError:
                # Un profil individuel invalide ne doit pas faire échouer la
                # liste entière — il est simplement absent, à corriger.
                continue
            out.append({"name": prof.name, "label": prof.label, "on": sorted(prof.on)})
        active = None
        if Path(active_file).exists():
            active = Path(active_file).read_text(encoding="utf-8").strip() or None
        return {"profiles": out, "active": active}

    @app.get("/api/v1/profiles/pins")
    async def get_pins(_claims=Depends(require_jwt)):
        root = _root()
        _mod_dir, _prof_dir, pins_file, _active = _cli._paths(root)
        return {"pins": _load_pins_or_500(pins_file)}

    @app.get("/api/v1/profiles/diff")
    async def get_diff(profile: Optional[str] = None, _claims=Depends(require_jwt)):
        root = _root()
        mod_dir, _prof_dir, pins_file, _active = _cli._paths(root)
        manifests = _load_manifests_or_500(mod_dir)
        name = _cli._active_profile_name(root, profile)
        try:
            prof = _cli._load_profile_or_none(root, name)
        except StateError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        pins = _load_pins_or_500(pins_file)
        actuals = _cli._observe_all(manifests, load_routes())
        try:
            changes = plan_changes(manifests, prof, pins, actuals)
        except ProtectedViolation as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "profile": name,
            "changes": [
                {"id": c.id, "action": c.action, "reason": c.reason, "priority": c.priority}
                for c in changes
            ],
        }

    @app.post("/api/v1/profiles/profiles/{name}/members")
    async def set_member(name: str, body: MemberUpdate, _claims=Depends(require_jwt)):
        root = _root()
        mod_dir, prof_dir, _pins_file, _active = _cli._paths(root)
        prof_path = Path(prof_dir) / f"{name}.toml"
        if not prof_path.exists():
            raise HTTPException(status_code=404, detail=f"profil inconnu: {name}")
        manifests = _load_manifests_or_500(mod_dir)
        if body.id not in manifests:
            raise HTTPException(status_code=404, detail=f"module inconnu: {body.id}")
        try:
            prof = load_profile(prof_path)
        except StateError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        new_on = set(prof.on)
        if body.on:
            new_on.add(body.id)
        else:
            new_on.discard(body.id)
        updated = Profile(name=prof.name, label=prof.label, on=frozenset(new_on))
        _write_profile(prof_path, updated)
        return {"name": updated.name, "label": updated.label, "on": sorted(updated.on)}

    @app.post("/api/v1/profiles/pins")
    async def set_pin(body: PinUpdate, _claims=Depends(require_jwt)):
        if body.pin not in (None, ON, OFF):
            raise HTTPException(status_code=400, detail="pin doit être 'on', 'off' ou null")
        root = _root()
        mod_dir, _prof_dir, pins_file, _active = _cli._paths(root)
        manifests = _load_manifests_or_500(mod_dir)
        m = manifests.get(body.id)
        if m is None:
            raise HTTPException(status_code=404, detail=f"module inconnu: {body.id}")
        # Refus STRUCTUREL, indépendant de diff.plan_changes : un pin qui
        # éteindrait un module protégé ne doit JAMAIS atteindre le disque.
        # plan_changes lève bien ProtectedViolation, mais seulement au moment
        # où /diff est consulté — trop tard si l'utilisateur ne le consulte
        # jamais après coup : pins.toml serait déjà corrompu par une valeur
        # qui verrouille la box (hard constraint #3 du plan).
        if body.pin == OFF and m.protected:
            raise HTTPException(
                status_code=409,
                detail=f"{body.id} est protégé et ne peut pas être épinglé sur 'off'",
            )
        pins = _load_pins_or_500(pins_file)
        if body.pin is None:
            pins.pop(body.id, None)
        else:
            pins[body.id] = body.pin
        _write_pins(Path(pins_file), pins)
        return {"pins": pins}

    @app.post("/api/v1/profiles/active")
    async def set_active(body: ActiveUpdate, _claims=Depends(require_jwt)):
        root = _root()
        _mod, prof_dir, _pins, active_file = _cli._paths(root)
        async with _apply_lock:
            if not (Path(prof_dir) / f"{body.name}.toml").exists():
                raise HTTPException(status_code=404, detail=f"profil inconnu: {body.name}")
            _atomic_write(Path(active_file), body.name + "\n")
            return {"active": body.name}

    @app.post("/api/v1/profiles/apply")
    async def apply_active(body: ApplyRequest, _claims=Depends(require_jwt)):
        # Actue TOUJOURS le profil demandé par CET appel : on réécrit `active`
        # avec body.profile puis on lance le CLI, sous le même verrou. Si le CLI
        # se replie (rolled_back), l'état système est revenu au profil PRÉCÉDENT
        # — `active` doit donc repointer dessus, sinon le pointeur ment (il
        # nommerait un profil qui n'a jamais pris). L'argv sudo reste FIXE.
        root = _root()
        _mod, prof_dir, _pins, active_file = _cli._paths(root)
        active_path = Path(active_file)
        async with _apply_lock:
            if not (Path(prof_dir) / f"{body.profile}.toml").exists():
                raise HTTPException(status_code=404, detail=f"profil inconnu: {body.profile}")
            prior = active_path.read_text(encoding="utf-8") if active_path.exists() else None
            _atomic_write(active_path, body.profile + "\n")
            report = await _run_ctl_json("apply")
            if isinstance(report, dict) and report.get("status") == "rolled_back":
                if prior is None:
                    active_path.unlink(missing_ok=True)
                else:
                    _atomic_write(active_path, prior)
            return report

    @app.post("/api/v1/profiles/rollback")
    async def rollback_active(_claims=Depends(require_jwt)):
        # A rollback restores an ARBITRARY point-in-time snapshot, which has no
        # associated profile name — unlike /apply, there is no "prior profile"
        # to revert `active` to. On a SUCCESSFUL rollback the honest state
        # afterward is "no named profile / custom": clear the pointer rather
        # than leave it naming whatever profile the last /apply set, which no
        # longer matches the (rolled-back) board state. Success predicate
        # mirrors the CLI's own (see api/cli.py _cmd_rollback: rc 0 iff
        # status in ("applied", "planned")) — "planned" is not structurally
        # reachable here (the ctl is always invoked with --yes) but matching
        # the CLI's exact predicate beats an ad-hoc single-value check.
        root = _root()
        _mod, _prof_dir, _pins, active_file = _cli._paths(root)
        active_path = Path(active_file)
        async with _apply_lock:
            report = await _run_ctl_json("rollback")
            if isinstance(report, dict) and report.get("status") in ("applied", "planned"):
                active_path.unlink(missing_ok=True)
            return report

    def _sleepable_module_or_error(mod_dir, module: str):
        """Refus STRUCTUREL, comme la refus-avant-écriture des pins (voir
        set_pin) : un module inconnu ou non-endormable (always-on/manual, y
        compris protected forcé always-on) ne doit JAMAIS déclencher un appel
        sudo — il est rejeté ICI, avant que /wake ou /sleep ne shell out."""
        manifests = _load_manifests_or_500(mod_dir)
        m = manifests.get(module)
        if m is None:
            raise HTTPException(status_code=404, detail=f"module inconnu: {module}")
        if not is_sleepable(m):
            raise HTTPException(
                status_code=409,
                detail=f"{module} n'est pas endormable (lifecycle={effective_lifecycle(m)})",
            )
        return m

    @app.post("/api/v1/profiles/wake")
    async def wake_module(body: ModuleAction, _claims=Depends(require_jwt)):
        root = _root()
        mod_dir, _prof_dir, _pins_file, _active = _cli._paths(root)
        _sleepable_module_or_error(mod_dir, body.module)
        async with _apply_lock:
            return await _run_wake_ctl(body.module)

    @app.post("/api/v1/profiles/sleep")
    async def sleep_module(body: ModuleAction, _claims=Depends(require_jwt)):
        root = _root()
        mod_dir, _prof_dir, _pins_file, _active = _cli._paths(root)
        _sleepable_module_or_error(mod_dir, body.module)
        async with _apply_lock:
            return await _run_sleep_ctl(body.module)

    @app.post("/api/v1/profiles/lifecycle")
    async def set_lifecycle_route(body: LifecycleUpdate, _claims=Depends(require_jwt)):
        """Fixe le niveau d'éveil (lifecycle + wake_class) d'un module. Refus
        STRUCTUREL avant tout sudo (comme /wake, /sleep, set_pin) : valeur hors
        énum -> 422, module inconnu -> 404. L'écriture du manifeste + resync est
        déléguée au ctl root."""
        if body.lifecycle not in LIFECYCLES:
            raise HTTPException(status_code=422,
                                detail=f"lifecycle invalide: {body.lifecycle} (attendu {list(LIFECYCLES)})")
        if body.wake_class not in WAKE_CLASSES:
            raise HTTPException(status_code=422,
                                detail=f"wake_class invalide: {body.wake_class} (attendu {list(WAKE_CLASSES)})")
        root = _root()
        mod_dir, _prof_dir, _pins_file, _active = _cli._paths(root)
        manifests = _load_manifests_or_500(mod_dir)
        m = manifests.get(body.module)
        if m is None:
            raise HTTPException(status_code=404, detail=f"module inconnu: {body.module}")
        # Refus STRUCTUREL comme set_pin : un module protégé est forcé always-on
        # (effective_lifecycle), fixer son niveau d'éveil n'aurait aucun effet et
        # ne ferait que salir un manifeste du cœur — jamais de sudo pour ça.
        if m.protected:
            raise HTTPException(status_code=409,
                                detail=f"{body.module} est protégé (toujours actif) — "
                                       "niveau d'éveil non modifiable")
        async with _apply_lock:
            return await _run_setlifecycle_ctl(body.module, body.lifecycle, body.wake_class)

    return app


app = create_app()
