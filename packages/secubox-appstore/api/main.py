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
import tomllib
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from secubox_core.auth import require_lecture
from secubox_core.auth import require_jwt
from pydantic import BaseModel

CATALOG_FILE = Path(os.environ.get(
    "APPSTORE_CATALOG", "/usr/share/secubox/appstore/catalog.json"))
TIER_RANK = {"all": 0, "lite": 1, "standard": 2, "pro": 3}
_STATE_TTL = 30.0
_state_cache = {"ts": 0.0, "data": {}}

# GARDE JWT SUR LES ECRITURES (#1256). Ce module n'importait pas require_jwt.
# Rien ne rattrapait l'oubli en amont : l'aggregator monte sans middleware, le
# snippet nginx transmet `Authorization` sans le verifier, et auth_request
# teste le LAN, pas un jeton.

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


def load_catalog_raw() -> dict:
    """Le catalogue ENTIER : modules et groupes. `load_catalog` n'en rend que
    la liste des modules, et les groupes seraient perdus en route."""
    try:
        return json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_catalog() -> list:
    return load_catalog_raw().get("modules", [])


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
    # Une seule interrogation d'APT par calcul d'état — elle est mise en cache
    # avec lui : `apt-cache` coûte, et l'appeler par module serait absurde.
    dispo = _installables()
    brank = TIER_RANK.get(board_tier(), 2)
    result = {}
    for m in catalog:
        name = m["name"]
        d = dpkg.get(name, {})
        installed = bool(d.get("installed"))
        running = bool(active.get(name))
        tier = m.get("tier", "lite")
        tier_locked = (tier != "all") and (TIER_RANK.get(tier, 1) > brank)
        # « DISPONIBLE » VEUT DIRE INSTALLABLE, PAS « CONNU DU CATALOGUE ».
        # L'état se calculait sans jamais demander à APT s'il pouvait fournir
        # le paquet : une carte annonçait « available » avec un bouton grisé,
        # ce qui ne veut rien dire pour celui qui la lit (constaté sur `isp`).
        # 14 modules du catalogue ne sont pas publiés au dépôt ; ils le disent.
        publie = (name in dispo) if dispo else True
        if not installed:
            state = ("tier-locked" if tier_locked
                     else "available" if publie else "unpublished")
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
            "installable": publie,
            "state": state,
        }
    _state_cache["ts"] = now
    _state_cache["data"] = result
    return result


@app.get("/health")
async def health():
    return {"ok": True, "module": "appstore",
            "catalog_count": len(load_catalog()), "board_tier": board_tier()}


@app.get("/categories", dependencies=[Depends(require_lecture)])
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


@app.get("/catalog", dependencies=[Depends(require_lecture)])
async def catalog(category: Optional[str] = None, tier: Optional[str] = None,
                  state: Optional[str] = None, q: Optional[str] = None):
    st = compute_state()
    items = list(st.values())
    # INSTALLABLE, MARQUÉ À LA LECTURE (#1323). 25 entrées du catalogue
    # existent en source mais ne sont pas publiées au dépôt : sans ce
    # marquage, l'interface offrirait un bouton « installer » voué à échouer.
    # On ne les purge pas — elles reviendront une fois publiées, et un module
    # absent du catalogue est un module qu'on ne sait plus nommer.
    profils_par_module = {}
    for pr in _profils():
        for mod in pr["modules"]:
            profils_par_module.setdefault(mod, []).append(pr["name"])
    for m in items:
        m["profils"] = profils_par_module.get(m["name"], [])
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


@app.get("/mesh-catalog", dependencies=[Depends(require_lecture)])
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


@app.get("/module/{name}", dependencies=[Depends(require_lecture)])
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
# Les verbes de CYCLE DE VIE : réversibles d'un clic, sans confirmation.
ACTIONS = {"start", "stop", "restart", "enable", "disable"}
# Les verbes de PARC : ils touchent dpkg. `install` s'annule par `remove` ;
# `remove` emporte un service en production, d'où la confirmation explicite.
ACTIONS_PARC = {"install", "remove", "repair"}
ACTIONS_CONFIRMEES = {"remove"}
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


PROFILS_DIR = Path(os.environ.get("SECUBOX_PROFILES", "/etc/secubox/profiles"))


def _installables() -> set:
    """Les modules qu'APT peut RÉELLEMENT installer, maintenant (#1323).

    CALCULÉ EN DIRECT, PAS FIGÉ AU CATALOGUE. Le catalogue est généré à la
    construction, dans le monorepo, où l'état des dépôts de la board est
    inconnu : 25 de ses entrées existent en source mais ne sont pas publiées.
    Les purger serait pire — elles reviendront dès qu'elles seront publiées, et
    un module absent du catalogue est un module qu'on ne sait plus nommer. On
    marque donc chaque entrée `installable` à la lecture, pour que l'interface
    grise le bouton plutôt que de proposer un geste voué à l'échec.
    """
    try:
        r = subprocess.run(["apt-cache", "pkgnames", "secubox-"],
                           capture_output=True, text=True, timeout=20)
        return set(r.stdout.split())
    except Exception:  # noqa: BLE001 — apt absent ou lent : on ne bloque pas
        return set()


def _profils() -> list:
    """Les profils de secubox-profiles, vus du catalogue.

    Un profil est une SÉLECTION de modules ; le dire ici permet de répondre
    « ce module fait partie de Media Lab » au lieu de laisser deviner. On ne
    lit que `name`, `label` et `on` : le reste appartient au moteur de profils.
    """
    out = []
    if not PROFILS_DIR.is_dir():
        return out
    for f in sorted(PROFILS_DIR.glob("*.toml")):
        try:
            with open(f, "rb") as fh:
                d = tomllib.load(fh)
        except Exception:  # noqa: BLE001 — un profil illisible n'en cache pas les autres
            continue
        on = d.get("on") or []
        if not isinstance(on, list):
            continue
        out.append({"name": d.get("name") or f.stem,
                    "label": d.get("label") or f.stem,
                    "modules": [f"secubox-{m}" if not str(m).startswith("secubox-")
                                else str(m) for m in on],
                    "count": len(on)})
    return out


def _route_nginx(court: str) -> dict:
    """Quelque chose, dans la configuration nginx CHARGÉE, mène-t-il à ce module ?

    Trois formes coexistent sur la board et sont toutes légitimes : une route
    dans `secubox-routes.d/`, un vhost dédié dans `sites-enabled/`, ou un
    relais posé par le Hall. On cherche la trace d'`/api/v1/<nom>/` dans ce
    que nginx lit vraiment, plutôt que l'existence d'un chemin conventionnel.
    """
    motif = f"/api/v1/{court}/"
    illisibles = 0
    for rep in (Path("/etc/nginx/secubox-routes.d"), Path("/etc/nginx/sites-enabled")):
        if not rep.is_dir():
            continue
        for f in rep.iterdir():
            # nginx n'inclut que `*.conf` dans secubox-routes.d, mais
            # sites-enabled est globé en entier : on lit les deux comme lui.
            if rep.name == "secubox-routes.d" and f.suffix != ".conf":
                continue
            try:
                if motif in f.read_text(errors="ignore"):
                    return {"ok": True, "bloquant": True, "detail": str(f)}
            except (OSError, IsADirectoryError):
                # CE QU'ON N'A PAS PU LIRE N'EST PAS ABSENT. L'App Store
                # tourne sans privilège et plusieurs vhosts sont en 0600 root
                # (webui.conf le premier) : traduire « illisible » en
                # « manquant » déclarait 55 modules cassés alors qu'ils
                # répondent. On le COMPTE, et on conclut en conséquence.
                illisibles += 1
                continue
    if illisibles:
        return {"ok": None, "bloquant": False,
                "detail": f"indéterminé — {illisibles} fichier(s) nginx illisibles "
                          f"par ce service (droits root)"}
    return {"ok": False, "bloquant": True, "detail": f"aucune route vers {motif}"}


@app.get("/module/{name}/check", dependencies=[Depends(require_lecture)])
async def module_check(name: str):
    """Qu'est-ce qui MANQUE à ce module pour fonctionner ? (#1323)

    UN MODULE N'EST PAS QU'UN PAQUET. Pour répondre sous son nom, il lui faut
    une unité, une route nginx, une route sbxwaf, parfois une configuration —
    et chacun de ces maillons a déjà manqué séparément sur cette board : la
    route sbxwaf de podcaster (421), le vhost du Hall, l'unité de metablogizer
    désactivée par le sleeper. Un état « installé » ne dit donc rien.

    On REGARDE, on ne répare pas : la réparation est un geste, et elle porte
    son propre verbe.
    """
    etat = compute_state()
    name = _resolve(name, etat)
    m = etat[name]
    court = name[len("secubox-"):] if name.startswith("secubox-") else name

    def fichier(chemin, quoi, pourquoi):
        return {"maillon": quoi, "ok": Path(chemin).exists(),
                "detail": chemin, "pourquoi": pourquoi}

    maillons = [
        {"maillon": "paquet", "ok": bool(m.get("installed")),
         "detail": m.get("version") or "absent",
         "pourquoi": "sans le paquet, rien d'autre n'existe"},
    ]
    if m.get("installed"):
        unite = Path(f"/usr/lib/systemd/system/secubox-{court}.service")
        if unite.exists() or Path(f"/lib/systemd/system/secubox-{court}.service").exists():
            maillons.append({"maillon": "unité", "ok": True,
                             "detail": f"secubox-{court}.service",
                             "pourquoi": "le service qui répond"})
        # LA ROUTE SE CHERCHE PARTOUT OÙ NGINX LA LIRAIT, pas à un seul
        # chemin. Un module peut être servi par `secubox-routes.d/<nom>.conf`,
        # par son PROPRE vhost (radio, metablogizer, torrent…), ou par un
        # relais du Hall. Tester le seul premier cas déclarait `radio` cassé
        # alors qu'il répond 200 — et un diagnostic qui crie au loup est pire
        # que pas de diagnostic.
        maillons.append({"maillon": "route nginx", **_route_nginx(court),
                         "pourquoi": "sans elle, le nom n'atteint pas le module"})
        # LE MANIFESTE N'EST PAS BLOQUANT. Son absence ne casse rien : le
        # module retombe sur `always-on`, le défaut sûr. C'est une observation,
        # pas une panne — la compter comme manquante ferait sonner l'alarme
        # pour un module qui marche.
        man = Path(f"/etc/secubox/modules.d/{court}.toml")
        maillons.append({"maillon": "manifeste", "ok": man.exists(), "bloquant": False,
                         "detail": str(man) if man.exists() else "absent — always-on par défaut",
                         "pourquoi": "porte le cycle de vie ; absent, le module ne dort jamais"})
        # Route sbxwaf : on ne la cherche que si le module a un domaine portail.
        dom = None
        try:
            with open(f"/etc/secubox/modules.d/{court}.toml", "rb") as fh:
                dom = tomllib.load(fh).get("portal_domain")
        except Exception:  # noqa: BLE001
            pass
        if dom:
            try:
                table = json.loads(Path("/etc/secubox/waf/haproxy-routes.json")
                                   .read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                table = {}
            maillons.append({"maillon": "route sbxwaf", "ok": dom in table,
                             "detail": dom,
                             "pourquoi": "sans elle sbxwaf rend 421 sur ce nom"})
    # Seuls les maillons BLOQUANTS comptent comme manquants.
    manquants = [x["maillon"] for x in maillons
                 if x["ok"] is False and x.get("bloquant", True)]
    indetermines = [x["maillon"] for x in maillons if x["ok"] is None]
    return {"module": name, "state": m.get("state"),
            "maillons": maillons, "manquants": manquants,
            "indetermines": indetermines,
            "reparable": bool(m.get("installed")) and bool(manquants),
            "ok": not manquants}


@app.get("/groupes", dependencies=[Depends(require_lecture)])
async def groupes():
    """Les fonctionnalités : une intention, plusieurs paquets (#1323).

    Une CATÉGORIE range, un GROUPE propose. On ne veut pas installer « les 14
    modules classés média », on veut « écouter et regarder chez soi » — trois
    modules choisis qui marchent ensemble.
    """
    cat = load_catalog_raw()
    dispo = _installables()
    etat = compute_state()
    out = []
    for g in cat.get("groupes", []):
        membres = []
        for n in g.get("modules", []):
            membres.append({"name": n,
                            "installed": n in etat,
                            "installable": n in dispo})
        out.append({**g, "membres": membres,
                    "installes": sum(1 for m in membres if m["installed"]),
                    "total": len(membres)})
    return {"groupes": out, "count": len(out)}


# ── MÉTAPAQUETS IMBRIQUÉS (#1397) ─────────────────────────────────────────
# L'arbre vient de secubox-meta (arbre.yaml → debian/control), figé dans le
# catalogue à la construction. Ici on n'ajoute que l'ÉTAT : ce qui est installé
# sur CETTE box — nœuds, modules, et leurs dépendances système (lxc, openssl…).
_etat_paquets = {"ts": 0.0, "data": {}}


def _dpkg_noms(noms) -> dict:
    """État dpkg d'une liste de paquets quelconques (pas seulement secubox-*)."""
    noms = sorted(set(noms))
    if not noms:
        return {}
    out = {}
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\t${Version}\n", *noms],
            capture_output=True, text=True, timeout=15)
        for ligne in r.stdout.splitlines():
            p = ligne.split("\t")
            if len(p) >= 3 and p[1].strip().startswith("ii"):
                out[p[0]] = p[2].strip()
    except Exception:
        pass
    return out


@app.get("/metapaquets", dependencies=[Depends(require_lecture)])
async def metapaquets():
    """L'arbre sbxos ⊃ secubox ⊃ fonctions ⊃ services ⊃ modules, avec l'état.

    Chaque nœud dit, par force de lien, combien de modules il atteint et combien
    sont installés : « requis 5/5 · recommandés 2/4 · suggérés 0/3 ».
    """
    arbre = load_catalog_raw().get("arbre")
    if not arbre:
        return {"noeuds": [], "paquets": {}, "disponible": False}
    noeuds = arbre["noeuds"]
    fiches = arbre["paquets"]
    metas = {n["meta"]: n for n in noeuds}
    now = time.time()
    if now - _etat_paquets["ts"] > _STATE_TTL:
        noms = set(metas) | set(fiches)
        for f in fiches.values():
            for champ in ("depends", "recommends", "suggests"):
                noms.update(d["nom"] for d in f.get(champ, []))
        _etat_paquets.update(ts=now, data=_dpkg_noms(noms))
    inst = _etat_paquets["data"]

    def atteint(m, force_max, vus=None):
        """Feuilles atteintes depuis m, chacune avec la force la plus faible du chemin."""
        vus = vus if vus is not None else {}
        rang = {"requiert": 0, "recommande": 1, "suggere": 2}
        for lien in ("requiert", "recommande", "suggere"):
            f = max(force_max, rang[lien])
            for x in metas[m][lien]:
                if x in metas:
                    atteint(x, f, vus)
                elif f < vus.get(x, 9):
                    vus[x] = f
        return vus

    out = []
    for n in noeuds:
        feuilles = atteint(n["meta"], 0)
        compte = {}
        for nom, f in feuilles.items():
            c = compte.setdefault(("requis", "recommandes", "suggeres")[f], [0, 0])
            c[1] += 1
            c[0] += 1 if nom in inst else 0
        out.append({**n, "installe": n["meta"] in inst, "version": inst.get(n["meta"], ""),
                    "compte": {k: {"installes": v[0], "total": v[1]} for k, v in compte.items()}})
    paquets = {}
    for nom, f in fiches.items():
        d = dict(f)
        d["installe"], d["version"] = nom in inst, inst.get(nom, "")
        for champ in ("depends", "recommends", "suggests"):
            d[champ] = [dict(x, installe=x["nom"] in inst) for x in f.get(champ, [])]
        paquets[nom] = d
    return {"noeuds": out, "paquets": paquets, "hors_arbre": arbre.get("hors_arbre", []),
            "disponible": True}


@app.get("/profils", dependencies=[Depends(require_lecture)])
async def profils():
    """Les profils, et ce qu'ils contiennent — le lien catalogue ↔ profils."""
    etat = compute_state()
    out = []
    for p in _profils():
        presents = sum(1 for m in p["modules"] if m in etat)
        out.append({**p, "installes": presents,
                    "manquants": [m for m in p["modules"] if m not in etat][:40]})
    return {"profils": out, "count": len(out)}


@app.post("/module/{name}/action/{verb}", dependencies=[Depends(require_jwt)])
async def module_action(name: str, verb: str, confirmer: str | None = None):
    """Agir sur un module : cycle de vie, ou ajout/retrait dans le parc (#1323).

    LA CONFIRMATION EST UN NOM, PAS UNE CASE À COCHER. `remove` exige que
    l'appelant RÉÉCRIVE le nom complet du module (`?confirmer=secubox-radio`).
    Une case se coche par réflexe et se pré-remplit par erreur ; retaper un nom
    oblige à lire lequel on retire.

    Les gardes de fond — liste de protection, refus si d'autres paquets en
    dépendent, jamais de purge — vivent dans secubox-appstorectl, qui est la
    vraie frontière : le sudoers lui accorde NOPASSWD.
    """
    verbe_parc = verb in ACTIONS_PARC
    if verb not in ACTIONS and not verbe_parc:
        raise HTTPException(status_code=400, detail=f"unknown action {verb!r}")
    if verb == "install":
        # `install` porte sur un module PAS ENCORE installé : le résoudre
        # contre l'état courant le rejetterait en 404. On valide sur le
        # catalogue, seule liste de ce qui a le droit d'entrer.
        connus = {m.get("name") for m in load_catalog()}
        if name not in connus:
            alt = f"secubox-{name}"
            if alt not in connus:
                raise HTTPException(status_code=404,
                                    detail=f"module {name!r} absent du catalogue")
            name = alt
    else:
        name = _resolve(name, compute_state())
    if verb in ACTIONS_CONFIRMEES and confirmer != name:
        raise HTTPException(status_code=428,
                            detail=f"confirmation requise : renvoyez ?confirmer={name}")
    rc, out, err = _appstorectl([verb, name])
    if rc != 0:
        # UN REFUS N'EST PAS UNE PANNE. Le script sort sur des codes parlants ;
        # les rendre tous en 500 dirait « le serveur a cassé » là où la vérité
        # est « votre demande est refusée, et voici pourquoi » — et l'interface
        # ne pourrait qu'afficher une erreur générique au lieu du motif.
        STATUTS = {
            2: 400,   # nom hors liste blanche, ou verbe inconnu du script
            4: 404,   # paquet absent des dépôts configurés
            5: 409,   # une autre opération dpkg est en cours (verrou)
            6: 403,   # module protégé : retrait interdit
            7: 409,   # d'autres paquets en dépendent encore
        }
        raise HTTPException(status_code=STATUTS.get(rc, 500),
                            detail=f"{verb} refusé : {err or out}" if rc in STATUTS
                                   else f"{verb} failed: {err or out}")
    new = compute_state(force=True).get(name, {})
    return {"status": "ok", "action": verb, "module": name,
            "state": new.get("state"), "running": new.get("running"), "message": out}


@app.get("/module/{name}/config", dependencies=[Depends(require_lecture)])
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


@app.put("/module/{name}/config", dependencies=[Depends(require_jwt)])
async def put_config(name: str, body: ConfigIn):
    name = _resolve(name, compute_state())
    rc, out, err = _appstorectl(["write-config", name], input_text=body.content)
    if rc != 0:
        raise HTTPException(status_code=400, detail=f"config write failed: {err or out}")
    return {"status": "ok", "module": name, "message": out}
