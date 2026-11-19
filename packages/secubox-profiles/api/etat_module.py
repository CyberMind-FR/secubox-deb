# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — état d'UN module, de ses unités et de ses dépendances (#3812)
CyberMind — https://cybermind.fr

Lu par le bouton d'état que la coquille commune (`/shared/etat-module.js`) pose
dans l'en-tête de chaque page de module, et par la raison du badge
« HORS LIGNE ». Ce module CONSTATE, il ne décide rien et n'agit sur rien.

Deux règles :
  * « endormi » n'est dit que si `sleep_state` (même règle que /status) le dit
    ET que la sonde a répondu : une sonde muette donne « inconnu », jamais un
    sommeil inventé ;
  * une unité en échec l'emporte sur le sommeil : c'est elle, la vraie raison.

Coût : une commande `systemctl show` batchée pour les unités du module et de
ses dépendances, plus l'observation habituelle (observe_all) de ce petit
sous-ensemble. Appelé hors de la boucle (asyncio.to_thread) et mis en cache
court par l'API web.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

from .lifecycle import effective_lifecycle, is_sleepable, wake_budget
from .manifest import Manifest
from .observe import (_TEMPLATE_UNIT_RE, Actual, _parse_systemctl_show_blocks,
                      _run_batch, is_on, observe_all)

# Même alphabet que les noms de fichiers des manifestes produits par `scan`
# (secubox-<id>.service) ; borné pour qu'aucun id hostile n'atteigne la sonde.
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

_PROPS = ("Id", "LoadState", "ActiveState", "SubState", "Result", "UnitFileState")

# Profondeur de dépendances lues : les `needs` directs seulement. Une
# dépendance de dépendance se lit sur la page de cette dépendance.
_MAX_NEEDS = 16


def id_valide(mid: str) -> bool:
    return bool(ID_RE.fullmatch(mid or ""))


def etat_unite(props: Optional[dict]) -> str:
    """Classe une unité d'après `systemctl show` : actif, demarrage, arret,
    inactif, echec, absente, inconnu (jamais un état fabriqué)."""
    if not props:
        return "inconnu"
    if props.get("LoadState") == "not-found":
        return "absente"
    a = props.get("ActiveState")
    if a == "failed":
        return "echec"
    if a == "active" or a == "reloading":
        return "actif"
    if a == "activating":
        return "demarrage"
    if a == "deactivating":
        return "arret"
    if a == "inactive":
        return "inactif"
    return "inconnu"


def _sonder_unites(units: list[str], run: Callable) -> dict[str, dict]:
    vraies = [u for u in units if not _TEMPLATE_UNIT_RE.search(u)]
    if not vraies:
        return {}
    argv = ["systemctl", "show", *vraies]
    for p in _PROPS:
        argv += ["-p", p]
    argv.append("--no-pager")
    _, out = run(argv)
    return _parse_systemctl_show_blocks(out) if out else {}


def _observation(a: Actual) -> str:
    """on / off / unknown : le module TOURNE-t-il ? Le conteneur fait foi pour
    un module LXC (comme is_on), sinon l'état actif de la première unité —
    pas `enabled` : une unité lancée mais non activée tourne quand même, et
    l'afficher arrêtée serait faux. Sonde muette = unknown, jamais off."""
    if a.lxc_running is not None:
        return "on" if a.lxc_running else "off"
    if a.active is None:
        return "unknown"
    return "on" if a.active else "off"


def _sleep_state(m: Manifest, a: Actual) -> str:
    if effective_lifecycle(m) in ("always-on", "manual"):
        return "n/a"
    return "up" if is_on(a) else "asleep"


def _fiche(m: Manifest, a: Actual, props_par_unite: dict) -> dict:
    unites = []
    for u in m.units:
        props = props_par_unite.get(u)
        unites.append({
            "unite": u,
            "etat": etat_unite(props),
            "active_state": (props or {}).get("ActiveState"),
            "sub_state": (props or {}).get("SubState"),
            "result": (props or {}).get("Result"),
        })
    obs = _observation(a)
    sleep_state = _sleep_state(m, a)
    en_echec = [u["unite"] for u in unites if u["etat"] == "echec"]
    if en_echec:
        etat = "echec"
    elif obs == "on":
        etat = "eveille"
    elif obs == "unknown":
        etat = "inconnu"
    elif sleep_state == "asleep":
        # Les deux sources d'accord : sommeil (sleep_state) ET rien ne tourne.
        etat = "endormi"
    else:
        etat = "arrete"
    return {
        "id": m.id,
        "lifecycle": effective_lifecycle(m),
        "wake_class": m.wake_class,
        "protected": m.protected,
        "runtime": m.runtime,
        "lxc": m.lxc,
        "lxc_running": a.lxc_running,
        "sleepable": is_sleepable(m),
        "sleep_state": sleep_state,
        "on": obs,
        "etat": etat,
        "unites": unites,
        "unites_en_echec": en_echec,
        "wake_budget_s": wake_budget(m) if is_sleepable(m) else None,
    }


def _raison(fiche: dict, deps: list[dict]) -> dict:
    """La raison qu'on peut afficher à côté d'un « HORS LIGNE », par ordre de
    vérité : échec d'une unité, sommeil, arrêt, dépendance, rien de connu."""
    e = fiche["etat"]
    if e == "echec":
        return {"code": "echec", "unite": fiche["unites_en_echec"][0]}
    if e == "endormi":
        return {"code": "endormi"}
    if e == "arrete":
        return {"code": "arrete"}
    for d in deps:
        if d.get("etat") == "endormi":
            return {"code": "dependance_endormie", "dependance": d["id"]}
        if d.get("etat") in ("echec", "arrete", "absente"):
            return {"code": "dependance_en_panne", "dependance": d["id"]}
    if e == "eveille":
        return {"code": "eveille"}
    return {"code": "inconnu"}


def etat_du_module(mid: str, manifests: dict[str, Manifest], *, routes=None,
                   run: Optional[Callable] = None) -> Optional[dict]:
    """Fiche du module `mid` (None s'il n'a pas de manifeste). Bloquant :
    à appeler par asyncio.to_thread. `run` (argv -> (rc, sortie)) est résolu à
    l'appel : les tests remplacent `_run_batch` sans toucher au vrai systemctl."""
    run = run or _run_batch
    m = manifests.get(mid)
    if m is None:
        return None
    needs = [n for n in m.needs if n != mid][:_MAX_NEEDS]
    connus = {mid: m}
    for n in needs:
        if n in manifests:
            connus[n] = manifests[n]
    actuals = observe_all(connus, run=run, routes=routes if routes is not None else set())
    units: list[str] = []
    for x in connus.values():
        for u in x.units:
            if u not in units:
                units.append(u)
    props = _sonder_unites(units, run)

    fiche = _fiche(m, actuals.get(mid, Actual()), props)
    deps = []
    for n in needs:
        dm = connus.get(n)
        if dm is None:
            deps.append({"id": n, "etat": "absente", "connue": False, "unites": [],
                         "sleep_state": None, "sleepable": False, "lifecycle": None})
            continue
        f = _fiche(dm, actuals.get(n, Actual()), props)
        f["connue"] = True
        deps.append(f)
    fiche["dependances"] = deps
    fiche["raison"] = _raison(fiche, deps)
    if fiche["etat"] == "eveille" and fiche["raison"]["code"].startswith("dependance_"):
        fiche["etat_global"] = "dependance"
    else:
        fiche["etat_global"] = fiche["etat"]
    return fiche
