# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Profils, appareils et configuration effective (#1962, phase 2). `config.json` est écrit par un compte non root : tout est validé comme
entrée hostile, aucune valeur libre n'atteint la configuration d'Unbound."""
import hashlib
import json
import re

from . import domaines

_PROFIL = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MODES = ("observe", "block")
MAX_PROFILS, MAX_APPAREILS, MAX_AUTORISES = 16, 256, 200


class ErreurProfils(ValueError):
    pass


def vide(categories) -> dict:
    return {"version": 0, "profils": {"defaut": {"categories": {c: "observe" for c in sorted(categories)}, "autorise": []}}, "appareils": {}}


def _modes(d, categories, quoi, complet: bool) -> dict:
    if not isinstance(d, dict):
        raise ErreurProfils(f"{quoi} : table attendue")
    for c, m in d.items():
        if c not in categories:
            raise ErreurProfils(f"{quoi} : catégorie inconnue {c!r}")
        if m not in MODES:
            raise ErreurProfils(f"{quoi} : mode invalide pour {c}")
    if complet:
        return {c: d.get(c, "observe") for c in sorted(categories)}
    return dict(d)


def valider(brut, categories) -> dict:
    if not isinstance(brut, dict) or set(brut) - {"version", "profils", "appareils"}:
        raise ErreurProfils("configuration invalide : clés inattendues")
    v = brut.get("version", 0)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ErreurProfils("version invalide")
    pr, ap = brut.get("profils"), brut.get("appareils", {})
    if not isinstance(pr, dict) or "defaut" not in pr or len(pr) > MAX_PROFILS:
        raise ErreurProfils("profils : « defaut » obligatoire, 16 au plus")
    if not isinstance(ap, dict) or len(ap) > MAX_APPAREILS:
        raise ErreurProfils("appareils : 256 au plus")
    sortie = {"version": v, "profils": {}, "appareils": {}}
    for nom, p in pr.items():
        if not isinstance(nom, str) or not _PROFIL.match(nom):
            raise ErreurProfils(f"nom de profil invalide : {nom!r}")
        if not isinstance(p, dict) or set(p) - {"categories", "autorise"}:
            raise ErreurProfils(f"profil {nom} : clés inattendues")
        aut = p.get("autorise", [])
        if not isinstance(aut, list) or len(aut) > MAX_AUTORISES:
            raise ErreurProfils(f"profil {nom} : 200 autorisations au plus")
        noms = []
        for d in aut:
            n = domaines.valider(d)
            if n is None or n != d:                                   # forme canonique exigée : jamais de réécriture silencieuse
                raise ErreurProfils(f"profil {nom} : domaine autorisé invalide")
            noms.append(n)
        sortie["profils"][nom] = {"categories": _modes(p.get("categories", {}), categories, f"profil {nom}", True), "autorise": sorted(set(noms))}
    for mac, a in ap.items():
        if not isinstance(mac, str) or not _MAC.match(mac):
            raise ErreurProfils(f"adresse MAC invalide : {mac!r}")
        if not isinstance(a, dict) or set(a) - {"nom", "profil", "exceptions"}:
            raise ErreurProfils(f"appareil {mac} : clés inattendues")
        nom = a.get("nom", "")
        if not isinstance(nom, str) or len(nom) > 64 or not nom.isprintable():
            raise ErreurProfils(f"appareil {mac} : nom invalide")
        if a.get("profil") not in sortie["profils"]:
            raise ErreurProfils(f"appareil {mac} : profil inexistant")
        sortie["appareils"][mac] = {"nom": nom, "profil": a["profil"], "exceptions": _modes(a.get("exceptions", {}), categories, f"appareil {mac}", False)}
    return sortie


def effective(cfg: dict, mac: str) -> dict:
    """Modes par catégorie et autorisations d'un appareil : son profil, modifié par ses exceptions. Un appareil inconnu prend le profil `defaut`."""
    a = cfg["appareils"].get(mac)
    p = cfg["profils"][a["profil"] if a else "defaut"]
    modes = dict(p["categories"])
    if a:
        modes.update(a["exceptions"])
    return {"modes": modes, "autorise": list(p["autorise"])}


def bloquees(eff: dict) -> list:
    return sorted(c for c, m in eff["modes"].items() if m == "block")


def cle_vue(eff: dict) -> str:
    """Nom de la vue d'Unbound d'une configuration effective : deux appareils de même configuration partagent la même vue."""
    b = bloquees(eff)
    if not b and not eff["autorise"]:
        return "wf-libre"
    return "wf-" + hashlib.blake2b(json.dumps([b, sorted(eff["autorise"])]).encode(), digest_size=4).hexdigest()
