# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: journal des décisions SBX TV PRIVACY (lot 3, #3374).

Une ligne JSON par décision (blocage, déblocage, essai, confirmation, retrait, pause, reprise…) dans `decisions.jsonl` (0640) :
appareil (nom), MAC TRONQUÉE, domaine, catégorie, action, origine (auto, admin, usager), motif, horodatage. Borné à `TAILLE_MAX`
octets ; au-delà, une rotation vers `decisions.jsonl.1` (une seule génération). Les transitions de règles sont DÉDUITES de
l'historique de `dnstv_regles` (`depuis_regles`), pour le moteur comme pour les routes. L'écrivain tient le verrou des règles.
Ce journal sert la consultation ; l'audit de sécurité reste dans audit.log, écrit par le contrôleur root.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

try:
    from . import dnstv, dnstv_appareils
except ImportError:                                   # lancé hors paquet
    from api import dnstv, dnstv_appareils

FICHIER = "decisions.jsonl"
TAILLE_MAX = 1024 * 1024
ACTIONS = ("blocage", "deblocage", "candidat", "essai", "confirmation", "retrait", "rejet", "observe", "pause", "reprise", "exception")
ORIGINES = ("auto", "admin", "usager")
ACTION_DE_TRANSITION = {"candidat": "candidat", "essai": "essai", "confirme": "confirmation", "retire": "retrait", "rejete": "rejet"}
MODE_FICHIER = 0o640


def entree(ts: int, appareil: str, mac: Optional[str], domaine: str, categorie: str, action: str, origine: str, motif: str = "") -> dict:
    """Une entrée validée ; la MAC est TRONQUÉE ici (jamais complète dans le journal)."""
    if action not in ACTIONS:
        raise ValueError("action de journal inconnue")
    if origine not in ORIGINES:
        raise ValueError("origine de journal inconnue")
    if domaine and dnstv.valider_domaine(domaine) != domaine:
        raise ValueError("domaine invalide")
    return {"ts": int(ts), "appareil": str(appareil or "")[:40], "mac": dnstv_appareils.mac_courte(mac) if mac else "",
            "domaine": domaine or "", "categorie": str(categorie or "")[:24], "action": action, "origine": origine, "motif": str(motif or "")[:120]}


def ajouter(entrees: Iterable[dict], dossier: Optional[Path] = None) -> None:
    """Ajoute des entrées (déjà validées par `entree`) ; rotation au-delà de `TAILLE_MAX`. Un lien symbolique est refusé."""
    lignes = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entrees)
    if not lignes:
        return
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    f = d / FICHIER
    try:
        if f.stat().st_size + len(lignes.encode()) > TAILLE_MAX:
            os.replace(f, d / (FICHIER + ".1"))
    except FileNotFoundError:
        pass
    fd = os.open(f, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, MODE_FICHIER)
    try:
        os.fchmod(fd, MODE_FICHIER)
        os.write(fd, lignes.encode())
    finally:
        os.close(fd)


def lire(dossier: Optional[Path] = None, depuis: int = 0) -> List[dict]:
    """Entrées depuis `depuis` (les deux générations), les plus récentes d'abord. Lignes illisibles ignorées."""
    d = dossier or dnstv.DOSSIER_ETAT
    out: List[dict] = []
    for nom in (FICHIER + ".1", FICHIER):
        try:
            fd = os.open(d / nom, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            for ligne in h.read(2 * TAILLE_MAX).splitlines():
                try:
                    e = json.loads(ligne)
                except ValueError:
                    continue
                if isinstance(e, dict) and isinstance(e.get("ts"), int) and e["ts"] >= depuis and e.get("action") in ACTIONS:
                    out.append(e)
    return sorted(out, key=lambda e: -e["ts"])


def agreger(entrees: List[dict]) -> List[dict]:
    """Agrégat par appareil × domaine × action : occurrences, premier et dernier horodatage, origines. Le plus récent d'abord."""
    g: Dict[tuple, dict] = {}
    for e in entrees:
        k = (e.get("appareil", ""), e.get("domaine", ""), e["action"])
        x = g.setdefault(k, {"appareil": k[0], "mac": e.get("mac", ""), "domaine": k[1], "categorie": e.get("categorie", ""),
                             "action": k[2], "occurrences": 0, "premier": e["ts"], "dernier": e["ts"], "origines": set()})
        x["occurrences"] += 1
        x["premier"], x["dernier"] = min(x["premier"], e["ts"]), max(x["dernier"], e["ts"])
        x["origines"].add(e.get("origine", ""))
    out = [dict(x, origines=sorted(x["origines"])) for x in g.values()]
    return sorted(out, key=lambda x: (-x["dernier"], x["appareil"], x["domaine"]))


def _par_slug(etat: dict) -> Dict[str, tuple]:
    out: Dict[str, tuple] = {}
    for c in (etat or {}).get("clients", []):
        s = dnstv._slug(c["nom"])
        if s not in out or (c.get("mac") and not out[s][1]):
            out[s] = (c["nom"], c.get("mac"))
    return out


def depuis_regles(avant: List[dict], apres: List[dict], etat: dict, categorie: Optional[Callable[[str], str]] = None) -> List[dict]:
    """Entrées de journal pour chaque pas d'historique AJOUTÉ entre deux relevés des règles (`Regles.liste()`)."""
    vu = {r["id"]: max((h["ts"] for h in r.get("historique", [])), default=-1) for r in avant}
    nb = {r["id"]: len(r.get("historique", [])) for r in avant}
    noms = _par_slug(etat)
    out = []
    for r in apres:
        hist = r.get("historique", [])
        if r["id"] in vu:
            # l'historique est borné (10) : on garde les pas plus récents que le dernier connu, ou les pas en surnombre à même seconde
            nouveaux = [h for h in hist if h["ts"] > vu[r["id"]]]
            if not nouveaux and len(hist) > nb[r["id"]]:
                nouveaux = hist[nb[r["id"]] - len(hist):]
        else:
            nouveaux = hist
        nom, mac = noms.get(r["appareil"], (r["appareil"], None))
        cat = categorie(r["domaine"]) if categorie else ""
        for h in nouveaux:
            act = ACTION_DE_TRANSITION.get(h["vers"])
            if act and not (h.get("de") == h["vers"]):
                out.append(entree(h["ts"], nom, mac, r["domaine"], cat, act, h.get("origine", "auto") if h.get("origine") in ORIGINES else "auto",
                                  h.get("motif", "")))
    return out
