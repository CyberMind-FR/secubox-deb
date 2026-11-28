# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Évolutions d'un sujet (#4058, Task 5).

Compare le dossier courant de gk2 au dernier dossier validé (`Magasin.dernier_valide`) et rend des faits courts,
sans adresse, que la consigne donne à l'IA : `{"genre", "texte", "marquant"}`. Ordre : retour d'acteur, extinction,
nouvelle vague, opérateurs, phases, chiffres — le plus parlant d'abord.
"""
from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

GENRES = {"nouvelle_vague", "extinction", "operateur_nouveau", "retour_acteur", "phase", "chiffre"}
EXTINCTION_JOURS = 7
SEUIL_CHIFFRE = 0.25

_V4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.]*\d)")
_V6 = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?(?![0-9A-Za-z:])")

_CHIFFRES = {"bans_90j": "bans sur 90 jours", "adresses_90j": "adresses distinctes", "blocs24_90j": "réseaux /24",
             "jours_actifs": "jours actifs", "vagues": "vagues"}


def _sans_adresse(texte: str) -> str:
    return _V6.sub("une adresse", _V4.sub("une adresse", texte))


def _jour(x: Any) -> Optional[date]:
    try:
        return date.fromisoformat(str(x)[:10])
    except ValueError:
        return None


def _dernier_ban(d: Dict[str, Any]) -> Optional[date]:
    """Dernier jour avec des bans : fin de la dernière vague, ou fin de la dernière semaine non nulle."""
    jours = [_jour(v.get("fin")) for v in d.get("vagues") or [] if isinstance(v, dict)]
    for s in d.get("serie_semaine") or []:
        if isinstance(s, dict) and (s.get("bans") or 0) > 0 and _jour(s.get("debut")):
            jours.append(_jour(s["debut"]) + timedelta(days=6))
    jours = [j for j in jours if j]
    return max(jours) if jours else None


def _actif(d: Dict[str, Any], ref: Optional[date]) -> bool:
    dernier = _dernier_ban(d)
    return bool(dernier and ref and (ref - dernier).days < EXTINCTION_JOURS)


def _noms(d: Dict[str, Any], cle: str, champ: str) -> List[str]:
    return [x[champ] for x in d.get(cle) or [] if isinstance(x, dict) and isinstance(x.get(champ), str)]


def _fait(genre: str, texte: str, marquant: bool) -> Dict[str, Any]:
    return {"genre": genre, "texte": _sans_adresse(texte), "marquant": bool(marquant)}


def evolutions(courant: Dict[str, Any], precedent: Optional[Dict[str, Any]], maintenant: float, *,
               seuil_chiffre: float = SEUIL_CHIFFRE) -> List[Dict[str, Any]]:
    nom = str((courant.get("sujet") or {}).get("nom") or "ce sujet")
    if precedent is None:
        return [_fait("premiere_lecture", f"Première lecture de {nom} : aucun dossier validé auparavant.", True)]
    if courant == precedent:
        return []
    aujourdhui = datetime.fromtimestamp(maintenant, timezone.utc).date()
    ref_prec = _jour(precedent.get("genere_le")) or aujourdhui
    faits: List[Dict[str, Any]] = []
    prec_actif, cour_actif = _actif(precedent, ref_prec), _actif(courant, aujourdhui)
    retour = False
    if not prec_actif and _dernier_ban(precedent) and cour_actif:
        retour = True
        faits.append(_fait("retour_acteur", f"{nom} réapparaît après une extinction (dernier ban précédent le "
                                            f"{_dernier_ban(precedent).isoformat()}).", True))
    if prec_actif and not cour_actif and _dernier_ban(courant):
        faits.append(_fait("extinction", f"{nom} s'est éteint : aucun ban depuis le {_dernier_ban(courant).isoformat()}"
                                         f", au moins {EXTINCTION_JOURS} jours.", True))
    debuts_prec = {v.get("debut") for v in precedent.get("vagues") or [] if isinstance(v, dict)}
    dernier_prec = max((d for d in debuts_prec if isinstance(d, str)), default="")
    nouvelles = [v for v in courant.get("vagues") or [] if isinstance(v, dict) and isinstance(v.get("debut"), str)
                 and v["debut"] not in debuts_prec and v["debut"] > dernier_prec]
    if nouvelles and not retour:
        v = nouvelles[-1]
        faits.append(_fait("nouvelle_vague", f"Nouvelle vague de {nom} depuis le {v['debut'][:10]} "
                                             f"({int(v.get('bans') or 0)} bans).", True))
    for o in [o for o in _noms(courant, "operateurs", "nom") if o not in _noms(precedent, "operateurs", "nom")]:
        faits.append(_fait("operateur_nouveau", f"Nouvel opérateur parmi les sources de {nom} : {o}.", False))
    for p in [p for p in _noms(courant, "phases", "phase") if p not in _noms(precedent, "phases", "phase")]:
        faits.append(_fait("phase", f"{nom} entre dans une nouvelle phase : {p}.", True))
    cc, cp = courant.get("chiffres") or {}, precedent.get("chiffres") or {}
    for cle, libelle in _CHIFFRES.items():
        a, b = cp.get(cle), cc.get(cle)
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)) or a == b:
            continue
        ecart = abs(b - a) / a if a else 1.0
        sens = "hausse" if b > a else "baisse"
        faits.append(_fait("chiffre", f"{libelle.capitalize()} : {int(a)} → {int(b)} ({sens} de {round(ecart * 100)} %).",
                           ecart >= seuil_chiffre))
    return faits
