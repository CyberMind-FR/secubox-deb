# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: règles fermées des macros (#3702)

Module PUR (aucune E/S, ni FastAPI ni stockage) : validation des étapes, conditions, comparaisons, estimation et macros
livrées. Une étape est `action`, `releve`, `condition`, `comparer` ou `attendre`, rien d'autre : aucune commande libre,
aucune expression, aucun `eval`. Toute valeur venue de l'utilisateur est comparée à des listes fermées ou à des motifs
`fullmatch` ; une clé inconnue ou manquante dans une étape est refusée. Une étape `action` ne désigne qu'une clé du
`CATALOGUE` et ses `args` passent par `arguments()`.
"""
from __future__ import annotations

import math
import re
from typing import Optional

from .operations import CATALOGUE, arguments

ETAPES_MAX = 20
RE_NOM_MACRO = re.compile(r"^[\w àâçéèêëîïôûùüÿœ'-]{1,60}$")
RE_NOM_RELEVE = re.compile(r"^(avant|apres|[a-z0-9-]{1,20})$")
RE_HEURE = r"([01]\d|2[0-3]):[0-5]\d"
_RE_HEURE = re.compile(RE_HEURE)
MESURES = ("memoire_dispo_mo", "cpu_pct", "swap_utilise_pct", "services_en_echec")
REGLES = ("nouveau_service_en_echec", "memoire_dispo_baisse_mo")
OPS = (">", "<")
ALORS = ("arreter", "passer")
ACTION_DELAI = (60, 3600)
ACTION_DELAI_DEFAUT = 900
RELEVE_DUREE = (10, 300)
ATTENDRE_DELAI = (30, 900)
ATTENDRE_DEFAUT = 300
SEUIL_MAX = 1e6
HORS_MACRO = ("renommer",)   # change la clé de la box : les étapes suivantes viseraient une box disparue
SERVICES_MAX = 200

ESTIMATION_S = {"reboot": 120, "maj-paquets": 300, "installer": 180, "service-demarrer": 15, "service-arreter": 15,
                "service-redemarrer": 15, "renommer": 60, "renouveler": 30, "interface-distante": 60, "interface-locale": 60}
_COUPURES = {"reboot": "redémarrage", "interface-distante": "bascule d'interface", "interface-locale": "bascule d'interface",
             "renommer": "changement de nom"}


class MacroInvalide(ValueError):
    """Macro refusée ; le message, en français, est rendu tel quel en 400."""


def _entier(v, bas: int, haut: int, nom: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not bas <= v <= haut:
        raise MacroInvalide(f"{nom} doit être un entier entre {bas} et {haut}")
    return v


def _seuil(v) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not abs(v) <= SEUIL_MAX:   # NaN et inf échouent ici ; sûr pour tout entier
        raise MacroInvalide("le seuil doit être un nombre fini d'au plus un million en valeur absolue")
    return v


def _dans(v, liste: tuple, nom: str) -> str:
    if not isinstance(v, str) or v not in liste:
        raise MacroInvalide(f"{nom} doit valoir l'une de ces valeurs : {', '.join(liste)}")
    return v


def _nom_releve(v, nom: str) -> str:
    if not isinstance(v, str) or not RE_NOM_RELEVE.fullmatch(v):
        raise MacroInvalide(f"{nom} : nom de relevé invalide (avant, apres ou 1 à 20 caractères a-z, 0-9, tiret)")
    return v


def _liste(cles) -> str:
    """Noms de clés pour un message : bornés (5 noms de 40 caractères), les clés viennent de l'utilisateur."""
    noms = sorted(str(c)[:40] for c in cles)
    return ", ".join(noms[:5]) + (" …" if len(noms) > 5 else "")


def _champs(e: dict, obligatoires: set, facultatifs: set, type_: str) -> None:
    cles = set(e)
    manque, trop = obligatoires - cles, cles - obligatoires - facultatifs
    if manque:
        raise MacroInvalide(f"étape « {type_} » : champ manquant : {_liste(manque)}")
    if trop:
        raise MacroInvalide(f"étape « {type_} » : champ non permis : {_liste(trop)}")


def valider_nom(nom) -> str:
    if not isinstance(nom, str) or not RE_NOM_MACRO.fullmatch(nom):
        raise MacroInvalide("nom de macro invalide (1 à 60 lettres, chiffres, espaces, apostrophe ou tiret)")
    return nom


def valider_etapes(etapes) -> list:
    """Étapes normalisées (défauts posés) ou MacroInvalide. Les noms de relevé sont uniques et référencés après leur production."""
    if not isinstance(etapes, list) or not etapes:
        raise MacroInvalide("une macro compte au moins une étape")
    if len(etapes) > ETAPES_MAX:
        raise MacroInvalide(f"une macro compte {ETAPES_MAX} étapes au plus")
    sortie: list = []
    releves: set = set()
    for rang, e in enumerate(etapes, 1):
        if not isinstance(e, dict):
            raise MacroInvalide(f"étape {rang} : objet attendu")
        t = e.get("type")
        try:
            if t == "action":
                _champs(e, {"type", "action"}, {"args", "delai_s"}, t)
                nom = e["action"]
                act = CATALOGUE.get(nom) if isinstance(nom, str) else None
                if act is None:
                    raise MacroInvalide("action inconnue du catalogue")
                if nom in HORS_MACRO:
                    raise MacroInvalide(f"l'action {nom} ne se met pas dans une macro (action seule de la console)")
                args = e.get("args", {})
                if arguments(act, args) is None:
                    raise MacroInvalide(f"paramètres invalides pour l'action {nom}")
                n = {"type": t, "action": nom, "args": dict(args),
                     "delai_s": _entier(e.get("delai_s", ACTION_DELAI_DEFAUT), *ACTION_DELAI, "delai_s")}
            elif t == "releve":
                _champs(e, {"type", "duree_s", "nom"}, set(), t)
                nom = _nom_releve(e["nom"], "nom")
                if nom in releves:
                    raise MacroInvalide(f"le relevé « {nom} » est déjà produit par une étape précédente")
                n = {"type": t, "duree_s": _entier(e["duree_s"], *RELEVE_DUREE, "duree_s"), "nom": nom}
                releves.add(nom)
            elif t == "condition":
                _champs(e, {"type", "mesure", "releve", "op", "seuil", "alors"}, set(), t)
                ref = _nom_releve(e["releve"], "releve")
                if ref not in releves:
                    raise MacroInvalide(f"le relevé « {ref} » doit être produit par une étape antérieure")
                n = {"type": t, "mesure": _dans(e["mesure"], MESURES, "mesure"), "releve": ref, "op": _dans(e["op"], OPS, "op"),
                     "seuil": _seuil(e["seuil"]), "alors": _dans(e["alors"], ALORS, "alors")}
            elif t == "comparer":
                _champs(e, {"type", "avant", "apres", "regle"}, {"seuil"}, t)
                av, ap = _nom_releve(e["avant"], "avant"), _nom_releve(e["apres"], "apres")
                if av == ap:
                    raise MacroInvalide("avant et apres doivent nommer deux relevés différents")
                for ref in (av, ap):
                    if ref not in releves:
                        raise MacroInvalide(f"le relevé « {ref} » doit être produit par une étape antérieure")
                n = {"type": t, "avant": av, "apres": ap, "regle": _dans(e["regle"], REGLES, "regle"),
                     "seuil": _seuil(e.get("seuil", 0))}
            elif t == "attendre":
                _champs(e, {"type"}, {"delai_s"}, t)
                n = {"type": t, "delai_s": _entier(e.get("delai_s", ATTENDRE_DEFAUT), *ATTENDRE_DELAI, "delai_s")}
            else:
                raise MacroInvalide("type d'étape inconnu (action, releve, condition, comparer ou attendre)")
        except MacroInvalide as exc:
            raise MacroInvalide(f"étape {rang} : {exc}") from None
        sortie.append(n)
    return sortie


def contient_forte(etapes: list) -> bool:
    """Vrai si une étape `action` du catalogue exige la confirmation forte."""
    for e in etapes:
        if isinstance(e, dict) and e.get("type") == "action":
            act = CATALOGUE.get(e.get("action")) if isinstance(e.get("action"), str) else None
            if act is not None and act.forte:
                return True
    return False


def valider_programmation(prog, etapes: list, cibles_clientes: bool) -> Optional[dict]:
    """None si pas de programmation ; sinon {"quotidien": "HH:MM"}, refusée si une étape est forte ou une cible cliente."""
    if prog is None:
        return None
    if not isinstance(prog, dict) or set(prog) != {"quotidien"}:
        raise MacroInvalide('la programmation est {"quotidien": "HH:MM"} ou rien')
    h = prog["quotidien"]
    if not isinstance(h, str) or not _RE_HEURE.fullmatch(h):
        raise MacroInvalide("l'heure doit avoir la forme HH:MM (00:00 à 23:59)")
    if contient_forte(etapes):
        raise MacroInvalide("une macro à confirmation forte ne se programme pas : personne pour retaper les noms la nuit")
    if cibles_clientes:
        raise MacroInvalide("une macro visant une box cliente ne se programme pas")
    return {"quotidien": h}


LIVREES: tuple = (
    {"id": "livree:diagnostic-complet", "nom": "Diagnostic complet",
     "etapes": [{"type": "releve", "duree_s": 300, "nom": "diag"}]},
    {"id": "livree:mise-a-jour-sure", "nom": "Mise à jour sûre",
     "etapes": [{"type": "releve", "duree_s": 60, "nom": "avant"},
                {"type": "condition", "mesure": "services_en_echec", "releve": "avant", "op": ">", "seuil": 0, "alors": "arreter"},
                {"type": "action", "action": "maj-paquets"},
                {"type": "releve", "duree_s": 60, "nom": "apres"},
                {"type": "comparer", "avant": "avant", "apres": "apres", "regle": "nouveau_service_en_echec", "seuil": 0}]},
    {"id": "livree:remise-en-route", "nom": "Remise en route",
     "etapes": [{"type": "releve", "duree_s": 60, "nom": "avant"}]},
    {"id": "livree:retour-en-local", "nom": "Retour en local",
     "etapes": [{"type": "action", "action": "interface-locale"}]},
)


def services_en_echec(valeurs: dict) -> list:
    """Noms `Device.X_SECUBOX_Services.{i}.Name` dont `ActiveState` vaut « failed » (i = 1..200, arrêt au premier nom absent), triés."""
    noms = []
    for i in range(1, SERVICES_MAX + 1):
        nom = valeurs.get(f"Device.X_SECUBOX_Services.{i}.Name")
        if not isinstance(nom, str):
            break
        if valeurs.get(f"Device.X_SECUBOX_Services.{i}.ActiveState") == "failed":
            noms.append(nom)
    return sorted(noms)


def instantane(resume: dict, valeurs: dict) -> dict:
    """Mesures d'une box à un instant : valeurs de `resumes()` (None si absentes) et noms des services en échec de l'inventaire
    (None si l'inventaire ne liste aucun service : liste inconnue, pas vide)."""
    connus = "Device.X_SECUBOX_Services.1.Name" in valeurs
    return {"memoire_dispo_mo": resume.get("memoire_dispo_mo"), "cpu_pct": resume.get("cpu_pct"),
            "swap_utilise_pct": resume.get("swap_utilise_pct"), "services_en_echec": resume.get("services_en_echec"),
            "services": services_en_echec(valeurs) if connus else None, "inventaire_le": resume.get("inventaire_le")}


def _nombre(v) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    try:
        return v if math.isfinite(v) else None
    except OverflowError:
        return None


def evaluer_condition(etape: dict, instantanes: dict) -> dict:
    """Prédicat de l'étape sur le relevé nommé. Mesure absente = condition fausse, `mesure_absente` vrai (noté au journal)."""
    inst = instantanes.get(etape["releve"])
    valeur = _nombre(inst.get(etape["mesure"])) if isinstance(inst, dict) else None
    if valeur is None:
        return {"vrai": False, "mesure_absente": True, "valeur": None}
    vrai = valeur > etape["seuil"] if etape["op"] == ">" else valeur < etape["seuil"]
    return {"vrai": vrai, "mesure_absente": False, "valeur": valeur}


def comparer(etape: dict, instantanes: dict) -> dict:
    """Règle de comparaison entre deux relevés. Mesure absente d'un côté : pas d'écart, `mesure_absente` vrai."""
    av, ap = instantanes.get(etape["avant"]), instantanes.get(etape["apres"])
    av, ap = (av if isinstance(av, dict) else {}), (ap if isinstance(ap, dict) else {})
    seuil = etape.get("seuil", 0)
    res = {"ecart": False, "nouveaux": [], "hausse": None, "baisse_mo": None, "mesure_absente": False, "propositions": []}
    if etape["regle"] == "nouveau_service_en_echec":
        ls_av, ls_ap = av.get("services"), ap.get("services")
        if isinstance(ls_av, list) and isinstance(ls_ap, list):
            res["nouveaux"] = sorted(set(ls_ap) - set(ls_av))
        n_av, n_ap = _nombre(av.get("services_en_echec")), _nombre(ap.get("services_en_echec"))
        if n_av is not None and n_ap is not None:
            res["hausse"] = int(n_ap - n_av)
        if res["hausse"] is None and not (isinstance(ls_av, list) and isinstance(ls_ap, list)):
            res["mesure_absente"] = True
        else:
            res["ecart"] = len(res["nouveaux"]) > seuil or (res["hausse"] is not None and res["hausse"] > seuil)
        for u in res["nouveaux"]:
            if arguments(CATALOGUE["service-redemarrer"], {"unite": u}) is not None:
                res["propositions"].append({"action": "service-redemarrer", "args": {"unite": u}})
    else:
        m_av, m_ap = _nombre(av.get("memoire_dispo_mo")), _nombre(ap.get("memoire_dispo_mo"))
        if m_av is None or m_ap is None:
            res["mesure_absente"] = True
        else:
            res["baisse_mo"] = int(m_av - m_ap)
            res["ecart"] = (m_av - m_ap) > seuil
    return res


def estimer_s(etape: dict) -> int:
    t = etape["type"]
    if t == "releve":
        return etape["duree_s"] + 10
    if t == "action":
        return min(etape["delai_s"], ESTIMATION_S.get(etape["action"], etape["delai_s"]))
    if t == "attendre":
        return etape["delai_s"]
    return 0


def coupure(etape: dict) -> Optional[str]:
    """Nature de la coupure de service que l'étape provoque, ou None."""
    return _COUPURES.get(etape.get("action")) if etape.get("type") == "action" else None
