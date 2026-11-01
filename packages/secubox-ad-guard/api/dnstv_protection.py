# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: protection SBX TV PRIVACY (lot 3, #3374) — retour en un geste, pause minutée, exceptions unifiées.

Fonctions PURES sur l'état (`etat.json`), les règles (`dnstv_regles.Regles`) et deux petits fichiers revalidés à la lecture :
- `pauses.json` : appareils en pause, avec leurs modes d'avant et l'échéance (reprise automatique par le moteur) ;
- `exceptions.json` : modèle unique d'exception appareil × domaine, `autoriser` (liste blanche) ou `bloquer` (liste noire).

Une exception n'invente aucun mécanisme DNS : `autoriser` rejette la règle du couple (jamais reproposée) et pose, si l'appareil voit
le puits global, l'autorisation au puits (#1965) ; `bloquer` pose une règle confirmée par l'administrateur, que le contrôleur root
applique et audite déjà. Les écrivains tiennent `dnstv_regles.verrou` ; écritures atomiques, liens symboliques refusés.
"""
from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional

try:
    from . import dnstv, dnstv_regles
except ImportError:                                   # lancé hors paquet
    from api import dnstv, dnstv_regles

FICHIER_PAUSES = "pauses.json"
FICHIER_EXCEPTIONS = "exceptions.json"
DUREES_MIN = (15, 60, 240, 1440)                     # 24 h au plus (décision du propriétaire, #3374)
MODES_PROTEGES = ("auto", "block")                    # ce qu'une pause ou un retour en OBSERVE relâche
TYPES = ("autoriser", "bloquer")
ORIGINES = ("admin", "usager", "auto")
EXCEPTIONS_MAX = 500
EXCEPTIONS_PAR_APPAREIL = 50
LECTURE_MAX = 512 * 1024
MESSAGE_HONNETE = "SBX TV Privacy bloque les pubs que la TV va chercher, pas celles qu'un service insère dans sa propre vidéo."


class ErreurProtection(ValueError):
    """Entrée refusée ; le message est sûr à montrer."""


class ErreurPlafond(ErreurProtection):
    """Plafond atteint (autorisations au puits, exceptions) : refus explicite (409), jamais un succès silencieux."""


def modes_effectifs(etat: dict, pauses: Iterable[dict], nom: str) -> List[str]:
    """Modes d'un appareil, PAUSE comprise : une adresse en pause compte pour le mode qu'elle retrouvera à la reprise."""
    avant = {}
    for p in pauses or []:
        if p["appareil"] == nom:
            avant.update(p["modes"])
    return [avant.get(c["ip"], c["mode"]) for c in etat.get("clients", []) if c["nom"] == nom]


def _noms(etat: dict, noms: Optional[Iterable[str]]) -> List[str]:
    connus = sorted({c["nom"] for c in etat.get("clients", [])})
    if noms is None:
        return connus
    sel = list(noms)
    for n in sel:
        if n not in connus:
            raise ErreurProtection("appareil inconnu")
    return sel


def duree_lisible(minutes: int) -> str:
    """15 min, 1 h, 4 h."""
    return f"{minutes // 60} h" if minutes % 60 == 0 else f"{minutes} min"


# ── pause, reprise, retour en OBSERVE ────────────────────────────────────────────────────────────────

def mettre_en_pause(etat: dict, pauses: list, noms: Optional[Iterable[str]], minutes: int, maintenant: int, origine: str) -> List[str]:
    """Passe en `observe` les adresses protégées (auto, block) des appareils choisis (tous si `noms` est None) jusqu'à l'échéance.
    Un appareil déjà en pause voit son échéance reportée ; ses modes d'avant sont conservés. Rend les noms touchés."""
    if minutes not in DUREES_MIN:
        raise ErreurProtection("durée de pause : 15 min, 1 h, 4 h ou 24 h")
    if origine not in ORIGINES:
        raise ErreurProtection("origine inconnue")
    fin = int(maintenant) + minutes * 60
    touches = []
    for nom in _noms(etat, noms):
        p = next((x for x in pauses if x["appareil"] == nom), None)
        cs = [c for c in etat["clients"] if c["nom"] == nom]
        a_relacher = {c["ip"]: c["mode"] for c in cs if c["mode"] in MODES_PROTEGES}
        if p is None and not a_relacher:
            continue
        if p is None:
            p = {"appareil": nom, "fin": fin, "modes": {}, "origine": origine}
            pauses.append(p)
        p["modes"].update(a_relacher)
        p["fin"], p["origine"] = fin, origine
        for c in cs:
            if c["ip"] in a_relacher:
                c["mode"] = "observe"
        touches.append(nom)
    return sorted(touches)


def reprendre(etat: dict, pauses: list, noms: Optional[Iterable[str]], maintenant: int, echues: bool = False) -> List[str]:
    """Rend leurs modes d'avant aux appareils en pause (tous, ceux choisis, ou les seules pauses échues). Une adresse que
    l'administrateur a changée entre-temps (mode ≠ observe) n'est pas touchée. Rend les noms repris."""
    choisis = None if noms is None else set(noms)
    repris = []
    for p in list(pauses):
        if (choisis is not None and p["appareil"] not in choisis) or (echues and p["fin"] > maintenant):
            continue
        for c in etat["clients"]:
            if c["nom"] == p["appareil"] and c["ip"] in p["modes"] and c["mode"] == "observe":
                c["mode"] = p["modes"][c["ip"]]
        pauses.remove(p)
        repris.append(p["appareil"])
    return sorted(repris)


def passer_en_observe(etat: dict, pauses: list, noms: Optional[Iterable[str]]) -> List[str]:
    """Retour en un geste : les appareils choisis (tous si None) passent en `observe` sans échéance ; leur pause éventuelle est oubliée."""
    touches = []
    for nom in _noms(etat, noms):
        t = False
        for c in etat["clients"]:
            if c["nom"] == nom and c["mode"] in MODES_PROTEGES:
                c["mode"] = "observe"
                t = True
        avant = len(pauses)
        pauses[:] = [p for p in pauses if p["appareil"] != nom]
        if t or len(pauses) != avant:
            touches.append(nom)
    return sorted(touches)


def _valider_pause(p) -> dict:
    if not isinstance(p, dict) or set(p) - {"appareil", "fin", "modes", "origine"}:
        raise ErreurProtection("pause invalide")
    if not isinstance(p.get("appareil"), str) or not dnstv.NOM_RE.match(p["appareil"]):
        raise ErreurProtection("pause : nom d'appareil invalide")
    if not isinstance(p.get("fin"), int) or isinstance(p["fin"], bool) or p["fin"] < 0:
        raise ErreurProtection("pause : échéance invalide")
    modes = p.get("modes")
    if not isinstance(modes, dict) or len(modes) > 32:
        raise ErreurProtection("pause : modes invalides")
    propres = {}
    for ip, m in modes.items():
        try:
            if not isinstance(ip, str) or str(ipaddress.ip_address(ip)) != ip:
                raise ValueError
        except ValueError:
            raise ErreurProtection("pause : adresse invalide") from None
        if m not in MODES_PROTEGES:
            raise ErreurProtection("pause : mode invalide")
        propres[ip] = m
    origine = p.get("origine", "admin")
    if origine not in ORIGINES:
        raise ErreurProtection("pause : origine inconnue")
    return {"appareil": p["appareil"], "fin": p["fin"], "modes": propres, "origine": origine}


def _lire_json(f: Path):
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise ErreurProtection(f"{f.name} refusé ({type(e).__name__})") from e
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            return json.loads(h.read(LECTURE_MAX))
    except ValueError as e:
        raise ErreurProtection(f"{f.name} illisible") from e


def _ecrire_json(f: Path, contenu: dict) -> None:
    f.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=f.parent, prefix="." + f.stem + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            json.dump(contenu, h, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o640)
        os.replace(tmp, f)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def charger_pauses(dossier: Optional[Path] = None) -> list:
    """Pauses en cours, revalidées ; fichier absent = aucune ; contenu invalide = refus entier."""
    brut = _lire_json((dossier or dnstv.DOSSIER_ETAT) / FICHIER_PAUSES)
    if brut is None:
        return []
    if not isinstance(brut, dict) or brut.get("version") != 1 or not isinstance(brut.get("pauses"), list) or len(brut["pauses"]) > 64:
        raise ErreurProtection("pauses.json illisible")
    return [_valider_pause(p) for p in brut["pauses"]]


def ecrire_pauses(pauses: list, dossier: Optional[Path] = None) -> None:
    _ecrire_json((dossier or dnstv.DOSSIER_ETAT) / FICHIER_PAUSES, {"version": 1, "pauses": [_valider_pause(p) for p in pauses]})


# ── exceptions unifiées ──────────────────────────────────────────────────────────────────────────────

def _valider_exception(e) -> dict:
    if not isinstance(e, dict) or set(e) - {"appareil", "mac", "domaine", "type", "origine", "maj"}:
        raise ErreurProtection("exception invalide")
    if not isinstance(e.get("appareil"), str) or dnstv._slug(e["appareil"]) != e["appareil"]:
        raise ErreurProtection("exception : appareil invalide")
    mac = e.get("mac", "")
    if not isinstance(mac, str) or (mac and not dnstv.MAC_RE.match(mac)):
        raise ErreurProtection("exception : MAC invalide")
    if not isinstance(e.get("domaine"), str) or dnstv.valider_domaine(e["domaine"]) != e["domaine"]:
        raise ErreurProtection("exception : domaine invalide")
    if e.get("type") not in TYPES or e.get("origine", "admin") not in ORIGINES:
        raise ErreurProtection("exception : type ou origine inconnu")
    maj = e.get("maj", 0)
    if not isinstance(maj, int) or isinstance(maj, bool) or maj < 0:
        raise ErreurProtection("exception : date invalide")
    return {"appareil": e["appareil"], "mac": mac, "domaine": e["domaine"], "type": e["type"], "origine": e.get("origine", "admin"), "maj": maj}


def charger_exceptions(dossier: Optional[Path] = None) -> list:
    brut = _lire_json((dossier or dnstv.DOSSIER_ETAT) / FICHIER_EXCEPTIONS)
    if brut is None:
        return []
    if not isinstance(brut, dict) or brut.get("version") != 1 or not isinstance(brut.get("exceptions"), list) \
            or len(brut["exceptions"]) > EXCEPTIONS_MAX:
        raise ErreurProtection("exceptions.json illisible")
    return [_valider_exception(e) for e in brut["exceptions"]]


def ecrire_exceptions(exceptions: list, dossier: Optional[Path] = None) -> None:
    _ecrire_json((dossier or dnstv.DOSSIER_ETAT) / FICHIER_EXCEPTIONS,
                 {"version": 1, "exceptions": [_valider_exception(e) for e in exceptions]})


def _vers(regles, rid: str, chemin: List[str], origine: str, motif: str, maintenant: int) -> None:
    for etat_suivant in chemin:
        regles.transiter(rid, etat_suivant, origine, motif, maintenant)


def poser_exception(exceptions: list, etat: dict, regles, nom: str, domaine: str, type_: str, actif: bool, maintenant: int,
                    origine: str = "admin", pauses: Iterable[dict] = ()) -> list:
    """Pose (`actif`) ou retire une exception appareil × domaine et met les règles et les autorisations en cohérence. Rend la nouvelle
    liste ; modifie `etat` et `regles` en place. Seule l'origine `admin` est admise : l'usager ne pose aucune exception.

    Effet selon le mode EFFECTIF (pause comprise) : AUTO et PROTECT reçoivent l'exception (`autoriser` : autorisation de l'appareil,
    qui prime sur le puits global en AUTO et sur la liste livrée en PROTECT ; `bloquer` : règle confirmée appliquée dans la vue de
    l'appareil). OBSERVE sans pause : `autoriser` est admis (rien n'est bloqué), `bloquer` est REFUSÉ (aucun effet) ; OFF : refusé.
    Plafond d'autorisations atteint : `ErreurPlafond` (409), jamais un succès silencieux."""
    if origine != "admin":
        raise ErreurProtection("seul l'administrateur pose une exception")
    if type_ not in TYPES:
        raise ErreurProtection("type d'exception : autoriser ou bloquer")
    d = dnstv.valider_domaine(domaine) if isinstance(domaine, str) else None
    if not d or d != domaine.strip().lower().rstrip("."):
        raise ErreurProtection("nom de domaine invalide")
    cs = [c for c in etat.get("clients", []) if c["nom"] == nom]
    if not cs:
        raise ErreurProtection("appareil inconnu")
    slug = dnstv._slug(nom)
    mac = next((c["mac"] for c in cs if c.get("mac")), "")
    modes = set(modes_effectifs(etat, pauses, nom))
    if actif and modes <= {"off"}:
        raise ErreurProtection("appareil hors du périmètre (OFF) : une exception n'aurait aucun effet")
    if actif and type_ == "bloquer" and not modes & {"auto", "block"}:
        raise ErreurProtection("appareil en OBSERVE : un blocage n'aurait aucun effet ; passez-le en PROTECT ou AUTO d'abord")
    autres = [e for e in exceptions if not (e["appareil"] == slug and e["domaine"] == d)]
    rid = dnstv_regles.identifiant(slug, d)
    try:
        r = regles.get(rid)
    except dnstv_regles.ErreurRegle:
        r = None
    motif = f"exception : {type_}" if actif else f"exception retirée : {type_}"
    if actif:
        if len(autres) >= EXCEPTIONS_MAX or sum(1 for e in autres if e["appareil"] == slug) >= EXCEPTIONS_PAR_APPAREIL:
            raise ErreurPlafond(f"{EXCEPTIONS_MAX} exceptions au plus, {EXCEPTIONS_PAR_APPAREIL} par appareil")
        if r is None:
            r = regles.proposer(slug, d, 0, "faible", maintenant, origine="admin", motif=motif)
        if type_ == "autoriser":
            _vers(regles, rid, {"candidat": ["rejete"], "essai": ["retire", "rejete"], "confirme": ["retire", "rejete"],
                                "retire": ["rejete"], "rejete": []}[r["etat"]], "admin", motif, maintenant)
            aut = {k: list(v) for k, v in etat.get("autorisations", {}).items()}
            liste = set(aut.get(slug, [])) | {d}
            if len(liste) > dnstv.AUTORISATIONS_PAR_APPAREIL:
                raise ErreurPlafond(f"{dnstv.AUTORISATIONS_PAR_APPAREIL} autorisations au plus pour cet appareil : en retirer une d'abord")
            if sum(len(v) for k, v in aut.items() if k != slug) + len(liste) > dnstv.AUTORISATIONS_MAX:
                raise ErreurPlafond(f"{dnstv.AUTORISATIONS_MAX} autorisations au plus pour la maison : en retirer une d'abord")
            aut[slug] = sorted(liste)
            etat["autorisations"] = aut
        else:
            if d in etat.get("autorisations", {}).get(slug, []):          # « bloquer » remplace une autorisation du même couple
                aut = {k: [x for x in v if not (k == slug and x == d)] for k, v in etat["autorisations"].items()}
                aut = {k: v for k, v in aut.items() if v}
                if aut:
                    etat["autorisations"] = aut
                else:
                    etat.pop("autorisations", None)
            _vers(regles, rid, {"candidat": ["essai", "confirme"], "essai": ["confirme"], "confirme": [],
                                "retire": ["essai", "confirme"], "rejete": ["candidat", "essai", "confirme"]}[r["etat"]], "admin", motif, maintenant)
        return autres + [{"appareil": slug, "mac": mac, "domaine": d, "type": type_, "origine": "admin", "maj": int(maintenant)}]
    ancienne = next((e for e in exceptions if e["appareil"] == slug and e["domaine"] == d and e["type"] == type_), None)
    if ancienne is None:
        raise ErreurProtection("exception inconnue")
    if r is not None:
        if type_ == "bloquer" and r["etat"] in ("essai", "confirme"):
            _vers(regles, rid, ["retire"], "admin", motif, maintenant)
        elif type_ == "autoriser" and r["etat"] == "rejete":
            _vers(regles, rid, ["candidat", "retire"], "admin", motif, maintenant)
    if type_ == "autoriser" and d in etat.get("autorisations", {}).get(slug, []):
        aut = {k: [x for x in v if not (k == slug and x == d)] for k, v in etat["autorisations"].items()}
        aut = {k: v for k, v in aut.items() if v}
        if aut:
            etat["autorisations"] = aut
        else:
            etat.pop("autorisations", None)
    return autres


def vue_exceptions(exceptions: list, etat: dict, suspects_legitimes: Iterable[str]) -> dict:
    """Vue UNIFIÉE : exceptions du lot 3, autorisations au puits par appareil (#1965) et suspects jugés légitimes (toute la maison),
    plus les mécanismes laissés hors champ, documentés."""
    noms = {dnstv._slug(c["nom"]): c["nom"] for c in etat.get("clients", [])}
    out = [dict(e, nom=noms.get(e["appareil"], e["appareil"]), source="exception") for e in exceptions]
    for slug, doms in sorted(etat.get("autorisations", {}).items()):
        for d in doms:
            if not any(e["appareil"] == slug and e["domaine"] == d and e["type"] == "autoriser" for e in exceptions):
                out.append({"appareil": slug, "nom": noms.get(slug, slug), "mac": "", "domaine": d, "type": "autoriser", "origine": "admin",
                            "maj": 0, "source": "puits"})
    for d in sorted(suspects_legitimes):
        out.append({"appareil": "", "nom": "toute la maison", "mac": "", "domaine": d, "type": "autoriser", "origine": "admin", "maj": 0,
                    "source": "suspect-legitime"})
    return {"exceptions": out, "hors_champ": [
        {"mecanisme": "liste blanche globale (main.py)", "raison": "table héritée de l'ancien ad-guard, non lue par le filtrage TV"},
        {"mecanisme": "adult-exempt", "raison": "exemption du filtre adulte (autre finalité), gérée par secubox-adguard-adult-sync"}]}
