# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: assistant de détection en direct, lot 5b SBX TV PRIVACY (#3374).

`assistant.json` (DOSSIER_ETAT, 0640) : file d'actions DIFFÉRÉES choisies par l'administrateur dans la vue « En direct » et liste des
appareils en apprentissage guidé. L'API y ajoute (sous `dnstv_regles.verrou`, après audit root) ; le moteur `secubox-adguard-auto` la
consomme à son passage, sous le même verrou : `bloquer` et `legitime` deviennent les exceptions du lot 3 (`poser_exception`, origine
admin : décision manuelle), `plus-tard` ne change rien au DNS. Aucun nouveau mécanisme DNS.
"""
from __future__ import annotations

import os
import secrets
import tempfile
import json
from pathlib import Path
from typing import Iterable, List, Optional

try:
    from . import dnstv, dnstv_protection, dnstv_regles, dnstv_taxonomie
except ImportError:                                   # lancé hors paquet
    from api import dnstv, dnstv_protection, dnstv_regles, dnstv_taxonomie

FICHIER = "assistant.json"
CHOIX = ("bloquer", "legitime", "plus-tard")
ETATS = ("en-attente", "applique", "refuse")
MARQUES = {"bloquer": "confirmee", "legitime": "legitime", "plus-tard": "plus-tard"}
EXCEPTION = {"bloquer": "bloquer", "legitime": "autoriser"}
ATTENTE_MAX = 100                                     # actions en attente
FILE_MAX = 300                                        # entrées en tout (attente + historique de 24 h)
GUIDES_MAX = 64
VUS_MAX = 500                                         # passe 2 : découvertes sans domaine marquées « vu » en attente du moteur
CONSERVATION_S = 86400
LECTURE_MAX = 512 * 1024
APPRIS_JOURS = 7
_CLES = {"id", "mac", "appareil", "domaine", "choix", "force", "decouverte", "acteur", "cree", "etat", "applique", "raison"}


class ErreurAssistant(ValueError):
    """Entrée refusée ; le message est sûr à montrer."""


class ErreurDoublon(ErreurAssistant):
    """Une action est déjà en attente pour ce couple appareil × domaine (409)."""


class ErreurPlafond(ErreurAssistant):
    """File pleine (409) : jamais un succès silencieux."""


def vide() -> dict:
    return {"version": 1, "guides": [], "file": [], "vus": []}


def _entier(v, mini=0) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= mini


def _valider(x) -> dict:
    if not isinstance(x, dict) or set(x) != _CLES:
        raise ErreurAssistant("action invalide")
    ok = (isinstance(x["id"], str) and len(x["id"]) == 16 and all(c in "0123456789abcdef" for c in x["id"])
          and isinstance(x["mac"], str) and dnstv.MAC_RE.match(x["mac"])
          and isinstance(x["appareil"], str) and dnstv.NOM_RE.match(x["appareil"])
          and isinstance(x["domaine"], str) and dnstv.valider_domaine(x["domaine"]) == x["domaine"]
          and x["choix"] in CHOIX and isinstance(x["force"], bool)
          and (x["decouverte"] is None or _entier(x["decouverte"], 1))
          and isinstance(x["acteur"], str) and 1 <= len(x["acteur"]) <= 64
          and _entier(x["cree"]) and x["etat"] in ETATS
          and (x["applique"] is None or _entier(x["applique"]))
          and isinstance(x["raison"], str) and len(x["raison"]) <= 200)
    if not ok:
        raise ErreurAssistant("action invalide")
    return dict(x)


def _valider_vu(v) -> dict:
    if not (isinstance(v, dict) and set(v) == {"id", "mac"} and _entier(v["id"], 1) and isinstance(v["mac"], str) and dnstv.MAC_RE.match(v["mac"])):
        raise ErreurAssistant(f"{FICHIER} : découverte vue invalide")
    return {"id": v["id"], "mac": v["mac"]}


def _valider_tout(brut) -> dict:
    if (not isinstance(brut, dict) or not {"version", "guides", "file"} <= set(brut) <= {"version", "guides", "file", "vus"}
            or brut["version"] != 1 or not isinstance(brut["guides"], list) or not isinstance(brut["file"], list)
            or not isinstance(brut.get("vus", []), list) or len(brut.get("vus", [])) > VUS_MAX
            or len(brut["guides"]) > GUIDES_MAX or len(brut["file"]) > FILE_MAX):
        raise ErreurAssistant(f"{FICHIER} illisible")
    if not all(isinstance(m, str) and dnstv.MAC_RE.match(m) for m in brut["guides"]):
        raise ErreurAssistant(f"{FICHIER} : MAC invalide")
    return {"version": 1, "guides": sorted(set(brut["guides"])), "file": [_valider(x) for x in brut["file"]],
            "vus": [_valider_vu(v) for v in brut.get("vus", [])]}


def charger(dossier: Optional[Path] = None) -> dict:
    """Fichier absent = vide ; lien symbolique ou contenu invalide = refus entier (jamais une file à moitié lue)."""
    f = (dossier or dnstv.DOSSIER_ETAT) / FICHIER
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return vide()
    except OSError as e:
        raise ErreurAssistant(f"{FICHIER} refusé ({type(e).__name__})") from e
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            return _valider_tout(json.loads(h.read(LECTURE_MAX)))
    except ValueError as e:
        if isinstance(e, ErreurAssistant):
            raise
        raise ErreurAssistant(f"{FICHIER} illisible") from e


def ecrire(contenu: dict, dossier: Optional[Path] = None) -> None:
    """Écriture atomique (nom aléatoire créé en O_EXCL, puis `os.replace`) ; revalidée avant d'écrire."""
    propre = _valider_tout(contenu)
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".assistant.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            os.fchmod(h.fileno(), 0o640)
            json.dump(propre, h, ensure_ascii=False, indent=1)
        os.replace(tmp, d / FICHIER)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ── file ─────────────────────────────────────────────────────────────────────────────────────────────────
def ajouter(c: dict, mac: str, appareil: str, domaine: str, choix: str, force: bool, decouverte: Optional[int], acteur: str,
            maintenant: int) -> dict:
    """Ajoute une action EN ATTENTE ; une seule par couple (MAC, domaine) ; file bornée."""
    d = dnstv.valider_domaine(domaine) if isinstance(domaine, str) else None
    if not d or d != domaine:
        raise ErreurAssistant("nom de domaine invalide")
    if choix not in CHOIX:
        raise ErreurAssistant("choix : bloquer, legitime ou plus-tard")
    if not isinstance(mac, str) or not dnstv.MAC_RE.match(mac):
        raise ErreurAssistant("MAC invalide")
    purger(c, maintenant)                              # m1 : les entrées traitées de plus de 24 h ne comptent plus
    attente = [x for x in c["file"] if x["etat"] == "en-attente"]
    if any(x["mac"] == mac and x["domaine"] == d for x in attente):
        raise ErreurDoublon("une action est déjà en attente pour ce domaine sur cet appareil : l'annuler d'abord")
    if len(attente) >= ATTENTE_MAX:
        raise ErreurPlafond(f"{ATTENTE_MAX} actions en attente au plus : attendre le passage du moteur")
    if len(c["file"]) >= FILE_MAX:
        raise ErreurPlafond(f"{FILE_MAX} choix traités en 24 h au plus : les plus anciens sortent de la file au bout de 24 h")
    x = _valider({"id": secrets.token_hex(8), "mac": mac, "appareil": appareil, "domaine": d, "choix": choix, "force": bool(force),
                  "decouverte": decouverte, "acteur": acteur, "cree": int(maintenant), "etat": "en-attente", "applique": None, "raison": ""})
    c["file"].append(x)
    return x


def annuler(c: dict, ident: str) -> dict:
    """Retire une action tant qu'elle n'est pas appliquée (ni refusée)."""
    x = next((y for y in c["file"] if y["id"] == ident), None)
    if x is None:
        raise ErreurAssistant("action inconnue")
    if x["etat"] != "en-attente":
        raise ErreurAssistant("action déjà traitée par le moteur : plus annulable")
    c["file"].remove(x)
    return x


def purger(c: dict, maintenant: int) -> None:
    c["file"] = [x for x in c["file"] if x["etat"] == "en-attente" or maintenant - int(x["applique"] or x["cree"]) <= CONSERVATION_S]


def marquer_vu(c: dict, mac: str, ident: int) -> bool:
    """Passe 2 (I2) : découverte SANS domaine (adresse:port) vue par l'administrateur ; le moteur la marque « plus-tard ». Aucun effet DNS."""
    if not isinstance(mac, str) or not dnstv.MAC_RE.match(mac) or not _entier(ident, 1):
        raise ErreurAssistant("découverte invalide")
    vus = c.setdefault("vus", [])
    if any(v["id"] == ident for v in vus):
        return False
    if len(vus) >= VUS_MAX:
        raise ErreurPlafond(f"{VUS_MAX} découvertes vues en attente au plus : attendre le passage du moteur")
    vus.append({"id": ident, "mac": mac})
    return True


def basculer_guide(c: dict, mac: str, actif: bool) -> bool:
    """Apprentissage guidé d'un appareil (MAC). Rend vrai si quelque chose a changé."""
    if not isinstance(mac, str) or not dnstv.MAC_RE.match(mac):
        raise ErreurAssistant("MAC invalide")
    avant = set(c["guides"])
    apres = (avant | {mac}) if actif else (avant - {mac})
    if len(apres) > GUIDES_MAX:
        raise ErreurPlafond(f"{GUIDES_MAX} appareils guidés au plus")
    c["guides"] = sorted(apres)
    return apres != avant


def slugs_guides(c: dict, etat: dict) -> set:
    """Slugs (identifiants du moteur) des appareils en apprentissage guidé."""
    g = set(c.get("guides", []))
    return {dnstv._slug(x["nom"]) for x in etat.get("clients", []) if x.get("mac") in g}


def _categorie_refusee(taxo, domaine: str, force: bool) -> Optional[str]:
    """Garde du lot 3 sur un blocage manuel : catégorie protégée (hors INCONNU) sans `force` = refus."""
    if force:
        return None
    c = taxo.classer(domaine)
    if c["protegee"] and c["categorie"] != "INCONNU":
        return f"catégorie {c['categorie']} protégée : confirmer le blocage (force)"
    return None


def consommer(c: dict, etat: dict, regles, exceptions: list, pauses: Iterable[dict], taxo, maintenant: int) -> dict:
    """Passage du moteur : applique les actions en attente, dans l'ordre. Modifie `c`, `etat` et `regles` en place. Rend les nouvelles
    exceptions, les découvertes à marquer `(id, état, mac, domaine)`, `appliquees` (identifiants appliqués À CE passage, pour le journal)
    et `dns` (vrai si une exception a changé règles ou état).
    m2 : rejeu après un arrêt entre l'écriture des exceptions et celle de la file : une exception déjà présente dans le même sens est
    marquée `applique` sans être reposée ni journalisée une seconde fois."""
    ex, marques, dns, appliquees = list(exceptions), [], False, []
    pauses = list(pauses)
    for x in c["file"]:
        if x["etat"] != "en-attente":
            continue
        nom = next((k["nom"] for k in etat.get("clients", []) if k.get("mac") == x["mac"]), None)
        raison, deja = None, False
        if x["choix"] in EXCEPTION and nom is not None:
            deja = any(e["appareil"] == dnstv._slug(nom) and e["domaine"] == x["domaine"] and e["type"] == EXCEPTION[x["choix"]] for e in ex)
        if x["choix"] in EXCEPTION and not deja:
            if nom is None:
                raison = "appareil inconnu (retiré du périmètre ?)"
            elif x["choix"] == "bloquer":
                raison = _categorie_refusee(taxo, x["domaine"], x["force"])
            if raison is None:
                try:
                    ex = dnstv_protection.poser_exception(ex, etat, regles, nom, x["domaine"], EXCEPTION[x["choix"]], True, maintenant,
                                                          origine="admin", pauses=pauses)
                    dns = True
                except (dnstv_protection.ErreurProtection, ValueError) as e:
                    raison = str(e)[:200]
        if raison:
            x.update(etat="refuse", applique=int(maintenant), raison=raison[:200])
            continue
        x.update(etat="applique", applique=int(maintenant), raison="")
        if not deja:
            appliquees.append(x["id"])
        if x["decouverte"]:
            marques.append((x["decouverte"], MARQUES[x["choix"]], x["mac"], x["domaine"]))
    marques += [(v["id"], "plus-tard", v["mac"], None) for v in c.get("vus", [])]
    c["vus"] = []
    purger(c, maintenant)
    return {"exceptions": ex, "marques": marques, "dns": dns, "appliquees": appliquees}


# ── taxonomie partagée par l'API et le moteur (I1), en cache dans le processus (m4) ──────────────────────────
_CACHE: dict = {}


def vider_cache() -> None:
    _CACHE.clear()


def _empreinte() -> tuple:
    def mt(f: Path):
        try:
            st = f.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None
    try:
        listes = tuple(sorted((p.name, mt(p)) for p in dnstv.DOSSIER_LISTES.iterdir() if p.is_file()))
    except OSError:
        listes = ()
    return (str(dnstv.DOSSIER_LISTES), str(dnstv.DOSSIER_ETAT), listes, mt(dnstv.DOSSIER_ETAT / dnstv_taxonomie.FICHIER),
            mt(dnstv.DOSSIER_ETAT / dnstv_regles.FICHIER), mt(dnstv.DOSSIER_ETAT / "custom.txt"))


def taxonomie(regles=None):
    """Taxonomie COMPLÈTE (listes, référence, services, profil, corrections manuelles, règles), exactement celle que le moteur revérifie.
    Sans `regles` (API) : rechargée seulement si un fichier source a changé (date et taille). Lève ErreurTaxonomie / ErreurRegle."""
    if regles is not None:
        return dnstv_taxonomie.Taxonomie.depuis_dossier(manuelles=dnstv_taxonomie.charger_manuelles(), regles=regles)
    cle = _empreinte()
    if _CACHE.get("cle") != cle:
        _CACHE.update(cle=cle, taxo=dnstv_taxonomie.Taxonomie.depuis_dossier(manuelles=dnstv_taxonomie.charger_manuelles(),
                                                                               regles=dnstv_regles.charger()))
    return _CACHE["taxo"]


# ── kiosque : compteur agrégé ────────────────────────────────────────────────────────────────────────────
def nouveaux_pisteurs(regles, maintenant: int, jours: int = APPRIS_JOURS) -> int:
    """Domaines distincts passés en essai ou confirmés sur la fenêtre : un nombre, sans appareil ni domaine."""
    depuis = maintenant - jours * 86400
    return len({r["domaine"] for r in regles.liste() if r["etat"] in ("essai", "confirme") and int(r.get("maj", 0)) >= depuis})


def pour_page(c: dict) -> List[dict]:
    """File affichable (plus récentes d'abord)."""
    return sorted((dict(x) for x in c["file"]), key=lambda x: x["cree"], reverse=True)
