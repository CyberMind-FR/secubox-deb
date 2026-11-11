# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: indices de détection TV Privacy partagés entre box (#3666).

Deux sens, sans entrée/sortie réseau :
- `contenu` : ce que cette box publie (domaines confirmés / légitimes), SANS appareil ni date ;
- `charger` : ce que les autres box ont livré (dossier alimenté par MirrorNet), relu avec méfiance :
  liens symboliques refusés (O_NOFOLLOW), taille vérifiée avant `json.loads`, tout est revalidé,
  un fichier défectueux est ignoré en entier sans empêcher les autres.
"""
from __future__ import annotations

import json
import logging
import os
import re
import stat
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from . import dnstv

PUBLICATION = Path("/var/lib/secubox/ad-guard/dnstv/indices-publication.json")
RESUME = Path("/var/lib/secubox/ad-guard/dnstv/indices-resume.json")     # écrit par le moteur, lu par GET /indices
LIVRAISONS = Path("/var/lib/secubox-mirrornet-partage/livraisons/tv-indices")
CATEGORIES_INDICE = ("PUBLICITE", "TRACKING", "TELEMETRIE")
CATEGORIES_LEGITIME = CATEGORIES_INDICE + ("INCONNU",)

TAILLE_MAX = 2 * 1024 * 1024        # un fichier de livraison ou l'index
INDICES_MAX = 20000                 # indices par livraison ; au-delà, la livraison est ignorée en entier
LEGITIMES_MAX = 5000                # légitimes par livraison ; idem
PRODUCTEURS_MAX = 64                # producteurs lus (ordre de l'index) ; les suivants sont ignorés
DOMAINES_MAX = 50000                # indices + légitimes, tous producteurs ; au-delà, les producteurs suivants sont ignorés

log = logging.getLogger(__name__)
DID_RE = re.compile(r"^did:plc:([0-9a-f]{32})$")
NOM_RE = re.compile(r"^[a-z0-9-]{1,32}$")


def _derniere_origine(r: dict) -> str:
    h = r.get("historique") or []
    return (h[-1] or {}).get("origine", "") if h else ""


def contenu(regles, exceptions: list, taxo) -> dict:
    """Contenu publié : {"format", "jeu", "indices": {domaine: catégorie}, "legitimes": [domaines triés]}.

    Vie privée (#3666) : un domaine n'est publié que si sa catégorie LOCALE est PUBLICITE, TRACKING ou TELEMETRIE (étiquette =
    cette catégorie), ou INCONNU avec une règle confirmée par l'ADMINISTRATEUR (étiquette PUBLICITE). Une exception « bloquer » sur
    un domaine d'une autre catégorie (contrôle parental, streaming…) n'est jamais publiée. Légitimes : seulement les domaines
    autorisés ou rejetés de catégorie pub / pistage / télémétrie ou INCONNU."""
    indices: Dict[str, str] = {}
    legitimes: Set[str] = set()

    def categorie(d: str) -> Optional[str]:
        c = (taxo.classer(d) or {}).get("categorie")
        return c if isinstance(c, str) else None

    for r in regles.liste():
        d = dnstv.valider_domaine(r.get("domaine"))
        if not d:
            continue
        adm = _derniere_origine(r) == "admin"
        if r.get("etat") == "confirme":
            if r.get("indice") and not adm:         # indice reçu d'une autre box : jamais renvoyé (pas d'écho)
                continue
            c = categorie(d)
            if c in CATEGORIES_INDICE:
                indices[d] = c
            elif c == "INCONNU" and adm:
                indices[d] = "PUBLICITE"
        elif r.get("etat") in ("rejete", "retire") and adm and categorie(d) in CATEGORIES_LEGITIME:
            legitimes.add(d)
    for e in exceptions or []:
        d = dnstv.valider_domaine(e.get("domaine"))
        if not d:
            continue
        if e.get("type") == "bloquer":
            c = categorie(d)
            if c in CATEGORIES_INDICE:
                indices[d] = c
        elif e.get("type") == "autoriser" and categorie(d) in CATEGORIES_LEGITIME:
            legitimes.add(d)
    for d in legitimes:                              # légitime l'emporte
        indices.pop(d, None)
    return {"format": 1, "jeu": "tv-indices", "indices": indices, "legitimes": sorted(legitimes)}


def octets(c: dict) -> bytes:
    """Octets canoniques (MirrorNet les reproduit à l'identique pour l'empreinte)."""
    return json.dumps(c, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _ecrire_atomique(chemin: Path, doc: dict, prefixe: str) -> None:
    chemin.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(chemin.parent), prefix=prefixe, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False).encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _deja_ecrit(chemin: Path, doc: dict) -> bool:
    """Vrai si `chemin` porte déjà `doc` ; un mode qui a dérivé est alors remis à 0640 (fichier ordinaire seulement)."""
    if _lire_json(chemin) != doc:
        return False
    st = os.lstat(chemin)
    if stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) != 0o640:
        os.chmod(chemin, 0o640)
    return True


def ecrire_publication(publier: bool, recevoir: bool, c: dict, chemin: Path = PUBLICATION) -> bool:
    """Écrit le fichier lu par MirrorNet, en atomique (0640), seulement s'il change. Rend True si écrit."""
    doc = {"format": 1, "publier": bool(publier), "recevoir": bool(recevoir), "contenu": c}
    try:
        if _deja_ecrit(chemin, doc):
            return False
    except OSError:
        pass
    _ecrire_atomique(chemin, doc, ".indices-")
    return True


def contenu_vide() -> dict:
    return {"format": 1, "jeu": "tv-indices", "indices": {}, "legitimes": []}


def ecrire_drapeaux(publier: bool, recevoir: bool, chemin: Path = PUBLICATION) -> bool:
    """Interrupteurs seuls (#3666) : le contenu publié actuel est conservé (vide si absent ou illisible), seuls `publier` et
    `recevoir` changent — appelé par POST /indices et par le moteur avant une sortie anticipée. Rend True si écrit."""
    doc = _lire_json(chemin)
    c = doc.get("contenu") if isinstance(doc, dict) else None
    if not (isinstance(c, dict) and c.get("format") == 1 and c.get("jeu") == "tv-indices"
            and isinstance(c.get("indices"), dict) and isinstance(c.get("legitimes"), list)):
        c = contenu_vide()
    return ecrire_publication(publier, recevoir, c, chemin)


@dataclass
class Index:
    confirmes: Dict[str, Dict[str, str]] = field(default_factory=dict)    # domaine -> {nom_box: catégorie}
    legitimes: Dict[str, Set[str]] = field(default_factory=dict)          # domaine -> {nom_box}
    # Lecture LOCALE ratée = jamais un retrait de protection : `lisible` faux si le dossier ou index.json manque ou est illisible ;
    # `indisponibles` : producteurs listés dont le fichier n'a pas pu être LU ici (absent, lien, trop gros sur disque, JSON
    # tronqué). Un contenu lu mais invalide (schéma, plafonds, listes qui se recoupent) n'en fait pas partie : le producteur est
    # traité comme n'ayant AUCUN indice (ce qu'il signe ne peut pas figer un blocage).
    lisible: bool = True
    indisponibles: Set[str] = field(default_factory=set)

    def confirmateurs(self, d: str) -> List[str]:
        return sorted(self.confirmes.get(d, {}))

    def legitime_chez(self, d: str) -> List[str]:
        return sorted(self.legitimes.get(d, set()))

    def categorie(self, d: str) -> Optional[str]:
        cats = Counter(self.confirmes.get(d, {}).values())
        if not cats:
            return None
        return sorted(cats.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def _lire_json(chemin: Path):
    """JSON d'un fichier ordinaire (pas de lien symbolique), de taille bornée ; None au moindre défaut."""
    fd = -1
    try:
        fd = os.open(str(chemin), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > TAILLE_MAX:
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            brut = f.read(TAILLE_MAX + 1)
        if len(brut) > TAILLE_MAX:
            return None
        return json.loads(brut.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _valider_contenu(c):
    """(indices {domaine: catégorie}, légitimes {domaines}) ou None si le contenu est invalide (schéma, plafonds, un même domaine
    à la fois indice et légitime). Une entrée isolée mal formée (domaine invalide, catégorie hors liste) est seulement écartée."""
    if not isinstance(c, dict) or c.get("format") != 1 or c.get("jeu") != "tv-indices":
        return None
    ind, leg = c.get("indices"), c.get("legitimes")
    if not isinstance(ind, dict) or not isinstance(leg, list) or len(ind) > INDICES_MAX or len(leg) > LEGITIMES_MAX:
        return None
    indices: Dict[str, str] = {}
    for d in sorted(k for k in ind if isinstance(k, str)):      # ordre trié : en cas de doublon normalisé, le premier gagne
        cat = ind[d]
        n = dnstv.valider_domaine(d)
        if n and cat in CATEGORIES_INDICE and n not in indices:
            indices[n] = cat
    legitimes = {n for n in (dnstv.valider_domaine(d) for d in leg if isinstance(d, str)) if n}
    if legitimes & set(indices):
        return None                                  # contradictoire : le producteur entier est rejeté
    return indices, legitimes


def charger(dossier: Path = LIVRAISONS) -> Index:
    """Lit `index.json` puis le fichier de chaque producteur. Ne lève jamais ; dossier ou index.json absent ou illisible =
    index vide NON lisible (réception pas encore en place ou lecture ratée : le moteur ne retire alors rien).

    Fichier d'un producteur absent ou illisible ici → `indisponibles` ; contenu lu mais invalide → aucun indice de ce producteur.
    Plafond global DOMAINES_MAX (indices + légitimes) : dans l'ordre de l'index, le producteur qui le dépasserait et tous les
    suivants sont ignorés."""
    ix = Index()
    try:
        chemin_index = Path(dossier) / "index.json"
        idx = _lire_json(chemin_index)
        if not isinstance(idx, dict):
            if os.path.lexists(chemin_index):
                log.warning("indices : %s illisible ou invalide, aucun indice lu (rien n'est retiré)", chemin_index)
            else:
                log.info("indices : %s absent (réception pas encore en place)", chemin_index)
            return Index(lisible=False)
        total, plein = 0, False
        for did, meta in list(idx.items())[:PRODUCTEURS_MAX]:
            valide = None
            try:
                m = DID_RE.match(did) if isinstance(did, str) else None
                nom = meta.get("nom") if isinstance(meta, dict) else None
                if not m or not isinstance(nom, str) or not NOM_RE.match(nom):
                    continue
                valide = nom
                brut = _lire_json(Path(dossier) / (m.group(1) + ".json"))
                if brut is None:
                    log.warning("indices : livraison de %s illisible ici (absente, trop grosse ou tronquée)", nom)
                    ix.indisponibles.add(nom)
                    continue
                v = _valider_contenu(brut)
                if v is None:
                    log.warning("indices : contenu de %s invalide, traité comme sans indice", nom)
                    continue
                indices, legitimes = v
                if plein or total + len(indices) + len(legitimes) > DOMAINES_MAX:
                    if not plein:
                        log.warning("indices : plus de %s domaines reçus, %s et les producteurs suivants sont ignorés", DOMAINES_MAX, nom)
                    plein = True
                    continue
                total += len(indices) + len(legitimes)
                for d, cat in indices.items():
                    ix.confirmes.setdefault(d, {})[nom] = cat
                for d in legitimes:
                    ix.legitimes.setdefault(d, set()).add(nom)
            except Exception:                        # noqa: BLE001 — un producteur défectueux n'affecte pas les autres
                log.warning("indices : producteur ignoré (erreur inattendue)")
                if valide:
                    ix.indisponibles.add(valide)
    except Exception:                                # noqa: BLE001 — jamais d'exception vers l'appelant
        log.exception("indices : lecture des livraisons en échec, aucun indice lu (rien n'est retiré)")
        return Index(lisible=False)
    return ix


def resume(ix: Index, dossier: Path = LIVRAISONS) -> dict:
    """Petit résumé pour GET /indices (#3666) : domaines reçus, producteurs {nom, indices, legitimes}, `maj` = date (s) de
    index.json (None si la réception n'est pas lisible). Aucun domaine n'y figure."""
    prod: Dict[str, List[int]] = {}
    for par in ix.confirmes.values():
        for nom in par:
            prod.setdefault(nom, [0, 0])[0] += 1
    for noms in ix.legitimes.values():
        for nom in noms:
            prod.setdefault(nom, [0, 0])[1] += 1
    maj = None
    if ix.lisible:
        try:
            maj = int(os.lstat(Path(dossier) / "index.json").st_mtime)
        except OSError:
            maj = None
    return {"format": 1, "recus": len(ix.confirmes), "maj": maj,
            "producteurs": [{"nom": n, "indices": v[0], "legitimes": v[1]} for n, v in sorted(prod.items())]}


def ecrire_resume(r: dict, chemin: Path = RESUME) -> bool:
    """Écrit le résumé (atomique, 0640) seulement s'il change. Rend True si écrit."""
    try:
        if _deja_ecrit(chemin, r):
            return False
    except OSError:
        pass
    _ecrire_atomique(chemin, r, ".indices-resume-")
    return True


def lire_resume(chemin: Path = RESUME) -> dict:
    """Résumé relu pour la route : champs revalidés ; absent ou invalide = rien reçu, date inconnue."""
    r = _lire_json(chemin)
    vide = {"recus": 0, "producteurs": [], "maj": None}
    if not isinstance(r, dict):
        return vide
    recus, maj, prod = r.get("recus"), r.get("maj"), r.get("producteurs")
    if type(recus) is not int or recus < 0 or not (maj is None or type(maj) is int) or not isinstance(prod, list):
        return vide
    propres = []
    for p in prod[:PRODUCTEURS_MAX]:
        if (isinstance(p, dict) and isinstance(p.get("nom"), str) and NOM_RE.match(p["nom"])
                and type(p.get("indices")) is int and type(p.get("legitimes")) is int):
            propres.append({"nom": p["nom"], "indices": p["indices"], "legitimes": p["legitimes"]})
    return {"recus": recus, "producteurs": propres, "maj": maj}
