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
LIVRAISONS = Path("/var/lib/secubox-mirrornet-partage/livraisons/tv-indices")
CATEGORIES_INDICE = ("PUBLICITE", "TRACKING", "TELEMETRIE")

TAILLE_MAX = 2 * 1024 * 1024        # un fichier de livraison ou l'index
INDICES_MAX = 20000                 # indices par livraison ; au-delà, la livraison est ignorée en entier
LEGITIMES_MAX = 5000                # légitimes par livraison ; idem
PRODUCTEURS_MAX = 64                # producteurs lus (ordre de l'index) ; les suivants sont ignorés

log = logging.getLogger(__name__)
DID_RE = re.compile(r"^did:plc:([0-9a-f]{32})$")
NOM_RE = re.compile(r"^[a-z0-9-]{1,32}$")


def _derniere_origine(r: dict) -> str:
    h = r.get("historique") or []
    return (h[-1] or {}).get("origine", "") if h else ""


def contenu(regles, exceptions: list, taxo) -> dict:
    """Contenu publié : {"format", "jeu", "indices": {domaine: catégorie}, "legitimes": [domaines triés]}."""
    indices: Dict[str, str] = {}
    legitimes: Set[str] = set()

    def categorie(d: str) -> str:
        c = (taxo.classer(d) or {}).get("categorie")
        return c if c in CATEGORIES_INDICE else "PUBLICITE"

    for r in regles.liste():
        d = dnstv.valider_domaine(r.get("domaine"))
        if not d:
            continue
        adm = _derniere_origine(r) == "admin"
        if r.get("etat") == "confirme":
            if r.get("indice") and not adm:         # indice reçu d'une autre box : jamais renvoyé (pas d'écho)
                continue
            indices[d] = categorie(d)
        elif r.get("etat") in ("rejete", "retire") and adm:
            legitimes.add(d)
    for e in exceptions or []:
        d = dnstv.valider_domaine(e.get("domaine"))
        if not d:
            continue
        if e.get("type") == "bloquer":
            indices[d] = categorie(d)
        elif e.get("type") == "autoriser":
            legitimes.add(d)
    for d in legitimes:                              # légitime l'emporte
        indices.pop(d, None)
    return {"format": 1, "jeu": "tv-indices", "indices": indices, "legitimes": sorted(legitimes)}


def octets(c: dict) -> bytes:
    """Octets canoniques (MirrorNet les reproduit à l'identique pour l'empreinte)."""
    return json.dumps(c, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def ecrire_publication(publier: bool, recevoir: bool, c: dict, chemin: Path = PUBLICATION) -> bool:
    """Écrit le fichier lu par MirrorNet, en atomique (0640), seulement s'il change. Rend True si écrit."""
    doc = {"format": 1, "publier": bool(publier), "recevoir": bool(recevoir), "contenu": c}
    try:
        if json.loads(chemin.read_text(encoding="utf-8")) == doc:
            return False
    except (OSError, ValueError):
        pass
    chemin.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(chemin.parent), prefix=".indices-", suffix=".tmp")
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
    return True


@dataclass
class Index:
    confirmes: Dict[str, Dict[str, str]] = field(default_factory=dict)    # domaine -> {nom_box: catégorie}
    legitimes: Dict[str, Set[str]] = field(default_factory=dict)          # domaine -> {nom_box}
    # Lecture ratée = jamais un retrait de protection : `lisible` faux si le dossier ou index.json manque ou est illisible ;
    # `indisponibles` : producteurs listés dont le fichier a été écarté (illisible, trop gros, invalide).
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
    """(indices {domaine: catégorie}, légitimes {domaines}) ou None si le fichier est défectueux."""
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
    return indices, legitimes


def charger(dossier: Path = LIVRAISONS) -> Index:
    """Lit `index.json` puis le fichier de chaque producteur. Ne lève jamais ; dossier ou index.json absent ou illisible =
    index vide NON lisible (réception pas encore en place ou lecture ratée : le moteur ne retire alors rien)."""
    ix = Index()
    try:
        idx = _lire_json(Path(dossier) / "index.json")
        if not isinstance(idx, dict):
            return Index(lisible=False)
        for did, meta in list(idx.items())[:PRODUCTEURS_MAX]:
            valide = None
            try:
                m = DID_RE.match(did) if isinstance(did, str) else None
                nom = meta.get("nom") if isinstance(meta, dict) else None
                if not m or not isinstance(nom, str) or not NOM_RE.match(nom):
                    continue
                valide = nom
                v = _valider_contenu(_lire_json(Path(dossier) / (m.group(1) + ".json")))
                if v is None:
                    log.warning("indices : livraison de %s ignorée (illisible, trop grosse ou invalide)", nom)
                    ix.indisponibles.add(nom)
                    continue
                indices, legitimes = v
                for d, cat in indices.items():
                    ix.confirmes.setdefault(d, {})[nom] = cat
                for d in legitimes:
                    ix.legitimes.setdefault(d, set()).add(nom)
            except Exception:                        # noqa: BLE001 — un producteur défectueux n'affecte pas les autres
                log.warning("indices : producteur ignoré (erreur inattendue)")
                if valide:
                    ix.indisponibles.add(valide)
    except Exception:                                # noqa: BLE001 — jamais d'exception vers l'appelant
        return Index(lisible=False)
    return ix
