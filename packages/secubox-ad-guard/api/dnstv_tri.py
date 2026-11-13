# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tri Netflix par insistance, au niveau DNS (#3226) — pour une TV que la box ne route pas (Wi-Fi de l'opérateur).

Constat du banc (octobre, TV routée) : la vidéo de l'épisode vient d'un serveur sur lequel la TV INSISTE, la publicité
d'un serveur qu'elle abandonne. En Wi-Fi la box ne voit que le DNS : chaque NOUVEAU serveur vidéo Netflix
(`<hôte>.<n>.oca.nflxvideo.net`) demandé par un appareil « trié » reçoit NXDOMAIN (zone de sa vue auto) ; s'il est
redemandé dans `fenetre_s` secondes au moins `seuil` fois (secondes distinctes : A et AAAA d'une même tentative comptent
une fois), il est autorisé `duree_s` secondes (zone transparente plus précise, posée à chaud par le contrôleur root).

Expérimental et désactivable d'un clic : l'état garde `tri_netflix.appareils` (vues auto concernées) et les seuils.
Trois pièces : ce module (logique pure, testée), `secubox-adguard-dnsfeed` (voit les requêtes, détecte l'insistance,
dépose une demande), `secubox-adguard-tv tri-appliquer` (root : valide, `view_local_zone_add`, garde l'échéance).
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ZONE = "oca.nflxvideo.net"
# Motifs ENTIERS (fullmatch partout) : « $ » accepterait un saut de ligne final, qui finirait dans le drop-in Unbound.
SERVEUR_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\.[0-9]{1,3}\.oca\.nflxvideo\.net")
SLUG_RE = re.compile(r"[a-z0-9-]{1,40}")
DEMANDES = Path(os.environ.get("SECUBOX_ADGUARD_TRI_DEMANDES", "/run/secubox/ad-guard-tri"))
# seuil/fenetre_s : insistance sur UN nom (rarement vue en DNS : la TV bascule de serveur au lieu d'insister).
# serveurs/fenetre_zone_s : RAFALE de serveurs nouveaux refusés (démarrage d'épisode) → zone ouverte ouverture_s ;
# chaque serveur résolu pendant l'ouverture reste autorisé duree_s (l'épisode), la zone se referme (pubs isolées).
DEFAUTS = {"seuil": 3, "fenetre_s": 20, "duree_s": 10800, "serveurs": 2, "fenetre_zone_s": 30, "ouverture_s": 180}
BORNES = {"seuil": (2, 10), "fenetre_s": (5, 120), "duree_s": (600, 86400), "serveurs": (2, 10),
          "fenetre_zone_s": (5, 300), "ouverture_s": (30, 1800)}
OUVRIR = "ouvrir"                      # demande spéciale : ouverture de la zone pour l'appareil
MAX_AUTORISES = 64                     # par appareil : au-delà, les plus anciens tombent (un épisode n'en demande que quelques-uns)


class ErreurTri(ValueError):
    pass


def valider(brut) -> Optional[dict]:
    """Réglage `tri_netflix` de l'état : None (absent), ou {appareils: [slugs], seuil, fenetre_s, duree_s} borné."""
    if brut is None:
        return None
    if not isinstance(brut, dict) or set(brut) - {"appareils", *DEFAUTS}:
        raise ErreurTri("tri_netflix : clés admises appareils, seuil, fenetre_s, duree_s")
    app = brut.get("appareils", [])
    if not isinstance(app, list) or len(app) > 8 or any(not isinstance(a, str) or not SLUG_RE.fullmatch(a) for a in app):
        raise ErreurTri("tri_netflix : appareils = 8 identifiants de vue au plus")
    out = {"appareils": sorted(set(app))}
    for cle, (mini, maxi) in BORNES.items():
        v = brut.get(cle, DEFAUTS[cle])
        if type(v) is not int or not mini <= v <= maxi:
            raise ErreurTri(f"tri_netflix : {cle} entier entre {mini} et {maxi}")
        out[cle] = v
    return out


def reglage(etat: dict) -> dict:
    return {**DEFAUTS, "appareils": [], **(etat.get("tri_netflix") or {})}


@dataclass
class Insistance:
    """Vu par dnsfeed : une demande de déblocage quand un serveur refusé est redemandé avec insistance, ou quand un serveur
    déjà autorisé est de nouveau refusé (Unbound rechargé entre-temps : la zone posée à chaud a disparu)."""
    seuil: int = DEFAUTS["seuil"]
    fenetre_s: int = DEFAUTS["fenetre_s"]
    vues: Dict[Tuple[str, str], List[int]] = field(default_factory=dict)
    demandes: Dict[Tuple[str, str], int] = field(default_factory=dict)
    serveurs: int = DEFAUTS["serveurs"]
    fenetre_zone_s: int = DEFAUTS["fenetre_zone_s"]
    ouverture_s: int = DEFAUTS["ouverture_s"]
    refuses: Dict[str, List[Tuple[int, str]]] = field(default_factory=dict)    # slug -> [(ts, serveur)] refusés récents
    ouvert_jusque: Dict[str, int] = field(default_factory=dict)                  # slug -> fin supposée de l'ouverture
    gardes: Dict[str, set] = field(default_factory=dict)                         # slug -> serveurs déjà demandés (ouverture)

    def rafale(self, slug: str, nom: str, ts: int, refuse: bool) -> List[str]:
        """Demandes à déposer pour la règle « par zone » : [OUVRIR] quand `serveurs` serveurs DISTINCTS ont été refusés en
        `fenetre_zone_s` ; pendant l'ouverture supposée, chaque serveur résolu (autorisé) est demandé pour `duree_s`."""
        if not SERVEUR_RE.fullmatch(nom) or not SLUG_RE.fullmatch(slug):
            return []
        if not refuse:
            if ts > self.ouvert_jusque.get(slug, -1):
                return []
            deja = self.gardes.setdefault(slug, set())
            if nom in deja:
                return []                                        # un serveur résolu n'est demandé qu'une fois par ouverture
            deja.add(nom)
            return [nom]
        recents = [(t, n) for t, n in self.refuses.get(slug, []) if ts - t < self.fenetre_zone_s and n != nom] + [(ts, nom)]
        self.refuses[slug] = recents[-32:]
        if len({n for _t, n in recents}) >= self.serveurs and ts > self.ouvert_jusque.get(slug, -1):
            self.ouvert_jusque[slug] = ts + self.ouverture_s
            self.refuses[slug] = []
            self.gardes[slug] = set()
            return [OUVRIR]
        return []

    def voir(self, slug: str, nom: str, ts: int, refuse: bool) -> bool:
        """True quand une demande de déblocage doit partir pour (slug, nom)."""
        if not refuse or not SERVEUR_RE.fullmatch(nom) or not SLUG_RE.fullmatch(slug):
            return False
        cle = (slug, nom)
        secondes = [s for s in self.vues.get(cle, []) if ts - s < self.fenetre_s]
        if ts not in secondes:
            secondes.append(ts)
        self.vues[cle] = secondes[-32:]
        if len(secondes) < self.seuil:
            return False
        if ts - self.demandes.get(cle, -10 ** 9) < 10:          # au plus une demande toutes les 10 s par serveur
            return False
        self.demandes[cle] = ts
        self.vues.pop(cle, None)
        if len(self.vues) > 4096:                                # mémoire bornée : on oublie les plus anciens
            for k in sorted(self.vues, key=lambda k: self.vues[k][-1])[:1024]:
                del self.vues[k]
        if len(self.demandes) > 4096:
            for k in sorted(self.demandes, key=self.demandes.get)[:1024]:
                del self.demandes[k]
        return True


MAX_POSES = 16                         # appels unbound-control par passe du contrôleur, au plus


def deposer_demande(slug: str, nom: str, dossier: Path = DEMANDES) -> bool:
    """Une demande = un fichier vide `<slug>__<nom>` (création exclusive, jamais suivi de lien) ; le contrôleur root la lit."""
    if not SLUG_RE.fullmatch(slug) or not (nom == OUVRIR or SERVEUR_RE.fullmatch(nom)):
        return False
    try:
        fd = os.open(dossier / f"{slug}__{nom}", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        return True
    except FileExistsError:
        return True
    except OSError:
        return False


def lire_demande(nom_fichier: str) -> Optional[Tuple[str, str]]:
    """Nom de fichier → (slug, serveur) revalidés, ou None."""
    slug, sep, nom = nom_fichier.partition("__")
    if not sep or not SLUG_RE.fullmatch(slug) or not (nom == OUVRIR or SERVEUR_RE.fullmatch(nom)):
        return None
    return slug, nom


# ── registre des autorisations (contrôleur root) ────────────────────────────────────────────────────────────────────

def charger_autorises(brut) -> Dict[str, Dict[str, int]]:
    """{slug: {serveur: échéance}} revalidé ; toute entrée douteuse est ignorée (jamais un argument d'unbound-control)."""
    out: Dict[str, Dict[str, int]] = {}
    if not isinstance(brut, dict):
        return out
    for slug, noms in brut.items():
        if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug) or not isinstance(noms, dict):
            continue
        out[slug] = {n: int(e) for n, e in noms.items()
                     if isinstance(n, str) and SERVEUR_RE.fullmatch(n) and type(e) is int and e > 0}
    return out


def autoriser(autorises: Dict[str, Dict[str, int]], slug: str, nom: str, duree_s: int, maintenant: Optional[int] = None) -> bool:
    """Ajoute ou prolonge ; rend True si le serveur n'était pas déjà autorisé (zone à poser)."""
    maintenant = int(maintenant if maintenant is not None else time.time())
    noms = autorises.setdefault(slug, {})
    nouveau = noms.get(nom, 0) <= maintenant
    noms[nom] = maintenant + duree_s
    if len(noms) > MAX_AUTORISES:
        for vieux in sorted(noms, key=noms.get)[: len(noms) - MAX_AUTORISES]:
            del noms[vieux]
    return nouveau


def echus(autorises: Dict[str, Dict[str, int]], maintenant: Optional[int] = None) -> List[Tuple[str, str]]:
    """Retire et rend les (slug, serveur) arrivés à échéance."""
    maintenant = int(maintenant if maintenant is not None else time.time())
    out = []
    for slug, noms in autorises.items():
        for nom in [n for n, e in noms.items() if e <= maintenant]:
            del noms[nom]
            out.append((slug, nom))
    return out


def zones_vue(slug: str, etat: dict, autorises: Dict[str, Dict[str, int]], maintenant: Optional[int] = None,
              ouvertures: Optional[Dict[str, int]] = None) -> List[str]:
    """Lignes `local-zone` à écrire dans la vue auto de `slug` (rendu complet : un rechargement d'Unbound les garde).
    Le refus de zone est TOUJOURS rendu : l'ouverture (démarrage d'épisode) n'existe qu'à chaud, un rechargement la referme
    (échec fermé ; la TV refait une rafale si elle a encore besoin de vidéo). `ouvertures` est ignoré, gardé pour l'appel."""
    r = reglage(etat)
    if slug not in r["appareils"]:
        return []
    maintenant = int(maintenant if maintenant is not None else time.time())
    lignes = [f'    local-zone: "{ZONE}." always_nxdomain']
    for nom, e in sorted((autorises.get(slug) or {}).items()):
        if e > maintenant and SERVEUR_RE.fullmatch(nom):
            lignes.append(f'    local-zone: "{nom}." transparent')
    return lignes


def lire_json(chemin: Path) -> dict:
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return {}
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            return json.loads(h.read(1 << 20))
    except (OSError, ValueError):
        return {}


def charger_ouvertures(brut) -> Dict[str, int]:
    """{slug: fin d'ouverture} revalidé."""
    if not isinstance(brut, dict):
        return {}
    return {k: v for k, v in brut.items() if isinstance(k, str) and SLUG_RE.fullmatch(k) and type(v) is int and v > 0}
