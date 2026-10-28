# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — ce que le profil actif ajoute au plan (#3218)
CyberMind — https://cybermind.fr

Les manifestes ne décrivent que des services (`secubox-<id>.service`, dérivés par `scan`) : une MINUTERIE leur
échappait. Sa tâche est un oneshot, jamais « actif » ; l'arrêter ne coupe pas la minuterie, qui la relance. Le banc
de l'ESPRESSObin de 1 Go (gk5, 2026-10-28) a pourtant mesuré ces minuteries comme un surplus du profil minimal :
netstats toutes les 30 s, metrics-publish toutes les minutes, relevé et réchauffage de caches toutes les 5 min.

`etendre` rend, pour le SEUL calcul du plan (diff, apply), deux corrections du profil actif :

  * `minuteurs_off` : chaque minuterie nommée devient un pseudo-module `minuteur:<id>` (unité `secubox-<id>.timer`).
    L'ensemble géré est l'UNION des `minuteurs_off` de tous les profils du dossier : le profil qui la nomme l'arrête
    et la désactive ; les autres la rétablissent (activée et démarrée), comme pour un module, de sorte qu'un
    basculement donne le même état quel que soit le départ. N'y nommer que des minuteries que leur paquet active
    par défaut : la rétablir ailleurs, c'est revenir au défaut du paquet. Une unité absente du disque n'est pas
    gérée (un START sur une unité inconnue échouerait et annulerait tout l'apply).
  * `proteges_off` : un module protégé de manifest.PROTEGES_COUPABLES que le profil coupe est vu non protégé ici,
    et seulement ici (statut, sommeil, pins gardent la protection). load_profile a déjà refusé tout autre id.

Les manifestes sur disque ne sont jamais modifiés ; sans profil actif, rien n'est ajouté.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

from .manifest import PROTEGES_COUPABLES, Manifest
from .state import MINUTEUR_ID, Profile, StateError, load_profile

PREFIXE = "minuteur:"
# Priorité basse : arrêtées les premières, rétablies les dernières (diff.plan_changes trie par priorité).
PRIORITE = 10
DOSSIERS_UNITES = (Path("/etc/systemd/system"), Path("/usr/lib/systemd/system"), Path("/lib/systemd/system"))


def unite(tid: str) -> str:
    return f"secubox-{tid}.timer"


def manifeste(tid: str) -> Manifest:
    return Manifest(id=PREFIXE + tid, category="infra", runtime="native", exposure="internal",
                    units=(unite(tid),), priority=PRIORITE)


def manifestes_du_snapshot(snap: dict) -> dict[str, Manifest]:
    """Pseudo-manifestes des minuteries capturées par un apply (snapshot 4R), pour que le rollback les restaure.
    Un id qui n'est pas une minuterie valide est ignoré (jamais une unité construite d'un nom arbitraire)."""
    out: dict[str, Manifest] = {}
    for mid in (snap or {}).get("modules", {}) or {}:
        if isinstance(mid, str) and mid.startswith(PREFIXE) and MINUTEUR_ID.fullmatch(mid[len(PREFIXE):]):
            out[mid] = manifeste(mid[len(PREFIXE):])
    return out


def unite_presente(nom: str, dossiers=None) -> bool:
    """Le fichier d'unité existe-t-il ? Une instance `a@b.timer` sans fichier propre vaut par son gabarit `a@.timer`.
    Dossiers lus à l'appel (DOSSIERS_UNITES), pas figés à l'import : les tests les redirigent."""
    dossiers = DOSSIERS_UNITES if dossiers is None else dossiers
    noms = [nom]
    if "@" in nom:
        base, _, reste = nom.partition("@")
        noms.append(f"{base}@{reste[reste.rfind('.'):]}")
    return any((Path(d) / n).is_file() for d in dossiers for n in noms)


def minuteurs_geres(prof_dir: Path) -> set[str]:
    """Union des `minuteurs_off` des profils du dossier. Un profil illisible n'empêche pas d'appliquer les autres :
    il est ignoré ici (son propre chargement, lui, échoue en le disant)."""
    out: set[str] = set()
    for p in sorted(Path(prof_dir).glob("*.toml")):
        try:
            out |= load_profile(p).minuteurs_off
        except StateError:
            continue
    return out


def etendre(manifests: dict[str, Manifest], profile: Profile | None, prof_dir: Path, *,
            presente=None) -> tuple[dict[str, Manifest], Profile | None]:
    """Manifestes et profil EFFECTIFS pour planifier (voir l'en-tête)."""
    if profile is None:
        return manifests, profile
    presente = presente or unite_presente
    eff = dict(manifests)
    for mid in sorted(profile.proteges_off & PROTEGES_COUPABLES):
        m = eff.get(mid)
        if m is not None and m.protected:
            eff[mid] = dataclasses.replace(m, protected=False)
    on = set(profile.on)
    for tid in sorted(minuteurs_geres(prof_dir) | profile.minuteurs_off):
        if not presente(unite(tid)):
            continue
        m = manifeste(tid)
        eff[m.id] = m
        if tid not in profile.minuteurs_off:
            on.add(m.id)
    return eff, dataclasses.replace(profile, on=frozenset(on))
