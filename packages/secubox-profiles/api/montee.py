# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — montée de niveau par apt (#3428)
CyberMind — https://cybermind.fr

Les images sont livrées en profil d'AMORÇAGE (lite, minimal sur ESPRESSObin) : seul le méta-paquet du profil et
ses Depends y sont. `apply --profile isp|full` ne faisait que démarrer et arrêter des unités : sur une box lite,
les modules d'isp n'étant pas installés, rien ne changeait. Avant l'apply, on installe donc le méta-paquet
`secubox-<profil>` par apt (dépôt signé apt.secubox.in posé par chaque image).

Règles :
  - JAMAIS de délai sur apt/dpkg : une installation coupée en route laisse dpkg à moitié configuré ;
  - chaque décision (déjà installé, installé, échec) est écrite dans le journal d'audit ;
  - SANS RÉSEAU : apt échoue, on le dit clairement et on rend RC_DIFFERE sans rien changer — la box garde
    son profil d'amorçage, l'opération se relance une fois le réseau revenu (premier pas ne bloque pas).
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from . import audit

#: Profils adossés à un méta-paquet secubox-<profil> (Section: metapackages). Les autres profils d'activation
#: (media-lab, secure-gateway, distante…) ne pilotent que des services déjà installés.
PROFILS_META = ("lite", "minimal", "isp", "full")

#: Code rendu quand les paquets du profil n'ont pas pu être TÉLÉCHARGÉS (réseau, dépôt) : rien n'a changé.
RC_DIFFERE = 4
#: Code rendu quand l'installation/configuration elle-même a échoué : le système a pu changer, c'est un ÉCHEC.
RC_ECHEC = 5

Lanceur = Callable[[List[str]], Tuple[int, str]]

_APT_ENV = {"DEBIAN_FRONTEND": "noninteractive"}
_DPKG_OPTS = ["-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]


def lancer(argv: List[str]) -> Tuple[int, str]:
    """Sans timeout (règle du projet : jamais de délai sur apt/dpkg). rc 127 si l'outil manque."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, env={**os.environ, **_APT_ENV})
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except OSError as exc:
        return 127, str(exc)


def meta_paquet(profil: Optional[str]) -> Optional[str]:
    return f"secubox-{profil}" if profil in PROFILS_META else None


def est_installe(paquet: str, run: Lanceur = lancer) -> bool:
    rc, out = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}", paquet])
    return rc == 0 and out.startswith("ii")


def _trace(evenement: str, paquet: str, audit_path: Path, **plus) -> None:
    audit.record({"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "module": "profiles", "event": evenement, "package": paquet, **plus}, path=audit_path)


def _fin(sortie: str, n: int = 400) -> str:
    lignes = [ln for ln in sortie.strip().splitlines() if ln.strip()]
    return " | ".join(lignes[-3:])[-n:]


def installer(profil: Optional[str], *, run: Lanceur = lancer,
              audit_path: Path = audit.AUDIT_LOG) -> Tuple[int, str, bool]:
    """Installe le méta-paquet du profil s'il manque. Rend (rc, message, installe_maintenant).

    rc 0 : déjà présent, profil sans méta-paquet, ou installé ; RC_DIFFERE : mise à jour des index ou téléchargement
    impossible (rien n'a changé) ; RC_ECHEC : l'installation elle-même a échoué.
    """
    paquet = meta_paquet(profil)
    if paquet is None:
        return 0, f"profil « {profil} » sans méta-paquet : services déjà installés seulement", False
    if est_installe(paquet, run):
        _trace("profile_upgrade_skip", paquet, audit_path, profile=profil)
        return 0, f"{paquet} déjà installé", False
    _trace("profile_upgrade_start", paquet, audit_path, profile=profil)
    # Télécharger D'ABORD (--download-only ne touche pas au système) : seul un échec à ce stade garantit « rien changé ».
    rc, out = run(["apt-get", "update", "-q"])
    if rc == 0:
        rc, out = run(["apt-get", "install", "-y", "-q", "--download-only", paquet])
    if rc == 0:
        rc, out = run(["apt-get", "install", "-y", "-q", *_DPKG_OPTS, paquet])
        if rc != 0:
            _trace("profile_upgrade_failed", paquet, audit_path, profile=profil, rc=rc, stage="install", detail=_fin(out))
            return RC_ECHEC, (
                f"installation de {paquet} échouée (apt rc={rc} : {_fin(out, 200) or 'sans détail'}). Paquets "
                "téléchargés mais installation/configuration interrompue : vérifier `dpkg --audit` puis "
                f"`apt-get -f install`, et relancer secubox-profilectl apply --profile {profil} --yes"), False
    if rc != 0:
        _trace("profile_upgrade_failed", paquet, audit_path, profile=profil, rc=rc, stage="download", detail=_fin(out))
        return RC_DIFFERE, (
            f"{paquet} n'a pas pu être installé (apt rc={rc} : {_fin(out, 200) or 'sans détail'}). "
            "Réseau ou dépôt apt.secubox.in injoignable ? Rien n'a été changé : la box garde son profil actuel. "
            f"Relancer une fois connecté : secubox-profilectl apply --profile {profil} --yes"), False
    _trace("profile_upgrade_done", paquet, audit_path, profile=profil)
    return 0, f"{paquet} installé par apt", True
