# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Émissions hebdomadaires (#4058, Task 16) : minuterie utilisateur, lundi 06:00.

D'abord UNE synthèse de tous les sujets qui ont changé dans la semaine, puis une émission par sujet dont les
évolutions marquantes atteignent le seuil (réglage `seuil`, défaut 3 ; un chiffre est marquant à `ecart`, défaut 25 %).
Tout passe par la file du service (une production à la fois, la synthèse d'abord). Des BROUILLONS seulement, puis une
notification : ce module n'a aucun chemin vers la publication, qui reste le clic du propriétaire.

    python -m emissions.hebdo        (unité secubox-ai-emissions-hebdo.service)
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

SEUIL = 3


def planifier_semaine(sujets: Dict[str, List[Dict[str, Any]]], seuil: int = SEUIL) -> List[Dict[str, Any]]:
    changes = [s for s, faits in sujets.items() if faits]
    if not changes:
        return []
    plan = [{"format": "synthese", "sources": changes}]
    plan += [{"format": "sujet", "sources": [s]} for s in changes
             if sum(bool(f.get("marquant")) for f in sujets[s]) >= seuil]
    return plan


def purger_mp4(base: Path, jours: int, maintenant: Optional[float] = None) -> int:
    """Rétention locale : MP4 des brouillons plus vieux que `jours` ôtés (MP3 et diapos gardés)."""
    limite = (maintenant or time.time()) - jours * 86400
    n = 0
    for f in (Path(base) / "brouillons").glob("*/emission.mp4"):
        if not f.is_symlink() and f.stat().st_mtime < limite:
            f.unlink(missing_ok=True)
            n += 1
    return n


def notifier_bureau(texte: str) -> None:
    if shutil.which("notify-send"):
        subprocess.run(["notify-send", "-a", "SecuBox AI", "Atelier des émissions", texte], check=False, timeout=10,
                       capture_output=True)


async def executer(client: httpx.AsyncClient, notifier: Callable[[str], None] = notifier_bureau,
                   base: Optional[Path] = None) -> List[str]:
    r = await client.get("/reglages")
    r.raise_for_status()
    reg = r.json()
    if base is not None:
        purger_mp4(base, int(reg.get("mp4_jours") or 14))
    e = await client.get("/evolutions", timeout=600)
    e.raise_for_status()
    plan = planifier_semaine(e.json().get("sujets") or {}, int(reg.get("seuil") or SEUIL))
    ids = []
    for p in plan:
        rep = await client.post("/produire", json=p)
        rep.raise_for_status()
        ids.append(rep.json()["id"])
    if ids:
        notifier(f"{len(ids)} brouillon(s) d'émission en production : à relire et valider dans l'onglet Émissions.")
    else:
        notifier("Aucune évolution cette semaine : pas d'émission.")
    return ids


def main() -> int:
    from .app import JETON_DEFAUT, lire_jeton
    from .reglages import etat_dir
    sock = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "secubox-ai-emissions/emissions.sock"
    jeton = lire_jeton(Path(os.environ.get("SECUBOX_AI_EMISSIONS_JETON") or JETON_DEFAUT))

    async def go() -> List[str]:
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(sock)), base_url="http://emissions",
                                     headers={"Authorization": f"Bearer {jeton}"}, timeout=60, trust_env=False) as c:
            return await executer(c, base=etat_dir())
    asyncio.run(go())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
