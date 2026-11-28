# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Réglages de l'atelier des émissions (#4058, Task 14).

Trois couches : défauts du code ← `~/.config/secubox-ai-emissions/reglages.toml` (posé par le propriétaire : adresses
de gk2, des billets, du Voice Studio) ← `<état>/reglages.json` (écrit par le panneau, clés MODIFIABLES seulement).
Les adresses ne se changent JAMAIS depuis le panneau : une page ne doit pas pouvoir pointer le service ailleurs.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any, Dict

DEFAUTS: Dict[str, Any] = {
    "voix_url": "http://127.0.0.1:3910",                       # Voice Studio LOCAL de gk0 (voicestudio-worker)
    "voix_gpu": False,                                         # CUDA en panne : voix sur CPU, Gemma non suspendu
    "voix1": "nova", "voix2": "onyx",
    "gk2_base": "https://admin.gk2.secubox.in/api/v1/waf",     # lecture seule : /rapports, /rapports/{genre}/{id}
    "gk2_aud": "gk2",                                          # audience des jetons ai-lecture (= AUD_GK2 du relais)
    "billets_base": "https://billets.gk2.secubox.in",          # API d'administration des billets (Task 17)
    "seuil": 3,                                                # hebdo : évolutions marquantes pour une émission par sujet
    "ecart": 0.25,                                             # écart d'un chiffre jugé marquant
    "mp4_jours": 14,                                           # rétention des MP4 locaux des brouillons
}
_VOIX = re.compile(r"^[a-z0-9_-]{1,40}$")
MODIFIABLES = {
    "voix_gpu": lambda v: v if isinstance(v, bool) else _refus("voix_gpu : booléen"),
    "voix1": lambda v: v if isinstance(v, str) and _VOIX.match(v) else _refus("voix1 invalide"),
    "voix2": lambda v: v if isinstance(v, str) and _VOIX.match(v) else _refus("voix2 invalide"),
    "seuil": lambda v: v if isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 50 else _refus("seuil 1..50"),
    "ecart": lambda v: float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and 0.01 <= v <= 5
    else _refus("ecart 0,01..5"),
    "mp4_jours": lambda v: v if isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 365
    else _refus("mp4_jours 1..365"),
}
CONFIG = Path(os.environ.get("SECUBOX_AI_EMISSIONS_CONFIG")
              or Path.home() / ".config/secubox-ai-emissions/reglages.toml")


def _refus(msg: str):
    raise ValueError(msg)


def etat_dir() -> Path:
    return Path(os.environ.get("SECUBOX_AI_EMISSIONS_ETAT") or Path.home() / ".local/state/secubox-ai-emissions")


def lire(base: Path | None = None, config: Path | None = None) -> Dict[str, Any]:
    r = dict(DEFAUTS)
    try:
        t = tomllib.loads(Path(config or CONFIG).read_text(encoding="utf-8"))
        r.update({k: v for k, v in t.items() if k in DEFAUTS and type(v) is type(DEFAUTS[k])})
    except (OSError, ValueError):
        pass
    try:
        j = json.loads((Path(base or etat_dir()) / "reglages.json").read_text(encoding="utf-8"))
        for k, v in (j if isinstance(j, dict) else {}).items():
            if k in MODIFIABLES:
                try:
                    r[k] = MODIFIABLES[k](v)
                except ValueError:
                    continue
    except (OSError, ValueError):
        pass
    return r


def modifier(changes: Dict[str, Any], base: Path | None = None) -> Dict[str, Any]:
    """Valide puis écrit (fichier temporaire → os.replace, 0600) ; une clé hors MODIFIABLES → ValueError."""
    inconnues = set(changes) - set(MODIFIABLES)
    if inconnues:
        raise ValueError("réglage non modifiable : " + ", ".join(sorted(inconnues)))
    propres = {k: MODIFIABLES[k](v) for k, v in changes.items()}
    d = Path(base or etat_dir())
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    f = d / "reglages.json"
    try:
        ancien = json.loads(f.read_text(encoding="utf-8"))
        ancien = ancien if isinstance(ancien, dict) else {}
    except (OSError, ValueError):
        ancien = {}
    tmp = f.with_name(".reglages.json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({**{k: v for k, v in ancien.items() if k in MODIFIABLES}, **propres}, fh)
    os.replace(tmp, f)
    return lire(d)
