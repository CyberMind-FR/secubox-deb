# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3795 : lecture des alertes du capteur DNS (`/var/lib/secubox/dns-guard/alerts.jsonl`) pour la veille V2 de gk3.

`GET /dnsguard/alertes?depuis=&max=` — garde `require_lecture_ou_compte("ai-lecture")` (jeton lié à GET et au chemin
vu par l'application : voir le README). Lecture par la FIN, par blocs, bornée en octets : on remonte jusqu'à la
première alerte antérieure à `depuis`, jamais le fichier entier. Rend les PLUS ANCIENNES alertes `>= depuis` (au plus
`max`), dans l'ordre du fichier ; `complet = false` s'il en reste (redemander avec `depuis = suivant`, dédoublonner
par `id` : la borne est inclusive), `trou = true` si la borne d'octets a coupé la remontée avant `depuis`.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool

from secubox_core.compte_service import require_lecture_ou_compte

ALERTES = Path("/var/lib/secubox/dns-guard/alerts.jsonl")
#: Octets relus au plus par requête (remontée depuis la fin).
OCTETS_MAX = 16 * 1024 * 1024
MAX_ALERTES = 2000
DEFAUT_H = 24
_BLOC = 64 * 1024
_EPOCH_MAX = 10 ** 10
_RE_EPOCH = re.compile(r"[0-9]{1,10}")
_RE_RFC3339 = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})")

require_lecture_veille = require_lecture_ou_compte("ai-lecture")
router = APIRouter()


def instant(valeur: Any, strict: bool = False) -> Optional[float]:
    """Epoch (secondes) d'une valeur RFC 3339 (fuseau obligatoire si `strict`, UTC sinon) ou d'un entier epoch."""
    if not isinstance(valeur, str) or len(valeur) > 40:
        return None
    if _RE_EPOCH.fullmatch(valeur):
        return float(int(valeur))
    if strict and not _RE_RFC3339.fullmatch(valeur):
        return None
    try:
        d = datetime.fromisoformat(valeur.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def _rfc3339(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def lire(chemin: Path, depuis: float, maximum: int, octets_max: int) -> Tuple[List[dict], bool, bool]:
    """(alertes >= depuis, les plus anciennes d'abord, au plus `maximum` ; complet ; trou)."""
    try:
        f = open(chemin, "rb")
    except OSError:
        return [], True, False
    gardees: List[dict] = []
    atteint = False
    with f:
        pos = os.fstat(f.fileno()).st_size
        lus, reste, premier = 0, b"", True
        while pos > 0 and not atteint:
            n = min(_BLOC, pos, octets_max - lus)
            if n <= 0:
                break
            pos -= n
            f.seek(pos)
            bloc = f.read(n) + reste
            lus += n
            morceaux = bloc.split(b"\n")
            reste = morceaux[0] if pos > 0 else b""
            completes = morceaux[1:] if pos > 0 else morceaux
            if premier:
                completes, premier = completes[:-1], False   # dernière ligne sans « \n » : en cours d'écriture
            for brut in reversed(completes):
                if not brut.strip():
                    continue
                try:
                    r = json.loads(brut.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    continue
                if not isinstance(r, dict):
                    continue
                t = instant(r.get("timestamp"))
                if t is None:
                    continue
                if t < depuis:
                    atteint = True
                    break
                gardees.append(r)
        if pos == 0:
            atteint = True
    gardees.reverse()
    return gardees[:maximum], len(gardees) <= maximum, not atteint


@router.get("/dnsguard/alertes")
async def dnsguard_alertes(depuis: Optional[str] = Query(None, max_length=40),
                           max: int = Query(500, ge=1, le=MAX_ALERTES),  # noqa: A002 — nom du paramètre public
                           lecteur: Dict[str, Any] = Depends(require_lecture_veille)) -> Dict[str, Any]:
    now = time.time()
    if depuis is None:
        t = now - DEFAUT_H * 3600
    else:
        t = instant(depuis, strict=True)
        if t is None or t < 0 or t >= _EPOCH_MAX:
            raise HTTPException(status_code=422, detail="depuis : RFC 3339 avec fuseau, ou epoch en secondes")
    alertes, complet, trou = await run_in_threadpool(lire, ALERTES, t, max, OCTETS_MAX)
    suivant = alertes[-1].get("timestamp") if alertes and not complet else None
    return {"alertes": alertes, "depuis": _rfc3339(t), "suivant": suivant, "complet": complet, "trou": trou,
            "releve": _rfc3339(now)}
