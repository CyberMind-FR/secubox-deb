# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Interceptor — supervision RÉELLE de la chaîne d'inspection (#2447).

L'inspection est faite par sbxmitm (ng-worker@1..4, proxy transparent du tunnel wg-toolbox) et sbxwaf (WAF). Ce module ne la remplace pas : il la
LIT (lecture seule) — état des moteurs et de leurs ports, activité d'inspection tirée du journal de sbxmitm (SNI et empreintes JA4 vus), niveaux
d'inspection par pair, exclusions (bypass / splice). Aucune mesure inventée : une source illisible rend « null », jamais un zéro trompeur.

Servi en processus par l'agrégateur : aucun appel bloquant dans la boucle (les lectures lourdes passent par un thread, avec cache et un seul vol).
"""
from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi import Depends, FastAPI

try:
    from secubox_core.auth import require_lecture
except ImportError:  # pragma: no cover - hors paquet
    async def require_lecture():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Interceptor API", version="2.0.0")

TOOLBOX_DIR = Path("/var/lib/secubox/toolbox")
WORKERS = [f"secubox-toolbox-ng-worker@{i}" for i in range(1, 5)]
# (libellé, unité systemd, adresses d'écoute attendues) ; l'adresse d'écoute est lue dans `ss`, jamais supposée
MOTEURS = [(f"sbxmitm {i}", u, p) for i, (u, p) in enumerate(zip(WORKERS, ("10.99.1.1:8091", "10.99.1.1:8092", "10.99.1.1:8093", "10.99.1.1:8094")), 1)] + [
    ("sbxwaf", "secubox-waf-ng", "127.0.0.1:8085"),
]
_SNI = re.compile(r"\bja4 (\S+?)_sni=(\S+)")
_TTL = 20


# ── lectures (fonctions pures, testées) ─────────────────────────────────────────────────────────────────────────────────────────────────────
def _sh(cmd: list, timeout: int = 10) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (OSError, subprocess.SubprocessError):
        return None


def parse_ss(texte: str) -> set:
    """Adresses en écoute (`ss -ltnH`, colonne « Local Address:Port »)."""
    out = set()
    for ligne in (texte or "").splitlines():
        c = ligne.split()
        if len(c) >= 4:
            out.add(c[3])
    return out


def moteurs() -> list:
    ecoute = parse_ss(_sh(["ss", "-ltnH"]) or "")
    res = []
    for nom, unite, adr in MOTEURS:
        etat = (_sh(["systemctl", "is-active", unite]) or "").strip() or None
        res.append({"nom": nom, "unite": unite, "etat": etat, "actif": etat == "active", "ecoute": adr, "port_ouvert": (adr in ecoute) if ecoute else None})
    return res


def parse_journal(texte: str, maintenant: float, minutes: int) -> dict:
    """Lignes JSON du journal de sbxmitm -> clients-hello vus (SNI + JA4), par hôte, par moteur et par minute. Les lignes illisibles sont ignorées."""
    hotes, par_moteur, empreintes = Counter(), Counter(), set()
    serie = [0] * minutes
    total = 0
    for ligne in (texte or "").splitlines():
        try:
            e = json.loads(ligne)
        except ValueError:
            continue
        m = _SNI.search(str(e.get("MESSAGE", "")))
        if not m:
            continue
        try:
            t = int(e.get("__REALTIME_TIMESTAMP", 0)) / 1e6
        except (TypeError, ValueError):
            continue
        age = int((maintenant - t) // 60)
        if age < 0 or age >= minutes:
            continue
        total += 1
        serie[minutes - 1 - age] += 1
        hote = m.group(2).strip().lower()
        hotes[hote] += 1
        empreintes.add(m.group(1))
        u = str(e.get("_SYSTEMD_UNIT", ""))
        mm = re.search(r"@(\d+)\.service", u)
        par_moteur[mm.group(1) if mm else "?"] += 1
    return {"total": total, "hotes_distincts": len(hotes), "empreintes_distinctes": len(empreintes), "serie": serie,
            "top_hotes": [{"hote": h, "n": n} for h, n in hotes.most_common(15)], "par_moteur": dict(sorted(par_moteur.items()))}


def activite(minutes: int = 60) -> dict:
    minutes = max(5, min(int(minutes), 240))
    texte = _sh(["journalctl", "-u", "secubox-toolbox-ng-worker@*", "--since", f"-{minutes}m", "-o", "json", "--output-fields=_SYSTEMD_UNIT,MESSAGE",
                 "--no-pager", "-n", "50000"], timeout=20)
    if texte is None:
        return {"disponible": False, "minutes": minutes}
    r = parse_journal(texte, time.time(), minutes)
    r.update(disponible=True, minutes=minutes)
    return r


def _json(chemin: Path) -> Optional[dict]:
    try:
        d = json.loads(chemin.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def niveaux(dossier: Path = TOOLBOX_DIR) -> dict:
    """Niveaux d'inspection par pair WireGuard (off/passive/active/reel) et répartition cumulée du Toolbox ; une source absente donne null."""
    rl = _json(dossier / "peer-rlevel.json")
    cum = _json(dossier / "cumulative-cache.json")
    out: dict[str, Any] = {"defaut": None, "pairs": None, "repartition_pairs": None, "niveaux_clients": None, "evenements_7j": None}
    if rl is not None:
        pairs = rl.get("peers") or {}
        out["defaut"] = rl.get("defaults")
        out["pairs"] = len(pairs)
        out["repartition_pairs"] = dict(Counter(str((p or {}).get("chosen") or "défaut") for p in pairs.values()))
    if cum is not None:
        out["niveaux_clients"] = cum.get("level_distribution_7d")
        out["evenements_7j"] = (cum.get("events") or {}).get("total_7d")
    return out


def _lignes(chemin: Path) -> Optional[list]:
    try:
        return [l.strip() for l in chemin.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip() and not l.lstrip().startswith("#")]
    except OSError:
        return None


def exclusions(dossier: Path = TOOLBOX_DIR) -> dict:
    """Hôtes que l'inspection ne déchiffre pas (bypass : laissés passer ; splice : relayés sans déchiffrer) et motifs de filtre désactivés."""
    return {"bypass": _lignes(dossier / "mitm-bypass.conf"), "splice": _lignes(dossier / "splice-learned.txt"),
            "filtres_desactives": _lignes(dossier / "mitm-filter-disabled.txt")}


# ── cache à un seul vol : la boucle n'attend jamais une lecture lourde ──────────────────────────────────────────────────────────────────────
_cache: dict = {}
_verrous: dict = {}


async def _mis_en_cache(cle: str, f: Callable[[], Any]):
    t, v = _cache.get(cle, (0.0, None))
    if v is not None and time.monotonic() - t < _TTL:
        return v
    verrou = _verrous.setdefault(cle, asyncio.Lock())
    async with verrou:
        t, v = _cache.get(cle, (0.0, None))
        if v is not None and time.monotonic() - t < _TTL:
            return v
        v = await asyncio.to_thread(f)
        _cache[cle] = (time.monotonic(), v)
        return v


# ── routes (lecture seule) ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    return {"status": "ok", "module": "interceptor"}


@app.get("/moteurs", dependencies=[Depends(require_lecture)])
async def get_moteurs():
    m = await _mis_en_cache("moteurs", moteurs)
    return {"moteurs": m, "actifs": sum(1 for x in m if x["actif"]), "total": len(m)}


@app.get("/activite", dependencies=[Depends(require_lecture)])
async def get_activite(minutes: int = 60):
    minutes = max(5, min(int(minutes), 240))
    return await _mis_en_cache(f"activite{minutes}", lambda: activite(minutes))


@app.get("/niveaux", dependencies=[Depends(require_lecture)])
async def get_niveaux():
    return await _mis_en_cache("niveaux", niveaux)


@app.get("/exclusions", dependencies=[Depends(require_lecture)])
async def get_exclusions():
    return await _mis_en_cache("exclusions", exclusions)


@app.get("/status", dependencies=[Depends(require_lecture)])
async def get_status():
    m = await _mis_en_cache("moteurs", moteurs)
    a = await _mis_en_cache("activite60", lambda: activite(60))
    n = await _mis_en_cache("niveaux", niveaux)
    return {"moteurs_actifs": sum(1 for x in m if x["actif"]), "moteurs_total": len(m),
            "hello_60min": a.get("total") if a.get("disponible") else None, "pairs": n.get("pairs")}


@app.get("/info", dependencies=[Depends(require_lecture)])
async def get_info():
    return {"module": "secubox-interceptor", "version": "2.0.0", "description": "Supervision de la chaîne d'inspection (sbxmitm, sbxwaf), lecture seule"}
