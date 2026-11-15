# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Filtres du WAF proposés par une box d'IA (#3732) : `POST /ai/filtres`, `DELETE /ai/filtres/{id}`, `GET /ai/filtres`.

Sur le patron de `gestes_ia` (#3716) : exception écrite à RULES-CODE § 3, garde `require_ai_filtres`
(`secubox_core.compte_service`, portée `waf-filtres` : un jeton `ai-ban` n'y vaut rien, et inversement), servie par
le SEUL processus désigné (`SECUBOX_WAF_GESTES_IA=1`, secubox-waf.service ; 503 `processus` avant la garde ailleurs).
Aucun modèle de corps FastAPI (P11) : le corps brut, lu et borné par la garde, est validé par `model_validate_json`.

Le tri, les bornes et l'écriture des règles appartiennent à la commande root `secubox-cvectl filtres-ia` (lignes
exactes du sudoers de secubox-security-posture), appelée par `sudo -n` avec l'entrée sur STDIN :
`{"acteur": "ai-filtres:<kid>", "filtres": [...]}` ou `{"acteur": …, "id": "ia-…"}`. Codes : 0 → 200 (409 `rejete`
si rien n'est appliqué ni inchangé), 2 → 422, 3 → 409, 4 → 404, 5 (erreur interne du ctl) et autre → 503 `ctl` ; délai dépassé ou binaire absent
→ 503 `ctl`. Chaque appel est audité (`ai-filtres-appliquer|retirer|lister`) ; un changement fait dont l'audit ne
peut pas être écrit rend 500 (jamais caché).
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Any, Callable, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from secubox_core.compte_service import TAILLE_MAX_CORPS, require_ai_filtres

try:
    from api.gestes_ia import processus_designe, _valider
except ImportError:  # pragma: no cover — import hors paquet
    from gestes_ia import processus_designe, _valider

log = logging.getLogger("secubox.waf.filtres_ia")

router = APIRouter(prefix="/ai/filtres", dependencies=[Depends(processus_designe)])

CVECTL = "/usr/sbin/secubox-cvectl"
_SUDO = ["sudo", "-n"]
_DELAI_CTL_S = 60
FILTRES_MAX = 50
#: Id d'un filtre de l'IA (forme de `filtres_ia.verifier_id_filtre` côté cvectl : `ia-` + ID_RE).
_RE_ID = re.compile(r"ia-[a-z0-9._-]{1,93}")
_STATUTS = {2: 422, 3: 409, 4: 404}

#: Branchement fourni par main.py : `audit(action, detail, user)` qui LÈVE si la ligne n'est pas écrite.
_config: Dict[str, Callable[..., Any]] = {}


def configurer(audit: Callable[[str, str, dict], None]) -> None:
    _config["audit"] = audit


class Proposition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filtres: List[Dict[str, Any]] = Field(min_length=1, max_length=FILTRES_MAX)


async def _corps(request: Request, _user: dict = Depends(require_ai_filtres)) -> bytes:
    """Le corps brut, APRÈS la garde (qui l'a lu, borné et mis en cache) : P11."""
    corps = await request.body()
    if len(corps) > TAILLE_MAX_CORPS:
        raise HTTPException(413, detail={"motif": "corps_trop_grand"})
    return corps


def _executer(argv: List[str], entree: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=entree, capture_output=True, timeout=_DELAI_CTL_S, check=False)


def _acteur(user: dict) -> str:
    return f"ai-filtres:{str((user or {}).get('cle') or '')[:64]}"


def _auditer(action: str, detail: str, user: dict, lever: bool) -> None:
    usager = {"sub": str((user or {}).get("sub") or "ai-filtres")}
    try:
        _config["audit"](action, f"{detail} cle {str((user or {}).get('cle') or '')[:64]}", usager)
    except Exception as e:  # noqa: BLE001
        if lever:
            log.error("ai-filtres : audit %s non écrit : %s", action, type(e).__name__)
            raise HTTPException(500, detail={"motif": "audit"}) from None
        log.warning("ai-filtres : audit %s non écrit : %s", action, type(e).__name__)


def _texte(x: Any) -> str:
    return x.decode("utf-8", "replace") if isinstance(x, (bytes, bytearray)) else str(x or "")


def _ctl(verbe: str, action: str, user: dict, entree: bytes) -> dict:
    """Lance cvectl, rend sa sortie JSON (code 0) ou lève l'HTTPException du code, l'échec audité sans lever."""
    argv = _SUDO + [CVECTL, "filtres-ia", verbe] + (["--apply"] if verbe != "lister" else []) + ["--json"]
    try:
        r = _executer(argv, entree)
    except (subprocess.TimeoutExpired, OSError) as e:
        _auditer(action, f"echec ctl {type(e).__name__}", user, lever=False)
        raise HTTPException(503, detail={"motif": "ctl"}) from None
    try:
        sortie = json.loads(_texte(r.stdout) or "{}")
    except ValueError:
        sortie = None
    if r.returncode in _STATUTS:
        statut = _STATUTS[r.returncode]
        erreur = str((sortie or {}).get("erreur") or "")[:200] if isinstance(sortie, dict) else ""
        _auditer(action, f"refus {r.returncode} {erreur}".strip(), user, lever=False)
        raise HTTPException(statut, detail={"motif": "refus", "erreur": erreur})
    if r.returncode != 0 or not isinstance(sortie, dict):
        _auditer(action, f"echec ctl code {r.returncode}", user, lever=False)
        raise HTTPException(503, detail={"motif": "ctl"})
    return sortie


@router.post("")
def ai_filtres_appliquer(user: dict = Depends(require_ai_filtres), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    try:
        prop = _valider(Proposition, corps)
    except HTTPException:
        _auditer("ai-filtres-appliquer", "refus forme", user, lever=False)
        raise
    entree = json.dumps({"acteur": _acteur(user), "filtres": prop.filtres}, ensure_ascii=False).encode()
    sortie = _ctl("appliquer", "ai-filtres-appliquer", user, entree)
    appliques = sortie.get("appliques") or []
    inchanges = sortie.get("inchanges") or []
    rejets = sortie.get("rejets") or []
    if not appliques and not inchanges:
        _auditer("ai-filtres-appliquer", f"tout rejete ({len(rejets)})", user, lever=False)
        raise HTTPException(409, detail={"motif": "rejete", "rejets": rejets})
    # Changement fait : son audit DOIT être écrit, sinon 500 (jamais caché).
    # cvectl rend des listes d'ids (chaînes) ; un dict {"id": …} reste accepté.
    ids = ",".join(str(a.get("id") if isinstance(a, dict) else a) for a in appliques + inchanges)[:200]
    _auditer("ai-filtres-appliquer",
             f"appliques {len(appliques)} inchanges {len(inchanges)} rejets {len(rejets)} ids {ids}", user, lever=True)
    return sortie


@router.delete("/{fid}")
def ai_filtres_retirer(fid: str, user: dict = Depends(require_ai_filtres),
                       corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    if corps:
        _auditer("ai-filtres-retirer", "refus corps", user, lever=False)
        raise HTTPException(422, detail={"motif": "corps"})
    if not _RE_ID.fullmatch(fid):
        _auditer("ai-filtres-retirer", "refus id", user, lever=False)
        raise HTTPException(422, detail={"motif": "id"})
    entree = json.dumps({"acteur": _acteur(user), "id": fid}).encode()
    sortie = _ctl("retirer", "ai-filtres-retirer", user, entree)
    _auditer("ai-filtres-retirer", f"retire {fid}", user, lever=True)
    return sortie


@router.get("")
def ai_filtres_lister(user: dict = Depends(require_ai_filtres), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    if corps:
        _auditer("ai-filtres-lister", "refus corps", user, lever=False)
        raise HTTPException(422, detail={"motif": "corps"})
    sortie = _ctl("lister", "ai-filtres-lister", user, b"")
    _auditer("ai-filtres-lister", f"lister {len(sortie.get('filtres') or [])}", user, lever=False)
    return sortie
