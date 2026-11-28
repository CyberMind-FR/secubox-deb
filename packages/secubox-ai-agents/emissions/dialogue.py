# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Dialogue de l'émission (#4058, Task 7) : écriture par le LLM local, découpage V1/V2, vérification par réplique.

Chaque réplique passe par `verif_rapport.verifier` (le code de gk2, tel quel) : une phrase retirée retire toute la
réplique (✗, jamais dite) ; une supposition la marque ⚠ (lecture IA seule, dite et signalée) ; sinon ✓. Une phrase
sans affirmation (question, transition) n'est pas retirée pour seul défaut d'ancrage.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from . import graphiques, verif_rapport

GABARIT = Path(__file__).with_name("gabarit-7-parties.txt")
SOCKET_DEFAUT = str(Path.home() / "poc-secubox-ai/run/llama.sock")
DELAI_S = 300.0
MARQUES = {"verifiee": "✓", "ia_seule": "⚠", "retiree": "✗"}
_LIGNE = re.compile(r"^\W*V\s*([12])\s*\W*?\s*[:\-–]\W*\s*(.*)$")
# Motifs d'ANCRAGE seulement : une phrase qui n'affirme rien de chiffré n'a rien à ancrer (règle assouplie, spec).
_SANS_AFFIRMATION = ("phrase non adossée", "ne redit que la fenêtre")


async def ecrire(consigne: str, *, socket: Optional[str] = None, delai_s: float = DELAI_S,
                 max_tokens: int = 2048, temperature: float = 0.4) -> str:
    """Un appel au llama-server local (contrat OpenAI) sur son socket Unix ; rend le texte de la réponse."""
    sock = socket or os.environ.get("SECUBOX_AI_AGENTS_MOTEUR", SOCKET_DEFAUT)
    async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=sock), base_url="http://moteur",
                                 timeout=delai_s, trust_env=False) as c:
        r = await c.post("/v1/chat/completions", json={
            "messages": [{"role": "user", "content": consigne}], "max_tokens": max_tokens,
            "temperature": temperature, "stream": False})
        r.raise_for_status()
        texte = (r.json().get("choices") or [{}])[0].get("message", {}).get("content")
    if not isinstance(texte, str) or not texte.strip():
        raise RuntimeError("le moteur a rendu une réponse vide")
    return texte


def decouper(sortie: str) -> List[Dict[str, Any]]:
    """Lignes « V1: » / « V2: » (gras et espaces tolérés) ; une ligne sans préfixe prolonge la réplique en cours ;
    le texte avant la première réplique est ignoré."""
    out: List[Dict[str, Any]] = []
    for ligne in (sortie or "").splitlines():
        ligne = ligne.strip()
        if not ligne:
            continue
        m = _LIGNE.match(ligne)
        if m:
            texte = m.group(2).strip().strip("*").strip()
            out.append({"rang": len(out), "voix": int(m.group(1)), "texte": texte})
        elif out:
            out[-1]["texte"] = (out[-1]["texte"] + " " + ligne).strip()
    return [r for r in out if r["texte"]]


def _verifier(texte: str, dossier: Dict[str, Any]) -> Dict[str, Any]:
    v = verif_rapport.verifier(texte, dossier)
    motifs = [m for p in v["retirees"] for m in p["motifs"] if not m.startswith(_SANS_AFFIRMATION)]
    if motifs:
        return {"statut": "retiree", "motifs": motifs}
    hyp = [m for g in v["gardees"] if g["statut"] == "hypothese" for m in g["motifs"]]
    for p in v["retirees"]:                     # phrase sans ancrage admise, mais une supposition reste signalée
        s = verif_rapport._SUPPOSITION.search(verif_rapport.normaliser(p.get("texte") or ""))
        if s:
            hyp.append("supposition : « " + s.group(0).strip() + " »")
    return {"statut": "ia_seule", "motifs": hyp} if hyp else {"statut": "verifiee", "motifs": []}


def verifier_repliques(repliques: List[Dict[str, Any]], dossier: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for r in repliques:
        v = _verifier(r.get("texte") or "", dossier)
        out.append({**r, **v, "marque": MARQUES[v["statut"]]})
    return out


def dites(repliques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Les répliques qui seront dites : toutes sauf les retirées."""
    return [r for r in repliques if r.get("statut") != "retiree"]


def associer_diapos(repliques: List[Dict[str, Any]], graphs: List[Dict[str, Any]]) -> Dict[int, str]:
    """Rang → id de graphique, sur les seules répliques dites (Task 8 `associer`)."""
    return graphiques.associer(dites(repliques), graphs)
