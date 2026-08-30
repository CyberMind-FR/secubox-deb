# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ZIA — niveau 2, la ZIA d'un VHOST (RAG local).

Quand ZIA (niveau 1) délègue « explique-moi le WAF en détail », c'est ICI que la
« ZIA · waf » répond — avec un vrai RAG borné au service : on RÉCUPÈRE des passages
de sa DOCUMENTATION DÉPLOYÉE (le changelog Debian du/des paquets = son histoire de
développement réelle) et on GÉNÈRE une réponse ancrée dessus (si un modèle est là),
sinon on rend les passages les plus pertinents. Aucune invention : la réponse cite
ce que le service dit de lui-même. Le RAG reste local au VHOST — pas de fuite.
"""
from __future__ import annotations

import gzip
import os
import re
from typing import Optional

DOC = "/usr/share/doc"

# Un service -> le(s) paquet(s) dont on lit l'histoire. Étendre au besoin.
_PKGS = {
    "waf": ["secubox-waf-ng", "secubox-waf"],
    "bbs": ["secubox-bbs"],
    "metanews": ["secubox-metanews"],
    "billets": ["secubox-billets"],
    "peertube": ["secubox-peertube"],
    "radio": ["secubox-radio"],
    "podcaster": ["secubox-podcaster"],
    "nextcloud": ["secubox-nextcloud"],
    "devwatch": ["secubox-devwatch"],
    "zia": ["secubox-zia", "secubox-zia-llm"],
}

_BULLET = re.compile(r"^\s*\*\s+(.+(?:\n\s{4,}.+)*)", re.M)


def _chunks(service: str) -> list[str]:
    """Passages = les puces des changelogs du service (son histoire réelle)."""
    out: list[str] = []
    for pkg in _PKGS.get(service, [f"secubox-{service}"]):
        path = os.path.join(DOC, pkg, "changelog.Debian.gz")
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                txt = f.read(9000)
        except Exception:
            continue
        for m in _BULLET.finditer(txt):
            c = re.sub(r"\s+", " ", m.group(1)).strip()
            if len(c) > 15:
                out.append(c)
    return out[:80]


def _retrieve(chunks: list[str], question: str, k: int = 5) -> list[str]:
    """Récupération lexicale simple : les passages qui recoupent le plus la question."""
    mots = [m for m in re.split(r"\W+", (question or "").lower()) if len(m) > 2]
    scored = []
    for c in chunks:
        low = c.lower()
        s = sum(low.count(m) for m in mots) if mots else 1
        if s > 0:
            scored.append((s, c))
    scored.sort(key=lambda x: x[0], reverse=True)
    top = [c for _, c in scored[:k]]
    return top or chunks[:k]   # à défaut de recoupement, les plus récents


async def answer(service: str, question: str, cfg: dict, generate=None) -> dict:
    """Réponse de la ZIA du VHOST. `generate(cfg, prompt)->str|None` = le modèle (option).

    Rend {ok, text, sources[], grounded}. Sans passages : ok=False (on ne bluffe pas).
    """
    chunks = _chunks(service)
    if not chunks:
        return {"ok": False, "text": "", "sources": [], "grounded": False}
    passages = _retrieve(chunks, question)
    src = [p[:110] for p in passages]

    if generate is not None and cfg.get("llm_url"):
        ctx = "\n".join(f"- {p}" for p in passages)
        prompt = (
            f"Tu es ZIA·{service}, l'assistante locale du service « {service} » de SecuBox. "
            f"Réponds à la question EN T'APPUYANT UNIQUEMENT sur ces notes de développement "
            f"du service (n'invente rien, cite ce qui est pertinent, 2-3 phrases max) :\n{ctx}\n\n"
            f"Question : {question}\nRéponse :"
        )
        gen = await generate(cfg, prompt)
        if gen:
            return {"ok": True, "text": gen.strip(), "sources": src, "grounded": True}

    # Repli sans modèle : on RESTITUE les passages (honnête, ancré).
    txt = f"D'après l'historique de **{service}** :\n" + "\n".join(f"• {p}" for p in passages[:3])
    return {"ok": True, "text": txt, "sources": src, "grounded": True}
