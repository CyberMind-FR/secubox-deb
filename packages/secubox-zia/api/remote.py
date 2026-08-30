# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ZIA — niveau 3, escalade REMOTE (dernier recours).

Désactivé par défaut. N'est tenté QUE si la politique l'autorise (rôle) ET qu'un endpoint
est configuré. Même alors : seul le contexte nécessaire part, les secrets sont rédigés, un
budget horaire et un timeout bornent l'usage, un circuit breaker coupe après des échecs, et
en cas de doute on retombe TOUJOURS sur le local. Le remote n'est jamais requis pour
fonctionner — c'est une extension, pas une dépendance.
"""
from __future__ import annotations

import re
import time
from typing import Optional

import httpx

from . import policy

# Rédaction des secrets AVANT tout envoi : jetons, clés, emails, IP privées.
_SECRETS = [
    re.compile(r"(?i)\b(bearer|token|api[_-]?key|password|secret)\b\s*[:=]?\s*\S+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\b"),                       # JWT
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),                    # emails
    re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
]


def redige(txt: str) -> str:
    out = txt or ""
    for rx in _SECRETS:
        out = rx.sub("[rédigé]", out)
    return out


class Remote:
    """Circuit breaker + budget horaire, autour d'un seul appel HTTP borné."""

    def __init__(self):
        self._echecs = 0
        self._ouvert_jusqu = 0.0     # circuit breaker : t où l'on réessaie
        self._fenetre = 0.0          # début de la fenêtre horaire de budget
        self._utilise = 0            # escalades dans la fenêtre

    def _budget_ok(self, budget: int) -> bool:
        now = time.time()
        if now - self._fenetre > 3600:
            self._fenetre, self._utilise = now, 0
        return self._utilise < max(0, int(budget))

    async def escalate(self, message: str, cfg: dict, role: str) -> Optional[dict]:
        """Rend {text, source:'remote'} si l'escalade a abouti, sinon None (→ local)."""
        if not policy.remote_autorise(cfg, role):
            return None
        url = str(cfg.get("remote_url", "") or "").strip()
        if not url:
            return None
        now = time.time()
        if now < self._ouvert_jusqu:            # circuit ouvert : on ne tente pas
            return None
        if not self._budget_ok(int(cfg.get("remote_budget", 20))):
            return None
        try:
            payload = {"message": redige(message), "role": role}  # contexte minimal, rédigé
            async with httpx.AsyncClient(timeout=float(cfg.get("remote_timeout_s", 15))) as cli:
                r = await cli.post(url.rstrip("/") + "/v1/chat", json=payload)
            if r.status_code != 200:
                raise RuntimeError(f"remote {r.status_code}")
            self._echecs = 0
            self._utilise += 1
            j = r.json()
            return {"text": redige(str(j.get("text", "")))[:1200], "source": "remote"}
        except Exception:
            # Circuit breaker : après 3 échecs, on coupe 5 min et on reste local.
            self._echecs += 1
            if self._echecs >= 3:
                self._ouvert_jusqu = now + 300
            return None
