# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ZIA — client du bus d'objets.

Le LLM n'accède JAMAIS aux bases ni aux VHOST : il passe par ce bus, qui expose des
objets NORMALISÉS au contrat (id/type/service/title/summary/uri/visibility/actions) et
applique la visibilité (voir policy). Au POC : un socle d'objets « seed » (toujours là,
déterministe) enrichi par des ADAPTERS réels lus sur les sockets des services (P2). Un
service injoignable est simplement ignoré — jamais d'erreur qui casse le chat.
"""
from __future__ import annotations

import re
import time
from typing import Any, Optional

import httpx

from . import policy

# ── Socle « seed » : représentatif, toujours disponible (P1) ────────────────────
_SEED: list[dict] = [
    {"id": "peertube:video:9NHwh", "type": "media.video", "service": "peertube",
     "title": "WAF autonome : nft direct, hors-HTTP", "summary": "Le pare-feu applicatif qui agit au niveau paquet, sans passer par HTTP.",
     "uri": "sbx://peertube/video/9NHwh", "visibility": "member",
     "actions": ["open", "play", "discuss"], "tags": ["waf", "sécurité", "nftables", "vidéo"]},
    {"id": "radio:item:live", "type": "media.audio", "service": "radio",
     "title": "Émission du jour", "summary": "Le direct de la radio souveraine du Hall.",
     "uri": "sbx://radio/item/live", "visibility": "guest",
     "actions": ["open", "play"], "tags": ["radio", "audio", "direct"]},
    {"id": "bbs:thread:waf", "type": "forum.thread", "service": "bbs",
     "title": "Régler le WAF sans se bannir soi-même", "summary": "Retours d'expérience sur les faux positifs et les routes.",
     "uri": "sbx://bbs/thread/waf", "visibility": "registered",
     "actions": ["open", "discuss"], "tags": ["waf", "forum", "faux positifs"]},
    {"id": "nextcloud:file:cspn", "type": "document", "service": "nextcloud",
     "title": "Notes CSPN — séparation des privilèges", "summary": "Document de travail sur les exigences ANSSI.",
     "uri": "sbx://nextcloud/file/cspn", "visibility": "member",
     "actions": ["open"], "tags": ["cspn", "anssi", "document", "sécurité"]},
    {"id": "podcaster:ep:12328", "type": "media.audio", "service": "podcaster",
     "title": "Souveraineté numérique — épisode", "summary": "Un épisode rapatrié en local par le podcaster.",
     "uri": "sbx://podcaster/ep/12328", "visibility": "guest",
     "actions": ["open", "play"], "tags": ["podcast", "souveraineté", "audio"]},
    {"id": "billets:post:hall", "type": "post", "service": "billets",
     "title": "Le Hall réunit vos services vivants", "summary": "Un billet sur le bureau web SBXOS.",
     "uri": "sbx://billets/post/hall", "visibility": "guest",
     "actions": ["open", "discuss"], "tags": ["hall", "sbxos", "billet"]},
]


class Bus:
    """Vue unifiée des objets, avec adapters branchables et cache court."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._cache: list[dict] = []
        self._ts = 0.0
        self.ttl = float(cfg.get("bus_cache_s", 45))

    async def _metanews(self) -> list[dict]:
        """Adapter MetaNews : topics récents -> objets news.topic (via socket UDS)."""
        sock = self.cfg.get("metanews_sock", "/run/secubox/metanews.sock")
        out: list[dict] = []
        try:
            tr = httpx.AsyncHTTPTransport(uds=sock)
            async with httpx.AsyncClient(transport=tr, timeout=4.0) as cli:
                r = await cli.get("http://x/api/v1/metanews/topics?limit=30",
                                  headers={"Accept": "application/json"})
                if r.status_code != 200:
                    return out
                for t in (r.json().get("topics") or []):
                    tid = t.get("id")
                    if not tid:
                        continue
                    out.append({
                        "id": f"metanews:topic:{tid}", "type": "news.topic", "service": "metanews",
                        "title": t.get("title", ""), "summary": (t.get("summary") or "")[:220],
                        "uri": f"sbx://metanews/topic/{tid}", "visibility": "guest",
                        "actions": ["open", "discuss"],
                        "tags": [str(x).lstrip("#") for x in (t.get("tags") or [])][:8],
                    })
        except Exception:
            return out
        return out

    async def _registry(self) -> list[dict]:
        """Adapter REGISTRE : chaque service du Hall devient un objet ouvrable.

        Source publique (webos), donc réel et actionnable : « ouvre le cloud »,
        « quels services de sécurité ». Le path du registre porte le lien profond.
        """
        sock = self.cfg.get("webos_sock", "/run/secubox/webos.sock")
        out: list[dict] = []
        try:
            tr = httpx.AsyncHTTPTransport(uds=sock)
            async with httpx.AsyncClient(transport=tr, timeout=4.0) as cli:
                r = await cli.get("http://x/api/v1/webos/public/services",
                                  headers={"Accept": "application/json"})
                if r.status_code != 200:
                    return out
                for s in (r.json().get("services") or []):
                    sid = s.get("id")
                    if not sid:
                        continue
                    path = s.get("path") or f"/{sid}/"
                    out.append({
                        "id": f"service:{sid}", "type": "service", "service": sid,
                        "title": s.get("name", sid), "summary": s.get("description", ""),
                        "uri": f"sbx://{sid}{path}", "visibility": "guest",
                        "actions": ["open"],
                        "tags": [s.get("category", ""), sid, "service"],
                    })
        except Exception:
            return out
        return out

    async def objets(self, role: str = "guest", force: bool = False) -> list[dict]:
        """Tous les objets visibles pour ce rôle (cache court, adapters best-effort)."""
        now = time.time()
        if force or not self._cache or (now - self._ts) > self.ttl:
            news = await self._metanews()
            svcs = await self._registry()
            self._cache = list(_SEED) + news + svcs
            self._ts = now
        return policy.filtre(self._cache, role)

    async def search(self, query: str, type_: str = "", role: str = "guest", limit: int = 8) -> list[dict]:
        """Recherche plein-texte simple sur titre/résumé/tags (+ filtre de type)."""
        objs = await self.objets(role)
        q = (query or "").strip().lower()
        mots = [m for m in re.split(r"\W+", q) if len(m) > 1]

        def touche(hay: str, m: str) -> int:
            # Tolérant au pluriel / à la troncature : « podcasts » trouve « podcast ».
            if m in hay:
                return 2
            r = m.rstrip("s")
            if len(r) >= 3 and r in hay:
                return 1
            return 0

        res = []
        for o in objs:
            if type_ and not str(o.get("type", "")).startswith(type_):
                continue
            hay = " ".join([o.get("title", ""), o.get("summary", ""),
                            " ".join(o.get("tags", [])), o.get("service", "")]).lower()
            score = sum(touche(hay, m) for m in mots) if mots else 1
            if score > 0 or not mots:
                res.append((score, o))
        res.sort(key=lambda x: x[0], reverse=True)
        return [o for _, o in res[:limit]]

    async def get(self, oid: str, role: str = "guest") -> Optional[dict]:
        for o in await self.objets(role):
            if o.get("id") == oid:
                return o
        return None

    async def recent(self, limit: int = 6, role: str = "guest") -> list[dict]:
        # Faute d'horodatage uniforme au POC, « récent » = tête de liste (news d'abord).
        objs = await self.objets(role)
        objs = sorted(objs, key=lambda o: 0 if o.get("type", "").startswith("news") else 1)
        return objs[:limit]
