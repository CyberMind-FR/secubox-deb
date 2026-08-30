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

# PLUS DE « seed » factice (#1245) : ZIA ne montre QUE des objets RÉELS, tirés des
# adapters ci-dessous. Hors ligne, elle le dit — elle n'invente jamais de contenu.
_SEED: list[dict] = []

# Domaines des services (pour fabriquer une URL ouvrable, `url`, à côté de `sbx://`).
_DOMAIN = {
    "metanews": "metanews.gk2.secubox.in",
    "billets": "billets.gk2.secubox.in",
    "peertube": "peertube.gk2.secubox.in",
    "bbs": "bbs.gk2.secubox.in",
    "radio": "radio.gk2.secubox.in",
}


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
                        "uri": f"sbx://metanews/topic/{tid}",
                        "url": f"https://{_DOMAIN['metanews']}/#{tid}", "visibility": "guest",
                        "actions": ["open", "discuss"],
                        "tags": [str(x).lstrip("#") for x in (t.get("tags") or [])][:8],
                    })
        except Exception:
            return out
        return out

    async def _billets(self) -> list[dict]:
        """Adapter BILLETS : le JSON Feed public (/feed.json) -> objets post réels."""
        sock = self.cfg.get("billets_sock", "/run/secubox/billets.sock")
        out: list[dict] = []
        try:
            tr = httpx.AsyncHTTPTransport(uds=sock)
            async with httpx.AsyncClient(transport=tr, timeout=4.0) as cli:
                r = await cli.get("http://x/feed.json", headers={"Accept": "application/json"})
                if r.status_code != 200:
                    return out
                for it in (r.json().get("items") or []):
                    u = str(it.get("url") or it.get("id") or "")
                    m = re.search(r"/b/([^/?#]+)", u)
                    slug = m.group(1) if m else ""
                    if not slug:
                        continue
                    txt = re.sub(r"<[^>]+>", " ", str(it.get("content_html") or "")).strip()
                    out.append({
                        "id": f"billets:post:{slug}", "type": "post", "service": "billets",
                        "title": it.get("title", ""), "summary": txt[:200],
                        "uri": f"sbx://billets/post/{slug}",
                        "url": f"https://{_DOMAIN['billets']}/b/{slug}", "visibility": "guest",
                        "actions": ["open", "discuss"], "tags": ["billet"],
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

    async def _peertube(self) -> list[dict]:
        """Adapter PEERTUBE : vidéos publiques réelles -> objets media.video JOUABLES.

        La box résout peertube.gk2… vers elle-même ; on interroge l'API publique en
        HTTPS (cert interne -> verify off, serveur-à-serveur). L'URL de visionnage
        `/w/<id>` est justement ce que le viewer du Hall sait jouer en SOUVERAIN
        (estPeertube). « Trouve une vidéo » ramène donc du réel, lisible d'un clic.
        """
        base = str(self.cfg.get("peertube_url", "https://peertube.gk2.secubox.in")).rstrip("/")
        out: list[dict] = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as cli:
                r = await cli.get(base + "/api/v1/videos",
                                  params={"count": 25, "sort": "-publishedAt", "nsfw": "false"},
                                  headers={"Accept": "application/json"})
                if r.status_code != 200:
                    return out
                for v in (r.json().get("data") or []):
                    sid = v.get("shortUUID") or v.get("uuid")
                    if not sid:
                        continue
                    chan = (v.get("channel") or {}).get("displayName", "")
                    out.append({
                        "id": f"peertube:video:{sid}", "type": "media.video", "service": "peertube",
                        "title": v.get("name", ""), "summary": (v.get("description") or chan or "")[:200],
                        "uri": f"sbx://peertube/video/{sid}",
                        "url": f"{base}/w/{sid}", "visibility": "guest",
                        "actions": ["play", "open", "discuss"],
                        "tags": [t for t in [chan.lower(), "vidéo", "peertube"] if t],
                    })
        except Exception:
            return out
        return out

    async def objets(self, role: str = "guest", force: bool = False) -> list[dict]:
        """Tous les objets visibles pour ce rôle (cache court, adapters best-effort)."""
        now = time.time()
        if force or not self._cache or (now - self._ts) > self.ttl:
            news = await self._metanews()
            posts = await self._billets()
            vids = await self._peertube()
            svcs = await self._registry()
            self._cache = list(_SEED) + news + posts + vids + svcs
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
