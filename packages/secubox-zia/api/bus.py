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

import asyncio
import contextvars
import re
import time
from typing import Optional

import httpx

from . import policy
from .capabilities import Capabilities


class Verdict:
    """Verdict d'une demande d'action : autorisée ? sinon pourquoi. `params` porte
    la valeur VALIDÉE/bornée à renvoyer au Hall (ex. {'value': 0.3})."""
    __slots__ = ("ok", "error", "params")

    def __init__(self, ok: bool, error: str = "", params: Optional[dict] = None):
        self.ok = ok
        self.error = error
        self.params = params or {}


def _service_de(target: str) -> str:
    """« service:radio » → « radio » ; « radio » → « radio »."""
    t = (target or "").strip()
    if ":" in t:
        t = t.split(":", 1)[1]
    return t.strip().lower()

# PLUS DE « seed » factice (#1245) : ZIA ne montre QUE des objets RÉELS, tirés des
# adapters ci-dessous. Hors ligne, elle le dit — elle n'invente jamais de contenu.
_SEED: list[dict] = []

# Domaines des services (pour fabriquer une URL ouvrable, `url`, à côté de
# `sbx://`) : <service>.<domaine de CETTE box> — [global] domain, sinon
# [api] sso_cookie_domain (#1615, #1623). Jamais un nom de box écrit en dur.
# Jeton du DEMANDEUR, posé par /v1/chat le temps d'une requête (#3574). Sert à lire, en son nom et avec ses seuls
# droits, ce qui exige une session (podcasts). Jamais mis en cache, jamais partagé entre demandeurs.
JETON_DEMANDEUR: contextvars.ContextVar[str] = contextvars.ContextVar("zia_jeton_demandeur", default="")
_AUDIO = re.compile(r"podcast|[ée]pisode|audio|[ée]mission", re.I)


def _hote(service: str) -> str:
    try:
        from secubox_core.auth import domaine_box
        dom = domaine_box()
    except Exception:  # noqa: BLE001 — bibliothèque ancienne : pas d'URL plutôt qu'une fausse
        dom = ""
    return f"{service}.{dom}" if dom else ""


def adresses_service(sid: str, path: str) -> tuple[str, str]:
    """(sbx://, url réelle) d'un service du registre. Le path porte déjà le module : ne pas le doubler (#3520).
    La page d'un module vit sur l'hôte admin : sur le Hall, /<module>/ rend le Hall lui-même."""
    chemin = "/" + str(path or f"/{sid}/").lstrip("/")
    prive = chemin[len(sid) + 1:] if chemin.startswith(f"/{sid}/") else chemin
    hote = _hote("admin")
    return f"sbx://{sid}/{prive.lstrip('/')}", f"https://{hote}{chemin}" if hote else ""


class Bus:
    """Vue unifiée des objets, avec adapters branchables et cache court."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._cache: list[dict] = []
        self._ts = 0.0
        self._dernier: dict[str, list[dict]] = {}   # dernier relevé NON vide de chaque source (#3574)
        self._releve: Optional[asyncio.Task] = None  # relevé en cours, partagé par toutes les requêtes
        self._pair_hs: dict[str, float] = {}         # voisine injoignable → mise de côté jusqu'à (monotonic)
        self.ttl = float(cfg.get("bus_cache_s", 45))
        # Registre des capacités (couche d'actions) : bootstrap + manifestes des
        # modules. Le LLM ne l'écrit jamais ; il propose, on valide ici.
        self.caps = Capabilities(cfg.get("capabilities_dir",
                                         "/usr/share/secubox/capabilities.d"))

    def action_allowed(self, service: str, action: str, params: Optional[dict],
                       role: str) -> Verdict:
        """Une action est-elle permise pour ce rôle sur ce service ? (hors LLM)

        Trois barrières, dans l'ordre : (1) la capacité EXISTE (liste blanche du
        registre) ; (2) le RÔLE atteint le plancher de la famille d'action ; (3) la
        VALEUR valide (type + bornes). Rend un Verdict avec la valeur bornée.
        """
        if not self.caps.has(service, action):
            return Verdict(False, error="capacité non disponible")
        if not policy.action_role_ok(role, action):
            return Verdict(False, error="action non autorisée pour ce rôle")
        r = self.caps.resolve(service, action, params)
        if not r.ok:
            return Verdict(False, error=r.error)
        out = {} if r.value is None else {"value": r.value}
        return Verdict(True, params=out)

    async def _metanews(self) -> list[dict]:
        """Adapter MetaNews : topics récents -> objets news.topic (via socket UDS)."""
        sock = self.cfg.get("metanews_sock", "/run/secubox/metanews.sock")
        out: list[dict] = []
        # metanews met 8 à 14 s à rendre ses sujets sur gk2 : à 4 s, ZIA n'en voyait jamais aucun (#3574).
        attente = float(self.cfg.get("metanews_timeout_s", 20))
        try:
            tr = httpx.AsyncHTTPTransport(uds=sock)
            async with httpx.AsyncClient(transport=tr, timeout=attente) as cli:
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
                        "url": f"https://{_hote('metanews')}/#{tid}", "visibility": "guest",
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
                        "url": f"https://{_hote('billets')}/b/{slug}", "visibility": "guest",
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
                    uri, url = adresses_service(sid, s.get("path") or f"/{sid}/")
                    # Contrat d'objet enrichi (RFC §3) : on GARDE `actions` plat
                    # (["open"…], compat UI existante) et on AJOUTE `capabilities`
                    # structurées, tirées du registre — uniquement si le module a
                    # DÉCLARÉ des capacités (jamais inventées d'après le nom).
                    caps = self.caps.actions_for(sid)
                    obj = {
                        "id": f"service:{sid}", "type": "service", "service": sid,
                        "title": s.get("name", sid), "summary": s.get("description", ""),
                        "uri": uri, "url": url, "visibility": "guest",
                        "actions": ["open"],
                        "tags": [s.get("category", ""), sid, "service"],
                    }
                    if caps:
                        obj["type"] = "service.media" if any(
                            c["name"].startswith("media.") for c in caps) else "service"
                        obj["capabilities"] = caps
                    out.append(obj)
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
        base = str(self.cfg.get("peertube_url") or "").rstrip("/")
        if not base:
            # Celui de cette box s'il y est installé, sinon la référence (#1723).
            from secubox_core.auth import hote_parc
            base = "https://" + hote_parc("peertube", "secubox-peertube")
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

    async def _ytsas(self) -> list[dict]:
        """Adapter YTSAS : la médiathèque téléchargée -> objets media.video réservés aux MEMBRES (#3574).

        C'est la bibliothèque personnelle du propriétaire : jamais visible d'un invité du Hall ni de l'IA
        publique. Ni chemin interne ni URL d'origine ne sortent : titre, et lien vers la page ytsas.
        """
        base = str(self.cfg.get("ytsas_url") or "http://10.100.0.180:8091").rstrip("/")
        page = f"https://{_hote('admin')}/ytsas/" if _hote("admin") else ""
        out: list[dict] = []
        try:
            async with httpx.AsyncClient(timeout=6.0) as cli:
                r = await cli.get(base + "/api/v1/ytsas/list", headers={"Accept": "application/json"})
            if r.status_code != 200:
                return out
            elements = [e for e in r.json() if isinstance(e, dict) and str(e.get("complete")) == "1" and e.get("id")]
            elements.sort(key=lambda e: float(e.get("added_at") or 0), reverse=True)
            for e in elements[:40]:
                out.append({
                    "id": f"ytsas:media:{e['id']}", "type": "media.video", "service": "ytsas",
                    "title": str(e.get("title") or "")[:160], "summary": "Médiathèque ytsas",
                    "uri": f"sbx://ytsas/media/{e['id']}", "url": page, "visibility": "member",
                    "actions": ["open"], "tags": ["vidéo", "ytsas", "médiathèque"],
                })
        except Exception:
            return out
        return out

    async def _bbs(self) -> list[dict]:
        """Adapter BBS : les rubriques publiques (/api/v1/bbs/menu) -> objets forum.section, visibles de tous.

        Les FILS exigent un jeton : ils attendent le compte de service de ZIA (#3574), pas un contournement.
        """
        sock = self.cfg.get("bbs_sock", "/run/secubox/bbs.sock")
        out: list[dict] = []
        try:
            tr = httpx.AsyncHTTPTransport(uds=sock)
            async with httpx.AsyncClient(transport=tr, timeout=4.0) as cli:
                r = await cli.get("http://x/api/v1/bbs/menu", headers={"Accept": "application/json"})
            if r.status_code != 200:
                return out
            for c in (r.json().get("categories") or []):
                slug = c.get("slug")
                if not slug:
                    continue
                n = c.get("threads")
                out.append({
                    "id": f"bbs:rubrique:{slug}", "type": "forum.section", "service": "bbs",
                    "title": c.get("title") or slug,
                    "summary": f"Rubrique du BBS · {n} fils" if isinstance(n, int) else "Rubrique du BBS",
                    "uri": f"sbx://bbs/rubrique/{slug}",
                    "url": f"https://{_hote('bbs')}/c/{slug}" if _hote("bbs") else "", "visibility": "guest",
                    "actions": ["open"], "tags": ["bbs", "forum", "discussion", str(slug).lower()],
                })
        except Exception:
            return out
        return out

    async def _rafraichir(self) -> None:
        """Les sources EN PARALLÈLE : le relevé dure le temps de la plus lente (metanews, jusqu'à 20 s), pas leur
        somme. Double tampon (#3011, #3574) : une source en échec rend [] et ne vide jamais son dernier relevé."""
        noms = ("metanews", "billets", "peertube", "registre", "ytsas", "bbs")
        lots = await asyncio.gather(self._metanews(), self._billets(), self._peertube(), self._registry(),
                                    self._ytsas(), self._bbs(), return_exceptions=True)
        frais = []
        for nom, lot in zip(noms, lots):
            frais += self._garde(nom, lot if isinstance(lot, list) else [])
        self._cache = list(_SEED) + frais
        self._ts = time.time()

    def prechauffer(self) -> asyncio.Task:
        """Lance un relevé s'il n'y en a pas déjà un (démarrage du service, cache expiré)."""
        if self._releve is None or self._releve.done():
            self._releve = asyncio.create_task(self._rafraichir())
        return self._releve

    async def objets(self, role: str = "guest", force: bool = False) -> list[dict]:
        """Tous les objets visibles pour ce rôle.

        Jamais d'attente une fois un premier relevé fait : cache expiré = réponse immédiate avec le dernier relevé,
        nouveau relevé en tâche de fond. Le chemin public coupe à 30 s (HAProxy) : attendre metanews (20 s) puis le
        modèle (20 s) donnait « Oups, réseau » (#3574). Seul le tout premier relevé (ou `force`) est attendu.
        """
        if force or not self._ts:
            await self.prechauffer()
        elif (time.time() - self._ts) > self.ttl:
            self.prechauffer()
        return policy.filtre(self._cache, role)

    def _garde(self, source: str, objets: list[dict]) -> list[dict]:
        if objets:
            self._dernier[source] = objets
        return self._dernier.get(source, [])

    async def _podcasts(self, jeton: str) -> list[dict]:
        """Épisodes du podcaster lus AVEC LE JETON DU DEMANDEUR (#3574) : la bibliothèque exige une session.

        ZIA ne reçoit que ce que cette personne a le droit de lire ; rien n'est gardé au-delà de la requête.
        """
        sock = self.cfg.get("podcaster_sock", "/run/secubox/podcaster.sock")
        hote = _hote("admin")
        out: list[dict] = []
        try:
            tr = httpx.AsyncHTTPTransport(uds=sock)
            async with httpx.AsyncClient(transport=tr, timeout=6.0) as cli:
                r = await cli.get("http://x/public/library",
                                  headers={"Accept": "application/json", "Authorization": f"Bearer {jeton}"})
            if r.status_code != 200:
                return out
            eps = sorted((r.json().get("episodes") or []), key=lambda e: e.get("pubdate") or 0, reverse=True)
            for e in eps[:25]:
                if not e.get("id"):
                    continue
                out.append({
                    "id": f"podcaster:episode:{e['id']}", "type": "media.audio", "service": "podcaster",
                    "title": str(e.get("title") or "")[:160], "summary": str(e.get("feed") or "Podcast"),
                    "uri": f"sbx://podcaster/episode/{e['id']}",
                    "url": f"https://{hote}{e['media']}" if hote and e.get("media") else "",
                    "visibility": "guest", "actions": ["play", "open"],
                    "tags": ["podcast", "audio", str(e.get("feed") or "").lower()],
                })
        except Exception:
            return out
        return out

    async def _pairs(self, query: str) -> list[dict]:
        """Objets PUBLICS des autres box du maillage (#3574), par leur route /objets (rôle invité, sans génération).

        Les voisines viennent de `pairs_maillage` (zia.toml) : ZIA ne lit jamais le fichier du maillage, qui porte la
        clé privée WireGuard. Appels en parallèle, 3 s ; une voisine muette est mise de côté 5 min. /objets ne relaie
        jamais aux voisines : pas de boucle entre box.
        """
        pairs = [str(u).rstrip("/") for u in (self.cfg.get("pairs_maillage") or []) if str(u).startswith("https://")]
        now = time.monotonic()
        actifs = [u for u in pairs if self._pair_hs.get(u, 0) <= now]
        if not actifs or not (query or "").strip():
            return []

        async def un(url: str) -> list[dict]:
            try:
                # Certificats internes des box : TLS sans vérification, comme l'adapter PeerTube (serveur-à-serveur).
                async with httpx.AsyncClient(verify=False, timeout=3.0) as cli:
                    r = await cli.get(url + "/api/v1/zia/objets", params={"q": query[:200], "limit": 4},
                                      headers={"Accept": "application/json"})
                if r.status_code != 200:
                    raise ValueError(r.status_code)
                noeud = url.split("//", 1)[1].split("/", 1)[0]
                out = []
                for o in (r.json().get("objets") or [])[:4]:
                    if not (o.get("id") and o.get("title")):
                        continue
                    out.append({**{k: o.get(k) for k in ("type", "service", "title", "url")},
                                "summary": f"sur {noeud} · " + str(o.get("summary") or ""),
                                "id": f"maillage:{noeud}:{o['id']}", "visibility": "guest", "noeud": noeud,
                                "actions": ["open"], "tags": list(o.get("tags") or []) + ["maillage", noeud]})
                return out
            except Exception:
                self._pair_hs[url] = time.monotonic() + 300
                return []
        lots = await asyncio.gather(*(un(u) for u in actifs))
        return [o for lot in lots for o in lot]

    async def search(self, query: str, type_: str = "", role: str = "guest", limit: int = 8,
                     maillage: bool = True) -> list[dict]:
        """Recherche plein-texte simple sur titre/résumé/tags (+ filtre de type), puis les box voisines."""
        objs = await self.objets(role)
        if maillage:
            objs = objs + policy.filtre(await self._pairs(query), role)
        jeton = JETON_DEMANDEUR.get()
        if jeton and (type_.startswith("media.audio") or _AUDIO.search(query or "")):
            objs = objs + await self._podcasts(jeton)
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
