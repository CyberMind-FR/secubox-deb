# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""FastAPI app factory for billets.

`create_app(conn)` wires the public read surface over an already-open aiosqlite
connection (tests pass a fixture conn; the runtime opens one in a lifespan).
The public feed is server-rendered Jinja2 with keyset pagination."""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

import aiosqlite
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import repo
from .routes.admin import register_admin
from .routes.public import _samesite
from .routes.jwt_admin import register_jwt_admin
from .routes.public import (PCSRF_COOKIE, VISITOR_COOKIE, reactions_context,
                            register_public, _visitor)
from .services import antispam, feeds, media
from .services import security as sec
from .services.render import linkify_plain, render_markdown

SITE_URL = os.environ.get("BILLETS_SITE_URL", "")


def _base(request: Request) -> str:
    if SITE_URL:
        return SITE_URL.rstrip("/")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", request.url.netloc)
    return f"{proto}://{host}"


def _share_intents(url: str, title: str) -> dict:
    from urllib.parse import quote_plus
    u, t = quote_plus(url), quote_plus(title)
    ut = quote_plus(f"{title} {url}")
    return {
        "bluesky": f"https://bsky.app/intent/compose?text={ut}",
        "x": f"https://twitter.com/intent/tweet?url={u}&text={t}",
        "facebook": f"https://www.facebook.com/sharer/sharer.php?u={u}",
        "linkedin": f"https://www.linkedin.com/sharing/share-offsite/?url={u}",
        "whatsapp": f"https://wa.me/?text={ut}",
        "telegram": f"https://t.me/share/url?url={u}&text={t}",
        "reddit": f"https://www.reddit.com/submit?url={u}&title={t}",
        "email": f"mailto:?subject={t}&body={u}",
    }

_HERE = Path(__file__).resolve().parent
TEMPLATES_DIR = _HERE / "templates"
STATIC_DIR = _HERE / "static"
DEFAULT_REVISIONS_DIR = os.environ.get(
    "BILLETS_REVISIONS_DIR", "/var/lib/secubox/billets/revisions")

SITE_TITLE = "billets"
SITE_TAGLINE = "micro-blog gateway"
PAGE_SIZE = 20

# frame-src is limited to the embed provider allowlist (spec). Registrable
# domains → "https://d https://*.d" so provider embed subdomains match.
_FRAME_HOSTS = [
    "youtube.com", "youtube-nocookie.com", "vimeo.com", "twitter.com",
    "bsky.app", "soundcloud.com", "bandcamp.com", "flickr.com",
]


def _frame_src(extra_hosts: tuple[str, ...] = ()) -> str:
    parts = []
    for d in list(_FRAME_HOSTS) + [h for h in extra_hosts if h]:
        parts.append(f"https://{d}")
        parts.append(f"https://*.{d}")
    return " ".join(parts)


def _ancetres() -> str:
    """Qui a le droit d'encadrer Billets.

    `'none'` interdisait TOUT cadrage, y compris par le Hall — la carte y
    restait donc vide, et le Hall retombait sur un portrait générique du
    service (#1256). Un module SecuBox est fait pour être affiché dans une
    carte : il nomme ses hôtes plutôt que de fermer la porte à tout le monde,
    exactement comme le BBS.

    La liste reste EXPLICITE : `frame-ancestors *` accepterait n'importe quel
    site, ce qui est précisément l'attaque que cette directive existe pour
    empêcher. SECUBOX_FRAME_ANCESTORS permet d'en ajouter sur une autre box.
    """
    base = "'self' https://hall.gk2.secubox.in https://hall.gk2.net"
    sup = os.environ.get("SECUBOX_FRAME_ANCESTORS", "").strip()
    # Un `;` ou un guillemet dans la variable clôturerait la directive et
    # laisserait injecter la suite de la politique : on refuse plutôt que de
    # produire une CSP que le navigateur pourrait lire de travers.
    if sup and not any(c in sup for c in ";'\""):
        base += " " + sup
    return base


def _csp(frame_src: str, *, fonts: bool = False) -> str:
    # style-src allows 'unsafe-inline': the SecuBox health-banner is injected by
    # the WAF (sbxmitm sub_filter) and self-styles via a dynamic <style> element;
    # a strict style-src blocked it, so the banner fell to the page bottom
    # unstyled. script-src stays 'self' (the real XSS lever); user content is
    # nh3-sanitized. `fonts` also adds Google Fonts for the communiqué permalink.
    style_src = "style-src 'self' 'unsafe-inline'" + (" https://fonts.googleapis.com" if fonts else "")
    font_src = " font-src https://fonts.gstatic.com;" if fonts else ""
    # Bandeau santé injecté par le WAF (sbxwaf sub_filter) : un <script> inline
    # que `script-src 'self'` bloquait (erreur console). On l'autorise par son
    # EMPREINTE exacte — pas d'ouverture générale de l'inline.
    waf_banner = " 'sha256-eDTYsncfrGT/tlGmdDgSPq9JNg8lg8MeoFWIUtAxVHs='"
    return (
        "default-src 'self'; img-src 'self' https: data:; "
        f"{style_src}; script-src 'self'{waf_banner}; base-uri 'none'; "
        f"form-action 'self'; frame-ancestors {_ancetres()};{font_src} frame-src {frame_src}"
    )


def _extra_frame_hosts(rows) -> tuple[str, ...]:
    """Self-hosted embed hosts (Mastodon/PeerTube) among the given billet rows,
    to add to frame-src beyond the static provider allowlist."""
    from urllib.parse import urlparse
    hosts: list[str] = []
    for r in rows:
        if r["embed_html"] and r["embed_url"]:
            h = urlparse(r["embed_url"]).hostname
            if h and h not in hosts and not any(h == d or h.endswith("." + d) for d in _FRAME_HOSTS):
                hosts.append(h)
    return tuple(hosts)


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": _csp(_frame_src()),
}


def _depuis(iso: str | None) -> str:
    """Delai court et humain. Une date complete deborderait la ligne d'une
    carte et n'apprendrait rien de plus a cette taille."""
    if not iso:
        return ""
    from datetime import datetime, timezone
    try:
        t = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
    except ValueError:
        return ""
    s = max(0.0, (datetime.now(timezone.utc) - t).total_seconds())
    if s < 3600:
        return "il y a %d min" % round(s / 60)
    if s < 86400:
        return "il y a %d h" % round(s / 3600)
    if s < 2592000:
        return "il y a %d j" % round(s / 86400)
    return t.strftime("%d/%m/%y")


# Poster (vignette) d'une carte média (#1268). Un identifiant YouTube (11 car.)
# se lit dans une URL de source OU d'embed ; la miniature i.ytimg est
# déterministe, donc pas d'appel API au rendu. Les PeerTube dont la source n'est
# pas YouTube (rares) retombent sur le placeholder typé.
_YT_ID = re.compile(r"(?:youtu\.be/|[?&]v=|/embed/|/vi/)([A-Za-z0-9_-]{11})")


def _poster_for(d: dict) -> str | None:
    """URL de vignette pour la couverture de carte, ou None (→ placeholder)."""
    if d.get("embed_snapshot_url"):
        return d["embed_snapshot_url"]        # capture locale (souveraine) si présente
    for u in (d.get("ref_url"), d.get("embed_url")):
        if not u:
            continue
        m = _YT_ID.search(u)
        if m:
            return f"https://i.ytimg.com/vi/{m.group(1)}/hqdefault.jpg"
    return None


# Auto-catégorisation (fil immersif #1268) : 6 catégories souveraines, assignées
# de façon stable par hachage de l'id — en attendant une vraie taxonomie, ça
# colore le fil et alimente la légende/filtre. Ordre = look & feel de la barre.
_CATS = ("auth", "wall", "boot", "mind", "root", "mesh")


def _categorie(billet_id: str) -> str:
    import hashlib
    return _CATS[int(hashlib.sha1((billet_id or "").encode()).hexdigest(), 16) % len(_CATS)]


def _billet_view(row: aiosqlite.Row, base: str = "", media_rows=None, tags=None) -> dict:
    from urllib.parse import urlparse
    d = dict(row)
    d["body_html"] = render_markdown(d["body"])
    d["tags"] = tags or []
    # A few words for list/preview contexts; body_html keeps the full billet.
    d["summary"] = feeds.excerpt(d["body"], max_len=140)
    # Only long billets get resumed in the feed — `excerpt` collapses markdown, so
    # compare against IT, not len(body): a short billet padded with link syntax
    # would otherwise be "resumed" to a copy of itself followed by "Lire la suite".
    d["is_long"] = len(feeds.excerpt(d["body"], max_len=10_000)) > 140
    d["ref_host"] = (urlparse(d["ref_url"]).hostname if d.get("ref_url") else None)
    title = feeds.billet_title(d["body"])
    d["title"] = title
    d["permalink"] = f"{base}/b/{d['slug']}" if base else f"/b/{d['slug']}"
    d["share"] = _share_intents(d["permalink"], title) if base else {}
    d["media"] = [dict(m) for m in (media_rows or [])]
    d["style"] = d.get("style") or "default"
    snap = d.get("embed_snapshot")
    d["embed_snapshot_url"] = f"/media/{snap}" if snap else None
    # OBJET MEDIA (#1227) : un embed VIDEO (youtube/peertube/vimeo…) gagne la
    # barre d'actions du Hall (voir dans le lecteur, diffuser au parc). Les embeds
    # non-video (mastodon, bsky, soundcloud…) gardent leur embed nu.
    _eu = d.get("embed_url") or ""
    _eh = (urlparse(_eu).hostname or "").lower() if _eu else ""
    _VID = ("youtube.com", "youtu.be", "youtube-nocookie.com", "vimeo.com", "dailymotion.com")
    d["embed_is_video"] = bool(_eh) and (
        any(_eh == h or _eh.endswith("." + h) for h in _VID)
        or "peertube" in _eh or _eh.startswith("tube.") or _eh.endswith(".tv"))
    d["poster"] = _poster_for(d)
    d["cat"] = _categorie(d.get("id", ""))
    return d


def create_app(conn: aiosqlite.Connection | None = None, *, secret: str | None = None,
               revisions_dir: str | None = None, lifespan=None) -> FastAPI:
    # `conn` may be None when a `lifespan` opens the DB at startup (runtime);
    # tests pass a live connection and no lifespan. Routes read
    # `app.state.conn` at request time, so either wiring works.
    app = FastAPI(title="billets", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.conn = conn
    app.state.secret = secret or sec.get_secret()
    app.state.revisions_dir = revisions_dir or DEFAULT_REVISIONS_DIR
    # Outbound HTTP for oEmbed/OpenGraph (SSRF-guarded in services.ssrf). Tests
    # override app.state.http_client with a MockTransport client + resolver.
    import httpx as _httpx
    app.state.http_client = _httpx.AsyncClient(headers={"user-agent": "billets/0.1 (+secubox)"})
    from .services import ssrf as _ssrf
    app.state.resolver = _ssrf._default_resolver
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    # User-uploaded media (re-encoded, EXIF-stripped in services.media). In prod
    # nginx serves /media/ directly; this mount is the in-process fallback.
    try:
        media_root = media.media_dir()
        media_root.mkdir(parents=True, exist_ok=True)
        app.mount("/media", StaticFiles(directory=str(media_root)), name="media")
    except OSError:
        pass
    register_admin(app, templates)
    register_jwt_admin(app)  # JWT/SSO JSON surface for the SecuBox Companion
    register_public(app, templates)

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "module": "billets"}

    @app.get("/", response_class=HTMLResponse)
    async def feed(request: Request, cursor: str | None = None, tag: str | None = None):
        rows, next_cursor = await repo.list_published(app.state.conn, limit=PAGE_SIZE,
                                                      cursor=cursor, tag=tag)
        base = _base(request)
        media_map = await repo.list_media_for(app.state.conn, [r["id"] for r in rows])
        # One batched lookup for the page's chips + the whole-site chip bar.
        tag_map = await repo.tags_for_many(app.state.conn, [r["id"] for r in rows])
        resp = templates.TemplateResponse(request, "feed.html", {
            "site_title": SITE_TITLE, "tagline": SITE_TAGLINE,
            "billets": [_billet_view(r, base, media_map.get(r["id"]), tag_map.get(r["id"]))
                        for r in rows],
            "next_cursor": next_cursor,
            "all_tags": await repo.list_tags(app.state.conn),
            "active_tag": tag,
        })
        # Embeds render inline in the feed too; allow any self-hosted embed hosts
        # of the shown billets in frame-src (static providers already covered).
        # frame-src doit couvrir les embeds de TOUS les billets publiés, pas
        # seulement ceux de la page 1 : le défilement infini (#1268) appende des
        # billets des pages suivantes (ex. 122 PeerTube auto-hébergés), dont
        # l'hôte n'apparaîtrait pas dans la CSP du document et serait bloqué.
        allh = await repo.embed_hosts_published(app.state.conn)
        extra = tuple(h for h in allh
                      if not any(h == d or h.endswith("." + d) for d in _FRAME_HOSTS))
        # Fil immersif (#1268) : 'self' dans frame-src (le dialog encadre le
        # permalien même-origine) + fonts (Cinzel/Inter/JetBrains via Google).
        resp.headers["Content-Security-Policy"] = _csp("'self' " + _frame_src(extra), fonts=True)
        # Fil immersif : page vivante, on ne veut pas d'une vieille version en
        # cache navigateur qui référencerait d'anciens assets (#1268).
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.get("/feed/suite")
    async def feed_suite(request: Request, cursor: str | None = None,
                         tag: str | None = None):
        """Fragment du fil pour le DÉFILEMENT INFINI (#1268).

        Rend EXACTEMENT les mêmes cartes que la page (partiel `_feed_items.html`)
        et renvoie le curseur keyset suivant. Le client (billets.js) appende le
        HTML sous `#fil-billets` et poursuit tant que `next_cursor` n'est pas nul.
        Sans JS, le lecteur garde le pager `?cursor=` classique de la page."""
        from fastapi.responses import JSONResponse
        rows, next_cursor = await repo.list_published(app.state.conn, limit=PAGE_SIZE,
                                                      cursor=cursor, tag=tag)
        base = _base(request)
        media_map = await repo.list_media_for(app.state.conn, [r["id"] for r in rows])
        tag_map = await repo.tags_for_many(app.state.conn, [r["id"] for r in rows])
        vues = [_billet_view(r, base, media_map.get(r["id"]), tag_map.get(r["id"]))
                for r in rows]
        html = templates.env.get_template("_immersif_items.html").render(billets=vues)
        # Pas d'en-tête CSP ici : le fragment est injecté dans le document de la
        # page, dont la CSP fait foi (un embed exotique d'une page ultérieure
        # peut donc être bloqué — cas rare, borné au v1 du mur infini).
        return JSONResponse({"html": html, "next_cursor": next_cursor})

    @app.get("/activity/{slug}")
    async def activity(request: Request, slug: str):
        """Activité réelle d'un billet pour les couloirs latéraux du fil immersif
        (#1268) : derniers commentaires + réactions. Lecture seule, publique."""
        from fastapi.responses import JSONResponse
        row = await repo.get_by_slug(app.state.conn, slug)
        if row is None or row["status"] != "published":
            return JSONResponse({"comments": [], "reactions": {}})
        cmts = await repo.list_approved_comments(app.state.conn, row["id"])
        counts = await repo.reaction_counts(app.state.conn, row["id"])
        items = []
        for c in cmts[-8:]:
            c = dict(c)
            items.append({"who": (c.get("author_name") or "anon")[:32],
                          "msg": (c.get("body") or "")[:180],
                          "when": _depuis(c.get("created_at"))})
        resp = JSONResponse({"comments": items, "reactions": counts})
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.get("/feed/activity")
    async def feed_activity(request: Request):
        """Flux d'activité GLOBAL (#1268) : derniers commentaires + réactions,
        tous billets — pour les couloirs latéraux, toujours visibles."""
        from fastapi.responses import JSONResponse
        conn = app.state.conn
        comments = []
        async with conn.execute(
            "SELECT c.author_name, c.body, c.created_at, b.slug FROM comment c "
            "JOIN billet b ON b.id = c.billet_id "
            "WHERE c.status='approved' AND b.status='published' "
            "ORDER BY c.created_at DESC LIMIT 16") as cur:
            async for r in cur:
                comments.append({"who": (r[0] or "anon")[:32], "msg": (r[1] or "")[:160],
                                 "when": _depuis(r[2]), "slug": r[3]})
        reactions = []
        try:
            async with conn.execute(
                "SELECT r.emoji, b.slug FROM reaction r JOIN billet b ON b.id = r.billet_id "
                "WHERE b.status='published' ORDER BY r.rowid DESC LIMIT 18") as cur:
                async for r in cur:
                    reactions.append({"emoji": r[0], "slug": r[1]})
        except Exception:  # noqa: BLE001 — le flux d'activité ne doit jamais casser la page
            pass
        resp = JSONResponse({"comments": comments, "reactions": reactions})
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.get("/micro", response_class=HTMLResponse)
    async def micro(request: Request):
        """La carte que Billets sert au Hall (#1261).

        POURQUOI LE SERVICE LA SERT LUI-MEME. Le Hall montrait jusqu'ici la
        page complete reduite a la taille d'une carte : lisible de loin,
        illisible de pres. Une carte RESUME, elle ne retrecit pas — et le
        service est le seul a savoir ce qui, chez lui, merite le resume.

        Quatre billets suffisent : le dernier en entier, les trois suivants en
        titres. Au-dela la carte redevient un fil, et le fil a deja sa page.
        """
        rows, _ = await repo.list_published(app.state.conn, limit=6)
        async with app.state.conn.execute(
                "SELECT COUNT(*) FROM billet WHERE status = 'published'") as cur:
            total = (await cur.fetchone())[0]
        base = _base(request)
        media_map = await repo.list_media_for(app.state.conn, [r["id"] for r in rows])
        vues = [_billet_view(r, base, media_map.get(r["id"])) for r in rows]
        for v in vues:
            v["quand"] = _depuis(v.get("published_at") or v.get("created_at"))
            # Une vignette seulement si le billet en a une : un cadre gris a la
            # place d'une image absente ferait croire a un chargement en panne.
            img = next((m for m in v.get("media", []) if str(m.get("mime", "")).startswith("image/")), None)
            v["vignette"] = (img or {}).get("url") or None
        import json as _json
        resp = templates.TemplateResponse(request, "micro.html", {
            "dernier": vues[0] if vues else None,
            "suivants": vues[1:4],
            # LA ROTATION porte sur les cinq derniers : au-delà, une carte
            # mettrait une minute à revenir au premier et rien ne s'imprimerait.
            # C'est un carrousel, pas un archivage.
            "rotation": _json.dumps([
                {"title": v.get("title") or "", "permalink": v.get("permalink") or "/",
                 "quand": v.get("quand") or "", "vignette": v.get("vignette") or ""}
                for v in vues[:5]
            ], ensure_ascii=False),
            # Le VRAI total, pas la longueur de la page : « 4 publiés »
            # alors qu'il y en a trente serait un chiffre faux, et un chiffre
            # faux vaut moins que pas de chiffre.
            "total": total,
        })
        # La carte est encadree par le Hall : meme politique que le reste du
        # module, frame-ancestors compris (#1256).
        resp.headers["Content-Security-Policy"] = _csp(_frame_src([]))
        # UNE CARTE EST UNE VUE VIVANTE (#1298). Sans en-tete de fraicheur, le
        # navigateur lui applique son cache heuristique : le cadre gardait une
        # version d'il y a des heures, et un correctif deploye ne se voyait
        # jamais — on croyait le correctif rate alors qu'il n'etait pas relu.
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.get("/b/{slug}", response_class=HTMLResponse)
    async def permalink(request: Request, slug: str):
        row = await repo.get_by_slug(app.state.conn, slug)
        if row is None or row["status"] != "published":
            raise HTTPException(status_code=404, detail="Billet introuvable")
        await repo.increment_view(app.state.conn, row["id"])
        vhash, new_vtoken = _visitor(request)
        pcsrf = request.cookies.get(PCSRF_COOKIE) or sec.new_csrf_token()
        ts_token = antispam.issue_form_token(app.state.secret, now_epoch=int(time.time()))
        rctx = await reactions_context(request, row["id"], vhash, slug=row["slug"])
        rctx["pcsrf"] = pcsrf
        comments = await repo.list_approved_comments(app.state.conn, row["id"])
        comment_views = [{**dict(c), "body_html": linkify_plain(c["body"])} for c in comments]
        base = _base(request)
        permalink_url = f"{base}/b/{row['slug']}"
        media_rows = await repo.list_media(app.state.conn, row["id"])
        tmpl = "billet_communique.html" if row["style"] == "communique" else "billet.html"
        resp = templates.TemplateResponse(request, tmpl, {
            "site_title": SITE_TITLE, "tagline": SITE_TAGLINE,
            "billet": _billet_view(row, base, media_rows), "reactions": rctx,
            "comments": comment_views, "pcsrf": pcsrf,
            "ts_token": ts_token, "flash": request.query_params.get("c"),
            "og": {"title": feeds.billet_title(row["body"]),
                   "desc": feeds.excerpt(row["body"]), "url": permalink_url,
                   "image": (f"{base}/media/{media_rows[0]['filename']}" if media_rows else None)},
            "oembed_url": f"{base}/oembed?url={permalink_url}&format=json",
            "share": _share_intents(permalink_url, feeds.billet_title(row["body"])),
        })
        resp.set_cookie(PCSRF_COOKIE, pcsrf, httponly=True, samesite=_samesite(request),
                        secure=(request.headers.get("x-forwarded-proto", request.url.scheme) == "https"),
                        path="/")
        if new_vtoken:
            resp.set_cookie(VISITOR_COOKIE, new_vtoken, httponly=True, samesite=_samesite(request),
                            secure=(request.headers.get("x-forwarded-proto", request.url.scheme) == "https"),
                            max_age=31536000, path="/")
        # A self-hosted embed (Mastodon/PeerTube) needs its instance host in
        # frame-src; add it for this page only. La vue billet a le look du fil
        # immersif (#1268) : elle tire Cinzel/Inter/JetBrains de Google Fonts,
        # comme le communiqué — d'où fonts=True pour les deux gabarits.
        extra_hosts: tuple[str, ...] = ()
        if row["embed_html"] and row["embed_url"]:
            from urllib.parse import urlparse
            host = urlparse(row["embed_url"]).hostname
            if host and not any(host == d or host.endswith("." + d) for d in _FRAME_HOSTS):
                extra_hosts = (host,)
        resp.headers["Content-Security-Policy"] = _csp(_frame_src(extra_hosts), fonts=True)
        return resp

    async def _feed_rows() -> list[aiosqlite.Row]:
        rows, _ = await repo.list_published(app.state.conn, limit=30)
        return rows

    @app.get("/feed.xml")
    async def feed_atom(request: Request):
        from fastapi.responses import Response
        base = _base(request)
        rows = await _feed_rows()
        entries = [{
            "title": feeds.billet_title(r["body"]),
            "url": f"{base}/b/{r['slug']}", "id": f"{base}/b/{r['slug']}",
            "updated": r["updated_at"], "published": r["published_at"] or r["updated_at"],
            "content_html": render_markdown(r["body"]),
        } for r in rows]
        updated = rows[0]["updated_at"] if rows else "1970-01-01T00:00:00Z"
        xml = feeds.build_atom(site_title=SITE_TITLE, base_url=base,
                               self_url=f"{base}/feed.xml", entries=entries, updated=updated)
        return Response(xml, media_type="application/atom+xml")

    @app.get("/tags.json")
    async def tags_json():
        """The quick-view chip bar: every emoji hashtag in use, most-used first."""
        return {"tags": await repo.list_tags(app.state.conn)}

    @app.get("/feed.json")
    async def feed_json(request: Request, tag: str | None = None):
        base = _base(request)
        rows, _ = await repo.list_published(app.state.conn, limit=30, tag=tag)
        # One batched lookup for the whole page — never per-item (N+1).
        tag_map = await repo.tags_for_many(app.state.conn, [r["id"] for r in rows])
        items = [{
            "id": f"{base}/b/{r['slug']}", "url": f"{base}/b/{r['slug']}",
            "title": feeds.billet_title(r["body"]),
            # Short excerpt so list views can show a few words instead of a wall
            # of text; content_html still carries the full billet.
            "summary": feeds.excerpt(r["body"], max_len=140),
            "content_html": render_markdown(r["body"]),
            "date_published": r["published_at"] or r["updated_at"],
            "tags": tag_map.get(r["id"], []),
        } for r in rows]
        feed = feeds.build_jsonfeed(site_title=SITE_TITLE, base_url=base,
                                    feed_url=f"{base}/feed.json", items=items)
        if tag:
            feed["feed_url"] = f"{base}/feed.json?tag={tag}"
            feed["title"] = f"{SITE_TITLE} · #{tag}"
        return feed

    @app.get("/stats.json")
    async def stats_json(request: Request):
        # Public aggregate counts for the SecuBox admin panel (cross-origin).
        from fastapi.responses import JSONResponse
        base = _base(request)
        s = await repo.stats(app.state.conn)
        rows, _ = await repo.list_published(app.state.conn, limit=6)
        s["latest"] = [{"title": feeds.billet_title(r["body"]),
                        "url": f"{base}/b/{r['slug']}",
                        "date": (r["published_at"] or r["updated_at"])[:10]} for r in rows]
        s["site_url"] = f"{base}/"
        return JSONResponse(s, headers={"Access-Control-Allow-Origin": "*",
                                        "Cache-Control": "public, max-age=30"})

    @app.get("/oembed")
    async def oembed_out(request: Request, url: str, format: str = "json",
                         maxwidth: int | None = None, maxheight: int | None = None):
        # Outbound oEmbed so billets embed elsewhere. Only OUR own permalinks.
        from urllib.parse import urlparse
        from fastapi import HTTPException as _HE
        p = urlparse(url)
        parts = [seg for seg in p.path.split("/") if seg]
        if len(parts) != 2 or parts[0] != "b":
            raise _HE(status_code=404, detail="not an oembeddable billet URL")
        row = await repo.get_by_slug(app.state.conn, parts[1])
        if row is None or row["status"] != "published":
            raise _HE(status_code=404, detail="billet not found")
        base = _base(request)
        title = feeds.billet_title(row["body"])
        from html import escape as _esc
        permalink = f"{base}/b/{row['slug']}"
        html = (f'<blockquote class="billet-embed" lang="fr">'
                f'<p>{_esc(feeds.excerpt(row["body"]))}</p>'
                f'<cite>— <a href="{_esc(permalink)}">{_esc(SITE_TITLE)}</a></cite>'
                f'</blockquote>')
        return {
            "type": "rich", "version": "1.0", "provider_name": SITE_TITLE,
            "provider_url": f"{base}/", "title": title,
            "html": html, "width": maxwidth or 480, "height": maxheight or 180,
        }

    return app
