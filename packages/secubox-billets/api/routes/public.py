# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Public write actions: emoji reactions (anonymous, signed visitor cookie) and
moderated comments (honeypot + timed token + rate-limit). Both degrade
gracefully without JS (plain POST → 303 redirect); a same-origin fetch swaps the
reactions fragment when JS is on."""
from __future__ import annotations

import os

import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import repo
from ..models import CommentIn, ReactionEmoji
from ..services import antispam
from ..services import security as sec

VISITOR_COOKIE = "billets_visitor"
PCSRF_COOKIE = "billets_pcsrf"
EMOJIS = [e.value for e in ReactionEmoji]
_comment_limiter = sec.RateLimiter(max_events=5, window_s=3600)


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _visitor(request: Request) -> tuple[str, str | None]:
    """Return (visitor_hash, new_token_or_None). Mints a token if absent."""
    secret = request.app.state.secret
    token = request.cookies.get(VISITOR_COOKIE)
    if token:
        return sec.visitor_hash(token, secret), None
    token = sec.new_visitor_token()
    return sec.visitor_hash(token, secret), token


async def reactions_context(request: Request, billet_id: str, vhash: str,
                            *, slug: str = "") -> dict:
    counts = await repo.reaction_counts(request.app.state.conn, billet_id)
    mine = await repo.visitor_reactions(request.app.state.conn, billet_id, vhash)
    return {"billet_id": billet_id, "slug": slug, "emojis": EMOJIS,
            "counts": counts, "mine": mine,
            "pcsrf": request.cookies.get(PCSRF_COOKIE) or ""}


def register_public(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.post("/b/{slug}/react")
    async def react(request: Request, slug: str, emoji: str = Form(...), csrf: str = Form("")):
        conn = request.app.state.conn
        row = await repo.get_by_slug(conn, slug)
        if row is None or row["status"] != "published":
            return RedirectResponse("/", status_code=303)
        if not sec.csrf_ok(request.cookies.get(PCSRF_COOKIE), csrf) or emoji not in EMOJIS:
            return RedirectResponse(f"/b/{slug}", status_code=303)
        vhash, new_token = _visitor(request)
        await repo.toggle_reaction(conn, row["id"], emoji, vhash, now=_now())
        ctx = await reactions_context(request, row["id"], vhash, slug=slug)
        wants_fragment = request.headers.get("hx-request") or \
            request.query_params.get("fragment") == "1"
        if wants_fragment:
            resp = templates.TemplateResponse(request, "_reactions.html", {"reactions": ctx})
        else:
            resp = RedirectResponse(f"/b/{slug}#reactions", status_code=303)
        if new_token:
            resp.set_cookie(VISITOR_COOKIE, new_token, httponly=True, samesite=_samesite(request),
                            secure=_secure(request), max_age=31536000, path="/")
        return resp

    @app.get("/jeton")
    async def jeton(request: Request):
        """Jetons de publication pour LE FIL (#1268).

        Le fil ne rend aucun formulaire : la saisie vit dans le popup théâtre,
        fabriqué en JavaScript. Il lui faut donc la même paire que la vue billet
        — le jeton CSRF (dont la moitié est posée en cookie) et le jeton
        anti-spam signé, qui impose trois secondes de réflexion. On le sert au
        chargement du fil, pas au moment d'écrire : sinon le premier envoi
        tomberait systématiquement sous le délai minimal.

        Rien du visiteur n'est exposé : deux jetons opaques, et un cookie que la
        page recevait déjà en visitant n'importe quel billet.
        """
        pcsrf = request.cookies.get(PCSRF_COOKIE) or sec.new_csrf_token()
        resp = JSONResponse({
            "csrf": pcsrf,
            "ts_token": antispam.issue_form_token(request.app.state.secret,
                                                  now_epoch=int(time.time())),
        })
        resp.set_cookie(PCSRF_COOKIE, pcsrf, httponly=True, samesite=_samesite(request),
                        secure=_secure(request), path="/")
        return resp

    @app.post("/b/{slug}/comment")
    async def comment(request: Request, slug: str, author_name: str = Form(...),
                      body: str = Form(...), author_email: str = Form(""),
                      website: str = Form(""), ts_token: str = Form(""), csrf: str = Form("")):
        # ENVOI SANS RECHARGEMENT (#1268). La vue billet joue une vidéo : la
        # redirection 303 rechargeait la page, l'embed repartait en autoplay
        # SONORE — que le navigateur refuse sans geste — et l'image restait
        # figée le temps d'un clic. Le client poste donc en `Accept: json` et
        # reste sur place. Le chemin HTML (sans JS) est inchangé : mêmes
        # contrôles, mêmes redirections, dans le même ordre.
        veut_json = "application/json" in (request.headers.get("accept") or "")

        def rep(code: str, *, cible: str | None = None, **extra):
            if veut_json:
                return JSONResponse({"ok": code in ("ok", "pending"), "c": code, **extra})
            return RedirectResponse(cible or f"/b/{slug}?c={code}", status_code=303)

        conn = request.app.state.conn
        row = await repo.get_by_slug(conn, slug)
        if row is None or row["status"] != "published":
            return rep("absent", cible="/")
        secret = request.app.state.secret
        if not sec.csrf_ok(request.cookies.get(PCSRF_COOKIE), csrf):
            return rep("csrf", cible=f"/b/{slug}")
        # Honeypot: pretend success, store nothing.
        if antispam.honeypot_tripped(website):
            return rep("ok")
        # Minimum think-time (signed token).
        if not antispam.form_token_ok(secret, ts_token, now_epoch=int(time.time())):
            return rep("slow")
        ip_hash = sec.hash_ip(_client_ip(request), secret)
        if not _comment_limiter.check_and_add(ip_hash):
            return rep("rate")
        try:
            data = CommentIn(author_name=author_name, body=body,
                             author_email=(author_email or None))
        except Exception:  # noqa: BLE001
            return rep("bad")
        auto = await repo.has_prior_approved(conn, ip_hash, data.author_name)
        status = "approved" if auto else "pending"
        await repo.add_comment(conn, row["id"], author_name=data.author_name,
                               email_hash=antispam.email_hash(data.author_email, secret),
                               body=data.body, ip_hash=ip_hash, honeypot=False,
                               status=status, now=_now())
        code = "ok" if auto else "pending"
        return rep(code, cible=f"/b/{slug}?c={code}#comments",
                   who=data.author_name, msg=data.body, when="à l'instant")


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _secure(request: Request) -> bool:
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


def _samesite(request: Request) -> str:
    """Politique SameSite d'un cookie SecuBox.

    ENCADRE PAR LE HALL, UN SERVICE EST UN CONTEXTE TIERS. Le navigateur
    rejette purement et simplement un cookie SameSite=Lax ou Strict pose la :
    le service ne reconnait plus le visiteur et rend 401 sur ses propres
    ressources — la panne exacte constatee sur la radio (#1251).

    None exige Secure, donc HTTPS. En clair on retombe sur Lax : un cookie
    premier-partie qui fonctionne vaut mieux qu'un cookie que le navigateur
    jette.

    L'operateur peut fermer la porte avec SECUBOX_COOKIE_SAMESITE=lax|strict —
    au prix de l'affichage encadre, qui cessera de fonctionner.

    Ce que SameSite ne protege PAS ici : le jeton anti-rejeu est verifie par
    DOUBLE ENVOI (cookie contre champ de formulaire). Un site tiers ne peut pas
    LIRE le cookie — c'est l'isolation d'origine, pas SameSite, qui l'en
    empeche. La protection reste donc entiere.
    """
    force = os.environ.get("SECUBOX_COOKIE_SAMESITE", "").strip().lower()
    if force in ("lax", "strict", "none"):
        return force
    return "none" if _secure(request) else "lax"
