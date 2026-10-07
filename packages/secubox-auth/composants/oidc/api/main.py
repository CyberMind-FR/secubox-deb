# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-oidc — fournisseur OpenID Connect adossé à la session
SecuBox (#1589, #1562).

Monté par l'agrégateur sous /api/v1/oidc ; le Hall l'expose en /oidc/.
L'ÉMETTEUR vient de la configuration, jamais de l'en-tête Host : un nom
présenté par le client ne doit pas pouvoir changer l'identité du fournisseur.

QUI EST AUTHENTIFIÉ : seule une session SecuBox valide qui désigne une PERSONNE
(personne_du_porteur). Une session d'appareil non rattaché, un compte système
seul, le mode lecture LAN : rien de tout cela n'ouvre un compte ailleurs.
"""
from __future__ import annotations

import base64
import html
import os
import sys
import time
import tomllib
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

# En QUEUE, jamais en tête : devant /usr/local, le websockets 10.4 de Debian
# masquait celui qu'attend uvicorn ≥ 0.54 → service en boucle (#1796).
if "/usr/lib/python3/dist-packages" not in sys.path:
    sys.path.append("/usr/lib/python3/dist-packages")
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import fournisseur as F

CONF = Path(os.environ.get("SECUBOX_OIDC_CONF", "/etc/secubox/oidc.toml"))


def _conf() -> dict:
    try:
        return tomllib.loads(CONF.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def emetteur() -> str:
    iss = _conf().get("issuer")
    if not iss:
        # Le Hall de CETTE box (#1723) : l'émetteur d'une autre box (hall.gk2)
        # ne correspondrait à rien de ce que cette box signe.
        from secubox_core.auth import hote_box
        iss = f"https://{hote_box('hall') or 'hall.localhost'}/oidc"
    return str(iss).rstrip("/")


def _domaine_mail() -> str:
    d = str(_conf().get("domaine_mail") or "")
    if d:
        return d
    h = urlsplit(emetteur()).hostname or "secubox.local"
    return h[5:] if h.startswith("hall.") else h


def personne(request: Request) -> Optional[dict]:
    """La personne derrière la session SecuBox de la requête, ou None."""
    try:
        from secubox_core import auth, capacites  # noqa: PLC0415
    except ImportError:
        return None
    tok = request.cookies.get(auth.SESSION_COOKIE)
    if not tok:
        return None
    payload = auth._validate_token(tok)
    if not payload:
        return None
    per = capacites.personne_du_porteur(payload)
    if not per:
        return None
    return {"payload": payload, "per": per}


def claims_pour(ident: dict, c: dict) -> dict:
    """Ce que le service apprend de la personne — et rien d'autre."""
    from secubox_core import capacites  # noqa: PLC0415
    payload, per = ident["payload"], ident["per"]
    app = str(c.get("app") or "")
    nom = (capacites.compte_lie(payload, app) if app else None) or per["pseudo"]
    mail = capacites.compte_lie(payload, "email")
    verifie = bool(mail and "@" in mail)
    if not verifie:
        mail = f"{per['pseudo']}@{_domaine_mail()}"
    return {"sub": per["user_uuid"], "preferred_username": nom, "name": per["pseudo"],
            "nickname": per["pseudo"], "email": mail, "email_verified": verifie,
            "auth_time": int(time.time())}


app = FastAPI(title="secubox-oidc", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)

SANS_CACHE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _erreur_json(code: str, detail: str, statut: int = 400) -> JSONResponse:
    return JSONResponse({"error": code, "error_description": detail}, status_code=statut, headers=SANS_CACHE)


def _page(titre: str, corps: str, statut: int = 200) -> HTMLResponse:
    return HTMLResponse(f"""<!doctype html><html lang="fr"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(titre)}</title>
<style>:root{{--f:#f4f6fb;--t:#141824;--m:#5b6478;--a:#0784a8}}
@media (prefers-color-scheme:dark){{:root{{--f:#0b0e14;--t:#e7ebf4;--m:#8791a6;--a:#28d6ff}}}}
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--f);color:var(--t);
font:15px/1.5 system-ui,sans-serif;padding:0 16px}}main{{max-width:30rem}}h1{{font-size:1.25rem}}
p{{color:var(--m)}}a{{color:var(--a)}}</style><main>{corps}</main></html>""",
                        status_code=statut, headers=SANS_CACHE)


def _avec_params(uri: str, params: dict) -> str:
    s = urlsplit(uri)
    q = parse_qsl(s.query, keep_blank_values=True) + [(k, v) for k, v in params.items() if v]
    return urlunsplit((s.scheme, s.netloc, s.path, urlencode(q), s.fragment))


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "issuer": emetteur(), "cle": F.CLE.exists()}


@app.get("/.well-known/openid-configuration")
async def decouverte() -> JSONResponse:
    i = emetteur()
    return JSONResponse({
        "issuer": i,
        "authorization_endpoint": i + "/authorize",
        "token_endpoint": i + "/token",
        "userinfo_endpoint": i + "/userinfo",
        "jwks_uri": i + "/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                             "preferred_username", "name", "nickname", "email", "email_verified"],
    })


@app.get("/jwks")
async def cles() -> JSONResponse:
    return JSONResponse(F.jwks())


@app.get("/authorize")
async def autorise(request: Request):
    q = request.query_params
    client_id, redirect_uri = q.get("client_id", ""), q.get("redirect_uri", "")
    c = F.client(client_id)
    # Client et redirect_uri vérifiés AVANT toute redirection : sinon ce point
    # d'entrée deviendrait un redirecteur ouvert vers n'importe où.
    if not c:
        return _page("Client inconnu", "<h1>Application inconnue</h1><p>Ce service n'est pas enregistré auprès de la box.</p>", 400)
    try:
        F.verifie_redirection(c, redirect_uri)
    except F.Refus:
        return _page("Redirection refusée", "<h1>Adresse de retour refusée</h1><p>Elle ne correspond pas à celle enregistrée pour ce service.</p>", 400)
    state = q.get("state", "")
    if q.get("response_type") != "code":
        return RedirectResponse(_avec_params(redirect_uri, {"error": "unsupported_response_type", "state": state}), 302)
    if "openid" not in q.get("scope", "").split():
        return RedirectResponse(_avec_params(redirect_uri, {"error": "invalid_scope", "state": state}), 302)

    ident = personne(request)
    if not ident:
        if q.get("prompt") == "none":
            return RedirectResponse(_avec_params(redirect_uri, {"error": "login_required", "state": state}), 302)
        hall = emetteur().rsplit("/oidc", 1)[0]
        ici = html.escape(str(request.url.path) + "?" + str(request.url.query))
        nom = html.escape(str(c.get("name") or client_id))
        return _page("Connexion SecuBox", f"""<h1>Entrer dans {nom} avec SecuBox</h1>
<p>Aucune session SecuBox rattachée à une personne n'est ouverte dans ce navigateur.
Connectez-vous au <a href="{html.escape(hall)}/" target="_blank" rel="noopener">Hall</a>, puis
<a href="/oidc/authorize?{html.escape(str(request.url.query))}">réessayez</a>.</p>""")
    try:
        code = F.emet_code(client_id, redirect_uri, claims_pour(ident, c), q.get("nonce", ""),
                           q.get("code_challenge", ""), q.get("code_challenge_method", ""))
    except F.Refus as e:
        return RedirectResponse(_avec_params(redirect_uri, {"error": e.code, "error_description": e.detail,
                                                            "state": state}), 302)
    return RedirectResponse(_avec_params(redirect_uri, {"code": code, "state": state, "iss": emetteur()}), 302)


def _identifiants(request: Request, form: dict) -> tuple[str, str]:
    a = request.headers.get("authorization", "")
    if a.lower().startswith("basic "):
        try:
            from urllib.parse import unquote  # noqa: PLC0415
            cid, _, sec = base64.b64decode(a[6:].strip()).decode("utf-8").partition(":")
            return unquote(cid), unquote(sec)
        except Exception:  # noqa: BLE001
            return "", ""
    return str(form.get("client_id") or ""), str(form.get("client_secret") or "")


@app.post("/token")
async def jeton(request: Request) -> JSONResponse:
    form = dict(await request.form())
    cid, sec = _identifiants(request, form)
    try:
        F.authentifie_client(cid, sec)
        if form.get("grant_type") != "authorization_code":
            raise F.Refus("unsupported_grant_type", "seul authorization_code est accepté")
        claims, nonce = F.echange_code(str(form.get("code") or ""), cid, str(form.get("redirect_uri") or ""),
                                       str(form.get("code_verifier") or ""))
    except F.Refus as e:
        return _erreur_json(e.code, e.detail, 401 if e.code == "invalid_client" else 400)
    acces = F.emet_jeton(cid, claims)
    return JSONResponse({"access_token": acces, "token_type": "Bearer", "expires_in": F.DUREE_JETON,
                         "scope": "openid profile email",
                         "id_token": F.id_token(emetteur(), cid, claims, nonce)}, headers=SANS_CACHE)


@app.api_route("/userinfo", methods=["GET", "POST"])
async def infos(request: Request) -> JSONResponse:
    a = request.headers.get("authorization", "")
    if not a.lower().startswith("bearer "):
        return _erreur_json("invalid_token", "jeton d'accès requis", 401)
    try:
        claims = F.lit_jeton(a[7:].strip())
    except F.Refus as e:
        return _erreur_json(e.code, e.detail, 401)
    return JSONResponse({k: v for k, v in claims.items() if k != "auth_time"}, headers=SANS_CACHE)
