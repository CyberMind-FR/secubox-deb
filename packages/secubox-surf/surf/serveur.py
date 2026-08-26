# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Surf — le serveur de relais (POC vivant)
CyberMind — https://cybermind.fr

Le harnais `mesure` disait SI un site est relayable. Ceci le relaie POUR DE
VRAI, en lecture, tracker-strippé, sur une origine par site.

    surf-www-lemonde-fr.gk2.secubox.in  →  www.lemonde.fr

L'hôte cible se lit dans l'en-tête `Host` de la requête : chaque origine proxy
ne sert qu'UN site, et c'est ce qui fait l'isolation (§piège structurant de
`docs/POC-SURF.md`). Une origine de pisteur — `surf-connect-facebook-net…` —
répond 204 et ne relaie rien.

CE SERVICE RESTE HORS DE LA CHAÎNE D'INSPECTION. Il relaie du contenu externe,
possiblement hostile ; le faire passer par sbxwaf reviendrait à demander à
notre WAF d'avaler Facebook. D'où le `waf_bypass` du vhost.

ASGI pur, sans cadre : un POC n'a pas à traîner Starlette pour trois routes.
Lancé par uvicorn sur un port loopback, derrière nginx (TLS terminé par
HAProxy, wildcard `*.gk2.secubox.in`).
"""

from __future__ import annotations

import httpx

from urllib.parse import parse_qs, unquote

from . import relais
from . import egress


# Un seul client async par mode, réutilisé : ouvrir une connexion par requête
# jetterait le bénéfice du keep-alive vers l'amont.
_clients: dict[str, httpx.AsyncClient] = {}


def _client(mode: str) -> httpx.AsyncClient:
    if mode not in _clients:
        commun = dict(timeout=25.0, follow_redirects=False,
                      headers=egress.ENTETES_NAV)
        if mode == "tor":
            try:
                _clients[mode] = httpx.AsyncClient(proxy=egress.TOR_SOCKS, **commun)
            except TypeError:
                _clients[mode] = httpx.AsyncClient(proxies=egress.TOR_SOCKS, **commun)
        else:
            _clients[mode] = httpx.AsyncClient(**commun)
    return _clients[mode]


async def _lire_corps(receive) -> bytes:
    corps = b""
    while True:
        ev = await receive()
        corps += ev.get("body", b"")
        if not ev.get("more_body"):
            break
    return corps


def _bannette(cible: str, message: str, code: int = 502) -> bytes:
    return (
        "<!doctype html><meta charset=utf-8>"
        "<style>body{background:#0a0a0f;color:#e8e6d9;font:15px/1.6 system-ui;"
        "margin:0;display:grid;place-items:center;height:100vh;text-align:center}"
        "div{max-width:32rem;padding:2rem}b{color:#00d4ff}"
        "small{color:#6b6b7a}</style><div>"
        "<p>🛰️ <b>SecuBox Surf</b></p>"
        "<p>" + message + "</p>"
        "<p><small>" + cible + " · relais en lecture, pisteurs coupés</small></p>"
        # UN BOUTON RETOUR, PAS UN CUL-DE-SAC (#1357). Beaucoup de « injoignable »
        # viennent d'un portail de consentement (first-id.fr et consorts) que le
        # DNS de la box bloque a dessein : ce n'est pas une panne, c'est une
        # protection. On offre le retour au Hall plutot qu'un mur.
        "<p style=\"margin-top:1.4rem\">"
        "<button onclick=\"parent.postMessage({sbx:'surf-vide'},'*')\" "
        "style=\"background:#00d4ff;color:#04222a;border:0;border-radius:8px;"
        "padding:.5rem 1rem;font-weight:700;cursor:pointer\">← Revenir</button></p>"
        "<p><small>Ce domaine est souvent un pisteur de consentement, "
        "coupé par le pare-feu de la box.</small></p>"
        "</div>"
    ).encode()


async def app(scope, receive, send):
    if scope["type"] != "http":
        return

    entetes_in = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
    hote_proxy = entetes_in.get("host", "").split(":")[0]
    cible = relais.cible_de(hote_proxy)

    async def repond(code, entetes, corps):
        await send({"type": "http.response.start", "status": code,
                    "headers": [(k.encode(), v.encode()) for k, v in entetes]})
        await send({"type": "http.response.body", "body": corps})

    # Origine mal formée : on ne devine pas une cible, on le dit.
    if not cible:
        await repond(400, [("content-type", "text/html; charset=utf-8")],
                     _bannette(hote_proxy or "?",
                               "Cette adresse ne nomme aucun site à relayer.", 400))
        return

    chemin = scope.get("raw_path", scope["path"].encode()).decode()
    qs = scope.get("query_string", b"").decode()

    # ORIGINE DE PISTEUR / PORTAIL DE CONSENTEMENT.
    #
    # On ne le relaie pas — mais avant de fermer, on regarde s'il porte une URL
    # de RETOUR dans sa query (redirect=, return=, r=, url=...). Ces portails
    # (first-id, etc.) y mettent toujours la page d'ou l'on vient. Plutot que de
    # laisser le site en carafe (« bfmtv perdu »), on SAUTE le portail : on
    # renvoie le navigateur directement a cette page, relayee. Sinon, 204.
    def _saut_portail():
        """L'URL de retour d'un portail, relayee — ou None.

        Deux formes : soit un parametre porte l'URL de retour COMPLETE, soit —
        cas de first-id — l'hote et le chemin sont SEPARES (redirectHost +
        redirectUri). On gere les deux.
        """
        q = parse_qs(qs)
        # Forme separee : redirectHost + redirectUri.
        hote_r, uri_r = None, ""
        for k, v in q.items():
            kl = k.lower()
            if v and kl in ("redirecthost", "host", "returnhost"):
                hote_r = unquote(v[0])
            if v and kl in ("redirecturi", "uri", "returnuri", "path"):
                uri_r = unquote(v[0])
        if hote_r and hote_r.startswith(("http://", "https://")):
            rp = relais.urlsplit(hote_r)
            if rp.hostname and not relais.est_pisteur(rp.hostname):
                chemin = uri_r if uri_r.startswith("/") else (rp.path or "/")
                return "https://" + relais.origine_de(rp.hostname) + chemin
        # Forme complete : une URL http(s) dans un parametre.
        for vals in q.values():
            for cand in vals:
                c = unquote(cand)
                if c.startswith(("http://", "https://")):
                    rp = relais.urlsplit(c)
                    if rp.hostname and not relais.est_pisteur(rp.hostname):
                        return ("https://" + relais.origine_de(rp.hostname)
                                + (rp.path or "/") + (("?" + rp.query) if rp.query else ""))
        return None

    if relais.est_pisteur(cible):
        dest = _saut_portail()
        if dest:
            await repond(302, [("location", dest)], b"")
            return
        await repond(204, [("content-type", "text/plain")], b"")
        return
    base = "https://" + cible + "/"
    cible_url = "https://" + cible + chemin + (("?" + qs) if qs else "")
    mode = "tor" if egress._onion(cible) else "direct"

    # On transmet la méthode et le corps (formulaires de recherche, etc.), mais
    # on filtre les en-têtes qui trahiraient l'origine proxy ou casseraient la
    # négociation. `Host` est réécrit vers la vraie cible.
    methode = scope["method"]
    corps_req = await _lire_corps(receive) if methode in ("POST", "PUT", "PATCH") else None
    entetes_req = dict(egress.ENTETES_NAV)
    entetes_req["Host"] = cible
    if "cookie" in entetes_in:
        entetes_req["Cookie"] = entetes_in["cookie"]
    if "content-type" in entetes_in and corps_req is not None:
        entetes_req["Content-Type"] = entetes_in["content-type"]

    rap = relais.Rapport(cible=cible, egress=mode)

    def sur_hote(h: str):
        if relais.est_pisteur(h):
            return None
        return relais.origine_de(h)

    try:
        r = await _client(mode).request(methode, cible_url, headers=entetes_req,
                                        content=corps_req)
    except httpx.HTTPError as e:
        # Un portail injoignable (DNS bloque par la box) porte souvent l'URL de
        # retour : on saute le portail plutot que d'echouer.
        dest = _saut_portail()
        if dest:
            await repond(302, [("location", dest)], b"")
            return
        await repond(502, [("content-type", "text/html; charset=utf-8")],
                     _bannette(cible, "Injoignable (%s)." % type(e).__name__))
        return

    entetes_out = relais.reecris_entetes(dict(r.headers), base, rap, sur_hote)
    ct = r.headers.get("content-type", "").lower()

    if "text/html" in ct:
        corps = relais.reecris_html(r.text, base, rap, sur_hote).encode()
    elif "css" in ct:
        corps = relais.reecris_css(r.text, base, rap, sur_hote).encode()
    else:
        # Images, polices, JS, JSON : relayés tels quels. On ne réécrit pas le
        # JS (indécidable) — d'où le mode « lecture » : ce qui a besoin du JS
        # pour vivre vivra mal. C'est la mesure du POC, pas un défaut caché.
        corps = r.content

    sortie = [(k, v) for k, v in entetes_out.items()
              if k.lower() not in ("content-length",)]
    sortie.append(("content-length", str(len(corps))))
    sortie.append(("x-surf-cible", cible))
    await repond(r.status_code, sortie, corps)
