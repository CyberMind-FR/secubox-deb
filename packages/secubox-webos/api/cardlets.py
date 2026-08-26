# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — adaptateurs cardlets (résumés vivants par service).

Un adaptateur traduit l'API RÉELLE d'un service (lue côté serveur, DANS la box,
via sa socket /run/secubox/<id>.sock) en un payload cardlet normalisé (brief §6).
Souverain : aucune donnée n'est une capture figée, le client ne contacte jamais
le service directement. Radio = cardlet de référence.
"""
import json
import socket
from typing import Callable, Optional

RADIO_SOCK = "/run/secubox/radio.sock"


def uds_get(sock_path: str, path: str, timeout: float = 2.0) -> dict:
    """GET JSON minimal sur une socket Unix HTTP (sans dépendance externe)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        req = "GET %s HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" % path
        s.sendall(req.encode("ascii"))
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    _, _, body = buf.partition(b"\r\n\r\n")
    return json.loads(body.decode("utf-8", "replace"))


def radio_cardlet(sock: str = RADIO_SOCK, _get: Optional[Callable] = None) -> dict:
    """Résumé « now-playing » de la Radio → payload cardlet normalisé (brief §6)."""
    get = _get or uds_get
    cur = get(sock, "/api/v1/radio/current") or {}
    try:
        st = get(sock, "/api/v1/radio/stats") or {}
    except Exception:
        st = {}
    piste = cur.get("piste") or {}
    silence = bool(cur.get("silence"))
    title = piste.get("titre") or ("— silence à l'antenne —" if silence else "Radio souveraine")
    return {
        "id": "radio",
        "kind": "radio-now-playing",
        "status": "online",
        "content": {
            "title": title,
            "subtitle": piste.get("auteur") or "",
            "station": "Radio souveraine",
        },
        "metrics": [
            {"id": "listeners", "value": int(st.get("auditeurs", 0) or 0)},
            {"id": "tracks", "value": int(st.get("pistes", 0) or 0)},
        ],
        "silence": silence,
    }


def radio_cardlet_safe(sock: str = RADIO_SOCK, _get: Optional[Callable] = None) -> dict:
    """radio_cardlet() avec repli `offline` si la Radio est injoignable."""
    try:
        return radio_cardlet(sock, _get)
    except Exception:
        return {
            "id": "radio", "kind": "radio-now-playing", "status": "offline",
            "content": {"title": "Radio", "subtitle": "", "station": "Radio souveraine"},
            "metrics": [], "silence": False,
        }


BBS_SOCK = "/run/secubox/bbs.sock"


def bbs_menu(sock: str = BBS_SOCK, _get=None) -> dict:
    """Rubriques BBS (navbar) → sous-menu Hall, lues côté serveur via bbs.sock."""
    get = _get or uds_get
    d = get(sock, "/api/v1/bbs/menu") or {}
    items = [
        {"slug": c.get("slug"), "title": c.get("title"), "threads": c.get("threads", 0)}
        for c in (d.get("categories") or [])
        if c.get("slug")
    ]
    return {"id": "bbs", "items": items}


def bbs_menu_safe(sock: str = BBS_SOCK, _get=None) -> dict:
    try:
        return bbs_menu(sock, _get)
    except Exception:
        return {"id": "bbs", "items": []}


WAF_SOCK = "/run/secubox/waf.sock"


def waf_cardlet(sock: str = WAF_SOCK, _get: Optional[Callable] = None) -> dict:
    """Posture du WAF → payload cardlet normalisé (#1228).

    MÊME FORME QUE LA RADIO, à dessein : le Hall sait déjà afficher un cardlet,
    il n'a pas à apprendre un second gabarit. Ce qui change est le contenu —
    une radio dit ce qu'elle joue, un pare-feu dit ce qu'il écarte.

    QUATRE CHIFFRES, pas davantage. Un cardlet est lu d'un coup d'œil depuis
    l'accueil : au-delà, il faut ouvrir le tableau de bord, qui est fait pour
    ça. On garde donc ce qui répond à « suis-je couvert, et est-ce que ça
    travaille » — bannis actifs, menaces du jour, surfaces surveillées,
    détections en service.

    Chaque source est facultative : une partie indisponible retire son chiffre
    au lieu d'emporter tout le cardlet. Un pare-feu muet serait plus inquiétant
    qu'un chiffre manquant.
    """
    get = _get or uds_get
    stats = get(sock, "/stats") or {}

    try:
        bans = get(sock, "/bans") or {}
    except Exception:
        bans = {}
    try:
        detec = get(sock, "/detections") or {}
    except Exception:
        detec = {}

    par_type = stats.get("par_type") or {}
    detections = detec.get("detections") or []
    actives = sum(1 for d in detections if d.get("actif"))

    # La catégorie dominante donne au cardlet sa phrase : « ce qui frappe en ce
    # moment ». Sans elle, le cardlet afficherait quatre nombres sans récit.
    cats = stats.get("by_category") or {}
    tete = max(cats.items(), key=lambda kv: kv[1])[0] if cats else ""

    # Les trois premieres origines, separees par un point median. « premiere
    # origine : US » disait moins en trois fois plus de place ; trois codes
    # pays tiennent sur la meme ligne et dessinent d'ou vient la pression.
    pays = stats.get("pays") or {}
    tete_pays = [p for p in list(pays)[:3] if p and p not in ("LAN", "??")]

    metrics = [
        {"id": "bans", "value": int(bans.get("total", 0) or 0)},
        {"id": "jour", "value": int(stats.get("threats_today", 0) or 0)},
        {"id": "surfaces", "value": len(par_type)},
        {"id": "detections", "value": actives},
    ]

    return {
        "id": "waf",
        "kind": "waf-posture",
        "status": "online",
        "content": {
            "title": _phrase_waf(tete, bans.get("total", 0) or 0),
            "subtitle": ("🌍 " + " · ".join(tete_pays)) if tete_pays else "",
            "station": "Pare-feu applicatif",
        },
        "metrics": metrics,
        "categorie": tete,
        "silence": not cats,
    }


# Les catégories du moteur, dites en français et d'un mot. Un cardlet qui
# afficherait « host_anomaly:unrouted » parlerait au développeur, pas à
# l'opérateur qui passe devant son accueil.
_PHRASES = {
    "host_anomaly": "noms qu'on ne sert pas",
    "auth_": "tentatives d'authentification",
    "leurre:": "contacts sur les leurres",
    "robots": "robots d'indexation",
    "scanners": "balayages",
    "recon_crawler": "reconnaissance",
    "honeypot": "pots de miel",
    "sqli": "injections SQL",
    "xss": "scripts injectés",
    "lfi": "traversées de chemin",
    "rce": "exécutions distantes",
    "credential_harvest": "vols d'identifiants",
    "api_abuse": "abus d'API",
}


def _phrase_waf(categorie: str, bannis: int) -> str:
    """Ce que le cardlet raconte, en une ligne.

    Sans preambule : « Surtout : » occupait le tiers de la ligne pour ne rien
    dire de plus. Le cardlet est etroit, chaque caractere y compte, et le sens
    tient sans lui — c'est bien la categorie dominante qu'on lit.
    """
    if not categorie:
        return "Rien à signaler"
    for prefixe, mot in _PHRASES.items():
        if categorie.startswith(prefixe):
            return mot[:1].upper() + mot[1:]
    return categorie


def waf_cardlet_safe(sock: str = WAF_SOCK, _get: Optional[Callable] = None) -> dict:
    """waf_cardlet() avec repli `offline` si le WAF est injoignable.

    Le repli ne prétend rien : ni zéro menace, ni zéro ban. Afficher « 0 banni »
    quand on n'a pas pu demander serait rassurer à tort — précisément ce qu'un
    tableau de sécurité ne doit jamais faire.
    """
    try:
        return waf_cardlet(sock, _get)
    except Exception:
        return {
            "id": "waf", "kind": "waf-posture", "status": "offline",
            "content": {"title": "WAF injoignable", "subtitle": "",
                        "station": "Pare-feu applicatif"},
            "metrics": [], "categorie": "", "silence": False,
        }
