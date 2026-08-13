# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: torrent — indexeurs Usenet (Newznab) (#1032)

CyberMind — https://cybermind.fr

POURQUOI CE VOLET EST CONFIGURÉ ET NON CÂBLÉ EN DUR. Les index Usenet ne
répondent qu'à une clé d'API nominative : il n'existe aucun équivalent d'un
`apibay.org` ouvert. Un onglet NZB « qui marche tout seul » est donc impossible
— et c'est précisément pour masquer cette impossibilité que l'ancienne page
fabriquait sept résultats avec `Math.random()`.

CE QU'ON FAIT À LA PLACE : le protocole est implémenté pour de bon, et tant
qu'aucune clé n'est déposée, l'interface le DIT. Une page qui annonce
« aucun indexeur configuré » est utile ; une page qui invente des résultats
vraisemblables ne l'est jamais.

LES CLÉS NE SONT PAS DANS CE FICHIER NI DANS UN TOML VERSIONNÉ. Elles vivent
dans `/etc/secubox/secrets/torrent-nzb.toml`, chmod 600, propriété du service —
et ne ressortent jamais dans une réponse ni dans un journal.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import httpx

try:
    import tomllib
except ModuleNotFoundError:  # bookworm : python3.11 a tomllib, on reste prudent
    tomllib = None  # type: ignore

log = logging.getLogger("torrent.nzb")

CONFIG = Path("/etc/secubox/secrets/torrent-nzb.toml")
DELAI = 10.0
BORNE = 60
OCTETS_MAX = 4 << 20


def charge_indexeurs(chemin: Path | None = None) -> list[dict]:
    """Lit les indexeurs déclarés. NE LÈVE JAMAIS.

    Un fichier absent est le cas NORMAL — personne n'a encore de clé — et non
    une panne : il rend une liste vide, que l'appelant sait présenter.
    """
    p = chemin or CONFIG
    if tomllib is None or not p.exists():
        return []
    try:
        d = tomllib.loads(p.read_text())
    except (OSError, ValueError) as e:
        # ON NE JOURNALISE PAS LE CONTENU : le fichier ne contient que des clés.
        log.error("indexeurs NZB illisibles (%s) : %s", p, type(e).__name__)
        return []

    out = []
    for e in d.get("indexeur") or []:
        url, cle = (e.get("url") or "").strip(), (e.get("cle") or "").strip()
        if not url or not cle:
            log.warning("indexeur NZB ignoré : url ou clé manquante")
            continue
        out.append({"id": (e.get("id") or url)[:40],
                    "libelle": e.get("libelle") or e.get("id") or url,
                    "url": url, "cle": cle})
    return out


def indexeurs_publics(indexeurs: list[dict]) -> list[dict]:
    """Ce qu'on peut montrer : tout sauf la clé."""
    return [{"id": i["id"], "libelle": i["libelle"]} for i in indexeurs]


def _attributs(item: dict) -> dict:
    """Newznab range l'essentiel dans une liste d'attributs nommés."""
    out = {}
    a = item.get("attr") or item.get("newznab:attr") or []
    if isinstance(a, dict):
        a = [a]
    for x in a:
        d = x.get("@attributes") or x
        n, v = d.get("name"), d.get("value")
        if n is not None:
            out[n] = v
    return out


async def _interroge(client: httpx.AsyncClient, ix: dict, q: str) -> list[dict]:
    params = {"t": "search", "q": q, "o": "json", "limit": 50,
              "apikey": ix["cle"]}
    async with client.stream("GET", ix["url"], params=params,
                             timeout=DELAI) as r:
        r.raise_for_status()
        morceaux, total = [], 0
        async for m in r.aiter_bytes():
            morceaux.append(m)
            total += len(m)
            if total > OCTETS_MAX:
                raise ValueError("réponse trop longue")
    import json
    d = json.loads(b"".join(morceaux))

    items = ((d or {}).get("channel") or {}).get("item") or []
    if isinstance(items, dict):
        items = [items]
    out = []
    for it in items:
        at = _attributs(it)
        try:
            taille = int(at.get("size") or it.get("size") or 0)
        except (TypeError, ValueError):
            taille = 0
        out.append({
            "titre": it.get("title") or "?",
            "taille": taille,
            "date": it.get("pubDate") or "",
            "groupes": at.get("group") or "",
            "indexeur": ix["libelle"],
            # LE LIEN PORTE LA CLÉ : c'est le protocole Newznab. Il n'est donc
            # PAS rendu au navigateur — le téléchargement passera par la box.
            "id": at.get("guid") or it.get("guid") or "",
        })
    return out


async def cherche(q: str, chemin: Path | None = None) -> dict:
    """Interroge les indexeurs configurés, en parallèle.

    Même règle que côté torrent : un indexeur en panne n'emporte pas les
    autres, et les échecs sont nommés.
    """
    q = (q or "").strip()
    indexeurs = charge_indexeurs(chemin)
    if not indexeurs:
        # LE MESSAGE EST LA FONCTIONNALITÉ. C'est ce qui remplace les faux
        # résultats : on dit quoi faire, pas seulement que c'est vide.
        return {"resultats": [], "total": 0, "indexeurs": [],
                "configure": False,
                "detail": "Aucun indexeur Usenet configuré. Déposez vos clés "
                          "dans /etc/secubox/secrets/torrent-nzb.toml"}
    if not q:
        return {"resultats": [], "total": 0,
                "indexeurs": indexeurs_publics(indexeurs), "configure": True,
                "detail": "requête vide"}

    ok, ko, res = [], {}, []
    entetes = {"User-Agent": "SecuBox/torrent-search (+https://secubox.in)"}
    async with httpx.AsyncClient(headers=entetes, follow_redirects=True) as c:
        taches = [_interroge(c, ix, q) for ix in indexeurs]
        for ix, r in zip(indexeurs, await asyncio.gather(*taches,
                                                        return_exceptions=True)):
            if isinstance(r, Exception):
                # LE JOURNAL NE PORTE NI L'URL COMPLÈTE NI LA CLÉ.
                log.warning("indexeur %s : %s", ix["id"], type(r).__name__)
                ko[ix["id"]] = type(r).__name__
            else:
                ok.append(ix["id"])
                res += r

    res.sort(key=lambda x: x.get("taille", 0), reverse=True)
    return {"resultats": res[:BORNE], "total": len(res),
            "indexeurs": indexeurs_publics(indexeurs), "configure": True,
            "sources_ok": ok, "sources_ko": ko}
