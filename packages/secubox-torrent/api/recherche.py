# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: torrent — recherche d'index, côté serveur (#1032)

CyberMind — https://cybermind.fr

POURQUOI CÔTÉ SERVEUR, ET PAS DEPUIS LE NAVIGATEUR. Deux raisons, la seconde
étant la seule qui compte vraiment :

  1. CORS. Aucun indexeur n'autorise une page tierce à l'interroger.
  2. L'ADRESSE DU VISITEUR. Une requête émise par le navigateur expose son IP
     aux trackers. Émise par la box, elle ne l'expose pas. Sur une appliance
     dont c'est la promesse, la question ne se pose même pas.

CE MODULE NE TÉLÉCHARGE RIEN. Il interroge des index publics et rend des
adresses `magnet:`. Ce qu'on en fait ensuite relève de l'utilisateur et du
module de téléchargement, qui a ses propres règles de sortie réseau.
"""
from __future__ import annotations

import asyncio
import logging
import urllib.parse
from dataclasses import dataclass, field

import httpx

log = logging.getLogger("torrent.recherche")

# Traqueurs joints à chaque magnet. Sans eux, un client qui n'a ni DHT ni PEX
# ne trouve aucun pair et le téléchargement ne démarre jamais — le lien
# paraîtrait cassé alors qu'il est juste orphelin.
TRAQUEURS = (
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.stealth.si:80/announce",
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://exodus.desync.com:6969/announce",
)

# Un index qui traîne ne doit pas retenir toute la recherche : les sources sont
# interrogées en parallèle et chacune a son propre budget.
DELAI = 8.0

# Ce qu'on rend au plus. Au-delà, la page devient illisible et la charge utile
# grossit pour rien.
BORNE = 50


@dataclass
class Resultat:
    """Un résultat, normalisé — les sources ne parlent pas la même langue."""

    titre: str
    hash: str
    taille: int
    seeders: int
    leechers: int
    source: str
    magnet: str = field(default="")

    def __post_init__(self):
        if not self.magnet:
            self.magnet = fabrique_magnet(self.hash, self.titre)


def fabrique_magnet(info_hash: str, nom: str) -> str:
    """Construit l'adresse magnet depuis l'empreinte du torrent.

    LE HASH EST LA SEULE CHOSE QUI COMPTE ; `dn` n'est qu'un libellé d'agrément
    et les traqueurs sont un secours. C'est pourquoi on rend une chaîne vide
    plutôt qu'un magnet bancal quand le hash est absent ou mal formé : un lien
    qui ne mène à rien est pire qu'un lien absent, parce qu'on l'essaie.
    """
    h = (info_hash or "").strip().lower()
    if len(h) != 40 or any(c not in "0123456789abcdef" for c in h):
        return ""
    parts = [f"magnet:?xt=urn:btih:{h}"]
    if nom:
        parts.append("dn=" + urllib.parse.quote(nom[:200]))
    parts += ["tr=" + urllib.parse.quote(t) for t in TRAQUEURS]
    return "&".join(parts)


def _entier(v, defaut: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return defaut


async def cherche_apibay(client: httpx.AsyncClient, q: str) -> list[Resultat]:
    """The Pirate Bay, par son propre point d'entrée JSON."""
    r = await client.get("https://apibay.org/q.php",
                         params={"q": q, "cat": "0"}, timeout=DELAI)
    r.raise_for_status()
    out = []
    for e in r.json() or []:
        # APIBAY REND UNE LIGNE SENTINELLE quand il n'a rien : un faux résultat
        # nommé « No results returned », avec un hash de zéros. Le rendre tel
        # quel afficherait un torrent inexistant en tête de liste.
        if e.get("id") in ("0", 0) or e.get("name") == "No results returned":
            continue
        h = (e.get("info_hash") or "").lower()
        if not h or h == "0" * 40:
            continue
        out.append(Resultat(
            titre=e.get("name", "?"),
            hash=h,
            taille=_entier(e.get("size")),
            seeders=_entier(e.get("seeders")),
            leechers=_entier(e.get("leechers")),
            source="TPB",
        ))
    return out


# UNE SEULE SOURCE POUR L INSTANT, ET C EST DIT. YTS avait ete cable puis
# retire : `yts.mx` rend NXDOMAIN, y compris depuis un resolveur public — le
# domaine n existe plus, ce n est pas notre filtrage. Garder une source qui
# echoue a CHAQUE recherche apprend a l utilisateur a ignorer la ligne des
# echecs, et c est precisement la ligne qui doit rester credible le jour ou un
# index tombe vraiment.
SOURCES = {"tpb": cherche_apibay}


async def cherche(q: str, sources: list[str] | None = None) -> dict:
    """Interroge les index en parallèle et rend des résultats normalisés.

    UNE SOURCE QUI ÉCHOUE N'EMPORTE PAS LES AUTRES. Un index en panne est le
    cas ordinaire, pas l'exception : rendre une erreur globale priverait
    l'utilisateur des résultats que les autres ont bien rendus. Les échecs sont
    NOMMÉS dans la réponse — une liste courte sans explication laisserait croire
    que la recherche n'a rien trouvé.
    """
    q = (q or "").strip()
    if not q:
        return {"resultats": [], "sources_ok": [], "sources_ko": {},
                "detail": "requête vide"}

    choisies = [s for s in (sources or list(SOURCES)) if s in SOURCES]
    if not choisies:
        choisies = list(SOURCES)

    resultats: list[Resultat] = []
    ok: list[str] = []
    ko: dict[str, str] = {}

    # `User-Agent` explicite : se faire passer pour un navigateur serait mentir
    # sur ce qu'on est, et plusieurs index refusent un agent vide.
    entetes = {"User-Agent": "SecuBox/torrent-search (+https://secubox.in)"}
    async with httpx.AsyncClient(headers=entetes, follow_redirects=True) as c:
        taches = [SOURCES[s](c, q) for s in choisies]
        for nom, r in zip(choisies, await asyncio.gather(*taches,
                                                        return_exceptions=True)):
            if isinstance(r, Exception):
                log.warning("recherche %s : %s", nom, r)
                ko[nom] = type(r).__name__
            else:
                ok.append(nom)
                resultats += r

    # LES RÉSULTATS SANS MAGNET SONT ÉCARTÉS. C'est l'objet même de cette
    # recherche : une ligne sans adresse ne sert à rien et redonnerait
    # exactement le défaut qu'on corrige — un bouton qui ne mène nulle part.
    resultats = [r for r in resultats if r.magnet]
    resultats.sort(key=lambda r: r.seeders, reverse=True)

    return {
        "resultats": [vars(r) for r in resultats[:BORNE]],
        "total": len(resultats),
        "sources_ok": ok,
        "sources_ko": ko,
    }
