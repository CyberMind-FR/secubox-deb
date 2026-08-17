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

LE REGISTRE `SOURCES` EST LA SEULE VÉRITÉ. L'interface le lit par `/sources` au
lieu de tenir sa propre liste : une page qui affiche des pastilles écrites en
dur finit toujours par proposer des index qu'on n'interroge plus — c'était
exactement le cas ici, où sept sources étaient affichées et zéro interrogée.
"""
from __future__ import annotations

import asyncio
import logging
import urllib.parse
import xml.etree.ElementTree as ET
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
BORNE = 60

# Plafond de lecture par source. UNE RÉPONSE N'EST PAS UNE PROMESSE : un index
# hostile ou en panne peut répondre indéfiniment, et `xml.etree` se laisse
# épuiser par une entité récursive. On borne AVANT d'analyser.
OCTETS_MAX = 4 << 20


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


async def _corps(client: httpx.AsyncClient, methode: str, url: str, **kw) -> bytes:
    """Lit une réponse en la BORNANT. Voir OCTETS_MAX."""
    async with client.stream(methode, url, timeout=DELAI, **kw) as r:
        r.raise_for_status()
        morceaux, total = [], 0
        async for m in r.aiter_bytes():
            morceaux.append(m)
            total += len(m)
            if total > OCTETS_MAX:
                raise ValueError("réponse trop longue")
        return b"".join(morceaux)


# --------------------------------------------------------------------------
# Les sources. Chacune traduit SA forme vers `Resultat` — et rien d'autre :
# le tri, la déduplication et les bornes sont l'affaire de `cherche()`.
# --------------------------------------------------------------------------

async def cherche_apibay(client: httpx.AsyncClient, q: str) -> list[Resultat]:
    """The Pirate Bay, par son propre point d'entrée JSON."""
    import json
    b = await _corps(client, "GET", "https://apibay.org/q.php",
                     params={"q": q, "cat": "0"})
    out = []
    for e in json.loads(b) or []:
        # APIBAY REND UNE LIGNE SENTINELLE quand il n'a rien : un faux résultat
        # nommé « No results returned », avec un hash de zéros. Le rendre tel
        # quel afficherait un torrent inexistant en tête de liste.
        if e.get("id") in ("0", 0) or e.get("name") == "No results returned":
            continue
        h = (e.get("info_hash") or "").lower()
        if not h or h == "0" * 40:
            continue
        out.append(Resultat(titre=e.get("name", "?"), hash=h,
                            taille=_entier(e.get("size")),
                            seeders=_entier(e.get("seeders")),
                            leechers=_entier(e.get("leechers")),
                            source="TPB"))
    return out


async def cherche_torrents_csv(client: httpx.AsyncClient, q: str) -> list[Resultat]:
    """Torrents-CSV, un index ouvert et volontairement minimal."""
    import json
    b = await _corps(client, "GET", "https://torrents-csv.com/service/search",
                     params={"q": q, "size": 50})
    out = []
    for e in (json.loads(b) or {}).get("torrents") or []:
        h = (e.get("infohash") or "").lower()
        if not h:
            continue
        out.append(Resultat(titre=e.get("name") or "?", hash=h,
                            taille=_entier(e.get("size_bytes")),
                            seeders=_entier(e.get("seeders")),
                            leechers=_entier(e.get("leechers")),
                            source="Torrents-CSV"))
    return out


_NS_NYAA = "{https://nyaa.si/xmlns/nyaa}"


async def cherche_nyaa(client: httpx.AsyncClient, q: str) -> list[Resultat]:
    """Nyaa, par son flux RSS — il n'expose pas d'autre interface."""
    b = await _corps(client, "GET", "https://nyaa.si/",
                     params={"page": "rss", "q": q})
    # ON REFUSE TOUTE DÉCLARATION DE TYPE DE DOCUMENT. `xml.etree` se laisse
    # épuiser par une entité récursive ; le flux légitime n'en a aucune, donc
    # refuser ne coûte rien et ferme la porte sans dépendre d'une bibliothèque
    # supplémentaire.
    if b"<!DOCTYPE" in b[:2048]:
        raise ValueError("DOCTYPE refusé")
    racine = ET.fromstring(b.decode("utf-8", "replace"))
    out = []
    for it in racine.iter("item"):
        h = (it.findtext(_NS_NYAA + "infoHash") or "").lower()
        if not h:
            continue
        out.append(Resultat(titre=it.findtext("title") or "?", hash=h,
                            taille=0,  # Nyaa ne rend la taille qu'en texte.
                            seeders=_entier(it.findtext(_NS_NYAA + "seeders")),
                            leechers=_entier(it.findtext(_NS_NYAA + "leechers")),
                            source="Nyaa"))
    return out


# LE REGISTRE. `id` est ce que l'interface renvoie, `libelle` ce qu'elle
# affiche : une pastille ne peut plus désigner un index qui n'existe pas ici.
SOURCES = {
    "tpb":     {"libelle": "The Pirate Bay", "fn": cherche_apibay},
    "tcsv":    {"libelle": "Torrents-CSV",   "fn": cherche_torrents_csv},
    "nyaa":    {"libelle": "Nyaa",           "fn": cherche_nyaa},
}


def liste_sources() -> list[dict]:
    return [{"id": i, "libelle": s["libelle"]} for i, s in SOURCES.items()]


def pertinent(titre: str, q: str) -> bool:
    """Le titre porte-t-il au moins un terme cherché ?

    POURQUOI CETTE GARDE EXISTE. Knaben avait été câblée puis retirée : elle
    rendait, pour TOUTE requête, le dernier contenu indexé — de la pornographie
    en tête de liste pour une recherche « debian ». Aucun de ses modes
    (`score`, `100%`, `50%`) ne filtrait quoi que ce soit.

    LA LECON PORTE PLUS LOIN QUE CETTE SOURCE-LA. Un index qui cesse d'honorer
    la requête ne tombe pas en panne : il répond 200, vite, avec des résultats
    parfaitement formés. Rien dans la mécanique ne le distingue d'un succès —
    seul le contenu le trahit. La garde est donc posée sur TOUTES les sources,
    y compris celles qui se comportent bien aujourd'hui.

    Elle reste volontairement lâche : un seul terme suffit, la casse et les
    séparateurs sont ignorés. Exiger tous les termes écarterait
    `ubuntu-24.04-desktop` pour la recherche « ubuntu 24 ».
    """
    termes = [t for t in "".join(c if c.isalnum() else " "
                                 for c in q.lower()).split() if len(t) >= 3]
    if not termes:
        # Une requête sans terme exploitable ne permet aucun jugement : on ne
        # va pas écarter des résultats sur une base qu'on n'a pas.
        return True
    plat = "".join(c if c.isalnum() else " " for c in titre.lower())
    return any(t in plat for t in termes)


def dedoublonne(res: list[Resultat]) -> list[Resultat]:
    """Un même torrent rendu par plusieurs index n'apparaît qu'une fois.

    LA DÉDUPLICATION SE FAIT SUR L'EMPREINTE, jamais sur le titre : deux index
    nomment rarement un fichier pareil, et Knaben agrège justement des index
    qu'on interroge aussi en direct — sans cela, la moitié de la liste serait
    des doublons.

    ON GARDE L'EXEMPLAIRE LE MIEUX POURVU EN SEEDERS, et on note les autres
    sources : l'information « trois index le connaissent » vaut mieux que trois
    lignes identiques.
    """
    par_hash: dict[str, Resultat] = {}
    for r in res:
        vu = par_hash.get(r.hash)
        if vu is None:
            par_hash[r.hash] = r
            continue
        if r.source not in vu.source.split(", "):
            vu.source = f"{vu.source}, {r.source}"
        if r.seeders > vu.seeders:
            vu.seeders, vu.leechers = r.seeders, r.leechers
        if r.taille and not vu.taille:
            vu.taille = r.taille
    return list(par_hash.values())


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
        return {"resultats": [], "total": 0, "sources_ok": [], "sources_ko": {},
                "detail": "requête vide"}

    # UNE SÉLECTION VIDE N'EST PAS UNE SÉLECTION DE TOUT. `sources or
    # list(SOURCES)` faisait exactement l'inverse : une liste vide étant fausse,
    # décocher toutes les pastilles rendait TOUS les index — le geste de
    # l'utilisateur annulé en silence, c'est-à-dire le défaut même qu'on répare.
    # `None` (pas de préférence) et `[]` (tout décoché) sont deux choses.
    if sources is None:
        choisies = list(SOURCES)
    else:
        choisies = [s for s in sources if s in SOURCES]
        if not choisies:
            return {"resultats": [], "total": 0, "sources_ok": [],
                    "sources_ko": {}, "detail": "aucune source sélectionnée"}

    resultats: list[Resultat] = []
    ok: list[str] = []
    ko: dict[str, str] = {}

    # `User-Agent` explicite : se faire passer pour un navigateur serait mentir
    # sur ce qu'on est, et plusieurs index refusent un agent vide.
    entetes = {"User-Agent": "SecuBox/torrent-search (+https://secubox.in)"}
    async with httpx.AsyncClient(headers=entetes, follow_redirects=True) as c:
        taches = [SOURCES[s]["fn"](c, q) for s in choisies]
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
    resultats = dedoublonne([r for r in resultats
                             if r.magnet and pertinent(r.titre, q)])
    resultats.sort(key=lambda r: r.seeders, reverse=True)

    return {
        "resultats": [vars(r) for r in resultats[:BORNE]],
        "total": len(resultats),
        "sources_ok": ok,
        "sources_ko": ko,
    }
