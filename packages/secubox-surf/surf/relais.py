# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Surf — le cœur du relais MITM
CyberMind — https://cybermind.fr

CE FICHIER EST UN POC, ET C'EST UNE MESURE AVANT D'ÊTRE UN PRODUIT.

L'objectif du §0bis (WIP) : relayer un site EXTERNE à travers la box, en
origine isolée, pour lui retirer son traçage — anti-censure, blocage des
pisteurs, faux témoins rejoués pour que le service distant croie ses publicités
affichées. Trois transports d'égress : DIRECT (la box sort déjà), TOR (le
`.onion` et l'anti-censure), et — plus tard — l'encapsulation du torrent dans
le même tunnel.

Ce module fait DEUX choses, et sépare soigneusement l'une de l'autre :

  1. Il RÉÉCRIT ce qui est réécrivable — les URL absolues d'un HTML ou d'un CSS,
     l'en-tête `Location`, le domaine d'un `Set-Cookie`. C'est mécanique et sûr.

  2. Il RECENSE ce qui ne l'est PAS — un `fetch()` construit en JavaScript, un
     import dynamique, un service worker, une WebSocket, un sous-ressource à
     intégrité vérifiée. C'est là qu'un proxy de surf échoue, et le POC existe
     pour chiffrer cet échec plutôt que de le découvrir en production.

LE PIÈGE STRUCTURANT, écrit une fois pour toutes : une origine unique est un
contexte de sécurité unique. Acceptable pour NOS services (WEBOS-DESIGN §4bis),
DANGEREUX pour du surf arbitraire — une page de Facebook relayée sous l'origine
du Hall lirait le stockage de Nextcloud. D'où la règle non négociable :
UNE ORIGINE PAR SITE. `origine_de()` la fabrique ; rien dans ce module ne la
contourne.
"""

from __future__ import annotations

import re
import base64
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit, urljoin

# ── L'ORIGINE PAR SITE ──────────────────────────────────────────────────────
#
# Le certificat de la box est `*.gk2.secubox.in` : il ne couvre qu'UN label.
# `fb.surf.gk2.secubox.in` ne serait donc pas couvert. On aplatit l'hôte cible
# en un SEUL label — `surf-www-facebook-com` — qui tient sous le wildcard et
# donne malgré tout une origine distincte par site. Isolation satisfaite sans
# nouveau certificat.
#
# L'aplatissement est RÉVERSIBLE et ne perd rien : le point devient `-`, le `-`
# d'origine est doublé, de sorte que `a-b.c` et `a.b-c` ne se confondent pas.

SUFFIXE = "gk2.secubox.in"
PREFIXE = "surf"


def origine_de(hote_cible: str) -> str:
    """`www.facebook.com` → `surf-www--facebook--com.gk2.secubox.in`."""
    plat = hote_cible.strip().lower().replace("-", "--").replace(".", "-")
    return f"{PREFIXE}-{plat}.{SUFFIXE}"


def cible_de(origine: str) -> str | None:
    """L'inverse : de l'origine du proxy, retrouver l'hôte réel."""
    h = origine.strip().lower()
    if not h.endswith("." + SUFFIXE):
        return None
    label = h[: -(len(SUFFIXE) + 1)]
    if not label.startswith(PREFIXE + "-"):
        return None
    plat = label[len(PREFIXE) + 1:]
    # On défait dans l'ordre inverse : d'abord les `--` en sentinelle, sinon un
    # `-` simple issu d'un point serait pris pour la moitié d'un `--`.
    jeton = "\x00"
    return plat.replace("--", jeton).replace("-", ".").replace(jeton, "-")


# ── LES PISTEURS — LA VRAIE RAISON D'ÊTRE ───────────────────────────────────
#
# Bloquer, ce n'est pas cloisonner (la distinction du 26/08). Cloisonner isole
# un témoin nécessaire dans son contexte ; bloquer SUPPRIME une requête qui
# n'existe que pour suivre. Ici on bloque — cette liste est ce dont on ne veut
# À AUCUN prix, même relayé.
PISTEURS = frozenset({
    "connect.facebook.net", "graph.facebook.com", "pixel.facebook.com",
    "an.facebook.com", "analytics.facebook.com",
    "google-analytics.com", "www.google-analytics.com", "ssl.google-analytics.com",
    "googletagmanager.com", "www.googletagmanager.com",
    "doubleclick.net", "stats.g.doubleclick.net", "adservice.google.com",
    "scorecardresearch.com", "sb.scorecardresearch.com",
    "hotjar.com", "static.hotjar.com", "amplitude.com", "api.amplitude.com",
    "segment.io", "cdn.segment.com", "sentry.io", "browser.sentry-cdn.com",
    "branch.io", "app.link", "criteo.com", "static.criteo.net",
})


def est_pisteur(hote: str) -> bool:
    h = (hote or "").lower()
    return any(h == p or h.endswith("." + p) for p in PISTEURS)


# ── LE RECENSEMENT DES CASSES ───────────────────────────────────────────────

@dataclass
class Casse:
    """Une chose qu'on n'a pas su relayer, et pourquoi elle compte."""
    genre: str          # 'js-fetch', 'service-worker', 'websocket', 'sri'…
    gravite: str        # 'bloquant' | 'degrade' | 'note'
    detail: str
    echantillon: str = ""


@dataclass
class Rapport:
    cible: str
    egress: str
    statut: int = 0
    type_contenu: str = ""
    reecrit: int = 0            # nombre d'URL réécrites avec succès
    casses: list[Casse] = field(default_factory=list)

    def note(self, genre, gravite, detail, echantillon=""):
        self.casses.append(Casse(genre, gravite, detail, echantillon[:200]))

    @property
    def verdict(self) -> str:
        if any(c.gravite == "bloquant" for c in self.casses):
            return "MUR — le site ne fonctionnera pas relayé tel quel"
        if any(c.gravite == "degrade" for c in self.casses):
            return "DÉGRADÉ — s'affiche, fonctionne en partie"
        return "PASSABLE — à confirmer à l'usage"


# ── LA RÉÉCRITURE DE CE QUI SE LAISSE RÉÉCRIRE ──────────────────────────────

# Attributs d'URL dans le HTML. `srcset` est traité à part (liste).
_ATTRS = ("href", "src", "action", "poster", "data-src", "data-href", "formaction")
_RE_ATTR = re.compile(
    r'(?P<a>%s)\s*=\s*(?P<q>["\'])(?P<v>[^"\']*)(?P=q)' % "|".join(_ATTRS),
    re.IGNORECASE)
_RE_SRCSET = re.compile(r'srcset\s*=\s*(["\'])(.*?)\1', re.IGNORECASE | re.DOTALL)
_RE_CSS_URL = re.compile(r'url\(\s*(["\']?)([^"\')]+)\1\s*\)', re.IGNORECASE)
_RE_INTEGRITY = re.compile(r'\s+integrity\s*=\s*(["\']).*?\1', re.IGNORECASE)

# Signaux qu'on ne peut PAS suivre statiquement — le nerf du POC.
_RE_JS_FETCH = re.compile(r'\bfetch\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
_RE_JS_XHR = re.compile(r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)', re.IGNORECASE)
_RE_JS_IMPORT = re.compile(r'\bimport\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
_RE_WS = re.compile(r'\bnew\s+WebSocket\s*\(\s*["\']([^"\']+)', re.IGNORECASE)
_RE_SW = re.compile(r'serviceWorker\s*\.\s*register\s*\(\s*["\']([^"\']+)', re.IGNORECASE)
_RE_WORKER = re.compile(r'\bnew\s+(?:Shared)?Worker\s*\(\s*["\']([^"\']+)', re.IGNORECASE)


def _map_url(u: str, base: str, sur_hote) -> tuple[str, bool]:
    """Réécrit UNE URL vers l'origine proxy. Rend (url, a_change).

    `sur_hote(hote)` est appelé pour chaque hôte tiers rencontré : il décide de
    l'origine à lui donner (une par site) et signale les pisteurs.
    """
    u = u.strip()
    if not u or u.startswith(("#", "data:", "blob:", "javascript:", "mailto:", "tel:", "about:")):
        return u, False
    absolu = urljoin(base, u)
    p = urlsplit(absolu)
    if p.scheme not in ("http", "https", ""):
        return u, False
    if not p.hostname:
        return u, False
    nouvelle_origine = sur_hote(p.hostname)
    if not nouvelle_origine:
        return u, False   # pisteur : on laisse tel quel, un filtre amont le coupe
    # Toujours https vers la box ; le chemin et la requête sont conservés.
    return urlunsplit(("https", nouvelle_origine, p.path, p.query, p.fragment)), True


def reecris_html(corps: str, base: str, rap: Rapport, sur_hote) -> str:
    """Réécrit les URL d'un HTML et RECENSE ce qu'il n'a pas su suivre."""
    # 1. Ce qui se réécrit : attributs, srcset, url() inline.
    def _attr(m):
        v, ch = _map_url(m.group("v"), base, sur_hote)
        if ch:
            rap.reecrit += 1
        return f'{m.group("a")}={m.group("q")}{v}{m.group("q")}'
    corps = _RE_ATTR.sub(_attr, corps)

    def _srcset(m):
        parts = []
        for bout in m.group(2).split(","):
            bout = bout.strip()
            if not bout:
                continue
            morceaux = bout.split(None, 1)
            v, ch = _map_url(morceaux[0], base, sur_hote)
            if ch:
                rap.reecrit += 1
            parts.append(v + (" " + morceaux[1] if len(morceaux) > 1 else ""))
        return 'srcset="%s"' % ", ".join(parts)
    corps = _RE_SRCSET.sub(_srcset, corps)

    def _css(m):
        v, ch = _map_url(m.group(2), base, sur_hote)
        if ch:
            rap.reecrit += 1
        return "url(%s%s%s)" % (m.group(1), v, m.group(1))
    corps = _RE_CSS_URL.sub(_css, corps)

    # 2. RÉÉCRIRE LE CORPS CASSE L'INTÉGRITÉ DES SOUS-RESSOURCES. Un attribut
    #    `integrity=` compare un hash ; nos réécritures le font échouer, et le
    #    navigateur REFUSE alors la ressource. On doit le retirer — ce qui
    #    signifie qu'on renonce à la garantie qu'il offrait. À noter, pas à
    #    cacher.
    n_sri = len(_RE_INTEGRITY.findall(corps))
    if n_sri:
        corps = _RE_INTEGRITY.sub("", corps)
        rap.note("sri", "note",
                 "%d sous-ressources à intégrité vérifiée : attribut retiré "
                 "(sinon le navigateur les refuse une fois le corps réécrit). "
                 "On perd la garantie d'intégrité qu'elles portaient." % n_sri)

    # 3. Ce qu'on ne peut PAS suivre. On ne modifie rien — on compte.
    _recense_js(corps, rap, ou="html-inline")
    return corps


def _recense_js(texte: str, rap: Rapport, ou: str):
    """Le cœur de la mesure : ce que la réécriture statique ne peut atteindre."""
    fetches = _RE_JS_FETCH.findall(texte) + _RE_JS_XHR.findall(texte)
    # Seuls les chemins RELATIFS ou ABSOLUS comptent : `fetch(variable)` nous
    # échappe déjà (aucune chaîne à trouver), et c'est le cas le plus fréquent.
    concrets = [u for u in fetches if u.startswith(("/", "http"))]
    if concrets:
        rap.note("js-fetch", "bloquant",
                 "%d appels réseau en dur dans le JS (%s) : ils visent l'origine "
                 "réelle, pas le proxy, et aucune réécriture statique ne les "
                 "détourne. Un `fetch(url)` où `url` est calculée échappe même "
                 "au comptage." % (len(concrets), ou),
                 " · ".join(concrets[:3]))
    imp = _RE_JS_IMPORT.findall(texte)
    if imp:
        rap.note("js-import", "bloquant",
                 "%d imports dynamiques : chargés à l'exécution vers l'origine "
                 "réelle, hors de portée d'une réécriture du HTML." % len(imp),
                 " · ".join(imp[:3]))
    ws = _RE_WS.findall(texte)
    if ws:
        rap.note("websocket", "bloquant",
                 "%d WebSocket : le temps réel (fil, présence, notifications) "
                 "ouvre vers l'origine réelle. À relayer, il faut un proxy WS "
                 "dédié, origine par origine." % len(ws),
                 " · ".join(ws[:3]))
    sw = _RE_SW.findall(texte)
    if sw:
        rap.note("service-worker", "bloquant",
                 "%d service worker : il s'installe sur NOTRE origine et y "
                 "intercepte TOUT le réseau ensuite — y compris ce qu'on croyait "
                 "maîtriser. À neutraliser explicitement, jamais à laisser "
                 "passer." % len(sw),
                 " · ".join(sw[:3]))
    wk = _RE_WORKER.findall(texte)
    if wk:
        rap.note("worker", "degrade",
                 "%d web worker : script chargé à part, à réécrire aussi sinon "
                 "il sort du cadre." % len(wk), " · ".join(wk[:3]))


def reecris_css(corps: str, base: str, rap: Rapport, sur_hote) -> str:
    def _css(m):
        v, ch = _map_url(m.group(2), base, sur_hote)
        if ch:
            rap.reecrit += 1
        return "url(%s%s%s)" % (m.group(1), v, m.group(1))
    return _RE_CSS_URL.sub(_css, corps)


# ── LES EN-TÊTES ────────────────────────────────────────────────────────────

def reecris_entetes(entetes: dict, base: str, rap: Rapport, sur_hote) -> dict:
    """Réécrit ou retire les en-têtes qui trahiraient l'origine réelle."""
    out = {}
    for cle, val in entetes.items():
        bas = cle.lower()

        if bas == "location":
            v, _ = _map_url(val, base, sur_hote)
            out[cle] = v
            continue

        if bas == "set-cookie":
            # Le témoin doit être posé sur NOTRE origine, pas sur `.facebook.com`
            # (qui ne serait jamais renvoyé). On retire `Domain`, et `Secure`
            # reste — on est en https.
            v = re.sub(r';\s*[Dd]omain=[^;]+', '', val)
            out[cle] = v
            rap.note("set-cookie", "note",
                     "témoin réécrit : `Domain` retiré pour qu'il tienne sur "
                     "l'origine proxy. C'est ici que se brancherait le rejeu de "
                     "session (le « catcher »).")
            continue

        if bas == "content-security-policy":
            # La CSP du site nomme SES origines ; sous la nôtre, elle bloque
            # tout. On la retire pour le POC, en notant ce qu'elle exigeait —
            # une vraie version la RÉÉCRIRAIT origine par origine.
            rap.note("csp", "degrade",
                     "CSP du site retirée pour le POC. Elle listait ses propres "
                     "origines et aurait tout bloqué sous la nôtre ; la réécrire "
                     "proprement est un chantier à part.", val)
            continue

        if bas in ("x-frame-options", "content-security-policy-report-only",
                   "cross-origin-opener-policy", "cross-origin-embedder-policy",
                   "strict-transport-security"):
            # Retirés : ils empêchent l'encadrement ou imposent des règles
            # d'isolation incompatibles avec le relais.
            continue

        if bas in ("content-length", "content-encoding", "transfer-encoding",
                   "connection"):
            continue  # recalculés par le serveur du proxy

        out[cle] = val
    return out
