# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Surf — le rendu headless (la copie carbone)
CyberMind — https://cybermind.fr

CERTAINS SITES NE SE RENDENT PAS EN LEGER (#1218/#1221/#1235). BFM/Altice rend
son article APRES un ballet de consentement (Didomi + first-id) qui, dans le
contexte TIERS de l'overlay du Hall (storage partitionne, sandbox), n'aboutit
pas : ecran noir. Or le meme relais, rendu en TOP-LEVEL par un vrai navigateur,
materialise l'article proprement.

L'IDEE (Gandalf) : « traiter le HTML du headless pour l'afficher apres rejeu ».
On rend l'origine surf avec Chromium headless (qui execute le JS, passe le
consentement, coupe les pisteurs comme d'habitude), on CAPTURE le DOM abouti,
on le FIGE (scripts retires) et on le sert STATIQUE. Le navigateur de
l'utilisateur n'a plus de ballet a jouer : il affiche une copie carbone.

C'est la phase LOURDE de la machine a etats (#1218) : couteuse mais ponctuelle,
mise en cache. La phase LEGERE (relais direct) reste le defaut.
"""

from __future__ import annotations

import hashlib
import subprocess
import threading
import time
from pathlib import Path

CHROMIUM = "/usr/bin/chromium"
_CACHE = Path("/var/lib/secubox/surf/rendu")
_TTL = 300.0          # une copie carbone vaut 5 min — l'actu bouge, pas l'article
_VERROU = threading.Lock()

# UA distinctif : la requete que le headless envoie au relais NE DOIT PAS
# re-declencher un rendu headless (sinon recursion infinie). serveur.py detecte
# ce marqueur et force la voie legere.
MARQUEUR_UA = "SBXHeadless"
_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 "
       "Firefox/128.0 " + MARQUEUR_UA)


# ── CE QUE LE RENDU A VU PASSER (#1323) ─────────────────────────────────────
#
# La copie carbone retire TOUT le JS. Le lecteur video de la page ne tourne
# donc plus, et le `<video>` qu'il avait construit reste avec un `blob:` —
# le handle MediaSource d'un Chromium qui n'existe plus. Servi tel quel, il
# ne designe rien : la page s'affiche, le media ne joue pas.
#
# Pour le rendre jouable, il faut l'URL VRAIE du media. On ne la DEVINE pas :
# le Chromium du rendu l'a DEMANDEE, et il l'a demandee AU RELAIS (l'injection
# de tete rabat fetch/XHR/`<video>.src` vers l'origine surf). Le relais n'a
# donc qu'a noter ce qu'il sert au rendu en cours. Pas de CDP, pas de
# websocket, pas de dependance : on lit ce qui passe deja.
#
# Le verrou de `rends` serialise les Chromium — UN SEUL rendu a la fois sur
# cette carte. Cette ardoise peut donc etre un emplacement global : il n'y a
# jamais deux rendus a melanger.
_MAX_ARDOISE = 8
_ardoise: list[str] = []
_ouverte = False


def observe(url_media: str) -> None:
    """Le relais signale un media servi AU RENDU en cours (no-op sinon)."""
    if not _ouverte or url_media in _ardoise:
        return
    if len(_ardoise) < _MAX_ARDOISE:
        _ardoise.append(url_media)


def _manifeste(u: str) -> bool:
    return ".m3u8" in u.lower() or ".mpd" in u.lower()


def _classe(medias: list[str]) -> list[str]:
    """Manifestes d'abord : une piste HLS bat un fichier isole, car c'est elle
    qui porte toutes les qualites. L'ordre d'arrivee departage le reste."""
    return [u for u in medias if _manifeste(u)] + [u for u in medias if not _manifeste(u)]


def disponible() -> bool:
    return Path(CHROMIUM).exists()


def _cle(url: str) -> Path:
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]
    return _CACHE / (h + ".html")


def _du_cache(url: str) -> tuple[str, list[str]] | None:
    f = _cle(url)
    try:
        if f.exists() and (time.time() - f.stat().st_mtime) < _TTL:
            dom = f.read_text(encoding="utf-8", errors="replace")
            # LES MEDIAS SE CACHENT AVEC LE DOM. Sans ce compagnon, un rendu
            # relu du cache rendrait une page dont le lecteur est de nouveau
            # muet : le DOM survivrait, l'observation non — et le media ne
            # jouerait qu'une fois sur N, au hasard du TTL.
            g = f.with_suffix(".media")
            medias = g.read_text(encoding="utf-8").split("\n") if g.exists() else []
            return dom, [u for u in medias if u]
    except OSError:
        pass
    return None


def _au_cache(url: str, html: str, medias: list[str]) -> None:
    try:
        _CACHE.mkdir(parents=True, exist_ok=True)
        f = _cle(url)
        tmp = f.with_suffix(".tmp")
        tmp.write_text(html, encoding="utf-8")
        tmp.replace(f)
        g = f.with_suffix(".media")
        gtmp = g.with_suffix(".media.tmp")
        gtmp.write_text("\n".join(medias), encoding="utf-8")
        gtmp.replace(g)
    except OSError:
        pass


def rends(url: str, budget_ms: int = 9000,
          timeout: float = 90.0) -> tuple[str, list[str]] | None:
    """Le DOM abouti d'une URL (origine surf) ET les medias qu'il a charges.

    Renvoie None si l'outil manque, si le rendu echoue, ou s'il est trop maigre.
    Mise en cache par URL (TTL court) : le rendu est lourd, on ne le refait pas
    a chaque requete. Un verrou global serialise les rendus — un seul Chromium a
    la fois, c'est le garde-fou de cout sur une petite carte arm64, et c'est
    aussi ce qui rend l'ardoise des medias sans ambiguite.
    """
    global _ouverte
    if not disponible():
        return None
    cache = _du_cache(url)
    if cache is not None:
        return cache
    with _VERROU:
        # Deux requetes concurrentes sur la meme URL : la seconde relit le cache
        # que la premiere vient d'ecrire.
        cache = _du_cache(url)
        if cache is not None:
            return cache
        _ardoise.clear()
        _ouverte = True
        try:
            p = subprocess.run(
                [CHROMIUM, "--headless=new", "--no-sandbox", "--disable-gpu",
                 "--disable-dev-shm-usage", "--ignore-certificate-errors",
                 "--hide-scrollbars", "--user-agent=" + _UA,
                 # Sous le sandbox systemd (ProtectSystem=strict, PrivateTmp),
                 # seul /tmp est inscriptible : Chromium y pose son profil.
                 "--user-data-dir=/tmp/sbx-chromium",
                 "--disable-crash-reporter", "--no-first-run",
                 # On veut le DOM, pas les pixels : couper images/polices
                 # distantes accelere fortement le chargement (les `src`/`href`
                 # restent dans le DOM, c'est tout ce qu'on capture). Cle sur
                 # arm64 ou chaque sous-ressource relayee coute.
                 "--blink-settings=imagesEnabled=false",
                 "--disable-remote-fonts",
                 # ON NE COUPE PAS LE SON. Chromium bloque la lecture auto sans
                 # geste : le lecteur n'irait alors JAMAIS chercher son
                 # manifeste, et l'ardoise resterait vide. On l'autorise pour
                 # que le media se declare — personne n'ecoute ce Chromium.
                 "--autoplay-policy=no-user-gesture-required",
                 "--virtual-time-budget=%d" % budget_ms, "--dump-dom", url],
                capture_output=True, text=True, timeout=timeout)
            dom = p.stdout or ""
        except (subprocess.TimeoutExpired, OSError):
            return None
        finally:
            _ouverte = False
        if len(dom) < 500:
            return None
        # LA COPIE DOIT ÊTRE CELLE DE LA PAGE DEMANDÉE.
        #
        # Le site peut naviguer AILLEURS pendant le rendu : portail de
        # consentement (first-id), mur anti-robot, redirection marketing. La
        # box bloque ces destinations, Chromium affiche sa page d'erreur, et
        # c'est ELLE que `--dump-dom` rendait — mise en cache cinq minutes sous
        # le nom de l'article. Le visiteur recevait alors `gate.first-id.fr`
        # au lieu de son journal, et une relance n'y changeait rien avant
        # expiration.
        #
        # Le contrôle est simple parce que la réécriture nous le donne : un
        # rendu de NOTRE origine en est truffé (chaque lien, chaque image, y a
        # été rabattu). Zéro occurrence, c'est qu'on regarde une autre page.
        # Dans le doute on rend None : l'appelant sert la voie légère figée,
        # qui est lisible — une copie fausse, elle, ne l'est jamais.
        hote = url.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
        if hote and hote not in dom:
            return None
        medias = _classe(list(_ardoise))
        _au_cache(url, dom, medias)
        return dom, medias
