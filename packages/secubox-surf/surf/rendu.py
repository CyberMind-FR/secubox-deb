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


def disponible() -> bool:
    return Path(CHROMIUM).exists()


def _cle(url: str) -> Path:
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]
    return _CACHE / (h + ".html")


def _du_cache(url: str) -> str | None:
    f = _cle(url)
    try:
        if f.exists() and (time.time() - f.stat().st_mtime) < _TTL:
            return f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return None


def _au_cache(url: str, html: str) -> None:
    try:
        _CACHE.mkdir(parents=True, exist_ok=True)
        f = _cle(url)
        tmp = f.with_suffix(".tmp")
        tmp.write_text(html, encoding="utf-8")
        tmp.replace(f)
    except OSError:
        pass


def rends(url: str, budget_ms: int = 9000, timeout: float = 90.0) -> str | None:
    """Le DOM abouti d'une URL (origine surf), via Chromium headless.

    Renvoie None si l'outil manque, si le rendu echoue, ou s'il est trop maigre.
    Mise en cache par URL (TTL court) : le rendu est lourd, on ne le refait pas
    a chaque requete. Un verrou global serialise les rendus — un seul Chromium a
    la fois, c'est le garde-fou de cout sur une petite carte arm64.
    """
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
                 "--virtual-time-budget=%d" % budget_ms, "--dump-dom", url],
                capture_output=True, text=True, timeout=timeout)
            dom = p.stdout or ""
        except (subprocess.TimeoutExpired, OSError):
            return None
        if len(dom) < 500:
            return None
        _au_cache(url, dom)
        return dom
