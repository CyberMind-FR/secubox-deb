# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-ytsas :: flux du compte YouTube
CyberMind — https://cybermind.fr

Lit, AVEC LES COOKIES DU COFFRE, les listes que YouTube tient pour le compte : « à regarder plus tard », propositions
d'accueil, abonnements, historique. LECTURE SEULE : une seule requête de métadonnées à plat (`--flat-playlist`), rien n'est
téléchargé, rien n'est modifié dans le compte.

 · SANS COOKIES, ON REFUSE (AuthRequise) : ces listes sont celles d'une personne, jamais publiques.
 · UN APPEL À LA FOIS PAR FLUX, mis en cache le temps du TTL : l'accueil de YouTube ne change pas à la seconde, et la
   board est contrainte.
 · SI YOUTUBE REFUSE OU LIMITE, on rend le DERNIER résultat, signalé `perime` ; sans ancien résultat, l'erreur remonte.
 · LES VIGNETTES PASSENT PAR LA BOX (`/flux/vignette/<id>`) : le navigateur ne contacte pas Google à chaque affichage.
   L'hôte source est restreint à ytimg / ggpht.
"""

import asyncio
import json
import os
import re
import time
import urllib.request

TYPES = {
    "envie": ":ytwatchlater",
    "propositions": ":ytrec",
    "abonnements": ":ytsubs",
    "historique": ":ythistory",
}
LIMITE_DEFAUT = 24
LIMITE_MAX = 60
DELAI_YTDLP_S = 90

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
_HOTES_VIGNETTES = ("i.ytimg.com", "i1.ytimg.com", "i2.ytimg.com", "i3.ytimg.com", "yt3.ggpht.com")


class AuthRequise(Exception):
    """Pas de cookies : les listes d'un compte ne se lisent pas sans lui."""


class ErreurYoutube(Exception):
    """yt-dlp ou YouTube a refusé / limité / répondu à côté."""


def borne(limite):
    try:
        n = int(limite)
    except (TypeError, ValueError):
        return LIMITE_DEFAUT
    return max(1, min(n, LIMITE_MAX))


def id_valide(vid):
    return bool(isinstance(vid, str) and _ID_RE.match(vid))


def commande(ytdlp_bin, type_, limite, cookie_path):
    return [ytdlp_bin, "--flat-playlist", "--dump-json", "--playlist-end", str(borne(limite)), "--no-warnings",
            "--cookies", cookie_path, TYPES[type_]]


def _hote_ok(url):
    m = re.match(r"^https://([^/]+)/", url or "")
    return bool(m and m.group(1) in _HOTES_VIGNETTES)


def vignette_source(d):
    """Plus grande miniature fournie par yt-dlp, sinon le repli standard ; jamais un hôte hors ytimg / ggpht."""
    vid = d.get("id")
    meilleures = [t for t in (d.get("thumbnails") or []) if isinstance(t, dict) and _hote_ok(t.get("url"))]
    if meilleures:
        return max(meilleures, key=lambda t: t.get("width") or 0)["url"]
    return f"https://i.ytimg.com/vi/{vid}/mqdefault.jpg"


def analyser(sortie):
    items = []
    for ligne in (sortie or "").splitlines():
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            d = json.loads(ligne)
        except ValueError:
            continue
        vid = d.get("id")
        if not id_valide(vid):
            continue
        items.append({
            "id": vid,
            "titre": d.get("title") or "",
            "chaine": d.get("channel") or d.get("uploader") or "",
            "duree": d.get("duration"),
            "url": "https://www.youtube.com/watch?v=" + vid,
            "vignette": "/api/v1/ytsas/flux/vignette/" + vid,
            "_source": vignette_source(d),
        })
    return items


async def executer_ytdlp(argv):
    """Exécuteur réel : yt-dlp en sous-processus asynchrone, jamais bloquant."""
    try:
        proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=DELAI_YTDLP_S)
    except asyncio.TimeoutError:
        raise ErreurYoutube("délai dépassé")
    except FileNotFoundError:
        raise ErreurYoutube("yt-dlp introuvable dans le conteneur")
    texte = out.decode("utf-8", "replace")
    if not texte.strip():
        detail = (err.decode("utf-8", "replace").strip().splitlines() or ["flux vide"])[-1][:200]
        raise ErreurYoutube(detail)
    return texte


class Flux:
    def __init__(self, dossier, cookie_path, executeur=executer_ytdlp, ttl=900, horloge=time.time, ytdlp_bin="yt-dlp"):
        self.dossier = os.path.join(dossier, ".flux")
        self.cookie_path = cookie_path
        self.executeur = executeur
        self.ttl = ttl
        self.horloge = horloge
        self.ytdlp_bin = ytdlp_bin
        self._verrous = {}
        self._sources = {}   # id -> URL de vignette, apprise lors d'un listage

    def _verrou(self, type_):
        if type_ not in self._verrous:
            self._verrous[type_] = asyncio.Lock()
        return self._verrous[type_]

    def _fichier(self, type_):
        return os.path.join(self.dossier, f"{type_}.json")

    def _lire(self, type_):
        try:
            with open(self._fichier(type_), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _ecrire(self, type_, doc):
        os.makedirs(self.dossier, mode=0o700, exist_ok=True)
        tmp = self._fichier(type_) + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(doc, ensure_ascii=False).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, self._fichier(type_))

    def _public(self, items):
        return [{k: v for k, v in i.items() if not k.startswith("_")} for i in items]

    async def lister(self, type_, limite=LIMITE_DEFAUT):
        if type_ not in TYPES:
            raise ValueError("type de flux inconnu")
        if not self.cookie_path:
            raise AuthRequise("auth requise — dépose tes cookies")
        limite = borne(limite)
        async with self._verrou(type_):
            maintenant = self.horloge()
            ancien = self._lire(type_)
            if ancien and ancien.get("limite", 0) >= limite and maintenant - ancien.get("date", 0) < self.ttl:
                self._retenir(ancien["items"])
                return {"type": type_, "items": self._public(ancien["items"])[:limite], "en_cache": True,
                        "perime": False, "date": int(ancien["date"])}
            try:
                sortie = await self.executeur(commande(self.ytdlp_bin, type_, limite, self.cookie_path))
                items = analyser(sortie)
                if not items:
                    raise ErreurYoutube("flux vide ou illisible")
            except ErreurYoutube:
                if ancien and ancien.get("items"):
                    self._retenir(ancien["items"])
                    return {"type": type_, "items": self._public(ancien["items"])[:limite], "en_cache": True,
                            "perime": True, "date": int(ancien["date"])}
                raise
            doc = {"date": maintenant, "limite": limite, "items": items}
            self._ecrire(type_, doc)
            self._retenir(items)
            return {"type": type_, "items": self._public(items), "en_cache": False, "perime": False, "date": int(maintenant)}

    def _retenir(self, items):
        for i in items:
            if i.get("_source"):
                self._sources[i["id"]] = i["_source"]

    def source_vignette(self, vid):
        """URL de vignette apprise lors d'un listage ; à défaut le repli standard. L'identifiant est validé."""
        if not id_valide(vid):
            return None
        return self._sources.get(vid) or f"https://i.ytimg.com/vi/{vid}/mqdefault.jpg"

    def vignette(self, vid, ttl=7 * 86400):
        """(octets, type) de la vignette, mise en cache disque. None si identifiant douteux ou source injoignable."""
        src = self.source_vignette(vid)
        if not src or not _hote_ok(src):
            return None
        chemin = os.path.join(self.dossier, "vignettes", vid + ".jpg")
        try:
            if self.horloge() - os.path.getmtime(chemin) < ttl:
                with open(chemin, "rb") as f:
                    return f.read(), "image/jpeg"
        except OSError:
            pass
        try:
            req = urllib.request.Request(src, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:   # nosec - hôte restreint à ytimg / ggpht
                data = r.read(2_000_000)
        except Exception:
            return None
        try:
            os.makedirs(os.path.dirname(chemin), mode=0o700, exist_ok=True)
            fd = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
        except OSError:
            pass
        return data, "image/jpeg"
