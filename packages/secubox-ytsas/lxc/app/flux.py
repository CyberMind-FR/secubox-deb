# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-ytsas :: flux du compte YouTube
CyberMind — https://cybermind.fr

Lit, AVEC LES COOKIES DU COFFRE, les listes que YouTube tient pour le compte : « à regarder plus tard », propositions
d'accueil, abonnements, historique, chaînes suivies, playlists (#2708), puis les dernières vidéos d'UNE chaîne ou le contenu
d'UNE playlist (`chaine/<id>`, `playlist/<id>`). LECTURE SEULE : une seule requête de métadonnées à plat (`--flat-playlist`), rien n'est
téléchargé, rien n'est modifié dans le compte.

 · SANS COOKIES, ON REFUSE (AuthRequise) : ces listes sont celles d'une personne, jamais publiques.
 · UN APPEL À LA FOIS PAR FLUX, mis en cache le temps du TTL : l'accueil de YouTube ne change pas à la seconde, et la
   board est contrainte.
 · SI YOUTUBE REFUSE OU LIMITE, on rend le DERNIER résultat, signalé `perime` ; sans ancien résultat, l'erreur remonte.
 · LES VIGNETTES PASSENT PAR LA BOX (`/flux/vignette/<id>`) : le navigateur ne contacte pas Google à chaque affichage.
   L'hôte source est restreint à ytimg / ggpht.
 · CHAÎNES ET PLAYLISTS (#2708) : l'identifiant venu du client est validé par un motif strict (UC + 22, @handle, PL/UU/LL/FL/OL…),
   l'adresse envoyée à yt-dlp est CONSTRUITE ici, jamais une URL libre. Les avatars et vignettes de ces listes passent par la
   même route /flux/vignette sous une clé opaque de 11 caractères (empreinte de l'identifiant) : aucune route nouvelle.
 · ADMINISTRATION (#2714) : `etat()` rend l'état de chaque liste (cache fichier + métadonnées, SANS lecture YouTube),
   `actualiser()` relit UNE liste à la demande (borne anti-rafale), `vider()` supprime son cache. Les erreurs gardées pour
   l'affichage sont ASSAINIES (`assainir`) : ni chemin, ni URL, ni cookie, ni jeton.
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import shutil
import time
import urllib.request

TYPES = {
    "envie": ":ytwatchlater",
    "propositions": ":ytrec",
    "abonnements": ":ytsubs",
    "historique": ":ythistory",
    # #2708 — yt-dlp 2026.8.19 lit `feed/channels` (entrées channelRenderer : channel_id, abonnés) et `feed/playlists`
    # (entrées playlist : id, titre, miniature). Adresses fixes, jamais fournies par le client.
    "chaines": "https://www.youtube.com/feed/channels",
    "playlists": "https://www.youtube.com/feed/playlists",
}
MAX_DETAILS_EN_CACHE = 200
LIMITE_DEFAUT = 24
LIMITE_MAX = 60
DELAI_YTDLP_S = 90
ANTI_RAFALE_S = 30           # une relance manuelle par liste toutes les 30 s (#2714)
MAX_ECHECS = 10
TAILLE_TEXTE_ECHEC = 160
MOTEURS_JS = ("deno", "node", "bun", "qjs")    # moteurs que yt-dlp sait utiliser pour résoudre les défis JavaScript

_ID_RE = re.compile(r"[A-Za-z0-9_-]{11}")
_CHAINE_RE = re.compile(r"UC[A-Za-z0-9_-]{22}")
_HANDLE_RE = re.compile(r"@[A-Za-z0-9._-]{1,64}")
_PLAYLIST_RE = re.compile(r"(?:PL|UU|LL|FL|OL)[A-Za-z0-9_-]{10,40}")
_HOTES_VIGNETTES = ("i.ytimg.com", "i1.ytimg.com", "i2.ytimg.com", "i3.ytimg.com", "yt3.ggpht.com")


class AuthRequise(Exception):
    """Pas de cookies : les listes d'un compte ne se lisent pas sans lui."""


class ErreurYoutube(Exception):
    """yt-dlp ou YouTube a refusé / limité / répondu à côté."""


class Rafale(Exception):
    """Relance manuelle trop rapprochée pour cette liste (borne anti-rafale)."""
    def __init__(self, reste):
        super().__init__("trop rapproché")
        self.reste = reste


class Occupe(Exception):
    """Une relance manuelle est déjà en cours."""


class CookiesRefuses(ErreurYoutube):
    """YouTube dit que le compte n'est pas connecté : cookies périmés, ou exportés sans session."""


# « Login details are needed… », « Sign in to confirm… », « use --cookies… » : le compte n'est pas reconnu.
_REFUS_COOKIES = re.compile(r"login details are needed|sign in|use --cookies|--cookies-from-browser|not a bot|cookies", re.I)


_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://\S+")
_COOKIE_RE = re.compile(r"(?i)(?:__secure-\w+|__host-\w+|login_info|visitor_info1_live|sapisid|apisid|hsid|ssid|sid|sidcc|ysc|pref|consent)\s*[=:]\s*\S+")
_CHEMIN_RE = re.compile(r"(?:[A-Za-z]:\\[^\s]*|(?<![\w.])(?:~|\.{1,2})?/[^\s:;,'\"]+)")
_LONG_RE = re.compile(r"[A-Za-z0-9_%+=/-]{24,}")
_BLANCS_RE = re.compile(r"\s+")


def assainir(texte, n=TAILLE_TEXTE_ECHEC):
    """Texte d'erreur yt-dlp rendu inoffensif avant d'être gardé ou montré : plus d'URL (signées ou non), de chemin, de
    valeur de cookie ni de longue chaîne opaque (jeton, identifiant). Court, sur une ligne. Jamais le détail brut."""
    t = texte if isinstance(texte, str) else ""
    t = _URL_RE.sub("[adresse]", t)
    t = _COOKIE_RE.sub("[cookie]", t)
    t = _CHEMIN_RE.sub("[chemin]", t)
    t = _LONG_RE.sub("[…]", t)
    t = "".join(c if c.isprintable() else " " for c in t)
    return _BLANCS_RE.sub(" ", t).strip()[:n]


def borne(limite):
    try:
        n = int(limite)
    except (TypeError, ValueError):
        return LIMITE_DEFAUT
    return max(1, min(n, LIMITE_MAX))


def id_valide(vid):
    return bool(isinstance(vid, str) and _ID_RE.fullmatch(vid))


def chaine_valide(ident):
    """Identifiant de chaîne (UC + 22) ou handle (@nom). fullmatch : un « \n » final ne passe pas."""
    return bool(isinstance(ident, str) and (_CHAINE_RE.fullmatch(ident) or _HANDLE_RE.fullmatch(ident)))


def playlist_valide(ident):
    return bool(isinstance(ident, str) and _PLAYLIST_RE.fullmatch(ident))


def _argv(ytdlp_bin, cible, limite, cookie_path):
    return [ytdlp_bin, "--flat-playlist", "--dump-json", "--playlist-end", str(borne(limite)), "--no-warnings",
            "--cookies", cookie_path, cible]


def commande(ytdlp_bin, type_, limite, cookie_path):
    return _argv(ytdlp_bin, TYPES[type_], limite, cookie_path)


def url_detail(genre, ident):
    """Adresse CONSTRUITE pour yt-dlp à partir d'un identifiant déjà validé : jamais une URL libre du client."""
    if genre == "chaine" and chaine_valide(ident):
        return f"https://www.youtube.com/channel/{ident}/videos" if ident.startswith("UC") else f"https://www.youtube.com/{ident}/videos"
    if genre == "playlist" and playlist_valide(ident):
        return f"https://www.youtube.com/playlist?list={ident}"
    raise ValueError("identifiant invalide")


def commande_detail(ytdlp_bin, genre, ident, limite, cookie_path):
    # « -- » : plus aucune option possible après lui, quoi que contienne l'adresse
    return _argv(ytdlp_bin, "--", limite, cookie_path) + [url_detail(genre, ident)]


def cle_vignette(ident):
    """Clé opaque de 11 caractères pour l'avatar d'une chaîne / la miniature d'une playlist : /flux/vignette/<clé>."""
    return base64.urlsafe_b64encode(hashlib.sha256(ident.encode("utf-8")).digest())[:11].decode("ascii")


def _entier(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _texte(v, n=200):
    return v.strip()[:n] if isinstance(v, str) else ""


# `feed/playlists` : yt-dlp y met le TEXTE DU LIEN (« View full playlist », « Voir la playlist complète »…) là où l'on attend l'auteur.
_LIBELLE_LIEN_RE = re.compile(r"^(view|voir|afficher|see|show|ver|ansehen)\b.*\bplaylist\b|^(view|voir|afficher)\b.*\b(liste|lista)\b", re.IGNORECASE)


def _nom_auteur(v, n=200):
    """Nom de chaîne ou de compte ; le libellé d'un lien de yt-dlp n'en est pas un (rien n'est inventé : « » si absent)."""
    t = _texte(v, n)
    return "" if _LIBELLE_LIEN_RE.match(t) else t


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


def miniature_source(d):
    """Plus grande miniature de yt-dlp sur un hôte admis (ytimg / ggpht), sinon None — jamais de repli inventé."""
    ok = []
    for t in (d.get("thumbnails") or []):
        if not isinstance(t, dict) or not isinstance(t.get("url"), str):
            continue
        u = "https:" + t["url"] if t["url"].startswith("//") else t["url"]
        if _hote_ok(u):
            ok.append((t.get("width") if isinstance(t.get("width"), int) else 0, u))
    return max(ok, key=lambda x: x[0])[1] if ok else None


def _lignes(sortie):
    for ligne in (sortie or "").splitlines():
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            d = json.loads(ligne)
        except ValueError:
            continue
        if isinstance(d, dict):
            yield d


def analyser_chaines(sortie):
    """Chaînes auxquelles le compte est abonné. Rien n'est inventé : abonnés / vidéos / avatar seulement s'ils sont fournis."""
    items = []
    for d in _lignes(sortie):
        ident = d.get("channel_id") or d.get("id")
        if not isinstance(ident, str) or not _CHAINE_RE.fullmatch(ident):
            continue
        handle = d.get("uploader_id")
        src = miniature_source(d)
        items.append({
            "id": ident,
            "nom": _texte(d.get("channel") or d.get("title") or d.get("uploader")),
            "handle": handle if isinstance(handle, str) and _HANDLE_RE.fullmatch(handle) else None,
            "abonnes": _entier(d.get("channel_follower_count")),
            "videos": _entier(d.get("playlist_count")),
            "url": "https://www.youtube.com/channel/" + ident,
            "vignette": "/api/v1/ytsas/flux/vignette/" + cle_vignette(ident) if src else None,
            "_cle": cle_vignette(ident),
            "_source": src,
        })
    return items


def analyser_playlists(sortie):
    """Playlists du compte. Le nombre de vidéos n'est pas fourni par la lecture à plat : il reste absent (None)."""
    items = []
    for d in _lignes(sortie):
        ident = d.get("id")
        if not isinstance(ident, str) or not _PLAYLIST_RE.fullmatch(ident):
            continue
        src = miniature_source(d)
        items.append({
            "id": ident,
            "titre": _texte(d.get("title")),
            "chaine": _nom_auteur(d.get("channel") or d.get("uploader")),
            "videos": _entier(d.get("playlist_count")),
            "url": "https://www.youtube.com/playlist?list=" + ident,
            "vignette": "/api/v1/ytsas/flux/vignette/" + cle_vignette(ident) if src else None,
            "_cle": cle_vignette(ident),
            "_source": src,
        })
    return items


def titre_detail(genre, sortie):
    """Nom de la chaîne / de la playlist, tel que yt-dlp le donne sur les entrées ; '' s'il ne le dit pas."""
    for d in _lignes(sortie):
        brut = d.get("playlist_title") if genre == "playlist" else (d.get("channel") or d.get("playlist_channel") or d.get("uploader"))
        t = _texte(brut)
        if t:
            return t
    return ""


ANALYSEURS = {"chaines": analyser_chaines, "playlists": analyser_playlists}


async def executer_ytdlp(argv):
    """Exécuteur réel : yt-dlp en sous-processus asynchrone, jamais bloquant."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=DELAI_YTDLP_S)
    except asyncio.TimeoutError:
        # #2985 : `wait_for` n'annule que la coroutine `communicate()` — le sous-processus
        # OS, lui, continue de tourner pour toujours si on ne le tue pas explicitement
        # (constaté sur gk2 : 26 yt-dlp orphelins accumulés en 1 jour, chacun bloqué sur un
        # défi YouTube qui ne répond jamais). `wait()` après `kill()` évite aussi un zombie.
        if proc is not None:
            proc.kill()
            await proc.wait()
        raise ErreurYoutube("délai dépassé")
    except FileNotFoundError:
        raise ErreurYoutube("yt-dlp introuvable dans le conteneur")
    texte = out.decode("utf-8", "replace")
    if not texte.strip():
        detail = (err.decode("utf-8", "replace").strip().splitlines() or ["flux vide"])[-1][:200]
        raise (CookiesRefuses if _REFUS_COOKIES.search(detail) else ErreurYoutube)(detail)
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
        self._version = (0, None)        # (date, version de yt-dlp) : lue une fois par 10 minutes
        self._admin = asyncio.Lock()     # une relance manuelle à la fois, toutes listes confondues

    def _verrou(self, type_):
        if type_ not in self._verrous:
            self._verrous[type_] = asyncio.Lock()
        return self._verrous[type_]

    def _fichier(self, cle):
        return os.path.join(self.dossier, f"{cle}.json")

    def _lire(self, cle):
        try:
            with open(self._fichier(cle), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _ecrire(self, cle, doc):
        os.makedirs(self.dossier, mode=0o700, exist_ok=True)
        tmp = self._fichier(cle) + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(doc, ensure_ascii=False).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, self._fichier(cle))

    def _elaguer_details(self):
        """Les détails (chaîne / playlist) sont à la demande : on en garde MAX_DETAILS_EN_CACHE, les plus récents."""
        try:
            fichiers = [os.path.join(self.dossier, n) for n in os.listdir(self.dossier) if n.startswith("d-") and n.endswith(".json")]
            fichiers.sort(key=os.path.getmtime, reverse=True)
            for f in fichiers[MAX_DETAILS_EN_CACHE:]:
                os.unlink(f)
        except OSError:
            pass

    def _public(self, items):
        return [{k: v for k, v in i.items() if not k.startswith("_")} for i in items]

    async def _servir(self, cle, verrou, argv, analyseur, limite, base, titre=None, forcer=False):
        """Cache fichier, appel unique, repli périmé avec sa cause : le MÊME mécanisme pour les listes et les détails."""
        async with self._verrou(verrou):
            maintenant = self.horloge()
            ancien = self._lire(cle)
            if not forcer and ancien and ancien.get("limite", 0) >= limite and maintenant - ancien.get("date", 0) < self.ttl:
                self._retenir(ancien["items"])
                r = {**base, "items": self._public(ancien["items"])[:limite], "en_cache": True, "perime": False,
                     "date": int(ancien["date"])}
                if titre:
                    r["titre"] = ancien.get("titre", "")
                return r
            debut = time.monotonic()
            try:
                sortie = await self.executeur(argv)
                items = analyseur(sortie)
                if not items:
                    raise ErreurYoutube("flux vide ou illisible")
            except ErreurYoutube as e:
                self._noter(verrou, maintenant, time.monotonic() - debut, e)
                if ancien and ancien.get("items"):
                    self._retenir(ancien["items"])
                    # La CAUSE accompagne le repli (#2633) : sans elle, « YouTube n'a pas répondu » cache que le compte
                    # n'est plus reconnu, et l'utilisateur ne sait pas qu'il doit redéposer ses cookies. Jamais le détail brut.
                    r = {**base, "items": self._public(ancien["items"])[:limite], "en_cache": True, "perime": True,
                         "cause": "cookies" if isinstance(e, CookiesRefuses) else "youtube", "date": int(ancien["date"])}
                    if titre:
                        r["titre"] = ancien.get("titre", "")
                    return r
                raise
            doc = {"date": maintenant, "limite": limite, "items": items}
            r = {**base, "items": self._public(items), "en_cache": False, "perime": False, "date": int(maintenant)}
            if titre:
                doc["titre"] = r["titre"] = titre(sortie)
            self._ecrire(cle, doc)
            self._retenir(items)
            self._noter(verrou, maintenant, time.monotonic() - debut, None)
            return r

    async def lister(self, type_, limite=LIMITE_DEFAUT, forcer=False):
        if type_ not in TYPES:
            raise ValueError("type de flux inconnu")
        if not self.cookie_path:
            raise AuthRequise("auth requise — dépose tes cookies")
        limite = borne(limite)
        return await self._servir(type_, type_, commande(self.ytdlp_bin, type_, limite, self.cookie_path),
                                  ANALYSEURS.get(type_, analyser), limite, {"type": type_}, forcer=forcer)

    async def detail(self, genre, ident, limite=LIMITE_DEFAUT):
        """Dernières vidéos d'une chaîne, ou vidéos d'une playlist. L'identifiant est validé AVANT tout, cookies compris."""
        url_detail(genre, ident)         # ValueError si le motif strict n'est pas respecté
        if not self.cookie_path:
            raise AuthRequise("auth requise — dépose tes cookies")
        limite = borne(limite)
        cle = "d-" + hashlib.sha256(f"{genre}:{ident}".encode("utf-8")).hexdigest()[:24]
        r = await self._servir(cle, genre, commande_detail(self.ytdlp_bin, genre, ident, limite, self.cookie_path),
                               analyser, limite, {"type": genre, "id": ident}, titre=lambda sortie: titre_detail(genre, sortie))
        self._elaguer_details()
        return r

    # ───────────────────────── administration (#2714) ─────────────────────────
    def _meta(self):
        m = self._lire("_etat")
        if not isinstance(m, dict):
            m = {}
        if not isinstance(m.get("listes"), dict):
            m["listes"] = {}
        if not isinstance(m.get("echecs"), list):
            m["echecs"] = []
        return m

    def _noter(self, etiquette, date, duree, erreur):
        """Garde, pour l'administration, le résultat de la dernière lecture réelle : date, durée, cause, et l'échec ASSAINI."""
        try:
            m = self._meta()
            if etiquette in TYPES:
                fiche = m["listes"].setdefault(etiquette, {})
                fiche.update({"tentative": int(date), "ok": erreur is None, "duree": round(max(0.0, duree), 1),
                              "cause": None if erreur is None else ("cookies" if isinstance(erreur, CookiesRefuses) else "youtube")})
            if erreur is not None:
                m["echecs"] = ([{"liste": etiquette if etiquette in TYPES or etiquette in ("chaine", "playlist") else "autre",
                                 "date": int(date), "cause": "cookies" if isinstance(erreur, CookiesRefuses) else "youtube",
                                 "texte": assainir(str(erreur))}] + m["echecs"])[:MAX_ECHECS]
            self._ecrire("_etat", m)
        except (OSError, ValueError, TypeError):
            pass      # l'état d'administration ne doit jamais faire échouer une lecture

    def _relance_dans(self, type_):
        fiche = self._meta()["listes"].get(type_) or {}
        reste = ANTI_RAFALE_S - (self.horloge() - fiche.get("relance", 0))
        return max(0, int(reste + 0.999)) if reste > 0 else 0

    def taille_cache(self):
        fichiers, octets = 0, 0
        for racine, _dossiers, noms in os.walk(self.dossier):
            for n in noms:
                try:
                    octets += os.path.getsize(os.path.join(racine, n))
                    fichiers += 1
                except OSError:
                    pass
        return {"fichiers": fichiers, "octets": octets}

    @staticmethod
    def moteurs_js():
        """Moteurs JavaScript trouvés dans le conteneur (yt-dlp en a besoin pour résoudre les défis de YouTube). Lecture du PATH
        seulement : aucun processus lancé. `deno` est celui que yt-dlp active par défaut ; les autres s'activent par réglage."""
        trouves = [m for m in MOTEURS_JS if shutil.which(m)]
        return {"present": bool(trouves), "moteurs": trouves, "par_defaut": "deno" in trouves}

    async def version_ytdlp(self):
        """Version de yt-dlp (`--version`, par l'exécuteur existant, argv fixe) ; mémorisée 10 minutes. None si illisible."""
        maintenant = self.horloge()
        date, v = self._version
        if v is not None and maintenant - date < 600:
            return v
        try:
            sortie = await self.executeur([self.ytdlp_bin, "--version"])
        except Exception:
            return None
        ligne = (sortie or "").strip().splitlines()[0].strip() if (sortie or "").strip() else ""
        v = ligne if re.fullmatch(r"[0-9A-Za-z._+-]{1,40}", ligne) else None
        self._version = (maintenant, v)
        return v

    async def etat(self):
        """État de chaque liste, LU dans le cache fichier et les métadonnées : aucune lecture YouTube n'est lancée."""
        maintenant = self.horloge()
        m = self._meta()
        listes = []
        for t in TYPES:
            doc = self._lire(t) or {}
            fiche = m["listes"].get(t) or {}
            date = int(doc["date"]) if isinstance(doc.get("date"), (int, float)) else None
            items = doc.get("items") if isinstance(doc.get("items"), list) else None
            echec = fiche.get("ok") is False and fiche.get("tentative", 0) >= (date or 0)
            cause = None
            if not self.cookie_path:
                cause = "absent"
            elif echec:
                cause = fiche.get("cause") if fiche.get("cause") in ("cookies", "youtube") else "youtube"
            listes.append({
                "type": t,
                "date": date,
                "age_s": int(maintenant - date) if date is not None else None,
                "videos": len(items) if items is not None else None,
                "perime": None if date is None else bool(echec or maintenant - date >= self.ttl or not self.cookie_path),
                "cause": cause,
                "derniere_tentative": fiche.get("tentative"),
                "duree_s": fiche.get("duree"),
                "relance_dans_s": self._relance_dans(t),
            })
        return {
            "ttl_s": self.ttl,
            "anti_rafale_s": ANTI_RAFALE_S,
            "listes": listes,
            "diagnostic": {
                "ytdlp": await self.version_ytdlp(),
                "js": self.moteurs_js(),
                "echecs": m["echecs"][:MAX_ECHECS],
                "cache": self.taille_cache(),
            },
        }

    async def actualiser(self, type_):
        """Relit UNE liste maintenant (lecture seule du compte). Un seul appel à la fois ; au plus une relance par liste toutes
        les ANTI_RAFALE_S secondes. Lève Rafale / Occupe / AuthRequise / ErreurYoutube (sans ancien résultat)."""
        if type_ not in TYPES:
            raise ValueError("type de flux inconnu")
        if not self.cookie_path:
            raise AuthRequise("auth requise — dépose tes cookies")
        if self._admin.locked():
            raise Occupe("une relance est déjà en cours")
        async with self._admin:
            reste = self._relance_dans(type_)
            if reste:
                raise Rafale(reste)
            m = self._meta()
            m["listes"].setdefault(type_, {})["relance"] = self.horloge()
            self._ecrire("_etat", m)
            return await self.lister(type_, LIMITE_DEFAUT, forcer=True)

    def vider(self, type_):
        """Supprime le cache d'UNE liste (jamais celui des autres, jamais les cookies). True s'il y avait quelque chose."""
        if type_ not in TYPES:
            raise ValueError("type de flux inconnu")
        try:
            os.unlink(self._fichier(type_))
        except FileNotFoundError:
            return False
        return True

    def _retenir(self, items):
        for i in items:
            if i.get("_source"):
                self._sources[i.get("_cle") or i["id"]] = i["_source"]

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
