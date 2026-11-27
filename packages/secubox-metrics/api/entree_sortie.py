# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Entrée / sortie des visites par vhost (#4011).

Ce qui ENTRE (requêtes HTTP, adresses, octets, par type de visite et type de page) mis en regard de ce qui SORT
(servi en 2xx/3xx), avec la réduction apportée par :
  * les bans nftables (avant HTTP) : delta des compteurs de paquets des éléments de `waf_ban`/`waf_ban6`,
    imputé au vhost que l'adresse visitait en dernier (sinon « (non attribué) ») ;
  * le WAF : lignes de `waf-threats.log` dont l'action bloque (la requête n'atteint jamais nginx) ;
  * les erreurs : 4xx/5xx de nginx.

Visites des vrais visiteurs (type « humain » seulement) : sessions sans cookie, par empreinte salée
sha256(sel du jour + IP + UA) ; le sel vit en mémoire et change chaque jour ; pause > 30 min = nouvelle session.

Typage déterministe (aucune IA). Lecture incrémentale (inode + position) ; tâche de fond ; double tampon : une passe
dégradée (source illisible, nft en échec) n'écrase jamais un rapport complet. AUCUNE adresse, aucun UA, aucune
empreinte dans le cache ni dans la sortie : seulement des compteurs.
"""

from __future__ import annotations

import asyncio
import calendar
import hashlib
import json
import os
import re
import subprocess
import threading
import time
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Any, Callable, Dict, Optional

from vhost_stats import ACCESSOIRE, LIGNE, LIGNE_HOTE, SONDES, _hote_reel, cle_seau

# ── sources (lecture seule) ───────────────────────────────────────────────
REP_LOGS = Path("/var/log/nginx")
JOURNAL_HOTES = REP_LOGS / "secubox-hosts.log"
SUFFIXE = "_access.log"
MENACES = Path("/var/log/secubox/waf/waf-threats.log")
ETAT = Path("/var/cache/secubox/metrics/entree-sortie-etat.json")
RAPPORT = Path("/var/cache/secubox/metrics/entree-sortie.json")
ENSEMBLES_BAN = ("waf_ban", "waf_ban6")

# ── plafonds ──────────────────────────────────────────────────────────────
AMORCE = 512 * 1024                 # première rencontre d'un journal : on part près de la fin
PLAFOND_CYCLE = 4 * 1024 * 1024     # octets lus au plus par source et par passe
HEURES_GARDEES = 5 * 24             # seaux horaires : 1 h / 8 h / 1 j et leurs fenêtres précédentes
JOURS_GARDES = 50                   # seaux journaliers : 7 j et 6 semaines précédentes
MAX_VHOSTS_SEAU = 300
MAX_VHOSTS_RAPPORT = 40
MAX_IP_SUIVIES = 100_000            # adresse → dernier vhost (mémoire seulement, jamais écrit)
MAX_SESSIONS = 50_000
MAX_EMPREINTES = 20_000             # empreintes distinctes retenues par vhost et par heure / jour
AUTRES = "(autres)"
NON_ATTRIBUE = "(non attribué)"
AUTOTEST = "SecuBox-WAF-SelfTest/"

# ── comparaison (même règle que packages/secubox-waf-ng/composants/waf/api/profil.py, #4005) ─────────────
FENETRES = (("1h", 1, "h"), ("8h", 8, "h"), ("1j", 24, "h"), ("7j", 7, "j"))
VOLUME_MIN = {"1h": 10, "8h": 30, "1j": 50, "7j": 200}
FACTEUR = 3.0
N_PRECEDENTES = 6
MIN_PRECEDENTES = 3

# ── sessions ──────────────────────────────────────────────────────────────
PAUSE_SESSION = 30 * 60
BORNES_DUREE = (10, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200, 14400)   # secondes ; au-delà : « + »

# ── typage des visites ────────────────────────────────────────────────────
VISITES = ("humain", "robot", "outil", "aspirateur", "sonde")
PAGES = ("page", "statique", "api", "forge", "medias", "admin", "autre")
ROBOT = re.compile(r"bot\b|bot/|crawl|spider|slurp|facebookexternalhit|meta-webindexer|externalhit|"
                   r"bingpreview|mediapartners|feedfetcher|ia_archiver|petalbot|yandex|baidu", re.I)
OUTIL = re.compile(r"^-?$|curl/|wget/|python-|python/|aiohttp|httpx|go-http-client|okhttp|libwww|java/|"
                   r"node-fetch|axios|undici|scrapy|headless|httpclient|guzzle|ruby|perl|php/|"
                   r"zgrab|masscan|nmap|nuclei|secubox-", re.I)
SEUIL_RAFALE = 200                  # une même empreinte de navigateur ≥ 200 pages de forge en une heure : aspirateur
ACTIONS_BLOQUANTES = frozenset(("banned", "block", "blocked", "deny", "denied", "drop"))
CATEGORIES_NEUTRES = ("host_anomaly", "robots")     # signalements sans valeur de sonde
DUREE_SUSPECT = 24 * 3600

# Repris de profil.py (#4005, non importable : autre paquet) : verbes d'historique de forge (Gitea, Forgejo).
VERBES_FORGE = frozenset(("src", "blame", "raw", "commits", "commit", "tree", "archive", "releases", "tags", "branches",
                          "issues", "pulls", "wiki", "activity", "compare", "media", "rss", "atom", "graph", "find",
                          "search", "stars", "forks", "watchers", "settings", "actions", "packages", "projects"))
MEDIAS = re.compile(r"\.(mp4|webm|m4s|m3u8|mp3|ogg|oga|opus|flac|wav|mkv|mov|vtt)(\?|$)|^/(media|videos?|"
                    r"static/streaming-playlists|download)/", re.I)
ADMIN = re.compile(r"^/(login|logout|signin|sign_in|sign_up|user/(login|sign_up|forgot_password)|admin|"
                   r"wp-admin|wp-login|administrator|api/v1/(auth|session)|-/admin|auth|account|"
                   r"index\.php/login|ocs/v[12]\.php/core/getapppassword)(/|\?|$|\.)", re.I)
API = re.compile(r"^/(api|graphql|ocs|remote\.php|v[0-9]+/|_next/data|wp-json)(/|\?|$)|\.json(\?|$)", re.I)

MOIS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_DATE = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")


def horodatage(brut: str) -> Optional[int]:
    """`27/Nov/2026:05:34:59 +0100` → secondes epoch ; None si illisible."""
    m = _DATE.match(brut or "")
    if not m or m.group(2) not in MOIS:
        return None
    j, mo, a, h, mi, s, signe, dh, dm = m.groups()
    dec = (int(dh) * 3600 + int(dm) * 60) * (1 if signe == "+" else -1)
    return calendar.timegm((int(a), MOIS[mo], int(j), int(h), int(mi), int(s), 0, 0, 0)) - dec


def classer_page(methode: str, chemin: str) -> str:
    """Type de page publiée : page, statique, api, forge, medias, admin, autre."""
    c = (chemin or "").split("#", 1)[0]
    nu = c.split("?", 1)[0]
    if ADMIN.search(nu):
        return "admin"
    segs = [s for s in nu.split("/") if s]
    if len(segs) >= 3 and segs[2] in VERBES_FORGE:
        return "forge"
    if MEDIAS.search(nu):
        return "medias"
    if API.search(nu):
        return "api"
    if ACCESSOIRE.search(nu) or nu.startswith(("/assets/", "/static/", "/_next/static/")) or nu in ("/favicon.ico", "/robots.txt"):
        return "statique"
    if methode in ("GET", "HEAD"):
        return "page"
    return "autre"


def classer_ua(ua: str) -> str:
    """humain, robot (déclaré), outil — par l'UA seul ; sonde et aspirateur viennent du contexte."""
    if ROBOT.search(ua or ""):
        return "robot"
    if OUTIL.search(ua or ""):
        return "outil"
    return "humain"


def _vierge() -> Dict[str, int]:
    return {}


def _inc(d: Dict[str, int], cle: str, n: int = 1) -> None:
    if n:
        d[cle] = d.get(cle, 0) + n


def _borne(duree: int) -> str:
    for b in BORNES_DUREE:
        if duree <= b:
            return str(b)
    return "+"


def quantile_histo(histo: Dict[str, int], q: float) -> Optional[int]:
    """Borne haute du segment qui contient le quantile `q` (approximation par histogramme, en secondes)."""
    total = sum(histo.values())
    if not total:
        return None
    cible, cumul = q * total, 0
    for b in [str(x) for x in BORNES_DUREE] + ["+"]:
        cumul += histo.get(b, 0)
        if cumul >= cible:
            return BORNES_DUREE[-1] * 2 if b == "+" else int(b)
    return None


def rupture(serie: Dict[int, int], fin: int, longueur: int, debut: Optional[int], volume_min: int) -> Dict[str, Any]:
    """Fenêtre [fin-L, fin) contre la médiane des fenêtres précédentes de même longueur couvertes par l'historique
    (règle de profil.py, #4005 : au plus 6, au moins 3, facteur 3, volume minimal)."""
    def somme(a: int, b: int) -> int:
        return sum(serie.get(i, 0) for i in range(a, b))

    courant = somme(fin - longueur, fin)
    prec = []
    for k in range(1, N_PRECEDENTES + 1):
        a = fin - (k + 1) * longueur
        if debut is None or a < debut:
            break
        prec.append(somme(a, a + longueur))
    r: Dict[str, Any] = {"courant": courant}
    if len(prec) < MIN_PRECEDENTES:
        r["sens"] = "insuffisant"
        return r
    med = median(prec)
    r["mediane"], r["fenetres"] = med, len(prec)
    if courant >= volume_min and courant >= FACTEUR * max(med, 1):
        r["sens"], r["facteur"] = "hausse", round(courant / max(med, 1), 1)
    elif med >= volume_min and courant * FACTEUR <= med:
        r["sens"], r["facteur"] = "baisse", round(med / max(courant, 1), 1)
    else:
        r["sens"] = "stable"
    return r


def _lire_nft(nom: str) -> Dict[str, int]:
    """Éléments d'un ensemble de bans → paquets reçus depuis la pose. OSError/ValueError si nft échoue."""
    p = subprocess.run(["nft", "-j", "list", "set", "inet", "secubox", nom], capture_output=True, timeout=15, check=False)
    if p.returncode != 0:
        raise OSError(f"nft list set {nom}: rc {p.returncode}")
    doc = json.loads(p.stdout or b"{}")
    out: Dict[str, int] = {}
    for e in doc.get("nftables", []):
        s = e.get("set") if isinstance(e, dict) else None
        if not s:
            continue
        for el in s.get("elem", []) or []:
            v = el.get("elem", el) if isinstance(el, dict) else None
            if not isinstance(v, dict):
                continue
            val, cpt = v.get("val"), v.get("counter") or {}
            if isinstance(val, str):
                out[val] = int(cpt.get("packets", 0) or 0)
    return out


def lire_bans() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for nom in ENSEMBLES_BAN:
        out.update(_lire_nft(nom))
    return out


class EntreeSortie:
    """Compteurs horaires et journaliers par vhost ; rapport rebâti en fond, servi tel quel."""

    def __init__(self, rep_logs: Path = REP_LOGS, menaces: Path = MENACES, etat: Path = ETAT, rapport: Path = RAPPORT,
                 bans: Callable[[], Dict[str, int]] = lire_bans, horloge: Callable[[], float] = time.time,
                 intervalle: int = 120):
        self.rep_logs, self.menaces, self.etat_f, self.rapport_f = rep_logs, menaces, etat, rapport
        self.bans_lecteur, self.horloge, self.intervalle = bans, horloge, intervalle
        self._verrou = threading.RLock()
        self._suivi: Dict[str, list] = {}                     # chemin → [inode, position]
        self.heures: Dict[int, Dict[str, Dict[str, int]]] = {}   # heure epoch → vhost → compteurs
        self.jours: Dict[int, Dict[str, Dict[str, int]]] = {}
        self.debut_h: Optional[int] = None
        self.debut_j: Optional[int] = None
        # Mémoire seulement (jamais persisté) : adresses, empreintes, sel.
        self._ip_vhost: "OrderedDict[str, str]" = OrderedDict()
        self._suspects: Dict[str, tuple] = {}                 # ip → (type, échéance)
        self._bans_prec: Optional[Dict[str, int]] = None
        self._sel: tuple = (None, b"")
        self._vus: Dict[tuple, set] = {}                      # (échelle, seau, vhost) → empreintes
        self._rafales: Dict[tuple, int] = {}                  # (heure, vhost, empreinte UA) → pages de forge
        self._sessions: Dict[tuple, list] = {}                # (vhost, empreinte) → [début, dernier, pages]
        self._rapport: Optional[dict] = None                  # tampon ACTIF
        self._charger()

    # ── persistance ───────────────────────────────────────────────────────
    def _charger(self) -> None:
        try:
            d = json.loads(self.etat_f.read_text())
            if d.get("version") == 1:
                self._suivi = {k: list(v) for k, v in d.get("suivi", {}).items()}
                self.heures = {int(k): v for k, v in d.get("heures", {}).items()}
                self.jours = {int(k): v for k, v in d.get("jours", {}).items()}
                self.debut_h, self.debut_j = d.get("debut_h"), d.get("debut_j")
        except (OSError, ValueError, AttributeError):
            pass
        try:
            r = json.loads(self.rapport_f.read_text())
            if isinstance(r, dict) and "vhosts" in r:
                self._rapport = r
        except (OSError, ValueError):
            pass

    @staticmethod
    def _ecrire(f: Path, contenu: str) -> None:
        f.parent.mkdir(parents=True, exist_ok=True)
        tmp = f.with_name(f.name + ".tmp")
        tmp.write_text(contenu)
        os.replace(tmp, f)                                    # remplacement atomique

    def _persister(self) -> None:
        with self._verrou:
            contenu = json.dumps({"version": 1, "suivi": self._suivi, "debut_h": self.debut_h, "debut_j": self.debut_j,
                                  "heures": self.heures, "jours": self.jours}, separators=(",", ":"))
        try:
            self._ecrire(self.etat_f, contenu)
        except OSError:
            pass

    # ── lecture incrémentale ──────────────────────────────────────────────
    def _queue(self, f: Path, budget: int = PLAFOND_CYCLE) -> Optional[list]:
        """Lignes complètes ajoutées depuis le dernier passage ; None si le fichier est illisible."""
        try:
            with f.open("rb") as fh:
                st = os.fstat(fh.fileno())
                cle = str(f)
                connu = cle in self._suivi
                inode, pos = self._suivi.get(cle, (0, 0))
                if st.st_ino != inode or st.st_size < pos:
                    pos = 0                                   # rotation : le nouveau fichier depuis son début
                if not connu:
                    pos = max(0, st.st_size - AMORCE)
                fh.seek(pos)
                donnees = fh.read(budget)
        except OSError:
            return None
        if not connu and pos > 0:
            saut = donnees.find(b"\n")
            donnees = donnees[saut + 1:] if saut >= 0 else b""
            pos += saut + 1 if saut >= 0 else 0
        coupe = donnees.rfind(b"\n")
        donnees = donnees[:coupe + 1] if coupe >= 0 else b""
        self._suivi[cle] = [st.st_ino, pos + len(donnees)]
        return [x.decode("utf-8", "replace") for x in donnees.splitlines()]

    # ── seaux ─────────────────────────────────────────────────────────────
    def _seaux(self, t: int, vhost: str) -> tuple:
        h, j = t // 3600, t // 86400
        if self.debut_h is None or h < self.debut_h:
            self.debut_h = h
        if self.debut_j is None or j < self.debut_j:
            self.debut_j = j
        out = []
        for table, cle in ((self.heures, h), (self.jours, j)):
            par_vhost = table.setdefault(cle, {})
            v = vhost if vhost in par_vhost or len(par_vhost) < MAX_VHOSTS_SEAU else AUTRES
            out.append(par_vhost.setdefault(v, _vierge()))
        return tuple(out)

    def _sel_du_jour(self, jour: int) -> bytes:
        if self._sel[0] != jour:
            self._sel = (jour, os.urandom(16))
            self._vus.clear()
        return self._sel[1]

    def _empreinte(self, jour: int, *parts: str) -> str:
        h = hashlib.sha256(self._sel_du_jour(jour))
        for p in parts:
            h.update(b"\x1f" + p.encode("utf-8", "replace"))
        return h.hexdigest()[:20]

    def _distinct(self, echelle: str, seau: int, vhost: str, empreinte: str) -> bool:
        cle = (echelle, seau, vhost)
        vus = self._vus.get(cle)
        if vus is None:
            for k in [k for k in self._vus if k[0] == echelle and k[1] != seau]:
                del self._vus[k]
            vus = self._vus[cle] = set()
        if empreinte in vus or len(vus) >= MAX_EMPREINTES:
            return False
        vus.add(empreinte)
        return True

    def _retenir_ip(self, ip: str, vhost: str) -> None:
        self._ip_vhost[ip] = vhost
        self._ip_vhost.move_to_end(ip)
        while len(self._ip_vhost) > MAX_IP_SUIVIES:
            self._ip_vhost.popitem(last=False)

    def _suspect(self, ip: str, t: int) -> Optional[str]:
        s = self._suspects.get(ip)
        if s and s[1] >= t:
            return s[0]
        return None

    # ── une requête ───────────────────────────────────────────────────────
    def compter_requete(self, vhost: str, ip: str, t: int, methode: str, chemin: str, statut: int, octets: int,
                        ua: str, bloquee: bool = False, type_force: Optional[str] = None) -> None:
        if ua.startswith(AUTOTEST):
            return                                            # auto-test du WAF : jamais une visite
        vhost = cle_seau(vhost.split(":")[0].lower())
        if not _hote_reel(vhost):
            return
        page = classer_page(methode, chemin)
        heure, jour = t // 3600, t // 86400
        emp_ua = self._empreinte(jour, ua)
        visite = type_force or self._suspect(ip, t)
        if visite is None and SONDES.search(chemin or ""):
            visite = "sonde"
        if visite is None:
            visite = classer_ua(ua)
            if visite == "humain" and page == "forge":
                k = (heure, vhost, emp_ua)
                self._rafales[k] = self._rafales.get(k, 0) + 1
                if self._rafales[k] >= SEUIL_RAFALE:
                    visite = "aspirateur"
        sh, sj = self._seaux(t, vhost)
        emp_ip = self._empreinte(jour, ip)
        for s, echelle, seau in ((sh, "h", heure), (sj, "j", jour)):
            _inc(s, "e")
            _inc(s, "eo", octets)
            _inc(s, "v:" + visite)
            _inc(s, "vo:" + visite, octets)
            _inc(s, "p:" + page)
            _inc(s, "vp:" + visite + ":" + page)
            if self._distinct(echelle, seau, vhost, emp_ip):
                _inc(s, "a")
            if bloquee:
                _inc(s, "w")
            elif statut >= 500:
                _inc(s, "x5")
            elif statut >= 400:
                _inc(s, "x4")
            elif 200 <= statut < 400:
                _inc(s, "s")
                _inc(s, "so", octets)
        if not bloquee:
            self._retenir_ip(ip, vhost)
        if visite == "humain" and page == "page" and not bloquee and statut < 400:
            self._session(vhost, self._empreinte(jour, ip, ua), t)

    # ── sessions des vrais visiteurs ──────────────────────────────────────
    def _session(self, vhost: str, emp: str, t: int) -> None:
        cle = (vhost, emp)
        s = self._sessions.get(cle)
        if s and t - s[1] > PAUSE_SESSION:
            self._clore(vhost, s)
            s = None
        if s is None:
            if len(self._sessions) >= MAX_SESSIONS:
                return
            self._sessions[cle] = [t, t, 1]
            return
        s[1] = max(s[1], t)
        s[2] += 1

    def _clore(self, vhost: str, s: list) -> None:
        for b in self._seaux(s[1], vhost):
            _inc(b, "ss")
            _inc(b, "sp", s[2])
            if s[2] == 1:
                _inc(b, "s1")                                 # une page : durée inconnue, jamais 0
            else:
                _inc(b, "d:" + _borne(s[1] - s[0]))

    def clore_sessions(self, maintenant: int, toutes: bool = False) -> None:
        for cle in [k for k, s in self._sessions.items() if toutes or maintenant - s[1] > PAUSE_SESSION]:
            self._clore(cle[0], self._sessions.pop(cle))

    # ── sources ───────────────────────────────────────────────────────────
    def _nginx(self) -> bool:
        hotes = self.rep_logs / JOURNAL_HOTES.name
        sources = [(hotes, None)] if hotes.exists() else [
            (f, f.name[:-len(SUFFIXE)]) for f in sorted(self.rep_logs.glob(f"*{SUFFIXE}"))]
        ok = bool(sources)
        for f, vhost in sources:
            lignes = self._queue(f)
            if lignes is None:
                ok = False
                continue
            for ligne in lignes:
                m = (LIGNE_HOTE if vhost is None else LIGNE).match(ligne)
                if not m:
                    continue
                t = horodatage(m.group("date"))
                if t is None:
                    continue
                o = m.group("octets")
                self.compter_requete(m.group("hote") if vhost is None else vhost, m.group("ip"), t, m.group("methode"),
                                     m.group("chemin"), int(m.group("statut")), int(o) if o.isdigit() else 0, m.group("ua"))
        return ok

    def _waf(self) -> bool:
        lignes = self._queue(self.menaces)
        if lignes is None:
            return False
        for ligne in lignes:
            try:
                r = json.loads(ligne)
                t = int(datetime.fromisoformat(r["timestamp"]).timestamp())
            except (ValueError, KeyError, TypeError):
                continue
            ip, cat, action = str(r.get("client_ip") or ""), str(r.get("category") or ""), str(r.get("action") or "")
            ua, methode = str(r.get("user_agent") or ""), str(r.get("method") or "")
            if ip in ("", "local") or ua.startswith(AUTOTEST):
                continue
            famille_cat = cat.split(":", 1)[0]
            if famille_cat not in CATEGORIES_NEUTRES and action != "robot":
                typ = "aspirateur" if famille_cat == "aspirateur_ua" else "sonde"
                self._suspects[ip] = (typ, t + DUREE_SUSPECT)
                if len(self._suspects) > MAX_IP_SUIVIES:
                    for k in sorted(self._suspects, key=lambda k: self._suspects[k][1])[:len(self._suspects) // 10]:
                        del self._suspects[k]
            if action in ACTIONS_BLOQUANTES and methode:       # sans méthode : leurre hors HTTP, pas une visite
                typ = "aspirateur" if famille_cat == "aspirateur_ua" else "sonde"
                self.compter_requete(str(r.get("host") or ""), ip, t, methode, str(r.get("path") or ""), 403, 0, ua,
                                     bloquee=True, type_force=typ)
        return True

    def _bans(self, t: int) -> bool:
        try:
            actuels = self.bans_lecteur()
        except (OSError, ValueError, subprocess.SubprocessError):
            return False
        prec, self._bans_prec = self._bans_prec, actuels
        if prec is None:
            return True                                       # première passe : la ligne de base seulement
        for ip, n in actuels.items():
            delta = n - prec.get(ip, 0) if n >= prec.get(ip, 0) else n
            if delta <= 0:
                continue
            vhost = self._ip_vhost.get(ip, NON_ATTRIBUE)
            for s in self._seaux(t, vhost):
                _inc(s, "b", delta)
                _inc(s, "ba")
        return True

    def _elaguer(self, maintenant: int) -> None:
        h, j = maintenant // 3600, maintenant // 86400
        for k in [k for k in self.heures if k < h - HEURES_GARDEES]:
            del self.heures[k]
        for k in [k for k in self.jours if k < j - JOURS_GARDES]:
            del self.jours[k]
        if self.heures and self.debut_h is not None and self.debut_h < min(self.heures):
            self.debut_h = min(self.heures)
        if self.jours and self.debut_j is not None and self.debut_j < min(self.jours):
            self.debut_j = min(self.jours)
        for k in [k for k in self._rafales if k[0] < h - 1]:
            del self._rafales[k]
        for k in [k for k, s in self._suspects.items() if s[1] < maintenant]:
            del self._suspects[k]

    # ── passe ─────────────────────────────────────────────────────────────
    def collecter(self) -> dict:
        maintenant = int(self.horloge())
        with self._verrou:
            ok_waf = self._waf()          # d'abord : les sondes et aspirateurs connus typent les lignes nginx
            ok_nginx = self._nginx()
            ok_bans = self._bans(maintenant)
            self.clore_sessions(maintenant)
            self._elaguer(maintenant)
            sources = {"nginx": ok_nginx, "waf": ok_waf, "bans": ok_bans}
            neuf = self.construire(maintenant, sources)
        self._persister()
        self._basculer(neuf)
        return self._rapport or neuf

    def _basculer(self, neuf: dict) -> None:
        """Double tampon : un rapport dégradé ne remplace jamais un rapport complet."""
        ancien = self._rapport
        if not neuf["complet"] and ancien and ancien.get("complet"):
            ancien = dict(ancien)
            ancien["passe_degradee"] = {"a": neuf["genere"], "sources": neuf["sources"]}
            self._rapport = ancien
            return
        self._rapport = neuf
        try:
            self._ecrire(self.rapport_f, json.dumps(neuf, separators=(",", ":"), ensure_ascii=False))
        except OSError:
            pass

    def rapport(self) -> dict:
        r = self._rapport
        return r if r is not None else {"complet": False, "vhosts": [], "genere": None, "en_attente": True}

    # ── rapport ───────────────────────────────────────────────────────────
    @staticmethod
    def _somme(table: Dict[int, Dict[str, Dict[str, int]]], vhost: Optional[str], a: int, b: int) -> Dict[str, int]:
        tot: Dict[str, int] = {}
        for k in range(a, b):
            for v, c in table.get(k, {}).items():
                if vhost is None or v == vhost:
                    for cle, n in c.items():
                        tot[cle] = tot.get(cle, 0) + n
        return tot

    @staticmethod
    def _serie(table, vhost: Optional[str], cle: str) -> Dict[int, int]:
        return {k: sum(c.get(cle, 0) for v, c in par.items() if vhost is None or v == vhost) for k, par in table.items()}

    @staticmethod
    def _bloc(c: Dict[str, int]) -> Dict[str, Any]:
        e = c.get("e", 0)
        err = c.get("x4", 0) + c.get("x5", 0)
        histo = {k[2:]: n for k, n in c.items() if k.startswith("d:")}
        ss = c.get("ss", 0)
        return {
            "entree": {"requetes": e, "octets": c.get("eo", 0), "adresses_heure": c.get("a", 0),
                       "par_visite": {t: {"requetes": c.get("v:" + t, 0), "octets": c.get("vo:" + t, 0)} for t in VISITES},
                       "par_page": {p: c.get("p:" + p, 0) for p in PAGES},
                       "croise": {t: {p: c["vp:" + t + ":" + p] for p in PAGES if c.get("vp:" + t + ":" + p)}
                                  for t in VISITES if c.get("v:" + t)}},
            "reductions": {"bans": {"paquets": c.get("b", 0), "adresses": c.get("ba", 0)},
                           "waf": {"requetes": c.get("w", 0)},
                           "erreurs": {"requetes": err, "c4xx": c.get("x4", 0), "c5xx": c.get("x5", 0)},
                           "taux": round((c.get("w", 0) + err) / e, 3) if e else None},
            "sortie": {"requetes": c.get("s", 0), "octets": c.get("so", 0),
                       "taux": round(c.get("s", 0) / e, 3) if e else None},
            "visiteurs": {"sessions": ss, "pages": c.get("sp", 0),
                          "pages_par_session": round(c.get("sp", 0) / ss, 2) if ss else None,
                          "une_page": c.get("s1", 0),
                          "duree_mediane_s": quantile_histo(histo, 0.5), "duree_p75_s": quantile_histo(histo, 0.75)},
        }

    def _vhost(self, vhost: Optional[str], maintenant: int) -> Dict[str, Any]:
        h, j = maintenant // 3600, maintenant // 86400
        fen, tend = {}, {}
        for nom, L, ech in FENETRES:
            table, fin, debut = (self.heures, h, self.debut_h) if ech == "h" else (self.jours, j, self.debut_j)
            fen[nom] = self._bloc(self._somme(table, vhost, fin - L, fin))
            tend[nom] = {m: rupture(self._serie(table, vhost, cle), fin, L, debut, VOLUME_MIN[nom])
                         for m, cle in (("entree", "e"), ("sortie", "s"), ("bans", "b"), ("waf", "w"),
                                        ("erreurs_4xx", "x4"), ("erreurs_5xx", "x5"), ("sessions", "ss"))}
        # « en cours » : l'heure entamée, hors comparaison (incomplète)
        fen["en_cours"] = self._bloc(self._somme(self.heures, vhost, h, h + 1))
        histo = [[self._somme(self.heures, vhost, k, k + 1).get(c, 0) for c in ("e", "s", "w", "b")]
                 for k in range(h - 23, h + 1)]
        return {"vhost": vhost or "(tous)", "fenetres": fen, "tendance": tend,
                "histo_24h": {"colonnes": ["entree", "sortie", "waf", "bans"], "heures": histo}}

    def construire(self, maintenant: int, sources: Dict[str, bool]) -> dict:
        h = maintenant // 3600
        poids: Dict[str, int] = {}
        for k in range(h - 24, h + 1):
            for v, c in self.heures.get(k, {}).items():
                poids[v] = poids.get(v, 0) + c.get("e", 0) + c.get("b", 0)
        retenus = sorted(poids, key=lambda v: -poids[v])[:MAX_VHOSTS_RAPPORT]
        return {
            "version": 1, "genere": datetime.fromtimestamp(maintenant).astimezone().isoformat(timespec="seconds"),
            "complet": all(sources.values()), "sources": sources,
            "regles": {"pause_session_s": PAUSE_SESSION, "seuil_rafale": SEUIL_RAFALE, "facteur": FACTEUR,
                       "robots": "déclaré (UA) ; la vérification DNS de sbxwaf n'est pas journalisée",
                       "octets_entree": "octets des réponses (nginx ne journalise pas la taille des requêtes)",
                       "adresses_heure": "adresses distinctes cumulées heure par heure"},
            "total": self._vhost(None, maintenant),
            "vhosts": [self._vhost(v, maintenant) for v in retenus],
        }

    async def run_forever(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.collecter)
            except Exception:                                 # noqa: BLE001 — la boucle de fond ne meurt jamais
                pass
            await asyncio.sleep(self.intervalle)
