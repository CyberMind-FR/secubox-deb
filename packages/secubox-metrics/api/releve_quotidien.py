# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: metrics :: relevé quotidien des chiffres du rapport de pilotage (#3970)

Deux rôles :

1. La COLLECTE commune au relevé et au rapport de pilotage : des lecteurs bornés, en flux, des sources réelles de la box (journal des
   menaces du WAF et ses rotations compressées, journal des bans, propositions de ban, compteurs DNS, compteurs nginx par jour,
   historique de disponibilité, sonde des temps de réponse, contrôles de santé, acteurs suivis). Chaque lecteur rend `None` quand la
   source manque : une mesure absente est « non mesuré », jamais 0, jamais estimée.
2. Le RELEVÉ : une ligne JSON par jour de Paris (`releve-AAAAMM.jsonl`, un fichier par mois, 13 mois gardés, écriture atomique,
   ligne bornée), pour qu'un rapport mensuel trouve plus tard les jours que les journaux tournés ont oubliés.

Aucune adresse IP n'est écrite dans le relevé : les adresses ne servent qu'à compter (bans distincts, propositions en attente).
Usage : `python3 -m api.releve_quotidien` (minuterie quotidienne) ; `--jour AAAA-MM-JJ` pour un jour précis.
"""
from __future__ import annotations

import gzip
import http.client
import ipaddress
import json
import os
import re
import socket
import sqlite3
import sys
import time
import zlib
from collections import Counter
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional
from urllib.parse import quote
from zoneinfo import ZoneInfo

PARIS = ZoneInfo("Europe/Paris")

# ── sources (lecture seule) ───────────────────────────────────────────────
MENACES = Path("/var/log/secubox/waf/waf-threats.log")
BANS = Path("/var/lib/secubox/waf/bans.jsonl")
MESURES = Path("/var/lib/secubox/waf/mesures.jsonl")
POPULATIONS = Path("/var/lib/secubox/waf/populations.json")
DNSTV = Path("/var/lib/secubox/ad-guard/dnstv/dnstv.db")
NGINX_JOURS = Path("/var/cache/secubox/metrics/vhost-jours.json")
DISPO_JOURS = Path("/var/lib/secubox-status/disponibilite.json")
SONDE = Path("/var/cache/secubox/health/status.json")
DOCTEUR = Path("/var/cache/secubox/health-doctor.json")
ACTOR_SOCK = "/run/secubox/actor.sock"
GEOIP = (Path("/var/lib/secubox/geoip/GeoLite2-Country.mmdb"), Path("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
         Path("/var/lib/GeoIP/GeoLite2-Country.mmdb"))
# Le relevé : chemin par variable d'environnement (rien n'est créé à l'import).
RELEVES_DEFAUT = "/var/lib/secubox/metrics/releve"

# ── plafonds (mémoire et temps bornés sur une box arm64 chargée) ──────────
LIGNE_MAX = 64 * 1024              # une ligne plus longue est ignorée (comptée illisible)
BUDGET_MENACES = 512 << 20         # octets décompressés lus au plus dans les journaux de menaces
BUDGET_BANS = 64 << 20
BUDGET_MESURES = 32 << 20
JSON_MAX = 8 << 20                 # fichiers JSON d'état lus au plus
CLES_MAX = 2000                    # clés distinctes au plus par compteur (sites, catégories, pays) ; au-delà : « autres »
IPS_MAX = 200_000                  # adresses distinctes retenues au plus pour compter (jamais écrites)
GEO_CACHE_MAX = 20_000
RELEVE_LIGNE_MAX = 32 * 1024       # une ligne de relevé ne dépasse jamais cette taille
RELEVE_FICHIER_MAX = 4 << 20
RELEVE_MOIS = 13
SONDE_PERIMEE_S = 15 * 60
DOCTEUR_PERIME_S = 15 * 60
DISPO_RELEVES_MIN = 1296           # relevés connus exigés pour dire la disponibilité d'un jour (90 % des 1440 minutes)
DELAI_ACTORD_S = 8.0

# Contrôles vitaux du docteur de santé (son REGISTRY) : un échec y est un service vital en panne.
VITAUX = ("haproxy", "nginx", "secubox-metrics", "secubox-hub", "gitea-lxc", "mail-lxc", "cookie-audit-ledger", "filesystems",
          "waf-selftest", "clamav")

# Couches du journal des menaces (même lecture que les dossiers du WAF, #3963).
COUCHE = {"banned": "arrete", "warning": "refuse", "leurre_redirige": "detourne", "detect": "passe", "robot": "robots"}
BLOQUANTES = ("arrete", "refuse", "detourne")
HOSTILES = ("arrete", "refuse", "detourne", "passe")

_RE_TS = re.compile(rb'"timestamp"\s*:\s*"([^"]{10,40})"')
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"[0-9A-Fa-f]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f.]*")


# ── jours de Paris ────────────────────────────────────────────────────────
def jour_de(ts: float) -> str:
    return datetime.fromtimestamp(ts, PARIS).date().isoformat()


def bornes(jour: str) -> tuple[float, float]:
    """[début, fin[ du jour de Paris, en secondes epoch (les jours de 23 h et 25 h compris)."""
    d = date.fromisoformat(jour)
    t0 = datetime(d.year, d.month, d.day, tzinfo=PARIS).timestamp()
    s = d + timedelta(days=1)
    return t0, datetime(s.year, s.month, s.day, tzinfo=PARIS).timestamp()


def jours_entre(debut: str, fin: str) -> list[str]:
    a, b = date.fromisoformat(debut), date.fromisoformat(fin)
    return [(a + timedelta(days=i)).isoformat() for i in range((b - a).days + 1)]


def hier(maintenant: Optional[float] = None) -> str:
    m = datetime.fromtimestamp(time.time() if maintenant is None else maintenant, PARIS).date()
    return (m - timedelta(days=1)).isoformat()


def sans_ip(texte: str) -> str:
    """Toute adresse IP restée dans un texte est masquée : rien ne sort du rapport qui désigne une machine."""
    t = _RE_IPV4.sub("[adresse]", str(texte))
    return _RE_IPV6.sub(lambda m: "[adresse]" if _est_ip(m.group(0)) else m.group(0), t)


def _est_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def nom_site(host: Any) -> str:
    h = str(host or "").strip().lower()
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
    elif h.count(":") == 1:
        h = h.split(":", 1)[0]
    if not h:
        return "(sans nom)"
    if _est_ip(h):
        return "(adresse IP nue)"
    return h[:80]


# ── lecture bornée en flux ────────────────────────────────────────────────
class Budget:
    def __init__(self, octets: int):
        self.reste = octets
        self.epuise = False


def lignes(chemin: Path, budget: Budget, compteur: Optional[Counter] = None) -> Iterator[bytes]:
    """Les lignes d'un fichier clair ou .gz, en flux. Une ligne > LIGNE_MAX est sautée ; le budget épuisé arrête la lecture."""
    ouvrir = gzip.open if str(chemin).endswith(".gz") else open
    with ouvrir(chemin, "rb") as f:
        while True:
            if budget.reste <= 0:
                budget.epuise = True
                return
            ligne = f.readline(LIGNE_MAX + 1)
            if not ligne:
                return
            budget.reste -= len(ligne)
            if len(ligne) > LIGNE_MAX and not ligne.endswith(b"\n"):
                while True:                                    # reste de la ligne trop longue : jeté sans le garder
                    bout = f.readline(LIGNE_MAX)
                    budget.reste -= len(bout)
                    if not bout or bout.endswith(b"\n"):
                        break
                if compteur is not None:
                    compteur["trop_longues"] += 1
                continue
            yield ligne


def fichiers_rotation(base: Path) -> list[Path]:
    """Le journal et ses rotations, du plus récent au plus ancien : base, base.1, base.2.gz, …"""
    out = [base] if base.exists() else []
    for i in range(1, 60):
        for c in (Path(f"{base}.{i}"), Path(f"{base}.{i}.gz")):
            if c.exists():
                out.append(c)
                break
    return out


def _ts(v: Any) -> Optional[float]:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if isinstance(v, str):
        try:
            d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
        if d.tzinfo is None:
            d = d.replace(tzinfo=PARIS)
        return d.timestamp()
    return None


def _plus(c: Counter, cle: str, n: int = 1) -> None:
    """Compteur plafonné : une clé nouvelle au-delà de CLES_MAX va dans « autres »."""
    if cle in c or len(c) < CLES_MAX:
        c[cle] += n
    else:
        c["autres"] += n


# ── journal des menaces du WAF ────────────────────────────────────────────
def _jour_vierge() -> dict:
    return {"couches": Counter(), "categories": Counter(), "heures": [0] * 24, "sites_bloques": Counter(), "sites_hostiles": Counter(),
            "pays": {}}


class Menaces:
    """Comptes par jour de Paris : couches, catégories bloquées, heures, sites, pays. Aucune adresse n'est gardée."""

    def __init__(self, geo: Optional[Callable[[str], Optional[str]]] = None):
        self.jours: dict[str, dict] = {}
        self.ts_min: Optional[float] = None
        self.ts_max: Optional[float] = None
        self.lus = 0
        self.erreurs: Counter = Counter()
        self.geo = geo

    def ajouter(self, e: dict) -> None:
        ts = _ts(e.get("timestamp"))
        couche = COUCHE.get(str(e.get("action") or ""))
        if ts is None or couche is None:
            self.erreurs["incompletes"] += 1
            return
        self.lus += 1
        self.ts_min = ts if self.ts_min is None else min(self.ts_min, ts)
        self.ts_max = ts if self.ts_max is None else max(self.ts_max, ts)
        j = self.jours.setdefault(jour_de(ts), _jour_vierge())
        n = 1
        if couche == "detourne":
            s = e.get("servies")
            n = min(10_000, s) if isinstance(s, int) and not isinstance(s, bool) and s >= 1 else 1
        j["couches"][couche] += n
        if couche not in HOSTILES:
            return
        site = nom_site(e.get("host"))
        _plus(j["sites_hostiles"], site, n)
        bloque = couche in BLOQUANTES
        if bloque:
            _plus(j["categories"], str(e.get("category") or "?")[:60], n)
            _plus(j["sites_bloques"], site, n)
            j["heures"][datetime.fromtimestamp(ts, PARIS).hour] += n
        if self.geo is not None:
            cc = self.geo(str(e.get("client_ip") or ""))
            if cc:
                if cc not in j["pays"] and len(j["pays"]) >= CLES_MAX:
                    cc = "autres"
                p = j["pays"].setdefault(cc, [0, 0])
                p[0] += n
                if bloque:
                    p[1] += n

    def fusionner(self, autre: "Menaces") -> None:
        for jour, a in autre.jours.items():
            j = self.jours.setdefault(jour, _jour_vierge())
            j["couches"].update(a["couches"])
            for k in ("categories", "sites_bloques", "sites_hostiles"):
                for c, n in a[k].items():
                    _plus(j[k], c, n)
            j["heures"] = [x + y for x, y in zip(j["heures"], a["heures"])]
            for cc, (h, b) in a["pays"].items():
                p = j["pays"].setdefault(cc, [0, 0])
                p[0] += h
                p[1] += b
        for v in (autre.ts_min,):
            if v is not None:
                self.ts_min = v if self.ts_min is None else min(self.ts_min, v)
        if autre.ts_max is not None:
            self.ts_max = autre.ts_max if self.ts_max is None else max(self.ts_max, autre.ts_max)
        self.lus += autre.lus
        self.erreurs.update(autre.erreurs)


def lire_menaces(base: Path = MENACES, depuis: Optional[float] = None, geo=None, budget_octets: int = BUDGET_MENACES) -> Optional[Menaces]:
    """Les journaux du plus récent au plus ancien. Un fichier n'est compté que s'il est lu EN ENTIER : la couverture reste continue
    (`ts_min` = plus vieille ligne lue), et un budget épuisé laisse les jours plus anciens « non mesurés ». Aucun fichier : None."""
    fichiers = fichiers_rotation(base)
    if not fichiers:
        return None
    total = Menaces(geo)
    budget = Budget(budget_octets)
    for ch in fichiers:
        try:
            mtime = ch.stat().st_mtime
            if depuis is not None and mtime < depuis:
                # Plus ancien que la fenêtre (les suivants aussi) : sa dernière ligne date au plus de `mtime`, donc la
                # couverture des fichiers plus récents remonte jusque-là.
                total.erreurs["fichiers_anciens_ignores"] += 1
                total.ts_min = mtime if total.ts_min is None else min(total.ts_min, mtime)
                break
            part = Menaces(geo)
            for brut in lignes(ch, budget, part.erreurs):
                m = _RE_TS.search(brut, 0, 200)
                if m and depuis is not None:
                    t = _ts(m.group(1).decode("ascii", "replace"))
                    if t is not None and t < depuis:
                        part.ts_min = t if part.ts_min is None else min(part.ts_min, t)
                        continue
                try:
                    e = json.loads(brut)
                except ValueError:
                    part.erreurs["illisibles"] += 1
                    continue
                if isinstance(e, dict):
                    part.ajouter(e)
                else:
                    part.erreurs["illisibles"] += 1
        except (OSError, EOFError, zlib.error) as ex:
            total.erreurs["fichiers_illisibles"] += 1
            total.erreurs[f"arret:{type(ex).__name__}"] += 1
            break
        if budget.epuise:
            total.erreurs["budget_epuise"] += 1
            break
        total.fusionner(part)
    return total


def jour_couvert(jour: str, ts_min: Optional[float], ts_fin: Optional[float]) -> bool:
    """Un jour est mesuré par une source si elle couvre le jour en entier : sa plus vieille donnée est antérieure à son début et
    la source a été lue après sa fin."""
    if ts_min is None or ts_fin is None:
        return False
    t0, t1 = bornes(jour)
    return ts_min <= t0 and ts_fin >= t1


# ── géolocalisation (optionnelle) ─────────────────────────────────────────
def ouvrir_geo(chemins: Iterable[Path] = GEOIP) -> Optional[Callable[[str], Optional[str]]]:
    """Pays d'une adresse publique par la base GeoLite2-Country ; None si la bibliothèque ou la base manque."""
    try:
        import maxminddb  # noqa: PLC0415 — dépendance du paquet, absente des postes de développement
    except ImportError:
        return None
    lecteur = None
    for ch in chemins:
        try:
            lecteur = maxminddb.open_database(str(ch))
            break
        except (OSError, ValueError):
            continue
    if lecteur is None:
        return None
    cache: dict[str, Optional[str]] = {}

    def pays(ip: str) -> Optional[str]:
        if ip in cache:
            return cache[ip]
        cc = None
        try:
            a = ipaddress.ip_address(ip)
            if a.is_global:
                r = lecteur.get(ip) or {}
                cc = ((r.get("country") or r.get("registered_country") or {}).get("iso_code")) or None
        except ValueError:
            cc = None
        if len(cache) < GEO_CACHE_MAX:
            cache[ip] = cc
        return cc
    return pays


# ── journal des bans ──────────────────────────────────────────────────────
def lire_bans(chemin: Path = BANS, depuis: Optional[float] = None, budget_octets: int = BUDGET_BANS) -> Optional[dict]:
    """Par jour de Paris : bans posés (hors prolongations), adresses distinctes bannies, prolongations. Garde aussi, pour compter
    les propositions en attente, le dernier ban de chaque adresse (en mémoire seulement, plafonné). Fichier absent : None."""
    try:
        taille = os.path.getsize(chemin)
    except OSError:
        return None
    par_jour: dict[str, dict] = {}
    ips_jour: dict[str, set] = {}
    dernier_ban: dict[str, float] = {}
    erreurs: Counter = Counter()
    ts_min: Optional[float] = None
    budget = Budget(budget_octets)
    try:
        for brut in lignes(chemin, budget, erreurs):
            try:
                e = json.loads(brut)
            except ValueError:
                erreurs["illisibles"] += 1
                continue
            if not isinstance(e, dict) or not isinstance(e.get("at"), (int, float)) or not e.get("ip"):
                erreurs["incompletes"] += 1
                continue
            at = float(e["at"])
            ts_min = at if ts_min is None else min(ts_min, at)
            if e.get("action") != "ban" or (depuis is not None and at < depuis):
                continue
            ip = str(e["ip"])
            if ip in dernier_ban or len(dernier_ban) < IPS_MAX:
                dernier_ban[ip] = max(dernier_ban.get(ip, 0.0), at)
            j = jour_de(at)
            d = par_jour.setdefault(j, {"bans": 0, "adresses": 0, "prolongations": 0})
            if "|prolonge" in str(e.get("cat") or ""):
                d["prolongations"] += 1
            else:
                d["bans"] += 1
                s = ips_jour.setdefault(j, set())
                if len(s) < IPS_MAX:
                    s.add(ip)
    except OSError:
        return None
    for j, s in ips_jour.items():
        par_jour[j]["adresses"] = len(s)
    return {"jours": par_jour, "ts_min": ts_min, "dernier_ban": dernier_ban, "erreurs": dict(erreurs), "taille": taille,
            "budget_epuise": budget.epuise}


def lire_attente(chemin: Path = MESURES, dernier_ban: Optional[dict] = None, depuis: Optional[float] = None,
                 budget_octets: int = BUDGET_MESURES) -> Optional[dict]:
    """Adresses proposées au ban (décision « a_bannir », mode proposition) depuis `depuis` et qu'aucun ban n'a suivies. On ne rend
    que des NOMBRES. Journal absent (mesures désactivées) : None."""
    if not Path(chemin).exists():
        return None
    proposees: dict[str, float] = {}
    plus_ancienne: Optional[float] = None
    budget = Budget(budget_octets)
    try:
        for brut in lignes(Path(chemin), budget):
            try:
                e = json.loads(brut)
            except ValueError:
                continue
            if not isinstance(e, dict) or e.get("decision") != "a_bannir" or not isinstance(e.get("ts"), (int, float)):
                continue
            ts = float(e["ts"])
            if depuis is not None and ts < depuis:
                continue
            ip = str(e.get("ip") or "")
            if ip and (ip in proposees or len(proposees) < IPS_MAX):
                proposees[ip] = max(proposees.get(ip, 0.0), ts)
    except OSError:
        return None
    db = dernier_ban or {}
    attente = [ts for ip, ts in proposees.items() if db.get(ip, 0.0) < ts]
    if attente:
        plus_ancienne = min(attente)
    return {"proposees": len(proposees), "en_attente": len(attente), "plus_ancienne": plus_ancienne}


# ── compteurs DNS (ad-guard, jours UTC) ───────────────────────────────────
def _sqlite_ro(chemin: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{quote(str(chemin))}?mode=ro", uri=True, timeout=5)


def lire_dns(chemin: Path = DNSTV, debut: str = "", fin: str = "") -> Optional[dict]:
    """Par jour UTC (clé de la base) : requêtes vues, requêtes filtrées, domaines filtrés distincts. Un jour sans ligne n'est pas
    mesuré (le flux du capteur a pu être arrêté). Base absente ou illisible : None."""
    if not Path(chemin).exists():
        return None
    try:
        with closing(_sqlite_ro(Path(chemin))) as cx:
            rows = cx.execute("SELECT jour, decision, SUM(hits), COUNT(DISTINCT domaine) FROM dnstv_counts WHERE jour >= ? AND jour <= ? "
                              "GROUP BY jour, decision", (debut, fin)).fetchall()
    except (sqlite3.Error, OSError):
        return None
    out: dict[str, dict] = {}
    for jour, decision, hits, domaines in rows:
        d = out.setdefault(str(jour), {"requetes": 0, "filtrees": 0, "domaines": 0})
        d["requetes"] += int(hits or 0)
        if decision == "BLOCKED":
            d["filtrees"] += int(hits or 0)
            d["domaines"] += int(domaines or 0)
    return out


# ── compteurs nginx par jour (résumé léger écrit par le service metrics) ──
def lire_json(chemin: Path, maxi: int = JSON_MAX) -> Any:
    try:
        with open(chemin, "rb") as f:
            brut = f.read(maxi + 1)
        if len(brut) > maxi:
            return None
        return json.loads(brut)
    except (OSError, ValueError):
        return None


def lire_nginx(chemin: Path = NGINX_JOURS) -> Optional[dict]:
    """{jours: {jour: {requetes, visites, robots, sondes, erreurs, par_site}}, depuis, maj} ; None si le résumé manque."""
    d = lire_json(chemin)
    if not isinstance(d, dict) or not isinstance(d.get("jours"), dict):
        return None
    return d


def nginx_jour(d: Optional[dict], jour: str) -> Optional[dict]:
    """Le jour est mesuré s'il est entre le début du suivi et la dernière mise à jour (un jour absent est alors un 0 réel)."""
    if not d:
        return None
    depuis, maj = str(d.get("depuis") or ""), str(d.get("maj") or "")
    if not depuis or not maj or jour < depuis or maj[:10] <= jour:
        return None
    j = (d.get("jours") or {}).get(jour) or {}
    tot = {"requetes": 0, "visites": 0, "robots": 0, "sondes": 0, "erreurs": 0}
    sites: Counter = Counter()
    for site, s in j.items():
        if not isinstance(s, dict):
            continue
        for k in tot:
            tot[k] += int(s.get(k) or 0)
        sites[nom_site(site)] += int(s.get("requetes") or 0)
    tot["par_site"] = dict(sites.most_common(15))
    return tot


# ── disponibilité (Status Live) ───────────────────────────────────────────
def lire_dispo(chemin: Path = DISPO_JOURS, jours: Iterable[str] = (), noeud: Optional[str] = None) -> Optional[dict]:
    """Part des relevés « operational » parmi les relevés connus, par jour de Paris, d'après le résumé exporté par Status Live
    (`disponibilite.json`, une fois l'heure). Un jour n'est mesuré qu'avec au moins DISPO_RELEVES_MIN relevés connus. Résumé
    absent ou d'un autre nœud que `noeud` (s'il est donné) : None."""
    jours = list(jours)
    d = lire_json(chemin)
    if not jours or not isinstance(d, dict) or not isinstance(d.get("jours"), dict):
        return None
    if noeud and d.get("noeud") != noeud:
        return None
    out: dict[str, Optional[float]] = {}
    for j in jours:
        e = d["jours"].get(j)
        connus = int(e.get("connus") or 0) if isinstance(e, dict) else 0
        pannes = e.get("pannes") if isinstance(e, dict) else None
        # Disponible = relevé connu qui n'est pas une panne (« outage ») ; « degraded » (un site qui refuse, un module en veille) reste
        # un service rendu. Sans le compte des pannes (secubox-status < 0.1.6), le jour n'est pas mesuré : jamais déduit d'« operational ».
        ok = isinstance(pannes, int) and not isinstance(pannes, bool) and 0 <= pannes <= connus
        out[j] = round(100.0 * (connus - pannes) / connus, 3) if ok and connus >= DISPO_RELEVES_MIN else None
    return out


# ── sonde des temps de réponse et contrôles de santé (instantanés) ────────
def _code(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def confirmer_injoignables(premier: Optional[dict], second: Optional[dict]) -> Optional[dict]:
    """Un site n'est injoignable que s'il l'est à deux relevés CONSÉCUTIFS de la sonde (instants différents) ; sans second relevé
    plus récent, la liste n'est pas confirmée (vide), jamais supposée."""
    if premier is None:
        return None
    r = dict(premier)
    if not premier.get("injoignables"):
        return r
    if not second or second.get("instant") is None or second.get("instant") == premier.get("instant"):
        r["injoignables"] = []
        r["injoignables_non_confirmes"] = len(premier["injoignables"])
        return r
    deux = set(second.get("injoignables") or [])
    r["injoignables"] = [x for x in premier["injoignables"] if x in deux]
    return r


def latence_confirmee(maintenant: Optional[float] = None, attendre: Callable[[float], None] = time.sleep, essais: int = 6) -> Optional[dict]:
    """Lit la sonde ; si des sites semblent injoignables, attend le relevé suivant (au plus 6 × 15 s) pour confirmer."""
    a = lire_latence(maintenant=maintenant)
    if not a or not a.get("injoignables"):
        return a
    b = None
    for _ in range(essais):
        attendre(15)
        b = lire_latence()
        if b and b.get("instant") != a.get("instant"):
            break
    return confirmer_injoignables(a, b)


def lire_latence(chemin: Path = SONDE, maintenant: Optional[float] = None) -> Optional[dict]:
    """Médiane des temps de réponse des sites joints, sites lents et injoignables, au moment du relevé. Sonde périmée : None."""
    d = lire_json(chemin)
    if not isinstance(d, dict) or not isinstance(d.get("vhosts"), dict):
        return None
    t = _ts(d.get("timestamp"))
    maintenant = time.time() if maintenant is None else maintenant
    if t is None or maintenant - t > SONDE_PERIMEE_S:
        return None
    lat, lents, bas = [], [], []
    for nom, v in d["vhosts"].items():
        if not isinstance(v, dict):
            continue
        st = v.get("status")
        if st in ("ok", "slow") and isinstance(v.get("latency_ms"), (int, float)):
            lat.append(float(v["latency_ms"]))
            if st == "slow":
                lents.append((nom_site(nom), float(v["latency_ms"])))
        elif st == "down" and (v.get("error") == "timeout" or _code(v.get("status_code")) >= 500):
            # Même règle que les situations du SOC : « down » compte aussi les refus voulus (401, 403, 404) et les
            # redirections ; seuls un délai dépassé ou une erreur 5xx disent une panne.
            bas.append(nom_site(nom))
    if not lat and not bas:
        return None
    lat.sort()
    med = (lat[len(lat) // 2] if len(lat) % 2 else (lat[len(lat) // 2 - 1] + lat[len(lat) // 2]) / 2) if lat else None
    return {"mediane_ms": None if med is None else round(med, 1), "sites": len(lat) + len(bas), "lents": sorted(lents, key=lambda x: -x[1])[:5],
            "injoignables": sorted(bas)[:10], "instant": t}


def lire_sante(chemin: Path = DOCTEUR, maintenant: Optional[float] = None) -> Optional[dict]:
    """Contrôles du docteur de santé : vitaux en échec (une veille voulue n'en est pas une), avertissements. Périmé : None."""
    d = lire_json(chemin)
    if not isinstance(d, dict) or not isinstance(d.get("checks"), dict):
        return None
    t = _ts(d.get("generated_at"))
    maintenant = time.time() if maintenant is None else maintenant
    if t is None or maintenant - t > DOCTEUR_PERIME_S:
        return None
    vitaux_ko, avert, ok = [], [], 0
    for nom, c in d["checks"].items():
        if not isinstance(c, dict):
            continue
        if c.get("ok"):
            ok += 1
            continue
        if c.get("niveau") == "avertissement":
            avert.append(str(nom))
        elif str(nom) in VITAUX:
            vitaux_ko.append(str(nom))
        else:
            avert.append(str(nom))
    return {"total": len(d["checks"]), "ok": ok, "vitaux_ko": sorted(vitaux_ko), "avertissements": sorted(avert), "instant": t}


# ── acteurs suivis (actord, vue réduite) ──────────────────────────────────
class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, chemin: str, delai: float):
        super().__init__("actord", timeout=delai)
        self._chemin = chemin

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._chemin)


def actord(chemin_api: str, sock: str = ACTOR_SOCK, delai: float = DELAI_ACTORD_S) -> Any:
    """Lecture de la VUE RÉDUITE d'actord (préfixe /api/v1/actor : jamais d'adresse ni de cible). None si actord ne répond pas."""
    try:
        c = _UnixHTTP(sock, delai)
        c.request("GET", chemin_api, headers={"Accept": "application/json"})
        r = c.getresponse()
        corps = r.read(JSON_MAX)
        c.close()
        return json.loads(corps) if r.status == 200 else None
    except (OSError, ValueError, http.client.HTTPException):
        return None


def lire_acteurs(lire: Callable[[str], Any] = actord, n: int = 6) -> Optional[dict]:
    """Les acteurs les plus risqués du radar, avec leur fiche réduite (adresses, bans, activité par jour UTC). None si actord est muet."""
    radar = lire("/api/v1/actor/radar?limit=30")
    if not isinstance(radar, dict) or not isinstance(radar.get("acteurs"), list):
        return None
    tries = sorted((a for a in radar["acteurs"] if isinstance(a, dict) and a.get("id")),
                   key=lambda a: -float((a.get("risque") or {}).get("valeur") or 0))
    out = []
    for a in tries[:n]:
        fiche = lire(f"/api/v1/actor/actors/{quote(str(a['id']), safe='')}")
        fiche = fiche if isinstance(fiche, dict) else {}
        det = fiche.get("detail") if isinstance(fiche.get("detail"), dict) else {}
        jours = det.get("jours") if isinstance(det.get("jours"), dict) else None
        out.append({"id": str(a["id"]), "niveau": a.get("niveau"), "action": a.get("action_proposee"), "scenario": a.get("scenario") or "",
                    "risque": (a.get("risque") or {}).get("valeur"), "confiance": (a.get("confiance") or {}).get("valeur"),
                    "evenements": a.get("evenements"), "mesure": a.get("mesure") if isinstance(a.get("mesure"), dict) else None,
                    "adresses": (fiche.get("src") or {}).get("ips") if fiche else None, "bans": fiche.get("bans") if fiche else None,
                    "tags": [t[0] for t in (fiche.get("tags") or []) if isinstance(t, (list, tuple)) and t][:3],
                    "jours": jours})
    return {"suivis": len(tries), "a_bloquer": sum(1 for a in tries if a.get("niveau") == "BLOCK" and not a.get("mesure")),
            "acteurs": out, "genere_le": radar.get("genere_le")}


def lire_populations(chemin: Path = POPULATIONS) -> Optional[dict]:
    d = lire_json(chemin)
    if not isinstance(d, dict) or not isinstance(d.get("populations"), list):
        return None
    return d


# ── résumé d'un jour ──────────────────────────────────────────────────────
def resume_waf(m: Optional[Menaces], jour: str, lu_le: float) -> Optional[dict]:
    if m is None or not jour_couvert(jour, m.ts_min, lu_le):
        return None
    j = m.jours.get(jour) or _jour_vierge()
    c = j["couches"]
    return {"couches": {k: int(c.get(k, 0)) for k in ("arrete", "refuse", "detourne", "passe", "robots")},
            "bloquees": int(sum(c.get(k, 0) for k in BLOQUANTES)), "hostiles": int(sum(c.get(k, 0) for k in HOSTILES)),
            "categories": dict(j["categories"].most_common(12)), "heures": list(j["heures"]),
            "sites_bloques": dict(j["sites_bloques"].most_common(15)), "sites_hostiles": dict(j["sites_hostiles"].most_common(15)),
            "pays": None if m.geo is None else dict(sorted(j["pays"].items(), key=lambda kv: -kv[1][0])[:25])}


def resume_bans(b: Optional[dict], jour: str, lu_le: float) -> Optional[dict]:
    if not b or not jour_couvert(jour, b.get("ts_min"), lu_le):
        return None
    return dict((b.get("jours") or {}).get(jour) or {"bans": 0, "adresses": 0, "prolongations": 0})


def collecter_jours(jours: list[str], maintenant: Optional[float] = None, geo="auto", sources: Optional[dict] = None) -> dict:
    """Les résumés par jour de Paris pour `jours` (lecture unique de chaque source). `sources` remplace des lecteurs (tests)."""
    maintenant = time.time() if maintenant is None else maintenant
    s = sources or {}
    depuis = bornes(jours[0])[0] - 3600
    g = ouvrir_geo() if geo == "auto" else geo
    m = s["menaces"] if "menaces" in s else lire_menaces(depuis=depuis, geo=g)
    b = s["bans"] if "bans" in s else lire_bans(depuis=depuis)
    dns = s["dns"] if "dns" in s else lire_dns(debut=jours[0], fin=jours[-1])
    ngx = s["nginx"] if "nginx" in s else lire_nginx()
    dispo = s["dispo"] if "dispo" in s else lire_dispo(jours=jours)
    out = {}
    for j in jours:
        out[j] = {"jour": j, "waf": resume_waf(m, j, maintenant), "bans": resume_bans(b, j, maintenant),
                  "dns": (dns or {}).get(j) if dns is not None else None, "nginx": nginx_jour(ngx, j),
                  "dispo": (dispo or {}).get(j) if dispo is not None else None, "latence": None, "sante": None, "acteurs": None,
                  "attente": None}
    return {"jours": out, "bans_brut": b, "menaces_erreurs": dict(m.erreurs) if m else None}


# ── le relevé : écriture atomique, rotation par mois, ligne bornée ────────
def dossier_releves() -> Path:
    return Path(os.environ.get("SECUBOX_RELEVE_DIR", RELEVES_DEFAUT))


def _fichier_mois(dossier: Path, jour: str) -> Path:
    return dossier / f"releve-{jour[:4]}{jour[5:7]}.jsonl"


def borner(resume: dict, maxi: int = RELEVE_LIGNE_MAX) -> str:
    """La ligne JSON du jour, sous `maxi` octets : les listes longues sont raccourcies d'abord, puis les détails retirés."""
    r = json.loads(json.dumps(resume, default=str))
    ligne = json.dumps(r, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    for garde in (10, 5, 3, 0):
        if len(ligne.encode()) <= maxi:
            return ligne
        w = r.get("waf") or {}
        for k in ("pays", "sites_bloques", "sites_hostiles", "categories"):
            if isinstance(w.get(k), dict):
                w[k] = dict(sorted(w[k].items(), key=lambda kv: -(kv[1][0] if isinstance(kv[1], list) else kv[1]))[:garde]) if garde else None
        ng = r.get("nginx") or {}
        if isinstance(ng.get("par_site"), dict):
            ng["par_site"] = dict(list(ng["par_site"].items())[:garde]) if garde else None
        for k in ("latence", "sante", "acteurs"):
            if isinstance(r.get(k), dict) and not garde:
                r[k] = None
        ligne = json.dumps(r, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(ligne.encode()) > maxi:
        raise ValueError("relevé trop long même réduit")
    return ligne


def lire_mois(chemin: Path) -> dict:
    """{jour: résumé} d'un fichier de mois ; lignes corrompues ou trop longues ignorées, fichier trop gros lu jusqu'au plafond."""
    out: dict[str, dict] = {}
    if not chemin.exists():
        return out
    try:
        for brut in lignes(chemin, Budget(RELEVE_FICHIER_MAX)):
            try:
                e = json.loads(brut)
            except ValueError:
                continue
            if isinstance(e, dict) and isinstance(e.get("jour"), str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", e["jour"]):
                out[e["jour"]] = e
    except OSError:
        return {}
    return out


def ecrire_releve(dossier: Path, resume: dict) -> Path:
    """Remplace (ou ajoute) la ligne du jour dans le fichier de son mois : fichier temporaire du même dossier, fsync, renommage."""
    jour = resume["jour"]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(jour)):
        raise ValueError("jour invalide")
    dossier.mkdir(mode=0o750, parents=True, exist_ok=True)
    cible = _fichier_mois(dossier, jour)
    tous = lire_mois(cible)
    tous[jour] = json.loads(borner(resume))
    contenu = "".join(borner(tous[j]) + "\n" for j in sorted(tous))
    tmp = cible.with_name(f".{cible.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(contenu)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, cible)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return cible


def purger(dossier: Path, aujourdhui: Optional[date] = None, mois: int = RELEVE_MOIS) -> list[str]:
    """Retire les fichiers de mois plus vieux que les `mois` derniers (le mois courant compris)."""
    a = aujourdhui or datetime.now(PARIS).date()
    rang = a.year * 12 + a.month - 1
    retires = []
    if not dossier.is_dir():
        return retires
    for f in dossier.iterdir():
        m = re.fullmatch(r"releve-(\d{4})(\d{2})\.jsonl", f.name)
        if m and f.is_file() and not f.is_symlink() and rang - (int(m.group(1)) * 12 + int(m.group(2)) - 1) >= mois:
            f.unlink()
            retires.append(f.name)
    return sorted(retires)


def lire_releves(dossier: Path, jours: Iterable[str]) -> dict:
    jours = list(jours)
    out: dict[str, dict] = {}
    for mois in sorted({j[:7] for j in jours}):
        for j, e in lire_mois(_fichier_mois(dossier, mois + "-01")).items():
            if j in jours:
                out[j] = e
    return out


def releve(jours: Optional[list[str]] = None, maintenant: Optional[float] = None, dossier: Optional[Path] = None,
           sources: Optional[dict] = None, instantanes: Optional[dict] = None) -> dict:
    """Écrit le relevé d'hier (instantanés compris : temps de réponse, santé, acteurs, propositions en attente) et rattrape les
    jours des 7 derniers absents du relevé, pour ce que les sources gardent encore (sans instantané : il ne vaut que pour l'instant)."""
    maintenant = time.time() if maintenant is None else maintenant
    dossier = dossier or dossier_releves()
    h = hier(maintenant)
    if jours is None:
        fen = jours_entre((date.fromisoformat(h) - timedelta(days=6)).isoformat(), h)
        deja = lire_releves(dossier, fen)
        jours = [j for j in fen if j not in deja] or [h]
        if h not in jours:
            jours.append(h)
    c = collecter_jours(sorted(jours), maintenant, sources=sources)
    inst = instantanes if instantanes is not None else {
        "latence": latence_confirmee(maintenant=maintenant), "sante": lire_sante(maintenant=maintenant), "acteurs": None, "attente": None}
    if instantanes is None:
        a = lire_acteurs()
        inst["acteurs"] = None if a is None else {"suivis": a["suivis"], "a_bloquer": a["a_bloquer"]}
        bb = c.get("bans_brut") or {}
        att = lire_attente(dernier_ban=bb.get("dernier_ban"), depuis=maintenant - 7 * 86400)
        inst["attente"] = None if att is None else {"en_attente": att["en_attente"], "proposees": att["proposees"]}
    ecrits = []
    for j in sorted(jours):
        r = dict(c["jours"][j])
        if j == h:
            r.update({k: inst.get(k) for k in ("latence", "sante", "acteurs", "attente")})
        r["v"] = 1
        r["ecrit_le"] = datetime.fromtimestamp(maintenant, timezone.utc).isoformat()
        ecrire_releve(dossier, r)
        ecrits.append(j)
    retires = purger(dossier, datetime.fromtimestamp(maintenant, PARIS).date())
    return {"ecrits": ecrits, "retires": retires, "dossier": str(dossier)}


def main(argv: Optional[list[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    jours = None
    if len(args) == 2 and args[0] == "--jour" and re.fullmatch(r"\d{4}-\d{2}-\d{2}", args[1]):
        jours = [args[1]]
    elif args:
        print("usage : python3 -m api.releve_quotidien [--jour AAAA-MM-JJ]", file=sys.stderr)
        return 2
    try:
        r = releve(jours)
    except (OSError, ValueError) as e:
        print(f"relevé quotidien : échec : {e}", file=sys.stderr)
        return 1
    print(f"relevé quotidien : {', '.join(r['ecrits'])} écrit(s) dans {r['dossier']}" + (f" ; retirés : {', '.join(r['retires'])}" if r["retires"] else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
