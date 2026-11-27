# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Profil déduit des populations et ruptures par couches (#4005).

Trois choses, toutes par RÈGLES déterministes (« l'IA propose, le code décide ») :

  · le PROFIL d'une population : empreinte (user-agents), méthodes, classes de pages, vhosts, retours après relâchement,
    et une LECTURE FACTUELLE en français où chaque phrase porte son chiffre (jamais une adresse) ;
  · les RUPTURES : pour chaque mesure de base, la fenêtre courante (1 h, 8 h, 1 j, 7 j) comparée à la médiane des
    fenêtres précédentes de même longueur ; une couche = une mesure, un calcul lisible ;
  · la DOUBLE LECTURE : bans posés et adresses bannies neuves comptés depuis bans.jsonl ET depuis le journal des menaces,
    les deux valeurs publiées avec un indicateur d'écart.

Calcul pur sur des compteurs ; seules `lire_bans` et `lire_relaches` lisent des fichiers (en flux, bornés). Appelé par
le processus de calcul des populations (populations.rafraichir), jamais par une route."""
import gzip
import ipaddress
import json
import os
import re
import zlib
from datetime import datetime
from statistics import median
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

QUART = 900                      # pas des séries : le quart d'heure
FENETRES = (("1h", 4), ("8h", 32), ("1j", 96), ("7j", 672))
VOLUME_MIN = {"1h": 10, "8h": 30, "1j": 50, "7j": 200}   # en dessous, pas de hausse annoncée (bruit)
FACTEUR = 3.0                    # hausse : courant ≥ 3 × médiane ; baisse : courant ≤ médiane / 3
N_PRECEDENTES = 6                # fenêtres précédentes comparées (au plus)
MIN_PRECEDENTES = 3              # en dessous : « historique insuffisant », jamais une rupture
RODAGE_Q = 96                    # mesures « neuves » : la première journée d'historique ne compte pas (tout y est neuf)
TOLERANCE_ABS, TOLERANCE_REL = 5, 0.20   # double lecture : écart signalé au-delà de max(5, 20 %)
MAX_VHOSTS_RUPTURES = 8
HISTO_JOURS = 7                  # mini-histogramme de chaque mesure : 7 totaux journaliers
BANS_JOURS = 36                  # bans.jsonl : de quoi comparer 7 j à 4 semaines précédentes
RELACHES_JOURS = 30

MAX_UA, MAX_PAGES, MAX_VHOSTS, MAX_METHODES, MAX_PAIRES = 500, 100, 100, 16, 1000
SEP = "\x1f"                     # séparateur user-agent / vhost des paires (absent d'un en-tête HTTP lisible)
UA_LONGUEUR = 160
MIN_REQUETES_LECTURE = 50        # sous ce volume, pas de lecture (trop peu pour qualifier)

_SEGMENT = re.compile(r"^[A-Za-z0-9._~-]{1,40}$")
_IDENT = re.compile(r"^(?:[0-9]+|[0-9a-fA-F]{12,})$")
_METHODE = re.compile(r"^[A-Z]{1,10}$")
VERBES_FORGE = frozenset(("src", "blame", "raw", "commits", "commit", "tree", "archive", "releases", "tags", "branches",
                          "issues", "pulls", "wiki", "activity", "compare", "media", "rss", "atom", "graph", "find",
                          "search", "stars", "forks", "watchers", "settings", "actions", "packages", "projects"))
QUALIFS_FORGE = frozenset(("commit", "branch", "tag"))
HORS_HTTP = "(hors HTTP)"
COMPTE = "(compte)"


# ── classes de pages ────────────────────────────────────────────────────────────────────────────────────────────

def classer_page(methode: Any, chemin: Any, auth: bool = False) -> str:
    """La classe d'une page, sans rien de variable : `/<u>/<r>/src/commit/<sha>/…` → « src/commit ». Un chemin
    d'authentification est un compte (jamais gardé) ; une ligne sans méthode n'est pas du HTTP (leurre de service)."""
    if auth:
        return COMPTE
    if not isinstance(methode, str) or not methode:
        return HORS_HTTP
    c = chemin if isinstance(chemin, str) else ""
    c = c.split("?", 1)[0].split("#", 1)[0]
    segs = [s for s in c.split("/") if s]
    if not segs:
        return "/"
    if len(segs) >= 3 and segs[2] in VERBES_FORGE:            # forge (Gitea, Forgejo) : /<compte>/<dépôt>/<verbe>/…
        if len(segs) >= 4 and segs[3] in QUALIFS_FORGE:
            return segs[2] + "/" + segs[3]
        return segs[2]
    s = segs[0]
    tete = "/*" if not _SEGMENT.match(s) or _IDENT.match(s) else "/" + s
    return tete + ("/…" if len(segs) > 1 else "")


# ── profil : compteurs d'une clé (famille ou rotation:<hex>) ─────────────────────────────────────────────────────

def profil_vide() -> Dict[str, Any]:
    return {"n": 0, "ua": {}, "ua_hors": 0, "m": {}, "p": {}, "v": {}, "uv": {}}


def _compter(d: Dict[str, int], cle: str, k: int, plafond: int) -> bool:
    if cle in d:
        d[cle] += k
        return True
    if len(d) < plafond:
        d[cle] = k
        return True
    return False


def ajouter(pr: Dict[str, Any], ua: Any, methode: Any, page: str, vhost: str) -> None:
    pr["n"] += 1
    u = ua[:UA_LONGUEUR].replace(SEP, " ") if isinstance(ua, str) else ""
    if not _compter(pr["ua"], u, 1, MAX_UA):
        pr["ua_hors"] += 1
    m = methode if isinstance(methode, str) and _METHODE.match(methode) else "-"
    _compter(pr["m"], m, 1, MAX_METHODES)
    _compter(pr["p"], page, 1, MAX_PAGES)
    if vhost:
        _compter(pr["v"], vhost, 1, MAX_VHOSTS)
        _compter(pr["uv"], u + SEP + vhost, 1, MAX_PAIRES)


def fusionner(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    dst["n"] += src["n"]
    dst["ua_hors"] += src["ua_hors"]
    for cle, plafond in (("ua", MAX_UA), ("m", MAX_METHODES), ("p", MAX_PAGES), ("v", MAX_VHOSTS), ("uv", MAX_PAIRES)):
        for k, n in src[cle].items():
            if not _compter(dst[cle], k, n, plafond) and cle == "ua":
                dst["ua_hors"] += n


def profil_valide(pr: Any) -> bool:
    """Un profil relu de la réserve est exactement de la forme écrite, sinon le journal est relu."""
    if not isinstance(pr, dict) or set(pr) != {"n", "ua", "ua_hors", "m", "p", "v", "uv"}:
        return False
    if type(pr["n"]) is not int or type(pr["ua_hors"]) is not int or pr["n"] < 0 or pr["ua_hors"] < 0:
        return False
    for cle, plafond, long_max in (("ua", MAX_UA, UA_LONGUEUR), ("m", MAX_METHODES, 10), ("p", MAX_PAGES, 64),
                                   ("v", MAX_VHOSTS, 253), ("uv", MAX_PAIRES, UA_LONGUEUR + 254)):
        d = pr[cle]
        if not isinstance(d, dict) or len(d) > plafond:
            return False
        if not all(isinstance(k, str) and len(k) <= long_max and type(v) is int and v > 0 for k, v in d.items()):
            return False
    return True


def _tri(d: Dict[str, int]) -> List[Tuple[str, int]]:
    return sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))


def _part(k: int, n: int) -> int:
    return (k * 100 + n // 2) // n if n else 0


def rendre_profil(pr: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Les chiffres publiés : parts entières, 5 premières valeurs ; le premier user-agent tel que lu (donnée hostile,
    affichée en textContent par la page)."""
    if not pr or not pr["n"]:
        return None
    n = pr["n"]
    uas = _tri(pr["ua"])
    cible_ua: List[Any] = []
    if uas:          # la cible principale du premier user-agent, en part de SES requêtes
        prefixe = uas[0][0] + SEP
        siennes = [(k[len(prefixe):], v) for k, v in pr["uv"].items() if k.startswith(prefixe)]
        if siennes:
            h, v = max(siennes, key=lambda kv: (kv[1], kv[0]))
            cible_ua = [h, _part(v, uas[0][1])]
    sortie = {
        "requetes": n,
        "ua_distincts": len(pr["ua"]) + (1 if pr["ua_hors"] else 0),
        "ua_plafond": bool(pr["ua_hors"]),
        "ua_premier": uas[0][0] if uas else "",
        "ua_premier_part": _part(uas[0][1], n) if uas else 0,
        "ua_premier_cible": cible_ua,
        "methodes": [[k, _part(v, n)] for k, v in _tri(pr["m"])[:5]],
        "pages": [[k, _part(v, n)] for k, v in _tri(pr["p"])[:5]],
        "vhosts": [[k, _part(v, n)] for k, v in _tri(pr["v"])[:5]],
    }
    return sortie


# ── lecture factuelle ───────────────────────────────────────────────────────────────────────────────────────────

def nombre(n: int) -> str:
    """12345 → « 12 345 » (séparateur de milliers français)."""
    return f"{int(n):,}".replace(",", " ")


def _duree(s: float) -> str:
    if s < 3600:
        return f"{max(1, round(s / 60))} min"
    if s < 2 * 86400:
        return f"{round(s / 3600)} h"
    return f"{round(s / 86400)} j"


def lecture(pop: Dict[str, Any], profil: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Les phrases qui s'appliquent, chacune adossée à un chiffre (`valeur`) et à un code stable. Aucune adresse."""
    res: List[Dict[str, Any]] = []

    def dire(code: str, valeur: Any, texte: str) -> None:
        res.append({"code": code, "valeur": valeur, "texte": texte})

    if profil and profil["requetes"] >= MIN_REQUETES_LECTURE:
        n, d, part = profil["requetes"], profil["ua_distincts"], profil["ua_premier_part"]
        if d == 1:
            dire("empreinte_unique", 100, "Empreinte unique : 1 user-agent pour 100 % des requêtes.")
        elif part >= 80:
            dire("empreinte_dominante", part,
                 f"Empreinte dominante : un même user-agent pour {part} % des requêtes ({nombre(d)} user-agents"
                 f"{' ou plus' if profil['ua_plafond'] else ''} au total).")
        elif part >= 50:
            dire("empreinte_majoritaire", part,
                 f"Empreinte majoritaire : un même user-agent pour {part} % des requêtes ({nombre(d)} user-agents"
                 f"{' ou plus' if profil['ua_plafond'] else ''} au total).")
        elif d >= 50 and d * 100 >= 20 * max(pop.get("adresses") or 0, 1):
            dire("empreintes_variees", d, f"Empreintes variées : {nombre(d)} user-agents distincts"
                 f"{' ou plus' if profil['ua_plafond'] else ''} pour {nombre(n)} requêtes.")
        cu = profil.get("ua_premier_cible") or []
        if d > 1 and part >= 50 and cu and cu[1] >= 90:
            dire("empreinte_ciblee", cu[1], f"Empreinte ciblée : ce user-agent vise {cu[0]} pour {cu[1]} % de ses requêtes.")
        meth = profil["methodes"]
        if meth and meth[0][0] == "GET" and meth[0][1] >= 95:
            dire("lecture_seule", meth[0][1], f"Lecture seule : {meth[0][1]} % de GET.")
        pages = [p for p in profil["pages"] if p[0] not in (HORS_HTTP, COMPTE)]
        if pages and sum(p[1] for p in pages[:3]) >= 60:
            liste = ", ".join(f"{p[0]} ({p[1]} %)" for p in pages[:3])
            dire("pages_visees", sum(p[1] for p in pages[:3]), f"Pages visées : {liste}.")
        vh = profil["vhosts"]
        if vh and vh[0][1] >= 90:
            dire("cible_unique", vh[0][1], f"Cible unique : {vh[0][1]} % des requêtes sur {vh[0][0]}.")
    classes = pop.get("classes") or {}
    loue = (classes.get("proxy_loue") or 0) + (classes.get("hebergeur") or 0)
    if (pop.get("adresses") or 0) >= 20 and loue >= 80:
        dire("infrastructure_louee", loue, f"Infrastructure louée : {loue} % d'adresses chez des hébergeurs/proxys.")
    if (pop.get("adresses") or 0) >= 1000 and pop.get("blocs24"):
        dire("dispersion", pop["blocs24"], f"Dispersion : {nombre(pop['adresses'])} adresses sur "
             f"{nombre(pop['blocs24'])} réseaux /24.")
    r = pop.get("retours")
    if r and r.get("relachees", 0) >= 100:
        rel, ret = r["relachees"], r["retours"]
        delai = f", délai médian {_duree(r['delai_median_s'])}" if r.get("delai_median_s") else ""
        if ret * 100 <= 5 * rel:
            dire("adresses_jetables", ret, f"Adresses jetables : {nombre(ret)} retours sur {nombre(rel)} relâchées{delai}.")
        elif ret * 100 >= 30 * rel:
            dire("retours_frequents", ret, f"Retours fréquents : {nombre(ret)} retours sur {nombre(rel)} relâchées{delai}.")
    serie = pop.get("serie") or []
    if serie:
        pic = max(serie)
        aujourd = serie[-1]
        if pic >= 1000 and aujourd * 10 <= pic:
            dire("vague_eteinte", aujourd,
                 f"Vague éteinte : {nombre(aujourd)} requêtes aujourd'hui contre {nombre(pic)} au pic.")
        elif len(serie) >= 4 and aujourd >= 100 and aujourd >= 3 * max(median(serie[:-1]), 1):
            dire("vague_en_cours", aujourd, f"Vague en cours : {nombre(aujourd)} requêtes aujourd'hui, "
                 f"{round(aujourd / max(median(serie[:-1]), 1), 1)} fois la médiane des jours précédents.")
    return res


# ── sources externes : bans.jsonl, reevaluations.jsonl ─────────────────────────────────────────────────────────

def _fichiers(dossier: str, base: str, maintenant: float, mois: int = 2) -> List[str]:
    """`<base>.jsonl` et les archives `<base>-AAAAMM.jsonl.gz` des `mois` derniers mois, le courant en dernier."""
    d = datetime.fromtimestamp(maintenant)
    noms = []
    a, m = d.year, d.month
    for _ in range(mois):
        noms.append(f"{base}-{a:04d}{m:02d}.jsonl.gz")
        a, m = (a, m - 1) if m > 1 else (a - 1, 12)
    return [os.path.join(dossier, x) for x in reversed(noms)] + [os.path.join(dossier, base + ".jsonl")]


def _lignes(chemin: str) -> Iterator[str]:
    """Lignes d'un fichier (gz ou non) ; absent : rien ; illisible : OSError remontée."""
    try:
        f = gzip.open(chemin, "rt", encoding="utf-8", errors="replace") if chemin.endswith(".gz") \
            else open(chemin, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return
    with f:
        yield from f


def lire_relaches(dossier: str, maintenant: float) -> Tuple[Dict[str, float], bool]:
    """adresse → première relâche (RELEASE) des RELACHES_JOURS derniers jours ; (dict, lisible)."""
    depuis = maintenant - RELACHES_JOURS * 86400
    rel: Dict[str, float] = {}
    try:
        for chemin in _fichiers(dossier, "reevaluations", maintenant):
            for brut in _lignes(chemin):
                if '"RELEASE"' not in brut:
                    continue
                try:
                    e = json.loads(brut)
                except ValueError:
                    continue
                ip, ts = (e.get("ip"), e.get("ts")) if isinstance(e, dict) else (None, None)
                if e.get("decision") != "RELEASE" or not isinstance(ip, str) or not isinstance(ts, (int, float)):
                    continue
                if depuis <= ts <= maintenant + 300 and (ip not in rel or ts < rel[ip]) and len(rel) < 400_000:
                    rel[ip] = float(ts)
    except (OSError, EOFError, zlib.error):
        return rel, False
    return rel, True


class BansLus:
    """Ce que bans.jsonl apporte : bans neufs (pas une prolongation) par quart d'heure, premier ban de chaque adresse,
    et le premier ban NEUF qui suit la relâche de chaque adresse relâchée. Seules les familles comptées par les
    populations entrent (même prédicat que le journal : la double lecture compare la même chose)."""

    def __init__(self):
        self.quarts: Dict[int, int] = {}
        self.premier: Dict[str, float] = {}
        self.retour: Dict[str, float] = {}
        self.debut_q: Optional[int] = None
        self.lisible = True


UA_AUTOTEST = "SecuBox-WAF-SelfTest/"   # auto-test du WAF (health-doctor) : ses lignes ne sont pas une attaque


def est_autotest(ua: Any) -> bool:
    return isinstance(ua, str) and ua.startswith(UA_AUTOTEST)


def lire_bans(dossier: str, maintenant: float, relaches: Dict[str, float], famille, publique=None) -> BansLus:
    """`publique(ip)` : l'adresse normalisée si elle compte (même règle que le journal : l'auto-test du WAF frappe
    depuis une adresse de documentation, ses bans réels sont ainsi écartés) ; None = toutes comptent."""
    b = BansLus()
    depuis = maintenant - BANS_JOURS * 86400
    utiles: Dict[str, bool] = {}
    try:
        for chemin in _fichiers(dossier, "bans", maintenant):
            for brut in _lignes(chemin):
                try:
                    e = json.loads(brut)
                except ValueError:
                    continue
                if not isinstance(e, dict) or e.get("action") != "ban":
                    continue
                ip, cat, at = e.get("ip"), e.get("cat"), e.get("at")
                if not isinstance(ip, str) or not isinstance(cat, str) or not isinstance(at, (int, float)):
                    continue
                if at < depuis or at > maintenant + 300 or "|prolonge" in cat:
                    continue
                if publique is not None:
                    ip = publique(ip)
                    if ip is None:
                        continue
                ok = utiles.get(cat)
                if ok is None:
                    ok = famille(cat) != "autre"
                    if len(utiles) < 10_000:
                        utiles[cat] = ok
                if not ok:
                    continue
                q = int(at // QUART)
                b.debut_q = q if b.debut_q is None or q < b.debut_q else b.debut_q
                b.quarts[q] = b.quarts.get(q, 0) + 1
                if ip not in b.premier or at < b.premier[ip]:
                    if ip in b.premier or len(b.premier) < 400_000:
                        b.premier[ip] = float(at)
                r = relaches.get(ip)
                if r is not None and at > r + 60 and (ip not in b.retour or at < b.retour[ip]):
                    b.retour[ip] = float(at)
    except (OSError, EOFError, zlib.error):
        b.lisible = False
    return b


def retours_population(adresses: Iterable[str], relaches: Dict[str, float], retour: Dict[str, float]) -> Optional[Dict[str, Any]]:
    """Relâchées de la population, combien rebannies (ban neuf, pas une prolongation) et le délai médian."""
    if not relaches:
        return None
    delais = []
    rel = 0
    for ip in adresses:
        r = relaches.get(ip)
        if r is None:
            continue
        rel += 1
        t = retour.get(ip)
        if t is not None:
            delais.append(t - r)
    return {"relachees": rel, "retours": len(delais), "delai_median_s": int(median(delais)) if delais else None}


# ── ruptures ────────────────────────────────────────────────────────────────────────────────────────────────────

def bloc24(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return str(ipaddress.ip_network(f"{ip}/24" if a.version == 4 else f"{ip}/48", strict=False))


def premieres_vues(premiers: Dict[Any, float]) -> Dict[int, int]:
    """Clé → première vue : nombre de clés NEUVES par quart d'heure."""
    q: Dict[int, int] = {}
    for t in premiers.values():
        k = int(t // QUART)
        q[k] = q.get(k, 0) + 1
    return q


def rupture(quarts: Dict[int, int], fin: int, longueur: int, debut_valide: Optional[int], volume_min: int) -> Dict[str, Any]:
    """Fenêtre courante [fin-L, fin) contre la médiane des N_PRECEDENTES fenêtres précédentes entièrement couvertes
    par l'historique (à partir de `debut_valide`). `fin` exclu : le quart d'heure en cours, incomplet, ne compte pas."""
    def somme(a: int, b: int) -> int:
        return sum(quarts.get(i, 0) for i in range(a, b))

    courant = somme(fin - longueur, fin)
    prec = []
    for k in range(1, N_PRECEDENTES + 1):
        a = fin - (k + 1) * longueur
        if debut_valide is None or a < debut_valide:
            break
        prec.append(somme(a, a + longueur))
    r: Dict[str, Any] = {"courant": courant}
    if len(prec) < MIN_PRECEDENTES or (debut_valide is not None and fin - longueur < debut_valide):
        r["sens"] = "insuffisant"
        return r
    med = median(prec)
    r["mediane"] = med
    r["fenetres"] = len(prec)
    if courant >= volume_min and courant >= FACTEUR * max(med, 1):
        r["sens"], r["facteur"] = "hausse", round(courant / max(med, 1), 1)
    elif med >= volume_min and courant * FACTEUR <= med:
        r["sens"], r["facteur"] = "baisse", round(med / max(courant, 1), 1)
    else:
        r["sens"] = "stable"
    return r


def _jours(quarts: Dict[int, int], fin: int) -> List[int]:
    """Les HISTO_JOURS derniers totaux sur 24 h glissantes (le plus ancien d'abord), pour le mini-histogramme."""
    return [sum(quarts.get(i, 0) for i in range(fin - (k + 1) * 96, fin - k * 96)) for k in reversed(range(HISTO_JOURS))]


def couche(ident: str, libelle: str, source: str, quarts: Dict[int, int], fin: int, debut_valide: Optional[int],
           echelle: float = 1.0) -> Dict[str, Any]:
    return {"id": ident, "libelle": libelle, "source": source, "jours": _jours(quarts, fin),
            "fenetres": {nom: rupture(quarts, fin, L, debut_valide, max(1, int(VOLUME_MIN[nom] * echelle)))
                         for nom, L in FENETRES}}


def ecart(a: int, b: int) -> bool:
    return abs(a - b) > max(TOLERANCE_ABS, TOLERANCE_REL * max(a, b))


def double_lecture(c: Dict[str, Any], autre: Dict[int, int], source: str, fin: int, debut_commun: Optional[int],
                   quarts_a: Dict[int, int]) -> None:
    """Pose `double` sur la couche `c` : sur chaque fenêtre couverte par les DEUX sources, les deux valeurs et l'écart."""
    vals = {}
    for nom, L in FENETRES:
        if debut_commun is None or fin - L < debut_commun:
            continue
        a = sum(quarts_a.get(i, 0) for i in range(fin - L, fin))
        b = sum(autre.get(i, 0) for i in range(fin - L, fin))
        vals[nom] = {"a": a, "b": b, "ecart": ecart(a, b)}
    c["double"] = {"source_b": source, "valeurs": vals, "ecart": any(v["ecart"] for v in vals.values())}


def ruptures(maintenant: float, journal: Dict[str, Dict[int, int]], debut_journal: Optional[int],
             neufs_journal: Dict[str, Dict[Any, float]], bans: Optional[BansLus]) -> Dict[str, Any]:
    """Toutes les couches. `journal` : séries par quart du journal des menaces (`f:<famille>`, `v:<hôte>`, `b` bans
    vus au journal) ; `neufs_journal` : premières vues par adresse (`adresses`, `blocs24`, `asn`, `bannies`)."""
    fin = int(maintenant // QUART)
    rodage = debut_journal + RODAGE_Q if debut_journal is not None else None
    couches: List[Dict[str, Any]] = []
    neuves_j = {k: premieres_vues(v) for k, v in neufs_journal.items()}

    if bans is not None and bans.lisible:
        c = couche("bans_poses", "Bans posés", "bans.jsonl", bans.quarts, fin, bans.debut_q)
        double_lecture(c, journal.get("b", {}), "journal", fin, max(bans.debut_q or 0, debut_journal or 0)
                       if bans.debut_q is not None and debut_journal is not None else None, bans.quarts)
        couches.append(c)
        # adresses bannies neuves : les deux sources sur leur historique COMMUN (une adresse vue avant le début du journal
        # n'est pas « neuve » pour bans.jsonl et le serait pour le journal)
        commun = max(bans.debut_q, debut_journal) if bans.debut_q is not None and debut_journal is not None else None
        b_neuves = premieres_vues(bans.premier)
        c = couche("bannies_neuves", "Adresses bannies neuves", "bans.jsonl", b_neuves, fin,
                   bans.debut_q + RODAGE_Q if bans.debut_q is not None else None)
        if commun is not None:
            depuis_commun = commun * QUART
            a_commun = premieres_vues({ip: t for ip, t in bans.premier.items() if t >= depuis_commun})
            b_commun = premieres_vues({ip: t for ip, t in neufs_journal.get("bannies", {}).items() if t >= depuis_commun})
            double_lecture(c, b_commun, "journal", fin, commun + RODAGE_Q, a_commun)
        couches.append(c)
    couches.append(couche("adresses_neuves", "Adresses neuves", "journal", neuves_j.get("adresses", {}), fin, rodage))
    couches.append(couche("blocs24_neufs", "Réseaux /24 neufs", "journal", neuves_j.get("blocs24", {}), fin, rodage, 0.5))
    couches.append(couche("asn_neufs", "Opérateurs (ASN) neufs", "journal", neuves_j.get("asn", {}), fin, rodage, 0.2))
    for cle in sorted(k for k in journal if k.startswith("f:")):
        couches.append(couche("alertes:" + cle[2:], "Alertes " + cle[2:].replace("_", " "), "journal", journal[cle],
                              fin, debut_journal))
    vh = sorted((k for k in journal if k.startswith("v:")), key=lambda k: (-sum(journal[k].values()), k))
    for cle in vh[:MAX_VHOSTS_RUPTURES]:
        couches.append(couche("vhost:" + cle[2:], "Alertes sur " + cle[2:], "journal", journal[cle], fin, debut_journal))
    signalees = sum(1 for c in couches for f in c["fenetres"].values() if f["sens"] in ("hausse", "baisse"))
    return {"pas_s": QUART, "facteur": FACTEUR, "couches": couches, "signalees": signalees,
            "ecarts": sum(1 for c in couches if c.get("double", {}).get("ecart")),
            "bans_lisibles": bans is not None and bans.lisible}
