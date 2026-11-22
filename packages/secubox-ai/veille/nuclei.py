# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tour de filtres WAF Nuclei (#3862), porté du POC gk0 (`relais/filtres.py`, #3732/#3745) : modèles Nuclei →
filtres, gravité (KEV de la CISA, EPSS de FIRST/cyentia), vérification locale, versions, lots, ordre et quota.

Deux processus s'en servent, sans jamais partager une clé :

- le COLLECTEUR (`secubox-ai-nuclei.service`, oneshot horaire, AUCUNE clé, réseau sortant vers GitHub, CISA, cyentia)
  appelle `tour_collecteur` : dépôt git `--depth 1` (taille bornée), KEV et EPSS en cache 24 h, filtres vérifiés
  localement et versionnés, écrits dans `candidats.json` (écriture atomique, 0640, forme versionnée, taille bornée)
  avec `etat.json` (dernier tour, compteurs, erreur) ;
- la VEILLE (`veille/apprentissage.py`, réseau fermé sauf gk2, clé `ai-filtres`) ne lit QUE `lire_candidats` et
  `lire_etat_collecteur` : le fichier est une DONNÉE, revalidée en entier (forme, taille, id recalculé) ; aucune
  fonction de téléchargement n'y est appelée.

Anti-invention : un filtre ne vient QUE d'un modèle Nuclei lu en YAML (`yaml.safe_load`, jamais exécuté), et son motif
est une sous-chaîne exacte du texte du modèle (aucun décodage : une cible portant « % » ou « ? » est écartée). gk2
revérifie tout (forme, spécificité, trafic légitime, produit présent, plafonds).

Identifiants, empreintes et versions IDENTIQUES au POC (`ia-<cve>-<sha1(motif)[:6]>`, `_empreinte`) : les filtres que
gk0 a posés sur gk2 sont reconnus « inchangés » (même id, même version), jamais dupliqués ni retirés.

Interrupteur : `[filtres] nuclei = true` dans /etc/secubox/ai.toml ; éteint par défaut (absent, autre valeur, fichier
illisible), le collecteur ne fait rien et la veille n'envoie rien.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import logging
import os
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

import httpx

log = logging.getLogger("secubox-ai-nuclei")

DOSSIER = Path(os.environ.get("SECUBOX_AI_NUCLEI", "/var/lib/secubox/ai/nuclei"))
#: Compte DÉDIÉ du collecteur (groupe secubox-ai) : seul propriétaire admis de candidats.json et etat.json.
COMPTE_COLLECTEUR = "secubox-ai-nuclei"
#: Liste de refus de l'opérateur (un id par ligne, facultative, root, jamais inscriptible par le groupe ou les autres).
REFUSES = Path("/etc/secubox/ai/filtres-refuses.txt")
REFUSES_MAX_OCTETS = 64 * 1024
#: Propriétaires admis de la liste de refus : root seul.
PROPRIETAIRES_REFUSES = frozenset({0})
DEPOT = DOSSIER / "depot"
SOURCES = DOSSIER
VERSIONS = DOSSIER / "versions.json"
CANDIDATS = DOSSIER / "candidats.json"
ETAT = DOSSIER / "etat.json"
CONF = "/etc/secubox/ai.toml"
#: Options git imposées à chaque appel (#3862, S3) : ni crochet, ni fsmonitor, https seul, objets vérifiés, liens
#: symboliques extraits comme de simples fichiers.
GIT_OPTIONS = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.allow=never",
               "-c", "protocol.https.allow=always", "-c", "transfer.fsckObjects=true", "-c", "core.symlinks=false")
GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
STDERR_MAX = 400
REDIRECTIONS_MAX = 5

URL_NUCLEI = "https://github.com/projectdiscovery/nuclei-templates.git"
URL_NUCLEI_FICHIER = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
URL_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URL_KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
URL_EPSS = "https://epss.cyentia.com/epss_scores-current.csv.gz"
URL_EPSS_API = "https://api.first.org/data/v1/epss?cve="
AGENT = {"User-Agent": "secubox-ai-nuclei/1"}
CACHE_S = 86400
LOT_MAX = 50
LOT_OCTETS = 15 * 1024
MODELE_MAX = 256 * 1024
TELECHARGEMENT_MAX = 64 << 20
DECOMPRESSE_MAX = 256 << 20
SPECIFICITE_MIN = 8
#: Bornes du collecteur (#3862) : dépôt cloné, espace libre exigé, fichier de candidats.
DEPOT_MAX_OCTETS = 1 << 30
ESPACE_MIN_OCTETS = 1 << 30
CANDIDATS_MAX = 20000
CANDIDATS_MAX_OCTETS = 16 << 20
ETAT_MAX_OCTETS = 64 * 1024
FORME = 1
DELAI_GIT_S = 900

FAMILLES = ("rce", "lfi", "sqli", "auth_bypass", "ssrf", "deserialisation", "xss", "traversal", "divulgation", "autre")
#: Étiquette Nuclei → famille, dans l'ordre de priorité (la plus grave d'abord).
_ETIQUETTES = (("rce", "rce"), ("deserialization", "deserialisation"), ("sqli", "sqli"), ("lfi", "lfi"),
               ("traversal", "traversal"), ("ssrf", "ssrf"), ("auth-bypass", "auth_bypass"), ("xss", "xss"),
               ("exposure", "divulgation"))
_CHAMPS = ("id", "version", "cve", "produit", "famille", "motif_type", "motif", "parametre", "kev", "epss", "cvss",
           "sources")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
PARAMETRE_RE = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,64}$")
_BASES = ("{{BaseURL}}", "{{RootURL}}")
_LIGNE_RAW = re.compile(r"^[A-Z]{3,10} (\S+) HTTP/[0-9.]+$")
_TYPES_SOURCE = ("nuclei", "kev", "epss")

#: F1 (#3862, faux positif de production sur gk2 le 22/11 : `ia-cve-2025-8110-c109f2` = /user/login, la page de
#: connexion de Gitea, 40 bans à tort en 4 h). Chemins que visite un usager légitime : jamais un filtre, quelle que
#: soit la méthode de la requête du modèle (sbxwaf compare le chemin, pas la méthode). Liste fermée, après
#: normalisation (minuscules, « / » répétés réduits, « / » final retiré).
CHEMINS_LEGITIMES = frozenset({
    "/", "/login", "/user/login", "/users/login", "/signin", "/sign_in", "/sign-in", "/users/sign_in",
    "/user/sign_in", "/auth", "/auth/login", "/account/login", "/accounts/login", "/session", "/sessions",
    "/admin", "/administrator", "/index.php", "/index.html", "/index.htm", "/index.jsp", "/index.asp",
    "/index.aspx", "/default.aspx", "/default.asp", "/wp-login.php", "/wp-admin", "/api", "/dashboard", "/home",
    "/logout", "/user", "/users", "/register", "/signup", "/explore", "/portal", "/console", "/webui", "/ui",
    "/owa", "/owa/auth/logon.aspx", "/remote/login", "/cgi-bin/luci", "/manager/html",
    "/wp-admin/admin-ajax.php", "/xmlrpc.php", "/wp-json", "/graphql", "/api/v1",
})
#: Dernier segment d'une page d'accueil ou d'authentification courante (sans extension) : jamais un filtre.
PAGES_LEGITIMES = frozenset({"index", "login", "signin", "sign_in", "sign-in", "logon", "default", "home", "dashboard",
                             "welcome", "main", "start", "logout", "signout", "sign_out"})
_EXTENSIONS_PAGES = ("", ".php", ".html", ".htm", ".jsp", ".jspx", ".asp", ".aspx", ".do", ".action", ".cgi", ".py",
                     ".json", ".shtml", ".xhtml", ".jsf")


def normaliser_chemin(motif: str) -> str:
    c = re.sub(r"/{2,}", "/", motif.strip().lower())
    while True:                               # « /./ » réduits (« /a/./b », « /./ », « /. » final)
        d = re.sub(r"/\.(?=/|$)", "", c)
        if d == c:
            break
        c = d
    c = re.sub(r"/{2,}", "/", c)
    return c.rstrip("/") or "/"


def chemin_legitime(motif: str) -> bool:
    """Vrai si le chemin est la racine, une page d'authentification ou d'accueil courante (F1)."""
    c = normaliser_chemin(motif)
    if c in CHEMINS_LEGITIMES:
        return True
    dernier = c.rsplit("/", 1)[-1]
    for ext in _EXTENSIONS_PAGES:
        if ext and dernier.endswith(ext):
            if dernier[:-len(ext)] in PAGES_LEGITIMES:
                return True
        elif dernier in PAGES_LEGITIMES:
            return True
    return False


def _requete_de_detection(doc: dict) -> bool:
    """F1 : l'unique requête est un GET (ou HEAD) sans corps et le modèle ne fait que RECONNAÎTRE un produit ou sa
    version (étiquette `passive`, `compare_versions`, extracteur `version`) : il charge une page légitime, le filtre
    toucherait les usagers."""
    b = (doc.get("http") or doc.get("requests"))[0]
    if b.get("path"):
        methode, corps = str(b.get("method") or "GET").upper(), b.get("body")
    else:
        brut = str(b["raw"][0]).strip()
        lignes = [x for x in brut.splitlines() if not x.strip().startswith("@")]
        methode = (lignes[0].split() or ["GET"])[0].upper() if lignes else "GET"
        corps = brut.split("\n\n", 1)[1].strip() if "\n\n" in brut else ""
    if methode not in ("GET", "HEAD") or corps:
        return False
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    tags = info.get("tags")
    tags = tags.split(",") if isinstance(tags, str) else (tags or [])
    if "passive" in {str(t).strip().lower() for t in tags}:
        return True
    texte = json.dumps([b.get("matchers"), b.get("extractors")], default=str)
    if "compare_versions" in texte:
        return True
    return any(isinstance(e, dict) and str(e.get("name", "")).lower() == "version" for e in b.get("extractors") or [])


# ── Modèle Nuclei → filtre (identique au POC) ──────────────────────────
def _famille(tags) -> str:
    if isinstance(tags, str):
        tags = tags.split(",")
    vus = {str(t).strip().lower() for t in tags or []}
    for etiquette, famille in _ETIQUETTES:
        if etiquette in vus:
            return famille
    return "autre"


def _cible_unique(doc: dict):
    """(cible brute telle qu'écrite dans le modèle, chemin+requête relatif) de l'UNIQUE requête HTTP, sinon None."""
    if set(doc) & {"code", "javascript", "flow", "dns", "network", "tcp", "headless", "ssl", "websocket", "file"}:
        return None
    blocs = doc.get("http", doc.get("requests"))
    if not isinstance(blocs, list) or len(blocs) != 1 or not isinstance(blocs[0], dict):
        return None
    b = blocs[0]
    chemins, raws = b.get("path") or [], b.get("raw") or []
    if not isinstance(chemins, list) or not isinstance(raws, list) or len(chemins) + len(raws) != 1:
        return None
    if b.get("payloads") or b.get("fuzzing"):
        return None
    if chemins:
        p = chemins[0]
        if not isinstance(p, str):
            return None
        for base in _BASES:
            if p.startswith(base):
                rel = p[len(base):]
                return rel, rel
        return None
    r = raws[0]
    if not isinstance(r, str):
        return None
    lignes = [x.strip() for x in r.strip().splitlines() if x.strip() and not x.strip().startswith("@")]
    m = _LIGNE_RAW.match(lignes[0]) if lignes else None
    if not m:
        return None
    return m.group(1), m.group(1)


def _motif(rel: str):
    """(motif_type, motif, parametre) depuis le chemin relatif BRUT, ou None. Anti-invention : aucun décodage — une
    cible portant « % » ou « ? » est écartée, le motif est donc toujours une sous-chaîne exacte du modèle."""
    if "{{" in rel or "}}" in rel or not rel.startswith("/") or "#" in rel or "%" in rel or "?" in rel:
        return None
    if not rel.isprintable():
        return None
    if verifier_local({"motif_type": "chemin_exact", "motif": rel}, forme=False) is not None:
        return None
    return "chemin_exact", rel, None


def _sha_motif(motif: str) -> str:
    return hashlib.sha1(motif.encode()).hexdigest()


def identifiant(cve: str, motif: str) -> str:
    """Id stable du POC : la CVE et sha1(motif)[:6], jamais réattribué à un autre motif."""
    return f"ia-{cve.lower()}-{_sha_motif(motif)[:6]}"


def filtre_depuis_nuclei(modele: dict) -> dict | None:
    """Le filtre d'un modèle `{"texte", "doc", "fichier"}`, ou None (pas http, plusieurs requêtes, sans CVE, sans
    produit, motif peu spécifique, ou motif ABSENT du texte du modèle)."""
    doc, texte = modele.get("doc"), modele.get("texte")
    if not isinstance(doc, dict) or not isinstance(texte, str):
        return None
    info = doc.get("info")
    if not isinstance(info, dict):
        return None
    cl = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cve = cl.get("cve-id")
    if isinstance(cve, list):
        cve = cve[0] if len(cve) == 1 else None
    cve = str(cve).strip().upper() if cve else ""
    if not CVE_RE.fullmatch(cve):
        return None
    md = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
    produit = md.get("product") or md.get("vendor")
    if isinstance(produit, list):
        produit = produit[0] if produit else None
    produit = str(produit).strip().lower() if produit else ""
    if not produit or len(produit) > 64 or not produit.isprintable():
        return None
    cible = _cible_unique(doc)
    if cible is None:
        return None
    brut, rel = cible
    if _requete_de_detection(doc):            # F1 : simple reconnaissance d'une page légitime
        return None
    if brut not in texte:                     # anti-invention : la cible est écrite telle quelle dans le modèle
        return None
    m = _motif(rel)
    if m is None:
        return None
    motif_type, motif, parametre = m
    if motif not in texte:                    # garde finale : sous-chaîne exacte du modèle
        return None
    cvss = cl.get("cvss-score")
    cvss = float(cvss) if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) and 0 <= cvss <= 10 else None
    fichier = str(modele.get("fichier") or "")
    return {"id": identifiant(cve, motif), "version": 1, "cve": cve, "produit": produit,
            "famille": _famille(info.get("tags")),
            "motif_type": motif_type, "motif": motif, "parametre": parametre, "kev": False, "epss": None, "cvss": cvss,
            "sources": [{"type": "nuclei", "ref": str(doc.get("id") or cve)[:96], "url": URL_NUCLEI_FICHIER + fichier}]}


def collecter_nuclei(depot: Path = DEPOT) -> list[dict]:
    """Les filtres des modèles `http` à CVE du dépôt (lecture YAML seule) ; plusieurs filtres d'une même CVE se
    distinguent par leur id, qui porte sha1(motif)[:6] (stable, jamais de suffixe « -2 »)."""
    import yaml                               # collecteur seulement : la veille n'en a pas besoin

    depot = Path(depot)
    racine = depot / "http" / "cves"
    sortie, motifs = [], set()
    if depot_piege(depot):
        return []
    for f in sorted(racine.rglob("*.yaml")) if racine.is_dir() else []:
        try:
            if f.is_symlink() or not f.is_file() or f.stat().st_size > MODELE_MAX:
                continue
            texte = f.read_text(encoding="utf-8")
            doc = yaml.safe_load(texte)
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            continue
        filtre = filtre_depuis_nuclei({"texte": texte, "doc": doc, "fichier": str(f.relative_to(depot))})
        if filtre is None:
            continue
        cle = (filtre["cve"], filtre["motif_type"], filtre["parametre"], filtre["motif"])
        if cle in motifs:
            continue
        motifs.add(cle)
        sortie.append(filtre)
    return sortie


_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()*+][0-9A-Za-z]|[@-Z\\-_])")


def imprimable(texte: str) -> str:
    """Texte d'un retour externe (git) sans séquences ANSI ni caractère non imprimable : sûr pour le journal."""
    return "".join(ch for ch in _ANSI.sub("", texte) if ch.isprintable())


def depot_piege(depot: Path) -> bool:
    """Vrai si le dépôt, `http/` ou `http/cves` est un lien symbolique (jamais suivi)."""
    depot = Path(depot)
    return any(p.is_symlink() for p in (depot, depot / "http", depot / "http" / "cves"))


def taille_depot(depot: Path, borne: int = DEPOT_MAX_OCTETS) -> int:
    """Octets du dépôt (liens jamais suivis) ; le parcours s'arrête dès que `borne` est dépassée."""
    total, pile = 0, [Path(depot)]
    while pile:
        try:
            with os.scandir(pile.pop()) as it:
                for e in it:
                    if e.is_dir(follow_symlinks=False):
                        pile.append(Path(e.path))
                    else:
                        total += e.stat(follow_symlinks=False).st_size
                    if total > borne:
                        return total
        except OSError:
            continue
    return total


def mettre_a_jour_depot(depot: Path = DEPOT, executer=subprocess.run) -> bool:
    """Clone (ou met à jour) le dépôt des modèles, superficiellement ; rend True si le dépôt est utilisable."""
    depot = Path(depot)
    env = {**os.environ, **GIT_ENV}
    git = ["git", *GIT_OPTIONS]
    if (depot / ".git").is_dir():
        cmds = [[*git, "-C", str(depot), "fetch", "--depth", "1", "origin", "main"],
                [*git, "-C", str(depot), "reset", "--hard", "FETCH_HEAD"]]
    else:
        depot.parent.mkdir(parents=True, exist_ok=True)
        cmds = [[*git, "clone", "--depth", "1", URL_NUCLEI, str(depot)]]
    for c in cmds:
        try:
            r = executer(c, env=env, capture_output=True, text=True, timeout=DELAI_GIT_S, check=True)
            if r.returncode != 0:
                raise subprocess.CalledProcessError(r.returncode, c, getattr(r, "stdout", ""),
                                                    getattr(r, "stderr", ""))
        except subprocess.CalledProcessError as e:
            extrait = imprimable(str(e.stderr or "").replace("\r", "\n").replace("\n", " | "))[-STDERR_MAX:]
            log.warning("git %s : code %s : %s", c[len(git)] if len(c) > len(git) else "?", e.returncode, extrait)
            return (depot / "http").is_dir() and not depot_piege(depot)
        except (OSError, subprocess.TimeoutExpired) as e:
            log.warning("git : %s", e.__class__.__name__)
            return (depot / "http").is_dir() and not depot_piege(depot)
    return True


# ── Gravité : KEV et EPSS (caches 24 h) ────────────────────────────────
def telecharger_defaut(url: str, transport=None) -> bytes:
    """GET borné (64 Mio), TLS vérifié, sans les mandataires de l'environnement, redirections suivies À LA MAIN et
    seulement vers https (5 au plus). Collecteur seulement."""
    with httpx.Client(headers=AGENT, timeout=httpx.Timeout(120, connect=15), follow_redirects=False,
                      trust_env=False, transport=transport) as client:
        for _ in range(REDIRECTIONS_MAX + 1):
            if httpx.URL(url).scheme != "https":
                raise ValueError("redirection hors https refusée")
            with client.stream("GET", url) as r:
                if r.is_redirect:
                    url = str(r.url.join(r.headers.get("location", "")))
                    continue
                r.raise_for_status()
                morceaux, total = [], 0
                for m in r.iter_bytes():
                    total += len(m)
                    if total > TELECHARGEMENT_MAX:
                        raise ValueError("téléchargement trop gros")
                    morceaux.append(m)
                return b"".join(morceaux)
    raise ValueError("trop de redirections")


def _en_cache(sources: Path, nom: str, url: str, telecharger, maintenant: float) -> bytes:
    f = Path(sources) / nom
    try:
        if maintenant - f.stat().st_mtime < CACHE_S:
            return f.read_bytes()
    except OSError:
        pass
    donnees = telecharger(url)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(f.suffix + ".tmp")
    tmp.write_bytes(donnees)
    os.utime(tmp, (maintenant, maintenant))
    os.replace(tmp, f)
    return donnees


def lire_kev(sources: Path = SOURCES, telecharger=telecharger_defaut, maintenant: float | None = None) -> set[str]:
    brut = _en_cache(sources, "kev.json", URL_KEV, telecharger, time.time() if maintenant is None else maintenant)
    vulns = json.loads(brut).get("vulnerabilities", [])
    return {str(v.get("cveID", "")).upper() for v in vulns if isinstance(v, dict)
            and CVE_RE.fullmatch(str(v.get("cveID", "")).upper())}


def _decompresser(brut: bytes) -> bytes:
    """gzip borné (une bombe de décompression lève ValueError)."""
    with gzip.GzipFile(fileobj=io.BytesIO(brut)) as g:
        donnees = g.read(DECOMPRESSE_MAX + 1)
    if len(donnees) > DECOMPRESSE_MAX:
        raise ValueError("EPSS décompressé trop gros")
    return donnees


def lire_epss(sources: Path = SOURCES, telecharger=telecharger_defaut,
              maintenant: float | None = None) -> dict[str, float]:
    brut = _en_cache(sources, "epss.csv.gz", URL_EPSS, telecharger, time.time() if maintenant is None else maintenant)
    texte = _decompresser(brut).decode("utf-8", "replace")
    sortie = {}
    for ligne in csv.reader(io.StringIO(texte)):
        if len(ligne) < 2 or ligne[0].startswith("#") or not CVE_RE.fullmatch(ligne[0].strip().upper()):
            continue
        try:
            v = float(ligne[1])
        except ValueError:
            continue
        if 0 <= v <= 1:
            sortie[ligne[0].strip().upper()] = v
    return sortie


def enrichir(cands: list[dict], kev: set[str], epss: dict[str, float]) -> list[dict]:
    """Copie des filtres avec `kev`, `epss` et leurs sources."""
    sortie = []
    for c in cands:
        f = dict(c, sources=[s for s in c.get("sources", []) if s.get("type") not in ("kev", "epss")])
        f["kev"] = f["cve"] in kev
        f["epss"] = epss.get(f["cve"])
        if f["kev"]:
            f["sources"].append({"type": "kev", "ref": f["cve"], "url": URL_KEV_PAGE})
        if f["epss"] is not None:
            f["sources"].append({"type": "epss", "ref": f["cve"], "url": URL_EPSS_API + f["cve"]})
        sortie.append(f)
    return sortie


# ── Vérification locale (miroir de la forme exigée par gk2) ────────────
def verifier_local(f: dict, forme: bool = True) -> str | None:
    """Motif de refus local ou None. `forme=False` : seulement motif, paramètre et spécificité."""
    mt, motif, parametre = f.get("motif_type"), f.get("motif"), f.get("parametre")
    if mt not in ("chemin_exact", "chemin_prefixe", "parametre_egal", "corps_contient"):
        return "motif_type"
    if not isinstance(motif, str) or not 0 < len(motif) <= 256 or not motif.isprintable():
        return "motif"
    if mt.startswith("chemin_") and (not motif.startswith("/") or "%" in motif):
        return "motif"
    if mt.startswith("chemin_") and chemin_legitime(motif):
        return "chemin_legitime"
    if mt == "parametre_egal":
        if not isinstance(parametre, str) or not PARAMETRE_RE.fullmatch(parametre):
            return "parametre"
    elif parametre is not None:
        return "parametre"
    litteral = f"{parametre}={motif}" if mt == "parametre_egal" else motif
    if len(litteral.replace("/", "")) < SPECIFICITE_MIN:
        return "specificite"
    if not forme:
        return None
    if set(f) - set(_CHAMPS):
        return "champs"
    fid = f.get("id")
    if not isinstance(fid, str) or not fid.startswith("ia-") or not ID_RE.fullmatch(fid):
        return "id"
    if type(f.get("version")) is not int or f["version"] < 1:
        return "version"
    if not isinstance(f.get("cve"), str) or not CVE_RE.fullmatch(f["cve"]):
        return "cve"
    p = f.get("produit")
    if not isinstance(p, str) or not 0 < len(p) <= 64 or not p.isprintable():
        return "produit"
    if f.get("famille") not in FAMILLES:
        return "famille"
    if not isinstance(f.get("kev", False), bool):
        return "kev"
    for nom, maxi in (("epss", 1), ("cvss", 10)):
        v = f.get(nom)
        if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= maxi):
            return nom
    s = f.get("sources", [])
    if not isinstance(s, list) or len(s) > 20 or not all(isinstance(x, dict) for x in s):
        return "sources"
    return None


# ── Versions ───────────────────────────────────────────────────────────
def _empreinte(f: dict) -> str:
    return hashlib.sha256(json.dumps([f["cve"], f["motif_type"], f.get("parametre"), f["motif"], f["famille"],
                                      f["produit"]]).encode()).hexdigest()


def versionner(filtres: list[dict], chemin: Path = VERSIONS) -> list[dict]:
    """Pose `version` : inchangée si le filtre (motif, famille, produit) n'a pas changé, sinon +1 ; garde l'état."""
    chemin = Path(chemin)
    try:
        etat = json.loads(chemin.read_text(encoding="utf-8"))
        if not isinstance(etat, dict):
            etat = {}
    except (OSError, ValueError):
        etat = {}
    sortie = []
    for f in filtres:
        e = _empreinte(f)
        v, ancienne = (etat.get(f["id"]) or [0, None])[:2]
        if ancienne != e:
            v = int(v) + 1
            etat[f["id"]] = [v, e]
        sortie.append(dict(f, version=int(v)))
    tmp = chemin.with_suffix(chemin.suffix + ".tmp")
    tmp.write_text(json.dumps(etat), encoding="utf-8")
    os.replace(tmp, chemin)
    return sortie


# ── Lots ───────────────────────────────────────────────────────────────
def serialiser(lot: list[dict]) -> bytes:
    return json.dumps({"filtres": lot}, ensure_ascii=False, separators=(",", ":")).encode()


def decouper(filtres: list[dict]) -> list[list[dict]]:
    """Lots d'au plus LOT_MAX filtres ET de moins de LOT_OCTETS octets sérialisés."""
    lots, courant = [], []
    for f in filtres:
        if courant and (len(courant) >= LOT_MAX or len(serialiser(courant + [f])) >= LOT_OCTETS):
            lots.append(courant)
            courant = []
        courant.append(f)
    if courant:
        lots.append(courant)
    return lots


# ── Ordre, éligibilité et quota (plafonds de gk2 : 10 nouveaux par heure, 50 par 24 h) ──
def _borne(nom: str, defaut: int, maxi: int) -> int:
    try:
        v = int(os.environ.get(nom, defaut))
    except ValueError:
        return defaut
    return v if 1 <= v <= maxi else defaut


# Réglables (#3745) pour l'amorçage de toute la base : doivent suivre les plafonds de gk2 (cve-triage.toml).
PAR_TOUR = _borne("SECUBOX_AI_FILTRES_PAR_TOUR", 10, 1000)
PAR_JOUR = _borne("SECUBOX_AI_FILTRES_PAR_JOUR", 50, 5000)
REESSAI_ERREUR_S = 86400


def ordonner(filtres: list[dict]) -> list[dict]:
    """KEV d'abord, puis EPSS décroissant (absent en dernier), CVSS décroissant (absent en dernier), puis id."""
    return sorted(filtres, key=lambda f: (not f.get("kev"), f.get("epss") is None, -(f.get("epss") or 0),
                                          f.get("cvss") is None, -(f.get("cvss") or 0), f.get("id", "")))


def eligibles(filtres: list[dict], etats: dict, maintenant: float | None = None) -> list[dict]:
    """Filtres à (re)proposer, selon le dernier état connu `etats[id] = {"version", "statut", "ts"}` (vocabulaire du
    POC) du MÊME (id, version) : appliqué, inchangé ou rejeté → jamais renvoyé (un changement de contenu monte la
    version et le rend éligible) ; erreur → seulement 24 h après le dernier essai ; en_attente (plafond) ou inconnu →
    éligible. Ajouts de gk3 : `retiré` (touche d'une adresse protégée) et `envoi` (issue pas encore connue) → jamais,
    quelle que soit la version."""
    maintenant = time.time() if maintenant is None else maintenant
    sortie = []
    for f in filtres:
        e = etats.get(f["id"])
        if e is not None and e.get("statut") in ("retiré", "envoi"):
            continue
        if e is not None and e.get("version") == f["version"]:
            st = e.get("statut")
            if st in ("appliqué", "inchangé", "rejeté"):
                continue
            ts = e.get("ts")
            if st == "erreur" and isinstance(ts, (int, float)) and maintenant - ts < REESSAI_ERREUR_S:
                continue
        sortie.append(f)
    return sortie


def quota(envoyes_heure: int, envoyes_jour: int, plafond_heure: int = 10) -> int:
    """Filtres à envoyer à ce passage : au plus PAR_TOUR, et ce qui reste des plafonds de gk2 (10 par heure, PAR_JOUR
    par 24 h) d'après les nouveaux filtres envoyés et non refusés des fenêtres glissantes."""
    return max(0, min(PAR_TOUR, plafond_heure - envoyes_heure, PAR_JOUR - envoyes_jour))


# ── Interrupteur ───────────────────────────────────────────────────────
def interrupteur(cfg) -> bool:
    """Vrai seulement si `[filtres] nuclei = true` (booléen) ; toute autre forme : éteint."""
    sec = cfg.get("filtres") if isinstance(cfg, dict) else None
    return isinstance(sec, dict) and sec.get("nuclei") is True


def lire_interrupteur(chemin: str = CONF) -> bool:
    import tomllib
    try:
        with open(chemin, "rb") as f:
            return interrupteur(tomllib.load(f))
    except (OSError, ValueError):
        return False


# ── Fichiers d'échange collecteur → veille ─────────────────────────────
def ecrire_json(chemin: Path, donnees, borne: int | None = None) -> int:
    """Écriture atomique (temporaire dans le même dossier, fsync, renommage), 0640 ; rend la taille écrite. Lève
    ValueError au-delà de `borne` octets (rien n'est écrit)."""
    chemin = Path(chemin)
    octets = json.dumps(donnees, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if borne is not None and len(octets) > borne:
        raise ValueError(f"{chemin.name} : {len(octets)} octets, au-delà de {borne}")
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=f".{chemin.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o640)
            f.write(octets)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return len(octets)


class CandidatsInvalides(Exception):
    """candidats.json illisible, trop gros ou de forme inattendue : aucun envoi."""


def _proprietaire_attendu():
    """uid du compte dédié du collecteur, ou None s'il n'existe pas (tout fichier est alors refusé)."""
    try:
        return pwd.getpwnam(COMPTE_COLLECTEUR).pw_uid
    except KeyError:
        return None


def _lire_borne(chemin: Path, borne: int, proprietaires=None) -> bytes:
    """Fichier ordinaire, jamais un lien ni un tube (O_NONBLOCK, fstat AVANT toute lecture), au plus `borne` octets,
    jamais inscriptible par le groupe ni les autres, et d'un propriétaire de `proprietaires` (défaut : le compte du
    collecteur)."""
    if proprietaires is None:
        proprietaires = {_proprietaire_attendu()}
    try:
        fd = os.open(str(chemin), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        raise CandidatsInvalides(f"illisible ({e.__class__.__name__})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CandidatsInvalides("pas un fichier ordinaire")
        if st.st_mode & 0o022:
            raise CandidatsInvalides("inscriptible par le groupe ou les autres")
        if st.st_uid not in proprietaires:
            raise CandidatsInvalides("proprietaire inattendu")
        if st.st_size > borne:
            raise CandidatsInvalides("trop gros")
        with os.fdopen(os.dup(fd), "rb") as f:
            brut = f.read(borne + 1)
    finally:
        os.close(fd)
    if len(brut) > borne:
        raise CandidatsInvalides("trop gros")
    return brut


def _source_valide(s) -> bool:
    return (isinstance(s, dict) and set(s) == {"type", "ref", "url"} and s["type"] in _TYPES_SOURCE
            and isinstance(s["ref"], str) and 0 < len(s["ref"]) <= 96 and s["ref"].isprintable()
            and isinstance(s["url"], str) and s["url"].startswith("https://") and len(s["url"]) <= 512
            and s["url"].isprintable())


def valider_candidat(f) -> str | None:
    """Motif de refus d'un filtre lu dans candidats.json, ou None. Plus strict que `verifier_local` : forme du POC
    exacte (chemin_exact, sans paramètre), tous les champs présents, id RECALCULÉ depuis la CVE et le motif."""
    if not isinstance(f, dict) or set(f) != set(_CHAMPS):
        return "champs"
    raison = verifier_local(f)
    if raison:
        return raison
    if f["motif_type"] != "chemin_exact" or f["parametre"] is not None:
        return "motif_type"
    if f["id"] != identifiant(f["cve"], f["motif"]):
        return "id"
    if not f["sources"] or not all(_source_valide(s) for s in f["sources"]):
        return "sources"
    return None


def lire_candidats(chemin: Path = CANDIDATS) -> dict:
    """{"genere_le", "filtres"} de candidats.json, revalidé EN ENTIER (c'est une donnée, jamais une consigne). Lève
    CandidatsInvalides au moindre écart : aucun filtre n'en est alors envoyé."""
    brut = _lire_borne(Path(chemin), CANDIDATS_MAX_OCTETS)
    try:
        doc = json.loads(brut)
    except (ValueError, RecursionError, MemoryError):
        raise CandidatsInvalides("json") from None
    if not isinstance(doc, dict) or doc.get("forme") != FORME or set(doc) != {"forme", "genere_le", "filtres"}:
        raise CandidatsInvalides("forme")
    filtres = doc["filtres"]
    if not isinstance(doc["genere_le"], (int, float)) or isinstance(doc["genere_le"], bool):
        raise CandidatsInvalides("genere_le")
    if not isinstance(filtres, list) or len(filtres) > CANDIDATS_MAX:
        raise CandidatsInvalides("filtres")
    vus = set()
    for f in filtres:
        raison = valider_candidat(f)
        if raison:
            raise CandidatsInvalides(f"filtre : {raison}")
        if f["id"] in vus:
            raise CandidatsInvalides("filtre : id en double")
        vus.add(f["id"])
    return {"genere_le": float(doc["genere_le"]), "filtres": filtres}


_RE_ID_REFUS = re.compile(r"^ia-[a-z0-9._-]{1,93}$")


def lire_refuses(chemin: Path | None = None, proprietaires=None) -> set | None:
    """Ids de la liste de refus de l'opérateur (un par ligne, « # » commente) ; absente : vide. Illisible, trop
    grosse, d'un autre propriétaire que root, inscriptible par le groupe ou les autres, ou portant une ligne hors de la
    forme `ia-…` : None — l'appelant n'envoie alors RIEN (une liste de refus qu'on ne sait pas lire ne s'ignore pas)."""
    chemin = Path(chemin or REFUSES)
    if not os.path.lexists(str(chemin)):
        return set()
    try:
        brut = _lire_borne(chemin, REFUSES_MAX_OCTETS, set(proprietaires or PROPRIETAIRES_REFUSES))
        texte = brut.decode("utf-8")
    except (CandidatsInvalides, UnicodeDecodeError):
        return None
    ids = set()
    for ligne in texte.splitlines():
        ligne = ligne.split("#", 1)[0].strip()
        if not ligne:
            continue
        if not _RE_ID_REFUS.fullmatch(ligne):
            return None
        ids.add(ligne)
    return ids


_CLES_ETAT = {"forme", "allume", "dernier_tour", "duree_s", "compteurs", "erreur"}
_COMPTEURS = ("candidats", "ecartes", "kev", "epss")


def lire_etat_collecteur(chemin: Path = ETAT) -> dict | None:
    """etat.json du collecteur, réduit à ses champs connus et typés ; None s'il est absent ou illisible."""
    try:
        doc = json.loads(_lire_borne(Path(chemin), ETAT_MAX_OCTETS))
    except (CandidatsInvalides, ValueError, RecursionError, MemoryError):
        return None
    if not isinstance(doc, dict) or doc.get("forme") != FORME:
        return None
    nombre = lambda v: v if isinstance(v, (int, float)) and not isinstance(v, bool) else None  # noqa: E731
    c = doc.get("compteurs") if isinstance(doc.get("compteurs"), dict) else {}
    erreur = doc.get("erreur")
    return {"allume": doc.get("allume") is True, "dernier_tour": nombre(doc.get("dernier_tour")),
            "duree_s": nombre(doc.get("duree_s")),
            "compteurs": {k: (c.get(k) if type(c.get(k)) is int else None) for k in _COMPTEURS},
            "erreur": erreur[:64] if isinstance(erreur, str) and erreur.isprintable() else None}


# ── Tour du collecteur (oneshot horaire, sans clé) ─────────────────────
def _noter(etat: Path, debut: float, allume: bool, compteurs: dict, erreur: str | None) -> None:
    donnees = {"forme": FORME, "allume": allume, "dernier_tour": debut, "duree_s": round(time.time() - debut, 3),
               "compteurs": compteurs, "erreur": erreur}
    try:
        ecrire_json(etat, donnees, ETAT_MAX_OCTETS)
    except (OSError, ValueError) as e:
        log.error("etat.json non écrit (%s) : %s", e.__class__.__name__, donnees)


def tour_collecteur(dossier: Path = DOSSIER, conf: str = CONF, executer=subprocess.run,
                    telecharger=telecharger_defaut, maintenant: float | None = None, libre=None) -> int:
    """Un tour : interrupteur, garde d'espace, dépôt (taille bornée), KEV, EPSS, filtres vérifiés et versionnés,
    candidats.json puis etat.json. Rend le code de sortie de l'unité (0 : fait ou éteint ; 1 : erreur notée)."""
    dossier = Path(dossier)
    debut = time.time() if maintenant is None else maintenant
    etat = dossier / "etat.json"
    compteurs = {k: None for k in _COMPTEURS}
    if not lire_interrupteur(conf):
        _noter(etat, debut, False, compteurs, None)
        return 0
    libre = libre or (lambda: shutil.disk_usage(str(dossier)).free)
    try:
        if libre() < ESPACE_MIN_OCTETS:
            _noter(etat, debut, True, compteurs, "espace")
            return 1
    except OSError:
        _noter(etat, debut, True, compteurs, "espace")
        return 1
    depot = dossier / "depot"
    if depot_piege(depot):
        _noter(etat, debut, True, compteurs, "depot_lien")
        return 1
    if not mettre_a_jour_depot(depot, executer):
        _noter(etat, debut, True, compteurs, "depot")
        return 1
    if depot_piege(depot):
        _noter(etat, debut, True, compteurs, "depot_lien")
        return 1
    if taille_depot(depot) > DEPOT_MAX_OCTETS:
        log.error("dépôt au-delà de %d octets : supprimé, recloné au prochain tour", DEPOT_MAX_OCTETS)
        shutil.rmtree(depot, ignore_errors=True)
        _noter(etat, debut, True, compteurs, "depot_trop_gros")
        return 1
    cands = collecter_nuclei(depot)
    erreurs = []
    try:
        kev = lire_kev(dossier, telecharger, debut)
        compteurs["kev"] = len(kev)
    except Exception:  # noqa: BLE001 — sans KEV : gravité moindre, jamais inventée ; dite, jamais tue
        log.warning("KEV illisible : filtres sans KEV à ce tour", exc_info=True)
        kev = set()
        erreurs.append("kev")
    try:
        epss = lire_epss(dossier, telecharger, debut)
        compteurs["epss"] = len(epss)
    except Exception:  # noqa: BLE001
        log.warning("EPSS illisible : filtres sans EPSS à ce tour", exc_info=True)
        epss = {}
        erreurs.append("epss")
    filtres = versionner(enrichir(cands, kev, epss), dossier / "versions.json")
    valides = [f for f in filtres if valider_candidat(f) is None]
    compteurs["ecartes"] = len(filtres) - len(valides)
    valides = ordonner(valides)[:CANDIDATS_MAX]
    compteurs["candidats"] = len(valides)
    try:
        ecrire_json(dossier / "candidats.json", {"forme": FORME, "genere_le": debut, "filtres": valides},
                    CANDIDATS_MAX_OCTETS)
    except (OSError, ValueError):
        _noter(etat, debut, True, compteurs, "candidats")
        return 1
    _noter(etat, debut, True, compteurs, ",".join(erreurs) or None)
    return 0
