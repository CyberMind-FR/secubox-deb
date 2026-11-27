#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: waf — construction de la bibliothèque figée de motifs (#4020)
CyberMind — https://cybermind.fr

OUTIL DU DÉPÔT, jamais exécuté sur une box. Il lit des CLONES LOCAUX d'OWASP CRS (Apache-2.0) et des modèles
Nuclei (MIT) — de simples SOURCES DE MOTIFS : aucun de leurs moteurs n'est utilisé — et écrit la bibliothèque
livrée dans secubox-waf-ng (`config/bibliotheque/`), que waf-rules-sync range dans waf-rules.json et que seul
sbxwaf évalue.

Même chaîne que les filtres IA des CVE (#3732) : candidats → vérificateur → rejeu → bornes → émission.

1. Candidats. CRS : une règle `SecRule` devient UN motif par champ lu (chemin, requete, ua, corps) si elle est
   seule (pas de `chain`), de niveau de paranoïa 1, à opérateur `@rx`, `@pm` ou `@pmFromFile`, et si ses
   transformations se ramènent à ce que fait sbxwaf (décodage d'URL, minuscules, repli du chemin). Nuclei : chaque
   chemin littéral d'une requête GET (`{{BaseURL}}/…`) devient un motif exact « ^chemin$ » sur le chemin.
   Tout le reste est ÉCARTÉ et compté par motif dans le rapport (transformation, anomalie cumulée, chaîne,
   opérateur, regex hors RE2, chemin variable…).
2. Vérificateur : `hors_re2` de cve-triage (le même que pour waf-rules.json), compilation, spécificité, pages de
   SecuBox elle-même jamais touchées.
3. Rejeu sur des journaux réels (TSV anonymisé : hôte, client haché, méthode, chemin, statut, UA ; AUCUNE
   adresse) : un motif qui touche une réponse 2xx/3xx légitime d'un vrai site est rejeté. Ne compte pas comme
   légitime : une sonde évidente (UA d'outil de la règle CRS 913100, client qui a reçu ≥ 10 réponses 404 dans
   l'échantillon ou touché ≥ 3 motifs distincts), ni un 3xx d'un vhost qui redirige presque tout (≥ 80 % de ses
   chemins distincts).
4. Bornes par famille (coût de sbxwaf) puis émission : `categories.json` (catégories `bib_<famille>`, mode
   detect, `bibliotheque: true`), `rapport.json` (chiffres par famille et par vhost, sans adresse).

Usage :
  construire.py --crs DOSSIER_CRS --nuclei DOSSIER_NUCLEI [--rejeu journal.tsv]… [--sortie DOSSIER]
"""
from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote_plus

ICI = Path(__file__).resolve().parent
RACINE = ICI.parents[4]                       # racine du dépôt
CVE_TRIAGE = RACINE / "packages/secubox-security-posture/composants/cve-triage"
SORTIE = ICI.parent / "config/bibliotheque"

def _hors_re2():
    """Le vérificateur RE2 de waf-rules.json (#3732), chargé sous un nom de paquet propre : le paquet `api` de
    cve-triage ne doit jamais masquer (ni être masqué par) celui du WAF quand les deux vivent dans un même processus."""
    dossier = CVE_TRIAGE / "api" / "wafgen"
    nom = "_bibliotheque_wafgen"
    if nom + ".leurres" not in sys.modules:
        spec = importlib.util.spec_from_file_location(nom, dossier / "__init__.py",
                                                      submodule_search_locations=[str(dossier)])
        if spec is None or spec.loader is None:
            raise SystemExit("construire.py : vérificateur hors_re2 introuvable (cve-triage)")
        paquet = importlib.util.module_from_spec(spec)
        sys.modules[nom] = paquet
        spec.loader.exec_module(paquet)
    return importlib.import_module(nom + ".leurres").hors_re2


hors_re2 = _hors_re2()

# ── familles ────────────────────────────────────────────────────────────────────────────────────────────────────
FAMILLES = {
    "ua_outils": "UA d'outils de balayage",
    "fichiers_exposes": "Fichiers de configuration et secrets exposés",
    "panneaux_admin": "Panneaux d'administration",
    "sondes_techno": "Sondes de technologies (CMS, cadriciels)",
    "defauts_web": "Défauts de configuration du web",
    "lfi": "Inclusion de fichiers locaux",
    "rce": "Exécution de commandes",
    "php": "Injection PHP",
    "sqli": "Injection SQL",
    "xss": "Script intersite",
}
#: Fichier CRS (préfixe numérique) → famille ; absent : famille non retenue.
CRS_FAMILLE = {"913": "ua_outils", "930": "lfi", "932": "rce", "933": "php", "942": "sqli", "941": "xss"}
CRS_FAMILLE_ID = {"930130": "fichiers_exposes"}
NUCLEI_FAMILLE = {"exposures": "fichiers_exposes", "exposed-panels": "panneaux_admin",
                  "technologies": "sondes_techno", "misconfiguration": "defauts_web"}
#: Transformations ModSecurity équivalentes à ce que fait sbxwaf : décodage d'URL (unquote_plus), minuscules,
#: variante normalisée du chemin (replierchemin.go). Toute autre transformation écarte la règle.
TRANSFO_OK = {"none", "lowercase", "urldecode", "urldecodeuni", "utf8tounicode", "normalizepath",
              "normalizepathwin", "removenulls"}
#: Cible CRS → champ sbxwaf. REQUEST_URI (chemin + requête) et les cookies ne sont pas repris.
CRS_CHAMP = {"REQUEST_FILENAME": "chemin", "REQUEST_BASENAME": "chemin", "REQUEST_HEADERS:User-Agent": "ua",
             "ARGS": "requete", "ARGS_GET": "requete", "ARGS_NAMES": "requete", "ARGS_GET_NAMES": "requete",
             "QUERY_STRING": "requete", "ARGS_POST": "corps", "REQUEST_BODY": "corps"}
SEVERITE = {"CRITICAL": "critical", "ERROR": "high", "WARNING": "medium", "NOTICE": "low",
            "critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}
SPECIFICITE_MIN = 8               # caractères utiles (hors « / ») d'un chemin exact
LITTERAUX_MIN = 3                 # longueur minimale d'un littéral @pm
#: Bornes par famille (#4020 point 7) : regex évaluées à chaque requête, chemins exacts en table.
REGEX_MAX = 40
#: Familles CRS converties et rejouées, mais NON livrées dans cette édition : leurs grandes alternatives (RCE, SQLi,
#: XSS) doublaient le temps de MatchDetail au banc, pour zéro touche sur l'échantillon réel. Comptées « différées ».
FAMILLES_DIFFEREES = {"rce", "sqli", "xss"}
EXACTS_MAX = 4000
NUCLEI_TAGS_GENERIQUES = {
    "panel", "login", "detect", "discovery", "tech", "exposure", "config", "misconfig", "files", "file", "logs",
    "backup", "debug", "disclosure", "listing", "api", "admin", "intrusive", "takeover", "default-login",
    "misconfiguration", "unauth", "auth-bypass", "osint", "info", "vuln", "web", "http", "cms", "devops", "iot",
    "token", "keys", "secret", "generic", "fileupload", "exposures", "exposed", "edb", "packetstorm", "cve",
    "status", "phpinfo", "log", "sql", "dashboard", "monitoring", "service", "server", "proxy", "router",
}
#: Pages de SecuBox elle-même (même liste que cve-triage, #3764).
CHEMINS_SECUBOX_FIXES = frozenset({"/", "/login.html", "/index.html", "/favicon.ico", "/robots.txt",
                                   "/api/v1/", "/api/v1/auth/login", "/hub/", "/hall/", "/public/", "/static/"})
SONDE_404_MIN = 10
SONDE_MOTIFS_MIN = 3
REDIRIGE_TOUT = 0.8

_NOM = re.compile(r"[^a-z0-9_.-]+")
_META = set("\\.+*?()|[]{}^$")


def echapper(litteral: str) -> str:
    """Échappe un littéral pour RE2 ET Python : seuls les métacaractères (Go refuse « \\ » devant une lettre ou
    un espace, que re.escape produit)."""
    return "".join("\\" + c if c in _META else c for c in litteral)


def nom_court(s: str, defaut: str = "generique") -> str:
    s = _NOM.sub("-", str(s or "").lower()).strip("-.")[:48]
    return s or defaut


@dataclass
class Candidat:
    id: str
    famille: str
    techno: str
    severite: str
    champ: str
    pattern: str
    source: str                   # owasp-crs | nuclei
    ref: str                      # id de règle CRS ou id de modèle Nuclei
    desc: str
    exact: str | None = None      # chemin littéral (minuscules) si motif « ^…$ » sur le chemin
    touches: int = 0
    legitimes: list = field(default_factory=list)


@dataclass
class Bilan:
    importees: Counter = field(default_factory=Counter)        # par famille (ou « non_retenue »)
    ecartees: dict = field(default_factory=lambda: defaultdict(Counter))   # famille → motif → nombre


# ── OWASP CRS ───────────────────────────────────────────────────────────────────────────────────────────────────
_SECRULE = re.compile(r'^SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"\s*(?:"((?:[^"\\]|\\.)*)")?', re.S)


def crs_instructions(texte: str) -> list[str]:
    """Les instructions d'un fichier .conf, lignes de continuation jointes, commentaires retirés."""
    out, cour = [], ""
    for ligne in texte.splitlines():
        s = ligne.strip()
        if not cour and (not s or s.startswith("#")):
            continue
        if s.endswith("\\"):
            cour += s[:-1] + " "
            continue
        cour += s
        out.append(cour.strip())
        cour = ""
    return out


def _actions(brut: str) -> list[tuple[str, str]]:
    """`id:1,phase:2,t:none,msg:'a, b'` → [(clé, valeur)] (virgules entre apostrophes respectées)."""
    out, cour, dans = [], "", False
    for c in brut:
        if c == "'":
            dans = not dans
        if c == "," and not dans:
            out.append(cour.strip())
            cour = ""
        else:
            cour += c
    if cour.strip():
        out.append(cour.strip())
    paires = []
    for a in out:
        k, _, v = a.partition(":")
        paires.append((k.strip(), v.strip().strip("'")))
    return paires


def _litteraux(fichier: Path) -> list[str]:
    try:
        lignes = fichier.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [s.strip().lower() for s in lignes if s.strip() and not s.lstrip().startswith("#")]


def crs_candidats(dossier: Path, bilan: Bilan) -> list[Candidat]:
    out: list[Candidat] = []
    regles = Path(dossier) / "rules"
    chaine_suivante = False
    for conf in sorted(regles.glob("REQUEST-9*.conf")):
        prefixe = conf.name.split("-")[1]
        for instr in crs_instructions(conf.read_text(encoding="utf-8")):
            m = _SECRULE.match(instr)
            if not m:
                continue
            cibles, operateur, brut = m.group(1), m.group(2), m.group(3) or ""
            acts = _actions(brut)
            d = dict(acts)
            rid = d.get("id", "")
            if chaine_suivante:                       # maillon d'une chaîne : compté avec sa tête
                chaine_suivante = "chain" in d
                continue
            if not rid:
                continue
            chaine_suivante = "chain" in d
            if d.get("phase") is None or rid.endswith(("011", "012", "013", "014", "015", "016", "017", "018")) \
                    and cibles.startswith("TX:DETECTION_PARANOIA_LEVEL"):
                continue                              # garde de niveau de paranoïa : pas une règle de détection
            fam = CRS_FAMILLE_ID.get(rid) or CRS_FAMILLE.get(prefixe)
            cle = fam or "non_retenue"
            bilan.importees[cle] += 1
            ecart = bilan.ecartees[cle]
            if fam is None:
                ecart[f"famille CRS {prefixe} non retenue"] += 1
                continue
            if "chain" in d:
                ecart["règle chaînée"] += 1
                continue
            tags = [v for k, v in acts if k == "tag"]
            if "paranoia-level/1" not in tags:
                ecart["niveau de paranoïa > 1"] += 1
                continue
            if cibles.startswith("TX:") or "TX:" in cibles:
                ecart["anomalie cumulée (cible TX)"] += 1
                continue
            transfos = {v.lower() for k, v in acts if k == "t"}
            hors = sorted(transfos - TRANSFO_OK)
            if hors:
                ecart["transformation " + hors[0]] += 1
                continue
            champs = []
            for c in cibles.split("|"):
                if c.startswith("!"):
                    continue
                ch = CRS_CHAMP.get(c) or CRS_CHAMP.get(c.split(":")[0] if not c.startswith("REQUEST_HEADERS") else c)
                if ch and ch not in champs:
                    champs.append(ch)
            if not champs:
                ecart["cible non reprise (" + cibles.split("|")[0].split(":")[0] + ")"] += 1
                continue
            if operateur.startswith("!"):
                ecart["opérateur nié"] += 1
                continue
            op, _, arg = operateur.partition(" ")
            if op == "@rx":
                motif = arg
            elif op in ("@pm", "@pmFromFile"):
                mots = arg.split() if op == "@pm" else _litteraux(regles / arg.strip())
                mots = sorted({w for w in mots if len(w) >= LITTERAUX_MIN})
                if not mots:
                    ecart["liste vide ou trop courte"] += 1
                    continue
                motif = "(?:" + "|".join(echapper(w) for w in mots) + ")"
            else:
                ecart["opérateur " + (op or "?")] += 1
                continue
            sev = SEVERITE.get(d.get("severity", ""), "medium")
            for ch in champs:
                if ch in ("requete", "corps") and re.search(r"(?<!\\)[\^$]", motif.replace("[^", "[")):
                    ecart["ancre sur un argument (sbxwaf lit la requête entière)"] += 1
                    continue
                out.append(Candidat(id=f"bib-crs-{rid}-{ch}", famille=fam, techno="generique", severite=sev,
                                    champ=ch, pattern=motif, source="owasp-crs", ref=f"CRS {rid}",
                                    desc=(d.get("msg") or "")[:160]))
    return out


# ── Nuclei ──────────────────────────────────────────────────────────────────────────────────────────────────────
def _techno_nuclei(info: dict) -> str:
    meta = info.get("metadata") or {}
    for cle in ("product", "vendor"):
        v = meta.get(cle)
        if isinstance(v, str) and v.strip():
            return nom_court(v)
    tags = info.get("tags") or ""
    for t in (tags.split(",") if isinstance(tags, str) else tags):
        t = nom_court(t, "")
        if t and t not in NUCLEI_TAGS_GENERIQUES and not re.fullmatch(r"cve\d*|cve-\d{4}-\d+|\d+", t):
            return t
    return "generique"


def nuclei_candidats(dossier: Path, bilan: Bilan) -> list[Candidat]:
    import yaml                                         # outil du dépôt seulement (python3-yaml)
    par_chemin: dict[str, Candidat] = {}
    technos: dict[str, set] = defaultdict(set)
    racine = Path(dossier) / "http"
    for sous, fam in NUCLEI_FAMILLE.items():
        for f in sorted((racine / sous).rglob("*.yaml")):
            bilan.importees[fam] += 1
            ecart = bilan.ecartees[fam]
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError, UnicodeDecodeError):
                ecart["modèle illisible"] += 1
                continue
            if not isinstance(doc, dict) or not isinstance(doc.get("info"), dict):
                ecart["modèle illisible"] += 1
                continue
            reqs = doc.get("http") or doc.get("requests")
            if not isinstance(reqs, list) or doc.get("flow") or doc.get("variables"):
                ecart["flux, variables ou protocole non HTTP"] += 1
                continue
            info, tid = doc["info"], nom_court(doc.get("id"), "")
            techno, sev = _techno_nuclei(info), SEVERITE.get(str(info.get("severity", "")).lower(), "low")
            chemins, motif_ecart = [], None
            for r in reqs:
                if not isinstance(r, dict) or "raw" in r or r.get("payloads") or r.get("fuzzing"):
                    motif_ecart = "requête brute, charges ou fuzzing"
                    break
                if str(r.get("method", "GET")).upper() != "GET":
                    motif_ecart = "méthode autre que GET"
                    break
                for p in r.get("path") or []:
                    if not isinstance(p, str) or not p.startswith("{{BaseURL}}"):
                        motif_ecart = "chemin hors {{BaseURL}}"
                        continue
                    c = p[len("{{BaseURL}}"):]
                    if "{{" in c:
                        motif_ecart = "chemin variable"
                        continue
                    if "?" in c or "#" in c:
                        motif_ecart = "chemin avec requête"
                        continue
                    c = unquote_plus(c)
                    if not c.startswith("/") or len(c.replace("/", "")) < SPECIFICITE_MIN:
                        motif_ecart = "chemin trop générique"
                        continue
                    chemins.append(c.lower())
            if not chemins:
                ecart[motif_ecart or "aucun chemin"] += 1
                continue
            for c in chemins:
                technos[c].add(techno)
                if c in par_chemin:
                    continue
                par_chemin[c] = Candidat(id=f"bib-nuclei-{tid}"[:80] + f"-{len(par_chemin):05d}", famille=fam,
                                         techno=techno, severite=sev, champ="chemin",
                                         pattern="^" + echapper(c) + "$", source="nuclei", ref=f"nuclei {tid}",
                                         desc=str(info.get("name") or "")[:160], exact=c)
    out = []
    for c, cand in par_chemin.items():
        if len(technos[c]) > 1:
            bilan.ecartees[cand.famille]["chemin ambigu (plusieurs technos)"] += 1
            continue
        out.append(cand)
    return out


# ── vérificateur ────────────────────────────────────────────────────────────────────────────────────────────────
def chemins_secubox(racine: Path = RACINE) -> set[str]:
    """Pages servies par SecuBox elle-même : un motif qui en touche une bannirait nos propres usagers (#3764)."""
    vus = set(CHEMINS_SECUBOX_FIXES)
    for www in (racine / "packages").glob("*/www"):
        for f in www.rglob("*"):
            if f.is_file():
                vus.add("/" + str(f.relative_to(www)).lower())
    return vus


def verifier(c: Candidat, pages: set[str]) -> str | None:
    """Motif d'écart, ou None si le candidat est retenu."""
    h = hors_re2(c.pattern)
    if h:
        return f"regex hors RE2 ({h})"
    try:
        rx = re.compile("(?i)" + c.pattern)
    except re.error:
        return "regex invalide"
    if c.champ in ("chemin", "requete") and rx.search(""):
        return "motif vide"
    if c.champ == "chemin":
        if c.exact is not None and c.exact in pages:
            return "page de SecuBox"
        if c.exact is None and any(rx.search(p) for p in pages):
            return "page de SecuBox"
    return None


# ── rejeu ───────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclass
class Requete:
    hote: str
    client: str
    methode: str
    chemin: str
    requete: str
    statut: int
    ua: str


def lire_journal(lignes) -> list[Requete]:
    """TSV : hôte, client haché, méthode, URI, statut, UA. Une ligne mal formée est ignorée."""
    out = []
    for ligne in lignes:
        p = ligne.rstrip("\n").split("\t")
        if len(p) != 6 or not p[4].isdigit():
            continue
        uri = p[3]
        chemin, _, req = uri.partition("?")
        out.append(Requete(p[0].lower(), p[1], p[2], unquote_plus(chemin).lower(), unquote_plus(req).lower(),
                           int(p[4]), p[5].lower()))
    return out


def _texte(c: Candidat, r: Requete) -> str:
    return {"chemin": r.chemin, "requete": r.requete, "ua": r.ua}.get(c.champ, "")


def rejouer(cands: list[Candidat], reqs: list[Requete], ua_outils: re.Pattern | None) -> dict:
    """Compte les touches de chaque candidat et remplit `legitimes` (hôtes des 2xx/3xx légitimes touchés)."""
    exacts = {c.exact: c for c in cands if c.exact is not None}
    regex = [(c, re.compile("(?i)" + c.pattern)) for c in cands if c.exact is None]
    n404 = Counter(r.client for r in reqs if r.statut == 404)
    chemins = defaultdict(set)
    redir = defaultdict(set)
    for r in reqs:
        chemins[r.hote].add(r.chemin)
        if 300 <= r.statut < 400:
            redir[r.hote].add(r.chemin)
    redirige_tout = {h for h, s in chemins.items() if len(s) >= 5 and len(redir[h]) / len(s) >= REDIRIGE_TOUT}
    touches = []                                   # (requête, candidat)
    par_client = defaultdict(set)
    for r in reqs:
        c = exacts.get(r.chemin)
        trouves = [c] if c is not None else []
        for cand, rx in regex:
            t = _texte(cand, r)
            if t and rx.search(t):
                trouves.append(cand)
        for cand in trouves:
            touches.append((r, cand))
            par_client[r.client].add(cand.id)
    sondes = 0
    for r, cand in touches:
        cand.touches += 1
        legit = 200 <= r.statut < 300 or (300 <= r.statut < 400 and r.hote not in redirige_tout)
        # L'UA d'outil ne rend pas « évidente » une touche de la famille ua_outils : elle se jugerait elle-même.
        evidente = (n404[r.client] >= SONDE_404_MIN or len(par_client[r.client]) >= SONDE_MOTIFS_MIN
                    or (cand.famille != "ua_outils" and ua_outils is not None and bool(ua_outils.search(r.ua))))
        if legit and evidente:
            sondes += 1
        elif legit:
            cand.legitimes.append(r.hote)
    return {"requetes": len(reqs), "touches": len(touches), "sondes_evidentes_2xx_3xx": sondes,
            "vhosts_redirigeant_tout": len(redirige_tout)}


def hote_affichable(h: str) -> str:
    return "(adresse)" if re.fullmatch(r"[0-9.:a-f\[\]]+", h) and any(ch.isdigit() for ch in h) else h


# ── émission ────────────────────────────────────────────────────────────────────────────────────────────────────
def borner(cands: list[Candidat], bilan: Bilan) -> list[Candidat]:
    out, nb_rx, nb_ex = [], Counter(), Counter()
    sev_ordre = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for c in sorted(cands, key=lambda c: (sev_ordre.get(c.severite, 9), -c.touches, c.id)):
        if c.famille in FAMILLES_DIFFEREES:
            bilan.ecartees[c.famille]["famille différée (coût au banc, édition suivante)"] += 1
            continue
        if c.exact is None:
            if nb_rx[c.famille] >= REGEX_MAX:
                bilan.ecartees[c.famille]["borne de regex par famille"] += 1
                continue
            nb_rx[c.famille] += 1
        else:
            if nb_ex[c.famille] >= EXACTS_MAX:
                bilan.ecartees[c.famille]["borne de chemins exacts par famille"] += 1
                continue
            nb_ex[c.famille] += 1
        out.append(c)
    return sorted(out, key=lambda c: c.id)


def categories(cands: list[Candidat], versions: dict) -> dict:
    cats = {}
    for fam, nom in FAMILLES.items():
        motifs = [c for c in cands if c.famille == fam]
        if not motifs:
            continue
        sev = min((c.severite for c in motifs), key=lambda s: ["critical", "high", "medium", "low"].index(s))
        cats["bib_" + fam] = {
            "name": f"Bibliothèque — {nom} (#4020)",
            "severity": sev,
            "enabled": True,
            "mode": "detect",
            "bibliotheque": True,
            "famille": fam,
            "note": "Identifier seulement par défaut : chaque touche est étiquetée bib:<famille>:<techno>. "
                    "Le passage en escalate ou block est un choix de la page WAF › Modes.",
            "patterns": [{"id": c.id, "pattern": c.pattern, "champ": c.champ, "famille": fam, "techno": c.techno,
                          "source": c.source, "ref": c.ref, "desc": c.desc} for c in motifs],
        }
    return {"_meta": {"bibliotheque": "4020", "sources": versions,
                      "licences": "Motifs dérivés d'OWASP CRS (Apache-2.0) et des modèles Nuclei (MIT) : "
                                  "voir LICENCES/ et NOTICE.md"},
            "categories": cats}


def construire(crs: Path | None, nuclei: Path | None, journaux: list[Path], versions: dict) -> tuple[dict, dict]:
    bilan = Bilan()
    cands = (crs_candidats(crs, bilan) if crs else []) + (nuclei_candidats(nuclei, bilan) if nuclei else [])
    converties = Counter(c.famille for c in cands)
    pages = chemins_secubox()
    gardes = []
    for c in cands:
        motif = verifier(c, pages)
        if motif:
            bilan.ecartees[c.famille][motif] += 1
        else:
            gardes.append(c)
    verifiees = Counter(c.famille for c in gardes)
    ua = next((re.compile("(?i)" + c.pattern) for c in gardes if c.ref == "CRS 913100" and c.champ == "ua"), None)
    reqs = []
    for j in journaux:
        with open(j, encoding="utf-8", errors="replace") as f:
            reqs.extend(lire_journal(f))
    rejeu = rejouer(gardes, reqs, ua) if reqs else {"requetes": 0}
    rejetees = Counter()
    vhosts_rejet = defaultdict(Counter)
    ids_rejet: dict = {}
    retenues = []
    for c in gardes:
        if c.legitimes:
            rejetees[c.famille] += 1
            ids_rejet[c.id] = sorted({hote_affichable(h) for h in c.legitimes})[:5]
            for h in set(c.legitimes):
                vhosts_rejet[hote_affichable(h)][c.famille] += 1
            continue
        retenues.append(c)
    finales = borner(retenues, bilan)
    touches_fam, etiquettes = Counter(), Counter()
    ids_finals = {c.id for c in finales}
    if reqs:
        for c in gardes:
            c.touches, c.legitimes = 0, []
        rejouer(finales, reqs, ua)
        for c in finales:
            touches_fam[c.famille] += c.touches
            if c.touches:
                etiquettes[f"bib:{c.famille}:{c.techno}"] += c.touches
    regles = categories(finales, versions)
    familles = {}
    for fam in sorted(set(bilan.importees) | set(FAMILLES)):
        if not bilan.importees.get(fam) and fam not in converties:
            continue
        familles[fam] = {
            "importees": bilan.importees.get(fam, 0), "converties": converties.get(fam, 0),
            "verifiees": verifiees.get(fam, 0), "rejetees_rejeu": rejetees.get(fam, 0),
            "retenues": sum(1 for c in finales if c.famille == fam),
            "regex": sum(1 for c in finales if c.famille == fam and c.exact is None),
            "chemins_exacts": sum(1 for c in finales if c.famille == fam and c.exact is not None),
            "touches_rejouees": touches_fam.get(fam, 0),
            "ecartees": dict(sorted(bilan.ecartees.get(fam, {}).items(), key=lambda kv: -kv[1])),
        }
    rapport = {"sources": versions, "rejeu": rejeu, "familles": familles,
               "rejets_par_vhost": {h: dict(v) for h, v in sorted(vhosts_rejet.items())},
               "rejetees_rejeu_motifs": dict(sorted(ids_rejet.items())),
               "etiquettes_echantillon": dict(etiquettes.most_common(60)),
               "motifs_les_plus_touches": {c.id: c.touches for c in sorted(finales, key=lambda c: -c.touches)[:30]
                                           if c.touches},
               "total_retenues": len(ids_finals)}
    return regles, rapport


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--crs", type=Path)
    ap.add_argument("--nuclei", type=Path)
    ap.add_argument("--crs-version", default="")
    ap.add_argument("--nuclei-version", default="")
    ap.add_argument("--rejeu", type=Path, action="append", default=[])
    ap.add_argument("--sortie", type=Path, default=SORTIE)
    a = ap.parse_args(argv)
    versions = {"owasp-crs": a.crs_version, "nuclei-templates": a.nuclei_version}
    regles, rapport = construire(a.crs, a.nuclei, a.rejeu, versions)
    a.sortie.mkdir(parents=True, exist_ok=True)
    texte = json.dumps(regles, ensure_ascii=False, indent=1) + "\n"
    json.loads(texte)
    (a.sortie / "categories.json").write_text(texte, encoding="utf-8")
    (a.sortie / "rapport.json").write_text(json.dumps(rapport, ensure_ascii=False, indent=1) + "\n",
                                           encoding="utf-8")
    print(json.dumps({f: {k: v for k, v in d.items() if k != "ecartees"} for f, d in rapport["familles"].items()},
                     ensure_ascii=False, indent=1))
    print(f"retenues : {rapport['total_retenues']} — rejeu : {rapport['rejeu']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
