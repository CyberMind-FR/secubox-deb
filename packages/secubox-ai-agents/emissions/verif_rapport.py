# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Vérificateur par le code des rapports rédigés par l'IA (#4006), sans modèle.

Règle (#3509) : le contrôle est fait ICI, jamais confié à une consigne. Le texte rédigé est découpé en phrases ; chaque
phrase est confrontée au DOSSIER DE FAITS qui a servi à la rédaction, et à lui seul :

1. une adresse IP dans la phrase → RETIRÉE (et jamais rendue, même dans la liste des retraits) ;
2. un motif de CAUSALITÉ ou de CAPACITÉ (liste `CAUSALITE`, `CAPACITE` ci-dessous) → RETIRÉE : le dossier ne porte que
   des mesures, jamais un lien de cause à effet (« a révélé », « a corrigé », « exploite », « grâce à »…) ni ce que la
   box « sait faire » ;
3. chaque NOMBRE (les milliers groupés « 13 630 » comptent pour un), chaque DATE (« 24/11 », « 24 novembre »,
   « 2026-11-24 ») et chaque NOM repéré (CVE, nom d'hôte, catégorie `a_b` / `a:b`, sigle ou nom propre d'opérateur)
   doit se retrouver dans le dossier ; un seul manque → RETIRÉE ;
4. une TENDANCE (hausse, baisse…) sans tendance mesurée dans le dossier (`tendances` vide) → RETIRÉE ;
5. une phrase sans AUCUN ancrage (ni nombre, ni date, ni terme nommé du dossier) → RETIRÉE (« non adossée ») ;
6. une phrase adossée qui porte un motif de SUPPOSITION (`SUPPOSITION` : « semble », « pourrait »…) est GARDÉE mais
   marquée « hypothèse ».

Le taux publié est (retenues + hypothèses) / phrases. Ce contrôle ne prouve pas qu'une phrase est vraie (deux chiffres
justes peuvent être mal reliés) ; il prouve qu'elle ne cite rien que le dossier ne contienne.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, Iterable, List, Set, Tuple

# ── motifs documentés (minuscules, sans accents : la phrase est normalisée de même) ──────────────────────────────────
# Causalité : un lien de cause à effet que le dossier ne mesure jamais.
CAUSALITE = (
    r"\ba revele", r"\brevel(?:e|ent|er|ant)\b", r"\bmet(?:tent)? en evidence\b", r"\ba mis en evidence\b",
    r"\ba corrige", r"\bcorrig(?:e|ent|er|eant)\b", r"\ba resolu", r"\bresou(?:t|dre)\b", r"\bregle(?:r)? (?:ce|le) probleme",
    r"\bexploit", r"\bfailles?\b", r"\bcontourn", r"\bvulnerabilites? du waf",
    r"\ba permis de\b", r"\bpermet(?:tent)? de\b", r"\bgrace a\b", r"\ba cause de\b", r"\ben raison de\b",
    r"\bprovoqu", r"\ba cause\b", r"\bcaus(?:e|ent|ant)\b", r"\bentrain", r"\ba conduit a\b", r"\bconduit a\b",
    r"\bresult(?:e|ent|ant) de\b", r"\bdu fait de\b", r"\bexpliqu", r"\bdonc\b", r"\ben reaction a\b",
    r"\bajust(?:e|ent|er|ant) ses tactiques", r"\badapt(?:e|ent|er|ant) (?:sa|ses) (?:tactique|strategie)",
)
# Capacité : ce que la box « sait faire » n'est pas un fait du dossier.
CAPACITE = (r"\bsait (?:deja )?(?:faire|deduire|detecter|reconnaitre)", r"\best capable de\b", r"\bsont capables de\b",
            r"\bsait deja\b", r"\bpeut deja\b",
            # la box elle-même n'est jamais le sujet d'un fait du dossier (il décrit l'attaquant, pas la défense)
            r"\b(?:la box|secubox) (?:secubox )?(?:a ete|est|etait|sait|peut|a su|detecte|bloque|protege)\b")
# Supposition : gardée si adossée, marquée « hypothèse ».
SUPPOSITION = (r"\bsembl", r"\bpourrai", r"\bpeut indiquer", r"\bpeuvent indiquer", r"\bprobabl", r"\bvraisemblabl",
               r"\bhypothese", r"\bsuggere", r"\bsuggerant", r"\blaisse(?:nt)? penser", r"\bpossiblement\b", r"\bpeut-etre\b",
               r"\bsans doute\b")
TENDANCE = (r"\bhausse", r"\bbaisse", r"\baugment", r"\bdiminu", r"\brecul", r"\bexplos", r"\ben forte\b",
            r"\bs'intensifi", r"\bacceler", r"\bralenti")

_CAUSALITE = re.compile("|".join(CAUSALITE))
_CAPACITE = re.compile("|".join(CAPACITE))
_SUPPOSITION = re.compile("|".join(SUPPOSITION))
_TENDANCE = re.compile("|".join(TENDANCE))

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])|"
                  r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{1,4}::(?:[0-9A-Fa-f]{1,4}:?){0,6}")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
HOTE = re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.[a-z]{2,24}\b", re.I)
CATEGORIE = re.compile(r"\b[a-z][a-z0-9]*(?:[_:][a-z0-9]+)+\b")
_MASQUE = re.compile(r"/\s?(?:8|16|24|32|48|64)\b|\bblocs?\s?24\b")
_HEX = re.compile(r"\b[0-9a-f]{8,64}\b")
MOIS = {"janvier": 1, "fevrier": 2, "mars": 3, "avril": 4, "mai": 5, "juin": 6, "juillet": 7, "aout": 8,
        "septembre": 9, "octobre": 10, "novembre": 11, "decembre": 12}
DATE_ISO = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
DATE_JM = re.compile(r"\b(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?\b")
DATE_TEXTE = re.compile(r"\b(\d{1,2})(?:er)?\s+(" + "|".join(MOIS) + r")\b(?:\s+(\d{4}))?")
ORDINAL = re.compile(r"\b\d{1,2}(?:re|er|ere|e|eme|nd|nde)\b")
NOMBRE = re.compile(r"(?<![\w.,])\d{1,3}(?:[   ]\d{3})+(?![\d])|\d+(?:[.,]\d+)?")
# Mots en capitales qui ne sont pas des noms d'opérateur : vocabulaire du produit et du métier.
SIGLES_LIBRES = frozenset("""secubox waf ia ip ips ua uas asn asns http https get post head put url urls api dns tls ssh
smtp imap jarvis json markdown cve cves sbxwaf actord nb box lan wan id ids md utc vpn tor cdn ok bans ban""".split())


def normaliser(texte: str) -> str:
    """Minuscules, sans accents, apostrophes droites : les motifs s'écrivent une fois."""
    t = unicodedata.normalize("NFD", str(texte)).encode("ascii", "ignore").decode("ascii")
    return t.replace("’", "'").lower()


# ── ce que le dossier contient ──────────────────────────────────────────────────────────────────────────────────────

class Index:
    """Nombres et dates du dossier AVEC le chemin de leur clé (« chiffres.bans_90j »), chaînes et termes nommés.
    Un nombre lu dans une chaîne (phrase de la lecture #4005, libellé) porte le chemin de cette chaîne et la marque
    `texte` : il n'est lié à aucune unité."""

    CLES_NOMS = frozenset(("nom", "noms", "operateurs", "operateur", "org", "vhost", "vhosts", "cibles", "categorie",
                           "categories", "cves", "outil", "libelle", "pistes", "phase", "phases", "ua_premier",
                           "pages", "famille", "nom_cible", "avec", "motifs", "jalons"))

    def __init__(self, dossier: Dict[str, Any]):
        self.nombres: List[Tuple[float, str]] = []
        self.dates: Dict[Tuple[int, int], Set[str]] = {}
        self.chaines: List[str] = []
        self.termes: Set[str] = set()
        self.tendances = bool(dossier.get("tendances"))
        self._parcourir(dossier, False, "")
        self.texte = normaliser(" \n ".join(self.chaines))

    def _date(self, d: int, m: int, chemin: str) -> None:
        self.dates.setdefault((d, m), set()).add(chemin)

    def _parcourir(self, x: Any, nom: bool, chemin: str) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                self._parcourir(v, nom or str(k) in self.CLES_NOMS, (chemin + "." if chemin else "") + normaliser(k))
        elif isinstance(x, (list, tuple)):
            for v in x:
                self._parcourir(v, nom, chemin)
        elif isinstance(x, bool) or x is None:
            return
        elif isinstance(x, (int, float)):
            self.nombres.append((float(x), chemin))
        elif isinstance(x, str):
            self.chaines.append(x)
            t = _HEX.sub(" ", x)
            for m in DATE_ISO.finditer(t):
                self._date(int(m.group(3)), int(m.group(2)), chemin)
            t = DATE_ISO.sub(" ", t)
            for m in DATE_JM.finditer(t):
                self._date(int(m.group(1)), int(m.group(2)), chemin)
            t = DATE_JM.sub(" ", t)
            tn = normaliser(t)
            for m in NOMBRE.finditer(tn):
                # #4042 : l'unité lue après le nombre dans la chaîne (« 18 723 bans ») ; vide = nombre sans unité
                u = ",".join(_unite(tn[m.end():m.end() + 30]))
                self.nombres.append((float(re.sub(r"[ \u00a0\u202f]", "", m.group(0)).replace(",", ".")),
                                     chemin + "#texte:" + u))
            if nom:
                n = normaliser(x).strip()
                if len(n) >= 4:
                    self.termes.add(n)
                    if "_" in n:
                        self.termes.add(n.replace("_", " "))

    def nombre_connu(self, x: float, cles: Tuple[str, ...] = ()) -> bool:
        """Le nombre figure dans le dossier ; avec `cles` (unité lue dans la phrase), sous une clé qui en porte une
        (ou dans une chaîne)."""
        for v, chemin in self.nombres:
            if abs(x - v) > 0.5:
                continue
            if "#texte:" in chemin:
                u = chemin.split("#texte:", 1)[1]
                # un nombre lu dans une phrase n'ancre que la même unité (ou toute unité s'il n'en porte pas)
                if not cles or not u or any(c in u.split(",") for c in cles):
                    return True
                continue
            if not cles or any(c in chemin for c in cles):
                return True
        return False

    def date_connue(self, d: Tuple[int, int], cles: Tuple[str, ...] = ()) -> bool:
        chemins = self.dates.get(d)
        if not chemins:
            return False
        return not cles or any(c in ch for ch in chemins for c in cles)

    def contient(self, terme: str) -> bool:
        t = normaliser(terme).strip()
        return bool(t) and (t in self.texte or t.replace(" ", "_") in self.texte)


# Unité lue juste après un nombre → fragments de clé du dossier sous lesquels ce nombre doit se trouver. « 18 651
# adresses » quand 18 651 est un nombre de BANS est une invention de liaison : la phrase est retirée.
UNITES = (
    ("%", ("part", "pct", "classes", "profil", "methodes", "pages", "vhosts")),
    ("adresse", ("adresse", "liste", "retours", "relachees")), ("ip", ("adresse", "liste", "retours", "relachees")),
    ("ban", ("bans",)), ("blocage", ("bans",)), ("bloque", ("bans",)),
    ("reseau", ("blocs24", "reseaux")), ("bloc", ("blocs24",)),
    ("jour", ("jours", "extinction", "duree", "delai")),
    ("requete", ("requetes",)), ("retour", ("retours",)), ("relache", ("relachees",)),
    ("vague", ("vagues",)), ("user-agent", ("ua_",)), ("operateur", ("operateurs",)), ("semaine", ("semaine",)),
    ("cible", ("cibles",)), ("phase", ("phases",)), ("lien", ("liens",)),
)
# Rôle d'une date selon les mots qui la précèdent : début (« depuis », « dès », « a débuté le », « du ») ou fin.
ROLE_DEBUT = re.compile(r"(?:depuis|des|du|debut\w*|commence\w*|demarre\w*|apparu\w*|premiere?s?)(?:\s+(?:le|la|du|au))?\s*$")
ROLE_FIN = re.compile(r"(?:au|jusqu'au|jusqu'a|termine\w*|fini\w*|eteint\w*|dernier\w*|arrete\w*|fin)(?:\s+(?:le|la))?\s*$")
CLES_DEBUT = ("debut", "retour", "date", "premier")
CLES_FIN = ("fin", "date", "dernier")


def _unite(suite: str) -> Tuple[str, ...]:
    """Fragments de clé exigés par l'unité qui suit le nombre (texte normalisé), ou () si aucune n'est reconnue."""
    s = suite.lstrip()
    if s.startswith("%"):
        return UNITES[0][1]
    m = re.match(r"([a-z/0-9-]+)", s)
    if not m:
        return ()
    mot = m.group(1)
    for prefixe, cles in UNITES[1:]:
        if mot.startswith(prefixe):
            return cles
    return ()


# ── découpage ───────────────────────────────────────────────────────────────────────────────────────────────────────

def phrases(texte: str) -> List[str]:
    """Une phrase par entrée : coupure aux fins de phrase et aux lignes ; les titres Markdown ne sont pas des phrases
    (ni comptés, ni publiés : le rapport publié porte ses propres titres), les puces sont retirées."""
    sortie: List[str] = []
    for ligne in str(texte or "").replace("\r", "\n").split("\n"):
        if re.match(r"^\s*#{1,6}\s", ligne):
            continue
        ligne = re.sub(r"^\s*(?:[-*•·]\s+|\d{1,2}[.)]\s+|>\s*)", "", ligne).strip()
        ligne = ligne.replace("**", "").replace("__", "").strip()
        if not ligne:
            continue
        for p in re.split(r"(?<=[.!?…])\s+(?=[A-ZÀ-ÖØ-Þ«\"(])", ligne):
            p = p.strip()
            if len(re.sub(r"\W", "", p)) >= 3:
                sortie.append(p)
    return sortie


def _dates_de(phrase: str) -> Tuple[List[Tuple[Tuple[int, int], Tuple[str, ...]]], str]:
    """Les dates de la phrase avec les clés que leur rôle exige (début, fin, ou aucune), et la phrase normalisée sans
    elles (leurs chiffres ne sont pas des nombres)."""
    t = normaliser(phrase)
    vues: List[Tuple[int, int, int]] = []          # (position, jour, mois)
    for rx, f in ((DATE_ISO, lambda m: (int(m.group(3)), int(m.group(2)))),
                  (DATE_TEXTE, lambda m: (int(m.group(1)), MOIS[m.group(2)])),
                  (DATE_JM, lambda m: (int(m.group(1)), int(m.group(2))))):
        def ote(m, f=f):
            j, mo = f(m)
            if 1 <= j <= 31 and 1 <= mo <= 12:
                vues.append((m.start(), j, mo))
                return " " * len(m.group(0))      # même longueur : les positions des suivantes restent justes
            return m.group(0)
        t = rx.sub(ote, t)
    sortie = []
    for pos, j, mo in sorted(vues):
        avant = normaliser(phrase)[max(0, pos - 30):pos]
        cles: Tuple[str, ...] = CLES_DEBUT if ROLE_DEBUT.search(avant) else CLES_FIN if ROLE_FIN.search(avant) else ()
        sortie.append(((j, mo), cles))
    return sortie, t


def _noms_de(phrase: str) -> List[str]:
    """Noms que la phrase CITE et qui doivent figurer dans le dossier."""
    noms = [m.group(0) for m in CVE.finditer(phrase)]
    sans = CVE.sub(" ", phrase)
    noms += [m.group(0) for m in HOTE.finditer(sans)]
    sans = HOTE.sub(" ", sans)
    noms += [m.group(0) for m in CATEGORIE.finditer(sans) if not m.group(0).startswith(("http", "www"))]
    # Opérateurs : sigles (≥ 3 capitales) et mots à capitale hors début de phrase, hors vocabulaire du produit.
    debut = True
    for m in re.finditer(r"[A-Za-zÀ-ÖØ-öø-ÿ][\wÀ-ÖØ-öø-ÿ'-]*|[.:;!?(«\"]", sans):
        mot = m.group(0)
        if mot in ".:;!?(«\"":
            debut = True
            continue
        mot = re.split(r"['\u2019]", mot)[-1]           # « d'OVH » : le nom est après l'apostrophe
        if not mot:
            continue
        base = normaliser(mot)
        if not debut and mot[:1].isupper() and base not in SIGLES_LIBRES and len(base) >= 3:
            noms.append(mot)
        elif debut and mot.isupper() and len(mot) >= 3 and base not in SIGLES_LIBRES:
            noms.append(mot)
        debut = False
    return noms


def verifier_phrase(phrase: str, idx: Index) -> Dict[str, Any]:
    """{statut: retenue|hypothese|retiree, motifs: [...]} ; le texte n'est rendu que s'il ne porte aucune adresse."""
    motifs: List[str] = []
    if IPV4.search(phrase) or IPV6.search(phrase):
        return {"statut": "retiree", "motifs": ["adresse IP"], "texte": None}
    n = normaliser(phrase)
    if _CAUSALITE.search(n):
        motifs.append("lien de causalité absent du dossier : « " + _CAUSALITE.search(n).group(0).strip() + " »")
    if _CAPACITE.search(n):
        motifs.append("capacité affirmée, absente du dossier : « " + _CAPACITE.search(n).group(0).strip() + " »")
    if _TENDANCE.search(n) and not idx.tendances:
        motifs.append("tendance sans mesure dans le dossier : « " + _TENDANCE.search(n).group(0).strip() + " »")
    dates, reste = _dates_de(phrase)
    ancres = 0
    for d, cles in dates:
        if idx.date_connue(d, cles):
            ancres += 1
        elif idx.date_connue(d):
            motifs.append(f"date du dossier mal attribuée : {d[0]:02d}/{d[1]:02d} n'y est pas un "
                          + ("début" if cles is CLES_DEBUT else "fin"))
        else:
            motifs.append(f"date absente du dossier : {d[0]:02d}/{d[1]:02d}")
    reste = ORDINAL.sub(lambda m: " " * len(m.group(0)), reste)
    reste = _HEX.sub(lambda m: " " * len(m.group(0)), reste)
    reste = _MASQUE.sub(lambda m: re.sub(r"\d", " ", m.group(0)) if m.group(0)[:1].isalpha() else " " * len(m.group(0)),
                        reste)      # « /24 », « blocs 24 » : une notation, pas un nombre ; « blocs » reste l'unité (#4042)
    for m in NOMBRE.finditer(reste):
        brut = m.group(0)
        v = float(re.sub(r"[ \u00a0\u202f]", "", brut).replace(",", "."))
        cles = _unite(reste[m.end():m.end() + 30])
        if idx.nombre_connu(v, cles):
            ancres += 1
        elif idx.nombre_connu(v):
            motifs.append(f"nombre du dossier mal attribué : {brut} n'y compte pas des « "
                          + re.match(r"\s*(%|[a-z/0-9-]+)", reste[m.end():]).group(1) + " »")
        else:
            motifs.append("nombre absent du dossier : " + brut)
    for nom in _noms_de(phrase):
        if idx.contient(nom):
            ancres += 1
        else:
            motifs.append("nom absent du dossier : " + nom)
    if not ancres:
        ancres = sum(1 for t in idx.termes if t in n)
    if not ancres and not motifs:
        motifs.append("phrase non adossée au dossier (aucun nombre, date ni nom du dossier)")
    if motifs:
        return {"statut": "retiree", "motifs": motifs, "texte": phrase}
    if _SUPPOSITION.search(n):
        return {"statut": "hypothese", "motifs": ["supposition : « " + _SUPPOSITION.search(n).group(0).strip() + " »"],
                "texte": phrase}
    return {"statut": "retenue", "motifs": [], "texte": phrase}


# #4030 — trois contrôles de CONTEXTE, que l'ancrage seul ne voit pas :
#  · « bloc 24 heures » : le bloc /24 (réseau d'adresses) lu comme une durée ;
#  · un niveau de risque contraire à celui du dossier (acteur.level) ;
#  · une phrase qui ne redit QUE la fenêtre d'analyse (période, date de génération, nom du sujet) : elle est juste mais
#    n'apprend rien, et gonflait le taux de phrases retenues.
HEURES_BLOC = re.compile(r"\bblocs?\b[^.]{0,30}?\b24\s*(?:h\b|heures?\b)|\b24\s*heures?\b[^.]{0,20}?\bblocs?\b")
NIVEAUX = {"low": "faible", "medium": "modere", "high": "eleve", "critical": "critique"}
SYNONYMES_NIVEAU = {"faible": "faible", "bas": "faible", "modere": "modere", "moyen": "modere", "eleve": "eleve",
                    "fort": "eleve", "haut": "eleve", "critique": "critique"}
RISQUE = re.compile(r"\b(?:risque|niveau|priorite|menace|danger)\b[^.]{0,40}?\b(faible|bas|modere|moyen|eleve|fort|haut|"
                    r"critique)\b")


DATE_TEXTE_BRUT = re.compile(r"\b(\d{1,2})(?:er)?\s+([^\W\d_]+)\b(?:\s+\d{4})?")


class Contexte:
    """Ce qu'un contrôle de contexte lit du dossier : jours de la fenêtre, sujet, niveau ; index sans la fenêtre."""

    def __init__(self, dossier: Dict[str, Any]):
        per = dossier.get("periode") or {}
        self.jours_fenetre: Set[Tuple[int, int]] = set()
        for v in (per.get("debut"), per.get("fin"), dossier.get("genere_le")):
            m = DATE_ISO.match(v) if isinstance(v, str) else None
            if m:
                self.jours_fenetre.add((int(m.group(3)), int(m.group(2))))
        self.duree = per.get("jours")
        suj = dossier.get("sujet") or {}
        self.sujet = [str(suj.get(k)) for k in ("id", "nom") if suj.get(k)]
        niv = str((dossier.get("acteur") or {}).get("level") or "").lower()
        self.niveau = NIVEAUX.get(niv)
        self.idx_sans_fenetre = Index({k: v for k, v in dossier.items() if k not in ("periode", "genere_le", "sujet")})

    def _sans_fenetre(self, phrase: str) -> str:
        """La phrase, casse gardée (les noms propres restent repérables), sans les dates de la fenêtre, sans « 90 jours »
        ni le nom du sujet."""
        def blanc(m, jour, mois):
            return " " * len(m.group(0)) if (jour, mois) in self.jours_fenetre else m.group(0)

        def texte(m):
            mois = MOIS.get(normaliser(m.group(2)))
            return blanc(m, int(m.group(1)), mois) if mois else m.group(0)
        t = DATE_ISO.sub(lambda m: blanc(m, int(m.group(3)), int(m.group(2))), phrase)
        t = DATE_JM.sub(lambda m: blanc(m, int(m.group(1)), int(m.group(2))), t)
        t = DATE_TEXTE_BRUT.sub(texte, t)
        if isinstance(self.duree, int):
            t = re.sub(rf"\b{self.duree}\s+jours\b", " ", t)
        for s in self.sujet:
            t = re.sub(re.escape(s), " ", t, flags=re.I)
        return t

    def motifs(self, phrase: str) -> List[str]:
        n = normaliser(phrase)
        out = []
        if HEURES_BLOC.search(n):
            out.append("bloc /24 lu comme une durée (« 24 heures »)")
        if isinstance(self.duree, int) and re.search(
                rf"\b(?:dur\w*|pendant|poursuivi\w*|couvr\w*|etal\w*)\b[^.]{{0,40}}\b{self.duree}\s+jours\b|"
                rf"\b{self.duree}\s+jours d'activite", n):
            out.append(f"fenêtre d'analyse ({self.duree} jours) lue comme une durée d'activité")
        m = RISQUE.search(n)
        if m and self.niveau and SYNONYMES_NIVEAU[m.group(1)] != self.niveau:
            out.append(f"niveau de risque contraire au dossier : « {m.group(1)} » au lieu de « {self.niveau} »")
        if not out:
            r = verifier_phrase(self._sans_fenetre(phrase), self.idx_sans_fenetre)
            if r["motifs"] and all(x.startswith("phrase non adossée") for x in r["motifs"]):
                out.append("ne redit que la fenêtre d'analyse ou le nom du sujet")
        return out


def verifier(texte: str, dossier: Dict[str, Any]) -> Dict[str, Any]:
    """Le rapport relu : phrases gardées (avec leur statut), phrases retirées (motifs ; texte absent si adresse),
    taux de phrases retenues en pourcentage entier."""
    idx = Index(dossier)
    ctx = Contexte(dossier)
    gardees, retirees = [], []
    for p in phrases(texte):
        r = verifier_phrase(p, idx)
        if r["statut"] != "retiree":
            m = ctx.motifs(p)
            if m:
                r = {"statut": "retiree", "motifs": m, "texte": p}
        (retirees if r["statut"] == "retiree" else gardees).append(r)
    total = len(gardees) + len(retirees)
    return {"phrases": total, "retenues": len(gardees), "retirees_n": len(retirees),
            "taux_retenues_pct": (len(gardees) * 100 + total // 2) // total if total else 0,
            "gardees": gardees, "retirees": retirees}


def texte_publie(gardees: Iterable[Dict[str, Any]]) -> str:
    """Les phrases gardées, une par ligne ; une hypothèse est préfixée « (hypothèse) »."""
    return "\n".join(("(hypothèse) " if g["statut"] == "hypothese" else "") + g["texte"] for g in gardees)
