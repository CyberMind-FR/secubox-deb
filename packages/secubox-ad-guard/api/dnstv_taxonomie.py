# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: SBX TV PRIVACY lot 2 (#3374) — taxonomie unique et garde de sûreté du moteur AUTO.

Une seule taxonomie à 10 catégories remplace, pour la décision, les trois classements historiques (`dnstv.CATEGORIES`,
`dnstv.TYPES_SERVICE`, `main.AdCategory`) ; ceux-ci restent lisibles dans les réponses, la nouvelle catégorie s'ajoute.
Chaque classification porte sa SOURCE, sa CONFIANCE (0-100) et, côté API, la date de dernière observation.

Garde : STREAMING, CDN, DRM, AUTHENTIFICATION, MISE_A_JOUR et INCONNU ne sont JAMAIS bloqués par le moteur AUTO. Seule une décision
explicite de l'administrateur le peut (règle d'origine `admin`, ou correction manuelle de catégorie). Bibliothèque stdlib seule.
"""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Union

try:
    from . import dnstv
except ImportError:                                   # lancé hors paquet
    from api import dnstv

CATEGORIES = ("PUBLICITE", "TRACKING", "TELEMETRIE", "STREAMING", "CDN", "DRM", "AUTHENTIFICATION",
              "MISE_A_JOUR", "SERVICES_CONSTRUCTEUR", "INCONNU")
PROTEGEES = frozenset({"STREAMING", "CDN", "DRM", "AUTHENTIFICATION", "MISE_A_JOUR", "INCONNU"})
SOURCES = ("liste", "apprentissage", "ndpi", "manuelle", "profil")      # `ndpi` : réservé, aucun flux nDPI -> ad-guard n'existe encore

# Ancienne valeur -> catégorie unique. Origines : dnstv.CATEGORIES, dnstv.TYPES_SERVICE, main.AdCategory (code hérité).
CORRESPONDANCE = {
    "advertising": "PUBLICITE", "tracking": "TRACKING", "telemetry": "TELEMETRIE",
    "social": "TRACKING",                             # boutons et widgets sociaux : du pistage
    "custom": "PUBLICITE",                            # liste de l'exploitant, faite pour bloquer
    "contenu": "STREAMING", "publicite": "PUBLICITE", "mesure_audience": "TRACKING", "analytique": "TRACKING",
    "qualite_video": "TELEMETRIE",                    # NPAW, Quanteec : mesure de qualité de lecture
    "cdn": "CDN", "inconnu": "INCONNU",
    # Arbitrage #3374 : une box Free, un miwifi, accounts.google.com ne sont JAMAIS bloqués seuls. SERVICES_CONSTRUCTEUR n'est alimentée
    # que par des sources explicites (référence, correction manuelle), jamais par ces deux types génériques.
    "connectivite": "INCONNU", "systeme": "INCONNU",
    "analytics": "TRACKING",
    "malware": "INCONNU", "cryptominer": "INCONNU",   # hors périmètre vie privée : jamais une raison de blocage AUTO ici
}

CONFIANCE = {"manuelle": 100, "reference": 90, "liste": 80, "services": 70, "profil": 70}
FICHIER = "classification.json"
FICHIER_CACHE = "classification-cache.json"
MODE_FICHIER = 0o640
SOURCE_AUCUNE = "aucune"                              # rien ne classe le domaine (hors SOURCES : ce n'est pas une source)
# Suffixes publics : une correction posée là couvrirait des milliers de domaines. Les SUFFIXES_2 du détecteur d'anomalies + suffixes français.
SUFFIXES_PUBLICS = frozenset({"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.kr", "co.za",
                              "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "com.hk", "com.sg", "com.tw", "co.in", "co.id", "com.pl",
                              "com.ua", "com.fr", "asso.fr", "gouv.fr", "nom.fr", "tm.fr", "presse.fr"})
FICHIER_REFERENCE = "reference-tv.txt"
MANUELLES_MAX = 2000
LECTURE_MAX = 1024 * 1024
DOSSIER_LISTES_PAQUET = Path(__file__).resolve().parents[1] / "lists"

Manuelles = Dict[Tuple[str, str], dict]             # (mac ou "", domaine) -> {"domaine", "mac", "categorie", "maj"}


class ErreurTaxonomie(ValueError):
    """Entrée refusée ; le message est sûr à montrer."""


def depuis_ancienne(valeur: Optional[str]) -> str:
    """Catégorie unique pour une ancienne valeur ; toute valeur absente ou inconnue donne INCONNU (donc protégée)."""
    return CORRESPONDANCE.get(valeur or "", "INCONNU")


def blocage_auto_permis(categorie: str) -> bool:
    """Vrai si le moteur AUTO peut, de lui-même, bloquer un domaine de cette catégorie. Une catégorie inconnue est protégée."""
    return categorie in CATEGORIES and categorie not in PROTEGEES


def _mac(brut: Optional[str]) -> str:
    if brut is None or brut == "":
        return ""
    m = brut.strip().lower() if isinstance(brut, str) else ""
    if not dnstv.MAC_RE.match(m):
        raise ErreurTaxonomie("MAC invalide")
    return m


def _domaine(brut) -> str:
    d = dnstv.valider_domaine(brut) if isinstance(brut, str) and brut == brut.strip() else None
    if not d:
        raise ErreurTaxonomie("domaine invalide")
    return d


def _suffixes(domaine: str) -> List[str]:
    parts = domaine.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


# ── référence TV ─────────────────────────────────────────────────────────────────────────────────────

def charger_reference_detail(chemin: Path) -> Tuple[List[Tuple[str, str]], List[str]]:
    """(entrées valides, lignes rejetées) de `suffixe CATEGORIE  # source`. Les rejets remontent dans `dnstv.verifier_manifeste`."""
    out, rejets = [], []
    for n, ligne in enumerate(chemin.read_text(encoding="utf-8").splitlines(), 1):
        brut = ligne.split("#", 1)[0].split()
        if not brut:
            continue
        if len(brut) == 2 and brut[1] in CATEGORIES and dnstv.valider_domaine(brut[0]) == brut[0]:
            out.append((brut[0], brut[1]))
        else:
            rejets.append(f"{chemin.name}:{n}: {' '.join(brut)[:60]}")
    return out, rejets


def charger_reference(chemin: Path) -> List[Tuple[str, str]]:
    """Entrées valides de la référence ; les lignes mal formées sont écartées (et signalées par le manifeste)."""
    return charger_reference_detail(chemin)[0]


# ── corrections manuelles ────────────────────────────────────────────────────────────────────────────

def _valider_manuelle(e) -> dict:
    if not isinstance(e, dict):
        raise ErreurTaxonomie("correction invalide")
    cat, maj = e.get("categorie"), e.get("maj", 0)
    if cat not in CATEGORIES:
        raise ErreurTaxonomie("catégorie inconnue")
    if not isinstance(maj, int) or isinstance(maj, bool) or maj < 0:
        raise ErreurTaxonomie("date invalide")
    return {"domaine": _domaine(e.get("domaine")), "mac": _mac(e.get("mac", "")), "categorie": cat, "maj": maj}


def verifier_portee(domaine: str, categorie: Optional[str], reference: Iterable[Tuple[str, str]] = (),
                    services: Iterable[Tuple[str, str]] = ()) -> None:
    """Refuse une correction trop large : TLD seul, suffixe public (co.uk, com.fr…), domaine parent qui rendrait bloquable une
    entrée protégée de la référence TV (ftven.fr -> PUBLICITE couvrirait k7.ftven.fr, nécessaire à la lecture), ou domaine qui
    couvrirait une entrée PROTÉGÉE de services.txt, elle-même comprise (free.fr -> PUBLICITE rendrait bloquable mafreebox.free.fr, #3374 lot 3).
    `services` : couples (suffixe, type de service)."""
    if isinstance(domaine, str) and "." not in domaine.strip(".") and domaine.strip():
        raise ErreurTaxonomie("correction trop large : un domaine de premier niveau seul est un suffixe public")
    d = domaine.strip().lower().rstrip(".") if isinstance(domaine, str) else ""
    if d in SUFFIXES_PUBLICS:
        raise ErreurTaxonomie(f"correction trop large : {d} est un suffixe public")
    if categorie is not None and blocage_auto_permis(categorie):
        couvertes = sorted(r for r, c in reference if c in PROTEGEES and (r == d or r.endswith("." + d)) and r != d)
        if couvertes:
            raise ErreurTaxonomie(f"correction trop large : {d} couvre {couvertes[0]} (catégorie protégée de la référence) ; "
                                  "corriger le sous-domaine visé")
        srv = sorted(x for x, t in services if depuis_ancienne(t) in PROTEGEES and (x == d or x.endswith("." + d)))
        if srv:
            raise ErreurTaxonomie(f"correction trop large : {d} couvre {srv[0]} (service protégé de services.txt) ; "
                                  "corriger le sous-domaine visé")


def corriger(manuelles: Manuelles, domaine: str, mac: Optional[str], categorie: Optional[str], maintenant: int,
             reference: Iterable[Tuple[str, str]] = (), services: Iterable[Tuple[str, str]] = ()) -> Manuelles:
    """Pose (ou retire si `categorie` est None) la correction manuelle d'un domaine, pour une MAC ou pour toute la maison. Pur.
    `reference` : entrées de la référence TV, pour refuser une correction qui en couvrirait une protégée (voir `verifier_portee`)."""
    verifier_portee(domaine, categorie, reference, services)
    d = _domaine(domaine.lower() if isinstance(domaine, str) else domaine)
    m = _mac(mac)
    out = dict(manuelles)
    if categorie is None:
        out.pop((m, d), None)
        return out
    if categorie not in CATEGORIES:
        raise ErreurTaxonomie("catégorie inconnue")
    if (m, d) not in out and len(out) >= MANUELLES_MAX:
        raise ErreurTaxonomie("trop de corrections manuelles")
    out[(m, d)] = {"domaine": d, "mac": m, "categorie": categorie, "maj": int(maintenant)}
    return out


def charger_manuelles(dossier: Optional[Path] = None) -> Manuelles:
    """Corrections manuelles ; fichier absent = aucune. Lien symbolique ou contenu invalide : refus entier (rien de partiellement digne de confiance)."""
    f = (dossier or dnstv.DOSSIER_ETAT) / FICHIER
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise ErreurTaxonomie(f"corrections refusées ({type(e).__name__})") from e
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            brut = json.loads(h.read(LECTURE_MAX))
    except (OSError, ValueError) as e:
        raise ErreurTaxonomie("corrections illisibles") from e
    if not isinstance(brut, dict) or brut.get("version") != 1 or not isinstance(brut.get("manuelles"), list) \
            or len(brut["manuelles"]) > MANUELLES_MAX:
        raise ErreurTaxonomie("corrections illisibles")
    out: Manuelles = {}
    for e in brut["manuelles"]:
        v = _valider_manuelle(e)
        out[(v["mac"], v["domaine"])] = v
    return out


def ecrire_manuelles(manuelles: Manuelles, dossier: Optional[Path] = None) -> None:
    """Écriture atomique ; l'appelant tient `dnstv_regles.verrou`."""
    lignes = sorted((_valider_manuelle(e) for e in manuelles.values()), key=lambda x: (x["domaine"], x["mac"]))
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".classification.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            json.dump({"version": 1, "manuelles": lignes}, h, indent=2, ensure_ascii=False)
        os.chmod(tmp, MODE_FICHIER)
        os.replace(tmp, d / FICHIER)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ── classification ───────────────────────────────────────────────────────────────────────────────────

class Taxonomie:
    """Classe un domaine (pour un appareil) : catégorie, source, confiance. Aucune entrée/sortie après construction.

    Ordre : correction manuelle (MAC puis maison) ; suffixe le plus long parmi la référence TV, les listes livrées et services.txt (la
    référence gagne à suffixe égal) ; profil de base ; apprentissage (règle connue, toujours INCONNU) ; sinon INCONNU.
    """

    def __init__(self, reference: Iterable[Tuple[str, str]] = (), services: Iterable[Tuple[str, str, str]] = (),
                 listes: Union[Dict[str, str], Callable[[str], str], None] = None, profil: Iterable[str] = (),
                 manuelles: Optional[Manuelles] = None, regles=None):
        self.reference = {d: c for d, c in reference}
        self.services = {s: t for s, _org, t in services}
        self.table = listes if isinstance(listes, dict) else {}
        self.classer_listes = listes if callable(listes) else None
        self.profil = set(profil)
        self.manuelles = manuelles or {}
        self.appris = {}
        for r in (regles.liste() if regles is not None else []):
            self.appris[r["domaine"]] = max(self.appris.get(r["domaine"], 0), min(100, int(r.get("score", 0))))

    @classmethod
    def depuis_dossier(cls, dossier: Optional[Path] = None, perso: Optional[Path] = None, classer=None, **kw) -> "Taxonomie":
        """Taxonomie depuis un dossier de listes (par défaut celui du paquet installé, sinon l'arbre de sources)."""
        d = dossier or dnstv.DOSSIER_LISTES

        def f(nom: str) -> Path:                       # fichier du dossier, sinon celui de l'arbre de sources (paquet non installé, tests)
            return d / nom if (d / nom).is_file() or dossier else DOSSIER_LISTES_PAQUET / nom
        ref, srv, prof = f(FICHIER_REFERENCE), f("services.txt"), f("profil-tv-base.txt")
        return cls(reference=charger_reference(ref) if ref.is_file() else [],
                   services=dnstv.charger_services(srv) if srv.is_file() else [],
                   listes=classer if classer is not None else dnstv.charger_listes(d, perso),
                   profil=dnstv.lire_liste(prof)[0] if prof.is_file() else [], **kw)

    def _resultat(self, domaine, categorie, source, confiance, ancienne=None) -> dict:
        return {"domaine": domaine, "categorie": categorie, "source": source, "confiance": int(confiance), "ancienne": ancienne,
                "protegee": not blocage_auto_permis(categorie)}

    def classer(self, domaine: str, macs: Iterable[str] = ()) -> dict:
        d = dnstv.valider_domaine(dnstv.domaine_reel(domaine.strip().lower().rstrip("."))) if isinstance(domaine, str) else None
        if not d:
            return self._resultat(str(domaine)[:253], "INCONNU", SOURCE_AUCUNE, 0)
        suff = _suffixes(d)
        for m in [x for x in macs if x] + [""]:
            for s in suff:
                e = self.manuelles.get((m, s))
                if e:
                    return self._resultat(d, e["categorie"], "manuelle", CONFIANCE["manuelle"])
        for s in suff:
            if s in self.reference:
                return self._resultat(d, self.reference[s], "liste", CONFIANCE["reference"])
            if s in self.table:
                return self._resultat(d, depuis_ancienne(self.table[s]), "liste", CONFIANCE["liste"], self.table[s])
            if s in self.services:
                return self._resultat(d, depuis_ancienne(self.services[s]), "liste", CONFIANCE["services"], self.services[s])
        if self.classer_listes is not None:
            a = self.classer_listes(d) or ""
            if a:
                return self._resultat(d, depuis_ancienne(a), "liste", CONFIANCE["liste"], a)
        if d in self.profil:
            return self._resultat(d, "PUBLICITE", "profil", CONFIANCE["profil"])     # graine validée sur deux TV réelles (#1943/#1954)
        if d in self.appris:
            return self._resultat(d, "INCONNU", "apprentissage", self.appris[d])  # l'apprentissage ne se justifie jamais lui-même
        return self._resultat(d, "INCONNU", SOURCE_AUCUNE, 0)


def confirmes_par_admin(regles) -> set:
    """Domaines dont la DERNIÈRE transition est une confirmation de l'administrateur, sur au moins un appareil. Calculé une fois par passage."""
    out = set()
    for r in (regles.liste() if regles is not None else []):
        h = (r.get("historique") or [{}])[-1]
        if r["etat"] == "confirme" and h.get("vers") == "confirme" and h.get("origine") == "admin":
            out.add(r["domaine"])
    return out


def refus_auto(taxo: Taxonomie, domaine: str, macs: Iterable[str] = (), confirmes_admin: Iterable[str] = frozenset()) -> Optional[str]:
    """Motif du refus si le moteur AUTO ne peut PAS bloquer seul ce domaine ; None s'il le peut.

    Exception (arbitrée) : un domaine CONFIRMÉ PAR L'ADMINISTRATEUR sur au moins un appareil (`confirmes_admin`, voir
    `confirmes_par_admin`) n'est plus protégé, et ce sur TOUS les chemins automatiques et pour TOUS les appareils : essai automatique
    d'un candidat détecté, essai automatique d'un candidat agrégé, confirmation automatique d'un essai échu, profil posé à l'ajout
    automatique d'un appareil. Une confirmation par le moteur lui-même (origine `auto`) ne lève jamais la garde.
    """
    c = taxo.classer(domaine, macs)
    if blocage_auto_permis(c["categorie"]):
        return None
    if c["domaine"] in confirmes_admin:
        return None
    return f"catégorie {c['categorie']} protégée : décision manuelle requise"


def macs_par_appareil(etat: dict) -> Dict[str, List[str]]:
    """slug d'appareil -> MAC connues (pour les corrections propres à un appareil)."""
    out: Dict[str, List[str]] = {}
    for c in etat.get("clients", []):
        if c.get("mac"):
            lst = out.setdefault(dnstv._slug(c["nom"]), [])
            if c["mac"] not in lst:
                lst.append(c["mac"])
    return out


# ── classification par appareil et cache (calculé par le moteur AUTO, lu par l'API) ────────────────────────────────────

def construire_classification(etat: dict, taxo: Taxonomie, observations: Dict[str, Dict[str, dict]], regles: List[dict]) -> List[dict]:
    """Une ligne par (domaine, appareil) : domaines observés (`Magasin.observations`), domaines des règles et corrections manuelles,
    même non observés. Appareil = MAC si connue, sinon l'adresse. Pur."""
    mac_de_ip = {c["ip"]: c.get("mac") for c in etat.get("clients", [])}
    macs_slug = macs_par_appareil(etat)
    lignes: Dict[Tuple[str, str], dict] = {}

    def ajouter(domaine: str, mac: Optional[str], ip: Optional[str] = None, obs: Optional[dict] = None) -> None:
        cle = (domaine, mac or f"ip:{ip or ''}")
        e = lignes.get(cle)
        if e is None:
            e = lignes[cle] = dict(taxo.classer(domaine, [mac] if mac else []), mac=mac, ips=[], requetes=0, bloquees=0,
                                   derniere_observation=None, precision=None)
        if ip and ip not in e["ips"]:
            e["ips"].append(ip)
        if obs:
            e["requetes"] += obs["requetes"]
            e["bloquees"] += obs["bloquees"]
            if obs["derniere"] and (e["derniere_observation"] is None or obs["derniere"] > e["derniere_observation"]):
                e["derniere_observation"], e["precision"] = obs["derniere"], obs["precision"]

    for ip, doms in observations.items():
        for d, o in doms.items():
            if dnstv.valider_domaine(d) == d:
                ajouter(d, mac_de_ip.get(ip), ip, o)
    deja = {(d, e["mac"]) for (d, _), e in lignes.items()}
    domaines_vus = {d for d, _ in deja}
    for r in regles:                                                      # domaines appris ou décidés, même non observés récemment
        for mac in macs_slug.get(r["appareil"], [None]):
            if (r["domaine"], mac) not in deja:
                ajouter(r["domaine"], mac)
                deja.add((r["domaine"], mac))
                domaines_vus.add(r["domaine"])
    for (mac, d) in taxo.manuelles:                                       # corrections manuelles, même non observées
        propre_a_un_appareil = bool(mac)
        if propre_a_un_appareil and (d, mac) not in deja:
            ajouter(d, mac)
        elif not propre_a_un_appareil and d not in domaines_vus:          # correction pour la maison : une ligne si aucun appareil ne l'a
            ajouter(d, None)
    return sorted(lignes.values(), key=lambda e: (-(e["derniere_observation"] or 0), e["domaine"], e["mac"] or ""))


def ecrire_cache(lignes: List[dict], maintenant: int, dossier: Optional[Path] = None) -> None:
    """Cache de la classification (#3374, PERF-CACHE) : écriture atomique, 0640 (données personnelles : MAC, adresses)."""
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".classification-cache.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            json.dump({"version": 1, "genere": int(maintenant), "domaines": lignes}, h, ensure_ascii=False)
        os.chmod(tmp, MODE_FICHIER)
        os.replace(tmp, d / FICHIER_CACHE)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def lire_cache(dossier: Optional[Path] = None) -> Optional[dict]:
    """Cache ou None (absent, lien symbolique, illisible) : l'API ne recalcule jamais de façon synchrone."""
    f = (dossier or dnstv.DOSSIER_ETAT) / FICHIER_CACHE
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            brut = json.loads(h.read(16 * 1024 * 1024))
    except (OSError, ValueError):
        return None
    if not isinstance(brut, dict) or brut.get("version") != 1 or not isinstance(brut.get("domaines"), list):
        return None
    return brut
