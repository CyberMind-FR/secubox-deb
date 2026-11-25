# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Dossiers par site (#3963) : agrégat horaire, 24 h glissantes, du journal des menaces, par site servi.

Tâche de fond seulement, jamais sur le chemin d'une requête : un curseur `<inode>:<octet>` suit le journal par
`veille_lecture.lire_flux` (rotation, troncature, ligne coupée), donc seuls les octets NEUFS sont lus (17 lignes par
minute sur la box de production). Premier départ : `REPRISE_OCTETS` au plus par la fin de `.1` puis du courant, étalés
sur plusieurs passes. L'état (compteurs et curseur) est écrit par remplacement atomique toutes les `ECRITURE_S` : un
redémarrage ne relit que ce qui a suivi.

Couches (ce que le moteur a réellement répondu) : `banned` = arrêté (adresse bannie) ; `warning` = refusé (page 403, ou
421 pour un nom non servi, adresse pas encore bannie) ; `leurre_redirige` = détourné (champ `servies` : requêtes
représentées par la ligne) ; `detect` = vu, laissé passer ; `robot` = robots refusés, à part. Les lignes d'état
(multipart-*, body-inspect-*, gravité « audit ») ne sont pas des requêtes hostiles et ne comptent pas.

Couverture à la minute : une minute est couverte si une ligne y porte sa date, si deux lignes consécutives l'encadrent à
PONT_S au plus, ou si le moteur a donné signe de vie (état nft publié toutes les 30 s) à deux passes rapprochées qui ont
lu le journal jusqu'au bout. Une heure complète se lit telle quelle ; une heure partielle se lit comme un minimum et ne
vaut jamais 0 (null) ; une heure sans couverture vaut null. Aucune adresse n'est gardée.

Un lot (une passe) s'ajoute sur une copie de l'état et n'avance le curseur qu'avec le lot entier. Le fichier suivi se
reconnaît à son inode ET à sa première ligne : journal supprimé, recréé ou tronqué, rien n'est compté deux fois. Retard
de plus de RETARD_MAX octets : on saute au plus récent, les minutes sautées restent non couvertes."""
import asyncio
import hashlib
import json
import logging
import math
import os
import re
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi import Path as ParamChemin
from fastapi.security import HTTPAuthorizationCredentials

from secubox_core.auth import SESSION_COOKIE, _validate_token, est_admin_reel, require_jwt, require_lecture

try:
    from api import populations as _populations, veille_lecture as _veille
except ImportError:  # standalone
    import populations as _populations
    import veille_lecture as _veille

log = logging.getLogger("secubox.waf.dossiers")
router = APIRouter(prefix="/dossiers", tags=["dossiers"])

VERSION = 2
HEURES = 24
PERIODE_S = 55                    # s : une passe par minute (la boucle de fond tourne toutes les 30 s)
ECRITURE_S = 300                  # s entre deux écritures de l'état (usure de l'eMMC)
PERIME_S = 600                    # relevé plus vieux : la page le dit
REPRISE_OCTETS = 24 * 1024 * 1024  # relus au plus au premier départ
PASSE_LIGNES, PASSE_OCTETS, PASSE_TOURS = 4000, 1024 * 1024, 4   # par passe de fond
MAX_SITES = 300                   # sites distincts suivis
MAX_CATS = 24                     # catégories par site et par heure, le reste dans « autres »
MAX_CELLULES = 40_000             # cellules site × heure × catégorie, tous sites confondus
MAX_CALMES = 500
MAX_FAITS = 8
VIE_MOTEUR_S = 180                # état nft plus récent : le moteur vit ; deux passes plus proches : signe continu
PONT_S = 600                      # deux lignes consécutives plus proches : le journal couvre l'entre-deux
COMPLETE_MIN = 55                 # minutes couvertes d'une heure complète
TOLERANCE_MIN = 60 - COMPLETE_MIN
RETARD_MAX = 8 * 1024 * 1024      # retard de lecture au-delà duquel on saute (hors premier rattrapage)
SAUT_OCTETS = 1024 * 1024         # relus avant la fin après un saut
MAX_SAUTS, MAX_LUS = 1500, 8
ROTATION_FRAICHE_S = 6 * 3600
ETAT_DECISION_S = 15 * 60         # même fraîcheur que enforcement.FRAICHEUR_ETAT_S
TAILLE_MAX = 8 * 1024 * 1024
ATTAQUE_MIN, ATTAQUE_FACTEUR, ATTAQUE_HISTORIQUE = 30, 3, 6
PARIS = ZoneInfo("Europe/Paris")

INCONNUS = "noms-inconnus"
NOM_INCONNUS = "Noms inconnus"
COUCHES = ("arrete", "refuse", "detourne", "passe", "robots")
HOSTILES = 4                      # les quatre premières couches ; les robots sont à part
NOMS_COUCHES = {"arrete": "Arrêté", "refuse": "Refusé", "detourne": "Détourné", "passe": "Laissé passer",
                "robots": "Robots refusés"}
ACTIONS = {"banned": 0, "warning": 1, "leurre_redirige": 2, "detect": 3, "robot": 4}
DEFINITIONS = {"arrete": "Requête refusée et adresse bannie.",
               "refuse": "Page de refus, adresse pas encore bannie.",
               "detourne": "Réponse jouée par un leurre, jamais le vrai site.",
               "passe": "Vue par une règle en détection seule, puis servie.",
               "robots": "Robot déclaré refusé pour la charge, pas une attaque."}

CATEGORIES = {
    "sqli": "Injection SQL", "xss": "Script injecté", "lfi": "Lecture de fichiers interdits", "rce": "Exécution de code",
    "cve_2024": "Failles connues", "scanners": "Outils de balayage", "webmail": "Attaque du webmail",
    "api_abuse": "Abus d’API", "voip": "Attaque de la téléphonie", "xmpp": "Attaque de la messagerie instantanée",
    "cve_voip": "Failles de téléphonie", "cve_xmpp": "Failles de messagerie instantanée",
    "router_botnet": "Robots de prise de contrôle", "waf_fingerprint": "Sonde du pare-feu", "honeypot": "Pièges touchés",
    "recon_crawler": "Exploration", "credential_harvest": "Recherche de mots de passe",
    "product_absent_probes": "Logiciels absents d’ici", "roundcube": "Failles de Roundcube",
    "nextcloud": "Failles de Nextcloud", "php_requete": "Requêtes PHP anormales", "aspirateur_ua": "Outil d’aspiration",
    "php2shell": "Envoi de code PHP", "leurre_redirige": "Redirigé vers un leurre", "robots": "Robots",
    "rotation": "Adresses tournantes", "host_anomaly:unrouted": "Nom non servi", "host_anomaly:empty": "Nom absent",
    "host_anomaly:ip_literal": "Adresse à la place du nom", "host_anomaly:dga": "Nom fabriqué",
    "autres": "Autres motifs",
}
CLASSES = {"proxy_loue": "Relais loués", "hebergeur": "Hébergeurs", "acces": "Accès grand public",
           "mobile_partage": "Mobile ou satellite", "cdn": "Réseaux de diffusion", "relais_vie_privee": "Relais de vie privée",
           "scanner_recherche": "Balayeurs de recherche", "inconnu": "Réseau inconnu"}
FAMILLES = {"collecte": "Collecte", "messagerie": "Mots de passe sur la messagerie",
            "acces_distant": "Balayage des leurres de service", "balayage_web": "Balayage des sites web",
            "autre": "Autre activité"}

_CAT = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")
_AUTHWATCH = ("auth_", "leurre:", "leurre_ssh", "leurre_smtp")

#: Chemins (remplacés dans les tests) : posés par `configurer` depuis main.py.
CHEMINS: Dict[str, Path] = {
    "journal": Path("/var/log/secubox/waf/waf-threats.log"),
    "etat": Path("/var/lib/secubox/waf/dossiers.json"),
    "routes": Path("/etc/secubox/waf/haproxy-routes.json"),
    "vie": Path("/var/cache/secubox/waf/nft-etat.json"),
    "populations": Path("/var/lib/secubox/waf/populations.json"),
    "rotation": Path("/var/lib/secubox/waf/rotation-etat.json"),
    "campagnes": Path("/var/lib/secubox/waf/campagne-ban-etat.json"),
    "acteurs": Path("/var/lib/secubox/waf/actor-ban-etat.json"),
}


def configurer(**chemins: Any) -> None:
    CHEMINS.update({k: Path(v) for k, v in chemins.items()})


# ── français ─────────────────────────────────────────────────────────────────────────────────────────────────────

def nb(n: Any) -> str:
    """Nombre groupé à la française (espace insécable)."""
    return f"{int(n):,}".replace(",", " ")


def pl(n: int, sing: str, plur: str) -> str:
    """« 1 adresse », « 2 adresses » ; zéro est au singulier, comme en français."""
    return f"{nb(n)} {sing if abs(int(n)) < 2 else plur}"


def pct(x: float) -> str:
    """Pour cent, une décimale, arrondi vers le bas : 99,97 % ne s'écrit jamais 100 %."""
    v = int(x * 10) / 10
    return (f"{int(v)}" if v == int(v) else f"{v:.1f}".replace(".", ",")) + " %"


def libelle_cat(cat: str) -> str:
    if cat in CATEGORIES:
        return CATEGORIES[cat]
    if cat.startswith("ia_filtres"):
        return "Filtres de l’IA"
    texte = cat.replace("_", " ").replace(":", " ")
    return texte[:1].upper() + texte[1:]


def _bas(texte: str) -> str:
    """Première lettre en minuscule, sigles gardés : « Injection SQL » → « injection SQL »."""
    return texte if len(texte) > 1 and texte[1].isupper() else texte[:1].lower() + texte[1:]


# ── état ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def _neuf() -> Dict[str, Any]:
    return {"v": VERSION, "curseur": None, "tete": None, "lus": [], "couverture_depuis": None, "dernier_ts": None,
            "pont": None, "vu": None, "initial": True, "rattrapage": False, "couv": {}, "heures": {}, "derniers": {},
            "hors_web": {}, "sauts": [], "illisibles": 0, "hors_plafond": 0, "trous": 0}


_HEURE = re.compile(r"^[0-9]{1,8}$")
_TETE = re.compile(r"^[0-9a-f]{40}$")


def _nat(v: Any, maxi: int = 1 << 52) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < maxi


def _valide_site(k: Any) -> bool:
    return k == INCONNUS or (isinstance(k, str) and normaliser_hote(k) == k)


def _valide_cat(k: Any) -> bool:
    return isinstance(k, str) and _categorie(k) == k


def _valide_case(s: Any) -> bool:
    return (isinstance(s, dict) and set(s) == {"c", "o"} and isinstance(s["c"], dict) and isinstance(s["o"], dict)
            and len(s["c"]) <= MAX_CATS + 1
            and all(_valide_cat(k) and isinstance(v, list) and len(v) == len(COUCHES) and all(map(_nat, v)) for k, v in s["c"].items())
            and all(k in CLASSES and _nat(v) for k, v in s["o"].items()))


def _valide(e: Any) -> bool:
    """Schéma entier de l'état : un champ de trop, manquant ou d'un autre type, et l'état est refusé en bloc."""
    if not (isinstance(e, dict) and e.get("v") == VERSION and set(_neuf()) <= set(e) <= set(_neuf()) | {"lu", "genere_le"}):
        return False
    if any(not isinstance(e[k], dict) for k in ("couv", "heures", "derniers", "hors_web")):
        return False
    if any(not isinstance(e[k], bool) for k in ("initial", "rattrapage")) or not isinstance(e.get("lu", False), bool):
        return False
    if any(e[k] is not None and not _nat(e[k]) for k in ("couverture_depuis", "dernier_ts", "pont", "vu")):
        return False
    if not all(_nat(e[k]) for k in ("illisibles", "hors_plafond", "trous")) or not _nat(e.get("genere_le", 0)):
        return False
    if e["curseur"] is not None and not (isinstance(e["curseur"], str) and _veille.RE_POSITION.fullmatch(e["curseur"])):
        return False
    if e["tete"] is not None and not (isinstance(e["tete"], str) and _TETE.match(e["tete"])):
        return False
    if not (isinstance(e["lus"], list) and len(e["lus"]) <= MAX_LUS and all(isinstance(x, str) and _TETE.match(x) for x in e["lus"])):
        return False
    if not (isinstance(e["sauts"], list) and len(e["sauts"]) <= MAX_SAUTS and all(map(_nat, e["sauts"]))):
        return False
    if not all(_HEURE.match(h) and _nat(m, 1 << 60) for h, m in e["couv"].items()):
        return False
    if not all(_HEURE.match(h) and _nat(n) for h, n in e["hors_web"].items()):
        return False
    if not all(_HEURE.match(h) and isinstance(d, dict) and len(d) <= MAX_SITES + 1
               and all(_valide_site(k) and _valide_case(v) for k, v in d.items()) for h, d in e["heures"].items()):
        return False
    return all(_valide_site(s) and isinstance(d, dict) and all(
        c in COUCHES and isinstance(v, list) and len(v) == 2 and _nat(v[0]) and _valide_cat(v[1]) for c, v in d.items())
        for s, d in e["derniers"].items())


def lire_etat(chemin: Path) -> Dict[str, Any]:
    """L'état gardé, ou un état neuf s'il manque, est illisible ou d'une autre version."""
    e = _json(chemin)
    if e is not None and _valide(e):
        return {k: e[k] for k in _neuf()}
    return _neuf()


def ecrire_etat(chemin: Path, etat: Dict[str, Any]) -> bool:
    """Remplacement atomique : un lecteur ne voit jamais un fichier à moitié écrit."""
    tmp = None
    try:
        chemin.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".dossiers-", suffix=".tmp", dir=chemin.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o640)
            json.dump(etat, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, chemin)
        return True
    except OSError as e:
        log.warning("dossiers : état non écrit : %s", e)
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                log.debug("dossiers : temporaire déjà parti")
        return False


def _json(chemin: Path) -> Any:
    try:
        with open(chemin, "rb") as f:
            brut = f.read(TAILLE_MAX + 1)
    except OSError:
        return None
    if len(brut) > TAILLE_MAX:
        return None
    try:
        return json.loads(brut.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None


def _entier(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


# ── sites servis ─────────────────────────────────────────────────────────────────────────────────────────────────

def normaliser_hote(v: Any) -> Optional[str]:
    """Nom d'hôte en minuscules, sans port ni point final ; None pour une adresse ou un nom impossible."""
    h = _populations._hote(v)
    return None if h is None or _populations._adresse_litterale(h) else h


_routes_memo: Dict[str, Any] = {}


def sites_servis() -> Optional[frozenset]:
    """Noms de la table de routes du moteur (relue si elle change) ; None si elle est absente ou illisible."""
    chemin = CHEMINS["routes"]
    try:
        st = chemin.stat()
    except OSError:
        return None
    cle = (str(chemin), st.st_mtime_ns, st.st_size, st.st_ino)
    if _routes_memo.get("cle") != cle:
        d = _json(chemin)
        noms = frozenset(h for h in map(normaliser_hote, d) if h) if isinstance(d, dict) else None
        _routes_memo.update(cle=cle, noms=noms)
    return _routes_memo["noms"]


# ── ingestion ────────────────────────────────────────────────────────────────────────────────────────────────────

def _categorie(v: Any) -> str:
    c = v if isinstance(v, str) else ""
    if c.startswith("rotation:"):
        return "rotation"
    return c if _CAT.match(c) else "autres"


class Agregateur:
    """Compteurs en mémoire, bornés : MAX_SITES sites, MAX_CATS catégories par site et par heure, MAX_CELLULES en tout."""

    def __init__(self, etat: Optional[Dict[str, Any]] = None):
        self.e = etat if etat is not None else _neuf()
        self._sites = {s for sites in self.e["heures"].values() for s in sites}
        self._cellules = sum(len(s["c"]) for sites in self.e["heures"].values() for s in sites.values())

    def copie(self) -> "Agregateur":
        return Agregateur(json.loads(json.dumps(self.e)))

    # ── couverture, à la minute ──
    def couvrir(self, debut: float, fin: float) -> None:
        for m in range(int(debut // 60), int(fin // 60) + 1):
            cle = str(m // 60)
            self.e["couv"][cle] = self.e["couv"].get(cle, 0) | (1 << (m % 60))
        if self.e["couverture_depuis"] is None:
            self.e["couverture_depuis"] = int(debut)

    def minutes(self, heure: int) -> int:
        return bin(self.e["couv"].get(str(heure), 0)).count("1")

    def complete(self, heure: int, maintenant: float) -> bool:
        attendu = 60 if heure < int(maintenant // 3600) else int(maintenant % 3600 // 60) + 1
        return self.minutes(heure) >= max(1, attendu - TOLERANCE_MIN)

    def vivant(self, maintenant: float, vie: bool) -> None:
        """Journal lu jusqu'au bout. Moteur vivant à deux passes rapprochées : l'entre-deux est couvert, même sans
        événement. Un signe de vie interrompu ne couvre que sa minute."""
        if not vie:
            self.e["vu"] = None
            return
        vu = self.e["vu"]
        self.couvrir(vu if vu is not None and 0 <= maintenant - vu <= VIE_MOTEUR_S else maintenant, maintenant)
        self.e["vu"] = int(maintenant)

    # ── une ligne ──
    def ajouter(self, ligne: Any, servis: Optional[frozenset], maintenant: float) -> None:
        """Une ligne qui lève est comptée illisible et sautée : jamais relue en boucle."""
        try:
            self._ajouter(ligne, servis, maintenant)
        except Exception as e:  # noqa: BLE001 — contenu venu de l'extérieur : aucune ligne ne doit bloquer le journal
            self.e["illisibles"] += 1
            log.debug("dossiers : ligne sautée : %s", type(e).__name__)

    def _ajouter(self, ligne: Any, servis: Optional[frozenset], maintenant: float) -> None:
        t = _populations._horodatage(ligne.get("timestamp")) if isinstance(ligne, dict) else None
        # date illisible, infinie ou du futur : ni heure couverte, ni compte
        if t is None or not math.isfinite(t) or t > maintenant + 300:
            self.e["illisibles"] += 1
            return
        t = min(t, maintenant)
        h = int(t // 3600)
        if h <= int(maintenant // 3600) - HEURES:
            return
        cat = ligne.get("category")
        cat = cat if isinstance(cat, str) else ""
        action = ligne.get("action")
        hote = normaliser_hote(ligne.get("host"))
        classe = ligne.get("reseau_classe")
        classe = classe if isinstance(classe, str) and classe in CLASSES else "inconnu"
        pont = self.e["pont"]
        self.couvrir(pont if pont is not None and 0 <= t - pont <= PONT_S else t, t)
        self.e["pont"] = max(int(t), pont or 0)
        self.e["dernier_ts"] = max(int(t), self.e["dernier_ts"] or 0)
        if ligne.get("tool") == "authwatch" or cat.startswith(_AUTHWATCH):
            if ligne.get("severity") != "audit":
                self.e["hors_web"][str(h)] = self.e["hors_web"].get(str(h), 0) + 1
            return
        couche = ACTIONS.get(action) if isinstance(action, str) else None
        if couche is None:
            return
        n = 1
        if action == "leurre_redirige":
            n = max(1, min(_entier(ligne.get("servies")), 1_000_000))
        elif ligne.get("severity") == "audit" or cat.startswith(("multipart-", "body-inspect-")):
            return                     # ligne d'état, pas une requête hostile
        # table de routes illisible : échec fermé, un nom qu'on ne peut pas vérifier n'est jamais un site
        site = hote if hote is not None and not cat.startswith("host_anomaly") and servis is not None and hote in servis else INCONNUS
        if site not in self._sites and site != INCONNUS and len(self._sites) >= MAX_SITES:
            self.e["hors_plafond"] += n
            return
        self._sites.add(site)
        s = self.e["heures"].setdefault(str(h), {}).setdefault(site, {"c": {}, "o": {}})
        cle = _categorie(cat)
        if cle not in s["c"] and cle != "autres" and (len(s["c"]) >= MAX_CATS or self._cellules >= MAX_CELLULES):
            cle = "autres"
        if cle not in s["c"]:
            s["c"][cle] = [0] * len(COUCHES)
            self._cellules += 1
        s["c"][cle][couche] += n
        if couche < HOSTILES:
            s["o"][classe] = s["o"].get(classe, 0) + n
        d = self.e["derniers"].setdefault(site, {})
        if int(t) >= (d.get(COUCHES[couche]) or [0])[0]:
            d[COUCHES[couche]] = [int(t), cle]

    def trou(self) -> None:
        """Des lignes ont pu être perdues : rien ne relie la dernière ligne lue à la suivante."""
        self.e["trous"] += 1
        self.e["pont"] = self.e["vu"] = None

    def purger(self, maintenant: float) -> None:
        seuil = int(maintenant // 3600) - HEURES
        for table in ("heures", "hors_web", "couv"):
            for k in [k for k in self.e[table] if int(k) <= seuil]:
                del self.e[table][k]
        self.e["sauts"] = [x for x in self.e["sauts"] if x > maintenant - HEURES * 3600][-MAX_SAUTS:]
        self._sites = {s for sites in self.e["heures"].values() for s in sites}
        self._cellules = sum(len(s["c"]) for sites in self.e["heures"].values() for s in sites.values())
        self.e["derniers"] = {s: {c: v for c, v in d.items() if v[0] > maintenant - HEURES * 3600}
                              for s, d in self.e["derniers"].items() if s in self._sites}

    # ── suivi du journal ──
    def _placer(self, journal: Path) -> bool:
        """Place le curseur sur un fichier QUI EXISTE. Même inode et même première ligne : on continue. Même première
        ligne ailleurs (fichier recopié) : on continue au même octet. Sinon le fichier suivi est perdu : on repart au
        début d'un fichier jamais lu, jamais d'un fichier déjà compté."""
        courant, tourne = _fichier(journal), _fichier(journal.with_name(journal.name + ".1"))
        if courant is None:
            return False
        if self.e["curseur"] is None:
            self.e["curseur"], self.e["tete"] = depart(journal, courant, tourne, REPRISE_OCTETS)
            return True
        ino, octet = (int(x) for x in self.e["curseur"].split(":"))
        tete = self.e["tete"]
        presents = [f for f in (courant, tourne) if f is not None]
        for f in presents:
            if f["ino"] == ino and octet <= f["taille"] and (tete is None and octet == 0 or f["tete"] == tete):
                self.e["tete"] = f["tete"]
                return True
        for f in presents:
            if tete is not None and f["tete"] == tete and octet <= f["taille"]:
                self.e["curseur"] = f"{f['ino']}:{octet}"
                return True
        self.trou()
        self._lu(tete)
        depuis = self.e["dernier_ts"] or 0
        f = courant
        if tourne is not None and tourne["tete"] is not None and tourne["tete"] not in self.e["lus"] and (tourne["premier"] or 0) > depuis:
            f = tourne
        if f["tete"] is not None and f["tete"] in self.e["lus"]:
            if not f["finie"]:
                return False                       # ligne en cours : repris au tour suivant, jamais relu depuis le début
            self.e["curseur"], self.e["tete"] = f"{f['ino']}:{f['taille']}", f["tete"]      # déjà compté
            return True
        self.e["curseur"], self.e["tete"] = f"{f['ino']}:0", f["tete"]
        return True

    def _lu(self, tete: Optional[str]) -> None:
        if tete is not None and tete not in self.e["lus"]:
            self.e["lus"] = (self.e["lus"] + [tete])[-MAX_LUS:]

    def retard(self, journal: Path) -> int:
        """Octets du journal (courant et `.1`) pas encore lus."""
        if self.e["curseur"] is None:
            return 0
        ino, octet = (int(x) for x in self.e["curseur"].split(":"))
        courant, tourne = _fichier(journal), _fichier(journal.with_name(journal.name + ".1"))
        if courant is None:
            return 0
        if courant["ino"] == ino:
            return max(0, courant["taille"] - octet)
        return courant["taille"] + (max(0, tourne["taille"] - octet) if tourne is not None and tourne["ino"] == ino else 0)

    def suivre(self, journal: Path, servis: Optional[frozenset], maintenant: float) -> bool:
        """Lit ce qui est neuf (borné par passe). Rend vrai si la fin du journal est atteinte."""
        self.e["rattrapage"] = False
        if not self._placer(journal):
            self.e["vu"] = None
            return False
        if self.retard(journal) > (REPRISE_OCTETS + RETARD_MAX if self.e["initial"] else RETARD_MAX):
            courant = _fichier(journal)
            if courant is not None:
                log.warning("dossiers : retard de lecture, saut au plus récent")
                self.trou()
                self._lu(self.e["tete"] if self.e["tete"] != courant["tete"] else None)
                self.e["sauts"] = (self.e["sauts"] + [int(maintenant)])[-MAX_SAUTS:]
                self.e["curseur"], self.e["tete"] = depart(journal, courant, None, SAUT_OCTETS)
        for _ in range(PASSE_TOURS):
            try:
                flux = _veille.lire_flux(journal, self.e["curseur"], PASSE_LIGNES, PASSE_OCTETS)
            except _veille.PositionInvalide:
                # fichier réécrit sous le curseur : état neuf plutôt que compter deux fois
                log.warning("dossiers : curseur du journal invalide, reprise bornée")
                self.__init__(_neuf())
                self.e["trous"] = 1
                return False
            if flux["trou"]:                       # le fichier a changé entre la place et la lecture : reprise au tour suivant
                self.e["vu"] = None
                return False
            for x in flux["lignes"]:
                self.ajouter(x.get("ligne"), servis, maintenant)
            self._avancer(journal, flux["suivant"])
            if not flux["lignes"]:
                self.e["initial"] = False
                return True
        self.e["rattrapage"], self.e["vu"] = True, None
        return False

    def _avancer(self, journal: Path, suivant: str) -> None:
        ino = int(suivant.split(":")[0])
        if self.e["curseur"].split(":")[0] != str(ino):
            self._lu(self.e["tete"])
            self.e["tete"] = None
        self.e["curseur"] = suivant
        if self.e["tete"] is None:
            for nom in (journal.name, journal.name + ".1"):
                f = _fichier(journal.with_name(nom))
                if f is not None and f["ino"] == ino:
                    self.e["tete"] = f["tete"]
                    break


def _fichier(p: Path) -> Optional[Dict[str, Any]]:
    """Identité d'un journal : inode, taille, empreinte de sa première ligne (None si elle n'est pas entière), sa date."""
    try:
        with open(p, "rb") as f:
            st = os.fstat(f.fileno())
            ligne = f.readline(_veille.LIGNE_MAX)
            fin = b""
            if st.st_size:
                f.seek(st.st_size - 1)
                fin = f.read(1)
    except OSError:
        return None
    entiere = ligne.endswith(b"\n") or len(ligne) >= _veille.LIGNE_MAX
    premier = None
    if entiere:
        try:
            premier = _populations._horodatage(json.loads(ligne).get("timestamp"))
        except (ValueError, AttributeError, RecursionError):
            premier = None
    return {"ino": st.st_ino, "taille": st.st_size, "finie": fin == b"\n" or not st.st_size,
            "tete": hashlib.sha1(ligne).hexdigest() if entiere else None,
            "premier": premier if premier is not None and math.isfinite(premier) else None}


def depart(journal: Path, courant: Dict[str, Any], tourne: Optional[Dict[str, Any]], budget: int) -> Tuple[str, Optional[str]]:
    """(curseur, tête) `budget` octets au plus avant la fin, au début d'une ligne ; dans `.1` si le courant n'y suffit pas."""
    f, chemin, octet = courant, journal, max(0, courant["taille"] - budget)
    if not octet and tourne is not None and budget > courant["taille"]:
        f, chemin = tourne, journal.with_name(journal.name + ".1")
        octet = max(0, tourne["taille"] - (budget - courant["taille"]))
    if octet:
        try:
            with open(chemin, "rb") as fd:
                if os.fstat(fd.fileno()).st_ino == f["ino"]:
                    fd.seek(octet - 1)
                    while True:
                        bloc = fd.readline(_veille.LIGNE_MAX)
                        if not bloc or bloc.endswith(b"\n"):
                            break
                    octet = fd.tell()
        except OSError:
            octet = 0
    return f"{f['ino']}:{octet}", f["tete"]


# ── sources accessoires (aucune adresse n'en sort) ───────────────────────────────────────────────────────────────

def _rotation(maintenant: float, servis: Optional[frozenset]) -> Dict[str, Any]:
    d = _json(CHEMINS["rotation"])
    if not isinstance(d, dict):
        return {"etat": "absent", "mode": None, "campagnes": [], "tronque": False}
    tronque = False
    frais = maintenant - _entier(d.get("genere_le")) <= ETAT_DECISION_S
    out = []
    for c in d.get("campagnes") if isinstance(d.get("campagnes"), list) else []:
        if not isinstance(c, dict) or not isinstance(c.get("signature"), str):
            continue
        hote = normaliser_hote(c.get("hote"))
        court = c["signature"][:8].lower()
        if not re.fullmatch(r"[0-9a-f]{8}", court):
            continue
        if len(out) >= 50:
            tronque = True
            break
        hote = hote if servis is not None and hote in servis else None      # un nom non servi n'est pas rendu
        out.append({"id": "rotation:" + court, "hote": hote, "etablie_le": _entier(c.get("etablie_le")) or None,
                    "dernier": _entier(c.get("dernier")) or None,
                    **{k: _entier(c.get(k)) for k in ("sources", "bannies", "epargnees", "a_bannir", "ecartees")}})
    mode = d.get("mode") if d.get("mode") in ("off", "propose", "auto") else None
    return {"etat": "ok" if frais else "perime", "mode": mode, "campagnes": out, "tronque": tronque}


def _candidats(chemin: Path, maintenant: float) -> Dict[str, Any]:
    d = _json(chemin)
    if not isinstance(d, dict):
        return {"etat": "absent", "mode": None, "a_bannir": None, "bannis": None, "genere_le": None}
    frais = maintenant - _entier(d.get("genere_le")) <= ETAT_DECISION_S
    liste = [c for c in (d.get("candidats") if isinstance(d.get("candidats"), list) else []) if isinstance(c, dict) and isinstance(c.get("ip"), str)]
    mode = d.get("mode") if d.get("mode") in ("off", "propose", "auto") else None
    return {"etat": "ok" if frais else "perime", "mode": mode, "genere_le": _entier(d.get("genere_le")) or None,
            "a_bannir": len({c.get("ip") for c in liste if c.get("decision") == "a_bannir"}) if frais else None,
            "bannis": len({c.get("ip") for c in liste if c.get("decision") == "banni"}) if frais else None}


def _populations_actives(maintenant: float) -> List[Dict[str, Any]]:
    r = _populations.lire_cache(str(CHEMINS["populations"]))
    out = []
    for p in (r or {}).get("populations", []):
        if isinstance(p, dict) and p.get("etat") != "inactive" and _entier(p.get("actives_24h")):
            out.append(p)
    return out


# ── vues ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def _heures(maintenant: float) -> List[int]:
    c = int(maintenant // 3600)
    return list(range(c - HEURES + 1, c + 1))


def nom_heure(heure: int) -> str:
    """« 4 h » à Paris, comme sur la page ; au retour à l'heure d'hiver, les deux « 2 h » se distinguent."""
    h = [datetime.fromtimestamp(x * 3600, tz=PARIS).hour for x in (heure - 1, heure, heure + 1)]
    return f"{h[1]}\u00a0h" + (" (été)" if h[2] == h[1] else " (hiver)" if h[0] == h[1] else "")


def _recent(a: Agregateur, maintenant: float) -> Tuple[int, bool]:
    """(minutes couvertes depuis le début de l'heure précédente, sans trou)."""
    c = int(maintenant // 3600)
    return a.minutes(c - 1) + a.minutes(c), a.complete(c - 1, maintenant) and a.complete(c, maintenant)


def _attaque(a: Agregateur, hostiles: List[Optional[int]], maintenant: float, degrade: bool) -> Tuple[Optional[bool], int, int, Optional[float]]:
    """(sous attaque, requêtes récentes, minutes couvertes, rythme habituel À DURÉE ÉGALE). Le rythme habituel ne vient
    que des heures complètes. None : on ne sait pas (pas d'historique, heures récentes mal couvertes, lecture en retard)."""
    minutes, sans_trou = _recent(a, maintenant)
    recent = sum(v or 0 for v in hostiles[-2:])
    heures = _heures(maintenant)
    autres = [v for v, h in zip(hostiles[:-2], heures[:-2]) if v is not None and a.complete(h, maintenant)]
    if degrade or not minutes or len(autres) < ATTAQUE_HISTORIQUE:
        return None, recent, minutes, None
    habituel = sum(autres) / len(autres) / 60 * minutes
    if recent >= ATTAQUE_MIN and recent >= ATTAQUE_FACTEUR * max(habituel, 1):
        return True, recent, minutes, habituel      # un trou ne peut que minorer `recent`
    return (False if sans_trou else None), recent, minutes, habituel


def _couche(site: str, c: str) -> Dict[str, str]:
    """Nom et définition d'une couche ; derrière un nom non servi, une requête notée n'a atteint aucun site (421)."""
    if site == INCONNUS and c == "passe":
        return {"cle": c, "nom": "Noté", "def": "Réseau local ou nom de la maison : noté, aucun site derrière."}
    return {"cle": c, "nom": NOMS_COUCHES[c], "def": DEFINITIONS[c]}


def _nom(site: str) -> str:
    return NOM_INCONNUS if site == INCONNUS else site


def _dossier(a: Agregateur, site: str, maintenant: float, rot: Dict[str, Any], pops: List[dict], degrade: bool,
             servis_ok: bool) -> Dict[str, Any]:
    heures = _heures(maintenant)
    couches = {c: [None] * HEURES for c in COUCHES}
    cats: Dict[str, List[int]] = {}
    origines: Dict[str, int] = {}
    for i, h in enumerate(heures):
        if not a.minutes(h):
            continue
        t_h = [0] * len(COUCHES)
        s = a.e["heures"].get(str(h), {}).get(site) or {"c": {}, "o": {}}
        for cat, v in s["c"].items():
            t = cats.setdefault(cat, [0] * len(COUCHES))
            for k, n in enumerate(v):
                t[k] += n
                t_h[k] += n
        for cl, n in s["o"].items():
            origines[cl] = origines.get(cl, 0) + n
        # heure partielle : un compte y est un minimum, un zéro n'y est pas une mesure
        pleine = a.complete(h, maintenant)
        for k, c in enumerate(COUCHES):
            if pleine or (sum(t_h[:HOSTILES]) if k < HOSTILES else t_h[k]):
                couches[c][i] = t_h[k]
    totaux = {c: (sum(v or 0 for v in couches[c]) if any(v is not None for v in couches[c]) else None) for c in COUCHES}
    hostiles = [None if couches["arrete"][i] is None else sum(couches[c][i] for c in COUCHES[:HOSTILES])
                for i in range(HEURES)]
    n_h = sum(v or 0 for v in hostiles)
    ecartees = n_h - (totaux["passe"] or 0)
    inconnu = site == INCONNUS
    mes, completes = sum(v is not None for v in hostiles), sum(a.complete(h, maintenant) for h in heures)
    attaque, recent, minutes, habituel = _attaque(a, hostiles, maintenant, degrade)
    actives = [c for c in rot["campagnes"] if c["hote"] == site and c["dernier"] and maintenant - c["dernier"] <= ROTATION_FRAICHE_S]
    a_bannir = sum(c["a_bannir"] for c in actives) if rot["mode"] == "propose" and rot["etat"] == "ok" else 0
    passe = totaux["passe"] or 0

    etiq: List[List[str]] = []
    if a_bannir:
        etiq.append(["à décider", "r"])
    if attaque:
        etiq.append(["sous attaque", "r"])
    if actives:
        etiq.append(["adresses tournantes", "o"])
    if n_h and not inconnu:
        etiq.append([f"{nb(passe)} laissées passer" if passe > 1 else "1 laissée passer", "o"] if passe else ["tout écarté", "v"])
    if not n_h:
        etiq.append(["calme", "v"] if mes else ["non mesuré", "o"])
    if inconnu and n_h:
        etiq.append(["aucun site derrière", ""])
    etat = "a_decider" if a_bannir else "attaque" if attaque else "passe" if passe and not inconnu else "ecarte" if n_h else "calme" if mes else "non_mesure"
    urgence = {"non_mesure": 20, "a_decider": 100, "attaque": 80, "passe": 50, "ecarte": 30, "calme": 10}[etat] if not inconnu else (60 if attaque else 5)

    tri_cats = sorted(((c, sum(v[:HOSTILES]), v) for c, v in cats.items()), key=lambda x: (-x[1], x[0]))
    tri_cats = [x for x in tri_cats if x[1]]
    tenu = None if not n_h or inconnu else 100 * ecartees / n_h
    sous = ("Non mesuré" if not mes else "Rien d’hostile en 24 h" if completes >= HEURES
            else f"Rien d’hostile sur {pl(mes, 'heure mesurée', 'heures mesurées')}") if not n_h else (
        f"{pl(n_h, 'requête hostile', 'requêtes hostiles')} · {_bas(libelle_cat(tri_cats[0][0]))}" if tri_cats
        else pl(n_h, "requête hostile", "requêtes hostiles"))
    return {
        "id": site, "nom": _nom(site), "titre": _nom(site), "sous_titre": sous, "etat": etat, "etiquettes": etiq,
        "urgence": urgence, "total": n_h if mes else None, "serie": hostiles, "heures_mesurees": mes,
        "tenu_pct": None if tenu is None else int(tenu * 10) / 10, "totaux": totaux, "attaque": attaque, "heures_completes": completes,
        "phrase": _phrase(site, n_h, totaux, tri_cats, hostiles, heures, mes, completes, attaque, recent, minutes, habituel, a_bannir, tenu,
                          servis_ok),
        "couches": [{**_couche(site, c), "serie": couches[c]} for c in COUCHES[:HOSTILES]],
        "robots": {"serie": couches["robots"], "total": totaux["robots"]},
        "chaine": _chaine(site, totaux, n_h, mes),
        "categories": [{"cle": c, "nom": libelle_cat(c), "n": n, "arrete": n - v[3]} for c, n, v in tri_cats[:8]],
        "origine": {"unite": "requêtes", "lignes": [{"cle": c, "nom": CLASSES[c], "n": n} for c, n in
                                                    sorted(origines.items(), key=lambda x: (-x[1], x[0]))]},
        "faits": _faits(a, site, maintenant, hostiles, heures, actives, rot, pops),
        "geste": _geste(site, a_bannir, passe, n_h),
    }


def _phrase(site, n, tot, cats, hostiles, heures, mes, completes, attaque, recent, minutes, habituel, a_bannir, tenu, servis_ok) -> str:
    if not mes:
        return "Aucune heure n’est mesurée."
    fin = "" if completes >= HEURES else f" Mesure complète sur {pl(completes, 'heure', 'heures')} seulement."
    robots = tot["robots"] or 0
    if not n:
        r = f" {pl(robots, 'visite de robot refusée', 'visites de robots refusées')} à part." if robots else ""
        return ("Aucune requête hostile vue en 24 h." if completes >= HEURES else "Aucune requête hostile vue sur les heures mesurées.") + r + fin
    p = [pl(n, "requête hostile", "requêtes hostiles") + " en 24 h"]
    if cats and len(cats) > 1:
        p[0] += f", surtout « {_bas(libelle_cat(cats[0][0]))} » ({pct(100 * cats[0][1] / n)})."
    elif cats:
        p[0] += f", toutes de type « {_bas(libelle_cat(cats[0][0]))} »." if n > 1 else f", de type « {_bas(libelle_cat(cats[0][0]))} »."
    else:
        p[0] += "."
    passe = tot["passe"] or 0
    if site == INCONNUS and not servis_ok:
        p.append("La table des sites est illisible\u00a0: ces requêtes ne peuvent pas être rattachées.")
    elif site == INCONNUS:
        p.append("Ces noms ne sont pas servis ici : aucun site n’a répondu.")
    elif not passe:
        p.append("Le mur l’a écartée." if n == 1 else "Le mur les a toutes écartées.")
    elif passe == n:
        p.append("Elle a été vue puis laissée passer." if n == 1 else "Elles ont été vues puis laissées passer.")
    else:
        p.append(f"Le mur en a écarté {pct(tenu)} ; {pl(passe, 'a été vue puis laissée passer', 'ont été vues puis laissées passer')}.")
    pic = max((v or 0) for v in hostiles)
    if pic > 1:
        i = max(range(HEURES), key=lambda k: (hostiles[k] or 0))
        p.append(f"Le pic est de {nb(pic)} à {nom_heure(heures[i])}.")
    if attaque and habituel is not None:
        rythme = "bien plus que d’habitude" if habituel < 1 else f"{nb(round(recent / habituel))} fois le rythme habituel"
        p.append(f"En ce moment\u00a0: {nb(recent)} en {pl(minutes, 'minute', 'minutes')}, {rythme}.")
    if a_bannir:
        p.append(f"{pl(a_bannir, 'adresse est proposée', 'adresses sont proposées')} au bannissement et "
                 f"{'attend' if a_bannir < 2 else 'attendent'} ta décision.")
    return " ".join(p) + fin


def _chaine(site, tot, n, mes) -> List[Dict[str, Any]]:
    v = lambda x: x if mes else None  # noqa: E731
    return [
        {"nom": "Requêtes reçues", "n": None, "cle": "recues",
         "def": "Pas de total par site sur 24 h : le moteur ne garde que les 1 000 dernières visites."},
        {"nom": "Jugées hostiles", "n": v(n), "cle": "hostiles", "def": "Requêtes reconnues par une règle, robots à part."},
        *[{**_couche(site, c), "n": v(tot[c])} for c in COUCHES[:HOSTILES]],
    ]


def _faits(a: Agregateur, site, maintenant, hostiles, heures, actives, rot, pops) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    pic = max((v or 0) for v in hostiles)
    if pic:
        i = max(range(HEURES), key=lambda k: (hostiles[k] or 0))
        out.append({"ts": heures[i] * 3600, "texte": f"Pic : {pl(pic, 'requête hostile', 'requêtes hostiles')} en une heure",
                    "preuve": "journal des menaces"})
    for c, texte, preuve in (("arrete", "Dernier bannissement", "pare-feu"), ("refuse", "Dernière page de refus", "pare-feu"),
                             ("detourne", "Dernière requête envoyée au leurre", "leurre"),
                             ("passe", "Dernière requête notée", "pare-feu") if site == INCONNUS else
                             ("passe", "Dernière requête laissée passer", "détection seule")):
        d = a.e["derniers"].get(site, {}).get(c)
        if d:
            out.append({"ts": d[0], "texte": f"{texte} : {_bas(libelle_cat(d[1]))}", "preuve": preuve})
    for c in actives:
        if c["etablie_le"]:
            out.append({"ts": c["etablie_le"], "texte": f"Campagne à adresses tournantes reconnue : {pl(c['sources'], 'adresse', 'adresses')}",
                        "preuve": "détecteur de rotation"})
        if c["bannies"]:
            out.append({"ts": c["dernier"], "texte": pl(c["bannies"], "adresse bannie par le détecteur", "adresses bannies par le détecteur"),
                        "preuve": "détecteur de rotation"})
        if c["a_bannir"] and rot["mode"] == "propose":
            out.append({"ts": c["dernier"], "texte": pl(c["a_bannir"], "adresse proposée au bannissement", "adresses proposées au bannissement"),
                        "preuve": "attend ta décision"})
    for p in pops:
        if p.get("nom_cible") == site and _entier(p.get("dernier")):
            out.append({"ts": _entier(p["dernier"]), "texte": f"{FAMILLES[p['famille']] if isinstance(p.get('famille'), str) and p['famille'] in FAMILLES else FAMILLES['autre']} : "
                        f"{pl(_entier(p.get('adresses')), 'adresse', 'adresses')} en sept jours",
                        "preuve": "relevé des populations"})
    out.sort(key=lambda f: f["ts"])
    return out[-MAX_FAITS:]


def _geste(site, a_bannir, passe, n) -> Dict[str, str]:
    if a_bannir:
        return {"libelle": "Voir ce qui serait banni", "href": "/actor/", "genre": "r",
                "note": "Ouvre Actor. Rien n’est posé avant ta confirmation."}
    if site == INCONNUS:
        return {"libelle": "Voir les noms demandés", "href": "/waf/#recon", "genre": "",
                "note": "Un nom attendu dans cette liste est peut-être un site qui manque ici."}
    if passe:
        return {"libelle": "Ouvrir les modes", "href": "/waf/#modes", "genre": "",
                "note": "Ce qui passe vient de règles en détection seule. Leur mode se change là, à ta main."}
    if n:
        return {"libelle": "Ouvrir les menaces", "href": "/waf/#overview", "genre": "", "note": "Rien à décider."}
    return {"libelle": "Ouvrir les visites", "href": "/waf/#visits", "genre": "", "note": "Rien à décider."}


def construire(a: Agregateur, maintenant: float, lu: bool) -> Dict[str, Any]:
    """Toutes les vues servies, calculées une fois par passe. Lecture en retard ou journal illisible : les chiffres
    de synthèse valent null, l'attaque est inconnue."""
    servis = sites_servis()
    rot = _rotation(maintenant, servis)
    pops = _populations_actives(maintenant)
    heures = _heures(maintenant)
    retard = bool(a.e["rattrapage"])
    degrade = retard or not lu
    vus = {s for h in heures for s in a.e["heures"].get(str(h), {})}
    vus |= {c["hote"] for c in rot["campagnes"] if c["hote"]}
    dossiers = {s: _dossier(a, s, maintenant, rot, pops, degrade, servis is not None) for s in sorted(vus | {INCONNUS})}
    cles = ("id", "nom", "titre", "sous_titre", "etat", "etiquettes", "urgence", "total", "serie", "tenu_pct", "totaux", "attaque")
    liste = sorted(dossiers.values(), key=lambda d: (-d["urgence"], -(d["total"] or 0), d["nom"]))
    calmes = sorted((servis or frozenset()) - set(dossiers))
    sites = [d for d in dossiers.values() if d["id"] != INCONNUS]
    couvertes = [bool(a.minutes(h)) for h in heures]
    completes = [a.complete(h, maintenant) for h in heures]
    chiffrable = any(couvertes) and not degrade

    def par_heure(cs: Tuple[int, ...]) -> Optional[List[Optional[int]]]:
        if not chiffrable:
            return None
        v = [sum(d["couches"][k]["serie"][i] or 0 for d in sites for k in cs) for i in range(HEURES)]
        return [x if completes[i] or (couvertes[i] and x) else None for i, x in enumerate(v)]

    def somme(c: str) -> Optional[int]:
        return sum(d["totaux"][c] or 0 for d in sites) if chiffrable else None

    hostiles = sum(d["total"] or 0 for d in sites) if chiffrable else None
    passe = somme("passe")
    historique = sum(c for c in completes[:-2]) >= ATTAQUE_HISTORIQUE
    attaques = sum(1 for d in sites if d["attaque"] is True)
    commun = {
        "genere_le": int(maintenant), "couverture_depuis": a.e["couverture_depuis"], "heures_mesurees": sum(completes),
        "debut": heures[0] * 3600, "pas": 3600, "partielles": [i for i in range(HEURES) if couvertes[i] and not completes[i]],
        "complet": bool(lu) and not retard, "rattrapage": retard, "sauts_24h": len(a.e["sauts"]),
        "journal": "retard" if retard else "ok" if lu else "illisible", "routes": "ok" if servis is not None else "illisible",
        "illisibles": a.e["illisibles"], "hors_plafond": a.e["hors_plafond"],
    }
    return {
        "commun": commun, "dossiers": dossiers, "calmes": calmes, "servis": servis is not None, "couv": dict(a.e["couv"]), "degrade": degrade,
        "liste": {
            **commun,
            "chiffres": {
                "sites_proteges": None if servis is None else len(servis),
                "hostiles": hostiles, "ecartees": None if hostiles is None else hostiles - passe, "passees": passe,
                "tenu_pct": None if not hostiles else int(1000 * (hostiles - passe) / hostiles) / 10,
                # inconnue dès que les heures récentes ne sont pas bien couvertes ; une attaque vue reste une attaque vue
                "sous_attaque": attaques if chiffrable and historique and (_recent(a, maintenant)[1] or attaques) else None,
                "robots": somme("robots"),
                "series": {"ecartees": par_heure((0, 1, 2)), "passees": par_heure((3,))},
                "hors_web": sum(n for h, n in a.e["hors_web"].items() if int(h) in heures) if chiffrable else None,
            },
            "sites": [{k: d[k] for k in cles} for d in liste], "calmes": calmes[:MAX_CALMES], "calmes_total": len(calmes),
            # cibles de population qu'une page peut nommer : des sites servis qui ont des événements
            "cibles_servies": sorted({p["nom_cible"] for p in pops if isinstance(p.get("nom_cible"), str)} & (set(dossiers) & (servis or frozenset()))),
            "decisions": {"rotation": rot, "campagnes": _candidats(CHEMINS["campagnes"], maintenant),
                          "acteurs": _candidats(CHEMINS["acteurs"], maintenant)},
        },
    }


# ── tâche de fond et service ─────────────────────────────────────────────────────────────────────────────────────

_verrou = threading.Lock()
_passe = threading.Lock()
_relecture = threading.Lock()
_fond: Dict[str, Any] = {"agregateur": None, "vues": None, "ecrit": 0.0}
_relu: Dict[str, Any] = {"cle": None, "vues": None}


def _vie(maintenant: float) -> bool:
    try:
        return -60 <= maintenant - CHEMINS["vie"].stat().st_mtime <= VIE_MOTEUR_S
    except OSError:
        return False


def rafraichir(maintenant: Optional[float] = None, forcer: bool = False) -> Dict[str, Any]:
    """Une passe (tâche de fond seulement) : lit le neuf, purge, reconstruit les vues, écrit l'état s'il est temps."""
    t = time.time() if maintenant is None else maintenant
    with _passe:
        a = _fond["agregateur"]
        if a is None:
            a = Agregateur(lire_etat(CHEMINS["etat"]))
            a.e["initial"] = True      # après un arrêt, le rattrapage est borné mais pas sauté
        a = a.copie()                  # le lot entier ou rien : une passe qui lève laisse l'état et le curseur d'avant
        lu = a.suivre(CHEMINS["journal"], sites_servis(), t)
        if lu:
            a.vivant(t, _vie(t))
        a.purger(t)
        vues = construire(a, t, lu)
        _fond["agregateur"] = a
        with _verrou:
            _fond["vues"] = vues
        if forcer or t - _fond["ecrit"] >= ECRITURE_S or t < _fond["ecrit"]:
            if ecrire_etat(CHEMINS["etat"], {**a.e, "lu": lu, "genere_le": int(t)}):
                _fond["ecrit"] = t
        return vues


def vider() -> None:
    """Oublie l'état en mémoire (tests)."""
    with _verrou:
        _fond.update(agregateur=None, vues=None, ecrit=0.0)
        _relu.update(cle=None, vues=None)
        _routes_memo.clear()


def _vues() -> Optional[Dict[str, Any]]:
    """Les vues de la tâche de fond ; dans un processus qui ne la lance pas (agrégateur), celles du fichier d'état,
    reconstruites une fois par écriture. None : rien n'a encore été mesuré."""
    with _verrou:
        if _fond["vues"] is not None:
            return _fond["vues"]
    try:
        st = CHEMINS["etat"].stat()
    except OSError:
        return None
    cle = (st.st_mtime_ns, st.st_ino, st.st_size)
    with _relecture:                   # une seule reconstruction à la fois, les autres attendent son résultat
        with _verrou:
            if _relu["cle"] == cle:
                return _relu["vues"]
        brut = _json(CHEMINS["etat"])
        vues = None
        if _valide(brut) and _entier(brut.get("genere_le")):
            vues = construire(Agregateur({k: brut[k] for k in _neuf()}), float(brut["genere_le"]), bool(brut.get("lu")))
        with _verrou:
            _relu.update(cle=cle, vues=vues)
        return vues


def _avec_age(d: Dict[str, Any], maintenant: Callable[[], float] = time.time) -> Dict[str, Any]:
    age = max(0, int(maintenant() - d["genere_le"]))
    return {**d, "age_s": age, "perime": age > PERIME_S, "disponible": True}


async def _est_admin(request: Request) -> bool:
    """Vrai seulement si l'appelant passe `require_jwt` (administrateur réel) : même test que `_est_admin` de
    secubox-soc (api/defense.py), sonde silencieuse d'abord pour ne pas journaliser un refus à chaque lecture."""
    creds = None
    brut = request.headers.get("authorization", "")
    if brut.lower().startswith("bearer ") and brut[7:].strip():
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=brut[7:].strip())
    try:
        for jeton in ([creds.credentials] if creds is not None else []) + [t for t in [request.cookies.get(SESSION_COOKIE)] if t]:
            payload = _validate_token(jeton)
            if payload is not None:
                if not est_admin_reel(payload):
                    return False
                break
    except Exception as e:  # noqa: BLE001 — sonde seulement : en cas de doute, la garde réelle tranche
        log.debug("sonde admin : %s", type(e).__name__)
    try:
        await require_jwt(request, creds)
        return True
    except HTTPException:
        return False
    except Exception as e:  # noqa: BLE001 — dans le doute, vue réduite
        log.warning("garde admin en échec : %s", type(e).__name__)
        return False


_VIDE = {"disponible": False, "genere_le": None, "couverture_depuis": None}


def _liste(admin: bool) -> Dict[str, Any]:
    v = _vues()
    if v is None:
        return dict(_VIDE)
    return {**_avec_age(v["liste"]), **({} if admin else {"calmes": []})}


@router.get("/sites", dependencies=[Depends(require_lecture)])
async def dossiers_sites(admin: bool = Depends(_est_admin)):
    """Les sites servis, du plus urgent au plus calme, avec leur série de 24 h. Aucune adresse. Les noms des sites sans
    événement sont un inventaire : administrateur réel seulement (leur nombre reste rendu à tous)."""
    return await asyncio.to_thread(_liste, admin)


def _un(site: str, admin: bool) -> Dict[str, Any]:
    v = _vues()
    if v is None:
        return dict(_VIDE)
    d = v["dossiers"].get(site)
    if d is None:
        if not admin or site not in v["calmes"]:
            raise HTTPException(404, detail={"motif": "site"})
        # un site calme partage la couverture du relevé entier
        a = Agregateur({**_neuf(), "couv": v["couv"]})
        d = _dossier(a, site, float(v["commun"]["genere_le"]), {"mode": None, "etat": "absent", "campagnes": []}, [], v["degrade"], v["servis"])
    return {**_avec_age(v["commun"]), **d}


@router.get("/sites/{site}", dependencies=[Depends(require_lecture)])
async def dossier_site(site: str = ParamChemin(..., min_length=1, max_length=253, pattern=r"^[a-z0-9][a-z0-9._-]*$"),
                       admin: bool = Depends(_est_admin)):
    """Le dossier d'un site : phrase, couches par heure, chaîne, motifs, origine, faits datés, lien du geste."""
    return await asyncio.to_thread(_un, site, admin)
