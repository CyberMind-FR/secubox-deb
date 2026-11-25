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

Une heure est mesurée si une ligne y porte sa date, ou si le moteur y a donné signe de vie (état nft publié toutes les
30 s) pendant que le journal était lu jusqu'au bout. Sinon elle vaut null, jamais 0. Aucune adresse n'est gardée."""
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

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Path as ParamChemin

from secubox_core.auth import require_lecture

try:
    from api import populations as _populations, veille_lecture as _veille
except ImportError:  # standalone
    import populations as _populations
    import veille_lecture as _veille

log = logging.getLogger("secubox.waf.dossiers")
router = APIRouter(prefix="/dossiers", tags=["dossiers"])

VERSION = 1
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
VIE_MOTEUR_S = 180                # état nft plus récent : le moteur vit
ROTATION_FRAICHE_S = 6 * 3600
ETAT_DECISION_S = 15 * 60         # même fraîcheur que enforcement.FRAICHEUR_ETAT_S
TAILLE_MAX = 8 * 1024 * 1024
ATTAQUE_MIN, ATTAQUE_FACTEUR, ATTAQUE_HISTORIQUE = 30, 3, 6

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
    return {"v": VERSION, "curseur": None, "couverture_depuis": None, "dernier_ts": None, "rattrapage": False,
            "mesurees": [], "partielles": [], "heures": {}, "derniers": {}, "hors_web": {}, "illisibles": 0,
            "hors_plafond": 0, "trous": 0}


def _valide(e: Any) -> bool:
    if not (isinstance(e, dict) and e.get("v") == VERSION):
        return False
    modele = _neuf()
    if any(not isinstance(e.get(k), type(modele[k])) for k in ("mesurees", "partielles", "heures", "derniers", "hors_web")):
        return False
    c = e.get("curseur")
    if c is not None and not (isinstance(c, str) and _veille.RE_POSITION.fullmatch(c)):
        return False
    try:
        for h, sites in e["heures"].items():
            int(h)
            for s in sites.values():
                if any(len(v) != len(COUCHES) or not all(isinstance(x, int) for x in v) for v in s["c"].values()):
                    return False
                if not all(isinstance(x, int) for x in s["o"].values()):
                    return False
    except (ValueError, TypeError, KeyError, AttributeError):
        return False
    return True


def lire_etat(chemin: Path) -> Dict[str, Any]:
    """L'état gardé, ou un état neuf s'il manque, est illisible ou d'une autre version."""
    e = _json(chemin)
    if e is not None and _valide(e):
        return {**_neuf(), **e}
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
        self._poser(etat if etat is not None else _neuf())

    def _poser(self, etat: Dict[str, Any]) -> None:
        self.e = etat
        self._trou_ouvert = False
        self._mesurees = {int(h) for h in self.e["mesurees"] if isinstance(h, int)}
        self._partielles = {int(h) for h in self.e["partielles"] if isinstance(h, int)}
        self._sites = {s for sites in self.e["heures"].values() for s in sites}
        self._cellules = sum(len(s["c"]) for sites in self.e["heures"].values() for s in sites.values())

    # ── une ligne ──
    def ajouter(self, ligne: Any, servis: Optional[frozenset], maintenant: float) -> None:
        if not isinstance(ligne, dict):
            self.e["illisibles"] += 1
            return
        t = _populations._horodatage(ligne.get("timestamp"))
        # date illisible, infinie ou du futur : ni heure mesurée, ni compte
        if t is None or not math.isfinite(t) or t > maintenant + 300:
            self.e["illisibles"] += 1
            return
        h, courante = int(t // 3600), int(maintenant // 3600)
        if h <= courante - HEURES:
            return
        if self.e["couverture_depuis"] is None:
            self.e["couverture_depuis"] = int(t)
            self._partielles.add(h)
        self.e["dernier_ts"] = max(int(t), self.e["dernier_ts"] or 0)
        self._mesurees.add(min(h, courante))
        cat = ligne.get("category")
        cat = cat if isinstance(cat, str) else ""
        action = ligne.get("action")
        if ligne.get("tool") == "authwatch" or cat.startswith(_AUTHWATCH):
            if ligne.get("severity") != "audit":
                cle = str(h)
                self.e["hors_web"][cle] = self.e["hors_web"].get(cle, 0) + 1
            return
        couche = ACTIONS.get(action) if isinstance(action, str) else None
        if couche is None:
            return
        n = 1
        if action == "leurre_redirige":
            n = max(1, min(_entier(ligne.get("servies")), 1_000_000))
        elif ligne.get("severity") == "audit" or cat.startswith(("multipart-", "body-inspect-")):
            return                     # ligne d'état, pas une requête hostile
        site = None if cat.startswith("host_anomaly") else normaliser_hote(ligne.get("host"))
        if site is not None and servis is not None and site not in servis:
            site = None
        site = site or INCONNUS
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
            classe = ligne.get("reseau_classe")
            classe = classe if isinstance(classe, str) and classe in CLASSES else "inconnu"
            s["o"][classe] = s["o"].get(classe, 0) + n
        d = self.e["derniers"].setdefault(site, {})
        if int(t) >= (d.get(COUCHES[couche]) or [0])[0]:
            d[COUCHES[couche]] = [int(t), cle]

    def trou(self) -> None:
        """Des lignes ont pu être perdues : l'heure de la dernière ligne lue et celle de la suivante sont partielles."""
        self.e["trous"] += 1
        if self.e["dernier_ts"]:
            self._partielles.add(int(self.e["dernier_ts"] // 3600))
        self._trou_ouvert = True

    def _apres_trou(self, ligne: Dict[str, Any]) -> None:
        t = _populations._horodatage(ligne.get("timestamp"))
        if t is not None and math.isfinite(t):
            self._partielles.add(int(t // 3600))
            self._trou_ouvert = False

    def vivant(self, maintenant: float) -> None:
        """Le moteur vit et le journal est lu jusqu'au bout : l'heure en cours est mesurée, même sans événement."""
        h = int(maintenant // 3600)
        if self.e["couverture_depuis"] is None:
            self.e["couverture_depuis"] = int(maintenant)
            self._partielles.add(h)
        self._mesurees.add(h)

    def purger(self, maintenant: float) -> None:
        seuil = int(maintenant // 3600) - HEURES
        for table in ("heures", "hors_web"):
            for k in [k for k in self.e[table] if int(k) <= seuil]:
                del self.e[table][k]
        self._mesurees = {h for h in self._mesurees if h > seuil}
        self._partielles = {h for h in self._partielles if h > seuil}
        self._sites = {s for sites in self.e["heures"].values() for s in sites}
        self._cellules = sum(len(s["c"]) for sites in self.e["heures"].values() for s in sites.values())
        self.e["derniers"] = {s: {c: v for c, v in d.items() if v[0] > maintenant - HEURES * 3600}
                              for s, d in self.e["derniers"].items() if s in self._sites}
        self.e["mesurees"], self.e["partielles"] = sorted(self._mesurees), sorted(self._partielles)

    def suivre(self, journal: Path, servis: Optional[frozenset], maintenant: float) -> bool:
        """Lit ce qui est neuf (borné par passe). Rend vrai si la fin du journal est atteinte."""
        if self.e["curseur"] is None:
            self.e["curseur"] = depart(journal)
            if self.e["curseur"] is None:
                return False
        for _ in range(PASSE_TOURS):
            try:
                flux = _veille.lire_flux(journal, self.e["curseur"], PASSE_LIGNES, PASSE_OCTETS)
            except _veille.PositionInvalide:
                # le fichier a été réécrit sous le curseur : on repart d'un état neuf plutôt que de compter deux fois
                log.warning("dossiers : curseur du journal invalide, reprise bornée")
                self._poser(_neuf())
                self.e["trous"] = 1
                self.e["curseur"] = depart(journal)
                return False
            if flux["trou"]:
                self.trou()
            for x in flux["lignes"]:
                ligne = x.get("ligne")
                if self._trou_ouvert and isinstance(ligne, dict):
                    self._apres_trou(ligne)
                self.ajouter(ligne, servis, maintenant)
            self.e["curseur"] = flux["suivant"]
            if not flux["lignes"]:
                self.e["rattrapage"] = False
                return True
        self.e["rattrapage"] = True
        return False


def depart(journal: Path) -> Optional[str]:
    """Curseur de premier départ : REPRISE_OCTETS au plus avant la fin, au début d'une ligne. None sans journal."""
    reste = REPRISE_OCTETS
    choix: Optional[str] = None
    for p in (journal, journal.with_name(journal.name + ".1")):
        try:
            with open(p, "rb") as f:
                st = os.fstat(f.fileno())
                octet = max(0, st.st_size - reste)
                if octet:
                    f.seek(octet - 1)
                    while True:
                        bloc = f.readline(_veille.LIGNE_MAX)
                        if not bloc or bloc.endswith(b"\n"):
                            break
                    octet = f.tell()
                choix = f"{st.st_ino}:{octet}"
                reste -= st.st_size
        except OSError:
            if choix is None:
                return None            # journal courant absent ou illisible : rien à suivre
            break
        if reste <= 0:
            break
    return choix


# ── sources accessoires (aucune adresse n'en sort) ───────────────────────────────────────────────────────────────

def _rotation(maintenant: float) -> Dict[str, Any]:
    d = _json(CHEMINS["rotation"])
    if not isinstance(d, dict):
        return {"etat": "absent", "mode": None, "campagnes": []}
    frais = maintenant - _entier(d.get("genere_le")) <= ETAT_DECISION_S
    out = []
    for c in d.get("campagnes") if isinstance(d.get("campagnes"), list) else []:
        if not isinstance(c, dict) or not isinstance(c.get("signature"), str):
            continue
        hote = normaliser_hote(c.get("hote"))
        court = c["signature"][:8].lower()
        if hote is None or not re.fullmatch(r"[0-9a-f]{8}", court):
            continue
        out.append({"id": "rotation:" + court, "hote": hote, "etablie_le": _entier(c.get("etablie_le")) or None,
                    "dernier": _entier(c.get("dernier")) or None,
                    **{k: _entier(c.get(k)) for k in ("sources", "bannies", "epargnees", "a_bannir", "ecartees")}})
        if len(out) >= 50:
            break
    mode = d.get("mode") if d.get("mode") in ("off", "propose", "auto") else None
    return {"etat": "ok" if frais else "perime", "mode": mode, "campagnes": out}


def _candidats(chemin: Path, maintenant: float) -> Dict[str, Any]:
    d = _json(chemin)
    if not isinstance(d, dict):
        return {"etat": "absent", "mode": None, "a_bannir": None, "bannis": None, "genere_le": None}
    frais = maintenant - _entier(d.get("genere_le")) <= ETAT_DECISION_S
    liste = [c for c in (d.get("candidats") if isinstance(d.get("candidats"), list) else []) if isinstance(c, dict)]
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


def _hhmm(heure: int) -> str:
    return datetime.fromtimestamp(heure * 3600).strftime("%H").lstrip("0") or "0"


def _attaque(hostiles: List[Optional[int]]) -> Tuple[bool, int, Optional[float]]:
    """(sous attaque, requêtes des deux dernières heures, rythme habituel pour deux heures). Il faut au moins
    ATTAQUE_HISTORIQUE autres heures mesurées pour parler de rythme habituel."""
    recent = sum(v or 0 for v in hostiles[-2:])
    autres = [v for v in hostiles[:-2] if v is not None]
    if len(autres) < ATTAQUE_HISTORIQUE:
        return False, recent, None
    habituel = 2 * sum(autres) / len(autres)
    return recent >= ATTAQUE_MIN and recent >= ATTAQUE_FACTEUR * max(habituel, 1), recent, habituel


def _couche(site: str, c: str) -> Dict[str, str]:
    """Nom et définition d'une couche ; derrière un nom non servi, une requête notée n'a atteint aucun site (421)."""
    if site == INCONNUS and c == "passe":
        return {"cle": c, "nom": "Noté", "def": "Réseau local ou nom de la maison : noté, aucun site derrière."}
    return {"cle": c, "nom": NOMS_COUCHES[c], "def": DEFINITIONS[c]}


def _nom(site: str) -> str:
    return NOM_INCONNUS if site == INCONNUS else site


def _dossier(a: Agregateur, site: str, maintenant: float, rot: Dict[str, Any], pops: List[dict]) -> Dict[str, Any]:
    heures = _heures(maintenant)
    mesurees = a._mesurees
    couches = {c: [None] * HEURES for c in COUCHES}
    cats: Dict[str, List[int]] = {}
    origines: Dict[str, int] = {}
    for i, h in enumerate(heures):
        if h not in mesurees:
            continue
        for c in COUCHES:
            couches[c][i] = 0
        s = a.e["heures"].get(str(h), {}).get(site)
        if not s:
            continue
        for cat, v in s["c"].items():
            t = cats.setdefault(cat, [0] * len(COUCHES))
            for k, n in enumerate(v):
                t[k] += n
                couches[COUCHES[k]][i] += n
        for cl, n in s["o"].items():
            origines[cl] = origines.get(cl, 0) + n
    totaux = {c: (sum(v or 0 for v in couches[c]) if mesurees else None) for c in COUCHES}
    hostiles = [None if couches["arrete"][i] is None else sum(couches[c][i] for c in COUCHES[:HOSTILES])
                for i in range(HEURES)]
    n_h = sum(v or 0 for v in hostiles)
    ecartees = n_h - (totaux["passe"] or 0)
    inconnu = site == INCONNUS
    attaque, recent, habituel = _attaque(hostiles)
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
        etiq.append(["calme", "v"])
    if inconnu and n_h:
        etiq.append(["aucun site derrière", ""])
    etat = "a_decider" if a_bannir else "attaque" if attaque else "passe" if passe and not inconnu else "ecarte" if n_h else "calme"
    urgence = {"a_decider": 100, "attaque": 80, "passe": 50, "ecarte": 30, "calme": 10}[etat] if not inconnu else (60 if attaque else 5)

    tri_cats = sorted(((c, sum(v[:HOSTILES]), v) for c, v in cats.items()), key=lambda x: (-x[1], x[0]))
    tri_cats = [x for x in tri_cats if x[1]]
    tenu = None if not n_h or inconnu else 100 * ecartees / n_h
    sous = "Rien d’hostile en 24 h" if not n_h else (
        f"{pl(n_h, 'requête hostile', 'requêtes hostiles')} · {_bas(libelle_cat(tri_cats[0][0]))}" if tri_cats
        else pl(n_h, "requête hostile", "requêtes hostiles"))
    mes = sum(v is not None for v in hostiles)
    return {
        "id": site, "nom": _nom(site), "titre": _nom(site), "sous_titre": sous, "etat": etat, "etiquettes": etiq,
        "urgence": urgence, "total": n_h if mes else None, "serie": hostiles, "heures_mesurees": mes,
        "tenu_pct": None if tenu is None else int(tenu * 10) / 10, "totaux": totaux, "attaque": attaque,
        "phrase": _phrase(site, n_h, totaux, tri_cats, hostiles, heures, mes, attaque, recent, habituel, a_bannir, tenu),
        "couches": [{**_couche(site, c), "serie": couches[c]} for c in COUCHES[:HOSTILES]],
        "robots": {"serie": couches["robots"], "total": totaux["robots"]},
        "chaine": _chaine(site, totaux, n_h, mes),
        "categories": [{"cle": c, "nom": libelle_cat(c), "n": n, "arrete": n - v[3]} for c, n, v in tri_cats[:8]],
        "origine": {"unite": "requêtes", "lignes": [{"cle": c, "nom": CLASSES[c], "n": n} for c, n in
                                                    sorted(origines.items(), key=lambda x: (-x[1], x[0]))]},
        "faits": _faits(a, site, maintenant, hostiles, heures, actives, rot, pops),
        "geste": _geste(site, a_bannir, passe, n_h),
    }


def _phrase(site, n, tot, cats, hostiles, heures, mes, attaque, recent, habituel, a_bannir, tenu) -> str:
    if not mes:
        return "Aucune heure n’est encore mesurée."
    fin = "" if mes >= HEURES else f" Mesure sur {pl(mes, 'heure', 'heures')} seulement."
    robots = tot["robots"] or 0
    if not n:
        r = f" {pl(robots, 'visite de robot refusée', 'visites de robots refusées')} à part." if robots else ""
        return "Aucune requête hostile vue en 24 h." + r + fin
    p = [pl(n, "requête hostile", "requêtes hostiles") + " en 24 h"]
    if cats and len(cats) > 1:
        p[0] += f", surtout « {_bas(libelle_cat(cats[0][0]))} » ({pct(100 * cats[0][1] / n)})."
    elif cats:
        p[0] += f", toutes de type « {_bas(libelle_cat(cats[0][0]))} »." if n > 1 else f", de type « {_bas(libelle_cat(cats[0][0]))} »."
    else:
        p[0] += "."
    passe = tot["passe"] or 0
    if site == INCONNUS:
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
        p.append(f"Le pic est de {nb(pic)} à {_hhmm(heures[i])} h.")
    if attaque and habituel is not None:
        rythme = "bien plus que d’habitude" if habituel < 1 else f"{nb(round(recent / habituel))} fois le rythme habituel"
        p.append(f"En ce moment : {nb(recent)} en deux heures, {rythme}.")
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
            out.append({"ts": _entier(p["dernier"]), "texte": f"{FAMILLES.get(p.get('famille'), FAMILLES['autre'])} : "
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
    """Toutes les vues servies, calculées une fois par passe."""
    servis = sites_servis()
    rot = _rotation(maintenant)
    pops = _populations_actives(maintenant)
    vus = {s for h in _heures(maintenant) for s in a.e["heures"].get(str(h), {})}
    vus |= {c["hote"] for c in rot["campagnes"] if c["hote"] in (servis or ())}
    dossiers = {s: _dossier(a, s, maintenant, rot, pops) for s in sorted(vus)}
    dossiers.setdefault(INCONNUS, _dossier(a, INCONNUS, maintenant, rot, pops))
    cles = ("id", "nom", "titre", "sous_titre", "etat", "etiquettes", "urgence", "total", "serie", "tenu_pct", "totaux", "attaque")
    liste = sorted(dossiers.values(), key=lambda d: (-d["urgence"], -(d["total"] or 0), d["nom"]))
    calmes = sorted((servis or frozenset()) - set(dossiers))
    sites = [d for d in dossiers.values() if d["id"] != INCONNUS]
    mes = len([h for h in _heures(maintenant) if h in a._mesurees])
    somme = lambda c: sum(d["totaux"][c] or 0 for d in sites) if mes else None  # noqa: E731
    hostiles = sum(d["total"] or 0 for d in sites) if mes else None
    passe = somme("passe")
    masque = [int(h) in a._mesurees for h in _heures(maintenant)]
    par_heure = lambda cs: [sum(d["couches"][k]["serie"][i] or 0 for d in sites for k in cs) if m else None  # noqa: E731
                            for i, m in enumerate(masque)]
    commun = {
        "genere_le": int(maintenant), "couverture_depuis": a.e["couverture_depuis"], "heures_mesurees": mes,
        "debut": _heures(maintenant)[0] * 3600, "pas": 3600,
        "partielles": [i for i, h in enumerate(_heures(maintenant)) if h in a._partielles],
        "complet": bool(lu) and not a.e["rattrapage"], "rattrapage": bool(a.e["rattrapage"]),
        "journal": "ok" if lu or a.e["rattrapage"] else "illisible",
        "illisibles": a.e["illisibles"], "hors_plafond": a.e["hors_plafond"],
    }
    return {
        "commun": commun, "dossiers": dossiers, "calmes": calmes, "servis": servis is not None,
        "liste": {
            **commun,
            "chiffres": {
                "sites_proteges": None if servis is None else len(servis),
                "hostiles": hostiles, "ecartees": None if hostiles is None else hostiles - passe, "passees": passe,
                "tenu_pct": None if not hostiles else int(1000 * (hostiles - passe) / hostiles) / 10,
                "sous_attaque": sum(1 for d in sites if d["attaque"]) if mes else None,
                "robots": somme("robots"),
                "series": {"ecartees": par_heure((0, 1, 2)), "passees": par_heure((3,))},
                "hors_web": sum(n for h, n in a.e["hors_web"].items() if int(h) in _heures(maintenant)) if mes else None,
            },
            "sites": [{k: d[k] for k in cles} for d in liste], "calmes": calmes[:MAX_CALMES], "calmes_total": len(calmes),
            "decisions": {"rotation": rot, "campagnes": _candidats(CHEMINS["campagnes"], maintenant),
                          "acteurs": _candidats(CHEMINS["acteurs"], maintenant)},
        },
    }


# ── tâche de fond et service ─────────────────────────────────────────────────────────────────────────────────────

_verrou = threading.Lock()
_passe = threading.Lock()
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
            a = _fond["agregateur"] = Agregateur(lire_etat(CHEMINS["etat"]))
        lu = a.suivre(CHEMINS["journal"], sites_servis(), t)
        if lu and not _present(CHEMINS["journal"]):
            lu = False
        if lu and _vie(t):
            a.vivant(t)
        a.purger(t)
        vues = construire(a, t, lu)
        with _verrou:
            _fond["vues"] = vues
        if forcer or t - _fond["ecrit"] >= ECRITURE_S or t < _fond["ecrit"]:
            if ecrire_etat(CHEMINS["etat"], {**a.e, "lu": lu, "genere_le": int(t)}):
                _fond["ecrit"] = t
        return vues


def _present(p: Path) -> bool:
    try:
        with open(p, "rb"):
            return True
    except OSError:
        return False


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
    with _verrou:
        if _relu["cle"] == cle:
            return _relu["vues"]
    brut = _json(CHEMINS["etat"])
    vues = None
    if _valide(brut) and _entier(brut.get("genere_le")):
        vues = construire(Agregateur({**_neuf(), **brut}), float(brut["genere_le"]), bool(brut.get("lu")))
    with _verrou:
        _relu.update(cle=cle, vues=vues)
    return vues


def _avec_age(d: Dict[str, Any], maintenant: Callable[[], float] = time.time) -> Dict[str, Any]:
    age = max(0, int(maintenant() - d["genere_le"]))
    return {**d, "age_s": age, "perime": age > PERIME_S, "disponible": True}


_VIDE = {"disponible": False, "genere_le": None, "couverture_depuis": None}


@router.get("/sites", dependencies=[Depends(require_lecture)])
def dossiers_sites():
    """Les sites servis, du plus urgent au plus calme, avec leur série de 24 h. Aucune adresse."""
    v = _vues()
    return dict(_VIDE) if v is None else _avec_age(v["liste"])


@router.get("/sites/{site}", dependencies=[Depends(require_lecture)])
def dossier_site(site: str = ParamChemin(..., min_length=1, max_length=253, pattern=r"^[a-z0-9][a-z0-9._-]*$")):
    """Le dossier d'un site : phrase, couches par heure, chaîne, motifs, origine, faits datés, lien du geste."""
    v = _vues()
    if v is None:
        return dict(_VIDE)
    d = v["dossiers"].get(site)
    if d is None:
        if site not in v["calmes"]:
            raise HTTPException(404, detail={"motif": "site"})
        a = Agregateur(_neuf())
        a._mesurees = {v["commun"]["debut"] // 3600 + i for i, x in enumerate(_mesure_commune(v)) if x}
        d = _dossier(a, site, float(v["commun"]["genere_le"]), {"mode": None, "etat": "absent", "campagnes": []}, [])
    return {**_avec_age(v["commun"]), **d}


def _mesure_commune(v: Dict[str, Any]) -> List[bool]:
    """Les heures mesurées sont celles du relevé entier : un site calme les partage avec « Noms inconnus »."""
    return [x is not None for x in v["dossiers"][INCONNUS]["serie"]]
