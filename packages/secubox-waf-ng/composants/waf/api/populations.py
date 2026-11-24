# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Relevé « populations d'attaquants » (#3919, tâche 5) : qui attaque, depuis quels réseaux, sur quelle cible, sur
7 jours du journal des menaces (journaux tournés et compressés compris).

Calcul PUR et coûteux : appelé seulement par la tâche de fond de l'API (toutes les 10 min, dans un fil), qui en écrit
le résultat dans un cache fichier en double tampon ; la route ne lit jamais le journal. Lecture en flux, mémoire
bornée (MAX_ADRESSES adresses suivies ; au-delà le relevé est marqué `complet: False`).

Ce qui ne sort JAMAIS : une adresse (seulement des comptes), un compte visé en clair (masqué au-delà de 3
caractères, comme `reseau.MasquerCompte`), un mot de passe. Les classes de réseau viennent du catalogue seul : un ASN
absent est `inconnu`, jamais déduit du nom de l'opérateur."""
import bisect
import gzip
import http.client
import ipaddress
import json
import os
import re
import socket
import tempfile
import zlib
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

try:  # facultatif : sans lui (ou sans base), classes tirées des lignes seules, pays vides
    import maxminddb as _maxminddb
except ImportError:  # pragma: no cover — dépend de l'hôte
    _maxminddb = None
try:
    import tomllib as _tomllib
except ImportError:  # pragma: no cover — Python < 3.11
    _tomllib = None

# ── sources (mêmes chemins que les options Go --geoip-asn / --reseaux-classes) ──────────────────────────────────────
# Bases essayées dans l'ordre, la première qui s'ouvre gagne (la box n'a pas toujours le même emplacement).
BASES_ASN = ("/var/lib/GeoIP/GeoLite2-ASN.mmdb", "/var/lib/secubox/geoip/GeoLite2-ASN.mmdb",
             "/usr/share/GeoIP/GeoLite2-ASN.mmdb")
BASES_PAYS = ("/var/lib/secubox/geoip/GeoLite2-Country.mmdb", "/var/lib/GeoIP/GeoLite2-Country.mmdb",
              "/usr/share/GeoIP/GeoLite2-Country.mmdb")
JOURNAL_DOSSIER = "/var/log/secubox/waf"
CAMPAGNES_PROFILEUR = "/var/cache/secubox/waf/campaigns.json"
CATALOGUES = ("/usr/share/secubox/waf/reseaux-classes.toml", "/etc/secubox/waf/reseaux-classes.toml")
AUTHWATCH_CAMPAGNES = "/run/secubox-authwatch/campagnes.json"
ROTATION_ETAT = "/var/lib/secubox/waf/rotation-etat.json"
ACTORD_SOCK = "/run/secubox/actor.sock"
ACTORD_DELAI_S = 2.0
JOURNAL = "waf-threats.log"

FENETRE_JOURS = 7
MAX_ADRESSES = 200_000          # adresses distinctes suivies, toutes populations confondues
MAX_CIBLES_SUIVIES = 1_000      # cibles distinctes comptées par population
SEUIL_PROFILEUR = 10            # une campagne du profileur devient sa population à partir de 10 adresses
ROTATION_ADRESSES = 50          # indicateur de rotation (spec 5.3) : ≥ 50 adresses…
ROTATION_LE3 = 80               # … dont ≥ 80 % à ≤ 3 tentatives
ROTATION_PIVOT = 50             # … et, pour une population de FAMILLE, ≥ 50 % des tentatives sur une même cible (pivot)
INACTIVE_S = 86400
BANNIE_PART = 50                # « bannie » : ≥ 50 % des adresses actives depuis 24 h ont été bannies depuis 24 h
DOUBLE_TAMPON_S = 3600          # un partiel ne remplace pas un complet de moins d'1 h
MAX_CVES = 20
MODE_CACHE = 0o640              # groupe secubox-waf seulement ; l'accès de DataScope est décidé dans #3921 (README)

CLASSES = ("acces", "cdn", "hebergeur", "proxy_loue", "scanner_recherche", "mobile_partage", "relais_vie_privee")
INCONNU = "inconnu"

# ── familles : COPIE EXACTE de reseau.Famille (TNG/internal/reseau/famille.go), lue dans l'ordre, la première gagne.
# Toute modification là-bas se reporte ici (test_famille_table rejoue les cas de TestFamille). ─────────────────────
FAMILLE = (
    ("auth_smtp", True, "messagerie"),
    ("auth_imap", True, "messagerie"),
    ("auth_ssh", True, "acces_distant"),
    ("leurre", True, "acces_distant"),
    ("aspirateur_ua", False, "collecte"),
    ("recon_crawler", False, "collecte"),
    ("robots", False, "collecte"),
    ("scanners", False, "balayage_web"),
    ("honeypot", False, "balayage_web"),
    ("lfi", False, "balayage_web"),
    ("api_abuse", False, "balayage_web"),
    ("waf_fingerprint", False, "balayage_web"),
    ("host_anomaly:", True, "balayage_web"),
    ("rotation:", True, "collecte"),
)
AUTRE = "autre"

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_HEX8 = re.compile(r"^[0-9a-f]{8}$")
_SIGNATURE = re.compile(r"^[0-9A-Za-z_-]{1,64}$")
_HOTE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")
_LABEL_NUMERIQUE = re.compile(r"^(?:[0-9]+|0x[0-9a-f]*)$")
_PAYS = re.compile(r"^[A-Z]{2}$")


def famille(categorie: str) -> str:
    """La famille d'une catégorie de règle ; « autre » si aucune règle ne s'applique."""
    if not isinstance(categorie, str):
        return AUTRE
    for motif, prefixe, fam in FAMILLE:
        if (prefixe and categorie.startswith(motif)) or (not prefixe and categorie == motif):
            return fam
    return AUTRE


def masquer_compte(compte: str) -> str:
    """Les 3 premiers caractères suivis de « … » ; 3 ou moins : « … » seul (miroir de reseau.MasquerCompte)."""
    c = str(compte or "")
    return "…" if len(c) <= 3 else c[:3] + "…"


def _part(k: int, n: int) -> int:
    """Pourcentage entier arrondi au plus proche (même formule que `part` d'actord)."""
    return (k * 100 + n // 2) // n if n else 0


def _horodatage(valeur: Any) -> Optional[float]:
    """Horodatage RFC 3339 (ou entier Unix) en secondes ; sans fuseau, UTC."""
    try:
        if isinstance(valeur, bool):
            return None
        if isinstance(valeur, (int, float)):
            return float(valeur)
        d = datetime.fromisoformat(str(valeur).replace("Z", "+00:00"))
    except (ValueError, TypeError, OverflowError):
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def _adresse_publique(ip: Any) -> Optional[str]:
    """L'adresse normalisée si elle est publique ; None pour « local », une adresse privée ou illisible."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    return str(a) if a.is_global else None


def _hote(valeur: Any) -> Optional[str]:
    h = str(valeur or "").strip().lower()
    if not h or h.startswith("["):
        return None
    h = h.rsplit(":", 1)[0] if h.count(":") == 1 else h
    return h if _HOTE.match(h) and not _adresse_litterale(h) else None


def _adresse_litterale(h: str) -> bool:
    """L'hôte est une adresse IP, écriture décimale, octale ou hexadécimale incluse (dernier label numérique) : aucune
    adresse ne part vers gk3 sous couvert de cible. Miroir d'`estAdresseLitterale` (sbx-actord)."""
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(_LABEL_NUMERIQUE.match(h.rsplit(".", 1)[-1]))


def _jour(ts: float) -> date:
    return datetime.fromtimestamp(ts).date()     # jour LOCAL de la box : la série se lit en jours de l'opérateur


# ── catalogue et annuaire ───────────────────────────────────────────────────────────────────────────────────────

def charger_catalogue(chemins: Iterable[str]) -> Dict[int, str]:
    """Fusionne les catalogues dans l'ordre, le dernier gagnant ASN par ASN. Un fichier absent, illisible ou qui
    nomme une classe inconnue est ignoré EN ENTIER (comme côté Go : un catalogue tronqué fausserait tout)."""
    res: Dict[int, str] = {}
    if _tomllib is None:
        return res
    for chemin in chemins:
        if not chemin:
            continue
        try:
            with open(chemin, "rb") as f:
                d = _tomllib.load(f)
        except (OSError, ValueError):
            continue
        classes = d.get("classes") if isinstance(d, dict) else None
        if not isinstance(classes, dict):
            continue
        lu: Dict[int, str] = {}
        valide = True
        for classe, asns in classes.items():
            if classe not in CLASSES or not isinstance(asns, list):
                valide = False
                break
            for asn in asns:
                if isinstance(asn, bool) or not isinstance(asn, int) or not 0 < asn < 2 ** 32:
                    valide = False
                    break
                lu[asn] = classe
            if not valide:
                break
        if valide:
            res.update(lu)
    return res


class Annuaire:
    """ASN, opérateur, classe et pays d'une adresse, lus dans les bases locales (jamais un appel réseau). Base absente
    ou illisible : annuaire dégradé (classe `inconnu`, pays vide), jamais une exception."""

    def __init__(self, base_asn, base_pays, catalogues: Iterable[str]):
        """`base_asn`/`base_pays` : un chemin, ou une suite de chemins essayés dans l'ordre (le premier qui s'ouvre)."""
        self._classes = charger_catalogue(catalogues)
        self._asn = self._ouvrir(base_asn)
        self._pays = self._ouvrir(base_pays)

    @staticmethod
    def _ouvrir(chemins):
        if not chemins or _maxminddb is None:
            return None
        for chemin in ([chemins] if isinstance(chemins, str) else chemins):
            if not chemin:
                continue
            try:
                return _maxminddb.open_database(chemin)
            except Exception:  # noqa: BLE001 — absente, ou tronquée pendant sa mise à jour : la suivante
                continue
        return None

    @property
    def disponible(self) -> bool:
        return self._asn is not None

    @property
    def pays_disponible(self) -> bool:
        return self._pays is not None

    def classe_asn(self, asn: int) -> str:
        return self._classes.get(asn, INCONNU) if asn else INCONNU

    def classer(self, ip: str) -> Tuple[int, str, str]:
        vide = (0, "", INCONNU)
        if self._asn is None or _adresse_publique(ip) is None:
            return vide
        try:
            e = self._asn.get(ip)
        except Exception:  # noqa: BLE001 — base corrompue : champs vides
            return vide
        if not isinstance(e, dict):
            return vide
        asn = e.get("autonomous_system_number")
        if not isinstance(asn, int) or isinstance(asn, bool) or asn <= 0:
            return vide
        org = e.get("autonomous_system_organization")
        return asn, (org if isinstance(org, str) else ""), self.classe_asn(asn)

    def pays(self, ip: str) -> str:
        if self._pays is None:
            return ""
        try:
            e = self._pays.get(ip)
        except Exception:  # noqa: BLE001
            return ""
        if not isinstance(e, dict):
            return ""
        for cle in ("country", "registered_country"):
            v = e.get(cle)
            code = v.get("iso_code") if isinstance(v, dict) else None
            if isinstance(code, str) and _PAYS.match(code):
                return code
        return ""

    def fermer(self) -> None:
        for b in (self._asn, self._pays):
            try:
                if b is not None:
                    b.close()
            except Exception:  # noqa: BLE001
                pass
        self._asn = self._pays = None


# ── calcul ──────────────────────────────────────────────────────────────────────────────────────────────────────

class _Pop:
    __slots__ = ("ident", "fam", "adresses", "serie", "bannies", "actives_24h", "bannies_24h", "premier", "dernier",
                 "cibles", "familles")

    def __init__(self, ident: str, fam: str):
        self.ident = ident
        self.fam = fam
        self.adresses: Dict[str, int] = {}
        self.serie = [0] * FENETRE_JOURS
        self.bannies: set = set()
        self.actives_24h: set = set()
        self.bannies_24h: set = set()
        self.premier: Optional[float] = None
        self.dernier: Optional[float] = None
        self.cibles: Dict[str, int] = {}
        self.familles: Dict[str, int] = {}


def _index_profileur(campagnes: list) -> Dict[str, str]:
    """adresse → signature, pour les campagnes du profileur d'au moins SEUIL_PROFILEUR adresses publiques."""
    idx: Dict[str, str] = {}
    for c in campagnes if isinstance(campagnes, list) else []:
        if not isinstance(c, dict):
            continue
        sig = c.get("signature")
        membres = c.get("attaquants")
        if not isinstance(sig, str) or not _SIGNATURE.match(sig) or not isinstance(membres, list):
            continue
        ips = {a for a in (_adresse_publique(m) for m in membres) if a}     # une clé JA4 n'est pas une adresse
        if len(ips) >= SEUIL_PROFILEUR:
            for ip in ips:
                idx.setdefault(ip, sig)
    return idx


def _campagnes_smtp(campagnes: list) -> List[Tuple[str, int]]:
    """(compte masqué, sources) des campagnes d'authwatch, par sources décroissantes (ordre stable)."""
    res: Dict[str, int] = {}
    for c in campagnes if isinstance(campagnes, list) else []:
        if not isinstance(c, dict):
            continue
        compte = masquer_compte(c.get("compte"))     # déjà masqué par authwatch ; idempotent, et sûr s'il ne l'était pas
        if compte == "…":
            continue
        s = c.get("sources")
        res[compte] = res.get(compte, 0) + (s if isinstance(s, int) and not isinstance(s, bool) else 0)
    return sorted(res.items(), key=lambda kv: -kv[1])


def _entier(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def calculer(lignes: Iterable[str], maintenant: float, pays: Callable[[str], str],
             classer: Callable[[str], Tuple[int, str, str]], campagnes_smtp: list, campagnes_profileur: list,
             rotation: list, campagnes_actord: Optional[list] = None,
             classe_asn: Optional[Callable[[int], str]] = None) -> Dict[str, Any]:
    """Le relevé des populations sur les FENETRE_JOURS jours calendaires (locaux) qui finissent aujourd'hui.

    `classer(ip) -> (asn, org, classe)` n'est appelé que pour une adresse dont aucune ligne ne porte le réseau ;
    `classe_asn(asn)` classe une ligne qui porte un ASN sans classe ; `campagnes_actord` None = actord absent."""
    jour_j = _jour(maintenant)
    # Minuits locaux de J-6 … J+1 : l'indice du jour d'une ligne se trouve par dichotomie, sans datetime par ligne.
    minuits = [datetime.combine(date.fromordinal(jour_j.toordinal() - FENETRE_JOURS + 1 + k), datetime.min.time())
               .timestamp() for k in range(FENETRE_JOURS + 1)]
    debut = minuits[0]
    fin = maintenant + 300
    complet = True
    infos: Dict[str, Tuple[int, str, str]] = {}      # adresse → réseau (première valeur vue)
    orgs: Dict[str, str] = {}                         # opérateurs partagés : une chaîne par opérateur
    cves: Dict[str, set] = {}
    pops: Dict[str, _Pop] = {}
    familles_vues: Dict[str, str] = {}               # mémo catégorie → famille (quelques dizaines de catégories)
    hotes_vus: Dict[str, Optional[str]] = {}         # mémo hôte brut → hôte assaini (borné)
    profileur = _index_profileur(campagnes_profileur)
    classe_de = classe_asn or (lambda asn: INCONNU)

    for brut in lignes:
        if not brut or not brut.strip():
            continue
        try:
            e = json.loads(brut)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        cat = e.get("category")
        if not isinstance(cat, str):
            continue
        # La famille d'abord (mémoïsée) : les lignes hors familles (sqli, xss…) ne coûtent ni date ni adresse.
        fam = familles_vues.get(cat)
        if fam is None:
            fam = famille(cat)
            if len(familles_vues) < 10_000:
                familles_vues[cat] = fam
        filtre_ia = cat.startswith("ia_filtres_")
        if fam == AUTRE and not filtre_ia:
            continue
        t = _horodatage(e.get("timestamp"))
        if t is None or t < debut or t > fin:
            continue
        brut_ip = e.get("client_ip")
        if not isinstance(brut_ip, str):
            continue
        ip = brut_ip if brut_ip in infos else _adresse_publique(brut_ip)
        if ip is None:
            continue
        if filtre_ia:
            if ip in cves or len(cves) < MAX_ADRESSES:
                trouve = cves.setdefault(ip, set())
                if len(trouve) < MAX_CVES:
                    trouve.update(_CVE.findall(str(e.get("rule_id") or "")))
            continue
        if ip not in infos:
            if len(infos) >= MAX_ADRESSES:
                complet = False
                continue
            asn = e.get("asn")
            if isinstance(asn, int) and not isinstance(asn, bool) and asn > 0:
                org = e.get("asn_org") if isinstance(e.get("asn_org"), str) else ""
                cl = e.get("reseau_classe")
                cl = cl if cl in CLASSES or cl == INCONNU else classe_de(asn)
                info = (asn, org, cl)
            else:
                info = classer(ip)
            org = orgs.setdefault(info[1], info[1])
            infos[ip] = (info[0], org, info[2])

        # population de la ligne (spec 5.3)
        if cat.startswith("rotation:") and _HEX8.match(cat[9:]):
            cle = "rotation:" + cat[9:]
        elif ip in profileur:
            cle = "profileur:" + profileur[ip]
        else:
            cle = "famille:" + fam
        p = pops.get(cle)
        if p is None:
            p = pops[cle] = _Pop(cle, fam)
        p.adresses[ip] = p.adresses.get(ip, 0) + 1
        p.familles[fam] = p.familles.get(fam, 0) + 1
        i = bisect.bisect_right(minuits, t) - 1
        if 0 <= i < FENETRE_JOURS:
            p.serie[i] += 1
        p.premier = t if p.premier is None or t < p.premier else p.premier
        p.dernier = t if p.dernier is None or t > p.dernier else p.dernier
        recente = maintenant - t <= INACTIVE_S
        if recente:
            p.actives_24h.add(ip)
        if e.get("action") == "banned":
            p.bannies.add(ip)
            if recente:
                p.bannies_24h.add(ip)
        path = e.get("path") if cat.startswith("auth_") else None
        if isinstance(path, str) and path:
            cible = masquer_compte(path)          # compte visé : JAMAIS gardé en clair
        else:
            h = e.get("host")
            h = h if isinstance(h, str) else ""
            cible = hotes_vus.get(h, False)
            if cible is False:
                cible = _hote(h)
                if len(hotes_vus) < MAX_CIBLES_SUIVIES:
                    hotes_vus[h] = cible
        if cible and cible != "…" and (cible in p.cibles or len(p.cibles) < MAX_CIBLES_SUIVIES):
            p.cibles[cible] = p.cibles.get(cible, 0) + 1

    etat_rotation = _etat_rotation(rotation)
    for cle in etat_rotation:
        if cle not in pops:
            pops[cle] = _Pop(cle, "collecte")
    smtp = _campagnes_smtp(campagnes_smtp)

    sortie = []
    vues: Dict[str, int] = {}
    for p in pops.values():
        if not p.familles and p.ident not in etat_rotation:
            continue
        pop = _rendre(p, maintenant, infos, pays, cves, smtp, etat_rotation.get(p.ident))
        if pop["famille"] == AUTRE:
            continue
        pop["campagne_actord"] = _rapprocher(pop, campagnes_actord)
        sortie.append(pop)
        for ip in p.adresses:
            vues[ip] = vues.get(ip, 0) + 1
    sortie.sort(key=lambda x: (-x["serie"][-1], -x["adresses"], x["id"]))
    return {
        "genere_le": int(maintenant),
        "complet": complet,
        "fenetre_jours": FENETRE_JOURS,
        "populations": sortie,
        "recouvrement": {"adresses_communes": sum(1 for n in vues.values() if n > 1), "adresses_total": len(vues)},
    }


def _etat_rotation(rotation: list) -> Dict[str, dict]:
    """Campagnes actives du détecteur de rotation de sbxwaf (tâche 9), par `rotation:<8 premiers caractères>`."""
    res: Dict[str, dict] = {}
    for c in rotation if isinstance(rotation, list) else []:
        if not isinstance(c, dict) or not isinstance(c.get("signature"), str):
            continue
        court = c["signature"][:8].lower()
        if _HEX8.match(court):
            res.setdefault("rotation:" + court, c)
    return res


def _rendre(p: _Pop, maintenant: float, infos: Dict[str, Tuple[int, str, str]], pays: Callable[[str], str],
            cves: Dict[str, set], smtp: List[Tuple[str, int]], etat: Optional[dict]) -> Dict[str, Any]:
    n = len(p.adresses)
    fam = max(p.familles.items(), key=lambda kv: (kv[1], kv[0]))[0] if p.familles else p.fam
    if p.ident.startswith("rotation:"):
        fam = "collecte"
    classes: Dict[str, int] = {}
    reseaux: Dict[int, List] = {}
    par_pays: Dict[str, int] = {}
    une = le3 = 0
    trouvees: set = set()
    for ip, k in p.adresses.items():
        une += k == 1
        le3 += k <= 3
        asn, org, cl = infos.get(ip, (0, "", INCONNU))
        classes[cl] = classes.get(cl, 0) + 1
        if asn:
            r = reseaux.setdefault(asn, [org, cl, 0])
            r[2] += 1
        try:
            code = pays(ip)
        except Exception:  # noqa: BLE001 — base de pays défaillante : pays ignoré
            code = ""
        if isinstance(code, str) and _PAYS.match(code):
            par_pays[code] = par_pays.get(code, 0) + 1
        if ip in cves:
            trouvees |= cves[ip]

    cibles = [c for c, _ in sorted(p.cibles.items(), key=lambda kv: (-kv[1], kv[0]))]
    if fam == "messagerie" and smtp:
        cibles = [c for c, _ in smtp] + [c for c in cibles if c not in {x for x, _ in smtp}]
    if etat and isinstance(etat.get("hote"), str) and _hote(etat["hote"]):
        h = _hote(etat["hote"])
        cibles = [h] + [c for c in cibles if c != h]
    cibles = cibles[:3]

    pop: Dict[str, Any] = {
        "id": p.ident,
        "famille": fam,
        "nom_cible": cibles[0] if cibles else "",
        "cibles": cibles,
        "adresses": n,
        "reseaux": len(reseaux),
        "une": _part(une, n),
        "le3": _part(le3, n),
        "classes": {c: _part(k, n) for c, k in sorted(classes.items(), key=lambda kv: (-kv[1], kv[0]))},
        "pays_top": [[c, _part(k, n)] for c, k in sorted(par_pays.items(), key=lambda kv: (-kv[1], kv[0]))[:3]],
        "reseaux_top": [{"asn": asn, "org": r[0], "classe": r[1], "adresses": r[2]}
                        for asn, r in sorted(reseaux.items(), key=lambda kv: (-kv[1][2], kv[0]))[:5]],
        "serie": list(p.serie),
        "bans": len(p.bannies),
        "premier": int(p.premier) if p.premier is not None else None,
        "dernier": int(p.dernier) if p.dernier is not None else None,
        "actives_24h": len(p.actives_24h),
        "bannies_24h": len(p.bannies_24h),
        "rotation": n >= ROTATION_ADRESSES and _part(le3, n) >= ROTATION_LE3 and _a_un_pivot(p),
        "cves": sorted(trouvees)[:MAX_CVES],
    }
    if etat is not None:
        pop["rotation"] = True
        if n == 0:     # campagne établie (mode propose) sans ligne au journal : chiffres de l'état du détecteur
            pop["adresses"] = _entier(etat.get("sources"))
            pop["une"], pop["le3"] = min(_entier(etat.get("une")), 100), min(_entier(etat.get("le3")), 100)
            cl = etat.get("classes")
            pop["classes"] = {c: min(_entier(v), 100) for c, v in cl.items()
                              if c in CLASSES or c == INCONNU} if isinstance(cl, dict) else {}
            pop["bans"] = _entier(etat.get("bannies"))
            vu = _horodatage(etat.get("dernier"))
            if vu is not None and maintenant - vu <= INACTIVE_S:
                pop["actives_24h"] = pop["adresses"]
                pop["bannies_24h"] = min(pop["bans"], pop["adresses"])
        for champ, cle, plus_tot in (("premier", "etablie_le", True), ("dernier", "dernier", False)):
            v = _horodatage(etat.get(cle))
            if v is not None and (pop[champ] is None or (v < pop[champ] if plus_tot else v > pop[champ])):
                pop[champ] = int(v)
    if pop["dernier"] is None or maintenant - pop["dernier"] > INACTIVE_S:
        pop["etat"] = "inactive"
    elif pop["bannies_24h"] and pop["bannies_24h"] * 100 >= BANNIE_PART * pop["actives_24h"]:
        pop["etat"] = "bannie"
    else:
        pop["etat"] = "observee"
    return pop


def _a_un_pivot(p: _Pop) -> bool:
    """Une famille réunit des activités sans lien : beaucoup d'adresses pressées n'y font une rotation que si elles
    visent la même cible pour moitié au moins. Une campagne (profileur, détecteur) porte déjà son pivot."""
    if not p.ident.startswith("famille:"):
        return True
    return bool(p.cibles) and max(p.cibles.values()) * 100 >= ROTATION_PIVOT * sum(p.adresses.values())


def _rapprocher(pop: Dict[str, Any], campagnes_actord: Optional[list]) -> Optional[str]:
    """Signature de la campagne d'actord de même famille dont les cibles contiennent la cible principale."""
    if not campagnes_actord or not pop["nom_cible"]:
        return None
    for c in campagnes_actord:
        if not isinstance(c, dict) or c.get("famille") != pop["famille"]:
            continue
        cibles = c.get("cibles_noms")
        sig = c.get("signature")
        if isinstance(cibles, list) and pop["nom_cible"] in cibles and isinstance(sig, str) and sig:
            return sig
    return None


# ── lecture des sources ─────────────────────────────────────────────────────────────────────────────────────────

def _rang_rotation(nom: str) -> Optional[int]:
    """0 pour le journal courant, N pour `.log.N` ou `.log.N.gz`, None pour un autre fichier."""
    if nom == JOURNAL:
        return 0
    reste = nom[len(JOURNAL) + 1:] if nom.startswith(JOURNAL + ".") else ""
    if reste.endswith(".gz"):
        reste = reste[:-3]
    return int(reste) if reste.isdigit() else None


def lignes_du_journal(dossier: str, jours: int = FENETRE_JOURS, maintenant: Optional[float] = None) -> Iterator[str]:
    """Le journal des menaces et ses rotations (`.log.N`, `.log.N.gz`), fichier le plus RÉCENT d'abord, EN FLUX : au plafond
    d'adresses (MAX_ADRESSES), celles du jour sont gardées. L'ordre des lignes est sans effet sur le relevé.
    Un fichier non modifié depuis plus de `jours`+1 jours est sauté ; un gzip corrompu s'arrête là, sans erreur."""
    import time
    limite = (maintenant if maintenant is not None else time.time()) - (jours + 1) * 86400
    try:
        noms = os.listdir(dossier)
    except OSError:
        return
    fichiers = sorted(((r, n) for n in noms if (r := _rang_rotation(n)) is not None))
    for _, nom in fichiers:
        chemin = os.path.join(dossier, nom)
        try:
            if os.stat(chemin).st_mtime < limite:
                continue
            ouvrir = gzip.open if nom.endswith(".gz") else open
            with ouvrir(chemin, "rt", encoding="utf-8", errors="replace") as f:
                yield from f
        except (OSError, EOFError, zlib.error):
            continue


def lire_json(chemin: str) -> Tuple[Any, bool]:
    """(contenu, présent). Absent → (None, False) ; présent mais illisible → (None, True)."""
    try:
        with open(chemin, encoding="utf-8") as f:
            return json.load(f), True
    except FileNotFoundError:
        return None, False
    except (OSError, ValueError):
        return None, True


class _ConnexionUnix(http.client.HTTPConnection):
    def __init__(self, chemin: str, delai: float):
        super().__init__("localhost", timeout=delai)
        self._chemin = chemin

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self._chemin)
        except OSError:
            s.close()
            raise
        self.sock = s


def lire_campagnes_actord(chemin: str = ACTORD_SOCK, delai: float = ACTORD_DELAI_S) -> Optional[list]:
    """Les campagnes d'actord en vue complète (`X-Sbx-Vue: complete`), ou None : socket absente, refusée, lente,
    réponse illisible. Jamais une exception."""
    c = _ConnexionUnix(chemin, delai)
    try:
        c.request("GET", "/campaigns", headers={"X-Sbx-Vue": "complete"})
        r = c.getresponse()
        if r.status != 200:
            return None
        d = json.loads(r.read(8 * 1024 * 1024))
    except (OSError, ValueError, http.client.HTTPException):
        return None
    finally:
        c.close()
    return d if isinstance(d, list) else None


def _liste(d: Any, cle: Optional[str] = None) -> list:
    if cle is not None:
        d = d.get(cle) if isinstance(d, dict) else None
    return d if isinstance(d, list) else []


def rafraichir(dossier: str, cache: str, campagnes_profileur: str, maintenant: float) -> bool:
    """Une passe complète : lit toutes les sources, calcule, écrit le cache. Lancée dans un PROCESSUS à part (`main`),
    jamais dans le processus de l'API. Le relevé porte sa durée (`duree_s`)."""
    import time
    debut = time.monotonic()
    manques = []
    smtp, present = lire_json(AUTHWATCH_CAMPAGNES)
    if present and not isinstance(smtp, list):
        manques.append("authwatch")
    prof, present = lire_json(campagnes_profileur)
    if present and not isinstance(prof, dict):
        manques.append("profileur")
    rot, present = lire_json(ROTATION_ETAT)
    if present and not isinstance(rot, dict):
        manques.append("rotation")
    actord = lire_campagnes_actord(ACTORD_SOCK)
    annuaire = Annuaire(BASES_ASN, BASES_PAYS, CATALOGUES)
    try:
        releve = calculer(lignes_du_journal(dossier, FENETRE_JOURS, maintenant), maintenant, annuaire.pays,
                          annuaire.classer, _liste(smtp), _liste(prof, "campagnes"), _liste(rot, "campagnes"),
                          campagnes_actord=actord, classe_asn=annuaire.classe_asn)
        if not annuaire.disponible:
            manques.append("base_asn")
        if not annuaire.pays_disponible:
            manques.append("base_pays")
    finally:
        annuaire.fermer()
    if not os.path.isdir(dossier):
        manques.append("journal")
    if manques:
        releve["manques"] = manques
    # Une source présente mais illisible, ou le journal absent : relevé partiel (spec 5.3). La base ASN manquante
    # n'en fait pas un partiel (classes tirées des lignes, comptes justes), elle est seulement signalée.
    if set(manques) - {"base_asn", "base_pays"}:
        releve["complet"] = False
    releve["duree_s"] = round(time.monotonic() - debut, 2)
    return ecrire_cache(cache, releve)



# ── cache en double tampon ──────────────────────────────────────────────────────────────────────────────────────

def lire_cache(chemin: str) -> Optional[Dict[str, Any]]:
    """Le dernier relevé, ou None s'il manque ou est illisible."""
    try:
        d = json.loads(Path(chemin).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) and isinstance(d.get("populations"), list) else None


def ecrire_cache(chemin: str, releve: Dict[str, Any]) -> bool:
    """Écriture atomique (temporaire du même dossier puis rename), mode 0640. Double tampon (#3011) : un relevé
    `complet: False` n'écrase pas un relevé `complet: True` de moins de DOUBLE_TAMPON_S. Rend True si écrit."""
    if releve.get("complet") is False:
        ancien = lire_cache(chemin)
        if ancien and ancien.get("complet") is True:
            a, n = ancien.get("genere_le"), releve.get("genere_le")
            if isinstance(a, (int, float)) and isinstance(n, (int, float)) and n - a < DOUBLE_TAMPON_S:
                return False
    dossier = os.path.dirname(os.path.abspath(chemin))
    try:
        os.makedirs(dossier, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".populations-", suffix=".tmp", dir=dossier)
    except OSError:
        return False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), MODE_CACHE)
            json.dump(releve, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, chemin)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False
    return True


# ── point d'entrée du processus de calcul ───────────────────────────────────────────────────────────────────────

def _dossier_journal() -> str:
    """Même choix que l'API : SECUBOX_WAF_THREATS_LOG (hérité du processus parent), sinon le dossier de sbxwaf."""
    journal = os.environ.get("SECUBOX_WAF_THREATS_LOG")
    return os.path.dirname(journal) if journal else JOURNAL_DOSSIER


def main(argv: Optional[List[str]] = None) -> int:
    """`python3 -m api.populations --ecrire <cache>` : calcule le relevé et l'écrit. Lancé par la tâche de fond de
    l'API (nice 10, ionice, délai 540 s), sous le même utilisateur qu'elle. Code 0 si écrit, 1 sinon (double tampon, droits)."""
    import argparse
    import time
    ap = argparse.ArgumentParser(prog="api.populations", description="Relevé des populations d'attaquants (#3919)")
    ap.add_argument("--ecrire", required=True, help="chemin du cache à écrire")
    ap.add_argument("--journal", default=None, help="dossier de waf-threats.log* (défaut : celui de sbxwaf)")
    ap.add_argument("--campagnes", default=CAMPAGNES_PROFILEUR, help="instantané des campagnes du profileur")
    args = ap.parse_args(argv)
    ecrit = rafraichir(args.journal or _dossier_journal(), args.ecrire, args.campagnes, time.time())
    releve = lire_cache(args.ecrire) if ecrit else None
    print(json.dumps({"ecrit": ecrit, "duree_s": (releve or {}).get("duree_s")}))
    return 0 if ecrit else 1


if __name__ == "__main__":
    raise SystemExit(main())
