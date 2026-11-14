# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Gestes d'une box d'IA sur le pare-feu du WAF (#3716) : `POST /ai/ban`, `POST /ai/unban`, `GET /ai/etat`.

LE SEUL CHEMIN D'ÉCRITURE D'UNE IA DANS LE PARE-FEU. Exception écrite à RULES-CODE § 3 : ces routes ne portent pas
`require_jwt` mais `require_ai_ban` (`secubox_core.compte_service`) : jeton EdDSA par requête, signé par la clé privée
de la box de l'IA (jamais sur gk2), `aud` = cette box, portée `waf-ban`, `jti` à usage unique, empreinte du corps.

Bornes, toutes vérifiées ICI (le relais ne fait foi de rien) :

- forme : IPv4 publique seule, ou bloc /24 exact (canonique) ; jamais d'IPv6 ; 422 sinon ;
- durée : `GesteBan.duree_s` de 1 h à 7 j (422) ; d'office (`mode = auto`) 24 h au plus (409 `duree`) ;
- plafonds en fenêtres glissantes sur le journal : d'office 5/h et 20/j (`plafond_auto`), compte 30/h et 100/j
  (`plafond_compte`) ; un ban annulé reste compté ;
- d'office : bloc seulement, et le CAS SÛR RECONTRÔLÉ sur gk2 (≥ `SEUIL_BLOC` adresses du bloc dans `waf_ban`,
  toutes de catégories ⊆ `CATEGORIES_SURES`) ; `pas_sur` sinon ;
- une cible déjà bannie (au journal, par le WAF dans `waf_ban`, ou un bloc de l'administrateur) est refusée
  (`deja_actif`) ; `waf_ban` ou la liste des blocs illisibles ⇒ 503 `etat` (jamais « libre » par défaut) ;
- les gardes root de `wafctl` / `waf-blocs` (privé, plages protégées, box, pairs) ; leur motif rendu en 409 ;
- débannir : un `id` du journal seulement, jamais une adresse ; et JAMAIS une cible qu'une autre source couvre
  désormais (ruling P12) : adresse dont le dernier enregistrement de `bans.jsonl` (sbxwaf) est un `ban` non échu,
  bloc dont la fin enregistrée par waf-blocs dépasse celle du journal ai-ban de plus de 5 s. Le ban ai-ban est alors
  clos sans rien lever : état `couvert` ;
- chaque geste est audité (`audit.log`, `by = ai-ban`, empreinte `cle` de la clé, jamais le jeton) : une ligne
  `ai-ban-demande` AVANT wafctl (sans elle, rien n'est fait), `ai-ban` après ; un ban dont l'audit échoue est retiré.
  Les refus (`ai-ban-refus`) et pannes (`ai-ban-echec`) répétés sont regroupés : une ligne par (motif, mode) toutes les
  `INTERVALLE_AUDIT_S`, avec le `nombre` qu'elle résume.

Réponses pour le relais (Tâches 6-7) : `/ai/ban` 200 `{id, cible, fin, audit}`, 409/5xx `{"detail": {"motif"}}` ;
`/ai/unban` 200 `{id, etat}` avec `etat ∈ {annule, echu, deja_annule, couvert}`, 404 `{"detail": {"motif": "inconnu"}}`.

CONTRAINTE P9 : le jeton lie le corps, pas la route. Chaque corps porte un `geste` obligatoire propre à sa route
(`ban`, `unban`) ; `GET /ai/etat` n'accepte aucun corps. CONTRAINTE P11 : aucune route ne déclare de modèle de corps
FastAPI (FastAPI lirait le corps AVANT la garde) ; le corps brut, déjà lu et borné par la garde, est relu puis validé
par `model_validate_json`.

Les gestes sont sérialisés par un verrou de processus (contrôle du journal → wafctl → journal → audit) : les routes
sont servies par UN seul processus, comme l'exige la mémoire de rejeu de la garde : `secubox-waf.service` (uvicorn
mono-processus, sans `--workers`, `User=secubox`, sur /run/secubox/waf.sock), seul processus qui porte
`SECUBOX_WAF_GESTES_IA=1` (drop-in `secubox-waf.service.d/secubox-waf-gestes-ia.conf` livré par ce paquet). Le
serveur d'administration (webui.conf de secubox-hub) envoie `/api/v1/waf/` à waf.sock : `/api/v1/waf/ai/*` y arrive
sans route à part. Tout autre importateur de ce module (un agrégateur qui monterait `waf`, groupd) rend 503
`processus` avant la garde (`processus_designe`) — aucun jeton n'y est lu, aucun jti consommé.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Set, Tuple, Union

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError, field_validator

from secubox_core.compte_service import TAILLE_MAX_CORPS, require_ai_ban

log = logging.getLogger("secubox.waf.gestes_ia")

#: Posé à « 1 » par le seul drop-in de secubox-waf.service (waf.sock) : mémoire de rejeu, verrou et plafonds sont PAR
#: PROCESSUS, deux processus serviraient deux fois le même jeton.
DRAPEAU_PROCESSUS = "SECUBOX_WAF_GESTES_IA"


def processus_designe() -> None:
    """503 `processus` hors du processus désigné, AVANT la garde (la route n'existe pas ici, le jeton n'est pas lu)."""
    if os.environ.get(DRAPEAU_PROCESSUS) != "1":
        raise HTTPException(503, detail={"motif": "processus"})


# Dépendance de routeur : FastAPI la place avant celles de chaque route (require_ai_ban, _corps).
router = APIRouter(prefix="/ai", dependencies=[Depends(processus_designe)])

#: Journal des gestes (ajout seul) : `ban` et `annule`. Il fait foi pour les plafonds et pour « ses propres bans ».
JOURNAL_AI = Path("/var/lib/secubox/waf/ai-ban.jsonl")
#: Journal des bans de sbxwaf (BanRecord `ip`, `at`, `exp`, `action`) : qui d'autre couvre une adresse.
BANS_WAF = Path("/var/lib/secubox/waf/bans.jsonl")
#: Fin d'un journal relue à chaque geste : à 100 bans par jour au plus, des mois de gestes, bien plus que 7 j de ban.
_TAILLE_LECTURE = 4 * 1024 * 1024
_TAILLE_LECTURE_BANS_WAF = 16 * 1024 * 1024

DUREE_MIN_S, DUREE_MAX_S = 3600, 604_800
DUREE_AUTO_MAX_S = 86_400
SEUIL_BLOC = 20
#: Ruling P1 : catégories sûres au départ (waf_fingerprint, product_absent_probes en attente d'arbitrage).
CATEGORIES_SURES = frozenset({"scanners", "recon_crawler"})
HEURE, JOUR = 3600, 86_400
PLAFONDS = {"auto_heure": 5, "auto_jour": 20, "compte_heure": 30, "compte_jour": 100}
#: Un bloc dont la fin enregistrée dépasse la nôtre de plus que ceci a été rebanni par quelqu'un d'autre.
MARGE_BLOC_S = 5
INTERVALLE_AUDIT_S = 10

WAFCTL = "/usr/sbin/wafctl"
_SUDO = ["sudo", "-n"]
#: Les bans de bloc passent par systemd-run : l'état root des blocs s'écrit dans une unité root, hors du bac à sable.
_SYSTEMD_RUN = ["/usr/bin/systemd-run", "--wait", "--pipe", "--collect", "--quiet"]
#: Lecture de l'ensemble du WAF : argv EXACT du sudoers (SBX_WAF_NFTLIST).
NFT_LISTE_WAF_BAN = ["/usr/sbin/nft", "-j", "list", "set", "inet", "secubox", "waf_ban"]
_DELAI_WAFCTL_S = 30

#: Non globales, refusées dès la forme. PAS `ipaddress.is_global` : les plages de DOCUMENTATION (192.0.2.0/24,
#: 198.51.100.0/24, 203.0.113.0/24) restent bannissables, comme dans wafctl et waf-blocs (banc et essais).
NON_GLOBALES = tuple(ipaddress.IPv4Network(r) for r in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"))
_RE_FORME = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/24)?")

#: Motifs que wafctl / waf-blocs peuvent rendre (ensemble FERMÉ : jamais une chaîne arbitraire dans une réponse).
_MOTIFS_409 = frozenset({"privee", "protegee", "box", "pair", "garde_illisible", "duree", "nft"})
_MOTIFS_503 = frozenset({"etat", "audit"})
_MOTIFS_500 = frozenset({"incoherent", "invalide", "usage"})
_MOTIFS_WAFCTL = _MOTIFS_409 | _MOTIFS_503 | _MOTIFS_500
_RE_REFUS = re.compile(r"refus:([a-z_]{1,32})")

_RE_ID = re.compile(r"[0-9a-f]{32}")

#: Branchements fournis par main.py (`configurer`) : bans actifs de `waf_ban` (`ip`, `reason`), audit qui LÈVE.
_config: Dict[str, Callable[..., Any]] = {}
_verrou = threading.Lock()


class Illisible(Exception):
    """Une source dont dépend une garde n'a pas pu être lue : on refuse (503 `etat`), jamais « libre » par défaut."""


def configurer(bans: Callable[[], List[dict]], audit: Callable[[str, str, dict], None]) -> None:
    """`bans()` : bannissements actifs de `waf_ban` (`ip`, `reason`), lecture STRICTE (lève si nft ne répond pas) et
    légère (sans GeoIP) ; `audit(action, detail, user)` : une ligne d'`audit.log`, qui LÈVE si elle n'a pas pu être
    écrite (un geste non audité n'est pas fait, ou est défait)."""
    _config["bans"] = bans
    _config["audit"] = audit


# ── Forme ──────────────────────────────────────────────────────────────
Cible = Union[ipaddress.IPv4Address, ipaddress.IPv4Network]


def forme_cible(texte: Any) -> Cible:
    """Une IPv4 publique ou un /24 exact, écrits sous forme canonique. Lève ValueError sinon."""
    if not isinstance(texte, str) or not _RE_FORME.fullmatch(texte):
        raise ValueError("cible : IPv4 publique ou bloc a.b.c.0/24 attendu")
    try:
        cible: Cible = ipaddress.IPv4Network(texte) if "/" in texte else ipaddress.IPv4Address(texte)
    except ValueError:
        raise ValueError("cible : adresse ou bloc /24 exact attendu") from None
    if str(cible) != texte:
        raise ValueError("cible : forme non canonique")
    reseau = cible if isinstance(cible, ipaddress.IPv4Network) else ipaddress.IPv4Network(f"{cible}/32")
    if any(reseau.overlaps(r) for r in NON_GLOBALES):
        raise ValueError("cible : adresse non publique")
    return cible


class GesteBan(BaseModel):
    model_config = {"extra": "forbid"}

    geste: Literal["ban"]
    cible: str = Field(max_length=18)
    duree_s: int = Field(ge=DUREE_MIN_S, le=DUREE_MAX_S, strict=True)
    mode: Literal["auto", "clic"]
    conseil: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    motif: str = Field("", max_length=200)

    @field_validator("cible")
    @classmethod
    def _cible(cls, v: str) -> str:
        forme_cible(v)
        return v


class GesteAnnuler(BaseModel):
    model_config = {"extra": "forbid"}

    geste: Literal["unban"]
    id: str = Field(pattern=r"^[0-9a-f]{32}$")


def _valider(modele, corps: bytes):
    try:
        return modele.model_validate_json(corps)
    except ValidationError as e:
        raise HTTPException(422, detail=[{"loc": list(err.get("loc", ())), "msg": err.get("msg", ""),
                                          "type": err.get("type", "")} for err in e.errors(include_url=False)])


async def _corps(request: Request, _user: dict = Depends(require_ai_ban)) -> bytes:
    """Le corps brut, APRÈS la garde (qui l'a lu, borné et mis en cache) : P11."""
    corps = await request.body()
    if len(corps) > TAILLE_MAX_CORPS:
        raise HTTPException(413, detail={"motif": "corps_trop_grand"})
    return corps


# ── Journaux ───────────────────────────────────────────────────────────
def _maintenant() -> float:
    return time.time()


def _entier(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _entree_valide(e: Any) -> bool:
    if not isinstance(e, dict) or e.get("type") not in ("ban", "annule"):
        return False
    if not isinstance(e.get("id"), str) or not _RE_ID.fullmatch(e["id"]) or not _entier(e.get("at")):
        return False
    if e["type"] == "ban":
        return isinstance(e.get("cible"), str) and _entier(e.get("fin")) and e.get("mode") in ("auto", "clic")
    return True


def _lire_fin_jsonl(chemin: Path, taille_max: int) -> Optional[List[Any]]:
    """Objets JSON des lignes de la fin d'un fichier (première ligne coupée ignorée) ; None s'il n'existe pas. Lève
    OSError s'il est illisible (lien, dossier, droits)."""
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        taille = os.fstat(f.fileno()).st_size
        debut = max(0, taille - taille_max)
        f.seek(debut)
        donnees = f.read(taille_max)
    lignes = donnees.split(b"\n")
    if debut:
        lignes = lignes[1:]
    objets = []
    for ligne in lignes:
        try:
            objets.append(json.loads(ligne))
        except ValueError:
            continue
    return objets


def _lire_journal() -> List[dict]:
    """Entrées valides de la fin du journal ai-ban ; [] s'il n'existe pas encore. Lève OSError s'il est illisible :
    sans journal, ni plafond ni « ses propres bans » ne peuvent être vérifiés."""
    return [e for e in (_lire_fin_jsonl(JOURNAL_AI, _TAILLE_LECTURE) or []) if _entree_valide(e)]


def _ecrire_journal(entree: dict) -> None:
    """Une ligne ajoutée, écrite et synchronisée. Lève OSError (jamais à travers un lien)."""
    ligne = (json.dumps(entree, ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(JOURNAL_AI, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    try:
        os.write(fd, ligne)
        os.fsync(fd)
    finally:
        os.close(fd)


def _horodatage() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _bilan(entrees: List[dict], maintenant: int) -> Tuple[Dict[str, dict], set, List[dict], Dict[str, int]]:
    """(bans par id, ids annulés, bans actifs, compteurs des fenêtres glissantes). Un ban daté du futur (horloge
    reculée) compte pour un âge nul : un retour de l'horloge ne fait jamais sauter un plafond."""
    bans: Dict[str, dict] = {}
    annules = set()
    for e in entrees:
        if e["type"] == "ban":
            bans.setdefault(e["id"], e)
        else:
            annules.add(e["id"])
    actifs = [b for i, b in bans.items() if i not in annules and b["fin"] > maintenant]
    compteurs = {"auto_heure": 0, "auto_jour": 0, "compte_heure": 0, "compte_jour": 0}
    for b in bans.values():
        age = max(0, maintenant - b["at"])
        if age >= JOUR:
            continue
        compteurs["compte_jour"] += 1
        if age < HEURE:
            compteurs["compte_heure"] += 1
        if b["mode"] == "auto":
            compteurs["auto_jour"] += 1
            if age < HEURE:
                compteurs["auto_heure"] += 1
    return bans, annules, actifs, compteurs


def adresse_couverte_par_le_waf(ip: str, maintenant: int) -> bool:
    """Le DERNIER enregistrement de sbxwaf pour cette adresse est-il un `ban` non échu (`exp` 0 : jusqu'à un unban
    explicite) ? Fichier absent : sbxwaf n'a jamais rien banni. Lève Illisible s'il ne peut pas être lu."""
    try:
        objets = _lire_fin_jsonl(BANS_WAF, _TAILLE_LECTURE_BANS_WAF)
    except OSError as e:
        raise Illisible(f"bans.jsonl : {type(e).__name__}") from None
    dernier = None
    for r in objets or []:
        if isinstance(r, dict) and r.get("ip") == ip:
            dernier = r
    if dernier is None or dernier.get("action") != "ban":
        return False
    exp = dernier.get("exp")
    if exp is None:
        exp = 0
    if not _entier(exp):
        raise Illisible("bans.jsonl : échéance illisible")
    return exp == 0 or exp > maintenant


# ── wafctl, nft ────────────────────────────────────────────────────────
def _executer(argv: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=False, timeout=_DELAI_WAFCTL_S, capture_output=True, text=True)


def _argv(verbe: str, cible: Cible, duree_s: Optional[int] = None) -> List[str]:
    bloc = isinstance(cible, ipaddress.IPv4Network)
    if bloc:
        argv = _SUDO + _SYSTEMD_RUN + [WAFCTL, f"{verbe}-bloc", str(cible)]
    else:
        argv = _SUDO + [WAFCTL, verbe, str(cible)]
    if duree_s is not None:
        argv.append(f"{duree_s}s")
    return argv


def _motif_sortie(r: subprocess.CompletedProcess) -> Optional[str]:
    """Le motif d'un refus : ligne JSON `{"motif": …}` (waf-blocs) ou `refus:<motif>` (garde de `wafctl ban`), pris
    dans l'ensemble fermé des motifs connus ; None sinon."""
    for ligne in (r.stdout or "").splitlines():
        try:
            d = json.loads(ligne)
        except ValueError:
            continue
        if isinstance(d, dict) and d.get("motif") in _MOTIFS_WAFCTL:
            return d["motif"]
    for ligne in (r.stderr or "").splitlines():
        m = _RE_REFUS.fullmatch(ligne.strip())
        if m and m.group(1) in _MOTIFS_WAFCTL:
            return m.group(1)
    return None


def _statut_motif(motif: Optional[str]) -> Tuple[int, str]:
    """etat / audit / incoherent ne sont jamais des refus métier (409) : ce sont des pannes de gk2."""
    if motif in _MOTIFS_409:
        return 409, motif
    if motif in _MOTIFS_500:
        return 500, motif
    if motif in _MOTIFS_503:
        return 503, motif
    return 503, "wafctl"


def _lancer(argv: List[str]) -> Tuple[Optional[subprocess.CompletedProcess], Optional[str]]:
    """(résultat, None) ou (None, raison) si la commande n'a pas pu être lancée ou n'a pas répondu dans le délai."""
    try:
        return _executer(argv), None
    except subprocess.TimeoutExpired:
        return None, "delai"
    except OSError as e:
        return None, type(e).__name__


def _fin_enregistree(r: subprocess.CompletedProcess, repli: int) -> int:
    """La `fin` de la ligne JSON `{"ok": true, …, "fin"}` rendue par `waf-blocs ajouter` (l'entrée qu'il a
    enregistrée) ; `repli` (date prise APRÈS l'appel + durée, jamais avant la sienne) si elle manque ou est illisible."""
    for ligne in (r.stdout or "").splitlines():
        try:
            d = json.loads(ligne)
        except ValueError:
            continue
        if isinstance(d, dict) and d.get("ok") is True and _entier(d.get("fin")) and d["fin"] > 0:
            return d["fin"]
    return repli


def _defaire(cible: Cible) -> bool:
    """Retire le ban qu'on vient de poser (audit ou journal impossibles, wafctl muet). False s'il reste peut-être
    (`wafctl unban` d'une adresse absente rend 0 : l'absence n'est pas un échec)."""
    r, _ = _lancer(_argv("unban", cible))
    if r is None or r.returncode != 0:
        log.error("ai-ban : retour arrière impossible pour %s", cible)
        return False
    return True


def lire_waf_ban() -> Set[str]:
    """Adresses de l'ensemble nft `waf_ban`, lecture STRICTE et légère (ni GeoIP, ni journal) : lève Illisible si nft
    ne répond pas, si la table ou l'ensemble manquent (un pare-feu rechargé n'est pas « aucun ban ») ou si la
    réponse est illisible."""
    r, panne = _lancer(_SUDO + NFT_LISTE_WAF_BAN)
    if r is None:
        raise Illisible(f"nft : {panne}")
    if r.returncode != 0 or not r.stdout:
        raise Illisible(f"nft : code {r.returncode}")
    try:
        doc = json.loads(r.stdout)
        jeux = [b["set"] for b in doc["nftables"] if isinstance(b, dict) and "set" in b]
    except (ValueError, KeyError, TypeError):
        raise Illisible("nft : réponse illisible") from None
    if len(jeux) != 1 or not isinstance(jeux[0], dict) or jeux[0].get("name") != "waf_ban":
        raise Illisible("nft : ensemble waf_ban absent")
    adresses = set()
    for elem in jeux[0].get("elem", []) or []:
        e = elem.get("elem") if isinstance(elem, dict) else None
        val = e.get("val") if isinstance(e, dict) else elem
        if isinstance(val, str):
            adresses.add(val)
    return adresses


def _bans_waf() -> List[dict]:
    """`bans()` de main.py : lève Illisible (ou toute erreur) si `waf_ban` ne peut pas être lu."""
    bans = _config["bans"]()
    if not isinstance(bans, list):
        raise Illisible("bans : réponse illisible")
    return [b for b in bans if isinstance(b, dict)]


def _blocs_enregistres() -> Dict[str, dict]:
    """Blocs de l'état de waf-blocs (`wafctl blocs`, lecture) par bloc ; lève Illisible."""
    r, _ = _lancer(_SUDO + [WAFCTL, "blocs"])
    if r is None or r.returncode != 0:
        raise Illisible("wafctl blocs")
    try:
        blocs = json.loads(r.stdout)["blocs"]
        return {b["bloc"]: b for b in blocs if isinstance(b, dict) and isinstance(b.get("bloc"), str)
                and _entier(b.get("fin")) and _entier(b.get("reste"))}
    except (ValueError, KeyError, TypeError):
        raise Illisible("wafctl blocs : réponse illisible") from None


def _deja_banni_ailleurs(cible: Cible, bans_waf: Optional[List[dict]]) -> bool:
    """La cible est-elle déjà bannie hors du journal ai-ban (WAF, administrateur) ? Lève Illisible."""
    if isinstance(cible, ipaddress.IPv4Network):
        b = _blocs_enregistres().get(str(cible))
        return b is not None and b["reste"] > 0
    if bans_waf is None:
        bans_waf = _bans_waf()
    return str(cible) in {b.get("ip") for b in bans_waf}


def cas_sur(bloc: ipaddress.IPv4Network, bans_waf: List[dict]) -> bool:
    """≥ `SEUIL_BLOC` adresses distinctes du bloc déjà bannies par le WAF, TOUTES de catégories sûres."""
    categories: Dict[str, set] = {}
    for b in bans_waf:
        try:
            adresse = ipaddress.IPv4Address(b.get("ip"))
        except (ValueError, TypeError):
            continue
        if adresse in bloc:
            categories.setdefault(str(adresse), set()).add(str(b.get("reason") or ""))
    return len(categories) >= SEUIL_BLOC and all(c <= CATEGORIES_SURES for c in categories.values())


# ── Audit ──────────────────────────────────────────────────────────────
def _usager(user: dict) -> dict:
    return {"sub": str((user or {}).get("sub") or "ai-ban")}


def _cle(user: dict) -> str:
    return str((user or {}).get("cle") or "")[:64]


def _auditer(action: str, detail: str, user: dict) -> None:
    """Lève si la ligne n'a pas pu être écrite. L'empreinte de la clé qui a signé est ajoutée."""
    _config["audit"](action, f"{detail} cle {_cle(user)}", _usager(user))


def _auditer_sans_lever(action: str, detail: str, user: dict) -> None:
    try:
        _auditer(action, detail, user)
    except Exception as e:  # noqa: BLE001 — la réponse (refus, panne) part quand même
        log.warning("ai-ban : audit %s non écrit : %s", action, type(e).__name__)


#: (action, motif, mode) → [instant de la dernière ligne, refus non encore écrits, dernier détail, usager].
_derniers_refus: Dict[Tuple[str, str, str], list] = {}
_verrou_refus = threading.Lock()
_minuterie: Dict[str, Any] = {"active": None}


def _horloge() -> float:
    return time.monotonic()


def _echus(instant: float) -> list:
    """Sous `_verrou_refus` : les lignes des refus en attente dont la fenêtre est passée (et les remet à zéro)."""
    lignes = []
    for (action, _m, _mode), etat in _derniers_refus.items():
        if etat[1] and instant - etat[0] >= INTERVALLE_AUDIT_S:
            lignes.append((action, f"{etat[2]} nombre {etat[1]}", etat[3]))
            etat[0], etat[1] = instant, 0
    return lignes


def _armer_minuterie() -> None:
    """Sous `_verrou_refus` : une minuterie (fil démon) écrira les refus en attente, même sans nouveau refus."""
    if _minuterie["active"] is not None:
        return
    m = threading.Timer(INTERVALLE_AUDIT_S, _vider_en_attente)
    m.daemon = True
    _minuterie["active"] = m
    m.start()


def _vider_en_attente() -> None:
    with _verrou_refus:
        _minuterie["active"] = None
        lignes = _echus(_horloge())
        if any(e[1] for e in _derniers_refus.values()):
            _armer_minuterie()
    for action, detail, user in lignes:
        _auditer_sans_lever(action, detail, user)


def _auditer_regroupe(action: str, motif: str, mode: str, detail: str, user: dict) -> None:
    """Une ligne par (action, motif, mode) toutes les `INTERVALLE_AUDIT_S` au plus, avec le `nombre` qu'elle
    résume ; les refus retenus sont écrits au refus suivant ou par la minuterie : chacun est compté (gk2 : disque
    plein à 91 %, un relais qui réessaie en boucle ne doit pas remplir `audit.log`)."""
    instant = _horloge()
    with _verrou_refus:
        cle = (action, motif, mode)
        etat = _derniers_refus.get(cle)
        if etat is None:
            _derniers_refus[cle] = [instant, 0, detail, user]
            lignes = [(action, f"{detail} nombre 1", user)]
        else:
            etat[1] += 1
            etat[2], etat[3] = detail, user
            lignes = []
        lignes += _echus(instant)
        if any(e[1] for e in _derniers_refus.values()):
            _armer_minuterie()
    for a, d, u in lignes:
        _auditer_sans_lever(a, d, u)


def _refus(statut: int, motif: str, geste: GesteBan, user: dict) -> HTTPException:
    action = "ai-ban-refus" if statut == 409 else "ai-ban-echec"
    _auditer_regroupe(action, motif, geste.mode,
                      f"motif {motif} cible {geste.cible} mode {geste.mode} conseil {geste.conseil}", user)
    return HTTPException(statut, detail={"motif": motif})


# ── Routes ─────────────────────────────────────────────────────────────
@router.post("/ban")
def ai_ban(user: dict = Depends(require_ai_ban), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    geste: GesteBan = _valider(GesteBan, corps)
    cible = forme_cible(geste.cible)
    bloc = isinstance(cible, ipaddress.IPv4Network)
    with _verrou:
        maintenant = int(_maintenant())
        try:
            _, _, actifs, compteurs = _bilan(_lire_journal(), maintenant)
        except OSError:
            raise _refus(503, "journal", geste, user) from None
        if geste.cible in {b["cible"] for b in actifs}:
            raise _refus(409, "deja_actif", geste, user)
        if geste.mode == "auto" and geste.duree_s > DUREE_AUTO_MAX_S:
            raise _refus(409, "duree", geste, user)
        if (compteurs["compte_heure"] >= PLAFONDS["compte_heure"]
                or compteurs["compte_jour"] >= PLAFONDS["compte_jour"]):
            raise _refus(409, "plafond_compte", geste, user)
        if geste.mode == "auto" and (compteurs["auto_heure"] >= PLAFONDS["auto_heure"]
                                     or compteurs["auto_jour"] >= PLAFONDS["auto_jour"]):
            raise _refus(409, "plafond_auto", geste, user)
        try:
            bans_waf = None
            if geste.mode == "auto":
                if not bloc:
                    raise _refus(409, "pas_sur", geste, user)
                bans_waf = _bans_waf()
                if not cas_sur(cible, bans_waf):
                    raise _refus(409, "pas_sur", geste, user)
            if _deja_banni_ailleurs(cible, bans_waf):
                raise _refus(409, "deja_actif", geste, user)
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001 — waf_ban ou blocs illisibles : jamais « libre » par défaut
            log.warning("ai-ban : garde illisible : %s", e)
            raise _refus(503, "etat", geste, user) from None

        ident = secrets.token_hex(16)
        fin = maintenant + geste.duree_s
        resume = f"id {ident} cible {geste.cible} {geste.duree_s}s fin {fin} mode {geste.mode} conseil {geste.conseil}"
        try:
            _auditer("ai-ban-demande", resume, user)
        except Exception:  # noqa: BLE001 — sans trace de la demande, rien n'est fait
            raise _refus(503, "audit", geste, user) from None

        r, panne = _lancer(_argv("ban", cible, geste.duree_s))
        if r is None:
            # wafctl muet : le ban est peut-être posé, on le retire (la cible n'était bannie par personne d'autre).
            log.error("ai-ban : wafctl injoignable (%s) pour %s", panne, cible)
            _defaire(cible)
            raise _refus(503, "wafctl", geste, user)
        if r.returncode != 0:
            raise _refus(*_statut_motif(_motif_sortie(r)), geste, user)
        if bloc:
            # Revue finale I1 : la fin qui fait foi est celle que waf-blocs a ENREGISTRÉE (sa date est prise après
            # nos lectures, l'audit et systemd-run) ; `_couverte` la compare à la nôtre à MARGE_BLOC_S près.
            fin = _fin_enregistree(r, int(_maintenant()) + geste.duree_s)
            resume = (f"id {ident} cible {geste.cible} {geste.duree_s}s fin {fin} mode {geste.mode} "
                      f"conseil {geste.conseil}")

        entree = {"ts": _horodatage(), "at": maintenant, "type": "ban", "id": ident, "cible": geste.cible,
                  "fin": fin, "mode": geste.mode, "conseil": geste.conseil, "motif": geste.motif,
                  "jti": str((user or {}).get("jti") or ""), "cle": _cle(user), "duree_s": geste.duree_s}
        try:
            _ecrire_journal(entree)
        except OSError:
            # hors journal, le ban échapperait aux plafonds et ne pourrait pas être annulé par son id
            if _defaire(cible):
                raise _refus(503, "journal", geste, user) from None
            raise _refus(500, "incoherent", geste, user) from None
        try:
            _auditer("ai-ban", resume, user)
        except Exception:  # noqa: BLE001 — un ban non audité n'existe pas : il est retiré
            defait = _defaire(cible)
            try:
                _ecrire_journal({"ts": _horodatage(), "at": maintenant, "type": "annule", "id": ident,
                                 "cible": geste.cible, "cause": "audit"})
            except OSError:
                log.error("ai-ban : annulation %s non journalisée", ident)
            raise HTTPException(500, detail={"motif": "audit" if defait else "incoherent"}) from None
    return {"id": ident, "cible": geste.cible, "fin": fin, "audit": ident}


def _couverte(cible: Cible, ban: dict, maintenant: int) -> bool:
    """Ruling P12 : une autre source couvre-t-elle désormais la cible ? Lève Illisible."""
    if isinstance(cible, ipaddress.IPv4Network):
        b = _blocs_enregistres().get(str(cible))
        return b is not None and b["fin"] > ban["fin"] + MARGE_BLOC_S
    return adresse_couverte_par_le_waf(str(cible), maintenant)


def _clore(ident: str, ban: dict, maintenant: int, cause: str) -> None:
    """Ligne `annule` au journal ; 503 `journal` si elle ne peut pas être écrite."""
    try:
        _ecrire_journal({"ts": _horodatage(), "at": maintenant, "type": "annule", "id": ident,
                         "cible": ban["cible"], "cause": cause})
    except OSError:
        raise HTTPException(503, detail={"motif": "journal"}) from None


@router.post("/unban")
def ai_unban(user: dict = Depends(require_ai_ban), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    geste: GesteAnnuler = _valider(GesteAnnuler, corps)
    with _verrou:
        maintenant = int(_maintenant())
        try:
            bans, annules, _, _ = _bilan(_lire_journal(), maintenant)
        except OSError:
            raise HTTPException(503, detail={"motif": "journal"}) from None
        ban = bans.get(geste.id)
        if ban is None:
            raise HTTPException(404, detail={"motif": "inconnu"})
        if geste.id in annules:
            return {"id": geste.id, "etat": "deja_annule"}
        if ban["fin"] <= maintenant:
            return {"id": geste.id, "etat": "echu"}
        try:
            cible = forme_cible(ban["cible"])
        except ValueError:
            raise HTTPException(500, detail={"motif": "journal"}) from None
        try:
            couverte = _couverte(cible, ban, maintenant)
        except Exception as e:  # noqa: BLE001 — sans savoir qui d'autre couvre la cible, on ne lève rien
            log.warning("ai-unban : couverture illisible : %s", e)
            raise HTTPException(503, detail={"motif": "etat"}) from None
        if couverte:
            # Une autre source (WAF, administrateur) a banni la cible depuis : ai-ban clôt SON ban sans rien lever.
            try:
                _auditer("ai-unban-couvert", f"id {geste.id} cible {ban['cible']}", user)
            except Exception:  # noqa: BLE001
                raise HTTPException(503, detail={"motif": "audit"}) from None
            _clore(geste.id, ban, maintenant, "couvert")
            return {"id": geste.id, "etat": "couvert"}
        # Audit AVANT le geste : lever un ban sans trace serait pire que ne pas le lever.
        try:
            _auditer("ai-unban", f"id {geste.id} cible {ban['cible']}", user)
        except Exception:  # noqa: BLE001
            raise HTTPException(503, detail={"motif": "audit"}) from None
        r, _ = _lancer(_argv("unban", cible))
        if r is None or r.returncode != 0:
            statut, motif = (503, "wafctl") if r is None else _statut_motif(_motif_sortie(r))
            _auditer_sans_lever("ai-unban-echec", f"id {geste.id} cible {ban['cible']} motif {motif}", user)
            raise HTTPException(statut, detail={"motif": motif})
        # le ban est levé et audité ; si la ligne manque, un nouvel essai refera un retrait idempotent puis la ligne
        _clore(geste.id, ban, maintenant, "unban")
    return {"id": geste.id, "etat": "annule"}


@router.get("/etat")
def ai_etat(user: dict = Depends(require_ai_ban), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    _ = user
    if corps:
        raise HTTPException(422, detail={"motif": "corps"})   # P9 : un jeton de geste ne vaut rien ici
    try:
        _, _, actifs, compteurs = _bilan(_lire_journal(), int(_maintenant()))
    except OSError:
        raise HTTPException(503, detail={"motif": "journal"}) from None
    return {"actifs": [{"id": b["id"], "cible": b["cible"], "fin": b["fin"], "mode": b["mode"]}
                       for b in sorted(actifs, key=lambda b: (b["fin"], b["id"]))],
            "compteurs": compteurs, "plafonds": dict(PLAFONDS)}
