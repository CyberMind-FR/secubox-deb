# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Gestes d'une box d'IA sur le pare-feu du WAF (#3716, #3723) : `POST /ai/ban`, `POST /ai/unban`,
`POST /ai/prolonger`, `POST /ai/limiter`, `POST /ai/leurre`, `GET /ai/etat`.

LE SEUL CHEMIN D'ÉCRITURE D'UNE IA DANS LE PARE-FEU. Exception écrite à RULES-CODE § 3 : ces routes ne portent pas
`require_jwt` mais `require_ai_ban` (`secubox_core.compte_service`) : jeton EdDSA par requête, signé par la clé privée
de la box de l'IA (jamais sur gk2), `aud` = cette box, portée `waf-ban`, `jti` à usage unique, empreinte du corps.

Bornes, toutes vérifiées ICI (le relais ne fait foi de rien) :

- forme : IPv4 publique seule, ou bloc /24 exact (canonique) ; jamais d'IPv6 ; 422 sinon ;
- porte du mode SADE (#3723), AVANT tout autre contrôle d'un geste d'office (`mode = auto`, et `prolonger`) : le
  fichier `/run/secubox/sade-mode.json` publié par secubox-soc (`mode_sade`). Absent : aucune porte (comportement
  d'avant) ; `observe` (ou fichier illisible, daté de plus de `SADE_PERIME_S`, mode inconnu) : 409 `sade_observe` ;
  `reactive` : seul `limiter` passe, 409 `sade_reactive` sinon ; `active` / `aggressive` : la porte est ouverte. Sa
  `liste_blanche` est une liste de cibles protégées (409 `protegee`, tous modes) ; illisible ⇒ 503 `etat` ;
- durée : `GesteBan.duree_s` de 1 h à 7 j (422) ; bloc d'office 24 h au plus (409 `duree`) ; adresse d'office :
  la durée du client est ignorée, gk2 la calcule (24 h × 4 par ban ai-ban précédent de l'adresse, 7 j au plus) ;
- plafonds PAR GESTE en fenêtres glissantes sur le journal (`PLAFONDS_PAR_GESTE`, chaque ligne porte son `geste`,
  les anciennes lignes sans lui sont classées par la forme de la cible) : `ban` d'adresse 60/h et 400/j, d'office et
  clic sommés (`plafond_heure`, `plafond_jour`) ; `ban_bloc` d'office 5/h et 20/j (`plafond_auto`) et tout bloc
  30/h et 100/j (`plafond_compte`, les blocs seuls) ; `prolonger` 30/h et 100/j ; un ban annulé reste compté ;
- adresse d'office : vue dans le journal des menaces depuis moins de 24 h (`non_vue` sinon, lecture bornée de sa
  fin) ; jamais un pair du maillage (`wg_mesh.json` + threatmesh `/peers`) ni un robot vérifié (FCrDNS, règle de
  sbxwaf) : 409 `protegee`, source muette ou DNS en doute ⇒ 409 `protegee_inconnue` ; `wafctl ban … --exiger-protegees`
  (protegees.env exigé par la garde root, comme pour un bloc) ; bloc d'office : le CAS SÛR RECONTRÔLÉ sur gk2 (≥ `SEUIL_BLOC` adresses du bloc dans `waf_ban`,
  toutes de familles ⊆ `CATEGORIES_SURES`) ; `pas_sur` sinon. Famille d'une adresse (I4) : celle de son DERNIER
  enregistrement `ban` de `bans.jsonl` (historique de sbxwaf), à défaut le motif du journal des menaces (~6 h), à
  défaut « waf » ; `bans.jsonl` illisible ⇒ 503 `etat` ;
- une cible déjà bannie (au journal, par le WAF dans `waf_ban`, ou un bloc de l'administrateur) est refusée
  (`deja_actif`) ; `waf_ban` ou la liste des blocs illisibles ⇒ 503 `etat` (jamais « libre » par défaut) ;
- les gardes root de `wafctl` / `waf-blocs` (privé, plages protégées, box, pairs) ; leur motif rendu en 409 ;
- prolonger : un `id` d'un ban ai-ban ACTIF du journal seulement (409 `inconnu` sinon, jamais le ban d'une autre
  source) ; nouvelle fin = maintenant + `duree_s`, jamais plus tôt que la fin actuelle (409 `raccourcit`), jamais
  au-delà de 7 j (409 `duree`) ; ligne `prolonge` au journal, qui fait foi pour la fin ensuite ;
- limiter (#3723, tâche 2) : une adresse publique IPv4 ou IPv6 (forme canonique) ; 1 h à 24 h (409 `duree`) ;
  60/h et 400/j ; mêmes cibles protégées et même porte SADE que les gestes d'office (seul geste admis en `reactive`) ;
  `wafctl limiter <ip> <N>s` (ensembles limite_ia_v4|v6 de inet secubox_waf_ratelimit, règle `drop`) ; ligne
  `limite` au journal, levée par `/ai/unban` de son id (`wafctl limiter-lever`), jamais prolongée ;
- leurre (#3723, tâche 3) : une adresse publique IPv4 ou IPv6 (forme canonique) redirigée vers le théâtre de sbxwaf ;
  1 h à 7 j (409 `duree`) ; 30/h et 200/j ; mêmes cibles protégées et même porte SADE que les gestes d'office (refusé
  en `reactive`) ; une cible déjà bannie (ban ai-ban actif, bloc ai-ban ou de l'administrateur, `waf_ban`/`waf_ban6`)
  est refusée en 409 `deja_banni` : un attaquant banni n'atteint pas le leurre, rien n'est levé ici ;
  `wafctl leurre <ip> <N>s` (liste /var/lib/secubox/waf/leurres-ip.json, root, remplacement atomique) ; ligne
  `leurre` au journal, levée par `/ai/unban` de son id (`wafctl leurre-lever`), jamais prolongée ;
- débannir : un `id` du journal seulement, jamais une adresse ; et JAMAIS une cible qu'une autre source couvre
  désormais (ruling P12) : adresse dont le dernier enregistrement de `bans.jsonl` (sbxwaf) est un `ban` non échu,
  bloc dont la fin enregistrée par waf-blocs dépasse celle du journal ai-ban de plus de 5 s. Le ban ai-ban est alors
  clos sans rien lever : état `couvert` ;
- chaque geste est audité (`audit.log`, `by = ai-ban`, empreinte `cle` de la clé, jamais le jeton) : une ligne
  `ai-ban-demande` AVANT wafctl (sans elle, rien n'est fait), `ai-ban` après ; un ban dont l'audit échoue est retiré.
  Les refus (`ai-ban-refus`) et pannes (`ai-ban-echec`) répétés sont regroupés : une ligne par (motif, mode) toutes les
  `INTERVALLE_AUDIT_S`, avec le `nombre` qu'elle résume.

Réponses pour le relais (Tâches 6-7) : `/ai/ban` 200 `{id, cible, fin, duree_s, audit}`, 409/5xx
`{"detail": {"motif"}}` ; `/ai/prolonger` 200 `{id, cible, fin, audit}` ;
`/ai/unban` 200 `{id, etat}` avec `etat ∈ {annule, echu, deja_annule, couvert}`, 404 `{"detail": {"motif": "inconnu"}}`.

CONTRAINTE P9 : le jeton lie le corps, pas la route. Chaque corps porte un `geste` obligatoire propre à sa route
(`ban`, `unban`, `prolonger`) ; `GET /ai/etat` n'accepte aucun corps. CONTRAINTE P11 : aucune route ne déclare de
modèle de corps FastAPI (FastAPI lirait le corps AVANT la garde) ; le corps brut, déjà lu et borné par la garde, est
relu puis validé par `model_validate_json`.

Les gestes sont sérialisés par un verrou de processus (contrôle du journal → wafctl → journal → audit) : les routes
sont servies par UN seul processus, comme l'exige la mémoire de rejeu de la garde : `secubox-waf.service` (uvicorn
mono-processus, sans `--workers`, `User=secubox`, sur /run/secubox/waf.sock), seul processus qui porte
`SECUBOX_WAF_GESTES_IA=1` (drop-in `secubox-waf.service.d/secubox-waf-gestes-ia.conf` livré par ce paquet). Le
serveur d'administration (webui.conf de secubox-hub) envoie `/api/v1/waf/` à waf.sock : `/api/v1/waf/ai/*` y arrive
sans route à part. Tout autre importateur de ce module (un agrégateur qui monterait `waf`, groupd) rend 503
`processus` avant la garde (`processus_designe`) — aucun jeton n'y est lu, aucun jti consommé.
"""
from __future__ import annotations

import concurrent.futures
import http.client
import ipaddress
import json
import logging
import os
import pwd
import re
import secrets
import socket
import stat
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Callable, Dict, List, Literal, Optional, Set, Tuple, Union

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError, field_validator

from fastapi.concurrency import run_in_threadpool
from secubox_core import auth as _auth
from secubox_core.compte_service import TAILLE_MAX_CORPS, cles_publiques, garde_compte_service, require_ai_ban

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
#: Journal des bans de sbxwaf (BanRecord `ip`, `cat`, `at`, `exp`, `action`) : qui d'autre couvre une adresse, et la
#: catégorie de chaque ban (cas sûr). Lu par sa FIN, 16 Mio au plus : au-delà, les enregistrements les plus anciens
#: ne sont plus lus (une adresse bannie il y a longtemps retombe alors sur le journal des menaces).
BANS_WAF = Path("/var/lib/secubox/waf/bans.jsonl")
#: Fin d'un journal relue à chaque geste : à 100 bans par jour au plus, des mois de gestes, bien plus que 7 j de ban.
_TAILLE_LECTURE = 4 * 1024 * 1024
_TAILLE_LECTURE_BANS_WAF = 16 * 1024 * 1024

#: Journal des menaces de sbxwaf (`timestamp`, `client_ip`) : « vue depuis moins de 24 h » d'une adresse d'office.
JOURNAL_MENACES = Path(os.environ.get("SECUBOX_WAF_THREATS_LOG") or "/var/log/secubox/waf/waf-threats.log")
_TAILLE_LECTURE_MENACES = 16 * 1024 * 1024
VUE_FENETRE_S = 86_400

#: Mode SADE publié par secubox-soc (`defense_etat.publier_mode`) : `{"mode", "depuis", "liste_blanche"}`, `depuis`
#: = instant de la publication (battement de 60 s). Jamais la base du SOC : ce fichier seul.
FICHIER_SADE = Path("/run/secubox/sade-mode.json")  # cru seulement s'il est à root ou à COMPTE_SADE, sans g+w/o+w
#: /run/secubox est 1777 : le fichier n'est cru que s'il appartient à root ou au compte de l'API SOC (`secubox`), sans
#: écriture du groupe ni des autres. Tout processus de ce compte peut l'écrire (limite documentée au README).
COMPTE_SADE = "secubox"
_TAILLE_MAX_SADE = 256 * 1024
SADE_PERIME_S = 900
#: Une publication datée du futur au-delà de ceci est illisible (même horloge des deux côtés : c'est la même box).
_SADE_AVANCE_MAX_S = 60
MODES_SADE = frozenset({"observe", "reactive", "active", "aggressive"})
#: Gestes d'office admis en `reactive` (décision du propriétaire : limiter seul) ; `observe` n'en admet aucun.
GESTES_AUTO_REACTIVE = frozenset({"limiter"})

#: Pairs du maillage, jamais visés par un geste d'office (mêmes sources que sade_auto de secubox-soc) : le fichier
#: local `wg_mesh.json` (`mesh_ip`, `endpoint`) et threatmesh `GET /peers` (`address`, `endpoint`, `ip`).
WG_MESH = Path(os.environ.get("SECUBOX_WAF_WG_MESH") or "/var/lib/secubox/p2p/wg_mesh.json")
_TAILLE_MAX_WG_MESH = 1024 * 1024
SOCKET_THREATMESH = "/run/secubox/threatmesh.sock"
_DELAI_THREATMESH_S = 3.0
_TAILLE_MAX_PAIRS = 1024 * 1024
#: Robots d'indexation vérifiés : même règle que sbxwaf (crawlers.go, #2240), DNS inverse CONFIRMÉ par le direct
#: (FCrDNS) vers un de ces domaines. Une erreur DNS transitoire ou un délai : protection inconnue (on ne bannit pas).
DOMAINES_ROBOTS = ("googlebot.com", "google.com", "search.msn.com", "applebot.apple.com", "crawl.baidu.com",
                   "yandex.com", "yandex.ru", "yandex.net")
_DELAI_DNS_S = 4.0
_dns = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="ai-ban-dns")

DUREE_MIN_S, DUREE_MAX_S = 3600, 604_800
DUREE_AUTO_MAX_S = 86_400
#: Adresse d'office : 24 h, × 4 par ban ai-ban précédent de la même adresse, `DUREE_MAX_S` au plus.
DUREE_AUTO_ADRESSE_S, FACTEUR_RECIDIVE = 86_400, 4
SEUIL_BLOC = 20
#: Familles sûres (I4, décision du propriétaire du 14/11) : reconnaissance, sondes, leurres. Les familles d'attaque
#: (xss, lfi, sqli, rce, api_abuse, campagne, mesure…), toute autre, et « waf » (inconnue) restent en un clic.
#: MÊME ENSEMBLE côté relais du POC (`gestes.py`) : la règle effective est relais ∧ gk2.
CATEGORIES_SURES = frozenset({"scanners", "recon_crawler", "host_anomaly", "leurre", "product_absent_probes",
                              "honeypot", "waf_fingerprint"})
HEURE, JOUR = 3600, 86_400
#: Plafonds des blocs (#3716) : `auto_*` les blocs d'office, `compte_*` tous les blocs (les adresses ont les leurs).
PLAFONDS = {"auto_heure": 5, "auto_jour": 20, "compte_heure": 30, "compte_jour": 100}
#: Plafonds par geste (#3723), fenêtres glissantes, sommés sur tous les niveaux. `ban` : adresses (d'office et clic) ;
#: `ban_bloc` : blocs d'office (les mêmes que `auto_*`). Un geste nouveau ajoute ici sa ligne et son compteur.
PLAFONDS_PAR_GESTE = {"ban": {"heure": 60, "jour": 400},
                      "ban_bloc": {"heure": PLAFONDS["auto_heure"], "jour": PLAFONDS["auto_jour"]},
                      "prolonger": {"heure": 30, "jour": 100},
                      "limiter": {"heure": 60, "jour": 400},
                      "leurre": {"heure": 30, "jour": 200}}
LIMITE_MIN_S, LIMITE_MAX_S = 3600, 86_400
LEURRE_MIN_S, LEURRE_MAX_S = 3600, 604_800
#: Gestes « sans ban » du journal : rangés avec les bans (annulables par leur id), jamais un ban actif ni prolongés.
#: type de la ligne → (nom du geste, verbe wafctl de levée).
GESTES_SANS_BAN = {"limite": ("limiter", "limiter-lever"), "leurre": ("leurre", "leurre-lever")}
#: Causes d'annulation qui retirent un ban de la récidive : jamais posé (audit) ou retiré par l'IA ou l'humain.
_CAUSES_SANS_RECIDIVE = frozenset({"audit", "unban"})
#: Un bloc dont la fin enregistrée dépasse la nôtre de plus que ceci a été rebanni par quelqu'un d'autre.
MARGE_BLOC_S = 5
INTERVALLE_AUDIT_S = 10

WAFCTL = "/usr/sbin/wafctl"
_SUDO = ["sudo", "-n"]
#: Les bans de bloc passent par systemd-run : l'état root des blocs s'écrit dans une unité root, hors du bac à sable.
_SYSTEMD_RUN = ["/usr/bin/systemd-run", "--wait", "--pipe", "--collect", "--quiet"]
#: Lecture de l'ensemble du WAF : argv EXACT du sudoers (SBX_WAF_NFTLIST).
NFT_LISTE_WAF_BAN = ["/usr/sbin/nft", "-j", "list", "set", "inet", "secubox", "waf_ban"]
#: Idem pour l'IPv6 (SBX_WAF_NFTLIST l'autorise aussi) : lu par le geste garde-ban (#3794).
NFT_LISTE_WAF_BAN6 = ["/usr/sbin/nft", "-j", "list", "set", "inet", "secubox", "waf_ban6"]
_DELAI_WAFCTL_S = 30

#: Non globales, refusées dès la forme. PAS `ipaddress.is_global` : les plages de DOCUMENTATION (192.0.2.0/24,
#: 198.51.100.0/24, 203.0.113.0/24) restent bannissables, comme dans wafctl et waf-blocs (banc et essais).
NON_GLOBALES = tuple(ipaddress.IPv4Network(r) for r in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"))
_RE_FORME = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/24)?")

#: Motifs que wafctl / waf-blocs peuvent rendre (ensemble FERMÉ : jamais une chaîne arbitraire dans une réponse).
_MOTIFS_409 = frozenset({"privee", "protegee", "box", "pair", "garde_illisible", "duree", "nft", "absent", "plein"})
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
Cible = Union[ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address]


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


#: IPv6 jamais limitables : non globales, ou porteuses d'IPv4 (contourneraient les gardes IPv4), comme waf-blocs.
_V6_REFUSES = tuple(ipaddress.IPv6Network(r) for r in ("::ffff:0:0/96", "::/96", "2002::/16", "64:ff9b::/96",
                                                      "64:ff9b:1::/48", "2001::/32"))
_V6_DOCUMENTATION = ipaddress.IPv6Network("2001:db8::/32")
_RE_FORME_V6 = re.compile(r"[0-9a-f:]{2,39}")


def forme_limite(texte: Any) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    """Cible du geste `limiter` (#3723) : une adresse publique IPv4 (règles de `forme_cible`) ou IPv6 globale, écrite
    sous forme canonique (minuscules, compressée). Lève ValueError sinon."""
    if isinstance(texte, str) and ":" in texte:
        if not _RE_FORME_V6.fullmatch(texte):
            raise ValueError("cible : adresse IPv6 canonique attendue")
        try:
            a = ipaddress.IPv6Address(texte)
        except ValueError:
            raise ValueError("cible : adresse IPv6 attendue") from None
        if str(a) != texte:
            raise ValueError("cible : forme non canonique")
        # 2001:db8::/32 (documentation) reste limitable comme 192.0.2.0/24 : banc et essais (comme wafctl)
        documentation = a in _V6_DOCUMENTATION
        if a.is_multicast or (not a.is_global and not documentation) or any(a in r for r in _V6_REFUSES):
            raise ValueError("cible : adresse non publique")
        return a
    cible = forme_cible(texte)
    if not isinstance(cible, ipaddress.IPv4Address):
        raise ValueError("cible : une adresse seule, jamais un bloc")
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


class GesteProlonger(BaseModel):
    """`duree_s` : nouvelle fin = maintenant + `duree_s` ; au-delà de 7 j, 409 `duree` (borne de la forme bien plus
    large : le refus est un motif métier, pas une erreur de forme)."""
    model_config = {"extra": "forbid"}

    geste: Literal["prolonger"]
    id: str = Field(pattern=r"^[0-9a-f]{32}$")
    duree_s: int = Field(ge=1, le=10 * DUREE_MAX_S, strict=True)
    conseil: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    motif: str = Field("", max_length=200)


class GesteLimiter(BaseModel):
    """`duree_s` : 1 h à 24 h, sinon 409 `duree` (borne de la forme bien plus large : refus métier)."""
    model_config = {"extra": "forbid"}

    geste: Literal["limiter"]
    cible: str = Field(max_length=39)
    duree_s: int = Field(ge=1, le=10 * DUREE_MAX_S, strict=True)
    conseil: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    motif: str = Field("", max_length=200)

    @field_validator("cible")
    @classmethod
    def _cible(cls, v: str) -> str:
        forme_limite(v)
        return v


class GesteLeurre(BaseModel):
    """`duree_s` : 1 h à 7 j, sinon 409 `duree` (borne de la forme bien plus large : refus métier)."""
    model_config = {"extra": "forbid"}

    geste: Literal["leurre"]
    cible: str = Field(max_length=39)
    duree_s: int = Field(ge=1, le=10 * DUREE_MAX_S, strict=True)
    conseil: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    motif: str = Field("", max_length=200)

    @field_validator("cible")
    @classmethod
    def _cible(cls, v: str) -> str:
        forme_limite(v)
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
    if not isinstance(e, dict) or e.get("type") not in ("ban", "annule", "prolonge", *GESTES_SANS_BAN):
        return False
    if not isinstance(e.get("id"), str) or not _RE_ID.fullmatch(e["id"]) or not _entier(e.get("at")):
        return False
    if e["type"] == "ban":
        return isinstance(e.get("cible"), str) and _entier(e.get("fin")) and e.get("mode") in ("auto", "clic")
    if e["type"] == "prolonge":
        return _entier(e.get("fin"))
    if e["type"] in GESTES_SANS_BAN:
        return isinstance(e.get("cible"), str) and _entier(e.get("fin"))
    return True


def geste_de(e: dict) -> str:
    """Geste d'une entrée du journal. Un ban est classé par la FORME de sa cible (`ban` / `ban_bloc`), qui fait foi
    pour les lignes d'avant #3723 sans champ `geste` comme pour les autres ; `prolonge` → `prolonger`."""
    if e["type"] == "prolonge":
        return "prolonger"
    if e["type"] in GESTES_SANS_BAN:
        return GESTES_SANS_BAN[e["type"]][0]
    if e["type"] == "ban":
        return "ban_bloc" if "/" in e["cible"] else "ban"
    return "unban"


def _lire_fin_octets(chemin: Path, taille_max: int) -> Optional[List[bytes]]:
    """Lignes de la fin d'un fichier, `taille_max` octets au plus (première ligne coupée ignorée) ; None s'il
    n'existe pas. Lève OSError s'il est illisible (lien, dossier, droits)."""
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
    return lignes


def _lire_fin_jsonl(chemin: Path, taille_max: int) -> Optional[List[Any]]:
    """Objets JSON des lignes de la fin d'un fichier (première ligne coupée ignorée) ; None s'il n'existe pas. Lève
    OSError s'il est illisible (lien, dossier, droits)."""
    lignes = _lire_fin_octets(chemin, taille_max)
    if lignes is None:
        return None
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
    fd = os.open(JOURNAL_AI, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o660)
    try:
        # Ouvert au GROUPE secubox-waf, quel que soit l'umask : secubox-waf-ng.service fait `chown -R secubox-waf`
        # sur ce répertoire à chaque démarrage, et ce service (compte secubox) n'écrit plus alors que par le groupe.
        st = os.fstat(fd)
        if st.st_uid == os.geteuid() and st.st_mode & 0o060 != 0o060:
            os.fchmod(fd, 0o660)
        os.write(fd, ligne)
        os.fsync(fd)
    finally:
        os.close(fd)


def _horodatage() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _bilan(entrees: List[dict], maintenant: int) -> Tuple[Dict[str, dict], set, List[dict], Dict[str, int]]:
    """(bans par id, ids annulés, bans actifs, compteurs des fenêtres glissantes). La fin d'un ban est la plus tardive
    de la sienne et de ses lignes `prolonge`. Compteurs : `PLAFONDS` (blocs) et `<geste>_heure` / `<geste>_jour` de
    chaque geste de `PLAFONDS_PAR_GESTE`. Une entrée datée du futur (horloge reculée) compte pour un âge nul : un
    retour de l'horloge ne fait jamais sauter un plafond."""
    bans: Dict[str, dict] = {}
    annules = set()
    prolongees: Dict[str, int] = {}
    comptees: List[Tuple[str, str, int]] = []
    for e in entrees:
        if e["type"] == "ban":
            if e["id"] not in bans:
                bans[e["id"]] = e
                comptees.append((geste_de(e), e["mode"], e["at"]))
        elif e["type"] == "prolonge":
            prolongees[e["id"]] = max(prolongees.get(e["id"], 0), e["fin"])
            comptees.append(("prolonger", "auto", e["at"]))
        elif e["type"] in GESTES_SANS_BAN:
            # une limite, un leurre : rangés avec les bans (annulables par leur id), jamais un ban actif
            if e["id"] not in bans:
                bans[e["id"]] = {**e, "mode": "auto"}
                comptees.append((GESTES_SANS_BAN[e["type"]][0], "auto", e["at"]))
        else:
            annules.add(e["id"])
    for i, fin in prolongees.items():
        if i in bans and fin > bans[i]["fin"]:
            bans[i] = {**bans[i], "fin": fin}
    actifs = [b for i, b in bans.items() if i not in annules and b["fin"] > maintenant and b["type"] == "ban"]
    compteurs = dict.fromkeys(PLAFONDS, 0)
    for g in PLAFONDS_PAR_GESTE:
        compteurs[f"{g}_heure"] = compteurs[f"{g}_jour"] = 0
    for geste, mode, at in comptees:
        age = max(0, maintenant - at)
        if age >= JOUR:
            continue
        fenetres = ("jour", "heure") if age < HEURE else ("jour",)
        cles = []
        if geste == "ban_bloc":
            cles.append("compte")
            if mode == "auto":
                cles += ["auto", "ban_bloc"]
        else:
            cles.append(geste)
        for cle in cles:
            for f in fenetres:
                if f"{cle}_{f}" in compteurs:
                    compteurs[f"{cle}_{f}"] += 1
    return bans, annules, actifs, compteurs


def limites_actives(bans: Dict[str, dict], annules: set, maintenant: int, type_: str = "limite") -> List[dict]:
    """Limites (geste `limiter`), ou leurres (`type_` = `leurre`), non annulés et non échus, du journal."""
    return [b for i, b in bans.items() if b["type"] == type_ and i not in annules and b["fin"] > maintenant]


def _plafond_atteint(compteurs: Dict[str, int], geste: str) -> Optional[str]:
    """`plafond_heure` / `plafond_jour` si le geste a atteint l'un de ses plafonds, None sinon."""
    p = PLAFONDS_PAR_GESTE[geste]
    if compteurs[f"{geste}_heure"] >= p["heure"]:
        return "plafond_heure"
    if compteurs[f"{geste}_jour"] >= p["jour"]:
        return "plafond_jour"
    return None


def plafonds_par_geste(compteurs: Dict[str, int]) -> Dict[str, Dict[str, int]]:
    return {g: {"heure": p["heure"], "jour": p["jour"],
                "restant_heure": max(0, p["heure"] - compteurs[f"{g}_heure"]),
                "restant_jour": max(0, p["jour"] - compteurs[f"{g}_jour"])}
            for g, p in PLAFONDS_PAR_GESTE.items()}


def duree_recidive(entrees: List[dict], ip: str) -> int:
    """Durée d'un ban d'office de l'adresse : 24 h × 4 par ban ai-ban précédent de cette adresse dans le journal
    (hors bans jamais posés ou retirés : causes `_CAUSES_SANS_RECIDIVE`), `DUREE_MAX_S` au plus."""
    retires = {e["id"] for e in entrees if e["type"] == "annule" and e.get("cause") in _CAUSES_SANS_RECIDIVE}
    n = len({e["id"] for e in entrees if e["type"] == "ban" and e["cible"] == ip and e["id"] not in retires})
    return min(DUREE_MAX_S, DUREE_AUTO_ADRESSE_S * FACTEUR_RECIDIVE ** min(n, 8))


# ── Journal des menaces, mode SADE ─────────────────────────────────────
def _instant(valeur: Any) -> Optional[float]:
    """Instant d'un horodatage RFC 3339 (`2026-11-21T10:00:00Z`) ou d'un entier epoch ; None s'il est illisible."""
    if _entier(valeur):
        return float(valeur)
    if not isinstance(valeur, str) or not valeur:
        return None
    try:
        d = datetime.fromisoformat(valeur.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d.timestamp() if d.tzinfo is not None else None


def vue_recemment(ip: str, maintenant: int) -> bool:
    """L'adresse a-t-elle une ligne de menace de moins de `VUE_FENETRE_S` dans la FIN du journal des menaces
    (`_TAILLE_LECTURE_MENACES` au plus) ? Champ `client_ip` (ou `ip`) EXACT, instant `timestamp` (RFC 3339 avec
    décalage ; sans décalage : ignorée). Journal absent : jamais vue. Lève Illisible s'il ne peut pas être lu."""
    try:
        lignes = _lire_fin_octets(JOURNAL_MENACES, _TAILLE_LECTURE_MENACES)
    except OSError as e:
        raise Illisible(f"journal des menaces : {type(e).__name__}") from None
    aiguille = f'"{ip}"'.encode()
    seuil = maintenant - VUE_FENETRE_S
    for ligne in reversed(lignes or []):
        if aiguille not in ligne:
            continue
        try:
            e = json.loads(ligne)
        except ValueError:
            continue
        if not isinstance(e, dict) or ip not in (e.get("client_ip"), e.get("ip")):
            continue
        # sbxwaf (threatlog.go, logEntry) écrit `timestamp` en RFC 3339 avec le décalage local
        # (`time.Now().Format(time.RFC3339)`), et aucun champ `at` : seul `timestamp` fait foi.
        instant = _instant(e.get("timestamp")) if isinstance(e.get("timestamp"), str) else None
        if instant is not None and instant >= seuil:
            return True
    return False


def _reseaux(valeur: Any) -> Optional[List[Any]]:
    """Réseaux IPv4 et IPv6 d'une liste blanche publiée (IPv6 : cibles du geste `limiter`) ; None si elle est
    illisible (une seule entrée illisible suffit : jamais une liste partielle)."""
    if not isinstance(valeur, list):
        return None
    reseaux = []
    for v in valeur:
        if not isinstance(v, str) or len(v) > 64:
            return None
        try:
            n = ipaddress.ip_network(v, strict=False)
        except ValueError:
            return None
        reseaux.append(n)
    return reseaux


def lire_sade() -> Optional[Dict[str, Any]]:
    """None : fichier absent (aucune porte). Sinon `{"mode", "liste"}` : `mode` vaut `observe` si le fichier est
    illisible, daté de plus de `SADE_PERIME_S` (ou du futur), ou d'un mode inconnu ; `liste` (réseaux IPv4 protégés)
    vaut None si elle ne peut pas être lue. Jamais à travers un lien, jamais plus de `_TAILLE_MAX_SADE` octets."""
    illisible: Dict[str, Any] = {"mode": "observe", "liste": None}
    try:
        fd = os.open(FICHIER_SADE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as e:
        log.warning("ai-ban : mode SADE illisible : %s", type(e).__name__)
        return illisible
    try:
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                return illisible
            if st.st_uid not in _uids_sade() or st.st_mode & 0o022:
                # /run/secubox est 1777 : un fichier d'un autre compte, ou modifiable par d'autres, peut être forgé
                _signaler_une_fois(f"proprietaire uid {st.st_uid} mode {stat.S_IMODE(st.st_mode):o}")
                return {"mode": "observe", "liste": []}
            donnees = f.read(_TAILLE_MAX_SADE + 1)
    except OSError as e:
        log.warning("ai-ban : mode SADE illisible : %s", type(e).__name__)
        return illisible
    if len(donnees) > _TAILLE_MAX_SADE:
        return illisible
    try:
        d = json.loads(donnees)
    except ValueError:
        return illisible
    if not isinstance(d, dict):
        return illisible
    mode, depuis = d.get("mode"), _instant(d.get("depuis"))
    maintenant = _maintenant()
    if (not isinstance(mode, str) or mode not in MODES_SADE or depuis is None
            or maintenant - depuis > SADE_PERIME_S or depuis - maintenant > _SADE_AVANCE_MAX_S):
        mode = "observe"
    return {"mode": mode, "liste": _reseaux(d.get("liste_blanche"))}


def _uids_sade() -> Set[int]:
    """root et le compte de l'API SOC ; compte inconnu : root seul."""
    try:
        return {0, pwd.getpwnam(COMPTE_SADE).pw_uid}
    except KeyError:
        return {0}


_signales: Set[str] = set()


def _signaler_une_fois(raison: str) -> None:
    if raison not in _signales:
        _signales.add(raison)
        log.error("ai-ban : fichier du mode SADE non fiable (%s) : tenu pour observe, liste vide", raison)


def mode_sade() -> Optional[str]:
    """Mode SADE effectif pour gk2 : None (fichier absent, comportement d'avant #3723), sinon le mode publié, ou
    `observe` si le fichier est illisible ou daté de plus de 15 min."""
    sade = lire_sade()
    return None if sade is None else sade["mode"]


def porte_sade(geste: str, sade: Optional[Dict[str, Any]]) -> Optional[str]:
    """Motif du refus d'un geste d'office par le mode SADE, None s'il passe."""
    if sade is None:
        return None
    if sade["mode"] == "observe":
        return "sade_observe"
    if sade["mode"] == "reactive" and geste not in GESTES_AUTO_REACTIVE:
        return "sade_reactive"
    return None


def protegee_par_sade(cible: Cible, sade: Optional[Dict[str, Any]]) -> bool:
    """La cible touche-t-elle la liste blanche SADE ? Lève Illisible si la liste n'a pas pu être lue."""
    if sade is None:
        return False
    if sade["liste"] is None:
        raise Illisible("liste blanche SADE illisible")
    return any(_touche(cible, n) for n in sade["liste"])


def _touche(cible: Cible, n: Any) -> bool:
    """La cible (adresse ou bloc) recoupe-t-elle le réseau `n` (même famille seulement) ?"""
    if cible.version != n.version:
        return False
    if isinstance(cible, ipaddress.IPv4Network):
        return cible.overlaps(n)
    return cible in n


def famille(categorie: Any) -> str:
    """Famille d'une catégorie de sbxwaf : coupée au premier « | » (suffixe `|prolonge`), puis au premier « : »
    (sous-catégorie). `host_anomaly:unrouted` → `host_anomaly` ; `scanners|prolonge` → `scanners` ; non-chaîne → ""."""
    if not isinstance(categorie, str):
        return ""
    return categorie.split("|", 1)[0].split(":", 1)[0].strip()


#: État de la lecture incrémentale de `bans.jsonl` : fichier (chemin, dev, ino), `lu` (octets déjà consommés),
#: `reste` (fin de ligne sans « \n » encore), `base` (début de la lecture de départ), `familles`. Lu à la fois par le
#: fil de fond de `_get_bans` et par `/ai/ban` : tout passe par `_verrou_familles`.
_verrou_familles = threading.Lock()
_cache_familles: Dict[str, Any] = {"etat": None}
#: Une fin de ligne en attente plus longue que ceci n'est plus un enregistrement : abandonnée.
_RESTE_MAX = 1024 * 1024


def _appliquer_familles(familles: Dict[str, str], donnees: bytes) -> None:
    for ligne in donnees.split(b"\n"):
        try:
            r = json.loads(ligne)
        except ValueError:
            continue
        if isinstance(r, dict) and r.get("action") == "ban" and isinstance(r.get("ip"), str):
            familles[r["ip"]] = famille(r.get("cat"))


def familles_bans_waf() -> Dict[str, str]:
    """Famille du DERNIER enregistrement `ban` de chaque adresse dans `bans.jsonl` (les `unban` ne changent pas la
    catégorie). Fichier absent : {}. Lecture STRICTE : lève Illisible s'il ne peut pas être lu (jamais « aucune
    catégorie »). Lecture INCRÉMENTALE : même fichier (dev, ino) et taille ≥ octets déjà lus ⇒ seuls les octets
    ajoutés sont analysés (lignes entières ; la fin sans « \n » attend le tour suivant, mais est comptée si c'est
    déjà un JSON entier, comme une lecture complète). Sinon (rotation, troncature, nouvel inode) ou si le fichier a
    grandi de plus de deux bornes depuis la lecture de départ : reconstruit depuis la FIN du fichier, au plus
    `_TAILLE_LECTURE_BANS_WAF` (mémoire bornée)."""
    try:
        st = os.stat(BANS_WAF, follow_symlinks=False)
    except FileNotFoundError:
        with _verrou_familles:
            _cache_familles["etat"] = None
        return {}
    except OSError as e:
        raise Illisible(f"bans.jsonl : {type(e).__name__}") from None
    cle = (str(BANS_WAF), st.st_dev, st.st_ino)
    with _verrou_familles:
        etat = _cache_familles["etat"]
        if etat is not None and etat["cle"] == cle and etat["taille"] == st.st_size \
                and etat["mtime"] == st.st_mtime_ns:
            return _vue_familles(etat)
        try:
            fd = os.open(BANS_WAF, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as f:
                etat = _lire_familles(f, os.fstat(f.fileno()), etat)
        except FileNotFoundError:
            _cache_familles["etat"] = None
            return {}
        except OSError as e:
            raise Illisible(f"bans.jsonl : {type(e).__name__}") from None
        _cache_familles["etat"] = etat
        return _vue_familles(etat)


def _vue_familles(etat: dict) -> Dict[str, str]:
    """Copie des familles, plus la fin sans « \n » si c'est déjà un enregistrement entier (sans la retenir)."""
    familles = dict(etat["familles"])
    if etat["reste"]:
        _appliquer_familles(familles, etat["reste"])
    return familles


def _lire_familles(f, st: os.stat_result, etat: Optional[dict]) -> dict:
    """Prolonge `etat` des octets ajoutés, ou le reconstruit depuis la fin du fichier ouvert `f` (état `st`)."""
    taille = st.st_size
    cle = (str(BANS_WAF), st.st_dev, st.st_ino)
    borne = _TAILLE_LECTURE_BANS_WAF
    if (etat is not None and etat["cle"] == cle and taille >= etat["lu"] and taille - etat["base"] <= 2 * borne):
        f.seek(etat["lu"])
        donnees = etat["reste"] + f.read(taille - etat["lu"])
        familles, base = etat["familles"], etat["base"]
    else:
        debut = max(0, taille - borne)
        f.seek(debut)
        donnees = f.read(taille - debut)
        if debut:  # première ligne probablement coupée
            donnees = donnees.split(b"\n", 1)[1] if b"\n" in donnees else b""
        familles, base = {}, debut
    complet, _, reste = donnees.rpartition(b"\n")
    _appliquer_familles(familles, complet)
    if len(reste) > _RESTE_MAX:
        reste = b""
    return {"cle": cle, "lu": taille, "reste": reste, "base": base, "familles": familles,
            "taille": taille, "mtime": st.st_mtime_ns}


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


def _argv(verbe: str, cible: Cible, duree_s: Optional[int] = None, d_office: bool = False) -> List[str]:
    """argv exact du sudoers. `prolonger` d'une adresse : `wafctl prolonger <ip> <N>s` (retrait + ajout en une
    transaction nft) ; d'un bloc : `ban-bloc` (waf-blocs ne raccourcit jamais). `d_office` sur un ban d'adresse :
    `--exiger-protegees` (protegees.env exigé par la garde root, #3723)."""
    bloc = isinstance(cible, ipaddress.IPv4Network)
    if bloc and verbe in ("limiter", "limiter-lever", "leurre", "leurre-lever"):
        raise ValueError(f"{verbe} : une adresse seule")
    if bloc:
        argv = _SUDO + _SYSTEMD_RUN + [WAFCTL, f"{'ban' if verbe == 'prolonger' else verbe}-bloc", str(cible)]
    else:
        argv = _SUDO + [WAFCTL, verbe, str(cible)]
    if duree_s is not None:
        argv.append(f"{duree_s}s")
    if d_office and verbe == "ban" and not bloc:
        argv.append("--exiger-protegees")
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


def _defaire(cible: Cible, etiquette: str = "ai-ban") -> bool:
    """Retire le ban qu'on vient de poser (audit ou journal impossibles, wafctl muet). False s'il reste peut-être
    (`wafctl unban` d'une adresse absente rend 0 : l'absence n'est pas un échec)."""
    r, _ = _lancer(_argv("unban", cible))
    if r is None or r.returncode != 0:
        log.error("%s : retour arrière impossible pour %s", etiquette, cible)
        return False
    return True


def lire_waf_ban(ensemble: str = "waf_ban") -> Set[str]:
    """Adresses de l'ensemble nft `waf_ban`, lecture STRICTE et légère (ni GeoIP, ni journal) : lève Illisible si nft
    ne répond pas, si la table ou l'ensemble manquent (un pare-feu rechargé n'est pas « aucun ban ») ou si la
    réponse est illisible."""
    if ensemble not in ("waf_ban", "waf_ban6"):
        raise ValueError(ensemble)
    r, panne = _lancer(_SUDO + (NFT_LISTE_WAF_BAN if ensemble == "waf_ban" else NFT_LISTE_WAF_BAN6))
    if r is None:
        raise Illisible(f"nft : {panne}")
    if r.returncode != 0 or not r.stdout:
        raise Illisible(f"nft : code {r.returncode}")
    try:
        doc = json.loads(r.stdout)
        jeux = [b["set"] for b in doc["nftables"] if isinstance(b, dict) and "set" in b]
    except (ValueError, KeyError, TypeError):
        raise Illisible("nft : réponse illisible") from None
    if len(jeux) != 1 or not isinstance(jeux[0], dict) or jeux[0].get("name") != ensemble:
        raise Illisible(f"nft : ensemble {ensemble} absent")
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


def cas_sur(bloc: ipaddress.IPv4Network, bans_waf: List[dict], familles: Dict[str, str]) -> bool:
    """≥ `SEUIL_BLOC` adresses distinctes du bloc déjà bannies par le WAF, TOUTES de familles sûres. Famille d'une
    adresse : `familles` (dernier `ban` de bans.jsonl), à défaut celle de son motif `reason` (journal des menaces)."""
    categories: Dict[str, set] = {}
    for b in bans_waf:
        try:
            adresse = ipaddress.IPv4Address(b.get("ip"))
        except (ValueError, TypeError):
            continue
        if adresse in bloc:
            ip = str(adresse)
            fam = familles[ip] if ip in familles else famille(b.get("reason"))
            categories.setdefault(ip, set()).add(fam)
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


# ── Cibles protégées des gestes d'office : pairs du maillage, robots vérifiés ──
class ProtectionInconnue(Exception):
    """Une source de cibles protégées n'a pas pu être lue : le geste d'office est refusé (409 `protegee_inconnue`)."""


def _reseau_pair(texte: Any) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Réseau d'une adresse, d'un CIDR ou d'un point d'accès « hôte:port » / « [v6]:port » (comme
    `defense._reseau` de secubox-soc) ; None si illisible (un nom d'hôte n'est pas une adresse)."""
    if not isinstance(texte, str) or not texte.strip() or len(texte) > 128:
        return None
    t = texte.strip()
    if t.startswith("[") and "]" in t:
        t = t[1:t.index("]")]
    elif t.count(":") == 1:
        t = t.split(":")[0]
    try:
        return ipaddress.ip_network(t, strict=False)
    except ValueError:
        return None


def pairs_wg_mesh() -> List[Any]:
    """Pairs du fichier local `wg_mesh.json` ; absent : [] (box sans maillage). Illisible ou de forme inattendue :
    ProtectionInconnue."""
    try:
        fd = os.open(WG_MESH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise ProtectionInconnue(f"wg_mesh.json : {type(e).__name__}") from None
    try:
        with os.fdopen(fd, "rb") as f:
            donnees = f.read(_TAILLE_MAX_WG_MESH + 1)
    except OSError as e:
        raise ProtectionInconnue(f"wg_mesh.json : {type(e).__name__}") from None
    if len(donnees) > _TAILLE_MAX_WG_MESH:
        raise ProtectionInconnue("wg_mesh.json : trop grand")
    try:
        doc = json.loads(donnees)
    except ValueError:
        raise ProtectionInconnue("wg_mesh.json : illisible") from None
    pairs = doc.get("peers") if isinstance(doc, dict) else doc
    if not isinstance(pairs, list):
        raise ProtectionInconnue("wg_mesh.json : forme inattendue")
    return [n for p in pairs if isinstance(p, dict) for n in (_reseau_pair(p.get(c)) for c in ("mesh_ip", "endpoint"))
            if n is not None]


class _ConnexionUnix(http.client.HTTPConnection):
    def __init__(self, chemin: str, delai: float):
        super().__init__("localhost", timeout=delai)
        self._chemin = chemin

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._chemin)


def _lire_threatmesh_peers() -> Any:
    """`GET /peers` de threatmesh sur sa socket (comme le substrat de secubox-soc : en-tête LAN si le mode tableau de
    bord est armé). Lève ProtectionInconnue sur toute défaillance (socket absente comprise : jamais « aucun pair »)."""
    entetes = {_auth.ENTETE_LAN: "1"} if _auth.mode_tableau_de_bord_actif() else {}
    conn = _ConnexionUnix(SOCKET_THREATMESH, _DELAI_THREATMESH_S)
    try:
        conn.request("GET", "/peers", headers=entetes)
        rep = conn.getresponse()
        corps = rep.read(_TAILLE_MAX_PAIRS + 1)
    except (OSError, http.client.HTTPException) as e:
        raise ProtectionInconnue(f"threatmesh : {type(e).__name__}") from None
    finally:
        conn.close()
    if rep.status != 200 or len(corps) > _TAILLE_MAX_PAIRS:
        raise ProtectionInconnue(f"threatmesh : http {rep.status}")
    try:
        return json.loads(corps)
    except ValueError:
        raise ProtectionInconnue("threatmesh : réponse illisible") from None


def pairs_threatmesh() -> List[Any]:
    doc = _lire_threatmesh_peers()
    pairs = doc.get("peers") if isinstance(doc, dict) else None
    if not isinstance(pairs, list):
        raise ProtectionInconnue("threatmesh : forme inattendue")
    return [n for p in pairs if isinstance(p, dict) for n in (_reseau_pair(p.get(c)) for c in ("address", "endpoint", "ip"))
            if n is not None]


def domaine_robot(nom: str) -> str:
    """Le domaine reconnu dont `nom` est un sous-domaine (jamais un simple suffixe de texte)."""
    nom = nom.lower().rstrip(".")
    for d in DOMAINES_ROBOTS:
        if nom == d or nom.endswith("." + d):
            return d
    return ""


def _fcrdns(ip: str) -> str:
    """Domaine du robot si `ip` est un robot vérifié (inverse dans un domaine reconnu ET direct qui revient à `ip`),
    "" sinon. Lève ProtectionInconnue sur une erreur DNS transitoire (TRY_AGAIN, EAI_AGAIN, délai)."""
    try:
        nom, alias, _ = socket.gethostbyaddr(ip)
    except socket.herror as e:
        if e.errno in (1, 4):       # HOST_NOT_FOUND, NO_DATA : aucun nom inverse, ce n'est pas un robot
            return ""
        raise ProtectionInconnue(f"dns inverse : {e.errno}") from None
    except OSError as e:
        raise ProtectionInconnue(f"dns inverse : {type(e).__name__}") from None
    for n in [nom, *alias]:
        dom = domaine_robot(n)
        if not dom:
            continue
        try:
            famille_ip = socket.AF_INET6 if ":" in ip else socket.AF_INET
            infos = socket.getaddrinfo(n.rstrip("."), None, famille_ip)
        except socket.gaierror as e:
            if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)):
                continue
            raise ProtectionInconnue(f"dns direct : {e.errno}") from None
        except OSError as e:
            raise ProtectionInconnue(f"dns direct : {type(e).__name__}") from None
        if any(_meme_adresse(i[4][0], ip) for i in infos):
            return dom
    return ""


def _meme_adresse(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a.split("%")[0]) == ipaddress.ip_address(b)
    except ValueError:
        return False


def robot_verifie(ip: str) -> str:
    """`_fcrdns` borné à `_DELAI_DNS_S` : au-delà, ProtectionInconnue (le doute ne vaut jamais ban)."""
    tache = _dns.submit(_fcrdns, ip)
    try:
        return tache.result(timeout=_DELAI_DNS_S)
    except concurrent.futures.TimeoutError:
        raise ProtectionInconnue("dns : délai") from None


def protegee_d_office(cible: Cible) -> bool:
    """Pair du maillage (wg_mesh.json + threatmesh /peers) ou robot vérifié (adresse seule) ? Lève
    ProtectionInconnue si une source ne répond pas : un geste d'office n'est jamais fait à l'aveugle."""
    pairs = pairs_wg_mesh() + pairs_threatmesh()
    if any(_touche(cible, n) for n in pairs):
        return True
    return not isinstance(cible, ipaddress.IPv4Network) and bool(robot_verifie(str(cible)))


def _refus(statut: int, motif: str, geste: Union[GesteBan, GesteProlonger, GesteLimiter, GesteLeurre], user: dict,
           etiquette: str = "ai-ban") -> HTTPException:
    action = f"{etiquette}-refus" if statut == 409 else f"{etiquette}-echec"
    if isinstance(geste, GesteProlonger):
        mode, quoi = "auto", f"id {geste.id}"
    elif isinstance(geste, (GesteLimiter, GesteLeurre)):
        mode, quoi = "auto", f"cible {geste.cible}"
    else:
        mode, quoi = geste.mode, f"cible {geste.cible}"
    _auditer_regroupe(action, motif, mode, f"motif {motif} {quoi} mode {mode} conseil {geste.conseil}", user)
    return HTTPException(statut, detail={"motif": motif})


# ── Routes ─────────────────────────────────────────────────────────────
@router.post("/ban")
def ai_ban(user: dict = Depends(require_ai_ban), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    geste: GesteBan = _valider(GesteBan, corps)
    cible = forme_cible(geste.cible)
    bloc = isinstance(cible, ipaddress.IPv4Network)
    nom = "ban_bloc" if bloc else "ban"
    auto_adresse = geste.mode == "auto" and not bloc
    sade = lire_sade()
    if geste.mode == "auto":
        motif = porte_sade(nom, sade)   # AVANT tout autre contrôle d'un geste d'office
        if motif:
            raise _refus(409, motif, geste, user)
    with _verrou:
        maintenant = int(_maintenant())
        try:
            entrees = _lire_journal()
            _, _, actifs, compteurs = _bilan(entrees, maintenant)
        except OSError:
            raise _refus(503, "journal", geste, user) from None
        if geste.cible in {b["cible"] for b in actifs}:
            raise _refus(409, "deja_actif", geste, user)
        if bloc:
            if geste.mode == "auto" and geste.duree_s > DUREE_AUTO_MAX_S:
                raise _refus(409, "duree", geste, user)
            if (compteurs["compte_heure"] >= PLAFONDS["compte_heure"]
                    or compteurs["compte_jour"] >= PLAFONDS["compte_jour"]):
                raise _refus(409, "plafond_compte", geste, user)
            if geste.mode == "auto" and (compteurs["auto_heure"] >= PLAFONDS["auto_heure"]
                                         or compteurs["auto_jour"] >= PLAFONDS["auto_jour"]):
                raise _refus(409, "plafond_auto", geste, user)
        else:
            motif = _plafond_atteint(compteurs, "ban")
            if motif:
                raise _refus(409, motif, geste, user)
        try:
            if protegee_par_sade(cible, sade):
                raise _refus(409, "protegee", geste, user)
            if geste.mode == "auto":
                try:
                    if protegee_d_office(cible):
                        raise _refus(409, "protegee", geste, user)
                except ProtectionInconnue as e:
                    log.warning("ai-ban : cibles protégées inconnues : %s", e)
                    raise _refus(409, "protegee_inconnue", geste, user) from None
            bans_waf = None
            if geste.mode == "auto":
                if bloc:
                    bans_waf = _bans_waf()
                    if not cas_sur(cible, bans_waf, familles_bans_waf()):
                        raise _refus(409, "pas_sur", geste, user)
                elif not vue_recemment(geste.cible, maintenant):
                    raise _refus(409, "non_vue", geste, user)
            if _deja_banni_ailleurs(cible, bans_waf):
                raise _refus(409, "deja_actif", geste, user)
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001 — waf_ban, blocs, menaces ou liste blanche illisibles : jamais « libre »
            log.warning("ai-ban : garde illisible : %s", e)
            raise _refus(503, "etat", geste, user) from None

        # Adresse d'office : la durée est celle de gk2 (récidive), jamais celle du client.
        duree_s = duree_recidive(entrees, geste.cible) if auto_adresse else geste.duree_s
        ident = secrets.token_hex(16)
        fin = maintenant + duree_s
        resume = f"id {ident} cible {geste.cible} {duree_s}s fin {fin} mode {geste.mode} conseil {geste.conseil}"
        try:
            _auditer("ai-ban-demande", resume, user)
        except Exception:  # noqa: BLE001 — sans trace de la demande, rien n'est fait
            raise _refus(503, "audit", geste, user) from None

        r, panne = _lancer(_argv("ban", cible, duree_s, d_office=geste.mode == "auto"))
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
            fin = _fin_enregistree(r, int(_maintenant()) + duree_s)
            resume = (f"id {ident} cible {geste.cible} {duree_s}s fin {fin} mode {geste.mode} "
                      f"conseil {geste.conseil}")

        entree = {"ts": _horodatage(), "at": maintenant, "type": "ban", "geste": nom, "id": ident,
                  "cible": geste.cible, "fin": fin, "mode": geste.mode, "conseil": geste.conseil, "motif": geste.motif,
                  "jti": str((user or {}).get("jti") or ""), "cle": _cle(user), "duree_s": duree_s}
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
                _ecrire_journal({"ts": _horodatage(), "at": maintenant, "type": "annule", "geste": nom, "id": ident,
                                 "cible": geste.cible, "cause": "audit"})
            except OSError:
                log.error("ai-ban : annulation %s non journalisée", ident)
            raise HTTPException(500, detail={"motif": "audit" if defait else "incoherent"}) from None
    return {"id": ident, "cible": geste.cible, "fin": fin, "duree_s": duree_s, "audit": ident}


@router.post("/prolonger")
def ai_prolonger(user: dict = Depends(require_ai_ban), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    """Prolonge un ban ai-ban ACTIF du journal (#3723). Geste d'office : la porte du mode SADE passe d'abord."""
    geste: GesteProlonger = _valider(GesteProlonger, corps)
    sade = lire_sade()
    motif = porte_sade("prolonger", sade)
    if motif:
        raise _refus(409, motif, geste, user, "ai-prolonger")
    with _verrou:
        maintenant = int(_maintenant())
        try:
            _, _, actifs, compteurs = _bilan(_lire_journal(), maintenant)
        except OSError:
            raise _refus(503, "journal", geste, user, "ai-prolonger") from None
        ban = next((b for b in actifs if b["id"] == geste.id), None)
        if ban is None:
            # inconnu, annulé ou échu : jamais le ban d'une autre source, jamais un ban levé
            raise _refus(409, "inconnu", geste, user, "ai-prolonger")
        if geste.duree_s > DUREE_MAX_S:
            raise _refus(409, "duree", geste, user, "ai-prolonger")
        nouvelle_fin = maintenant + geste.duree_s
        if nouvelle_fin < ban["fin"]:
            raise _refus(409, "raccourcit", geste, user, "ai-prolonger")
        motif = _plafond_atteint(compteurs, "prolonger")
        if motif:
            raise _refus(409, motif, geste, user, "ai-prolonger")
        try:
            cible = forme_cible(ban["cible"])
        except ValueError:
            raise _refus(500, "journal", geste, user, "ai-prolonger") from None
        try:
            if protegee_par_sade(cible, sade):
                raise _refus(409, "protegee", geste, user, "ai-prolonger")
        except Illisible as e:
            log.warning("ai-prolonger : garde illisible : %s", e)
            raise _refus(503, "etat", geste, user, "ai-prolonger") from None
        try:
            if protegee_d_office(cible):
                raise _refus(409, "protegee", geste, user, "ai-prolonger")
        except ProtectionInconnue as e:
            log.warning("ai-prolonger : cibles protégées inconnues : %s", e)
            raise _refus(409, "protegee_inconnue", geste, user, "ai-prolonger") from None

        ident = secrets.token_hex(16)
        resume = (f"id {ident} ban {geste.id} cible {ban['cible']} {geste.duree_s}s fin {nouvelle_fin} "
                  f"conseil {geste.conseil}")
        try:
            _auditer("ai-prolonger-demande", resume, user)
        except Exception:  # noqa: BLE001 — sans trace de la demande, rien n'est fait
            raise _refus(503, "audit", geste, user, "ai-prolonger") from None
        r, panne = _lancer(_argv("prolonger", cible, geste.duree_s))
        if r is None:
            # Rien à défaire : la cible était déjà bannie par ce ban, la prolonger ou non ne lève rien.
            log.error("ai-prolonger : wafctl injoignable (%s) pour %s", panne, cible)
            raise _refus(503, "wafctl", geste, user, "ai-prolonger")
        if r.returncode != 0:
            raise _refus(*_statut_motif(_motif_sortie(r)), geste, user, "ai-prolonger")
        fin = nouvelle_fin
        if isinstance(cible, ipaddress.IPv4Network):
            # waf-blocs ne raccourcit jamais un bloc : sa fin enregistrée fait foi
            fin = _fin_enregistree(r, int(_maintenant()) + geste.duree_s)
        try:
            _ecrire_journal({"ts": _horodatage(), "at": maintenant, "type": "prolonge", "geste": "prolonger",
                             "id": geste.id, "cible": ban["cible"], "fin": fin, "duree_s": geste.duree_s,
                             "conseil": geste.conseil, "motif": geste.motif, "audit": ident,
                             "jti": str((user or {}).get("jti") or ""), "cle": _cle(user)})
        except OSError:
            # La prolongation est posée (sens sûr : la cible reste bannie plus longtemps) mais hors journal.
            log.error("ai-prolonger : prolongation %s de %s non journalisée", ident, geste.id)
            raise _refus(503, "journal", geste, user, "ai-prolonger") from None
        try:
            _auditer("ai-prolonger", f"id {ident} ban {geste.id} cible {ban['cible']} fin {fin}", user)
        except Exception:  # noqa: BLE001 — la demande est tracée ; la prolongation ne se défait pas (nft)
            raise HTTPException(500, detail={"motif": "audit"}) from None
    return {"id": geste.id, "cible": ban["cible"], "fin": fin, "audit": ident}


def _couverte(cible: Cible, ban: dict, maintenant: int) -> bool:
    """Ruling P12 : une autre source couvre-t-elle désormais la cible ? Lève Illisible."""
    if isinstance(cible, ipaddress.IPv4Network):
        b = _blocs_enregistres().get(str(cible))
        return b is not None and b["fin"] > ban["fin"] + MARGE_BLOC_S
    return adresse_couverte_par_le_waf(str(cible), maintenant)


def _clore(ident: str, ban: dict, maintenant: int, cause: str) -> None:
    """Ligne `annule` au journal ; 503 `journal` si elle ne peut pas être écrite."""
    try:
        _ecrire_journal({"ts": _horodatage(), "at": maintenant, "type": "annule", "geste": "unban", "id": ident,
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
        limite = ban["type"] in GESTES_SANS_BAN
        try:
            cible = forme_limite(ban["cible"]) if limite else forme_cible(ban["cible"])
        except ValueError:
            raise HTTPException(500, detail={"motif": "journal"}) from None
        try:
            # une limite, un leurre ne sont couverts par personne : les lever ne libère jamais une cible bannie
            couverte = False if limite else _couverte(cible, ban, maintenant)
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
        r, _ = _lancer(_argv(GESTES_SANS_BAN[ban["type"]][1] if limite else "unban", cible))
        if r is None or r.returncode != 0:
            statut, motif = (503, "wafctl") if r is None else _statut_motif(_motif_sortie(r))
            _auditer_sans_lever("ai-unban-echec", f"id {geste.id} cible {ban['cible']} motif {motif}", user)
            raise HTTPException(statut, detail={"motif": motif})
        # le ban est levé et audité ; si la ligne manque, un nouvel essai refera un retrait idempotent puis la ligne
        _clore(geste.id, ban, maintenant, "unban")
    return {"id": geste.id, "etat": "annule"}


def _fin_limite(r: subprocess.CompletedProcess, repli: int) -> int:
    """La `fin` de la ligne JSON `{"fin": …}` de `wafctl limiter` ; `repli` si elle manque ou est illisible."""
    for ligne in (r.stdout or "").splitlines():
        try:
            d = json.loads(ligne)
        except ValueError:
            continue
        if isinstance(d, dict) and _entier(d.get("fin")) and d["fin"] > 0:
            return d["fin"]
    return repli


@router.post("/limiter")
def ai_limiter(user: dict = Depends(require_ai_ban), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    """Limite de débit d'une adresse publique, IPv4 ou IPv6 (#3723). Geste d'office : la porte du mode SADE passe
    d'abord (`limiter` est le seul geste d'office admis en `reactive`)."""
    geste: GesteLimiter = _valider(GesteLimiter, corps)
    cible = forme_limite(geste.cible)
    sade = lire_sade()
    motif = porte_sade("limiter", sade)
    if motif:
        raise _refus(409, motif, geste, user, "ai-limiter")
    with _verrou:
        maintenant = int(_maintenant())
        try:
            bans, annules, _, compteurs = _bilan(_lire_journal(), maintenant)
        except OSError:
            raise _refus(503, "journal", geste, user, "ai-limiter") from None
        if geste.cible in {b["cible"] for b in limites_actives(bans, annules, maintenant)}:
            raise _refus(409, "deja_actif", geste, user, "ai-limiter")
        if not LIMITE_MIN_S <= geste.duree_s <= LIMITE_MAX_S:
            raise _refus(409, "duree", geste, user, "ai-limiter")
        motif = _plafond_atteint(compteurs, "limiter")
        if motif:
            raise _refus(409, motif, geste, user, "ai-limiter")
        try:
            if protegee_par_sade(cible, sade):
                raise _refus(409, "protegee", geste, user, "ai-limiter")
        except Illisible as e:
            log.warning("ai-limiter : garde illisible : %s", e)
            raise _refus(503, "etat", geste, user, "ai-limiter") from None
        try:
            if protegee_d_office(cible):
                raise _refus(409, "protegee", geste, user, "ai-limiter")
        except ProtectionInconnue as e:
            log.warning("ai-limiter : cibles protégées inconnues : %s", e)
            raise _refus(409, "protegee_inconnue", geste, user, "ai-limiter") from None

        ident = secrets.token_hex(16)
        fin = maintenant + geste.duree_s
        resume = f"id {ident} cible {geste.cible} {geste.duree_s}s fin {fin} conseil {geste.conseil}"
        try:
            _auditer("ai-limiter-demande", resume, user)
        except Exception:  # noqa: BLE001 — sans trace de la demande, rien n'est fait
            raise _refus(503, "audit", geste, user, "ai-limiter") from None
        r, panne = _lancer(_argv("limiter", cible, geste.duree_s))
        if r is None:
            # wafctl muet : la limite est peut-être posée ; aucune autre source ne limite par ces ensembles
            log.error("ai-limiter : wafctl injoignable (%s) pour %s", panne, cible)
            _defaire_limite(cible)
            raise _refus(503, "wafctl", geste, user, "ai-limiter")
        if r.returncode != 0:
            raise _refus(*_statut_motif(_motif_sortie(r)), geste, user, "ai-limiter")
        fin = _fin_limite(r, int(_maintenant()) + geste.duree_s)
        entree = {"ts": _horodatage(), "at": maintenant, "type": "limite", "geste": "limiter", "id": ident,
                  "cible": geste.cible, "fin": fin, "mode": "auto", "conseil": geste.conseil, "motif": geste.motif,
                  "jti": str((user or {}).get("jti") or ""), "cle": _cle(user), "duree_s": geste.duree_s}
        try:
            _ecrire_journal(entree)
        except OSError:
            # hors journal, la limite échapperait aux plafonds et ne pourrait pas être levée par son id
            if _defaire_limite(cible):
                raise _refus(503, "journal", geste, user, "ai-limiter") from None
            raise _refus(500, "incoherent", geste, user, "ai-limiter") from None
        try:
            _auditer("ai-limiter", f"id {ident} cible {geste.cible} {geste.duree_s}s fin {fin} conseil {geste.conseil}",
                     user)
        except Exception:  # noqa: BLE001 — une limite non auditée n'existe pas : elle est levée
            defaite = _defaire_limite(cible)
            try:
                _ecrire_journal({"ts": _horodatage(), "at": maintenant, "type": "annule", "geste": "limiter",
                                 "id": ident, "cible": geste.cible, "cause": "audit"})
            except OSError:
                log.error("ai-limiter : annulation %s non journalisée", ident)
            raise HTTPException(500, detail={"motif": "audit" if defaite else "incoherent"}) from None
    return {"id": ident, "cible": geste.cible, "fin": fin, "audit": ident}


def _defaire_limite(cible: Any) -> bool:
    r, _ = _lancer(_argv("limiter-lever", cible))
    if r is None or r.returncode != 0:
        log.error("ai-limiter : retour arrière impossible pour %s", cible)
        return False
    return True


def _cible_bannie(cible: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], actifs: List[dict]) -> bool:
    """La cible est-elle déjà bannie : ban ai-ban actif (adresse, ou bloc qui la couvre), bloc de waf-blocs, ou
    ensemble `waf_ban` / `waf_ban6` du WAF ? Lève Illisible (jamais « libre » par défaut)."""
    for b in actifs:
        try:
            reseau = ipaddress.ip_network(b["cible"])
        except ValueError:
            continue
        if reseau.version == cible.version and cible in reseau:
            return True
    if isinstance(cible, ipaddress.IPv6Address):
        return str(cible) in {str(ipaddress.ip_address(a)) for a in lire_waf_ban("waf_ban6") if _ip_lisible(a)}
    if str(cible) in {b.get("ip") for b in _bans_waf()}:
        return True
    return any(b["reste"] > 0 and cible in ipaddress.IPv4Network(bloc, strict=False)
               for bloc, b in _blocs_enregistres().items() if _reseau_lisible(bloc))


def _ip_lisible(a: str) -> bool:
    try:
        ipaddress.ip_address(a)
        return True
    except ValueError:
        return False


def _reseau_lisible(bloc: str) -> bool:
    try:
        ipaddress.IPv4Network(bloc, strict=False)
        return True
    except ValueError:
        return False


@router.post("/leurre")
def ai_leurre(user: dict = Depends(require_ai_ban), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    """Redirige une adresse publique, IPv4 ou IPv6, vers le théâtre de sbxwaf (#3723). Geste d'office : la porte du
    mode SADE passe d'abord (refusé en `observe` et en `reactive`). Une cible déjà bannie est refusée (`deja_banni`) :
    un attaquant banni n'atteint pas le leurre, et ce geste ne lève jamais un ban."""
    geste: GesteLeurre = _valider(GesteLeurre, corps)
    cible = forme_limite(geste.cible)
    sade = lire_sade()
    motif = porte_sade("leurre", sade)
    if motif:
        raise _refus(409, motif, geste, user, "ai-leurre")
    with _verrou:
        maintenant = int(_maintenant())
        try:
            bans, annules, actifs, compteurs = _bilan(_lire_journal(), maintenant)
        except OSError:
            raise _refus(503, "journal", geste, user, "ai-leurre") from None
        if geste.cible in {b["cible"] for b in limites_actives(bans, annules, maintenant, "leurre")}:
            raise _refus(409, "deja_actif", geste, user, "ai-leurre")
        if not LEURRE_MIN_S <= geste.duree_s <= LEURRE_MAX_S:
            raise _refus(409, "duree", geste, user, "ai-leurre")
        motif = _plafond_atteint(compteurs, "leurre")
        if motif:
            raise _refus(409, motif, geste, user, "ai-leurre")
        try:
            if protegee_par_sade(cible, sade):
                raise _refus(409, "protegee", geste, user, "ai-leurre")
        except Illisible as e:
            log.warning("ai-leurre : garde illisible : %s", e)
            raise _refus(503, "etat", geste, user, "ai-leurre") from None
        try:
            if protegee_d_office(cible):
                raise _refus(409, "protegee", geste, user, "ai-leurre")
        except ProtectionInconnue as e:
            log.warning("ai-leurre : cibles protégées inconnues : %s", e)
            raise _refus(409, "protegee_inconnue", geste, user, "ai-leurre") from None
        try:
            bannie = _cible_bannie(cible, actifs)
        except Exception as e:  # noqa: BLE001 — sans savoir si la cible est bannie, rien n'est posé
            log.warning("ai-leurre : état des bans illisible : %s", e)
            raise _refus(503, "etat", geste, user, "ai-leurre") from None
        if bannie:
            raise _refus(409, "deja_banni", geste, user, "ai-leurre")

        ident = secrets.token_hex(16)
        fin = maintenant + geste.duree_s
        resume = f"id {ident} cible {geste.cible} {geste.duree_s}s fin {fin} conseil {geste.conseil}"
        try:
            _auditer("ai-leurre-demande", resume, user)
        except Exception:  # noqa: BLE001 — sans trace de la demande, rien n'est fait
            raise _refus(503, "audit", geste, user, "ai-leurre") from None
        r, panne = _lancer(_argv("leurre", cible, geste.duree_s))
        if r is None:
            # wafctl muet : l'entrée est peut-être écrite ; aucune autre source n'écrit cette liste
            log.error("ai-leurre : wafctl injoignable (%s) pour %s", panne, cible)
            _defaire_leurre(cible)
            raise _refus(503, "wafctl", geste, user, "ai-leurre")
        if r.returncode != 0:
            raise _refus(*_statut_motif(_motif_sortie(r)), geste, user, "ai-leurre")
        fin = _fin_limite(r, int(_maintenant()) + geste.duree_s)
        entree = {"ts": _horodatage(), "at": maintenant, "type": "leurre", "geste": "leurre", "id": ident,
                  "cible": geste.cible, "fin": fin, "mode": "auto", "conseil": geste.conseil, "motif": geste.motif,
                  "jti": str((user or {}).get("jti") or ""), "cle": _cle(user), "duree_s": geste.duree_s}
        try:
            _ecrire_journal(entree)
        except OSError:
            # hors journal, le leurre échapperait aux plafonds et ne pourrait pas être levé par son id
            if _defaire_leurre(cible):
                raise _refus(503, "journal", geste, user, "ai-leurre") from None
            raise _refus(500, "incoherent", geste, user, "ai-leurre") from None
        try:
            _auditer("ai-leurre", f"id {ident} cible {geste.cible} {geste.duree_s}s fin {fin} conseil {geste.conseil}",
                     user)
        except Exception:  # noqa: BLE001 — un leurre non audité n'existe pas : il est levé
            defait = _defaire_leurre(cible)
            try:
                _ecrire_journal({"ts": _horodatage(), "at": maintenant, "type": "annule", "geste": "leurre",
                                 "id": ident, "cible": geste.cible, "cause": "audit"})
            except OSError:
                log.error("ai-leurre : annulation %s non journalisée", ident)
            raise HTTPException(500, detail={"motif": "audit" if defait else "incoherent"}) from None
    return {"id": ident, "cible": geste.cible, "fin": fin, "audit": ident}


def _defaire_leurre(cible: Any) -> bool:
    r, _ = _lancer(_argv("leurre-lever", cible))
    if r is None or r.returncode != 0:
        log.error("ai-leurre : retour arrière impossible pour %s", cible)
        return False
    return True


_garde_ai_lecture = garde_compte_service("ai-lecture")


async def require_ai_etat(request: Request, creds=Depends(_auth._bearer)) -> Dict[str, Any]:
    """#3720 : `/ai/etat` en lecture pour `ai-ban` OU `ai-lecture` (jeton lié à GET et au chemin). Aiguillage par le
    `kid` NON vérifié : une clé du dossier `ai-lecture` ⇒ vérifiée comme `ai-lecture`, sinon comme `ai-ban` ; la
    garde choisie vérifie tout (signature, portée, jti) : l'aiguillage ne donne aucun droit."""
    jeton = creds.credentials if creds is not None and creds.credentials else ""
    kid = None
    if jeton:
        try:
            entete = jwt.get_unverified_header(jeton)
            kid = entete.get("kid") if isinstance(entete, dict) else None
        except Exception:  # noqa: BLE001 — illisible : la garde ai-ban le refusera
            kid = None
    if isinstance(kid, str) and kid in await run_in_threadpool(cles_publiques, "ai-lecture"):
        return await _garde_ai_lecture(request, creds)
    return await require_ai_ban(request, creds)


async def _corps_etat(request: Request, _user: dict = Depends(require_ai_etat)) -> bytes:
    corps = await request.body()
    if len(corps) > TAILLE_MAX_CORPS:
        raise HTTPException(413, detail={"motif": "corps_trop_grand"})
    return corps


@router.get("/etat")
def ai_etat(user: dict = Depends(require_ai_etat), corps: bytes = Depends(_corps_etat)) -> Dict[str, Any]:
    _ = user
    if corps:
        raise HTTPException(422, detail={"motif": "corps"})   # P9 : un jeton de geste ne vaut rien ici
    maintenant = int(_maintenant())
    try:
        bans, annules, actifs, compteurs = _bilan(_lire_journal(), maintenant)
    except OSError:
        raise HTTPException(503, detail={"motif": "journal"}) from None
    return {"actifs": [{"id": b["id"], "cible": b["cible"], "fin": b["fin"], "mode": b["mode"]}
                       for b in sorted(actifs, key=lambda b: (b["fin"], b["id"]))],
            "compteurs": {k: compteurs[k] for k in PLAFONDS}, "plafonds": dict(PLAFONDS),
            "plafonds_par_geste": plafonds_par_geste(compteurs), "sade_mode": mode_sade(),
            "limites": [{"id": b["id"], "cible": b["cible"], "fin": b["fin"]}
                        for b in sorted(limites_actives(bans, annules, maintenant), key=lambda b: (b["fin"], b["id"]))],
            "leurres": [{"id": b["id"], "cible": b["cible"], "fin": b["fin"]}
                        for b in sorted(limites_actives(bans, annules, maintenant, "leurre"),
                                        key=lambda b: (b["fin"], b["id"]))]}
