#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: verifie-relais-hall
CyberMind — https://cybermind.fr

Le gabarit des relais du Hall, vérifié plutôt que recommandé (#1609, #1608).

Le Hall (hall.<domaine>) porte la clé de l'appareil, et ses `location` qui
mandatent (`proxy_pass`) exposent des API de modules sur cette origine. Une
règle tenue à la main diverge : ce script lit packages/secubox-webos/nginx/
hall.vhost.conf et échoue (code 1), location par location, dès qu'un relais
s'écarte du gabarit.

  A. VERDICT LAN. Tout relais pose lui-même `X-SecuBox-LAN $lan_client`
     (ou le vide). nginx n'hérite d'AUCUN `proxy_set_header` du niveau
     serveur dès qu'un location en pose un seul : l'héritage ne compte que
     pour un location qui n'en pose aucun.

  B. EN-TÊTES DE CONFIANCE. Ce qu'un module tient pour acquis ne vient jamais
     du client : l'adresse d'origine (X-Real-IP, X-Forwarded-For = l'adresse
     résolue par real_ip), et les en-têtes d'identité propres à chaque module
     (table ENTETES_DE_CONFIANCE, relevée dans le dépôt).

  C. RELAIS DE LECTURE. Un location marqué `# relais: lecture` (commentaire
     DANS le bloc) est exact (`=`) ou une expression ancrée `^…$` sans joker
     ouvert, porte `limit_except GET { deny all; }` et `X-Real-IP
     $remote_addr`.

  D. DÉCISIONS DU HALL. Verrou LAN des modules à usage local, session exigée
     pour la vue des acteurs, chemins qui ne sont relayés par aucun location,
     et repli `location /api/ { return 404; }` pour tout ce qui n'est pas
     relayé.

Usage :
    python3 scripts/verifie-relais-hall.py            # le vhost du dépôt
    python3 scripts/verifie-relais-hall.py --resume   # + un relais par ligne
    python3 scripts/verifie-relais-hall.py --syntaxe  # + `nginx -t` isolé
    python3 scripts/verifie-relais-hall.py --vhost autre.conf

Codes de sortie : 0 conforme, 1 écart(s) au gabarit, 2 fichier illisible ou
syntaxe nginx refusée.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

RACINE_DEPOT = Path(__file__).resolve().parents[1]
VHOST_HALL = Path("packages/secubox-webos/nginx/hall.vhost.conf")

# Les snippets que le vérificateur sait relire dans le dépôt. Un `include`
# absent de cette table ne compte pour AUCUN en-tête : on ne tient pas pour
# posé ce qu'on ne peut pas lire.
SNIPPETS_DU_DEPOT: Dict[str, str] = {
    "/etc/nginx/snippets/secubox-proxy.conf": "common/nginx/secubox-proxy.conf",
}

# ── A + B : ce que TOUT relais du Hall réécrit ──────────────────────────────
#
# Le verdict LAN est lu par secubox_core.auth.require_lecture ; l'adresse
# d'origine par la journalisation de connexion de secubox_core, par
# l'accès (cadence par adresse), par la messagerie (plafond des visiteurs) et,
# via webos, par le dépôt. Le Hall étant le dernier mandataire, l'adresse
# résolue par real_ip est la seule valeur juste. La chaîne vide est admise :
# elle retire l'en-tête, ce qui ferme aussi.
ENTETES_TOUJOURS: Dict[str, Set[str]] = {
    "X-SecuBox-LAN": {"$lan_client", ""},
    "X-Real-IP": {"$remote_addr", ""},
    "X-Forwarded-For": {"$remote_addr", ""},
}

# Valeur admise : toute valeur que le client ne choisit pas — chaîne vide,
# littéral, ou variable serveur (y compris posée par auth_request_set).
NON_CLIENT = "non-client"

ValeursAdmises = Union[Set[str], str]

# ── B : en-têtes d'identité, par module ─────────────────────────────────────
#
# Relevés dans le dépôt (lectures d'en-têtes de requête qui décident d'une
# identité ou d'une vue). Un module absent d'ici ne lit que ENTETES_TOUJOURS.
#   radio      secubox-radio/cmd/secubox-radiod/main.go (X-Sbx-User*, X-Sbx-Role)
#   actor      contrat sbx-actord #1608 : la vue réduite est celle du Hall
#   peertube   greffon secubox-sso (X-Sbx-Peertube-User)
#   nextcloud  vhost nextcloud, entrée /sbx/entrer (X-Sbx-Nextcloud-User)
#   bbs        secubox-bbs/internal/web/sbx_entree.go
#   annuaire   secubox-annuaire/api/main.py (X-SecuBox-Maillage)
#   acces      secubox-sbxid/acces/api/main.py (racine, hôte)
#   profiles   secubox-profiles/api/waker.py (X-SecuBox-Origin-Status)
# X-Sbx-Radio, X-Sbx-Messagerie et X-Sbx-Member n'y figurent pas, et c'est
# voulu : ce sont des marques d'intention ou des jetons que le module vérifie
# lui-même — le client DOIT pouvoir les envoyer.
ENTETES_DE_CONFIANCE: Dict[str, Dict[str, ValeursAdmises]] = {
    "radio": {"X-Sbx-User-Id": NON_CLIENT, "X-Sbx-User": NON_CLIENT,
              "X-Sbx-Role": NON_CLIENT},
    "actor": {"X-Sbx-Vue": {"reduite"}},
    "peertube": {"X-Sbx-Peertube-User": NON_CLIENT},
    "nextcloud": {"X-Sbx-Nextcloud-User": NON_CLIENT},
    "bbs": {"X-Sbx-Membre": NON_CLIENT, "X-Sbx-Compte-Bbs": NON_CLIENT,
            "X-Sbx-Profil": NON_CLIENT},
    "annuaire": {"X-SecuBox-Maillage": {""}},
    "acces": {"X-Acces-Racine": NON_CLIENT, "X-Forwarded-Host": NON_CLIENT},
    "profiles": {"X-SecuBox-Origin-Status": NON_CLIENT},
}

# Variables dont le client choisit la valeur. `$host` n'y est pas : sur ce
# vhost, il vaut l'un des `server_name`.
_VARIABLE_CLIENT = re.compile(
    r"\$\{?(http_\w+|cookie_\w+|arg_\w+|args|query_string|request_uri|uri|"
    r"document_uri|request|request_body|is_args|proxy_add_x_forwarded_for)\b")

# Adresses d'amont nommées (proxy_pass vers une adresse IP).
AMONTS_NOMMES: Dict[str, str] = {
    "10.100.0.180:8091": "ytsas",
}

# ── D : décisions du Hall ───────────────────────────────────────────────────
#
# Usage local : chaque relais vers ces modules (ou sous ces chemins) porte
# `if ($lan_client = 0) { return 403; }`.
VERROU_LAN_MODULES: Set[str] = {"zigbee", "freeboxtv", "lyrion"}
VERROU_LAN_CHEMINS: Tuple[str, ...] = ("/api/v1/acces/file", "/api/v1/sbxid/admin/")

# Vue des acteurs : session vérifiée par l'agrégateur, sauf le tableau agrégé.
SESSION_MODULES: Dict[str, Set[str]] = {"actor": {"/api/v1/actor/stats"}}
VERIFICATION_SESSION = "aggregator.sock:/api/v1/auth/auth/verify"

# Chemins qu'AUCUN relais du Hall ne doit servir : ils restent sur le vhost
# d'administration (ou n'ont pas de vue réduite).
JAMAIS_RELAYES: Tuple[Tuple[str, str], ...] = (
    ("/api/v1/actor/evidence/ACT-0001", "les preuves restent sur le vhost d'administration"),
    ("/api/v1/actor/feedback/ACT-0001", "les retours d'analyste restent sur le vhost d'administration"),
    ("/api/v1/zigbee/backups", "sauvegardes Zigbee : vhost d'administration"),
    ("/api/v1/zigbee/backup", "sauvegardes Zigbee : vhost d'administration"),
    ("/api/v1/zigbee/restore", "sauvegardes Zigbee : vhost d'administration"),
    ("/api/v1/zigbee/access", "accès Zigbee : vhost d'administration"),
    ("/api/v1/zigbee/components", "la carte Zigbee ne lit que /devices"),
    ("/api/v1/zigbee/status", "la carte Zigbee ne lit que /devices"),
    ("/api/v1/lyrion/rescan", "maintenance Lyrion : vhost d'administration"),
    ("/api/v1/lyrion/upgrade", "maintenance Lyrion : vhost d'administration"),
    ("/api/v1/lyrion/medialib/mount", "maintenance Lyrion : vhost d'administration"),
    ("/api/v1/acces/profils/promouvoir", "gouvernance des profils : vhost d'administration (#1366)"),
    ("/api/v1/p2p/mesh", "pas de relais brut du maillage : vue réduite par sbxid"),
)

MARQUEUR = re.compile(r"^#\s*relais\s*:\s*(\S+)")
MARQUEURS_CONNUS = {"lecture"}


# ═══════════════════════════════════════════════════════════════════════════
# Lecture de la configuration nginx
# ═══════════════════════════════════════════════════════════════════════════

class ErreurAnalyse(Exception):
    """Le fichier ne se lit pas comme une configuration nginx."""


@dataclass
class Jeton:
    genre: str          # "mot", "{", "}", ";", "commentaire"
    valeur: str
    ligne: int


@dataclass
class Directive:
    nom: str
    args: List[str]
    ligne: int
    bloc: Optional[List["Directive"]] = None
    commentaires: List[Tuple[int, str]] = field(default_factory=list)

    def enfants(self, nom: str) -> Iterator["Directive"]:
        for d in self.bloc or []:
            if d.nom == nom:
                yield d


def jetons(texte: str) -> Iterator[Jeton]:
    """Découpe à la manière de nginx : mots, guillemets, `{ } ;`, commentaires.

    Un `#` ne commence un commentaire qu'en début de mot ; entre guillemets,
    `{`, `}`, `;` et `#` sont du texte. `${var}` reste un seul mot.
    """
    i, n, ligne = 0, len(texte), 1
    while i < n:
        c = texte[i]
        if c == "\n":
            ligne += 1
            i += 1
            continue
        if c in " \t\r":
            i += 1
            continue
        if c == "#":
            fin = texte.find("\n", i)
            fin = n if fin < 0 else fin
            yield Jeton("commentaire", texte[i:fin].rstrip(), ligne)
            i = fin
            continue
        if c in "{};":
            yield Jeton(c, c, ligne)
            i += 1
            continue
        if c in "\"'":
            debut, j, morceaux = ligne, i + 1, []
            while j < n and texte[j] != c:
                if texte[j] == "\\" and j + 1 < n:
                    morceaux.append(texte[j + 1])
                    j += 2
                    continue
                if texte[j] == "\n":
                    ligne += 1
                morceaux.append(texte[j])
                j += 1
            if j >= n:
                raise ErreurAnalyse(f"ligne {debut} : guillemet {c} jamais refermé")
            yield Jeton("mot", "".join(morceaux), debut)
            i = j + 1
            continue
        j, morceaux, dans_variable = i, [], False
        while j < n:
            d = texte[j]
            if d in " \t\r\n;":
                break
            if d == "{":
                if not (morceaux and morceaux[-1] == "$"):
                    break
                dans_variable = True
            elif d == "}":
                if not dans_variable:
                    break
                dans_variable = False
            if d == "\\" and j + 1 < n:
                morceaux.append(texte[j:j + 2])
                j += 2
                continue
            morceaux.append(d)
            j += 1
        yield Jeton("mot", "".join(morceaux), ligne)
        i = j


def analyse_texte(texte: str) -> List[Directive]:
    """Arbre des directives. Les commentaires d'un bloc sont rangés sur lui."""
    racine = Directive("<fichier>", [], 0, bloc=[])
    pile: List[Directive] = [racine]
    courant: List[Jeton] = []
    for j in jetons(texte):
        if j.genre == "commentaire":
            pile[-1].commentaires.append((j.ligne, j.valeur))
            continue
        if j.genre == "mot":
            courant.append(j)
            continue
        if j.genre == ";":
            if not courant:
                raise ErreurAnalyse(f"ligne {j.ligne} : `;` sans directive")
            pile[-1].bloc.append(Directive(courant[0].valeur,
                                           [m.valeur for m in courant[1:]],
                                           courant[0].ligne))
            courant = []
            continue
        if j.genre == "{":
            if not courant:
                raise ErreurAnalyse(f"ligne {j.ligne} : `{{` sans directive")
            d = Directive(courant[0].valeur, [m.valeur for m in courant[1:]],
                          courant[0].ligne, bloc=[])
            pile[-1].bloc.append(d)
            pile.append(d)
            courant = []
            continue
        # "}"
        if courant:
            raise ErreurAnalyse(f"ligne {courant[0].ligne} : directive « "
                                f"{courant[0].valeur} » sans `;` avant `}}`")
        if len(pile) == 1:
            raise ErreurAnalyse(f"ligne {j.ligne} : `}}` sans bloc ouvert")
        pile.pop()
    if courant:
        raise ErreurAnalyse(f"ligne {courant[0].ligne} : directive « "
                            f"{courant[0].valeur} » non terminée")
    if len(pile) > 1:
        raise ErreurAnalyse(f"ligne {pile[-1].ligne} : bloc « {pile[-1].nom} » "
                            "jamais refermé")
    return racine.bloc


# ═══════════════════════════════════════════════════════════════════════════
# Relais : ce que chaque location mandate, et avec quels en-têtes
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Relais:
    location: Directive
    serveur: Directive
    proxy_pass: str
    entetes: Dict[str, Tuple[str, str]]     # minuscule -> (nom, valeur)
    marqueurs: List[Tuple[int, str]]
    inclusions_ignorees: List[str]

    @property
    def modificateur(self) -> str:
        return self.location.args[0] if len(self.location.args) > 1 else ""

    @property
    def motif(self) -> str:
        return self.location.args[-1] if self.location.args else ""

    @property
    def lecture(self) -> bool:
        return any(m == "lecture" for _, m in self.marqueurs)

    @property
    def interne(self) -> bool:
        return any(True for _ in self.location.enfants("internal"))

    def libelle(self) -> str:
        return "location " + " ".join(self.location.args)

    def entete(self, nom: str) -> Optional[str]:
        e = self.entetes.get(nom.lower())
        return None if e is None else e[1]


def _developpe(bloc: Iterable[Directive], racine: Path,
               ignorees: List[str]) -> List[Directive]:
    """Remplace les `include` connus par le contenu du snippet du dépôt."""
    sortie: List[Directive] = []
    for d in bloc:
        if d.nom == "include" and d.args:
            relatif = SNIPPETS_DU_DEPOT.get(d.args[0])
            source = (racine / relatif) if relatif else None
            if source is not None and source.is_file():
                sortie.extend(_developpe(analyse_texte(source.read_text(encoding="utf-8")),
                                         racine, ignorees))
            else:
                ignorees.append(d.args[0])
            continue
        sortie.append(d)
    return sortie


def _entetes_poses(bloc: Iterable[Directive]) -> Dict[str, Tuple[str, str]]:
    poses: Dict[str, Tuple[str, str]] = {}
    for d in bloc:
        if d.nom == "proxy_set_header" and len(d.args) >= 2:
            poses[d.args[0].lower()] = (d.args[0], d.args[1])
    return poses


def _proxy_pass(bloc: Iterable[Directive]) -> Optional[str]:
    """Le `proxy_pass` du location, y compris dans ses `if` / `limit_except`
    (mais pas dans un location imbriqué, qui est un relais à part)."""
    for d in bloc:
        if d.nom == "proxy_pass" and d.args:
            return d.args[0]
        if d.nom in ("if", "limit_except") and d.bloc:
            trouve = _proxy_pass(d.bloc)
            if trouve:
                return trouve
    return None


def relais_du_fichier(arbre: List[Directive], racine: Path) -> List[Relais]:
    """Tous les locations qui mandatent, avec leurs en-têtes EFFECTIFS."""
    resultat: List[Relais] = []

    def parcourt(bloc: List[Directive], serveur: Directive,
                 herites: Dict[str, Tuple[str, str]]) -> None:
        for d in bloc:
            if d.nom != "location" or d.bloc is None:
                continue
            ignorees: List[str] = []
            propre = _developpe(d.bloc, racine, ignorees)
            poses = _entetes_poses(propre)
            # La règle de nginx : un seul proxy_set_header au niveau du
            # location, et plus rien n'est hérité.
            effectifs = poses if poses else dict(herites)
            pp = _proxy_pass(propre)
            if pp:
                marqueurs = []
                for ligne, texte in d.commentaires:
                    m = MARQUEUR.match(texte)
                    if m:
                        marqueurs.append((ligne, m.group(1).lower()))
                resultat.append(Relais(d, serveur, pp, effectifs, marqueurs, ignorees))
            parcourt(d.bloc, serveur, effectifs)

    def serveurs(bloc: List[Directive]) -> Iterator[Directive]:
        for d in bloc:
            if d.nom == "server" and d.bloc is not None:
                yield d
            elif d.nom == "http" and d.bloc is not None:
                yield from serveurs(d.bloc)

    for s in serveurs(arbre):
        ignorees: List[str] = []
        niveau_serveur = _entetes_poses(_developpe(
            [x for x in s.bloc if x.nom != "location"], racine, ignorees))
        parcourt(s.bloc, s, niveau_serveur)
    return resultat


# ═══════════════════════════════════════════════════════════════════════════
# Règles
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Constat:
    regle: str
    ligne: int
    location: str
    message: str


def prefixe_litteral(relais: Relais) -> str:
    """La partie fixe du chemin : le chemin lui-même, ou le début d'une regex
    jusqu'au premier métacaractère."""
    motif = relais.motif
    if relais.modificateur not in ("~", "~*"):
        return motif
    motif = motif[1:] if motif.startswith("^") else motif
    sortie = []
    for c in motif:
        if c in ".[](){}*+?|\\$^":
            break
        sortie.append(c)
    return "".join(sortie)


def module_de(relais: Relais) -> str:
    """Le module servi, déduit de la cible du `proxy_pass`."""
    pp = relais.proxy_pass
    m = re.match(r"^https?://unix:/run/secubox/([^:/]+)\.sock(?::(.*))?$", pp)
    if m:
        sock, uri = m.group(1), m.group(2) or ""
        if sock != "aggregator":
            return sock
        chemin = uri if uri.startswith("/api/v1/") else prefixe_litteral(relais)
        mm = re.match(r"^/api/v1/([A-Za-z0-9_-]+)", chemin)
        return mm.group(1) if mm else "aggregator"
    m = re.match(r"^https?://([^/:]+(?::\d+)?)", pp)
    if not m:
        return "inconnu"
    amont = m.group(1)
    if amont in AMONTS_NOMMES:
        return AMONTS_NOMMES[amont]
    if amont == "nginx_local":
        hote = (relais.entete("Host") or "").split(".")[0]
        return hote or "nginx_local"
    return "amont:" + amont


def vient_du_client(valeur: str) -> bool:
    return bool(_VARIABLE_CLIENT.search(valeur))


def _valeur_admise(valeur: str, admises: ValeursAdmises) -> bool:
    if admises == NON_CLIENT:
        return not vient_du_client(valeur)
    return valeur in admises


def _decrit(admises: ValeursAdmises) -> str:
    if admises == NON_CLIENT:
        return 'une valeur posée par le relais, par exemple ""'
    return " ou ".join(f'"{v}"' if v == "" else v for v in sorted(admises))


def correspond(relais: Relais, uri: str) -> bool:
    """Le location prendrait-il cette URI ? (sans la priorité entre blocs)"""
    mod, motif = relais.modificateur, relais.motif
    if mod == "=":
        return uri == motif
    if mod in ("~", "~*"):
        try:
            return re.search(motif, uri, re.IGNORECASE if mod == "~*" else 0) is not None
        except re.error:
            return False
    if mod == "@":
        return False
    return uri.startswith(motif)


def _regex_ancree(motif: str) -> bool:
    if not motif.startswith("^") or not motif.endswith("$") or motif.endswith("\\$"):
        return False
    # Un joker qui traverse les segments (`.*`, `.+`) ouvre un préfixe déguisé.
    return re.search(r"(?<!\\)\.[*+]", motif) is None


def _verrou_lan(relais: Relais) -> bool:
    for d in relais.location.enfants("if"):
        cond = re.sub(r"\s+", " ", " ".join(d.args)).strip()
        if re.fullmatch(r"\( ?\$lan_client (= 0|!= 1) ?\)", cond):
            if any(r.nom == "return" and r.args[:1] == ["403"] for r in d.bloc or []):
                return True
    return False


def _verifications_session(relais_tous: List[Relais]) -> Set[str]:
    """Les URI des locations internes qui vérifient la session à l'agrégateur."""
    return {r.motif for r in relais_tous
            if r.interne and r.modificateur == "=" and VERIFICATION_SESSION in r.proxy_pass}


def _proxy_pass_avec_uri(cible: str) -> bool:
    """Vrai si la cible du `proxy_pass` porte sa propre URI : nginx remplace
    alors la partie qui correspond au location par l'URI normalisée."""
    if cible.startswith("http://unix:") or cible.startswith("https://unix:"):
        reste = cible.split("unix:", 1)[1]
        return ":" in reste
    reste = cible.split("://", 1)[-1]
    return "/" in reste


def _reecrit_en_break(relais: "Relais") -> bool:
    """Un `rewrite … break;` au niveau du location (ou dans un `if`)."""
    def cherche(bloc) -> bool:
        for d in bloc or []:
            if d.nom == "rewrite" and d.args and d.args[-1] == "break":
                return True
            if d.nom == "if" and cherche(d.bloc):
                return True
        return False
    return cherche(relais.location.bloc)


def verifie(relais_tous: List[Relais]) -> List[Constat]:
    constats: List[Constat] = []
    verifs = _verifications_session(relais_tous)

    for r in relais_tous:
        def note(regle: str, message: str) -> None:
            constats.append(Constat(regle, r.location.ligne, r.libelle(), message))

        module = module_de(r)

        # ── A et B : en-têtes réécrits par TOUT relais ──────────────────────
        for nom, admises in ENTETES_TOUJOURS.items():
            regle = "A" if nom == "X-SecuBox-LAN" else "B"
            valeur = r.entete(nom)
            if valeur is None:
                if nom == "X-SecuBox-LAN":
                    note(regle, "X-SecuBox-LAN n'est pas posé par ce relais : écrire "
                                "`proxy_set_header X-SecuBox-LAN $lan_client;` DANS le "
                                "location (aucun proxy_set_header du serveur n'est hérité "
                                "dès que le location en pose un).")
                else:
                    note(regle, f"{nom} n'est pas posé par ce relais : écrire "
                                f"`proxy_set_header {nom} $remote_addr;`.")
            elif not _valeur_admise(valeur, admises):
                note(regle, f"{nom} vaut « {valeur} » ; attendu : {_decrit(admises)}.")
        if r.inclusions_ignorees:
            note("A", "include non relu par le vérificateur ("
                      + ", ".join(r.inclusions_ignorees) + ") : ses en-têtes ne "
                      "comptent pas, les écrire dans le location.")

        # ── B : en-têtes d'identité propres au module ───────────────────────
        for nom, admises in ENTETES_DE_CONFIANCE.get(module, {}).items():
            valeur = r.entete(nom)
            if valeur is None:
                note("B", f"le module « {module} » lit {nom} : le relais doit le poser "
                          f"lui-même — {_decrit(admises)} — sinon la valeur du client "
                          "passe telle quelle.")
            elif not _valeur_admise(valeur, admises):
                note("B", f"{nom} vaut « {valeur} » pour le module « {module} » ; "
                          f"attendu : {_decrit(admises)}.")

        # ── U : l'amont reçoit l'URI normalisée, jamais l'URI brute ─────────
        # Sans URI dans le proxy_pass ni `rewrite … break`, nginx transmet la
        # requête telle que le client l'a écrite : le chemin que le location a
        # admis n'est alors pas celui que le module voit.
        if not _proxy_pass_avec_uri(r.proxy_pass) and not _reecrit_en_break(r):
            note("U", "proxy_pass sans URI et sans `rewrite … break` : donner l'URI "
                      "dans le proxy_pass (location exact) ou écrire "
                      "`rewrite ^ $uri break;` avant lui, pour que le module reçoive "
                      "le chemin normalisé que le location a admis.")
        vu_rewrite = False
        for d in r.location.bloc or []:
            if d.nom == "rewrite" and d.args and d.args[-1] == "break":
                vu_rewrite = True
            elif d.nom == "if" and vu_rewrite:
                note("U", "`if` placé après `rewrite … break` : nginx ne l'évalue plus. "
                          "Écrire les verrous `if` avant le rewrite.")

        # ── Marqueurs ───────────────────────────────────────────────────────
        for ligne, m in r.marqueurs:
            if m not in MARQUEURS_CONNUS:
                note("C", f"marqueur « # relais: {m} » inconnu (ligne {ligne}) ; "
                          "seul « # relais: lecture » est reconnu.")

        # ── C : relais de lecture ───────────────────────────────────────────
        if r.lecture:
            if r.modificateur == "=":
                pass
            elif r.modificateur in ("~", "~*"):
                if not _regex_ancree(r.motif):
                    note("C", f"relais de lecture sur l'expression « {r.motif} » : elle "
                              "doit être ancrée `^…$` et énumérer les chemins (ni `.*`, "
                              "ni `.+`, ni suffixe ouvert).")
            else:
                note("C", f"relais de lecture par préfixe (« {r.motif} ») : écrire "
                          "`location =` ou une expression ancrée listant les chemins "
                          "lus par les cartes.")
            limites = list(r.location.enfants("limit_except"))
            if not limites:
                note("C", "relais de lecture sans `limit_except GET { deny all; }`.")
            for le in limites:
                methodes = {a.upper() for a in le.args}
                if methodes != {"GET"}:
                    note("C", "relais de lecture : `limit_except` doit n'admettre que GET "
                              f"(trouvé : {' '.join(le.args)}).")
                if not any(x.nom == "deny" and x.args == ["all"] for x in le.bloc or []):
                    note("C", "relais de lecture : le bloc `limit_except GET` doit "
                              "contenir `deny all;`.")
            if r.entete("X-Real-IP") != "$remote_addr":
                note("C", "relais de lecture : `proxy_set_header X-Real-IP $remote_addr;` "
                          "attendu.")

        # ── D : décisions du Hall ───────────────────────────────────────────
        if r.interne:
            continue
        chemin = prefixe_litteral(r)
        if (module in VERROU_LAN_MODULES
                or any(chemin.startswith(p) for p in VERROU_LAN_CHEMINS)) \
                and not _verrou_lan(r):
            note("D", f"le module « {module} » est d'usage local : le relais porte "
                      "`if ($lan_client = 0) { return 403; }`.")
        publics = SESSION_MODULES.get(module)
        if publics is not None and not (r.modificateur == "=" and r.motif in publics):
            cibles = [a.args[0] for a in r.location.enfants("auth_request") if a.args]
            if not cibles:
                note("D", f"le module « {module} » ne sert sans session que "
                          f"{', '.join(sorted(publics))} : ce relais exige "
                          "`auth_request` vers la vérification de session de l'agrégateur.")
            elif not all(c in verifs for c in cibles):
                note("D", f"auth_request vers {', '.join(cibles)} : ce doit être un "
                          "location interne exact qui mandate vers "
                          f"{VERIFICATION_SESSION}.")
        for uri, raison in JAMAIS_RELAYES:
            if correspond(r, uri):
                note("D", f"ce relais servirait {uri} — {raison}.")

    # ── D : une API non relayée répond 404, pas la page du Hall en 200 ──────
    vus: Set[int] = set()
    for r in relais_tous:
        s = r.serveur
        if id(s) in vus or not any(prefixe_litteral(x).startswith("/api/")
                                   for x in relais_tous if x.serveur is s):
            continue
        vus.add(id(s))
        if not _repli_api_404(s):
            constats.append(Constat(
                "D", s.ligne, "server",
                "aucun `location /api/ { return 404 …; }` (préfixe simple, sans `^~`) : "
                "une API que le Hall ne relaie pas retomberait sur la page du Hall en 200."))

    constats.sort(key=lambda c: (c.ligne, c.regle))
    return constats


def _repli_api_404(serveur: Directive) -> bool:
    for d in serveur.enfants("location"):
        if d.args == ["/api/"]:
            return any(x.nom == "return" and x.args[:1] == ["404"] for x in d.bloc or [])
    return False


# ═══════════════════════════════════════════════════════════════════════════
# Syntaxe : `nginx -t` sur une copie isolée
# ═══════════════════════════════════════════════════════════════════════════

_HARNAIS = """\
# Harnais de verifie-relais-hall.py : seules les variables et formats que le
# vhost emprunte à d'autres paquets sont définis ici.
pid {tmp}/nginx.pid;
error_log {tmp}/error.log;
events {{}}
http {{
    client_body_temp_path {tmp}/body;
    proxy_temp_path {tmp}/proxy;
    fastcgi_temp_path {tmp}/fastcgi;
    uwsgi_temp_path {tmp}/uwsgi;
    scgi_temp_path {tmp}/scgi;
    access_log off;
    log_format sbx_host '$host $remote_addr';
    geo $lan_client {{ default 0; 127.0.0.0/8 1; }}
    include {tmp}/vhost.conf;
}}
"""


def verifie_syntaxe(vhost: Path, exiger: bool = False) -> Tuple[Optional[bool], str]:
    """`nginx -t` sur le vhost, ses `include` remplacés par des fichiers vides.

    Rend (None, raison) si nginx est absent et qu'on ne l'exige pas.
    """
    nginx = shutil.which("nginx") or next(
        (p for p in ("/usr/sbin/nginx", "/sbin/nginx") if Path(p).exists()), None)
    if not nginx:
        return (False if exiger else None), "nginx absent : syntaxe non vérifiée"
    with tempfile.TemporaryDirectory(prefix="relais-hall-") as t:
        tmp = Path(t)
        vide = tmp / "vide.conf"
        vide.write_text("")
        texte = vhost.read_text(encoding="utf-8")
        texte = re.sub(r"(?m)^(\s*)include\s+[^;]+;", lambda m: f"{m.group(1)}include {vide};", texte)
        texte = re.sub(r"(?m)^(\s*)(access_log|error_log)\s+/[^\s;]+",
                       lambda m: f"{m.group(1)}{m.group(2)} {tmp}/{m.group(2)}.log", texte)
        (tmp / "vhost.conf").write_text(texte, encoding="utf-8")
        (tmp / "nginx.conf").write_text(_HARNAIS.format(tmp=tmp), encoding="utf-8")
        cmd = [nginx, "-t", "-q", "-p", str(tmp), "-c", str(tmp / "nginx.conf"),
               "-e", str(tmp / "error.log")]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"nginx -t n'a pas pu tourner : {e}"
        sortie = (p.stdout + p.stderr).strip().replace(str(tmp), "<tmp>")
        return p.returncode == 0, sortie or "nginx -t : syntaxe acceptée"


# ═══════════════════════════════════════════════════════════════════════════
# Point d'entrée
# ═══════════════════════════════════════════════════════════════════════════

def analyse_fichier(vhost: Path, racine: Path = RACINE_DEPOT) -> Tuple[List[Relais], List[Constat]]:
    arbre = analyse_texte(vhost.read_text(encoding="utf-8"))
    tous = relais_du_fichier(arbre, racine)
    return tous, verifie(tous)


def _resume(tous: List[Relais]) -> str:
    lignes = []
    for r in tous:
        drapeaux = []
        if r.lecture:
            drapeaux.append("lecture")
        if _verrou_lan(r):
            drapeaux.append("LAN")
        if any(True for _ in r.location.enfants("auth_request")):
            drapeaux.append("session")
        if r.interne:
            drapeaux.append("interne")
        lignes.append(f"  {r.location.ligne:>4}  {module_de(r):<12} "
                      f"{' '.join(r.location.args):<72} {','.join(drapeaux)}")
    return "\n".join(lignes)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Vérifie le gabarit des relais du Hall (#1609).")
    ap.add_argument("--vhost", type=Path, default=None,
                    help=f"fichier à vérifier (défaut : {VHOST_HALL})")
    ap.add_argument("--racine", type=Path, default=RACINE_DEPOT,
                    help="racine du dépôt, pour relire les snippets inclus")
    ap.add_argument("--resume", action="store_true", help="lister les relais reconnus")
    ap.add_argument("--syntaxe", action="store_true",
                    help="valider aussi par `nginx -t` (include remplacés par des fichiers vides)")
    ap.add_argument("--exiger-nginx", action="store_true",
                    help="avec --syntaxe : échouer si nginx est absent")
    a = ap.parse_args(argv)

    vhost = a.vhost or (a.racine / VHOST_HALL)
    try:
        tous, constats = analyse_fichier(vhost, a.racine)
    except (OSError, UnicodeDecodeError, ErreurAnalyse) as e:
        print(f"{vhost} : illisible — {e}", file=sys.stderr)
        return 2

    nom = vhost.name
    if a.resume:
        print(f"{nom} : {len(tous)} relais")
        print(_resume(tous))

    code = 0
    if constats:
        code = 1
        courant = None
        for c in constats:
            cle = (c.ligne, c.location)
            if cle != courant:
                print(f"{nom}:{c.ligne}  {c.location}")
                courant = cle
            print(f"    [{c.regle}] {c.message}")
        nb_loc = len({(c.ligne, c.location) for c in constats})
        print(f"\n{len(constats)} écart(s) au gabarit des relais, sur {nb_loc} location(s).")
    else:
        nb_lecture = sum(1 for r in tous if r.lecture)
        print(f"{nom} : {len(tous)} relais conformes au gabarit "
              f"(dont {nb_lecture} relais de lecture).")

    if a.syntaxe:
        ok, sortie = verifie_syntaxe(vhost, exiger=a.exiger_nginx)
        if ok is None:
            print(f"syntaxe : {sortie}")
        elif ok:
            print("syntaxe : nginx -t accepte le vhost (include remplacés par des fichiers vides).")
        else:
            print(f"syntaxe : nginx -t refuse le vhost\n{sortie}", file=sys.stderr)
            code = 2
    return code


if __name__ == "__main__":
    sys.exit(main())
