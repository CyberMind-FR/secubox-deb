# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Contrôleur root du mode routeur (#3189) : sauvegarde → rendu → validation → bascule → retour automatique sous 180 s.

Aucune commande ne nomme eth* : le WAN mvpp2 bloque son comphy si on le relance à distance (redémarrage à froid).
Seule exception : `nft -c -f` / `nft -f` du fichier généré, qui lit le nom du WAN dans ses règles (NAT, transit).
Tout chemin absolu est préfixé par `ctx.racine`, toute commande passe par `ctx.executer` (faux en test)."""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path
from typing import Callable, Generator

import yaml

from . import routeur_fichiers as fichiers
from .routeur_config import (
    PORTS_LAN, ConfigRouteur, ErreurConfig, charger, depuis_dict, en_toml, verifier_reseaux,
)
from .routeur_rendu import CHEMINS, COMMENTAIRE_NFT, TABLE_NFT, rendre

VERROU = "/run/lock/secubox-netmodes.lock"
VERROU_UNBOUND = "/run/lock/secubox-dns-lan.lock"           # partagé avec secubox-dns-lan
DELAI_VERROU_UNBOUND = 30.0
ETAT = "/var/lib/secubox/netmodes/routeur-etat.json"
SAUVEGARDES = "/var/lib/secubox/netmodes-backup/routeur"
TOML = "/etc/secubox/netmodes/routeur.toml"
ANCIEN_PONT = "/etc/systemd/network/10-br-lan.network"      # pont fait main de gk2 : mis de côté, remis au retour
DOSSIERS_NETWORKD = ("/etc/systemd/network", "/run/systemd/network")
DOSSIER_GEO = "/etc/nginx/secubox-lan-geo.d"
NETPLAN = "/etc/netplan"
IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"
BAUX = "/var/lib/misc/dnsmasq.leases"                       # déjà lu par le NAC
AUDIT = "/var/log/secubox/audit.log"
NETMODESCTL = "/usr/sbin/netmodesctl"
MINUTEUR = "secubox-netmodes-retour"
DELAI_RETOUR = 180
PREFIXE_TEMPORAIRE = "sbx-lan-temporaire"
ADRESSE_GESTION = IPv4Address("192.168.255.1")              # HAProxy :9443 et TURN y écoutent
ACTEUR = re.compile(r"[A-Za-z0-9._@-]{1,64}")
GERES = (*CHEMINS.values(), TOML, ANCIEN_PONT)
MODES = {TOML: 0o640}                                       # le reste en 0644 : lu par les démons
LISTE_INPUT = ["nft", "-j", "-a", "list", "chain", "inet", "filter", "input"]
_ETATS = ("inactif", "en_attente", "actif")


class Occupe(RuntimeError):
    """Une autre opération du contrôleur tient le verrou."""


class Refus(RuntimeError):
    """Refus expliqué à l'administrateur : rien n'a été basculé."""


class Echec(RuntimeError):
    """Une commande système a échoué."""


@dataclass
class Contexte:
    racine: Path
    executer: Callable[[list[str]], subprocess.CompletedProcess]
    maintenant: Callable[[], datetime]


def executer_systeme(argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(argv, 127, "", f"{argv[0]} introuvable")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "délai de 120 s dépassé")


def contexte_systeme() -> Contexte:
    return Contexte(Path("/"), executer_systeme, lambda: datetime.now(timezone.utc))


# --- outils --------------------------------------------------------------------------------------------------------------

def _p(ctx: Contexte, chemin: str) -> Path:
    return ctx.racine / chemin.lstrip("/")


def _geres(ctx: Contexte) -> dict[str, Path]:
    return {c: _p(ctx, c) for c in GERES}


def _utc(ctx: Contexte) -> datetime:
    return ctx.maintenant().astimezone(timezone.utc)


def _auditer(ctx: Contexte, action: str, acteur: str, detail: str) -> None:
    ligne = json.dumps({"ts": _utc(ctx).strftime("%Y-%m-%dT%H:%M:%SZ"), "module": "netmodes", "action": action,
                        "acteur": acteur, "detail": detail[:1000]}, ensure_ascii=False) + "\n"
    try:
        fd = os.open(_p(ctx, AUDIT), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        try:
            os.write(fd, ligne.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError as exc:                                  # ne bloque pas l'action, mais ne se tait pas
        print(f"netmodesctl : audit non écrit ({action}) : {exc}", file=sys.stderr)


def _sortie(r: subprocess.CompletedProcess) -> str:
    return " ".join(f"{r.stderr or ''} {r.stdout or ''}".split())[-400:] or "sans message"


def _exiger(ctx: Contexte, argv: list[str]) -> subprocess.CompletedProcess:
    r = ctx.executer(argv)
    if r.returncode != 0:
        raise Echec(f"« {' '.join(argv)} » a échoué (code {r.returncode}) : {_sortie(r)}")
    return r


def _actif(ctx: Contexte, unite: str) -> bool:
    return ctx.executer(["systemctl", "is-active", "--quiet", unite]).returncode == 0


def _verifier_acteur(acteur) -> None:
    if not isinstance(acteur, str) or not ACTEUR.fullmatch(acteur):
        raise Refus("acteur invalide : lettres, chiffres et . _ @ - (64 au plus)")


def _ouvrir_verrou(chemin: Path) -> int:
    fichiers.creer_dossiers(chemin.parent, 0o755)
    return os.open(chemin, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)


@contextlib.contextmanager
def _verrou(ctx: Contexte) -> Generator[None, None, None]:
    fd = _ouvrir_verrou(_p(ctx, VERROU))
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Occupe("une autre opération du mode routeur est en cours : réessayer dans un instant") from None
        yield
    finally:
        os.close(fd)


@contextlib.contextmanager
def _verrou_unbound(ctx: Contexte) -> Generator[None, None, None]:
    fd = _ouvrir_verrou(_p(ctx, VERROU_UNBOUND))
    try:
        limite = time.monotonic() + DELAI_VERROU_UNBOUND
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= limite:
                    raise Refus(f"Unbound est tenu par secubox-dns-lan depuis {DELAI_VERROU_UNBOUND:g} s : "
                                "réessayer dans un instant") from None
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


def _adresses(ctx: Contexte, dev: str | None = None) -> dict[str, list[IPv4Interface]]:
    argv = ["ip", "-j", "-4", "addr"] + (["show", "dev", dev] if dev else [])
    r = _exiger(ctx, argv)
    sortie: dict[str, list[IPv4Interface]] = {}
    try:
        for lien in json.loads(r.stdout or "[]"):
            if not lien:                                    # `ip -4` rend {} pour un lien sans IPv4
                continue
            for a in lien.get("addr_info", []):
                if a.get("family") == "inet":
                    sortie.setdefault(lien["ifname"], []).append(IPv4Interface(f"{a['local']}/{a['prefixlen']}"))
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise Echec(f"sortie de « {' '.join(argv)} » illisible : {exc}") from exc
    return sortie


def _adresses_pont(ctx: Contexte) -> list[IPv4Interface]:
    try:
        return _adresses(ctx, "br-lan").get("br-lan", [])
    except Echec:                                           # pont absent : mode routeur jamais appliqué
        return []


def _network_de_br_lan(texte: str) -> bool:
    section = None
    for brute in texte.splitlines():
        ligne = brute.strip()
        if not ligne or ligne[0] in "#;":
            continue
        if ligne.startswith("[") and ligne.endswith("]"):
            section = ligne[1:-1].strip()
        elif section == "Match" and "=" in ligne:
            cle, valeur = ligne.split("=", 1)
            if cle.strip() == "Name" and "br-lan" in valeur.split():
                return True
    return False


def _pont_declare(ctx: Contexte) -> bool:
    for dossier in DOSSIERS_NETWORKD:
        d = _p(ctx, dossier)
        for f in sorted(d.glob("*.network")) if d.is_dir() else []:
            if _network_de_br_lan(f.read_text(encoding="utf-8", errors="replace")):
                return True
    return False


def _supprimer_regles(ctx: Contexte, prefixe: str) -> None:
    """Règles de `inet filter input` retrouvées par leur commentaire et supprimées par handle (idempotence)."""
    r = _exiger(ctx, LISTE_INPUT)
    try:
        handles = [o["rule"]["handle"] for o in json.loads(r.stdout)["nftables"]
                   if isinstance(o, dict) and isinstance(o.get("rule"), dict)
                   and str(o["rule"].get("comment", "")).startswith(prefixe)]
    except (ValueError, TypeError, KeyError) as exc:
        raise Echec(f"liste des règles d'entrée illisible : {exc}") from exc
    for h in handles:
        if not isinstance(h, int) or isinstance(h, bool):
            raise Echec(f"handle nft inattendu : {h!r}")
        _exiger(ctx, ["nft", "delete", "rule", "inet", "filter", "input", "handle", str(h)])


def _ports(ctx: Contexte) -> tuple[str, ...]:
    if not os.path.lexists(_p(ctx, TOML)):
        return ()
    try:
        return charger(_p(ctx, TOML)).ports
    except ErreurConfig:
        return PORTS_LAN


def _en_dict(cfg: ConfigRouteur) -> dict:
    return {"adresse": str(cfg.adresse), "dhcp_debut": str(cfg.dhcp_debut), "dhcp_fin": str(cfg.dhcp_fin),
            "bail": cfg.bail, "ports": list(cfg.ports), "wan": cfg.wan}


# --- état --------------------------------------------------------------------------------------------------------------

def _lire_etat(ctx: Contexte) -> dict:
    vide = {"etat": "inactif", "depuis": None, "acteur": None, "sauvegarde": None}
    try:
        brut = fichiers.lire(_p(ctx, ETAT))
        d = json.loads(brut) if brut is not None else vide
    except (OSError, ValueError) as exc:
        return {**vide, "erreur": f"fichier d'état {ETAT} illisible ({exc.__class__.__name__})"}
    if not isinstance(d, dict) or d.get("etat") not in _ETATS:
        return {**vide, "erreur": f"fichier d'état {ETAT} incohérent"}
    return {"etat": d["etat"], **{k: d[k] if isinstance(d.get(k), str) else None
                                  for k in ("depuis", "acteur", "sauvegarde")}}


def _ecrire_etat(ctx: Contexte, valeur: str, acteur: str, sauvegarde: str | None) -> None:
    contenu = {"etat": valeur, "depuis": _utc(ctx).strftime("%Y-%m-%dT%H:%M:%SZ"), "acteur": acteur,
               "sauvegarde": sauvegarde}
    fichiers.ecrire(_p(ctx, ETAT), json.dumps(contenu, ensure_ascii=False) + "\n", 0o640)


def etat(ctx: Contexte) -> dict:
    sortie = _lire_etat(ctx)
    erreur = sortie.pop("erreur", None)
    config = None
    if os.path.lexists(_p(ctx, TOML)):
        try:
            config = _en_dict(charger(_p(ctx, TOML)))
        except ErreurConfig as exc:
            erreur = erreur or str(exc)
    if erreur:
        sortie["etat"], sortie["erreur"] = "config_invalide", erreur
    sortie["config"] = config
    sortie["minuteur_actif"] = _actif(ctx, f"{MINUTEUR}.timer")
    sortie["dhcp_actif"] = _actif(ctx, "secubox-lan-dhcp.service")
    sortie["adresses_pont"] = [str(a) for a in _adresses_pont(ctx)]
    return sortie


# --- appliquer ---------------------------------------------------------------------------------------------------------

def _refus_prealables(ctx: Contexte, liens: dict[str, list[IPv4Interface]]) -> None:
    for f in sorted(_p(ctx, NETPLAN).glob("*.yaml")):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise Refus(f"{NETPLAN}/{f.name} est illisible ({exc.__class__.__name__}) : impossible de vérifier "
                        "qu'il ne déclare pas br-lan ; le corriger d'abord") from exc
        reseau = doc.get("network") if isinstance(doc, dict) else None
        ponts = reseau.get("bridges") if isinstance(reseau, dict) else None
        if isinstance(ponts, dict) and "br-lan" in ponts:
            raise Refus(f"{NETPLAN}/{f.name} déclare déjà br-lan : le pont aurait deux propriétaires ; "
                        "retirer br-lan de netplan d'abord")
    if _actif(ctx, "pseudo-routeur-sonde.timer"):
        raise Refus("le pseudo-routeur (#2940) est actif : sa chaîne forward ne doit pas coexister avec le mode "
                    "routeur ; le désactiver d'abord")
    try:
        forward = (fichiers.lire(_p(ctx, IP_FORWARD)) or b"").decode("ascii", "replace").strip()
    except OSError:
        forward = ""
    if forward != "1":
        raise Refus(f"net.ipv4.ip_forward vaut « {forward or 'illisible'} » : le LAN ne sortirait pas "
                    "(secubox-core le met à 1)")
    if _actif(ctx, "dnsmasq.service"):
        raise Refus(f"dnsmasq.service est actif : il écrirait le même fichier de baux ({BAUX}) ; l'arrêter d'abord")
    if any(a.ip == ADRESSE_GESTION for a in liens.get("br-lan", [])):
        lo = _adresses(ctx, "lo").get("lo", [])
        if IPv4Interface(f"{ADRESSE_GESTION}/32") not in lo:
            raise Refus(f"br-lan porte {ADRESSE_GESTION} mais lo ne la porte pas en /32 : la retirer du pont "
                        "couperait HAProxy :9443 et TURN ; installer d'abord secubox-core 1.7.16 (lo en /32)")


def _restaurer(ctx: Contexte, nom: str) -> tuple[list[str], list[str]]:
    return fichiers.restaurer(_p(ctx, SAUVEGARDES) / nom, _geres(ctx), MODES)


def _poser(ctx: Contexte, cfg: ConfigRouteur, rendu: dict[str, str], geo: bool) -> None:
    for cle, chemin in CHEMINS.items():
        if cle != "geo" or geo:
            fichiers.ecrire(_p(ctx, chemin), rendu[cle], 0o644)
    fichiers.ecrire(_p(ctx, TOML), en_toml(cfg), 0o640)
    ancien = _p(ctx, ANCIEN_PONT)
    contenu = fichiers.lire(ancien)
    if contenu is not None and _network_de_br_lan(contenu.decode("utf-8", "replace")):
        ancien.unlink()                                     # sa copie est dans la sauvegarde


def _valider(ctx: Contexte, geo: bool) -> None:
    controles = [(["nft", "-c", "-f", str(_p(ctx, CHEMINS["nft"]))], "nft refuse le pare-feu généré"),
                 (["unbound-checkconf"], "unbound-checkconf refuse la configuration DNS")]
    if geo:
        controles.append((["nginx", "-t"], "nginx -t refuse la configuration"))
    for argv, motif in controles:
        r = ctx.executer(argv)
        if r.returncode != 0:
            raise Refus(f"{motif} : {_sortie(r)}")


def _reprendre_lan_temporaire(ctx: Contexte, cfg: ConfigRouteur) -> None:
    """LAN fait main de gk2 : son dnsmasq s'arrête, ses baux sont repris, ses règles et 192.168.255.1/24 partent."""
    if _actif(ctx, "sbx-lan-dhcp.service"):
        _exiger(ctx, ["systemctl", "stop", "sbx-lan-dhcp.service"])
    baux = _p(ctx, BAUX)
    if not fichiers.lire(baux):                             # absent ou vide : les clients gardent leur adresse
        sources = sorted(p for p in _p(ctx, "/run").glob("sbx-lan-dhcp-*.leases")
                         if p.is_file() and not p.is_symlink())
        if sources:
            fichiers.ecrire(baux, b"".join(fichiers.lire(p) or b"" for p in sources), 0o644)
    _supprimer_regles(ctx, PREFIXE_TEMPORAIRE)
    for a in _adresses(ctx, "br-lan").get("br-lan", []):
        if a != cfg.adresse:
            _exiger(ctx, ["ip", "addr", "del", str(a), "dev", "br-lan"])


def _basculer(ctx: Contexte, cfg: ConfigRouteur, geo: bool, acteur: str, nom: str) -> None:
    nft = str(_p(ctx, CHEMINS["nft"]))
    _exiger(ctx, ["networkctl", "reload"])                                       # 7
    _exiger(ctx, ["networkctl", "reconfigure", "br-lan", *cfg.ports])
    _reprendre_lan_temporaire(ctx, cfg)                                          # 8
    _supprimer_regles(ctx, COMMENTAIRE_NFT)                                      # 9
    _exiger(ctx, ["nft", "-f", nft])
    with _verrou_unbound(ctx):                                                   # 10 : nouvelle écoute
        _exiger(ctx, ["systemctl", "restart", "unbound.service"])
    _exiger(ctx, ["systemctl", "enable", "secubox-lan-dhcp.service"])            # 11
    _exiger(ctx, ["systemctl", "restart", "secubox-lan-dhcp.service"])
    if geo:                                                                      # 12
        _exiger(ctx, ["systemctl", "reload", "nginx.service"])
    ctx.executer(["systemctl", "stop", f"{MINUTEUR}.timer"])                     # 13 : code ignoré (souvent absent)
    _ecrire_etat(ctx, "en_attente", acteur, nom)            # avant le minuteur : un arrêt brutal ici revient au boot
    # --collect : un retour en échec ne laisse pas l'unité chargée, le nom reste réutilisable
    _exiger(ctx, ["systemd-run", f"--unit={MINUTEUR}", f"--on-active={DELAI_RETOUR}", "--collect",
                  "--description=Retour automatique du mode routeur SecuBox sauf confirmation",
                  NETMODESCTL, "routeur-retour", "minuteur"])


def _appliquer(ctx: Contexte, cfg_dict: dict, acteur: str) -> None:
    try:
        courant = _lire_etat(ctx)
        if courant["etat"] == "en_attente":
            raise Refus("une application attend déjà sa confirmation : confirmer ou revenir en arrière d'abord")
        cfg = depuis_dict(cfg_dict)                                              # 2
        liens = _adresses(ctx)
        verifier_reseaux(cfg, [a.network for nom_lien, adresses in liens.items()
                               if nom_lien not in ("br-lan", "lo") for a in adresses])
        _refus_prealables(ctx, liens)                                            # 3
        try:                                                                     # 4
            nom = fichiers.sauvegarder(_p(ctx, SAUVEGARDES), _utc(ctx).strftime("%Y%m%dT%H%M%SZ"), _geres(ctx),
                                       proteger=courant["sauvegarde"])
        except fichiers.LienSymbolique as exc:
            raise Refus(f"{exc.filename} est un lien symbolique : sauvegarde et écriture refusées") from exc
    except (ErreurConfig, Refus) as exc:
        _auditer(ctx, "appliquer-refus", acteur, str(exc))
        raise
    geo = _p(ctx, DOSSIER_GEO).is_dir()
    if not geo:
        _auditer(ctx, "geo-absente", acteur, f"{DOSSIER_GEO} absent : fragment géo non posé, nginx inchangé")
    rendu = rendre(cfg)
    try:
        with _verrou_unbound(ctx):
            try:
                _poser(ctx, cfg, rendu, geo)                                     # 5
                _valider(ctx, geo)                                               # 6
            except (Refus, OSError) as exc:
                _, erreurs = _restaurer(ctx, nom)
                lien = isinstance(exc, fichiers.LienSymbolique)
                motif = f"{exc.filename} est un lien symbolique" if lien else str(exc)
                suite = "fichiers d'avant restaurés" if not erreurs else "restauration INCOMPLÈTE : " + " ; ".join(erreurs)
                if lien or isinstance(exc, Refus):
                    raise Refus(f"{motif} ; {suite}") from exc
                raise Echec(f"écriture impossible : {motif} ; {suite}") from exc
    except (Refus, Echec) as exc:
        _auditer(ctx, "appliquer-echec", acteur, str(exc))
        raise
    try:
        _basculer(ctx, cfg, geo, acteur, nom)                                    # 7 à 13
    except (Echec, Refus, OSError) as exc:
        _auditer(ctx, "appliquer-echec", acteur, f"{exc} ; retour à la sauvegarde {nom}")
        erreurs = _retour(ctx, "echec", nom)
        suite = "configuration précédente restaurée" if not erreurs else "retour INCOMPLET : " + " ; ".join(erreurs)
        raise Echec(f"{exc} ; {suite}") from exc
    _auditer(ctx, "appliquer", acteur,
             f"pont {cfg.adresse}, DHCP {cfg.dhcp_debut}-{cfg.dhcp_fin} ({cfg.bail}), ports {' '.join(cfg.ports)} ; "
             f"sauvegarde {nom} ; retour automatique dans {DELAI_RETOUR} s sauf confirmation")


def appliquer(ctx: Contexte, cfg_dict: dict, acteur: str) -> dict:
    _verifier_acteur(acteur)
    with _verrou(ctx):                                                           # 1
        _appliquer(ctx, cfg_dict, acteur)
    return {**etat(ctx), "delai_confirmation": DELAI_RETOUR}


# --- confirmer, retour -------------------------------------------------------------------------------------------------

def confirmer(ctx: Contexte, acteur: str) -> dict:
    _verifier_acteur(acteur)
    with _verrou(ctx):
        courant = _lire_etat(ctx)
        if courant["etat"] != "en_attente":
            raise Refus(f"rien à confirmer : le mode routeur est « {courant['etat']} »")
        r = ctx.executer(["systemctl", "stop", f"{MINUTEUR}.timer"])
        _ecrire_etat(ctx, "actif", acteur, courant["sauvegarde"])
        detail = "mode routeur confirmé, retour automatique annulé"
        if r.returncode != 0:                               # sans danger : le minuteur ne revient plus hors attente
            detail += f" (arrêt du minuteur : code {r.returncode}, {_sortie(r)})"
        _auditer(ctx, "confirmer", acteur, detail)
    return etat(ctx)


def _retour_reseau(ctx: Contexte, ports: tuple[str, ...]) -> None:
    _exiger(ctx, ["networkctl", "reload"])
    if _pont_declare(ctx):
        _exiger(ctx, ["networkctl", "reconfigure", "br-lan", *ports])
    elif ctx.executer(["ip", "link", "show", "dev", "br-lan"]).returncode == 0:
        _exiger(ctx, ["ip", "link", "delete", "br-lan"])  # networkd ne supprime jamais un netdev dont le .netdev a disparu


def _retour_pare_feu(ctx: Contexte) -> None:
    _supprimer_regles(ctx, COMMENTAIRE_NFT)
    fichier = _p(ctx, CHEMINS["nft"])
    if fichier.is_file():
        _exiger(ctx, ["nft", "-f", str(fichier)])
    elif ctx.executer(["nft", "list", "table", "inet", TABLE_NFT]).returncode == 0:
        _exiger(ctx, ["nft", "delete", "table", "inet", TABLE_NFT])


def _redemarrer_unbound(ctx: Contexte) -> None:
    with _verrou_unbound(ctx):
        _exiger(ctx, ["systemctl", "restart", "unbound.service"])


def _retour_dhcp(ctx: Contexte) -> None:
    if _p(ctx, CHEMINS["dhcp"]).is_file():
        _exiger(ctx, ["systemctl", "restart", "secubox-lan-dhcp.service"])
    else:
        _exiger(ctx, ["systemctl", "disable", "--now", "secubox-lan-dhcp.service"])


def _recharger_nginx(ctx: Contexte) -> None:
    if _p(ctx, DOSSIER_GEO).is_dir():
        _exiger(ctx, ["systemctl", "reload", "nginx.service"])


def _retour(ctx: Contexte, acteur: str, nom: str | None = None) -> list[str]:
    """Restaure une sauvegarde et la remet en service ; continue après une erreur et les renvoie toutes.
    Sans `nom` : celle de la dernière application réussie (fichier d'état), sinon la plus récente — une application
    refusée à la validation laisse une sauvegarde identique à l'état courant, qui ne doit pas masquer la bonne."""
    noms = fichiers.sauvegardes(_p(ctx, SAUVEGARDES))
    if nom is None:
        reference = _lire_etat(ctx)["sauvegarde"]           # fichier non fiable : seul un nom listé est retenu
        nom = reference if reference in noms else (noms[-1] if noms else None)
    if nom is None or nom not in noms:
        raise Refus("aucune sauvegarde du mode routeur : rien à restaurer")
    ports_avant = _ports(ctx)
    try:
        absents, erreurs = _restaurer(ctx, nom)
    except OSError as exc:
        raise Echec(f"sauvegarde {nom} inutilisable : {exc}") from exc
    ports = tuple(p for p in PORTS_LAN if p in {*ports_avant, *_ports(ctx)}) or PORTS_LAN
    etapes = (("réseau", lambda: _retour_reseau(ctx, ports)), ("pare-feu", lambda: _retour_pare_feu(ctx)),
              ("Unbound", lambda: _redemarrer_unbound(ctx)), ("DHCP", lambda: _retour_dhcp(ctx)),
              ("nginx", lambda: _recharger_nginx(ctx)))
    for nom_etape, etape in etapes:
        try:
            etape()
        except (Echec, Refus, OSError) as exc:              # chaque étape remise compte : on poursuit
            erreurs.append(f"{nom_etape} : {exc}")
    ctx.executer(["systemctl", "stop", f"{MINUTEUR}.timer"])  # code ignoré : absent après échéance ou confirmation
    nouvel = "inactif" if TOML in absents else "actif"
    try:
        _ecrire_etat(ctx, nouvel, acteur, nom)
    except OSError as exc:
        erreurs.append(f"état : {exc}")
    _auditer(ctx, "retour", acteur, f"sauvegarde {nom} restaurée, état {nouvel}"
             + (f" ; INCOMPLET : {' ; '.join(erreurs)}" if erreurs else ""))
    return erreurs


def retour(ctx: Contexte, acteur: str) -> dict:
    _verifier_acteur(acteur)
    with _verrou(ctx):
        courant = _lire_etat(ctx)["etat"]
        if acteur == "minuteur" and courant != "en_attente":   # échu après une confirmation : ne rien défaire
            _auditer(ctx, "retour-ignore", acteur, f"minuteur échu hors attente (état {courant}) : rien à faire")
            return etat(ctx)
        erreurs = _retour(ctx, acteur)
    if erreurs:
        raise Echec("retour incomplet : " + " ; ".join(erreurs))
    return etat(ctx)


def retour_si_en_attente(ctx: Contexte) -> dict:
    """Au démarrage : le minuteur transitoire a disparu avec le redémarrage, l'attente non confirmée est défaite."""
    with _verrou(ctx):
        courant = _lire_etat(ctx)["etat"]
        if courant != "en_attente":
            return {"etat": courant}
        erreurs = _retour(ctx, "demarrage")
    if erreurs:
        raise Echec("retour incomplet : " + " ; ".join(erreurs))
    return etat(ctx)
