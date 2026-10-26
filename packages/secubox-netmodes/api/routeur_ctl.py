# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Contrôleur root du mode routeur (#3189) : sauvegarde → rendu → validation → bascule → retour automatique sous 180 s.

Aucune commande ne nomme eth* : le WAN mvpp2 bloque son comphy si on le relance à distance (redémarrage à froid).
Seule exception : `nft -c -f` / `nft -f` du fichier généré, qui lit le nom du WAN dans ses règles (NAT, transit).
Tout chemin absolu est préfixé par `ctx.racine`, toute commande passe par `ctx.executer` (faux en test).
L'état, les sauvegardes et lan-dhcp.conf vivent dans un arbre root seul (/var/lib/secubox-netmodes, 0700) vérifié à
chaque usage : /var/lib/secubox appartient à secubox, qui pourrait sinon substituer un retour piégé."""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import threading
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
from .routeur_rendu import CHEMINS, COMMENTAIRE_NFT, MARQUE, TABLE_NFT, rendre

VERROU = "/run/lock/secubox-netmodes.lock"
VERROU_UNBOUND = "/run/lock/secubox-dns-lan.lock"           # partagé avec secubox-dns-lan
DELAI_VERROU_UNBOUND = 30.0
DELAI_VERROU_RETOUR = 60.0                                  # minuteur et démarrage attendent, un humain non
ARBRE = "/var/lib/secubox-netmodes"                         # root seul, 0700
ETAT = f"{ARBRE}/routeur-etat.json"
SAUVEGARDES = f"{ARBRE}/sauvegardes"
STRICTS = frozenset({CHEMINS["dhcp"]})                      # gérés ET dans l'arbre root : contrôle strict
# secubox-hub inclut ce fichier nommément dans son bloc geo (nginx refuse un joker) : absent, `nginx -t` échoue.
# Jamais supprimé : un retour le remet neutre (commentaires seuls), s'il a un dossier où vivre.
NEUTRES = {CHEMINS["geo"]: ("# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
                            f"# {MARQUE}\n# mode routeur inactif : aucun réseau LAN ajouté\n")}
TOML = "/etc/secubox/netmodes/routeur.toml"
ANCIEN_PONT = "/etc/systemd/network/10-br-lan.network"      # pont fait main de gk2 : mis de côté, remis au retour
DOSSIERS_NETWORKD = ("/etc/systemd/network", "/run/systemd/network")
DOSSIER_GEO = "/etc/nginx/secubox-lan-geo.d"
NETPLAN = "/etc/netplan"
# nftables.service ne recharge au démarrage le fragment du LAN (CHEMINS["nft"]) que par cette inclusion
NFTABLES_CONF = "/etc/nftables.conf"
_INCLUSION_NFT = re.compile(r"""include\s+(["']?)/etc/nftables\.d/\*(?:\.nft)?\1\s*;?""")
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
# nginx -t ouvre /run/nginx.pid et ses journaux en écriture : dans l'espace de montage de l'API (ProtectSystem=strict,
# hérité par sudo) il échouerait toujours. systemd-run le lance dans le contexte de PID 1 ; --pipe rend sa sortie.
NGINX_T = ["systemd-run", "--wait", "--pipe", "--collect", "--quiet", "/usr/sbin/nginx", "-t"]
_ETATS = ("inactif", "en_attente", "actif")
_SIGNAUX = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


class Occupe(RuntimeError):
    """Une autre opération du contrôleur tient le verrou."""


class Refus(RuntimeError):
    """Refus expliqué à l'administrateur : rien n'a été basculé."""


class CheminRefuse(Refus):
    """Un chemin de l'arbre root seul pourrait être substitué par un autre compte."""


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


def _prendre(fd: int, attente: float) -> bool:
    limite = time.monotonic() + attente
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.monotonic() >= limite:
                return False
            time.sleep(0.1)


@contextlib.contextmanager
def _verrou(ctx: Contexte, attente: float = 0.0) -> Generator[None, None, None]:
    fd = _ouvrir_verrou(_p(ctx, VERROU))
    try:
        if not _prendre(fd, attente):
            raise Occupe("une autre opération du mode routeur est en cours : réessayer dans un instant")
        yield
    finally:
        os.close(fd)


@contextlib.contextmanager
def _verrou_unbound(ctx: Contexte) -> Generator[None, None, None]:
    fd = _ouvrir_verrou(_p(ctx, VERROU_UNBOUND))
    try:
        if not _prendre(fd, DELAI_VERROU_UNBOUND):
            raise Refus(f"Unbound est tenu par secubox-dns-lan depuis {DELAI_VERROU_UNBOUND:g} s : "
                        "réessayer dans un instant")
        yield
    finally:
        os.close(fd)


@contextlib.contextmanager
def _sans_interruption() -> Generator[None, None, None]:
    """Un arrêt au milieu laisserait le réseau à moitié basculé : TERM, HUP et INT sont ignorés le temps de finir."""
    if threading.current_thread() is not threading.main_thread():   # signal.signal n'existe que là (CLI : toujours)
        yield
        return
    anciens = [(s, signal.signal(s, signal.SIG_IGN)) for s in _SIGNAUX]
    try:
        yield
    finally:
        for s, ancien in anciens:
            signal.signal(s, ancien if ancien is not None else signal.SIG_DFL)


def _chemin_sur(ctx: Contexte, chemin: str) -> Path:
    p = _p(ctx, chemin)
    try:
        fichiers.verifier_sur(ctx.racine, p)
    except fichiers.CheminNonSur as exc:
        raise CheminRefuse(f"{exc} : un autre compte pourrait y substituer son contenu ; corriger propriétaire "
                           "et droits avant toute opération") from exc
    return p


def _verifier_arbre(ctx: Contexte) -> None:
    for chemin in (ETAT, SAUVEGARDES, *sorted(STRICTS)):
        _chemin_sur(ctx, chemin)


@contextlib.contextmanager
def _auditer_chemins(ctx: Contexte, acteur: str) -> Generator[None, None, None]:
    try:
        yield
    except CheminRefuse as exc:
        _auditer(ctx, "chemin-refuse", acteur, str(exc))
        raise


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


def _match_br_lan_seul(texte: str) -> bool:
    """[Match] réduit à une seule ligne `Name=br-lan` : mettre ce fichier de côté (puis `networkctl reload`) ne touche
    aucune autre interface. `Name=br-lan eth2`, un joker, une seconde ligne ou une autre clé ne le sont pas."""
    section, cles = None, []
    for brute in texte.splitlines():
        ligne = brute.strip()
        if not ligne or ligne[0] in "#;":
            continue
        if ligne.startswith("[") and ligne.endswith("]"):
            section = ligne[1:-1].strip()
        elif section == "Match":
            cle, _, valeur = ligne.partition("=")
            cles.append((cle.strip(), valeur.strip()))
    return cles == [("Name", "br-lan")]


def _refus_ancien_pont(texte: str) -> Refus | None:
    if _match_br_lan_seul(texte):
        return None
    return Refus(f"{ANCIEN_PONT} ne vise pas br-lan seul ([Match] attendu : la seule ligne Name=br-lan) : le mettre de "
                 "côté puis recharger networkd reconfigurerait d'autres interfaces, le WAN compris ; le corriger ou "
                 "le retirer d'abord")


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
    """Ports du TOML ; absent : aucun ; illisible ou invalide : tous ceux du LAN. Ne lève pas : le retour s'en sert
    pour savoir quels ports reconfigurer et ne doit jamais dépendre d'un TOML édité à la main (relecture finale I1)."""
    if not os.path.lexists(_p(ctx, TOML)):
        return ()
    try:
        return charger(_p(ctx, TOML)).ports
    except (ErreurConfig, OSError, ValueError, TypeError, RecursionError):   # charger les convertit ; filet du retour
        return PORTS_LAN


def _en_dict(cfg: ConfigRouteur) -> dict:
    return {"adresse": str(cfg.adresse), "dhcp_debut": str(cfg.dhcp_debut), "dhcp_fin": str(cfg.dhcp_fin),
            "bail": cfg.bail, "ports": list(cfg.ports), "wan": cfg.wan}


# --- état --------------------------------------------------------------------------------------------------------------

def _lire_etat(ctx: Contexte) -> dict:
    vide = {"etat": "inactif", "depuis": None, "acteur": None, "sauvegarde": None}
    chemin = _chemin_sur(ctx, ETAT)                         # CheminRefuse : l'appelant décide (refus ou affichage)
    try:
        brut = fichiers.lire(chemin)
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
    fichiers.ecrire(_p(ctx, ETAT), json.dumps(contenu, ensure_ascii=False) + "\n", 0o640, ctx.racine)


def _remettre_etat(ctx: Contexte, brut: bytes | None) -> list[str]:
    """Remet le fichier d'état tel qu'il était avant l'application (absent compris)."""
    try:
        if brut is None:
            _p(ctx, ETAT).unlink(missing_ok=True)
        else:
            fichiers.ecrire(_p(ctx, ETAT), brut, 0o640, ctx.racine)
    except OSError as exc:
        return [f"état : {exc}"]
    return []


def etat(ctx: Contexte) -> dict:
    try:
        sortie = _lire_etat(ctx)
    except CheminRefuse as exc:                             # lecture seule et interrogée en boucle : affiché, pas audité
        sortie = {"etat": "inactif", "depuis": None, "acteur": None, "sauvegarde": None, "erreur": str(exc)}
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

def _verifier_inclusion_nft(ctx: Contexte) -> None:
    """Sans `include "/etc/nftables.d/*.nft"` dans nftables.conf, le pare-feu du LAN (DHCP, DNS, NAT) disparaîtrait au
    premier redémarrage. Lu comme nft le lit (lien suivi) ; commentaires ignorés, espaces et guillemets tolérés."""
    try:
        texte = _p(ctx, NFTABLES_CONF).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise Refus(f"{NFTABLES_CONF} illisible ({exc.__class__.__name__}) : impossible de vérifier que le pare-feu "
                    "du LAN y est rechargé au démarrage") from exc
    if not any(_INCLUSION_NFT.fullmatch(ligne.split("#", 1)[0].strip()) for ligne in texte.splitlines()):
        raise Refus(f"{NFTABLES_CONF} n'inclut pas /etc/nftables.d/*.nft : le pare-feu du LAN ({CHEMINS['nft']}) ne "
                    "serait pas rechargé au démarrage ; y ajouter include \"/etc/nftables.d/*.nft\" "
                    "(base de secubox-hardening) d'abord")


def _verifier_ancien_pont(ctx: Contexte) -> None:
    try:
        contenu = fichiers.lire(_p(ctx, ANCIEN_PONT))
    except OSError as exc:
        raise Refus(f"{ANCIEN_PONT} illisible ({exc.__class__.__name__}) : impossible de vérifier qu'il ne vise que "
                    "br-lan ; le corriger d'abord") from exc
    refus = _refus_ancien_pont(contenu.decode("utf-8", "replace")) if contenu is not None else None
    if refus is not None:
        raise refus


def _refus_prealables(ctx: Contexte, liens: dict[str, list[IPv4Interface]]) -> None:
    _verifier_inclusion_nft(ctx)
    _verifier_ancien_pont(ctx)
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
    return fichiers.restaurer(_p(ctx, SAUVEGARDES) / nom, _geres(ctx), MODES, ctx.racine, STRICTS, NEUTRES)


def _contenu_unbound(ctx: Contexte) -> object:
    """Drop-in Unbound du LAN (None : absent). Illisible : une sentinelle neuve, jamais égale, qui force le redémarrage."""
    try:
        return fichiers.lire(_p(ctx, CHEMINS["unbound"]))
    except OSError:
        return object()


def _poser(ctx: Contexte, cfg: ConfigRouteur, rendu: dict[str, str], geo: bool) -> bool:
    """Pose les fichiers rendus ; renvoie True si le drop-in Unbound change, seul cas où Unbound doit redémarrer
    (un redémarrage coupe le DNS de toute la box)."""
    unbound_change = _contenu_unbound(ctx) != rendu["unbound"].encode("utf-8")
    for cle, chemin in CHEMINS.items():
        if cle != "geo" or geo:
            fichiers.ecrire(_p(ctx, chemin), rendu[cle], 0o644, ctx.racine if chemin in STRICTS else None)
    fichiers.ecrire(_p(ctx, TOML), en_toml(cfg), 0o640)
    ancien = _p(ctx, ANCIEN_PONT)
    contenu = fichiers.lire(ancien)
    if contenu is not None:
        refus = _refus_ancien_pont(contenu.decode("utf-8", "replace"))
        if refus is not None:                               # vérifié aux refus préalables : changé depuis
            raise refus
        ancien.unlink()                                     # sa copie est dans la sauvegarde
    return unbound_change


def _valider(ctx: Contexte, geo: bool) -> None:
    controles = [(["nft", "-c", "-f", str(_p(ctx, CHEMINS["nft"]))], "nft refuse le pare-feu généré"),
                 (["unbound-checkconf"], "unbound-checkconf refuse la configuration DNS")]
    if geo:
        controles.append((NGINX_T, "nginx -t refuse la configuration"))
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
        if a == cfg.adresse:
            continue
        argv = ["ip", "addr", "del", str(a), "dev", "br-lan"]
        r = ctx.executer(argv)
        # networkd retire lui-même ce que le nouveau .network ne déclare plus : course bénigne si l'adresse a disparu
        if r.returncode == 0 or (r.returncode == 2 and "Cannot assign requested address" in (r.stderr or "")
                                 and a not in _adresses(ctx, "br-lan").get("br-lan", [])):
            continue
        raise Echec(f"« {' '.join(argv)} » a échoué (code {r.returncode}) : {_sortie(r)}")


def _basculer(ctx: Contexte, cfg: ConfigRouteur, geo: bool, unbound_change: bool) -> None:
    nft = str(_p(ctx, CHEMINS["nft"]))
    _exiger(ctx, ["networkctl", "reload"])                                       # 7
    _exiger(ctx, ["networkctl", "reconfigure", "br-lan", *cfg.ports])
    _reprendre_lan_temporaire(ctx, cfg)                                          # 8
    _supprimer_regles(ctx, COMMENTAIRE_NFT)                                      # 9
    _exiger(ctx, ["nft", "-f", nft])
    if unbound_change:                                                           # 10 : nouvelle écoute
        with _verrou_unbound(ctx):
            _exiger(ctx, ["systemctl", "restart", "unbound.service"])
    _exiger(ctx, ["systemctl", "enable", "secubox-lan-dhcp.service"])            # 11
    _exiger(ctx, ["systemctl", "restart", "secubox-lan-dhcp.service"])
    if geo:                                                                      # 12
        _exiger(ctx, ["systemctl", "reload", "nginx.service"])
    ctx.executer(["systemctl", "stop", f"{MINUTEUR}.timer"])                     # 13 : code ignoré (souvent absent)
    # --collect : un retour en échec ne laisse pas l'unité chargée, le nom reste réutilisable
    _exiger(ctx, ["systemd-run", f"--unit={MINUTEUR}", f"--on-active={DELAI_RETOUR}", "--collect",
                  "--description=Retour automatique du mode routeur SecuBox sauf confirmation",
                  NETMODESCTL, "routeur-retour", "minuteur"])


def _connue(exc: BaseException) -> bool:
    return isinstance(exc, (Refus, Echec, OSError))


def _texte(exc: BaseException) -> str:
    return str(exc) if _connue(exc) else f"{exc.__class__.__name__} : {exc}"


def _appliquer(ctx: Contexte, cfg_dict: dict, acteur: str) -> None:
    try:
        _verifier_arbre(ctx)
        courant = _lire_etat(ctx)
        if courant["etat"] == "en_attente":
            raise Refus("une application attend déjà sa confirmation : confirmer ou revenir en arrière d'abord")
        cfg = depuis_dict(cfg_dict)                                              # 2
        liens = _adresses(ctx)
        verifier_reseaux(cfg, [a.network for nom_lien, adresses in liens.items()
                               if nom_lien not in ("br-lan", "lo") for a in adresses])
        _refus_prealables(ctx, liens)                                            # 3
    except (ErreurConfig, Refus) as exc:
        if not isinstance(exc, CheminRefuse):              # audité par _auditer_chemins
            _auditer(ctx, "appliquer-refus", acteur, str(exc))
        raise
    geo = _p(ctx, DOSSIER_GEO).is_dir()
    rendu = rendre(cfg)
    with _sans_interruption():                          # de la première écriture à la fin de la bascule
        etat_avant = fichiers.lire(_p(ctx, ETAT))           # remis tel quel si la validation refuse
        try:                                                                     # 4
            nom = fichiers.sauvegarder(_p(ctx, SAUVEGARDES), _utc(ctx).strftime("%Y%m%dT%H%M%SZ"), _geres(ctx),
                                       ctx.racine, STRICTS, proteger=courant["sauvegarde"])
        except fichiers.LienSymbolique as exc:
            refus = Refus(f"{exc.filename} est un lien symbolique : sauvegarde et écriture refusées")
            _auditer(ctx, "appliquer-refus", acteur, str(refus))
            raise refus from exc
        if not geo:
            _auditer(ctx, "geo-absente", acteur, f"{DOSSIER_GEO} absent : fragment géo non posé, nginx inchangé")
        erreurs: list[str] = []
        unbound_change = True
        try:
            # garde armée avant le premier fichier géré : une coupure d'ici à la fin revient au démarrage
            _ecrire_etat(ctx, "en_attente", acteur, nom)
            with _verrou_unbound(ctx):
                try:
                    unbound_change = _poser(ctx, cfg, rendu, geo)                # 5
                    _valider(ctx, geo)                                           # 6
                except BaseException:
                    erreurs += _restaurer(ctx, nom)[1]                           # encore sous le verrou Unbound
                    raise
        except BaseException as exc:
            erreurs += _remettre_etat(ctx, etat_avant)
            suite = "fichiers et état d'avant remis" if not erreurs else "remise INCOMPLÈTE : " + " ; ".join(erreurs)
            _auditer(ctx, "appliquer-echec", acteur, f"{_texte(exc)} ; {suite}")
            if isinstance(exc, fichiers.LienSymbolique):
                raise Refus(f"{exc.filename} est un lien symbolique ; {suite}") from exc
            if isinstance(exc, Refus):
                raise Refus(f"{exc} ; {suite}") from exc
            if _connue(exc):
                raise Echec(f"{exc} ; {suite}") from exc
            raise
        try:
            _basculer(ctx, cfg, geo, unbound_change)                             # 7 à 13
        except BaseException as exc:                    # même une exception imprévue défait la bascule
            _auditer(ctx, "appliquer-echec", acteur, f"{_texte(exc)} ; retour à la sauvegarde {nom}")
            erreurs = _retour(ctx, "echec", nom)
            suite = "configuration précédente restaurée" if not erreurs else "retour INCOMPLET : " + " ; ".join(erreurs)
            if _connue(exc):
                raise Echec(f"{exc} ; {suite}") from exc
            raise
    _auditer(ctx, "appliquer", acteur,
             f"pont {cfg.adresse}, DHCP {cfg.dhcp_debut}-{cfg.dhcp_fin} ({cfg.bail}), ports {' '.join(cfg.ports)} ; "
             f"{'Unbound redémarré' if unbound_change else 'Unbound inchangé, non redémarré'} ; "
             f"sauvegarde {nom} ; retour automatique dans {DELAI_RETOUR} s sauf confirmation")


def appliquer(ctx: Contexte, cfg_dict: dict, acteur: str) -> dict:
    _verifier_acteur(acteur)
    with _verrou(ctx), _auditer_chemins(ctx, acteur):                            # 1
        _appliquer(ctx, cfg_dict, acteur)
    return {**etat(ctx), "delai_confirmation": DELAI_RETOUR}


# --- confirmer, retour -------------------------------------------------------------------------------------------------

def confirmer(ctx: Contexte, acteur: str) -> dict:
    _verifier_acteur(acteur)
    with _verrou(ctx), _auditer_chemins(ctx, acteur):
        _verifier_arbre(ctx)
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


def _sans_attente(bloquer: bool) -> list[str]:
    """Au démarrage, secubox-netmodes-retour-boot est ordonné AVANT secubox-lan-dhcp (et nginx attend le réseau) :
    attendre leur relance bloquerait jusqu'au délai. La relance part alors sans attendre et s'exécute après."""
    return [] if bloquer else ["--no-block"]


def _retour_dhcp(ctx: Contexte, bloquer: bool = True) -> None:
    if _p(ctx, CHEMINS["dhcp"]).is_file():
        _exiger(ctx, ["systemctl", "restart", *_sans_attente(bloquer), "secubox-lan-dhcp.service"])
    else:                                                   # un arrêt n'attend jamais un démarrage ordonné après lui
        _exiger(ctx, ["systemctl", "disable", "--now", "secubox-lan-dhcp.service"])


def _recharger_nginx(ctx: Contexte, bloquer: bool = True) -> None:
    if _p(ctx, DOSSIER_GEO).is_dir():
        _exiger(ctx, ["systemctl", "reload", *_sans_attente(bloquer), "nginx.service"])


def _retour(ctx: Contexte, acteur: str, nom: str | None = None) -> list[str]:
    with _sans_interruption():
        _verifier_arbre(ctx)
        return _restaurer_et_relancer(ctx, acteur, nom)


def _restaurer_et_relancer(ctx: Contexte, acteur: str, nom: str | None) -> list[str]:
    """Restaure une sauvegarde et la remet en service ; continue après une erreur et les renvoie toutes.
    Sans `nom` : celle de la dernière application réussie (fichier d'état), sinon la plus récente — une application
    refusée à la validation laisse une sauvegarde identique à l'état courant, qui ne doit pas masquer la bonne."""
    noms = fichiers.sauvegardes(_p(ctx, SAUVEGARDES), ctx.racine)
    if nom is None:
        reference = _lire_etat(ctx)["sauvegarde"]           # fichier non fiable : seul un nom listé est retenu
        nom = reference if reference in noms else (noms[-1] if noms else None)
    if nom is None or nom not in noms:
        raise Refus("aucune sauvegarde du mode routeur : rien à restaurer")
    ports_avant = _ports(ctx)
    unbound_avant = _contenu_unbound(ctx)
    try:
        absents, erreurs = _restaurer(ctx, nom)
    except OSError as exc:
        raise Echec(f"sauvegarde {nom} inutilisable : {exc}") from exc
    ports = tuple(p for p in PORTS_LAN if p in {*ports_avant, *_ports(ctx)}) or PORTS_LAN
    unbound_change = _contenu_unbound(ctx) != unbound_avant     # identique : le DNS de la box n'est pas coupé
    bloquer = acteur != "demarrage"
    etapes = [("réseau", lambda: _retour_reseau(ctx, ports)), ("pare-feu", lambda: _retour_pare_feu(ctx))]
    if unbound_change:
        etapes.append(("Unbound", lambda: _redemarrer_unbound(ctx)))
    etapes += [("DHCP", lambda: _retour_dhcp(ctx, bloquer)), ("nginx", lambda: _recharger_nginx(ctx, bloquer))]
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
             + ("" if unbound_change else ", Unbound inchangé, non redémarré")
             + (f" ; INCOMPLET : {' ; '.join(erreurs)}" if erreurs else ""))
    return erreurs


def retour(ctx: Contexte, acteur: str) -> dict:
    _verifier_acteur(acteur)
    # le minuteur n'a qu'une chance : il attend le verrou au lieu de laisser la config non gardée
    attente = DELAI_VERROU_RETOUR if acteur in ("minuteur", "demarrage") else 0.0
    with _verrou(ctx, attente), _auditer_chemins(ctx, acteur):
        _verifier_arbre(ctx)
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
    with _verrou(ctx, DELAI_VERROU_RETOUR), _auditer_chemins(ctx, "demarrage"):
        _verifier_arbre(ctx)
        courant = _lire_etat(ctx)["etat"]
        if courant != "en_attente":
            return {"etat": courant}
        erreurs = _retour(ctx, "demarrage")
    if erreurs:
        raise Echec("retour incomplet : " + " ; ".join(erreurs))
    return etat(ctx)
