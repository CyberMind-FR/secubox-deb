# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Configuration du composant SearXNG (#3581) : lecture de /etc/secubox/searxng.toml, génération et validation de settings.yml.

Le secret de SearXNG (server.secret_key) n'est JAMAIS ici : searxngctl le génère dans /etc/secubox/secrets/searxng/ et le
remet au service du conteneur par la variable SEARXNG_SECRET. La génération refuse un TOML qui tenterait d'en poser un."""
from __future__ import annotations

import copy
import ipaddress
import os
import re
import stat
import tomllib
from pathlib import Path
from typing import Any

CHEMIN_DEFAUT = Path("/etc/secubox/searxng.toml")
# Réseau des conteneurs (br-lxc, netplan de secubox-netmodes) : l'API n'a le droit d'aller que là (IPAddressAllow).
RESEAU_LXC = ipaddress.IPv4Network("10.100.0.0/24")

DEFAUTS: dict[str, dict[str, Any]] = {
    "lxc": {
        "name": "searxng",
        # 10.100.0.85 : libre dans tout le dépôt (vérifié par tests/test_adresse_unique_3581.py) ; yacy = .80.
        "ip": "10.100.0.85",
        "gateway": "10.100.0.1",
        "bridge": "br-lxc",
        "path": "/data/lxc",
        # gk2 n'a qu'environ 900 Mio disponibles : SearXNG (un processus) tient sous ce plafond.
        "memoire_max": "384M",
        "memoire_haute": "320M",
        "dns": ["1.1.1.1", "9.9.9.9"],
    },
    "searxng": {
        "port": 8888,
        "instance_name": "SecuBox",
        "langue": "fr",
        "safe_search": 0,
        # Délais sortants bornés : un moteur lent ne fait pas attendre la page plus de max_request_timeout.
        "request_timeout": 3.0,
        "max_request_timeout": 6.0,
        # Moteur en échec (dont « trop de requêtes ») suspendu, puis de plus en plus longtemps : on n'insiste pas.
        "ban_time_on_fail": 5,
        "max_ban_time_on_fail": 120,
        "moteurs_desactives": [],
    },
}

_NOM = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
_PONT = re.compile(r"^[a-z][a-z0-9-]{0,14}$")
_CHEMIN = re.compile(r"^/[A-Za-z0-9_./-]{1,200}$")
_MEMOIRE = re.compile(r"^[1-9][0-9]{0,5}[MG]$")
_LANGUE = re.compile(r"^[a-z]{2}(-[A-Z]{2})?$")
_MOTEUR = re.compile(r"^[a-z0-9][a-z0-9 _.-]{0,63}$")


class ConfigInvalide(ValueError):
    """Configuration (TOML) ou settings.yml refusés : le message dit quelle clé et pourquoi, jamais une valeur secrète."""


def _ipv4(valeur: Any, cle: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(str(valeur))
    except ValueError as e:
        raise ConfigInvalide(f"{cle} : adresse IPv4 attendue") from e


def _entier(valeur: Any, cle: str, mini: int, maxi: int) -> int:
    if isinstance(valeur, bool) or not isinstance(valeur, int) or not mini <= valeur <= maxi:
        raise ConfigInvalide(f"{cle} : entier de {mini} à {maxi} attendu")
    return valeur


def _reel(valeur: Any, cle: str, mini: float, maxi: float) -> float:
    if isinstance(valeur, bool) or not isinstance(valeur, (int, float)) or not mini <= float(valeur) <= maxi:
        raise ConfigInvalide(f"{cle} : nombre de {mini} à {maxi} attendu")
    return float(valeur)


def valider(cfg: dict) -> dict:
    """Valide une configuration complète (défauts fusionnés) ; rend une copie normalisée ou lève ConfigInvalide."""
    lxc, sx = dict(cfg["lxc"]), dict(cfg["searxng"])
    for cle, motif in (("name", _NOM), ("bridge", _PONT), ("path", _CHEMIN)):
        if not isinstance(lxc.get(cle), str) or not motif.match(lxc[cle]):
            raise ConfigInvalide(f"lxc.{cle} : valeur refusée")
    if ".." in lxc["path"].split("/"):
        raise ConfigInvalide("lxc.path : « .. » refusé")
    ip, passerelle = _ipv4(lxc.get("ip"), "lxc.ip"), _ipv4(lxc.get("gateway"), "lxc.gateway")
    if ip not in RESEAU_LXC or passerelle not in RESEAU_LXC:
        raise ConfigInvalide(f"lxc.ip, lxc.gateway : dans {RESEAU_LXC} (réseau br-lxc) seulement")
    if ip == passerelle or ip in (RESEAU_LXC.network_address, RESEAU_LXC.broadcast_address):
        raise ConfigInvalide("lxc.ip : adresse d'hôte du réseau br-lxc, distincte de la passerelle")
    for cle in ("memoire_max", "memoire_haute"):
        if not isinstance(lxc.get(cle), str) or not _MEMOIRE.match(lxc[cle]):
            raise ConfigInvalide(f"lxc.{cle} : « 384M » ou « 1G » attendu")
    dns = lxc.get("dns")
    if not isinstance(dns, list) or not 1 <= len(dns) <= 3:
        raise ConfigInvalide("lxc.dns : une à trois adresses")
    lxc["dns"] = [str(_ipv4(d, "lxc.dns")) for d in dns]
    lxc["ip"], lxc["gateway"] = str(ip), str(passerelle)

    sx["port"] = _entier(sx.get("port"), "searxng.port", 1024, 65535)
    nom = sx.get("instance_name")
    if not isinstance(nom, str) or not 1 <= len(nom) <= 64 or any(ord(c) < 32 or ord(c) == 127 for c in nom):
        raise ConfigInvalide("searxng.instance_name : 1 à 64 caractères imprimables")
    if not isinstance(sx.get("langue"), str) or not _LANGUE.match(sx["langue"]):
        raise ConfigInvalide("searxng.langue : « fr » ou « fr-FR » attendu")
    sx["safe_search"] = _entier(sx.get("safe_search"), "searxng.safe_search", 0, 2)
    sx["request_timeout"] = _reel(sx.get("request_timeout"), "searxng.request_timeout", 0.5, 30.0)
    sx["max_request_timeout"] = _reel(sx.get("max_request_timeout"), "searxng.max_request_timeout", 0.5, 60.0)
    if sx["max_request_timeout"] < sx["request_timeout"]:
        raise ConfigInvalide("searxng.max_request_timeout : au moins request_timeout")
    sx["ban_time_on_fail"] = _entier(sx.get("ban_time_on_fail"), "searxng.ban_time_on_fail", 0, 86400)
    sx["max_ban_time_on_fail"] = _entier(sx.get("max_ban_time_on_fail"), "searxng.max_ban_time_on_fail", 0, 86400)
    if sx["max_ban_time_on_fail"] < sx["ban_time_on_fail"]:
        raise ConfigInvalide("searxng.max_ban_time_on_fail : au moins ban_time_on_fail")
    moteurs = sx.get("moteurs_desactives")
    if not isinstance(moteurs, list) or len(moteurs) > 200:
        raise ConfigInvalide("searxng.moteurs_desactives : liste de 200 noms au plus")
    for m in moteurs:
        if not isinstance(m, str) or not _MOTEUR.match(m):
            raise ConfigInvalide("searxng.moteurs_desactives : nom de moteur refusé")
    sx["moteurs_desactives"] = sorted(set(moteurs))
    return {"lxc": lxc, "searxng": sx}


def fusionner(brut: dict) -> dict:
    """Défauts + sections [lxc] et [searxng] du TOML. Une clé inconnue est refusée (faute de frappe = réglage ignoré)."""
    cfg = copy.deepcopy(DEFAUTS)
    for section, valeurs in brut.items():
        if section not in cfg:
            raise ConfigInvalide(f"section [{section}] inconnue")
        if not isinstance(valeurs, dict):
            raise ConfigInvalide(f"[{section}] : table attendue")
        for cle, valeur in valeurs.items():
            if cle not in cfg[section]:
                # Couvre aussi « secret_key » : le secret ne vit jamais dans le TOML.
                raise ConfigInvalide(f"{section}.{cle} : clé inconnue")
            cfg[section][cle] = valeur
    return valider(cfg)


TAILLE_MAX = 64 * 1024


def _lire_toml_protege(p: Path, proprietaire: int) -> bytes:
    """Contenu du TOML lu par un contrôleur root : ouvert sans suivre de lien ni bloquer, fichier ordinaire appartenant
    à `proprietaire`, inscriptible ni par le groupe ni par les autres, taille bornée. FileNotFoundError si absent."""
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigInvalide(f"{p} : fichier ordinaire attendu")
        if st.st_uid != proprietaire:
            raise ConfigInvalide(f"{p} : doit appartenir à root")
        if st.st_mode & 0o022:
            raise ConfigInvalide(f"{p} : inscriptible par le groupe ou les autres (chmod go-w)")
        if st.st_size > TAILLE_MAX:
            raise ConfigInvalide(f"{p} : plus de {TAILLE_MAX} octets")
        return os.read(fd, TAILLE_MAX + 1)
    finally:
        os.close(fd)


def charger(chemin: Path | str | None = None, *, proprietaire: int | None = None) -> dict:
    """Lit le TOML (absent = défauts) ; lève ConfigInvalide si illisible ou refusé. `proprietaire` (uid, 0 pour
    searxngctl) : le fichier est en plus ouvert en O_NOFOLLOW et refusé s'il n'appartient pas à cet uid ou s'il est
    inscriptible par le groupe ou les autres."""
    p = Path(chemin) if chemin else CHEMIN_DEFAUT
    try:
        if proprietaire is None:
            with open(p, "rb") as f:
                brut = tomllib.load(f)
        else:
            brut = tomllib.loads(_lire_toml_protege(p, proprietaire).decode("utf-8"))
    except FileNotFoundError:
        brut = {}
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ConfigInvalide(f"{p} illisible : {e.__class__.__name__}") from e
    return fusionner(brut)


def generer_settings(cfg: dict) -> dict:
    """settings.yml de SearXNG, sur le modèle du POC de gk0 (relais.py), sans secret."""
    lxc, sx = cfg["lxc"], cfg["searxng"]
    reglages: dict[str, Any] = {
        "use_default_settings": True,
        "general": {"instance_name": sx["instance_name"], "enable_metrics": False},
        "server": {
            "bind_address": lxc["ip"],
            "port": sx["port"],
            "limiter": False,
            "public_instance": False,
            "image_proxy": False,
        },
        "search": {
            "safe_search": sx["safe_search"],
            "formats": ["html", "json"],
            "ban_time_on_fail": sx["ban_time_on_fail"],
            "max_ban_time_on_fail": sx["max_ban_time_on_fail"],
        },
        "ui": {"default_locale": sx["langue"]},
        "outgoing": {
            "request_timeout": sx["request_timeout"],
            "max_request_timeout": sx["max_request_timeout"],
        },
    }
    if sx["moteurs_desactives"]:
        # use_default_settings: true fusionne la liste par nom avec les moteurs par défaut.
        reglages["engines"] = [{"name": m, "disabled": True} for m in sx["moteurs_desactives"]]
    return reglages


ENTETE = ("# /etc/searxng/settings.yml — ÉCRIT PAR searxngctl (secubox-metanews, #3581). Ne pas modifier ici :\n"
          "# /etc/secubox/searxng.toml puis « searxngctl reload ». server.secret_key vient de SEARXNG_SECRET.\n")


def rendre_yaml(reglages: dict) -> str:
    import yaml  # noqa: PLC0415 — python3-yaml, chargé seulement quand on écrit

    return ENTETE + yaml.safe_dump(reglages, sort_keys=False, allow_unicode=True, default_flow_style=False)


def valider_settings(texte: str, cfg: dict) -> dict:
    """Relit un settings.yml ÉCRIT (pas celui qu'on croit avoir écrit) : YAML lisible, clés attendues, aucun secret."""
    import yaml  # noqa: PLC0415

    if not isinstance(texte, str) or not texte.strip() or len(texte) > 256 * 1024:
        raise ConfigInvalide("settings.yml vide ou trop long")
    try:
        d = yaml.safe_load(texte)
    except yaml.YAMLError as e:
        raise ConfigInvalide(f"settings.yml : YAML illisible ({e.__class__.__name__})") from e
    if not isinstance(d, dict):
        raise ConfigInvalide("settings.yml : table attendue")
    attendu = generer_settings(cfg)
    if d.get("use_default_settings") is not True:
        raise ConfigInvalide("settings.yml : use_default_settings doit valoir true")
    for section in ("general", "server", "search", "ui", "outgoing"):
        if not isinstance(d.get(section), dict):
            raise ConfigInvalide(f"settings.yml : section {section} absente")
    if "secret_key" in d["server"]:
        raise ConfigInvalide("settings.yml : server.secret_key interdit (SEARXNG_SECRET)")
    for section, valeurs in attendu.items():
        if section == "use_default_settings":
            continue
        if d.get(section) != valeurs:
            raise ConfigInvalide(f"settings.yml : section {section} différente de la configuration")
    if "json" not in d["search"].get("formats", []):
        raise ConfigInvalide("settings.yml : search.formats doit contenir json")
    return d
