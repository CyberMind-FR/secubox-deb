# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Configuration validée du mode routeur (#3189) : modèle pur, sans effet de bord."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from ipaddress import (
    AddressValueError, IPv4Address, IPv4Interface, IPv4Network, NetmaskValueError,
)
from pathlib import Path
from typing import Iterable

PORTS_LAN: tuple[str, ...] = ("lan0", "lan1", "lan2", "lan3")
RESEAUX_INTERDITS: tuple[IPv4Network, ...] = (
    IPv4Network("192.168.255.0/24"),  # gestion des box
    IPv4Network("10.100.0.0/24"),
)
_BAIL = re.compile(r"^[1-9][0-9]{0,3}[mh]$")
_WAN = re.compile(r"^eth[0-9]$")


class ErreurConfig(ValueError):
    """Configuration du mode routeur invalide (message destiné à l'administrateur)."""


@dataclass(frozen=True)
class ConfigRouteur:
    adresse: IPv4Interface
    dhcp_debut: IPv4Address
    dhcp_fin: IPv4Address
    bail: str
    ports: tuple[str, ...]
    wan: str


def _ipv4(valeur, champ: str, cls):
    try:
        return cls(str(valeur))
    except (AddressValueError, NetmaskValueError, ValueError) as exc:
        raise ErreurConfig(f"{champ} : « {valeur} » n'est pas une adresse IPv4 valide ({exc})") from exc


def _interdit(reseau: IPv4Network) -> None:
    for interdit in RESEAUX_INTERDITS:
        if reseau.overlaps(interdit):
            raise ErreurConfig(
                f"{interdit} est le réseau de gestion des box : choisir un autre sous-réseau")


def depuis_dict(d: dict) -> ConfigRouteur:
    if not isinstance(d, dict):
        raise ErreurConfig("la configuration du mode routeur doit être une table")
    for cle in ("adresse", "dhcp_debut", "dhcp_fin"):
        if cle not in d:
            raise ErreurConfig(f"clé obligatoire absente : {cle}")
    adresse = _ipv4(d["adresse"], "adresse", IPv4Interface)
    debut = _ipv4(d["dhcp_debut"], "dhcp_debut", IPv4Address)
    fin = _ipv4(d["dhcp_fin"], "dhcp_fin", IPv4Address)
    reseau = adresse.network
    if reseau.prefixlen > 30:
        raise ErreurConfig(f"{adresse} : préfixe /{reseau.prefixlen} trop étroit, /30 au plus")
    if adresse.ip == reseau.network_address or adresse.ip == reseau.broadcast_address:
        raise ErreurConfig(f"{adresse.ip} est l'adresse de réseau ou de diffusion : choisir une adresse d'hôte")
    _interdit(reseau)
    for nom, ip in (("dhcp_debut", debut), ("dhcp_fin", fin)):
        if ip not in reseau or ip in (reseau.network_address, reseau.broadcast_address):
            raise ErreurConfig(f"{nom} {ip} est hors du réseau {reseau}")
    if debut > fin:
        raise ErreurConfig(f"la plage DHCP est inversée : {debut} > {fin}")
    if debut <= adresse.ip <= fin:
        raise ErreurConfig(f"la plage DHCP {debut}-{fin} contient l'adresse du pont {adresse.ip}")

    bail = d.get("bail", "12h")
    if not isinstance(bail, str) or not _BAIL.match(bail):
        raise ErreurConfig(f"bail « {bail} » invalide : nombre de 1 à 9999 suivi de m ou h (ex. 12h)")

    ports = d.get("ports", PORTS_LAN)
    if isinstance(ports, str) or not isinstance(ports, (list, tuple)):
        raise ErreurConfig("ports doit être une liste")
    ports = tuple(ports)
    if not ports:
        raise ErreurConfig("ports : au moins un port du commutateur est nécessaire")
    for p in ports:
        if p not in PORTS_LAN:
            raise ErreurConfig(f"port « {p} » refusé : seuls {', '.join(PORTS_LAN)} peuvent rejoindre le pont")
    if len(set(ports)) != len(ports):
        raise ErreurConfig("ports : un port est cité plusieurs fois")

    wan = d.get("wan", "eth2")
    if not isinstance(wan, str) or not _WAN.match(wan):
        raise ErreurConfig(f"wan « {wan} » invalide : attendu ethN (un chiffre)")
    return ConfigRouteur(adresse, debut, fin, bail, ports, wan)


def verifier_reseaux(cfg: ConfigRouteur, occupes: Iterable[IPv4Network]) -> None:
    reseau = cfg.adresse.network
    _interdit(reseau)
    for autre in occupes:
        if reseau.overlaps(autre):
            raise ErreurConfig(
                f"{reseau} chevauche {autre}, déjà porté par une autre interface : choisir un autre sous-réseau")


def charger(chemin: Path) -> ConfigRouteur:
    try:
        with open(chemin, "rb") as f:
            donnees = tomllib.load(f)
    except OSError as exc:
        raise ErreurConfig(f"lecture de {chemin} impossible : {exc.strerror or exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ErreurConfig(f"{chemin} n'est pas un TOML valide : {exc}") from exc
    lan = donnees.get("lan")
    if not isinstance(lan, dict):
        raise ErreurConfig(f"{chemin} : table [lan] absente")
    return depuis_dict(lan)


def en_toml(cfg: ConfigRouteur) -> str:
    # valeurs déjà validées : ni guillemet ni antislash possibles
    ports = ", ".join(f'"{p}"' for p in cfg.ports)
    return (
        "[lan]\n"
        f'adresse = "{cfg.adresse}"\n'
        f'dhcp_debut = "{cfg.dhcp_debut}"\n'
        f'dhcp_fin = "{cfg.dhcp_fin}"\n'
        f'bail = "{cfg.bail}"\n'
        f"ports = [{ports}]\n"
        f'wan = "{cfg.wan}"\n'
    )
