# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: freebox :: maillage distant (#3742)
CyberMind — https://cybermind.fr

Un nœud du maillage placé hors du LAN (autre maison, derrière une autre box) appelle le rendez-vous `wg-mesh` par son point
d'accès public. Ce module rassemble :
  - la lecture de l'annonce publique déclarée dans /etc/secubox/p2p.toml (`[wireguard] public_endpoint`, `listen_port`) ;
  - le contrôle périodique de l'IPv6 fixe du WAN (présente, et égale à l'AAAA publiée s'il en existe une), écrit dans un
    fichier d'état lu par l'API (le service n'a pas accès au netlink : c'est l'unité du minuteur qui relève les adresses).
Aucune modification DNS : aucun module ne publie l'AAAA proprement aujourd'hui, l'écart est seulement signalé.
"""
import ipaddress
import json
import os
import socket
import subprocess
import time
import tomllib

CHEMIN_P2P = os.environ.get("SECUBOX_P2P_TOML", "/etc/secubox/p2p.toml")
CHEMIN_CONF = os.environ.get("SECUBOX_FREEBOX_TOML", "/etc/secubox/freebox.toml")
CHEMIN_CONTROLE = os.environ.get("SECUBOX_FREEBOX_CONTROLE", "/var/lib/secubox/freebox/maillage-controle.json")
PORT_DEFAUT = 51822
# Interfaces qui ne sont jamais le WAN : tunnels et ponts internes.
_PAS_WAN = ("lo", "wg", "br-lxc", "lxc", "eye", "veth", "docker", "tor")


def _lire_toml(chemin):
    try:
        with open(chemin, "rb") as f:
            return tomllib.load(f) or {}
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def annonce(chemin_p2p=None):
    """{"public_endpoint", "hote", "port"} déclarés par p2p.toml, ou None si aucune annonce publique (ce nœud n'est pas un rendez-vous)."""
    wg = _lire_toml(chemin_p2p or CHEMIN_P2P).get("wireguard") or {}
    ep = str(wg.get("public_endpoint") or "").strip()
    if not ep:
        return None
    hote, _, port = ep.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        return None
    hote = hote.strip("[]")
    if not hote or not 1 <= port <= 65535:
        return None
    try:
        lp = int(wg.get("listen_port") or port)
    except (TypeError, ValueError):
        lp = port
    return {"public_endpoint": ep, "hote": hote, "port": port, "port_local": lp}


def ipv6_configuree(chemin_conf=None):
    """IPv6 fixe déclarée (`[maillage] ipv6_fixe` de /etc/secubox/freebox.toml), validée, ou ""."""
    v = str((_lire_toml(chemin_conf or CHEMIN_CONF).get("maillage") or {}).get("ipv6_fixe") or "").split("/")[0].strip()
    try:
        a = ipaddress.IPv6Address(v)
    except ValueError:
        return ""
    return str(a) if a.is_global else ""


def ipv6_fixes(doc_ip):
    """Adresses IPv6 globales STATIQUES (durée de vie illimitée, ni dynamiques ni temporaires) d'après `ip -j -6 addr show scope global`."""
    sortie = []
    for iface in doc_ip if isinstance(doc_ip, list) else []:
        nom = str(iface.get("ifname") or "")
        if not nom or nom.startswith(_PAS_WAN):
            continue
        for a in iface.get("addr_info") or []:
            if a.get("family") != "inet6" or a.get("scope") != "global":
                continue
            if a.get("dynamic") or a.get("temporary") or a.get("mngtmpaddr") or a.get("deprecated"):
                continue
            if a.get("valid_life_time", 4294967295) != 4294967295:
                continue
            try:
                ad = ipaddress.IPv6Address(a.get("local") or "")
            except ValueError:
                continue
            if ad.is_global:
                sortie.append({"interface": nom, "adresse": str(ad)})
    return sortie


def controler(fixes, aaaa, attendue="", horloge=time.time):
    """Verdict du contrôle : l'IPv6 attendue (déclarée, sinon la première fixe) est présente, et égale à l'AAAA publiée si une existe."""
    adresses = [f["adresse"] for f in fixes]
    attendue = attendue or (adresses[0] if adresses else "")
    aaaa = sorted({str(ipaddress.IPv6Address(x)) for x in aaaa or []})
    alertes = []
    presente = bool(attendue) and attendue in adresses
    if not attendue:
        alertes.append("Aucune IPv6 fixe sur le WAN : les nœuds distants ne joindront le maillage qu'en IPv4.")
    elif not presente:
        alertes.append("L'IPv6 fixe %s n'est plus présente sur le WAN." % attendue)
    if aaaa and attendue and attendue not in aaaa:
        alertes.append("L'AAAA publiée (%s) ne correspond pas à l'IPv6 fixe %s." % (", ".join(aaaa), attendue))
    return {"ipv6_attendue": attendue, "presente": presente, "ipv6_fixes": fixes, "aaaa": aaaa,
            "aaaa_publiee": bool(aaaa), "aaaa_conforme": (attendue in aaaa) if aaaa else None,
            "conforme": not alertes, "alertes": alertes, "verifie_le": int(horloge())}


def _ip_json():
    r = subprocess.run(["ip", "-j", "-6", "addr", "show", "scope", "global"], check=True, timeout=10, capture_output=True, text=True)
    return json.loads(r.stdout or "[]")


def _aaaa(nom):
    try:
        return [i[4][0] for i in socket.getaddrinfo(nom, None, socket.AF_INET6, socket.SOCK_DGRAM)]
    except (socket.gaierror, UnicodeError):
        return []


def relever(chemin_p2p=None, chemin_conf=None, ip_json=_ip_json, resoudre=_aaaa, horloge=time.time):
    """Relève les adresses et l'AAAA, rend le verdict (rien n'est modifié)."""
    an = annonce(chemin_p2p)
    try:
        doc = ip_json()
    except (OSError, subprocess.SubprocessError, ValueError):
        doc = []
    hote = (an or {}).get("hote", "")
    try:
        ipaddress.ip_address(hote)
        aaaa = []                          # annonce par adresse littérale : pas de nom à résoudre
    except ValueError:
        aaaa = resoudre(hote) if hote else []
    r = controler(ipv6_fixes(doc), aaaa, ipv6_configuree(chemin_conf), horloge)
    r["annonce"] = an
    return r


def ecrire_controle(etat, chemin=None):
    chemin = chemin or CHEMIN_CONTROLE
    tmp = chemin + ".tmp"
    with open(tmp, "w") as f:
        json.dump(etat, f, ensure_ascii=False)
    os.replace(tmp, chemin)


def lire_controle(chemin=None):
    try:
        with open(chemin or CHEMIN_CONTROLE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
