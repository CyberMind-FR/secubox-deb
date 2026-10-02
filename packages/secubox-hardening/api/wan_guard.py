# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: hardening — garde des ports de backend (#1306)
CyberMind — https://cybermind.fr

Lit la règle livrée (/etc/nftables.d/secubox-wan-guard.nft) et les sockets en
écoute (ss, sans privilège) : ports gardés, ports de backend encore exposés.
La vérification que la table est chargée relève de root (`hardeningctl wan-guard`).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

GARDE_NFT = Path("/etc/nftables.d/secubox-wan-guard.nft")
# Frontaux voulus côté LAN/WAN : jamais signalés comme exposés.
FRONTAUX = {22, 80, 443, 9443}

_RE_PORTS = re.compile(r'iifname\s+"(?P<iface>[^"]+)"\s+tcp\s+dport\s+\{(?P<ports>[^}]*)\}')


def ports_gardes(texte: str) -> tuple[str, list[int]]:
    """(interface, ports) de la règle de garde ; ('', []) si absente."""
    for ligne in texte.splitlines():
        if ligne.lstrip().startswith("#"):
            continue
        m = _RE_PORTS.search(ligne)
        if m:
            ports = sorted(int(p) for p in re.findall(r"\d+", m.group("ports")))
            return m.group("iface"), ports
    return "", []


def ports_en_ecoute(sortie_ss: str) -> dict[int, str]:
    """Ports TCP écoutant hors boucle locale : {port: adresse}."""
    res: dict[int, str] = {}
    for ligne in sortie_ss.splitlines():
        cols = ligne.split()
        if len(cols) < 4:
            continue
        local = cols[3]
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        addr = addr.strip("[]")
        if addr.startswith("127.") or addr in ("::1",):
            continue
        res.setdefault(int(port), addr)
    return res


def joignable_depuis_lan(addr: str) -> bool:
    """Écoute atteignable par eth2 : toutes adresses, ou l'IP LAN. Pas les tunnels (10.x)."""
    return addr in ("0.0.0.0", "*", "::") or addr.startswith("*%") or addr.startswith("192.168.1.")


def etat() -> dict:
    try:
        texte = GARDE_NFT.read_text()
    except OSError:
        texte = ""
    iface, gardes = ports_gardes(texte)
    try:
        ss = subprocess.run(["ss", "-tlnH"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        ss = ""
    ecoute = ports_en_ecoute(ss)
    expose = {p: a for p, a in sorted(ecoute.items()) if p not in gardes and p not in FRONTAUX and joignable_depuis_lan(a)}
    return {
        "livree": bool(gardes),
        "interface": iface,
        "ports_gardes": gardes,
        "ports_gardes_en_ecoute": [p for p in gardes if p in ecoute],
        "ports_non_gardes": [{"port": p, "adresse": a} for p, a in expose.items()],
    }
