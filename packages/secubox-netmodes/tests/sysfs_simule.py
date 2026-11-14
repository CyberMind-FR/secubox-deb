# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Arborescences /sys/class/net simulées (#3688), d'après ce que le noyau expose réellement :

- MOCHAbin : eth0 (SFP), eth1 (conduit du switch : dossier `dsa/`), eth2 (WAN), lan0..lan3 (ports, DEVTYPE=dsa), br-lan ;
- ESPRESSObin v7 : eth0 (conduit), wan, lan0, lan1 (ports DEVTYPE=dsa) ;
- Raspberry Pi 4 (relevé sur gk7 le 2026-11-12) : eth0 (lien device vers fd580000.ethernet), wlan0 (DEVTYPE=wlan, lien device
  vers mmc0:0001:1), et les interfaces virtuelles br-lxc, br0, wg-mesh, lo (sans lien device).
Toutes ont aussi les virtuelles de la box (lo, br-lxc, wg-mesh)."""
from __future__ import annotations

from pathlib import Path

VIRTUELLES = {"lo": ("772", None), "br-lxc": ("1", "bridge"), "wg-mesh": ("65534", "wireguard")}


def _iface(racine: Path, nom: str, *, type_="1", devtype=None, device=True, dsa=False, wifi=False, etat="up",
           porteuse="1", vitesse="1000"):
    d = racine / "class" / "net" / nom
    d.mkdir(parents=True)
    (d / "type").write_text(type_ + "\n")
    (d / "operstate").write_text(etat + "\n")
    if porteuse is not None:
        (d / "carrier").write_text(porteuse + "\n")
    if vitesse is not None:
        (d / "speed").write_text(vitesse + "\n")
    (d / "uevent").write_text(f"INTERFACE={nom}\nIFINDEX=2\n" + (f"DEVTYPE={devtype}\n" if devtype else ""))
    if device:
        cible = racine / "devices" / ("dev-" + nom)
        cible.mkdir(parents=True)
        (d / "device").symlink_to(cible)
    if dsa:
        (d / "dsa").mkdir()
        (d / "dsa" / "tagging").write_text("mv88e6xxx\n")
    if wifi:
        (d / "wireless").mkdir()
    if devtype == "bridge":
        (d / "bridge").mkdir()


def _virtuelles(racine: Path, extra=()):
    for nom, (t, dt) in VIRTUELLES.items():
        _iface(racine, nom, type_=t, devtype=dt, device=False, etat="unknown", porteuse="1", vitesse=None)
    for nom in extra:
        _iface(racine, nom, devtype="bridge", device=False, etat="down", porteuse="0", vitesse=None)


def mochabin(racine: Path) -> Path:
    _iface(racine, "eth0", porteuse="0", vitesse="-1", etat="down")            # SFP+ sans module
    _iface(racine, "eth1", dsa=True, vitesse="2500")
    _iface(racine, "eth2")
    for i in range(4):
        _iface(racine, f"lan{i}", devtype="dsa", porteuse="1" if i in (0, 3) else "0")
    _virtuelles(racine, extra=("br-lan",))
    return racine / "class" / "net"


def espressobin(racine: Path) -> Path:
    _iface(racine, "eth0", dsa=True)
    for nom in ("wan", "lan0", "lan1"):
        _iface(racine, nom, devtype="dsa")
    _virtuelles(racine)
    return racine / "class" / "net"


def rpi(racine: Path, *, br_lan=False) -> Path:
    _iface(racine, "eth0")
    _iface(racine, "wlan0", devtype="wlan", wifi=True, etat="down", porteuse=None, vitesse=None)
    _virtuelles(racine, extra=("br0",) + (("br-lan",) if br_lan else ()))
    return racine / "class" / "net"
