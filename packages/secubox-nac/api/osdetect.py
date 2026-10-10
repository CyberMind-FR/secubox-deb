# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-nac — détection passive de l'OS et du type fin d'un appareil (#2236).

Fonctions PURES : la preuve entre en argument (`DeviceEvidence`), la conclusion sort avec sa source (`os_source`). Aucune réponse sans preuve : sans
indice, `os`, `os_source` et `device_subtype` valent `None`. Le fabricant (OUI) seul ne donne JAMAIS d'OS — un OUI Apple peut être un Mac, un iPhone ou
une Apple TV — et une adresse MAC aléatoire (bit « localement administré ») n'est pas typée par son fabricant, qui ne signifie rien.

Force des preuves, de la plus forte à la plus faible : classe vendeur DHCP > User-Agent > domaines DNS de connectivité > nom de l'appareil > empreinte
du NAC (OpenWrt, SecuBox). Les services mDNS ne servent qu'au type fin.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# Conteneurs LXC : plage du pont br-lxc et OUI attribué aux conteneurs.
_LXC_OUI = "00:16:3e"
_LXC_IP = re.compile(r"^10\.100\.\d{1,3}\.\d{1,3}$")


@dataclass
class DeviceEvidence:
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    mac: Optional[str] = None
    dhcp_vendor_class: Optional[str] = None
    user_agents: list = field(default_factory=list)
    dns_domains: list = field(default_factory=list)
    mdns: list = field(default_factory=list)
    is_openwrt: bool = False
    is_secubox: bool = False


def mac_aleatoire(mac: Optional[str]) -> bool:
    """Bit 0x02 du premier octet : adresse administrée localement (confidentialité iOS/Android/Windows)."""
    try:
        return bool(int(str(mac).split(":")[0], 16) & 0x02) if mac and ":" in str(mac) else False
    except ValueError:
        return False


def est_conteneur_lxc(mac: str, ip: str, interface: str) -> bool:
    return bool((mac or "").lower().startswith(_LXC_OUI) or _LXC_IP.match(ip or "") or "lxc" in (interface or "").lower())


# ── Classe vendeur DHCP (option 60) ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def _dhcp(vc: str):
    m = re.match(r"android-dhcp-(\d+)", vc, re.I)
    if m:
        return "Android " + m.group(1)
    if re.match(r"MSFT ", vc, re.I):
        return "Windows"
    if re.match(r"udhcp", vc, re.I):
        return "Linux"
    return None


# ── User-Agent ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _ua(ua: str):
    """(os, sous-type) d'un User-Agent. Ordre : les plus spécifiques d'abord (iPhone avant « Mac OS X »)."""
    m = re.search(r"iPhone OS (\d+)", ua)
    if m:
        return "iOS " + m.group(1), "smartphone"
    m = re.search(r"CPU OS (\d+)[_\d]* like Mac OS X", ua)
    if m and "iPad" in ua:
        return "iPadOS " + m.group(1), "tablette"
    m = re.search(r"Android (\d+)", ua)
    if m:
        return "Android " + m.group(1), ("smartphone" if "Mobile" in ua else None)
    if "Windows NT 10.0" in ua:
        return "Windows 10/11", None
    if "Windows NT" in ua:
        return "Windows", None
    if "CrOS" in ua:
        return "ChromeOS", "ordinateur"
    if "Macintosh" in ua or "Mac OS X" in ua:
        return "macOS", "ordinateur"
    if "Linux" in ua or "X11" in ua:
        return "Linux", None
    return None


# ── Domaines DNS de connectivité (mêmes règles que la page /appareil/) ────────────────────────────────────────────────────────────────────────
_DNS = [
    (re.compile(r"(^|\.)connectivitycheck\.gstatic\.com$|(^|\.)android\.clients\.google\.com$|(^|\.)play\.googleapis\.com$", re.I), "Android", None),
    (re.compile(r"(^|\.)captive\.apple\.com$|(^|\.)gsp\d*-ssl\.ls\.apple\.com$|(^|\.)mzstatic\.com$", re.I), "Apple (iOS / macOS)", None),
    (re.compile(r"(^|\.)msftconnecttest\.com$|(^|\.)windowsupdate\.com$|(^|\.)msftncsi\.com$", re.I), "Windows", None),
    (re.compile(r"(^|\.)samsungcloudsolution\.com$|(^|\.)samsungotn\.net$|(^|\.)samsungads\.com$", re.I), "Tizen (Samsung)", "télévision"),
    (re.compile(r"(^|\.)lgtvsdp\.com$|(^|\.)lgappstv\.com$", re.I), "webOS (LG)", "télévision"),
    (re.compile(r"(^|\.)ping\.archlinux\.org$|(^|\.)deb\.debian\.org$|(^|\.)archive\.ubuntu\.com$", re.I), "Linux", None),
]

# Suffixes de domaines de connectivité (pré-filtre SQL du fournisseur DNS) et règle exacte : un domaine n'en est un que s'il EST le suffixe ou en est un
# sous-domaine (« evilmsftconnecttest.com » n'en est pas un).
DNS_SUFFIXES = ("connectivitycheck.gstatic.com", "android.clients.google.com", "play.googleapis.com", "captive.apple.com", "mzstatic.com",
                "msftconnecttest.com", "windowsupdate.com", "msftncsi.com", "samsungcloudsolution.com", "samsungotn.net", "samsungads.com",
                "lgtvsdp.com", "lgappstv.com", "ping.archlinux.org", "deb.debian.org", "archive.ubuntu.com")


def domaine_de_connectivite(domaine: str) -> bool:
    d = (domaine or "").lower().rstrip(".")
    return any(d == s or d.endswith("." + s) for s in DNS_SUFFIXES) or bool(re.search(r"(^|\.)gsp\d*-ssl\.ls\.apple\.com$", d))


# ── Nom de l'appareil : (motif, OS, sous-type) ───────────────────────────────────────────────────────────────────────────────────────────────
_NOM = [
    (re.compile(r"iphone|ipod", re.I), "iOS", "smartphone"),
    (re.compile(r"ipad", re.I), "iPadOS", "tablette"),
    (re.compile(r"macbook|imac|mac-?mini|^mbp", re.I), "macOS", "ordinateur"),
    (re.compile(r"redmi|^poco|pixel[-_ ]?\d", re.I), "Android", "smartphone"),
    (re.compile(r"^android|galaxy", re.I), "Android", None),
    (re.compile(r"^desktop-|^laptop-|^win(dows)?[-_]?", re.I), "Windows", "ordinateur"),
    (re.compile(r"raspberrypi|ubuntu|debian|fedora|archlinux", re.I), "Linux", None),
    (re.compile(r"tizen|samsung.*(tv|qled)", re.I), "Tizen (Samsung)", "télévision"),
    (re.compile(r"webos|lgwebos", re.I), "webOS (LG)", "télévision"),
    (re.compile(r"chromecast", re.I), "Google Cast", "streaming"),
    (re.compile(r"^roku", re.I), "Roku OS", "streaming"),
    (re.compile(r"openwrt", re.I), "OpenWrt (Linux)", "routeur"),
]

# Type fin sans OS : (motif du nom, sous-type)
_SOUS_TYPE_NOM = [
    (re.compile(r"chromecast|firetv|fire-?stick|appletv|apple-tv", re.I), "streaming"),
    (re.compile(r"laserjet|officejet|deskjet|printer|imprimante|epson|brother", re.I), "imprimante"),
    (re.compile(r"^esp[-_]|^shelly|^tasmota|^sonoff|tuya", re.I), "objet connecté"),
    (re.compile(r"freebox-?player|^player-", re.I), "décodeur"),
    (re.compile(r"cam(era)?[-_]|ipcam|^reolink|^hikvision", re.I), "caméra"),
    (re.compile(r"sonos|echo|homepod|google-home|nest-?(mini|audio)", re.I), "enceinte"),
    (re.compile(r"playstation|^ps[345]|xbox|nintendo|switch-", re.I), "console de jeu"),
]
_SOUS_TYPE_MDNS = [
    (re.compile(r"_ipp\._tcp|_printer\._tcp|_pdl-datastream", re.I), "imprimante"),
    (re.compile(r"_airplay\._tcp|_raop\._tcp|_googlecast\._tcp", re.I), "récepteur multimédia"),
    (re.compile(r"_hap\._tcp|_homekit\._tcp", re.I), "objet connecté"),
]


def _premier(regles, valeurs):
    for v in valeurs:
        for r in regles:
            if r[0].search(v):
                return v, r
    return None, None


def detecter(ev: DeviceEvidence) -> dict:
    """Rend {os, os_source, device_subtype}. Chaque champ non déterminé vaut None ; `os` s'accompagne TOUJOURS de `os_source`."""
    os_, source, sous = None, None, None

    if ev.dhcp_vendor_class:
        o = _dhcp(ev.dhcp_vendor_class)
        if o:
            os_, source = o, "dhcp-vendor-class:" + ev.dhcp_vendor_class
    if os_ is None:
        for ua in ev.user_agents or []:
            r = _ua(ua or "")
            if r:
                os_, source, sous = r[0], "user-agent:" + (ua or "")[:80], r[1]
                break
    if os_ is None:
        dom, r = _premier(_DNS, ev.dns_domains or [])
        if r:
            os_, source, sous = r[1], "dns:" + dom, r[2]
    if os_ is None and ev.hostname:
        _, r = _premier(_NOM, [ev.hostname])
        if r:
            os_, source, sous = r[1], "hostname:" + ev.hostname, r[2]
    if os_ is None:
        if ev.is_openwrt:
            os_, source, sous = "OpenWrt (Linux)", "empreinte-nac:openwrt", "routeur"
        elif ev.is_secubox:
            os_, source = "Linux (SecuBox)", "empreinte-nac:secubox"

    if sous is None and ev.hostname:
        _, r = _premier(_SOUS_TYPE_NOM, [ev.hostname])
        if r:
            sous = r[1]
    if sous is None and ev.mdns:
        _, r = _premier(_SOUS_TYPE_MDNS, ev.mdns)
        if r:
            sous = r[1]
    return {"os": os_, "os_source": source, "device_subtype": sous}
