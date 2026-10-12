# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Noms et services annoncés par Bonjour/mDNS (#2440).

ARP ne donne aucun nom ; un appareil Bonjour annonce le sien et ses services (impression, AirPlay, partage…). Une seule passe
`avahi-browse -a -r -t -p` par fenêtre de cache, regroupée par adresse IPv4. Tout échec (binaire absent, délai, sortie illisible) rend
le dernier résultat connu : la découverte ne dépend jamais de Bonjour. Les noms sont du texte brut — l'échappement est affaire de l'affichage."""
from __future__ import annotations

import re
import shutil
import subprocess
import time

_TTL = 120
_DELAI = 12
_CACHE: dict = {"at": 0.0, "data": {}}

# type de service -> libellé affiché ; un type absent ici (et `_workstation`, `_device-info`…) est gardé dans `types` mais pas affiché.
_LIBELLES = {
    "_ipp._tcp": "Impression", "_ipps._tcp": "Impression", "_printer._tcp": "Impression", "_pdl-datastream._tcp": "Impression",
    "_scanner._tcp": "Numériseur", "_uscan._tcp": "Numériseur",
    "_airplay._tcp": "AirPlay", "_raop._tcp": "AirPlay audio", "_googlecast._tcp": "Chromecast", "_spotify-connect._tcp": "Spotify Connect",
    "_hap._tcp": "HomeKit", "_homekit._tcp": "HomeKit", "_matter._tcp": "Matter", "_companion-link._tcp": "Apple",
    "_smb._tcp": "Partage Windows", "_afpovertcp._tcp": "Partage Apple", "_nfs._tcp": "Partage NFS",
    "_ssh._tcp": "SSH", "_sftp-ssh._tcp": "SFTP", "_http._tcp": "Web", "_https._tcp": "Web", "_rfb._tcp": "Bureau à distance",
    "_secubox._tcp": "SecuBox",
}
_OCTAL = re.compile(r"\\(\d{3})")


def _decoder(s: str) -> str:
    """avahi échappe en décimal à trois chiffres (\\032 = espace)."""
    return _OCTAL.sub(lambda m: chr(int(m.group(1))), s)


def parse_browse(texte: str) -> dict:
    """{ip: {name, host, services[], types[]}} pour les adresses IPv4 résolues ('=' lignes)."""
    out: dict = {}
    for ligne in (texte or "").splitlines():
        if not ligne.startswith("="):
            continue
        p = ligne.split(";")
        if len(p) < 9 or p[2] != "IPv4" or not p[7]:
            continue
        ip, type_ = p[7], p[4].strip()
        e = out.setdefault(ip, {"name": "", "host": "", "services": [], "types": []})
        nom = _decoder(p[3]).strip()
        if nom and not e["name"]:
            e["name"] = nom
        hote = p[6].split(".", 1)[0].lower()
        if hote and not e["host"]:
            e["host"] = hote
        if type_ not in e["types"]:
            e["types"].append(type_)
        lib = _LIBELLES.get(type_)
        if lib and lib not in e["services"]:
            e["services"].append(lib)
    return out


def _lancer() -> str:
    if not shutil.which("avahi-browse"):
        return ""
    return subprocess.run(["avahi-browse", "-a", "-r", "-t", "-p"], capture_output=True, text=True, timeout=_DELAI).stdout or ""


def snapshot() -> dict:
    """Résultat en cache (120 s) ; un échec rend le dernier résultat connu."""
    now = time.monotonic()
    if _CACHE["at"] and now - _CACHE["at"] < _TTL:
        return _CACHE["data"]
    _CACHE["at"] = now
    try:
        _CACHE["data"] = parse_browse(_lancer())
    except Exception:  # noqa: BLE001 - Bonjour est un bonus, jamais une dépendance
        pass
    return _CACHE["data"]
