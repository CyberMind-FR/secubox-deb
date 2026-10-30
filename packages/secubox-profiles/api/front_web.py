# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5 tâche 7 — front web réduit du profil léger « distante » (appelé en root par `secubox-profilectl apply`).

alleger   profil avec `front_web = "etat"` : chaque entrée de /etc/nginx/sites-enabled est MISE DE CÔTÉ (jamais effacée)
          dans ETAT_REL, le gabarit nginx `etat` (page d'état locale, LAN seulement) devient le seul site ; avec
          `agregateur = "relais"`, /etc/secubox/aggregator.toml est sauvegardé puis remplacé par un relais pur (aucun
          montage). `nginx -t` valide ; en cas d'échec, tout est rendu tel qu'avant et rien n'est rechargé.
retablir  tout autre profil, s'il reste un allègement : sites et aggregator.toml d'origine rendus, page d'état ôtée.
rien      sinon : un profil ordinaire ne touche jamais nginx ni l'agrégateur.

Idempotent : un second apply du profil léger ne déplace rien de plus et garde la sauvegarde d'origine (marqueur `actif`).
"""
from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Callable

ETAT_REL = "var/lib/secubox-profiles/allegement"
SITE = "secubox-etat"
GABARIT = Path("/usr/share/secubox/profiles/nginx/etat.conf")
RELAIS_PUR = ("# Écrit par secubox-profilectl (profil « distante », #3126 L5) : relais pur, aucun module monté ;\n"
              "# l'original est rendu par tout autre profil.\n"
              "modules = []\n")

ECOUTE_REL = "etc/nginx/secubox-etat-ecoute.conf"
# Réseaux du maillage et d'Auto-Load : jamais l'adresse d'écoute de la page (elle est pour le LAN de la box).
_TUNNELS = (ipaddress.ip_network("10.10.0.0/16"), ipaddress.ip_network("10.64.0.0/16"))

Run = Callable[[list], tuple]
log = logging.getLogger("secubox.profiles.front_web")


def ecoute(adresses: list) -> str:
    """Directive d'écoute de la page d'état : la première adresse IPv4 privée de la box hors tunnels (LAN) ; à défaut,
    la boucle locale seule. Jamais toutes les interfaces, jamais une adresse publique (R-L5-34 M1)."""
    for a in adresses:
        try:
            ip = ipaddress.ip_interface(a).ip
        except ValueError:
            continue
        if ip.version == 4 and ip.is_private and not ip.is_loopback and not ip.is_link_local \
                and not any(ip in n for n in _TUNNELS):
            return f"listen {ip}:80;\n"
    return "listen 127.0.0.1:80;\n"


def _adresses(run: Run) -> list:
    rc, sortie = run(["ip", "-o", "-4", "addr", "show", "scope", "global"])
    if rc != 0:
        return []
    out = []
    for ligne in (sortie or "").splitlines():
        champs = ligne.split()
        if "inet" in champs and champs.index("inet") + 1 < len(champs):
            out.append(champs[champs.index("inet") + 1])
    return out


def _ecrire(chemin: Path, texte: str, mode: int = 0o644) -> None:
    chemin.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=".sbx-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texte)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, chemin)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _chemins(racine: Path) -> dict:
    return {"se": racine / "etc/nginx/sites-enabled", "sa": racine / "etc/nginx/sites-available",
            "agg": racine / "etc/secubox/aggregator.toml", "etat": racine / ETAT_REL, "ecoute": racine / ECOUTE_REL}


def _ote_etat(c: dict) -> None:
    lien = c["se"] / SITE
    if lien.is_symlink() or lien.exists():
        lien.unlink()
    (c["sa"] / SITE).unlink(missing_ok=True)
    (c["ecoute"]).unlink(missing_ok=True)


def _rendre(c: dict) -> list:
    """Rend les sites mis de côté et aggregator.toml, ôte la page d'état et le marqueur. Rien n'est jamais écrasé : un
    site dont le nom a réapparu, ou un aggregator.toml modifié entre-temps (≠ relais pur), reste où il est et sa
    sauvegarde est GARDÉE (journalisée) ; la sauvegarde n'est effacée que vide. Rend la liste de ces restes."""
    _ote_etat(c)
    (c["etat"] / "actif").unlink(missing_ok=True)
    restes = []
    sauves = c["etat"] / "sites-enabled"
    if sauves.is_dir():
        for p in sorted(sauves.iterdir()):
            cible = c["se"] / p.name
            if cible.exists() or cible.is_symlink():
                restes.append(f"sites-enabled/{p.name}")
                log.warning("front web : %s a réapparu dans sites-enabled, la copie mise de côté reste dans %s", p.name, sauves)
            else:
                shutil.move(str(p), str(cible))
        if not any(sauves.iterdir()):
            sauves.rmdir()
    sauve_agg, absent = c["etat"] / "aggregator.toml", c["etat"] / "aggregator.absent"
    if sauve_agg.exists() or absent.exists():
        try:
            courant = c["agg"].read_text(encoding="utf-8")
        except FileNotFoundError:
            courant = None
        if courant not in (RELAIS_PUR, None):
            restes.append("aggregator.toml")
            log.warning("front web : aggregator.toml modifié pendant l'allègement, gardé ; l'original reste dans %s", sauve_agg)
        else:
            if sauve_agg.exists():
                shutil.copy2(sauve_agg, c["agg"])
                sauve_agg.unlink()
            else:
                c["agg"].unlink(missing_ok=True)
                absent.unlink()
    if c["etat"].is_dir() and not any(c["etat"].iterdir()):
        c["etat"].rmdir()
    return restes


def appliquer(profile, *, racine: Path = Path("/"), gabarit: Path = GABARIT, run: Run) -> dict:
    c = _chemins(Path(racine))
    leger = getattr(profile, "front_web", None) == "etat"
    if not leger:
        if not (c["etat"] / "actif").exists() and not (c["se"] / SITE).is_symlink():
            return {"ok": True, "action": "rien"}
        restes = _rendre(c)
        rc, sortie = run(["nginx", "-t"])
        run(["systemctl", "reload-or-restart", "nginx.service"])
        run(["systemctl", "try-restart", "secubox-aggregator.service"])
        return {"ok": rc == 0, "action": "retablir", "restes": restes, "nginx": (sortie or "")[-400:]}

    deja = (c["etat"] / "actif").exists()
    relais = getattr(profile, "agregateur", None) == "relais"
    if not deja:
        # Dossier 0755 : l'agent de pilotage y lit le marqueur `actif` ; les sites mis de côté restent en 0700.
        (c["etat"] / "sites-enabled").mkdir(parents=True, exist_ok=True)
        os.chmod(c["etat"], 0o755)
        os.chmod(c["etat"] / "sites-enabled", 0o700)
        for p in sorted(c["se"].iterdir()) if c["se"].is_dir() else []:
            if p.name != SITE:
                dest = c["etat"] / "sites-enabled" / p.name
                if dest.exists() or dest.is_symlink():   # reste d'un retour précédent : jamais écrasé
                    dest = dest.with_name(f"{p.name}.avant-{int(time.time())}")
                shutil.move(str(p), str(dest))
        if relais:
            if c["agg"].exists():
                shutil.copy2(c["agg"], c["etat"] / "aggregator.toml")
            else:
                (c["etat"] / "aggregator.absent").touch()
    _ecrire(c["ecoute"], ecoute(_adresses(run)))
    _ecrire(c["sa"] / SITE, Path(gabarit).read_text(encoding="utf-8"))
    lien = c["se"] / SITE
    if not lien.is_symlink():
        c["se"].mkdir(parents=True, exist_ok=True)
        lien.unlink(missing_ok=True)
        lien.symlink_to(f"../sites-available/{SITE}")
    if relais:
        _ecrire(c["agg"], RELAIS_PUR)
    rc, sortie = run(["nginx", "-t"])
    if rc != 0:
        if not deja:
            _rendre(c)
        return {"ok": False, "action": "alleger", "nginx": (sortie or "")[-400:]}
    (c["etat"] / "actif").touch()
    os.chmod(c["etat"] / "actif", 0o644)   # marqueur lu par l'agent : posé SEULEMENT après nginx -t (R-L5-34)
    run(["systemctl", "reload-or-restart", "nginx.service"])
    if relais:
        run(["systemctl", "try-restart", "secubox-aggregator.service"])
    return {"ok": True, "action": "alleger", "deja": deja}
