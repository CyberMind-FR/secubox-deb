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

import os
import shutil
import tempfile
from pathlib import Path
from typing import Callable

ETAT_REL = "var/lib/secubox-profiles/allegement"
SITE = "secubox-etat"
GABARIT = Path("/usr/share/secubox/profiles/nginx/etat.conf")
RELAIS_PUR = ("# Écrit par secubox-profilectl (profil « distante », #3126 L5) : relais pur, aucun module monté ;\n"
              "# l'original est rendu par tout autre profil.\n"
              "modules = []\n")

Run = Callable[[list], tuple]


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
            "agg": racine / "etc/secubox/aggregator.toml", "etat": racine / ETAT_REL}


def _ote_etat(c: dict) -> None:
    lien = c["se"] / SITE
    if lien.is_symlink() or lien.exists():
        lien.unlink()
    (c["sa"] / SITE).unlink(missing_ok=True)


def _rendre(c: dict) -> None:
    """Rend les sites mis de côté et aggregator.toml, ôte la page d'état, puis efface la sauvegarde."""
    _ote_etat(c)
    sauves = c["etat"] / "sites-enabled"
    if sauves.is_dir():
        for p in sorted(sauves.iterdir()):
            cible = c["se"] / p.name
            if not (cible.exists() or cible.is_symlink()):
                shutil.move(str(p), str(cible))
    if (c["etat"] / "aggregator.toml").exists():
        shutil.copy2(c["etat"] / "aggregator.toml", c["agg"])
    elif (c["etat"] / "aggregator.absent").exists():
        c["agg"].unlink(missing_ok=True)
    shutil.rmtree(c["etat"], ignore_errors=True)


def appliquer(profile, *, racine: Path = Path("/"), gabarit: Path = GABARIT, run: Run) -> dict:
    c = _chemins(Path(racine))
    leger = getattr(profile, "front_web", None) == "etat"
    if not leger:
        if not c["etat"].exists():
            return {"ok": True, "action": "rien"}
        _rendre(c)
        rc, sortie = run(["nginx", "-t"])
        run(["systemctl", "reload-or-restart", "nginx.service"])
        run(["systemctl", "try-restart", "secubox-aggregator.service"])
        return {"ok": rc == 0, "action": "retablir", "nginx": (sortie or "")[-400:]}

    deja = (c["etat"] / "actif").exists()
    relais = getattr(profile, "agregateur", None) == "relais"
    if not deja:
        (c["etat"] / "sites-enabled").mkdir(parents=True, exist_ok=True)
        os.chmod(c["etat"], 0o700)
        for p in sorted(c["se"].iterdir()) if c["se"].is_dir() else []:
            if p.name != SITE:
                shutil.move(str(p), str(c["etat"] / "sites-enabled" / p.name))
        if relais:
            if c["agg"].exists():
                shutil.copy2(c["agg"], c["etat"] / "aggregator.toml")
            else:
                (c["etat"] / "aggregator.absent").touch()
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
    run(["systemctl", "reload-or-restart", "nginx.service"])
    if relais:
        run(["systemctl", "try-restart", "secubox-aggregator.service"])
    return {"ok": True, "action": "alleger", "deja": deja}
