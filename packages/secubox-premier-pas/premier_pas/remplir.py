# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Premier Pas — REMPLIR le profil, commun à toutes les faces (#1522)
CyberMind — https://cybermind.fr

Le kiosque (via l'API) et la console appellent CE module : une seule manière
d'enregistrer une étape, de hacher le mot de passe, de demander l'application.
Deux faces qui auraient chacune leur copie finiraient par diverger — c'est
précisément ce que la maquette interdit (« un moteur, un profil »).
"""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any, Dict

from . import moteur as M
from . import profil as P

def dossier() -> Path:
    # Lu à chaque appel : les tests (et un opérateur) peuvent le déplacer.
    return Path(os.environ.get("PREMIER_PAS_DIR", "/var/lib/secubox/premier-pas"))
MDP_MIN = 12
MDP_FAIBLES = {"secubox", "admin", "password", "motdepasse", "azertyuiop", "0123456789ab"}


class Refus(ValueError):
    """Une saisie refusée : le message se montre tel quel à la personne."""


def profil_path() -> Path:
    return dossier() / "profil.toml"


def demande_path() -> Path:
    return dossier() / "demande"


def lit() -> Dict[str, Any]:
    try:
        return tomllib.loads(profil_path().read_text())
    except (OSError, ValueError):
        return {}


def _toml_val(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def ecrit(profil: Dict[str, Any]) -> None:
    lignes = ["# Profil Premier Pas — rempli par l'assistant (#1522)"]
    for section in ("box", "admin", "reseau", "services", "maillage", "apt"):
        bloc = profil.get(section)
        if not bloc:
            continue
        lignes += ["", f"[{section}]"] + [f"{k} = {_toml_val(v)}" for k, v in bloc.items() if v is not None]
    dossier().mkdir(parents=True, exist_ok=True)
    tmp = profil_path().with_suffix(".tmp")
    tmp.write_text("\n".join(lignes) + "\n")
    os.chmod(tmp, 0o640)
    os.replace(tmp, profil_path())


def vue(profil: Dict[str, Any]) -> Dict[str, Any]:
    """Le profil montrable : ni empreinte du mot de passe, ni jeton du maillage."""
    v = {k: dict(b) for k, b in profil.items() if isinstance(b, dict)}
    if "admin" in v and "mot_de_passe" in v["admin"]:
        v["admin"]["mot_de_passe"] = "défini" if v["admin"]["mot_de_passe"] != "demander" else "demander"
    if "maillage" in v and v["maillage"].get("jeton"):
        v["maillage"]["jeton"] = "défini"
    return v


def etat() -> Dict[str, Any]:
    profil = lit()
    ex = P.examine(profil)
    try:
        moteur = json.loads(M.ETAT.read_text())
    except (OSError, ValueError):
        moteur = {}
    etapes = []
    for e in P.ETAPES:
        statut = "erreur" if e in ex.erreurs else ("a_faire" if e in ex.manquantes else "pret")
        etapes.append({"id": e, "libelle": P.LIBELLES[e], "statut": statut, "motif": ex.erreurs.get(e)})
    return {"fait": M.MARQUEUR.exists(), "complet": ex.complet, "reprendre": ex.premiere_etape,
            "etapes": etapes, "profil": vue(profil), "moteur": moteur,
            "demande_en_cours": demande_path().exists()}


CHAMPS = {
    "bienvenue": ("box", {"langue", "clavier"}),
    "nom": ("box", {"nom"}),
    "horloge": ("box", {"fuseau", "ntp"}),
    "reseau": ("reseau", {"mode", "domaine"}),
    "services": ("services", {"profil"}),
    "maillage": ("maillage", {"mode", "rejoindre", "jeton"}),
    "majs": ("apt", {"auto", "heure"}),
}


def enregistre(etape: str, valeurs: Dict[str, Any]) -> Dict[str, Any]:
    """Enregistre UNE étape et rend l'état à jour. Lève Refus sur une saisie
    refusée ; une valeur fausse mais bien formée apparaît dans l'examen, à
    l'étape où on la corrige."""
    if M.MARQUEUR.exists():
        raise Refus("Cette box est déjà configurée : l'assistant est fermé.")
    profil = lit()
    if etape == "admin":
        mdp, conf = str(valeurs.get("mot_de_passe", "")), str(valeurs.get("confirmation", ""))
        if len(mdp) < MDP_MIN:
            raise Refus(f"Au moins {MDP_MIN} caractères.")
        if mdp != conf:
            raise Refus("Les deux saisies diffèrent.")
        if mdp.lower() in MDP_FAIBLES or re.fullmatch(r"(.)\1+", mdp):
            raise Refus("Ce mot de passe est trop facile à deviner.")
        from argon2 import PasswordHasher  # noqa: PLC0415
        profil.setdefault("admin", {})["mot_de_passe"] = PasswordHasher().hash(mdp)
        profil["admin"]["totp"] = "enroler"
    elif etape in CHAMPS:
        section, permis = CHAMPS[etape]
        inconnus = set(valeurs) - permis
        if inconnus:
            raise Refus(f"Champs inconnus : {', '.join(sorted(inconnus))}")
        bloc = profil.setdefault(section, {})
        for k, v in valeurs.items():
            if isinstance(v, str):
                v = v.strip()
                if k in ("nom", "domaine"):
                    v = v.lower()
            bloc[k] = v
        if section == "reseau" and bloc.get("mode") == "lan":
            bloc.pop("domaine", None)
        if section == "maillage" and bloc.get("mode") != "rejoindre":
            bloc.pop("rejoindre", None)
            bloc.pop("jeton", None)
    else:
        raise Refus("Étape inconnue.")
    ecrit(profil)
    return etat()


def demande_appliquer() -> None:
    if M.MARQUEUR.exists():
        raise Refus("Cette box est déjà configurée : l'assistant est fermé.")
    ex = P.examine(lit())
    if not ex.complet:
        raise Refus(f"Profil incomplet : reprendre à « {P.LIBELLES[ex.premiere_etape]} ».")
    dossier().mkdir(parents=True, exist_ok=True)
    demande_path().write_text("appliquer\n")
