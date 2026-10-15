# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: Premier Pas — une box est-elle DÉJÀ EN SERVICE ? (#1522, #2727)

Cette décision vivait en script inline dans le `postinst`, où elle ne se testait pas, et elle se rejouait à CHAQUE configuration du paquet :
une mise à jour en plein parcours fermait l'assistant. Constaté sur un RPi400 (2026-10-15) : `fait: true`, profil complet, moteur vide.

DEUX QUESTIONS, qu'il ne faut pas confondre.
- La box est-elle EN SERVICE ? Un compte admin a servi : mot de passe choisi, ou TOTP déjà enrôlé (vu sur l'amd64 : TOTP enrôlé, mot de passe par
  défaut jamais changé). C'est la règle de l'ancien postinst, inchangée.
- Un assistant est-il EN COURS ? Un profil est en train d'être rempli (`profil.toml` non vide). Une box peut être les deux : l'admin a servi PENDANT
  la préparation. Alors l'assistant n'est pas fini, et le fermer d'office enferme la personne dehors. Un profil qu'on ne sait pas lire compte comme
  « en cours » : dans le doute on ne ferme pas.

Le marqueur n'est posé que pour une box en service SANS assistant en cours.
"""
from __future__ import annotations

import json
import os
import sys
import tomllib
from pathlib import Path
from typing import Optional


def _users() -> Path:
    return Path(os.environ.get("SECUBOX_USERS_JSON", "/etc/secubox/users.json"))


def _dossier() -> Path:
    return Path(os.environ.get("PREMIER_PAS_DIR", "/var/lib/secubox/premier-pas"))


def box_en_service(users: Optional[Path] = None) -> bool:
    try:
        d = json.loads((users or _users()).read_text())
        admin = [u for u in d.get("users", []) if u.get("username") == "admin"]
    except (OSError, ValueError, AttributeError, TypeError):
        return False
    a = admin[0] if admin else {}
    return bool(a.get("password_hash") and (not a.get("must_change_password") or a.get("totp")))


def assistant_en_cours(dossier: Optional[Path] = None) -> bool:
    f = (dossier or _dossier()) / "profil.toml"
    try:
        texte = f.read_text()
    except OSError:
        return False
    if not texte.strip():
        return False
    try:
        return bool(tomllib.loads(texte))
    except ValueError:
        return True


def doit_marquer(users: Optional[Path] = None, dossier: Optional[Path] = None) -> bool:
    return box_en_service(users) and not assistant_en_cours(dossier)


if __name__ == "__main__":
    sys.exit(0 if doit_marquer() else 1)
