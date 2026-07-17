# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: users — expurgation des secrets avant sortie du processus
CyberMind — https://cybermind.fr

Module séparé, sans dépendance : `api.main` lit la config au niveau module, donc
l'importer exige de pouvoir lire /etc/secubox/secubox.conf. Une règle de sécurité
doit rester testable sans privilèges — d'où ce fichier, importable seul.
"""
from __future__ import annotations

# Jamais renvoyés à un client. `password_hash` est une primitive d'attaque
# hors-ligne ; `provision_results` peut contenir des retours de service bruts.
SECRET_KEYS = ("password_hash", "provision_results")

# Dans le sous-dict `totp` : `secret` permet à lui seul de forger des codes à
# 6 chiffres indéfiniment (contournement complet du MFA) ; `backup_codes` porte
# les hashes argon2id des codes de secours ; `last_step` est un détail interne.
TOTP_SECRET_KEYS = ("secret", "backup_codes", "last_step")


def redact_user(user: dict) -> dict:
    """Copie d'un enregistrement utilisateur sans aucun secret.

    users.json contient le hash argon2id du mot de passe, le SECRET TOTP et les
    hashes des codes de secours. Aucun n'a d'usage côté client.

    Toute route renvoyant un utilisateur DOIT passer par ici. Ces routes sont
    gardées par `require_jwt` — n'importe quel compte authentifié, pas seulement
    un admin — donc un enregistrement non expurgé transforme le compte le moins
    privilégié en moissonneuse d'identifiants de tous les autres.

    `totp` est conservé mais réduit à ses métadonnées non secrètes, et sa
    PRÉSENCE est préservée : la webui décide d'afficher le badge MFA par simple
    test de véracité (`u.totp_enabled || u.totp || u.mfa_enabled`), donc
    supprimer la clé éteindrait le badge en silence, et en émettre une toujours
    l'allumerait pour des utilisateurs jamais enrôlés.

    Ne mute jamais l'entrée : elle vient de users.json et serait réécrite telle
    quelle au prochain enregistrement.
    """
    out = {k: v for k, v in user.items() if k not in SECRET_KEYS}
    totp = user.get("totp")
    if isinstance(totp, dict):
        out["totp"] = {k: v for k, v in totp.items() if k not in TOTP_SECRET_KEYS}
    out["totp_enabled"] = bool(isinstance(totp, dict) and totp.get("enabled"))
    return out
