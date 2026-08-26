# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: vhost.antirobots — case « refuser les robots » par vhost (#1216).

Lecture directe, écriture déléguée. Le fichier de profils du WAF appartient à
root ; l'API tourne sous ``secubox`` et peut le LIRE (elle est dans le groupe
``secubox-waf``) mais pas l'écrire. Toute modification passe donc par
``sudo wafctl anti-robots``, qui valide, écrit atomiquement et recharge le
démon — voir /etc/sudoers.d/secubox-waf.

Lecture tolérante : fichier absent, illisible ou clé manquante rendent un
ensemble vide. Le panneau doit s'afficher même si le WAF n'est pas installé ;
une case décochée est la bonne réponse par défaut, jamais une erreur 500.
"""
import json
import subprocess
from pathlib import Path

PROFILS = Path("/etc/secubox/waf/vhost_profiles.json")
WAFCTL = "/usr/sbin/wafctl"


def lire_anti_robots(profils: Path = None) -> set:
    """Ensemble des vhosts cochés, en minuscules."""
    p = profils if profils is not None else PROFILS
    try:
        d = json.loads(p.read_text())
    except (OSError, ValueError):
        return set()
    liste = d.get("anti_robots") or []
    if not isinstance(liste, list):
        return set()
    return {str(h).strip().lower() for h in liste if str(h).strip()}


def basculer_anti_robots(vhost: str, actif: bool, timeout: int = 30) -> tuple:
    """Coche ou décoche un vhost. Rend (succès, message).

    On ne construit pas le JSON ici : un second point d'écriture, c'est deux
    façons de corrompre le fichier. `wafctl` reste le seul.
    """
    verbe = "on" if actif else "off"
    try:
        r = subprocess.run(
            ["sudo", "-n", WAFCTL, "anti-robots", verbe, vhost],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "wafctl n'a pas répondu dans le délai imparti"
    except OSError as e:
        return False, f"wafctl injoignable : {e}"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or "échec sans message").strip()
    return True, (r.stdout or "").strip()
