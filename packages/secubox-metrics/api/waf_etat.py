# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""État du WAF pour la santé globale (#2391). Module léger, sans configuration chargée : testable seul.

Le WAF est sbxwaf (service secubox-waf-ng, 127.0.0.1:8085) depuis la bascule ; l'ancien contrôle (conteneur LXC mitmproxy-in, processus
mitmdump) n'existe plus et affichait « WAF HORS SERVICE » alors que sbxwaf tournait."""
import socket
import subprocess


def _systemctl_actif(unite: str) -> bool:
    try:
        r = subprocess.run(["systemctl", "is-active", unite], capture_output=True, text=True, timeout=5)
    except Exception:
        return False
    return r.stdout.strip() == "active"


def sbxwaf_actif(hote: str = "127.0.0.1", port: int = 8085) -> bool:
    """Actif = le service systemd est actif ET le port répond ; l'un sans l'autre n'est pas un WAF qui protège."""
    if not _systemctl_actif("secubox-waf-ng"):
        return False
    try:
        with socket.create_connection((hote, port), timeout=1.5):
            return True
    except OSError:
        return False
