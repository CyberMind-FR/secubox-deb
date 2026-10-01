# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: courriel — un message court par le relais de la box (#1821)
CyberMind — https://cybermind.fr

LA BOX SAIT ENVOYER : le MTA vit dans le conteneur `mail` (10.100.0.10), pas
sur l'hôte. Même réglage que le rapport de fréquentation (`[rapport]` de
/etc/secubox/metrics.toml), surchargeable par `[courriel]` de secubox.conf :
  - relais LOCAL (défaut) : port 25, sans authentification, destinataire interne ;
  - soumission AUTHENTIFIÉE dès que `smtp_user` est posé (STARTTLS + login,
    mot de passe lu dans `smtp_pass_file`, jamais dans la configuration).

Bloquant : appeler depuis un fil ou une tâche, jamais dans une requête.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import tomllib
except ImportError:  # pragma: no cover — Python < 3.11
    import tomli as tomllib  # type: ignore

METRICS = Path("/etc/secubox/metrics.toml")
SECUBOX = Path("/etc/secubox/secubox.conf")

DEFAUTS = {"smtp_hote": "10.100.0.10", "smtp_port": 25, "expediteur": "secubox@localdomain"}


def _section(chemin: Path, nom: str) -> Dict[str, Any]:
    try:
        with chemin.open("rb") as f:
            return dict(tomllib.load(f).get(nom, {}) or {})
    except (OSError, ValueError):
        return {}


def config() -> Dict[str, Any]:
    c = dict(DEFAUTS)
    c.update({k: v for k, v in _section(METRICS, "rapport").items()
              if k in ("smtp_hote", "smtp_port", "expediteur", "smtp_user", "smtp_pass_file")})
    c.update(_section(SECUBOX, "courriel"))
    return c


def adresse_de_la_box() -> Optional[str]:
    """La boîte de la box (l'expéditeur configuré), si c'en est une vraie."""
    e = str(config().get("expediteur") or "")
    return e if "@" in e and not e.endswith("@localdomain") else None


def _secret(chemin: Optional[str]) -> Optional[str]:
    if not chemin:
        return None
    try:
        return Path(chemin).read_text(encoding="utf-8").strip("\r\n")
    except OSError:
        return None


def envoie(destinataire: str, sujet: str, corps: str) -> Dict[str, Any]:
    """Envoie un message texte. Lève ValueError sur une adresse invalide,
    OSError / smtplib.SMTPException si le relais refuse."""
    if "@" not in (destinataire or "") or "\n" in destinataire or "\r" in destinataire:
        raise ValueError("adresse destinataire invalide")
    c = config()
    msg = EmailMessage()
    msg["Subject"] = sujet.replace("\n", " ").replace("\r", " ")[:200]
    msg["From"] = c["expediteur"]
    msg["To"] = destinataire
    msg.set_content(corps)
    with smtplib.SMTP(c["smtp_hote"], int(c["smtp_port"]), timeout=20) as s:
        if c.get("smtp_user"):
            # Lien LAN vers la LXC mail au certificat souvent auto-signé : on
            # chiffre sans exiger la chaîne ; l'authentification garde l'usage.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s.starttls(context=ctx)
            mdp = _secret(c.get("smtp_pass_file"))
            if mdp:
                s.login(c["smtp_user"], mdp)
        s.send_message(msg)
    return {"envoye": True, "destinataire": destinataire}
