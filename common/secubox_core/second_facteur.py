# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: second_facteur — l'OTP hors de secubox-auth (#1827)
CyberMind — https://cybermind.fr

L'ÉLÉVATION D'ADMINISTRATION (Identity Manager) EXIGE LE MÊME SECOND FACTEUR
QUE LA CONNEXION PAR MOT DE PASSE, avec les mêmes règles :

- QUAND : hors du réseau local, toujours ; sur le LAN, selon `otp_lan`
  (« facultatif » par défaut). Même source que secubox-auth (#1699) :
  `reglages.json` du panneau Utilisateurs, sinon `[auth] otp_lan`. Le verdict
  LAN est celui de nginx (`X-SecuBox-LAN`) ; absent = hors LAN = OTP exigé.
- COMMENT : le secret du compte dans users.json, fenêtre ±1 pas, et le
  PLANCHER ANTI-REJEU partagé (`/var/lib/secubox/totp-replay.json`, celui du
  moteur secubox-users) : un code déjà consommé par la page de connexion ne
  sert pas une seconde fois ici, ni l'inverse.

Le secret n'est jamais rendu, journalisé ni comparé hors de pyotp.
"""
from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path
from typing import Optional

from . import user_store
from .auth import _requete_lan
from .config import get_config

OTP_LAN_VALEURS = ("facultatif", "obligatoire")
PAS_S = 30


def _reglages() -> Path:
    # Même résolution que secubox-auth : SECUBOX_AUTH_REGLAGES, sinon le
    # répertoire de données d'auth.
    brut = os.environ.get("SECUBOX_AUTH_REGLAGES")
    if brut:
        return Path(brut)
    return Path(os.environ.get("SECUBOX_AUTH_DATA_DIR", "/var/lib/secubox/auth")) / "reglages.json"


def _plancher() -> Path:
    return Path(os.environ.get("SECUBOX_TOTP_REPLAY_PATH", "/var/lib/secubox/totp-replay.json"))


def otp_lan() -> str:
    """« facultatif » ou « obligatoire » ; une valeur inconnue ne compte pas."""
    try:
        v = json.loads(_reglages().read_text()).get("otp_lan")
        if v in OTP_LAN_VALEURS:
            return v
    except (OSError, ValueError, AttributeError):
        pass
    try:
        v = (get_config("auth") or {}).get("otp_lan")
    except Exception:  # noqa: BLE001 — config illisible : le défaut
        v = None
    return v if v in OTP_LAN_VALEURS else "facultatif"


def otp_exige(request) -> bool:
    """Le second facteur est-il exigé pour cette requête ? L'échec ferme."""
    if not _requete_lan(request):
        return True
    return otp_lan() == "obligatoire"


def totp_actif(compte: str) -> bool:
    u = user_store.get_user(compte) or {}
    return bool(u.get("enabled") and (u.get("totp") or {}).get("enabled") and (u.get("totp") or {}).get("secret"))


def verifie_totp(compte: str, code: str, fenetre: int = 1) -> bool:
    """Vrai si `code` est un code valide, JAMAIS encore consommé, du compte.

    Le pas accepté devient le nouveau plancher, sous verrou : deux requêtes
    simultanées ne peuvent pas consommer le même code."""
    code = (code or "").strip()
    if not (code.isdigit() and len(code) == 6) or not totp_actif(compte):
        return False
    import pyotp
    u = user_store.get_user(compte) or {}
    t = u.get("totp") or {}
    totp = pyotp.TOTP(t["secret"])
    plancher = _plancher()
    plancher.parent.mkdir(parents=True, exist_ok=True)
    verrou = os.open(str(plancher) + ".verrou", os.O_RDONLY | os.O_CREAT, 0o644)
    try:
        fcntl.flock(verrou, fcntl.LOCK_EX)
        try:
            etat = json.loads(plancher.read_text())
            if not isinstance(etat, dict):
                etat = {}
        except (OSError, ValueError):
            etat = {}
        connus = [x for x in (t.get("last_step"), etat.get(compte)) if isinstance(x, int)]
        dernier = max(connus) if connus else None
        courant = int(time.time()) // PAS_S
        for delta in range(-fenetre, fenetre + 1):
            pas = courant + delta
            if totp.at(pas * PAS_S) == code:
                if dernier is not None and pas <= dernier:
                    return False                    # déjà consommé : rejeu
                etat[compte] = pas
                tmp = plancher.with_suffix(".tmp")
                tmp.write_text(json.dumps(etat))
                os.replace(tmp, plancher)
                return True
        return False
    finally:
        os.close(verrou)


def compte_admin_actif(compte: Optional[str]) -> bool:
    """Un compte SYSTÈME administrateur, existant et ouvert."""
    u = user_store.get_user(compte or "") or {}
    return u.get("role") == "admin" and bool(u.get("enabled", False)) and not u.get("_fallback")
