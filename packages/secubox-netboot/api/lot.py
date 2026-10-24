# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot de flash signé (#3100) : ce que le maître remet au live d'une box en cours de flash.

Le lot porte un code de jonction du maillage à usage unique, l'ancre du maître, le nom et le
domaine de la box et, si l'administrateur l'a préparée, l'empreinte argon2 de son mot de passe.
Il est signé de la clé des images netboot (openssl, la clé n'est jamais lue ici).
Chemins surchargeables par l'environnement pour les tests."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

NOM_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")
TTL_FLASH = 172800  # 48 h, comme sbx-mesh-invite --flash


def _env(nom: str, defaut: str) -> str:
    return os.environ.get(nom) or defaut


def chemin_cle() -> str:
    return _env("SBX_NETBOOT_KEY", "/etc/secubox/netboot/keys/secubox-netboot.key")


def dossier_prepares() -> Path:
    return Path(_env("SBX_LOT_PREPARES", "/var/lib/secubox/netboot/flash-prepares"))


def chemin_audit() -> str:
    return _env("SBX_LOT_AUDIT", "/var/log/secubox/audit.log")


def nom_valide(nom: str) -> bool:
    return isinstance(nom, str) and NOM_RE.fullmatch(nom) is not None


def domaine_pour(nom: str, domaine_maitre: str) -> str:
    """Domaine de la box `nom` : le premier label du domaine du maître est remplacé par `nom`."""
    if not nom_valide(nom):
        raise ValueError("nom de box invalide")
    reste = (domaine_maitre or "").strip().strip(".").lower().partition(".")[2]
    if not reste:
        raise ValueError("domaine du maître inexploitable")
    return f"{nom}.{reste}"


# ── Préparations d'administrateur ─────────────────────────────────────────────────────────────
def enregistrer_preparation(nom: str, mot_de_passe: str) -> None:
    """Hache le mot de passe (argon2) et écrit {nom, admin_empreinte} en 0600. Le clair n'est jamais écrit."""
    if not nom_valide(nom):
        raise ValueError("nom de box invalide")
    from argon2 import PasswordHasher
    empreinte = PasswordHasher().hash(mot_de_passe)
    d = dossier_prepares()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"nom": nom, "admin_empreinte": empreinte}, f)
        os.replace(tmp, d / f"{nom}.json")
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def lire_preparation(nom: str) -> Optional[str]:
    try:
        d = json.loads((dossier_prepares() / f"{nom}.json").read_text(encoding="utf-8"))
        e = d.get("admin_empreinte")
        return e if d.get("nom") == nom and isinstance(e, str) and e.startswith("$argon2") else None
    except (OSError, ValueError, AttributeError):
        return None


def consommer_preparation(nom: str) -> None:
    try:
        (dossier_prepares() / f"{nom}.json").unlink()
    except OSError:
        pass


# ── Lot ──────────────────────────────────────────────────────────────────────────────────────
def _module_p2p(nom: str):
    base = Path(_env("SBX_LOT_P2P", "/usr/lib/secubox/p2p/api"))
    spec = importlib.util.spec_from_file_location("sbx_p2p_" + nom, base / f"{nom}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _domaine_maitre() -> str:
    d = os.environ.get("SBX_LOT_DOMAINE_MAITRE")
    if d:
        return d
    from secubox_core.auth import domaine_box
    return domaine_box()


def _code(nom: str) -> str:
    r = subprocess.run([_env("SBX_LOT_INVITE", "/usr/bin/sbx-mesh-invite"), "--code", "--nom", nom, "--flash",
                        "--ttl", str(TTL_FLASH), "--json"], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError("émission du code de jonction impossible")
    try:
        return json.loads(r.stdout)["code"]
    except (ValueError, KeyError, TypeError):
        raise RuntimeError("réponse de l'invitation illisible") from None


def _cle_wg() -> str:
    with open(_env("SBX_LOT_WGMESH", "/var/lib/secubox/p2p/wg_mesh.json"), encoding="utf-8") as f:
        cle = json.load(f)["public_key"]
    if not isinstance(cle, str) or not cle:
        raise RuntimeError("clé publique du maillage absente")
    return cle


def construire(nom: str) -> dict:
    """{"lot": <texte JSON>, "signature": <base64>} pour la box `nom`. ValueError si le nom est invalide."""
    domaine = domaine_pour(nom, _domaine_maitre())
    code = _code(nom)
    adresse, _jeton = _module_p2p("automesh").decoder(code)
    cle = _cle_wg()
    lot = {"version": 1, "nom": nom, "domaine": domaine, "code": code,
           "ancre": {"cle_publique": cle, "adresse": adresse, "nom": _env("SBX_LOT_HOTE", socket.gethostname()),
                     "empreinte": _module_p2p("ancre").empreinte(cle)},
           "emis": int(time.time())}
    prep = lire_preparation(nom)
    if prep:
        lot["admin_empreinte"] = prep
    texte = json.dumps(lot, ensure_ascii=False, separators=(",", ":"))
    return {"lot": texte, "signature": signer(texte)}


def signer(texte: str) -> str:
    """Signature openssl SHA-256/RSA du texte exact (UTF-8), en base64 ; la clé ne passe que à openssl."""
    import base64
    r = subprocess.run(["openssl", "dgst", "-sha256", "-sign", chemin_cle()], input=texte.encode("utf-8"),
                       capture_output=True, timeout=30)
    if r.returncode != 0 or not r.stdout:
        raise RuntimeError("signature impossible")
    return base64.b64encode(r.stdout).decode("ascii")


def audit(evenement: str, **champs) -> None:
    """Ligne JSON ajoutée à l'audit global ; jamais de code ni de jeton."""
    if any(k in ("code", "jeton", "token", "mot_de_passe") for k in champs):
        raise ValueError("l'audit ne reçoit ni code ni secret")
    ligne = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "module": "netboot", "evenement": evenement, **champs}
    with open(chemin_audit(), "a", encoding="utf-8") as f:
        f.write(json.dumps(ligne, ensure_ascii=False) + "\n")
