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
import secrets
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

# Même motif que sbx-netflash et sbx-netflash-profil : 1 à 31 caractères, ni tiret final.
NOM_RE = re.compile(r"[a-z]([a-z0-9-]{0,29}[a-z0-9])?")
TTL_FLASH = 172800  # 48 h, comme sbx-mesh-invite --flash
DUREE_PREPARATION = 86400  # une préparation de flash vaut 24 h


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
# Une préparation (posée sous JWT administrateur) est la SEULE chose qui autorise un code de
# reflash (`--flash`, qui remplace la clé du pair de ce nom). Sans elle, le lot porte un code
# ordinaire : un nom neuf rejoint, un nom déjà approuvé est refusé (409) par le maître.
def enregistrer_preparation(nom: str, mot_de_passe: Optional[str] = None) -> None:
    """Écrit {nom, cree, expire[, admin_empreinte]} en 0600 ; le mot de passe (facultatif) n'est gardé
    qu'en empreinte argon2, le clair n'est jamais écrit. Valable DUREE_PREPARATION secondes."""
    if not nom_valide(nom):
        raise ValueError("nom de box invalide")
    maintenant = int(time.time())
    donnees = {"nom": nom, "cree": maintenant, "expire": maintenant + DUREE_PREPARATION}
    if mot_de_passe:
        from argon2 import PasswordHasher
        donnees["admin_empreinte"] = PasswordHasher().hash(mot_de_passe)
    d = dossier_prepares()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(donnees, f)
        os.replace(tmp, d / f"{nom}.json")
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _preparation_valide(donnees, nom: str, maintenant: float) -> bool:
    if not isinstance(donnees, dict) or donnees.get("nom") != nom:
        return False
    expire = donnees.get("expire")
    if not isinstance(expire, int) or isinstance(expire, bool) or expire <= maintenant:
        return False
    e = donnees.get("admin_empreinte")
    return e is None or (isinstance(e, str) and e.startswith("$argon2"))


def prendre_preparation(nom: str) -> Optional[Path]:
    """Prise ATOMIQUE de la préparation de `nom` : le fichier est renommé vers un nom propre à cet
    appel ; de deux demandes concurrentes, une seule l'obtient. Rend le chemin pris, ou None.
    Une préparation expirée ou illisible est supprimée et ignorée (audit `preparation_ignoree`)."""
    if not nom_valide(nom):
        return None
    d = dossier_prepares()
    pris = d / f".pris-{nom}-{os.getpid()}-{secrets.token_hex(6)}.json"
    try:
        os.rename(d / f"{nom}.json", pris)
    except OSError:
        return None
    try:
        donnees = json.loads(pris.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        donnees = None
    if not _preparation_valide(donnees, nom, time.time()):
        abandonner_preparation(pris)
        try:
            audit("preparation_ignoree", nom=nom, raison="expiree ou illisible")
        except OSError:
            pass
        return None
    return pris


def empreinte_preparation(pris: Optional[Path]) -> Optional[str]:
    """Empreinte argon2 portée par une préparation prise (None : la console du live la demandera)."""
    if pris is None:
        return None
    try:
        e = json.loads(pris.read_text(encoding="utf-8")).get("admin_empreinte")
    except (OSError, ValueError, AttributeError):
        return None
    return e if isinstance(e, str) and e.startswith("$argon2") else None


def abandonner_preparation(pris: Optional[Path]) -> None:
    """Supprime une préparation prise (consommée ou invalide)."""
    if pris is not None:
        try:
            pris.unlink()
        except OSError:
            pass


def rendre_preparation(pris: Optional[Path], nom: str) -> None:
    """Échec après la prise : la préparation est remise, sauf si une plus récente l'a remplacée
    (os.link échoue si la cible existe)."""
    if pris is None:
        return
    try:
        os.link(pris, dossier_prepares() / f"{nom}.json")
    except OSError:
        pass
    abandonner_preparation(pris)


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


def _code(nom: str, flash: bool, adresse: Optional[str] = None) -> str:
    """Code de jonction pour `nom`. `flash` (reflash, remplace la clé du pair de ce nom) n'est demandé
    que sur préparation de l'administrateur ; `adresse` : celle du maître que le live a jointe."""
    argv = [_env("SBX_LOT_INVITE", "/usr/bin/sbx-mesh-invite"), "--code", "--nom", nom,
            "--ttl", str(TTL_FLASH), "--json"]
    if flash:
        argv.append("--flash")
    if adresse:
        argv += ["--adresse", adresse]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
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


def construire(nom: str, adresse: Optional[str] = None) -> dict:
    """{"lot": <texte JSON>, "signature": <base64>, "flash": bool} pour la box `nom`.

    Le code n'est de reflash (`--flash`) que si une préparation valide existe pour ce nom ; elle est
    prise atomiquement et consommée au succès, remise en cas d'échec. ValueError si le nom est invalide."""
    domaine = domaine_pour(nom, _domaine_maitre())
    pris = prendre_preparation(nom)
    try:
        code = _code(nom, flash=pris is not None, adresse=adresse)
        adresse_code, _jeton = _module_p2p("automesh").decoder(code)
        cle = _cle_wg()
        lot = {"version": 1, "nom": nom, "domaine": domaine, "code": code,
               "ancre": {"cle_publique": cle, "adresse": adresse_code,
                         "nom": _env("SBX_LOT_HOTE", socket.gethostname()),
                         "empreinte": _module_p2p("ancre").empreinte(cle)},
               "emis": int(time.time())}
        prep = empreinte_preparation(pris)
        if prep:
            lot["admin_empreinte"] = prep
        texte = json.dumps(lot, ensure_ascii=False, separators=(",", ":"))
        sortie = {"lot": texte, "signature": signer(texte), "flash": pris is not None}
    except BaseException:
        rendre_preparation(pris, nom)
        raise
    abandonner_preparation(pris)
    return sortie


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
