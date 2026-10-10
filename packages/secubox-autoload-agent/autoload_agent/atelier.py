# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Atelier Auto-Load (#2280) : prépare une image ou une carte pour qu'elle se provisionne seule au premier démarrage.

    fichier de réponses → validation STRICTE (celle de la box) → signature (clé « SecuBox Provisioning ») → vérification contre le trousseau de la box → dépôt sur /boot

Rien n'est écrit tant que le fichier n'est pas valide ET que sa signature n'est pas vérifiée comme la box la vérifiera. Le jeton, à usage unique, est déposé en 0600 et ne
s'affiche jamais ; l'agent l'installe au premier démarrage puis l'efface de /boot. La partie privée de la clé reste dans le dossier GNUPG de l'atelier (0700) : elle ne sort pas."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

REF_JETON = "ref:/etc/secubox/secrets/autoload-jeton"          # le seul fichier que l'agent installe depuis /boot
IDENTITE = "SecuBox Provisioning <provisioning@secubox.in>"
_JETON = re.compile(r"^gk2_[0-9a-f]{32}$")


class AtelierErreur(RuntimeError):
    pass


def _gpg(home: Path, *args: str, entree: Optional[bytes] = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, GNUPGHOME=str(home), LC_ALL="C")
    return subprocess.run(["gpg", "--homedir", str(home), "--batch", "--no-tty", "--yes", *args], capture_output=True, input=entree, env=env, timeout=120)


def _empreinte(home: Path) -> str:
    r = _gpg(home, "--with-colons", "--list-secret-keys")
    for ligne in r.stdout.decode("utf-8", "replace").splitlines():
        if ligne.startswith("fpr:"):
            return ligne.split(":")[9]
    raise AtelierErreur("aucune clé privée dans ce dossier GNUPG")


def cle_init(home: Path, publique: Path) -> str:
    """Crée la clé « SecuBox Provisioning » (Ed25519, sans échéance) et exporte la partie PUBLIQUE. Refuse d'écraser une clé existante. Rend l'empreinte."""
    home, publique = Path(home), Path(publique)
    if publique.exists():
        raise AtelierErreur(f"{publique} existe déjà : une clé de provisionnement n'est jamais remplacée sans décision explicite")
    if home.exists() and any(home.iterdir()):
        r = _gpg(home, "--with-colons", "--list-secret-keys")
        if b"sec:" in r.stdout:
            raise AtelierErreur(f"{home} porte déjà une clé privée : elle n'est pas remplacée")
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(home, 0o700)
    r = _gpg(home, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", IDENTITE, "ed25519", "sign", "never")
    if r.returncode != 0:
        raise AtelierErreur("génération de la clé impossible : " + r.stderr.decode("utf-8", "replace").strip()[-200:])
    fpr = _empreinte(home)
    pub = _gpg(home, "--export", fpr)
    if pub.returncode != 0 or not pub.stdout:
        raise AtelierErreur("export de la clé publique impossible")
    publique.parent.mkdir(parents=True, exist_ok=True)
    publique.write_bytes(pub.stdout)
    os.chmod(publique, 0o644)
    return fpr


def preparer(reponses: Path, boot: Path, home: Path, trousseau: Path, jeton: Optional[str] = None) -> Path:
    """Valide, signe, vérifie puis dépose `secubox/autoload/{reponses.toml,reponses.toml.sig,jeton}` sous `boot` (la partition de démarrage montée). Rend le dossier."""
    from premier_pas import provision as PV
    reponses, boot = Path(reponses), Path(boot)
    try:
        examen = PV.examine_provision(PV.lit_strict(reponses))
    except PV.FichierInvalide as e:
        raise AtelierErreur(f"fichier de réponses refusé : {e}") from e
    if examen.erreurs or examen.manquantes:
        raise AtelierErreur("fichier de réponses incomplet ou faux : " + "; ".join([*examen.manquantes, *[f"{k}: {v}" for k, v in examen.erreurs.items()]]))
    if examen.profil["provision"]["jeton"] != REF_JETON:
        raise AtelierErreur(f"[provision].jeton doit valoir « {REF_JETON} » : c'est le seul fichier que l'agent installe depuis /boot")
    if jeton is not None and not _JETON.match(jeton):
        raise AtelierErreur("jeton mal formé (attendu : gk2_ + 32 caractères hexadécimaux)")
    with tempfile.TemporaryDirectory(prefix="sbx-atelier-") as tmp:
        copie = Path(tmp) / "reponses.toml"
        shutil.copyfile(reponses, copie)
        sig = Path(tmp) / "reponses.toml.sig"
        r = _gpg(Path(home), "--detach-sign", "--output", str(sig), str(copie))
        if r.returncode != 0 or not sig.is_file():
            raise AtelierErreur("signature impossible : " + r.stderr.decode("utf-8", "replace").strip()[-200:])
        try:
            PV.verifier_signature(copie, sig, Path(trousseau))                       # EXACTEMENT ce que fera la box
        except PV.SignatureInvalide as e:
            raise AtelierErreur(f"la signature ne serait pas acceptée par la box : {e}") from e
        dossier = boot / "secubox" / "autoload"
        dossier.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(copie, dossier / "reponses.toml")
        shutil.copyfile(sig, dossier / "reponses.toml.sig")
    for f in ("reponses.toml", "reponses.toml.sig"):
        os.chmod(dossier / f, 0o644)
    if jeton is not None:
        cible = dossier / "jeton"
        fd = os.open(cible, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(jeton + "\n")
        os.chmod(cible, 0o600)
    return dossier
