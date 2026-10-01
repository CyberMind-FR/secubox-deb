# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Clé OpenPGP d'une personne (Coffre P5, #1367).

ELLE NAÎT DANS UN TROUSSEAU JETABLE et n'en sort que vers le compartiment de
la personne : un répertoire 0700 sous le /tmp privé du démon, détruit — agent
arrêté, fichiers écrasés — avant de rendre la main. Le Coffre ne garde aucun
trousseau, ne signe ni ne déchiffre rien avec (pas d'oracle, #1417) : la
personne relit sa clé secrète avec SA serrure et l'emporte dans son client.

Primaire ed25519 [signer], sous-clé cv25519 [chiffrer] : deux secrets, comme
le veut POLITIQUE-CRYPTO. La clé exportée n'a pas de phrase propre : c'est le
compartiment qui la protège ; le client de la personne lui en posera une.
La publier dans l'annuaire des clés de la box relève de #1738.
"""
import os
import re
import shutil
import subprocess
import tempfile

COURRIEL_RE = re.compile(r"^[^@\s<>\"]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
NOM_RE = re.compile(r"^[^<>\"\n\r\0]{1,64}$")
DUREE = "2y"


class ErreurOpenPGP(RuntimeError):
    pass


def verifie_uid(nom: str, courriel: str) -> str:
    nom = (nom or "").strip()
    courriel = (courriel or "").strip()
    if not NOM_RE.match(nom):
        raise ValueError("nom invalide (1 à 64 caractères, sans < > \")")
    if not COURRIEL_RE.match(courriel):
        raise ValueError("adresse de courriel invalide")
    return f"{nom} <{courriel}>"


def _detruit(rep: str) -> None:
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=dict(os.environ, GNUPGHOME=rep), capture_output=True)
    for racine, _, fichiers in os.walk(rep):
        for n in fichiers:
            p = os.path.join(racine, n)
            try:
                if os.path.isfile(p) and not os.path.islink(p):
                    with open(p, "r+b") as h:
                        h.write(b"\0" * max(1, os.path.getsize(p)))
            except OSError:
                pass
    shutil.rmtree(rep, ignore_errors=True)


def generer(nom: str, courriel: str, duree: str = DUREE) -> dict:
    """Rend {empreinte, uid, secrete, publique} (armures ASCII)."""
    uid = verifie_uid(nom, courriel)
    rep = tempfile.mkdtemp(prefix="sbxk-")
    os.chmod(rep, 0o700)
    env = dict(os.environ, GNUPGHOME=rep)
    sans_phrase = ["--batch", "--pinentry-mode", "loopback", "--passphrase", ""]

    def gpg(*args: str) -> str:
        r = subprocess.run(["gpg", *args], env=env, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise ErreurOpenPGP("gpg a échoué : " + (r.stderr.strip().splitlines() or ["?"])[-1][:160])
        return r.stdout

    try:
        gpg(*sans_phrase, "--quick-gen-key", uid, "ed25519", "sign", duree)
        fprs = [l.split(":")[9] for l in gpg("--batch", "--with-colons", "--list-secret-keys").splitlines()
                if l.startswith("fpr:")]
        if not fprs:
            raise ErreurOpenPGP("aucune clé produite")
        empreinte = fprs[0]
        gpg(*sans_phrase, "--quick-add-key", empreinte, "cv25519", "encr", duree)
        secrete = gpg(*sans_phrase, "--armor", "--export-secret-keys", empreinte)
        publique = gpg("--batch", "--armor", "--export", empreinte)
        if "PRIVATE KEY BLOCK" not in secrete or "PUBLIC KEY BLOCK" not in publique:
            raise ErreurOpenPGP("export incomplet")
        return {"empreinte": empreinte, "uid": uid, "secrete": secrete, "publique": publique}
    finally:
        _detruit(rep)
