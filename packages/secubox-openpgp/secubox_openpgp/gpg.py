# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: openpgp — le trousseau de la box, par GnuPG (#1736)
CyberMind — https://cybermind.fr

GnuPG en ligne de commande, jamais une bibliothèque qui toucherait la clé
secrète : elle reste dans le GNUPGHOME du démon (0700, utilisateur
secubox-openpgp), et rien ici ne la lit, ne l'exporte ni ne la rend. Les
opérations rendent des empreintes, des clés PUBLIQUES et des messages armurés.

La clé de box : primaire ed25519 [certifier, signer], sous-clé cv25519
[chiffrer] — deux secrets, comme le veut POLITIQUE-CRYPTO (jamais un seul
secret qui signe et négocie). Elle n'est PAS node.key : c'est l'annuaire,
signé par node.key, qui la lie au did (annuaire.openpgp).

La confiance ne vient pas d'une toile OpenPGP : `--trust-model always` pour
chiffrer, parce que l'appelant a DÉJÀ vérifié que l'empreinte visée est celle
que la box a liée dans l'annuaire. Et à la réception, c'est l'empreinte
primaire du signataire (VALIDSIG) qui est rendue — à comparer à la liaison.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

EMPREINTE = re.compile(r"^[0-9A-F]{40}$")
NOTATION_USAGE = "usage@secubox.in"


class ErreurGpg(RuntimeError):
    """gpg a refusé ; le message ne contient jamais de matière secrète."""


@dataclass
class Dechiffre:
    texte: bytes
    signataire: str                  # empreinte PRIMAIRE du signataire (VALIDSIG)
    notations: Dict[str, str] = field(default_factory=dict)


class Trousseau:
    """Un GNUPGHOME. `prefixe` permet d'exécuter gpg sous un autre compte
    (la CLI root : ["runuser", "-u", "secubox-openpgp", "--"])."""

    def __init__(self, homedir: str, gpg: str = "gpg", prefixe: Sequence[str] = ()):
        self.homedir = homedir
        self.gpg = gpg
        self.prefixe = list(prefixe)

    # ── plomberie ────────────────────────────────────────────────────────
    def _gpg(self, *args: str, entree: Optional[bytes] = None,
             statut: bool = False, verifier: bool = True) -> subprocess.CompletedProcess:
        cmd = self.prefixe + [self.gpg, "--homedir", self.homedir, "--batch", "--no-tty",
                              "--quiet", "--no-greeting", "--pinentry-mode", "loopback",
                              "--passphrase", ""]
        if statut:
            cmd += ["--status-fd", "2"]
        cmd += list(args)
        r = subprocess.run(cmd, input=entree, capture_output=True, timeout=60)
        if verifier and r.returncode != 0:
            raise ErreurGpg(_resume(r.stderr))
        return r

    # ── la clé de box ────────────────────────────────────────────────────
    def cle_de_box(self) -> Optional[dict]:
        """{empreinte, creee, expire, chiffrement} de la clé SECRÈTE présente, ou None."""
        r = self._gpg("--list-secret-keys", "--with-colons", "--fixed-list-mode", verifier=False)
        if r.returncode != 0:
            return None
        cles = _cles_colons(r.stdout.decode(errors="replace"))
        for c in cles:
            if "s" in c["capacites"] and c["chiffrement"]:
                return c
        return None

    def generer(self, uid: str, duree: str = "2y") -> str:
        """Paire ed25519 [SC] + sous-clé cv25519 [E]. Rend l'empreinte primaire."""
        os.makedirs(self.homedir, mode=0o700, exist_ok=True)
        self._gpg("--quick-generate-key", uid, "ed25519", "cert,sign", duree)
        c = self._premiere_primaire(secrete=True)
        if not c:
            raise ErreurGpg("clé primaire introuvable après génération")
        self._gpg("--quick-add-key", c["empreinte"], "cv25519", "encr", duree)
        return c["empreinte"]

    def _premiere_primaire(self, secrete: bool) -> Optional[dict]:
        r = self._gpg("--list-secret-keys" if secrete else "--list-keys",
                      "--with-colons", "--fixed-list-mode", verifier=False)
        cles = _cles_colons(r.stdout.decode(errors="replace")) if r.returncode == 0 else []
        return cles[0] if cles else None

    def exporter_public(self, empreinte: str) -> str:
        _exige_empreinte(empreinte)
        r = self._gpg("--armor", "--export-options", "export-minimal", "--export", empreinte)
        a = r.stdout.decode()
        if "BEGIN PGP PUBLIC KEY BLOCK" not in a:
            raise ErreurGpg("export vide")
        return a

    # ── les clés des pairs ───────────────────────────────────────────────
    def empreintes_de(self, armure: str) -> List[str]:
        """Empreintes PRIMAIRES contenues dans un bloc armuré, sans l'importer."""
        r = self._gpg("--show-keys", "--with-colons", "--fixed-list-mode",
                      entree=armure.encode(), verifier=False)
        if r.returncode != 0:
            return []
        return [c["empreinte"] for c in _cles_colons(r.stdout.decode(errors="replace"))]

    def importer(self, armure: str, attendue: str) -> None:
        """Importe la clé publique d'un pair — seulement si le bloc contient
        EXACTEMENT la clé liée (`attendue`) : une clé glissée en plus, ou une
        autre à la place, et rien n'entre."""
        _exige_empreinte(attendue)
        if self.empreintes_de(armure) != [attendue]:
            raise ErreurGpg("le bloc ne contient pas exactement la clé liée")
        self._gpg("--import", "--import-options", "import-minimal", entree=armure.encode())

    # ── chiffrer, déchiffrer ─────────────────────────────────────────────
    def chiffrer_signer(self, clair: bytes, pour: str, par: str, usage: str) -> str:
        """Signé par `par` (notre clé), chiffré pour `pour` (la clé liée du
        pair), avec la notation d'usage — l'enveloppe dit à quoi sert la
        signature, pour qu'elle ne vaille pas ailleurs."""
        _exige_empreinte(pour)
        _exige_empreinte(par)
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", usage):
            raise ErreurGpg("usage invalide")
        r = self._gpg("--armor", "--trust-model", "always",
                      # `!` : EXACTEMENT notre primaire pour signer ; pour chiffrer,
                      # l'empreinte complète (40 hex) de la clé liée, sans `!` —
                      # gpg y prend la sous-clé cv25519, la primaire ne chiffre pas.
                      "--local-user", par + "!", "--recipient", pour,
                      "--sig-notation", f"{NOTATION_USAGE}={usage}",
                      "--sign", "--encrypt", entree=clair)
        return r.stdout.decode()

    def dechiffrer_verifier(self, armure: str) -> Dechiffre:
        """Déchiffre ET exige une bonne signature. Rend l'empreinte primaire du
        signataire — c'est à l'appelant de la comparer à une liaison."""
        r = self._gpg("--trust-model", "always", "--decrypt", entree=armure.encode(),
                      statut=True, verifier=False)
        st = r.stderr.decode(errors="replace").splitlines()
        jetons = [l.split()[1] for l in st if l.startswith("[GNUPG:] ") and len(l.split()) > 1]
        if r.returncode != 0 or "DECRYPTION_OKAY" not in jetons or "GOODSIG" not in jetons \
                or any(j in jetons for j in ("BADSIG", "ERRSIG", "DECRYPTION_FAILED",
                                              "EXPKEYSIG", "REVKEYSIG")):
            raise ErreurGpg("message illisible, non signé ou signature invalide")
        signataire, notations, nom = "", {}, None
        for l in st:
            p = l.split()
            if len(p) < 2 or p[0] != "[GNUPG:]":
                continue
            if p[1] == "VALIDSIG" and len(p) >= 3:
                signataire = p[-1] if EMPREINTE.match(p[-1]) else p[2]
            elif p[1] == "NOTATION_NAME" and len(p) >= 3:
                nom = p[2]
            elif p[1] == "NOTATION_DATA" and len(p) >= 3 and nom:
                notations[nom] = notations.get(nom, "") + _pourcent(p[2])
        if not EMPREINTE.match(signataire):
            raise ErreurGpg("signataire inconnu")
        return Dechiffre(texte=r.stdout, signataire=signataire, notations=notations)


# ── utilitaires ──────────────────────────────────────────────────────────

def _exige_empreinte(e: str) -> None:
    if not EMPREINTE.match(e or ""):
        raise ErreurGpg("empreinte invalide")


def _pourcent(s: str) -> str:
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)


def _resume(stderr: bytes) -> str:
    lignes = [l for l in stderr.decode(errors="replace").splitlines()
              if l.strip() and not l.startswith("[GNUPG:]")]
    return (lignes[-1] if lignes else "échec de gpg")[:300]


def _cles_colons(texte: str) -> List[dict]:
    """Clés primaires d'une sortie --with-colons : empreinte, dates,
    capacités, présence d'une sous-clé de chiffrement valide."""
    cles: List[dict] = []
    courant = None
    attente_fpr = None
    for l in texte.splitlines():
        c = l.split(":")
        if c[0] in ("pub", "sec"):
            courant = {"empreinte": "", "creee": int(c[5] or 0), "expire": int(c[6] or 0),
                       "capacites": c[11] if len(c) > 11 else "", "chiffrement": False,
                       "valide": c[1] not in ("r", "e", "i", "d")}
            cles.append(courant)
            attente_fpr = "primaire"
        elif c[0] in ("sub", "ssb") and courant is not None:
            if "e" in (c[11] if len(c) > 11 else "") and c[1] not in ("r", "e", "i", "d"):
                courant["chiffrement"] = True
            attente_fpr = "sous"
        elif c[0] == "fpr" and courant is not None and attente_fpr == "primaire":
            courant["empreinte"] = c[9]
            attente_fpr = None
    return [k for k in cles if k["empreinte"] and k["valide"]]
