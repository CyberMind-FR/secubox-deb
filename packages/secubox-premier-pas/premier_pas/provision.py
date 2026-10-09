# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Premier Pas — le FICHIER DE RÉPONSES du provisionnement Auto-Load (#2184, parent #2182)

C'est le profil de l'assistant (`profil.py`) étendu d'une section `[provision]`, avec trois exigences de plus :
  - SCHÉMA STRICT : une section ou une clé inconnue est refusée (le mode « assistant » les ignore, ce mode non) ;
  - AUCUN SECRET EN CLAIR : mot de passe = empreinte argon2, jeton = RÉFÉRENCE `ref:/etc/secubox/secrets/<nom>`, jamais sa valeur ;
  - SIGNATURE DÉTACHÉE : un fichier non signé, modifié ou signé par une clé hors du trousseau est refusé (gpgv, trousseau fourni).

    [provision]
    mode      = "auto" | "one-shot"           (auto : aucun écran ; one-shot : un opérateur est devant)
    jeton     = "ref:/etc/secubox/secrets/…"  (obligatoire)
    lot       = "lot-2026-10"                 (facultatif, [a-z0-9-], 40 au plus)
    grace_min = 15                            (délai de grâce avant application, 0 à 1440 minutes)
    infra     = "admin.gk2.secubox.in"        (point de rendez-vous ; ce défaut)
"""
from __future__ import annotations

import copy
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from . import profil as P
except ImportError:                                  # lancé hors paquet
    import profil as P                               # type: ignore[no-redef]

TAILLE_MAX = 64 * 1024
GRACE_DEFAUT_MIN = 15
GRACE_MAX_MIN = 24 * 60
INFRA_DEFAUT = "admin.gk2.secubox.in"
MODES_PROVISION = ("auto", "one-shot")

CLES: Dict[str, frozenset] = {
    "box": frozenset({"nom", "langue", "clavier", "fuseau", "ntp"}),
    "admin": frozenset({"mot_de_passe", "totp"}),
    "reseau": frozenset({"mode", "domaine"}),
    "services": frozenset({"profil"}),
    "maillage": frozenset({"mode", "rejoindre"}),                 # `jeton` y est refusé : il expire en 15 min et ne se signe pas
    "apt": frozenset({"auto", "heure"}),
    "provision": frozenset({"mode", "jeton", "lot", "grace_min", "infra"}),
}

_REF_JETON = re.compile(r"^ref:/etc/secubox/secrets/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_LOT = re.compile(r"^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$")


class FichierInvalide(ValueError):
    """Le fichier n'est pas un fichier de réponses acceptable : on ne devine pas, on refuse."""


class SignatureInvalide(ValueError):
    """La signature manque, ne correspond pas au fichier, ou n'est pas d'une clé du trousseau."""


def lit_strict(chemin: Path) -> Dict[str, Any]:
    """Lit un fichier de réponses : taille bornée, TOML valide, sections et clés connues, aucun jeton en clair."""
    chemin = Path(chemin)
    try:
        taille = chemin.stat().st_size
        if taille > TAILLE_MAX:
            raise FichierInvalide(f"taille : {taille} octets, {TAILLE_MAX} au plus")
        brut = tomllib.loads(chemin.read_bytes().decode("utf-8"))
    except FichierInvalide:
        raise
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise FichierInvalide(f"illisible : {type(e).__name__}") from e
    problemes: List[str] = []
    for nom, valeur in brut.items():
        if nom not in CLES:
            problemes.append(f"section inconnue : {nom!r}")
        elif not isinstance(valeur, dict):
            problemes.append(f"{nom} : une section est attendue")
        else:
            for cle, v in valeur.items():
                if cle == "jeton" and nom == "maillage":
                    problemes.append("maillage.jeton : refusé (un jeton d'invitation expire en 15 minutes ; le jeton du client est dans [provision])")
                elif cle not in CLES[nom]:
                    problemes.append(f"{nom}.{cle} : clé inconnue")
                elif isinstance(v, dict):
                    problemes.append(f"{nom}.{cle} : sous-table refusée")
    if problemes:
        raise FichierInvalide("; ".join(problemes))
    return brut


def examine_provision(profil: Dict[str, Any], profils_connus: Optional[List[str]] = None) -> "P.Examen":
    """L'examen de l'assistant, plus la section `[provision]`. Le profil rendu porte les valeurs par défaut."""
    ex = P.examine(profil, profils_connus)
    ex.profil = copy.deepcopy(profil)
    section = ex.profil.get("provision")
    if section is None:
        ex.manquantes.append("provision")
        return ex
    erreurs: List[str] = []
    mode = section.get("mode")
    if mode not in MODES_PROVISION:
        erreurs.append("mode : auto ou one-shot")
    jeton = section.get("jeton")
    if not isinstance(jeton, str) or not _REF_JETON.match(jeton):
        erreurs.append("jeton : une référence ref:/etc/secubox/secrets/<nom>, jamais la valeur")
    lot = section.get("lot")
    if lot is not None and (not isinstance(lot, str) or not _LOT.match(lot)):
        erreurs.append("lot : minuscules, chiffres et tirets, 40 au plus")
    grace = section.setdefault("grace_min", GRACE_DEFAUT_MIN)
    if isinstance(grace, bool) or not isinstance(grace, int) or not 0 <= grace <= GRACE_MAX_MIN:
        erreurs.append(f"grace_min : un entier de 0 à {GRACE_MAX_MIN}")
    infra = section.setdefault("infra", INFRA_DEFAUT)
    if not isinstance(infra, str) or not P._DOMAINE.match(infra):
        erreurs.append("infra : un nom de domaine (pas d'URL, pas d'adresse)")
    if not erreurs and mode == "auto":
        reste = [e for e in ex.manquantes if e != "provision"] + [e for e in ex.erreurs]
        if reste:
            erreurs.append("mode auto : aucun écran pour demander ce qui manque (" + ", ".join(reste) + ")")
    if erreurs:
        ex.erreurs["provision"] = "; ".join(erreurs)
    return ex


def verifier_signature(fichier: Path, signature: Path, trousseau: Path, gpgv: str = "gpgv") -> None:
    """Signature détachée OpenPGP vérifiée par `gpgv` contre le SEUL trousseau fourni (aucune confiance implicite)."""
    fichier, signature, trousseau = Path(fichier).resolve(), Path(signature).resolve(), Path(trousseau).resolve()
    if not signature.is_file():
        raise SignatureInvalide("signature absente")
    if not trousseau.is_file():
        raise SignatureInvalide("trousseau absent")
    if not fichier.is_file():
        raise SignatureInvalide("fichier absent")
    with tempfile.TemporaryDirectory(prefix="sbx-gpgv-") as home:
        try:
            r = subprocess.run([gpgv, "--homedir", home, "--keyring", str(trousseau), "--", str(signature), str(fichier)],
                               capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SignatureInvalide(f"vérification impossible ({type(e).__name__})") from e
    if r.returncode != 0:
        raise SignatureInvalide("signature refusée : " + ((r.stderr or "").strip().splitlines() or ["inconnue"])[-1][:200])


def charger_signe(fichier: Path, signature: Path, trousseau: Path, profils_connus: Optional[List[str]] = None) -> "P.Examen":
    """Le chemin d'entrée de l'agent : signature d'abord, puis lecture stricte, puis examen."""
    verifier_signature(fichier, signature, trousseau)
    return examine_provision(lit_strict(fichier), profils_connus)
