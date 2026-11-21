# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Politiques de réponse de la veille (`/etc/secubox/ai/politiques.toml`, V2 § 10.2), #3723.

Double tampon (CSPN) : le fichier est lu dans une OMBRE (sans suivre de lien, fichier ordinaire du propriétaire
attendu, ni groupe ni autres en écriture, taille bornée), validé (schéma strict), puis BASCULÉ d'un bloc. Un fichier
absent, illisible ou invalide ne touche pas la politique active : la précédente valide reste (retour arrière), et
l'audit `politiques-invalides` le dit UNE fois par contenu fautif (pas à chaque passe). Sans aucune politique valide
depuis le démarrage : politique FERMÉE (mode observation, automatique suspendu, aucun geste), jamais des défauts
permissifs inventés.

Schéma (toute clé inconnue = invalide) :
- `version = 1` ;
- `[defauts]` : `mode` (`observation` = rien n'est proposé | `hybride`), `refuser_inconnu = true` (obligatoire :
  catalogue fermé), `expiration_min` (5..1440) ;
- `[gestes.<g>]` : `actif`, `auto` (booléens), `<g>` du catalogue seulement ; un geste absent n'est pas admis ;
- `[suspension] automatique_suspendu` (booléen) : vrai = propositions en un clic seulement ;
- `[plafonds.unban]` (#3723) : plafond PROPRE à gk3 (gk2 n'en a pas), au plus `PLAFONDS_GK3` ; absent : ces valeurs ;
- `[plafonds.<g>] heure, jour` : entiers ≥ 0, AU PLUS ceux de gk2 (`PLAFONDS_GK2`, relus dans `gestes_ia.py` par le
  test) ; un plafond absent vaut celui de gk2.
"""
import hashlib
import logging
import os
import stat
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Callable, Optional

log = logging.getLogger("secubox-ai-veille")

CHEMIN = "/etc/secubox/ai/politiques.toml"
TAILLE_MAX = 64 * 1024
CATALOGUE = ("ban", "ban_bloc", "prolonger", "limiter", "leurre", "partager", "unban")
#: Plafonds de gk2 (`gestes_ia.PLAFONDS_PAR_GESTE`, fenêtres glissantes, sommés sur tous les niveaux).
PLAFONDS_GK2 = {"ban": {"heure": 60, "jour": 400}, "ban_bloc": {"heure": 5, "jour": 20},
                "prolonger": {"heure": 30, "jour": 100}, "limiter": {"heure": 60, "jour": 400},
                "leurre": {"heure": 30, "jour": 200}, "partager": {"heure": 30, "jour": 200}}
#: Plafonds propres à gk3 (gestes sans plafond sur gk2) : bornes hautes et défauts.
PLAFONDS_GK3 = {"unban": {"heure": 30, "jour": 100}}
PLAFONDS_BORNES = {**PLAFONDS_GK2, **PLAFONDS_GK3}
MODES = ("observation", "hybride")
EXPIRATION_BORNES = (5, 1440)
REAUDIT_S = 3600            # un même contenu fautif est redit au plus une fois par heure


class PolitiqueInvalide(ValueError):
    pass


@dataclass(frozen=True)
class Geste:
    actif: bool
    auto: bool


@dataclass(frozen=True)
class Politiques:
    version: int
    mode: str
    refuser_inconnu: bool
    expiration_min: int
    gestes: MappingProxyType
    automatique_suspendu: bool
    plafonds: MappingProxyType
    empreinte: str = ""

    def admet(self, geste: str) -> bool:
        """Geste du catalogue, présent et actif dans la politique. Tout autre nom : refusé."""
        g = self.gestes.get(geste) if geste in CATALOGUE else None
        return g is not None and g.actif

    def mode_de(self, geste: str) -> str:
        g = self.gestes.get(geste)
        return "auto" if g is not None and g.auto and not self.automatique_suspendu else "clic"


FERMEE = Politiques(1, "observation", True, 120, MappingProxyType({}), True,
                    MappingProxyType({g: MappingProxyType(dict(p)) for g, p in PLAFONDS_BORNES.items()}), "fermee")


def _bool(v, ou):
    if not isinstance(v, bool):
        raise PolitiqueInvalide(f"{ou} : booléen attendu")
    return v


def _entier(v, ou, bas, haut):
    if isinstance(v, bool) or not isinstance(v, int) or not bas <= v <= haut:
        raise PolitiqueInvalide(f"{ou} : entier dans [{bas}, {haut}] attendu")
    return v


def _table(v, ou, permises):
    if not isinstance(v, dict):
        raise PolitiqueInvalide(f"{ou} : table attendue")
    inconnues = set(v) - set(permises)
    if inconnues:
        raise PolitiqueInvalide(f"{ou} : clé(s) inconnue(s) {sorted(inconnues)[:5]}")
    return v


def valider(brut, empreinte: str = "") -> Politiques:
    """Dictionnaire TOML → Politiques ; lève PolitiqueInvalide (message du code, jamais le contenu du fichier)."""
    brut = _table(brut, "racine", ("version", "defauts", "gestes", "suspension", "plafonds"))
    if brut.get("version") != 1 or isinstance(brut.get("version"), bool):
        raise PolitiqueInvalide("version : 1 attendu")
    d = _table(brut.get("defauts", {}), "defauts", ("mode", "refuser_inconnu", "expiration_min"))
    mode = d.get("mode", "hybride")
    if mode not in MODES:
        raise PolitiqueInvalide("defauts.mode : observation ou hybride")
    if d.get("refuser_inconnu", True) is not True:
        raise PolitiqueInvalide("defauts.refuser_inconnu : true obligatoire (catalogue fermé)")
    expiration = _entier(d.get("expiration_min", 120), "defauts.expiration_min", *EXPIRATION_BORNES)
    gestes = {}
    for nom, g in _table(brut.get("gestes", {}), "gestes", CATALOGUE).items():
        g = _table(g, f"gestes.{nom}", ("actif", "auto"))
        gestes[nom] = Geste(_bool(g.get("actif", False), f"gestes.{nom}.actif"),
                            _bool(g.get("auto", False), f"gestes.{nom}.auto"))
    s = _table(brut.get("suspension", {}), "suspension", ("automatique_suspendu",))
    suspendu = _bool(s.get("automatique_suspendu", True), "suspension.automatique_suspendu")
    plafonds = {g: dict(p) for g, p in PLAFONDS_BORNES.items()}
    for nom, p in _table(brut.get("plafonds", {}), "plafonds", PLAFONDS_BORNES).items():
        p = _table(p, f"plafonds.{nom}", ("heure", "jour"))
        for champ in ("heure", "jour"):
            if champ in p:
                plafonds[nom][champ] = _entier(p[champ], f"plafonds.{nom}.{champ}", 0, PLAFONDS_BORNES[nom][champ])
    return Politiques(1, mode, True, expiration, MappingProxyType(gestes), suspendu,
                      MappingProxyType({g: MappingProxyType(p) for g, p in plafonds.items()}), empreinte)


def lire_octets(chemin, proprietaire: int = 0, taille_max: int = TAILLE_MAX) -> bytes:
    """Contenu d'un fichier de configuration : sans suivre de lien, fichier ordinaire du propriétaire attendu, ni
    groupe ni autres en écriture, taille bornée. Lève FileNotFoundError, PermissionError, OSError ou ValueError."""
    fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != proprietaire or st.st_mode & 0o022:
            raise PermissionError("fichier ordinaire du propriétaire attendu, ni groupe ni autres en écriture")
        donnees = os.read(fd, taille_max + 1)
    finally:
        os.close(fd)
    if len(donnees) > taille_max:
        raise ValueError("fichier trop grand")
    return donnees


def lire_toml(chemin, proprietaire: int = 0, taille_max: int = TAILLE_MAX) -> dict:
    """lire_octets puis TOML ; lève en plus tomllib.TOMLDecodeError ou UnicodeDecodeError."""
    return tomllib.loads(lire_octets(chemin, proprietaire, taille_max).decode("utf-8"))


class Tampon:
    """Double tampon de la politique : `active` ne change que par une bascule d'une ombre validée."""

    def __init__(self, proprietaire: int = 0):
        self.proprietaire = proprietaire
        self.active: Politiques = FERMEE
        self._dits = {}             # empreinte (ou motif) du contenu fautif → dernier audit (datetime)

    def _refuser(self, cle, motif, auditer, maintenant):
        dernier = self._dits.get(cle)
        if dernier is not None and maintenant - dernier < timedelta(seconds=REAUDIT_S):
            return
        self._dits = {k: v for k, v in self._dits.items() if maintenant - v < timedelta(seconds=REAUDIT_S)}
        self._dits[cle] = maintenant
        log.error("politiques.toml refusé (%s) : politique précédente gardée (%s)", motif, self.active.empreinte[:12])
        if auditer is not None:
            auditer("politiques-invalides", {"motif": motif, "gardee": self.active.empreinte[:16],
                                             "contenu": cle[:16]})

    def charger(self, chemin=CHEMIN, auditer: Optional[Callable[[str, dict], None]] = None,
                maintenant: Optional[datetime] = None) -> Politiques:
        maintenant = maintenant or datetime.now(timezone.utc)
        try:
            donnees = lire_octets(chemin, self.proprietaire)
        except FileNotFoundError:
            self._refuser("absent", "absent", auditer, maintenant)
            return self.active
        except ValueError:
            self._refuser("taille", "taille", auditer, maintenant)
            return self.active
        except OSError as e:                    # lien, type, propriétaire, droits, lecture
            self._refuser(f"acces:{e.__class__.__name__}", "acces", auditer, maintenant)
            return self.active
        empreinte = hashlib.sha256(donnees).hexdigest()
        if empreinte == self.active.empreinte:
            return self.active
        try:
            brut = tomllib.loads(donnees.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            self._refuser(empreinte, "toml", auditer, maintenant)
            return self.active
        try:
            ombre = valider(brut, empreinte)
        except PolitiqueInvalide as e:
            log.warning("politiques.toml : %s", e)
            self._refuser(empreinte, "schema", auditer, maintenant)
            return self.active
        self.active = ombre                     # bascule d'un bloc (référence unique)
        self._dits.clear()
        log.info("politiques.toml chargé (%s) : mode %s, %d geste(s)", empreinte[:12], ombre.mode, len(ombre.gestes))
        return ombre


_TAMPON = Tampon()


def charger_politiques(chemin=CHEMIN, auditer=None, maintenant=None, tampon: Optional[Tampon] = None) -> Politiques:
    """Politique active après une tentative de rechargement (double tampon du processus)."""
    return (tampon or _TAMPON).charger(chemin, auditer=auditer, maintenant=maintenant)
