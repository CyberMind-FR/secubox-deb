# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Premier Pas — le PROFIL (#1522)
CyberMind — https://cybermind.fr

Le profil est la seule source de vérité de l'assistant : le kiosque, la console
et le panneau maître ne font que le remplir ; le mode silencieux l'applique tel
quel. Un profil peut être PARTIEL : ce qui manque sera demandé par une face, à
l'étape qui manque. Il n'est jamais appliqué à moitié.

Format TOML (docs/design/premier-pas-maquette.html) :

    [box]      nom, langue, clavier, fuseau, ntp
    [admin]    mot_de_passe = "demander" | empreinte argon2 ; totp = "enroler"
    [reseau]   mode = routeur|pont|lan ; domaine (absent si mode = lan)
    [services] profil = un profil de secubox-profilectl
    [maillage] mode = rejoindre|premiere|plus_tard ; rejoindre, jeton
    [apt]      auto = true|false ; heure = "HH:MM"

JAMAIS de mot de passe en clair : firstboot.sh en écrivait un dans
secubox.conf ; ici, seule une empreinte argon2 est acceptée.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# L'ordre est celui de la maquette validée : l'horloge AVANT l'administrateur,
# parce que l'enrôlement TOTP dépend de l'heure (#1497).
ETAPES = ("bienvenue", "nom", "horloge", "admin", "reseau", "services",
          "maillage", "majs", "appliquer")

LIBELLES = {
    "bienvenue": "Bienvenue", "nom": "Nom de la box", "horloge": "Horloge",
    "admin": "Administrateur", "reseau": "Réseau et domaine", "services": "Services",
    "maillage": "Maillage", "majs": "Mises à jour", "appliquer": "Appliquer",
}

COMPTES_SYSTEME = frozenset({"root", "admin", "gk2", "operator"})
MODES_RESEAU = {"routeur": "router", "pont": "bridge", "lan": "single"}
MODES_MAILLAGE = ("rejoindre", "premiere", "plus_tard")
PROFILS_DIR = Path("/usr/share/secubox/profiles")
# « actuel » : garder les modules de l'image, sans secubox-profilectl. Un profil
# nommé est un instantané d'une AUTRE box : il arrête ce qu'il ne liste pas et
# bute sur les unités masquées d'ici (vu sur gk3, #1544).
GARDER = "actuel"
GARDER_LIBELLE = "Garder les modules actuels"

_NOM = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_DOMAINE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HEURE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_ARGON2 = re.compile(r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$")
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_JETON = re.compile(r"^[0-9a-f]{16,128}$")


class ProfilInvalide(ValueError):
    """Une valeur est présente mais fausse : on ne devine pas, on refuse."""


@dataclass
class Examen:
    """Ce que dit un profil : ce qui est prêt, ce qui manque, ce qui est faux."""
    profil: Dict[str, Any]
    manquantes: List[str] = field(default_factory=list)
    erreurs: Dict[str, str] = field(default_factory=dict)

    @property
    def complet(self) -> bool:
        return not self.manquantes and not self.erreurs

    @property
    def premiere_etape(self) -> str:
        """Où une face doit reprendre : la première étape à compléter."""
        for e in ETAPES:
            if e in self.erreurs or e in self.manquantes:
                return e
        return "appliquer"


def lit(chemin: Path) -> Dict[str, Any]:
    with open(chemin, "rb") as f:
        return tomllib.load(f)


def _profils_connus() -> List[str]:
    try:
        return sorted(p.stem for p in PROFILS_DIR.glob("*.toml"))
    except OSError:
        return []


def _verifie_nom(p) -> Optional[str]:
    nom = str((p.get("box") or {}).get("nom", "")).strip().lower()
    if not nom:
        return None
    if not _NOM.match(nom):
        raise ProfilInvalide("nom : lettres minuscules, chiffres et tirets (1 à 63)")
    return nom


def examine(profil: Dict[str, Any], profils_connus: Optional[List[str]] = None) -> Examen:
    """Valide un profil étape par étape, sans rien appliquer."""
    ex = Examen(profil=profil)
    box = profil.get("box") or {}

    def refuse(etape, motif):
        ex.erreurs[etape] = motif

    # nom
    try:
        if not _verifie_nom(profil):
            ex.manquantes.append("nom")
    except ProfilInvalide as e:
        refuse("nom", str(e))

    # horloge
    fuseau = box.get("fuseau")
    if not fuseau:
        ex.manquantes.append("horloge")
    elif not re.match(r"^[A-Za-z_]+(/[A-Za-z0-9_+-]+){0,2}$", str(fuseau)):
        refuse("horloge", f"fuseau inconnu : {fuseau!r}")

    # admin
    admin = profil.get("admin") or {}
    mdp = admin.get("mot_de_passe")
    if mdp is None or mdp == "demander":
        # « demander » est une réponse légitime, mais elle exige un écran :
        # en silencieux, l'assistant s'ouvrira à cette étape.
        ex.manquantes.append("admin")
    elif not _ARGON2.match(str(mdp)):
        refuse("admin", "mot_de_passe : « demander » ou une empreinte argon2, jamais du clair")

    # reseau
    reseau = profil.get("reseau") or {}
    mode = reseau.get("mode")
    if mode is None:
        ex.manquantes.append("reseau")
    elif mode not in MODES_RESEAU:
        refuse("reseau", f"mode : routeur, pont ou lan (pas {mode!r})")
    elif mode != "lan":
        dom = str(reseau.get("domaine", "")).strip().lower()
        if not dom:
            ex.manquantes.append("reseau")
        elif not _DOMAINE.match(dom):
            refuse("reseau", f"domaine invalide : {dom!r}")

    # services
    choix = (profil.get("services") or {}).get("profil")
    connus = _profils_connus() if profils_connus is None else profils_connus
    if not choix:
        ex.manquantes.append("services")
    elif choix != GARDER and connus and choix not in connus:
        refuse("services", f"profil inconnu : {choix!r} (connus : {', '.join(connus)})")

    # maillage
    m = profil.get("maillage") or {}
    mm = m.get("mode")
    if mm is None:
        ex.manquantes.append("maillage")
    elif mm not in MODES_MAILLAGE:
        refuse("maillage", f"mode : {', '.join(MODES_MAILLAGE)}")
    elif mm == "rejoindre":
        if not _IP.match(str(m.get("rejoindre", ""))):
            refuse("maillage", "rejoindre : l'adresse IP de la box maîtresse")
        elif not _JETON.match(str(m.get("jeton", ""))):
            refuse("maillage", "jeton : celui de l'invitation (sbx-mesh-invite)")

    # mises à jour
    apt = profil.get("apt") or {}
    if "auto" not in apt:
        ex.manquantes.append("majs")
    elif not isinstance(apt.get("auto"), bool):
        refuse("majs", "auto : true ou false")
    elif apt["auto"] and not _HEURE.match(str(apt.get("heure", "03:00"))):
        refuse("majs", "heure : HH:MM")

    return ex


# ── Fuseau horaire proposé (#1542) ─────────────────────────────────────────
# Une image neuve est en UTC : ce n'est le choix de personne. On propose
# alors le fuseau de la langue par défaut de l'assistant (fr → Paris).
FUSEAU_DEFAUT = "Europe/Paris"
_FUSEAUX_NEUTRES = {"", "UTC", "Etc/UTC", "Etc/Universal", "Universal", "Zulu", "GMT", "Etc/GMT"}


def fuseau_propose(chemin: Path = Path("/etc/timezone")) -> str:
    try:
        actuel = chemin.read_text().strip()
    except OSError:
        actuel = ""
    return FUSEAU_DEFAUT if actuel in _FUSEAUX_NEUTRES else actuel


def fuseaux() -> List[str]:
    """Les fuseaux « Région/Ville » que la box connaît, pour la liste à chercher."""
    try:
        import zoneinfo  # noqa: PLC0415
        tous = zoneinfo.available_timezones()
    except Exception:  # noqa: BLE001
        return [FUSEAU_DEFAUT]
    return sorted(z for z in tous if "/" in z
                  and not z.startswith(("Etc/", "posix/", "right/", "SystemV/", "US/", "Brazil/", "Canada/", "Chile/", "Mexico/")))
