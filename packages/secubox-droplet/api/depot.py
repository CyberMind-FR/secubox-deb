# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Droplet — réception d'un dépôt (#1026)

CyberMind — https://cybermind.fr

Le module droplet PUBLIE des fichiers ; ce fichier-ci en RECOIT. Les deux ne se
ressemblent qu'en surface : publier suppose un auteur authentifie qui choisit
une adresse, deposer suppose un inconnu qui laisse quelque chose et s'en va.

D'ou une regle qui gouverne tout ce module : on ne fait confiance a RIEN de ce
que le deposant declare — nom, type, taille annoncee. On ne rapporte que ce
qu'on a CONSTATE en ecrivant : la taille reelle et l'empreinte.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


class DepotRefuse(Exception):
    """Le dépôt n'a pas été accepté. Le message est destiné au déposant."""


# Un nom lisible : lettres, chiffres, et la ponctuation qui sert. Volontairement
# étroit — voir nom_affichable(), qui explique pourquoi ce filtre ne protège
# rien à lui seul.
_NOM_PROPRE = re.compile(r"[^A-Za-z0-9._ -]+")

# 1 Mio : assez grand pour ne pas multiplier les appels système sur une archive
# de 2 Gio, assez petit pour que la mémoire du processus ne suive pas la taille
# du dépôt.
TAILLE_BLOC = 1 << 20


def nom_affichable(brut: str, defaut: str = "depot.bin") -> str:
    """Rend un nom LISIBLE, destiné à l'affichage — jamais à un chemin.

    LE NOM FOURNI EST UNE DONNEE HOSTILE. Il vient d'un client qu'on ne
    contrôle pas et peut porter `../`, un octet nul, un séparateur Windows, ou
    quatre kilo-octets de texte.

    CE N'EST PAS CE FILTRE QUI PROTEGE. Un filtre finit toujours par laisser
    passer quelque chose. Ce qui protège, c'est que le chemin de stockage est
    DERIVE d'un identifiant que nous choisissons : ce nom-ci ne sert qu'à dire
    à un humain ce qu'il a envoyé, et n'ouvre jamais un fichier.
    """
    if not brut:
        return defaut
    # Les séparateurs des deux mondes, pour ne garder que le dernier segment.
    brut = brut.replace("\\", "/").split("/")[-1]
    # Les caractères de contrôle ne s'affichent pas mais COUPENT UN EN-TETE DE
    # COURRIER EN DEUX — c'est un vecteur réel, pas une coquetterie.
    brut = "".join(c for c in brut if unicodedata.category(c)[0] != "C")
    brut = _NOM_PROPRE.sub("_", brut).strip(" .")
    if not brut:
        return defaut
    # Un nom de 4 Kio tiendrait dans un en-tête MIME et rendrait l'alerte
    # illisible. Le tronquer garde l'extension, qu'on lit en premier.
    if len(brut) > 120:
        tige, point, ext = brut.rpartition(".")
        if point and 0 < len(ext) <= 12:
            brut = tige[: 120 - len(ext) - 1] + "." + ext
        else:
            brut = brut[:120]
    return brut


@dataclass
class Recu:
    """Ce qu'on CONSTATE d'un fichier, une fois ses octets sur le disque."""

    nom: str
    taille: int
    sha256: str
    chemin: Path


@dataclass
class Depot:
    """Un dépôt : un ou plusieurs fichiers, une origine, un instant."""

    identifiant: str
    recu_le: int
    origine: str
    dossier: Path
    fichiers: list[Recu] = field(default_factory=list)
    mot: str = ""

    @property
    def taille(self) -> int:
        return sum(f.taille for f in self.fichiers)


def identifiant(horloge=time.time) -> str:
    """Un identifiant de dépôt : trié dans l'ordre du temps, non devinable.

    L'HORODATAGE SEUL NE SUFFIT PAS. Deux dépôts dans la même seconde se
    marcheraient dessus. Le suffixe aléatoire règle cela, et accessoirement
    empêche de deviner les voisins — ce qui n'aurait d'importance que si les
    dépôts étaient reservis, et l'on ne veut pas dépendre de cette promesse.
    """
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime(horloge())) + \
        "-" + os.urandom(6).hex()


def ecris_flux(source: BinaryIO, cible: Path, taille_max: int) -> tuple[int, str]:
    """Écrit un flux sur le disque en comptant et en empreignant AU PASSAGE.

    ON NE FAIT PAS CONFIANCE A `Content-Length`. La taille annoncée est une
    intention ; la seule qui compte est celle qu'on a réellement écrite.
    Compter au fil de l'écriture permet de s'arrêter DES le dépassement, au
    lieu de découvrir après coup qu'on a rempli le disque.

    L'empreinte est calculée dans la MEME passe : relire le fichier ensuite
    doublerait les entrées-sorties sur une board dont le disque est la
    ressource rare.
    """
    h = hashlib.sha256()
    ecrit = 0
    try:
        with open(cible, "wb") as sortie:
            while True:
                bloc = source.read(TAILLE_BLOC)
                if not bloc:
                    break
                ecrit += len(bloc)
                if taille_max and ecrit > taille_max:
                    raise DepotRefuse(
                        f"dépôt refusé : au-delà de {taille_max} octets")
                h.update(bloc)
                sortie.write(bloc)
    except DepotRefuse:
        # LE FICHIER PARTIEL EST EFFACE. Le laisser occuperait le disque sans
        # qu'aucune trace ne le rattache à un dépôt — c'est-à-dire exactement
        # ce qu'un attaquant cherche à obtenir.
        cible.unlink(missing_ok=True)
        raise
    os.chmod(cible, 0o640)
    return ecrit, h.hexdigest()


class Limiteur:
    """Un seau percé par origine : borne le débit d'un déposant.

    POURQUOI UN LIMITEUR EST OBLIGATOIRE ICI. Le point de dépôt est public en
    écriture — c'est sa raison d'être. Sans borne, un seul client remplit
    `/data` en une nuit, et la board tombe pour une raison qui n'a rien à voir
    avec la sécurité : le disque plein.

    LE SEAU PERCE PLUTOT QU'UN COMPTEUR PAR FENETRE. Un compteur remis à zéro
    toutes les heures autorise deux fois le quota à cheval sur la bascule ; le
    seau se vide continûment et ne connaît pas ce bord.

    EN MEMOIRE, ASSUME. Le module tourne en un seul processus ; une base
    apporterait la persistance au prix d'une dépendance et d'un verrou. Un
    redémarrage remet les compteurs à zéro — qui sait provoquer nos
    redémarrages nous pose de toute façon un problème plus grave.
    """

    def __init__(self, octets_par_heure: int, depots_par_heure: int,
                 horloge=time.monotonic):
        self.octets_par_heure = octets_par_heure
        self.depots_par_heure = depots_par_heure
        self._horloge = horloge
        self._seaux: dict[str, tuple[float, float, float]] = {}

    def _etat(self, origine: str) -> tuple[float, float, float]:
        maintenant = self._horloge()
        vu, octets, depots = self._seaux.get(origine, (maintenant, 0.0, 0.0))
        ecoule = max(0.0, maintenant - vu)
        octets = max(0.0, octets - self.octets_par_heure * ecoule / 3600.0)
        depots = max(0.0, depots - self.depots_par_heure * ecoule / 3600.0)
        return maintenant, octets, depots

    def autorise(self, origine: str, octets: int) -> None:
        """Lève DepotRefuse si l'origine a déjà trop demandé."""
        maintenant, deja_o, deja_d = self._etat(origine)
        if self.depots_par_heure and deja_d + 1 > self.depots_par_heure:
            raise DepotRefuse(
                "trop de dépôts depuis cette adresse, réessayez plus tard")
        if self.octets_par_heure and deja_o + octets > self.octets_par_heure:
            raise DepotRefuse(
                "volume horaire dépassé pour cette adresse, réessayez plus tard")
        self._seaux[origine] = (maintenant, deja_o + octets, deja_d + 1)

    def rembourse(self, origine: str, octets: int) -> None:
        """Rend le volume d'un dépôt qui a finalement échoué.

        Sans cela, un envoi coupé par le réseau compterait comme abouti, et le
        déposant serait puni d'une panne qui n'est pas la sienne.
        """
        maintenant, deja_o, deja_d = self._etat(origine)
        self._seaux[origine] = (maintenant, max(0.0, deja_o - octets),
                                max(0.0, deja_d - 1))

    def oublie_les_vieux(self, borne: int = 10_000) -> None:
        """Empêche la table de croître sans fin.

        Une adresse par ligne, c'est peu ; un balayage de réseau entier, c'est
        des dizaines de milliers de lignes qu'on garderait pour rien.
        """
        if len(self._seaux) <= borne:
            return
        maintenant = self._horloge()
        self._seaux = {k: v for k, v in self._seaux.items()
                       if maintenant - v[0] < 3600}
