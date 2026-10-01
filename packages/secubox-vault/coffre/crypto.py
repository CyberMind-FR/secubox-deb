# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Primitives du Coffre — rien de fait maison (POLITIQUE-CRYPTO).

Argon2id (64 Mio, 3 passes, 4 voies : 0,42 s mesurées sur gk2) dérive la clé
d'une serrure ; AES-256-GCM emballe la MK et chiffre les secrets ; HKDF-SHA256
dérive la clé d'un compartiment. Chaque chiffrement porte une donnée associée
qui le lie à SA place : une MK emballée ne s'ouvre qu'avec sa serrure, un secret
ne se déchiffre pas déplacé dans un autre compartiment, sous un autre nom ou à
une autre version.
"""
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ARGON2_DEFAUT = {"t": 3, "m": 65536, "p": 4}
TAILLE_CLE = 32
TAILLE_SEL = 16
TAILLE_NONCE = 12
_ESPACE = b"secubox-coffre/v1/"


class Refus(Exception):
    """Déchiffrement refusé : mauvaise clé ou donnée déplacée/altérée."""


def nouvelle_cle() -> bytes:
    return os.urandom(TAILLE_CLE)


def nouveau_sel() -> bytes:
    return os.urandom(TAILLE_SEL)


def derive_kek(secret: bytes, sel: bytes, params: dict) -> bytes:
    if len(sel) < TAILLE_SEL:
        raise ValueError("sel trop court")
    return hash_secret_raw(secret, sel, time_cost=int(params["t"]), memory_cost=int(params["m"]),
                           parallelism=int(params["p"]), hash_len=TAILLE_CLE, type=Type.ID)


def aad_serrure(id_serrure: str) -> bytes:
    return _ESPACE + b"serrure/" + id_serrure.encode()


def aad_secret(compartiment: str, nom: str, version: int) -> bytes:
    return _ESPACE + b"secret/" + b"\0".join((compartiment.encode(), nom.encode(), str(version).encode()))


def chiffrer(cle: bytes, clair: bytes, aad: bytes) -> tuple:
    nonce = os.urandom(TAILLE_NONCE)
    return nonce, AESGCM(cle).encrypt(nonce, clair, aad)


def dechiffrer(cle: bytes, nonce: bytes, chiffre: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(cle).decrypt(nonce, chiffre, aad)
    except InvalidTag as e:
        raise Refus() from e


def cle_compartiment(mk: bytes, compartiment: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=TAILLE_CLE, salt=None,
                info=_ESPACE + b"compartiment/" + compartiment.encode()).derive(mk)


def derive_kek_appareil(prf: bytes, sel: bytes) -> bytes:
    """Clé d'une serrure d'appareil (P4) : la sortie WebAuthn PRF (32 octets
    d'entropie, rendus par l'authentificateur pour CE sel et CETTE origine)
    n'a pas besoin d'Argon2 — HKDF suffit."""
    if len(prf) != TAILLE_CLE:
        raise ValueError("sortie PRF de 32 octets attendue")
    return HKDF(algorithm=hashes.SHA256(), length=TAILLE_CLE, salt=sel,
                info=_ESPACE + b"appareil").derive(prf)


def aad_serrure_personnelle(id_serrure: str, personne: str) -> bytes:
    """Une serrure personnelle emballe la clé d'UNE personne : déplacée vers
    une autre, elle ne s'ouvre plus."""
    return _ESPACE + b"serrure-personnelle/" + personne.encode() + b"\0" + id_serrure.encode()


def cle_compartiment_personnel(mk: bytes, compartiment: str, cle_personne: bytes) -> bytes:
    """Clé d'un compartiment de personne (P5) : il faut la MK (Coffre ouvert)
    ET la clé de la personne (sa serrure à elle). L'une sans l'autre ne
    déchiffre rien — ni l'admin qui a ouvert le Coffre, ni la personne quand
    il est scellé."""
    if len(cle_personne) != TAILLE_CLE:
        raise ValueError("clé de personne de 32 octets attendue")
    return HKDF(algorithm=hashes.SHA256(), length=TAILLE_CLE, salt=None,
                info=_ESPACE + b"compartiment-personnel/" + compartiment.encode()).derive(
        cle_compartiment(mk, compartiment) + cle_personne)
