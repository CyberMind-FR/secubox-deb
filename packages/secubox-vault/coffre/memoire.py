# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Une clé en mémoire verrouillée, effaçable.

AU MIEUX, ET ON LE DIT. Les octets vivent dans un `bytearray` verrouillé par
mlock (jamais en swap) et mis à zéro au scellement. Mais `cryptography` reçoit
une copie `bytes`, immuable, que Python ne permet pas d'effacer : elle disparaît
avec le ramasse-miettes. Le processus tourne sans vidage mémoire (LimitCORE=0)
pour qu'aucune copie ne finisse sur disque.
"""
import ctypes
import ctypes.util

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


class CleVerrouillee:
    """Octets secrets : mlock à la création, zéro + munlock à l'effacement."""

    def __init__(self, donnees: bytes):
        self._b = bytearray(donnees)
        self._verrouillee = False
        if self._b:
            adr, n = self._adresse()
            self._verrouillee = _libc.mlock(ctypes.c_void_p(adr), ctypes.c_size_t(n)) == 0

    def _adresse(self):
        tampon = (ctypes.c_char * len(self._b)).from_buffer(self._b)
        adr = ctypes.addressof(tampon)
        del tampon
        return adr, len(self._b)

    @property
    def verrouillee(self) -> bool:
        return self._verrouillee

    def octets(self) -> bytes:
        if not self._b:
            raise ValueError("clé effacée")
        return bytes(self._b)

    def effacer(self) -> None:
        if not self._b:
            return
        adr, n = self._adresse()
        ctypes.memset(ctypes.c_void_p(adr), 0, n)
        if self._verrouillee:
            _libc.munlock(ctypes.c_void_p(adr), ctypes.c_size_t(n))
        self._b = bytearray()
        self._verrouillee = False

    def __bool__(self) -> bool:
        return bool(self._b)

    def __repr__(self) -> str:          # jamais les octets, même en débogage
        return f"<CleVerrouillee {'vide' if not self._b else len(self._b)}>"
