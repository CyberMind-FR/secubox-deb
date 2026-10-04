# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Validation d'un nom de domaine : rien d'autre qu'un nom valide n'atteint un index, un compteur ou une configuration."""
import re

_NOM = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$"
    r"|^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+xn--[a-z0-9-]{1,59}$")


def valider(brut) -> str | None:
    """Un nom de domaine DNS (au moins deux étiquettes, TLD alphabétique ou punycode) en minuscules ; None sinon. Jamais d'exception."""
    if not isinstance(brut, str) or not brut.isascii():
        return None
    n = brut.strip().rstrip(".").lower()
    return n if _NOM.match(n) else None
