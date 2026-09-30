# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: annuaire.openpgp — les clés OpenPGP liées aux box (#1736)

Lecteur pur : quelle clé OpenPGP chaque box a-t-elle LIÉE à son identité ?

La règle, et elle ne se discute pas : une liaison ne vaut que si son AUTEUR
vérifié est le did qu'elle nomme. import_entries fédère toute opération
valablement signée : un pair peut signer une entrée « did = gk2, empreinte =
la mienne » avec SA clé — elle est authentique, mais n'engage que lui. Sans ce
lien à l'auteur, n'importe quel nœud du maillage pourrait se faire passer pour
un autre auprès de ses correspondants chiffrés (même leçon qu'annuaire.assist).

Deux sources d'entrées :
  * le journal local (Journal.iter_entries) — déjà vérifié à l'import ;
  * l'export d'un annuaire (/log/export) — `verifier=True` refait la preuve
    (did = empreinte de la clé, signature de la charge) avant d'y croire.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Iterable, Optional

from pydantic import ValidationError

from .crypto import canonical_bytes, did_from_pubkey, verify
from .model import OpenPGPBinding, OpenPGPRevocation


def _champ(e: Any, nom: str) -> Any:
    v = getattr(e, nom, None)
    if v is None and isinstance(e, dict):
        v = e.get(nom)
    return v


def _op(e: Any) -> str:
    op = _champ(e, "op")
    return str(getattr(op, "value", op) or "")


def authentique(e: Any) -> bool:
    """did = sha256(clé)[:32] et signature valide sur canonical_bytes(payload)."""
    pub, auteur, sig, charge = (_champ(e, "author_pubkey"), _champ(e, "author"),
                                _champ(e, "sig"), _champ(e, "payload"))
    if not (isinstance(pub, str) and isinstance(auteur, str) and isinstance(sig, str)
            and isinstance(charge, dict)):
        return False
    try:
        if did_from_pubkey(bytes.fromhex(pub)) != auteur:
            return False
    except ValueError:
        return False
    return verify(pub, canonical_bytes(charge), sig)


def liaisons(entrees: Iterable[Any], maintenant: Optional[float] = None,
             verifier: bool = False) -> Dict[str, dict]:
    """{did: {empreinte, cle_publique, creee, expire, created_at}} — la DERNIÈRE
    liaison auto-signée de chaque box, ni révoquée ni expirée."""
    t = time.time() if maintenant is None else maintenant
    liees: Dict[str, dict] = {}
    revoquees: Dict[str, set] = {}
    for e in entrees:
        op = _op(e)
        if op not in ("openpgp_bind", "openpgp_revoke"):
            continue
        if verifier and not authentique(e):
            continue
        charge, auteur = _champ(e, "payload"), _champ(e, "author")
        if not isinstance(charge, dict):
            continue
        try:
            if op == "openpgp_bind":
                m = OpenPGPBinding(**charge)
            else:
                m = OpenPGPRevocation(**charge)
        except (ValidationError, TypeError):
            continue
        # L'op n'est pas signé : c'est `usage`, DANS la charge, qui dit le verbe.
        if m.usage != op or m.did != auteur:
            continue
        if op == "openpgp_revoke":
            revoquees.setdefault(m.did, set()).add(m.empreinte)
        else:
            liees[m.did] = {"empreinte": m.empreinte, "cle_publique": m.cle_publique,
                            "creee": m.creee, "expire": m.expire, "created_at": m.created_at}
    actives = {}
    for did, l in liees.items():
        if l["empreinte"] in revoquees.get(did, set()):
            continue
        if l["expire"] and l["expire"] <= t:
            continue
        actives[did] = l
    return actives


def empreinte_de(entrees: Iterable[Any], did: str, maintenant: Optional[float] = None,
                 verifier: bool = False) -> Optional[str]:
    """L'empreinte OpenPGP active de `did`, ou None."""
    l = liaisons(entrees, maintenant, verifier).get(did)
    return l["empreinte"] if l else None
