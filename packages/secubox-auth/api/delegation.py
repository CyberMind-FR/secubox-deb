# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: auth — entrée déléguée d'un autre nœud (#1720)
CyberMind — https://cybermind.fr

Décision de Gandalf : un compte d'un nœud (gk2@gk2, depuis le Hall de gk2)
administre ENTIÈREMENT un autre nœud à distance, pour une durée bornée, et
chaque geste est tracé.

Le pouvoir ne vient jamais de l'assertion : elle prouve seulement qui frappe
(signée par la clé publiée du nœud centre, 60 s, usage unique). Il vient du
consentement que CETTE box a signé dans son propre journal — session
d'assistance ouverte pour ce centre ET administration autorisée
(accord de console) — et il cesse avec lui.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ANNUAIRE_LIB = os.environ.get("ANNUAIRE_LIB", "/usr/lib/secubox/annuaire")
JOURNAL = os.environ.get("ANNUAIRE_JOURNAL", "/var/lib/secubox/annuaire/journal.db")
CLE = os.environ.get("ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")

_nonces: Dict[str, float] = {}
_verrou = threading.Lock()


def annuaire():
    """Modules de l'annuaire (paquet secubox-annuaire), chargés à la demande."""
    if ANNUAIRE_LIB not in sys.path:
        # En FIN de chemin : l'annuaire a aussi un paquet « api », qui
        # masquerait celui de l'auth.
        sys.path.append(ANNUAIRE_LIB)
    from annuaire import assist, delegation  # noqa: PLC0415
    from annuaire.crypto import did_from_pubkey, public_from_private  # noqa: PLC0415
    from annuaire.log import Journal  # noqa: PLC0415
    return Journal, assist, delegation, public_from_private, did_from_pubkey


def maintenant_rfc(t: Optional[float] = None) -> str:
    return datetime.fromtimestamp(t if t is not None else time.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _op(e) -> str:
    op = getattr(e, "op", None) or (e.get("op") if isinstance(e, dict) else None)
    return str(getattr(op, "value", op))


def _payload(e) -> dict:
    p = getattr(e, "payload", None) or (e.get("payload") if isinstance(e, dict) else None)
    return p if isinstance(p, dict) else {}


def _auteur(e) -> Optional[str]:
    return getattr(e, "author", None) or (e.get("author") if isinstance(e, dict) else None)


def cle_publiee(entries: List[Any], did: str) -> Optional[str]:
    """Clé publique de la DERNIÈRE fiche Identity signée par `did` lui-même."""
    pub = None
    for e in entries:
        p = _payload(e)
        if p.get("did") == did and _auteur(e) == did and p.get("pubkey") and \
                (getattr(e, "payload_type", None) or (e.get("payload_type") if isinstance(e, dict) else None)) == "Identity":
            pub = p["pubkey"]
    return pub


def fiche_noeud(entries: List[Any], did: str) -> dict:
    fiche: dict = {}
    for e in entries:
        p = _payload(e)
        if _op(e) == "node_publish" and p.get("did") == did and _auteur(e) == did:
            fiche = p
    return fiche


def nom_compte(compte: str, noeud: str) -> str:
    """`<compte>.<nœud>` au format des comptes (USERNAME_RE de secubox-users)."""
    brut = re.sub(r"[^a-z0-9._-]", "-", f"{compte}.{noeud}".lower()).strip("._-")
    brut = re.sub(r"\.{2,}", ".", brut)[:32].strip("._") or "delegue"
    return brut if len(brut) >= 2 else brut + "0"


def consommer_nonce(nonce: str, exp: float) -> bool:
    """Vrai la première fois qu'on voit ce nonce (jusqu'à son échéance)."""
    t = time.time()
    with _verrou:
        for n, e in list(_nonces.items()):
            if e < t - 120:
                del _nonces[n]
        if nonce in _nonces:
            return False
        _nonces[nonce] = exp
        return True


def verifier_entree(assertion: str, entries: List[Any], self_did: str,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """Payload + échéance si l'entrée est admise ; lève ValueError(motif) sinon."""
    _, assist, delegation, _, _ = annuaire()
    t = time.time() if now is None else now
    p = delegation.verifier(assertion, self_did=self_did,
                            pubkey_de=lambda did: cle_publiee(entries, did), now=t)
    fin = assist.delegation_active(entries, self_did, p["center_did"], p["session_id"],
                                   maintenant_rfc(t))
    if not fin:
        raise ValueError("aucune autorisation d'administration active pour ce centre")
    if not consommer_nonce(p["nonce"], p["exp"]):
        raise ValueError("assertion déjà utilisée")
    fiche = fiche_noeud(entries, p["center_did"])
    return {**p, "fin": fin,
            "noeud": fiche.get("boxname") or p["center_did"].split(":")[-1][:8]}


def fermees(registre: Dict[str, dict], entries: List[Any], self_did: str,
            now: Optional[float] = None) -> List[str]:
    """Comptes délégués dont l'autorisation n'est plus active."""
    _, assist, _, _, _ = annuaire()
    r = maintenant_rfc(now)
    return [nom for nom, d in registre.items()
            if not assist.delegation_active(entries, self_did, d.get("centre", ""),
                                            d.get("session", ""), r)]


def lire_registre(chemin: Path) -> Dict[str, dict]:
    try:
        d = json.loads(chemin.read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def ecrire_registre(chemin: Path, registre: Dict[str, dict]) -> None:
    tmp = chemin.with_suffix(".tmp")
    tmp.write_text(json.dumps(registre, ensure_ascii=False, indent=1))
    os.chmod(tmp, 0o640)
    tmp.replace(chemin)


def did_du_noeud(chemin: str = CLE) -> str:
    _, _, _, public_from_private, did_from_pubkey = annuaire()
    raw = bytes.fromhex(open(chemin).read().strip())
    return did_from_pubkey(public_from_private(raw))


def entrees(journal: str = JOURNAL) -> List[Any]:
    Journal = annuaire()[0]
    return list(Journal(journal).iter_entries())


PAGE = """<!doctype html><meta charset="utf-8"><title>Administration déléguée</title>
<p>Administration de cette box au nom de <b>{etiquette}</b>, jusqu'à {fin} (UTC).</p>
<script>try{{localStorage.setItem('sbx_token',{jeton});}}catch(e){{}}location.replace('/');</script>"""
