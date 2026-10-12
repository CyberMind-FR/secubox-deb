# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Code d'invitation du maillage (#2475) : l'adresse du parent ET le jeton en UNE seule chaîne.

Avant, rejoindre le maillage demandait deux saisies (l'IP du parent, le jeton de 64 caractères hexadécimaux). Le code les porte ensemble, avec une somme de contrôle pour
refuser une faute de frappe ou un copier-coller tronqué : `sbxmesh1.<base64url>.<4 caractères>`. Le code est un SECRET (il contient le jeton, à usage unique et à durée
limitée) : il ne se journalise jamais. Rien ici ne donne un droit : le parent valide le jeton et garde la décision d'approbation."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from typing import Tuple

PREFIXE = "sbxmesh1."
_JETON = re.compile(r"^[0-9a-f]{64}$")
_HOTE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_MAX = 600


def adresse_valide(adresse: str) -> bool:
    """Nom d'hôte ou adresse IP (v4/v6) nus : ni schéma, ni chemin, ni port, ni espace — l'adresse part dans une URL construite côté box."""
    a = (adresse or "").strip()
    if not a or len(a) > 253:
        return False
    try:
        ipaddress.ip_address(a)
        return True
    except ValueError:
        return bool(_HOTE.fullmatch(a))


def _somme(charge: str) -> str:
    return hashlib.sha256(charge.encode()).hexdigest()[:4]


def encoder(adresse: str, jeton: str) -> str:
    if not adresse_valide(adresse):
        raise ValueError("adresse du parent invalide")
    if not _JETON.fullmatch(jeton or ""):
        raise ValueError("jeton invalide")
    charge = base64.urlsafe_b64encode(json.dumps({"a": adresse.strip(), "t": jeton}, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{PREFIXE}{charge}.{_somme(charge)}"


def decoder(code: str) -> Tuple[str, str]:
    """(adresse, jeton) ou ValueError. Strict : préfixe, somme, JSON exact, adresse et jeton revalidés."""
    c = (code or "").strip()
    if not c.startswith(PREFIXE) or len(c) > _MAX:
        raise ValueError("code illisible")
    reste = c[len(PREFIXE):]
    charge, sep, somme = reste.rpartition(".")
    if not sep or not charge or somme != _somme(charge):
        raise ValueError("code corrompu (somme de contrôle)")
    try:
        brut = base64.urlsafe_b64decode(charge + "=" * (-len(charge) % 4))
        d = json.loads(brut.decode("utf-8"))
        adresse, jeton = d["a"], d["t"]
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise ValueError("code illisible") from None
    if not isinstance(adresse, str) or not isinstance(jeton, str) or set(d) != {"a", "t"}:
        raise ValueError("code illisible")
    if not adresse_valide(adresse) or not _JETON.fullmatch(jeton):
        raise ValueError("code invalide")
    return adresse.strip(), jeton


# ── Jonction automatique au démarrage ─────────────────────────────────────────────────────────────────────────────────────────────────────────
CODE_DEPOSE = "/var/lib/secubox/p2p/automesh.code"
ETAT = "/var/lib/secubox/p2p/automesh.json"
AGE_MAX_S = 24 * 3600
ECHECS_MAX = 5


def _lire_json(chemin: str) -> dict:
    try:
        with open(chemin, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _ecrire_etat(chemin: str, etat: dict) -> None:
    import os
    tmp = chemin + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(etat, f, ensure_ascii=False, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, chemin)


def executer(rejoindre, code_path: str = CODE_DEPOSE, etat_path: str = ETAT, maintenant: float | None = None) -> str:
    """Un passage de la jonction automatique : si un code a été déposé (par la préparation de la box), la box APPELLE le parent avec ce code.

    `rejoindre(adresse, jeton)` -> dict {status: approved|pending|…} (appel sortant) ; lève en cas d'échec. Rend l'état : aucun | approuve | en_attente | echec | invalide |
    expire. Le code (donc le jeton) n'est JAMAIS écrit dans l'état ni dans un message : seul le parent est nommé. Approuvé -> le code est supprimé (jeton à usage unique) ;
    en attente -> gardé pour le prochain passage (demande idempotente côté parent) jusqu'à 24 h ; refusé 5 fois -> supprimé."""
    import os
    import time
    now = time.time() if maintenant is None else maintenant
    try:
        with open(code_path, encoding="utf-8") as f:
            brut = f.read(_MAX + 2)
    except OSError:
        return "aucun"
    etat = _lire_json(etat_path)
    debut = etat.get("debut") if isinstance(etat.get("debut"), (int, float)) else now
    echecs = int(etat.get("echecs", 0)) if str(etat.get("echecs", 0)).isdigit() else 0

    def fin(statut: str, supprimer: bool, **extra) -> str:
        if supprimer:
            try:
                os.unlink(code_path)
            except OSError:
                pass
        _ecrire_etat(etat_path, {"statut": statut, "debut": debut, "dernier": now, "echecs": echecs, **extra})
        return statut

    try:
        adresse, jeton = decoder(brut)
    except ValueError as e:
        return fin("invalide", True, message=str(e))
    if now - debut > AGE_MAX_S:
        return fin("expire", True, parent=adresse, message="code déposé depuis plus de 24 h")
    try:
        res = rejoindre(adresse, jeton)
    except Exception as e:  # noqa: BLE001 — l'échec est dit, jamais le secret
        echecs += 1
        detail = getattr(e, "detail", None) or type(e).__name__
        return fin("echec", echecs >= ECHECS_MAX, parent=adresse, message=str(detail)[:120])
    statut = str((res or {}).get("status", ""))
    if statut == "approved":
        return fin("approuve", True, parent=adresse, mesh_ip=(res or {}).get("mesh_ip"))
    if statut == "pending":
        return fin("en_attente", False, parent=adresse, message="en attente de l'approbation du parent")
    echecs += 1
    return fin("echec", echecs >= ECHECS_MAX, parent=adresse, message="réponse inattendue du parent")


def rejoindre_par_script(adresse: str, jeton: str, run=None, script: str = "/usr/bin/sbx-mesh-join") -> dict:
    """Jonction COMPLÈTE par le script éprouvé `sbx-mesh-join` (clés WireGuard, offre du parent, tunnel) — la box appelle le parent. Le jeton passe par l'environnement
    (`-` à la place de l'argument), jamais en ligne de commande visible dans la liste des processus. Rend {status: approved|pending, mesh_ip?} ou lève RuntimeError."""
    import os
    import re as _re
    import subprocess
    run = run or subprocess.run
    if not adresse_valide(adresse) or not _JETON.fullmatch(jeton or ""):
        raise RuntimeError("code invalide")
    r = run([script, adresse, "-"], env={**os.environ, "SBX_MESH_TOKEN": jeton}, capture_output=True, text=True, timeout=180)
    sortie = (getattr(r, "stdout", "") or "")
    if getattr(r, "returncode", 1) != 0:
        raise RuntimeError(f"jonction refusée ou parent injoignable (code {getattr(r, 'returncode', '?')})")
    if "Status: APPROVED" in sortie:
        m = _re.search(r"Mesh address:\s*([0-9a-fA-F.:/]+)", sortie)
        return {"status": "approved", "mesh_ip": m.group(1) if m else None}
    if "PENDING" in sortie:
        return {"status": "pending"}
    raise RuntimeError("réponse inattendue du script de jonction")
