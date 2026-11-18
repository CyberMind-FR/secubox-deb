# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Liste des adresses isolées pour sbxwaf (#3800), dans le dossier dédié /run/secubox/garde (tmpfiles).

Un appareil en quarantaine d'infection voit toutes ses résolutions DNS pointer vers la box : ses requêtes HTTP
arrivent à sbxwaf avec un Host inconnu. sbxwaf lit ce fichier et sert alors la page d'explication au lieu du 421.
Écrit après chaque passage et au rapprochement, de façon atomique (temporaire + rename), mode 0644.
Seules les quarantaines d'infection actives y figurent, avec toutes les adresses de l'appareil.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import List

CHEMIN = Path("/run/secubox/garde/isoles.json")
MOTIF_MAX = 120


def lister(db) -> List[dict]:
    """Une entrée par adresse de chaque quarantaine d'infection active."""
    sortie: List[dict] = []
    vues = set()
    lignes = db.execute("SELECT id, cible, ip, motif, debut FROM decisions "
                        "WHERE etat='active' AND menace='infection' ORDER BY debut, id").fetchall()
    for did, cible, ip, motif, debut in lignes:
        noms = db.execute("SELECT noms FROM decision_noms WHERE decision_id=?", (did,)).fetchone()
        nom = next((n for n in (noms[0] if noms and noms[0] else "").split(",") if n), None) or cible or ""
        adresses = [r[0] for r in db.execute("SELECT ip FROM adresses WHERE decision_id=? ORDER BY ip", (did,))]
        for a in adresses or ([ip] if ip else []):
            if a in vues:
                continue
            vues.add(a)
            sortie.append({"ip": a, "nom": str(nom)[:80], "depuis": int(debut or 0),
                           "motif": str(motif or "infection")[:MOTIF_MAX]})
    return sortie


def ecrire(db, maintenant: int, chemin: Path = CHEMIN) -> int:
    """Écrit la liste atomiquement ; rend le nombre d'adresses. Un échec d'écriture lève OSError."""
    isoles = lister(db)
    donnees = json.dumps({"genere_le": int(maintenant), "isoles": isoles}, ensure_ascii=False)
    fd, tmp = tempfile.mkstemp(prefix=".isoles.", dir=str(chemin.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(donnees)
            f.flush()
            os.fchmod(f.fileno(), 0o644)
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return len(isoles)
