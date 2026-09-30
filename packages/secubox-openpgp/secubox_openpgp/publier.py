# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: openpgp — publier la liaison dans l'annuaire (#1736)

Exécuté SOUS L'UTILISATEUR `secubox` par `sbx-openpgp lier` : c'est le compte
qui lit node.key et écrit le journal. Le démon secubox-openpgp, lui, ne voit
jamais node.key — séparation voulue : la clé qui lie n'est pas celle qui
chiffre.

Entrée (stdin, JSON) : {empreinte, cle_publique, creee, expire}. Idempotent :
si la liaison active de la box porte déjà cette empreinte, rien n'est écrit.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time

sys.path.append(os.environ.get("ANNUAIRE_LIB", "/usr/lib/secubox/annuaire"))

from annuaire import openpgp as lecteur, verbs  # noqa: E402
from annuaire.crypto import did_from_pubkey, public_from_private  # noqa: E402
from annuaire.log import Journal  # noqa: E402

CLE = os.environ.get("ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")
JOURNAL = os.environ.get("ANNUAIRE_JOURNAL", "/var/lib/secubox/annuaire/journal.db")


def main() -> int:
    d = json.load(sys.stdin)
    raw = open(CLE).read().strip()
    if len(raw) != 64:
        print("node.key illisible", file=sys.stderr)
        return 2
    priv = bytes.fromhex(raw)
    did = did_from_pubkey(public_from_private(priv))
    j = Journal(JOURNAL)
    # Sans fiche Identity publiée, aucun pair ne pourrait vérifier l'entrée (#1711).
    verbs.genesis(j, priv)
    if lecteur.empreinte_de(j.iter_entries(), did) == d["empreinte"].upper():
        print(json.dumps({"ok": True, "deja": True, "did": did}))
        return 0
    # Plusieurs processus écrivent ce journal : une collision de hauteur est
    # une exception, pas une corruption — on retente.
    for essai in range(5):
        try:
            verbs.openpgp_bind(j, priv, d["empreinte"], d["cle_publique"],
                               int(d["creee"]), int(d["expire"]))
            break
        except sqlite3.IntegrityError:
            time.sleep(0.5 * (essai + 1))
    else:
        print("journal occupé — réessayer", file=sys.stderr)
        return 3
    print(json.dumps({"ok": True, "deja": False, "did": did}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
