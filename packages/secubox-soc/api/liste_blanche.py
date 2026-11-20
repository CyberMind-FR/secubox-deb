# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Liste blanche de SADE en ligne de commande, sur la box (#3839) : le même geste audité que la page.

    cd /usr/lib/secubox/soc && runuser -u secubox -- python3 -m api.liste_blanche lister
    runuser -u secubox -- python3 -m api.liste_blanche ajouter 203.0.113.7/32 "adresse publique du foyer"
    runuser -u secubox -- python3 -m api.liste_blanche retirer 203.0.113.7/32

Toujours sous le compte `secubox` (propriétaire de defense.db) : lancé en root, SQLite créerait des fichiers de
journal root que le service ne pourrait plus écrire. L'opérateur audité est `cli:<utilisateur sudo ou connecté>`.
"""
import os
import sys

from . import defense_etat


def _operateur() -> str:
    return "cli:" + (os.environ.get("SUDO_USER") or os.environ.get("LOGNAME") or os.environ.get("USER") or "inconnu")


def main(argv=None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    if os.geteuid() == 0:
        print("refusé en root : runuser -u secubox -- python3 -m api.liste_blanche …", file=sys.stderr)
        return 2
    try:
        if a[:1] == ["lister"] and len(a) == 1:
            for e in defense_etat.liste_blanche():
                print(f"{e['cidr']}\t{e['motif']}\t{'ajout' if e['supprimable'] else 'systeme'}")
            return 0
        if a[:1] == ["ajouter"] and len(a) == 3:
            print("ajouté :", defense_etat.ajouter_liste_blanche(a[1], a[2], _operateur()))
            return 0
        if a[:1] == ["retirer"] and len(a) == 2:
            print("retiré :", defense_etat.retirer_liste_blanche(a[1], _operateur()))
            return 0
    except (ValueError, KeyError, PermissionError) as e:
        print(f"refusé : {e}", file=sys.stderr)
        return 1
    except (defense_etat.EtatIndisponible, defense_etat.AuditIndisponible) as e:
        print(f"indisponible : {e.__class__.__name__}", file=sys.stderr)
        return 1
    print("usage : python3 -m api.liste_blanche lister | ajouter <cidr> <motif> | retirer <cidr>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
