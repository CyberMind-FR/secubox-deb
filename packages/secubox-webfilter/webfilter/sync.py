# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""secubox-webfilter-sync : télécharge les listes du catalogue et reconstruit les index."""
import argparse
import sys
from pathlib import Path

from . import catalogue, sources

CATALOGUE = "/etc/secubox/webfilter.toml"
ETAT = "/var/lib/secubox/webfilter"


def principal(argv=None, fetch=sources.telecharger) -> int:
    ap = argparse.ArgumentParser(prog="secubox-webfilter-sync", description="Synchronise les listes publiques de secubox-webfilter.")
    ap.add_argument("--catalogue", default=CATALOGUE)
    ap.add_argument("--etat", default=ETAT)
    a = ap.parse_args(argv)
    try:
        cats = catalogue.charger(a.catalogue)
    except catalogue.ErreurCatalogue as e:
        print(f"secubox-webfilter : {e}", file=sys.stderr)
        return 2
    rc = 0
    for cat in cats:
        res = sources.synchroniser(cat, Path(a.etat) / "listes", fetch=fetch)
        if cat.sources and not any(r["ok"] for r in res.values()):
            print(f"secubox-webfilter : {cat.id} : aucune source synchronisée ({'; '.join(r['erreur'] or '' for r in res.values())})", file=sys.stderr)
            rc = 1
    return rc
