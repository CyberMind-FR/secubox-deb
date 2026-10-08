# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Une unité systemd n'est livrée qu'UNE fois par paquet (#2146).

`secubox-soc-agent` posait son unité dans `lib/systemd/system` (debian/rules) pendant que `dh_installsystemd` la posait aussi
dans `usr/lib/systemd/system` : sur Debian 13 (usrmerge) `/lib` est `/usr/lib`, le paquet contenait deux fois le même fichier
et `dpkg` échouait au dépaquetage (« unable to open … .dpkg-new »). Or lite dépend de ce paquet : l'image n'aurait pas pu se construire."""
import re
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2] / "packages"


def test_aucune_unite_n_est_installee_a_la_main_en_plus_de_dh_installsystemd():
    fautifs = []
    for rules in sorted(PAQUETS.glob("*/debian/rules")):
        pkg = rules.parent.parent.name
        unite = rules.parent / f"{pkg}.service"
        if not unite.exists():
            continue
        t = rules.read_text(encoding="utf-8", errors="replace")
        # install de `<pkg>.service` sous lib/systemd/system (sans usr/), sur la même commande (continuations `\\` jointes)
        commandes = re.sub(r"\\\n\s*", " ", t).splitlines()
        # `<pkg>.service` seul : un drop-in `<pkg>.service.d/` ou `<pkg>.service-xyz` n'est pas l'unité principale.
        if any(re.search(rf"{re.escape(pkg)}\.service(?![.\w-])", c) and f"debian/{pkg}/lib/systemd/system" in c for c in commandes):
            fautifs.append(pkg)
    assert not fautifs, fautifs
