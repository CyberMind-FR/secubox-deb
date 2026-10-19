# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2822 — le postinst de secubox-hub se declare dans /etc/secubox/aggregator.toml SEULEMENT si ce fichier existe deja.

Sans `Depends: secubox-aggregator`, apt peut configurer hub AVANT l'agregateur (qui cree le fichier) : hub n'est jamais declare, /api/v1/hub/ repond 404
et la barre laterale passe en mode de secours (constate sur l'ESPRESSObin minimal ; deja vu sur gk3, #1544)."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
CONTROL = re.sub(r"^#.*\n", "", (PKG / "debian" / "control").read_text(), flags=re.M)
POSTINST = (PKG / "debian" / "postinst").read_text()


def depends_de(paquet):
    bloc = next(b for b in re.split(r"\n\n+", CONTROL) if re.search(rf"^Package:\s*{paquet}\s*$", b, re.M))
    d = " ".join(re.findall(r"^(?:Pre-)?Depends:((?:.*\n?(?: .*\n?)*))", bloc, re.M)).replace("\n", " ")
    return {m.group(1) for a in d.split(",") for m in [re.match(r"\s*([a-z0-9.+-]+)", a)] if m}


def test_hub_depend_de_l_agregateur_qui_cree_aggregator_toml():
    assert "secubox-aggregator" in depends_de("secubox-hub")


def test_la_declaration_reste_conditionnee_a_l_existence_du_fichier():
    """C'est precisement ce qui rend la dependance indispensable : le postinst ne cree pas le fichier, il ne fait qu'y ajouter « hub »."""
    assert "[ -f /etc/secubox/aggregator.toml ]" in POSTINST and 'modules = [\\n    "hub",' in POSTINST


def test_l_agregateur_cree_le_fichier_par_defaut_sans_hub():
    """Le defaut livre par l'agregateur ne contient pas hub : seule la declaration par le postinst de hub l'y met."""
    exemple = (PKG.parent / "secubox-aggregator" / "debian" / "aggregator.toml.example").read_text()
    assert '"hub"' not in exemple
