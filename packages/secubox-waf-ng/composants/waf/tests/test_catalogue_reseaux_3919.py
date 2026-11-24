# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3919, lot 1b : catalogue livré des classes de réseau — un ASN dans une seule classe, lu pareil en Python et en Go
(`TestCatalogueLivre`), classes connues seulement."""
import sys
import tomllib
from pathlib import Path

COMPOSANT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPOSANT))
from api import populations as P  # noqa: E402

CATALOGUE = COMPOSANT / "config" / "reseaux-classes.toml"
CLASSES = tomllib.loads(CATALOGUE.read_text(encoding="utf-8"))["classes"]


def test_un_asn_dans_une_seule_classe():
    tous = [a for liste in CLASSES.values() for a in liste]
    assert len(tous) == len(set(tous)), sorted({a for a in tous if tous.count(a) > 1})
    assert all(isinstance(a, int) and 0 < a < 2 ** 32 for a in tous) and set(CLASSES) == set(P.CLASSES)


def test_le_releve_lit_tout_le_catalogue():
    cat = P.charger_catalogue([str(CATALOGUE)])
    assert len(cat) == sum(len(x) for x in CLASSES.values())
    assert cat[22773] == cat[4134] == cat[29518] == "acces" and cat[24940] == "hebergeur" and cat[212238] == "proxy_loue"
    assert cat[14593] == "mobile_partage" and CLASSES["mobile_partage"] == [14593]
