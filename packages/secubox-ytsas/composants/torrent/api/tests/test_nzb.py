# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: torrent — indexeurs Usenet (#1032)"""
import asyncio

import nzb


def lance(coro):
    return asyncio.run(coro)


def test_sans_fichier_ce_n_est_pas_une_panne(tmp_path):
    """Personne n'a de cle au depart : l'absence est l'etat NORMAL."""
    d = lance(nzb.cherche("debian", tmp_path / "absent.toml"))
    assert d["configure"] is False
    assert d["resultats"] == []
    # LE MESSAGE EST LA FONCTIONNALITE : il remplace les faux resultats.
    assert "torrent-nzb.toml" in d["detail"]


def test_un_fichier_illisible_ne_leve_pas(tmp_path):
    p = tmp_path / "x.toml"
    p.write_text("ceci n est pas du toml [[[")
    assert nzb.charge_indexeurs(p) == []


def test_un_indexeur_sans_cle_est_ignore_sans_emporter_les_autres(tmp_path):
    p = tmp_path / "x.toml"
    p.write_text('''
[[indexeur]]
id = "sans-cle"
url = "https://exemple.invalid/api"

[[indexeur]]
id = "bon"
libelle = "Bon"
url = "https://exemple.invalid/api"
cle = "secret-a-ne-pas-fuiter"
''')
    ix = nzb.charge_indexeurs(p)
    assert [i["id"] for i in ix] == ["bon"]


def test_la_cle_ne_sort_jamais(tmp_path):
    """UNE CLE QUI FUIT DANS UNE REPONSE PUBLIQUE EST DONNEE A TOUT LE MONDE :
    la page qui appelle ce module est ouverte."""
    p = tmp_path / "x.toml"
    p.write_text('''
[[indexeur]]
id = "bon"
url = "https://exemple.invalid/api"
cle = "secret-a-ne-pas-fuiter"
''')
    ix = nzb.charge_indexeurs(p)
    public = nzb.indexeurs_publics(ix)
    assert "secret-a-ne-pas-fuiter" not in repr(public)
    assert all("cle" not in i for i in public)

    d = lance(nzb.cherche("debian", p))
    assert "secret-a-ne-pas-fuiter" not in repr(d)


def test_les_attributs_newznab_sont_lus():
    it = {"title": "x", "attr": [{"@attributes": {"name": "size", "value": "42"}},
                                 {"@attributes": {"name": "group",
                                                  "value": "alt.binaries.x"}}]}
    a = nzb._attributs(it)
    assert a["size"] == "42" and a["group"] == "alt.binaries.x"
