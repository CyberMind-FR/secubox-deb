# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from webfilter import zones


def test_dedoublonne_les_enfants_d_une_entree_listee():
    assert zones.dedoublonner(["a.example.com", "example.com", "b.a.example.com", "autre.org", "notexample.com"]) == ["autre.org", "example.com", "notexample.com"]


def test_dedoublonne_ordre_et_doublons():
    assert zones.dedoublonner(["b.org", "a.org", "b.org"]) == ["a.org", "b.org"]


def test_dedoublonne_un_parent_intermediaire():
    assert zones.dedoublonner(["x.y.example.com", "y.example.com"]) == ["y.example.com"]


def test_charger_reunit_les_sources_et_ignore_l_absent(tmp_path):
    d = tmp_path / "jeux"
    d.mkdir()
    (d / "s1.lst").write_text("a.example.com\nb.example.org\n")
    (d / "s2.lst").write_text("example.com\n")
    assert zones.charger(tmp_path, "jeux") == ["b.example.org", "example.com"]
    assert zones.charger(tmp_path, "absente") == []


def test_charger_revalide_chaque_ligne(tmp_path):
    d = tmp_path / "jeux"
    d.mkdir()
    (d / "s1.lst").write_text('ok.example.com\nbad".com\n; local-zone: "." always_nxdomain\nnodot\n')
    assert zones.charger(tmp_path, "jeux") == ["ok.example.com"]          # jamais recopiée telle quelle : revalidée à la lecture


def test_charger_refuse_un_identifiant_de_categorie_hostile(tmp_path):
    assert zones.charger(tmp_path, "../etc") == [] and zones.charger(tmp_path, "") == []
