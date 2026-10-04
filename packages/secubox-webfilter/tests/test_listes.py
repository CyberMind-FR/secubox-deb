# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import pytest

from webfilter import listes

HOSTS = "# Title: x\n127.0.0.1 localhost\n0.0.0.0 evil.example.com\n0.0.0.0\tAdult.Example.NET  # note\n!comment\n\n0.0.0.0 bad name.com\n"
DOMAINES = "# c\nevil.example.com\n  PORN.example.org  \n!x\n1.2.3.4\nnodot\n"


def test_lire_hosts():
    assert list(listes.lire(HOSTS, "hosts")) == ["evil.example.com", "adult.example.net"]


def test_lire_domaines():
    assert list(listes.lire(DOMAINES, "domaines")) == ["evil.example.com", "porn.example.org"]


def test_format_inconnu():
    with pytest.raises(ValueError):
        list(listes.lire("x", "xml"))


def test_index_suffixe_et_frontiere():
    i = listes.Index.depuis(["example.com", "sub.other.org"])
    assert i.contient("example.com") and i.contient("evil.example.com") and i.contient("a.b.example.com")
    assert not i.contient("notexample.com") and not i.contient("com") and not i.contient("other.org")
    assert i.contient("x.sub.other.org") and i.contient("sub.other.org")


def test_index_dedoublonne_et_compte():
    assert len(listes.Index.depuis(["a.com", "A.com", "b.com", "a.com"])) == 3


def test_aller_retour_fichier(tmp_path):
    i = listes.Index.depuis(["example.com", "b.org"])
    f = tmp_path / "x.idx"
    i.ecrire(f)
    j = listes.Index.charger(f)
    assert len(j) == 2 and j.contient("www.example.com") and not j.contient("c.net")
    assert oct(f.stat().st_mode & 0o777) == "0o640"
    assert [p.name for p in tmp_path.iterdir()] == ["x.idx"]            # aucun résidu temporaire


def test_charger_refuse_un_fichier_corrompu(tmp_path):
    f = tmp_path / "x.idx"
    f.write_bytes(b"pas un index")
    with pytest.raises(ValueError):
        listes.Index.charger(f)
    f.write_bytes(b"WFIDX1\n" + b"\x00" * 5)                           # longueur non multiple de 8
    with pytest.raises(ValueError):
        listes.Index.charger(f)


def test_index_vide_refuse_a_l_ecriture(tmp_path):
    with pytest.raises(ValueError):
        listes.Index.depuis([]).ecrire(tmp_path / "x.idx")


def test_correspondance_rend_l_entree_de_liste_et_non_le_nom_interroge():
    i = listes.Index.depuis(["example.com", "sub.other.org"])
    assert i.correspondance("a.b.example.com") == "example.com"
    assert i.correspondance("x.sub.other.org") == "sub.other.org"
    assert i.correspondance("notexample.com") is None and i.correspondance("other.org") is None
    assert i.contient("a.b.example.com") is True
