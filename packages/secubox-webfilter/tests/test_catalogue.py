# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from pathlib import Path

import pytest

from webfilter import catalogue

BON = '''
[[categorie]]
id = "adulte"
libelle = "Contenu adulte"
mode = "observe"
  [[categorie.source]]
  nom = "hagezi-nsfw"
  url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt"
  format = "domaines"
  licence = "GPL-3.0"
  taille_max = 5000000
'''


def ecrire(tmp_path, texte):
    p = tmp_path / "w.toml"
    p.write_text(texte)
    return p


def test_charge_le_catalogue(tmp_path):
    cats = catalogue.charger(ecrire(tmp_path, BON))
    assert [c.id for c in cats] == ["adulte"] and cats[0].mode == "observe"
    assert cats[0].sources[0].taille_max == 5_000_000 and cats[0].sources[0].format == "domaines"


@pytest.mark.parametrize("ancien,nouveau", [
    ('id = "adulte"', 'id = "Adulte!"'), ('id = "adulte"', 'id = "../x"'),
    ('mode = "observe"', 'mode = "block"'),                       # le blocage n'existe pas en P1
    ('url = "https://', 'url = "http://'), ('url = "https://', 'url = "file:///'),
    ('format = "domaines"', 'format = "xml"'),
    ("taille_max = 5000000", "taille_max = 900000000"), ("taille_max = 5000000", "taille_max = 0"),
    ('nom = "hagezi-nsfw"', 'nom = "a b"'),
])
def test_valeurs_refusees(tmp_path, ancien, nouveau):
    with pytest.raises(catalogue.ErreurCatalogue):
        catalogue.charger(ecrire(tmp_path, BON.replace(ancien, nouveau)))


def test_doublons_refuses(tmp_path):
    with pytest.raises(catalogue.ErreurCatalogue):
        catalogue.charger(ecrire(tmp_path, BON + BON))


def test_fichier_absent_ou_illisible(tmp_path):
    with pytest.raises(catalogue.ErreurCatalogue):
        catalogue.charger(tmp_path / "absent.toml")
    with pytest.raises(catalogue.ErreurCatalogue):
        catalogue.charger(ecrire(tmp_path, "[[categorie\n"))


def test_toml_livre_est_valide():
    cats = catalogue.charger(Path(__file__).resolve().parent.parent / "conf" / "webfilter.toml")
    assert {c.id for c in cats} == {"adulte", "jeux", "phishing"} and all(c.mode == "observe" for c in cats)
    assert all(s.url.startswith("https://") for c in cats for s in c.sources)
