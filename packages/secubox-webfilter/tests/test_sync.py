# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from webfilter import listes, sources, sync

CONF = '''
[[categorie]]
id = "adulte"
libelle = "A"
mode = "observe"
  [[categorie.source]]
  nom = "s1"
  url = "https://x.example/a"
  format = "domaines"
  licence = "MIT"
  taille_max = 1000
  [[categorie.source]]
  nom = "s2"
  url = "https://x.example/b"
  format = "domaines"
  licence = "MIT"
  taille_max = 1000
'''


def conf(tmp_path, texte=CONF):
    p = tmp_path / "w.toml"
    p.write_text(texte)
    return str(p)


def test_succes_total_et_partiel_rendent_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(sources.audit, "ecrire", lambda a, d="", chemin=None: None)

    def fetch(url, taille):
        if url.endswith("/b"):
            raise sources.ErreurSource("coupé")
        return b"evil.example.com\n"
    rc = sync.principal(["--catalogue", conf(tmp_path), "--etat", str(tmp_path)], fetch=fetch)
    assert rc == 0 and listes.Index.charger(tmp_path / "listes" / "adulte" / "s1.idx").contient("evil.example.com")


def test_toutes_les_sources_d_une_categorie_en_echec_rendent_un(tmp_path, monkeypatch):
    monkeypatch.setattr(sources.audit, "ecrire", lambda a, d="", chemin=None: None)

    def fetch(url, taille):
        raise sources.ErreurSource("coupé")
    assert sync.principal(["--catalogue", conf(tmp_path), "--etat", str(tmp_path)], fetch=fetch) == 1


def test_catalogue_invalide_rend_deux(tmp_path, capsys):
    assert sync.principal(["--catalogue", conf(tmp_path, "[[categorie\n"), "--etat", str(tmp_path)]) == 2
    assert "webfilter" in capsys.readouterr().err
