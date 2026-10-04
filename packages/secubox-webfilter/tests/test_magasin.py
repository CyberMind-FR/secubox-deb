# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from webfilter import analyse, magasin


def ev(ts, client, nom):
    return analyse.Evenement(ts, client, nom, "A", "NOERROR")


def test_comptage_et_exclusion(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    n = m.ajouter([(ev(1791090000, "192.168.1.95", "a.example.com"), "adulte"), (ev(1791090001, "192.168.1.95", "a.example.com"), "adulte"),
                   (ev(1791090002, "192.168.1.200", "a.example.com"), "adulte"), (ev(1791090003, "192.168.1.5", "bet.example.org"), "jeux")],
                  exclus={"192.168.1.200"})
    assert n == 3
    assert m.par_categorie("2026-10-01") == {"adulte": 2, "jeux": 1}
    assert m.par_client("2026-10-01")["192.168.1.95"] == {"adulte": 2}
    assert m.top_domaines("adulte", "2026-10-01") == [("a.example.com", 2)]


def test_cumul_sur_plusieurs_ecritures(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    m.ajouter([(ev(1791090000, "192.168.1.95", "a.example.com"), "adulte")], exclus=set())
    m.ajouter([(ev(1791090005, "192.168.1.95", "a.example.com"), "adulte")], exclus=set())
    assert m.top_domaines("adulte", "2026-10-01") == [("a.example.com", 2)]


def test_top_domaines_ordre_et_limite(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    lot = [(ev(1791090000, "192.168.1.95", f"d{i}.example.com"), "adulte") for i in range(5) for _ in range(i + 1)]
    m.ajouter(lot, exclus=set())
    top = m.top_domaines("adulte", "2026-10-01", n=2)
    assert top == [("d4.example.com", 5), ("d3.example.com", 4)]


def test_retention_et_droits(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    m.ajouter([(ev(1791090000, "192.168.1.95", "a.example.com"), "adulte")], exclus=set())
    assert m.purger(30, maintenant=1791090000 + 31 * 86400) == 1 and m.par_categorie("2020-01-01") == {}
    assert oct((tmp_path / "w.db").stat().st_mode & 0o777) == "0o640"


def test_depuis_jour_filtre(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    m.ajouter([(ev(1791090000, "192.168.1.95", "a.example.com"), "adulte")], exclus=set())      # 2026-10-04
    assert m.par_categorie("2026-10-05") == {} and m.par_categorie("2026-10-04") == {"adulte": 1}


def test_plafond_de_lignes_refuse_les_nouvelles_cles_mais_compte_les_existantes(tmp_path, capsys):
    m = magasin.Magasin(tmp_path / "w.db", max_lignes=5)
    m.ajouter([(ev(1791090000, "192.168.1.95", f"d{i}.example.com"), "adulte") for i in range(100)], exclus=set())
    with m._cx() as cx:
        assert cx.execute("SELECT COUNT(*) FROM wf_counts").fetchone()[0] == 5
    n = m.ajouter([(ev(1791090001, "192.168.1.95", "d0.example.com"), "adulte")], exclus=set())     # clé déjà connue : comptée
    assert n == 1 and ("d0.example.com", 2) in m.top_domaines("adulte", "2026-10-01")
    assert "plafond" in capsys.readouterr().err.lower()


def test_suppression_securisee_apres_purge(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    secret = "zzunique-historique.example.com"
    m.ajouter([(ev(1_000_000_000, "192.168.1.95", secret), "adulte")] * 3, exclus=set())
    m.purger(30)
    for f in tmp_path.iterdir():
        assert secret.encode() not in f.read_bytes(), f.name


def test_dernier_evenement_vu(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    assert m.dernier_evenement() is None
    m.ajouter([(ev(1791090000, "192.168.1.95", "a.example.com"), "adulte"), (ev(1791090500, "192.168.1.95", "b.example.com"), "adulte")], exclus=set())
    m.ajouter([(ev(1791090100, "192.168.1.95", "c.example.com"), "adulte")], exclus=set())
    assert m.dernier_evenement() == 1791090500                          # le plus récent, jamais un recul
