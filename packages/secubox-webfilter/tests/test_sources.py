# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import hashlib
import json

import pytest

from webfilter import catalogue, listes, sources

CAT = catalogue.Categorie("adulte", "Adulte", "observe", [catalogue.Source("s1", "https://x.example/l.txt", "domaines", "MIT", 1000)])
LISTE = "evil.example.com\nporn.example.org\n"


def fetch_ok(url, taille_max):
    return LISTE.encode()


@pytest.fixture(autouse=True)
def sans_audit_reel(monkeypatch):
    monkeypatch.setattr(sources.audit, "ecrire", lambda a, d="", chemin=None: None)


def test_synchronise_ecrit_index_et_meta(tmp_path):
    r = sources.synchroniser(CAT, tmp_path, fetch=fetch_ok, maintenant=lambda: 1000)
    assert r["s1"] == {"n": 2, "ok": True, "erreur": None}
    idx = listes.Index.charger(tmp_path / "adulte" / "s1.idx")
    assert idx.contient("a.evil.example.com")
    meta = json.loads((tmp_path / "adulte" / "s1.json").read_text())
    assert meta["n"] == 2 and meta["ts"] == 1000 and meta["sha256"] == hashlib.sha256(LISTE.encode()).hexdigest() and meta["licence"] == "MIT"


def test_echec_garde_l_ancienne_version(tmp_path):
    sources.synchroniser(CAT, tmp_path, fetch=fetch_ok)

    def boum(url, taille_max):
        raise sources.ErreurSource("réseau coupé")
    r = sources.synchroniser(CAT, tmp_path, fetch=boum)
    assert r["s1"]["ok"] is False and "réseau" in r["s1"]["erreur"]
    assert listes.Index.charger(tmp_path / "adulte" / "s1.idx").contient("evil.example.com")


@pytest.mark.parametrize("corps", [b"", b"# que des commentaires\n", b"nodot\n1.2.3.4\n"])
def test_liste_vide_ou_sans_domaine_valide_ne_remplace_rien(tmp_path, corps):
    sources.synchroniser(CAT, tmp_path, fetch=fetch_ok)
    r = sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: corps)
    assert r["s1"]["ok"] is False
    assert listes.Index.charger(tmp_path / "adulte" / "s1.idx").contient("evil.example.com")


def test_liste_vide_des_le_depart_n_ecrit_rien(tmp_path):
    r = sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: b"")
    assert r["s1"]["ok"] is False and not (tmp_path / "adulte" / "s1.idx").exists()


def test_liste_qui_perd_plus_de_la_moitie_est_refusee(tmp_path):
    gros = "\n".join(f"d{i}.example.com" for i in range(100)).encode()
    sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: gros)
    r = sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: b"seul.example.com\n")        # 100 → 1 : liste tronquée
    assert r["s1"]["ok"] is False and "tronqu" in r["s1"]["erreur"]


def test_telecharger_refuse_http_et_depassement(monkeypatch):
    with pytest.raises(sources.ErreurSource):
        sources.telecharger("http://x.example/l.txt", 100)

    class Rep:
        status = 200

        def __init__(self, n):
            self.n = n

        def read(self, k=-1):
            d = b"a" * min(self.n, k if k > 0 else self.n)
            self.n -= len(d)
            return d

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(sources, "_ouvrir", lambda url: Rep(5000))
    with pytest.raises(sources.ErreurSource):
        sources.telecharger("https://x.example/l.txt", 1000)
    monkeypatch.setattr(sources, "_ouvrir", lambda url: Rep(500))
    assert len(sources.telecharger("https://x.example/l.txt", 1000)) == 500


def test_erreur_reseau_devient_erreur_source(monkeypatch):
    def boum(url):
        raise OSError("connexion refusée")
    monkeypatch.setattr(sources, "_ouvrir", boum)
    with pytest.raises(sources.ErreurSource):
        sources.telecharger("https://x.example/l.txt", 1000)


def test_audit_a_chaque_synchronisation(tmp_path, monkeypatch):
    vus = []
    monkeypatch.setattr(sources.audit, "ecrire", lambda a, d="", chemin=None: vus.append((a, d)))
    sources.synchroniser(CAT, tmp_path, fetch=fetch_ok)
    assert vus and vus[0][0] == "sync" and "adulte/s1" in vus[0][1] and "n=2" in vus[0][1]
    vus.clear()
    sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: b"")
    assert vus and vus[0][0] == "sync-echec"


def test_ecrit_aussi_la_liste_brute_triee_en_0640(tmp_path):
    sources.synchroniser(CAT, tmp_path, fetch=fetch_ok)
    f = tmp_path / "adulte" / "s1.lst"
    assert f.read_text() == "evil.example.com\nporn.example.org\n"
    assert oct(f.stat().st_mode & 0o777) == "0o640"


def test_un_echec_garde_l_ancienne_liste_brute(tmp_path):
    sources.synchroniser(CAT, tmp_path, fetch=fetch_ok)
    sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: b"")
    assert (tmp_path / "adulte" / "s1.lst").read_text() == "evil.example.com\nporn.example.org\n"


def test_une_liste_tronquee_ne_remplace_pas_la_liste_brute(tmp_path):
    gros = "\n".join(f"d{i}.example.com" for i in range(100)).encode()
    sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: gros)
    sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: b"seul.example.com\n")
    assert (tmp_path / "adulte" / "s1.lst").read_text().count("\n") == 100


def test_aucun_residu_temporaire(tmp_path):
    sources.synchroniser(CAT, tmp_path, fetch=fetch_ok)
    assert sorted(p.name for p in (tmp_path / "adulte").iterdir()) == ["s1.idx", "s1.json", "s1.lst"]
