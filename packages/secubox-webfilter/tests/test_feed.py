# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
import subprocess
import sys
from pathlib import Path

from webfilter import catalogue, feed, listes, magasin

RACINE = Path(__file__).resolve().parent.parent
L = "[1791090000] unbound[1234:0] reply: {client} {nom}. A IN NOERROR 0.000000 0 60"


def ligne_unbound(client, nom):
    return L.format(client=client, nom=nom)


def indexes_fixes(**cats):
    return lambda: {c: listes.Index.depuis(noms) for c, noms in cats.items()}


def test_compte_les_noms_classes_et_exclut_la_box(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    lignes = [ligne_unbound("192.168.1.95", "a.evil.example.com"), ligne_unbound("192.168.1.95", "sain.example.net"), ligne_unbound("192.168.1.200", "a.evil.example.com"),
              ligne_unbound("192.168.1.5", "b.evil.example.com")]
    n = feed.suivre(iter(lignes), m, indexes_fixes(adulte=["evil.example.com"]), lambda: {"192.168.1.200"})
    assert n == 2 and m.par_categorie("2026-10-01") == {"adulte": 2}


def test_une_ligne_hostile_n_arrete_pas_la_boucle(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    lignes = [ligne_unbound("192.168.1.95", "a.evil.example.com"), "ligne\x00 absurde " * 50, ligne_unbound("pas-ip", "a.evil.example.com"), "x" * 5000,
              ligne_unbound("192.168.1.95", "b.evil.example.com")]
    assert feed.suivre(iter(lignes), m, indexes_fixes(adulte=["evil.example.com"]), lambda: set()) == 2


def test_un_index_remplace_est_pris_en_compte(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    etat = {"v": 1}

    def indexes():
        return {"adulte": listes.Index.depuis(["evil.example.com"] if etat["v"] == 1 else ["autre.example.org"])}

    def lignes():
        yield ligne_unbound("192.168.1.95", "a.evil.example.com")      # classé avec l'index v1
        etat["v"] = 2                                       # la synchronisation remplace l'index
        yield ligne_unbound("192.168.1.95", "a.evil.example.com")      # n'est plus classé
        yield ligne_unbound("192.168.1.95", "a.autre.example.org")     # l'est désormais
    t = iter(range(0, 10_000, 100))
    n = feed.suivre(lignes(), m, indexes, lambda: set(), recharge_s=1.0, horloge=lambda: next(t))
    assert n == 2 and m.top_domaines("adulte", "2026-10-01") == [("autre.example.org", 1), ("evil.example.com", 1)]


def test_charger_indexes_reunit_les_sources_et_ignore_un_fichier_corrompu(tmp_path, capsys):
    cat = catalogue.Categorie("phishing", "P", "observe", [catalogue.Source("s1", "https://x/a", "hosts", "MIT", 10),
                                                           catalogue.Source("s2", "https://x/b", "hosts", "MIT", 10),
                                                           catalogue.Source("s3", "https://x/c", "hosts", "MIT", 10)])
    d = tmp_path / "phishing"
    d.mkdir()
    listes.Index.depuis(["un.example.com"]).ecrire(d / "s1.idx")
    listes.Index.depuis(["deux.example.org"]).ecrire(d / "s2.idx")
    (d / "s3.idx").write_bytes(b"corrompu")
    idx = feed.charger_indexes(tmp_path, [cat])
    assert idx["phishing"].contient("a.un.example.com") and idx["phishing"].contient("deux.example.org") and not idx["phishing"].contient("trois.example.net")
    assert "s3" in capsys.readouterr().err


def test_categorie_sans_aucun_index_est_absente(tmp_path):
    cat = catalogue.Categorie("jeux", "J", "observe", [catalogue.Source("s1", "https://x/a", "hosts", "MIT", 10)])
    assert feed.charger_indexes(tmp_path, [cat]) == {}


def test_demon_stdin_de_bout_en_bout(tmp_path):
    (tmp_path / "listes" / "adulte").mkdir(parents=True)
    listes.Index.depuis(["evil.example.com"]).ecrire(tmp_path / "listes" / "adulte" / "s1.idx")
    conf = tmp_path / "w.toml"
    conf.write_text('[[categorie]]\nid = "adulte"\nlibelle = "A"\nmode = "observe"\n  [[categorie.source]]\n  nom = "s1"\n  url = "https://x/a"\n'
                    '  format = "domaines"\n  licence = "MIT"\n  taille_max = 10\n')
    r = subprocess.run([sys.executable, str(RACINE / "sbin" / "secubox-webfilter-feed"), "--stdin", "--catalogue", str(conf),
                        "--etat", str(tmp_path), "--sans-adresses-locales"], input=ligne_unbound("192.168.1.95", "a.evil.example.com") + "\n",
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert magasin.Magasin(tmp_path / "webfilter.db").par_client("2026-10-01") == {"192.168.1.95": {"adulte": 1}}


def test_une_erreur_d_ecriture_n_arrete_pas_le_demon(tmp_path, capsys):
    import sqlite3

    class Casse(magasin.Magasin):
        appels = 0

        def ajouter(self, lot, exclus):
            Casse.appels += 1
            if Casse.appels == 1:
                raise sqlite3.OperationalError("disque plein")
            return super().ajouter(lot, exclus)
    m = Casse(tmp_path / "w.db")
    t = iter(range(0, 10_000, 100))
    n = feed.suivre(iter([ligne_unbound("192.168.1.95", "a.evil.example.com"), ligne_unbound("192.168.1.95", "b.evil.example.com")]), m,
                    indexes_fixes(adulte=["evil.example.com"]), lambda: set(), periode_s=1.0, horloge=lambda: next(t))
    assert n == 1 and "disque plein" in capsys.readouterr().err


def test_la_retention_purge_au_demarrage(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    m.ajouter([(feed.analyse.Evenement(1_000_000_000, "192.168.1.95", "vieux.evil.example.com", "A", "NOERROR"), "adulte")], exclus=set())
    feed.suivre(iter([]), m, indexes_fixes(adulte=["evil.example.com"]), lambda: set(), retention_jours=30)
    assert m.par_categorie("2000-01-01") == {}


def test_cardinalite_bornee_par_la_liste_meme_avec_des_sous_domaines_aleatoires(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    lignes = [ligne_unbound("192.168.1.95", f"alea{i}.evil.example.com") for i in range(300)]
    n = feed.suivre(iter(lignes), m, indexes_fixes(adulte=["evil.example.com"]), lambda: set())
    assert n == 300 and m.top_domaines("adulte", "2026-10-01") == [("evil.example.com", 300)]


CARTE = {"version": 3, "adresses": {"192.168.1.95": {"mac": "aa:bb:cc:dd:ee:01", "profil": "enfants", "vue": "wf-1a2b3c4d", "modes": {"adulte": "block", "jeux": "observe"}}},
         "defaut": {"reseaux": ["192.168.1.0/24"], "modes": {"adulte": "observe", "jeux": "block"}}}


def test_decision_selon_la_carte():
    assert feed.decision(CARTE, "192.168.1.95", "adulte") == "bloque" and feed.decision(CARTE, "192.168.1.95", "jeux") == "observe"
    assert feed.decision(CARTE, "192.168.1.7", "jeux") == "bloque"                      # non assigné, dans le réseau : profil par défaut
    assert feed.decision(CARTE, "10.9.9.9", "jeux") == "observe"                       # hors réseau par défaut : jamais « bloqué »
    for mauvaise in (None, {}, [], "x", {"adresses": 3}, {"adresses": {"192.168.1.95": {"modes": 5}}}, {"defaut": {"reseaux": ["pas-un-reseau"], "modes": {}}}):
        assert feed.decision(mauvaise, "192.168.1.95", "adulte") == "observe"


def test_le_demon_note_bloque_ou_observe(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    lignes = [ligne_unbound("192.168.1.95", "x.evil.example.com"), ligne_unbound("192.168.1.5", "y.evil.example.com")]
    carte = {"adresses": {"192.168.1.95": {"modes": {"adulte": "block"}}}, "defaut": {"reseaux": ["192.168.1.0/24"], "modes": {"adulte": "observe"}}}
    feed.suivre(iter(lignes), m, indexes_fixes(adulte=["evil.example.com"]), lambda: set(), carte_fn=lambda: carte)
    assert m.par_client_decision("2026-10-01") == {"192.168.1.95": {"adulte": {"bloque": 1}}, "192.168.1.5": {"adulte": {"observe": 1}}}


def test_carte_illisible_donne_observe_sans_exception(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    feed.suivre(iter([ligne_unbound("192.168.1.95", "x.evil.example.com")]), m, indexes_fixes(adulte=["evil.example.com"]), lambda: set(), carte_fn=lambda: "n'importe quoi")
    assert m.par_categorie_decision("2026-10-01") == {"adulte": {"observe": 1}}


def test_la_carte_est_relue_toutes_les_60_secondes(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    etat = {"v": "block"}

    def carte():
        return {"adresses": {"192.168.1.95": {"modes": {"adulte": etat["v"]}}}}

    def lignes():
        yield ligne_unbound("192.168.1.95", "a.evil.example.com")
        etat["v"] = "observe"
        yield ligne_unbound("192.168.1.95", "b.evil.example.com")
    t = iter(range(0, 10_000, 100))
    feed.suivre(lignes(), m, indexes_fixes(adulte=["evil.example.com"]), lambda: set(), carte_fn=carte, recharge_s=1.0, horloge=lambda: next(t))
    assert m.par_categorie_decision("2026-10-01") == {"adulte": {"bloque": 1, "observe": 1}}


def test_lire_carte_tolerant(tmp_path):
    f = tmp_path / "carte.json"
    assert feed.lire_carte(f) == {}
    f.write_text("pas du json")
    assert feed.lire_carte(f) == {}
    f.write_text("x" * (2 * 1024 * 1024))
    assert feed.lire_carte(f) == {}
    f.write_text('{"adresses": {}}')
    assert feed.lire_carte(f) == {"adresses": {}}


def test_publier_connus_seulement_les_adresses_vues_et_borne(tmp_path):
    f = tmp_path / "connus.json"
    voisins = {"aa:bb:cc:dd:ee:01": ["192.168.1.50", "2a01:db8::50"], "aa:bb:cc:dd:ee:02": ["192.168.1.51"]}
    feed.publier_connus(f, voisins, {"192.168.1.50", "10.9.9.9"}, maintenant=lambda: 1791090000)
    d = json.loads(f.read_text())
    assert d == {"aa:bb:cc:dd:ee:01": {"adresses": ["192.168.1.50"], "vu": 1791090000}}
    assert oct(f.stat().st_mode & 0o777) == "0o640" and [p.name for p in tmp_path.iterdir()] == ["connus.json"]
    gros = {f"aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x}": [f"10.0.{i // 256}.{i % 256}"] for i in range(600)}
    feed.publier_connus(f, gros, {a for v in gros.values() for a in v}, maintenant=lambda: 1)
    assert len(json.loads(f.read_text())) == 512
