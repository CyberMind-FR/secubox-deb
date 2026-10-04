# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1963 : métriques de la partie standard — jamais de zéro trompeur. Chiffres tirés des compteurs DNS d'ad-guard ; une source illisible se dit « illisible »."""
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from secubox_core.auth import require_jwt
from api import dnstv, main as m

MAC = "38:07:16:94:fb:5b"
V6 = "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57"


@pytest.fixture
def monde(tmp_path, monkeypatch):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "interface_lan", lambda executer=None: "eth2")
    monkeypatch.setattr(dnstv, "lire_voisins", lambda executer=None, interface=None: {"192.168.1.128": MAC, V6: MAC})
    monkeypatch.setattr(dnstv, "adresses_locales", lambda executer=None: {"192.168.1.200"})
    monkeypatch.setattr(dnstv, "passerelles", lambda executer=None: {"192.168.1.254"})
    monkeypatch.setattr(m, "_TOOLBOX_DB", str(tmp_path / "absent.db"))
    monkeypatch.setattr(m, "_LEARNED_F", m._P(tmp_path / "learned.txt"))
    monkeypatch.setattr(m, "_PURE_F", m._P(tmp_path / "pure.txt"))
    monkeypatch.setattr(m, "_ADALLOW_F", m._P(tmp_path / "allow.txt"))
    monkeypatch.setattr(m, "_FILTERS_F", m._P(tmp_path / "filters.json"))
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "root"}
    yield tmp_path
    m.app.dependency_overrides.pop(require_jwt, None)


def evt(client, domaine, decision="ALLOWED", t=None):
    return (dnstv.Evenement(t or int(time.time()), client, domaine, "A", "NXDOMAIN" if decision == "BLOCKED" else "NOERROR", decision), "")


def remplir(tmp_path, evts):
    """Comme le démon d'alimentation : les adresses de la box et de la passerelle ne sont pas journalisées."""
    dnstv.Magasin(tmp_path / "dnstv.db").ajouter(evts, exclus={"192.168.1.200", "192.168.1.254"})


def stats():
    return TestClient(m.app).get("/stats").json()


def test_les_chiffres_viennent_des_compteurs_dns_et_regroupent_les_appareils_par_mac(monde):
    remplir(monde, [evt("192.168.1.128", "a.example.org"), evt(V6, "b.example.org"), evt("192.168.1.128", "ads.example.org", "BLOCKED"), evt(V6, "ads2.example.org", "BLOCKED"),
                    evt("192.168.1.5", "c.example.org"), evt("192.168.1.5", "ads3.example.org", "BLOCKED"),
                    evt("192.168.1.200", "box.example.org"), evt("192.168.1.254", "ra.example.org")])           # la box et la passerelle sont exclues
    s = stats()
    assert s["dns_requetes_jour"] == 6 and s["dns_bloquees_jour"] == 3 and s["dns_taux_blocage"] == 50
    assert s["monitored_devices"] == s["dns_appareils_jour"] == 2                                    # une MAC (IPv4+IPv6) + une adresse seule
    assert s["detections_24h"] == 3                                                                  # le champ que lit la carte « Bloqués »
    assert s["dns_fenetre"].startswith("aujourd")


def test_sans_aucune_requete_les_chiffres_sont_des_zeros_reels_pas_des_valeurs_absentes(monde):
    s = stats()
    assert s["dns_requetes_jour"] == 0 and s["detections_24h"] == 0 and s["monitored_devices"] == 0 and s["dns_taux_blocage"] == 0


def test_base_dns_illisible_champs_dns_absents_et_cartes_en_tiret(monde):
    (monde / "dnstv.db").write_bytes(b"pas une base sqlite " * 400)   # plus de 100 octets : SQLite y lit un en-tête invalide
    s = stats()
    assert "dns_requetes_jour" not in s and "detections_24h" not in s and s["dns_lisible"] is False       # l'interface affiche « — », jamais 0


def test_toolbox_illisible_n_invente_pas_de_zero(monde):
    s = stats()
    assert s["toolbox_lisible"] is False and "mitm_blocks_total" not in s and "toolbox_clients" not in s


def test_toolbox_lisible_donne_ses_chiffres_en_plus(monde, monkeypatch):
    p = monde / "toolbox.db"
    cx = sqlite3.connect(p)
    cx.executescript("CREATE TABLE clients(id INTEGER); CREATE TABLE ad_block_stats(hits INTEGER);")
    cx.executemany("INSERT INTO clients VALUES (?)", [(1,), (2,), (3,)])
    cx.executemany("INSERT INTO ad_block_stats VALUES (?)", [(10,), (5,)])
    cx.commit()
    cx.close()
    monkeypatch.setattr(m, "_TOOLBOX_DB", str(p))
    s = stats()
    assert s["toolbox_lisible"] is True and s["mitm_blocks_total"] == 15 and s["toolbox_clients"] == 3


def test_blocklist_garde_le_puits(monde):
    (monde / "x").write_text("")
    s = stats()
    assert "blocklist_domains" in s and "sinkhole_domains" in s


def learn():
    return TestClient(m.app).get("/learn/status").json()


def test_apprentissage_illisible_donne_null_et_lisible_faux(monde):
    j = learn()
    assert j["learned"] is None and j["pure"] is None and j["allowlist"] is None and j["lisible"] is False


def test_apprentissage_lisible_compte_les_lignes(monde):
    (monde / "learned.txt").write_text("# c\nads.example.com\ntracker.example.net\n")
    (monde / "pure.txt").write_text("p.example.com\n")
    (monde / "allow.txt").write_text("")
    j = learn()
    assert (j["learned"], j["pure"], j["allowlist"], j["lisible"]) == (2, 1, 0, True)


def test_statuts_autolearn_lus_dans_filters_json_pas_des_defauts_verts(monde):
    assert learn()["autolearn"] is None and learn()["ad_learn"] is None                         # fichier absent : inconnu
    (monde / "filters.json").write_text(json.dumps({"autolearn": False, "ad_learn": True}))
    j = learn()
    assert j["autolearn"] is False and j["ad_learn"] is True
    (monde / "filters.json").write_text("{corrompu")
    assert learn()["autolearn"] is None


def test_les_seuils_gardent_leurs_valeurs_par_defaut(monde):
    assert set(learn()["thresholds"]) == set(m._LEARN_DEFAULTS)
