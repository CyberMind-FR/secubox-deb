# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Garde d'origine des écritures authentifiées par cookie (#1607).

Le cookie de session est joint par le navigateur à toute requête vers
*.<domaine> ; un jeton porteur ne l'est jamais. Une écriture qui s'authentifie
par le cookie doit donc venir d'une page de la box. Ces tests figent la règle,
ses trois modes, et ce qu'elle ne touche pas (lectures, porteurs).
"""
from __future__ import annotations

import json

import pytest

from secubox_core import auth, config, origine

ETRANGERE = "https://ailleurs.example.net"
HALL_ORIGINE = "https://hall.gk2.secubox.in"


def _applique(monkeypatch):
    monkeypatch.setenv("SECUBOX_GARDE_ORIGINE", "applique")


# ── Ce que la garde ne touche pas ─────────────────────────────────────────
def test_porteur_exempte_meme_origine_etrangere(box, client, monkeypatch):
    _applique(monkeypatch)
    tok = box.jeton("alice")
    r = client.post("/ecrire", headers=box.porteur(tok, Origin=ETRANGERE))
    assert r.status_code == 200, r.text
    assert box.journal == []


def test_lecture_jamais_bloquee(box, client, monkeypatch):
    _applique(monkeypatch)
    tok = box.jeton("alice")
    for entetes in ({"Origin": ETRANGERE}, {"Sec-Fetch-Site": "cross-site"}, {"Origin": "null"}):
        r = client.get("/lire", headers=box.cookie(tok, **entetes))
        assert r.status_code == 200, (entetes, r.text)
    for methode in ("HEAD", "OPTIONS"):
        r = client.request(methode, "/lire", headers=box.cookie(tok, Origin=ETRANGERE))
        assert r.status_code == 200, methode
    assert box.journal == []


def test_mode_inactif_ne_regarde_pas(box, client, monkeypatch):
    monkeypatch.setenv("SECUBOX_GARDE_ORIGINE", "inactif")
    r = client.post("/ecrire", headers=box.cookie(box.jeton("alice"), Origin=ETRANGERE))
    assert r.status_code == 200
    assert box.journal == [] and not box.releve.exists()


# ── Mode applique ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("methode", ["POST", "PUT", "PATCH", "DELETE"])
def test_cookie_origine_etrangere_refusee_en_applique(box, client, monkeypatch, methode):
    _applique(monkeypatch)
    r = client.request(methode, "/ecrire", headers=box.cookie(box.jeton("alice"), Origin=ETRANGERE))
    assert r.status_code == 403
    assert r.json()["detail"] == "Origine refusée"


def test_post_sans_content_type_origine_etrangere_refuse(box, client, monkeypatch):
    _applique(monkeypatch)
    r = client.post("/ecrire", content=b'{"a": 1}',
                    headers=box.cookie(box.jeton("alice"), Origin=ETRANGERE))
    assert r.status_code == 403


def test_meme_post_en_json_de_meme_origine_admis(box, client, monkeypatch):
    _applique(monkeypatch)
    r = client.post("/ecrire", json={"a": 1},
                    headers=box.cookie(box.jeton("alice"), Origin="https://hall.gk2.secubox.in"))
    assert r.status_code == 200
    assert r.json()["sub"] == "alice"


def test_sous_domaine_et_domaine_admis(box, client, monkeypatch):
    _applique(monkeypatch)
    tok = box.jeton("alice")
    for o in ("https://admin.gk2.secubox.in", "https://gk2.secubox.in",
              "https://a.b.gk2.secubox.in:8443", "HTTPS://Radio.GK2.secubox.in"):
        r = client.post("/ecrire", headers=box.cookie(tok, Origin=o))
        assert r.status_code == 200, o


@pytest.mark.parametrize("o", [
    "https://gk3.secubox.in",               # une autre box du même domaine enregistré
    "https://secubox.in",
    "https://autregk2.secubox.in",          # suffixe sans point
    "https://gk2.secubox.in.example.net",
    "https://gk2.secubox.in@example.net",
    "null",
    "file://",
    "chrome-extension://abcdef",
    "n'importe quoi",
])
def test_origines_hors_de_la_box_refusees(box, client, monkeypatch, o):
    _applique(monkeypatch)
    r = client.post("/ecrire", headers=box.cookie(box.jeton("alice"), Origin=o))
    assert r.status_code == 403, o


@pytest.mark.parametrize("o", [
    "https://surf-www-example-com.gk2.secubox.in",
    "https://surf-0abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.gk2.secubox.in",
    "https://SURF-bbs-gk2-secubox-in.gk2.secubox.in",
])
def test_hote_du_relais_de_surf_n_est_pas_une_page_de_la_box(box, client, monkeypatch, o):
    # Sous le domaine, mais le contenu servi est celui d'un autre site.
    _applique(monkeypatch)
    r = client.post("/ecrire", headers=box.cookie(box.jeton("alice"), Origin=o))
    assert r.status_code == 403, o


def test_la_config_ajoute_des_hotes_tiers_sans_en_retirer(box, client, monkeypatch):
    _applique(monkeypatch)
    monkeypatch.setattr(config, "_CONFIG", {"api": {"sso_cookie_domain": ".gk2.secubox.in"},
                                            "securite": {"garde_origine_tiers": ["relais-"]}})
    tok = box.jeton("alice")
    for o in ("https://relais-x.gk2.secubox.in", "https://surf-x.gk2.secubox.in"):
        assert client.post("/ecrire", headers=box.cookie(tok, Origin=o)).status_code == 403, o
    assert client.post("/ecrire", headers=box.cookie(tok, Origin="https://radio.gk2.secubox.in")).status_code == 200
    assert origine.prefixes_tiers()[0] == "surf-"


@pytest.mark.parametrize("site", ["cross-site", "same-site", "inconnu"])
def test_sans_origin_sec_fetch_site_hors_origine_refuse(box, client, monkeypatch, site):
    _applique(monkeypatch)
    r = client.post("/ecrire", headers=box.cookie(box.jeton("alice"), **{"Sec-Fetch-Site": site}))
    assert r.status_code == 403


@pytest.mark.parametrize("site", ["same-origin", "none", "Same-Origin", None])
def test_sans_origin_meme_origine_ou_client_hors_navigateur_admis(box, client, monkeypatch, site):
    _applique(monkeypatch)
    entetes = {} if site is None else {"Sec-Fetch-Site": site}
    r = client.post("/ecrire", headers=box.cookie(box.jeton("alice"), **entetes))
    assert r.status_code == 200


def test_require_jwt_passe_aussi_par_la_garde(box, client, monkeypatch):
    _applique(monkeypatch)
    tok = box.jeton("gk2")
    assert client.post("/administrer", headers=box.cookie(tok, Origin=ETRANGERE)).status_code == 403
    assert client.post("/administrer", headers=box.cookie(tok, Origin=HALL_ORIGINE)).status_code == 200


def test_porteur_perime_ne_soustrait_pas_le_cookie_a_la_garde(box, client, monkeypatch):
    # Le porteur ne vaut rien : c'est le cookie qui est retenu, donc gardé.
    _applique(monkeypatch)
    entetes = box.cookie(box.jeton("alice"), Origin=ETRANGERE)
    entetes["Authorization"] = "Bearer perime"
    assert client.post("/ecrire", headers=entetes).status_code == 403


# ── Mode journal ──────────────────────────────────────────────────────────
def test_journal_par_defaut_observe_sans_bloquer(box, client):
    assert origine.mode() == "journal"
    r = client.post("/ecrire?jeton=secret", headers=box.cookie(
        box.jeton("alice"), Origin=ETRANGERE, **{"Sec-Fetch-Site": "cross-site"}))
    assert r.status_code == 200
    assert len(box.journal) == 1
    ligne = box.journal[0]
    assert "\n" not in ligne and ligne.startswith("garde_origine ")
    doc = json.loads(ligne.split(" ", 1)[1])
    assert doc["mode"] == "journal" and doc["verdict"] == "observe"
    assert doc["methode"] == "POST" and doc["chemin"] == "/ecrire"
    assert doc["origin"] == ETRANGERE and doc["sec_fetch_site"] == "cross-site"
    assert doc["sub"] == "alice" and doc["hote"] == "hall.gk2.secubox.in"


def test_releve_une_ligne_json_sans_chaine_de_requete(box, client):
    client.post("/ecrire?jeton=secret", headers=box.cookie(box.jeton("alice"), Origin=ETRANGERE))
    lignes = box.releve.read_text().splitlines()
    assert len(lignes) == 1
    doc = json.loads(lignes[0])
    assert doc["garde"] == "origine" and doc["chemin"] == "/ecrire"
    assert "secret" not in lignes[0]


def test_journal_ne_consigne_pas_une_requete_admise(box, client):
    client.post("/ecrire", headers=box.cookie(box.jeton("alice"), Origin="https://admin.gk2.secubox.in"))
    assert box.journal == [] and not box.releve.exists()


def test_releve_absent_ou_illisible_ne_bloque_rien(box, client, monkeypatch, tmp_path):
    monkeypatch.setenv("SECUBOX_GARDE_ORIGINE_RELEVE", str(tmp_path / "absent" / "garde.log"))
    r = client.post("/ecrire", headers=box.cookie(box.jeton("alice"), Origin=ETRANGERE))
    assert r.status_code == 200 and len(box.journal) == 1


def test_releve_plafonne(box, client, monkeypatch):
    box.releve.write_bytes(b"x" * (origine.RELEVE_PLAFOND + 1))
    client.post("/ecrire", headers=box.cookie(box.jeton("alice"), Origin=ETRANGERE))
    assert box.releve.stat().st_size == origine.RELEVE_PLAFOND + 1


def test_releve_ne_suit_pas_un_lien_symbolique(box, client, tmp_path):
    cible = tmp_path / "cible"
    cible.write_text("")
    box.releve.symlink_to(cible)
    client.post("/ecrire", headers=box.cookie(box.jeton("alice"), Origin=ETRANGERE))
    assert cible.read_text() == ""


# ── Modes et domaine lus dans la configuration ────────────────────────────
@pytest.mark.parametrize("valeur,attendu", [
    ("applique", 403), ("APPLIQUE", 403), ("journal", 200), ("inactif", 200),
    ("appliquee", 403), ("", 403), (True, 403), (1, 403),
])
def test_mode_lu_dans_la_config_valeur_inconnue_fermee(box, client, monkeypatch, valeur, attendu):
    monkeypatch.setattr(config, "_CONFIG", {"api": {"sso_cookie_domain": ".gk2.secubox.in"},
                                            "securite": {"garde_origine": valeur}})
    r = client.post("/ecrire", headers=box.cookie(box.jeton("alice"), Origin=ETRANGERE))
    assert r.status_code == attendu, valeur


def test_variable_d_environnement_inconnue_fermee(box, client, monkeypatch):
    monkeypatch.setenv("SECUBOX_GARDE_ORIGINE", "jounral")
    assert origine.mode() == "applique"


def test_domaine_global_prioritaire(box, client_pour, monkeypatch):
    _applique(monkeypatch)
    monkeypatch.setattr(config, "_CONFIG", {"global": {"domain": "exemple.org"},
                                            "api": {"sso_cookie_domain": ".gk2.secubox.in"}})
    assert auth.domaine_box() == "exemple.org"
    c = client_pour("https://hall.exemple.org")
    tok = box.jeton("alice")
    assert c.post("/ecrire", headers=box.cookie(tok, Origin="https://blog.exemple.org")).status_code == 200
    assert c.post("/ecrire", headers=box.cookie(tok, Origin="https://admin.gk2.secubox.in")).status_code == 403


def test_domaine_du_cookie_sans_point(box):
    assert auth.domaine_box() == "gk2.secubox.in"


def test_sans_domaine_seul_l_hote_de_la_requete_compte(box, client, monkeypatch):
    _applique(monkeypatch)
    monkeypatch.setattr(config, "_CONFIG", {"global": {}, "api": {}})
    assert auth.domaine_box() == ""
    tok = box.jeton("alice")
    assert client.post("/ecrire", headers=box.cookie(tok, Origin=HALL_ORIGINE)).status_code == 200
    assert client.post("/ecrire", headers=box.cookie(tok, Origin="https://admin.gk2.secubox.in")).status_code == 403


def test_hote_de_la_requete_avec_port(box, client_pour, monkeypatch):
    _applique(monkeypatch)
    monkeypatch.setattr(config, "_CONFIG", {"global": {}, "api": {}})
    c = client_pour("https://192.168.1.200:8443")
    tok = box.jeton("alice")
    assert c.post("/ecrire", headers=box.cookie(tok, Origin="https://192.168.1.200:8443")).status_code == 200
    assert c.post("/ecrire", headers=box.cookie(tok, Origin="https://192.168.1.201")).status_code == 403


def test_configuration_lue_une_seule_fois(box, client, monkeypatch, tmp_path):
    conf = tmp_path / "secubox.conf"
    conf.write_text('[api]\nsso_cookie_domain = ".gk2.secubox.in"\n'
                    '[securite]\ngarde_origine = "applique"\n')
    monkeypatch.setattr(config, "_CONFIG", None)
    monkeypatch.setattr(config, "_CONF_PATHS", [conf])
    lectures = []
    vrai = config.tomllib.load
    monkeypatch.setattr(config.tomllib, "load", lambda f: lectures.append(1) or vrai(f))
    tok = box.jeton("alice")
    for _ in range(5):
        assert client.post("/ecrire", headers=box.cookie(tok, Origin=ETRANGERE)).status_code == 403
    assert len(lectures) == 1


# ── Le verdict seul ───────────────────────────────────────────────────────
def test_verdict_pur():
    d = "gk2.secubox.in"
    assert origine.admise("https://hall.gk2.secubox.in", None, "hall.gk2.secubox.in", d)
    assert origine.admise("https://x.gk2.secubox.in", "cross-site", "hall.gk2.secubox.in", d)
    assert not origine.admise("null", "same-origin", "hall.gk2.secubox.in", d)
    assert origine.admise(None, None, "", "")
    assert origine.admise("", "same-origin", "", "")
    assert not origine.admise(None, "same-site", "hall.gk2.secubox.in", d)



def test_verdict_nom_du_domaine_exige_https():
    d = "gk2.secubox.in"
    h = "hall.gk2.secubox.in"
    assert not origine.admise("http://x.gk2.secubox.in", None, h, d)
    assert not origine.admise("http://hall.gk2.secubox.in", None, h, d)
    assert origine.admise("https://gk2.secubox.in:9443", None, h, d)
    assert origine.admise("https://hall.gk2.secubox.in:443", None, h, d)
    # Accès LAN en clair par IP, sans domaine : même hôte, admis.
    assert origine.admise("http://192.168.1.50", None, "192.168.1.50", d)
    assert origine.admise("http://192.168.1.50", None, "192.168.1.50", "")


def test_verdict_meme_origine_attestee_par_le_navigateur():
    assert origine.admise("https://192.168.1.50", "same-origin", "localhost", "")
    assert not origine.admise("https://192.168.1.50", "cross-site", "localhost", "")
    assert not origine.admise("https://192.168.1.50", None, "localhost", "")
    assert not origine.admise("null", "same-origin", "localhost", "")


def test_origine_en_clair_sous_le_domaine_refusee(box, client, monkeypatch):
    monkeypatch.setenv("SECUBOX_GARDE_ORIGINE", "applique")
    tok = box.jeton("alice")
    r = client.post("/ecrire", headers=box.cookie(tok, Origin="http://nimporte.gk2.secubox.in"))
    assert r.status_code == 403


def test_relais_hote_reecrit_meme_origine_admis(client, box, monkeypatch):
    monkeypatch.setenv("SECUBOX_GARDE_ORIGINE", "applique")
    tok = box.jeton("alice")
    r = client.post("/ecrire", headers=box.cookie(
        tok, Origin="https://192.168.1.50", **{"Sec-Fetch-Site": "same-origin"}))
    assert r.status_code == 200
