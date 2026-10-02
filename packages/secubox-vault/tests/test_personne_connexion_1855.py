# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La connexion d'une PERSONNE ouvre son compartiment (#1855), invités compris.

- le mot de passe de connexion est une serrure « compte » de la personne ;
- à la connexion (second facteur), sa clé est TENUE le temps de sa session ;
- la clé maîtresse reste exigée : un invité n'ouvre jamais le Coffre global ;
- scellement, inactivité, « verrouiller » : la clé tenue est oubliée ;
- pas de second facteur, pas d'ouverture ; le mot de passe n'entre pas au journal."""
import sys
from collections import defaultdict, deque
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coffre.coffre import Coffre, RefusPersonnel, Scelle  # noqa: E402
from coffre.journal import Journal  # noqa: E402

LEGER = {"t": 1, "m": 1024, "p": 1}
PHRASE = "une phrase assez longue pour le coffre"
ALICE = "0b6e3c3a-7d0f-4c1e-9a55-3f2a1b8c9d10"
GEK = "4f1d2e3c-1a2b-4c3d-8e9f-0a1b2c3d4e5f"
MDP = "court"          # un mot de passe de connexion n'a pas la longueur d'une phrase
SESSION = {"genre": "session"}


class Horloge:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def coffre(tmp_path):
    h = Horloge()
    c = Coffre(tmp_path / "c", Journal(tmp_path / "j"), delai_s=900, horloge=h, argon2=LEGER)
    c.horloge = h
    c.initialiser(PHRASE)            # ouvert : l'administrateur est passé
    return c


def _ouvre(c, personne=ALICE, mdp=MDP, compte="alice"):
    t = c.personne_compte_preparer(personne, compte, mdp)
    assert t and t.startswith("p.")
    assert c.compte_confirmer(t, origine="connexion lan")
    return t


def test_premiere_connexion_cree_le_compartiment_et_l_ouvre(coffre):
    assert coffre.personne_etat(ALICE)["serrures"] == []
    _ouvre(coffre)
    etat = coffre.personne_etat(ALICE)
    assert etat["session"] is True and [s["genre"] for s in etat["serrures"]] == ["compte"]
    coffre.personne_poser(ALICE, SESSION, "gpg", b"cle")
    assert coffre.personne_lire(ALICE, SESSION, "gpg") == b"cle"


def test_rien_n_est_ouvert_avant_la_confirmation(coffre):
    t = coffre.personne_compte_preparer(ALICE, "alice", MDP)
    assert coffre.personne_etat(ALICE)["session"] is False
    with pytest.raises(RefusPersonnel):
        coffre.personne_poser(ALICE, SESSION, "x", b"v")
    assert coffre.compte_confirmer(t)
    assert not coffre.compte_confirmer(t)                    # un ticket sert une fois


def test_mauvais_mot_de_passe_n_ouvre_rien(coffre):
    _ouvre(coffre)
    coffre.personne_fermer(ALICE)
    assert coffre.personne_compte_preparer(ALICE, "alice", "pas le bon") is None
    assert coffre.personne_etat(ALICE)["session"] is False


def test_la_cle_maitresse_reste_exigee_et_scelle_la_session(coffre):
    _ouvre(coffre)
    coffre.personne_poser(ALICE, SESSION, "x", b"v")
    coffre.sceller()
    assert coffre.personne_etat(ALICE)["session"] is False   # la clé tenue est oubliée
    with pytest.raises(Scelle):
        coffre.personne_lire(ALICE, SESSION, "x")
    coffre.ouvrir(PHRASE)                                    # l'admin rouvre la box…
    with pytest.raises(RefusPersonnel):                      # …la personne doit se reconnecter
        coffre.personne_lire(ALICE, SESSION, "x")
    _ouvre(coffre)
    assert coffre.personne_lire(ALICE, SESSION, "x") == b"v"


def test_sans_coffre_ouvert_une_personne_neuve_ne_cree_rien(tmp_path):
    c = Coffre(tmp_path / "c", Journal(tmp_path / "j"), argon2=LEGER)
    c.initialiser(PHRASE)
    c.sceller()
    assert c.personne_compte_preparer(ALICE, "alice", MDP) is None
    assert c.personne_etat(ALICE)["serrures"] == []


def test_inactivite_oublie_la_cle(coffre):
    _ouvre(coffre)
    coffre.horloge.t += 100
    coffre.personne_poser(ALICE, SESSION, "x", b"v")         # l'usage renouvelle
    coffre.horloge.t += 800
    assert coffre.personne_lire(ALICE, SESSION, "x") == b"v"
    coffre.horloge.t += 2000                                 # plus de 900 s sans usage
    assert coffre.personne_etat(ALICE)["session"] is False


def test_verrouiller_oublie_la_cle(coffre):
    _ouvre(coffre)
    coffre.personne_fermer(ALICE)
    with pytest.raises(RefusPersonnel):
        coffre.personne_lire(ALICE, SESSION, "x")


def test_une_personne_ne_lit_pas_celle_d_une_autre(coffre):
    _ouvre(coffre)
    _ouvre(coffre, personne=GEK, mdp="le mot de passe de gek", compte="gek")
    coffre.personne_poser(ALICE, SESSION, "secret", b"a alice")
    with pytest.raises(KeyError):
        coffre.personne_lire(GEK, SESSION, "secret")         # sa session n'ouvre que son compartiment


def test_personne_avec_phrase_seule_n_est_pas_ouverte_par_sa_connexion(coffre):
    coffre.personne_initialiser(ALICE, "la phrase personnelle d'alice")
    assert coffre.personne_compte_preparer(ALICE, "alice", MDP) is None
    # elle relie sa connexion à sa personne, une fois, avec sa phrase
    coffre.personne_ajouter_compte(ALICE, {"genre": "phrase", "secret": "la phrase personnelle d'alice"}, MDP)
    _ouvre(coffre)
    assert sorted(s["genre"] for s in coffre.personne_etat(ALICE)["serrures"]) == ["compte", "phrase"]


def test_changer_le_mot_de_passe_reemballe(coffre):
    _ouvre(coffre)
    coffre.personne_poser(ALICE, SESSION, "x", b"v")
    assert coffre.personne_compte_changer(ALICE, MDP, "un nouveau mot de passe")
    coffre.personne_fermer(ALICE)
    assert coffre.personne_compte_preparer(ALICE, "alice", MDP) is None
    _ouvre(coffre, mdp="un nouveau mot de passe")
    assert coffre.personne_lire(ALICE, SESSION, "x") == b"v"


def test_un_admin_ouvre_le_coffre_et_sa_personne(tmp_path):
    h = Horloge()
    c = Coffre(tmp_path / "c", Journal(tmp_path / "j"), delai_s=900, horloge=h, argon2=LEGER)
    t = c.compte_preparer("gk2", "le mot de passe admin", ALICE)      # première connexion : Coffre créé scellé
    assert c.compte_confirmer(t) and c.ouvert
    assert c.personne_etat(ALICE)["session"] is False                # pas de compartiment à la création
    c.sceller()
    t = c.compte_preparer("gk2", "le mot de passe admin", ALICE)      # connexion suivante, Coffre scellé
    assert c.compte_confirmer(t) and c.ouvert                        # la MK s'ouvre
    assert c.personne_etat(ALICE)["session"] is False                # rien à ouvrir : il n'a pas encore de serrure
    c.personne_initialiser(ALICE, "le mot de passe admin", "connexion", genre="compte")
    c.sceller()
    t = c.compte_preparer("gk2", "le mot de passe admin", ALICE)
    assert c.compte_confirmer(t) and c.personne_etat(ALICE)["session"] is True


def test_journal_sans_mot_de_passe(coffre, tmp_path):
    _ouvre(coffre, mdp="un mot de passe distinctif 8841")
    texte = (tmp_path / "j").read_text()
    assert "8841" not in texte and "personne_ouverte" in texte


# ── API ───────────────────────────────────────────────────────────────────
@pytest.fixture
def api(monkeypatch, tmp_path):
    from api import main as m
    from secubox_core import capacites, second_facteur, user_store
    from secubox_core.auth import require_session
    c = Coffre(tmp_path / "ca", Journal(tmp_path / "ja"), argon2=LEGER)
    c.initialiser(PHRASE)
    monkeypatch.setattr(m, "COFFRE", c)
    monkeypatch.setattr(m, "_echecs", defaultdict(deque))
    comptes = {"alice": {"mdp": MDP, "role": "user"}, "gek": {"mdp": "mot de passe de gek", "role": "guest"}}
    monkeypatch.setattr(user_store, "verify_password", lambda u, p: (comptes.get(u) or {}).get("mdp") == p)
    monkeypatch.setattr(user_store, "get_user", lambda u: {"role": comptes[u]["role"], "enabled": True}
                        if u in comptes else None)
    monkeypatch.setattr(second_facteur, "compte_admin_actif", lambda u: False)
    pers = {"alice": ALICE, "gek": GEK}
    monkeypatch.setattr(capacites, "personne_du_porteur",
                        lambda p: {"user_uuid": pers[p["sub"]], "pseudo": p["sub"]} if p.get("sub") in pers else None)
    qui = {"sub": "alice"}
    m.public.dependency_overrides[require_session] = lambda: dict(qui)
    yield TestClient(m.public), m, qui
    m.public.dependency_overrides.clear()


def _connecte(cl, compte, mdp):
    t = cl.post("/personne/preparer", json={"utilisateur": compte, "mot_de_passe": mdp}).json()["ticket"]
    assert t
    return cl.post("/compte/confirmer", json={"ticket": t}).json()["ouvert"]


def test_api_utilisateur_connecte_range_sans_phrase(api):
    cl, _, _ = api
    assert _connecte(cl, "alice", MDP)
    assert cl.get("/moi").json()["session"] is True
    r = cl.post("/moi/secrets", json={"ouverture": SESSION, "nom": "gpg", "valeur": "clé"})
    assert r.status_code == 200 and r.json()["version"] == 1
    assert cl.post("/moi/secrets/gpg/lire", json={"ouverture": SESSION}).json()["valeur"] == "clé"


def test_api_invite_avec_compte_ouvre_son_compartiment(api):
    cl, _, qui = api
    qui["sub"] = "gek"                                       # compte de rôle guest
    assert _connecte(cl, "gek", "mot de passe de gek")
    assert cl.post("/moi/secrets", json={"ouverture": SESSION, "nom": "n", "valeur": "v"}).status_code == 200


def test_api_mauvais_mot_de_passe_403_et_limite(api):
    cl, _, _ = api
    for _ in range(5):
        assert cl.post("/personne/preparer", json={"utilisateur": "alice", "mot_de_passe": "non"}).status_code == 403
    assert cl.post("/personne/preparer", json={"utilisateur": "alice", "mot_de_passe": MDP}).status_code == 429


def test_api_jamais_par_le_relais_web(api):
    cl, _, _ = api
    for chemin in ("/personne/preparer", "/personne/changer"):
        r = cl.post(chemin, json={"utilisateur": "alice", "mot_de_passe": MDP, "ancien": MDP, "nouveau": MDP},
                    headers={"X-SecuBox-Relais": "1"})
        assert r.status_code == 404


def test_api_session_sans_ticket_confirme_n_ouvre_rien(api):
    cl, _, _ = api
    t = cl.post("/personne/preparer", json={"utilisateur": "alice", "mot_de_passe": MDP}).json()["ticket"]
    assert t and cl.get("/moi").json()["session"] is False   # préparé seulement
    r = cl.post("/moi/secrets", json={"ouverture": SESSION, "nom": "x", "valeur": "v"})
    assert r.status_code == 403


def test_api_relier_et_verrouiller(api):
    cl, _, _ = api
    cl.post("/moi/initialiser", json={"phrase": "la phrase personnelle d'alice"})
    ph = {"genre": "phrase", "secret": "la phrase personnelle d'alice"}
    assert cl.post("/moi/serrures/compte", json={"ouverture": ph, "mot_de_passe": "faux"}).status_code == 403
    assert cl.post("/moi/serrures/compte", json={"ouverture": ph, "mot_de_passe": MDP}).status_code == 200
    assert _connecte(cl, "alice", MDP)
    assert cl.post("/moi/fermer").json()["ferme"] is True
    assert cl.get("/moi").json()["session"] is False
