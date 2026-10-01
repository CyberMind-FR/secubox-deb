# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La connexion de l'administrateur ouvre le Coffre (#1855).

- préparer ne rend qu'un ticket : RIEN n'est ouvert avant la confirmation ;
- un ticket sert une fois, et pas au-delà de son délai ;
- la première connexion crée le Coffre (scellé jusqu'à confirmation) ;
- un admin connecté pendant que le Coffre est ouvert reçoit sa serrure ;
- changer de mot de passe réemballe ; l'ancien n'ouvre plus ;
- le web n'atteint jamais ces routes ; le mot de passe n'entre pas au journal."""
import sqlite3
import sys
from collections import defaultdict, deque
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coffre.coffre import ATTENTE_S, Coffre, Interdit, Scelle  # noqa: E402
from coffre.journal import Journal  # noqa: E402

LEGER = {"t": 1, "m": 1024, "p": 1}
MDP = "le mot de passe de connexion de gk2"


class Horloge:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def coffre(tmp_path):
    h = Horloge()
    c = Coffre(tmp_path / "coffre", Journal(tmp_path / "coffre.journal"), delai_s=900, horloge=h, argon2=LEGER)
    c.horloge = h
    return c


def test_premiere_connexion_cree_le_coffre_scelle_jusqu_au_second_facteur(coffre):
    assert not coffre.initialise
    t = coffre.compte_preparer("gk2", MDP)
    assert coffre.initialise and not coffre.ouvert                     # créé, PAS ouvert
    with pytest.raises(Scelle):
        coffre.poser("box", "x", b"v")
    assert coffre.compte_confirmer(t)
    assert coffre.ouvert
    coffre.poser("box", "x", b"v")
    assert [s["genre"] for s in coffre.etat()["serrures"]] == ["compte"]


def test_connexion_suivante_ouvre_et_ticket_a_usage_unique(coffre):
    coffre.compte_confirmer(coffre.compte_preparer("gk2", MDP))
    coffre.poser("box", "x", b"v")
    coffre.sceller()
    t = coffre.compte_preparer("gk2", MDP)
    assert not coffre.ouvert
    assert coffre.compte_confirmer(t) and coffre.lire("box", "x") == b"v"
    coffre.sceller()
    assert not coffre.compte_confirmer(t)                                # déjà servi
    assert not coffre.ouvert


def test_mauvais_mot_de_passe_ou_ticket_perime(coffre):
    coffre.compte_confirmer(coffre.compte_preparer("gk2", MDP))
    coffre.sceller()
    assert coffre.compte_preparer("gk2", "pas le bon") is None
    assert coffre.compte_preparer("autre", MDP) is None                  # aucun compte : rien
    t = coffre.compte_preparer("gk2", MDP)
    coffre.horloge.t += ATTENTE_S + 1
    assert not coffre.compte_confirmer(t) and not coffre.ouvert


def test_second_admin_recoit_sa_serrure_quand_le_coffre_est_ouvert(coffre):
    coffre.compte_confirmer(coffre.compte_preparer("gk2", MDP))
    t = coffre.compte_preparer("admin", "le mot de passe de admin")
    assert coffre.compte_confirmer(t)
    coffre.sceller()
    assert coffre.compte_confirmer(coffre.compte_preparer("admin", "le mot de passe de admin"))
    assert sorted(s.get("compte") for s in coffre.etat()["serrures"]) == ["admin", "gk2"]


def test_changer_reemballe(coffre):
    coffre.compte_confirmer(coffre.compte_preparer("gk2", MDP))
    coffre.sceller()
    assert coffre.compte_changer("gk2", MDP, "le nouveau mot de passe")     # même scellé
    assert coffre.compte_preparer("gk2", MDP) is None
    assert coffre.compte_confirmer(coffre.compte_preparer("gk2", "le nouveau mot de passe"))
    assert not coffre.compte_changer("gk2", "faux", "x")


def test_reinitialisation_sans_ancien_puis_reinscription(coffre):
    coffre.compte_confirmer(coffre.compte_preparer("gk2", MDP))
    coffre.compte_confirmer(coffre.compte_preparer("admin", "mdp admin"))
    # le mot de passe de gk2 est remis par root : sa serrure est caduque ;
    # quand le Coffre est ouvert (par admin), la connexion de gk2 la refait.
    assert coffre.compte_confirmer(coffre.compte_preparer("gk2", "remis par root"))
    coffre.sceller()
    assert coffre.compte_preparer("gk2", MDP) is None
    assert coffre.compte_confirmer(coffre.compte_preparer("gk2", "remis par root"))


def test_derniere_serrure_humaine_reste(coffre):
    coffre.compte_confirmer(coffre.compte_preparer("gk2", MDP))
    [s] = coffre.etat()["serrures"]
    with pytest.raises(Interdit):
        coffre.retirer_serrure(s["id"])


def test_journal_sans_mot_de_passe(coffre, tmp_path):
    coffre.compte_confirmer(coffre.compte_preparer("gk2", MDP))
    coffre.compte_changer("gk2", MDP, "un autre mot de passe long")
    texte = (tmp_path / "coffre.journal").read_text()
    assert MDP not in texte and "un autre mot de passe long" not in texte
    assert "initialisation" in texte and '"genre": "compte"' in texte


def test_migration_v4_vers_v5(tmp_path):
    base = tmp_path / "c"
    c1 = Coffre(base, Journal(tmp_path / "j"), argon2=LEGER)
    c1.initialiser("une phrase assez longue pour le coffre")
    with sqlite3.connect(base / "coffre.db") as cx:
        cx.executescript("""
            CREATE TABLE s4 (id TEXT PRIMARY KEY,
              genre TEXT NOT NULL CHECK (genre IN ('phrase','secours','appareil','maillage')),
              libelle TEXT NOT NULL DEFAULT '', sel BLOB NOT NULL, params TEXT NOT NULL,
              nonce BLOB NOT NULL, mk BLOB NOT NULL, creee INTEGER NOT NULL, cred_id TEXT);
            INSERT INTO s4 SELECT id, genre, libelle, sel, params, nonce, mk, creee, cred_id FROM serrures;
            DROP TABLE serrures; ALTER TABLE s4 RENAME TO serrures;
            UPDATE meta SET valeur='4' WHERE cle='version';""")
    c2 = Coffre(base, Journal(tmp_path / "j"), argon2=LEGER)
    assert c2.ouvrir("une phrase assez longue pour le coffre")
    assert c2.compte_confirmer(c2.compte_preparer("gk2", MDP))
    with sqlite3.connect(base / "coffre.db") as cx:
        assert cx.execute("SELECT valeur FROM meta WHERE cle='version'").fetchone()[0] == "5"


# ── API ────────────────────────────────────────────────────────────────────

@pytest.fixture
def api(monkeypatch, tmp_path):
    from api import main as m
    from secubox_core import second_facteur, user_store
    monkeypatch.setattr(m, "COFFRE", Coffre(tmp_path / "c", Journal(tmp_path / "j"), argon2=LEGER))
    monkeypatch.setattr(m, "_echecs", defaultdict(deque))
    comptes = {"gk2": MDP}
    monkeypatch.setattr(user_store, "verify_password", lambda u, p: comptes.get(u) == p)
    monkeypatch.setattr(second_facteur, "compte_admin_actif", lambda u: u in comptes)
    alertes = []
    monkeypatch.setattr(m, "_alerte_distante", lambda qui: alertes.append(qui))
    return TestClient(m.public), m, alertes


def test_api_preparer_exige_le_vrai_mot_de_passe_d_un_admin(api):
    c, m, _ = api
    assert c.post("/compte/preparer", json={"utilisateur": "gk2", "mot_de_passe": "faux"}).status_code == 403
    assert c.post("/compte/preparer", json={"utilisateur": "intrus", "mot_de_passe": MDP}).status_code == 403
    t = c.post("/compte/preparer", json={"utilisateur": "gk2", "mot_de_passe": MDP}).json()["ticket"]
    assert not m.COFFRE.ouvert
    assert c.post("/compte/confirmer", json={"ticket": t}).json()["ouvert"] is True
    assert m.COFFRE.ouvert


def test_api_jamais_par_le_relais_web(api):
    c, _, _ = api
    h = {"X-SecuBox-Relais": "agregateur"}
    for chemin, corps in (("/compte/preparer", {"utilisateur": "gk2", "mot_de_passe": MDP}),
                          ("/compte/confirmer", {"ticket": "x" * 30}),
                          ("/compte/changer", {"utilisateur": "gk2", "ancien": "a", "nouveau": MDP})):
        assert c.post(chemin, json=corps, headers=h).status_code == 404, chemin


def test_api_cinq_echecs_puis_429(api):
    c, _, _ = api
    codes = [c.post("/compte/preparer", json={"utilisateur": "gk2", "mot_de_passe": "faux"}).status_code
             for _ in range(6)]
    assert codes == [403] * 5 + [429]


def test_api_connexion_distante_previent_la_box(api):
    c, m, alertes = api
    t = c.post("/compte/preparer", json={"utilisateur": "gk2", "mot_de_passe": MDP}).json()["ticket"]
    c.post("/compte/confirmer", json={"ticket": t, "distante": True})
    import time
    time.sleep(0.2)
    assert alertes == ["connexion"]
