# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Panneau maître (#1522, couche 4) : préparer, exporter, pousser à distance.
La « box neuve » est la vraie API, servie par un client de test."""
import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import maitre as MA, remplir as R  # noqa: E402

MDP = "une-phrase-longue-et-sure"
PROFIL = {"box": {"fuseau": "Europe/Paris", "langue": "fr", "clavier": "fr"},
          "admin": {"mot_de_passe": MDP, "confirmation": MDP},
          "reseau": {"mode": "routeur", "domaine": "gk3.secubox.in"},
          "services": {"profil": "full"}, "maillage": {"mode": "plus_tard"},
          "apt": {"auto": True, "heure": "03:00"}}


@pytest.fixture
def maitre(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_MAITRE_DIR", str(tmp_path / "maitre"))
    return tmp_path


def test_preparer_hache_et_n_exporte_jamais_le_clair(maitre):
    r = MA.enregistre("gk3", PROFIL)
    assert r["complet"] and r["profil"]["admin"]["mot_de_passe"] == "défini"
    texte = MA.texte(MA.lit("gk3"))
    assert MDP not in texte and "$argon2" in texte and 'nom = "gk3"' in texte
    # Réenregistrer sans mot de passe garde l'empreinte.
    p2 = {k: v for k, v in PROFIL.items() if k != "admin"}
    assert MA.enregistre("gk3", p2)["complet"]


@pytest.mark.parametrize("adr", ["8.8.8.8", "127.0.0.1", "gk3.secubox.in", "::1", "1.1.1.1"])
def test_pousser_seulement_vers_le_local(maitre, adr):
    MA.enregistre("gk3", PROFIL)
    with pytest.raises(R.Refus):
        MA.pousse("gk3", adr, "code")


class _Distant:
    """Adapte le client de test de l'API à l'URL https://<ip>/api/v1/premier-pas."""
    def __init__(self, tc):
        self.tc = tc

    def _p(self, url):
        return url.split("/api/v1/premier-pas", 1)[1]

    def put(self, url, **k):
        return self.tc.put(self._p(url), **k)

    def get(self, url, **k):
        return self.tc.get(self._p(url), **k)

    def post(self, url, **k):
        return self.tc.post(self._p(url), **k)


@pytest.fixture
def box_neuve(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_DIR", str(tmp_path / "neuve"))
    monkeypatch.setenv("PREMIER_PAS_JETON", str(tmp_path / "jeton"))
    monkeypatch.setenv("PREMIER_PAS_JETON_LOCAL", str(tmp_path / "jeton-local"))
    (tmp_path / "jeton").write_text("code-ecran\n")
    (tmp_path / "jeton-local").write_text("local\n")
    from api import main
    importlib.reload(R)
    importlib.reload(main)
    monkeypatch.setattr(main.M, "MARQUEUR", tmp_path / "fait")
    monkeypatch.setattr(main.M, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(main.P, "PROFILS_DIR", tmp_path / "profils")
    (tmp_path / "profils").mkdir()
    (tmp_path / "profils" / "full.toml").write_text('on = ["a"]\n')
    from fastapi.testclient import TestClient
    return _Distant(TestClient(main.app)), tmp_path


def test_pousser_proposer_puis_l_utilisateur_accepte(maitre, box_neuve):
    distant, t = box_neuve
    MA.enregistre("gk3", PROFIL)
    r = MA.pousse("gk3", "192.168.1.9", "code-ecran", "proposer", client=distant, par="gk2")
    assert r["ok"] and r["complet"] and r["proposition"]["statut"] == "en_attente"
    prof = (t / "neuve" / "profil.toml").read_text()
    assert "$argon2" in prof and MDP not in prof and 'nom = "gk3"' in prof
    assert not (t / "neuve" / "demande").exists()
    assert distant.post("x/api/v1/premier-pas/proposition/accepter", headers={"X-Premier-Pas": "local"}).status_code == 200
    assert (t / "neuve" / "demande").exists()


def test_mauvais_code_arret_a_la_premiere_etape(maitre, box_neuve):
    distant, _ = box_neuve
    MA.enregistre("gk3", PROFIL)
    r = MA.pousse("gk3", "192.168.1.9", "faux", "proposer", client=distant)
    assert not r["ok"] and r["code"] == 403 and r["faites"] == []


def test_forcer(maitre, box_neuve):
    distant, t = box_neuve
    MA.enregistre("gk3", PROFIL)
    r = MA.pousse("gk3", "10.10.0.6", "code-ecran", "forcer", client=distant, par="gk2")
    assert r["proposition"]["statut"] == "forcee" and (t / "neuve" / "demande").exists()


def test_le_code_garde_ses_tirets_et_tolere_les_espaces(maitre, box_neuve):
    distant, _ = box_neuve
    MA.enregistre("gk3", PROFIL)
    # Le vrai code contient un tiret (base64 urlsafe) ; affiché groupé par espaces.
    assert MA.pousse("gk3", "192.168.1.9", "code-e cran", "remplir", client=distant)["ok"]


def test_rejoindre_devient_l_adresse_vue_par_la_box_neuve():
    # L'invitation annonçait 192.168.255.1 (ancien maillage) : injoignable du LAN (#1544).
    mes = ["127.0.0.1", "192.168.1.200", "192.168.255.1"]
    assert MA.rejoindre_joignable("192.168.255.1", "192.168.1.9", mes, lambda a: "192.168.1.200") == "192.168.1.200"
    # Une AUTRE box comme cible : on n'y touche pas.
    assert MA.rejoindre_joignable("192.168.1.50", "192.168.1.9", mes, lambda a: "192.168.1.200") == "192.168.1.50"
    # Route introuvable : on garde ce qu'on avait.
    assert MA.rejoindre_joignable("192.168.255.1", "10.9.9.9", mes, lambda a: None) == "192.168.255.1"
