# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#1458 : le helper réveille et TIENT un module on-demand pendant une action."""
import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

P = Path(__file__).resolve().parents[1] / "sbin" / "secubox-usersctl-services"


@pytest.fixture
def H(tmp_path, monkeypatch):
    loader = importlib.machinery.SourceFileLoader("helper_1458", str(P))
    spec = importlib.util.spec_from_loader("helper_1458", loader)
    h = importlib.util.module_from_spec(spec)
    loader.exec_module(h)
    monkeypatch.setattr(h, "HOLD_DIR", tmp_path / "hold")
    monkeypatch.setattr(h.time, "sleep", lambda s: None)
    etat = {"up": False, "wakes": 0}
    monkeypatch.setattr(h, "lxc_actif", lambda nom: etat["up"])

    def lance(argv, entree=None, delai=0):
        if argv[:2] == [h.WAKECTL, "wake"]:
            etat["wakes"] += 1
            etat["up"] = True
        return 0, "", ""
    monkeypatch.setattr(h, "lance", lance)
    h._etat = etat
    return h


def test_une_lecture_ne_reveille_rien(H):
    H._CONTEXTE.update(action="etat", reveille=False)
    with pytest.raises(H.Endormi):
        H.exige("nextcloud")
    assert H._etat["wakes"] == 0 and not (H.HOLD_DIR / "nextcloud").exists()


def test_une_action_reveille_et_tient(H):
    H._CONTEXTE.update(action="creer", reveille=False)
    H.exige("nextcloud")
    assert H._etat["wakes"] == 1 and (H.HOLD_DIR / "nextcloud").exists()
    H.relache()
    assert not (H.HOLD_DIR / "nextcloud").exists()


def test_reprise_pendant_le_demarrage_mais_pas_sur_existe(H):
    H._CONTEXTE.update(action="creer", reveille=True, tenus={"peertube"})
    (H.HOLD_DIR).mkdir(parents=True, exist_ok=True)
    essais = {"n": 0}

    class A:
        def creer(self, d):
            essais["n"] += 1
            if essais["n"] < 3:
                raise H.Echec("API pas encore prête")
            return None
    H._agit_patiemment(A(), {"action": "creer"})
    assert essais["n"] == 3

    class B:
        def creer(self, d):
            essais["n"] += 1
            raise H.Echec("user already exists")
    essais["n"] = 0
    with pytest.raises(H.Echec):
        H._agit_patiemment(B(), {"action": "creer"})
    assert essais["n"] == 1


def test_injoignable_apres_reveil_est_attendu(H):
    H._CONTEXTE.update(action="creer", reveille=True, tenus={"peertube"})
    H.HOLD_DIR.mkdir(parents=True, exist_ok=True)
    n = {"k": 0}

    class A:
        def creer(self, d):
            n["k"] += 1
            if n["k"] < 2:
                raise H.Indisponible("PeerTube injoignable (refused)")
    H._agit_patiemment(A(), {"action": "creer"})
    assert n["k"] == 2


def test_nextcloud_seul_user_not_found_vaut_absent(H, monkeypatch):
    """#1470 : un occ en échec (démarrage) n'est pas « absent »."""
    H._CONTEXTE.update(action="etat", reveille=False)
    H._etat["up"] = True
    sorties = {"u": (1, "user not found\n", ""), "boot": (1, "", "Nextcloud is not installed / maintenance")}
    monkeypatch.setattr(H, "lance", lambda argv, entree=None, delai=0: sorties[argv[-1]])
    assert H.Nextcloud().etat({"user": "u"}) == {"existe": False, "actif": None}
    with pytest.raises(H.Echec):
        H.Nextcloud().etat({"user": "boot"})
