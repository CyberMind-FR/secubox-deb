# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""IPv6 Guardian phase 2 : lecture du pare-feu de la Freebox par la socket de secubox-freebox, avec les identifiants de l'appelant."""
from api import freebox as F
from api import verdict as V

PUBLIC = [{"adresses_publiques": ["2a01::1"], "services": []}]


def test_les_identifiants_de_l_appelant_sont_relayes_et_rien_d_autre():
    vus = {}

    def transport(chemin, entetes):
        vus.update(entetes)
        return 200, {"pare_feu_actif": True, "exceptions": [], "exceptions_lues": True}

    F.lire_pare_feu({"authorization": "Bearer abc", "cookie": "s=1", "x-secubox-lan": "1", "x-forwarded-for": "9.9.9.9", "host": "x"}, transport)
    assert vus == {"Authorization": "Bearer abc", "Cookie": "s=1", "X-SecuBox-LAN": "1"}


def test_pare_feu_actif_et_exceptions_lues_est_rendu_tel_quel():
    r = F.lire_pare_feu({}, lambda c, e: (200, {"pare_feu_actif": True, "exceptions_lues": True,
        "exceptions": [{"appareil": "nas", "protocole": "tcp", "port_debut": 443, "port_fin": 443}]}))
    assert r["pare_feu_actif"] is True and r["exceptions"] == [{"appareil": "nas", "port": 443}] and r["exceptions_lues"] is True


def test_pare_feu_desactive_est_rendu():
    r = F.lire_pare_feu({}, lambda c, e: (200, {"pare_feu_actif": False, "exceptions": [], "exceptions_lues": False}))
    assert r["pare_feu_actif"] is False


def test_tout_echec_rend_none_donc_a_verifier():
    assert F.lire_pare_feu({}, lambda c, e: (409, {"etat": "non_configure"})) is None
    assert F.lire_pare_feu({}, lambda c, e: (401, {})) is None
    assert F.lire_pare_feu({}, lambda c, e: (_ for _ in ()).throw(OSError("socket absente"))) is None
    assert F.lire_pare_feu({}, lambda c, e: (200, {"pare_feu_actif": None})) is None


def test_pare_feu_actif_mais_exceptions_illisibles_ne_dit_pas_protege():
    v = V.verdict(PUBLIC, {"pare_feu_actif": True, "exceptions": [], "exceptions_lues": False})
    assert v["niveau"] == "a_verifier" and "exceptions" in v["explication"] and "bloque par défaut" in v["explication"]


def test_exceptions_lues_vides_reste_protege():
    assert V.verdict(PUBLIC, {"pare_feu_actif": True, "exceptions": [], "exceptions_lues": True})["niveau"] == "protege"
    assert V.verdict(PUBLIC, {"pare_feu_actif": True, "exceptions": []})["niveau"] == "protege"   # compat phase 1


def test_pare_feu_desactive_est_expose():
    assert V.verdict(PUBLIC, {"pare_feu_actif": False, "exceptions": [], "exceptions_lues": False})["niveau"] == "expose"
