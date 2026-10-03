# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
import os

import pytest

from api import dnstv_regles as R

T0 = 1_800_000_000


def test_proposer_cree_un_candidat_unique_par_appareil_et_domaine():
    r = R.Regles()
    a = r.proposer("tv-banc", "videos-pub.ftv-publicite.fr", 70, "faible", T0)
    assert a["etat"] == "candidat"
    assert r.proposer("tv-banc", "videos-pub.ftv-publicite.fr", 90, "faible", T0 + 5) is None   # déjà là : pas de doublon
    assert len(r.liste()) == 1


def test_domaine_hostile_refuse():
    r = R.Regles()
    for mauvais in ('a"; reboot', "../etc", "UPPER.example.com ", "x" * 300 + ".com", "a b.com", "", "com"):
        with pytest.raises(R.ErreurRegle):
            r.proposer("tv-banc", mauvais, 10, "faible", T0)


def test_cycle_essai_confirme_retire():
    r = R.Regles()
    rid = r.proposer("tv", "ad.example.com", 50, "faible", T0)["id"]
    e = r.transiter(rid, "essai", "admin", "essai demandé", T0 + 1)
    assert e["etat"] == "essai" and e["fin_essai"] == T0 + 1 + R.ESSAI_S
    assert r.actives("tv") == ["ad.example.com"]
    assert r.transiter(rid, "confirme", "admin", "ok", T0 + 100)["etat"] == "confirme"
    assert r.actives("tv") == ["ad.example.com"]
    assert r.transiter(rid, "retire", "admin", "casse", T0 + 200)["etat"] == "retire"
    assert r.actives("tv") == []


def test_transition_interdite():
    r = R.Regles()
    rid = r.proposer("tv", "ad.example.com", 50, "faible", T0)["id"]
    with pytest.raises(R.ErreurRegle):
        r.transiter(rid, "confirme", "admin", "sans essai", T0 + 1)     # on ne confirme pas ce qui n'a pas été essayé


def test_essai_expire_sans_confirmation_est_retire():
    r = R.Regles()
    rid = r.proposer("tv", "ad.example.com", 50, "faible", T0)["id"]
    r.transiter(rid, "essai", "admin", "", T0)
    assert r.expirer(T0 + R.ESSAI_S - 1) == []
    ch = r.expirer(T0 + R.ESSAI_S + 1)
    assert [c["id"] for c in ch] == [rid] and r.get(rid)["etat"] == "retire"
    assert "expir" in r.get(rid)["motif"]
    assert r.actives("tv") == []


def test_candidat_trop_ancien_disparait_et_rejete_ne_revient_jamais():
    r = R.Regles()
    c = r.proposer("tv", "a.example.com", 50, "faible", T0)["id"]
    j = r.proposer("tv", "b.example.com", 50, "faible", T0)["id"]
    r.transiter(j, "rejete", "admin", "non", T0 + 1)
    r.expirer(T0 + R.CANDIDAT_S + 1)
    assert r.get(c)["etat"] == "retire"
    assert r.proposer("tv", "b.example.com", 99, "faible", T0 + 10) is None   # rejeté : jamais reproposé


def test_historique_borne():
    r = R.Regles()
    rid = r.proposer("tv", "a.example.com", 1, "faible", T0)["id"]
    for i in range(40):
        r.transiter(rid, "essai", "admin", "", T0 + i * 2)
        r.transiter(rid, "retire", "admin", "", T0 + i * 2 + 1)
    assert len(r.get(rid)["historique"]) <= 20


def test_stockage_atomique_et_lien_symbolique_refuse(tmp_path):
    r = R.Regles()
    r.proposer("tv", "a.example.com", 1, "faible", T0)
    R.ecrire(r, tmp_path)
    assert R.charger(tmp_path).liste()[0]["domaine"] == "a.example.com"
    (tmp_path / "regles.json").unlink()
    (tmp_path / "ailleurs.json").write_text(json.dumps({"version": 1, "regles": []}))
    os.symlink(tmp_path / "ailleurs.json", tmp_path / "regles.json")
    with pytest.raises(R.ErreurRegle):
        R.charger(tmp_path)


def test_fichier_corrompu_refuse_sans_deviner(tmp_path):
    (tmp_path / "regles.json").write_text("{pas du json")
    with pytest.raises(R.ErreurRegle):
        R.charger(tmp_path)
    (tmp_path / "regles.json").write_text(json.dumps({"version": 1, "regles": [{"domaine": "a b", "appareil": "tv", "etat": "essai"}]}))
    with pytest.raises(R.ErreurRegle):
        R.charger(tmp_path)


def test_absent_donne_un_ensemble_vide(tmp_path):
    assert R.charger(tmp_path).liste() == []


def test_slug():
    assert R.slug("TV banc") == "tv-banc"
    assert R.slug("  Salon/ TV_2 ") == "salon-tv-2"
