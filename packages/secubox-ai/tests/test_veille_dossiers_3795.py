# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Dossiers d'attaquant et étapes (#3795) : clé acteur d'actord ou adresse, étapes nommées avec preuves et heures,
campagnes par règle écrite, exclusions (documentation, LAN, autotest)."""
import json
from datetime import timedelta

import pytest

from veille import base, correlation, dossiers, normaliser
from test_veille_correlation_3721 import T0, _ajout, _auth, _waf


@pytest.fixture
def db(tmp_path):
    d = base.ouvrir(tmp_path / "veille.db")
    yield d
    d.close()


def _acteur(db, actor, ips, quand):
    return _ajout(db, "actord", quand, id=f"prop-{actor}", actor=actor, ips=ips, category="actord", severity="high")


def _par_cle(ds):
    return {d.cle: d for d in ds}


def test_dossier_chronologie_multicouche(db):
    _acteur(db, "ACT-0007", ["100.64.10.1", "100.64.11.2", "203.0.113.5"], T0 - timedelta(hours=2))
    w = _waf(db, "100.64.10.1", T0 - timedelta(minutes=50), cat="scanners:nmap", sev="low")
    a = _auth(db, "100.64.11.2", T0 - timedelta(minutes=30), "smtp", sev="medium")
    g = _ajout(db, "garde", T0 - timedelta(minutes=20), menace="intrusion", ip="100.64.10.1", gravite="high")
    _waf(db, "203.0.113.5", T0 - timedelta(minutes=10), cat="sqli:x")          # documentation : exclu
    ds = _par_cle(dossiers.construire(db, T0))
    assert "100.64.10.1" not in ds and "100.64.11.2" not in ds and "203.0.113.5" not in ds
    d = ds["ACT-0007"]
    assert d.type == "acteur" and d.adresses == ["100.64.10.1", "100.64.11.2"]
    assert d.evenements == [w.id, a.id, g.id]                                 # ordre chronologique, trois couches
    assert d.premiere_vue == w.horodatage and d.derniere_vue == g.horodatage and d.gravite == "high"
    assert d.outils == []
    ligne = db.execute("SELECT type, gravite, outils_json FROM dossiers WHERE cle = 'ACT-0007'").fetchone()
    assert ligne == ("acteur", "high", "[]")
    assert dossiers.construire(db, T0 + timedelta(seconds=60)) == []           # rien de neuf : rien rendu


def test_etapes_enchainees(db):
    ip = "100.64.12.1"
    ban = _ajout(db, "bans", T0 - timedelta(days=1), ip=ip, cat="scanners", sev="medium",
                 exp=int((T0 - timedelta(hours=1)).timestamp()))
    s = _waf(db, ip, T0 - timedelta(minutes=25), cat="scanners:x", sev="low")
    p = _waf(db, ip, T0 - timedelta(minutes=20), cat="product_absent_probes:wp", sev="low")
    x = _waf(db, ip, T0 - timedelta(minutes=10), cat="sqli:union", sev="high")
    correlation.correler(db, T0)
    d = _par_cle(dossiers.construire(db, T0))[ip]
    etapes = {e["etape"]: e for e in d.etapes}
    assert [e["etape"] for e in d.etapes] == ["reperage", "essais", "exploitation", "persistance"]
    assert etapes["reperage"]["regles"] == ["balayage"] and etapes["reperage"]["preuves"] == [s.id]
    assert etapes["essais"]["regles"] == ["sondes_produits_absents"] and etapes["essais"]["preuves"] == [p.id]
    assert etapes["exploitation"]["regles"] == ["regle_waf_attaque"]
    assert etapes["exploitation"]["debut"] == x.horodatage == etapes["exploitation"]["fin"]
    assert etapes["persistance"]["regles"] == ["retour_apres_ban"] and ban.id not in etapes["persistance"]["preuves"]
    assert set(etapes["persistance"]["preuves"]) == {s.id, p.id, x.id}
    assert d.enchainees == 3 and d.incidents                                  # reperage → essais → exploitation
    stocke = json.loads(db.execute("SELECT etapes_json FROM dossiers WHERE cle = ?", (ip,)).fetchone()[0])
    assert stocke == d.etapes


def test_campagne_meme_outil(db):
    for ip in ("100.64.13.1", "100.64.14.1"):
        _ajout(db, "bans", T0 - timedelta(hours=1), ip=ip, cat="campagne:ab12cd34", sev="high",
               exp=int((T0 + timedelta(hours=3)).timestamp()))
        _waf(db, ip, T0 - timedelta(minutes=15), cat="scanners:x", host=f"{ip}.example.net")
    _waf(db, "100.64.15.1", T0 - timedelta(minutes=15), cat="scanners:x", host="seul.example.net")
    ds = _par_cle(dossiers.construire(db, T0))
    c = ds["outil:ab12cd34"]
    assert c.type == "campagne" and c.membres == {"100.64.13.1": "meme_outil", "100.64.14.1": "meme_outil"}
    assert len(c.evenements) == 4
    assert not any(k.startswith(("bloc:", "cible:")) for k in ds)


def test_campagne_meme_bloc_et_cible(db):
    _waf(db, "100.64.16.1", T0 - timedelta(minutes=15), cat="scanners:x", host="a.example.net")
    _waf(db, "100.64.16.2", T0 - timedelta(minutes=14), cat="scanners:x", host="b.example.net")
    _waf(db, "100.64.17.1", T0 - timedelta(minutes=12), cat="sqli:x", host="c.example.net")
    _waf(db, "100.64.18.1", T0 - timedelta(minutes=11), cat="sqli:x", host="c.example.net")
    ds = _par_cle(dossiers.construire(db, T0))
    assert set(ds["bloc:100.64.16.0/24"].membres) == {"100.64.16.1", "100.64.16.2"}
    assert set(ds["cible:c.example.net"].membres) == {"100.64.17.1", "100.64.18.1"}


def test_dossier_sans_actord_par_adresse(db):
    w = _waf(db, "100.64.19.1", T0 - timedelta(minutes=5), cat="honeypot", sev="medium")
    _waf(db, "local", T0 - timedelta(minutes=5), cat="sqli:x")
    _waf(db, "100.64.19.9", T0 - timedelta(minutes=5), cat="sqli:x", user_agent="SecuBox-WAF-SelfTest/1")
    ds = dossiers.construire(db, T0)
    assert [d.cle for d in ds] == ["100.64.19.1"]
    assert ds[0].type == "acteur" and ds[0].evenements == [w.id]
    assert ds[0].etapes[0]["etape"] == "essais" and ds[0].etapes[0]["regles"] == ["leurre_touche"]
    # L'acteur arrive plus tard : l'adresse rejoint le dossier de l'acteur.
    _acteur(db, "ACT-0042", ["100.64.19.1"], T0 + timedelta(minutes=1))
    ds = _par_cle(dossiers.construire(db, T0 + timedelta(minutes=2)))
    assert ds["ACT-0042"].evenements == [w.id]
    assert normaliser.rfc3339(T0) <= ds["ACT-0042"].maj_le
