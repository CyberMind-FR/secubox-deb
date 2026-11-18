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


def _campagnes(ds, prefixe):
    return [d for d in ds if d.cle.startswith(prefixe)]


def test_campagne_meme_outil(db):
    for ip in ("100.64.13.1", "100.64.14.1"):
        _ajout(db, "bans", T0 - timedelta(hours=1), ip=ip, cat="campagne:ab12cd34", sev="high",
               exp=int((T0 + timedelta(hours=3)).timestamp()))
        _waf(db, ip, T0 - timedelta(minutes=15), cat="scanners:x", host=f"{ip}.example.net")
    _waf(db, "100.64.15.1", T0 - timedelta(minutes=15), cat="scanners:x", host="seul.example.net")
    ds = dossiers.construire(db, T0)
    [c] = _campagnes(ds, "outil:ab12cd34:")
    assert c.type == "campagne" and c.membres == {"100.64.13.1": "meme_outil", "100.64.14.1": "meme_outil"}
    assert len(c.evenements) == 2                                     # les bans de la signature
    assert not _campagnes(ds, "bloc:") and not _campagnes(ds, "cible:")


def test_balayage_massif_pas_campagne(db):
    for k in range(300):
        _waf(db, f"100.65.{k // 200}.{k % 200 + 1}", T0 - timedelta(seconds=6 * k), cat="scanners:x",
             host="www.example.net")
    ds = dossiers.construire(db, T0)
    assert len(ds) == 300 and all(d.type == "acteur" for d in ds)


def test_campagne_meme_cible_meme_famille(db):
    _waf(db, "100.64.17.1", T0 - timedelta(minutes=12), cat="sqli:union", host="c.example.net")
    _waf(db, "100.64.18.1", T0 - timedelta(minutes=11), cat="sqli:blind", host="c.example.net")
    _waf(db, "100.64.20.1", T0 - timedelta(minutes=11), cat="xss:reflet", host="c.example.net")
    ds = dossiers.construire(db, T0)
    [c] = _campagnes(ds, "cible:c.example.net:sqli:")
    assert set(c.membres) == {"100.64.17.1", "100.64.18.1"} and set(c.membres.values()) == {"meme_cible"}
    assert not _campagnes(ds, "cible:c.example.net:xss:")


def test_campagne_meme_bloc(db):
    _waf(db, "100.64.16.1", T0 - timedelta(minutes=15), cat="sqli:x", host="a.example.net")
    _waf(db, "100.64.16.2", T0 - timedelta(minutes=14), cat="sqli:y", host="b.example.net")
    [c] = _campagnes(dossiers.construire(db, T0), "bloc:100.64.16.0/24:sqli:")
    assert set(c.membres) == {"100.64.16.1", "100.64.16.2"}


def test_vague_apres_calme_nouvelle_campagne(db):
    _waf(db, "100.64.21.1", T0 - timedelta(minutes=12), cat="sqli:x", host="d.example.net")
    _waf(db, "100.64.22.1", T0 - timedelta(minutes=11), cat="sqli:x", host="d.example.net")
    [c1] = _campagnes(dossiers.construire(db, T0), "cible:d.example.net:sqli:")
    t = T0 + timedelta(hours=7)
    _waf(db, "100.64.21.1", t - timedelta(minutes=5), cat="sqli:x", host="d.example.net")
    _waf(db, "100.64.23.1", t - timedelta(minutes=4), cat="sqli:x", host="d.example.net")
    [c2] = _campagnes(dossiers.construire(db, t), "cible:d.example.net:sqli:")
    assert c2.cle != c1.cle and set(c2.membres) == {"100.64.21.1", "100.64.23.1"}
    # Pendant la vague, un nouvel attaquant étend la même campagne.
    _waf(db, "100.64.24.1", t + timedelta(minutes=1), cat="sqli:x", host="d.example.net")
    [c3] = _campagnes(dossiers.construire(db, t + timedelta(minutes=2)), "cible:d.example.net:sqli:")
    assert c3.cle == c2.cle and "100.64.24.1" in c3.membres


def test_adresse_vue_par_une_mesure_rejoint_acteur(db):
    w = _waf(db, "100.64.25.1", T0 - timedelta(minutes=5), cat="sqli:x")
    m = _ajout(db, "mesures", T0 - timedelta(minutes=2), actor="ACT-0001", ip="100.64.25.1", decision="banni",
               exclu_correlation="mesure")
    ds = {d.cle: d for d in dossiers.construire(db, T0)}
    assert "100.64.25.1" not in ds and ds["ACT-0001"].evenements == [w.id] and m.id not in ds["ACT-0001"].evenements
    # Rattachement le plus récent : une proposition plus récente déplace l'adresse.
    _acteur(db, "ACT-0002", ["100.64.25.1"], T0 - timedelta(minutes=1))
    _waf(db, "100.64.25.1", T0, cat="sqli:x")
    assert "ACT-0002" in {d.cle for d in dossiers.construire(db, T0 + timedelta(seconds=30))}


def test_fonte_deplace_appartenance_campagne(db):
    _waf(db, "100.64.26.1", T0 - timedelta(minutes=12), cat="sqli:x", host="e.example.net")
    _waf(db, "100.64.27.1", T0 - timedelta(minutes=11), cat="sqli:x", host="e.example.net")
    [c] = _campagnes(dossiers.construire(db, T0), "cible:e.example.net:")
    _acteur(db, "ACT-0050", ["100.64.26.1"], T0)
    dossiers.construire(db, T0 + timedelta(seconds=30))
    membres = {k for (k,) in db.execute("SELECT d.cle FROM dossier_membres m JOIN dossiers d ON d.id = m.membre_id "
                                        "WHERE m.campagne_id = ?", (c.id,))}
    assert membres == {"ACT-0050", "100.64.27.1"}


def test_passe_bornee(db):
    for k in range(5):
        _waf(db, f"100.64.28.{k + 1}", T0 - timedelta(minutes=5), cat="scanners:x")
    assert len(dossiers.construire(db, T0, max_recalcul=2)) == 2
    assert len(dossiers.construire(db, T0, max_recalcul=2)) == 2
    assert len(dossiers.construire(db, T0, max_recalcul=2)) == 1
    assert dossiers.construire(db, T0) == []


def test_retention_dossiers(db):
    from veille import retention
    vieux = T0 - timedelta(days=400)
    _waf(db, "100.64.29.1", vieux, cat="scanners:x")
    dossiers.construire(db, vieux + timedelta(minutes=1))
    retention.purger(db, T0)                     # événement purgé (30 j) → lien parti ; dossier vieux et vide
    assert db.execute("SELECT count(*) FROM dossiers").fetchone()[0] == 0


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


def test_source_mesures_garde_acteur_et_adresse():
    import asyncio
    from veille.sources import mesures

    class Client:
        appels = []

        def horloge(self):
            return T0.timestamp()

        async def get(self, nom, params=None):
            self.appels.append((nom, params))
            return {"complet": True, "mesures": [
                {"actor": "ACT-0001", "applique": True, "confiance": 90, "decision": "banni", "expire": 1795000000,
                 "ip": "34.118.70.1", "mode": "auto", "ts": 1794993809, "version": "v1"}]}

    c = Client()
    lot = asyncio.run(mesures.Mesures().lire(c, None))
    [e] = lot.evenements
    assert c.appels[0][0] == "mesures" and c.appels[0][1]["depuis"] == int(T0.timestamp()) - 86400
    assert e.ip_src == "34.118.70.1" and e.attributs == {"actor": "ACT-0001", "decision": "banni",
                                                         "exclu_correlation": "mesure"}
    assert e.horodatage == "2026-11-18T09:23:29Z" and lot.curseur == "1794993809"
    assert asyncio.run(mesures.Mesures().lire(c, lot.curseur)).curseur == "1794993809"
