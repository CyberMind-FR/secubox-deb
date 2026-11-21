# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Corrélateur d'incidents (#3721) : une règle par test, exclusions (LAN, autotest, documentation), extension sans
doublon, calme puis clos. Jeu de référence + cas construits (adresses hors plages de documentation)."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from veille import base, correlation, normaliser

DONNEES = Path(__file__).resolve().parent / "donnees"
T0 = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db(tmp_path):
    d = base.ouvrir(tmp_path / "veille.db")
    yield d
    d.close()


_n = [0]


def _ajout(db, source, quand, **brut):
    _n[0] += 1
    brut.setdefault("ts", int(quand.timestamp()))
    e = normaliser.evenement(source, brut, id_source=f"t{_n[0]}", maintenant=T0)
    db.execute(f"INSERT INTO evenements({', '.join(normaliser.COLONNES)}) VALUES ({', '.join('?' * len(normaliser.COLONNES))})", e.ligne())
    return e


def _waf(db, ip, quand, cat="xss:reflet", sev="high", host="site.example.net", **kw):
    return _ajout(db, "menaces", quand, category=cat, client_ip=ip, severity=sev, host=host, **kw)


def _auth(db, ip, quand, service="smtp", sev="high"):
    return _ajout(db, "menaces", quand, category=f"auth_{service}:sasl_failed", client_ip=ip, severity=sev,
                  host=service, tool="authwatch", action="banned")


def _regles(incs):
    return sorted(i.regle for i in incs)


def test_multi_source(db):
    a = _auth(db, "100.64.1.1", T0 - timedelta(minutes=10))
    w = _waf(db, "100.64.1.1", T0 - timedelta(minutes=5), cat="scanners:x", sev="medium")
    incs = [i for i in correlation.correler(db, T0) if i.regle == "multi_source"]
    assert len(incs) == 1 and incs[0].cle == "100.64.1.1"
    assert set(incs[0].preuves) == {a.id, w.id} and incs[0].sources == ["authwatch", "waf"]
    assert incs[0].gravite == "high" and incs[0].etat == "ouvert"


def test_une_seule_source_pas_incident(db):
    _waf(db, "100.64.1.2", T0 - timedelta(minutes=10))
    _ajout(db, "bans", T0 - timedelta(minutes=9), ip="100.64.1.2", cat="xss", sev="high", exp=int(T0.timestamp()) + 99)
    assert correlation.correler(db, T0) == []          # un ban de sbxwaf reste un fait du WAF


def test_multi_service(db):
    _auth(db, "100.64.2.1", T0 - timedelta(minutes=20), "smtp")
    _auth(db, "100.64.2.1", T0 - timedelta(minutes=15), "imap", sev="medium")
    incs = [i for i in correlation.correler(db, T0) if i.regle == "multi_service"]
    assert [i.cle for i in incs] == ["100.64.2.1"] and incs[0].gravite == "high"


def test_bloc_mixte(db):
    _waf(db, "100.64.3.1", T0 - timedelta(minutes=20), cat="scanners:x", sev="low")
    _waf(db, "100.64.3.2", T0 - timedelta(minutes=10), cat="sqli:union", sev="high")
    incs = [i for i in correlation.correler(db, T0) if i.regle == "bloc_mixte"]
    assert [i.cle for i in incs] == ["100.64.3.0/24"]


def test_bloc_mixte_familles_sures_seules(db):
    _waf(db, "100.64.3.1", T0 - timedelta(minutes=20), cat="scanners:x")
    _waf(db, "100.64.3.2", T0 - timedelta(minutes=10), cat="recon_crawler")
    assert correlation.correler(db, T0) == []


def test_retour_apres_ban(db):
    ban = _ajout(db, "bans", T0 - timedelta(days=1), ip="100.64.4.1", cat="scanners", sev="medium",
                 exp=int((T0 - timedelta(hours=1)).timestamp()))
    w = _waf(db, "100.64.4.1", T0 - timedelta(minutes=5), cat="scanners:x", sev="medium")
    incs = [i for i in correlation.correler(db, T0) if i.regle == "retour_apres_ban"]
    assert len(incs) == 1 and set(incs[0].preuves) == {ban.id, w.id}


def test_retour_bloc_apres_ban(db):
    db.execute("INSERT INTO blocs(bloc24, banni_jusqua, origine, vu_le) VALUES ('100.64.5.0/24', ?, 'clic', ?)",
               (normaliser.rfc3339(T0 - timedelta(hours=2)), normaliser.rfc3339(T0)))
    _waf(db, "100.64.5.9", T0 - timedelta(minutes=5), cat="scanners:x")
    assert [i.cle for i in correlation.correler(db, T0) if i.regle == "retour_apres_ban"] == ["100.64.5.0/24"]


def test_campagne_etendue(db):
    db.execute("INSERT INTO campagnes(id, premiere_vue, derniere_vue) VALUES ('cea8627e6f2c5244', ?, ?)",
               (normaliser.rfc3339(T0 - timedelta(days=1)), normaliser.rfc3339(T0)))
    _ajout(db, "bans", T0 - timedelta(hours=3), ip="100.64.6.1", cat="campagne:cea8627e6f2c5244", sev="high",
           exp=int((T0 + timedelta(hours=3)).timestamp()))
    _auth(db, "100.64.6.1", T0 - timedelta(minutes=3))
    incs = [i for i in correlation.correler(db, T0) if i.regle == "campagne_etendue"]
    assert len(incs) == 1 and incs[0].cle == "cea8627e6f2c5244" and incs[0].campagne_id == "cea8627e6f2c5244"


def test_leurre_puis_attaque(db):
    _waf(db, "100.64.7.1", T0 - timedelta(minutes=20), cat="honeypot", sev="medium")
    _waf(db, "100.64.7.1", T0 - timedelta(minutes=10), cat="sqli:union", sev="high")
    incs = [i for i in correlation.correler(db, T0) if i.regle == "leurre_puis_attaque"]
    assert len(incs) == 1 and incs[0].gravite == "critical"        # high + un cran


def test_attaque_puis_leurre_pas_incident(db):
    _waf(db, "100.64.7.2", T0 - timedelta(minutes=20), cat="sqli:union")
    _waf(db, "100.64.7.2", T0 - timedelta(minutes=10), cat="honeypot")
    assert [i for i in correlation.correler(db, T0) if i.regle == "leurre_puis_attaque"] == []


def test_garde_et_waf(db):
    _ajout(db, "garde", T0 - timedelta(minutes=8), menace="intrusion", ip="100.64.8.1", gravite="high")
    _waf(db, "100.64.8.1", T0 - timedelta(minutes=4), cat="scanners:x", sev="low")
    incs = [i for i in correlation.correler(db, T0) if i.regle == "garde_et_waf"]
    assert len(incs) == 1 and incs[0].sources == ["garde", "waf"]


def test_autotest_et_lan_jamais_incident(db):
    for k in range(3):
        _waf(db, "100.64.9.1", T0 - timedelta(minutes=10 + k), cat="sqli:x", user_agent="SecuBox-WAF-SelfTest/1")
        _waf(db, "local", T0 - timedelta(minutes=10 + k), cat="honeypot")
        _waf(db, "local", T0 - timedelta(minutes=5 + k), cat="sqli:x")
    _auth(db, "local", T0 - timedelta(minutes=2))
    _auth(db, "100.64.9.1", T0 - timedelta(minutes=2), "imap")
    assert correlation.correler(db, T0) == []
    assert db.execute("SELECT COUNT(*) FROM incident_preuves").fetchone()[0] == 0


def test_plages_documentation_exclues(db):
    """Jeu de référence entier (anonymisé en plages de documentation) : gardé en base, jamais corrélé."""
    lignes = [json.loads(x) for x in (DONNEES / "menaces.jsonl").read_text(encoding="utf-8").splitlines() if x]
    bans = [json.loads(x) for x in (DONNEES / "bans.jsonl").read_text(encoding="utf-8").splitlines() if x]
    evts = [normaliser.evenement("menaces", x, id_source=f"r{i}") for i, x in enumerate(lignes)]
    evts += [normaliser.evenement("bans", x, id_source=f"b{i}") for i, x in enumerate(bans)]
    db.executemany(f"INSERT OR IGNORE INTO evenements({', '.join(normaliser.COLONNES)}) VALUES "
                   f"({', '.join('?' * len(normaliser.COLONNES))})", [e.ligne() for e in evts])
    assert db.execute("SELECT COUNT(*) FROM evenements").fetchone()[0] > 300
    fin = max(datetime.fromisoformat(e.horodatage.replace("Z", "+00:00")) for e in evts)
    for k in range(0, 48):
        assert correlation.correler(db, fin - timedelta(hours=k), fenetre_s=7200) == []
    assert db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0
    # même motif, adresses hors documentation : un incident
    _auth(db, "100.64.10.1", T0 - timedelta(minutes=3))
    _waf(db, "100.64.10.1", T0 - timedelta(minutes=2))
    assert "multi_source" in _regles(correlation.correler(db, T0))


def test_incident_etendu_pas_duplique(db):
    _auth(db, "100.64.11.1", T0 - timedelta(minutes=10), sev="medium")
    _waf(db, "100.64.11.1", T0 - timedelta(minutes=9), sev="medium")
    premier = [i for i in correlation.correler(db, T0) if i.regle == "multi_source"][0]
    assert correlation.correler(db, T0 + timedelta(seconds=60)) == []           # rien de neuf : rien rendu
    t1 = T0 + timedelta(minutes=10)
    nouveau = _waf(db, "100.64.11.1", t1 - timedelta(minutes=1), cat="sqli:x", sev="critical")
    etendu = [i for i in correlation.correler(db, t1) if i.regle == "multi_source"][0]
    assert etendu.id == premier.id and nouveau.id in etendu.preuves and len(etendu.preuves) == 3
    assert etendu.gravite == "critical" and etendu.premiere_vue == premier.premiere_vue
    assert db.execute("SELECT COUNT(*) FROM incidents WHERE regle = 'multi_source'").fetchone()[0] == 1


def test_calme_puis_clos(db):
    _auth(db, "100.64.12.1", T0 - timedelta(minutes=10))
    _waf(db, "100.64.12.1", T0 - timedelta(minutes=9))
    iid = correlation.correler(db, T0)[0].id
    etat = lambda: db.execute("SELECT etat FROM incidents WHERE id = ?", (iid,)).fetchone()[0]  # noqa: E731
    correlation.correler(db, T0 + timedelta(hours=5))
    assert etat() == "ouvert"
    correlation.correler(db, T0 + timedelta(hours=7))
    assert etat() == "calme"
    correlation.correler(db, T0 + timedelta(days=8))
    assert etat() == "clos"
    # nouvelle activité après clôture : nouvel incident, l'ancien reste clos
    t = T0 + timedelta(days=8, minutes=5)
    _auth(db, "100.64.12.1", t - timedelta(minutes=2))
    _waf(db, "100.64.12.1", t - timedelta(minutes=1))
    nouveau = [i for i in correlation.correler(db, t) if i.regle == "multi_source"][0]
    assert nouveau.id != iid and etat() == "clos"


def test_calme_rouvert_par_nouvelle_preuve(db):
    _auth(db, "100.64.13.1", T0 - timedelta(minutes=10))
    _waf(db, "100.64.13.1", T0 - timedelta(minutes=9))
    iid = correlation.correler(db, T0)[0].id
    t = T0 + timedelta(hours=7)
    correlation.correler(db, t)
    _waf(db, "100.64.13.1", t + timedelta(minutes=1), cat="scanners:y")
    _auth(db, "100.64.13.1", t + timedelta(minutes=2), "imap")
    incs = {i.regle: i for i in correlation.correler(db, t + timedelta(minutes=3))}
    assert incs["multi_source"].id == iid and incs["multi_source"].etat == "ouvert"


def test_clos_court_ban_reutilise_ne_bloque_pas(db):
    """clos_s court (< 7 j) : le même ban, encore regardé en arrière, ne rouvre ni ne heurte l'incident clos."""
    ban = _ajout(db, "bans", T0 - timedelta(hours=2), ip="100.64.14.1", cat="scanners", sev="medium",
                 exp=int((T0 - timedelta(hours=1)).timestamp()))
    _waf(db, "100.64.14.1", T0 - timedelta(minutes=5), cat="scanners:x")
    premier = [i for i in correlation.correler(db, T0, calme_s=600, clos_s=1200) if i.regle == "retour_apres_ban"][0]
    correlation.correler(db, T0 + timedelta(hours=1), calme_s=600, clos_s=1200)
    assert db.execute("SELECT etat FROM incidents WHERE id = ?", (premier.id,)).fetchone()[0] == "clos"
    t = T0 + timedelta(hours=1, minutes=10)
    retour = _waf(db, "100.64.14.1", t - timedelta(minutes=1), cat="scanners:y")
    nouveaux = [i for i in correlation.correler(db, t, calme_s=600, clos_s=1200) if i.regle == "retour_apres_ban"]
    assert len(nouveaux) == 1 and nouveaux[0].id != premier.id
    assert ban.id not in nouveaux[0].preuves and retour.id in nouveaux[0].preuves
    correlation.correler(db, t + timedelta(seconds=60), calme_s=600, clos_s=1200)       # aucune exception


def test_collision_identifiant_tolere(db):
    _auth(db, "100.64.15.1", T0 - timedelta(minutes=10))
    _waf(db, "100.64.15.1", T0 - timedelta(minutes=9))
    iid = correlation.correler(db, T0)[0].id
    db.execute("UPDATE incidents SET etat = 'clos'")
    db.execute("DELETE FROM incident_preuves")                  # preuves détachées : même premiere_vue, même id
    assert any(i.id == iid for i in correlation.correler(db, T0 + timedelta(seconds=60)))


def test_reglages_bornes():
    r = correlation.reglages({"veille": {"correlation": {"clos_s": 3600, "calme_s": 10, "fenetre_s": "x"}}})
    assert r == {"fenetre_s": 1800, "calme_s": 600, "clos_s": correlation.RETOUR_BAN_S}
    assert correlation.reglages({}) == {"fenetre_s": 1800, "calme_s": 21600, "clos_s": 604800}


def test_familles_sures_alignees_waf_ng():
    import ast
    from veille import regles
    src = Path(__file__).resolve().parents[2] / "secubox-waf-ng" / "composants" / "waf" / "api" / "gestes_ia.py"
    if not src.exists():
        pytest.skip("secubox-waf-ng absent")
    for n in ast.parse(src.read_text(encoding="utf-8")).body:
        if isinstance(n, ast.Assign) and any(getattr(t, "id", None) == "CATEGORIES_SURES" for t in n.targets):
            assert set(ast.literal_eval(n.value.args[0])) == regles.CATEGORIES_SURES
            return
    pytest.fail("CATEGORIES_SURES introuvable dans gestes_ia.py")


def test_index_source(db):
    assert db.execute("SELECT name FROM sqlite_master WHERE name = 'idx_evt_source'").fetchone()
