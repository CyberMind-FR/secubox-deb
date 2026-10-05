# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Lecture du journal waf-threats.log tel que sbxwaf l'écrit (action, severity, category)."""
import json

from api import sbxwaf_log as j

DETECT = {"timestamp": "2026-10-05T09:57:57+02:00", "client_ip": "173.252.95.8", "host": "wanted.gk2.secubox.in",
          "method": "GET", "path": "/robots.txt", "category": "recon_crawler", "severity": "info",
          "rule_id": "recon-001", "action": "detect", "user_agent": "facebookexternalhit/1.1"}
BANNED = dict(DETECT, action="banned", category="sqli", severity="high", rule_id="sqli-007", client_ip="203.0.113.9")
WARNING = dict(DETECT, action="warning", category="scan", rule_id="scan-002", client_ip="198.51.100.4")
ROBOT = dict(DETECT, action="robot", category="robots", rule_id="")


def test_une_detection_devient_une_alerte():
    a = j.alerte_depuis_ligne(DETECT)
    assert a["source"] == "waf" and a["type"] == "recon_crawler" and a["ip"] == "173.252.95.8"
    assert a["severity"] == "low"


def test_un_bannissement_est_une_alerte_de_gravite_haute():
    a = j.alerte_depuis_ligne(BANNED)
    assert a["severity"] == "high" and a["type"] == "sqli"


def test_un_avertissement_est_de_gravite_moyenne():
    assert j.alerte_depuis_ligne(WARNING)["severity"] == "medium"


def test_un_passage_de_robot_n_est_pas_une_alerte():
    assert j.alerte_depuis_ligne(ROBOT) is None


def test_l_identifiant_est_stable_et_distingue_les_evenements():
    assert j.alerte_depuis_ligne(DETECT)["id"] == j.alerte_depuis_ligne(dict(DETECT))["id"]
    assert j.alerte_depuis_ligne(DETECT)["id"] != j.alerte_depuis_ligne(dict(DETECT, path="/autre"))["id"]


def test_les_details_gardent_l_essentiel_sans_le_user_agent_complet():
    a = j.alerte_depuis_ligne(dict(DETECT, user_agent="x" * 500, tool="sqlmap"))
    assert a["details"]["host"] == "wanted.gk2.secubox.in" and a["details"]["tool"] == "sqlmap"
    assert len(a["details"]["user_agent"]) <= 160


def test_les_lignes_illisibles_sont_ignorees():
    lignes = ["", "pas du json", json.dumps(DETECT), "{"]
    assert len(j.alertes_depuis_lignes(lignes)) == 1


def test_la_vue_d_ensemble_compte_ce_que_le_panneau_affiche():
    lignes = [json.dumps(x) for x in (DETECT, DETECT, BANNED, WARNING, ROBOT)]
    ov = j.vue_d_ensemble(lignes, aujourd_hui="2026-10-05")
    assert ov["running"] is True
    assert ov["threats_total"] == 5 and ov["threats_today"] == 5
    assert ov["blocked_24h"] == 1
    assert ov["rules_loaded"] == 3
    assert ov["by_category"]["recon_crawler"] == 2
    assert ov["by_severity"]["high"] == 1


def test_la_vue_d_ensemble_ne_compte_pas_aujourd_hui_les_lignes_d_hier():
    hier = dict(DETECT, timestamp="2026-10-04T23:59:59+02:00")
    ov = j.vue_d_ensemble([json.dumps(hier), json.dumps(DETECT)], aujourd_hui="2026-10-05")
    assert ov["threats_today"] == 1 and ov["threats_total"] == 2


def test_le_journal_vide_donne_une_vue_vide_mais_active():
    ov = j.vue_d_ensemble([], aujourd_hui="2026-10-05")
    assert ov["running"] is True and ov["threats_total"] == 0


def test_la_synthese_locale_resume_les_alertes_sans_modele():
    alertes = j.alertes_depuis_lignes([json.dumps(x) for x in (DETECT, DETECT, BANNED, WARNING)])
    texte = j.synthese_locale(alertes)
    assert "4 alerte" in texte
    assert "recon_crawler" in texte and "203.0.113.9" in texte
    assert "sqli" in texte


def test_la_synthese_locale_sans_alerte():
    assert "Aucune alerte" in j.synthese_locale([])


def test_l_horodatage_avec_fuseau_est_converti_en_utc_naif():
    from datetime import datetime
    assert j.horodatage_utc("2026-10-05T09:57:57+02:00") == datetime(2026, 10, 5, 7, 57, 57)
    assert j.horodatage_utc("2026-10-05T07:57:57Z") == datetime(2026, 10, 5, 7, 57, 57)
    assert j.horodatage_utc("2026-10-05T07:57:57") == datetime(2026, 10, 5, 7, 57, 57)


def test_l_horodatage_est_comparable_a_une_date_naive():
    from datetime import datetime, timedelta
    assert j.horodatage_utc("2026-10-05T09:57:57+02:00") > datetime(2026, 10, 5, 7, 0, 0) - timedelta(hours=1)
