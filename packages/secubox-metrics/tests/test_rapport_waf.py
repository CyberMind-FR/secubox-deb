# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Rapport WAF dédié (#1063) : lit l'historique WAF → PDF → email quotidien.

L'orchestrateur reçoit ses collaborateurs par injection (pas de matplotlib ni
SMTP en test) : on vérifie qu'il lit l'historique, expédie au bon destinataire,
et NE fait rien s'il n'y a pas de données.
"""
import rapport_waf as rw


def test_executer_waf_lit_l_historique_et_expedie():
    envois = []

    def faux_lire():
        return {"jours": {"2026-08-19": {"total": 100,
                                         "categories": {"scanners": 80},
                                         "severites": {"medium": 80}}},
                "top_ips": {"1.2.3.4": 100}, "total": 100}

    def faux_pdf(hist, jours):
        return b"%PDF-waf"

    def faux_envoyer(pdf, dest, portee, periode):
        envois.append((pdf, dest, portee, periode))
        return {"envoye": True, "destinataire": dest, "octets": len(pdf)}

    cfg = {"destinataire": "gk2@secubox.in", "jours": 7, "periode": "quotidien"}
    res = rw.executer_waf(faux_lire, faux_pdf, faux_envoyer, cfg)

    assert envois == [(b"%PDF-waf", "gk2@secubox.in", "Menaces WAF", "quotidien")]
    assert res["envoye"] is True


def test_executer_waf_sans_historique_n_envoie_rien():
    envois = []
    res = rw.executer_waf(
        lambda: None,
        lambda h, j: b"",
        lambda *a: envois.append(a) or {"envoye": True},
        {"destinataire": "x@y.z", "jours": 7, "periode": "quotidien"})
    assert res.get("envoye") is False
    assert envois == []  # rien expédié


def test_config_waf_par_defaut_gk2(monkeypatch, tmp_path):
    monkeypatch.setattr(rw, "CONF", tmp_path / "absent.toml")
    c = rw.config_waf()
    assert c["destinataire"] == "gk2@secubox.in"
    assert c["jours"] == 7
