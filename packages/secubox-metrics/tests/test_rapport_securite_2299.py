# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2299 : le rapport quotidien de sécurité (WAF, Actor Intelligence, DPI) ne dit que le vrai : une source muette est « — » et listée, jamais zéro ; le PDF se produit ; l'envoi garde ses règles."""
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
pytest.importorskip("fpdf")
pytest.importorskip("matplotlib")
import rapport_securite as RS  # noqa: E402

RADAR = {"acteurs": [{"id": "A", "niveau": "BLOCK", "risque": {"valeur": 97}, "confiance": {"valeur": 90}}, {"id": "B", "niveau": "OBSERVE", "risque": {"valeur": 50}, "confiance": {"valeur": 60}},
                     {"id": "C", "niveau": "OBSERVE", "risque": {"valeur": 10}, "confiance": {"valeur": 20}}]}


def donnees(**sur):
    d = {"genere": datetime(2026, 10, 11, 5, 39),
         "waf": {"hist": {"jours": {"2026-10-09": {"total": 10, "severites": {"high": 1}}, "2026-10-10": {"total": 20, "severites": {"high": 2, "medium": 3}}}, "top_ips": {"local": 9, "1.2.3.4": 5}},
                 "compteurs": {"par_origine": {"waf": 1000}, "blocked_24h": 7, "by_severity": {"critical": 1, "high": 2, "medium": 3, "info": 900}, "by_category": {"robots": 900, "lfi": 6},
                               "top_vhosts": [{"vhost": "x.test", "count": 4}], "pays": {"US": 3}},
                 "campagnes": {"campagnes": [{"signature": "abcdef0123456789", "outil": "scanner", "sondes": 12}]}},
         "actor": {"stats": {"actors": 5, "campaigns": 2, "events_24h": 100, "attempts_24h": 90, "blocked_24h": 10, "posture": "Protégée", "mode": "observe"},
                   "overview": {"activite_24h": [0] * 22 + [4, 6], "top_pays": [{"code": "US", "n": 3}], "techniques": {"A": [{"nom": "recon-001", "n": 3}]}, "robots": [{"famille": "meta", "hits": 8}]},
                   "radar": RADAR, "mesures": {"par_niveau": {"TARPIT": 2}}, "mode": {"mode": "ACTIVE", "detail": {"campagnes": "ACTIVE", "acteurs": "ACTIVE"}}},
         "dpi": {"genere_le": time.time(), "age_s": 1, "perime": False, "stats": {"flux": 10, "octets": 2048, "protocoles": [{"nom": "TLS", "pct": 90}]}, "usages": [{"nom": "ai", "octets": 5}],
                 "pays": [{"cc": "FR", "octets": 9}], "appareils_total": 1, "appareils": [{"nom": "a", "octets": 9, "destinations": [{"hote": "h", "octets": 1}]}], "suggestions": []}}
    d.update(sur)
    return d


def test_le_pdf_se_produit_sur_4_pages_a_partir_de_donnees_completes():
    pdf = RS.construire_pdf_securite(donnees())
    assert pdf[:5] == b"%PDF-" and pdf.count(b"/Type /Page\n") + pdf.count(b"/Type /Page ") >= 4


def test_le_pdf_se_produit_meme_sans_aucune_source():
    d = donnees(waf={}, actor={}, dpi=None)
    assert RS.construire_pdf_securite(d)[:5] == b"%PDF-"


def test_une_mesure_absente_est_un_tiret_pas_un_zero():
    assert RS.n(None) == "—" and RS.octets(None) == "—" and RS.gravite_menaces(None) is None and RS.seuils_actors(None) is None
    assert RS.n(0) == "0"                                                                   # un vrai zéro mesuré reste un zéro


def test_les_menaces_excluent_les_robots_et_les_seuils_sont_ceux_du_hall():
    assert RS.gravite_menaces({"critical": 1, "high": 2, "medium": 3, "info": 9999}) == 6
    assert RS.seuils_actors(RADAR) == {"suivis": 3, "critiques": 1, "suspects": 1, "observes": 1}


def test_les_sources_absentes_sont_listees_telles_quelles():
    m = RS.indisponibles(donnees(actor={"stats": None, "overview": {}, "radar": {}, "mesures": {}, "mode": None}, dpi=None))
    assert "Actor Intelligence : compteurs" in m and "Actor Intelligence : mode d'application des décisions" in m and any(x.startswith("DPI : résumé") for x in m)
    assert RS.indisponibles(donnees()) == []


def test_un_resume_dpi_perime_est_annonce(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps({"genere_le": 1000}))
    r = RS.lire_dpi(f, now=1000 + 5 * 3600)
    assert r["perime"] is True and r["age_s"] == 5 * 3600
    assert "DPI : résumé périmé (5 h)" in RS.indisponibles(donnees(dpi=r))
    assert RS.lire_dpi(tmp_path / "absent.json") is None


def test_le_mode_global_suit_la_regle_du_waf(tmp_path):
    now = 10_000.0
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps({"genere_le": now - 10, "mode": "propose"}))
    b.write_text(json.dumps({"genere_le": now - 10, "mode": "auto"}))
    assert RS.mode_application((a, b), now)["mode"] == "ACTIVE"
    b.write_text(json.dumps({"genere_le": now - 3600, "mode": "auto"}))                   # état trop vieux : on n'en tire aucune décision
    assert RS.mode_application((a, b), now) == {"mode": "SIMULATION", "detail": {"campagnes": "SIMULATION", "acteurs": "PASSIVE_ONLY"}}
    assert RS.mode_application((tmp_path / "x", tmp_path / "y"), now) is None


def test_actord_muet_rend_none_et_ne_leve_pas(tmp_path):
    assert RS.lire_actord("/api/v1/actor/stats", sock=str(tmp_path / "absent.sock")) is None


def test_rien_n_est_envoye_sans_destinataire_ni_sans_aucune_source():
    appels = []
    r = RS.executer_securite(lambda: donnees(), RS.construire_pdf_securite, lambda *a, **k: appels.append(1), {"destinataire": ""})
    assert r["envoye"] is False and not appels
    vide = donnees(waf={}, actor={}, dpi=None)
    r = RS.executer_securite(lambda: vide, RS.construire_pdf_securite, lambda *a, **k: appels.append(1), {"destinataire": "x@y.z"})
    assert r == {"envoye": False, "raison": "aucune source n'a répondu"} and not appels


def test_l_envoi_porte_un_objet_et_un_nom_de_fichier_propres():
    vu = {}

    def faux(pdf, dest, portee, periode, **kw):
        vu.update(dest=dest, portee=portee, periode=periode, **kw)
        return {"envoye": True, "destinataire": dest, "octets": len(pdf)}
    r = RS.executer_securite(lambda: donnees(), RS.construire_pdf_securite, faux, {"destinataire": "a@b.c", "periode": "quotidien"})
    assert r["envoye"] and vu["objet"].startswith("SecuBox — rapport quotidien de sécurité") and vu["nom_fichier"] == "secubox-securite-{date}.pdf"


def test_le_format_waf_ancien_reste_choisissable():
    import rapport_waf as RW
    assert RW.DEFAUTS["format"] == "securite"
    src = (Path(__file__).resolve().parents[1] / "api" / "rapport_waf.py").read_text(encoding="utf-8")
    assert 'cfg.get("format", "securite") == "securite"' in src and "construire_pdf_waf" in src


def test_envoyer_accepte_objet_nom_et_intro_sans_changer_les_anciens_appels(monkeypatch):
    import rapport as R
    envoyes = []

    class SMTP:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def send_message(self, m): envoyes.append(m)
    monkeypatch.setattr(R.smtplib, "SMTP", SMTP)
    monkeypatch.setattr(R, "config", lambda: {"smtp_hote": "h", "smtp_port": 25, "expediteur": "e@x", "destinataire": "d@x"})
    R.envoyer(b"%PDF", "d@x", "Menaces WAF", "quotidien")
    R.envoyer(b"%PDF", "d@x", "S", "quotidien", objet="OBJ", nom_fichier="s-{date}.pdf", intro="INTRO")
    ancien, nouveau = envoyes
    assert ancien["Subject"] == "SecuBox — frequentation Menaces WAF (quotidien)"
    assert nouveau["Subject"] == "OBJ" and "INTRO" in nouveau.get_body().get_content()
    assert next(nouveau.iter_attachments()).get_filename().startswith("s-")


def test_les_formes_du_cache_disque_du_waf_sont_lues_comme_celles_de_l_api():
    cache = {"total_threats": 14703, "top_vhosts": {"b.test": 5, "a.test": 9}, "top_countries": {"US": 3, "FR": 1}, "by_severity": {"high": 1}}
    api = {"blocked_24h": 7, "top_vhosts": [{"vhost": "c.test", "count": 2}, {"vhost": "d.test", "count": 6}], "pays": {"DE": 4}}
    assert RS.vhosts(cache) == [("a.test", 9), ("b.test", 5)] and RS.vhosts(api)[0] == ("d.test", 6) and RS.vhosts({}) == []
    assert RS.pays_waf(cache) == {"US": 3, "FR": 1} and RS.pays_waf(api) == {"DE": 4} and RS.pays_waf({"top_countries": [{"country": "US", "count": 2}]}) == {"US": 2}
    assert RS.total_menaces(cache) == 14703 and RS.total_menaces(api) == 7 and RS.total_menaces({}) is None


def test_le_pdf_se_produit_avec_les_formes_du_cache_disque():
    w = donnees()["waf"]
    w["compteurs"] = {"total_threats": 14703, "par_origine": {"waf": 5}, "top_vhosts": {"x.test": 4}, "top_countries": {"US": 3}, "by_severity": {"high": 1}, "by_category": {"robots": 9, "lfi": 2}}
    assert RS.construire_pdf_securite(donnees(waf=w))[:5] == b"%PDF-"
