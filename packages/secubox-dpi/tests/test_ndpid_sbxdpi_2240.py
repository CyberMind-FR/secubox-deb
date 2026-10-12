# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La page /ndpid/ lit la surface vivante de sbxdpi (nDPId → nDPIsrvd → sbxdpi) : protocoles, applications, risques, empreintes JA4, sessions."""
import ast
import sys
from pathlib import Path

import importlib.util

# Chargé par chemin : `api/__init__` du module tire main.py (zmq, FastAPI…), inutiles pour tester le pont.
_spec = importlib.util.spec_from_file_location("sbxdpi_bridge", Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "api" / "sbxdpi_bridge.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
SbxdpiBridge = _mod.SbxdpiBridge

STATS = {"updated_at": 1_800_000_000, "connected": True, "total_flows": 1000, "total_bytes": 5000,
         "protocols": [{"name": "TLS", "flows": 700, "bytes": 4000}, {"name": "DNS", "flows": 300, "bytes": 100}],
         "apps": [{"name": "TLS.YouTube", "flows": 10, "bytes": 3000}],
         "fingerprints": [{"name": "t13d1516h2_8daaf6152771_b186095e22b6", "flows": 42, "bytes": 1}],
         "risks": [{"name": "Probing Attempt", "count": 7, "severity": "Medium"}, {"name": "Malicious Fingerprint", "count": 3, "severity": "High"},
                   {"name": "Error Code", "count": 999, "severity": "Low"}]}
SESSIONS = [{"device": "192.168.1.60", "usage": "video", "application": "YouTube", "infra": "Google", "flows": 12, "bytes": 5000, "hosts": ["youtube.com"]},
            {"device": "192.168.1.61", "usage": "cloud", "infra": "AWS", "flows": 3, "bytes": 100, "hosts": []}]


def pont(stats=STATS, sessions=SESSIONS):
    cles = {"stats": stats, "sessions": sessions}
    return SbxdpiBridge(lire=lambda chemin: cles.get(chemin))


def test_disponible_seulement_si_sbxdpi_est_connecte_et_a_vu_des_flux():
    assert pont().available()
    assert not pont(stats={**STATS, "connected": False}).available()
    assert not pont(stats={**STATS, "total_flows": 0}).available()
    assert not pont(stats=None).available()                       # socket absent ou illisible


def test_statut_decrit_nDPId_et_compte_empreintes_et_risques():
    s = pont().status()
    assert s["daemon"]["running"] is True and s["daemon"]["source"] == "nDPId → sbxdpi" and s["daemon"]["socket_available"] is True
    d = s["database"]
    assert d["total_flows"] == 1000 and d["total_fingerprints"] == 1 and d["source"] == "nDPId → sbxdpi"
    assert d["risks_24h"] == 10 and d["total_risk_events"] == 10   # Low (bruit) exclus : Medium 7 + High 3


def test_protocoles_et_applications_au_format_de_la_page():
    assert pont().top_protocols(10) == [{"protocol": "TLS", "flow_count": 700, "bytes_total": 4000}, {"protocol": "DNS", "flow_count": 300, "bytes_total": 100}]
    assert pont().top_applications(10) == [{"application": "TLS.YouTube", "flow_count": 10, "bytes_total": 3000}]
    assert len(pont().top_protocols(1)) == 1


def test_risques_empreintes_et_flux_au_format_de_la_page():
    r = pont().risks(10)
    assert [x["risk_type"] for x in r] == ["Malicious Fingerprint", "Probing Attempt"]          # gravité décroissante, le bruit « Low » n'est pas listé
    assert r[0]["risk_score"] >= 70 and "3 flux" in r[0]["description"] and r[0]["src_ip"] == "—"
    f = pont().fingerprints("ja4", 10)
    assert f[0]["fingerprint"].startswith("t13d1516h2") and f[0]["hit_count"] == 42 and "last_seen" in f[0]
    assert pont().fingerprints("ja3", 10) == []                                                  # nDPId n'émet que du JA4
    fl = pont().flows(10)
    assert fl[0]["src_ip"] == "192.168.1.60" and fl[0]["dst_ip"] == "youtube.com" and fl[0]["application"] == "YouTube" and fl[0]["bytes_sent"] == 5000
    assert fl[1]["dst_ip"] == "" and fl[1]["application"] == "AWS"


def test_le_bruit_de_gravite_moyenne_ne_noie_pas_les_vrais_risques():
    bruyant = {**STATS, "risks": STATS["risks"] + [{"name": "Known Proto on Non Std Port", "count": 12_000_000, "severity": "Medium"},
                                                   {"name": "TCP Connection Issues", "count": 99_000, "severity": "Medium"}]}
    p = pont(stats=bruyant)
    assert p.status()["database"]["risks_24h"] == 10                       # inchangé : Probing 7 + Malicious 3
    assert all(r["risk_type"] not in ("Known Proto on Non Std Port", "TCP Connection Issues") for r in p.risks(10))


def test_une_lecture_qui_echoue_ne_leve_rien():
    def casse(chemin):
        raise OSError("socket")
    p = SbxdpiBridge(lire=casse)
    assert not p.available() and p.top_protocols(5) == [] and p.risks(5) == [] and p.flows(5) == [] and p.fingerprints("ja4", 5) == []


def test_main_prefere_sbxdpi_puis_retombe_sur_ndpireader():
    src = (Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "api" / "main.py").read_text()
    ast.parse(src)
    assert "sbxdpi_bridge" in src and "sbx_bridge.available()" in src and "dpi_bridge.available()" in src


def test_empreintes_ja3_calculees_par_sbxdpi_et_liste_mixte():
    # #2405 : sbxdpi lit le ClientHello lui-même (la libndpi 4.2 n'émet ni ja3 ni ja4).
    st = {**STATS, "fingerprints_ja3": [{"name": "11138d9933242c3a03b6aad35a296476", "flows": 90, "bytes": 0}]}
    j3 = pont(stats=st).fingerprints("ja3", 10)
    assert len(j3) == 1 and j3[0]["fingerprint"] == "11138d9933242c3a03b6aad35a296476" and j3[0]["fp_type"] == "ja3" and j3[0]["hit_count"] == 90
    assert "profil" not in j3[0]                                  # un JA3 est un hash : rien à décoder
    tous = pont(stats=st).fingerprints("", 10)                    # la page Empreintes demande sans type
    assert [(f["fp_type"], f["hit_count"]) for f in tous] == [("ja3", 90), ("ja4", 42)]   # tri par fréquence
    assert len(pont(stats=st).fingerprints("", 1)) == 1
    assert pont(stats=st).status()["database"]["total_fingerprints"] == 2


def test_empreintes_dates_reelles_sni_et_profil_deduit():
    # #2408 : première/dernière vue et SNI viennent de sbxdpi ; le profil est déduit de la forme du JA4.
    ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"
    st = {**STATS, "fingerprint_meta": {ja4: {"first": 1_799_000_000, "last": 1_799_900_000,
                                              "sni": [{"name": "www.exemple.test", "flows": 30}, {"name": "cdn.exemple.test", "flows": 4}]}}}
    f = pont(stats=st).fingerprints("ja4", 10)[0]
    assert f["first_seen"].startswith("2027-01-") or f["first_seen"].startswith("2026-")      # date de sbxdpi, pas l'heure du relevé
    assert f["first_seen"] < f["last_seen"]
    assert f["snis"] == [{"name": "www.exemple.test", "n": 30}, {"name": "cdn.exemple.test", "n": 4}]
    assert f["profil"] == "TLS 1.3 · avec SNI · 15 suites · 16 extensions · ALPN h2" and f["famille_deduite"] == "nav"
    # sans méta : dates de repli, pas de SNI, rien d'inventé
    g = pont().fingerprints("ja4", 10)[0]
    assert g["snis"] == [] and g["first_seen"] == g["last_seen"]


def test_profil_ja4_forme_seulement():
    prof = _mod.profil_ja4
    assert prof("t13d131100_f57a46bbacb6_ab7e3b40a677")["famille_deduite"] == "lib"    # sans ALPN : outil ou bibliothèque
    assert prof("t13i0306h2_5559582ccdc4_fb71836bce29")["famille_deduite"] == "aut"    # sans SNI : indéterminé
    assert prof("pas un ja4") == {} and prof("") == {}
