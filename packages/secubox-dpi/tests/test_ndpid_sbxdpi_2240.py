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


def test_une_lecture_qui_echoue_ne_leve_rien():
    def casse(chemin):
        raise OSError("socket")
    p = SbxdpiBridge(lire=casse)
    assert not p.available() and p.top_protocols(5) == [] and p.risks(5) == [] and p.flows(5) == [] and p.fingerprints("ja4", 5) == []


def test_main_prefere_sbxdpi_puis_retombe_sur_ndpireader():
    src = (Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "api" / "main.py").read_text()
    ast.parse(src)
    assert "sbxdpi_bridge" in src and "sbx_bridge.available()" in src and "dpi_bridge.available()" in src
