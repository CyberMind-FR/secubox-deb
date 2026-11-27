# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Couches de menace nourries par nDPId (#4010) : agrégation par source, UA ↔ JA4, double tampon, aucune adresse rendue."""
import importlib.util
import json
import sys
import time
from pathlib import Path

API = Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "api"
sys.path.insert(0, str(API))
_spec = importlib.util.spec_from_file_location("couches_menaces", API / "couches_menaces.py")
cm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cm)

JA4_LIB = "t13d0410h1_aaaaaaaaaaaa_bbbbbbbbbbbb"
JA4_NAV = "t13d1516h2_8daaf6152771_b186095e22b6"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

RELEVE = {"version": 1, "genere": 1_800_000_000, "complet": True, "fenetre_s": 86400, "sources": {
    "203.0.113.7": {"flux": 40, "octets": 900, "services": {"SSH/22": 30, "Telnet/23": 5, "TLS/443": 5},
                    "risques": {"Possible Exploit Attempt": 2, "Error Code": 9}, "ja4": {JA4_LIB: 5}},
    "198.51.100.4": {"flux": 3, "octets": 100, "services": {"TLS/443": 3}, "risques": {}, "ja4": {JA4_NAV: 3}},
    "198.51.100.9": {"flux": 2, "octets": 10, "services": {"TLS/443": 2}, "risques": {}, "ja4": {JA4_LIB: 2}},
}}


def _waf(tmp_path, lignes):
    p = tmp_path / "waf-threats.log"
    p.write_text("".join(json.dumps(x) + "\n" for x in lignes))
    return cm.LecteurWaf(p)


def test_familles_et_table_de_correspondance():
    assert cm.famille_ua(CHROME) == "navigateur"
    assert cm.famille_ua("python-requests/2.31") == "outil"
    assert cm.famille_ua("Googlebot/2.1") == "robot"
    assert cm.famille_ua("") == "absent"
    assert cm.verdict_agent("navigateur", "lib") == "outil_probable"
    assert cm.verdict_agent("navigateur", "nav") == "coherent"
    assert cm.verdict_agent("outil", "nav") == "outil_declare"
    assert cm.verdict_agent("absent", "lib") == "client_bibliotheque"
    assert cm.verdict_agent("autre", "") == "indetermine"


def test_agregation_par_source_et_rapprochement_ua(tmp_path):
    w = _waf(tmp_path, [{"client_ip": "203.0.113.7", "user_agent": CHROME}, {"client_ip": "198.51.100.4", "user_agent": CHROME}])
    d = cm.calculer(RELEVE, w.lire())
    s = d["sources"]["203.0.113.7"]
    assert s["hors_waf"] == ["SSH/22", "Telnet/23"]
    assert s["risques_notables"] == ["Possible Exploit Attempt"]       # « Error Code » est du bruit
    assert s["ja4_famille"] == "lib" and s["agent"] == "outil_probable"
    assert d["sources"]["198.51.100.4"]["agent"] == "coherent"
    assert d["sources"]["198.51.100.9"]["agent"] == "client_bibliotheque"   # jamais vu par le WAF


def test_lecture_incrementale_et_rotation(tmp_path):
    w = _waf(tmp_path, [{"client_ip": "203.0.113.1", "user_agent": "curl/8"}])
    assert w.lire()["203.0.113.1"]["ua"] == "curl/8"
    with open(w.chemin, "a") as f:
        f.write(json.dumps({"client_ip": "203.0.113.2", "user_agent": CHROME}) + "\n")
        f.write('{"client_ip": "203.0.113.3"')                           # ligne incomplète : relue au passage suivant
    ua = w.lire()
    assert "203.0.113.2" in ua and "203.0.113.3" not in ua
    w.chemin.unlink()
    w.chemin.write_text(json.dumps({"client_ip": "203.0.113.4", "user_agent": "x"}) + "\n")
    assert "203.0.113.4" in w.lire()


def test_double_tampon(tmp_path):
    cache = tmp_path / "c.json"
    assert cm.ecrire_double_tampon(cache, {"complet": True, "genere": 1000, "sources": {"203.0.113.7": {}}})
    assert not cm.ecrire_double_tampon(cache, {"complet": False, "genere": 1060, "sources": {}})
    assert json.loads(cache.read_text())["complet"] is True
    assert cm.ecrire_double_tampon(cache, {"complet": False, "genere": 1000 + 3 * 86400, "sources": {}})
    assert not (tmp_path / "c.json.tmp").exists()
    # relevé sbxdpi absent → passe dégradée, n'écrase pas
    assert cm.ecrire_double_tampon(cache, {"complet": True, "genere": int(time.time()), "sources": {"a": {}}})
    c = cm.CouchesMenaces(releve=tmp_path / "absent.json", cache=cache, waf=cm.LecteurWaf(tmp_path / "rien.log"))
    assert c.rafraichir()["sources"] == {"a": {}}


def test_aucune_adresse_rendue(tmp_path):
    w = _waf(tmp_path, [{"client_ip": "203.0.113.7", "user_agent": CHROME}])
    vue = cm.vue_publique(cm.calculer(RELEVE, w.lire()))
    texte = json.dumps(vue)
    for ip in RELEVE["sources"]:
        assert ip not in texte
    assert vue["sources_externes"] == 3 and vue["sources_hors_waf"] == 1
    assert vue["sources"][0]["agent"] == "outil_probable"
    assert vue["agents"] == {"outil_probable": 1, "indetermine": 1, "client_bibliotheque": 1}
    ssh = next(e for e in vue["services"] if e["service"] == "SSH/22")
    assert ssh["hors_waf"] and ssh["sources"] == 1
    assert vue["raisons"][0]["risque"] == "Possible Exploit Attempt"


def test_route_gardee():
    src = (API / "main.py").read_text()
    assert '@app.get("/couches-menaces", dependencies=[Depends(require_jwt)])' in src
    assert "asyncio.to_thread(couches.rafraichir)" in src


def test_section_page_risques():
    page = (API.parent / "www" / "ndpid" / "risques.html").read_text()
    assert "couches-menaces" in page and 'id="couches"' in page
