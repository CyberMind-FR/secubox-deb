# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Test dynamique du WAF : témoin non bloqué, canaris bloqués, cache de 5 min."""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "waf_selftest", Path(__file__).parent.parent / "api" / "waf_selftest.py")
ws = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ws)


def waf_sain(host, chemin):
    return 200 if chemin == "/robots.txt" else 403


def test_choisir_host_public_et_inspecte():
    r = {"10.55.0.1": [], "admin.gk2.secubox.in": [], "git.gk2.secubox.in": [],
         "z.gk2.secubox.in": [], "hall.gk2.secubox.in": []}
    assert ws.choisir_host(r) == "hall.gk2.secubox.in"
    assert ws.choisir_host({"b.x": [], "a.x": [], "admin.x": []}) == "a.x"
    assert ws.choisir_host({"10.55.0.1": [], "admin.x": [], "git.x": []}) is None


def test_waf_sain_passe():
    r = ws.executer("h.x", waf_sain)
    assert r["ok"] and len(r["tests"]) == 5
    assert [t["id"] for t in r["tests"]] == ["temoin", "xss", "sqli", "lfi", "rce"]


def test_canari_non_bloque_echoue():
    r = ws.executer("h.x", lambda h, c: 200)          # WAF qui ne bloque rien
    assert not r["ok"]
    assert [t["id"] for t in r["tests"] if not t["ok"]] == ["xss", "sqli", "lfi", "rce"]


def test_faux_positif_echoue():
    r = ws.executer("h.x", lambda h, c: 403)          # WAF qui bloque tout, témoin compris
    assert not r["ok"]
    assert [t["id"] for t in r["tests"] if not t["ok"]] == ["temoin"]


def test_erreur_reseau_ne_leve_pas():
    def casse(h, c):
        raise OSError("refusé")
    r = ws.executer("h.x", casse)
    assert not r["ok"] and all(t["code"] is None for t in r["tests"])


def test_verifier_cache_cinq_minutes(tmp_path, monkeypatch):
    routes = tmp_path / "routes.json"
    routes.write_text('{"hall.x.in": ["127.0.0.1", 1]}')
    monkeypatch.setattr(ws, "ROUTES", routes)
    appels = []

    def req(h, c):
        appels.append(c)
        return waf_sain(h, c)

    cache = tmp_path / "c.json"
    ok, d = ws.verifier(1000.0, req, lambda: True, cache)
    assert ok and not d["en_cache"] and len(appels) == 5
    ok, d = ws.verifier(1100.0, req, lambda: True, cache)       # 100 s plus tard : cache
    assert ok and d["en_cache"] and d["age_s"] == 100 and len(appels) == 5
    ok, d = ws.verifier(1400.0, req, lambda: True, cache)       # > 300 s : on rejoue
    assert not d["en_cache"] and len(appels) == 10


def test_waf_arrete(tmp_path):
    ok, d = ws.verifier(5.0, waf_sain, lambda: False, tmp_path / "c.json")
    assert not ok and d["ecoute"] is False and d["tests"] == []


# ---------- #2784 : un témoin qui expire sous charge n'est pas un WAF défaillant ----------

def amont_lent(host, chemin):
    if chemin == "/robots.txt":
        raise TimeoutError("timed out")             # l'amont (nginx, service) ne répond pas dans le délai
    return 403                                      # le WAF, lui, refuse les canaris aussitôt


def test_un_temoin_qui_expire_alors_que_les_canaris_sont_bloques_est_un_waf_sain():
    r = ws.executer("h.x", amont_lent)
    assert r["ok"] is True, "le WAF bloque : c'est l'amont qui est lent"
    t = next(x for x in r["tests"] if x["id"] == "temoin")
    assert t["ok"] is True and t["indetermine"] is True and t["code"] is None
    assert "lent" in r["avertissement"].lower()


def test_un_temoin_qui_expire_ne_masque_pas_un_canari_non_bloque():
    def casse(host, chemin):
        if chemin == "/robots.txt":
            raise TimeoutError("timed out")
        return 200                                  # le WAF ne bloque plus rien
    r = ws.executer("h.x", casse)
    assert r["ok"] is False and "avertissement" not in r


def test_un_canari_qui_expire_est_un_echec():
    def un_canari_muet(host, chemin):
        if "script" in chemin:
            raise TimeoutError("timed out")
        return 200 if chemin == "/robots.txt" else 403
    r = ws.executer("h.x", un_canari_muet)
    assert r["ok"] is False
    assert [t["id"] for t in r["tests"] if not t["ok"]] == ["xss"]


def test_un_temoin_bloque_reste_un_faux_positif_meme_si_les_canaris_passent():
    r = ws.executer("h.x", lambda h, c: 403)
    assert r["ok"] is False and not next(x for x in r["tests"] if x["id"] == "temoin")["ok"]


def test_un_temoin_en_refus_de_connexion_n_est_pas_un_delai():
    def refus(host, chemin):
        if chemin == "/robots.txt":
            raise ConnectionRefusedError("refused")
        return 403
    r = ws.executer("h.x", refus)
    t = next(x for x in r["tests"] if x["id"] == "temoin")
    assert t["ok"] is False and not t.get("indetermine"), "un refus de connexion est un vrai échec"


def test_le_delai_du_temoin_laisse_a_l_amont_le_temps_de_repondre():
    import inspect
    assert inspect.signature(ws._requete).parameters["timeout"].default >= 10
    assert ws.DELAI_TEMOIN_S >= 10


def test_le_verdict_en_cache_garde_l_avertissement(tmp_path, monkeypatch):
    routes = tmp_path / "routes.json"
    routes.write_text('{"hall.x": []}')
    monkeypatch.setattr(ws, "ROUTES", routes)
    c = tmp_path / "c.json"
    ok, res = ws.verifier(maintenant=1000.0, requete=amont_lent, ecoute=lambda: True, cache=c)
    assert ok is True
    ok2, res2 = ws.verifier(maintenant=1010.0, requete=lambda h, p: 500, ecoute=lambda: True, cache=c)
    assert ok2 is True and res2["en_cache"] is True and "lent" in res2.get("avertissement", "").lower()
