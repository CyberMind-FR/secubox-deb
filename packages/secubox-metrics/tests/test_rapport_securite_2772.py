# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2772 — rapport de sécurité : tuiles Actor (actord /stats lent), visites et bannissements (WAF + nft).

CONSTAT (PDF du 2026-10-16) : les quatre tuiles Actor affichaient « - » (actord met 5 s à répondre à /stats, le rapport n'attendait que 4 s) ; et le rapport
ne disait rien des visites ni des bannissements, alors que le WAF journalise les uns et les autres."""
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
pytest.importorskip("fpdf")
pytest.importorskip("matplotlib")
import rapport_securite as RS  # noqa: E402
from test_rapport_securite_2299 import donnees  # noqa: E402


# ---------- actord lent ----------

def faux_actord(chemin: str, delai_s: float, corps: dict):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(chemin)
    srv.listen(4)

    def servir():
        for _ in range(3):
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.recv(4096)
            time.sleep(delai_s)
            b = json.dumps(corps).encode()
            try:
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(b) + b)
            except OSError:
                pass
            c.close()
    threading.Thread(target=servir, daemon=True).start()
    return srv


def test_un_actord_lent_est_lu_avec_un_delai_suffisant(tmp_path):
    sock = str(tmp_path / "a.sock")
    srv = faux_actord(sock, 0.6, {"events_24h": 5})
    try:
        assert RS.lire_actord("/api/v1/actor/stats", sock, delai=0.2) is None, "trop court : None, sans lever"
        assert RS.lire_actord("/api/v1/actor/stats", sock, delai=3.0) == {"events_24h": 5}
    finally:
        srv.close()


def test_la_collecte_laisse_30_s_a_stats_mais_pas_aux_lectures_rapides(monkeypatch):
    appels = {}

    def faux(chemin, sock=RS.ACTOR_SOCK, delai=4.0):
        appels[chemin] = delai
        return {}
    monkeypatch.setattr(RS, "lire_actord", faux)
    monkeypatch.setattr(RS, "lire_visites", lambda *a, **k: None)
    monkeypatch.setattr(RS, "lire_bans", lambda *a, **k: None)
    monkeypatch.setattr(RS, "lire_nft_etat", lambda *a, **k: None)
    RS.collecter()
    assert appels["/api/v1/actor/stats"] >= 20, "actord /stats met 5 s sur gk2"
    assert appels["/api/v1/actor/overview"] <= 10


# ---------- visites (WAF) ----------

VISITES = {"total": 1000, "by_vhost": {"a.test": 600, "b.test": 300, "c.test": 100}, "by_client_type": {"browser": 700, "mobile-app": 50, "bot": 100, "crawler": 50, "other": 100},
           "by_os": {"Linux": 500, "Windows": 300, "other": 200}, "by_status": {"2xx": 800, "3xx": 20, "4xx": 100, "5xx": 80}, "top_ips": {"203.0.113.9": 40}}


def test_les_visites_du_waf_sont_lues_avec_leur_age(tmp_path):
    f = tmp_path / "visits.json"
    f.write_text(json.dumps(VISITES))
    os.utime(f, (time.time() - 120, time.time() - 120))
    v = RS.lire_visites(f)
    assert v["total"] == 1000 and v["by_vhost"]["a.test"] == 600 and 100 <= v["age_s"] <= 140


def test_visites_absentes_ou_corrompues_rendent_none(tmp_path):
    assert RS.lire_visites(tmp_path / "rien.json") is None
    f = tmp_path / "x.json"
    f.write_text("pas du json")
    assert RS.lire_visites(f) is None
    f.write_text("[1, 2]")
    assert RS.lire_visites(f) is None


def test_les_adresses_des_visiteurs_ne_sortent_pas_du_rapport(tmp_path):
    f = tmp_path / "v.json"
    f.write_text(json.dumps(VISITES))
    assert "top_ips" not in RS.lire_visites(f), "le PDF part par courriel : jamais d'adresse de visiteur"


# ---------- bannissements (journal du WAF) ----------

def ecrit(f, lignes):
    f.write_text("".join((l if isinstance(l, str) else json.dumps(l)) + "\n" for l in lignes))


def test_les_bans_sont_resumes_sur_24_h(tmp_path):
    now = 1_800_000_000.0
    f = tmp_path / "bans.jsonl"
    ecrit(f, [
        {"ip": "198.51.100.1", "cat": "scanners", "sev": "medium", "at": now - 3600, "exp": now + 3600, "action": "ban"},
        {"ip": "198.51.100.2", "cat": "lfi", "sev": "high", "at": now - 7200, "exp": now + 100, "action": "ban"},
        {"ip": "198.51.100.3", "cat": "lfi", "sev": "high", "at": now - 90000, "exp": now - 80000, "action": "ban"},        # plus de 24 h, expiré
        {"ip": "198.51.100.1", "cat": "scanners|prolonge", "sev": "medium", "at": now - 600, "exp": now + 7200, "action": "ban"},
        {"ip": "198.51.100.2", "cat": "", "sev": "", "at": now - 300, "exp": 0, "action": "unban"},
    ])
    b = RS.lire_bans(f, now)
    assert b["bans_24h"] == 2 and b["prolongations_24h"] == 1 and b["unbans_24h"] == 1
    assert b["actifs"] == 1, "un ban expiré, un autre levé : reste 198.51.100.1"
    assert b["ips_24h"] == 2
    assert dict(b["par_categorie"]) == {"scanners": 1, "lfi": 1}
    assert b["par_severite"] == {"medium": 1, "high": 1}


def test_les_bans_par_heure_sont_indexes_par_heure_du_jour(tmp_path):
    now = time.mktime(datetime(2026, 10, 16, 12, 0, 0).timetuple())
    f = tmp_path / "bans.jsonl"
    ecrit(f, [{"ip": f"198.51.100.{i}", "cat": "x", "sev": "medium", "at": now - 3600 * 2 + i, "exp": now + 1000, "action": "ban"} for i in range(5)])      # 10 h
    b = RS.lire_bans(f, now)
    assert len(b["par_heure"]) == 24 and b["par_heure"][10] == 5 and sum(b["par_heure"]) == 5


def test_les_categories_de_mesure_sont_regroupees(tmp_path):
    now = 1_800_000_000.0
    f = tmp_path / "bans.jsonl"
    ecrit(f, [{"ip": f"198.51.100.{i}", "cat": f"mesure:ACT-{i:04d}", "sev": "medium", "at": now - 100, "exp": now + 100, "action": "ban"} for i in range(4)])
    assert dict(RS.lire_bans(f, now)["par_categorie"]) == {"mesure d'acteur": 4}


def test_une_ligne_corrompue_ou_incomplete_est_ignoree(tmp_path):
    now = 1_800_000_000.0
    f = tmp_path / "bans.jsonl"
    ecrit(f, ["n'importe quoi", {"ip": "198.51.100.1"}, {"cat": "x"}, {"ip": "198.51.100.2", "cat": "lfi", "sev": "high", "at": now - 10, "exp": now + 10, "action": "ban"}, "{"])
    assert RS.lire_bans(f, now)["bans_24h"] == 1


def test_journal_absent_rend_none(tmp_path):
    assert RS.lire_bans(tmp_path / "rien.jsonl") is None


def test_un_journal_enorme_n_est_lu_que_par_la_fin(tmp_path):
    now = 1_800_000_000.0
    f = tmp_path / "bans.jsonl"
    ligne = json.dumps({"ip": "198.51.100.1", "cat": "x", "sev": "medium", "at": now - 10, "exp": now + 10, "action": "ban"}) + "\n"
    f.write_text("a" * 5000 + "\n" + ligne * 20)
    b = RS.lire_bans(f, now, lecture_max=len(ligne) * 5)
    assert 1 <= b["bans_24h"] <= 6, "borné : seule la fin du fichier est lue"


# ---------- nft ----------

def test_l_etat_nft_est_lu_avec_son_age(tmp_path):
    now = 1_800_000_000.0
    f = tmp_path / "nft.json"
    f.write_text(json.dumps({"actif": True, "table": "inet secubox", "verifie": now - 45, "reparations": 2, "dernier_ban": now - 600}))
    e = RS.lire_nft_etat(f, now)
    assert e["actif"] is True and e["table"] == "inet secubox" and e["reparations"] == 2 and e["verifie_il_y_a_s"] == 45 and e["dernier_ban_il_y_a_s"] == 600


def test_etat_nft_absent_ou_invalide_rend_none(tmp_path):
    assert RS.lire_nft_etat(tmp_path / "rien.json") is None
    f = tmp_path / "x.json"
    f.write_text("[]")
    assert RS.lire_nft_etat(f) is None


# ---------- le PDF ----------

def donnees_completes():
    return donnees()


def sans_nouvelles():
    d = donnees()
    for k in ("visites", "bans", "nft"):
        d["waf"].pop(k)
    return d


def titres_de(monkeypatch, d):
    vus = []
    orig = RS._titre_volet
    monkeypatch.setattr(RS, "_titre_volet", lambda pdf, y, t, s: (vus.append(t), orig(pdf, y, t, s))[1])
    RS.construire_pdf_securite(d)
    return vus


def test_le_pdf_a_un_volet_visites_et_bannissements(monkeypatch):
    titres = titres_de(monkeypatch, donnees_completes())
    assert any("visites" in t.lower() and "bannissements" in t.lower() for t in titres), titres


def test_le_pdf_se_produit_avec_et_sans_ces_sources():
    assert RS.construire_pdf_securite(donnees_completes())[:5] == b"%PDF-"
    assert RS.construire_pdf_securite(sans_nouvelles())[:5] == b"%PDF-"                      # sans visites, bans, nft : tirets, pas d'erreur
    d = donnees_completes()
    d["waf"]["bans"] = {"bans_24h": 0, "prolongations_24h": 0, "unbans_24h": 0, "ips_24h": 0, "actifs": 0, "par_heure": [0] * 24, "par_categorie": [], "par_severite": {}, "age_s": 5}
    d["waf"]["visites"] = {"total": 0, "by_vhost": {}, "by_client_type": {}, "by_os": {}, "by_status": {}, "age_s": 5}
    assert RS.construire_pdf_securite(d)[:5] == b"%PDF-", "des vrais zéros se dessinent aussi"


def test_le_pdf_compte_une_page_de_plus():
    pdf = RS.construire_pdf_securite(donnees_completes())
    assert pdf.count(b"/Type /Page\n") + pdf.count(b"/Type /Page ") >= 5


def test_les_sources_nouvelles_absentes_sont_listees():
    m = RS.indisponibles(sans_nouvelles())
    assert any("visites" in x.lower() for x in m) and any("bannissements" in x.lower() for x in m) and any("nft" in x.lower() for x in m)
    assert not [x for x in RS.indisponibles(donnees_completes()) if "visites" in x.lower() or "bannissements" in x.lower() or "nft" in x.lower()]


def test_une_source_perimee_est_annoncee():
    d = donnees_completes()
    d["waf"]["visites"]["age_s"] = 4 * 3600
    d["waf"]["nft"]["verifie_il_y_a_s"] = 2 * 3600
    m = " ".join(RS.indisponibles(d)).lower()
    assert "visites" in m and "nft" in m and "périm" in m


def test_rien_n_est_envoye_quand_aucune_des_onze_sources_ne_repond():
    d = donnees(waf={}, actor={}, dpi=None)
    assert len(RS.indisponibles(d)) == 11
    envoye = []
    r = RS.executer_securite(lambda: d, RS.construire_pdf_securite, lambda *a, **k: envoye.append(a) or {"envoye": True}, {"destinataire": "x@example.org"})
    assert r["envoye"] is False and not envoye
