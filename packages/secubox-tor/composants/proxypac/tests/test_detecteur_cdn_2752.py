# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2752 — détecteur de CDN : candidates.json alimenté en silence depuis les requêtes DNS déjà journalisées (lecture seule)."""
import importlib
import json
import sqlite3
import subprocess
import time
from pathlib import Path

import pytest

from proxypac import detecteur

ROOT = Path(__file__).resolve().parents[1]
AUJ = time.strftime("%Y-%m-%d")


def magasin(tmp_path, lignes):
    """lignes : (jour, client, domaine, decision, hits) — le schéma et valeurs RÉELS de dnstv_counts (ad-guard : ALLOWED, BLOCKED, UPSTREAM_ERROR)."""
    p = tmp_path / "dnstv.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE dnstv_counts (jour TEXT NOT NULL, client TEXT NOT NULL, domaine TEXT NOT NULL, categorie TEXT NOT NULL DEFAULT '', "
              "decision TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (jour, client, domaine, decision))")
    for j, cl, d, dec, h in lignes:
        c.execute("INSERT INTO dnstv_counts(jour,client,domaine,decision,hits) VALUES (?,?,?,?,?)", (j, cl, d, dec, h))
    c.commit()
    c.close()
    return p


# ---------- catalogue ----------

@pytest.mark.parametrize("hote,famille", [
    ("ajax.googleapis.com", "google"), ("fonts.gstatic.com", "google"), ("www.gstatic.com", "google"),
    ("lh3.googleusercontent.com", "google"), ("cdnjs.cloudflare.com", "cloudflare"), ("cdn.jsdelivr.net", "jsdelivr"),
    ("unpkg.com", "unpkg"), ("d111111abcdef8.cloudfront.net", "cloudfront"), ("code.jquery.com", "jquery"),
])
def test_les_cdn_connus_sont_reconnus(hote, famille):
    assert detecteur.famille(hote) == famille


@pytest.mark.parametrize("hote", ["example.org", "googleapis.com.evil.test", "notgstatic.com", "monsite.fr", "", "localhost", "evil.test/gstatic.com"])
def test_un_hote_ordinaire_ou_trompeur_n_est_pas_un_cdn(hote):
    assert detecteur.famille(hote) is None


def test_la_casse_et_le_point_final_ne_trompent_pas():
    assert detecteur.famille("AJAX.GoogleAPIs.com.") == "google"


# ---------- détection ----------

def test_les_requetes_cdn_deviennent_des_candidats(tmp_path):
    db = magasin(tmp_path, [(AUJ, "192.168.1.10", "ajax.googleapis.com", "ALLOWED", 12), (AUJ, "192.168.1.11", "ajax.googleapis.com", "ALLOWED", 3),
                            (AUJ, "192.168.1.10", "example.org", "ALLOWED", 50)])
    c = detecteur.detecter(db, jours=3, regles=set(), rejetes=set())
    assert [x["host"] for x in c] == ["ajax.googleapis.com"]
    assert c[0]["hits"] == 15 and c[0]["clients"] == 2 and c[0]["famille"] == "google" and c[0]["source"] == "dns"


def test_les_plus_demandes_d_abord_et_borne(tmp_path):
    db = magasin(tmp_path, [(AUJ, "c", f"h{i}.googleapis.com", "ALLOWED", i + 1) for i in range(30)])
    c = detecteur.detecter(db, jours=3, regles=set(), rejetes=set(), limite=5)
    assert len(c) == 5 and c[0]["hits"] == 30


def test_les_requetes_bloquees_ne_comptent_pas(tmp_path):
    db = magasin(tmp_path, [(AUJ, "c", "ajax.googleapis.com", "BLOCKED", 9)])
    assert detecteur.detecter(db, jours=3, regles=set(), rejetes=set()) == []


def test_un_jour_trop_ancien_est_ignore(tmp_path):
    vieux = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 30 * 86400))
    db = magasin(tmp_path, [(vieux, "c", "ajax.googleapis.com", "ALLOWED", 9)])
    assert detecteur.detecter(db, jours=3, regles=set(), rejetes=set()) == []


def test_un_hote_deja_regle_ou_rejete_n_est_plus_propose(tmp_path):
    db = magasin(tmp_path, [(AUJ, "c", "ajax.googleapis.com", "ALLOWED", 9), (AUJ, "c", "unpkg.com", "ALLOWED", 9), (AUJ, "c", "code.jquery.com", "ALLOWED", 9)])
    c = detecteur.detecter(db, jours=3, regles={"unpkg.com"}, rejetes={"code.jquery.com"})
    assert [x["host"] for x in c] == ["ajax.googleapis.com"]


def test_une_regle_joker_couvre_ses_sous_domaines(tmp_path):
    db = magasin(tmp_path, [(AUJ, "c", "ajax.googleapis.com", "ALLOWED", 9)])
    assert detecteur.detecter(db, jours=3, regles={"*.googleapis.com"}, rejetes=set()) == []


def test_un_magasin_absent_ou_corrompu_ne_leve_pas(tmp_path):
    assert detecteur.detecter(tmp_path / "absent.db", jours=3, regles=set(), rejetes=set()) is None
    (tmp_path / "x.db").write_text("pas une base")
    assert detecteur.detecter(tmp_path / "x.db", jours=3, regles=set(), rejetes=set()) is None


def test_le_magasin_n_est_jamais_modifie(tmp_path):
    db = magasin(tmp_path, [(AUJ, "c", "ajax.googleapis.com", "ALLOWED", 9)])
    avant = db.read_bytes()
    detecteur.detecter(db, jours=3, regles=set(), rejetes=set())
    assert db.read_bytes() == avant


# ---------- un passage ----------

def test_un_passage_ecrit_candidates_json_de_facon_atomique(tmp_path):
    db = magasin(tmp_path, [(AUJ, "c", "ajax.googleapis.com", "ALLOWED", 9)])
    rules = tmp_path / "rules.d"
    rules.mkdir()
    (rules / "50-webui.rules").write_text("# seed\nunpkg.com direct\n")
    sortie = tmp_path / "candidates.json"
    assert detecteur.passe(db, sortie, rules, tmp_path / "rejetes.json") == 0
    data = json.loads(sortie.read_text())
    assert [x["host"] for x in data] == ["ajax.googleapis.com"]
    assert not list(tmp_path.glob("*.tmp"))
    assert oct(sortie.stat().st_mode & 0o777) == "0o644"


def test_un_magasin_illisible_laisse_les_candidats_en_place(tmp_path):
    sortie = tmp_path / "candidates.json"
    sortie.write_text('[{"host":"garde.googleapis.com"}]')
    assert detecteur.passe(tmp_path / "absent.db", sortie, tmp_path / "r", tmp_path / "rej.json") == 0
    assert json.loads(sortie.read_text()) == [{"host": "garde.googleapis.com"}]


def test_un_fichier_de_rejetes_invalide_est_ignore(tmp_path):
    db = magasin(tmp_path, [(AUJ, "c", "ajax.googleapis.com", "ALLOWED", 9)])
    rej = tmp_path / "rejetes.json"
    rej.write_text("{pas du json")
    sortie = tmp_path / "candidates.json"
    detecteur.passe(db, sortie, tmp_path / "r", rej)
    assert json.loads(sortie.read_text())[0]["host"] == "ajax.googleapis.com"


# ---------- l'API : un rejet est mémorisé ----------

def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXYPAC_RULES_DIR", str(tmp_path / "rules.d"))
    monkeypatch.setenv("PROXYPAC_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PROXYPAC_CANDIDATES", str(tmp_path / "candidates.json"))
    monkeypatch.setenv("PROXYPAC_REJETES", str(tmp_path / "rejetes.json"))
    from fastapi.testclient import TestClient
    import api.main as m
    importlib.reload(m)
    monkeypatch.setattr(m, "run_once", lambda *a, **k: True)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    return TestClient(m.app)


def test_rejeter_un_candidat_le_retire_et_le_memorise(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    (tmp_path / "candidates.json").write_text(json.dumps([{"host": "unpkg.com"}, {"host": "code.jquery.com"}]))
    assert c.post("/candidate/unpkg.com/reject").status_code == 200
    assert json.loads((tmp_path / "rejetes.json").read_text()) == ["unpkg.com"]
    assert [x["host"] for x in c.get("/candidates").json()["candidates"]] == ["code.jquery.com"]


def test_rejeter_deux_fois_ne_double_pas(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    c.post("/candidate/unpkg.com/reject")
    c.post("/candidate/unpkg.com/reject")
    assert json.loads((tmp_path / "rejetes.json").read_text()) == ["unpkg.com"]


def test_un_hote_invalide_est_refuse_au_rejet(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.post("/candidate/bad%20host/reject").status_code in (400, 422)


# ---------- paquetage ----------

def test_l_unite_tourne_sous_secubox_et_la_minuterie_est_livree():
    s = (ROOT / "systemd" / "secubox-proxypac-detect.service").read_text()
    assert "ExecStart=/usr/sbin/proxypac-detect" in s and "User=secubox" in s and "Type=oneshot" in s
    assert "OnUnitActiveSec=" in (ROOT / "systemd" / "secubox-proxypac-detect.timer").read_text()
    assert subprocess.run(["python3", "-m", "py_compile", str(ROOT / "sbin" / "proxypac-detect")]).returncode == 0
    rules = (ROOT.parents[1] / "debian" / "rules").read_text()
    assert "proxypac-detect" in rules and "secubox-proxypac-detect.timer" in rules
